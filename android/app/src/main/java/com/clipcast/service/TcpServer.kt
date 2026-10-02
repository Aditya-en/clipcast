package com.clipcast.service

import com.clipcast.protocol.LargeTextLimits
import com.clipcast.protocol.TcpCrypto
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicInteger

/**
 * TCP listener serving pending large-text transfers to LAN peers.
 *
 * Bound to all interfaces on [port]; one accept thread plus a bounded worker
 * pool ([LargeTextLimits.MAX_SERVER_CONNECTIONS] concurrent connections —
 * extras are closed immediately). Start/stop with the foreground service.
 *
 * Authentication first: reads exactly the 70-byte request header plus the
 * 16-byte handshake tag under a 3 s deadline, derives the session key, and
 * verifies the tag. On ANY failure — bad magic/version/tag, unknown or
 * expired transfer id, exhausted fetch budget, I/O deadline — the connection
 * closes silently with no response. Nothing sized by attacker input is
 * allocated before authentication (fixed 86-byte read, map lookup only).
 *
 * Power note: the listener only works while the service is alive, and Doze
 * may delay it (see README).
 */
class TcpServer(
    private val port: Int,
    private val keyProvider: () -> ByteArray?,
    private val store: TransferStore,
    private val idleTimeoutMs: Int = LargeTextLimits.IDLE_TIMEOUT_MS,
    private val totalTimeoutMs: Long = LargeTextLimits.TOTAL_TIMEOUT_MS,
    private val maxConnections: Int = LargeTextLimits.MAX_SERVER_CONNECTIONS,
    private val listener: Listener? = null,
    /**
     * Diagnostic log sink. Defaults to no-op so this class stays pure-JVM
     * (unit tests run without the Android framework); the service passes
     * android.util.Log through.
     */
    private val log: (String) -> Unit = {}
) {
    interface Listener {
        /** Called once the socket is bound and accepting. */
        fun onListening(port: Int)

        /** Called when the socket cannot bind or the accept loop dies. */
        fun onError(message: String)
    }

    companion object {
        private const val HANDSHAKE_TIMEOUT_MS = 3000
        private const val REQUEST_PLUS_TAG = TcpCrypto.REQUEST_HEADER_LEN + TcpCrypto.TAG_LEN
    }

    @Volatile
    private var serverSocket: ServerSocket? = null
    private var acceptThread: Thread? = null
    private var workerPool = Executors.newCachedThreadPool { r ->
        Thread(r, "ClipcastTcpWorker").apply { isDaemon = true }
    }
    private val active = AtomicInteger(0)

    /** Actual bound port, or -1 while stopped (useful with port 0 in tests). */
    val localPort: Int get() = serverSocket?.localPort ?: -1

    /** Number of connections currently being served. */
    val activeConnections: Int get() = active.get()

    /**
     * Bind and start accepting. Returns true when listening; false when the
     * port is already in use or cannot bind (reported via [Listener.onError]).
     */
    @Synchronized
    fun start(): Boolean {
        if (serverSocket != null) return true
        val socket = try {
            ServerSocket(port)
        } catch (e: Exception) {
            log("TCP bind failed on port $port: ${e.message}")
            listener?.onError("TCP port $port in use")
            return false
        }
        serverSocket = socket
        acceptThread = Thread(::acceptLoop, "ClipcastTcpAccept").apply {
            isDaemon = true
            start()
        }
        log("listening on port ${socket.localPort}")
        listener?.onListening(socket.localPort)
        return true
    }

    @Synchronized
    fun stop() {
        try {
            serverSocket?.close()
        } catch (e: Exception) {
            log("close: ${e.message}")
        }
        serverSocket = null
        acceptThread?.interrupt()
        acceptThread = null
        workerPool.shutdownNow()
        workerPool = Executors.newCachedThreadPool { r ->
            Thread(r, "ClipcastTcpWorker").apply { isDaemon = true }
        }
        active.set(0)
    }

    private fun acceptLoop() {
        while (!Thread.currentThread().isInterrupted) {
            val socket = try {
                serverSocket?.accept()
            } catch (e: Exception) {
                // ServerSocket closed via stop(): normal shutdown.
                break
            } ?: break
            if (active.get() >= maxConnections) {
                log("connection over limit; closing immediately")
                try {
                    socket.close()
                } catch (e: Exception) {
                    // ignore
                }
                continue
            }
            active.incrementAndGet()
            try {
                workerPool.execute {
                    try {
                        handleConnection(socket)
                    } finally {
                        active.decrementAndGet()
                        try {
                            socket.close()
                        } catch (e: Exception) {
                            // ignore
                        }
                    }
                }
            } catch (e: Exception) {
                active.decrementAndGet()
                try {
                    socket.close()
                } catch (ignored: Exception) {
                }
            }
        }
    }

    private fun handleConnection(socket: Socket) {
        val startMs = System.currentTimeMillis()
        try {
            socket.soTimeout = HANDSHAKE_TIMEOUT_MS
            val input = DataInputStream(socket.getInputStream())
            val preAuth = ByteArray(REQUEST_PLUS_TAG)
            try {
                input.readFully(preAuth)
            } catch (e: Exception) {
                return // EOF/timeout before 86 bytes: close silently.
            }
            val headerBytes = preAuth.copyOfRange(0, TcpCrypto.REQUEST_HEADER_LEN)
            val tag = preAuth.copyOfRange(TcpCrypto.REQUEST_HEADER_LEN, REQUEST_PLUS_TAG)
            val req = TcpCrypto.decodeRequestHeader(headerBytes) ?: return
            val key = keyProvider() ?: return
            if (key.size != 32) return
            val sessionKey = try {
                TcpCrypto.deriveSessionKey(key, req.clientNonce, req.transferId)
            } catch (e: Exception) {
                return
            }
            if (!TcpCrypto.verifyHandshake(sessionKey, headerBytes, tag)) return
            // Authenticated: look up the transfer and record one fetch.
            // Unknown, expired, or exhausted ids close silently too.
            val (data, _) = store.serve(req.transferId) ?: return
            try {
                socket.soTimeout = idleTimeoutMs
            } catch (e: Exception) {
                return
            }
            val output = DataOutputStream(socket.getOutputStream())

            // Frame the bytes in 64 KiB chunks. When the length is an exact
            // (nonzero) multiple of the chunk size — or zero — the data chunks
            // alone cannot carry FINAL, so a trailing empty FINAL frame is sent.
            val exactMultiple =
                data.isNotEmpty() && data.size % TcpCrypto.MAX_FRAME_DATA == 0
            var offset = 0
            var counter = 0L
            while (offset < data.size) {
                if (System.currentTimeMillis() - startMs > totalTimeoutMs) return
                val end = minOf(offset + TcpCrypto.MAX_FRAME_DATA, data.size)
                val last = end == data.size
                val flags: Byte =
                    if (last && !exactMultiple) TcpCrypto.FLAG_FINAL else 0
                val chunk = data.copyOfRange(offset, end)
                if (!sendFrame(output, sessionKey, headerBytes, counter, flags, chunk)) return
                counter++
                offset = end
            }
            if (data.isEmpty() || exactMultiple) {
                if (System.currentTimeMillis() - startMs > totalTimeoutMs) return
                if (!sendFrame(
                        output, sessionKey, headerBytes, counter,
                        TcpCrypto.FLAG_FINAL, ByteArray(0)
                    )
                ) return
            }
            try {
                output.flush()
            } catch (e: Exception) {
                // peer went away; nothing to do.
            }
            log("served transfer (${data.size} bytes)")
        } catch (e: SocketTimeoutException) {
            log("connection idle timeout")
        } catch (e: EOFException) {
            log("connection EOF")
        } catch (e: Exception) {
            log("connection error: ${e.message}")
        }
    }

    private fun sendFrame(
        output: DataOutputStream,
        sessionKey: ByteArray,
        aad: ByteArray,
        counter: Long,
        flags: Byte,
        data: ByteArray
    ): Boolean {
        return try {
            val ct = TcpCrypto.sealFrame(
                sessionKey, aad, TcpCrypto.DIR_SERVER_TO_CLIENT, counter, flags, data
            )
            output.writeInt(ct.size)
            output.write(ct)
            true
        } catch (e: Exception) {
            false
        }
    }
}
