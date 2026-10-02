package com.clipcast.service

import com.clipcast.protocol.LargeTextLimits
import com.clipcast.protocol.TcpCrypto
import java.io.DataInputStream
import java.io.EOFException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * TCP fetch client (receiver side of a large-text transfer). Pure JVM:
 * no Android framework imports so unit tests run on localhost.
 *
 * The caller supplies the announce's UDP source address — never any other
 * address — and the transfer metadata from the (already authenticated and
 * ordered) announce. Timeouts: 3 s connect, 10 s idle between frames,
 * overall [LargeTextLimits.TOTAL_TIMEOUT_MS]. Cancellation is cooperative
 * via [cancel] plus closing [socketRef]'s socket (unblocks a pending read).
 */
object TcpFetchClient {

    class FetchException(val kind: Kind, message: String, cause: Throwable? = null) :
        Exception(message, cause) {
        enum class Kind {
            OVER_LIMIT,
            CANCELLED,
            CONNECT,
            IO,
            TIMEOUT,
            PROTOCOL
        }
    }

    data class Params(
        val key: ByteArray,
        val clientDeviceId: ByteArray,
        /** The announce datagram's source address. Nothing else is ever dialed. */
        val serverAddress: InetAddress,
        val tcpPort: Int,
        val transferId: ByteArray,
        val totalLen: Long,
        val expectedSha256: ByteArray,
        val innerContentType: Byte,
        val maxTransferBytes: Long = LargeTextLimits.DEFAULT_MAX_APPLY_BYTES.toLong(),
        val totalTimeoutMs: Long = LargeTextLimits.TOTAL_TIMEOUT_MS,
        val connectTimeoutMs: Int = LargeTextLimits.CONNECT_TIMEOUT_MS,
        val idleTimeoutMs: Int = LargeTextLimits.IDLE_TIMEOUT_MS
    )

    /**
     * Fetch one transfer to completion. Returns the plaintext content bytes.
     * On any failure throws [FetchException] and the caller applies nothing.
     */
    fun fetch(
        params: Params,
        cancel: AtomicBoolean,
        socketRef: AtomicReference<Socket?>? = null
    ): ByteArray {
        if (java.lang.Long.compareUnsigned(params.totalLen, params.maxTransferBytes) > 0) {
            throw FetchException(
                FetchException.Kind.OVER_LIMIT,
                "transfer len ${params.totalLen} exceeds max $params.maxTransferBytes"
            )
        }
        if (cancel.get()) throw FetchException(FetchException.Kind.CANCELLED, "cancelled before connect")
        val startMs = System.currentTimeMillis()

        val clientNonce = ByteArray(TcpCrypto.CLIENT_NONCE_LEN)
        SecureRandom().nextBytes(clientNonce)
        val header = TcpCrypto.RequestHeader(
            clientDeviceId = params.clientDeviceId.copyOf(),
            transferId = params.transferId.copyOf(),
            clientNonce = clientNonce
        )
        val headerBytes = TcpCrypto.encodeRequestHeader(header)
        val sessionKey = try {
            TcpCrypto.deriveSessionKey(params.key, clientNonce, params.transferId)
        } catch (e: Exception) {
            throw FetchException(FetchException.Kind.PROTOCOL, "key derivation failed: ${e.message}", e)
        }
        val tag = TcpCrypto.sealHandshake(sessionKey, headerBytes)

        val socket = Socket()
        socketRef?.set(socket)
        try {
            try {
                socket.connect(
                    InetSocketAddress(params.serverAddress, params.tcpPort),
                    params.connectTimeoutMs
                )
            } catch (e: Exception) {
                if (cancel.get()) throw FetchException(FetchException.Kind.CANCELLED, "cancelled", e)
                throw FetchException(
                    FetchException.Kind.CONNECT,
                    "connect to ${params.serverAddress.hostAddress}:${params.tcpPort} failed: ${e.message}",
                    e
                )
            }
            socket.soTimeout = params.idleTimeoutMs
            try {
                val out = socket.getOutputStream()
                out.write(headerBytes)
                out.write(tag)
                out.flush()
            } catch (e: Exception) {
                throw ioOrCancelled(e, cancel)
            }

            val input = DataInputStream(socket.getInputStream())
            val assembler = TcpCrypto.FrameAssembler(params.totalLen)
            var counter = 0L
            while (true) {
                if (cancel.get()) throw FetchException(FetchException.Kind.CANCELLED, "cancelled")
                checkTotalTimeout(startMs, params.totalTimeoutMs)
                val len = try {
                    input.readInt()
                } catch (e: SocketTimeoutException) {
                    throw FetchException(FetchException.Kind.TIMEOUT, "idle timeout waiting for frame", e)
                } catch (e: EOFException) {
                    throw FetchException(
                        FetchException.Kind.PROTOCOL,
                        "connection closed mid-stream (missing FINAL)",
                        e
                    )
                } catch (e: Exception) {
                    throw ioOrCancelled(e, cancel, startMs, params.totalTimeoutMs)
                }
                if (len < 0 || len > TcpCrypto.MAX_FRAME_CIPHERTEXT) {
                    throw FetchException(
                        FetchException.Kind.PROTOCOL,
                        "ciphertext length $len exceeds maximum ${TcpCrypto.MAX_FRAME_CIPHERTEXT}"
                    )
                }
                val ct = ByteArray(len)
                try {
                    input.readFully(ct)
                } catch (e: SocketTimeoutException) {
                    throw FetchException(FetchException.Kind.TIMEOUT, "idle timeout reading frame", e)
                } catch (e: Exception) {
                    throw ioOrCancelled(e, cancel, startMs, params.totalTimeoutMs)
                }
                val (flags, data) = TcpCrypto.openFrame(
                    sessionKey, headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, counter, ct
                ) ?: throw FetchException(FetchException.Kind.PROTOCOL, "frame open failed at counter $counter")
                val done = try {
                    assembler.feed(flags, data, counter)
                } catch (e: TcpCrypto.TcpException) {
                    throw FetchException(FetchException.Kind.PROTOCOL, e.message ?: "assembler rejected frame", e)
                }
                counter++
                if (done) break
            }
            val data = try {
                assembler.finish()
            } catch (e: TcpCrypto.TcpException) {
                throw FetchException(FetchException.Kind.PROTOCOL, e.message ?: "missing FINAL", e)
            }

            // Exactly one FINAL frame and nothing after it: the server must
            // close. A lingering connection (or extra bytes) is suspicious.
            socket.soTimeout = 2000
            try {
                val extra = input.read()
                if (extra >= 0) {
                    throw FetchException(FetchException.Kind.PROTOCOL, "data after FINAL frame")
                }
            } catch (e: FetchException) {
                throw e
            } catch (e: SocketTimeoutException) {
                throw FetchException(FetchException.Kind.TIMEOUT, "server did not close after FINAL", e)
            } catch (e: EOFException) {
                // Some stacks surface close as EOF: fine.
            } catch (e: Exception) {
                throw ioOrCancelled(e, cancel, startMs, params.totalTimeoutMs)
            }

            try {
                TcpCrypto.verifyContent(data, params.totalLen, params.expectedSha256, params.innerContentType)
            } catch (e: TcpCrypto.TcpException) {
                throw FetchException(FetchException.Kind.PROTOCOL, e.message ?: "content rejected", e)
            }
            return data
        } finally {
            socketRef?.compareAndSet(socket, null)
            try {
                socket.close()
            } catch (e: Exception) {
                // ignore
            }
        }
    }

    private fun checkTotalTimeout(startMs: Long, totalMs: Long) {
        if (System.currentTimeMillis() - startMs > totalMs) {
            throw FetchException(FetchException.Kind.TIMEOUT, "fetch timed out")
        }
    }

    private fun ioOrCancelled(
        e: Exception,
        cancel: AtomicBoolean,
        startMs: Long = 0,
        totalMs: Long = Long.MAX_VALUE
    ): FetchException {
        if (cancel.get()) return FetchException(FetchException.Kind.CANCELLED, "cancelled", e)
        if (startMs != 0L && System.currentTimeMillis() - startMs > totalMs) {
            return FetchException(FetchException.Kind.TIMEOUT, "fetch timed out", e)
        }
        return FetchException(FetchException.Kind.IO, "I/O during fetch: ${e.message}", e)
    }
}
