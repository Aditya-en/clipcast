package com.clipcast.service

import com.clipcast.protocol.TcpCrypto
import org.junit.Assert.*
import org.junit.Test
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * Fetch client tests: real server loopback plus canned stub servers for
 * negative cases (mirrors the daemon's fetch::tests).
 */
class TcpFetchClientTest {

    private val key = ByteArray(32) { 7 }
    private val loopback = InetAddress.getByName("127.0.0.1")

    private fun servingServer(data: ByteArray, id: ByteArray = ByteArray(16) { 0xAB.toByte() }): TcpServer {
        val store = TransferStore()
        store.insert(id, data)
        val server = TcpServer(0, { key }, store)
        assertTrue(server.start())
        return server
    }

    private fun paramsFor(port: Int, id: ByteArray, totalLen: Long, sha: ByteArray): TcpFetchClient.Params {
        return TcpFetchClient.Params(
            key = key,
            clientDeviceId = ByteArray(16) { 0x01 },
            serverAddress = loopback,
            tcpPort = port,
            transferId = id.copyOf(),
            totalLen = totalLen,
            expectedSha256 = sha.copyOf(),
            innerContentType = 0x01,
            maxTransferBytes = 64L * 1024 * 1024,
            totalTimeoutMs = 30_000
        )
    }

    /**
     * Raw stub server: performs the real handshake, then replays canned
     * *plaintext* frames sealed under the live session key. Frames are
     * (flags, data); an optional raw tail is appended after the frames.
     */
    private fun cannedServer(
        frames: List<Pair<Byte, ByteArray>>,
        key: ByteArray,
        extraTail: ByteArray? = null,
        holdMs: Long = 300
    ): Int {
        val listener = ServerSocket(0)
        val port = listener.localPort
        thread(isDaemon = true) {
            try {
                listener.use {
                    val socket = it.accept()
                    socket.use { s ->
                        s.soTimeout = 5000
                        val input = s.getInputStream()
                        val pre = ByteArray(TcpCrypto.REQUEST_HEADER_LEN + TcpCrypto.TAG_LEN)
                        var off = 0
                        while (off < pre.size) {
                            val n = input.read(pre, off, pre.size - off)
                            if (n < 0) return@thread
                            off += n
                        }
                        val header = pre.copyOfRange(0, TcpCrypto.REQUEST_HEADER_LEN)
                        val req = TcpCrypto.decodeRequestHeader(header) ?: return@thread
                        val sk = TcpCrypto.deriveSessionKey(key, req.clientNonce, req.transferId)
                        if (!TcpCrypto.verifyHandshake(sk, header, pre.copyOfRange(TcpCrypto.REQUEST_HEADER_LEN, pre.size))) {
                            return@thread
                        }
                        val out = DataOutputStream(s.getOutputStream())
                        frames.forEachIndexed { counter, (flags, data) ->
                            val ct = TcpCrypto.sealFrame(sk, header, TcpCrypto.DIR_SERVER_TO_CLIENT, counter.toLong(), flags, data)
                            out.writeInt(ct.size)
                            out.write(ct)
                        }
                        out.flush()
                        if (extraTail != null) {
                            s.getOutputStream().write(extraTail)
                            s.getOutputStream().flush()
                        }
                        Thread.sleep(holdMs)
                    }
                }
            } catch (e: Exception) {
                // test teardown; ignore.
            }
        }
        return port
    }

    @Test
    fun fetchSmallTransfer_loopback() {
        val id = ByteArray(16) { 0xAB.toByte() }
        val data = "fetch me over TCP".toByteArray()
        val server = servingServer(data, id)
        try {
            val params = paramsFor(server.localPort, id, data.size.toLong(), TcpCrypto.sha256(data))
            assertArrayEquals(data, TcpFetchClient.fetch(params, AtomicBoolean(false)))
        } finally {
            server.stop()
        }
    }

    @Test
    fun fetchMultiframeTransfer_loopback() {
        val id = ByteArray(16) { 0xCD.toByte() }
        val data = ByteArray(TcpCrypto.MAX_FRAME_DATA + 5000) { 0x41 }
        val server = servingServer(data, id)
        try {
            val params = paramsFor(server.localPort, id, data.size.toLong(), TcpCrypto.sha256(data))
            assertArrayEquals(data, TcpFetchClient.fetch(params, AtomicBoolean(false)))
        } finally {
            server.stop()
        }
    }

    @Test
    fun wrongKey_neverCompletes() {
        val id = ByteArray(16) { 0xAB.toByte() }
        val data = "secret bytes".toByteArray()
        val server = servingServer(data, id)
        try {
            val params = paramsFor(server.localPort, id, data.size.toLong(), TcpCrypto.sha256(data))
                .copy(key = ByteArray(32) { 9 })
            try {
                TcpFetchClient.fetch(params, AtomicBoolean(false))
                fail("expected FetchException")
            } catch (e: TcpFetchClient.FetchException) {
                assertTrue(e.kind == TcpFetchClient.FetchException.Kind.IO ||
                    e.kind == TcpFetchClient.FetchException.Kind.TIMEOUT ||
                    e.kind == TcpFetchClient.FetchException.Kind.PROTOCOL)
            }
        } finally {
            server.stop()
        }
    }

    @Test
    fun wrongHash_rejectedAfterFullReceipt() {
        val id = ByteArray(16) { 0xAB.toByte() }
        val data = "real bytes".toByteArray()
        val server = servingServer(data, id)
        try {
            val params = paramsFor(server.localPort, id, data.size.toLong(), ByteArray(32) { 0xFF.toByte() })
            try {
                TcpFetchClient.fetch(params, AtomicBoolean(false))
                fail("expected FetchException")
            } catch (e: TcpFetchClient.FetchException) {
                assertEquals(TcpFetchClient.FetchException.Kind.PROTOCOL, e.kind)
            }
        } finally {
            server.stop()
        }
    }

    @Test
    fun overLimit_rejectedWithoutConnecting() {
        // Nothing listens here; an over-limit fetch must fail before dialing.
        val params = paramsFor(9, ByteArray(16) { 0xAB.toByte() }, 101, ByteArray(32)).copy(maxTransferBytes = 100)
        try {
            TcpFetchClient.fetch(params, AtomicBoolean(false))
            fail("expected FetchException")
        } catch (e: TcpFetchClient.FetchException) {
            assertEquals(TcpFetchClient.FetchException.Kind.OVER_LIMIT, e.kind)
        }
    }

    @Test
    fun preCancelled_doesNotConnect() {
        val params = paramsFor(9, ByteArray(16) { 0xAB.toByte() }, 10, ByteArray(32))
        try {
            TcpFetchClient.fetch(params, AtomicBoolean(true))
            fail("expected FetchException")
        } catch (e: TcpFetchClient.FetchException) {
            assertEquals(TcpFetchClient.FetchException.Kind.CANCELLED, e.kind)
        }
    }

    @Test
    fun missingFinal_aborts() {
        // Stub sends one full non-final frame for a 65536+5 transfer, then
        // closes: the client must abort, never returning partial data.
        val total = TcpCrypto.MAX_FRAME_DATA.toLong() + 5
        val port = cannedServer(
            listOf(0.toByte() to ByteArray(TcpCrypto.MAX_FRAME_DATA) { 7 }),
            key, holdMs = 100
        )
        val params = paramsFor(port, ByteArray(16) { 0xEE.toByte() }, total, ByteArray(32))
        try {
            TcpFetchClient.fetch(params, AtomicBoolean(false))
            fail("expected FetchException")
        } catch (e: TcpFetchClient.FetchException) {
            assertEquals(TcpFetchClient.FetchException.Kind.PROTOCOL, e.kind)
        }
    }

    @Test
    fun dataAfterFinal_aborts() {
        val data = "exact".toByteArray()
        val port = cannedServer(
            listOf(TcpCrypto.FLAG_FINAL to data),
            key, extraTail = "X".toByteArray(), holdMs = 800
        )
        val params = paramsFor(port, ByteArray(16) { 0xEF.toByte() }, data.size.toLong(), TcpCrypto.sha256(data))
        try {
            TcpFetchClient.fetch(params, AtomicBoolean(false))
            fail("expected FetchException")
        } catch (e: TcpFetchClient.FetchException) {
            assertEquals(TcpFetchClient.FetchException.Kind.PROTOCOL, e.kind)
        }
    }

    @Test
    fun invalidUtf8_rejected() {
        val bad = byteArrayOf(0xFF.toByte(), 0xFE.toByte())
        val port = cannedServer(listOf(TcpCrypto.FLAG_FINAL to bad), key)
        val params = paramsFor(port, ByteArray(16) { 0xF1.toByte() }, 2, TcpCrypto.sha256(bad))
        try {
            TcpFetchClient.fetch(params, AtomicBoolean(false))
            fail("expected FetchException")
        } catch (e: TcpFetchClient.FetchException) {
            assertEquals(TcpFetchClient.FetchException.Kind.PROTOCOL, e.kind)
        }
    }

    @Test
    fun truncatedStream_aborts() {
        // Stub seals a FINAL frame but closes after sending only half the bytes.
        val data = "truncated payload".toByteArray()
        val listener = ServerSocket(0)
        val port = listener.localPort
        thread(isDaemon = true) {
            try {
                listener.use {
                    val socket = it.accept()
                    socket.use { s ->
                        s.soTimeout = 5000
                        val input = s.getInputStream()
                        val pre = ByteArray(TcpCrypto.REQUEST_HEADER_LEN + TcpCrypto.TAG_LEN)
                        var off = 0
                        while (off < pre.size) {
                            val n = input.read(pre, off, pre.size - off)
                            if (n < 0) return@thread
                            off += n
                        }
                        val header = pre.copyOfRange(0, TcpCrypto.REQUEST_HEADER_LEN)
                        val req = TcpCrypto.decodeRequestHeader(header) ?: return@thread
                        val sk = TcpCrypto.deriveSessionKey(key, req.clientNonce, req.transferId)
                        if (!TcpCrypto.verifyHandshake(sk, header, pre.copyOfRange(TcpCrypto.REQUEST_HEADER_LEN, pre.size))) return@thread
                        val ct = TcpCrypto.sealFrame(sk, header, TcpCrypto.DIR_SERVER_TO_CLIENT, 0, TcpCrypto.FLAG_FINAL, data)
                        val out = DataOutputStream(s.getOutputStream())
                        out.writeInt(ct.size)
                        out.write(ct, 0, ct.size / 2)
                        out.flush()
                        // Close mid-frame.
                    }
                }
            } catch (e: Exception) {
            }
        }
        val params = paramsFor(port, ByteArray(16) { 0xF2.toByte() }, data.size.toLong(), TcpCrypto.sha256(data))
        try {
            TcpFetchClient.fetch(params, AtomicBoolean(false))
            fail("expected FetchException")
        } catch (e: TcpFetchClient.FetchException) {
            assertTrue(e.kind == TcpFetchClient.FetchException.Kind.PROTOCOL ||
                e.kind == TcpFetchClient.FetchException.Kind.IO ||
                e.kind == TcpFetchClient.FetchException.Kind.TIMEOUT)
        }
    }

    @Test
    fun midFlightCancel_abortsFetch() {
        // (8b) A newer accepted message cancels a running fetch: the stub
        // holds the connection open; cancelling + closing the socket aborts.
        val listener = ServerSocket(0)
        val port = listener.localPort
        thread(isDaemon = true) {
            try {
                listener.use {
                    val socket = it.accept()
                    socket.use { s ->
                        s.soTimeout = 5000
                        val input = s.getInputStream()
                        val pre = ByteArray(TcpCrypto.REQUEST_HEADER_LEN + TcpCrypto.TAG_LEN)
                        var off = 0
                        while (off < pre.size) {
                            val n = input.read(pre, off, pre.size - off)
                            if (n < 0) return@thread
                            off += n
                        }
                        // Hold the connection without sending frames.
                        Thread.sleep(10_000)
                    }
                }
            } catch (e: Exception) {
            }
        }
        val data = ByteArray(100) { 0x41 }
        val params = paramsFor(port, ByteArray(16) { 0xF3.toByte() }, 100, TcpCrypto.sha256(data))
            .copy(totalTimeoutMs = 30_000)
        val cancel = AtomicBoolean(false)
        val socketRef = AtomicReference<Socket?>(null)
        var result: kotlin.Result<ByteArray>? = null
        val t = thread(isDaemon = true) {
            result = try {
                kotlin.Result.success(TcpFetchClient.fetch(params, cancel, socketRef))
            } catch (e: TcpFetchClient.FetchException) {
                kotlin.Result.failure(e)
            }
        }
        // Wait for the fetch to connect, then cancel like a newer announce would.
        var waited = 0
        while (socketRef.get() == null && waited < 5000) {
            Thread.sleep(50)
            waited += 50
        }
        assertNotNull("fetch should have connected", socketRef.get())
        cancel.set(true)
        try {
            socketRef.get()?.close()
        } catch (e: Exception) {
        }
        t.join(15_000)
        assertNotNull("fetch thread should finish after cancel", result)
        val err = result!!.exceptionOrNull() as? TcpFetchClient.FetchException
        assertNotNull("cancelled fetch must throw", err)
        assertEquals(TcpFetchClient.FetchException.Kind.CANCELLED, err!!.kind)
    }

    private operator fun ByteArray.plus(other: ByteArray): ByteArray {
        val out = ByteArray(size + other.size)
        copyInto(out, 0)
        other.copyInto(out, size)
        return out
    }
}
