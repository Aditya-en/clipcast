package com.clipcast.service

import com.clipcast.protocol.TcpCrypto
import org.junit.Assert.*
import org.junit.Test
import java.io.DataInputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * TCP server socket tests with raw handshakes (mirrors the daemon's
 * tcp_server::tests). Full client+server loopback incl. 5 MB lives in
 * TcpLoopbackTest once the fetch client exists (M3).
 */
class TcpServerTest {

    private val key = ByteArray(32) { 7 }

    private fun servingServer(data: ByteArray, transferId: ByteArray = ByteArray(16) { 0xAB.toByte() }): TcpServer {
        val store = TransferStore()
        store.insert(transferId, data)
        val server = TcpServer(0, { key }, store)
        assertTrue(server.start())
        return server
    }

    private fun handshakeFor(transferId: ByteArray): Pair<ByteArray, ByteArray> {
        val header = TcpCrypto.RequestHeader(
            clientDeviceId = ByteArray(16) { 0x01 },
            transferId = transferId.copyOf(),
            clientNonce = ByteArray(32) { 0x02 }
        )
        val bytes = TcpCrypto.encodeRequestHeader(header)
        val sk = TcpCrypto.deriveSessionKey(key, header.clientNonce, transferId)
        return Pair(bytes, TcpCrypto.sealHandshake(sk, bytes))
    }

    private fun connect(server: TcpServer): Socket {
        val s = Socket()
        s.connect(InetSocketAddress("127.0.0.1", server.localPort), 3000)
        s.soTimeout = 5000
        return s
    }

    private fun readAll(s: Socket): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(4096)
        s.soTimeout = 2000
        try {
            while (true) {
                val n = s.getInputStream().read(buf)
                if (n < 0) break
                out.write(buf, 0, n)
            }
        } catch (e: Exception) {
            // timeout/EOF: whatever arrived is what we got.
        }
        return out.toByteArray()
    }

    @Test
    fun badMagic_droppedSilently() {
        val server = servingServer("data".toByteArray())
        try {
            connect(server).use { s ->
                s.getOutputStream().write("XXXX".toByteArray() + ByteArray(82))
                s.getOutputStream().flush()
                assertEquals(0, readAll(s).size)
            }
        } finally {
            server.stop()
        }
    }

    @Test
    fun badTag_droppedSilently() {
        val server = servingServer("data".toByteArray())
        try {
            val (header, tag) = handshakeFor(ByteArray(16) { 0xAB.toByte() })
            val bad = tag.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
            connect(server).use { s ->
                s.getOutputStream().write(header + bad)
                s.getOutputStream().flush()
                assertEquals(0, readAll(s).size)
            }
        } finally {
            server.stop()
        }
    }

    @Test
    fun unknownTransfer_droppedSilently() {
        val server = servingServer("data".toByteArray())
        try {
            val (header, tag) = handshakeFor(ByteArray(16) { 0xFF.toByte() })
            connect(server).use { s ->
                s.getOutputStream().write(header + tag)
                s.getOutputStream().flush()
                assertTrue(readAll(s).isEmpty())
            }
        } finally {
            server.stop()
        }
    }

    @Test
    fun servesSmallTransfer_withSingleFinalFrame() {
        val data = "Hello, TCP server!".toByteArray()
        val server = servingServer(data)
        try {
            val (header, tag) = handshakeFor(ByteArray(16) { 0xAB.toByte() })
            connect(server).use { s ->
                s.getOutputStream().write(header + tag)
                s.getOutputStream().flush()
                val input = DataInputStream(s.getInputStream())
                val len = input.readInt()
                val ct = ByteArray(len).also { input.readFully(it) }
                val sk = TcpCrypto.deriveSessionKey(key, ByteArray(32) { 0x02 }, ByteArray(16) { 0xAB.toByte() })
                val (flags, out) = TcpCrypto.openFrame(sk, header, TcpCrypto.DIR_SERVER_TO_CLIENT, 0, ct)!!
                assertEquals(TcpCrypto.FLAG_FINAL, flags)
                assertArrayEquals(data, out)
                // Connection closes after the single frame: EOF, nothing more.
                s.soTimeout = 2000
                val extra = ByteArray(1)
                val n = try {
                    s.getInputStream().read(extra)
                } catch (e: Exception) {
                    -1
                }
                assertTrue("expected EOF after FINAL, got $n bytes", n <= 0)
            }
        } finally {
            server.stop()
        }
    }

    @Test
    fun exactMultiple_getsEmptyFinalFrame() {
        val payload = ByteArray(TcpCrypto.MAX_FRAME_DATA) { 0x42 }
        val server = servingServer(payload)
        try {
            val (header, tag) = handshakeFor(ByteArray(16) { 0xAB.toByte() })
            connect(server).use { s ->
                s.getOutputStream().write(header + tag)
                s.getOutputStream().flush()
                val input = DataInputStream(s.getInputStream())
                val sk = TcpCrypto.deriveSessionKey(key, ByteArray(32) { 0x02 }, ByteArray(16) { 0xAB.toByte() })
                val len0 = input.readInt()
                val ct0 = ByteArray(len0).also { input.readFully(it) }
                val (flags0, data0) = TcpCrypto.openFrame(sk, header, TcpCrypto.DIR_SERVER_TO_CLIENT, 0, ct0)!!
                assertEquals(0.toByte(), flags0)
                assertEquals(TcpCrypto.MAX_FRAME_DATA, data0.size)
                val len1 = input.readInt()
                assertEquals(TcpCrypto.TAG_LEN + 1, len1)
                val ct1 = ByteArray(len1).also { input.readFully(it) }
                val (flags1, data1) = TcpCrypto.openFrame(sk, header, TcpCrypto.DIR_SERVER_TO_CLIENT, 1, ct1)!!
                assertEquals(TcpCrypto.FLAG_FINAL, flags1)
                assertEquals(0, data1.size)
            }
        } finally {
            server.stop()
        }
    }

    @Test
    fun overLimitConnections_closedImmediately() {
        val store = TransferStore()
        store.insert(ByteArray(16) { 0xAB.toByte() }, "x".toByteArray())
        val server = TcpServer(0, { key }, store, maxConnections = 1)
        assertTrue(server.start())
        try {
            // Occupy the single slot with a connection that stays open a bit.
            val holder = connect(server)
            try {
                Thread.sleep(300)
                // Extra connection beyond the limit must be closed immediately:
                // reads EOF without sending anything.
                connect(server).use { extra ->
                    extra.soTimeout = 2000
                    val n = try {
                        extra.getInputStream().read()
                    } catch (e: Exception) {
                        -1
                    }
                    assertEquals(-1, n)
                }
            } finally {
                holder.close()
            }
        } finally {
            server.stop()
        }
    }

    private operator fun ByteArray.plus(other: ByteArray): ByteArray {
        val out = ByteArray(size + other.size)
        copyInto(out, 0)
        other.copyInto(out, size)
        return out
    }
}
