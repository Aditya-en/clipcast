package com.clipcast.service

import com.clipcast.protocol.TcpCrypto
import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

/**
 * (7) Loopback test with the real client and server code on localhost,
 * transferring about 5 MB (79 frames incl. the trailing data frame).
 */
class TcpLoopbackTest {

    @Test
    fun realClientAndServer_transferFiveMegabytes() {
        val key = ByteArray(32) { 0x2A }
        // ~5 MB of valid UTF-8 text (ASCII letters cycle).
        val size = 5 * 1024 * 1024
        val data = ByteArray(size) { i -> ('A'.code + (i % 26)).toByte() }
        val sha = TcpCrypto.sha256(data)
        val transferId = ByteArray(16) { 0x77 }

        val store = TransferStore()
        store.insert(transferId, data)
        val server = TcpServer(0, { key }, store)
        assertTrue(server.start())
        try {
            val params = TcpFetchClient.Params(
                key = key,
                clientDeviceId = ByteArray(16) { 0x05 },
                serverAddress = InetAddress.getByName("127.0.0.1"),
                tcpPort = server.localPort,
                transferId = transferId,
                totalLen = data.size.toLong(),
                expectedSha256 = sha,
                innerContentType = 0x01,
                maxTransferBytes = 64L * 1024 * 1024,
                totalTimeoutMs = 120_000
            )
            val received = TcpFetchClient.fetch(params, AtomicBoolean(false))
            assertEquals(data.size, received.size)
            assertArrayEquals(data, received)
            // Strict UTF-8 decodes (mirrors the apply path).
            val text = String(received, Charsets.UTF_8)
            assertEquals(size, text.length)
        } finally {
            server.stop()
        }
    }

    /**
     * Image bytes ride the same channel: the server falls back to the
     * image disk cache when the text store misses, and the client
     * verifies length + SHA-256 for inner type 0x02 without a UTF-8
     * requirement (the bytes below are not valid UTF-8).
     */
    @Test
    fun realClientAndServer_transferImageFromCache() {
        val key = ByteArray(32) { 0x2A }
        // 200 KiB of non-UTF-8 bytes (3 frames incl. FINAL).
        val size = 200 * 1024
        val data = ByteArray(size) { i -> ((i * 31) and 0xFF).toByte() }
        val sha = TcpCrypto.sha256(data)
        val transferId = ByteArray(16) { 0x78 }

        val dir = java.nio.file.Files.createTempDirectory("clipcast-img-loopback").toFile()
        try {
            val images = ImageCache(dir)
            images.insert(transferId, "image/png", data)
            val server = TcpServer(0, { key }, TransferStore(), imageCache = images)
            assertTrue(server.start())
            try {
                val params = TcpFetchClient.Params(
                    key = key,
                    clientDeviceId = ByteArray(16) { 0x05 },
                    serverAddress = InetAddress.getByName("127.0.0.1"),
                    tcpPort = server.localPort,
                    transferId = transferId,
                    totalLen = data.size.toLong(),
                    expectedSha256 = sha,
                    innerContentType = 0x02,
                    maxTransferBytes = 16L * 1024 * 1024,
                    totalTimeoutMs = 120_000
                )
                val received = TcpFetchClient.fetch(params, AtomicBoolean(false))
                assertArrayEquals(data, received)
            } finally {
                server.stop()
            }
        } finally {
            dir.deleteRecursively()
        }
    }
}
