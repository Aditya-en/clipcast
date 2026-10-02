package com.clipcast.protocol

import org.junit.Assert.*
import org.junit.Test
import java.nio.charset.StandardCharsets

/**
 * (5) Announce encode/decode round trip and malformed input.
 * Payload vector from clipcast docs/test-vectors-v2.md section 1.
 */
class AnnounceTest {

    private fun hex(s: String): ByteArray {
        return s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    @Test
    fun announcePayload_matchesDocumentedHex() {
        val sha = hex("b36a2ee430d07013c9c7ef342543b572c2ef92669d488fb12f73a3d101435205")
        val transferId = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
        val payload = Crypto.encodeAnnouncePayload(0x01, transferId, 11, sha, 47475)
        assertEquals(59, payload.size)
        assertEquals(
            "01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000000000000bb36a2ee430d07013c9c7ef342543b572c2ef92669d488fb12f73a3d101435205b973",
            Crypto.bytesToHex(payload)
        )
        val parsed = Crypto.decodeAnnouncePayload(payload)!!
        assertEquals(0x01.toByte(), parsed.innerContentType)
        assertArrayEquals(transferId, parsed.transferId)
        assertEquals(11L, parsed.totalLen)
        assertArrayEquals(sha, parsed.sha256)
        assertEquals(47475, parsed.tcpPort)
    }

    @Test
    fun announcePayload_rejectsMalformed() {
        assertNull(Crypto.decodeAnnouncePayload(ByteArray(0)))
        assertNull(Crypto.decodeAnnouncePayload(ByteArray(58)))
        assertNull(Crypto.decodeAnnouncePayload(ByteArray(60)))
        assertNull(Crypto.decodeAnnouncePayload(ByteArray(100)))
        // Port 0 is out of range.
        val good = Crypto.encodeAnnouncePayload(0x01, ByteArray(16) { 1 }, 5, ByteArray(32) { 2 }, 47475)
        val badPort = good.copyOf().also { it[57] = 0; it[58] = 0 }
        assertNull(Crypto.decodeAnnouncePayload(badPort))
    }

    @Test
    fun announceDatagram_roundTrip() {
        val key = Crypto.generateDeviceId()
        // 32-byte key: generateDeviceId is 16 bytes, so build one explicitly.
        val key32 = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val deviceId = Crypto.generateDeviceId()
        val transferId = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
        val content = "large text over TCP".toByteArray(StandardCharsets.UTF_8)
        val sha = TcpCrypto.sha256(content)
        val payload59 = Crypto.encodeAnnouncePayload(0x01, transferId, content.size.toLong(), sha, 47475)
        val lamport = 987654321L
        val now = System.currentTimeMillis()

        val datagram = Crypto.encodeAnnounce(key32, deviceId, lamport, now, payload59)!!
        // Small (non-send) sanity: announce datagram is bigger than a v1 header but small.
        assertTrue(datagram.size < 1400)

        val decoded = Crypto.decodeAnnounce(key32, datagram)!!
        assertArrayEquals(deviceId, decoded.deviceId)
        assertEquals(lamport, decoded.lamport)
        assertEquals(now, decoded.timestampMs)
        assertEquals(0x01.toByte(), decoded.innerContentType)
        assertArrayEquals(transferId, decoded.transferId)
        assertEquals(content.size.toLong(), decoded.totalLen)
        assertArrayEquals(sha, decoded.sha256)
        assertEquals(47475, decoded.tcpPort)
        assertEquals(key32.size, 32)
        assertEquals(key.size, 16)
    }

    @Test
    fun announceAndV1_doNotCrossDecode() {
        val key32 = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val deviceId = Crypto.generateDeviceId()
        // v1 text datagram is not an announce.
        val v1 = Crypto.encode(key32, deviceId, 1, 1000, "hi".toByteArray(StandardCharsets.UTF_8))!!
        assertNull(Crypto.decodeAnnounce(key32, v1))
        // Announce datagram is not v1 text.
        val payload59 = Crypto.encodeAnnouncePayload(0x01, ByteArray(16) { 9 }, 2, ByteArray(32) { 8 }, 47475)
        val announce = Crypto.encodeAnnounce(key32, deviceId, 2, 1000, payload59)!!
        assertNull(Crypto.decode(key32, announce))
    }

    @Test
    fun announceDatagram_rejectsTamperedAndTruncated() {
        val key32 = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val deviceId = Crypto.generateDeviceId()
        val payload59 = Crypto.encodeAnnouncePayload(0x01, ByteArray(16) { 9 }, 2, ByteArray(32) { 8 }, 47475)
        val datagram = Crypto.encodeAnnounce(key32, deviceId, 2, 1000, payload59)!!

        val tampered = datagram.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0xFF).toByte()
        assertNull(Crypto.decodeAnnounce(key32, tampered))

        val truncated = datagram.copyOfRange(0, datagram.size - 5)
        assertNull(Crypto.decodeAnnounce(key32, truncated))

        val wrongKey = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        assertNull(Crypto.decodeAnnounce(wrongKey, datagram))

        assertNull(Crypto.decodeAnnounce(key32, ByteArray(10)))
    }
}
