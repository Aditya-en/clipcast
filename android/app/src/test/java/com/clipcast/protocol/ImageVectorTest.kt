package com.clipcast.protocol

import org.junit.Assert.*
import org.junit.Test

/**
 * Image announce + TCP image frame vectors.
 *
 * Every hex blob below is copied verbatim from
 * desktop/docs/test-vectors-image.md (produced by the Rust
 * implementation), so this test proves byte-level interoperability
 * between the Kotlin and Rust codecs without a device.
 */
class ImageVectorTest {

    private fun hex(s: String): ByteArray =
        s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun key(): ByteArray = ByteArray(32) { it.toByte() }

    // Deterministic 1x1 PNG from the vectors document (69 bytes).
    private fun testImage(): ByteArray = hex(
        "89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de" +
            "0000000c4944415408d763f8cfc00000000300010005fed40000000049454e44ae426082"
    )

    @Test
    fun imageAnnouncePayload_matchesDocumentedHex() {
        val sha = hex("167a2b4b202a5c05e6fb5ac9f45b52d7bc5c5f8a0f94679362fd8a86912ee397")
        val transferId = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
        // The implementation must hash the image to the documented digest.
        assertArrayEquals(sha, TcpCrypto.sha256(testImage()))

        val payload = Crypto.encodeImageAnnouncePayload(transferId, 69, sha, 47475, "image/png")
        assertEquals(69, payload.size)
        assertEquals(
            "02b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000045167a2b4b202a5c05" +
                "e6fb5ac9f45b52d7bc5c5f8a0f94679362fd8a86912ee397b97309696d6167652f706e67",
            Crypto.bytesToHex(payload)
        )
        val parsed = Crypto.decodeImageAnnouncePayload(payload)!!
        assertArrayEquals(transferId, parsed.transferId)
        assertEquals(69L, parsed.totalLen)
        assertArrayEquals(sha, parsed.sha256)
        assertEquals(47475, parsed.tcpPort)
        assertEquals("image/png", parsed.mimeType)
    }

    @Test
    fun imageAnnounceDatagram_matchesDocumentedHex() {
        val deviceId = hex("202122232425262728292a2b2c2d2e2f")
        val nonce = hex("e0e1e2e3e4e5e6e7e8e9eaeb")
        val payload = hex(
            "02b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000045167a2b4b202a5c05" +
                "e6fb5ac9f45b52d7bc5c5f8a0f94679362fd8a86912ee397b97309696d6167652f706e67"
        )
        val datagram = Crypto.encodeImageAnnounce(
            key(), deviceId, 987654321L, 1700000000000L, payload, nonce
        )!!
        assertEquals(
            "43434c500101202122232425262728292a2b2c2d2e2fe0e1e2e3e4e5e6e7e8e9eaeb" +
                "34c2c983cf1ee29ac0037fc591f9908345a53be7bb867da92e32dec8ba869033e959" +
                "5d4fc71af86031cea5b03b1f15fb4f19f06d41e6fd6b99704dfca0603671abb8e643" +
                "ad67538b64042af5a96af97411cd8a5b9b52c7c208b1318b2f099155055c7ab27e12c9bb2a59",
            Crypto.bytesToHex(datagram)
        )
        // And the documented datagram opens through the receiver path.
        val opened = Crypto.decodeImageAnnounce(
            key(),
            hex(
                "43434c500101202122232425262728292a2b2c2d2e2fe0e1e2e3e4e5e6e7e8e9eaeb" +
                    "34c2c983cf1ee29ac0037fc591f9908345a53be7bb867da92e32dec8ba869033e959" +
                    "5d4fc71af86031cea5b03b1f15fb4f19f06d41e6fd6b99704dfca0603671abb8e643" +
                    "ad67538b64042af5a96af97411cd8a5b9b52c7c208b1318b2f099155055c7ab27e12c9bb2a59"
            )
        )!!
        assertArrayEquals(deviceId, opened.deviceId)
        assertEquals(987654321L, opened.lamport)
        assertEquals(1700000000000L, opened.timestampMs)
        assertEquals(69L, opened.totalLen)
        assertEquals(47475, opened.tcpPort)
        assertEquals("image/png", opened.mimeType)
    }

    @Test
    fun imageTcpVectors_matchDocumentedHex() {
        val transferId = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf")
        val clientId = hex("303132333435363738393a3b3c3d3e3f")
        val clientNonce = hex(
            "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        )
        val reqBytes = TcpCrypto.encodeRequestHeader(
            TcpCrypto.RequestHeader(clientId, transferId, clientNonce)
        )
        assertEquals(
            "43434c540101303132333435363738393a3b3c3d3e3fb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
                "d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef",
            Crypto.bytesToHex(reqBytes)
        )
        val skey = TcpCrypto.deriveSessionKey(key(), clientNonce, transferId)
        assertEquals(
            "bbc21c6ef3429aee544715ec07e690b5aa507e443d6491a431b260a8b68b25a4",
            Crypto.bytesToHex(skey)
        )
        val tag = TcpCrypto.sealHandshake(skey, reqBytes)
        assertEquals("8d44bb79dc2471ab93c9b0745a6cc9da", Crypto.bytesToHex(tag))
        assertTrue(TcpCrypto.verifyHandshake(skey, reqBytes, hex("8d44bb79dc2471ab93c9b0745a6cc9da")))

        // The documented FINAL frame opens to the exact test image, whose
        // hash verifies for inner type 0x02 (no UTF-8 requirement).
        val frame = hex(
            "000000565db649ebbc31786690ba9dc1eb582893d667c4f8859b069f707e41a4b77" +
                "0bea27eefb9b96a9e7cb0ca8275eab6e5fe99a5287365e2c0594edf3d80a073217af" +
                "6984184dcb2ae9096d4032c0b08c3971e012d77b3be6b"
        )
        val len = ((frame[0].toInt() and 0xFF) shl 24) or
            ((frame[1].toInt() and 0xFF) shl 16) or
            ((frame[2].toInt() and 0xFF) shl 8) or
            (frame[3].toInt() and 0xFF)
        assertEquals(frame.size - 4, len)
        val (flags, data) = TcpCrypto.openFrame(
            skey, reqBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 0,
            frame.copyOfRange(4, frame.size)
        )!!
        assertEquals(TcpCrypto.FLAG_FINAL, flags)
        assertArrayEquals(testImage(), data)
        TcpCrypto.verifyContent(data, 69, TcpCrypto.sha256(testImage()), Crypto.INNER_IMAGE)
    }

    @Test
    fun imageAnnounce_rejectsMalformed() {
        assertNull(Crypto.decodeImageAnnouncePayload(ByteArray(0)))
        assertNull(Crypto.decodeImageAnnouncePayload(ByteArray(59)))
        assertNull(Crypto.decodeImageAnnouncePayload(ByteArray(124)))
        // Wrong inner type.
        val good = Crypto.encodeImageAnnouncePayload(
            ByteArray(16) { 1 }, 5, ByteArray(32) { 2 }, 47475, "image/png"
        )
        val badInner = good.copyOf().also { it[0] = Crypto.INNER_TEXT }
        assertNull(Crypto.decodeImageAnnouncePayload(badInner))
        // Trailing byte past the declared MIME.
        assertNull(Crypto.decodeImageAnnouncePayload(good + byteArrayOf(0x00)))
        // Unsupported MIME, well-formed.
        val gif = good.copyOf()
        val gifMime = "image/gif".toByteArray()
        val rebuilt = ByteArray(59 + 1 + gifMime.size)
        good.copyInto(rebuilt, 0, 0, 59)
        rebuilt[59] = gifMime.size.toByte()
        gifMime.copyInto(rebuilt, 60)
        assertNull(Crypto.decodeImageAnnouncePayload(rebuilt))
        // Strict 59-byte text decoder ignores image payloads (old-client behavior).
        assertNull(Crypto.decodeAnnouncePayload(good))
    }

    @Test
    fun mimeAllowlist() {
        assertTrue(Crypto.isSupportedImageMime("image/png"))
        assertTrue(Crypto.isSupportedImageMime("image/jpeg"))
        assertTrue(Crypto.isSupportedImageMime("image/webp"))
        assertFalse(Crypto.isSupportedImageMime("image/gif"))
        assertFalse(Crypto.isSupportedImageMime("text/plain"))
        assertFalse(Crypto.isSupportedImageMime("IMAGE/PNG"))
    }
}
