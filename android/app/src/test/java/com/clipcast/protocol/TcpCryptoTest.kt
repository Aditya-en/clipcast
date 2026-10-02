package com.clipcast.protocol

import org.junit.Assert.*
import org.junit.Test

/**
 * Contract tests against clipcast docs/test-vectors-v2.md (produced by the
 * Rust implementation, verified by tcp::tests::test_vectors_match_documented_hex).
 */
class TcpCryptoTest {

    private fun hex(s: String): ByteArray {
        return s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun hexStr(b: ByteArray): String = Crypto.bytesToHex(b)

    private val key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    private val clientDeviceId = hex("101112131415161718191a1b1c1d1e1f")
    private val transferId = hex("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf")
    private val clientNonce = hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
    private val payload = "Hello, TCP!".toByteArray(Charsets.UTF_8)
    private val payloadSha = hex("b36a2ee430d07013c9c7ef342543b572c2ef92669d488fb12f73a3d101435205")
    private val headerBytes =
        hex("43434c540101101112131415161718191a1b1c1d1e1fa0a1a2a3a4a5a6a7a8a9aaabacadaeafc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf")
    private val sessionKeyHex = "cf6b9ebc804d61664134e76523191238880695fac7ba90bd1a335c15426fdbf2"

    private fun header(): TcpCrypto.RequestHeader = TcpCrypto.RequestHeader(
        clientDeviceId = clientDeviceId.copyOf(),
        transferId = transferId.copyOf(),
        clientNonce = clientNonce.copyOf()
    )

    private fun sessionKey(): ByteArray =
        TcpCrypto.deriveSessionKey(key, clientNonce, transferId)

    // (1) HKDF output equals the vector.
    @Test
    fun hkdf_matchesDocumentedVector() {
        assertEquals(sessionKeyHex, hexStr(sessionKey()))
    }

    // (2) Request header reproduced byte-exactly.
    @Test
    fun requestHeader_matchesDocumentedHex() {
        assertEquals(hexStr(headerBytes), hexStr(TcpCrypto.encodeRequestHeader(header())))
        assertEquals(header(), TcpCrypto.decodeRequestHeader(headerBytes))
    }

    @Test
    fun requestHeader_rejectsMalformed() {
        assertNull(TcpCrypto.decodeRequestHeader(headerBytes.copyOfRange(0, 69)))
        assertNull(TcpCrypto.decodeRequestHeader(headerBytes + 0x00.toByte()))
        val badMagic = headerBytes.copyOf().also { it[0] = 'X'.code.toByte() }
        assertNull(TcpCrypto.decodeRequestHeader(badMagic))
        val badVersion = headerBytes.copyOf().also { it[4] = 2 }
        assertNull(TcpCrypto.decodeRequestHeader(badVersion))
        val badType = headerBytes.copyOf().also { it[5] = 0x02 }
        assertNull(TcpCrypto.decodeRequestHeader(badType))
    }

    // (2) Handshake tag reproduced byte-exactly.
    @Test
    fun handshakeTag_matchesDocumentedHex() {
        val tag = TcpCrypto.sealHandshake(sessionKey(), headerBytes)
        assertEquals("e8841cef663f999d1af67e72d89da38d", hexStr(tag))
        assertTrue(TcpCrypto.verifyHandshake(sessionKey(), headerBytes, tag))
    }

    @Test
    fun handshake_rejectsTamperedTagAndHeader() {
        val tag = TcpCrypto.sealHandshake(sessionKey(), headerBytes)
        val badTag = tag.copyOf().also { it[0] = (it[0].toInt() xor 0x01).toByte() }
        assertFalse(TcpCrypto.verifyHandshake(sessionKey(), headerBytes, badTag))
        val badAad = headerBytes.copyOf().also { it[40] = (it[40].toInt() xor 0x01).toByte() }
        assertFalse(TcpCrypto.verifyHandshake(sessionKey(), badAad, tag))
        assertFalse(TcpCrypto.verifyHandshake(sessionKey(), headerBytes, tag.copyOfRange(0, 15)))
        assertFalse(TcpCrypto.verifyHandshake(sessionKey(), headerBytes, tag + 0x00.toByte()))
    }

    // (2) First server data frame (counter 0, FINAL) reproduced byte-exactly.
    @Test
    fun firstDataFrame_matchesDocumentedHex() {
        val ct = TcpCrypto.sealFrame(
            sessionKey(), headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 0,
            TcpCrypto.FLAG_FINAL, payload
        )
        val frame = lenPrefix(ct)
        assertEquals(
            "0000001c54623749f5569e27af8f598c61e0be85e0e311e42e20271f489f757b",
            hexStr(frame)
        )
    }

    // (2) Empty FINAL frame (counter 1) reproduced byte-exactly.
    @Test
    fun emptyFinalFrame_matchesDocumentedHex() {
        val ct = TcpCrypto.sealFrame(
            sessionKey(), headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 1,
            TcpCrypto.FLAG_FINAL, ByteArray(0)
        )
        val frame = lenPrefix(ct)
        assertEquals("000000110655f730879b22e1c9305ece6894f4383f", hexStr(frame))
    }

    private fun lenPrefix(ct: ByteArray): ByteArray {
        val out = ByteArray(4 + ct.size)
        out[0] = ((ct.size ushr 24) and 0xFF).toByte()
        out[1] = ((ct.size ushr 16) and 0xFF).toByte()
        out[2] = ((ct.size ushr 8) and 0xFF).toByte()
        out[3] = (ct.size and 0xFF).toByte()
        ct.copyInto(out, 4)
        return out
    }

    // (3) The vector's frames decode; tampering fails.
    @Test
    fun vectorFrames_decode() {
        val frame = hex("0000001c54623749f5569e27af8f598c61e0be85e0e311e42e20271f489f757b")
        val len = ((frame[0].toInt() and 0xFF) shl 24) or
            ((frame[1].toInt() and 0xFF) shl 16) or
            ((frame[2].toInt() and 0xFF) shl 8) or
            (frame[3].toInt() and 0xFF)
        assertEquals(28, len)
        val (flags, data) = TcpCrypto.openFrame(
            sessionKey(), headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 0,
            frame.copyOfRange(4, 4 + len)
        )!!
        assertEquals(TcpCrypto.FLAG_FINAL, flags)
        assertArrayEquals(payload, data)

        val emptyFrame = hex("000000110655f730879b22e1c9305ece6894f4383f")
        val len1 = ((emptyFrame[0].toInt() and 0xFF) shl 24) or
            ((emptyFrame[1].toInt() and 0xFF) shl 16) or
            ((emptyFrame[2].toInt() and 0xFF) shl 8) or
            (emptyFrame[3].toInt() and 0xFF)
        assertEquals(17, len1)
        val (flags1, data1) = TcpCrypto.openFrame(
            sessionKey(), headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 1,
            emptyFrame.copyOfRange(4, 4 + len1)
        )!!
        assertEquals(TcpCrypto.FLAG_FINAL, flags1)
        assertEquals(0, data1.size)
    }

    @Test
    fun frame_tamperingFails() {
        val sk = sessionKey()
        val ct = TcpCrypto.sealFrame(sk, headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 0, 0, "secret data".toByteArray())
        // Tampered ciphertext byte.
        val broken = ct.copyOf().also { it[2] = (it[2].toInt() xor 0x01).toByte() }
        assertNull(TcpCrypto.openFrame(sk, headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 0, broken))
        // Tampered AAD (header) byte.
        val badAad = headerBytes.copyOf().also { it[10] = (it[10].toInt() xor 0x01).toByte() }
        assertNull(TcpCrypto.openFrame(sk, badAad, TcpCrypto.DIR_SERVER_TO_CLIENT, 0, ct))
        // Wrong counter: the nonce differs, so the tag fails.
        assertNull(TcpCrypto.openFrame(sk, headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 1, ct))
        // Wrong direction likewise fails.
        assertNull(TcpCrypto.openFrame(sk, headerBytes, TcpCrypto.DIR_CLIENT_TO_SERVER, 0, ct))
        // Reserved flag bits set: seal manually with bad flags, open rejects.
        val bad = TcpCrypto.sealFrame(sk, headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 3, 0x02, "x".toByteArray())
        assertNull(TcpCrypto.openFrame(sk, headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 3, bad))
        // Over-long ciphertext rejected without allocating.
        val huge = ByteArray(TcpCrypto.MAX_FRAME_CIPHERTEXT + 1)
        assertNull(TcpCrypto.openFrame(sk, headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 0, huge))
    }

    // (4) Truncated stream, missing FINAL, data after FINAL, wrong length/hash/UTF-8 rejected.
    @Test
    fun assembler_happyPathSingleFinalFrame() {
        val asm = TcpCrypto.FrameAssembler(payload.size.toLong())
        assertTrue(asm.feed(TcpCrypto.FLAG_FINAL, payload, 0))
        assertArrayEquals(payload, asm.finish())
    }

    @Test
    fun assembler_rejectsTruncatedFinal() {
        // FINAL claims everything but carries fewer bytes than total_len.
        val asm = TcpCrypto.FrameAssembler(11)
        try {
            asm.feed(TcpCrypto.FLAG_FINAL, "Hello".toByteArray(), 0)
            fail("expected TcpException for short FINAL")
        } catch (e: TcpCrypto.TcpException) {
            // expected
        }
    }

    @Test
    fun assembler_rejectsMissingFinal() {
        val total = TcpCrypto.MAX_FRAME_DATA.toLong() + 3
        val asm = TcpCrypto.FrameAssembler(total)
        assertFalse(asm.feed(0, ByteArray(TcpCrypto.MAX_FRAME_DATA) { 7 }, 0))
        try {
            asm.finish()
            fail("expected TcpException for missing FINAL")
        } catch (e: TcpCrypto.TcpException) {
            // expected
        }
    }

    @Test
    fun assembler_rejectsShortNonFinalFrame() {
        val asm = TcpCrypto.FrameAssembler(10)
        try {
            asm.feed(0, "short".toByteArray(), 0)
            fail("expected TcpException for short non-final frame")
        } catch (e: TcpCrypto.TcpException) {
            // expected
        }
    }

    @Test
    fun assembler_rejectsDataAfterFinal() {
        val asm = TcpCrypto.FrameAssembler(3)
        assertTrue(asm.feed(TcpCrypto.FLAG_FINAL, "abc".toByteArray(), 0))
        try {
            asm.feed(TcpCrypto.FLAG_FINAL, ByteArray(0), 1)
            fail("expected TcpException for data after FINAL")
        } catch (e: TcpCrypto.TcpException) {
            // expected
        }
    }

    @Test
    fun assembler_rejectsOverflowBeyondTotalLen() {
        val asm = TcpCrypto.FrameAssembler(5)
        try {
            asm.feed(TcpCrypto.FLAG_FINAL, "toolong!".toByteArray(), 0)
            fail("expected TcpException for length mismatch")
        } catch (e: TcpCrypto.TcpException) {
            // expected
        }
    }

    @Test
    fun verifyContent_checks() {
        val data = "hello".toByteArray()
        val sha = TcpCrypto.sha256(data)
        TcpCrypto.verifyContent(data, 5, sha, 0x01)
        try {
            TcpCrypto.verifyContent(data, 6, sha, 0x01)
            fail("expected length mismatch")
        } catch (e: TcpCrypto.TcpException) {
        }
        try {
            TcpCrypto.verifyContent(data, 5, ByteArray(32), 0x01)
            fail("expected hash mismatch")
        } catch (e: TcpCrypto.TcpException) {
        }
        val badUtf8 = byteArrayOf(0xFF.toByte(), 0xFE.toByte())
        val shaBad = TcpCrypto.sha256(badUtf8)
        try {
            TcpCrypto.verifyContent(badUtf8, 2, shaBad, 0x01)
            fail("expected invalid UTF-8")
        } catch (e: TcpCrypto.TcpException) {
        }
        // Non-text inner types skip the UTF-8 check (reserved for later).
        TcpCrypto.verifyContent(badUtf8, 2, shaBad, 0x02)
    }

    @Test
    fun frameSealOpen_roundTrip() {
        val sk = sessionKey()
        val data = "frame payload".toByteArray()
        val ct = TcpCrypto.sealFrame(sk, headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 7, 0, data)
        val (flags, out) = TcpCrypto.openFrame(sk, headerBytes, TcpCrypto.DIR_SERVER_TO_CLIENT, 7, ct)!!
        assertEquals(0.toByte(), flags)
        assertArrayEquals(data, out)
    }
}
