package com.clipcast.protocol

import org.junit.Test
import org.junit.Assert.*
import java.nio.charset.StandardCharsets

class CryptoTest {

    @Test
    fun testVector1_encode() {
        val keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        val key = hexToBytes(keyHex)
        val deviceId = hexToBytes("000102030405060708090a0b0c0d0e0f")
        val nonce = hexToBytes("000102030405060708090a0b")
        val lamport = 1234567890L
        val timestampMs = 1700000000000L
        val payload = "Hello, clipcast!".toByteArray(StandardCharsets.UTF_8)

        val datagram = Crypto.encode(key, deviceId, lamport, timestampMs, payload, nonce)
        assertNotNull("Encoding should succeed", datagram)

        val expectedHex = "43434c500101000102030405060708090a0b0c0d0e0f000102030405060708090a0b4702d61b8c73c0c98d4196007e0c106d82d68734e0333a105408c9a57e0569c26271dd888e5679466764a2bc9c4f767b639625c652"
        val actualHex = Crypto.bytesToHex(datagram!!)
        assertEquals("Encoded datagram should match test vector", expectedHex, actualHex)
    }

    @Test
    fun testVector1_decode() {
        val keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        val key = hexToBytes(keyHex)
        val datagramHex = "43434c500101000102030405060708090a0b0c0d0e0f000102030405060708090a0b4702d61b8c73c0c98d4196007e0c106d82d68734e0333a105408c9a57e0569c26271dd888e5679466764a2bc9c4f767b639625c652"
        val datagram = hexToBytes(datagramHex)

        val decoded = Crypto.decode(key, datagram)
        assertNotNull("Decoding should succeed", decoded)

        assertEquals("Lamport should match", 1234567890L, decoded!!.lamport)
        assertEquals("Timestamp should match", 1700000000000L, decoded.timestampMs)
        assertEquals("Content type should be text", 0x01.toByte(), decoded.contentType)
        assertEquals("Payload should match", "Hello, clipcast!", String(decoded.payload, StandardCharsets.UTF_8))
        assertArrayEquals("Device ID should match", hexToBytes("000102030405060708090a0b0c0d0e0f"), decoded.deviceId)
    }

    @Test
    fun testVector1_roundtrip() {
        val keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        val key = hexToBytes(keyHex)
        val deviceId = hexToBytes("000102030405060708090a0b0c0d0e0f")
        val lamport = 1234567890L
        val timestampMs = 1700000000000L
        val payload = "Hello, clipcast!".toByteArray(StandardCharsets.UTF_8)

        val encoded = Crypto.encode(key, deviceId, lamport, timestampMs, payload)
        assertNotNull(encoded)

        val decoded = Crypto.decode(key, encoded!!)
        assertNotNull(decoded)

        assertEquals(lamport, decoded!!.lamport)
        assertEquals(timestampMs, decoded.timestampMs)
        assertEquals(0x01.toByte(), decoded.contentType)
        assertArrayEquals(payload, decoded.payload)
    }

    @Test
    fun testTamperedDatagram_rejected() {
        val keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        val key = hexToBytes(keyHex)
        val datagramHex = "43434c500101000102030405060708090a0b0c0d0e0f000102030405060708090a0b4702d61b8c73c0c98d4196007e0c106d82d68734e0333a105408c9a57e0569c26271dd888e5679466764a2bc9c4f767b639625c652"
        val datagram = hexToBytes(datagramHex)

        val tampered = datagram.copyOf()
        tampered[tampered.size - 1] = (tampered[tampered.size - 1].toInt() xor 0xFF).toByte()

        val decoded = Crypto.decode(key, tampered)
        assertNull("Tampered datagram should be rejected", decoded)
    }

    @Test
    fun testWrongMagic_rejected() {
        val keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        val key = hexToBytes(keyHex)
        val datagramHex = "43434c500101000102030405060708090a0b0c0d0e0f000102030405060708090a0b4702d61b8c73c0c98d4196007e0c106d82d68734e0333a105408c9a57e0569c26271dd888e5679466764a2bc9c4f767b639625c652"
        val datagram = hexToBytes(datagramHex)

        val wrongMagic = datagram.copyOf()
        wrongMagic[0] = 0xFF.toByte()

        val decoded = Crypto.decode(key, wrongMagic)
        assertNull("Wrong magic should be rejected", decoded)
    }

    @Test
    fun testWrongVersion_rejected() {
        val keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        val key = hexToBytes(keyHex)
        val datagramHex = "43434c500101000102030405060708090a0b0c0d0e0f000102030405060708090a0b4702d61b8c73c0c98d4196007e0c106d82d68734e0333a105408c9a57e0569c26271dd888e5679466764a2bc9c4f767b639625c652"
        val datagram = hexToBytes(datagramHex)

        val wrongVersion = datagram.copyOf()
        wrongVersion[4] = 2

        val decoded = Crypto.decode(key, wrongVersion)
        assertNull("Wrong version should be rejected", decoded)
    }

    @Test
    fun testWrongMsgType_rejected() {
        val keyHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        val key = hexToBytes(keyHex)
        val datagramHex = "43434c500101000102030405060708090a0b0c0d0e0f000102030405060708090a0b4702d61b8c73c0c98d4196007e0c106d82d68734e0333a105408c9a57e0569c26271dd888e5679466764a2bc9c4f767b639625c652"
        val datagram = hexToBytes(datagramHex)

        val wrongType = datagram.copyOf()
        wrongType[5] = 0x02

        val decoded = Crypto.decode(key, wrongType)
        assertNull("Wrong msg_type should be rejected", decoded)
    }

    @Test
    fun testInvalidUtf8_rejected() {
        val key = ByteArray(32) { it.toByte() }
        val deviceId = Crypto.generateDeviceId()
        val payload = byteArrayOf(0xFF.toByte(), 0xFE.toByte(), 0x41.toByte())

        val datagram = Crypto.encode(key, deviceId, 1, System.currentTimeMillis(), payload)
        assertNotNull(datagram)

        // Correct key but malformed UTF-8 payload must be dropped.
        val decoded = Crypto.decode(key, datagram!!)
        assertNull("Invalid UTF-8 should be rejected", decoded)

        // Wrong key must also fail tag verification.
        val wrongKey = ByteArray(32) { (it + 1).toByte() }
        val decodedWrongKey = Crypto.decode(wrongKey, datagram)
        assertNull("Invalid key should reject", decodedWrongKey)
    }

    @Test
    fun testOversizePayload_rejected() {
        val key = Crypto.generateDeviceId()
        val deviceId = Crypto.generateDeviceId()
        val oversizePayload = ByteArray(1500) { 0x41.toByte() }

        val datagram = Crypto.encode(key, deviceId, 1, System.currentTimeMillis(), oversizePayload)
        assertNull("Oversize payload should be rejected at encode", datagram)
    }

    @Test
    fun testMaxSizePayload_accepted() {
        val key = Crypto.generateDeviceId()
        val deviceId = Crypto.generateDeviceId()
        val maxPayload = ByteArray(1200) { 0x41.toByte() }

        val datagram = Crypto.encode(key, deviceId, 1, System.currentTimeMillis(), maxPayload)
        assertNotNull("Max size payload should be accepted", datagram)
        assertTrue("Datagram should not exceed 1400 bytes", datagram!!.size <= 1400)
    }

    @Test
    fun testKeyValidation() {
        val validKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        assertTrue("Valid base64 32-byte key should pass", Crypto.validateKey(validKey))

        // Missing padding is tolerated: same 32 bytes.
        val unpaddedKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        assertTrue("Unpadded 32-byte key should pass", Crypto.validateKey(unpaddedKey))

        // Genuinely short: 31 bytes.
        val shortKey = java.util.Base64.getEncoder().encodeToString(ByteArray(31) { it.toByte() })
        assertFalse("31-byte key should fail", Crypto.validateKey(shortKey))

        val longKey = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8AAA=="
        assertFalse("Long key should fail", Crypto.validateKey(longKey))

        val invalidBase64 = "!!!INVALID!!!"
        assertFalse("Invalid base64 should fail", Crypto.validateKey(invalidBase64))
    }

    @Test
    fun testDeviceIdGeneration() {
        val id1 = Crypto.generateDeviceId()
        val id2 = Crypto.generateDeviceId()
        assertEquals(16, id1.size)
        assertEquals(16, id2.size)
        assertFalse("Device IDs should be unique", java.util.Arrays.equals(id1, id2))
    }

    @Test
    fun testNonceGeneration() {
        val nonce1 = Crypto.generateNonce()
        val nonce2 = Crypto.generateNonce()
        assertEquals(12, nonce1.size)
        assertEquals(12, nonce2.size)
        assertFalse("Nonces should be unique", java.util.Arrays.equals(nonce1, nonce2))
    }

    private fun hexToBytes(hex: String): ByteArray {
        return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }
}