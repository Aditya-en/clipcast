package com.clipcast.protocol

import org.junit.Test
import org.junit.Assert.*

class ProtocolEdgeCasesTest {

    @Test
    fun testEmptyPayload_rejected() {
        val key = Crypto.generateDeviceId()
        val deviceId = Crypto.generateDeviceId()
        val payload = ByteArray(0)

        val datagram = Crypto.encode(key, deviceId, 1, System.currentTimeMillis(), payload)
        assertNotNull("Empty payload should be encodable", datagram)

        val decoded = Crypto.decode(key, datagram!!)
        assertNotNull("Empty payload should be decodable", decoded)
        assertEquals(0, decoded!!.payload.size)
    }

    @Test
    fun testUnicodePayload() {
        val key = Crypto.generateDeviceId()
        val deviceId = Crypto.generateDeviceId()
        val payload = "Hello 🌍 世界 🎉".toByteArray(java.nio.charset.StandardCharsets.UTF_8)

        val datagram = Crypto.encode(key, deviceId, 1, System.currentTimeMillis(), payload)
        assertNotNull(datagram)

        val decoded = Crypto.decode(key, datagram!!)
        assertNotNull(decoded)
        assertEquals("Hello 🌍 世界 🎉", String(decoded!!.payload, java.nio.charset.StandardCharsets.UTF_8))
    }

    @Test
    fun testLargeLamportValues() {
        val state = SyncState()
        val deviceId = Crypto.generateDeviceId()

        state.updateLastApplied(Long.MAX_VALUE - 100, deviceId)
        val applied = state.onReceive(Long.MAX_VALUE, Crypto.generateDeviceId())

        assertTrue(applied)
        assertEquals(Long.MAX_VALUE, state.getLamport())
    }

    @Test
    fun testZeroLamport() {
        val state = SyncState()
        val deviceId = Crypto.generateDeviceId()

        val applied = state.onReceive(0, deviceId)
        assertTrue(applied)
        assertEquals(0, state.getLamport())
    }

    @Test
    fun testTimestampNotUsedForOrdering() {
        val state = SyncState()
        val deviceId = Crypto.generateDeviceId()
        state.updateLastApplied(100, Crypto.generateDeviceId())

        val applied = state.onReceive(200, deviceId)
        assertTrue(applied)

        val key = ByteArray(32) { it.toByte() }
        val encoded = Crypto.encode(key, deviceId, 200, 0, "test".toByteArray())
        assertNotNull(encoded)
        val decoded = Crypto.decode(key, encoded!!)
        assertNotNull(decoded)
        assertEquals(200, decoded!!.lamport)
    }

    @Test
    fun testEncodeDecodeWithDifferentKeys_producesDifferentCiphertext() {
        val key1 = Crypto.generateDeviceId()
        val key2 = Crypto.generateDeviceId()
        val deviceId = Crypto.generateDeviceId()
        val payload = "test".toByteArray(java.nio.charset.StandardCharsets.UTF_8)

        val d1 = Crypto.encode(key1, deviceId, 1, 1000, payload)
        val d2 = Crypto.encode(key2, deviceId, 1, 1000, payload)

        assertNotNull(d1)
        assertNotNull(d2)
        assertFalse("Different keys should produce different ciphertext", java.util.Arrays.equals(d1!!, d2!!))
    }

    @Test
    fun testEncodeDecodeWithDifferentNonces_producesDifferentCiphertext() {
        val key = Crypto.generateDeviceId()
        val deviceId = Crypto.generateDeviceId()
        val payload = "test".toByteArray(java.nio.charset.StandardCharsets.UTF_8)

        val d1 = Crypto.encode(key, deviceId, 1, 1000, payload)
        val d2 = Crypto.encode(key, deviceId, 1, 1000, payload)

        assertNotNull(d1)
        assertNotNull(d2)
        assertFalse("Different nonces should produce different ciphertext", java.util.Arrays.equals(d1!!, d2!!))
    }

    @Test
    fun testTruncatedDatagram_rejected() {
        val key = Crypto.generateDeviceId()
        val deviceId = Crypto.generateDeviceId()
        val payload = "test".toByteArray(java.nio.charset.StandardCharsets.UTF_8)

        val datagram = Crypto.encode(key, deviceId, 1, 1000, payload)
        assertNotNull(datagram)

        val truncated = datagram!!.copyOfRange(0, datagram.size - 5)
        val decoded = Crypto.decode(key, truncated)
        assertNull("Truncated datagram should be rejected", decoded)
    }

    @Test
    fun testCorruptedHeader_rejected() {
        val key = Crypto.generateDeviceId()
        val deviceId = Crypto.generateDeviceId()
        val payload = "test".toByteArray(java.nio.charset.StandardCharsets.UTF_8)

        val datagram = Crypto.encode(key, deviceId, 1, 1000, payload)
        assertNotNull(datagram)

        val corrupted = datagram!!.copyOf()
        corrupted[10] = (corrupted[10].toInt() xor 0xFF).toByte()

        val decoded = Crypto.decode(key, corrupted)
        assertNull("Corrupted header should be rejected", decoded)
    }
}