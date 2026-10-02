package com.clipcast.service

import org.junit.Assert.*
import org.junit.Test

/**
 * (6) Pending-transfer eviction, TTL, and fetch-count limit.
 * Mirrors the daemon's transfer::tests.
 */
class TransferStoreTest {

    private fun store(
        ttlMs: Long = 120_000,
        maxFetches: Int = 16,
        memCap: Long = 32L * 1024 * 1024
    ) = TransferStore(ttlMs, maxFetches, memCap)

    private fun id(n: Byte): ByteArray = ByteArray(16) { n }

    @Test
    fun insertAndServe_roundTrip() {
        val s = store()
        val sha = s.insert(id(1), "hello large".toByteArray())
        assertArrayEquals(com.clipcast.protocol.TcpCrypto.sha256("hello large".toByteArray()), sha)
        val (data, gotSha) = s.serve(id(1))!!
        assertArrayEquals("hello large".toByteArray(), data)
        assertArrayEquals(sha, gotSha)
        assertEquals(1, s.fetchCount(id(1)))
    }

    @Test
    fun unknownId_servesNothing() {
        val s = store()
        s.insert(id(1), "x".toByteArray())
        assertNull(s.serve(id(2)))
    }

    @Test
    fun keepsOnlyNewestFour_evictOldestFirst() {
        val s = store()
        for (n in 0..5) s.insert(id(n.toByte()), ByteArray(10) { n.toByte() })
        assertEquals(4, s.size())
        assertNull(s.serve(id(0)))
        assertNull(s.serve(id(1)))
        assertNotNull(s.serve(id(2)))
        assertNotNull(s.serve(id(5)))
    }

    @Test
    fun globalMemoryCap_evictsOldest() {
        val s = store(memCap = 100)
        s.insert(id(1), ByteArray(60) { 1 })
        s.insert(id(2), ByteArray(60) { 2 })
        // 120 bytes buffered against a 100-byte cap: the oldest must go.
        assertNull(s.serve(id(1)))
        assertNotNull(s.serve(id(2)))
        assertTrue(s.memoryUsed() <= 100)
    }

    @Test
    fun ttlExpiry_stopsServing() {
        val s = store(ttlMs = 0)
        s.insert(id(1), "ephemeral".toByteArray())
        assertNull(s.serve(id(1)))
        assertEquals(0, s.size())
    }

    @Test
    fun perTransferFetchBudget_enforced() {
        val s = store(maxFetches = 2)
        s.insert(id(9), "twice".toByteArray())
        assertNotNull(s.serve(id(9)))
        assertNotNull(s.serve(id(9)))
        assertNull(s.serve(id(9)))
    }

    @Test
    fun transferMayBeFetchedByMultiplePeers() {
        val s = store()
        s.insert(id(3), "shared".toByteArray())
        repeat(5) { assertNotNull(s.serve(id(3))) }
        assertEquals(5, s.fetchCount(id(3)))
    }
}
