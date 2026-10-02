package com.clipcast.protocol

import org.junit.Test
import org.junit.Assert.*
import java.util.Arrays

class SyncStateTest {

    @Test
    fun testLocalSendIncrementsLamport() {
        val state = SyncState()
        val ourId = Crypto.generateDeviceId()
        val now = System.currentTimeMillis()

        val lamport1 = state.onLocalSend(now, ourId)
        val lamport2 = state.onLocalSend(now, ourId)

        assertTrue("Lamport should increment", lamport2 > lamport1)
        assertEquals("Last applied should match", lamport2, state.getLastApplied().first)
        assertTrue(Arrays.equals(ourId, state.getLastApplied().second))
    }

    @Test
    fun testLocalSendUsesMaxOfLamportAndNow() {
        val state = SyncState()
        val ourId = Crypto.generateDeviceId()
        state.onLocalSend(1000, ourId)
        state.onLocalSend(1000, ourId)

        val highNow = 5000L
        val lamport = state.onLocalSend(highNow, ourId)

        assertEquals("Lamport should be max(previous, now) + 1", highNow + 1, lamport)
    }

    @Test
    fun testReceiveDuplicateTuple_ignored() {
        // Echo of our own broadcast arrives with identical (lamport, deviceId).
        // The service also filters deviceId == ours before reaching SyncState.
        val state = SyncState()
        val deviceId = Crypto.generateDeviceId()
        state.updateLastApplied(100, deviceId)

        val applied = state.onReceive(100, deviceId)

        assertFalse("Duplicate tuple should be ignored", applied)
        assertEquals("Lamport should not change", 0, state.getLamport())
    }

    @Test
    fun testReceiveHigherLamport_applied() {
        val state = SyncState()
        val ourDeviceId = Crypto.generateDeviceId()
        val theirDeviceId = Crypto.generateDeviceId()
        state.updateLastApplied(100, ourDeviceId)

        val applied = state.onReceive(200, theirDeviceId)

        assertTrue("Higher lamport should be applied", applied)
        assertEquals("Lamport should update", 200, state.getLamport())
        assertEquals("Last applied should update", 200, state.getLastApplied().first)
        assertTrue("Last applied device ID should update", Arrays.equals(theirDeviceId, state.getLastApplied().second))
    }

    @Test
    fun testReceiveLowerLamport_rejected() {
        val state = SyncState()
        val ourDeviceId = Crypto.generateDeviceId()
        val theirDeviceId = Crypto.generateDeviceId()
        state.updateLastApplied(200, ourDeviceId)

        val applied = state.onReceive(100, theirDeviceId)

        assertFalse("Lower lamport should be rejected", applied)
        assertEquals("Lamport should not change", 0, state.getLamport())
    }

    @Test
    fun testReceiveSameLamport_differentDeviceId_tiebreak() {
        val state = SyncState()
        val ourDeviceId = ByteArray(16) { 0x00.toByte() }
        ourDeviceId[15] = 0x01.toByte()
        val theirDeviceId = ByteArray(16) { 0x00.toByte() }
        theirDeviceId[15] = 0x02.toByte()
        state.updateLastApplied(100, ourDeviceId)

        val applied = state.onReceive(100, theirDeviceId)

        assertTrue("Higher device ID should win tiebreak", applied)
        assertEquals(100, state.getLamport())
    }

    @Test
    fun testReceiveSameLamport_lowerDeviceId_rejected() {
        val state = SyncState()
        val ourDeviceId = ByteArray(16) { 0x00.toByte() }
        ourDeviceId[15] = 0x02.toByte()
        val theirDeviceId = ByteArray(16) { 0x00.toByte() }
        theirDeviceId[15] = 0x01.toByte()
        state.updateLastApplied(100, ourDeviceId)

        val applied = state.onReceive(100, theirDeviceId)

        assertFalse("Lower device ID should lose tiebreak", applied)
    }

    @Test
    fun testReceiveUpdatesLamportToMax() {
        val state = SyncState()
        val ourDeviceId = Crypto.generateDeviceId()
        val theirDeviceId = Crypto.generateDeviceId()
        state.updateLastApplied(100, ourDeviceId)
        state.onLocalSend(1000, ourDeviceId)
        assertEquals(1001, state.getLamport())

        // Remote 500 < local 1001 must be rejected...
        assertFalse(state.onReceive(500, theirDeviceId))
        assertEquals(1001, state.getLamport())

        // ...while a newer remote advances the clock.
        assertTrue(state.onReceive(1500, theirDeviceId))
        assertEquals("Lamport should be max(local, remote)", 1500, state.getLamport())
    }

    @Test
    fun testMultipleReceivesOrdering() {
        val state = SyncState()
        val deviceA = byteArrayOf(1.toByte()) + ByteArray(15)
        val deviceB = byteArrayOf(2.toByte()) + ByteArray(15)
        val deviceC = byteArrayOf(3.toByte()) + ByteArray(15)

        state.updateLastApplied(0, Crypto.generateDeviceId())

        assertTrue(state.onReceive(10, deviceA))
        assertTrue(state.onReceive(20, deviceB))
        // Lower than 20 -> rejected
        assertFalse(state.onReceive(15, deviceC))
        assertFalse(state.onReceive(15, deviceC))

        assertEquals(20, state.getLamport())
        assertEquals(20, state.getLastApplied().first)
        assertTrue(Arrays.equals(deviceB, state.getLastApplied().second))
    }

    @Test
    fun testReceiveDuplicate_ignored() {
        val state = SyncState()
        val deviceId = Crypto.generateDeviceId()
        state.updateLastApplied(100, Crypto.generateDeviceId())

        assertTrue(state.onReceive(200, deviceId))
        assertFalse("Duplicate should be ignored", state.onReceive(200, deviceId))
    }
}
