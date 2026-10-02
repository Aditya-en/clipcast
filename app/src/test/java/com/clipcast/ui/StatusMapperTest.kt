package com.clipcast.ui

import org.junit.Assert.*
import org.junit.Test

class StatusMapperTest {

    private fun base() = ServiceStateHolder.Snapshot(
        running = true,
        configured = true,
        wifiConnected = true,
        localIp = "192.168.1.23"
    )

    @Test
    fun on_whenRunningWithWifi() {
        val st = StatusMapper.mapStatus(base())
        assertTrue(st is StatusMapper.MainStatus.On)
        assertEquals("192.168.1.23 · Wi-Fi connected", (st as StatusMapper.MainStatus.On).ipLine)
    }

    @Test
    fun on_withoutIp_stillOn() {
        val st = StatusMapper.mapStatus(base().copy(localIp = null))
        assertTrue(st is StatusMapper.MainStatus.On)
        assertEquals("Wi-Fi connected", (st as StatusMapper.MainStatus.On).ipLine)
    }

    @Test
    fun off_whenStopped() {
        assertTrue(StatusMapper.mapStatus(base().copy(running = false)) is StatusMapper.MainStatus.Off)
    }

    @Test
    fun waiting_whenNoWifi() {
        assertTrue(StatusMapper.mapStatus(base().copy(wifiConnected = false)) is StatusMapper.MainStatus.WaitingWifi)
    }

    @Test
    fun needsSetup_beatsEverything() {
        val s = base().copy(configured = false, running = false)
        assertTrue(StatusMapper.mapStatus(s) is StatusMapper.MainStatus.NeedsSetup)
    }

    @Test
    fun error_onUdpBindFailure() {
        val st = StatusMapper.mapStatus(
            base().copy(running = false, udpError = "UDP port 47474 in use")
        )
        assertTrue(st is StatusMapper.MainStatus.Error)
        assertEquals("Port 47474 is already in use", (st as StatusMapper.MainStatus.Error).reason)
    }

    @Test
    fun error_onTcpBindFailureWhileRunning() {
        val st = StatusMapper.mapStatus(base().copy(tcpError = "TCP port 47475 in use"))
        assertTrue(st is StatusMapper.MainStatus.Error)
        assertEquals("Port 47475 is already in use", (st as StatusMapper.MainStatus.Error).reason)
    }

    @Test
    fun statusCard_tappableOnlyForSetupAndError() {
        assertTrue(StatusMapper.map(base().copy(configured = false)).statusTappable)
        assertTrue(
            StatusMapper.map(base().copy(tcpError = "TCP port 47475 in use")).statusTappable
        )
        assertFalse(StatusMapper.map(base()).statusTappable)
        assertFalse(StatusMapper.map(base().copy(running = false)).statusTappable)
    }

    @Test
    fun emptyState_whenNothingEver() {
        val screen = StatusMapper.map(base().copy(lastRxTime = 0, lastTxTime = 0))
        assertTrue(screen.empty)
        assertNull(screen.received)
        assertNull(screen.sent)
    }

    @Test
    fun rows_carryTimeSizeAndOutcome() {
        val screen = StatusMapper.map(
            base().copy(lastRxTime = 1000, lastRxLen = 4200, lastTxTime = 2000, lastTxLen = 812)
        )
        assertFalse(screen.empty)
        assertEquals(StatusMapper.ActivityRow(true, 1000, 4200, true, null), screen.received)
        assertEquals(StatusMapper.ActivityRow(true, 2000, 812, true, null), screen.sent)
    }

    @Test
    fun receivedRow_failedTransferSaysWhy() {
        val over = StatusMapper.map(
            base().copy(
                lastRxTime = 1000, lastRxLen = 100,
                lastTransfer = "Text too large for the Android clipboard (600000 bytes, max 524288)"
            )
        )
        assertEquals("Too large for this phone's clipboard", over.received!!.detail)

        val failed = StatusMapper.map(
            base().copy(
                lastRxTime = 1000, lastRxLen = 100,
                lastTransfer = "Transfer failed (timeout)"
            )
        )
        assertEquals("Transfer failed", failed.received!!.detail)

        val ok = StatusMapper.map(
            base().copy(lastRxTime = 1000, lastRxLen = 100, lastTransfer = "Received 100 bytes")
        )
        assertNull(ok.received!!.detail)
    }

    @Test
    fun sentRow_failedSendSaysWhy() {
        val tooLarge = StatusMapper.map(
            base().copy(lastTxTime = 1000, lastTxLen = 10, lastSendOk = false, lastSendError = "too_large")
        )
        assertFalse(tooLarge.sent!!.ok)
        assertEquals("Too large to send", tooLarge.sent!!.detail)

        val failed = StatusMapper.map(
            base().copy(lastTxTime = 1000, lastTxLen = 10, lastSendOk = false, lastSendError = "failed")
        )
        assertEquals("Couldn't send", failed.sent!!.detail)
    }

    @Test
    fun sendButton_disabledWithReason() {
        val noKey = StatusMapper.map(base().copy(configured = false))
        assertFalse(noKey.sendEnabled)
        assertEquals("Add your key in Settings to send", noKey.sendReason)

        val off = StatusMapper.map(base().copy(running = false))
        assertFalse(off.sendEnabled)
        assertEquals("Turn sync on to send", off.sendReason)

        val ready = StatusMapper.map(base())
        assertTrue(ready.sendEnabled)
        assertNull(ready.sendReason)
    }
}
