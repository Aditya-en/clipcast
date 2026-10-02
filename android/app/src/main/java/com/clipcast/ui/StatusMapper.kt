package com.clipcast.ui

/**
 * Pure mapping from service snapshots to main-screen state (no Android
 * imports, fully unit-tested). Plain language only; technical detail stays
 * in secondary lines. Never carries clipboard content.
 */
object StatusMapper {

    /** Status card state: always a text label plus a dot color, never color alone. */
    sealed class MainStatus {
        /** Sync running. [ipLine] is "IP · Wi-Fi connected" or "Wi-Fi connected". */
        data class On(val ipLine: String?) : MainStatus()
        object Off : MainStatus()
        object WaitingWifi : MainStatus()
        object NeedsSetup : MainStatus()
        /** One-line reason, e.g. port already in use. */
        data class Error(val reason: String) : MainStatus()
    }

    /** One Activity row (sizes and times only, never content). */
    data class ActivityRow(
        val hasData: Boolean,
        val timeMs: Long,
        val bytes: Long,
        /** Check (true) or cross (false) glyph. */
        val ok: Boolean,
        /** Plain-words second line, or null. */
        val detail: String? = null,
        /** Row describes an image ("Image · 2.4 MB"), not text. */
        val isImage: Boolean = false
    )

    data class MainScreen(
        val status: MainStatus,
        /** Status card is a tap target (needs-setup, error). */
        val statusTappable: Boolean,
        val received: ActivityRow?,
        val sent: ActivityRow?,
        val empty: Boolean,
        val sendEnabled: Boolean,
        /** Reason line under the send button, or null. */
        val sendReason: String?
    )

    fun map(s: ServiceStateHolder.Snapshot): MainScreen {
        val status = mapStatus(s)
        val received = mapReceived(s)
        val sent = mapSent(s)
        val empty = s.lastRxTime <= 0 && s.lastTxTime <= 0
        val sendEnabled = s.configured && s.running
        val sendReason = when {
            !s.configured -> "Add your key in Settings to send"
            !s.running -> "Turn sync on to send"
            else -> null
        }
        return MainScreen(
            status = status,
            statusTappable = status is MainStatus.NeedsSetup || status is MainStatus.Error,
            received = received,
            sent = sent,
            empty = empty,
            sendEnabled = sendEnabled,
            sendReason = sendReason
        )
    }

    fun mapStatus(s: ServiceStateHolder.Snapshot): MainStatus {
        if (!s.configured) return MainStatus.NeedsSetup
        if (!s.running) {
            if (s.udpError != null) return MainStatus.Error(plainPortReason(s.udpError))
            return MainStatus.Off
        }
        if (s.tcpError != null) return MainStatus.Error(plainPortReason(s.tcpError))
        if (!s.wifiConnected) return MainStatus.WaitingWifi
        val ipLine = if (s.localIp != null) "${s.localIp} · Wi-Fi connected" else "Wi-Fi connected"
        return MainStatus.On(ipLine)
    }

    private fun plainPortReason(technical: String): String {
        // "UDP port 47474 in use" -> "Port 47474 is already in use".
        val port = Regex("(\\d{2,5})").find(technical)?.groupValues?.get(1)
        if (technical.contains("in use", ignoreCase = true) && port != null) {
            return "Port $port is already in use"
        }
        return technical
    }

    private fun mapReceived(s: ServiceStateHolder.Snapshot): ActivityRow? {
        if (s.lastRxTime <= 0) return null
        return ActivityRow(
            hasData = true,
            timeMs = s.lastRxTime,
            bytes = s.lastRxLen.toLong(),
            ok = true,
            detail = receiveFailureDetail(s.lastTransfer),
            isImage = s.lastRxIsImage
        )
    }

    private fun mapSent(s: ServiceStateHolder.Snapshot): ActivityRow? {
        if (s.lastTxTime <= 0) return null
        return ActivityRow(
            hasData = true,
            timeMs = s.lastTxTime,
            bytes = s.lastTxLen.toLong(),
            ok = s.lastSendOk,
            detail = when (s.lastSendError) {
                "too_large" -> "Too large to send"
                "failed" -> "Couldn't send"
                else -> null
            },
            isImage = s.lastTxIsImage
        )
    }

    /**
     * A failed fetch says why in plain words on the row's second line.
     * Service wording in, plain words out.
     */
    fun receiveFailureDetail(lastTransfer: String): String? {
        if (lastTransfer.contains("sync limit", ignoreCase = true)) {
            return "Too large to sync"
        }
        if (lastTransfer.contains("too large", ignoreCase = true)) {
            return "Too large for this phone's clipboard"
        }
        if (lastTransfer.startsWith("Transfer failed", ignoreCase = true)) {
            return "Transfer failed"
        }
        return null
    }
}
