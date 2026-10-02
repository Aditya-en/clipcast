package com.clipcast.ui

import android.os.Handler
import android.os.Looper

/**
 * Simple in-process holder for service state (replaces the deprecated
 * LocalBroadcastManager). The service publishes snapshots from any thread;
 * delivery to listeners always happens on the main thread. The latest
 * snapshot is cached, so rotation and process-death restarts re-render
 * immediately, and listeners only get updates while registered (visible).
 */
object ServiceStateHolder {

    /** Everything the UI needs to render, in one snapshot. */
    data class Snapshot(
        val running: Boolean = false,
        /** False when no valid key is stored. */
        val configured: Boolean = false,
        val wifiConnected: Boolean = false,
        /** Device's local IPv4 address, or null when unknown. */
        val localIp: String? = null,
        /** UDP bind failure reason, or null. */
        val udpError: String? = null,
        /** TCP bind failure reason, or null. */
        val tcpError: String? = null,
        val lastRxTime: Long = 0,
        val lastRxLen: Int = 0,
        val lastTxTime: Long = 0,
        val lastTxLen: Int = 0,
        /** Last fetch outcome in plain service wording, or "none". */
        val lastTransfer: String = "none",
        /** Outcome of the most recent send (survives rotation). */
        val lastSendOk: Boolean = true,
        /** "too_large", "failed", or null when the last send succeeded. */
        val lastSendError: String? = null
    )

    /** One send result event (button feedback, hints). */
    data class SendEvent(
        val success: Boolean,
        /** Bytes sent (char length as before, display only). */
        val length: Int,
        val quiet: Boolean,
        val tooLarge: Boolean
    )

    fun interface StateListener {
        fun onState(snapshot: Snapshot)
    }

    fun interface SendListener {
        fun onSend(event: SendEvent)
    }

    private val mainHandler = Handler(Looper.getMainLooper())
    private val stateListeners = mutableSetOf<StateListener>()
    private val sendListeners = mutableSetOf<SendListener>()

    @Volatile
    var last: Snapshot = Snapshot()
        private set

    /** May be called from any thread; listeners run on the main thread. */
    fun publish(snapshot: Snapshot) {
        last = snapshot
        if (Looper.myLooper() == Looper.getMainLooper()) {
            dispatchState(snapshot)
        } else {
            mainHandler.post { dispatchState(snapshot) }
        }
    }

    /** May be called from any thread; listeners run on the main thread. */
    fun emitSend(event: SendEvent) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            dispatchSend(event)
        } else {
            mainHandler.post { dispatchSend(event) }
        }
    }

    fun addStateListener(listener: StateListener) {
        stateListeners.add(listener)
        // Immediate catch-up so a fresh/rotated UI renders without waiting.
        listener.onState(last)
    }

    fun removeStateListener(listener: StateListener) {
        stateListeners.remove(listener)
    }

    fun addSendListener(listener: SendListener) {
        sendListeners.add(listener)
    }

    fun removeSendListener(listener: SendListener) {
        sendListeners.remove(listener)
    }

    private fun dispatchState(snapshot: Snapshot) {
        // Snapshot the set: listeners may unregister mid-dispatch.
        for (listener in stateListeners.toList()) {
            listener.onState(snapshot)
        }
    }

    private fun dispatchSend(event: SendEvent) {
        for (listener in sendListeners.toList()) {
            listener.onSend(event)
        }
    }
}
