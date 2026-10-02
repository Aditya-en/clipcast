package com.clipcast.util

import android.content.Context
import android.content.SharedPreferences
import com.clipcast.protocol.Crypto
import com.clipcast.protocol.LargeTextLimits

class Preferences(private val prefs: SharedPreferences) {
    companion object {
        private const val PREFS_NAME = "clipcast_prefs"
        private const val KEY_ENCRYPTION_KEY = "encryption_key"
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_PORT = "port"
        private const val KEY_AUTOSTART = "autostart"
        private const val KEY_TCP_PORT = "tcp_port"
        private const val KEY_MAX_APPLY_BYTES = "max_apply_bytes"
        private const val KEY_ASKED_NOTIFICATIONS = "asked_notifications"
        private const val KEY_HINT_NOTIF_DISMISSED = "hint_notif_dismissed"
        private const val KEY_HINT_BATTERY_DISMISSED = "hint_battery_dismissed"
        private const val DEFAULT_PORT = 47474

        fun getInstance(context: Context): Preferences {
            return Preferences(context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE))
        }
    }

    var encryptionKey: String?
        get() = prefs.getString(KEY_ENCRYPTION_KEY, null)
        set(value) {
            prefs.edit().putString(KEY_ENCRYPTION_KEY, value).apply()
        }

    var deviceId: ByteArray
        get() {
            val str = prefs.getString(KEY_DEVICE_ID, null)
            return if (str != null) {
                java.util.Base64.getDecoder().decode(str)
            } else {
                val newId = Crypto.generateDeviceId()
                deviceId = newId
                newId
            }
        }
        set(value) {
            prefs.edit().putString(KEY_DEVICE_ID, java.util.Base64.getEncoder().withoutPadding().encodeToString(value)).apply()
        }

    var port: Int
        get() = prefs.getInt(KEY_PORT, DEFAULT_PORT)
        set(value) {
            prefs.edit().putInt(KEY_PORT, value).apply()
        }

    var autostart: Boolean
        get() = prefs.getBoolean(KEY_AUTOSTART, false)
        set(value) {
            prefs.edit().putBoolean(KEY_AUTOSTART, value).apply()
        }

    /**
     * TCP listener port for the large-text side channel (default 47475).
     * The peer learns it from our UDP announces; the firewall on the desktop
     * side must allow inbound TCP to the daemon's own tcp_port.
     */
    var tcpPort: Int
        get() = prefs.getInt(KEY_TCP_PORT, LargeTextLimits.DEFAULT_TCP_PORT)
        set(value) {
            prefs.edit().putInt(KEY_TCP_PORT, value).apply()
        }

    /**
     * Max text we will apply to the clipboard from a TCP fetch (default
     * 512 KiB). setPrimaryClip goes through Binder and fails near 1 MB, so
     * this is hard-capped at 900 KB.
     */
    var maxApplyBytes: Int
        get() = prefs.getInt(KEY_MAX_APPLY_BYTES, LargeTextLimits.DEFAULT_MAX_APPLY_BYTES)
            .coerceIn(0, LargeTextLimits.MAX_APPLY_HARD_CAP)
        set(value) {
            prefs.edit()
                .putInt(KEY_MAX_APPLY_BYTES, value.coerceIn(0, LargeTextLimits.MAX_APPLY_HARD_CAP))
                .apply()
        }

    fun isConfigured(): Boolean {
        return encryptionKey != null && Crypto.validateKey(encryptionKey!!)
    }

    /** True once the notification permission dialog has been shown. */
    var askedNotifications: Boolean
        get() = prefs.getBoolean(KEY_ASKED_NOTIFICATIONS, false)
        set(value) {
            prefs.edit().putBoolean(KEY_ASKED_NOTIFICATIONS, value).apply()
        }

    /** Dismissible one-at-a-time hint flags. */
    var hintNotifDismissed: Boolean
        get() = prefs.getBoolean(KEY_HINT_NOTIF_DISMISSED, false)
        set(value) {
            prefs.edit().putBoolean(KEY_HINT_NOTIF_DISMISSED, value).apply()
        }

    var hintBatteryDismissed: Boolean
        get() = prefs.getBoolean(KEY_HINT_BATTERY_DISMISSED, false)
        set(value) {
            prefs.edit().putBoolean(KEY_HINT_BATTERY_DISMISSED, value).apply()
        }

    fun getKeyBytes(): ByteArray? {
        return encryptionKey?.let { Crypto.decodeKey(it) }
    }
}