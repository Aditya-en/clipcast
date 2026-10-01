package com.clipcast.util

import android.content.Context
import android.content.SharedPreferences
import com.clipcast.protocol.Crypto

class Preferences(private val prefs: SharedPreferences) {
    companion object {
        private const val PREFS_NAME = "clipcast_prefs"
        private const val KEY_ENCRYPTION_KEY = "encryption_key"
        private const val KEY_DEVICE_ID = "device_id"
        private const val KEY_PORT = "port"
        private const val KEY_AUTOSTART = "autostart"
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

    fun isConfigured(): Boolean {
        return encryptionKey != null && Crypto.validateKey(encryptionKey!!)
    }

    fun getKeyBytes(): ByteArray? {
        return encryptionKey?.let { Crypto.decodeKey(it) }
    }
}