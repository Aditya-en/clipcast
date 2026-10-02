package com.clipcast.ui

import com.clipcast.protocol.Crypto
import com.clipcast.protocol.LargeTextLimits
import java.security.MessageDigest

/**
 * Pure settings validation (no Android imports, fully unit-tested).
 * Invalid input never overwrites the stored value: callers save only when
 * these return success.
 */
object SettingsValidation {

    /** Max-pasted-text presets in bytes (discrete SeekBar positions). */
    val MAX_APPLY_PRESETS = intArrayOf(
        64 * 1024,
        256 * 1024,
        512 * 1024,
        900 * 1024
    )

    sealed class KeyResult {
        object Valid : KeyResult()
        data class Invalid(val reason: String) : KeyResult()
    }

    /** Live key check: trims whitespace/newlines, then base64 + 32 bytes. */
    fun validateKey(raw: String?): KeyResult {
        val trimmed = (raw ?: "").trim { it <= ' ' }
        if (trimmed.isEmpty()) return KeyResult.Invalid("Enter your key")
        val bytes = try {
            Crypto.decodeKey(trimmed)
        } catch (e: IllegalArgumentException) {
            return KeyResult.Invalid("Not valid base64")
        } catch (e: Exception) {
            return KeyResult.Invalid("Not valid base64")
        }
        if (bytes.size != 32) {
            return KeyResult.Invalid("Key must decode to 32 bytes (got ${bytes.size})")
        }
        return KeyResult.Valid
    }

    /** Canonical stored form: surrounding whitespace/newlines stripped. */
    fun canonicalKey(raw: String?): String = (raw ?: "").trim { it <= ' ' }

    sealed class PortResult {
        data class Valid(val port: Int) : PortResult()
        data class Invalid(val reason: String) : PortResult()
    }

    /** Ports live in 1024-65535. */
    fun validatePort(raw: String?): PortResult {
        val trimmed = (raw ?: "").trim()
        val port = trimmed.toIntOrNull()
            ?: return PortResult.Invalid("Enter a number 1024–65535")
        if (port < 1024 || port > 65535) {
            return PortResult.Invalid("Enter a number 1024–65535")
        }
        return PortResult.Valid(port)
    }

    /** UDP and TCP ports must differ. */
    fun portsDiffer(udp: Int, tcp: Int): Boolean = udp != tcp

    /**
     * Key fingerprint for comparing with the desktop: first 3 bytes of
     * SHA-256("clipcast key fingerprint" || key), as "a3 f1 09".
     * Shown only when the desktop `clipcast doctor` prints the same line;
     * until then the row stays hidden (SHOW_KEY_FINGERPRINT = false).
     */
    const val SHOW_KEY_FINGERPRINT = false

    fun keyFingerprint(key: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("clipcast key fingerprint".toByteArray(Charsets.US_ASCII))
        digest.update(key)
        val hash = digest.digest()
        return "%02x %02x %02x".format(hash[0], hash[1], hash[2])
    }

    /** Index of the preset matching [bytes], or the nearest lower one. */
    fun presetIndexFor(bytes: Int): Int {
        var index = 0
        for (i in MAX_APPLY_PRESETS.indices) {
            if (bytes >= MAX_APPLY_PRESETS[i]) index = i
        }
        return index
    }

    /** Human label for a preset value ("512 KB"). */
    fun presetLabel(bytes: Int): String = "${bytes / 1024} KB"

    const val DEFAULT_UDP_PORT = 47474
    val DEFAULT_TCP_PORT: Int = LargeTextLimits.DEFAULT_TCP_PORT
}
