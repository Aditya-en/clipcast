package com.clipcast.util

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import java.security.MessageDigest

object ClipboardHelper {
    private const val MAX_TEXT_LENGTH = 1200

    fun getText(context: Context): String? {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        return if (clipboard.hasPrimaryClip()) {
            val clip = clipboard.primaryClip
            if (clip != null && clip.description.hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN)) {
                clip.getItemAt(0).text.toString()
            } else null
        } else null
    }

    fun setText(context: Context, text: String, label: String = "clipcast") {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, text)
        clipboard.setPrimaryClip(clip)
    }

    fun isSensitive(clipDescription: ClipDescription?): Boolean {
        if (clipDescription == null) return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            return clipDescription.extras?.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE) == true
        }
        return false
    }

    fun contentHash(text: String): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(text.toByteArray())
            hash.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            text.hashCode().toString()
        }
    }

    fun isValidForSend(text: String?): Boolean {
        return text != null && text.isNotEmpty() && text.length <= MAX_TEXT_LENGTH
    }

    fun getMaxTextLength(): Int = MAX_TEXT_LENGTH
}