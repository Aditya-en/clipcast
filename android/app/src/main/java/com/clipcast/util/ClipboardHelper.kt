package com.clipcast.util

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.os.Build
import com.clipcast.provider.ClipcastImageProvider
import java.io.File
import java.security.MessageDigest

object ClipboardHelper {
    private const val MAX_TEXT_LENGTH = 1200

    /** Image MIME types Clipcast will synchronize, best first. */
    val SUPPORTED_IMAGE_MIMES = arrayOf("image/png", "image/jpeg", "image/webp")

    /** Raw image bytes with their MIME type. */
    data class ImageContent(val mimeType: String, val bytes: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ImageContent) return false
            return mimeType == other.mimeType && bytes.contentEquals(other.bytes)
        }

        override fun hashCode(): Int = 31 * mimeType.hashCode() + bytes.contentHashCode()
    }

    /** True for a MIME type Clipcast will synchronize. */
    fun isSupportedImageMime(mime: String): Boolean = SUPPORTED_IMAGE_MIMES.contains(mime)

    /**
     * Preferred image MIME type in a clip description, best first, or null
     * when the clip offers no supported image type. Pure (unit-tested).
     */
    fun preferredImageMime(mimeTypes: Array<String>): String? =
        SUPPORTED_IMAGE_MIMES.firstOrNull { mimeTypes.contains(it) }

    fun extensionForMime(mimeType: String): String = when (mimeType) {
        "image/png" -> "png"
        "image/jpeg" -> "jpg"
        "image/webp" -> "webp"
        else -> "bin"
    }

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
        return contentHashBytes(text.toByteArray())
    }

    /** SHA-256 hex of raw bytes (text UTF-8 or image bytes share one suppression namespace). */
    fun contentHashBytes(bytes: ByteArray): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(bytes)
            hash.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            bytes.contentHashCode().toString()
        }
    }

    fun isValidForSend(text: String?): Boolean {
        return text != null && text.isNotEmpty() && text.length <= MAX_TEXT_LENGTH
    }

    /**
     * Foreground auto-send decision (pure, unit-tested). Sends unless the
     * text is invalid or repeats what we just sent within [repeatWindowMs].
     */
    fun shouldAutoSend(
        text: String?,
        lastSentHash: String?,
        lastSentTimeMs: Long,
        nowMs: Long,
        repeatWindowMs: Long = 2000
    ): Boolean {
        if (!isValidForSend(text)) return false
        if (lastSentHash != null && nowMs - lastSentTimeMs < repeatWindowMs &&
            contentHash(text!!) == lastSentHash
        ) {
            return false
        }
        return true
    }

    fun getMaxTextLength(): Int = MAX_TEXT_LENGTH

    /**
     * Read the current clipboard image, if the clip offers a supported
     * image MIME type. Images are read through ContentResolver (never
     * trusting another app's URI beyond a bounded byte count) and capped
     * at [maxBytes]; larger offers yield null. Returns null for text-only
     * or empty clips.
     */
    fun getImage(context: Context, maxBytes: Long): ImageContent? {
        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        if (!clipboard.hasPrimaryClip()) return null
        val clip = clipboard.primaryClip ?: return null
        val desc = clip.description ?: return null
        val mimeTypes = Array(desc.mimeTypeCount) { desc.getMimeType(it) }
        val mime = preferredImageMime(mimeTypes) ?: return null
        val uri = clip.getItemAt(0)?.uri ?: return null
        return try {
            context.contentResolver.openInputStream(uri)?.use { input ->
                val cap = maxBytes + 1
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(8192)
                var total = 0L
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    total += n
                    if (total > cap) return null
                    out.write(buf, 0, n)
                }
                val bytes = out.toByteArray()
                if (bytes.isEmpty()) null else ImageContent(mime, bytes)
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Publish image bytes to the clipboard as a secure content URI backed
     * by app-private storage (never a file:// URI). Returns the URI on
     * success, null when the MIME type is unsupported or the write fails.
     * Receiving apps get URI read access through the clipboard grant.
     */
    fun setImage(context: Context, mimeType: String, bytes: ByteArray): Uri? {
        if (!isSupportedImageMime(mimeType) || bytes.isEmpty()) return null
        return try {
            val dir = File(context.cacheDir, "clipboard_images").apply { mkdirs() }
            val name = "${contentHashBytes(bytes)}.${extensionForMime(mimeType)}"
            val file = File(dir, name)
            if (!file.exists()) file.writeBytes(bytes)
            val uri = ClipcastImageProvider.uriFor(context, name)
            val clip = ClipData.newUri(context.contentResolver, "clipcast image", uri)
            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clipboard.setPrimaryClip(clip)
            uri
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Stage image bytes where the service can read them (Binder cannot
     * carry megabytes in intent extras). Returns the absolute path, or
     * null on failure. The service deletes the file after reading it.
     */
    fun stageImageForSend(context: Context, image: ImageContent): String? {
        return try {
            val dir = File(context.cacheDir, "send_staging").apply { mkdirs() }
            val file = File(dir, "${java.util.UUID.randomUUID()}.${extensionForMime(image.mimeType)}")
            file.writeBytes(image.bytes)
            file.absolutePath
        } catch (e: Exception) {
            null
        }
    }
}