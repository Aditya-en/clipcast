package com.clipcast.ui

import android.app.Activity
import android.content.ClipDescription
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Toast
import com.clipcast.service.ClipcastService
import com.clipcast.R
import com.clipcast.protocol.LargeTextLimits
import com.clipcast.ui.UiFormat
import com.clipcast.util.ClipboardHelper
import com.clipcast.util.Preferences

class SendActivity : Activity() {
    private var hasWindowFocus = false
    private var preferences: Preferences? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(View(this))
        preferences = Preferences.getInstance(this)
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus && !hasWindowFocus) {
            hasWindowFocus = true
            processSend()
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (hasWindowFocus) {
            processSend()
        }
    }

    private fun processSend() {
        val intent = intent
        // 1. Shared image (Share → Clipcast with image/*).
        if (Intent.ACTION_SEND == intent.action && intent.type?.startsWith("image/") == true) {
            @Suppress("DEPRECATION")
            val uri = intent.getParcelableExtra<android.net.Uri>(Intent.EXTRA_STREAM)
            val image = uri?.let { readSharedImage(it, intent.type) }
            if (image == null) {
                Toast.makeText(this, getString(R.string.toast_sent_fail), Toast.LENGTH_SHORT).show()
                finish()
                return
            }
            if (image.bytes.size.toLong() > LargeTextLimits.MAX_IMAGE_BYTES) {
                Toast.makeText(this, getString(R.string.send_image_too_large), Toast.LENGTH_SHORT).show()
                finish()
                return
            }
            sendStagedImage(image)
            Toast.makeText(
                this,
                getString(R.string.toast_sent_image, UiFormat.humanSize(image.bytes.size.toLong())),
                Toast.LENGTH_SHORT
            ).show()
            finish()
            return
        }

        // 2. Clipboard image wins over clipboard text (user-triggered send).
        val clipImage = try {
            ClipboardHelper.getImage(this, LargeTextLimits.MAX_IMAGE_BYTES)
        } catch (e: Exception) {
            null
        }
        if (clipImage != null) {
            sendStagedImage(clipImage)
            Toast.makeText(
                this,
                getString(R.string.toast_sent_image, UiFormat.humanSize(clipImage.bytes.size.toLong())),
                Toast.LENGTH_SHORT
            ).show()
            finish()
            return
        }

        var text: String? = null

        if (Intent.ACTION_SEND.equals(intent.action) && intent.type != null) {
            if ("text/plain".equals(intent.type)) {
                text = intent.getStringExtra(Intent.EXTRA_TEXT)
            }
        } else {
            text = ClipboardHelper.getText(this)
        }

        if (text.isNullOrEmpty()) {
            Toast.makeText(this, "No text to send", Toast.LENGTH_SHORT).show()
            finish()
            return
        }
        if (text.toByteArray(Charsets.UTF_8).size > LargeTextLimits.DEFAULT_MAX_SEND_BYTES) {
            Toast.makeText(this, getString(R.string.toast_too_large, text.length), Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val clipboard = getSystemService(android.content.Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
            if (clipboard.hasPrimaryClip()) {
                val clip = clipboard.primaryClip
                if (clip != null && ClipboardHelper.isSensitive(clip.description)) {
                    Toast.makeText(this, "Clipboard marked sensitive", Toast.LENGTH_SHORT).show()
                    finish()
                    return
                }
            }
        }

        val serviceIntent = Intent(this, ClipcastService::class.java).apply {
            action = ClipcastService.ACTION_SEND_CLIPBOARD
            putExtra(ClipcastService.EXTRA_TEXT, text)
            putExtra(ClipcastService.EXTRA_QUIET, false)
        }
        startService(serviceIntent)

        Toast.makeText(this, getString(R.string.toast_sent, text!!.length), Toast.LENGTH_SHORT).show()
        finish()
    }

    /**
     * Read a shared image through ContentResolver (never trusting the
     * sending app's URI beyond a bounded byte count). Null when the MIME
     * type is unsupported, the stream is empty/oversize, or unreadable.
     */
    private fun readSharedImage(uri: android.net.Uri, intentMime: String?): ClipboardHelper.ImageContent? {
        return try {
            val resolved = contentResolver.getType(uri) ?: intentMime ?: return null
            if (!ClipboardHelper.isSupportedImageMime(resolved)) return null
            contentResolver.openInputStream(uri)?.use { input ->
                val cap = LargeTextLimits.MAX_IMAGE_BYTES + 1
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
                if (bytes.isEmpty()) null else ClipboardHelper.ImageContent(resolved, bytes)
            }
        } catch (e: Exception) {
            null
        }
    }

    private fun sendStagedImage(image: ClipboardHelper.ImageContent) {
        val staged = ClipboardHelper.stageImageForSend(this, image) ?: return
        val serviceIntent = Intent(this, ClipcastService::class.java).apply {
            action = ClipcastService.ACTION_SEND_CLIPBOARD
            putExtra(ClipcastService.EXTRA_IMAGE_PATH, staged)
            putExtra(ClipcastService.EXTRA_IMAGE_MIME, image.mimeType)
            putExtra(ClipcastService.EXTRA_QUIET, false)
        }
        startService(serviceIntent)
    }
}