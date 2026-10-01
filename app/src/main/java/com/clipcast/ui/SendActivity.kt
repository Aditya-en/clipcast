package com.clipcast.ui

import android.app.Activity
import android.content.ClipDescription
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.clipcast.service.ClipcastService
import com.clipcast.R
import com.clipcast.util.ClipboardHelper
import com.clipcast.util.Preferences

class SendActivity : AppCompatActivity() {
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
        var text: String? = null

        val intent = intent
        if (Intent.ACTION_SEND.equals(intent.action) && intent.type != null) {
            if ("text/plain".equals(intent.type)) {
                text = intent.getStringExtra(Intent.EXTRA_TEXT)
            }
        } else {
            text = ClipboardHelper.getText(this)
        }

        if (!ClipboardHelper.isValidForSend(text)) {
            val len = text?.length ?: 0
            val msg = if (len > ClipboardHelper.getMaxTextLength()) {
                getString(R.string.toast_oversize, len)
            } else {
                "No text to send"
            }
            Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
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
        }
        startService(serviceIntent)

        Toast.makeText(this, getString(R.string.toast_sent, text!!.length), Toast.LENGTH_SHORT).show()
        finish()
    }
}