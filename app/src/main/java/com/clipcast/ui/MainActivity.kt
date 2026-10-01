package com.clipcast.ui

import android.content.BroadcastReceiver
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.TextUtils
import android.util.Base64
import android.view.View
import android.widget.Button
import android.widget.CompoundButton
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.clipcast.service.ClipcastService
import com.clipcast.R
import com.clipcast.protocol.Crypto
import com.clipcast.util.ClipboardHelper
import com.clipcast.util.Preferences
import com.google.android.material.textfield.TextInputEditText
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity() {
    private var preferences: Preferences? = null
    private var statusReceiver: BroadcastReceiver? = null
    private var sendResultReceiver: BroadcastReceiver? = null

    private lateinit var deviceIdValue: TextView
    private lateinit var keyInput: TextInputEditText
    private lateinit var portInput: TextInputEditText
    private lateinit var autostartCheck: CompoundButton
    private lateinit var serviceSwitch: Switch
    private lateinit var statusText: TextView
    private lateinit var lastRxText: TextView
    private lateinit var lastTxText: TextView
    private lateinit var sendNowButton: Button

    private val dateFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    // Foreground-only auto-send (path a): Android 10+ blocks background
    // clipboard reads, so this listener is active only while resumed.
    private var clipboardManager: ClipboardManager? = null
    private var lastAutoSentHash: String? = null
    private var lastAutoSentTime: Long = 0
    private val debounceHandler = Handler(Looper.getMainLooper())
    private var pendingDebounce: Runnable? = null
    private val clipListener = ClipboardManager.OnPrimaryClipChangedListener {
        // Trailing-edge debounce: coalesce rapid successive copies, send once.
        pendingDebounce?.let { debounceHandler.removeCallbacks(it) }
        val task = Runnable { autoSendClipboard() }
        pendingDebounce = task
        debounceHandler.postDelayed(task, 100)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        preferences = Preferences.getInstance(this)

        deviceIdValue = findViewById(R.id.deviceIdValue)
        keyInput = findViewById(R.id.keyInput)
        portInput = findViewById(R.id.portInput)
        autostartCheck = findViewById(R.id.autostartCheck)
        serviceSwitch = findViewById(R.id.serviceSwitch)
        statusText = findViewById(R.id.statusText)
        lastRxText = findViewById(R.id.lastRxText)
        lastTxText = findViewById(R.id.lastTxText)
        sendNowButton = findViewById(R.id.sendNowButton)

        deviceIdValue.text = "Device ID: ${Crypto.bytesToHex(preferences?.deviceId ?: ByteArray(16))}"

        keyInput.setText(preferences?.encryptionKey ?: "")
        portInput.setText(preferences?.port.toString())
        autostartCheck.isChecked = preferences?.autostart ?: false

        serviceSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked) {
                validateAndStart()
            } else {
                stopService()
            }
        }

        sendNowButton.setOnClickListener {
            sendClipboardNow()
        }

        autostartCheck.setOnCheckedChangeListener { _, isChecked ->
            preferences?.autostart = isChecked
            updateBootReceiver(isChecked)
        }

        statusReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                updateStatusUI(intent)
            }
        }

        sendResultReceiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context?, intent: Intent?) {
                // Quiet (auto-send) results only update the status line, no toast.
                if (intent?.getBooleanExtra(ClipcastService.EXTRA_QUIET, false) == true) return
                val success = intent?.getBooleanExtra("success", false) ?: false
                val length = intent?.getIntExtra("length", 0) ?: 0
                if (success) {
                    Toast.makeText(this@MainActivity, getString(R.string.toast_sent, length), Toast.LENGTH_SHORT).show()
                } else {
                    Toast.makeText(this@MainActivity, R.string.toast_sent_fail, Toast.LENGTH_SHORT).show()
                }
            }
        }

        LocalBroadcastManager.getInstance(this).registerReceiver(
            statusReceiver!!,
            IntentFilter(ClipcastService.BROADCAST_STATUS)
        )
        LocalBroadcastManager.getInstance(this).registerReceiver(
            sendResultReceiver!!,
            IntentFilter("com.clipcast.SEND_RESULT")
        )
    }

    override fun onResume() {
        super.onResume()
        requestStatusBroadcast()
        // Foreground auto-send on: we can read the clipboard while resumed.
        clipboardManager = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboardManager?.addPrimaryClipChangedListener(clipListener)
    }

    override fun onPause() {
        clipboardManager?.removePrimaryClipChangedListener(clipListener)
        clipboardManager = null
        pendingDebounce?.let { debounceHandler.removeCallbacks(it) }
        pendingDebounce = null
        super.onPause()
    }

    override fun onDestroy() {
        statusReceiver?.let { LocalBroadcastManager.getInstance(this).unregisterReceiver(it) }
        sendResultReceiver?.let { LocalBroadcastManager.getInstance(this).unregisterReceiver(it) }
        super.onDestroy()
    }

    private fun validateAndStart() {
        val key = keyInput.text.toString().trim()
        val portStr = portInput.text.toString().trim()

        if (TextUtils.isEmpty(key) || !Crypto.validateKey(key)) {
            Toast.makeText(this, R.string.toast_key_invalid, Toast.LENGTH_LONG).show()
            serviceSwitch.isChecked = false
            return
        }

        val port = portStr.toIntOrNull() ?: 47474
        if (port < 1 || port > 65535) {
            Toast.makeText(this, "Invalid port", Toast.LENGTH_SHORT).show()
            serviceSwitch.isChecked = false
            return
        }

        preferences?.encryptionKey = key
        preferences?.port = port

        startService()
    }

    private fun startService() {
        val intent = Intent(this, ClipcastService::class.java).apply {
            action = ClipcastService.ACTION_START
        }
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            ContextCompat.startForegroundService(this, intent)
        } else {
            startService(intent)
        }
        serviceSwitch.isChecked = true
        statusText.text = getString(R.string.status_starting)
    }

    private fun stopService() {
        val intent = Intent(this, ClipcastService::class.java).apply {
            action = ClipcastService.ACTION_STOP
        }
        startService(intent)
        serviceSwitch.isChecked = false
    }

    private fun sendClipboardNow() {
        val text = ClipboardHelper.getText(this)
        if (!ClipboardHelper.isValidForSend(text)) {
            val len = text?.length ?: 0
            Toast.makeText(this, getString(R.string.toast_oversize, len), Toast.LENGTH_SHORT).show()
            return
        }

        val intent = Intent(this, ClipcastService::class.java).apply {
            action = ClipcastService.ACTION_SEND_CLIPBOARD
            putExtra(ClipcastService.EXTRA_TEXT, text)
            putExtra(ClipcastService.EXTRA_QUIET, false)
        }
        startService(intent)
    }

    /**
     * Foreground auto-send: fires on every clipboard change while the
     * activity is resumed. Quiet (no toast); oversize still warns.
     * The service drops echoes of just-applied remote content.
     */
    private fun autoSendClipboard() {
        val cm = clipboardManager ?: return
        if (!cm.hasPrimaryClip()) return
        val clip = cm.primaryClip ?: return
        if (!clip.description.hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN)) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            clip.description.extras?.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE) == true
        ) {
            return
        }
        val text = clip.getItemAt(0).coerceToText(this).toString()
        if (text.isEmpty()) return
        if (text.length > ClipboardHelper.getMaxTextLength()) {
            Toast.makeText(this, getString(R.string.toast_oversize, text.length), Toast.LENGTH_SHORT).show()
            return
        }
        // Skip repeats of what we just sent (e.g. our own setPrimaryClip echo).
        val now = System.currentTimeMillis()
        if (!ClipboardHelper.shouldAutoSend(text, lastAutoSentHash, lastAutoSentTime, now)) return
        lastAutoSentHash = ClipboardHelper.contentHash(text)
        lastAutoSentTime = now

        val intent = Intent(this, ClipcastService::class.java).apply {
            action = ClipcastService.ACTION_SEND_CLIPBOARD
            putExtra(ClipcastService.EXTRA_TEXT, text)
            putExtra(ClipcastService.EXTRA_QUIET, true)
        }
        startService(intent)
    }

    private fun requestStatusBroadcast() {
        val intent = Intent(this, ClipcastService::class.java).apply {
            action = ClipcastService.ACTION_QUERY_STATUS
        }
        try {
            startService(intent)
        } catch (e: Exception) {
            // Service not running yet; status stays at defaults.
        }
    }

    private fun updateStatusUI(intent: Intent?) {
        val status = intent?.getStringExtra(ClipcastService.EXTRA_STATUS) ?: "stopped"
        val broadcastAddr = intent?.getStringExtra(ClipcastService.EXTRA_BROADCAST_ADDR) ?: "none"
        val lastRxTime = intent?.getLongExtra(ClipcastService.EXTRA_LAST_RX_TIME, 0) ?: 0L
        val lastRxLen = intent?.getIntExtra(ClipcastService.EXTRA_LAST_RX_LEN, 0) ?: 0
        val lastTxTime = intent?.getLongExtra(ClipcastService.EXTRA_LAST_TX_TIME, 0) ?: 0L
        val lastTxLen = intent?.getIntExtra(ClipcastService.EXTRA_LAST_TX_LEN, 0) ?: 0

        when (status) {
            "running" -> {
                serviceSwitch.isChecked = true
                statusText.text = getString(R.string.status_running, broadcastAddr, preferences?.port ?: 47474)
            }
            "starting" -> {
                serviceSwitch.isChecked = true
                statusText.text = getString(R.string.status_starting)
            }
            else -> {
                serviceSwitch.isChecked = false
                if (broadcastAddr == "none") {
                    statusText.text = getString(R.string.status_no_wifi)
                } else {
                    statusText.text = getString(R.string.status_stopped)
                }
            }
        }

        lastRxText.text = if (lastRxTime > 0) {
            getString(R.string.last_rx, dateFormat.format(Date(lastRxTime)), lastRxLen)
        } else {
            getString(R.string.last_rx, getString(R.string.never), 0)
        }

        lastTxText.text = if (lastTxTime > 0) {
            getString(R.string.last_tx, dateFormat.format(Date(lastTxTime)), lastTxLen)
        } else {
            getString(R.string.last_tx, getString(R.string.never), 0)
        }
    }

    private fun updateBootReceiver(enabled: Boolean) {
        val componentName = android.content.ComponentName(this, com.clipcast.receiver.BootReceiver::class.java)
        val newState = if (enabled) {
            android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        } else {
            android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED
        }
        packageManager.setComponentEnabledSetting(componentName, newState, android.content.pm.PackageManager.DONT_KILL_APP)
    }
}