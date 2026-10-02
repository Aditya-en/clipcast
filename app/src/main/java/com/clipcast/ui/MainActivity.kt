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
import com.clipcast.protocol.LargeTextLimits
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
    private lateinit var tcpPortInput: TextInputEditText
    private lateinit var maxApplyInput: TextInputEditText
    private lateinit var autostartCheck: CompoundButton
    private lateinit var serviceSwitch: Switch
    private lateinit var statusText: TextView
    private lateinit var lastRxText: TextView
    private lateinit var lastTxText: TextView
    private lateinit var tcpStatusText: TextView
    private lateinit var lastTransferText: TextView
    private lateinit var sendNowButton: Button

    private val dateFormat = SimpleDateFormat("HH:mm:ss", Locale.getDefault())

    // Foreground-only auto-send (path a): Android 10+ blocks background
    // clipboard reads, so the listener is active only while resumed, plus we
    // snapshot on pause and re-check on resume to catch copies made in other
    // apps while we were away.
    private var clipboardManager: ClipboardManager? = null
    private var lastAutoSentHash: String? = null
    private var lastAutoSentTime: Long = 0
    private var lastSeenHash: String? = null
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
        tcpPortInput = findViewById(R.id.tcpPortInput)
        maxApplyInput = findViewById(R.id.maxApplyInput)
        autostartCheck = findViewById(R.id.autostartCheck)
        serviceSwitch = findViewById(R.id.serviceSwitch)
        statusText = findViewById(R.id.statusText)
        lastRxText = findViewById(R.id.lastRxText)
        lastTxText = findViewById(R.id.lastTxText)
        tcpStatusText = findViewById(R.id.tcpStatusText)
        lastTransferText = findViewById(R.id.lastTransferText)
        sendNowButton = findViewById(R.id.sendNowButton)

        deviceIdValue.text = "Device ID: ${Crypto.bytesToHex(preferences?.deviceId ?: ByteArray(16))}"

        keyInput.setText(preferences?.encryptionKey ?: "")
        portInput.setText(preferences?.port.toString())
        tcpPortInput.setText((preferences?.tcpPort ?: LargeTextLimits.DEFAULT_TCP_PORT).toString())
        maxApplyInput.setText(((preferences?.maxApplyBytes ?: LargeTextLimits.DEFAULT_MAX_APPLY_BYTES) / 1024).toString())
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
                } else if (intent?.getBooleanExtra("too_large", false) == true) {
                    Toast.makeText(this@MainActivity, getString(R.string.toast_too_large, length), Toast.LENGTH_SHORT).show()
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
        // Catch copies made in other apps while we were paused: if the
        // clipboard differs from what we last saw, sync it now.
        pollClipboardOnResume()
    }

    override fun onPause() {
        // Snapshot so onResume can detect changes made while away.
        lastSeenHash = currentClipboardText()?.let { ClipboardHelper.contentHash(it) }
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
        val tcpPortStr = tcpPortInput.text.toString().trim()
        val maxApplyStr = maxApplyInput.text.toString().trim()

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

        val tcpPort = tcpPortStr.toIntOrNull() ?: LargeTextLimits.DEFAULT_TCP_PORT
        if (tcpPort < 1 || tcpPort > 65535) {
            Toast.makeText(this, "Invalid TCP port", Toast.LENGTH_SHORT).show()
            serviceSwitch.isChecked = false
            return
        }

        val maxApplyKiB = maxApplyStr.toIntOrNull()
            ?: (LargeTextLimits.DEFAULT_MAX_APPLY_BYTES / 1024)
        if (maxApplyKiB < 0 || maxApplyKiB > LargeTextLimits.MAX_APPLY_HARD_CAP / 1024) {
            Toast.makeText(this, "Max applied text must be 0–900 KiB", Toast.LENGTH_SHORT).show()
            serviceSwitch.isChecked = false
            return
        }

        preferences?.encryptionKey = key
        preferences?.port = port
        preferences?.tcpPort = tcpPort
        preferences?.maxApplyBytes = maxApplyKiB * 1024

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
        if (text.isNullOrEmpty()) {
            Toast.makeText(this, getString(R.string.toast_empty), Toast.LENGTH_SHORT).show()
            return
        }
        if (text.toByteArray(Charsets.UTF_8).size > LargeTextLimits.DEFAULT_MAX_SEND_BYTES) {
            Toast.makeText(this, getString(R.string.toast_too_large, text.length), Toast.LENGTH_SHORT).show()
            return
        }
        lastSeenHash = ClipboardHelper.contentHash(text)

        val intent = Intent(this, ClipcastService::class.java).apply {
            action = ClipcastService.ACTION_SEND_CLIPBOARD
            putExtra(ClipcastService.EXTRA_TEXT, text)
            putExtra(ClipcastService.EXTRA_QUIET, false)
        }
        startService(intent)
    }

    /** Readable plain-text of the current primary clip, or null. */
    private fun currentClipboardText(): String? {
        val cm = clipboardManager
            ?: getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        if (!cm.hasPrimaryClip()) return null
        val clip = cm.primaryClip ?: return null
        if (!clip.description.hasMimeType(ClipDescription.MIMETYPE_TEXT_PLAIN)) return null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            clip.description.extras?.getBoolean(ClipDescription.EXTRA_IS_SENSITIVE) == true
        ) {
            return null
        }
        return clip.getItemAt(0).coerceToText(this)?.toString()
    }

    /**
     * Foreground auto-send: fires on every clipboard change while the
     * activity is resumed. Quiet (no toast); oversize still warns.
     * The service drops echoes of just-applied remote content.
     */
    private fun autoSendClipboard() {
        if (clipboardManager == null) return
        considerAutoSend(currentClipboardText(), warnOversize = true)
    }

    /**
     * Catches copies made in other apps while we were paused: sync on return
     * if the clipboard differs from what we last saw. (True background
     * sending is impossible on Android 10+; this is the closest equivalent.)
     */
    private fun pollClipboardOnResume() {
        if (clipboardManager == null) return
        val text = currentClipboardText() ?: return
        val hash = ClipboardHelper.contentHash(text)
        if (hash == lastSeenHash) return
        considerAutoSend(text, warnOversize = true)
    }

    /** Shared quiet-send core for the listener and the resume poll. */
    private fun considerAutoSend(text: String?, warnOversize: Boolean) {
        if (text.isNullOrEmpty()) return
        // Small text goes over UDP as before; large text (up to 16 MiB) goes
        // over the TCP side channel. Only beyond that do we warn.
        if (text.toByteArray(Charsets.UTF_8).size > LargeTextLimits.DEFAULT_MAX_SEND_BYTES) {
            if (warnOversize) {
                Toast.makeText(this, getString(R.string.toast_too_large, text.length), Toast.LENGTH_SHORT).show()
            }
            return
        }
        // Skip repeats of what we just sent (e.g. our own setPrimaryClip echo).
        val now = System.currentTimeMillis()
        if (!ClipboardHelper.shouldAutoSend(text, lastAutoSentHash, lastAutoSentTime, now)) return
        lastAutoSentHash = ClipboardHelper.contentHash(text)
        lastAutoSentTime = now
        lastSeenHash = lastAutoSentHash

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
        val tcpStatus = intent?.getStringExtra(ClipcastService.EXTRA_TCP_STATUS) ?: "TCP stopped"
        val lastTransfer = intent?.getStringExtra(ClipcastService.EXTRA_LAST_TRANSFER) ?: "none"

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

        // TCP listener state and last transfer result (size + outcome only).
        tcpStatusText.text = getString(R.string.tcp_listening, tcpStatus)
        lastTransferText.text = getString(R.string.last_transfer, lastTransfer)
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