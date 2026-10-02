package com.clipcast.ui

import android.app.Activity
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
import android.widget.EditText
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import com.clipcast.service.ClipcastService
import com.clipcast.R
import com.clipcast.protocol.Crypto
import com.clipcast.protocol.LargeTextLimits
import com.clipcast.util.ClipboardHelper
import com.clipcast.util.Preferences
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : Activity() {
    private var preferences: Preferences? = null
    private var stateListener: ServiceStateHolder.StateListener? = null
    private var sendListener: ServiceStateHolder.SendListener? = null

    private lateinit var deviceIdValue: TextView
    private lateinit var keyInput: EditText
    private lateinit var portInput: EditText
    private lateinit var tcpPortInput: EditText
    private lateinit var maxApplyInput: EditText
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
        EdgeToEdge.apply(this, findViewById(android.R.id.content))
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

        stateListener = ServiceStateHolder.StateListener { snapshot ->
            updateStatusUI(snapshot)
        }
        sendListener = ServiceStateHolder.SendListener { event ->
            // Quiet (auto-send) results only update the status line, no toast.
            if (event.quiet) return@SendListener
            if (event.success) {
                Toast.makeText(this@MainActivity, getString(R.string.toast_sent, event.length), Toast.LENGTH_SHORT).show()
            } else if (event.tooLarge) {
                Toast.makeText(this@MainActivity, getString(R.string.toast_too_large, event.length), Toast.LENGTH_SHORT).show()
            } else {
                Toast.makeText(this@MainActivity, R.string.toast_sent_fail, Toast.LENGTH_SHORT).show()
            }
        }
        ServiceStateHolder.addStateListener(stateListener!!)
        ServiceStateHolder.addSendListener(sendListener!!)
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
        stateListener?.let { ServiceStateHolder.removeStateListener(it) }
        sendListener?.let { ServiceStateHolder.removeSendListener(it) }
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
        // minSdk 26: startForegroundService always available.
        startForegroundService(intent)
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

    private fun updateStatusUI(s: ServiceStateHolder.Snapshot) {
        if (s.running) {
            serviceSwitch.isChecked = true
            statusText.text = getString(R.string.status_running, s.localIp ?: "…", preferences?.port ?: 47474)
        } else {
            serviceSwitch.isChecked = false
            statusText.text = if (!s.wifiConnected) {
                getString(R.string.status_no_wifi)
            } else {
                getString(R.string.status_stopped)
            }
        }

        lastRxText.text = if (s.lastRxTime > 0) {
            getString(R.string.last_rx, dateFormat.format(Date(s.lastRxTime)), s.lastRxLen)
        } else {
            getString(R.string.last_rx, getString(R.string.never), 0)
        }

        lastTxText.text = if (s.lastTxTime > 0) {
            getString(R.string.last_tx, dateFormat.format(Date(s.lastTxTime)), s.lastTxLen)
        } else {
            getString(R.string.last_tx, getString(R.string.never), 0)
        }

        // TCP listener state and last transfer result (size + outcome only).
        tcpStatusText.text = getString(
            R.string.tcp_listening,
            if (!s.running) "TCP stopped" else s.tcpError ?: "TCP listening"
        )
        lastTransferText.text = getString(R.string.last_transfer, s.lastTransfer)
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