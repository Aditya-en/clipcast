package com.clipcast.ui

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.TextWatcher
import android.transition.AutoTransition
import android.transition.TransitionManager
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ScrollView
import android.widget.SeekBar
import android.widget.Switch
import android.widget.TextView
import com.clipcast.R
import com.clipcast.protocol.Crypto
import com.clipcast.service.ClipcastService
import com.clipcast.util.ClipboardHelper
import com.clipcast.util.Preferences

/**
 * Settings: everything set-once. Same visual system as the main screen.
 * Changes apply immediately when valid (no Save button); an invalid field
 * never overwrites the stored value.
 */
class SettingsActivity : Activity() {

    private var preferences: Preferences? = null
    private val uiHandler = Handler(Looper.getMainLooper())

    private lateinit var keyInput: EditText
    private lateinit var keyToggleButton: Button
    private lateinit var keyState: TextView
    private lateinit var keyFingerprint: TextView
    private lateinit var bootSwitch: Switch
    private lateinit var maxApplyTitle: TextView
    private lateinit var maxApplySeek: SeekBar
    private lateinit var deviceIdValue: TextView
    private lateinit var advancedToggle: Button
    private lateinit var advancedGroup: View
    private lateinit var udpPortInput: EditText
    private lateinit var udpPortError: TextView
    private lateinit var tcpPortInput: EditText
    private lateinit var tcpPortError: TextView
    private lateinit var portsNote: TextView

    private var keyVisible = false
    private var updatingPortsProgrammatically = false
    private var deviceIdCopiedUntil: Long = 0
    private var deviceIdFull = ""
    private var deviceIdShort = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        EdgeToEdge.apply(this, findViewById(android.R.id.content))
        setContentView(R.layout.activity_settings)

        preferences = Preferences.getInstance(this)

        findViewById<ImageButton>(R.id.backButton).setOnClickListener { finish() }

        setupKeySection()
        setupBehaviorSection()
        setupDeviceSection()
        setupAdvancedSection()
        setupAboutSection()

        if (intent.getBooleanExtra(MainActivity.EXTRA_SCROLL_TO_KEY, false)) {
            findViewById<ScrollView>(R.id.root).post {
                val section = findViewById<View>(R.id.keySection)
                findViewById<ScrollView>(R.id.root).smoothScrollTo(0, section.top)
                keyInput.requestFocus()
            }
        }
    }

    // --- Encryption --------------------------------------------------------

    private fun setupKeySection() {
        keyInput = findViewById(R.id.keyInput)
        keyToggleButton = findViewById(R.id.keyToggleButton)
        keyState = findViewById(R.id.keyState)
        keyFingerprint = findViewById(R.id.keyFingerprint)

        keyInput.setText(preferences?.encryptionKey ?: "")
        renderKeyState(preferences?.encryptionKey)

        keyInput.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                onKeyEdited(s?.toString())
            }
        })

        keyToggleButton.setOnClickListener {
            // Toggle the transformation only: changing inputType at runtime
            // does not reliably reapply the dots, so the field would stay
            // visible once shown.
            keyVisible = !keyVisible
            keyInput.transformationMethod = if (keyVisible) {
                null
            } else {
                android.text.method.PasswordTransformationMethod.getInstance()
            }
            keyInput.setSelection(keyInput.text.length)
            keyToggleButton.setText(if (keyVisible) R.string.key_hide else R.string.key_show)
        }

        findViewById<Button>(R.id.keyPasteButton).setOnClickListener {
            val pasted = try {
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                if (!cm.hasPrimaryClip()) null
                else cm.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()
            } catch (e: Exception) {
                null
            }
            if (pasted == null) {
                keyState.text = getString(R.string.key_paste_fail)
                keyState.setTextColor(tintFor(R.attr.clipStatusError))
            } else {
                // Trim whitespace and newlines on paste.
                keyInput.setText(SettingsValidation.canonicalKey(pasted))
                keyInput.setSelection(keyInput.text.length)
            }
        }
    }

    private fun onKeyEdited(raw: String?) {
        when (SettingsValidation.validateKey(raw)) {
            is SettingsValidation.KeyResult.Valid -> {
                // Applies immediately; invalid text never reaches storage.
                preferences?.encryptionKey = SettingsValidation.canonicalKey(raw)
                renderKeyState(raw)
            }
            is SettingsValidation.KeyResult.Invalid -> renderKeyState(raw)
        }
    }

    private fun renderKeyState(raw: String?) {
        when (val result = SettingsValidation.validateKey(raw)) {
            is SettingsValidation.KeyResult.Valid -> {
                keyState.text = getString(R.string.key_valid)
                keyState.setTextColor(tintFor(R.attr.clipStatusOk))
                if (SettingsValidation.SHOW_KEY_FINGERPRINT) {
                    try {
                        val bytes = Crypto.decodeKey(SettingsValidation.canonicalKey(raw))
                        keyFingerprint.visibility = View.VISIBLE
                        keyFingerprint.text = getString(
                            R.string.key_fingerprint,
                            SettingsValidation.keyFingerprint(bytes)
                        )
                    } catch (e: Exception) {
                        keyFingerprint.visibility = View.GONE
                    }
                } else {
                    keyFingerprint.visibility = View.GONE
                }
            }
            is SettingsValidation.KeyResult.Invalid -> {
                keyState.text = result.reason
                keyState.setTextColor(tintFor(R.attr.clipStatusError))
                keyFingerprint.visibility = View.GONE
            }
        }
    }

    // --- Behavior ----------------------------------------------------------

    private fun setupBehaviorSection() {
        bootSwitch = findViewById(R.id.bootSwitch)
        bootSwitch.isChecked = preferences?.autostart == true
        bootSwitch.contentDescription = getString(R.string.pref_autostart)
        bootSwitch.setOnCheckedChangeListener { _, isChecked ->
            preferences?.autostart = isChecked
            updateBootReceiver(isChecked)
        }

        maxApplyTitle = findViewById(R.id.maxApplyTitle)
        maxApplySeek = findViewById(R.id.maxApplySeek)
        val current = preferences?.maxApplyBytes
            ?: com.clipcast.protocol.LargeTextLimits.DEFAULT_MAX_APPLY_BYTES
        maxApplySeek.progress = SettingsValidation.presetIndexFor(current)
        renderMaxApplyTitle(SettingsValidation.MAX_APPLY_PRESETS[maxApplySeek.progress])
        maxApplySeek.setOnSeekBarChangeListener(object : SeekBar.OnSeekBarChangeListener {
            override fun onProgressChanged(seek: SeekBar?, progress: Int, fromUser: Boolean) {
                if (!fromUser) return
                val bytes = SettingsValidation.MAX_APPLY_PRESETS[progress]
                preferences?.maxApplyBytes = bytes
                renderMaxApplyTitle(bytes)
            }

            override fun onStartTrackingTouch(seek: SeekBar?) = Unit
            override fun onStopTrackingTouch(seek: SeekBar?) = Unit
        })
    }

    private fun renderMaxApplyTitle(bytes: Int) {
        maxApplyTitle.text = getString(
            R.string.max_apply_title, SettingsValidation.presetLabel(bytes)
        )
    }

    private fun updateBootReceiver(enabled: Boolean) {
        val componentName = android.content.ComponentName(this, com.clipcast.receiver.BootReceiver::class.java)
        val newState = if (enabled) {
            android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_ENABLED
        } else {
            android.content.pm.PackageManager.COMPONENT_ENABLED_STATE_DISABLED
        }
        packageManager.setComponentEnabledSetting(
            componentName, newState, android.content.pm.PackageManager.DONT_KILL_APP
        )
    }

    // --- Device ------------------------------------------------------------

    private fun setupDeviceSection() {
        findViewById<TextView>(R.id.deviceName).text = Build.MODEL
        deviceIdValue = findViewById(R.id.deviceIdValue)
        deviceIdFull = Crypto.bytesToHex(preferences?.deviceId ?: ByteArray(16))
        deviceIdShort = UiFormat.shortId(deviceIdFull) + " · " + getString(R.string.device_tap_to_copy)
        deviceIdValue.text = deviceIdShort
        deviceIdValue.contentDescription =
            "Device ID ${UiFormat.shortId(deviceIdFull)}. ${getString(R.string.device_tap_to_copy)}."
        deviceIdValue.setOnClickListener {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            cm.setPrimaryClip(ClipData.newPlainText("clipcast device id", deviceIdFull))
            deviceIdValue.text = getString(R.string.copied)
            deviceIdCopiedUntil = System.currentTimeMillis() + 1500
            uiHandler.postDelayed({
                if (System.currentTimeMillis() >= deviceIdCopiedUntil) {
                    deviceIdValue.text = deviceIdShort
                }
            }, 1600)
        }
    }

    // --- Advanced (collapsed) -----------------------------------------------

    private fun setupAdvancedSection() {
        advancedToggle = findViewById(R.id.advancedToggle)
        advancedGroup = findViewById(R.id.advancedGroup)
        udpPortInput = findViewById(R.id.udpPortInput)
        udpPortError = findViewById(R.id.udpPortError)
        tcpPortInput = findViewById(R.id.tcpPortInput)
        tcpPortError = findViewById(R.id.tcpPortError)
        portsNote = findViewById(R.id.portsNote)

        udpPortInput.setText(preferences?.port.toString())
        tcpPortInput.setText(
            (preferences?.tcpPort
                ?: com.clipcast.protocol.LargeTextLimits.DEFAULT_TCP_PORT).toString()
        )

        advancedToggle.setOnClickListener {
            val show = advancedGroup.visibility != View.VISIBLE
            if (animatorsEnabled()) {
                TransitionManager.beginDelayedTransition(
                    advancedGroup.parent as ViewGroup, AutoTransition()
                )
            }
            advancedGroup.visibility = if (show) View.VISIBLE else View.GONE
            advancedToggle.setText(
                if (show) R.string.advanced_hide else R.string.advanced_show
            )
        }

        val watcher = object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) = Unit
            override fun afterTextChanged(s: Editable?) {
                if (!updatingPortsProgrammatically) tryApplyPorts()
            }
        }
        udpPortInput.addTextChangedListener(watcher)
        tcpPortInput.addTextChangedListener(watcher)

        findViewById<Button>(R.id.defaultsButton).setOnClickListener {
            updatingPortsProgrammatically = true
            udpPortInput.setText(SettingsValidation.DEFAULT_UDP_PORT.toString())
            tcpPortInput.setText(SettingsValidation.DEFAULT_TCP_PORT.toString())
            updatingPortsProgrammatically = false
            tryApplyPorts()
        }
    }

    private fun tryApplyPorts() {
        portsNote.visibility = View.GONE
        val udp = SettingsValidation.validatePort(udpPortInput.text.toString())
        val tcp = SettingsValidation.validatePort(tcpPortInput.text.toString())

        when (udp) {
            is SettingsValidation.PortResult.Valid -> udpPortError.visibility = View.GONE
            is SettingsValidation.PortResult.Invalid -> {
                udpPortError.visibility = View.VISIBLE
                udpPortError.text = udp.reason
                udpPortError.setTextColor(tintFor(R.attr.clipStatusError))
            }
        }
        when (tcp) {
            is SettingsValidation.PortResult.Valid -> tcpPortError.visibility = View.GONE
            is SettingsValidation.PortResult.Invalid -> {
                tcpPortError.visibility = View.VISIBLE
                tcpPortError.text = tcp.reason
                tcpPortError.setTextColor(tintFor(R.attr.clipStatusError))
            }
        }
        if (udp !is SettingsValidation.PortResult.Valid ||
            tcp !is SettingsValidation.PortResult.Valid
        ) {
            return
        }
        if (!SettingsValidation.portsDiffer(udp.port, tcp.port)) {
            tcpPortError.visibility = View.VISIBLE
            tcpPortError.text = getString(R.string.ports_same)
            tcpPortError.setTextColor(tintFor(R.attr.clipStatusError))
            return
        }
        val storedUdp = preferences?.port
        val storedTcp = preferences?.tcpPort
        if (udp.port == storedUdp && tcp.port == storedTcp) return
        preferences?.port = udp.port
        preferences?.tcpPort = tcp.port
        if (ServiceStateHolder.last.running) {
            restartService()
            portsNote.visibility = View.VISIBLE
            portsNote.text = getString(R.string.ports_restarted)
        }
    }

    private fun restartService() {
        startService(
            Intent(this, ClipcastService::class.java).apply {
                action = ClipcastService.ACTION_STOP
            }
        )
        startService(
            Intent(this, ClipcastService::class.java).apply {
                action = ClipcastService.ACTION_START
            }
        )
    }

    // --- About ---------------------------------------------------------------

    private fun setupAboutSection() {
        val info = try {
            packageManager.getPackageInfo(packageName, 0)
        } catch (e: Exception) {
            null
        }
        val code: Long = if (info == null) {
            0
        } else if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            info.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            info.versionCode.toLong()
        }
        findViewById<TextView>(R.id.aboutVersion).text = getString(
            R.string.about_version, info?.versionName ?: "?", code
        )
    }

    // --- helpers ---------------------------------------------------------------

    private fun animatorsEnabled(): Boolean {
        return android.animation.ValueAnimator.areAnimatorsEnabled()
    }

    private fun tintFor(attr: Int): android.content.res.ColorStateList {
        val out = android.util.TypedValue()
        theme.resolveAttribute(attr, out, true)
        return android.content.res.ColorStateList.valueOf(out.data)
    }
}
