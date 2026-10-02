package com.clipcast.ui

import android.app.Activity
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.format.DateUtils
import android.transition.Fade
import android.transition.TransitionManager
import android.view.HapticFeedbackConstants
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.Switch
import android.widget.TextView
import com.clipcast.R
import com.clipcast.service.ClipcastService
import com.clipcast.util.ClipboardHelper
import com.clipcast.util.Preferences

/**
 * Main screen: "is it working?" at a glance + one primary action.
 * Everything set-once lives in SettingsActivity. Observes service state
 * through ServiceStateHolder (updates only while visible). Never shows
 * clipboard content anywhere: sizes and times only.
 */
class MainActivity : Activity() {

    companion object {
        /** SettingsActivity scrolls to/highlights the key field. */
        const val EXTRA_SCROLL_TO_KEY = "extra_scroll_to_key"
        private const val SENT_FLASH_MS = 2000L
        private const val COPIED_MS = 1500L
        private const val REQUEST_NOTIFICATIONS = 41
    }

    private var preferences: Preferences? = null
    private var stateListener: ServiceStateHolder.StateListener? = null
    private var sendListener: ServiceStateHolder.SendListener? = null
    private var lastScreen: StatusMapper.MainScreen? = null

    private lateinit var statusCard: View
    private lateinit var statusDot: View
    private lateinit var statusTitle: TextView
    private lateinit var statusSub: TextView
    private lateinit var serviceSwitch: Switch
    private lateinit var emptyView: TextView
    private lateinit var rowReceived: View
    private lateinit var receivedTime: TextView
    private lateinit var receivedSize: TextView
    private lateinit var receivedGlyph: ImageView
    private lateinit var detailReceived: TextView
    private lateinit var rowSent: View
    private lateinit var sentTime: TextView
    private lateinit var sentSize: TextView
    private lateinit var sentGlyph: ImageView
    private lateinit var detailSent: TextView
    private lateinit var sendButton: Button
    private lateinit var sendReason: TextView
    private lateinit var firstRunCard: View
    private lateinit var pasteKeyButton: Button
    private lateinit var firstRunError: TextView
    private lateinit var hintCard: View
    private lateinit var hintText: TextView
    private lateinit var hintAction: Button
    private lateinit var hintDismiss: Button

    private var updatingSwitch = false
    private var transientReason: String? = null
    private var sentFlashUntil: Long = 0
    private var copiedUntil: Long = 0
    private var currentIpLine: String? = null
    private var statusTappable = false
    private val uiHandler = Handler(Looper.getMainLooper())
    private var sentRestore: Runnable? = null
    private var copiedRestore: Runnable? = null

    // Foreground-only auto-send: Android 10+ blocks background clipboard
    // reads, so the listener is active only while resumed, plus we snapshot
    // on pause and re-check on resume.
    private var clipboardManager: ClipboardManager? = null
    private var lastAutoSentHash: String? = null
    private var lastAutoSentTime: Long = 0
    private var lastSeenHash: String? = null
    private val debounceHandler = Handler(Looper.getMainLooper())
    private var pendingDebounce: Runnable? = null
    private val clipListener = ClipboardManager.OnPrimaryClipChangedListener {
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

        statusCard = findViewById(R.id.statusCard)
        statusDot = findViewById(R.id.statusDot)
        statusTitle = findViewById(R.id.statusTitle)
        statusSub = findViewById(R.id.statusSub)
        serviceSwitch = findViewById(R.id.serviceSwitch)
        emptyView = findViewById(R.id.emptyView)
        rowReceived = findViewById(R.id.rowReceived)
        receivedTime = findViewById(R.id.receivedTime)
        receivedSize = findViewById(R.id.receivedSize)
        receivedGlyph = findViewById(R.id.receivedGlyph)
        detailReceived = findViewById(R.id.detailReceived)
        rowSent = findViewById(R.id.rowSent)
        sentTime = findViewById(R.id.sentTime)
        sentSize = findViewById(R.id.sentSize)
        sentGlyph = findViewById(R.id.sentGlyph)
        detailSent = findViewById(R.id.detailSent)
        sendButton = findViewById(R.id.sendButton)
        sendReason = findViewById(R.id.sendReason)
        firstRunCard = findViewById(R.id.firstRunCard)
        pasteKeyButton = findViewById(R.id.pasteKeyButton)
        firstRunError = findViewById(R.id.firstRunError)
        hintCard = findViewById(R.id.hintCard)
        hintText = findViewById(R.id.hintText)
        hintAction = findViewById(R.id.hintAction)
        hintDismiss = findViewById(R.id.hintDismiss)

        serviceSwitch.contentDescription = getString(R.string.status_off)
        serviceSwitch.setOnCheckedChangeListener { _, isChecked ->
            if (updatingSwitch) return@setOnCheckedChangeListener
            transientReason = null
            if (isChecked) {
                turnSyncOn()
            } else {
                stopService()
            }
        }

        findViewById<ImageButton>(R.id.settingsButton).setOnClickListener {
            openSettings(scrollToKey = false)
        }
        statusCard.setOnClickListener {
            if (statusTappable) openSettings(scrollToKey = true)
        }
        statusSub.setOnClickListener {
            currentIpLine?.let { copyIp(it) }
        }
        sendButton.setOnClickListener {
            sendClipboardNow()
        }
        pasteKeyButton.setOnClickListener {
            pasteKeyFromClipboard()
        }
        hintDismiss.setOnClickListener {
            dismissCurrentHint()
        }

        if (savedInstanceState != null) {
            transientReason = savedInstanceState.getString("transientReason")
            sentFlashUntil = savedInstanceState.getLong("sentFlashUntil")
            copiedUntil = savedInstanceState.getLong("copiedUntil")
        }

        stateListener = ServiceStateHolder.StateListener { snapshot ->
            render(StatusMapper.map(snapshot))
        }
        sendListener = ServiceStateHolder.SendListener { event ->
            if (!event.quiet) onSendEvent(event)
        }
    }

    override fun onResume() {
        super.onResume()
        ServiceStateHolder.addStateListener(stateListener!!)
        ServiceStateHolder.addSendListener(sendListener!!)
        requestStatusRefresh()
        clipboardManager = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboardManager?.addPrimaryClipChangedListener(clipListener)
        pollClipboardOnResume()
    }

    override fun onPause() {
        lastSeenHash = currentClipboardText()?.let { ClipboardHelper.contentHash(it) }
        clipboardManager?.removePrimaryClipChangedListener(clipListener)
        clipboardManager = null
        pendingDebounce?.let { debounceHandler.removeCallbacks(it) }
        pendingDebounce = null
        stateListener?.let { ServiceStateHolder.removeStateListener(it) }
        sendListener?.let { ServiceStateHolder.removeSendListener(it) }
        sentRestore?.let { uiHandler.removeCallbacks(it) }
        copiedRestore?.let { uiHandler.removeCallbacks(it) }
        super.onPause()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString("transientReason", transientReason)
        outState.putLong("sentFlashUntil", sentFlashUntil)
        outState.putLong("copiedUntil", copiedUntil)
    }

    // --- sync control -----------------------------------------------------

    private fun turnSyncOn() {
        if (preferences?.isConfigured() != true) {
            // No key yet: send them to Settings instead of starting.
            setSwitchChecked(false)
            openSettings(scrollToKey = true)
            return
        }
        // Ask for notification permission the first time sync is turned on,
        // with a one-sentence explanation — never at app launch.
        if (needsNotifPermission() && preferences?.askedNotifications != true) {
            android.app.AlertDialog.Builder(this)
                .setMessage(R.string.notif_rationale)
                .setPositiveButton(R.string.notif_allow) { _, _ ->
                    preferences?.askedNotifications = true
                    requestPermissions(
                        arrayOf(android.Manifest.permission.POST_NOTIFICATIONS),
                        REQUEST_NOTIFICATIONS
                    )
                }
                .setNegativeButton(R.string.notif_later) { _, _ ->
                    startService()
                }
                .setOnCancelListener {
                    setSwitchChecked(false)
                }
                .show()
            return
        }
        startService()
    }

    private fun needsNotifPermission(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
        return checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) !=
            android.content.pm.PackageManager.PERMISSION_GRANTED
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_NOTIFICATIONS) {
            // Start regardless; a denial surfaces as the dismissible hint.
            if (ServiceStateHolder.last.configured) startService()
            else setSwitchChecked(false)
        }
    }

    private fun startService() {
        val intent = Intent(this, ClipcastService::class.java).apply {
            action = ClipcastService.ACTION_START
        }
        startForegroundService(intent)
        setSwitchChecked(true)
    }

    private fun stopService() {
        val intent = Intent(this, ClipcastService::class.java).apply {
            action = ClipcastService.ACTION_STOP
        }
        startService(intent)
        setSwitchChecked(false)
    }

    private fun setSwitchChecked(checked: Boolean) {
        updatingSwitch = true
        serviceSwitch.isChecked = checked
        updatingSwitch = false
    }

    private fun openSettings(scrollToKey: Boolean) {
        startActivity(
            Intent(this, SettingsActivity::class.java).apply {
                putExtra(EXTRA_SCROLL_TO_KEY, scrollToKey)
            }
        )
    }

    private fun requestStatusRefresh() {
        try {
            startService(
                Intent(this, ClipcastService::class.java).apply {
                    action = ClipcastService.ACTION_QUERY_STATUS
                }
            )
        } catch (e: Exception) {
            // Service not running yet; holder replay covers the defaults.
        }
    }

    // --- rendering --------------------------------------------------------

    private fun render(screen: StatusMapper.MainScreen) {
        lastScreen = screen
        val now = System.currentTimeMillis()

        if (animatorsEnabled()) {
            TransitionManager.beginDelayedTransition(statusCard as ViewGroup, Fade())
        }
        renderStatus(screen)
        renderActivity(screen, now)
        renderSend(screen, now)
        renderFirstRun()
        renderHint(screen)
    }

    private fun renderFirstRun() {
        val show = preferences?.isConfigured() != true
        firstRunCard.visibility = if (show) View.VISIBLE else View.GONE
        if (!show) firstRunError.visibility = View.GONE
    }

    /** Validates the clipboard key, saves it, and starts sync. */
    private fun pasteKeyFromClipboard() {
        val pasted = try {
            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            if (!cm.hasPrimaryClip()) null
            else cm.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()
        } catch (e: Exception) {
            null
        }
        val result = SettingsValidation.validateKey(pasted)
        if (result is SettingsValidation.KeyResult.Valid) {
            preferences?.encryptionKey = SettingsValidation.canonicalKey(pasted)
            firstRunError.visibility = View.GONE
            startService()
        } else {
            firstRunError.visibility = View.VISIBLE
            firstRunError.text = when (result) {
                is SettingsValidation.KeyResult.Invalid -> result.reason
                else -> getString(R.string.key_paste_fail)
            }
            firstRunError.setTextColor(tintFor(R.attr.clipStatusError))
        }
    }

    // --- conditional hints (at most one, dismissible) -------------------------

    private enum class Hint { NOTIFICATIONS, BATTERY }

    private var activeHint: Hint? = null

    private fun renderHint(screen: StatusMapper.MainScreen) {
        activeHint = when {
            notifHintDue() -> Hint.NOTIFICATIONS
            batteryHintDue() -> Hint.BATTERY
            else -> null
        }
        when (val hint = activeHint) {
            null -> hintCard.visibility = View.GONE
            Hint.NOTIFICATIONS -> {
                hintCard.visibility = View.VISIBLE
                hintText.setText(R.string.hint_notifications)
                hintAction.setText(R.string.hint_notifications_action)
                hintAction.setOnClickListener { openNotificationSettings() }
            }
            Hint.BATTERY -> {
                hintCard.visibility = View.VISIBLE
                hintText.setText(R.string.hint_battery)
                hintAction.setText(R.string.hint_battery_action)
                hintAction.setOnClickListener { openBatterySettings() }
            }
        }
    }

    private fun notifHintDue(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return false
        if (preferences?.hintNotifDismissed == true) return false
        if (preferences?.askedNotifications != true) return false
        return !hasNotifPermission()
    }

    private fun hasNotifPermission(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return true
        return checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
    }

    private fun batteryHintDue(): Boolean {
        if (!ServiceStateHolder.last.running) return false
        if (preferences?.hintBatteryDismissed == true) return false
        val pm: android.os.PowerManager = try {
            getSystemService(Context.POWER_SERVICE) as android.os.PowerManager
        } catch (e: Exception) {
            return false
        }
        return !pm.isIgnoringBatteryOptimizations(packageName)
    }

    private fun dismissCurrentHint() {
        when (activeHint) {
            Hint.NOTIFICATIONS -> preferences?.hintNotifDismissed = true
            Hint.BATTERY -> preferences?.hintBatteryDismissed = true
            null -> return
        }
        lastScreen?.let { renderHint(it) }
    }

    private fun openNotificationSettings() {
        try {
            startActivity(
                Intent(android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
                    putExtra(android.provider.Settings.EXTRA_APP_PACKAGE, packageName)
                }
            )
        } catch (e: Exception) {
            // OEM without this screen; the hint can be dismissed.
        }
    }

    private fun openBatterySettings() {
        try {
            startActivity(
                Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
            )
        } catch (e: Exception) {
            // OEM without this screen; the hint can be dismissed.
        }
    }

    private fun renderStatus(screen: StatusMapper.MainScreen) {
        statusTappable = screen.statusTappable
        statusCard.isClickable = screen.statusTappable
        statusCard.isFocusable = screen.statusTappable
        statusCard.foreground = if (screen.statusTappable) {
            val ripple = obtainStyledAttributes(
                intArrayOf(android.R.attr.selectableItemBackground)
            )
            val drawable = ripple.getDrawable(0)
            ripple.recycle()
            drawable
        } else {
            null
        }
        when (val st = screen.status) {
            is StatusMapper.MainStatus.On -> {
                tintDot(R.attr.clipStatusOk)
                statusTitle.setText(R.string.status_on)
                currentIpLine = st.ipLine?.substringBefore(" · ")
                if (st.ipLine != null) {
                    statusSub.visibility = View.VISIBLE
                    statusSub.text = st.ipLine
                    statusSub.setTypeface(android.graphics.Typeface.MONOSPACE)
                } else {
                    statusSub.visibility = View.GONE
                }
            }
            is StatusMapper.MainStatus.Off -> {
                tintDotSecondary()
                statusTitle.setText(R.string.status_off)
                statusSub.visibility = View.GONE
                currentIpLine = null
            }
            is StatusMapper.MainStatus.WaitingWifi -> {
                tintDot(R.attr.clipStatusWarn)
                statusTitle.setText(R.string.status_waiting_wifi)
                statusSub.visibility = View.GONE
                currentIpLine = null
            }
            is StatusMapper.MainStatus.NeedsSetup -> {
                tintDot(R.attr.clipStatusWarn)
                statusTitle.setText(R.string.status_needs_setup)
                statusSub.visibility = View.VISIBLE
                statusSub.text = getString(R.string.status_sub_no_key)
                statusSub.setTypeface(android.graphics.Typeface.DEFAULT)
                currentIpLine = null
            }
            is StatusMapper.MainStatus.Error -> {
                tintDot(R.attr.clipStatusError)
                statusTitle.text = st.reason
                statusSub.visibility = View.VISIBLE
                statusSub.text = getString(R.string.status_fix_in_settings)
                statusSub.setTypeface(android.graphics.Typeface.DEFAULT)
                currentIpLine = null
            }
        }
        // "Copied" feedback rides on the sub line; restore it below.
        if (nowMs() < copiedUntil && currentIpLine != null) {
            showCopiedFeedback()
        }
        setSwitchChecked(ServiceStateHolder.last.running)
        serviceSwitch.contentDescription = if (ServiceStateHolder.last.running) {
            getString(R.string.status_on)
        } else {
            getString(R.string.status_off)
        }
    }

    private fun renderActivity(screen: StatusMapper.MainScreen, now: Long) {
        if (screen.empty) {
            emptyView.visibility = View.VISIBLE
            rowReceived.visibility = View.GONE
            detailReceived.visibility = View.GONE
            rowSent.visibility = View.GONE
            detailSent.visibility = View.GONE
            return
        }
        emptyView.visibility = View.GONE
        renderRow(
            screen.received, rowReceived, receivedTime, receivedSize,
            receivedGlyph, detailReceived, now, R.string.activity_received
        )
        renderRow(
            screen.sent, rowSent, sentTime, sentSize,
            sentGlyph, detailSent, now, R.string.activity_sent
        )
    }

    private fun renderRow(
        row: StatusMapper.ActivityRow?,
        rowView: View,
        timeView: TextView,
        sizeView: TextView,
        glyphView: ImageView,
        detailView: TextView,
        now: Long,
        labelRes: Int
    ) {
        if (row == null) {
            rowView.visibility = View.GONE
            detailView.visibility = View.GONE
            return
        }
        rowView.visibility = View.VISIBLE
        val timeText = DateUtils.getRelativeTimeSpanString(
            row.timeMs, now, DateUtils.MINUTE_IN_MILLIS
        ).toString()
        timeView.text = timeText
        sizeView.text = UiFormat.humanSize(row.bytes)
        glyphView.setImageResource(if (row.ok) R.drawable.ic_check else R.drawable.ic_cross)
        glyphView.imageTintList = tintFor(if (row.ok) R.attr.clipStatusOk else R.attr.clipStatusError)
        val label = getString(labelRes)
        val outcome = if (row.ok) "succeeded" else "failed"
        rowView.contentDescription = "$label $timeText, ${UiFormat.talkSize(row.bytes)}, $outcome"
        if (row.detail != null) {
            detailView.visibility = View.VISIBLE
            detailView.text = row.detail
        } else {
            detailView.visibility = View.GONE
        }
    }

    private fun renderSend(screen: StatusMapper.MainScreen, now: Long) {
        sendButton.isEnabled = screen.sendEnabled
        if (now < sentFlashUntil) {
            // Keep the brief "Sent" state; the restore runnable resets it.
            scheduleSentRestore()
        } else {
            sendButton.setText(R.string.btn_send_now)
        }
        val reason = transientReason ?: when {
            !screen.sendEnabled -> reasonFor(screen.sendReason)
            else -> null
        }
        if (reason != null) {
            sendReason.visibility = View.VISIBLE
            sendReason.text = reason
        } else {
            sendReason.visibility = View.GONE
        }
    }

    private fun reasonFor(mapped: String?): String? {
        // Mapper strings are already resource-free plain words; resolve the
        // two disabled cases to localized text.
        if (mapped == null) return null
        return when (mapped) {
            "Add your key in Settings to send" -> getString(R.string.send_reason_no_key)
            "Turn sync on to send" -> getString(R.string.send_reason_off)
            else -> mapped
        }
    }

    // --- send flow --------------------------------------------------------

    private fun sendClipboardNow() {
        val text = currentClipboardTextForSend() ?: ClipboardHelper.getText(this)
        if (text.isNullOrEmpty()) {
            showTransientReason(getString(R.string.send_empty))
            return
        }
        if (text.toByteArray(Charsets.UTF_8).size > com.clipcast.protocol.LargeTextLimits.DEFAULT_MAX_SEND_BYTES) {
            showTransientReason(getString(R.string.toast_too_large, text.length))
            return
        }
        lastSeenHash = ClipboardHelper.contentHash(text)
        transientReason = null

        startService(
            Intent(this, ClipcastService::class.java).apply {
                action = ClipcastService.ACTION_SEND_CLIPBOARD
                putExtra(ClipcastService.EXTRA_TEXT, text)
                putExtra(ClipcastService.EXTRA_QUIET, false)
            }
        )
        // No toast: Android 12+ already shows its own clipboard-access notice.
    }

    /**
     * Reads the clipboard through the resumed listener path when possible so
     * sensitive-clip filtering stays in one place.
     */
    private fun currentClipboardTextForSend(): String? {
        return if (clipboardManager != null) currentClipboardText() else null
    }

    private fun onSendEvent(event: ServiceStateHolder.SendEvent) {
        if (event.success) {
            sentFlashUntil = nowMs() + SENT_FLASH_MS
            transientReason = null
            sendButton.text = getString(
                R.string.send_sent, UiFormat.humanSize(event.length.toLong())
            )
            sendButton.performHapticFeedback(HapticFeedbackConstants.VIRTUAL_KEY)
            scheduleSentRestore()
            renderSend(lastScreen ?: return, nowMs())
        } else {
            sentFlashUntil = 0
            showTransientReason(
                if (event.tooLarge) getString(R.string.toast_too_large, event.length)
                else getString(R.string.toast_sent_fail)
            )
        }
    }

    private fun scheduleSentRestore() {
        sentRestore?.let { uiHandler.removeCallbacks(it) }
        val task = Runnable {
            sentFlashUntil = 0
            sendButton.setText(R.string.btn_send_now)
            lastScreen?.let { renderSend(it, nowMs()) }
        }
        sentRestore = task
        uiHandler.postDelayed(task, SENT_FLASH_MS)
    }

    private fun showTransientReason(reason: String) {
        transientReason = reason
        lastScreen?.let { renderSend(it, nowMs()) }
    }

    private fun copyIp(ip: String) {
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        cm.setPrimaryClip(ClipData.newPlainText("clipcast ip", ip))
        // Don't auto-send our own copy: mark it seen on every path.
        val hash = ClipboardHelper.contentHash(ip)
        lastSeenHash = hash
        lastAutoSentHash = hash
        lastAutoSentTime = nowMs()
        copiedUntil = nowMs() + COPIED_MS
        showCopiedFeedback()
        copiedRestore?.let { uiHandler.removeCallbacks(it) }
        val task = Runnable {
            copiedUntil = 0
            lastScreen?.let { renderStatus(it) }
        }
        copiedRestore = task
        uiHandler.postDelayed(task, COPIED_MS)
    }

    private fun showCopiedFeedback() {
        statusSub.visibility = View.VISIBLE
        statusSub.text = getString(R.string.copied)
        statusSub.setTypeface(android.graphics.Typeface.DEFAULT)
    }

    // --- clipboard auto-send (unchanged behavior) --------------------------

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

    private fun autoSendClipboard() {
        if (clipboardManager == null) return
        considerAutoSend(currentClipboardText())
    }

    private fun pollClipboardOnResume() {
        if (clipboardManager == null) return
        val text = currentClipboardText() ?: return
        val hash = ClipboardHelper.contentHash(text)
        if (hash == lastSeenHash) return
        considerAutoSend(text)
    }

    /** Shared quiet-send core for the listener and the resume poll. */
    private fun considerAutoSend(text: String?) {
        if (text.isNullOrEmpty()) return
        if (text.toByteArray(Charsets.UTF_8).size >
            com.clipcast.protocol.LargeTextLimits.DEFAULT_MAX_SEND_BYTES
        ) {
            // Quiet send: oversize auto-sends stay silent (no toast storm).
            return
        }
        val now = System.currentTimeMillis()
        if (!ClipboardHelper.shouldAutoSend(text, lastAutoSentHash, lastAutoSentTime, now)) return
        lastAutoSentHash = ClipboardHelper.contentHash(text)
        lastAutoSentTime = now
        lastSeenHash = lastAutoSentHash

        startService(
            Intent(this, ClipcastService::class.java).apply {
                action = ClipcastService.ACTION_SEND_CLIPBOARD
                putExtra(ClipcastService.EXTRA_TEXT, text)
                putExtra(ClipcastService.EXTRA_QUIET, true)
            }
        )
    }

    // --- small helpers -----------------------------------------------------

    private fun nowMs(): Long = System.currentTimeMillis()

    private fun animatorsEnabled(): Boolean {
        return android.animation.ValueAnimator.areAnimatorsEnabled()
    }

    private fun tintDot(attr: Int) {
        statusDot.backgroundTintList = tintFor(attr)
    }

    private fun tintDotSecondary() {
        val out = android.util.TypedValue()
        theme.resolveAttribute(android.R.attr.textColorSecondary, out, true)
        statusDot.backgroundTintList = android.content.res.ColorStateList.valueOf(out.data)
    }

    private fun tintFor(attr: Int): android.content.res.ColorStateList {
        val out = android.util.TypedValue()
        theme.resolveAttribute(attr, out, true)
        return android.content.res.ColorStateList.valueOf(out.data)
    }
}
