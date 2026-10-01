package com.clipcast.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import android.os.Looper
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import com.clipcast.ClipcastApplication
import com.clipcast.R
import com.clipcast.protocol.Crypto
import com.clipcast.protocol.SyncState
import com.clipcast.ui.MainActivity
import com.clipcast.ui.SendActivity
import com.clipcast.util.ClipboardHelper
import com.clipcast.util.Preferences
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class ClipcastService : Service() {
    companion object {
        const val ACTION_START = "com.clipcast.ACTION_START"
        const val ACTION_STOP = "com.clipcast.ACTION_STOP"
        const val ACTION_SEND_CLIPBOARD = "com.clipcast.ACTION_SEND_CLIPBOARD"
        const val ACTION_QUERY_STATUS = "com.clipcast.ACTION_QUERY_STATUS"
        const val EXTRA_TEXT = "extra_text"
        const val EXTRA_QUIET = "extra_quiet"

        const val BROADCAST_STATUS = "com.clipcast.BROADCAST_STATUS"
        const val EXTRA_STATUS = "extra_status"
        const val EXTRA_BROADCAST_ADDR = "extra_broadcast_addr"
        const val EXTRA_LAST_RX_TIME = "extra_last_rx_time"
        const val EXTRA_LAST_RX_LEN = "extra_last_rx_len"
        const val EXTRA_LAST_TX_TIME = "extra_last_tx_time"
        const val EXTRA_LAST_TX_LEN = "extra_last_tx_len"

        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "clipcast_sync"
        private const val RECEIVE_BUFFER_SIZE = 1400
        private const val MAX_MESSAGES_PER_SECOND = 20
    }

    private var preferences: Preferences? = null
    private var syncState: SyncState? = null
    private var networkManager: NetworkManager? = null
    private var multicastLock: WifiManager.MulticastLock? = null
    private var receiveSocket: DatagramSocket? = null
    private var receiveThread: Thread? = null
    private var sendExecutor = Executors.newSingleThreadExecutor()
    private var isRunning = false
    private var currentPort = 47474
    private var currentBroadcastAddress: InetAddress? = null
    private var lastRxTime: Long = 0
    private var lastRxLen: Int = 0
    private var lastTxTime: Long = 0
    private var lastTxLen: Int = 0

    private var lastAppliedContentHash: String? = null
    private var lastAppliedTime: Long = 0
    private var messageTimestamps = mutableListOf<Long>()
    private val messageTimestampsLock = Any()

    override fun onCreate() {
        super.onCreate()
        preferences = Preferences.getInstance(this)
        syncState = SyncState()
        networkManager = NetworkManager(this).apply {
            setListener(object : NetworkManager.BroadcastAddressListener {
                override fun onBroadcastAddressChanged(address: InetAddress?) {
                    currentBroadcastAddress = address
                    broadcastStatus()
                }
            })
        }
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        when (action) {
            ACTION_START -> startServiceLogic()
            ACTION_STOP -> stopServiceLogic()
            ACTION_QUERY_STATUS -> broadcastStatus()
            ACTION_SEND_CLIPBOARD -> {
                val text = intent.getStringExtra(EXTRA_TEXT)
                val quiet = intent.getBooleanExtra(EXTRA_QUIET, false)
                if (text != null) {
                    sendText(text, quiet)
                }
            }
        }
        return START_STICKY
    }

    private fun startServiceLogic() {
        if (isRunning) return

        val keyBytes = preferences?.getKeyBytes() ?: return
        val port = preferences?.port ?: 47474
        currentPort = port

        val wifiManager = getSystemService(Context.WIFI_SERVICE) as WifiManager
        multicastLock = wifiManager.createMulticastLock("clipcast_multicast")
        multicastLock?.acquire()

        networkManager?.start()

        try {
            receiveSocket = DatagramSocket(port).apply {
                setBroadcast(true)
                setReuseAddress(true)
                setSoTimeout(1000)
            }
        } catch (e: Exception) {
            Log.e("ClipcastService", "Failed to bind socket", e)
            stopServiceLogic()
            return
        }

        isRunning = true
        receiveThread = Thread(this::receiveLoop, "ClipcastReceive").apply { start() }

        startForeground(NOTIFICATION_ID, buildNotification())
        broadcastStatus()
    }

    private fun stopServiceLogic() {
        if (!isRunning) return

        isRunning = false

        receiveThread?.interrupt()
        receiveThread = null

        receiveSocket?.close()
        receiveSocket = null

        multicastLock?.release()
        multicastLock = null

        networkManager?.stop()

        sendExecutor.shutdown()
        try {
            sendExecutor.awaitTermination(1, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        sendExecutor = Executors.newSingleThreadExecutor()

        stopForeground(true)
        stopSelf()
        broadcastStatus()
    }

    private fun receiveLoop() {
        val buffer = ByteArray(RECEIVE_BUFFER_SIZE)
        val packet = DatagramPacket(buffer, buffer.size)

        while (isRunning && !Thread.currentThread().isInterrupted) {
            try {
                receiveSocket?.receive(packet)
                val receivedLength = packet.length
                val data = buffer.copyOfRange(0, receivedLength)
                processReceivedPacket(data)
            } catch (e: java.net.SocketTimeoutException) {
            } catch (e: Exception) {
                if (isRunning) {
                    Log.w("ClipcastService", "Receive error", e)
                }
            }
        }
    }

    private fun processReceivedPacket(data: ByteArray) {
        val keyBytes = preferences?.getKeyBytes() ?: return
        val decoded = Crypto.decode(keyBytes, data) ?: return

        val now = System.currentTimeMillis()
        synchronized(messageTimestampsLock) {
            messageTimestamps.add(now)
            messageTimestamps.removeAll { now - it > 1000 }
            if (messageTimestamps.size > MAX_MESSAGES_PER_SECOND) {
                return
            }
        }

        val ourDeviceId = preferences?.deviceId ?: return
        if (Crypto.bytesToHex(decoded.deviceId) == Crypto.bytesToHex(ourDeviceId)) {
            return
        }

        val shouldApply = syncState?.onReceive(decoded.lamport, decoded.deviceId) ?: false
        if (!shouldApply) {
            return
        }

        val payloadText = try {
            String(decoded.payload, java.nio.charset.StandardCharsets.UTF_8)
        } catch (e: Exception) {
            return
        }

        val contentHash = ClipboardHelper.contentHash(payloadText)
        if (contentHash == lastAppliedContentHash && now - lastAppliedTime < 1000) {
            return
        }

        lastAppliedContentHash = contentHash
        lastAppliedTime = now

        Looper.getMainLooper().let { mainLooper ->
            android.os.Handler(mainLooper).post {
                ClipboardHelper.setText(this@ClipcastService, payloadText)
            }
        }

        lastRxTime = System.currentTimeMillis()
        lastRxLen = decoded.payload.size
        broadcastStatus()
    }

    fun sendText(text: String, quiet: Boolean = false) {
        if (!isRunning) {
            broadcastSendResult(false, text.length, quiet)
            return
        }
        if (!ClipboardHelper.isValidForSend(text)) {
            broadcastSendResult(false, text.length, quiet)
            return
        }

        // Echo prevention: never rebroadcast text we just applied from remote.
        val now = System.currentTimeMillis()
        val hash = ClipboardHelper.contentHash(text)
        if (hash == lastAppliedContentHash && now - lastAppliedTime < 1000) {
            Log.d("ClipcastService", "dropping echo of just-applied remote content")
            return
        }

        sendExecutor.execute {
            val keyBytes = preferences?.getKeyBytes() ?: return@execute
            val deviceId = preferences?.deviceId ?: return@execute
            val broadcastAddr = currentBroadcastAddress ?: return@execute
            val port = currentPort

            val nowMs = System.currentTimeMillis()
            val lamport = syncState?.onLocalSend(nowMs, deviceId) ?: nowMs

            val payload = text.toByteArray(charset = java.nio.charset.StandardCharsets.UTF_8)
            val datagram = Crypto.encode(keyBytes, deviceId, lamport, nowMs, payload) ?: return@execute

            try {
                val packet = DatagramPacket(datagram, datagram.size, broadcastAddr, port)
                receiveSocket?.send(packet)

                lastTxTime = System.currentTimeMillis()
                lastTxLen = payload.size
                broadcastStatus()
                broadcastSendResult(true, payload.size, quiet)
            } catch (e: Exception) {
                Log.w("ClipcastService", "Send error", e)
                broadcastSendResult(false, payload.size, quiet)
            }
        }
    }

    private fun broadcastSendResult(success: Boolean, length: Int, quiet: Boolean = false) {
        val intent = Intent("com.clipcast.SEND_RESULT")
        intent.putExtra("success", success)
        intent.putExtra("length", length)
        intent.putExtra(EXTRA_QUIET, quiet)
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent)
    }

    private fun broadcastStatus() {
        val intent = Intent(BROADCAST_STATUS)
        intent.putExtra(EXTRA_STATUS, if (isRunning) "running" else "stopped")
        intent.putExtra(EXTRA_BROADCAST_ADDR, currentBroadcastAddress?.hostAddress ?: "none")
        intent.putExtra(EXTRA_LAST_RX_TIME, lastRxTime)
        intent.putExtra(EXTRA_LAST_RX_LEN, lastRxLen)
        intent.putExtra(EXTRA_LAST_TX_TIME, lastTxTime)
        intent.putExtra(EXTRA_LAST_TX_LEN, lastTxLen)
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent)
    }

    private fun buildNotification(): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPendingIntent = PendingIntent.getActivity(
            this, 0, openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val sendIntent = Intent(this, SendActivity::class.java)
        val sendPendingIntent = PendingIntent.getActivity(
            this, 1, sendIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val stopIntent = Intent(this, ClipcastService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            this, 2, stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_upload)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setContentIntent(openPendingIntent)
            .addAction(android.R.drawable.ic_menu_send, getString(R.string.notification_action_send), sendPendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, "Stop", stopPendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_desc)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    override fun onDestroy() {
        stopServiceLogic()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null
}