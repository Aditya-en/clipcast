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
import com.clipcast.ClipcastApplication
import com.clipcast.R
import com.clipcast.protocol.Crypto
import com.clipcast.protocol.LargeTextLimits
import com.clipcast.protocol.SyncState
import com.clipcast.protocol.TcpCrypto
import com.clipcast.ui.MainActivity
import com.clipcast.ui.SendActivity
import com.clipcast.ui.ServiceStateHolder
import com.clipcast.util.ClipboardHelper
import com.clipcast.util.Preferences
import java.io.File
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class ClipcastService : Service() {
    companion object {
        const val ACTION_START = "com.clipcast.ACTION_START"
        const val ACTION_STOP = "com.clipcast.ACTION_STOP"
        const val ACTION_SEND_CLIPBOARD = "com.clipcast.ACTION_SEND_CLIPBOARD"
        const val ACTION_QUERY_STATUS = "com.clipcast.ACTION_QUERY_STATUS"
        const val EXTRA_TEXT = "extra_text"
        const val EXTRA_QUIET = "extra_quiet"
        /** Absolute path of a staged image file under our cache dir. */
        const val EXTRA_IMAGE_PATH = "extra_image_path"
        /** MIME type of the staged image (allowlisted). */
        const val EXTRA_IMAGE_MIME = "extra_image_mime"

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

    // UI hooks (no protocol impact): structured error/outcome state for the
    // status screen, published through ServiceStateHolder.
    private var lastUdpError: String? = null
    private var lastTcpError: String? = null
    private var lastSendOk: Boolean = true
    private var lastSendError: String? = null

    // Large-text side channel (v2).
    private var transferStore: TransferStore? = null
    private var imageCache: ImageCache? = null
    private var tcpServer: TcpServer? = null
    private var fetchExecutor = Executors.newFixedThreadPool(LargeTextLimits.MAX_CONCURRENT_FETCHES)
    private val fetchLock = Any()
    private var fetchGeneration = 0
    private val activeFetches = mutableMapOf<Int, FetchHandle>()
    /** Transfer ids with a live image fetch: re-announces never start a second download. */
    private val activeImageTransfers = mutableSetOf<String>()
    private var tcpStatus: String = "TCP stopped"
    private var lastTransfer: String = "none"
    private var lastRxIsImage: Boolean = false
    private var lastTxIsImage: Boolean = false

    private class FetchHandle {
        val cancel = AtomicBoolean(false)
        val socketRef: AtomicReference<Socket?> = AtomicReference(null)
    }

    override fun onCreate() {
        super.onCreate()
        preferences = Preferences.getInstance(this)
        syncState = SyncState()
        networkManager = NetworkManager(this).apply {
            setListener(object : NetworkManager.BroadcastAddressListener {
                override fun onBroadcastAddressChanged(address: InetAddress?) {
                    currentBroadcastAddress = address
                    refreshNotification()
                    publishState()
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
            ACTION_QUERY_STATUS -> publishState()
            ACTION_SEND_CLIPBOARD -> {
                val imagePath = intent.getStringExtra(EXTRA_IMAGE_PATH)
                val imageMime = intent.getStringExtra(EXTRA_IMAGE_MIME)
                val text = intent.getStringExtra(EXTRA_TEXT)
                val quiet = intent.getBooleanExtra(EXTRA_QUIET, false)
                if (imagePath != null && imageMime != null) {
                    sendImageFile(imagePath, imageMime, quiet)
                } else if (text != null) {
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
        lastUdpError = null

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
            lastUdpError = "UDP port $port in use"
            stopServiceLogic()
            return
        }

        isRunning = true
        receiveThread = Thread(this::receiveLoop, "ClipcastReceive").apply { start() }

        // Large-text side channel: serve our pending transfers over TCP.
        // The listener only works while this service is alive (see README).
        val store = TransferStore().also { transferStore = it }
        val images = ImageCache(File(cacheDir, "send_images")).also { imageCache = it }
        // Drop orphaned staging files (e.g. the process died mid-send).
        try {
            File(cacheDir, "send_staging").listFiles()?.forEach { file ->
                if (System.currentTimeMillis() - file.lastModified() > 3_600_000) {
                    file.delete()
                }
            }
        } catch (e: Exception) {
            Log.d("ClipcastService", "staging cleanup failed", e)
        }
        val tcpPort = preferences?.tcpPort ?: LargeTextLimits.DEFAULT_TCP_PORT
        val server = TcpServer(
            tcpPort,
            keyProvider = { preferences?.getKeyBytes() },
            store = store,
            imageCache = images,
            listener = object : TcpServer.Listener {
                override fun onListening(port: Int) {
                    tcpStatus = "TCP listening on port $port"
                    lastTcpError = null
                    publishState()
                }

                override fun onError(message: String) {
                    tcpStatus = message
                    lastTcpError = message
                    publishState()
                }
            },
            log = { msg -> Log.d("ClipcastTcp", msg) }
        )
        tcpServer = server
        lastTcpError = null
        tcpStatus = if (server.start()) {
            "TCP listening on port ${server.localPort}"
        } else {
            lastTcpError = "TCP port $tcpPort in use"
            "TCP port $tcpPort in use"
        }

        startForeground(NOTIFICATION_ID, buildNotification())
        publishState()
    }

    private fun stopServiceLogic() {
        if (!isRunning) return

        isRunning = false

        cancelActiveFetches("service stopping")

        receiveThread?.interrupt()
        receiveThread = null

        receiveSocket?.close()
        receiveSocket = null

        tcpServer?.stop()
        tcpServer = null
        transferStore = null
        imageCache = null
        tcpStatus = "TCP stopped"

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

        fetchExecutor.shutdown()
        try {
            fetchExecutor.awaitTermination(5, TimeUnit.SECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        fetchExecutor = Executors.newFixedThreadPool(LargeTextLimits.MAX_CONCURRENT_FETCHES)
        synchronized(fetchLock) {
            activeFetches.clear()
            fetchGeneration = 0
        }

        stopForeground(true)
        stopSelf()
        publishState()
    }

    private fun receiveLoop() {
        val buffer = ByteArray(RECEIVE_BUFFER_SIZE)
        val packet = DatagramPacket(buffer, buffer.size)

        while (isRunning && !Thread.currentThread().isInterrupted) {
            try {
                receiveSocket?.receive(packet)
                val receivedLength = packet.length
                val data = buffer.copyOfRange(0, receivedLength)
                val source = packet.address
                processReceivedPacket(data, source)
            } catch (e: java.net.SocketTimeoutException) {
            } catch (e: Exception) {
                if (isRunning) {
                    Log.w("ClipcastService", "Receive error", e)
                }
            }
        }
    }

    private fun processReceivedPacket(data: ByteArray, source: InetAddress? = null) {
        val keyBytes = preferences?.getKeyBytes() ?: return
        // v1 small-text path first: behavior unchanged.
        val decoded = Crypto.decode(keyBytes, data)
        if (decoded != null) {
            processV1Message(decoded)
            return
        }
        // Large-text announce (content_type 0x80, 59-byte payload).
        val announce = Crypto.decodeAnnounce(keyBytes, data)
        if (announce != null) {
            if (source != null) processAnnounce(announce, source)
            return
        }
        // Image announce (content_type 0x80, 60..123-byte payload).
        val imageAnnounce = Crypto.decodeImageAnnounce(keyBytes, data) ?: return
        if (source != null) {
            processImageAnnounce(imageAnnounce, source)
        }
    }

    /** Shared inbound rate limit: max 20 messages/second. */
    private fun checkRateLimit(now: Long): Boolean {
        synchronized(messageTimestampsLock) {
            messageTimestamps.add(now)
            messageTimestamps.removeAll { now - it > 1000 }
            if (messageTimestamps.size > MAX_MESSAGES_PER_SECOND) {
                return false
            }
        }
        return true
    }

    private fun processV1Message(decoded: Crypto.DecodedMessage) {
        val now = System.currentTimeMillis()
        if (!checkRateLimit(now)) {
            return
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
        publishState()
    }

    /**
     * Large-text announce path (content_type 0x80). Runs the same ordering
     * checks as v1 through [SyncState.onReceive]; when accepted,
     * last_applied advances immediately, then the content is fetched over TCP
     * from the announce's UDP source address on a worker thread.
     */
    private fun processAnnounce(announce: Crypto.DecodedAnnounce, source: InetAddress) {
        val now = System.currentTimeMillis()
        if (!checkRateLimit(now)) {
            return
        }

        val ourDeviceId = preferences?.deviceId ?: return
        if (announce.deviceId.contentEquals(ourDeviceId)) {
            return
        }

        val shouldApply = syncState?.onReceive(announce.lamport, announce.deviceId) ?: false
        if (!shouldApply) {
            return
        }
        // Accepted: last_applied already advanced by onReceive.

        val maxApply = (preferences?.maxApplyBytes
            ?: LargeTextLimits.DEFAULT_MAX_APPLY_BYTES).toLong()
        val announceHashHex = Crypto.bytesToHex(announce.sha256)
        when (AnnouncePolicy.decide(
            announce.totalLen, maxApply, announce.innerContentType,
            announceHashHex, lastAppliedContentHash
        )) {
            AnnouncePolicy.Decision.SKIP_OVER_LIMIT -> {
                Log.d("ClipcastService", "announce total_len ${announce.totalLen} exceeds max_apply $maxApply; skipping")
                // Brief, non-intrusive notice via the status line (no toast storm).
                lastTransfer =
                    "Text too large for the Android clipboard (${announce.totalLen} bytes, max $maxApply)"
                publishState()
                return
            }
            AnnouncePolicy.Decision.SKIP_UNKNOWN_TYPE -> {
                Log.d("ClipcastService", "ignoring announce with unknown inner_content_type ${announce.innerContentType}")
                return
            }
            AnnouncePolicy.Decision.SKIP_DUPLICATE -> {
                Log.d("ClipcastService", "ignoring announce matching already-applied content")
                return
            }
            AnnouncePolicy.Decision.FETCH -> Unit
        }

        enqueueFetch(
            FetchJob(
                transferId = announce.transferId.copyOf(),
                totalLen = announce.totalLen,
                sha256 = announce.sha256.copyOf(),
                tcpPort = announce.tcpPort,
                innerContentType = announce.innerContentType,
                mimeType = null,
                maxBytes = maxApply,
                source = source,
                isImage = false
            )
        )
    }

    /**
     * Image announce path (content_type 0x80, inner 0x02). Same ordering
     * machinery as text; the fetched bytes are verified (length, SHA-256)
     * and published to the clipboard as a content URI under the announced
     * MIME type. Nothing is applied before verification.
     */
    private fun processImageAnnounce(announce: Crypto.DecodedImageAnnounce, source: InetAddress) {
        val now = System.currentTimeMillis()
        if (!checkRateLimit(now)) {
            return
        }

        val ourDeviceId = preferences?.deviceId ?: return
        if (announce.deviceId.contentEquals(ourDeviceId)) {
            return
        }

        // Same transfer already downloading: never start a second download.
        // Checked before ordering so a re-announce disturbs nothing.
        val transferHex = Crypto.bytesToHex(announce.transferId)
        synchronized(fetchLock) {
            if (activeImageTransfers.contains(transferHex)) {
                Log.d("ClipcastService", "ignoring duplicate announce for in-flight image transfer")
                return
            }
        }

        val shouldApply = syncState?.onReceive(announce.lamport, announce.deviceId) ?: false
        if (!shouldApply) {
            return
        }
        // Accepted: last_applied already advanced by onReceive.

        val announceHashHex = Crypto.bytesToHex(announce.sha256)
        when (AnnouncePolicy.decideImage(
            announce.totalLen, LargeTextLimits.MAX_IMAGE_BYTES, announce.mimeType,
            announceHashHex, lastAppliedContentHash
        )) {
            AnnouncePolicy.Decision.SKIP_OVER_LIMIT -> {
                Log.d("ClipcastService", "image announce ${announce.totalLen} exceeds max ${LargeTextLimits.MAX_IMAGE_BYTES}; skipping")
                lastTransfer =
                    "Image exceeds the 16 MB sync limit (${announce.totalLen} bytes)"
                publishState()
                return
            }
            AnnouncePolicy.Decision.SKIP_UNKNOWN_TYPE -> {
                Log.d("ClipcastService", "ignoring image announce with unsupported MIME ${announce.mimeType}")
                return
            }
            AnnouncePolicy.Decision.SKIP_DUPLICATE -> {
                Log.d("ClipcastService", "ignoring image announce matching already-applied content")
                return
            }
            AnnouncePolicy.Decision.FETCH -> Unit
        }

        synchronized(fetchLock) { activeImageTransfers.add(transferHex) }
        enqueueFetch(
            FetchJob(
                transferId = announce.transferId.copyOf(),
                totalLen = announce.totalLen,
                sha256 = announce.sha256.copyOf(),
                tcpPort = announce.tcpPort,
                innerContentType = Crypto.INNER_IMAGE,
                mimeType = announce.mimeType,
                maxBytes = LargeTextLimits.MAX_IMAGE_BYTES,
                source = source,
                isImage = true
            )
        )
    }

    /** One accepted announce awaiting (or undergoing) a TCP fetch. */
    private data class FetchJob(
        val transferId: ByteArray,
        val totalLen: Long,
        val sha256: ByteArray,
        val tcpPort: Int,
        val innerContentType: Byte,
        /** Announced MIME type for images (from the authenticated announce, never the TCP bytes). */
        val mimeType: String?,
        val maxBytes: Long,
        /** The announce datagram's source address — the only address ever dialed. */
        val source: InetAddress,
        val isImage: Boolean
    )

    /** A newer accepted message cancels an older fetch. */
    private fun enqueueFetch(job: FetchJob) {
        val handle = FetchHandle()
        val generation = synchronized(fetchLock) {
            cancelActiveFetchesLocked()
            fetchGeneration += 1
            activeFetches[fetchGeneration] = handle
            fetchGeneration
        }
        try {
            fetchExecutor.execute {
                runFetch(generation, handle, job)
            }
        } catch (e: Exception) {
            synchronized(fetchLock) { activeFetches.remove(generation) }
            if (job.isImage) removeImageTransfer(job.transferId)
            Log.w("ClipcastService", "fetch submit failed", e)
        }
    }

    private fun removeImageTransfer(transferId: ByteArray) {
        synchronized(fetchLock) { activeImageTransfers.remove(Crypto.bytesToHex(transferId)) }
    }

    private fun runFetch(
        generation: Int,
        handle: FetchHandle,
        job: FetchJob
    ) {
        try {
            val keyBytes = preferences?.getKeyBytes()
            val deviceId = preferences?.deviceId
            if (keyBytes == null || deviceId == null) {
                finishFetch(generation, "Transfer failed (no key)", job)
                return
            }
            val params = TcpFetchClient.Params(
                key = keyBytes,
                clientDeviceId = deviceId,
                serverAddress = job.source,
                tcpPort = job.tcpPort,
                transferId = job.transferId.copyOf(),
                totalLen = job.totalLen,
                expectedSha256 = job.sha256.copyOf(),
                innerContentType = job.innerContentType,
                maxTransferBytes = job.maxBytes,
                totalTimeoutMs = LargeTextLimits.TOTAL_TIMEOUT_MS
            )
            val data = TcpFetchClient.fetch(params, handle.cancel, handle.socketRef)
            // Discard if a newer message won while we were fetching.
            synchronized(fetchLock) {
                if (generation != fetchGeneration) {
                    Log.d("ClipcastService", "fetch superseded by newer message; discarding")
                    if (job.isImage) removeImageTransfer(job.transferId)
                    return
                }
            }
            if (job.isImage) {
                applyFetchedImage(job, data)
            } else {
                applyFetchedText(data)
            }
            finishFetch(generation, null, job)
        } catch (e: TcpFetchClient.FetchException) {
            if (e.kind == TcpFetchClient.FetchException.Kind.CANCELLED) {
                Log.d("ClipcastService", "fetch cancelled (newer message accepted)")
                synchronized(fetchLock) { activeFetches.remove(generation) }
                if (job.isImage) removeImageTransfer(job.transferId)
            } else {
                Log.w("ClipcastService", "fetch failed: ${e.message}")
                finishFetch(generation, "Transfer failed (${e.kind.name.lowercase()})", job)
            }
        } catch (e: Exception) {
            Log.w("ClipcastService", "fetch failed", e)
            finishFetch(generation, "Transfer failed (error)", job)
        }
    }

    /** Text half: length, SHA-256, and strict UTF-8 already verified by the fetch. */
    private fun applyFetchedText(data: ByteArray) {
        // Only now touch the clipboard, on the main thread.
        val text = String(data, java.nio.charset.StandardCharsets.UTF_8)
        val now = System.currentTimeMillis()
        lastAppliedContentHash = ClipboardHelper.contentHash(text)
        lastAppliedTime = now
        Looper.getMainLooper().let { mainLooper ->
            android.os.Handler(mainLooper).post {
                try {
                    ClipboardHelper.setText(this@ClipcastService, text)
                } catch (t: Throwable) {
                    Log.w("ClipcastService", "setPrimaryClip failed", t)
                }
            }
        }
        lastRxTime = System.currentTimeMillis()
        lastRxLen = data.size
        lastRxIsImage = false
        lastTransfer = "Received ${data.size} bytes"
        publishState()
    }

    /**
     * Image half: the fetch already verified length and SHA-256. Publish
     * the bytes as a content URI under the announced MIME type, then arm
     * hash-based echo suppression so our own clipboard write is never
     * rebroadcast. Failures apply nothing.
     */
    private fun applyFetchedImage(job: FetchJob, data: ByteArray) {
        val mime = job.mimeType
        if (mime == null || !ClipboardHelper.isSupportedImageMime(mime)) {
            Log.w("ClipcastService", "fetched image has no valid MIME; applying nothing")
            return
        }
        val now = System.currentTimeMillis()
        lastAppliedContentHash = ClipboardHelper.contentHashBytes(data)
        lastAppliedTime = now
        var published = false
        Looper.getMainLooper().let { mainLooper ->
            android.os.Handler(mainLooper).post {
                try {
                    published = ClipboardHelper.setImage(this@ClipcastService, mime, data) != null
                } catch (t: Throwable) {
                    Log.w("ClipcastService", "setPrimaryClip image failed", t)
                }
            }
        }
        // The clipboard write happens on the main thread; record the
        // outcome optimistically — failures surface as a failed row only
        // when setImage returns null synchronously is impossible here, so
        // log verbosely instead.
        lastRxTime = System.currentTimeMillis()
        lastRxLen = data.size
        lastRxIsImage = true
        lastTransfer = "Received image $mime (${data.size} bytes)"
        Log.d("ClipcastService", "received $mime (${data.size} bytes) published=$published")
        publishState()
    }

    private fun finishFetch(generation: Int, transferStatus: String?, job: FetchJob) {
        synchronized(fetchLock) { activeFetches.remove(generation) }
        if (job.isImage) removeImageTransfer(job.transferId)
        // Null status = success: apply* already recorded the outcome.
        if (transferStatus != null) lastTransfer = transferStatus
        publishState()
    }

    private fun cancelActiveFetchesLocked() {
        for ((_, handle) in activeFetches) {
            handle.cancel.set(true)
            try {
                handle.socketRef.get()?.close()
            } catch (e: Exception) {
                // ignore: the fetch loop maps the closed socket to CANCELLED.
            }
        }
        activeFetches.clear()
        activeImageTransfers.clear()
    }

    private fun cancelActiveFetches(reason: String) {
        synchronized(fetchLock) {
            if (activeFetches.isEmpty()) return
            Log.d("ClipcastService", "cancelling fetches: $reason")
            cancelActiveFetchesLocked()
        }
    }

    fun sendText(text: String, quiet: Boolean = false) {
        if (!isRunning) {
            broadcastSendResult(false, text.length, quiet)
            return
        }
        if (text.isEmpty()) {
            broadcastSendResult(false, text.length, quiet)
            return
        }
        val byteLen = text.toByteArray(java.nio.charset.StandardCharsets.UTF_8).size
        if (byteLen > LargeTextLimits.DEFAULT_MAX_SEND_BYTES) {
            Log.d("ClipcastService", "text too large to send ($byteLen bytes)")
            broadcastSendResult(false, text.length, quiet, tooLarge = true)
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
            val datagram = if (payload.size <= LargeTextLimits.UDP_MAX_BYTES) {
                // Small text: behave as today (v1 CLIP_UPDATE).
                Crypto.encode(keyBytes, deviceId, lamport, nowMs, payload) ?: return@execute
            } else {
                // Large text: register a pending transfer and send one announce.
                // Several peers may fetch the same transfer during its TTL.
                val store = transferStore
                if (store == null) {
                    Log.w("ClipcastService", "no transfer store; dropping large send")
                    broadcastSendResult(false, payload.size, quiet)
                    return@execute
                }
                val transferId = TransferStore.newTransferId()
                val sha = store.insert(transferId, payload)
                val tcpPort = preferences?.tcpPort ?: LargeTextLimits.DEFAULT_TCP_PORT
                val announcePayload = try {
                    Crypto.encodeAnnouncePayload(
                        Crypto.INNER_TEXT, transferId, payload.size.toLong(), sha, tcpPort
                    )
                } catch (e: Exception) {
                    Log.w("ClipcastService", "announce build failed", e)
                    broadcastSendResult(false, payload.size, quiet)
                    return@execute
                }
                Crypto.encodeAnnounce(keyBytes, deviceId, lamport, nowMs, announcePayload)
                    ?: return@execute
            }

            try {
                val packet = DatagramPacket(datagram, datagram.size, broadcastAddr, port)
                receiveSocket?.send(packet)

                lastTxTime = System.currentTimeMillis()
                lastTxLen = payload.size
                publishState()
                broadcastSendResult(true, payload.size, quiet)
            } catch (e: Exception) {
                Log.w("ClipcastService", "Send error", e)
                broadcastSendResult(false, payload.size, quiet)
            }
        }
    }

    /**
     * Send a staged image file (written by a foreground activity into our
     * cache dir). The bytes are validated (allowlisted MIME, size ceiling),
     * stored in the sender image cache, and announced over UDP; receivers
     * fetch them over TCP. Over-limit or invalid images are logged by MIME
     * and size only — never broadcast.
     */
    fun sendImageFile(stagedPath: String, mimeType: String, quiet: Boolean = false) {
        // The staging file is ours (written by a foreground activity into
        // our cache dir); always consume it, even when not sending.
        val staged = File(stagedPath)
        val bytes = try {
            if (!staged.isFile) null else staged.readBytes()
        } catch (e: Exception) {
            null
        }
        try {
            staged.delete()
        } catch (e: Exception) {
            // ignore
        }
        if (!isRunning) {
            broadcastSendResult(false, 0, quiet, tooLarge = false, isImage = true)
            return
        }
        if (!ClipboardHelper.isSupportedImageMime(mimeType)) {
            Log.d("ClipcastService", "unsupported staged image MIME $mimeType; not sending")
            broadcastSendResult(false, 0, quiet, tooLarge = false, isImage = true)
            return
        }
        if (bytes == null || bytes.isEmpty()) {
            broadcastSendResult(false, 0, quiet, tooLarge = false, isImage = true)
            return
        }
        if (bytes.size.toLong() > LargeTextLimits.MAX_IMAGE_BYTES) {
            Log.d("ClipcastService", "image not sent: $mimeType, ${bytes.size} bytes exceeds ${LargeTextLimits.MAX_IMAGE_BYTES} limit")
            broadcastSendResult(false, bytes.size, quiet, tooLarge = true, isImage = true)
            return
        }

        // Echo prevention: never rebroadcast an image we just applied.
        val now = System.currentTimeMillis()
        val hash = ClipboardHelper.contentHashBytes(bytes)
        if (hash == lastAppliedContentHash && now - lastAppliedTime < 1000) {
            Log.d("ClipcastService", "dropping echo of just-applied remote image")
            return
        }

        sendExecutor.execute {
            val keyBytes = preferences?.getKeyBytes() ?: return@execute
            val deviceId = preferences?.deviceId ?: return@execute
            val broadcastAddr = currentBroadcastAddress ?: return@execute
            val port = currentPort
            val cache = imageCache
            if (cache == null) {
                Log.w("ClipcastService", "no image cache; dropping image send")
                broadcastSendResult(false, bytes.size, quiet, isImage = true)
                return@execute
            }

            val nowMs = System.currentTimeMillis()
            val lamport = syncState?.onLocalSend(nowMs, deviceId) ?: nowMs

            // Store first (hash computed inside), then announce: receivers
            // must be able to fetch the moment the datagram arrives.
            val transferId = ImageCache.newTransferId()
            cache.insert(transferId, mimeType, bytes)
            val sha = TcpCrypto.sha256(bytes)
            val tcpPort = preferences?.tcpPort ?: LargeTextLimits.DEFAULT_TCP_PORT
            val announcePayload = try {
                Crypto.encodeImageAnnouncePayload(
                    transferId, bytes.size.toLong(), sha, tcpPort, mimeType
                )
            } catch (e: Exception) {
                Log.w("ClipcastService", "image announce build failed", e)
                broadcastSendResult(false, bytes.size, quiet, isImage = true)
                return@execute
            }
            val datagram = Crypto.encodeImageAnnounce(
                keyBytes, deviceId, lamport, nowMs, announcePayload
            ) ?: return@execute

            try {
                val packet = DatagramPacket(datagram, datagram.size, broadcastAddr, port)
                receiveSocket?.send(packet)

                lastTxTime = System.currentTimeMillis()
                lastTxLen = bytes.size
                lastTxIsImage = true
                publishState()
                broadcastSendResult(true, bytes.size, quiet, isImage = true)
            } catch (e: Exception) {
                Log.w("ClipcastService", "Send error", e)
                broadcastSendResult(false, bytes.size, quiet, isImage = true)
            }
        }
    }

    private fun broadcastSendResult(success: Boolean, length: Int, quiet: Boolean = false, tooLarge: Boolean = false, isImage: Boolean = false) {
        if (success) {
            lastSendOk = true
            lastSendError = null
        } else {
            lastSendOk = false
            lastSendError = if (tooLarge) "too_large" else "failed"
        }
        publishState()
        ServiceStateHolder.emitSend(
            ServiceStateHolder.SendEvent(success, length, quiet, tooLarge)
        )
    }

    /** Snapshot everything the UI renders; delivery is always on the main thread. */
    private fun publishState() {
        ServiceStateHolder.publish(
            ServiceStateHolder.Snapshot(
                running = isRunning,
                configured = preferences?.isConfigured() == true,
                wifiConnected = networkManager?.isWifiConnected() == true,
                localIp = networkManager?.getLocalIpv4(),
                udpError = lastUdpError,
                tcpError = lastTcpError,
                lastRxTime = lastRxTime,
                lastRxLen = lastRxLen,
                lastTxTime = lastTxTime,
                lastTxLen = lastTxLen,
                lastRxIsImage = lastRxIsImage,
                lastTxIsImage = lastTxIsImage,
                lastTransfer = lastTransfer,
                lastSendOk = lastSendOk,
                lastSendError = lastSendError
            )
        )
    }

    /** Rebuild the foreground notification (e.g. the local IP changed). */
    private fun refreshNotification() {
        if (!isRunning) return
        try {
            val manager = getSystemService(NotificationManager::class.java)
            manager.notify(NOTIFICATION_ID, buildNotification())
        } catch (e: Exception) {
            Log.d("ClipcastService", "notification refresh failed", e)
        }
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

        // Low priority, ongoing, quiet: title + local IP, Send + Stop.
        // Tapping the notification opens the main screen.
        val ip = networkManager?.getLocalIpv4()
        // Framework builder (minSdk 26: channels exist, no compat needed).
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_menu_upload)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(ip ?: getString(R.string.notification_text_waiting))
            .setContentIntent(openPendingIntent)
            .addAction(
                android.app.Notification.Action.Builder(
                    android.graphics.drawable.Icon.createWithResource(
                        this, android.R.drawable.ic_menu_send
                    ),
                    getString(R.string.notification_action_send),
                    sendPendingIntent
                ).build()
            )
            .addAction(
                android.app.Notification.Action.Builder(
                    android.graphics.drawable.Icon.createWithResource(
                        this, android.R.drawable.ic_menu_close_clear_cancel
                    ),
                    getString(R.string.notification_action_stop),
                    stopPendingIntent
                ).build()
            )
            .setOngoing(true)
            .setCategory(Notification.CATEGORY_SERVICE)
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