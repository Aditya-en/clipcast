package com.clipcast.service

import com.clipcast.protocol.LargeTextLimits
import com.clipcast.protocol.TcpCrypto
import java.security.SecureRandom

/**
 * Pending outbound large-text transfers (text over the UDP limit that we
 * announced and now serve over TCP).
 *
 * Mirrors the daemon's transfer store: keeps only the newest
 * [LargeTextLimits.MAX_PENDING_TRANSFERS] transfers under a global
 * [LargeTextLimits.PENDING_MEMORY_CAP_BYTES] memory cap, evicting oldest
 * first. A transfer may be fetched by several peers during its TTL, up to
 * [LargeTextLimits.MAX_FETCHES_PER_TRANSFER] serves. Thread-safe.
 */
class TransferStore(
    private val ttlMs: Long = LargeTextLimits.TRANSFER_TTL_MS,
    private val maxFetchesPerTransfer: Int = LargeTextLimits.MAX_FETCHES_PER_TRANSFER,
    private val memoryCapBytes: Long = LargeTextLimits.PENDING_MEMORY_CAP_BYTES
) {
    data class Entry(
        val id: ByteArray,
        val data: ByteArray,
        val sha256: ByteArray,
        val expiresAtMs: Long,
        var fetchesUsed: Int = 0
    )

    private val entries = ArrayDeque<Entry>()
    private var memoryUsed: Long = 0

    /** Register a pending transfer. Returns its SHA-256. Evicts expired entries first, then oldest-first. */
    @Synchronized
    fun insert(id: ByteArray, bytes: ByteArray): ByteArray {
        require(id.size == 16) { "transfer_id must be 16 bytes" }
        pruneExpiredLocked()
        val sha = TcpCrypto.sha256(bytes)
        entries.addLast(
            Entry(
                id = id.copyOf(),
                data = bytes.copyOf(),
                sha256 = sha,
                expiresAtMs = System.currentTimeMillis() + ttlMs
            )
        )
        memoryUsed += bytes.size
        while (entries.size > LargeTextLimits.MAX_PENDING_TRANSFERS) popOldestLocked()
        while (memoryUsed > memoryCapBytes && entries.size > 1) popOldestLocked()
        return sha
    }

    /** Look up a live transfer without recording a fetch (peek, for tests). */
    @Synchronized
    fun get(id: ByteArray): Entry? {
        pruneExpiredLocked()
        return entries.firstOrNull { it.id.contentEquals(id) }
    }

    /**
     * Serve one fetch: returns the bytes + SHA-256 if the transfer is live
     * and under the per-transfer fetch budget, recording the use. Expired,
     * unknown, or exhausted ids yield null.
     */
    @Synchronized
    fun serve(id: ByteArray): Pair<ByteArray, ByteArray>? {
        pruneExpiredLocked()
        val entry = entries.firstOrNull { it.id.contentEquals(id) } ?: return null
        if (entry.fetchesUsed >= maxFetchesPerTransfer) return null
        entry.fetchesUsed += 1
        return Pair(entry.data.copyOf(), entry.sha256.copyOf())
    }

    @Synchronized
    fun size(): Int {
        pruneExpiredLocked()
        return entries.size
    }

    @Synchronized
    fun memoryUsed(): Long = memoryUsed

    @Synchronized
    fun fetchCount(id: ByteArray): Int? {
        pruneExpiredLocked()
        return entries.firstOrNull { it.id.contentEquals(id) }?.fetchesUsed
    }

    private fun popOldestLocked() {
        val old = entries.removeFirstOrNull() ?: return
        memoryUsed = (memoryUsed - old.data.size).coerceAtLeast(0)
    }

    private fun pruneExpiredLocked() {
        val now = System.currentTimeMillis()
        while (entries.firstOrNull()?.let { now >= it.expiresAtMs } == true) {
            popOldestLocked()
        }
    }

    companion object {
        fun newTransferId(random: SecureRandom = SecureRandom()): ByteArray {
            val id = ByteArray(16)
            random.nextBytes(id)
            return id
        }
    }
}
