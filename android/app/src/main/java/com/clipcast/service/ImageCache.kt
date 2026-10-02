package com.clipcast.service

import com.clipcast.protocol.LargeTextLimits
import com.clipcast.protocol.TcpCrypto
import java.io.File
import java.security.SecureRandom

/**
 * Temporary sender-side image cache (disk-backed, app-private storage).
 *
 * Mirrors the daemon's image cache: an announced image must stay available
 * after its UDP announcement because receivers fetch it over TCP seconds
 * later. Each image is one file named by the hex transfer_id; an in-memory
 * index carries MIME type, length, hash, and expiry. Entries expire after
 * [LargeTextLimits.IMAGE_CACHE_TTL_MS] and the cache keeps at most
 * [LargeTextLimits.MAX_CACHED_IMAGES], oldest first. Pure JVM (java.io
 * only) so unit tests run without the Android framework; the service
 * passes a directory under getCacheDir(). Thread-safe.
 */
class ImageCache(
    private val dir: File,
    private val ttlMs: Long = LargeTextLimits.IMAGE_CACHE_TTL_MS,
    private val maxImages: Int = LargeTextLimits.MAX_CACHED_IMAGES
) {
    data class Entry(
        val id: ByteArray,
        val mimeType: String,
        val len: Long,
        val sha256: ByteArray,
        val expiresAtMs: Long
    )

    private val entries = ArrayDeque<Entry>()

    init {
        require(maxImages >= 1) { "maxImages must be >= 1" }
        dir.mkdirs()
    }

    /** Store image bytes, returning their SHA-256. Evicts expired entries first, then oldest-first. */
    @Synchronized
    fun insert(id: ByteArray, mimeType: String, bytes: ByteArray): ByteArray {
        require(id.size == 16) { "transfer_id must be 16 bytes" }
        pruneExpiredLocked()
        val sha = TcpCrypto.sha256(bytes)
        File(dir, hexOf(id)).writeBytes(bytes)
        entries.removeAll { it.id.contentEquals(id) }
        entries.addLast(
            Entry(
                id = id.copyOf(),
                mimeType = mimeType,
                len = bytes.size.toLong(),
                sha256 = sha,
                expiresAtMs = System.currentTimeMillis() + ttlMs
            )
        )
        while (entries.size > maxImages) popOldestLocked()
        return sha
    }

    /**
     * Serve one fetch: returns (bytes, mimeType, sha256) for a live
     * transfer. Expired, unknown, or unreadable ids yield null.
     */
    @Synchronized
    fun serve(id: ByteArray): Triple<ByteArray, String, ByteArray>? {
        pruneExpiredLocked()
        val entry = entries.firstOrNull { it.id.contentEquals(id) } ?: return null
        val file = File(dir, hexOf(id))
        val bytes = try {
            file.readBytes()
        } catch (e: Exception) {
            entries.removeAll { it.id.contentEquals(id) }
            return null
        }
        if (bytes.size.toLong() != entry.len) {
            entries.removeAll { it.id.contentEquals(id) }
            try {
                file.delete()
            } catch (e: Exception) {
                // ignore
            }
            return null
        }
        return Triple(bytes, entry.mimeType, entry.sha256.copyOf())
    }

    /** Metadata lookup without reading bytes (for tests/diagnostics). */
    @Synchronized
    fun get(id: ByteArray): Entry? {
        pruneExpiredLocked()
        return entries.firstOrNull { it.id.contentEquals(id) }
    }

    @Synchronized
    fun size(): Int {
        pruneExpiredLocked()
        return entries.size
    }

    private fun popOldestLocked() {
        val old = entries.removeFirstOrNull() ?: return
        try {
            File(dir, hexOf(old.id)).delete()
        } catch (e: Exception) {
            // ignore
        }
    }

    private fun pruneExpiredLocked() {
        val now = System.currentTimeMillis()
        while (entries.firstOrNull()?.let { now >= it.expiresAtMs } == true) {
            popOldestLocked()
        }
    }

    companion object {
        fun hexOf(id: ByteArray): String = id.joinToString("") { "%02x".format(it) }

        fun newTransferId(random: SecureRandom = SecureRandom()): ByteArray {
            val id = ByteArray(16)
            random.nextBytes(id)
            return id
        }
    }
}
