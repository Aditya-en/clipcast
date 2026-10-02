package com.clipcast.service

import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * Sender-side image disk cache: availability, expiry, eviction,
 * unknown-id rejection. Mirrors the daemon's image_cache tests.
 */
class ImageCacheTest {

    private fun tempDir(): File =
        Files.createTempDirectory("clipcast-imagecache-test").toFile()

    private fun samplePng(): ByteArray = byteArrayOf(
        0x89.toByte(), 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
    )

    @Test
    fun insertServe_roundTrip() {
        val dir = tempDir()
        try {
            val cache = ImageCache(dir)
            val id = ByteArray(16) { 0xA5.toByte() }
            val bytes = samplePng()
            val sha = cache.insert(id, "image/png", bytes)
            assertArrayEquals(com.clipcast.protocol.TcpCrypto.sha256(bytes), sha)
            val (got, mime, gotSha) = cache.serve(id)!!
            assertArrayEquals(bytes, got)
            assertEquals("image/png", mime)
            assertArrayEquals(sha, gotSha)
            assertEquals(1, cache.size())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun unknownTransferId_rejected() {
        val dir = tempDir()
        try {
            val cache = ImageCache(dir)
            assertNull(cache.serve(ByteArray(16) { 0xFF.toByte() }))
            assertNull(cache.get(ByteArray(16) { 0xFF.toByte() }))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun expiredImage_deleted() {
        val dir = tempDir()
        try {
            val cache = ImageCache(dir, ttlMs = 5, maxImages = 20)
            val id = ByteArray(16) { 0x11 }
            cache.insert(id, "image/jpeg", byteArrayOf(1, 2, 3))
            assertNotNull(cache.serve(id))
            Thread.sleep(20)
            assertNull(cache.serve(id))
            assertEquals(0, cache.size())
            assertEquals(0, dir.listFiles()?.size ?: 0)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun oldestFirst_evictionOverCap() {
        val dir = tempDir()
        try {
            val cache = ImageCache(dir, ttlMs = 600_000, maxImages = 3)
            for (i in 0..4) {
                cache.insert(ByteArray(16) { i.toByte() }, "image/png", samplePng())
            }
            assertEquals(3, cache.size())
            assertNull(cache.serve(ByteArray(16) { 0 }))
            assertNull(cache.serve(ByteArray(16) { 1 }))
            assertNotNull(cache.serve(ByteArray(16) { 4 }))
            assertEquals(3, dir.listFiles()?.size ?: 0)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test
    fun missingBackingFile_servesNullAndDropsEntry() {
        val dir = tempDir()
        try {
            val cache = ImageCache(dir)
            val id = ByteArray(16) { 0x22 }
            cache.insert(id, "image/png", samplePng())
            File(dir, ImageCache.hexOf(id)).delete()
            assertNull(cache.serve(id))
            assertEquals(0, cache.size())
        } finally {
            dir.deleteRecursively()
        }
    }
}
