package com.clipcast.util

import org.junit.Assert.*
import org.junit.Test

/**
 * Pure clipboard-image helpers: MIME preference, allowlist, extensions,
 * byte hashing. Framework read/write paths need a device (see the manual
 * matrix in the task report).
 */
class ClipboardImageTest {

    @Test
    fun preferredImageMime_prefersPngOverText() {
        assertEquals(
            "image/png",
            ClipboardHelper.preferredImageMime(arrayOf("image/png", "text/plain", "text/html"))
        )
        assertEquals(
            "image/jpeg",
            ClipboardHelper.preferredImageMime(arrayOf("text/plain", "image/jpeg"))
        )
        assertEquals(
            "image/webp",
            ClipboardHelper.preferredImageMime(arrayOf("image/webp"))
        )
        assertNull(ClipboardHelper.preferredImageMime(arrayOf("text/plain")))
        assertNull(ClipboardHelper.preferredImageMime(arrayOf("image/gif")))
        assertNull(ClipboardHelper.preferredImageMime(emptyArray()))
    }

    @Test
    fun mimeAllowlist_caseSensitive() {
        assertTrue(ClipboardHelper.isSupportedImageMime("image/png"))
        assertTrue(ClipboardHelper.isSupportedImageMime("image/jpeg"))
        assertTrue(ClipboardHelper.isSupportedImageMime("image/webp"))
        assertFalse(ClipboardHelper.isSupportedImageMime("image/gif"))
        assertFalse(ClipboardHelper.isSupportedImageMime("IMAGE/PNG"))
    }

    @Test
    fun extensionForMime() {
        assertEquals("png", ClipboardHelper.extensionForMime("image/png"))
        assertEquals("jpg", ClipboardHelper.extensionForMime("image/jpeg"))
        assertEquals("webp", ClipboardHelper.extensionForMime("image/webp"))
        assertEquals("bin", ClipboardHelper.extensionForMime("image/gif"))
    }

    @Test
    fun contentHashBytes_isSha256Hex() {
        // SHA-256 of "abc".
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ClipboardHelper.contentHashBytes("abc".toByteArray())
        )
        // Binary bytes hash stably and differ from text hashing only in input.
        val a = ClipboardHelper.contentHashBytes(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47))
        val b = ClipboardHelper.contentHashBytes(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47))
        assertEquals(a, b)
        assertEquals(64, a.length)
    }

    @Test
    fun imageContent_equalityIsByBytes() {
        val x = ClipboardHelper.ImageContent("image/png", byteArrayOf(1, 2, 3))
        val y = ClipboardHelper.ImageContent("image/png", byteArrayOf(1, 2, 3))
        val z = ClipboardHelper.ImageContent("image/png", byteArrayOf(1, 2, 4))
        assertEquals(x, y)
        assertNotEquals(x, z)
        assertNotEquals(
            x,
            ClipboardHelper.ImageContent("image/jpeg", byteArrayOf(1, 2, 3))
        )
    }
}
