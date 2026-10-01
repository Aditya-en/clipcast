package com.clipcast.util

import org.junit.Test
import org.junit.Assert.*

class AutoSendTest {

    @Test
    fun testFreshText_sends() {
        assertTrue(ClipboardHelper.shouldAutoSend("hello", null, 0, 10000))
    }

    @Test
    fun testEmptyOrNull_skipped() {
        assertFalse(ClipboardHelper.shouldAutoSend(null, null, 0, 10000))
        assertFalse(ClipboardHelper.shouldAutoSend("", null, 0, 10000))
    }

    @Test
    fun testOversize_skipped() {
        val big = "x".repeat(ClipboardHelper.getMaxTextLength() + 1)
        assertFalse(ClipboardHelper.shouldAutoSend(big, null, 0, 10000))
    }

    @Test
    fun testRepeatWithinWindow_suppressed() {
        val text = "same text"
        val hash = ClipboardHelper.contentHash(text)
        // Same content 500 ms later: echo, skip.
        assertFalse(ClipboardHelper.shouldAutoSend(text, hash, 10000, 10500))
    }

    @Test
    fun testRepeatAfterWindow_sends() {
        val text = "same text"
        val hash = ClipboardHelper.contentHash(text)
        // Same content 5 s later: user re-copied, send.
        assertTrue(ClipboardHelper.shouldAutoSend(text, hash, 10000, 15000))
    }

    @Test
    fun testDifferentText_sends() {
        val hash = ClipboardHelper.contentHash("old")
        assertTrue(ClipboardHelper.shouldAutoSend("new", hash, 10000, 10500))
    }
}
