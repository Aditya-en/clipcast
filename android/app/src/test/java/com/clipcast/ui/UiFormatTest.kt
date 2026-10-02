package com.clipcast.ui

import org.junit.Assert.*
import org.junit.Test

class UiFormatTest {

    @Test
    fun humanSize_bytes() {
        assertEquals("0 B", UiFormat.humanSize(0))
        assertEquals("1 B", UiFormat.humanSize(1))
        assertEquals("812 B", UiFormat.humanSize(812))
        assertEquals("1023 B", UiFormat.humanSize(1023))
    }

    @Test
    fun humanSize_kilobytes() {
        assertEquals("1 KB", UiFormat.humanSize(1024))
        assertEquals("4.2 KB", UiFormat.humanSize((4.2 * 1024).toLong()))
        assertEquals("512 KB", UiFormat.humanSize(512 * 1024))
    }

    @Test
    fun humanSize_megabytes() {
        assertEquals("1 MB", UiFormat.humanSize(1024 * 1024))
        assertEquals("3.1 MB", UiFormat.humanSize((3.1 * 1024 * 1024).toLong()))
    }

    @Test
    fun relativeTimeSpan_buckets() {
        val now = 1_000_000_000L
        assertEquals("just now", UiFormat.relativeTimeSpan(now, now))
        assertEquals("just now", UiFormat.relativeTimeSpan(now, now - 30_000))
        assertEquals("2 min ago", UiFormat.relativeTimeSpan(now, now - 2 * 60_000))
        assertEquals("3 h ago", UiFormat.relativeTimeSpan(now, now - 3 * 3_600_000))
        assertEquals("4 d ago", UiFormat.relativeTimeSpan(now, now - 4 * 86_400_000))
        // Future timestamps clamp to just now.
        assertEquals("just now", UiFormat.relativeTimeSpan(now, now + 60_000))
    }

    @Test
    fun talkSize_spelledOut() {
        assertEquals("1 byte", UiFormat.talkSize(1))
        assertEquals("812 bytes", UiFormat.talkSize(812))
        assertEquals("4.2 kilobytes", UiFormat.talkSize((4.2 * 1024).toLong()))
        assertEquals("3 megabytes", UiFormat.talkSize(3 * 1024 * 1024))
    }

    @Test
    fun humanSize_negativeClamps() {
        assertEquals("0 B", UiFormat.humanSize(-1))
        assertEquals("0 bytes", UiFormat.talkSize(-5))
    }

    @Test
    fun shortId_truncates() {
        assertEquals("a3f109cc", UiFormat.shortId("a3f109cc00112233"))
        assertEquals("abc", UiFormat.shortId("abc"))
    }
}
