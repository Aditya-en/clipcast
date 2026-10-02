package com.clipcast.ui

/**
 * Pure UI formatting helpers (no Android imports): human-readable sizes and
 * relative times for the Activity card. The activity itself renders times
 * with DateUtils; this mirror exists so the buckets are unit-tested.
 */
object UiFormat {

    /** "0 B", "812 B", "4.2 KB", "3.1 MB". Never shows content, only sizes. */
    fun humanSize(bytes: Long): String {
        if (bytes < 0) return "0 B"
        if (bytes < 1024) return "$bytes B"
        val kb = bytes / 1024.0
        if (kb < 1024) return trimOne(kb) + " KB"
        return trimOne(kb / 1024.0) + " MB"
    }

    private fun trimOne(value: Double): String {
        val rounded = Math.round(value * 10) / 10.0
        return if (rounded == Math.floor(rounded)) {
            rounded.toInt().toString()
        } else {
            rounded.toString()
        }
    }

    /**
     * Coarse relative time ("just now", "2 min ago", "3 h ago", "4 d ago").
     * Test double for the DateUtils rendering used on screen.
     */
    fun relativeTimeSpan(nowMs: Long, thenMs: Long): String {
        val diff = (nowMs - thenMs).coerceAtLeast(0)
        val minutes = diff / 60_000
        if (minutes < 1) return "just now"
        if (minutes < 60) return "$minutes min ago"
        val hours = minutes / 60
        if (hours < 24) return "$hours h ago"
        return "${hours / 24} d ago"
    }

    /** First [chars] hex characters of a device ID (never the full ID). */
    fun shortId(hex: String, chars: Int = 8): String {
        return if (hex.length <= chars) hex else hex.substring(0, chars)
    }

    /**
     * Spelled-out size for TalkBack ("812 bytes", "4.2 kilobytes",
     * "3 megabytes") so a row reads as one sentence.
     */
    fun talkSize(bytes: Long): String {
        if (bytes < 0) return "0 bytes"
        if (bytes == 1L) return "1 byte"
        if (bytes < 1024) return "$bytes bytes"
        val kb = bytes / 1024.0
        if (kb < 1024) return trimOne(kb) + " kilobytes"
        return trimOne(kb / 1024.0) + " megabytes"
    }
}
