package com.clipcast.protocol

/**
 * Shared limits for the large-text TCP side channel.
 * Android SDK + Kotlin stdlib only; no Android framework imports so this
 * stays usable from JVM unit tests.
 */
object LargeTextLimits {
    /** Existing v1 UDP text limit in bytes: at or below this, send as today. */
    const val UDP_MAX_BYTES = 1200

    /** Default TCP listener port (configurable in the UI). */
    const val DEFAULT_TCP_PORT = 47475

    /**
     * Default cap on text we will apply to the clipboard from a fetch.
     * setPrimaryClip goes through Binder and fails near 1 MB.
     */
    const val DEFAULT_MAX_APPLY_BYTES = 512 * 1024

    /** Hard cap for the "max applied text size" setting (900 KB). */
    const val MAX_APPLY_HARD_CAP = 900 * 1024

    /** Default cap on text we will serve to peers (16 MiB). */
    const val DEFAULT_MAX_SEND_BYTES = 16 * 1024 * 1024

    /** Pending-transfer lifetime: peers may fetch during this TTL. */
    const val TRANSFER_TTL_MS = 120_000L

    /** Keep only the newest N pending transfers; evict oldest first. */
    const val MAX_PENDING_TRANSFERS = 4

    /** Total memory cap for buffered pending-transfer bytes (32 MiB). */
    const val PENDING_MEMORY_CAP_BYTES = 32L * 1024 * 1024

    /** A transfer is served at most this many times. */
    const val MAX_FETCHES_PER_TRANSFER = 16

    /** TCP connect timeout. */
    const val CONNECT_TIMEOUT_MS = 3_000

    /** Per-read (idle) timeout in either direction. */
    const val IDLE_TIMEOUT_MS = 10_000

    /** Overall cap for one fetch. */
    const val TOTAL_TIMEOUT_MS = 120_000L

    /** Max concurrent outbound fetches; a newer accepted message cancels an older fetch. */
    const val MAX_CONCURRENT_FETCHES = 2

    /** Max concurrent inbound TCP connections; extras are closed immediately. */
    const val MAX_SERVER_CONNECTIONS = 4
}
