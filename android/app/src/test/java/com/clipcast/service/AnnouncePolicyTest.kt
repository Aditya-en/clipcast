package com.clipcast.service

import org.junit.Assert.*
import org.junit.Test

/**
 * (8a) The over-limit / unknown-type / duplicate gate for announces.
 * Ordering and echo rules live in SyncState/the service; this covers the
 * Binder-safe apply limit decision.
 */
class AnnouncePolicyTest {

    @Test
    fun overLimit_skipped() {
        assertEquals(
            AnnouncePolicy.Decision.SKIP_OVER_LIMIT,
            AnnouncePolicy.decide(
                totalLen = 600L * 1024,
                maxApplyBytes = 512L * 1024,
                innerContentType = 0x01,
                announceShaHex = "aa".repeat(32),
                lastAppliedContentHashHex = null
            )
        )
        // Exactly at the cap still fetches.
        assertEquals(
            AnnouncePolicy.Decision.FETCH,
            AnnouncePolicy.decide(
                totalLen = 512L * 1024,
                maxApplyBytes = 512L * 1024,
                innerContentType = 0x01,
                announceShaHex = "aa".repeat(32),
                lastAppliedContentHashHex = null
            )
        )
    }

    @Test
    fun unknownInnerType_skipped() {
        assertEquals(
            AnnouncePolicy.Decision.SKIP_UNKNOWN_TYPE,
            AnnouncePolicy.decide(
                totalLen = 100,
                maxApplyBytes = 512L * 1024,
                innerContentType = 0x02,
                announceShaHex = "aa".repeat(32),
                lastAppliedContentHashHex = null
            )
        )
    }

    @Test
    fun duplicateHash_skipped() {
        val sha = "bb".repeat(32)
        assertEquals(
            AnnouncePolicy.Decision.SKIP_DUPLICATE,
            AnnouncePolicy.decide(100, 512L * 1024, 0x01, sha, sha)
        )
        assertEquals(
            AnnouncePolicy.Decision.FETCH,
            AnnouncePolicy.decide(100, 512L * 1024, 0x01, sha, "cc".repeat(32))
        )
    }

    @Test
    fun unsignedHugeTotalLen_treatedAsOverLimit() {
        // A u64 total_len above Long.MAX_VALUE arrives as a negative Long;
        // it must still count as over-limit, never as a small buffer.
        assertEquals(
            AnnouncePolicy.Decision.SKIP_OVER_LIMIT,
            AnnouncePolicy.decide(
                totalLen = -1L,
                maxApplyBytes = 512L * 1024,
                innerContentType = 0x01,
                announceShaHex = "aa".repeat(32),
                lastAppliedContentHashHex = null
            )
        )
    }
}
