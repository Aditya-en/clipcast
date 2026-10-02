package com.clipcast.service

import com.clipcast.protocol.Crypto
import com.clipcast.protocol.LargeTextLimits
import org.junit.Assert.*
import org.junit.Test

/**
 * Image-announce gate: size ceiling, MIME allowlist, duplicate hash.
 * Ordering, echo, and transfer-dedup rules live in the service/engine.
 */
class ImagePolicyTest {

    private val sha = "cc".repeat(32)

    @Test
    fun normalImage_fetches() {
        assertEquals(
            AnnouncePolicy.Decision.FETCH,
            AnnouncePolicy.decideImage(
                totalLen = 2_400_000,
                maxImageBytes = LargeTextLimits.MAX_IMAGE_BYTES,
                mimeType = "image/png",
                announceShaHex = sha,
                lastAppliedContentHashHex = null
            )
        )
    }

    @Test
    fun overLimit_skipped() {
        assertEquals(
            AnnouncePolicy.Decision.SKIP_OVER_LIMIT,
            AnnouncePolicy.decideImage(
                totalLen = LargeTextLimits.MAX_IMAGE_BYTES + 1,
                maxImageBytes = LargeTextLimits.MAX_IMAGE_BYTES,
                mimeType = "image/png",
                announceShaHex = sha,
                lastAppliedContentHashHex = null
            )
        )
        // Exactly at the cap still fetches.
        assertEquals(
            AnnouncePolicy.Decision.FETCH,
            AnnouncePolicy.decideImage(
                totalLen = LargeTextLimits.MAX_IMAGE_BYTES,
                maxImageBytes = LargeTextLimits.MAX_IMAGE_BYTES,
                mimeType = "image/jpeg",
                announceShaHex = sha,
                lastAppliedContentHashHex = null
            )
        )
    }

    @Test
    fun unsupportedMime_skipped() {
        for (mime in listOf("image/gif", "text/plain", "IMAGE/PNG", "")) {
            assertEquals(
                "mime $mime",
                AnnouncePolicy.Decision.SKIP_UNKNOWN_TYPE,
                AnnouncePolicy.decideImage(
                    totalLen = 100,
                    maxImageBytes = LargeTextLimits.MAX_IMAGE_BYTES,
                    mimeType = mime,
                    announceShaHex = sha,
                    lastAppliedContentHashHex = null
                )
            )
        }
        // Every allowlisted MIME fetches.
        for (mime in Crypto.SUPPORTED_IMAGE_MIMES) {
            assertEquals(
                "mime $mime",
                AnnouncePolicy.Decision.FETCH,
                AnnouncePolicy.decideImage(100, LargeTextLimits.MAX_IMAGE_BYTES, mime, sha, null)
            )
        }
    }

    @Test
    fun duplicateHash_skipped() {
        assertEquals(
            AnnouncePolicy.Decision.SKIP_DUPLICATE,
            AnnouncePolicy.decideImage(100, LargeTextLimits.MAX_IMAGE_BYTES, "image/png", sha, sha)
        )
        // Case-insensitive hex compare, like the text path.
        assertEquals(
            AnnouncePolicy.Decision.SKIP_DUPLICATE,
            AnnouncePolicy.decideImage(
                100, LargeTextLimits.MAX_IMAGE_BYTES, "image/png",
                sha.uppercase(), sha.lowercase()
            )
        )
    }
}
