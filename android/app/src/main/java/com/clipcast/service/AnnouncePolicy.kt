package com.clipcast.service

import com.clipcast.protocol.Crypto

/**
 * Pure, unit-tested gate for large-text announces on the receive path.
 * The service runs ordering first, then consults this before fetching.
 */
object AnnouncePolicy {

    enum class Decision {
        /** Fetch over TCP. */
        FETCH,

        /** total_len exceeds max_apply_bytes: Binder-safe apply limit. */
        SKIP_OVER_LIMIT,

        /** inner_content_type is not text/plain. */
        SKIP_UNKNOWN_TYPE,

        /** SHA-256 equals the content we last applied: already have it. */
        SKIP_DUPLICATE
    }

    fun decide(
        totalLen: Long,
        maxApplyBytes: Long,
        innerContentType: Byte,
        announceShaHex: String,
        lastAppliedContentHashHex: String?
    ): Decision {
        if (java.lang.Long.compareUnsigned(totalLen, maxApplyBytes) > 0) {
            return Decision.SKIP_OVER_LIMIT
        }
        if (innerContentType != Crypto.INNER_TEXT) return Decision.SKIP_UNKNOWN_TYPE
        if (lastAppliedContentHashHex != null && announceShaHex.equals(lastAppliedContentHashHex, ignoreCase = true)) {
            return Decision.SKIP_DUPLICATE
        }
        return Decision.FETCH
    }
}
