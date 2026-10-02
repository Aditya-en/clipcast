//! Pending outbound transfers (large-text store + TTL/eviction).
//!
//! Full implementation lands in milestone 2; this stub holds the shared
//! limits so the protocol module and config can reference them.

/// Keep only the newest N pending transfers; evict oldest first.
pub const MAX_PENDING_TRANSFERS: usize = 4;
/// Global cap on buffered pending-transfer bytes.
pub const DEFAULT_MEMORY_CAP_BYTES: u64 = 128 * 1024 * 1024;
