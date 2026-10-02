//! Pending outbound transfers (large-text store).
//!
//! The sender keeps the plaintext bytes of each large message for
//! `transfer_ttl_secs` so peers can fetch them over TCP. The store keeps
//! only the newest [`MAX_PENDING_TRANSFERS`] transfers under a global
//! [`DEFAULT_MEMORY_CAP_BYTES`] memory cap, evicting oldest first. A
//! transfer may be fetched by multiple peers during its TTL, up to
//! [`DEFAULT_MAX_FETCHES_PER_TRANSFER`] serves.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Keep only the newest N pending transfers; evict oldest first.
pub const MAX_PENDING_TRANSFERS: usize = 4;
/// Global cap on buffered pending-transfer bytes.
pub const DEFAULT_MEMORY_CAP_BYTES: u64 = 128 * 1024 * 1024;
/// A transfer is served at most this many times before the server stops.
pub const DEFAULT_MAX_FETCHES_PER_TRANSFER: u32 = 16;

#[derive(Debug, Clone)]
pub struct PendingTransfer {
    pub id: [u8; 16],
    pub data: Arc<[u8]>,
    pub sha256: [u8; 32],
    pub expires_at: Instant,
    pub fetches_used: u32,
}

#[derive(Debug)]
pub struct TransferStore {
    entries: VecDeque<PendingTransfer>,
    memory_used: u64,
    ttl: Duration,
    max_fetches_per_transfer: u32,
    memory_cap: u64,
}

impl TransferStore {
    pub fn new(ttl: Duration, max_fetches_per_transfer: u32, memory_cap: u64) -> Self {
        Self {
            entries: VecDeque::new(),
            memory_used: 0,
            ttl,
            max_fetches_per_transfer,
            memory_cap,
        }
    }

    pub fn with_defaults(ttl: Duration) -> Self {
        Self::new(
            ttl,
            DEFAULT_MAX_FETCHES_PER_TRANSFER,
            DEFAULT_MEMORY_CAP_BYTES,
        )
    }

    /// Register a pending transfer. Returns its SHA-256. Evicts expired
    /// entries first, then oldest-first while over the count or memory cap.
    pub fn insert(&mut self, id: [u8; 16], bytes: Vec<u8>) -> [u8; 32] {
        self.prune_expired();
        let sha256 = crate::tcp::sha256(&bytes);
        let len = bytes.len() as u64;
        self.entries.push_back(PendingTransfer {
            id,
            data: Arc::from(bytes.into_boxed_slice()),
            sha256,
            expires_at: Instant::now() + self.ttl,
            fetches_used: 0,
        });
        self.memory_used += len;
        while self.entries.len() > MAX_PENDING_TRANSFERS {
            self.pop_oldest();
        }
        while self.memory_used > self.memory_cap {
            if self.entries.len() <= 1 {
                break;
            }
            self.pop_oldest();
        }
        sha256
    }

    /// Look up a live transfer without recording a fetch (peeks, for tests).
    pub fn get(&mut self, id: &[u8; 16]) -> Option<PendingTransfer> {
        self.prune_expired();
        self.entries.iter().find(|e| &e.id == id).cloned()
    }

    /// Serve one fetch: returns the bytes if the transfer is live and under
    /// the per-transfer fetch budget, recording the use. Expired, unknown,
    /// or exhausted ids yield `None`.
    pub fn serve(&mut self, id: &[u8; 16]) -> Option<(Arc<[u8]>, [u8; 32])> {
        self.prune_expired();
        let entry = self.entries.iter_mut().find(|e| &e.id == id)?;
        if entry.fetches_used >= self.max_fetches_per_transfer {
            return None;
        }
        entry.fetches_used += 1;
        Some((Arc::clone(&entry.data), entry.sha256))
    }

    pub fn len(&mut self) -> usize {
        self.prune_expired();
        self.entries.len()
    }

    pub fn is_empty(&mut self) -> bool {
        self.len() == 0
    }

    pub fn memory_used(&self) -> u64 {
        self.memory_used
    }

    pub fn fetch_count(&mut self, id: &[u8; 16]) -> Option<u32> {
        self.prune_expired();
        self.entries
            .iter()
            .find(|e| &e.id == id)
            .map(|e| e.fetches_used)
    }

    fn pop_oldest(&mut self) {
        if let Some(old) = self.entries.pop_front() {
            self.memory_used = self.memory_used.saturating_sub(old.data.len() as u64);
        }
    }

    fn prune_expired(&mut self) {
        let now = Instant::now();
        while self.entries.front().is_some_and(|e| now >= e.expires_at) {
            self.pop_oldest();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> TransferStore {
        TransferStore::with_defaults(Duration::from_secs(120))
    }

    fn id(n: u8) -> [u8; 16] {
        [n; 16]
    }

    #[test]
    fn insert_and_serve_round_trip() {
        let mut s = store();
        let sha = s.insert(id(1), b"hello large".to_vec());
        assert_eq!(sha, crate::tcp::sha256(b"hello large"));
        let (data, got_sha) = s.serve(&id(1)).expect("live transfer serves");
        assert_eq!(&*data, b"hello large");
        assert_eq!(got_sha, sha);
        assert_eq!(s.fetch_count(&id(1)), Some(1));
    }

    #[test]
    fn unknown_id_serves_nothing() {
        let mut s = store();
        s.insert(id(1), b"x".to_vec());
        assert!(s.serve(&id(2)).is_none());
    }

    #[test]
    fn keeps_only_newest_four_evict_oldest_first() {
        let mut s = store();
        for n in 0..6u8 {
            s.insert(id(n), vec![n; 10]);
        }
        assert_eq!(s.len(), 4);
        assert!(s.serve(&id(0)).is_none());
        assert!(s.serve(&id(1)).is_none());
        assert!(s.serve(&id(2)).is_some());
        assert!(s.serve(&id(5)).is_some());
    }

    #[test]
    fn global_memory_cap_evicts_oldest() {
        let mut s = TransferStore::new(Duration::from_secs(120), 16, 100);
        s.insert(id(1), vec![1u8; 60]);
        s.insert(id(2), vec![2u8; 60]);
        // 120 bytes buffered against a 100-byte cap: the oldest must go.
        assert!(s.serve(&id(1)).is_none(), "oldest evicted by memory cap");
        assert!(s.serve(&id(2)).is_some());
        assert!(s.memory_used() <= 100);
    }

    #[test]
    fn ttl_expiry_stops_serving() {
        let mut s = TransferStore::with_defaults(Duration::ZERO);
        s.insert(id(1), b"ephemeral".to_vec());
        assert!(s.serve(&id(1)).is_none(), "zero TTL is already expired");
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn per_transfer_fetch_budget_enforced() {
        let mut s = TransferStore::new(Duration::from_secs(120), 2, DEFAULT_MEMORY_CAP_BYTES);
        s.insert(id(9), b"twice".to_vec());
        assert!(s.serve(&id(9)).is_some());
        assert!(s.serve(&id(9)).is_some());
        assert!(s.serve(&id(9)).is_none(), "third fetch exceeds budget of 2");
    }

    #[test]
    fn transfer_may_be_fetched_by_multiple_peers() {
        let mut s = store();
        s.insert(id(3), b"shared".to_vec());
        for _ in 0..5 {
            assert!(s.serve(&id(3)).is_some());
        }
        assert_eq!(s.fetch_count(&id(3)), Some(5));
    }
}
