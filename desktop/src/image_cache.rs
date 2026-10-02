//! Temporary sender-side image cache (disk-backed).
//!
//! An announced image must stay available after its UDP announcement because
//! receivers fetch it over TCP seconds later. Images live as individual
//! files under `~/.local/state/clipcast/images/<hex transfer_id>` with
//! restrictive permissions (dir `0700`, files `0600`), plus an in-memory
//! index carrying MIME type, length, hash, and expiry. Entries expire after
//! `image_cache_ttl_secs` (default 600 s) and the cache keeps at most
//! `max_cached_images` (default 20), oldest first. The cache is temporary:
//! expired entries are deleted, never retained.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// How long a sent image stays fetchable.
pub const DEFAULT_IMAGE_CACHE_TTL: Duration = Duration::from_secs(600);
/// Maximum images retained; oldest-first eviction beyond this.
pub const DEFAULT_MAX_CACHED_IMAGES: usize = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedImage {
    pub id: [u8; 16],
    pub mime_type: String,
    pub len: u64,
    pub sha256: [u8; 32],
}

struct Entry {
    meta: CachedImage,
    expires_at: Instant,
}

pub struct ImageCache {
    dir: PathBuf,
    entries: VecDeque<Entry>,
    ttl: Duration,
    max_images: usize,
}

fn hex16(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

impl ImageCache {
    /// Open (creating) the cache directory with `0700` permissions.
    pub fn new(dir: PathBuf, ttl: Duration, max_images: usize) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        set_restrictive_dir(&dir)?;
        Ok(Self {
            dir,
            entries: VecDeque::new(),
            ttl,
            max_images: std::cmp::max(max_images, 1),
        })
    }

    pub fn dir(&self) -> &PathBuf {
        &self.dir
    }

    /// Store image bytes, returning their SHA-256. Evicts expired entries
    /// first, then oldest-first while over the entry cap.
    pub fn insert(
        &mut self,
        id: [u8; 16],
        mime_type: &str,
        bytes: &[u8],
    ) -> std::io::Result<[u8; 32]> {
        self.prune_expired();
        let sha256 = crate::tcp::sha256(bytes);
        std::fs::write(self.path_for(&id), bytes)?;
        set_restrictive_file(&self.path_for(&id))?;
        // Re-announcing the same transfer id refreshes the entry.
        self.entries.retain(|e| e.meta.id != id);
        self.entries.push_back(Entry {
            meta: CachedImage {
                id,
                mime_type: mime_type.to_string(),
                len: bytes.len() as u64,
                sha256,
            },
            expires_at: Instant::now() + self.ttl,
        });
        while self.entries.len() > self.max_images {
            self.pop_oldest();
        }
        Ok(sha256)
    }

    /// Serve one fetch: returns `(bytes, mime_type, sha256)` for a live
    /// transfer. Expired, unknown, or unreadable ids yield `None`.
    pub fn serve(&mut self, id: &[u8; 16]) -> Option<(Vec<u8>, String, [u8; 32])> {
        self.prune_expired();
        let meta = self.entries.iter().find(|e| &e.meta.id == id)?.meta.clone();
        match std::fs::read(self.path_for(id)) {
            Ok(bytes) if bytes.len() as u64 == meta.len => {
                Some((bytes, meta.mime_type, meta.sha256))
            }
            // File vanished or size drifted: drop the index entry too.
            _ => {
                self.entries.retain(|e| &e.meta.id != id);
                std::fs::remove_file(self.path_for(id)).ok();
                None
            }
        }
    }

    /// Metadata lookup without reading bytes (for tests/diagnostics).
    pub fn get(&mut self, id: &[u8; 16]) -> Option<CachedImage> {
        self.prune_expired();
        self.entries
            .iter()
            .find(|e| &e.meta.id == id)
            .map(|e| e.meta.clone())
    }

    pub fn len(&mut self) -> usize {
        self.prune_expired();
        self.entries.len()
    }

    pub fn is_empty(&mut self) -> bool {
        self.len() == 0
    }

    fn path_for(&self, id: &[u8; 16]) -> PathBuf {
        self.dir.join(hex16(id))
    }

    fn pop_oldest(&mut self) {
        if let Some(old) = self.entries.pop_front() {
            std::fs::remove_file(self.path_for(&old.meta.id)).ok();
        }
    }

    fn prune_expired(&mut self) {
        let now = Instant::now();
        while self.entries.front().is_some_and(|e| now >= e.expires_at) {
            self.pop_oldest();
        }
    }
}

#[cfg(unix)]
fn set_restrictive_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

#[cfg(unix)]
fn set_restrictive_file(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_restrictive_dir(_dir: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
fn set_restrictive_file(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

/// Test helper (all modules' tests): a cache in a fresh unique temp dir.
#[cfg(test)]
pub fn temp_image_cache(
    ttl: Duration,
    max_images: usize,
) -> (std::sync::Arc<std::sync::Mutex<ImageCache>>, PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "clipcast-imgcache-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    ));
    let cache = ImageCache::new(dir.clone(), ttl, max_images).unwrap();
    (std::sync::Arc::new(std::sync::Mutex::new(cache)), dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("clipcast-imgcache-test-{name}"));
        std::fs::remove_dir_all(&dir).ok();
        dir
    }

    fn sample_png() -> Vec<u8> {
        // Minimal 1x1 PNG (opaque red); deterministic test bytes.
        vec![
            0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, b'I', b'H',
            b'D', b'R', 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00,
            0x00, 0x90, 0x77, 0x53, 0xde, 0x00, 0x00, 0x00, 0x0c, b'I', b'D', b'A', b'T', 0x08,
            0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x05, 0xfe,
            0xd4, 0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82,
        ]
    }

    #[test]
    fn insert_serve_round_trip() {
        let dir = test_dir("roundtrip");
        let mut cache = ImageCache::new(dir.clone(), DEFAULT_IMAGE_CACHE_TTL, 20).unwrap();
        let id = [0xA5; 16];
        let bytes = sample_png();
        let sha = cache.insert(id, "image/png", &bytes).unwrap();
        assert_eq!(sha, crate::tcp::sha256(&bytes));
        let (got, mime, got_sha) = cache.serve(&id).unwrap();
        assert_eq!(got, bytes);
        assert_eq!(mime, "image/png");
        assert_eq!(got_sha, sha);
        assert_eq!(cache.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn unknown_transfer_id_is_rejected() {
        let dir = test_dir("unknown");
        let mut cache = ImageCache::new(dir.clone(), DEFAULT_IMAGE_CACHE_TTL, 20).unwrap();
        assert!(cache.serve(&[0xFF; 16]).is_none());
        assert!(cache.get(&[0xFF; 16]).is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn expired_image_is_deleted() {
        let dir = test_dir("expiry");
        let mut cache = ImageCache::new(dir.clone(), Duration::from_millis(5), 20).unwrap();
        let id = [0x11; 16];
        cache.insert(id, "image/jpeg", b"fake-jpeg").unwrap();
        assert!(cache.serve(&id).is_some());
        std::thread::sleep(Duration::from_millis(15));
        assert!(cache.serve(&id).is_none());
        assert_eq!(cache.len(), 0);
        // Backing file is gone too, not just the index entry.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oldest_first_eviction_over_cap() {
        let dir = test_dir("evict");
        let mut cache = ImageCache::new(dir.clone(), DEFAULT_IMAGE_CACHE_TTL, 3).unwrap();
        for i in 0..5u8 {
            cache.insert([i; 16], "image/png", &sample_png()).unwrap();
        }
        assert_eq!(cache.len(), 3);
        assert!(cache.serve(&[0; 16]).is_none());
        assert!(cache.serve(&[1; 16]).is_none());
        assert!(cache.serve(&[4; 16]).is_some());
        // Evicted files are removed from disk.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 3);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[cfg(unix)]
    fn files_have_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let dir = test_dir("perms");
        let mut cache = ImageCache::new(dir.clone(), DEFAULT_IMAGE_CACHE_TTL, 20).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        cache
            .insert([0x22; 16], "image/png", &sample_png())
            .unwrap();
        let file = dir.join("22222222222222222222222222222222");
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o600
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}
