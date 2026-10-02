//! The sync state machine.
//!
//! Generic over two traits so it can be tested without a display or network:
//! `ClipboardBackend` and `Transport`. Real implementations live in
//! `crate::clipboard` and `crate::net`.
//!
//! Echo-loop prevention: content we write locally is never rebroadcast.
//! A received packet with our own device_id is ignored, received content is
//! never forwarded, and a change event matching `last_applied_content_hash`
//! inside the suppression window (~1 s) is dropped.
//!
//! Ordering: a Lamport clock with device-id tiebreak (never wall-clock for
//! ordering). Local copies bump `lamport = max(lamport, unix_ms) + 1`; a
//! received packet is applied only if `(lamport, device_id) > last_applied`.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing::{debug, warn};

use crate::crypto::{self, KeyBytes};
use crate::fetch::{FetchError, FetchParams, fetch_transfer};
use crate::image_cache::ImageCache;
use crate::proto::{
    self, AnnouncePayload, Body, CONTENT_ANNOUNCE, CONTENT_TEXT, DEVICE_ID_LEN, Header,
    INNER_IMAGE, INNER_TEXT, MSG_CLIP_UPDATE,
};
use crate::tcp::sha256;
use crate::transfer::TransferStore;

pub const DEFAULT_MAX_TEXT_BYTES: usize = 1200;
/// Inline limit for v2 (same default as the v1 `max_text_bytes`).
pub const DEFAULT_INLINE_MAX_BYTES: usize = 1200;
/// Per-transfer ceiling (64 MiB).
pub const DEFAULT_MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
/// Per-image ceiling (16 MiB): larger images are never announced or fetched.
pub const DEFAULT_MAX_IMAGE_BYTES: u64 = 16 * 1024 * 1024;
/// How long a sent image stays fetchable from the disk cache.
pub const DEFAULT_IMAGE_CACHE_TTL: Duration = Duration::from_secs(600);
/// Maximum images retained in the sender disk cache.
pub const DEFAULT_MAX_CACHED_IMAGES: usize = 20;
/// How long a pending transfer stays fetchable.
pub const DEFAULT_TRANSFER_TTL: Duration = Duration::from_secs(120);
/// Overall cap for one fetch.
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(120);
/// Default TCP side-channel port.
pub const DEFAULT_TCP_PORT: u16 = 47475;
/// Cap on simultaneous outgoing fetches.
pub const MAX_CONCURRENT_FETCHES: usize = 2;
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(100);
pub const DEFAULT_SUPPRESSION: Duration = Duration::from_secs(1);
pub const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 20;

/// One clipboard item the sync engine understands. Text keeps the existing
/// behavior; images are announced over UDP and fetched over TCP, never sent
/// inline. Backends that cannot produce an image report `None`/unsupported
/// instead of pretending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardContent {
    Text(String),
    Image(ClipboardImage),
}

/// Raw image bytes with their MIME type, as exchanged with backends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardImage {
    pub mime_type: String,
    pub bytes: Vec<u8>,
}

impl ClipboardImage {
    /// Short hash of the image bytes for echo suppression.
    pub fn suppression_hash(&self) -> u64 {
        crypto::content_hash_bytes(&self.bytes)
    }
}

impl ClipboardContent {
    /// Short hash of the content bytes (text UTF-8 or raw image bytes) for
    /// echo suppression. Text and images share one suppression namespace.
    pub fn suppression_hash(&self) -> u64 {
        match self {
            ClipboardContent::Text(t) => crypto::content_hash(t),
            ClipboardContent::Image(img) => crypto::content_hash_bytes(&img.bytes),
        }
    }
}

/// A local clipboard change delivered by a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardEvent {
    pub content: ClipboardContent,
    /// The backend flagged this content as secret (e.g. MIME type
    /// `x-kde-passwordManagerHint` with value `secret`).
    pub sensitive: bool,
}

impl ClipboardEvent {
    pub fn text(text: String, sensitive: bool) -> Self {
        Self {
            content: ClipboardContent::Text(text),
            sensitive,
        }
    }

    pub fn image(mime_type: String, bytes: Vec<u8>) -> Self {
        Self {
            content: ClipboardContent::Image(ClipboardImage { mime_type, bytes }),
            sensitive: false,
        }
    }
}

/// Content applied to the local clipboard from a remote peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppliedContent {
    Text(String),
    Image(ClipboardImage),
}

impl AppliedContent {
    pub fn as_text(&self) -> Option<&str> {
        match self {
            AppliedContent::Text(t) => Some(t),
            AppliedContent::Image(_) => None,
        }
    }
}

/// Local clipboard access.
pub trait ClipboardBackend {
    fn get_text(&self) -> std::io::Result<Option<String>>;
    fn set_text(&self, text: &str) -> std::io::Result<()>;
    /// Read the current clipboard image, if the backend supports it and the
    /// clipboard currently holds a supported image MIME type. Defaults to
    /// `None` (backend cannot provide images).
    fn get_image(&self) -> std::io::Result<Option<ClipboardImage>> {
        Ok(None)
    }
    /// Publish an image so local applications can paste it. The default
    /// reports unsupported; backends override where the platform allows it.
    fn set_image(&self, _image: &ClipboardImage) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "image clipboard not supported by this backend",
        ))
    }
    /// MIME types this backend can supply (for `doctor` diagnostics).
    fn image_mime_types(&self) -> Vec<String> {
        Vec::new()
    }
    /// Subscribe to change events. May be called more than once; each caller
    /// gets its own channel.
    fn subscribe_changes(&self) -> Receiver<ClipboardEvent>;
}

impl ClipboardBackend for Box<dyn ClipboardBackend> {
    fn get_text(&self) -> std::io::Result<Option<String>> {
        (**self).get_text()
    }
    fn set_text(&self, text: &str) -> std::io::Result<()> {
        (**self).set_text(text)
    }
    fn get_image(&self) -> std::io::Result<Option<ClipboardImage>> {
        (**self).get_image()
    }
    fn set_image(&self, image: &ClipboardImage) -> std::io::Result<()> {
        (**self).set_image(image)
    }
    fn image_mime_types(&self) -> Vec<String> {
        (**self).image_mime_types()
    }
    fn subscribe_changes(&self) -> Receiver<ClipboardEvent> {
        (**self).subscribe_changes()
    }
}

/// Packet transport.
pub trait Transport {
    fn send(&self, bytes: &[u8]);
    fn recv(&self) -> Receiver<Datagram>;
}

/// One received UDP datagram with its source address.
///
/// The source IP is the ONLY address a large-text fetch may dial: the
/// receiver fetches from the announce's UDP source IP at the announce's
/// tcp_port, never from any address carried inside the payload.
#[derive(Debug, Clone)]
pub struct Datagram {
    pub bytes: Vec<u8>,
    pub source: Option<IpAddr>,
}

impl Datagram {
    pub fn new(bytes: Vec<u8>, source: Option<IpAddr>) -> Self {
        Self { bytes, source }
    }
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub key: KeyBytes,
    pub device_id: [u8; DEVICE_ID_LEN],
    pub max_text_bytes: usize,
    /// v2 inline limit: text at or below this size is sent as a v1 inline
    /// message. Kept equal to `max_text_bytes` unless configured otherwise.
    pub inline_max_bytes: usize,
    /// v2 per-transfer ceiling; larger local text is never sent.
    pub max_transfer_bytes: u64,
    /// Per-image ceiling; larger local images are never sent and larger
    /// remote announces are never fetched.
    pub max_image_bytes: u64,
    /// How long a sent image stays fetchable from the disk cache.
    pub image_cache_ttl: Duration,
    /// Maximum images retained in the sender disk cache.
    pub max_cached_images: usize,
    /// TCP side-channel port we listen on and advertise in announces.
    pub tcp_port: u16,
    /// How long a pending outbound transfer stays fetchable.
    pub transfer_ttl: Duration,
    /// Overall cap for one incoming fetch.
    pub fetch_timeout: Duration,
    pub skip_sensitive: bool,
    pub debounce: Duration,
    pub suppression: Duration,
    pub rate_limit_per_sec: u32,
    /// Debug only: log clipboard content. Off by default — content must not
    /// appear in logs.
    pub log_content: bool,
}

impl Default for EngineConfig {
    /// Defaults suitable for tests only (`key`/`device_id` are all zeros —
    /// never use this for a real daemon).
    fn default() -> Self {
        Self {
            key: [0u8; 32],
            device_id: [0u8; DEVICE_ID_LEN],
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
            inline_max_bytes: DEFAULT_INLINE_MAX_BYTES,
            max_transfer_bytes: DEFAULT_MAX_TRANSFER_BYTES,
            max_image_bytes: DEFAULT_MAX_IMAGE_BYTES,
            image_cache_ttl: DEFAULT_IMAGE_CACHE_TTL,
            max_cached_images: DEFAULT_MAX_CACHED_IMAGES,
            tcp_port: DEFAULT_TCP_PORT,
            transfer_ttl: DEFAULT_TRANSFER_TTL,
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,
            skip_sensitive: true,
            debounce: DEFAULT_DEBOUNCE,
            suppression: DEFAULT_SUPPRESSION,
            rate_limit_per_sec: DEFAULT_RATE_LIMIT_PER_SEC,
            log_content: false,
        }
    }
}

/// Short, content-independent description of a clipboard item for logging.
fn content_meta(content: &ClipboardContent) -> String {
    match content {
        ClipboardContent::Text(text) => format!(
            "text len={} hash={:08x}",
            text.len(),
            crypto::content_hash(text) >> 32
        ),
        ClipboardContent::Image(img) => format!(
            "image {} len={} hash={:08x}",
            img.mime_type,
            img.bytes.len(),
            crypto::content_hash_bytes(&img.bytes) >> 32
        ),
    }
}

fn hex16(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Engine<B: ClipboardBackend, T: Transport> {
    backend: B,
    transport: T,
    cfg: EngineConfig,
    lamport: u64,
    last_applied: (u64, [u8; DEVICE_ID_LEN]),
    last_applied_hash: Option<u64>,
    suppression_deadline: Option<Instant>,
    pending: Option<ClipboardContent>,
    pending_since: Option<Instant>,
    recent_recv: VecDeque<Instant>,
    /// Plaintext of outbound large texts, shared with the TCP server thread.
    store: Arc<Mutex<TransferStore>>,
    /// Sender-side image disk cache, shared with the TCP server thread.
    /// `None` until the daemon wires the real cache (tests set a temp one);
    /// without it images are neither sent nor served.
    images: Option<Arc<Mutex<ImageCache>>>,
    /// Fetches the run loop should spawn (drained after each accepted announce).
    pending_fetch_requests: Vec<FetchRequest>,
    active_fetches: Vec<ActiveFetch>,
    /// MIME types of in-flight image fetches, by transfer id. The MIME comes
    /// from the authenticated announce — never from the TCP bytes.
    pending_image_mimes: Vec<([u8; 16], String)>,
    /// Transfer ids whose in-flight fetch was cancelled by a newer message.
    cancelled_fetch_ids: Vec<[u8; 16]>,
}

/// One accepted announce awaiting (or undergoing) a TCP fetch.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    pub transfer_id: [u8; 16],
    pub total_len: u64,
    pub expected_sha256: [u8; 32],
    pub tcp_port: u16,
    /// The announce datagram's source IP — the only address we may dial.
    pub source: IpAddr,
    pub lamport: u64,
    pub device_id: [u8; DEVICE_ID_LEN],
    pub inner_content_type: u8,
    pub cancel: Arc<AtomicBool>,
}

struct ActiveFetch {
    transfer_id: [u8; 16],
    total_len: u64,
    expected_sha256: [u8; 32],
    inner_content_type: u8,
    lamport: u64,
    device_id: [u8; DEVICE_ID_LEN],
    cancel: Arc<AtomicBool>,
}

enum Incoming {
    Local(ClipboardEvent),
    Remote(Datagram),
    FetchResult {
        transfer_id: [u8; 16],
        result: Result<Vec<u8>, FetchError>,
    },
    Shutdown,
}

impl EngineConfig {
    /// Construct with explicit identity; all other fields use defaults.
    pub fn new(key: KeyBytes, device_id: [u8; DEVICE_ID_LEN]) -> Self {
        Self {
            key,
            device_id,
            ..Self::default()
        }
    }
}

impl<B: ClipboardBackend, T: Transport> Engine<B, T> {
    pub fn new(backend: B, transport: T, cfg: EngineConfig) -> Self {
        let store = Arc::new(Mutex::new(TransferStore::with_defaults(cfg.transfer_ttl)));
        Self {
            backend,
            transport,
            cfg,
            lamport: 0,
            last_applied: (0, [0u8; DEVICE_ID_LEN]),
            last_applied_hash: None,
            suppression_deadline: None,
            pending: None,
            pending_since: None,
            recent_recv: VecDeque::new(),
            store,
            images: None,
            pending_fetch_requests: Vec::new(),
            active_fetches: Vec::new(),
            pending_image_mimes: Vec::new(),
            cancelled_fetch_ids: Vec::new(),
        }
    }

    pub fn device_id(&self) -> [u8; DEVICE_ID_LEN] {
        self.cfg.device_id
    }

    /// Shared outbound-transfer store (also served by the TCP listener).
    pub fn transfer_store(&self) -> Arc<Mutex<TransferStore>> {
        Arc::clone(&self.store)
    }

    /// Wire the sender-side image disk cache (also served by the TCP
    /// listener). The daemon calls this at startup; tests use temp dirs.
    pub fn set_image_cache(&mut self, images: Arc<Mutex<ImageCache>>) {
        self.images = Some(images);
    }

    pub fn image_cache(&self) -> Option<Arc<Mutex<ImageCache>>> {
        self.images.as_ref().map(Arc::clone)
    }

    /// Drain queued fetch requests (each accepted announce queues exactly
    /// one). The run loop spawns a worker per request; tests drive
    /// [`complete_fetch`](Self::complete_fetch) manually instead.
    pub fn take_fetch_requests(&mut self) -> Vec<FetchRequest> {
        std::mem::take(&mut self.pending_fetch_requests)
    }

    pub fn active_fetch_count(&self) -> usize {
        self.active_fetches.len()
    }

    /// Transfer ids whose in-flight fetch was cancelled by a newer message.
    pub fn cancelled_fetch_ids(&self) -> Vec<[u8; 16]> {
        self.cancelled_fetch_ids.clone()
    }

    /// Build fetch parameters for a queued request (real TCP dial). The
    /// per-fetch byte ceiling follows the content kind: text announces use
    /// `max_transfer_bytes`, image announces use `max_image_bytes`.
    pub fn fetch_params(&self, req: &FetchRequest) -> FetchParams {
        let max_bytes = if req.inner_content_type == INNER_IMAGE {
            self.cfg.max_image_bytes
        } else {
            self.cfg.max_transfer_bytes
        };
        FetchParams {
            key: self.cfg.key,
            client_device_id: self.cfg.device_id,
            server_ip: req.source,
            tcp_port: req.tcp_port,
            transfer_id: req.transfer_id,
            total_len: req.total_len,
            expected_sha256: req.expected_sha256,
            inner_content_type: req.inner_content_type,
            max_transfer_bytes: max_bytes,
            total_timeout: self.cfg.fetch_timeout,
        }
    }

    /// Handle a local clipboard change.
    ///
    /// Returns the sealed packet when it was sent immediately (debounce of
    /// zero); otherwise the change is parked as `pending` until
    /// [`flush_debounce`](Self::flush_debounce).
    pub fn handle_local_change(&mut self, event: ClipboardEvent) -> Option<Vec<u8>> {
        if event.sensitive && self.cfg.skip_sensitive {
            debug!(
                "not broadcasting sensitive content {}",
                content_meta(&event.content)
            );
            return None;
        }
        let echo = self
            .suppression_deadline
            .is_some_and(|d| Instant::now() < d)
            && self.last_applied_hash == Some(event.content.suppression_hash());
        if echo {
            debug!(
                "suppressed echo of applied content {}",
                content_meta(&event.content)
            );
            return None;
        }
        if self.cfg.debounce.is_zero() {
            return self.send_content(event.content);
        }
        self.pending = Some(event.content);
        self.pending_since = Some(Instant::now());
        None
    }

    /// Send the parked local change if the debounce window has elapsed.
    pub fn flush_debounce(&mut self) {
        let Some(since) = self.pending_since else {
            return;
        };
        if since.elapsed() < self.cfg.debounce {
            return;
        }
        if let Some(content) = self.pending.take() {
            self.pending_since = None;
            self.send_content(content);
        }
    }

    /// Time until the next debounced send is due (large when nothing pending).
    pub fn time_until_flush(&self) -> Duration {
        match self.pending_since {
            Some(since) => self.cfg.debounce.saturating_sub(since.elapsed()),
            None => Duration::from_secs(3600),
        }
    }

    /// Send one local clipboard item immediately: small text goes inline,
    /// large text goes as a v2 announce, images go as an image announce
    /// backed by the disk cache. Over-limit content is logged (type and
    /// size only, never bytes) and not sent.
    fn send_content(&mut self, content: ClipboardContent) -> Option<Vec<u8>> {
        match content {
            ClipboardContent::Text(text) => self.send_text(text),
            ClipboardContent::Image(image) => self.send_image(image),
        }
    }

    /// Send one local text immediately: inline v1 message when small,
    /// v2 announce + pending transfer when large, nothing when over-limit.
    fn send_text(&mut self, text: String) -> Option<Vec<u8>> {
        if text.len() <= self.cfg.inline_max_bytes {
            return Some(self.send_inline(text));
        }
        if (text.len() as u64) <= self.cfg.max_transfer_bytes {
            return Some(self.send_announce(text));
        }
        warn!(
            "local text too long to sync: {} bytes (max_transfer {} bytes); length only, content not logged",
            text.len(),
            self.cfg.max_transfer_bytes
        );
        None
    }

    fn send_inline(&mut self, text: String) -> Vec<u8> {
        let now_ms = unix_ms();
        self.lamport = self.lamport.max(now_ms) + 1;
        self.last_applied = (self.lamport, self.cfg.device_id);
        let header = Header {
            version: proto::VERSION,
            msg_type: MSG_CLIP_UPDATE,
            device_id: self.cfg.device_id,
            nonce: crypto::generate_nonce(),
        };
        let body = Body {
            lamport: self.lamport,
            timestamp_ms: now_ms,
            content_type: CONTENT_TEXT,
            payload: text.clone().into_bytes(),
        };
        let packet = crypto::seal(&self.cfg.key, &header, &body);
        debug!(
            "broadcasting local change lamport={} {}",
            self.lamport,
            content_meta(&ClipboardContent::Text(text.clone()))
        );
        self.transport.send(&packet);
        packet
    }

    /// Register a pending transfer and broadcast one UDP announce for it.
    fn send_announce(&mut self, text: String) -> Vec<u8> {
        let bytes = text.into_bytes();
        let total_len = bytes.len() as u64;
        let transfer_id = crypto::generate_transfer_id();
        let announced_sha = self.store.lock().unwrap().insert(transfer_id, bytes);
        let now_ms = unix_ms();
        self.lamport = self.lamport.max(now_ms) + 1;
        self.last_applied = (self.lamport, self.cfg.device_id);
        let header = Header {
            version: proto::VERSION,
            msg_type: MSG_CLIP_UPDATE,
            device_id: self.cfg.device_id,
            nonce: crypto::generate_nonce(),
        };
        let payload = proto::encode_announce(&AnnouncePayload {
            inner_content_type: INNER_TEXT,
            transfer_id,
            total_len,
            sha256: announced_sha,
            tcp_port: self.cfg.tcp_port,
        });
        let body = Body {
            lamport: self.lamport,
            timestamp_ms: now_ms,
            content_type: CONTENT_ANNOUNCE,
            payload: payload.to_vec(),
        };
        let packet = crypto::seal(&self.cfg.key, &header, &body);
        debug!(
            "broadcasting announce lamport={} transfer={} total_len={}",
            self.lamport,
            hex16(&transfer_id),
            total_len
        );
        self.transport.send(&packet);
        packet
    }

    /// Store a local image in the disk cache and broadcast one UDP image
    /// announce for it. The image MUST be fully stored (and hashed) before
    /// the announce goes out, so receivers can fetch it immediately.
    fn send_image(&mut self, image: ClipboardImage) -> Option<Vec<u8>> {
        let len = image.bytes.len() as u64;
        if !proto::is_supported_image_mime(&image.mime_type) {
            debug!(
                "image not sent: unsupported MIME type {} (len={})",
                image.mime_type,
                image.bytes.len()
            );
            return None;
        }
        if len > self.cfg.max_image_bytes {
            warn!(
                "image not sent: {}, {:.1} MiB exceeds {:.0} MiB limit; MIME and size only, bytes never logged",
                image.mime_type,
                len as f64 / (1024.0 * 1024.0),
                self.cfg.max_image_bytes as f64 / (1024.0 * 1024.0),
            );
            return None;
        }
        let Some(cache) = self.images.as_ref().map(Arc::clone) else {
            warn!("image not sent: no image cache wired");
            return None;
        };
        let transfer_id = crypto::generate_transfer_id();
        let announced_sha =
            match cache
                .lock()
                .unwrap()
                .insert(transfer_id, &image.mime_type, &image.bytes)
            {
                Ok(sha) => sha,
                Err(e) => {
                    warn!("image not sent: cache store failed: {e}");
                    return None;
                }
            };
        let now_ms = unix_ms();
        self.lamport = self.lamport.max(now_ms) + 1;
        self.last_applied = (self.lamport, self.cfg.device_id);
        let header = Header {
            version: proto::VERSION,
            msg_type: MSG_CLIP_UPDATE,
            device_id: self.cfg.device_id,
            nonce: crypto::generate_nonce(),
        };
        let payload = proto::encode_image_announce(&proto::ImageAnnouncePayload {
            transfer_id,
            total_len: len,
            sha256: announced_sha,
            tcp_port: self.cfg.tcp_port,
            mime_type: image.mime_type.clone(),
        });
        let body = Body {
            lamport: self.lamport,
            timestamp_ms: now_ms,
            content_type: CONTENT_ANNOUNCE,
            payload,
        };
        let packet = crypto::seal(&self.cfg.key, &header, &body);
        debug!(
            "broadcasting image announce lamport={} transfer={} {} len={}",
            self.lamport,
            hex16(&transfer_id),
            image.mime_type,
            len
        );
        self.transport.send(&packet);
        Some(packet)
    }

    /// Handle a received datagram. Returns the applied content for inline
    /// messages, if any. An accepted announce queues exactly one fetch
    /// request (see [`take_fetch_requests`](Self::take_fetch_requests)) and
    /// returns `None`; drive [`complete_fetch`](Self::complete_fetch) when
    /// the TCP fetch finishes.
    pub fn handle_packet(
        &mut self,
        datagram: &[u8],
        source: Option<IpAddr>,
    ) -> Option<AppliedContent> {
        if !self.take_recv_token() {
            debug!("dropping packet: rate limit exceeded");
            return None;
        }
        let (header, body) = match crypto::open(&self.cfg.key, datagram) {
            Ok(v) => v,
            Err(e) => {
                debug!("dropping malformed packet: {e}");
                return None;
            }
        };
        if header.device_id == self.cfg.device_id {
            debug!("ignoring packet with our own device_id");
            return None;
        }
        if header.msg_type != MSG_CLIP_UPDATE {
            debug!("ignoring reserved msg_type {:#04x}", header.msg_type);
            return None;
        }
        if body.content_type == CONTENT_ANNOUNCE {
            self.handle_announce(&header, &body, source);
            return None;
        }
        if body.content_type != CONTENT_TEXT {
            debug!("ignoring content_type {:#04x}", body.content_type);
            return None;
        }
        let remote = (body.lamport, header.device_id);
        if remote <= self.last_applied {
            debug!(
                "dropping stale/duplicate packet lamport={} (last_applied={})",
                body.lamport, self.last_applied.0
            );
            return None;
        }
        let text = match String::from_utf8(body.payload) {
            Ok(t) => t,
            Err(_) => {
                debug!("dropping packet: invalid UTF-8");
                return None;
            }
        };
        self.cancel_older_fetches(remote);
        if let Err(e) = self.backend.set_text(&text) {
            warn!("failed to set local clipboard: {e}");
            return None;
        }
        debug!(
            "applied remote change lamport={} {}",
            body.lamport,
            content_meta(&ClipboardContent::Text(text.clone()))
        );
        self.last_applied = remote;
        self.lamport = self.lamport.max(body.lamport);
        self.last_applied_hash = Some(crypto::content_hash(&text));
        self.suppression_deadline = Some(Instant::now() + self.cfg.suppression);
        Some(AppliedContent::Text(text))
    }

    /// Accepted-announce path: ordering + last_applied advance exactly as a
    /// v1 message, then fetch guards, then queue one fetch. Handles both
    /// text announces (fixed 59-byte payload) and image announces (extended
    /// payload with MIME type). Old clients only decode the 59-byte form.
    fn handle_announce(&mut self, header: &Header, body: &Body, source: Option<IpAddr>) {
        enum Announce {
            Text(AnnouncePayload),
            Image(proto::ImageAnnouncePayload),
        }
        let announce = match proto::decode_announce(&body.payload) {
            Ok(a) => Announce::Text(a),
            Err(_) => match proto::decode_image_announce(&body.payload) {
                Ok(a) => Announce::Image(a),
                Err(e) => {
                    debug!("ignoring malformed announce payload: {e}");
                    return;
                }
            },
        };
        let (inner, transfer_id, total_len, expected_sha256, tcp_port) = match &announce {
            Announce::Text(a) => (
                a.inner_content_type,
                a.transfer_id,
                a.total_len,
                a.sha256,
                a.tcp_port,
            ),
            Announce::Image(a) => (
                INNER_IMAGE,
                a.transfer_id,
                a.total_len,
                a.sha256,
                a.tcp_port,
            ),
        };
        if !matches!(inner, INNER_TEXT | INNER_IMAGE) {
            debug!("ignoring announce with reserved inner type {inner:#04x}");
            return;
        }
        // The same transfer announced twice (UDP duplicates, or a
        // re-announce with a bumped lamport): the first accept already
        // queued a fetch — never download twice. Checked before ordering so
        // a re-announce neither disturbs `last_applied` nor cancels the
        // live fetch.
        if self
            .active_fetches
            .iter()
            .any(|f| f.transfer_id == transfer_id)
        {
            debug!(
                "ignoring duplicate announce for in-flight transfer={}",
                hex16(&transfer_id)
            );
            return;
        }
        let remote = (body.lamport, header.device_id);
        if remote <= self.last_applied {
            debug!(
                "dropping stale/duplicate announce lamport={} (last_applied={})",
                body.lamport, self.last_applied.0
            );
            return;
        }
        // Accepted: advance ordering state immediately, exactly as v1 would.
        self.last_applied = remote;
        self.lamport = self.lamport.max(body.lamport);
        self.cancel_older_fetches(remote);
        let ceiling = if inner == INNER_IMAGE {
            self.cfg.max_image_bytes
        } else {
            self.cfg.max_transfer_bytes
        };
        let kind = if inner == INNER_IMAGE {
            "image"
        } else {
            "text"
        };
        debug!(
            "accepted {kind} announce lamport={} transfer={} total_len={}",
            body.lamport,
            hex16(&transfer_id),
            total_len
        );

        if total_len > ceiling {
            debug!(
                "not fetching over-limit {kind} announce: {} > {}",
                total_len, ceiling
            );
            return;
        }
        let Some(source_ip) = source else {
            debug!("not fetching announce: no source address");
            return;
        };
        // Same content as the local clipboard: nothing to do. Images compare
        // by SHA-256 of the bytes, never by URI/path.
        let already_here = match &announce {
            Announce::Text(_) => match self.backend.get_text() {
                Ok(Some(current)) => sha256(current.as_bytes()) == expected_sha256,
                Ok(None) => false,
                Err(e) => {
                    debug!("clipboard read for hash check failed ({e}); fetching anyway");
                    false
                }
            },
            Announce::Image(_) => match self.backend.get_image() {
                Ok(Some(current)) => sha256(&current.bytes) == expected_sha256,
                Ok(None) => false,
                Err(e) => {
                    debug!("clipboard image read for hash check failed ({e}); fetching anyway");
                    false
                }
            },
        };
        if already_here {
            debug!("not fetching announce: clipboard already holds this content");
            return;
        }
        // Cap concurrent fetches: make room by cancelling the oldest.
        // (Normally unreachable — any accepted newer message already cancelled
        // older fetches above — but it bounds resource use under races.)
        while self.active_fetches.len() >= MAX_CONCURRENT_FETCHES {
            let oldest = self.active_fetches.remove(0);
            oldest.cancel.store(true, Ordering::SeqCst);
            self.cancelled_fetch_ids.push(oldest.transfer_id);
            self.pending_image_mimes
                .retain(|(id, _)| *id != oldest.transfer_id);
            debug!("cancelled oldest fetch to cap concurrency");
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.pending_fetch_requests.push(FetchRequest {
            transfer_id,
            total_len,
            expected_sha256,
            tcp_port,
            source: source_ip,
            lamport: body.lamport,
            device_id: header.device_id,
            inner_content_type: inner,
            cancel: Arc::clone(&cancel),
        });
        self.active_fetches.push(ActiveFetch {
            transfer_id,
            total_len,
            expected_sha256,
            inner_content_type: inner,
            lamport: body.lamport,
            device_id: header.device_id,
            cancel,
        });
        if let Announce::Image(a) = &announce {
            self.pending_image_mimes
                .push((transfer_id, a.mime_type.clone()));
        }
    }

    /// A newly accepted message cancels every in-flight older fetch.
    fn cancel_older_fetches(&mut self, remote: (u64, [u8; DEVICE_ID_LEN])) {
        let mut kept = Vec::new();
        for fetch in self.pending_fetch_requests.drain(..) {
            if (fetch.lamport, fetch.device_id) < remote {
                fetch.cancel.store(true, Ordering::SeqCst);
                self.cancelled_fetch_ids.push(fetch.transfer_id);
                debug!("cancelled queued fetch older than lamport={}", remote.0);
            } else {
                kept.push(fetch);
            }
        }
        self.pending_fetch_requests = kept;
        let mut kept_active = Vec::new();
        for fetch in self.active_fetches.drain(..) {
            if (fetch.lamport, fetch.device_id) < remote {
                fetch.cancel.store(true, Ordering::SeqCst);
                self.cancelled_fetch_ids.push(fetch.transfer_id);
                self.pending_image_mimes
                    .retain(|(id, _)| *id != fetch.transfer_id);
                debug!(
                    "cancelled in-flight fetch transfer={} older than lamport={}",
                    hex16(&fetch.transfer_id),
                    remote.0
                );
            } else {
                kept_active.push(fetch);
            }
        }
        self.active_fetches = kept_active;
    }

    /// Apply a finished fetch. Validates length, hash, and UTF-8, then sets
    /// the clipboard through the echo-suppression path (so the resulting
    /// change event is dropped, never rebroadcast). Any failure applies
    /// nothing and returns `None`.
    ///
    /// Images get one extra gate: the fetch is applied only if its
    /// `(lamport, device_id)` is still `last_applied` — a newer text or
    /// image accepted while the download was in flight must not be
    /// overwritten by the stale image.
    pub fn complete_fetch(
        &mut self,
        transfer_id: [u8; 16],
        result: Result<Vec<u8>, FetchError>,
    ) -> Option<AppliedContent> {
        let pos = self
            .active_fetches
            .iter()
            .position(|f| f.transfer_id == transfer_id);
        let Some(pos) = pos else {
            debug!(
                "ignoring fetch result for unknown/cancelled transfer={}",
                hex16(&transfer_id)
            );
            return None;
        };
        let fetch = self.active_fetches.remove(pos);
        // Drop the queued request twin if the worker never started.
        self.pending_fetch_requests
            .retain(|r| r.transfer_id != transfer_id);
        // The MIME comes from the authenticated announce; snapshot it before
        // dropping the in-flight record.
        let image_mime = if fetch.inner_content_type == INNER_IMAGE {
            self.image_mime_for(&fetch.transfer_id)
        } else {
            None
        };
        self.pending_image_mimes
            .retain(|(id, _)| *id != transfer_id);
        let bytes = match result {
            Ok(b) => b,
            Err(e) => {
                debug!(
                    "fetch of transfer={} failed (applying nothing): {e}",
                    hex16(&transfer_id)
                );
                return None;
            }
        };
        if bytes.len() as u64 != fetch.total_len {
            debug!(
                "fetch of transfer={} has wrong length {} != {} (applying nothing)",
                hex16(&transfer_id),
                bytes.len(),
                fetch.total_len
            );
            return None;
        }
        if sha256(&bytes) != fetch.expected_sha256 {
            debug!(
                "fetch of transfer={} has SHA-256 mismatch (applying nothing)",
                hex16(&transfer_id)
            );
            return None;
        }
        if fetch.inner_content_type == INNER_IMAGE {
            return self.complete_image_fetch(&fetch, bytes, image_mime);
        }
        let text = match String::from_utf8(bytes) {
            Ok(t) => t,
            Err(_) => {
                debug!(
                    "fetch of transfer={} is not valid UTF-8 (applying nothing)",
                    hex16(&transfer_id)
                );
                return None;
            }
        };
        if fetch.inner_content_type != INNER_TEXT {
            debug!(
                "fetch of transfer={} has reserved inner type (applying nothing)",
                hex16(&transfer_id)
            );
            return None;
        }
        if let Err(e) = self.backend.set_text(&text) {
            warn!("failed to set local clipboard: {e}");
            return None;
        }
        debug!(
            "applied fetched transfer={} {}",
            hex16(&transfer_id),
            content_meta(&ClipboardContent::Text(text.clone()))
        );
        self.last_applied_hash = Some(crypto::content_hash(&text));
        self.suppression_deadline = Some(Instant::now() + self.cfg.suppression);
        Some(AppliedContent::Text(text))
    }

    /// Image half of [`complete_fetch`](Self::complete_fetch): final
    /// ordering check, MIME allowlist re-check, clipboard publish, and
    /// hash-based echo suppression. Never rebroadcasts.
    fn complete_image_fetch(
        &mut self,
        fetch: &ActiveFetch,
        bytes: Vec<u8>,
        image_mime: Option<String>,
    ) -> Option<AppliedContent> {
        if (fetch.lamport, fetch.device_id) != self.last_applied {
            debug!(
                "discarding fetched image transfer={}: a newer update won while downloading (applying nothing)",
                hex16(&fetch.transfer_id)
            );
            return None;
        }
        let Some(mime_type) = image_mime else {
            debug!(
                "fetch of transfer={} has no recorded MIME type (applying nothing)",
                hex16(&fetch.transfer_id)
            );
            return None;
        };
        if !proto::is_supported_image_mime(&mime_type) {
            debug!(
                "fetch of transfer={} has unsupported MIME {mime_type} (applying nothing)",
                hex16(&fetch.transfer_id)
            );
            return None;
        }
        let image = ClipboardImage { mime_type, bytes };
        // Publish normalization: some paste targets reject JPEG but accept
        // PNG, so received JPEGs are transcoded before hitting the local
        // clipboard. Everything downstream — publish AND echo suppression —
        // must use the normalized bytes, or the watcher's change event will
        // not match the suppression hash and will be rebroadcast.
        let (published_mime, published_bytes) = crate::image_norm::normalize_for_clipboard(
            &image.mime_type,
            &image.bytes,
            self.cfg.max_image_bytes,
        );
        let image = ClipboardImage {
            mime_type: published_mime,
            bytes: published_bytes,
        };
        if let Err(e) = self.backend.set_image(&image) {
            warn!("failed to set local clipboard image: {e}");
            return None;
        }
        debug!(
            "applied fetched image transfer={} {}",
            hex16(&fetch.transfer_id),
            content_meta(&ClipboardContent::Image(image.clone()))
        );
        self.last_applied_hash = Some(image.suppression_hash());
        self.suppression_deadline = Some(Instant::now() + self.cfg.suppression);
        Some(AppliedContent::Image(image))
    }

    /// MIME type recorded for an in-flight image fetch. The engine learns it
    /// from the authenticated announce; it is tracked alongside the fetch
    /// so the TCP bytes are never trusted for typing.
    fn image_mime_for(&self, transfer_id: &[u8; 16]) -> Option<String> {
        self.pending_image_mimes
            .iter()
            .find(|(id, _)| id == transfer_id)
            .map(|(_, mime)| mime.clone())
    }

    /// Refuse packets once `rate_limit_per_sec` have arrived within one second.
    fn take_recv_token(&mut self) -> bool {
        let now = Instant::now();
        while self
            .recent_recv
            .front()
            .is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(1))
        {
            self.recent_recv.pop_front();
        }
        if self.recent_recv.len() as u32 >= self.cfg.rate_limit_per_sec {
            return false;
        }
        self.recent_recv.push_back(now);
        true
    }

    /// Run the daemon loop until `shutdown` fires (or a source disconnects).
    pub fn run_with_shutdown(self, shutdown: Receiver<()>) {
        self.run_inner(shutdown);
    }

    /// Run the daemon loop, stopping on SIGINT/SIGTERM.
    pub fn run(self) {
        let (tx, rx) = channel::<()>();
        std::thread::spawn(move || {
            let Ok(mut signals) = signal_hook::iterator::Signals::new([
                signal_hook::consts::SIGINT,
                signal_hook::consts::SIGTERM,
            ]) else {
                return;
            };
            if signals.forever().next().is_some() {
                let _ = tx.send(());
            }
        });
        self.run_inner(rx);
    }

    fn run_inner(mut self, shutdown: Receiver<()>) {
        let local_rx = self.backend.subscribe_changes();
        let remote_rx = self.transport.recv();
        let (tx, rx) = channel::<Incoming>();

        let tx_local = tx.clone();
        std::thread::spawn(move || {
            for event in local_rx {
                if tx_local.send(Incoming::Local(event)).is_err() {
                    break;
                }
            }
        });
        let tx_remote = tx.clone();
        std::thread::spawn(move || {
            for datagram in remote_rx {
                if tx_remote.send(Incoming::Remote(datagram)).is_err() {
                    break;
                }
            }
        });
        let tx_shutdown = tx.clone();
        std::thread::spawn(move || {
            if shutdown.recv().is_ok() {
                let _ = tx_shutdown.send(Incoming::Shutdown);
            }
        });

        loop {
            match rx.recv_timeout(self.time_until_flush()) {
                Ok(Incoming::Local(event)) => {
                    self.handle_local_change(event);
                }
                Ok(Incoming::Remote(datagram)) => {
                    self.handle_packet(&datagram.bytes, datagram.source);
                    self.spawn_fetch_workers(&tx);
                }
                Ok(Incoming::FetchResult {
                    transfer_id,
                    result,
                }) => {
                    self.complete_fetch(transfer_id, result);
                }
                Ok(Incoming::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => self.flush_debounce(),
            }
        }
        debug!("engine loop exiting");
    }

    /// Spawn one worker thread per queued fetch request. Workers run the
    /// blocking TCP fetch and report back through the loop channel.
    fn spawn_fetch_workers(&mut self, tx: &std::sync::mpsc::Sender<Incoming>) {
        for req in self.take_fetch_requests() {
            let params = self.fetch_params(&req);
            let cancel = Arc::clone(&req.cancel);
            let transfer_id = req.transfer_id;
            let tx = tx.clone();
            std::thread::spawn(move || {
                let result = fetch_transfer(&params, &cancel);
                let _ = tx.send(Incoming::FetchResult {
                    transfer_id,
                    result,
                });
            });
        }
    }
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::Sender;

    const KEY: KeyBytes = [7u8; 32];
    const DEVICE_A: [u8; 16] = [0xA0; 16];
    const DEVICE_B: [u8; 16] = [0xB0; 16];

    fn cfg(device_id: [u8; 16]) -> EngineConfig {
        EngineConfig {
            debounce: Duration::ZERO,
            ..EngineConfig::new(KEY, device_id)
        }
    }

    #[derive(Default)]
    struct ClipboardInner {
        text: Mutex<String>,
        image: Mutex<Option<ClipboardImage>>,
        set_count: AtomicUsize,
        image_set_count: AtomicUsize,
        subscribers: Mutex<Vec<Sender<ClipboardEvent>>>,
    }

    #[derive(Clone)]
    struct FakeClipboard(Arc<ClipboardInner>);

    impl FakeClipboard {
        fn new() -> Self {
            Self(Arc::default())
        }
        fn text(&self) -> String {
            self.0.text.lock().unwrap().clone()
        }
        fn set_count(&self) -> usize {
            self.0.set_count.load(Ordering::SeqCst)
        }
        fn image(&self) -> Option<ClipboardImage> {
            self.0.image.lock().unwrap().clone()
        }
        fn image_set_count(&self) -> usize {
            self.0.image_set_count.load(Ordering::SeqCst)
        }
    }

    impl ClipboardBackend for FakeClipboard {
        fn get_text(&self) -> std::io::Result<Option<String>> {
            Ok(Some(self.text()))
        }
        fn set_text(&self, text: &str) -> std::io::Result<()> {
            *self.0.text.lock().unwrap() = text.to_string();
            self.0.set_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn get_image(&self) -> std::io::Result<Option<ClipboardImage>> {
            Ok(self.image())
        }
        fn set_image(&self, image: &ClipboardImage) -> std::io::Result<()> {
            *self.0.image.lock().unwrap() = Some(image.clone());
            self.0.image_set_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn image_mime_types(&self) -> Vec<String> {
            vec!["image/png".to_string()]
        }
        fn subscribe_changes(&self) -> Receiver<ClipboardEvent> {
            let (tx, rx) = channel();
            self.0.subscribers.lock().unwrap().push(tx);
            rx
        }
    }

    /// Wire a temp-dir image cache into an engine under test.
    fn wire_image_cache<B: ClipboardBackend, T: Transport>(engine: &mut Engine<B, T>) {
        let (cache, _dir) =
            crate::image_cache::temp_image_cache(crate::image_cache::DEFAULT_IMAGE_CACHE_TTL, 20);
        engine.set_image_cache(cache);
    }

    #[derive(Default)]
    struct TransportInner {
        sent: Mutex<Vec<Vec<u8>>>,
        incoming: Mutex<Option<Receiver<Datagram>>>,
        inject_tx: Mutex<Option<Sender<Datagram>>>,
    }

    #[derive(Clone)]
    struct FakeTransport(Arc<TransportInner>);

    impl FakeTransport {
        fn new() -> Self {
            let (tx, rx) = channel();
            let inner = TransportInner {
                sent: Mutex::new(Vec::new()),
                incoming: Mutex::new(Some(rx)),
                inject_tx: Mutex::new(Some(tx)),
            };
            Self(Arc::new(inner))
        }
        fn sent(&self) -> Vec<Vec<u8>> {
            self.0.sent.lock().unwrap().clone()
        }
        fn inject(&self, bytes: Vec<u8>) {
            self.inject_from(bytes, None);
        }
        fn inject_from(&self, bytes: Vec<u8>, source: Option<IpAddr>) {
            self.0
                .inject_tx
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .send(Datagram::new(bytes, source))
                .unwrap();
        }
    }

    impl Transport for FakeTransport {
        fn send(&self, bytes: &[u8]) {
            self.0.sent.lock().unwrap().push(bytes.to_vec());
        }
        fn recv(&self) -> Receiver<Datagram> {
            self.0
                .incoming
                .lock()
                .unwrap()
                .take()
                .expect("recv called twice")
        }
    }

    fn open_packet(key: &KeyBytes, datagram: &[u8]) -> (Header, Body) {
        crypto::open(key, datagram).expect("test packet must open")
    }

    /// (a) local change is broadcast exactly once.
    #[test]
    fn local_change_broadcast_once() {
        let transport = FakeTransport::new();
        let mut engine = Engine::new(FakeClipboard::new(), transport.clone(), cfg(DEVICE_A));
        let packet = engine
            .handle_local_change(ClipboardEvent::text("hello".into(), false))
            .expect("sent immediately (debounce zero)");
        assert_eq!(transport.sent().len(), 1);
        assert_eq!(transport.sent()[0], packet);
        let (header, body) = open_packet(&KEY, &packet);
        assert_eq!(header.device_id, DEVICE_A);
        assert_eq!(body.payload, b"hello");
        assert_eq!(body.content_type, CONTENT_TEXT);
        assert!(body.lamport > 0);
    }

    /// (b) remote change is applied and NOT rebroadcast.
    #[test]
    fn remote_change_applied_not_rebroadcast() {
        let transport = FakeTransport::new();
        let clipboard = FakeClipboard::new();
        let mut receiver = Engine::new(clipboard.clone(), transport.clone(), cfg(DEVICE_A));
        let mut sender = Engine::new(FakeClipboard::new(), transport.clone(), cfg(DEVICE_B));
        let packet = sender
            .handle_local_change(ClipboardEvent::text("from-b".into(), false))
            .unwrap();
        assert_eq!(transport.sent().len(), 1);

        let applied = receiver.handle_packet(&packet, None);
        assert_eq!(
            applied.as_ref().and_then(AppliedContent::as_text),
            Some("from-b")
        );
        assert_eq!(clipboard.text(), "from-b");
        // Only the originator's broadcast exists; receiving did not send.
        assert_eq!(transport.sent().len(), 1);
    }

    /// (c) a packet carrying our own device_id is ignored (broadcast loopback).
    #[test]
    fn own_device_packet_ignored() {
        let transport = FakeTransport::new();
        let clipboard = FakeClipboard::new();
        let mut engine = Engine::new(clipboard.clone(), transport.clone(), cfg(DEVICE_A));
        // Craft a packet with our own device_id but a fresh, higher lamport so
        // only the device_id rule can drop it.
        let header = Header {
            version: proto::VERSION,
            msg_type: MSG_CLIP_UPDATE,
            device_id: DEVICE_A,
            nonce: crypto::generate_nonce(),
        };
        let body = Body {
            lamport: u64::MAX,
            timestamp_ms: unix_ms(),
            content_type: CONTENT_TEXT,
            payload: b"loop".to_vec(),
        };
        let packet = crypto::seal(&KEY, &header, &body);
        assert_eq!(engine.handle_packet(&packet, None), None);
        assert_eq!(clipboard.text(), "");
        assert_eq!(clipboard.set_count(), 0);
        assert_eq!(transport.sent().len(), 0);
    }

    /// (d) older / duplicate packets are dropped.
    #[test]
    fn stale_and_duplicate_packets_dropped() {
        let transport = FakeTransport::new();
        let clipboard = FakeClipboard::new();
        let mut engine = Engine::new(clipboard.clone(), transport.clone(), cfg(DEVICE_A));
        let mut origin = Engine::new(FakeClipboard::new(), transport.clone(), cfg(DEVICE_B));

        let first = origin
            .handle_local_change(ClipboardEvent::text("one".into(), false))
            .unwrap();
        assert_eq!(
            engine
                .handle_packet(&first, None)
                .as_ref()
                .and_then(AppliedContent::as_text),
            Some("one")
        );

        // Duplicate of an already-applied packet.
        assert_eq!(engine.handle_packet(&first, None), None);

        // Older lamport from a third device must lose to the newer state.
        let header = Header {
            version: proto::VERSION,
            msg_type: MSG_CLIP_UPDATE,
            device_id: [0xC0; 16],
            nonce: crypto::generate_nonce(),
        };
        let old = Body {
            lamport: 1,
            timestamp_ms: 0,
            content_type: CONTENT_TEXT,
            payload: b"stale".to_vec(),
        };
        let stale = crypto::seal(&KEY, &header, &old);
        assert_eq!(engine.handle_packet(&stale, None), None);
        assert_eq!(clipboard.text(), "one");

        // A newer packet from the same origin replaces it (lamport must rise).
        let second = origin
            .handle_local_change(ClipboardEvent::text("two".into(), false))
            .unwrap();
        let (_, second_body) = open_packet(&KEY, &second);
        let (_, first_body) = open_packet(&KEY, &first);
        assert!(second_body.lamport > first_body.lamport);
        assert_eq!(
            engine
                .handle_packet(&second, None)
                .as_ref()
                .and_then(AppliedContent::as_text),
            Some("two")
        );
        assert_eq!(clipboard.text(), "two");
        // Still no rebroadcasts from the receiving engine.
        assert_eq!(transport.sent().len(), 2);
    }

    /// (e) two simultaneous updates converge to the same winner on every peer.
    #[test]
    fn simultaneous_updates_converge() {
        for reverse_delivery in [false, true] {
            let transport = FakeTransport::new();
            let clip_a = FakeClipboard::new();
            let clip_b = FakeClipboard::new();
            let mut a = Engine::new(clip_a.clone(), transport.clone(), cfg(DEVICE_A));
            let mut b = Engine::new(clip_b.clone(), transport.clone(), cfg(DEVICE_B));

            // The OS already holds our local copy when the watcher fires.
            let pa = a
                .handle_local_change(ClipboardEvent::text("alpha".into(), false))
                .expect("a broadcasts");
            clip_a.set_text("alpha").unwrap();
            let pb = b
                .handle_local_change(ClipboardEvent::text("bravo".into(), false))
                .expect("b broadcasts");
            clip_b.set_text("bravo").unwrap();

            let (_, ha) = open_packet(&KEY, &pa);
            let (_, hb) = open_packet(&KEY, &pb);
            let a_wins = (ha.lamport, DEVICE_A) > (hb.lamport, DEVICE_B);
            let expected = if a_wins { "alpha" } else { "bravo" };

            // Deliver both packets to both peers, in either order, then
            // replay them (duplicates) to prove idempotence.
            if reverse_delivery {
                assert_eq!(
                    b.handle_packet(&pa, None)
                        .as_ref()
                        .and_then(AppliedContent::as_text),
                    a_wins.then_some("alpha")
                );
                assert_eq!(
                    a.handle_packet(&pb, None)
                        .as_ref()
                        .and_then(AppliedContent::as_text),
                    (!a_wins).then_some("bravo")
                );
                assert_eq!(b.handle_packet(&pa, None), None, "replay dropped");
                assert_eq!(a.handle_packet(&pb, None), None, "replay dropped");
            } else {
                assert_eq!(
                    a.handle_packet(&pb, None)
                        .as_ref()
                        .and_then(AppliedContent::as_text),
                    (!a_wins).then_some("bravo")
                );
                assert_eq!(
                    b.handle_packet(&pa, None)
                        .as_ref()
                        .and_then(AppliedContent::as_text),
                    a_wins.then_some("alpha")
                );
                assert_eq!(a.handle_packet(&pb, None), None, "replay dropped");
                assert_eq!(b.handle_packet(&pa, None), None, "replay dropped");
            }

            assert_eq!(
                clip_a.text(),
                expected,
                "peer A converges (reverse={reverse_delivery})"
            );
            assert_eq!(
                clip_b.text(),
                expected,
                "peer B converges (reverse={reverse_delivery})"
            );
            // Receiving never produced additional broadcasts.
            assert_eq!(transport.sent().len(), 2);
        }
    }

    /// (v2) text just over the inline limit announces; exactly at the
    /// inline limit still sends inline.
    #[test]
    fn inline_boundary_stays_inline() {
        let transport = FakeTransport::new();
        let mut engine = Engine::new(FakeClipboard::new(), transport.clone(), cfg(DEVICE_A));
        let exact = "x".repeat(DEFAULT_INLINE_MAX_BYTES);
        let packet = engine
            .handle_local_change(ClipboardEvent::text(exact, false))
            .expect("exactly at the limit sends inline");
        assert_eq!(transport.sent().len(), 1);
        let (_, body) = open_packet(&KEY, &packet);
        assert_eq!(body.content_type, CONTENT_TEXT);
    }

    /// (f) over-limit text is not sent.
    #[test]
    fn over_limit_text_not_sent() {
        let transport = FakeTransport::new();
        let mut engine = Engine::new(
            FakeClipboard::new(),
            transport.clone(),
            EngineConfig {
                max_transfer_bytes: 2000,
                debounce: Duration::ZERO,
                ..EngineConfig::new(KEY, DEVICE_A)
            },
        );
        let long = "x".repeat(2001);
        assert!(
            engine
                .handle_local_change(ClipboardEvent::text(long, false))
                .is_none()
        );
        assert_eq!(transport.sent().len(), 0);
        // Just under the ceiling announces.
        let ok = "x".repeat(2000);
        assert!(
            engine
                .handle_local_change(ClipboardEvent::text(ok, false))
                .is_some()
        );
        assert_eq!(transport.sent().len(), 1);
    }

    /// (g) sensitive-flagged content is not sent.
    #[test]
    fn sensitive_content_not_sent() {
        let transport = FakeTransport::new();
        let mut engine = Engine::new(FakeClipboard::new(), transport.clone(), cfg(DEVICE_A));
        assert!(
            engine
                .handle_local_change(ClipboardEvent::text("hunter2".into(), true))
                .is_none()
        );
        assert_eq!(transport.sent().len(), 0);

        // With skip_sensitive = false it is broadcast.
        let mut permissive = Engine::new(
            FakeClipboard::new(),
            transport.clone(),
            EngineConfig {
                skip_sensitive: false,
                debounce: Duration::ZERO,
                ..EngineConfig::new(KEY, DEVICE_A)
            },
        );
        assert!(
            permissive
                .handle_local_change(ClipboardEvent::text("hunter2".into(), true))
                .is_some()
        );
        assert_eq!(transport.sent().len(), 1);
    }

    /// Echo of content we just applied locally is suppressed (never rebroadcast).
    #[test]
    fn echo_of_applied_content_suppressed() {
        let transport = FakeTransport::new();
        let clip = FakeClipboard::new();
        let mut engine = Engine::new(clip.clone(), transport.clone(), cfg(DEVICE_A));
        let mut origin = Engine::new(FakeClipboard::new(), transport.clone(), cfg(DEVICE_B));
        let packet = origin
            .handle_local_change(ClipboardEvent::text("remote-text".into(), false))
            .unwrap();
        let sent_before = transport.sent().len();
        assert_eq!(
            engine
                .handle_packet(&packet, None)
                .as_ref()
                .and_then(AppliedContent::as_text),
            Some("remote-text")
        );

        // The backend watcher now fires with the same content we just set.
        assert_eq!(
            engine.handle_local_change(ClipboardEvent::text("remote-text".into(), false)),
            None
        );
        assert_eq!(transport.sent().len(), sent_before);

        // Unrelated content still broadcasts.
        assert!(
            engine
                .handle_local_change(ClipboardEvent::text("different".into(), false))
                .is_some()
        );
        assert_eq!(transport.sent().len(), sent_before + 1);
    }

    /// Incoming rate limit: at most `rate_limit_per_sec` packets per second.
    #[test]
    fn incoming_rate_limit() {
        let transport = FakeTransport::new();
        let clip = FakeClipboard::new();
        let mut engine = Engine::new(clip.clone(), transport.clone(), cfg(DEVICE_A));
        let mut origin = Engine::new(FakeClipboard::new(), transport.clone(), cfg(DEVICE_B));

        let mut applied = 0;
        for i in 0..30 {
            let packet = origin
                .handle_local_change(ClipboardEvent::text(format!("msg-{i}"), false))
                .unwrap();
            if engine.handle_packet(&packet, None).is_some() {
                applied += 1;
            }
        }
        assert_eq!(applied, 20, "exactly the per-second budget is accepted");
    }

    /// Outgoing debounce collapses changes and sends only the last.
    #[test]
    fn outgoing_debounce_collapses() {
        let transport = FakeTransport::new();
        let mut engine = Engine::new(
            FakeClipboard::new(),
            transport.clone(),
            EngineConfig {
                debounce: Duration::from_millis(80),
                ..EngineConfig::new(KEY, DEVICE_A)
            },
        );
        for i in 0..5 {
            let sent = engine.handle_local_change(ClipboardEvent::text(format!("t{i}"), false));
            assert!(sent.is_none(), "nothing sent while debouncing");
        }
        assert_eq!(transport.sent().len(), 0);
        assert!(engine.time_until_flush() <= Duration::from_millis(80));
        std::thread::sleep(Duration::from_millis(100));
        engine.flush_debounce();
        assert_eq!(transport.sent().len(), 1);
        let (_, body) = open_packet(&KEY, &transport.sent()[0]);
        assert_eq!(body.payload, b"t4", "only the last change is broadcast");
        // Nothing left to flush.
        engine.flush_debounce();
        assert_eq!(transport.sent().len(), 1);
    }

    /// The run loop wires backend events, packets, debounce and shutdown.
    #[test]
    fn run_loop_applies_remote_and_exits_on_shutdown() {
        let transport = FakeTransport::new();
        let clipboard = FakeClipboard::new();
        let engine = Engine::new(clipboard.clone(), transport.clone(), cfg(DEVICE_A));
        let (shutdown_tx, shutdown_rx) = channel();
        let handle = std::thread::spawn(move || engine.run_with_shutdown(shutdown_rx));

        let mut origin = Engine::new(FakeClipboard::new(), transport.clone(), cfg(DEVICE_B));
        let packet = origin
            .handle_local_change(ClipboardEvent::text("via-loop".into(), false))
            .unwrap();
        transport.inject(packet);

        let deadline = Instant::now() + Duration::from_secs(2);
        while clipboard.text() != "via-loop" && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(clipboard.text(), "via-loop");

        shutdown_tx.send(()).unwrap();
        handle.join().expect("engine thread exits cleanly");
    }

    // ---------- v2 large-text transfer tests ----------

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

    fn craft_announce(
        device: [u8; 16],
        lamport: u64,
        transfer_id: [u8; 16],
        content: &[u8],
        tcp_port: u16,
    ) -> Vec<u8> {
        let payload = proto::encode_announce(&AnnouncePayload {
            inner_content_type: INNER_TEXT,
            transfer_id,
            total_len: content.len() as u64,
            sha256: sha256(content),
            tcp_port,
        });
        let header = Header {
            version: proto::VERSION,
            msg_type: MSG_CLIP_UPDATE,
            device_id: device,
            nonce: crypto::generate_nonce(),
        };
        let body = Body {
            lamport,
            timestamp_ms: 0,
            content_type: CONTENT_ANNOUNCE,
            payload: payload.to_vec(),
        };
        crypto::seal(&KEY, &header, &body)
    }

    fn craft_inline(device: [u8; 16], lamport: u64, text: &str) -> Vec<u8> {
        let header = Header {
            version: proto::VERSION,
            msg_type: MSG_CLIP_UPDATE,
            device_id: device,
            nonce: crypto::generate_nonce(),
        };
        let body = Body {
            lamport,
            timestamp_ms: 0,
            content_type: CONTENT_TEXT,
            payload: text.as_bytes().to_vec(),
        };
        crypto::seal(&KEY, &header, &body)
    }

    /// (a) large text produces an announce, not an inline message.
    #[test]
    fn large_text_produces_announce() {
        let transport = FakeTransport::new();
        let mut engine = Engine::new(FakeClipboard::new(), transport.clone(), cfg(DEVICE_A));
        let big = "x".repeat(DEFAULT_INLINE_MAX_BYTES + 500);
        let packet = engine
            .handle_local_change(ClipboardEvent::text(big.clone(), false))
            .expect("large text announces");
        assert_eq!(transport.sent().len(), 1);
        let (_, body) = open_packet(&KEY, &packet);
        assert_eq!(body.content_type, CONTENT_ANNOUNCE);
        assert_eq!(body.payload.len(), proto::ANNOUNCE_PAYLOAD_LEN);
        let announce = proto::decode_announce(&body.payload).unwrap();
        assert_eq!(announce.inner_content_type, INNER_TEXT);
        assert_eq!(announce.total_len, big.len() as u64);
        assert_eq!(announce.sha256, sha256(big.as_bytes()));
        assert_eq!(announce.tcp_port, DEFAULT_TCP_PORT);
        // The sender registered the transfer for future fetches.
        assert!(
            engine
                .transfer_store()
                .lock()
                .unwrap()
                .get(&announce.transfer_id)
                .is_some()
        );
    }

    /// (b) an accepted announce triggers exactly one fetch.
    #[test]
    fn accepted_announce_triggers_exactly_one_fetch() {
        let send_transport = FakeTransport::new();
        let mut sender = Engine::new(FakeClipboard::new(), send_transport, cfg(DEVICE_B));
        let big = "y".repeat(5000);
        let announce = sender
            .handle_local_change(ClipboardEvent::text(big, false))
            .unwrap();

        let recv_transport = FakeTransport::new();
        let mut receiver = Engine::new(FakeClipboard::new(), recv_transport.clone(), cfg(DEVICE_A));
        assert_eq!(receiver.handle_packet(&announce, Some(LOOPBACK)), None);
        let reqs = receiver.take_fetch_requests();
        assert_eq!(reqs.len(), 1, "exactly one fetch queued");
        let (_, body) = open_packet(&KEY, &announce);
        let decoded = proto::decode_announce(&body.payload).unwrap();
        assert_eq!(reqs[0].transfer_id, decoded.transfer_id);
        assert_eq!(reqs[0].source, LOOPBACK);
        assert_eq!(reqs[0].tcp_port, DEFAULT_TCP_PORT);
        assert_eq!(reqs[0].total_len, 5000);
        assert_eq!(receiver.active_fetch_count(), 1);
    }

    /// (c) a fetched result is applied and NOT rebroadcast (echo suppressed).
    #[test]
    fn fetched_result_applied_not_rebroadcast() {
        let recv_transport = FakeTransport::new();
        let clipboard = FakeClipboard::new();
        let mut receiver = Engine::new(clipboard.clone(), recv_transport.clone(), cfg(DEVICE_A));
        let content = b"fetched-large-text".to_vec();
        let announce = craft_announce(DEVICE_B, 1000, [0x11; 16], &content, DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&announce, Some(LOOPBACK)), None);
        let reqs = receiver.take_fetch_requests();
        assert_eq!(reqs.len(), 1);

        let applied = receiver
            .complete_fetch(reqs[0].transfer_id, Ok(content))
            .expect("valid fetch applies");
        assert_eq!(applied.as_text(), Some("fetched-large-text"));
        assert_eq!(clipboard.text(), "fetched-large-text");
        assert_eq!(recv_transport.sent().len(), 0, "no rebroadcast");
        assert_eq!(receiver.active_fetch_count(), 0);

        // The clipboard change event from our own write is echo-suppressed.
        assert_eq!(
            receiver.handle_local_change(ClipboardEvent::text("fetched-large-text".into(), false)),
            None
        );
        assert_eq!(recv_transport.sent().len(), 0);
    }

    /// (d) an older or duplicate announce triggers no fetch.
    #[test]
    fn older_or_duplicate_announce_no_fetch() {
        let mut receiver = Engine::new(FakeClipboard::new(), FakeTransport::new(), cfg(DEVICE_A));
        let content = b"v2 content".to_vec();
        let first = craft_announce(DEVICE_B, 1000, [0x21; 16], &content, DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&first, Some(LOOPBACK)), None);
        assert_eq!(receiver.take_fetch_requests().len(), 1);

        // Duplicate of the accepted announce: ordering rejects it.
        assert_eq!(receiver.handle_packet(&first, Some(LOOPBACK)), None);
        assert!(receiver.take_fetch_requests().is_empty());

        // Older lamport from another device: rejected too.
        let older = craft_announce([0xC0; 16], 500, [0x22; 16], &content, DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&older, Some(LOOPBACK)), None);
        assert!(receiver.take_fetch_requests().is_empty());

        // Same lamport, smaller device id: still not greater, no fetch.
        let tie_loser = craft_announce([0x00; 16], 1000, [0x23; 16], &content, DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&tie_loser, Some(LOOPBACK)), None);
        assert!(receiver.take_fetch_requests().is_empty());
        assert_eq!(
            receiver.active_fetch_count(),
            1,
            "only the first fetch lives"
        );
    }

    /// (e) a newer announce cancels the in-flight older fetch.
    #[test]
    fn newer_announce_cancels_inflight_fetch() {
        let mut receiver = Engine::new(FakeClipboard::new(), FakeTransport::new(), cfg(DEVICE_A));
        let old = craft_announce(DEVICE_B, 1000, [0x31; 16], b"old", DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&old, Some(LOOPBACK)), None);
        let reqs = receiver.take_fetch_requests();
        assert_eq!(reqs.len(), 1);
        let old_cancel = Arc::clone(&reqs[0].cancel);

        let new = craft_announce(DEVICE_B, 2000, [0x32; 16], b"new", DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&new, Some(LOOPBACK)), None);
        assert!(old_cancel.load(Ordering::SeqCst), "older fetch cancelled");
        assert_eq!(receiver.cancelled_fetch_ids(), vec![[0x31; 16]]);
        let reqs = receiver.take_fetch_requests();
        assert_eq!(reqs.len(), 1, "newer announce queues its own fetch");
        assert_eq!(reqs[0].transfer_id, [0x32; 16]);

        // A late result for the cancelled transfer applies nothing.
        assert_eq!(
            receiver.complete_fetch([0x31; 16], Ok(b"old".to_vec())),
            None
        );
    }

    /// (e2) a newer inline message also cancels an in-flight fetch.
    #[test]
    fn newer_inline_cancels_inflight_fetch() {
        let clipboard = FakeClipboard::new();
        let mut receiver = Engine::new(clipboard.clone(), FakeTransport::new(), cfg(DEVICE_A));
        let old = craft_announce(DEVICE_B, 1000, [0x41; 16], b"old", DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&old, Some(LOOPBACK)), None);
        assert_eq!(receiver.take_fetch_requests().len(), 1);

        let inline = craft_inline([0xC0; 16], 2000, "newer inline wins");
        assert_eq!(
            receiver
                .handle_packet(&inline, Some(LOOPBACK))
                .as_ref()
                .and_then(AppliedContent::as_text),
            Some("newer inline wins")
        );
        assert_eq!(receiver.cancelled_fetch_ids(), vec![[0x41; 16]]);
        assert_eq!(receiver.active_fetch_count(), 0);
        assert!(receiver.take_fetch_requests().is_empty());
        assert_eq!(clipboard.text(), "newer inline wins");
    }

    /// (f2) an over-limit announce is not fetched.
    #[test]
    fn over_limit_announce_not_fetched() {
        let clipboard = FakeClipboard::new();
        let mut receiver = Engine::new(
            clipboard.clone(),
            FakeTransport::new(),
            EngineConfig {
                max_transfer_bytes: 100,
                debounce: Duration::ZERO,
                ..EngineConfig::new(KEY, DEVICE_A)
            },
        );
        // total_len lies above the ceiling (payload itself is small).
        let announce = proto::encode_announce(&AnnouncePayload {
            inner_content_type: INNER_TEXT,
            transfer_id: [0x51; 16],
            total_len: 10_000,
            sha256: sha256(b"tiny"),
            tcp_port: DEFAULT_TCP_PORT,
        });
        let header = Header {
            version: proto::VERSION,
            msg_type: MSG_CLIP_UPDATE,
            device_id: DEVICE_B,
            nonce: crypto::generate_nonce(),
        };
        let body = Body {
            lamport: 1000,
            timestamp_ms: 0,
            content_type: CONTENT_ANNOUNCE,
            payload: announce.to_vec(),
        };
        let packet = crypto::seal(&KEY, &header, &body);
        assert_eq!(receiver.handle_packet(&packet, Some(LOOPBACK)), None);
        assert!(
            receiver.take_fetch_requests().is_empty(),
            "over-limit announce is not fetched"
        );
        assert_eq!(clipboard.text(), "", "nothing applied");
    }

    /// (g) same-hash-as-clipboard skips the fetch.
    #[test]
    fn same_hash_as_clipboard_skips_fetch() {
        let clipboard = FakeClipboard::new();
        clipboard.set_text("already here").unwrap();
        let mut receiver = Engine::new(clipboard, FakeTransport::new(), cfg(DEVICE_A));
        let announce = craft_announce(
            DEVICE_B,
            1000,
            [0x61; 16],
            b"already here",
            DEFAULT_TCP_PORT,
        );
        assert_eq!(receiver.handle_packet(&announce, Some(LOOPBACK)), None);
        assert!(
            receiver.take_fetch_requests().is_empty(),
            "nothing to do when hashes match"
        );
    }

    /// (h) a failed fetch applies nothing.
    #[test]
    fn failed_fetch_applies_nothing() {
        let clipboard = FakeClipboard::new();
        let mut receiver = Engine::new(clipboard.clone(), FakeTransport::new(), cfg(DEVICE_A));
        let announce = craft_announce(DEVICE_B, 1000, [0x71; 16], b"wanted", DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&announce, Some(LOOPBACK)), None);
        let reqs = receiver.take_fetch_requests();
        assert_eq!(reqs.len(), 1);

        assert_eq!(
            receiver.complete_fetch(reqs[0].transfer_id, Err(crate::fetch::FetchError::Timeout)),
            None
        );
        assert_eq!(clipboard.text(), "");
        // Corrupt bytes (hash mismatch) also apply nothing.
        let announce2 = craft_announce(DEVICE_B, 2000, [0x72; 16], b"wanted", DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&announce2, Some(LOOPBACK)), None);
        let reqs = receiver.take_fetch_requests();
        assert_eq!(
            receiver.complete_fetch(reqs[0].transfer_id, Ok(b"tampered".to_vec())),
            None
        );
        assert_eq!(clipboard.text(), "");
        // Unknown transfer id: ignored.
        assert_eq!(receiver.complete_fetch([0xFF; 16], Ok(b"x".to_vec())), None);
    }

    /// Integration (loopback, no display): 5 MB of text through the real TCP
    /// server + fetch client with fake clipboards, applied once, no echo.
    #[test]
    fn five_mb_loopback_through_real_tcp() {
        use std::net::TcpListener;

        let text = "Clipcast large ".repeat(5_000_000 / 15);
        assert!(text.len() > DEFAULT_INLINE_MAX_BYTES);

        let mut sender_cfg = cfg(DEVICE_B);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        sender_cfg.tcp_port = listener.local_addr().unwrap().port();
        let mut sender = Engine::new(FakeClipboard::new(), FakeTransport::new(), sender_cfg);
        let announce = sender
            .handle_local_change(ClipboardEvent::text(text.clone(), false))
            .expect("5 MB announces");
        crate::tcp_server::spawn_server(
            listener,
            KEY,
            sender.transfer_store(),
            None,
            Duration::from_secs(10),
            Duration::from_secs(120),
        );
        std::thread::sleep(Duration::from_millis(50));

        let recv_transport = FakeTransport::new();
        let clipboard = FakeClipboard::new();
        let mut receiver = Engine::new(clipboard.clone(), recv_transport.clone(), cfg(DEVICE_A));
        assert_eq!(receiver.handle_packet(&announce, Some(LOOPBACK)), None);
        let reqs = receiver.take_fetch_requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].total_len, text.len() as u64);

        let params = receiver.fetch_params(&reqs[0]);
        let cancel = AtomicBool::new(false);
        let bytes = crate::fetch::fetch_transfer(&params, &cancel).expect("5 MB fetch");
        assert_eq!(bytes.len(), text.len());
        let applied = receiver
            .complete_fetch(reqs[0].transfer_id, Ok(bytes))
            .expect("valid 5 MB fetch applies");
        assert_eq!(applied.as_text(), Some(text.as_str()));
        assert_eq!(clipboard.text(), text);
        assert_eq!(
            recv_transport.sent().len(),
            0,
            "fetched result not rebroadcast"
        );
        // Echo of the applied content is suppressed.
        assert_eq!(
            receiver.handle_local_change(ClipboardEvent::text(text, false)),
            None
        );
    }

    /// A wrong key fails before any fetch: the announce never opens.
    #[test]
    fn wrong_key_announce_never_fetches() {
        let mut sender = Engine::new(FakeClipboard::new(), FakeTransport::new(), cfg(DEVICE_B));
        let announce = sender
            .handle_local_change(ClipboardEvent::text("z".repeat(5000), false))
            .unwrap();
        let mut receiver = Engine::new(
            FakeClipboard::new(),
            FakeTransport::new(),
            EngineConfig::new([9u8; 32], DEVICE_A),
        );
        assert_eq!(receiver.handle_packet(&announce, Some(LOOPBACK)), None);
        assert!(receiver.take_fetch_requests().is_empty());
    }

    // ---------- image sync ----------

    fn sample_image() -> ClipboardImage {
        ClipboardImage {
            mime_type: "image/png".to_string(),
            // Deterministic 1x1 PNG bytes (not a real photo).
            bytes: vec![
                0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, b'I', b'H',
                b'D', b'R', 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00,
                0x00, 0x90, 0x77, 0x53, 0xde, 0x00, 0x00, 0x00, 0x0c, b'I', b'D', b'A', b'T', 0x08,
                0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x01, 0x00, 0x05, 0xfe,
                0xd4, 0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xae, 0x42, 0x60, 0x82,
            ],
        }
    }

    fn craft_image_announce(
        device: [u8; 16],
        lamport: u64,
        transfer_id: [u8; 16],
        image: &ClipboardImage,
        tcp_port: u16,
    ) -> Vec<u8> {
        let header = Header {
            version: proto::VERSION,
            msg_type: MSG_CLIP_UPDATE,
            device_id: device,
            nonce: crypto::generate_nonce(),
        };
        let payload = proto::encode_image_announce(&proto::ImageAnnouncePayload {
            transfer_id,
            total_len: image.bytes.len() as u64,
            sha256: sha256(&image.bytes),
            tcp_port,
            mime_type: image.mime_type.clone(),
        });
        let body = Body {
            lamport,
            timestamp_ms: 0,
            content_type: CONTENT_ANNOUNCE,
            payload,
        };
        crypto::seal(&KEY, &header, &body)
    }

    /// Local image produces exactly one image announce; the bytes are
    /// already in the sender cache (fetchable) before the announce exists.
    #[test]
    fn local_image_produces_exactly_one_announce() {
        let transport = FakeTransport::new();
        let mut engine = Engine::new(FakeClipboard::new(), transport.clone(), cfg(DEVICE_A));
        wire_image_cache(&mut engine);
        let image = sample_image();
        let packet = engine
            .handle_local_change(ClipboardEvent::image(
                image.mime_type.clone(),
                image.bytes.clone(),
            ))
            .expect("image announces");
        assert_eq!(transport.sent().len(), 1);
        let (_, body) = open_packet(&KEY, &packet);
        assert_eq!(body.content_type, CONTENT_ANNOUNCE);
        let announce = proto::decode_image_announce(&body.payload).unwrap();
        assert_eq!(announce.mime_type, "image/png");
        assert_eq!(announce.total_len, image.bytes.len() as u64);
        assert_eq!(announce.sha256, sha256(&image.bytes));
        // Fetchable immediately: the cache holds the exact bytes.
        let cache = engine.image_cache().unwrap();
        let (bytes, mime, sha) = cache.lock().unwrap().serve(&announce.transfer_id).unwrap();
        assert_eq!(bytes, image.bytes);
        assert_eq!(mime, "image/png");
        assert_eq!(sha, announce.sha256);
    }

    /// Oversized local images are never announced (MIME + size logged only).
    #[test]
    fn oversized_local_image_not_announced() {
        let transport = FakeTransport::new();
        let mut engine = Engine::new(
            FakeClipboard::new(),
            transport.clone(),
            EngineConfig {
                max_image_bytes: 10,
                debounce: Duration::ZERO,
                ..EngineConfig::new(KEY, DEVICE_A)
            },
        );
        wire_image_cache(&mut engine);
        let image = sample_image();
        assert!(image.bytes.len() as u64 > 10);
        assert_eq!(
            engine.handle_local_change(ClipboardEvent::image(image.mime_type, image.bytes)),
            None
        );
        assert_eq!(transport.sent().len(), 0);
    }

    /// Unsupported MIME types are never announced.
    #[test]
    fn unsupported_mime_not_announced() {
        let transport = FakeTransport::new();
        let mut engine = Engine::new(FakeClipboard::new(), transport.clone(), cfg(DEVICE_A));
        wire_image_cache(&mut engine);
        assert_eq!(
            engine.handle_local_change(ClipboardEvent::image(
                "image/gif".to_string(),
                vec![0x47, 0x49, 0x46],
            )),
            None
        );
        assert_eq!(transport.sent().len(), 0);
    }

    /// Full loopback: sender announces, receiver fetches over real TCP
    /// (served from the sender's disk cache), verifies, and applies the
    /// image exactly once without rebroadcasting.
    #[test]
    fn image_loopback_applies_once_without_rebroadcast() {
        use std::net::TcpListener;
        let image = sample_image();
        let mut sender_cfg = cfg(DEVICE_B);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        sender_cfg.tcp_port = listener.local_addr().unwrap().port();
        let mut sender = Engine::new(FakeClipboard::new(), FakeTransport::new(), sender_cfg);
        wire_image_cache(&mut sender);
        let sender_images = sender.image_cache().unwrap();
        let announce = sender
            .handle_local_change(ClipboardEvent::image(
                image.mime_type.clone(),
                image.bytes.clone(),
            ))
            .expect("image announces");
        crate::tcp_server::spawn_server(
            listener,
            KEY,
            sender.transfer_store(),
            Some(sender_images),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );
        std::thread::sleep(Duration::from_millis(50));

        let recv_transport = FakeTransport::new();
        let clipboard = FakeClipboard::new();
        let mut receiver = Engine::new(clipboard.clone(), recv_transport.clone(), cfg(DEVICE_A));
        assert_eq!(receiver.handle_packet(&announce, Some(LOOPBACK)), None);
        let reqs = receiver.take_fetch_requests();
        assert_eq!(reqs.len(), 1, "exactly one image fetch queued");

        let params = receiver.fetch_params(&reqs[0]);
        assert_eq!(params.max_transfer_bytes, DEFAULT_MAX_IMAGE_BYTES);
        let cancel = AtomicBool::new(false);
        let bytes = crate::fetch::fetch_transfer(&params, &cancel).expect("image fetch");
        let applied = receiver
            .complete_fetch(reqs[0].transfer_id, Ok(bytes))
            .expect("valid image applies");
        assert_eq!(applied, AppliedContent::Image(image.clone()));
        assert_eq!(clipboard.image(), Some(image.clone()));
        assert_eq!(clipboard.image_set_count(), 1);
        assert_eq!(
            recv_transport.sent().len(),
            0,
            "received image not rebroadcast"
        );

        // The clipboard change event from our own write is echo-suppressed.
        assert_eq!(
            receiver.handle_local_change(ClipboardEvent::image(
                image.mime_type.clone(),
                image.bytes.clone()
            )),
            None
        );
        assert_eq!(recv_transport.sent().len(), 0);
    }

    /// Duplicate announces for an in-flight transfer queue no second fetch.
    #[test]
    fn duplicate_image_announce_no_second_fetch() {
        let image = sample_image();
        let mut receiver = Engine::new(FakeClipboard::new(), FakeTransport::new(), cfg(DEVICE_A));
        let first = craft_image_announce(DEVICE_B, 1000, [0x71; 16], &image, DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&first, Some(LOOPBACK)), None);
        assert_eq!(receiver.take_fetch_requests().len(), 1);
        // Exact duplicate (same lamport): dropped by ordering.
        assert_eq!(receiver.handle_packet(&first, Some(LOOPBACK)), None);
        assert!(receiver.take_fetch_requests().is_empty());
        // Same transfer re-announced with a newer lamport: accepted for
        // ordering but no second download of the in-flight transfer.
        let reannounce = craft_image_announce(DEVICE_B, 1001, [0x71; 16], &image, DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&reannounce, Some(LOOPBACK)), None);
        assert!(receiver.take_fetch_requests().is_empty());
        assert_eq!(receiver.active_fetch_count(), 1);
    }

    /// An older image arriving after a newer one is ignored.
    #[test]
    fn older_image_ignored() {
        let image = sample_image();
        let mut receiver = Engine::new(FakeClipboard::new(), FakeTransport::new(), cfg(DEVICE_A));
        let new = craft_image_announce(DEVICE_B, 2000, [0x72; 16], &image, DEFAULT_TCP_PORT);
        let old = craft_image_announce(DEVICE_B, 1000, [0x73; 16], &image, DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&new, Some(LOOPBACK)), None);
        assert_eq!(receiver.take_fetch_requests().len(), 1);
        assert_eq!(receiver.handle_packet(&old, Some(LOOPBACK)), None);
        assert!(receiver.take_fetch_requests().is_empty());
    }

    /// Own-device image announces are ignored.
    #[test]
    fn own_device_image_announce_ignored() {
        let image = sample_image();
        let mut engine = Engine::new(FakeClipboard::new(), FakeTransport::new(), cfg(DEVICE_A));
        let packet = craft_image_announce(DEVICE_A, u64::MAX, [0x74; 16], &image, DEFAULT_TCP_PORT);
        assert_eq!(engine.handle_packet(&packet, Some(LOOPBACK)), None);
        assert!(engine.take_fetch_requests().is_empty());
    }

    /// §11 race: a newer text accepted while an image downloads wins — the
    /// stale image is discarded and the clipboard keeps the text.
    #[test]
    fn newer_text_during_image_download_wins() {
        let image = sample_image();
        let clipboard = FakeClipboard::new();
        let mut receiver = Engine::new(clipboard.clone(), FakeTransport::new(), cfg(DEVICE_A));
        let announce = craft_image_announce(DEVICE_B, 1000, [0x75; 16], &image, DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&announce, Some(LOOPBACK)), None);
        let reqs = receiver.take_fetch_requests();
        assert_eq!(reqs.len(), 1);

        // Newer inline text from another device arrives mid-download.
        let text_packet = craft_inline(DEVICE_B, 1001, "newer text");
        assert_eq!(
            receiver
                .handle_packet(&text_packet, Some(LOOPBACK))
                .as_ref()
                .and_then(AppliedContent::as_text),
            Some("newer text")
        );
        // The late image result is discarded: ordering moved on.
        assert_eq!(
            receiver.complete_fetch(reqs[0].transfer_id, Ok(image.bytes.clone())),
            None
        );
        assert_eq!(clipboard.image_set_count(), 0, "stale image never applied");
        assert_eq!(clipboard.text(), "newer text");
    }

    /// A received JPEG is normalized to PNG before hitting the clipboard
    /// (some paste targets reject JPEG), and echo suppression follows the
    /// PUBLISHED bytes so the watcher's PNG event does not rebroadcast.
    #[test]
    fn received_jpeg_published_as_png_with_matching_suppression() {
        let jpeg: Vec<u8> = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/red-8x8.jpg"
        ))
        .expect("test JPEG must exist");
        let image = ClipboardImage {
            mime_type: "image/jpeg".to_string(),
            bytes: jpeg.clone(),
        };
        let clipboard = FakeClipboard::new();
        let mut receiver = Engine::new(clipboard.clone(), FakeTransport::new(), cfg(DEVICE_A));
        let announce = craft_image_announce(DEVICE_B, 1000, [0x7C; 16], &image, DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&announce, Some(LOOPBACK)), None);
        let reqs = receiver.take_fetch_requests();
        assert_eq!(reqs.len(), 1);
        let applied = receiver
            .complete_fetch(reqs[0].transfer_id, Ok(jpeg))
            .expect("valid image applies");
        let AppliedContent::Image(published) = applied else {
            panic!("expected image content");
        };
        assert_eq!(published.mime_type, "image/png");
        assert_eq!(&published.bytes[0..8], b"\x89PNG\r\n\x1a\n");
        assert_eq!(clipboard.image(), Some(published.clone()));
        // The watcher's PNG change event is echo-suppressed (hash follows
        // the published bytes, not the wire bytes).
        assert_eq!(
            receiver
                .handle_local_change(ClipboardEvent::image(published.mime_type, published.bytes)),
            None
        );
    }

    /// Corrupt image bytes (hash mismatch) apply nothing.
    #[test]
    fn corrupt_image_fetch_applies_nothing() {
        let image = sample_image();
        let clipboard = FakeClipboard::new();
        let mut receiver = Engine::new(clipboard.clone(), FakeTransport::new(), cfg(DEVICE_A));
        let announce = craft_image_announce(DEVICE_B, 1000, [0x76; 16], &image, DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&announce, Some(LOOPBACK)), None);
        let reqs = receiver.take_fetch_requests();
        assert_eq!(reqs.len(), 1);
        let mut tampered = image.bytes.clone();
        tampered[10] ^= 0xFF;
        assert_eq!(
            receiver.complete_fetch(reqs[0].transfer_id, Ok(tampered)),
            None
        );
        assert_eq!(clipboard.image_set_count(), 0);
    }

    /// Over-limit image announces are never fetched.
    #[test]
    fn over_limit_image_announce_not_fetched() {
        let image = sample_image();
        let mut receiver = Engine::new(
            FakeClipboard::new(),
            FakeTransport::new(),
            EngineConfig {
                max_image_bytes: 10,
                debounce: Duration::ZERO,
                ..EngineConfig::new(KEY, DEVICE_A)
            },
        );
        let announce = craft_image_announce(DEVICE_B, 1000, [0x77; 16], &image, DEFAULT_TCP_PORT);
        assert_eq!(receiver.handle_packet(&announce, Some(LOOPBACK)), None);
        assert!(receiver.take_fetch_requests().is_empty());
    }

    /// A newer accepted announce cancels older in-flight fetches: only the
    /// newest transfer stays live, so one peer can never hold more than one
    /// fetch slot per ordering round (plus the hard
    /// [`MAX_CONCURRENT_FETCHES`] cap as backstop).
    #[test]
    fn newer_announce_cancels_older_image_fetch() {
        let image = sample_image();
        let mut receiver = Engine::new(FakeClipboard::new(), FakeTransport::new(), cfg(DEVICE_A));
        for (i, id) in [[0x78; 16], [0x79; 16], [0x7A; 16]].into_iter().enumerate() {
            let announce =
                craft_image_announce(DEVICE_B, 1000 + i as u64, id, &image, DEFAULT_TCP_PORT);
            assert_eq!(receiver.handle_packet(&announce, Some(LOOPBACK)), None);
        }
        assert_eq!(receiver.active_fetch_count(), 1);
        // Both the queued-request twin and the in-flight twin of each older
        // fetch are recorded cancelled.
        let mut cancelled = receiver.cancelled_fetch_ids();
        cancelled.sort();
        cancelled.dedup();
        assert_eq!(cancelled, vec![[0x78; 16], [0x79; 16]]);
    }

    /// Tampering with any byte of an image announce fails authentication.
    #[test]
    fn tampered_image_announce_fails_auth() {
        let image = sample_image();
        let packet = craft_image_announce(DEVICE_B, 1000, [0x7B; 16], &image, DEFAULT_TCP_PORT);
        for i in [0, 4, 5, 22, 34, 40, packet.len() - 1] {
            let mut bad = packet.clone();
            bad[i] ^= 0x01;
            assert!(
                crypto::open(&KEY, &bad).is_err(),
                "byte {i} tamper must fail auth"
            );
        }
    }
}
