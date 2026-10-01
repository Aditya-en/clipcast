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
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tracing::{debug, warn};

use crate::crypto::{self, KeyBytes};
use crate::proto::{self, Body, CONTENT_TEXT, DEVICE_ID_LEN, Header, MSG_CLIP_UPDATE};

pub const DEFAULT_MAX_TEXT_BYTES: usize = 1200;
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(100);
pub const DEFAULT_SUPPRESSION: Duration = Duration::from_secs(1);
pub const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 20;

/// A local clipboard change delivered by a backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardEvent {
    pub text: String,
    /// The backend flagged this content as secret (e.g. MIME type
    /// `x-kde-passwordManagerHint` with value `secret`).
    pub sensitive: bool,
}

/// Local clipboard access.
pub trait ClipboardBackend {
    fn get_text(&self) -> std::io::Result<Option<String>>;
    fn set_text(&self, text: &str) -> std::io::Result<()>;
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
    fn subscribe_changes(&self) -> Receiver<ClipboardEvent> {
        (**self).subscribe_changes()
    }
}

/// Packet transport.
pub trait Transport {
    fn send(&self, bytes: &[u8]);
    fn recv(&self) -> Receiver<Vec<u8>>;
}

#[derive(Debug, Clone)]
pub struct EngineConfig {
    pub key: KeyBytes,
    pub device_id: [u8; DEVICE_ID_LEN],
    pub max_text_bytes: usize,
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
            skip_sensitive: true,
            debounce: DEFAULT_DEBOUNCE,
            suppression: DEFAULT_SUPPRESSION,
            rate_limit_per_sec: DEFAULT_RATE_LIMIT_PER_SEC,
            log_content: false,
        }
    }
}

/// Short, content-independent description of text for logging.
fn content_meta(text: &str) -> String {
    format!(
        "len={} hash={:08x}",
        text.len(),
        crypto::content_hash(text) >> 32
    )
}

pub struct Engine<B: ClipboardBackend, T: Transport> {
    backend: B,
    transport: T,
    cfg: EngineConfig,
    lamport: u64,
    last_applied: (u64, [u8; DEVICE_ID_LEN]),
    last_applied_hash: Option<u64>,
    suppression_deadline: Option<Instant>,
    pending: Option<String>,
    pending_since: Option<Instant>,
    recent_recv: VecDeque<Instant>,
}

enum Incoming {
    Local(ClipboardEvent),
    Remote(Vec<u8>),
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
        }
    }

    pub fn device_id(&self) -> [u8; DEVICE_ID_LEN] {
        self.cfg.device_id
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
                content_meta(&event.text)
            );
            return None;
        }
        let echo = self
            .suppression_deadline
            .is_some_and(|d| Instant::now() < d)
            && self.last_applied_hash == Some(crypto::content_hash(&event.text));
        if echo {
            debug!(
                "suppressed echo of applied content {}",
                content_meta(&event.text)
            );
            return None;
        }
        if event.text.len() > self.cfg.max_text_bytes {
            warn!(
                "local text too long to sync: {} bytes (max {})",
                event.text.len(),
                self.cfg.max_text_bytes
            );
            return None;
        }
        if self.cfg.debounce.is_zero() {
            return Some(self.send_now(event.text));
        }
        self.pending = Some(event.text);
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
        if let Some(text) = self.pending.take() {
            self.pending_since = None;
            self.send_now(text);
        }
    }

    /// Time until the next debounced send is due (large when nothing pending).
    pub fn time_until_flush(&self) -> Duration {
        match self.pending_since {
            Some(since) => self.cfg.debounce.saturating_sub(since.elapsed()),
            None => Duration::from_secs(3600),
        }
    }

    fn send_now(&mut self, text: String) -> Vec<u8> {
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
            content_meta(&text)
        );
        self.transport.send(&packet);
        packet
    }

    /// Handle a received datagram. Returns the applied text, if any.
    pub fn handle_packet(&mut self, datagram: &[u8]) -> Option<String> {
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
        if let Err(e) = self.backend.set_text(&text) {
            warn!("failed to set local clipboard: {e}");
            return None;
        }
        debug!(
            "applied remote change lamport={} {}",
            body.lamport,
            content_meta(&text)
        );
        self.last_applied = remote;
        self.lamport = self.lamport.max(body.lamport);
        self.last_applied_hash = Some(crypto::content_hash(&text));
        self.suppression_deadline = Some(Instant::now() + self.cfg.suppression);
        Some(text)
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
            for bytes in remote_rx {
                if tx_remote.send(Incoming::Remote(bytes)).is_err() {
                    break;
                }
            }
        });
        let tx_shutdown = tx;
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
                Ok(Incoming::Remote(bytes)) => {
                    self.handle_packet(&bytes);
                }
                Ok(Incoming::Shutdown) | Err(RecvTimeoutError::Disconnected) => break,
                Err(RecvTimeoutError::Timeout) => self.flush_debounce(),
            }
        }
        debug!("engine loop exiting");
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
        set_count: AtomicUsize,
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
        fn subscribe_changes(&self) -> Receiver<ClipboardEvent> {
            let (tx, rx) = channel();
            self.0.subscribers.lock().unwrap().push(tx);
            rx
        }
    }

    #[derive(Default)]
    struct TransportInner {
        sent: Mutex<Vec<Vec<u8>>>,
        incoming: Mutex<Option<Receiver<Vec<u8>>>>,
        inject_tx: Mutex<Option<Sender<Vec<u8>>>>,
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
            self.0
                .inject_tx
                .lock()
                .unwrap()
                .as_ref()
                .unwrap()
                .send(bytes)
                .unwrap();
        }
    }

    impl Transport for FakeTransport {
        fn send(&self, bytes: &[u8]) {
            self.0.sent.lock().unwrap().push(bytes.to_vec());
        }
        fn recv(&self) -> Receiver<Vec<u8>> {
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
            .handle_local_change(ClipboardEvent {
                text: "hello".into(),
                sensitive: false,
            })
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
            .handle_local_change(ClipboardEvent {
                text: "from-b".into(),
                sensitive: false,
            })
            .unwrap();
        assert_eq!(transport.sent().len(), 1);

        let applied = receiver.handle_packet(&packet);
        assert_eq!(applied.as_deref(), Some("from-b"));
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
        assert_eq!(engine.handle_packet(&packet), None);
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
            .handle_local_change(ClipboardEvent {
                text: "one".into(),
                sensitive: false,
            })
            .unwrap();
        assert_eq!(engine.handle_packet(&first).as_deref(), Some("one"));

        // Duplicate of an already-applied packet.
        assert_eq!(engine.handle_packet(&first), None);

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
        assert_eq!(engine.handle_packet(&stale), None);
        assert_eq!(clipboard.text(), "one");

        // A newer packet from the same origin replaces it (lamport must rise).
        let second = origin
            .handle_local_change(ClipboardEvent {
                text: "two".into(),
                sensitive: false,
            })
            .unwrap();
        let (_, second_body) = open_packet(&KEY, &second);
        let (_, first_body) = open_packet(&KEY, &first);
        assert!(second_body.lamport > first_body.lamport);
        assert_eq!(engine.handle_packet(&second).as_deref(), Some("two"));
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
                .handle_local_change(ClipboardEvent {
                    text: "alpha".into(),
                    sensitive: false,
                })
                .expect("a broadcasts");
            clip_a.set_text("alpha").unwrap();
            let pb = b
                .handle_local_change(ClipboardEvent {
                    text: "bravo".into(),
                    sensitive: false,
                })
                .expect("b broadcasts");
            clip_b.set_text("bravo").unwrap();

            let (_, ha) = open_packet(&KEY, &pa);
            let (_, hb) = open_packet(&KEY, &pb);
            let a_wins = (ha.lamport, DEVICE_A) > (hb.lamport, DEVICE_B);
            let expected = if a_wins { "alpha" } else { "bravo" };

            // Deliver both packets to both peers, in either order, then
            // replay them (duplicates) to prove idempotence.
            if reverse_delivery {
                assert_eq!(b.handle_packet(&pa).as_deref(), a_wins.then_some("alpha"));
                assert_eq!(
                    a.handle_packet(&pb).as_deref(),
                    (!a_wins).then_some("bravo")
                );
                assert_eq!(b.handle_packet(&pa), None, "replay dropped");
                assert_eq!(a.handle_packet(&pb), None, "replay dropped");
            } else {
                assert_eq!(
                    a.handle_packet(&pb).as_deref(),
                    (!a_wins).then_some("bravo")
                );
                assert_eq!(b.handle_packet(&pa).as_deref(), a_wins.then_some("alpha"));
                assert_eq!(a.handle_packet(&pb), None, "replay dropped");
                assert_eq!(b.handle_packet(&pa), None, "replay dropped");
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

    /// (f) oversize text is not sent.
    #[test]
    fn oversize_text_not_sent() {
        let transport = FakeTransport::new();
        let mut engine = Engine::new(FakeClipboard::new(), transport.clone(), cfg(DEVICE_A));
        let long = "x".repeat(DEFAULT_MAX_TEXT_BYTES + 1);
        assert!(
            engine
                .handle_local_change(ClipboardEvent {
                    text: long,
                    sensitive: false
                })
                .is_none()
        );
        assert_eq!(transport.sent().len(), 0);
        // Exactly at the limit is fine.
        let exact = "x".repeat(DEFAULT_MAX_TEXT_BYTES);
        assert!(
            engine
                .handle_local_change(ClipboardEvent {
                    text: exact,
                    sensitive: false
                })
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
                .handle_local_change(ClipboardEvent {
                    text: "hunter2".into(),
                    sensitive: true
                })
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
                .handle_local_change(ClipboardEvent {
                    text: "hunter2".into(),
                    sensitive: true
                })
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
            .handle_local_change(ClipboardEvent {
                text: "remote-text".into(),
                sensitive: false,
            })
            .unwrap();
        let sent_before = transport.sent().len();
        assert_eq!(
            engine.handle_packet(&packet).as_deref(),
            Some("remote-text")
        );

        // The backend watcher now fires with the same content we just set.
        assert_eq!(
            engine.handle_local_change(ClipboardEvent {
                text: "remote-text".into(),
                sensitive: false
            }),
            None
        );
        assert_eq!(transport.sent().len(), sent_before);

        // Unrelated content still broadcasts.
        assert!(
            engine
                .handle_local_change(ClipboardEvent {
                    text: "different".into(),
                    sensitive: false
                })
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
                .handle_local_change(ClipboardEvent {
                    text: format!("msg-{i}"),
                    sensitive: false,
                })
                .unwrap();
            if engine.handle_packet(&packet).is_some() {
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
            let sent = engine.handle_local_change(ClipboardEvent {
                text: format!("t{i}"),
                sensitive: false,
            });
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
            .handle_local_change(ClipboardEvent {
                text: "via-loop".into(),
                sensitive: false,
            })
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
}
