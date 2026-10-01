//! Polling fallback backend built on arboard (X11/Xwayland).
//!
//! Used when the compositor has no data-control protocol. The poll loop
//! snapshots the clipboard on an interval and emits an event whenever the
//! text differs from the previous snapshot. Sensitive-flag detection is
//! impossible through this crate's text-only API (documented limitation).

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::thread;
use std::time::{Duration, Instant};

use tracing::debug;

use super::Subscribers;
use crate::engine::{ClipboardBackend, ClipboardEvent};

pub(crate) fn create(interval: Duration) -> io::Result<Box<dyn ClipboardBackend>> {
    let subs = Arc::new(Subscribers::default());
    let stop = Arc::new(AtomicBool::new(false));

    let thread_subs = Arc::clone(&subs);
    let thread_stop = Arc::clone(&stop);
    thread::Builder::new()
        .name("clipcast-poll".into())
        .spawn(move || poll_loop(&thread_subs, &thread_stop, interval))
        .map_err(|e| io::Error::other(format!("spawn poll thread: {e}")))?;

    Ok(Box::new(PollingBackend { subs, stop }))
}

fn poll_loop(subs: &Subscribers, stop: &AtomicBool, interval: Duration) {
    let mut last: Option<String> = None;
    let mut baseline = false;
    while !stop.load(Ordering::Relaxed) {
        match current_text() {
            Ok(Some(text)) => {
                if baseline && last.as_deref() != Some(text.as_str()) {
                    subs.emit(ClipboardEvent {
                        text: text.clone(),
                        sensitive: false,
                    });
                }
                last = Some(text);
                baseline = true;
            }
            Ok(None) => {
                // Cleared (or non-text content): no event, but remember it so
                // the next copy is seen as a change.
                last = None;
                baseline = true;
            }
            Err(e) => debug!("clipboard poll failed: {e}"),
        }
        let deadline = Instant::now() + interval;
        while Instant::now() < deadline {
            if stop.load(Ordering::Relaxed) {
                return;
            }
            thread::sleep(Duration::from_millis(50).min(interval));
        }
    }
}

fn current_text() -> io::Result<Option<String>> {
    let mut cb =
        arboard::Clipboard::new().map_err(|e| io::Error::other(format!("clipboard open: {e}")))?;
    match cb.get_text() {
        Ok(text) => Ok(Some(text)),
        Err(arboard::Error::ContentNotAvailable) | Err(arboard::Error::ClipboardNotSupported) => {
            Ok(None)
        }
        Err(e) => Err(io::Error::other(format!("clipboard read: {e}"))),
    }
}

struct PollingBackend {
    subs: Arc<Subscribers>,
    stop: Arc<AtomicBool>,
}

impl Drop for PollingBackend {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl ClipboardBackend for PollingBackend {
    fn get_text(&self) -> io::Result<Option<String>> {
        current_text()
    }

    fn set_text(&self, text: &str) -> io::Result<()> {
        let mut cb = arboard::Clipboard::new()
            .map_err(|e| io::Error::other(format!("clipboard open: {e}")))?;
        cb.set_text(text)
            .map_err(|e| io::Error::other(format!("clipboard write: {e}")))
    }

    fn subscribe_changes(&self) -> Receiver<ClipboardEvent> {
        self.subs.subscribe()
    }
}
