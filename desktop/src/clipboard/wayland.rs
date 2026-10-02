//! Wayland backend: wlr/ext data-control change detection via wl-clipboard-rs.
//!
//! A watcher thread blocks on selection-change events and reads text content
//! (plus the KDE password-manager hint) from each offer. `set_text` uses the
//! crate's copy path, which owns the selection on its own connection and
//! serves paste requests until replaced.

use std::io::{self, Read};
use std::sync::Arc;
use std::sync::mpsc::Receiver;
use std::thread;

use tracing::warn;
use wl_clipboard_rs::copy::{MimeType as CopyMimeType, Options, Source};
use wl_clipboard_rs::paste::{self, MimeType as PasteMimeType, Seat};
use wl_clipboard_rs::utils::PASSWORD_MANAGER_HINT_MIME_TYPE;
use wl_clipboard_rs::watch::{self, ClipboardType as WatchClipboardType, Watcher};

use super::Subscribers;
use crate::engine::{ClipboardBackend, ClipboardEvent};

/// Preferred text MIME types when reading a selection, best first.
const TEXT_MIMES: &[&str] = &[
    "text/plain;charset=utf-8",
    "text/plain",
    "UTF8_STRING",
    "STRING",
    "TEXT",
];

fn preferred_text_mime(mime_types: &[String]) -> Option<&str> {
    TEXT_MIMES
        .iter()
        .copied()
        .find(|want| mime_types.iter().any(|m| m == want))
}

fn read_all(mut reader: impl Read) -> io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf)?;
    Ok(buf)
}

fn hint_is_secret(bytes: &[u8]) -> bool {
    String::from_utf8_lossy(bytes)
        .trim()
        .eq_ignore_ascii_case("secret")
}

/// Extract `(text, sensitive)` from an offer; `None` for non-text or empty
/// content (ignored: v1 syncs plain text only).
fn read_offer(mime_types: &[String], offer: &mut watch::Offer<'_>) -> Option<(String, bool)> {
    let sensitive = mime_types
        .iter()
        .any(|m| m == PASSWORD_MANAGER_HINT_MIME_TYPE)
        && offer
            .receive(PASSWORD_MANAGER_HINT_MIME_TYPE)
            .ok()
            .and_then(|reader| read_all(reader).ok())
            .is_some_and(|bytes| hint_is_secret(&bytes));

    let mime = preferred_text_mime(mime_types)?;
    let bytes = read_all(offer.receive(mime).ok()?).ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some((String::from_utf8_lossy(&bytes).into_owned(), sensitive))
}

pub(crate) fn create() -> io::Result<Box<dyn ClipboardBackend>> {
    let watcher = Watcher::new(WatchClipboardType::Regular, Seat::Unspecified)
        .map_err(|e| io::Error::other(format!("wayland watcher: {e}")))?;
    let cancel = watcher.cancel_handle();
    let subs = Arc::new(Subscribers::default());

    let thread_subs = Arc::clone(&subs);
    thread::Builder::new()
        .name("clipcast-wayland".into())
        .spawn(move || {
            let mut watcher = watcher;
            loop {
                match watcher.next_event() {
                    Ok(Some(watch::ClipboardEvent::Changed {
                        mime_types,
                        mut offer,
                        ..
                    })) => {
                        if let Some((text, sensitive)) = read_offer(&mime_types, &mut offer) {
                            thread_subs.emit(ClipboardEvent { text, sensitive });
                        }
                    }
                    Ok(Some(watch::ClipboardEvent::Cleared { .. })) => {}
                    Ok(None) => break,
                    Err(e) => {
                        warn!("wayland clipboard watch stopped: {e}");
                        break;
                    }
                }
            }
        })
        .map_err(|e| io::Error::other(format!("spawn wayland thread: {e}")))?;

    Ok(Box::new(WaylandBackend { subs, cancel }))
}

struct WaylandBackend {
    subs: Arc<Subscribers>,
    cancel: watch::CancelHandle,
}

impl Drop for WaylandBackend {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

impl ClipboardBackend for WaylandBackend {
    fn get_text(&self) -> io::Result<Option<String>> {
        match paste::get_contents(
            paste::ClipboardType::Regular,
            Seat::Unspecified,
            PasteMimeType::Text,
        ) {
            Ok((reader, _mime)) => {
                let bytes = read_all(reader)?;
                if bytes.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
                }
            }
            Err(
                paste::Error::ClipboardEmpty | paste::Error::NoMimeType | paste::Error::NoSeats,
            ) => Ok(None),
            Err(e) => Err(io::Error::other(format!("wayland paste: {e}"))),
        }
    }

    fn set_text(&self, text: &str) -> io::Result<()> {
        let mut opts = Options::new();
        opts.trim_newline(false);
        opts.copy(
            Source::Bytes(text.as_bytes().to_vec().into()),
            CopyMimeType::Text,
        )
        .map_err(|e| io::Error::other(format!("wayland copy: {e}")))
    }

    fn subscribe_changes(&self) -> Receiver<ClipboardEvent> {
        self.subs.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_mime_preference() {
        let mimes = vec![
            "image/png".to_string(),
            "text/plain".to_string(),
            "text/plain;charset=utf-8".to_string(),
        ];
        assert_eq!(
            preferred_text_mime(&mimes),
            Some("text/plain;charset=utf-8")
        );

        let mimes = vec!["image/png".to_string(), "text/plain".to_string()];
        assert_eq!(preferred_text_mime(&mimes), Some("text/plain"));

        let mimes = vec!["image/png".to_string()];
        assert_eq!(preferred_text_mime(&mimes), None);
        assert_eq!(preferred_text_mime(&[]), None);
    }

    #[test]
    fn hint_value_parsing() {
        assert!(hint_is_secret(b"secret"));
        assert!(hint_is_secret(b"secret\n"));
        assert!(hint_is_secret(b"  SECRET  "));
        assert!(!hint_is_secret(b"not-secret"));
        assert!(!hint_is_secret(b""));
    }
}
