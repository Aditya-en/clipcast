//! Polling fallback backend built on arboard (X11/Xwayland).
//!
//! Used when the compositor has no data-control protocol. The poll loop
//! snapshots the clipboard on an interval and emits an event whenever the
//! content differs from the previous snapshot. Sensitive-flag detection is
//! impossible through this crate's text-only API (documented limitation).
//!
//! Images: arboard exposes raw RGBA pixels, so this backend syncs PNG only —
//! pixels are PNG-encoded on read and PNG-decoded on write via the `png`
//! crate. JPEG/WebP pass through untouched on the X11 and Wayland backends,
//! which transfer the original bytes. When both an image and text are
//! present, the image wins (it is the richer representation).

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::thread;
use std::time::{Duration, Instant};

use tracing::debug;

use super::Subscribers;
use crate::engine::{ClipboardBackend, ClipboardEvent, ClipboardImage};

/// MIME type this backend produces and consumes.
pub const POLLING_IMAGE_MIME: &str = "image/png";
/// Refuse absurd pixel buffers before allocating (256 megapixels RGBA).
const MAX_PIXELS: usize = 256 * 1024 * 1024;

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

/// Snapshot identity: enough to detect a change without keeping full bytes.
#[derive(Clone, PartialEq, Eq)]
enum Snapshot {
    Text(String),
    Image { hash: u64 },
    Empty,
}

fn poll_loop(subs: &Subscribers, stop: &AtomicBool, interval: Duration) {
    let mut last = Snapshot::Empty;
    let mut baseline = false;
    while !stop.load(Ordering::Relaxed) {
        match current_snapshot() {
            Ok((snapshot, event)) => {
                if baseline
                    && snapshot != last
                    && let Some(event) = event
                {
                    subs.emit(event);
                }
                last = snapshot;
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

/// Read the clipboard once, preferring an image over text. Returns the
/// snapshot identity plus the event to emit when it differs.
fn current_snapshot() -> io::Result<(Snapshot, Option<ClipboardEvent>)> {
    let mut cb =
        arboard::Clipboard::new().map_err(|e| io::Error::other(format!("clipboard open: {e}")))?;
    // Image first: when several representations exist, the image wins.
    match cb.get_image() {
        Ok(img) => {
            let png = encode_png_rgba(&img)?;
            let hash = crate::crypto::content_hash_bytes(&png);
            let event = ClipboardEvent::image(POLLING_IMAGE_MIME.to_string(), png);
            return Ok((Snapshot::Image { hash }, Some(event)));
        }
        Err(arboard::Error::ContentNotAvailable) | Err(arboard::Error::ClipboardNotSupported) => {}
        Err(e) => return Err(io::Error::other(format!("clipboard image read: {e}"))),
    }
    match cb.get_text() {
        Ok(text) => Ok((
            Snapshot::Text(text.clone()),
            Some(ClipboardEvent::text(text, false)),
        )),
        Err(arboard::Error::ContentNotAvailable) | Err(arboard::Error::ClipboardNotSupported) => {
            Ok((Snapshot::Empty, None))
        }
        Err(e) => Err(io::Error::other(format!("clipboard read: {e}"))),
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

fn current_image() -> io::Result<Option<ClipboardImage>> {
    let mut cb =
        arboard::Clipboard::new().map_err(|e| io::Error::other(format!("clipboard open: {e}")))?;
    match cb.get_image() {
        Ok(img) => Ok(Some(ClipboardImage {
            mime_type: POLLING_IMAGE_MIME.to_string(),
            bytes: encode_png_rgba(&img)?,
        })),
        Err(arboard::Error::ContentNotAvailable) | Err(arboard::Error::ClipboardNotSupported) => {
            Ok(None)
        }
        Err(e) => Err(io::Error::other(format!("clipboard image read: {e}"))),
    }
}

/// Encode arboard RGBA pixels as a PNG.
fn encode_png_rgba(img: &arboard::ImageData) -> io::Result<Vec<u8>> {
    let width: u32 = img.width.try_into().map_err(|_| too_big())?;
    let height: u32 = img.height.try_into().map_err(|_| too_big())?;
    let want = (img.width as u64)
        .checked_mul(img.height as u64)
        .and_then(|p| p.checked_mul(4))
        .ok_or_else(too_big)?;
    if want as usize != img.bytes.len() || img.width * img.height > MAX_PIXELS {
        return Err(too_big());
    }
    let mut buf = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut buf, width, height);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().map_err(io::Error::other)?;
        writer
            .write_image_data(&img.bytes)
            .map_err(io::Error::other)?;
        writer.finish().map_err(io::Error::other)?;
    }
    Ok(buf)
}

fn too_big() -> io::Error {
    io::Error::other("clipboard image dimensions out of range")
}

/// Decode PNG bytes to arboard RGBA pixels (8-bit RGB/RGBA/gray supported).
fn decode_png_to_rgba(png_bytes: &[u8]) -> io::Result<arboard::ImageData<'static>> {
    let decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
    let mut reader = decoder.read_info().map_err(io::Error::other)?;
    let mut buf = vec![
        0u8;
        reader
            .output_buffer_size()
            .ok_or_else(|| io::Error::other("PNG output size overflow"))?
    ];
    let info = reader.next_frame(&mut buf).map_err(io::Error::other)?;
    if info.bit_depth != png::BitDepth::Eight {
        return Err(io::Error::other("only 8-bit PNG supported for clipboard"));
    }
    let pixels = info.width as usize * info.height as usize;
    if pixels > MAX_PIXELS {
        return Err(too_big());
    }
    let raw = &buf[..info.buffer_size()];
    let rgba: Vec<u8> = match info.color_type {
        png::ColorType::Rgba => raw.to_vec(),
        png::ColorType::Rgb => {
            let (chunks, rest) = raw.as_chunks::<3>();
            if !rest.is_empty() {
                return Err(io::Error::other("truncated RGB data in PNG"));
            }
            chunks
                .iter()
                .flat_map(|p| [p[0], p[1], p[2], 0xFF])
                .collect()
        }
        png::ColorType::Grayscale => raw.iter().flat_map(|&g| [g, g, g, 0xFF]).collect(),
        png::ColorType::GrayscaleAlpha => {
            let (chunks, rest) = raw.as_chunks::<2>();
            if !rest.is_empty() {
                return Err(io::Error::other("truncated gray-alpha data in PNG"));
            }
            chunks
                .iter()
                .flat_map(|p| [p[0], p[0], p[0], p[1]])
                .collect()
        }
        _ => return Err(io::Error::other("unsupported PNG color type")),
    };
    Ok(arboard::ImageData {
        width: info.width as usize,
        height: info.height as usize,
        bytes: rgba.into(),
    })
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

    fn get_image(&self) -> io::Result<Option<ClipboardImage>> {
        current_image()
    }

    fn set_image(&self, image: &ClipboardImage) -> io::Result<()> {
        if image.mime_type != POLLING_IMAGE_MIME {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("polling backend syncs PNG only, got {}", image.mime_type),
            ));
        }
        let pixels = decode_png_to_rgba(&image.bytes)?;
        let mut cb = arboard::Clipboard::new()
            .map_err(|e| io::Error::other(format!("clipboard open: {e}")))?;
        cb.set_image(pixels)
            .map_err(|e| io::Error::other(format!("clipboard image write: {e}")))
    }

    fn image_mime_types(&self) -> Vec<String> {
        vec![POLLING_IMAGE_MIME.to_string()]
    }

    fn subscribe_changes(&self) -> Receiver<ClipboardEvent> {
        self.subs.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn red_1x1_rgba() -> arboard::ImageData<'static> {
        arboard::ImageData {
            width: 1,
            height: 1,
            bytes: vec![255u8, 0, 0, 255].into(),
        }
    }

    #[test]
    fn png_encode_decode_round_trip() {
        let png = encode_png_rgba(&red_1x1_rgba()).unwrap();
        assert_eq!(&png[0..8], b"\x89PNG\r\n\x1a\n");
        let back = decode_png_to_rgba(&png).unwrap();
        assert_eq!((back.width, back.height), (1, 1));
        assert_eq!(back.bytes.as_ref(), &[255u8, 0, 0, 255]);
    }

    #[test]
    fn png_decode_rejects_garbage() {
        assert!(decode_png_to_rgba(b"not a png").is_err());
        assert!(decode_png_to_rgba(&[]).is_err());
    }

    #[test]
    fn png_encode_rejects_bad_dimensions() {
        let bad = arboard::ImageData {
            width: 2,
            height: 2,
            bytes: vec![0u8; 3].into(),
        };
        assert!(encode_png_rgba(&bad).is_err());
    }

    #[test]
    fn polling_backend_advertises_png_only() {
        // Constructor needs no display; method is pure metadata.
        let backend = PollingBackend {
            subs: Arc::new(Subscribers::default()),
            stop: Arc::new(AtomicBool::new(false)),
        };
        assert_eq!(backend.image_mime_types(), vec!["image/png"]);
        let err = backend
            .set_image(&ClipboardImage {
                mime_type: "image/jpeg".to_string(),
                bytes: vec![0xFF, 0xD8],
            })
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
