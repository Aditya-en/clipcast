//! Clipboard-publish normalization for received images.
//!
//! Some paste targets (notably Chromium-based browsers on this project's
//! reference setup) accept PNG from the clipboard but silently ignore
//! JPEG, no matter which peer offered it. To make received images pastable
//! everywhere, JPEG bytes are transcoded to PNG before they are published
//! to the local clipboard.
//!
//! This is a local publish concern only: the bytes on the wire, the hashes,
//! and the sender cache are untouched. Callers must use the RETURNED bytes
//! (and MIME type) for everything downstream — clipboard publish and echo
//! suppression alike — or suppression will miss and cause a rebroadcast.
//!
//! Rules:
//! - non-JPEG content passes through untouched;
//! - a JPEG that fails to decode passes through untouched (best effort: a
//!   suspicious file still reaches apps that do accept it), never an error;
//! - a transcoded PNG that would exceed `max_bytes` is rejected in favor of
//!   the original bytes (same best-effort reasoning).

use std::io::Cursor;

/// Transcode JPEG clipboard bytes to PNG; see the module docs. `max_bytes`
/// is the configured `max_image_bytes` ceiling applied to the transcoded
/// output.
pub fn normalize_for_clipboard(mime_type: &str, bytes: &[u8], max_bytes: u64) -> (String, Vec<u8>) {
    if mime_type != "image/jpeg" {
        return (mime_type.to_string(), bytes.to_vec());
    }
    let png = match decode_jpeg_to_png(bytes) {
        Some(p) => p,
        None => return (mime_type.to_string(), bytes.to_vec()),
    };
    if png.len() as u64 > max_bytes {
        tracing::debug!(
            "normalized PNG ({} bytes) exceeds image limit; publishing original JPEG",
            png.len()
        );
        return (mime_type.to_string(), bytes.to_vec());
    }
    tracing::debug!(
        "normalized received JPEG ({} bytes) to PNG ({} bytes) for clipboard",
        bytes.len(),
        png.len()
    );
    ("image/png".to_string(), png)
}

/// Decode JPEG bytes and re-encode as 8-bit RGB/RGBA PNG. `None` when the
/// input is not decodable (caller falls back to the original bytes).
fn decode_jpeg_to_png(jpeg: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = jpeg_decoder::Decoder::new(Cursor::new(jpeg));
    let pixels = decoder.decode().ok()?;
    let info = decoder.info()?;
    if info.width == 0 || info.height == 0 {
        return None;
    }
    // Guard the encode dimensions against a hostile header.
    if info.width > 16384 || info.height > 16384 {
        return None;
    }
    let rgb: Vec<u8> = match info.pixel_format {
        jpeg_decoder::PixelFormat::RGB24 => pixels,
        jpeg_decoder::PixelFormat::L8 => pixels.iter().flat_map(|&g| [g, g, g]).collect(),
        jpeg_decoder::PixelFormat::L16 => {
            let (chunks, rest) = pixels.as_chunks::<2>();
            if !rest.is_empty() {
                return None;
            }
            chunks.iter().flat_map(|p| [p[0], p[0], p[0]]).collect()
        }
        jpeg_decoder::PixelFormat::CMYK32 => {
            let (chunks, rest) = pixels.as_chunks::<4>();
            if !rest.is_empty() {
                return None;
            }
            chunks
                .iter()
                .flat_map(|p| {
                    // Naive CMYK invert; browsers accept the approximation and
                    // the alternative is dropping the image entirely.
                    let (c, m, y, k) = (p[0] as u16, p[1] as u16, p[2] as u16, p[3] as u16);
                    [
                        (255 - (c + k).min(255)) as u8,
                        (255 - (m + k).min(255)) as u8,
                        (255 - (y + k).min(255)) as u8,
                    ]
                })
                .collect()
        }
    };
    encode_png_rgb8(info.width as u32, info.height as u32, &rgb).ok()
}

fn encode_png_rgb8(width: u32, height: u32, rgb: &[u8]) -> std::io::Result<Vec<u8>> {
    if rgb.len() != width as usize * height as usize * 3 {
        return Err(std::io::Error::other("RGB buffer size mismatch"));
    }
    let mut buf = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut buf, width, height);
        enc.set_color(png::ColorType::Rgb);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().map_err(std::io::Error::other)?;
        writer
            .write_image_data(rgb)
            .map_err(std::io::Error::other)?;
        writer.finish().map_err(std::io::Error::other)?;
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_jpeg() -> Vec<u8> {
        std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/red-8x8.jpg"
        ))
        .expect("test JPEG must exist")
    }

    #[test]
    fn jpeg_transcodes_to_decodable_png() {
        let jpeg = test_jpeg();
        assert!(jpeg.len() > 100);
        let (mime, png) = normalize_for_clipboard("image/jpeg", &jpeg, 16 * 1024 * 1024);
        assert_eq!(mime, "image/png");
        assert_eq!(&png[0..8], b"\x89PNG\r\n\x1a\n");
        // The output decodes back to an 8x8 red image.
        let decoder = png::Decoder::new(Cursor::new(&png));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0u8; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!((info.width, info.height), (8, 8));
        let px = &buf[..info.buffer_size()];
        assert!(px.len() >= 3);
        // Red dominates (JPEG is lossy; allow tolerance).
        assert!(px[0] > 200 && px[1] < 60 && px[2] < 60);
    }

    #[test]
    fn non_jpeg_passes_through() {
        let png = vec![0x89, b'P', b'N', b'G', 0x01, 0x02];
        let (mime, out) = normalize_for_clipboard("image/png", &png, 1024);
        assert_eq!(mime, "image/png");
        assert_eq!(out, png);
        let (mime, out) = normalize_for_clipboard("image/webp", &png, 1024);
        assert_eq!(mime, "image/webp");
        assert_eq!(out, png);
    }

    #[test]
    fn undecodable_jpeg_falls_back_to_original() {
        let garbage = b"not a jpeg at all";
        let (mime, out) = normalize_for_clipboard("image/jpeg", garbage, 16 * 1024 * 1024);
        assert_eq!(mime, "image/jpeg");
        assert_eq!(out, garbage);
    }

    #[test]
    fn oversize_transcode_falls_back_to_original() {
        let jpeg = test_jpeg();
        // A ceiling smaller than any real PNG forces the fallback path.
        let (mime, out) = normalize_for_clipboard("image/jpeg", &jpeg, 10);
        assert_eq!(mime, "image/jpeg");
        assert_eq!(out, jpeg);
    }
}
