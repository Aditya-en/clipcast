//! Wire protocol v1 — pure encode/decode, no I/O.
//!
//! This module is the contract shared with the Android client. All integers
//! are big-endian. One UDP datagram per message.
//!
//! Header (34 bytes, sent in clear, authenticated as AES-GCM AAD):
//! - magic: 4 bytes ASCII "CCLP"
//! - version: u8 = 1
//! - msg_type: u8 (0x01 = CLIP_UPDATE)
//! - device_id: 16 bytes
//! - nonce: 12 bytes
//!
//! Body plaintext (sealed with AES-256-GCM, AAD = the 34 header bytes):
//! - lamport: u64
//! - timestamp_ms: u64 (informational only, never used for ordering)
//! - content_type: u8 (0x01 = text/plain UTF-8)
//! - payload_len: u32
//! - payload: payload_len bytes

use thiserror::Error;

pub const MAGIC: [u8; 4] = *b"CCLP";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 34;
pub const MAX_DATAGRAM: usize = 1400;

pub const MSG_CLIP_UPDATE: u8 = 0x01;

pub const CONTENT_TEXT: u8 = 0x01;
pub const CONTENT_IMAGE: u8 = 0x02;
pub const CONTENT_ANNOUNCE: u8 = 0x80;

/// Inner content type carried inside an announce payload (v2, extensible for
/// images/files later). Only text is sent today.
pub const INNER_TEXT: u8 = 0x01;
/// Inner content type for an image announce: the announced bytes are raw
/// image bytes in the payload's MIME type, fetched over the TCP side
/// channel exactly like a large text. Old clients only accept the 59-byte
/// text announce and ignore longer image announces.
pub const INNER_IMAGE: u8 = 0x02;

/// Maximum MIME type length inside an image announce payload.
pub const MAX_MIME_LEN: usize = 63;
/// Longest possible image announce payload: 59 base bytes + mime_len(1) +
/// up to 63 MIME bytes.
pub const IMAGE_ANNOUNCE_MAX_LEN: usize = ANNOUNCE_PAYLOAD_LEN + 1 + MAX_MIME_LEN;

/// Image MIME types a Clipcast peer may announce. Anything else is ignored.
pub const SUPPORTED_IMAGE_MIMES: [&str; 3] = ["image/png", "image/jpeg", "image/webp"];

/// Returns true for a MIME type Clipcast will synchronize.
pub fn is_supported_image_mime(mime: &str) -> bool {
    SUPPORTED_IMAGE_MIMES.contains(&mime)
}

/// Announce payload length: inner(1) + transfer_id(16) + total_len(8) +
/// sha256(32) + tcp_port(2) = 59 bytes.
pub const ANNOUNCE_PAYLOAD_LEN: usize = 59;

pub const DEVICE_ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

/// Plaintext body header: lamport(8) + timestamp_ms(8) + content_type(1) + payload_len(4).
pub const BODY_HEADER_LEN: usize = 21;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub msg_type: u8,
    pub device_id: [u8; DEVICE_ID_LEN],
    pub nonce: [u8; NONCE_LEN],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    pub lamport: u64,
    pub timestamp_ms: u64,
    pub content_type: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnouncePayload {
    pub inner_content_type: u8,
    pub transfer_id: [u8; 16],
    pub total_len: u64,
    pub sha256: [u8; 32],
    pub tcp_port: u16,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AnnounceError {
    #[error("announce payload must be {expected} bytes, got {got}")]
    BadLength { expected: usize, got: usize },
}

/// An image announce: the 59-byte base announce with `inner_content_type =
/// 0x02`, followed by `mime_len: u8` and `mime_len` MIME bytes (UTF-8,
/// `<= 63`, one of [`SUPPORTED_IMAGE_MIMES`]). Total length 60..=123.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageAnnouncePayload {
    pub transfer_id: [u8; 16],
    pub total_len: u64,
    pub sha256: [u8; 32],
    pub tcp_port: u16,
    pub mime_type: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ImageAnnounceError {
    #[error("image announce payload must be 60..=123 bytes, got {0}")]
    BadLength(usize),
    #[error("image announce must carry inner type 0x02, got {0:#04x}")]
    BadInner(u8),
    #[error("mime_len {declared} exceeds available {available} bytes")]
    MimeLenMismatch { declared: usize, available: usize },
    #[error("MIME type is not valid UTF-8")]
    InvalidMimeUtf8,
    #[error("unsupported image MIME type: {0}")]
    UnsupportedMime(String),
}

pub fn encode_image_announce(a: &ImageAnnouncePayload) -> Vec<u8> {
    let mime = a.mime_type.as_bytes();
    debug_assert!(mime.len() <= MAX_MIME_LEN);
    let mut buf = Vec::with_capacity(ANNOUNCE_PAYLOAD_LEN + 1 + mime.len());
    buf.push(INNER_IMAGE);
    buf.extend_from_slice(&a.transfer_id);
    buf.extend_from_slice(&a.total_len.to_be_bytes());
    buf.extend_from_slice(&a.sha256);
    buf.extend_from_slice(&a.tcp_port.to_be_bytes());
    buf.push(mime.len() as u8);
    buf.extend_from_slice(mime);
    buf
}

pub fn decode_image_announce(bytes: &[u8]) -> Result<ImageAnnouncePayload, ImageAnnounceError> {
    if bytes.len() < ANNOUNCE_PAYLOAD_LEN + 1 || bytes.len() > IMAGE_ANNOUNCE_MAX_LEN {
        return Err(ImageAnnounceError::BadLength(bytes.len()));
    }
    if bytes[0] != INNER_IMAGE {
        return Err(ImageAnnounceError::BadInner(bytes[0]));
    }
    let mut transfer_id = [0u8; 16];
    transfer_id.copy_from_slice(&bytes[1..17]);
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&bytes[25..57]);
    let declared = bytes[59] as usize;
    let available = bytes.len() - 60;
    if declared > available {
        return Err(ImageAnnounceError::MimeLenMismatch {
            declared,
            available,
        });
    }
    // Trailing bytes beyond the declared MIME are rejected: the declared
    // mime_len is authoritative and extra bytes are a protocol violation.
    if declared != available {
        return Err(ImageAnnounceError::MimeLenMismatch {
            declared,
            available,
        });
    }
    let mime_bytes = &bytes[60..60 + declared];
    let mime_type = std::str::from_utf8(mime_bytes)
        .map_err(|_| ImageAnnounceError::InvalidMimeUtf8)?
        .to_string();
    if !is_supported_image_mime(&mime_type) {
        return Err(ImageAnnounceError::UnsupportedMime(mime_type));
    }
    Ok(ImageAnnouncePayload {
        transfer_id,
        total_len: u64::from_be_bytes(bytes[17..25].try_into().unwrap()),
        sha256,
        tcp_port: u16::from_be_bytes(bytes[57..59].try_into().unwrap()),
        mime_type,
    })
}

pub fn encode_announce(a: &AnnouncePayload) -> [u8; ANNOUNCE_PAYLOAD_LEN] {
    let mut buf = [0u8; ANNOUNCE_PAYLOAD_LEN];
    buf[0] = a.inner_content_type;
    buf[1..17].copy_from_slice(&a.transfer_id);
    buf[17..25].copy_from_slice(&a.total_len.to_be_bytes());
    buf[25..57].copy_from_slice(&a.sha256);
    buf[57..59].copy_from_slice(&a.tcp_port.to_be_bytes());
    buf
}

pub fn decode_announce(bytes: &[u8]) -> Result<AnnouncePayload, AnnounceError> {
    if bytes.len() != ANNOUNCE_PAYLOAD_LEN {
        return Err(AnnounceError::BadLength {
            expected: ANNOUNCE_PAYLOAD_LEN,
            got: bytes.len(),
        });
    }
    let mut transfer_id = [0u8; 16];
    transfer_id.copy_from_slice(&bytes[1..17]);
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&bytes[25..57]);
    Ok(AnnouncePayload {
        inner_content_type: bytes[0],
        transfer_id,
        total_len: u64::from_be_bytes(bytes[17..25].try_into().unwrap()),
        sha256,
        tcp_port: u16::from_be_bytes(bytes[57..59].try_into().unwrap()),
    })
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtoError {
    #[error("datagram too short for header: {0} bytes")]
    ShortHeader(usize),
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("body too short: {0} bytes")]
    ShortBody(usize),
    #[error("payload_len {declared} exceeds available {available} bytes")]
    PayloadLenMismatch { declared: u32, available: usize },
    #[error("invalid UTF-8 in text payload")]
    InvalidUtf8,
}

pub fn encode_header(header: &Header) -> [u8; HEADER_LEN] {
    let mut buf = [0u8; HEADER_LEN];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4] = header.version;
    buf[5] = header.msg_type;
    buf[6..22].copy_from_slice(&header.device_id);
    buf[22..34].copy_from_slice(&header.nonce);
    buf
}

pub fn decode_header(bytes: &[u8]) -> Result<Header, ProtoError> {
    if bytes.len() < HEADER_LEN {
        return Err(ProtoError::ShortHeader(bytes.len()));
    }
    if bytes[0..4] != MAGIC {
        return Err(ProtoError::BadMagic);
    }
    let version = bytes[4];
    if version != VERSION {
        return Err(ProtoError::UnsupportedVersion(version));
    }
    let mut device_id = [0u8; DEVICE_ID_LEN];
    device_id.copy_from_slice(&bytes[6..22]);
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[22..34]);
    Ok(Header {
        version,
        msg_type: bytes[5],
        device_id,
        nonce,
    })
}

pub fn encode_body(body: &Body) -> Vec<u8> {
    let mut buf = Vec::with_capacity(BODY_HEADER_LEN + body.payload.len());
    buf.extend_from_slice(&body.lamport.to_be_bytes());
    buf.extend_from_slice(&body.timestamp_ms.to_be_bytes());
    buf.push(body.content_type);
    buf.extend_from_slice(&(body.payload.len() as u32).to_be_bytes());
    buf.extend_from_slice(&body.payload);
    buf
}

pub fn decode_body(bytes: &[u8]) -> Result<Body, ProtoError> {
    if bytes.len() < BODY_HEADER_LEN {
        return Err(ProtoError::ShortBody(bytes.len()));
    }
    let lamport = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
    let timestamp_ms = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    let content_type = bytes[16];
    let payload_len = u32::from_be_bytes(bytes[17..21].try_into().unwrap()) as usize;
    let available = bytes.len() - BODY_HEADER_LEN;
    if payload_len > available {
        return Err(ProtoError::PayloadLenMismatch {
            declared: payload_len as u32,
            available,
        });
    }
    let payload = bytes[BODY_HEADER_LEN..BODY_HEADER_LEN + payload_len].to_vec();
    if content_type == CONTENT_TEXT && std::str::from_utf8(&payload).is_err() {
        return Err(ProtoError::InvalidUtf8);
    }
    Ok(Body {
        lamport,
        timestamp_ms,
        content_type,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_header() -> Header {
        Header {
            version: VERSION,
            msg_type: MSG_CLIP_UPDATE,
            device_id: [0xAB; DEVICE_ID_LEN],
            nonce: [0xCD; NONCE_LEN],
        }
    }

    fn sample_body() -> Body {
        Body {
            lamport: 42,
            timestamp_ms: 1_700_000_000_000,
            content_type: CONTENT_TEXT,
            payload: b"hello clipboard".to_vec(),
        }
    }

    #[test]
    fn header_round_trip() {
        let h = sample_header();
        let bytes = encode_header(&h);
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(&bytes[0..4], b"CCLP");
        assert_eq!(decode_header(&bytes).unwrap(), h);
    }

    #[test]
    fn body_round_trip() {
        let b = sample_body();
        let bytes = encode_body(&b);
        assert_eq!(decode_body(&bytes).unwrap(), b);
    }

    #[test]
    fn empty_payload_round_trip() {
        let b = Body {
            lamport: 0,
            timestamp_ms: 0,
            content_type: CONTENT_TEXT,
            payload: vec![],
        };
        let bytes = encode_body(&b);
        assert_eq!(bytes.len(), BODY_HEADER_LEN);
        assert_eq!(decode_body(&bytes).unwrap(), b);
    }

    #[test]
    fn decode_header_rejects_short() {
        assert_eq!(decode_header(&[0u8; 10]), Err(ProtoError::ShortHeader(10)));
    }

    #[test]
    fn decode_header_rejects_bad_magic() {
        let mut bytes = encode_header(&sample_header());
        bytes[0] = b'X';
        assert_eq!(decode_header(&bytes), Err(ProtoError::BadMagic));
    }

    #[test]
    fn decode_header_rejects_bad_version() {
        let mut bytes = encode_header(&sample_header());
        bytes[4] = 2;
        assert_eq!(
            decode_header(&bytes),
            Err(ProtoError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn decode_body_rejects_short() {
        assert_eq!(decode_body(&[0u8; 5]), Err(ProtoError::ShortBody(5)));
    }

    #[test]
    fn decode_body_rejects_inconsistent_payload_len() {
        let mut bytes = encode_body(&sample_body());
        // Claim a much larger payload than is present.
        bytes[17..21].copy_from_slice(&10_000u32.to_be_bytes());
        assert_eq!(
            decode_body(&bytes),
            Err(ProtoError::PayloadLenMismatch {
                declared: 10_000,
                available: 15
            })
        );
    }

    #[test]
    fn decode_body_rejects_invalid_utf8_for_text() {
        let b = Body {
            lamport: 1,
            timestamp_ms: 1,
            content_type: CONTENT_TEXT,
            payload: vec![0xFF, 0xFE, 0xFD],
        };
        let bytes = encode_body(&b);
        assert_eq!(decode_body(&bytes), Err(ProtoError::InvalidUtf8));
    }

    #[test]
    fn decode_body_allows_non_utf8_for_non_text() {
        let b = Body {
            lamport: 1,
            timestamp_ms: 1,
            content_type: CONTENT_IMAGE,
            payload: vec![0xFF, 0xFE, 0xFD],
        };
        let bytes = encode_body(&b);
        assert_eq!(decode_body(&bytes).unwrap(), b);
    }

    #[test]
    fn decode_body_allows_trailing_bytes() {
        // A datagram may carry extra bytes after the declared payload; the
        // declared payload_len is authoritative.
        let mut bytes = encode_body(&sample_body());
        bytes.extend_from_slice(b"trailing");
        let body = decode_body(&bytes).unwrap();
        assert_eq!(body.payload, b"hello clipboard");
    }

    #[test]
    fn fuzz_ish_never_panics() {
        // Deterministic pseudo-random malformed inputs must always yield Err.
        let mut state: u64 = 0x1234_5678_9abc_def0;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..10_000 {
            let len = (next() % 200) as usize;
            let mut bytes: Vec<u8> = (0..len).map(|_| (next() >> 33) as u8).collect();
            // Sometimes make the prefix look valid to exercise deeper paths.
            if next() % 4 == 0 && bytes.len() >= HEADER_LEN {
                bytes[0..4].copy_from_slice(&MAGIC);
                bytes[4] = VERSION;
            }
            let _ = decode_header(&bytes);
            let _ = decode_body(&bytes);
            let _ = decode_announce(&bytes);
        }
    }

    #[test]
    fn announce_round_trip() {
        let a = AnnouncePayload {
            inner_content_type: INNER_TEXT,
            transfer_id: [0xA5; 16],
            total_len: 5_000_000,
            sha256: [0x5A; 32],
            tcp_port: 47475,
        };
        let bytes = encode_announce(&a);
        assert_eq!(bytes.len(), ANNOUNCE_PAYLOAD_LEN);
        assert_eq!(bytes.len(), 59);
        assert_eq!(decode_announce(&bytes).unwrap(), a);
    }

    #[test]
    fn image_announce_round_trip() {
        for mime in SUPPORTED_IMAGE_MIMES {
            let a = ImageAnnouncePayload {
                transfer_id: [0xA5; 16],
                total_len: 2_400_000,
                sha256: [0x5A; 32],
                tcp_port: 47475,
                mime_type: mime.to_string(),
            };
            let bytes = encode_image_announce(&a);
            assert!(bytes.len() >= 60 && bytes.len() <= IMAGE_ANNOUNCE_MAX_LEN);
            assert_eq!(decode_image_announce(&bytes).unwrap(), a);
        }
    }

    #[test]
    fn image_announce_rejects_bad_length() {
        for len in [0, 1, 58, 59, 124, 200] {
            assert_eq!(
                decode_image_announce(&vec![0u8; len]),
                Err(ImageAnnounceError::BadLength(len)),
                "len {len}"
            );
        }
    }

    #[test]
    fn image_announce_rejects_wrong_inner() {
        let mut bytes = encode_image_announce(&ImageAnnouncePayload {
            transfer_id: [0u8; 16],
            total_len: 10,
            sha256: [0u8; 32],
            tcp_port: 47475,
            mime_type: "image/png".to_string(),
        });
        bytes[0] = INNER_TEXT;
        assert_eq!(
            decode_image_announce(&bytes),
            Err(ImageAnnounceError::BadInner(0x01))
        );
    }

    #[test]
    fn image_announce_rejects_trailing_bytes() {
        let mut bytes = encode_image_announce(&ImageAnnouncePayload {
            transfer_id: [0u8; 16],
            total_len: 10,
            sha256: [0u8; 32],
            tcp_port: 47475,
            mime_type: "image/png".to_string(),
        });
        bytes.push(0xFF);
        assert!(decode_image_announce(&bytes).is_err());
    }

    #[test]
    fn image_announce_rejects_unsupported_mime() {
        // image/gif is well-formed UTF-8 but not a supported sync type.
        let mut payload = encode_image_announce(&ImageAnnouncePayload {
            transfer_id: [0u8; 16],
            total_len: 10,
            sha256: [0u8; 32],
            tcp_port: 47475,
            mime_type: "image/png".to_string(),
        });
        let gif = b"image/gif";
        payload.truncate(59);
        payload.push(gif.len() as u8);
        payload.extend_from_slice(gif);
        assert_eq!(
            decode_image_announce(&payload),
            Err(ImageAnnounceError::UnsupportedMime("image/gif".to_string()))
        );
    }

    #[test]
    fn strict_announce_still_rejects_image_payload() {
        // Old-client behavior: the fixed 59-byte decoder ignores image
        // announces (wrong length), so text sync is undisturbed.
        let bytes = encode_image_announce(&ImageAnnouncePayload {
            transfer_id: [0u8; 16],
            total_len: 10,
            sha256: [0u8; 32],
            tcp_port: 47475,
            mime_type: "image/png".to_string(),
        });
        assert!(decode_announce(&bytes).is_err());
    }

    #[test]
    fn mime_allowlist() {
        assert!(is_supported_image_mime("image/png"));
        assert!(is_supported_image_mime("image/jpeg"));
        assert!(is_supported_image_mime("image/webp"));
        assert!(!is_supported_image_mime("image/gif"));
        assert!(!is_supported_image_mime("text/plain"));
        assert!(!is_supported_image_mime("IMAGE/PNG"));
    }

    #[test]
    fn announce_rejects_bad_length() {
        assert!(decode_announce(&[0u8; 58]).is_err());
        assert!(decode_announce(&[0u8; 60]).is_err());
        assert!(decode_announce(&[]).is_err());
        // Fuzz: no length other than 59 is accepted, never panics.
        for len in [0, 1, 21, 58, 60, 100, 200] {
            let v = vec![0u8; len];
            assert_eq!(
                decode_announce(&v),
                Err(AnnounceError::BadLength {
                    expected: ANNOUNCE_PAYLOAD_LEN,
                    got: len
                }),
                "len {len}"
            );
        }
    }
}
