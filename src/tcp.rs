//! Large-text side channel (v2): TCP fetch protocol.
//!
//! Contract shared with the Kotlin Android client. All integers big-endian.
//! This module holds the pure protocol pieces (header encode/decode, session
//! key derivation, frame seal/open, reassembly rules). Socket I/O lives in
//! [`serve`] / [`fetch`] helpers added alongside the store and client.
//!
//! Request header (70 bytes, sent in the clear, used as AEAD AAD):
//! - magic: 4 bytes ASCII "CCLT"
//! - version: u8 = 1
//! - msg_type: u8 = 0x01 (FETCH)
//! - client_device_id: 16 bytes
//! - transfer_id: 16 bytes
//! - client_nonce: 32 random bytes
//!
//! Session key (32 bytes): HKDF-SHA256 (RFC 5869) with IKM = the shared
//! 32-byte clipcast key, salt = client_nonce,
//! info = ASCII "clipcast tcp v1" followed by the 16 transfer_id bytes.
//!
//! AEAD nonces (12 bytes): byte 0 = direction (0x00 client-to-server,
//! 0x01 server-to-client), bytes 1..3 = zero, bytes 4..11 = u64 frame
//! counter big-endian, starting at 0 for each direction. Each connection
//! has its own session key, so nonce reuse across connections is impossible.
//! AAD for every sealed frame in both directions = the 70-byte header.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key};
use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

pub const TCP_MAGIC: [u8; 4] = *b"CCLT";
pub const TCP_VERSION: u8 = 1;
pub const TCP_MSG_FETCH: u8 = 0x01;
pub const REQUEST_HEADER_LEN: usize = 70;
pub const CLIENT_NONCE_LEN: usize = 32;
pub const TRANSFER_ID_LEN: usize = 16;
pub const SESSION_KEY_LEN: usize = 32;
pub const TAG_LEN: usize = 16;

/// Max plaintext data bytes per server data frame.
pub const MAX_FRAME_DATA: usize = 65536;
/// flags(1) + data(<=65536) + tag(16): largest accepted ciphertext length.
pub const MAX_FRAME_CIPHERTEXT: usize = 1 + MAX_FRAME_DATA + TAG_LEN;
/// flags byte bit 0 = FINAL (last frame). All other bits must be zero.
pub const FLAG_FINAL: u8 = 0x01;

pub const DIR_CLIENT_TO_SERVER: u8 = 0x00;
pub const DIR_SERVER_TO_CLIENT: u8 = 0x01;

/// Info prefix for the HKDF expand step (followed by the 16 transfer_id bytes).
pub const HKDF_INFO_PREFIX: &[u8] = b"clipcast tcp v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestHeader {
    pub client_device_id: [u8; 16],
    pub transfer_id: [u8; 16],
    pub client_nonce: [u8; CLIENT_NONCE_LEN],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TcpError {
    #[error("request header must be {expected} bytes, got {got}")]
    BadHeaderLength { expected: usize, got: usize },
    #[error("bad TCP magic")]
    BadMagic,
    #[error("unsupported TCP version: {0}")]
    UnsupportedVersion(u8),
    #[error("unexpected TCP msg_type: {0:#04x}")]
    UnexpectedMsgType(u8),
    #[error("AEAD open failed")]
    OpenFailed,
    #[error("ciphertext length {0} exceeds maximum {MAX_FRAME_CIPHERTEXT}")]
    FrameTooLong(usize),
    #[error("frame plaintext too short for flags byte")]
    FrameTooShort,
    #[error("frame flags have reserved bits set: {0:#04x}")]
    BadFlags(u8),
    #[error("handshake tag verification failed")]
    BadHandshake,
    #[error("non-final frame must carry exactly {MAX_FRAME_DATA} data bytes, got {0}")]
    ShortNonFinalFrame(usize),
    #[error("data after FINAL frame")]
    DataAfterFinal,
    #[error("missing FINAL frame")]
    MissingFinal,
    #[error("byte count {got} != announced total_len {want}")]
    LengthMismatch { got: u64, want: u64 },
    #[error("SHA-256 mismatch")]
    HashMismatch,
    #[error("invalid UTF-8 for text content")]
    InvalidUtf8,
    #[error("HKDF expand failed")]
    HkdfFailed,
}

pub fn encode_request_header(h: &RequestHeader) -> [u8; REQUEST_HEADER_LEN] {
    let mut buf = [0u8; REQUEST_HEADER_LEN];
    buf[0..4].copy_from_slice(&TCP_MAGIC);
    buf[4] = TCP_VERSION;
    buf[5] = TCP_MSG_FETCH;
    buf[6..22].copy_from_slice(&h.client_device_id);
    buf[22..38].copy_from_slice(&h.transfer_id);
    buf[38..70].copy_from_slice(&h.client_nonce);
    buf
}

pub fn decode_request_header(bytes: &[u8]) -> Result<RequestHeader, TcpError> {
    if bytes.len() != REQUEST_HEADER_LEN {
        return Err(TcpError::BadHeaderLength {
            expected: REQUEST_HEADER_LEN,
            got: bytes.len(),
        });
    }
    if bytes[0..4] != TCP_MAGIC {
        return Err(TcpError::BadMagic);
    }
    if bytes[4] != TCP_VERSION {
        return Err(TcpError::UnsupportedVersion(bytes[4]));
    }
    if bytes[5] != TCP_MSG_FETCH {
        return Err(TcpError::UnexpectedMsgType(bytes[5]));
    }
    let mut client_device_id = [0u8; 16];
    client_device_id.copy_from_slice(&bytes[6..22]);
    let mut transfer_id = [0u8; 16];
    transfer_id.copy_from_slice(&bytes[22..38]);
    let mut client_nonce = [0u8; CLIENT_NONCE_LEN];
    client_nonce.copy_from_slice(&bytes[38..70]);
    Ok(RequestHeader {
        client_device_id,
        transfer_id,
        client_nonce,
    })
}

/// RFC 5869 HKDF-SHA256: IKM = shared key, salt = client_nonce,
/// info = "clipcast tcp v1" || transfer_id, output 32 bytes.
pub fn derive_session_key(
    shared_key: &[u8; 32],
    client_nonce: &[u8; CLIENT_NONCE_LEN],
    transfer_id: &[u8; TRANSFER_ID_LEN],
) -> Result<[u8; SESSION_KEY_LEN], TcpError> {
    let hk = Hkdf::<Sha256>::new(Some(client_nonce), shared_key);
    let mut info = Vec::with_capacity(HKDF_INFO_PREFIX.len() + TRANSFER_ID_LEN);
    info.extend_from_slice(HKDF_INFO_PREFIX);
    info.extend_from_slice(transfer_id);
    let mut okm = [0u8; SESSION_KEY_LEN];
    hk.expand(&info, &mut okm)
        .map_err(|_| TcpError::HkdfFailed)?;
    Ok(okm)
}

/// 12-byte AEAD nonce: direction || 0x000000 || counter (big-endian u64).
pub fn frame_nonce(direction: u8, counter: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0] = direction;
    n[4..12].copy_from_slice(&counter.to_be_bytes());
    n
}

fn session_cipher(key: &[u8; SESSION_KEY_LEN]) -> Aes256Gcm {
    let key = Key::<Aes256Gcm>::try_from(key.as_slice()).expect("session key is 32 bytes");
    Aes256Gcm::new(&key)
}

/// Seal one frame plaintext (flags || data) under the session key.
/// Returns the raw ciphertext including the 16-byte tag (no length prefix).
pub fn seal_frame(
    session_key: &[u8; SESSION_KEY_LEN],
    aad_header: &[u8; REQUEST_HEADER_LEN],
    direction: u8,
    counter: u64,
    flags: u8,
    data: &[u8],
) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(1 + data.len());
    plaintext.push(flags);
    plaintext.extend_from_slice(data);
    let nonce =
        aes_gcm::aead::Nonce::<Aes256Gcm>::try_from(frame_nonce(direction, counter).as_slice())
            .expect("nonce length is fixed");
    session_cipher(session_key)
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: aad_header,
            },
        )
        .expect("AES-256-GCM encryption cannot fail for valid inputs")
}

/// Open one server/client data frame. Checks the length bound, the AEAD tag,
/// and that no reserved flag bits are set.
pub fn open_frame(
    session_key: &[u8; SESSION_KEY_LEN],
    aad_header: &[u8; REQUEST_HEADER_LEN],
    direction: u8,
    counter: u64,
    ciphertext: &[u8],
) -> Result<(u8, Vec<u8>), TcpError> {
    if ciphertext.len() > MAX_FRAME_CIPHERTEXT {
        return Err(TcpError::FrameTooLong(ciphertext.len()));
    }
    let nonce =
        aes_gcm::aead::Nonce::<Aes256Gcm>::try_from(frame_nonce(direction, counter).as_slice())
            .expect("nonce length is fixed");
    let plaintext = session_cipher(session_key)
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: aad_header,
            },
        )
        .map_err(|_| TcpError::OpenFailed)?;
    if plaintext.is_empty() {
        return Err(TcpError::FrameTooShort);
    }
    let flags = plaintext[0];
    if flags & !FLAG_FINAL != 0 {
        return Err(TcpError::BadFlags(flags));
    }
    Ok((flags, plaintext[1..].to_vec()))
}

/// Client handshake: AES-256-GCM of the empty plaintext, direction
/// client-to-server, counter 0 — exactly a 16-byte tag, no length prefix.
pub fn seal_handshake(
    session_key: &[u8; SESSION_KEY_LEN],
    aad_header: &[u8; REQUEST_HEADER_LEN],
) -> [u8; TAG_LEN] {
    // The handshake seals the *empty* plaintext (no flags byte on the wire),
    // so the output is exactly the 16-byte tag.
    let empty_nonce = aes_gcm::aead::Nonce::<Aes256Gcm>::try_from(
        frame_nonce(DIR_CLIENT_TO_SERVER, 0).as_slice(),
    )
    .expect("nonce length is fixed");
    let empty_tag = session_cipher(session_key)
        .encrypt(
            &empty_nonce,
            Payload {
                msg: &[],
                aad: aad_header,
            },
        )
        .expect("handshake seal cannot fail");
    debug_assert_eq!(empty_tag.len(), TAG_LEN);
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&empty_tag);
    out
}

/// Verify the client handshake tag (constant shape: exactly 16 bytes).
pub fn verify_handshake(
    session_key: &[u8; SESSION_KEY_LEN],
    aad_header: &[u8; REQUEST_HEADER_LEN],
    tag: &[u8],
) -> Result<(), TcpError> {
    if tag.len() != TAG_LEN {
        return Err(TcpError::BadHandshake);
    }
    let nonce = aes_gcm::aead::Nonce::<Aes256Gcm>::try_from(
        frame_nonce(DIR_CLIENT_TO_SERVER, 0).as_slice(),
    )
    .expect("nonce length is fixed");
    session_cipher(session_key)
        .decrypt(
            &nonce,
            Payload {
                msg: tag,
                aad: aad_header,
            },
        )
        .map_err(|_| TcpError::BadHandshake)?;
    Ok(())
}

/// Incremental reassembly of server data frames on the client.
/// Enforces: counters increase by one per frame, non-final frames carry
/// exactly [`MAX_FRAME_DATA`] bytes, exactly one FINAL frame, nothing after
/// it, and total data bytes == total_len.
pub struct FrameAssembler {
    total_len: u64,
    buf: Vec<u8>,
    next_counter: u64,
    got_final: bool,
}

impl FrameAssembler {
    pub fn new(total_len: u64) -> Self {
        Self {
            total_len,
            buf: Vec::new(),
            next_counter: 0,
            got_final: false,
        }
    }

    /// Feed one opened frame. Returns `true` when the FINAL frame arrived
    /// (the stream is complete; call [`finish`](Self::finish) to validate).
    pub fn feed(&mut self, flags: u8, data: &[u8], counter: u64) -> Result<bool, TcpError> {
        if self.got_final {
            return Err(TcpError::DataAfterFinal);
        }
        if flags & !FLAG_FINAL != 0 {
            return Err(TcpError::BadFlags(flags));
        }
        let final_frame = flags & FLAG_FINAL != 0;
        if !final_frame && data.len() != MAX_FRAME_DATA {
            return Err(TcpError::ShortNonFinalFrame(data.len()));
        }
        let _ = counter; // counters are enforced by the AEAD nonce in `open_frame`
        let new_total = self.buf.len() as u64 + data.len() as u64;
        if new_total > self.total_len {
            return Err(TcpError::LengthMismatch {
                got: new_total,
                want: self.total_len,
            });
        }
        self.buf.extend_from_slice(data);
        self.next_counter += 1;
        if final_frame {
            if self.buf.len() as u64 != self.total_len {
                return Err(TcpError::LengthMismatch {
                    got: self.buf.len() as u64,
                    want: self.total_len,
                });
            }
            self.got_final = true;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn finish(self) -> Result<Vec<u8>, TcpError> {
        if !self.got_final {
            return Err(TcpError::MissingFinal);
        }
        Ok(self.buf)
    }
}

/// Final content checks after all frames arrived: exact length, SHA-256
/// match, and valid UTF-8 for inner type 0x01 (text).
pub fn verify_content(
    data: &[u8],
    total_len: u64,
    expected_sha256: &[u8; 32],
    inner_content_type: u8,
) -> Result<(), TcpError> {
    if data.len() as u64 != total_len {
        return Err(TcpError::LengthMismatch {
            got: data.len() as u64,
            want: total_len,
        });
    }
    if sha256(data) != *expected_sha256 {
        return Err(TcpError::HashMismatch);
    }
    if inner_content_type == crate::proto::INNER_TEXT && std::str::from_utf8(data).is_err() {
        return Err(TcpError::InvalidUtf8);
    }
    Ok(())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0x42; 32]
    }

    fn test_header() -> ([u8; REQUEST_HEADER_LEN], RequestHeader) {
        let h = RequestHeader {
            client_device_id: [0x11; 16],
            transfer_id: [0x22; 16],
            client_nonce: [0x33; CLIENT_NONCE_LEN],
        };
        (encode_request_header(&h), h)
    }

    #[test]
    fn header_round_trip() {
        let (bytes, h) = test_header();
        assert_eq!(bytes.len(), REQUEST_HEADER_LEN);
        assert_eq!(&bytes[0..4], b"CCLT");
        assert_eq!(decode_request_header(&bytes).unwrap(), h);
    }

    #[test]
    fn header_rejects_malformed() {
        let (mut bytes, _) = test_header();
        assert_eq!(
            decode_request_header(&bytes[..69]),
            Err(TcpError::BadHeaderLength {
                expected: 70,
                got: 69
            })
        );
        bytes[0] = b'X';
        assert_eq!(decode_request_header(&bytes), Err(TcpError::BadMagic));
        let (mut bytes, _) = test_header();
        bytes[4] = 2;
        assert_eq!(
            decode_request_header(&bytes),
            Err(TcpError::UnsupportedVersion(2))
        );
        let (mut bytes, _) = test_header();
        bytes[5] = 0x02;
        assert_eq!(
            decode_request_header(&bytes),
            Err(TcpError::UnexpectedMsgType(0x02))
        );
    }

    #[test]
    fn hkdf_matches_rfc5869_test_case_1() {
        // RFC 5869 Appendix A, Test Case 1 (SHA-256).
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let info = [0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &ikm);
        let mut okm = [0u8; 42];
        hk.expand(&info, &mut okm).unwrap();
        let expected: [u8; 42] = [
            0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
            0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
            0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
        ];
        assert_eq!(okm, expected);
    }

    #[test]
    fn frame_seal_open_round_trip() {
        let (aad, _) = test_header();
        let key = derive_session_key(&test_key(), &[0x33; 32], &[0x22; 16]).unwrap();
        let data = b"frame payload";
        let ct = seal_frame(&key, &aad, DIR_SERVER_TO_CLIENT, 7, 0, data);
        let (flags, out) = open_frame(&key, &aad, DIR_SERVER_TO_CLIENT, 7, &ct).unwrap();
        assert_eq!(flags, 0);
        assert_eq!(out, data);
        let ct_final = seal_frame(&key, &aad, DIR_SERVER_TO_CLIENT, 8, FLAG_FINAL, b"end");
        let (flags, out) = open_frame(&key, &aad, DIR_SERVER_TO_CLIENT, 8, &ct_final).unwrap();
        assert_eq!(flags, FLAG_FINAL);
        assert_eq!(out, b"end");
    }

    #[test]
    fn frame_tampering_fails() {
        let (aad, _) = test_header();
        let key = derive_session_key(&test_key(), &[0x33; 32], &[0x22; 16]).unwrap();
        let ct = seal_frame(&key, &aad, DIR_SERVER_TO_CLIENT, 0, 0, b"secret data");
        // Tampered ciphertext byte.
        let mut broken = ct.clone();
        broken[2] ^= 0x01;
        assert_eq!(
            open_frame(&key, &aad, DIR_SERVER_TO_CLIENT, 0, &broken),
            Err(TcpError::OpenFailed)
        );
        // Tampered AAD (header) byte.
        let mut bad_aad = aad;
        bad_aad[10] ^= 0x01;
        assert_eq!(
            open_frame(&key, &bad_aad, DIR_SERVER_TO_CLIENT, 0, &ct),
            Err(TcpError::OpenFailed)
        );
        // Wrong counter: the nonce differs, so the tag fails.
        assert_eq!(
            open_frame(&key, &aad, DIR_SERVER_TO_CLIENT, 1, &ct),
            Err(TcpError::OpenFailed)
        );
        // Wrong direction likewise fails.
        assert_eq!(
            open_frame(&key, &aad, DIR_CLIENT_TO_SERVER, 0, &ct),
            Err(TcpError::OpenFailed)
        );
        // Reserved flag bits set: seal manually with bad flags, open rejects.
        let bad = seal_frame(&key, &aad, DIR_SERVER_TO_CLIENT, 3, 0x02, b"x");
        assert_eq!(
            open_frame(&key, &aad, DIR_SERVER_TO_CLIENT, 3, &bad),
            Err(TcpError::BadFlags(0x02))
        );
        // Over-long ciphertext rejected without allocating.
        let huge = vec![0u8; MAX_FRAME_CIPHERTEXT + 1];
        assert_eq!(
            open_frame(&key, &aad, DIR_SERVER_TO_CLIENT, 0, &huge),
            Err(TcpError::FrameTooLong(huge.len()))
        );
    }

    #[test]
    fn handshake_round_trip_and_tamper() {
        let (aad, _) = test_header();
        let key = derive_session_key(&test_key(), &[0x33; 32], &[0x22; 16]).unwrap();
        let tag = seal_handshake(&key, &aad);
        assert_eq!(tag.len(), TAG_LEN);
        verify_handshake(&key, &aad, &tag).unwrap();
        let mut bad = tag;
        bad[0] ^= 0x01;
        assert_eq!(
            verify_handshake(&key, &aad, &bad),
            Err(TcpError::BadHandshake)
        );
        // Tampered header fails too.
        let mut bad_aad = aad;
        bad_aad[40] ^= 0x01;
        assert_eq!(
            verify_handshake(&key, &bad_aad, &tag),
            Err(TcpError::BadHandshake)
        );
        // Wrong length fails.
        assert_eq!(
            verify_handshake(&key, &aad, &tag[..15]),
            Err(TcpError::BadHandshake)
        );
    }

    #[test]
    fn assembler_happy_path_single_final_frame() {
        let data = b"Hello, TCP!";
        let mut asm = FrameAssembler::new(data.len() as u64);
        assert!(asm.feed(FLAG_FINAL, data, 0).unwrap());
        assert_eq!(asm.finish().unwrap(), data);
    }

    #[test]
    fn assembler_rejects_truncated_missing_final_and_extras() {
        // Missing FINAL: stream ends without the flag.
        let mut asm = FrameAssembler::new(MAX_FRAME_DATA as u64 + 3);
        assert!(!asm.feed(0, &vec![7u8; MAX_FRAME_DATA], 0).unwrap());
        assert_eq!(asm.finish(), Err(TcpError::MissingFinal));
        // Short non-final frame rejected.
        let mut asm = FrameAssembler::new(10);
        assert_eq!(
            asm.feed(0, b"short", 0),
            Err(TcpError::ShortNonFinalFrame(5))
        );
        // Data after FINAL rejected.
        let mut asm = FrameAssembler::new(3);
        assert!(asm.feed(FLAG_FINAL, b"abc", 0).unwrap());
        assert_eq!(asm.feed(FLAG_FINAL, b"", 1), Err(TcpError::DataAfterFinal));
        // Final with wrong total length rejected.
        let mut asm = FrameAssembler::new(10);
        assert_eq!(
            asm.feed(FLAG_FINAL, b"abc", 0),
            Err(TcpError::LengthMismatch { got: 3, want: 10 })
        );
        // Overflow beyond total_len rejected.
        let mut asm = FrameAssembler::new(5);
        assert_eq!(
            asm.feed(FLAG_FINAL, b"toolong!", 0),
            Err(TcpError::LengthMismatch { got: 8, want: 5 })
        );
    }

    #[test]
    fn verify_content_checks() {
        let data = b"hello";
        let sha = sha256(data);
        verify_content(data, 5, &sha, crate::proto::INNER_TEXT).unwrap();
        assert_eq!(
            verify_content(data, 6, &sha, crate::proto::INNER_TEXT),
            Err(TcpError::LengthMismatch { got: 5, want: 6 })
        );
        assert_eq!(
            verify_content(data, 5, &[0u8; 32], crate::proto::INNER_TEXT),
            Err(TcpError::HashMismatch)
        );
        let bad_utf8 = &[0xFF, 0xFE];
        let sha_bad = sha256(bad_utf8);
        assert_eq!(
            verify_content(bad_utf8, 2, &sha_bad, crate::proto::INNER_TEXT),
            Err(TcpError::InvalidUtf8)
        );
        // Non-text inner types skip the UTF-8 check (reserved for later).
        verify_content(bad_utf8, 2, &sha_bad, 0x02).unwrap();
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The exact values documented in docs/test-vectors-v2.md. The Android
    /// client implements against that file; the Rust code must match it byte
    /// for byte.
    #[test]
    fn test_vectors_match_documented_hex() {
        use crate::proto::{ANNOUNCE_PAYLOAD_LEN, INNER_TEXT, decode_announce, encode_announce};

        let key: [u8; 32] = (0u8..32).collect::<Vec<u8>>().try_into().unwrap();
        let client_device_id: [u8; 16] = (0x10u8..0x20).collect::<Vec<u8>>().try_into().unwrap();
        let transfer_id: [u8; 16] = (0xa0u8..0xb0).collect::<Vec<u8>>().try_into().unwrap();
        let client_nonce: [u8; 32] = (0xc0u8..0xe0).collect::<Vec<u8>>().try_into().unwrap();
        let payload = b"Hello, TCP!";
        let sha = sha256(payload);

        // Announce payload.
        let announce = crate::proto::AnnouncePayload {
            inner_content_type: INNER_TEXT,
            transfer_id,
            total_len: payload.len() as u64,
            sha256: sha,
            tcp_port: 47475,
        };
        let announce_bytes = encode_announce(&announce);
        assert_eq!(announce_bytes.len(), ANNOUNCE_PAYLOAD_LEN);
        assert_eq!(
            hex_bytes(
                "01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000000000000bb36a2ee430d07013c9c7ef342543b572c2ef92669d488fb12f73a3d101435205b973"
            ),
            announce_bytes.to_vec()
        );
        assert_eq!(decode_announce(&announce_bytes).unwrap(), announce);

        // Request header.
        let header = RequestHeader {
            client_device_id,
            transfer_id,
            client_nonce,
        };
        let header_bytes = encode_request_header(&header);
        assert_eq!(
            hex_bytes(
                "43434c540101101112131415161718191a1b1c1d1e1fa0a1a2a3a4a5a6a7a8a9aaabacadaeafc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
            ),
            header_bytes.to_vec()
        );
        assert_eq!(decode_request_header(&header_bytes).unwrap(), header);

        // Session key.
        let session_key = derive_session_key(&key, &client_nonce, &transfer_id).unwrap();
        assert_eq!(
            hex_bytes("cf6b9ebc804d61664134e76523191238880695fac7ba90bd1a335c15426fdbf2"),
            session_key.to_vec()
        );

        // Handshake tag.
        let tag = seal_handshake(&session_key, &header_bytes);
        assert_eq!(hex_bytes("e8841cef663f999d1af67e72d89da38d"), tag.to_vec());
        verify_handshake(&session_key, &header_bytes, &tag).unwrap();

        // First server data frame (counter 0, FINAL since the payload fits).
        let ct = seal_frame(
            &session_key,
            &header_bytes,
            DIR_SERVER_TO_CLIENT,
            0,
            FLAG_FINAL,
            payload,
        );
        let mut frame = (ct.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(&ct);
        assert_eq!(
            hex_bytes("0000001c54623749f5569e27af8f598c61e0be85e0e311e42e20271f489f757b"),
            frame
        );
        let len = u32::from_be_bytes(frame[0..4].try_into().unwrap()) as usize;
        let (flags, data) = open_frame(
            &session_key,
            &header_bytes,
            DIR_SERVER_TO_CLIENT,
            0,
            &frame[4..4 + len],
        )
        .unwrap();
        assert_eq!(flags, FLAG_FINAL);
        assert_eq!(data, payload);

        // Empty FINAL frame (counter 1, exact-multiple boundary case).
        let ct1 = seal_frame(
            &session_key,
            &header_bytes,
            DIR_SERVER_TO_CLIENT,
            1,
            FLAG_FINAL,
            b"",
        );
        let mut frame1 = (ct1.len() as u32).to_be_bytes().to_vec();
        frame1.extend_from_slice(&ct1);
        assert_eq!(
            hex_bytes("000000110655f730879b22e1c9305ece6894f4383f"),
            frame1
        );
    }
}
