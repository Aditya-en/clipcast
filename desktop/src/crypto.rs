//! AES-256-GCM seal/open and key handling.
//!
//! The 32-byte shared key is distributed as base64 text. Nonces are 12 random
//! bytes from a CSPRNG, fresh per message.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key};
use rand::TryRng;
use rand::rngs::SysRng;
use sha2::{Digest, Sha256};

use crate::proto::{self, Body, HEADER_LEN, Header};

pub const KEY_LEN: usize = 32;
pub const DEVICE_ID_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

pub type KeyBytes = [u8; KEY_LEN];

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("AEAD open failed (bad magic/version, tag, or body)")]
    OpenFailed,
    #[error("invalid key length: {0}")]
    InvalidKeyLen(usize),
}

pub fn generate_key() -> KeyBytes {
    let mut key = [0u8; KEY_LEN];
    SysRng.try_fill_bytes(&mut key).expect("getrandom failed");
    key
}

pub fn generate_device_id() -> [u8; DEVICE_ID_LEN] {
    let mut id = [0u8; DEVICE_ID_LEN];
    SysRng.try_fill_bytes(&mut id).expect("getrandom failed");
    id
}

pub fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    SysRng.try_fill_bytes(&mut nonce).expect("getrandom failed");
    nonce
}

/// 16 random bytes identifying one large-text transfer (v2 announce).
pub fn generate_transfer_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    SysRng.try_fill_bytes(&mut id).expect("getrandom failed");
    id
}

/// Short non-cryptographic hash of content, used for echo suppression.
pub fn content_hash(text: &str) -> u64 {
    content_hash_bytes(text.as_bytes())
}

/// Byte-oriented variant for non-text content (e.g. image bytes): the
/// first 8 bytes of SHA-256, big-endian. Text and image hashes share one
/// suppression namespace, so an image that byte-matches a recent text (or
/// vice versa) still suppresses correctly.
pub fn content_hash_bytes(bytes: &[u8]) -> u64 {
    let digest = Sha256::digest(bytes);
    u64::from_be_bytes(digest[0..8].try_into().unwrap())
}

fn cipher(key: &KeyBytes) -> Aes256Gcm {
    let key = Key::<Aes256Gcm>::try_from(key.as_slice()).expect("key length is fixed");
    Aes256Gcm::new(&key)
}

fn nonce(nonce: &[u8; NONCE_LEN]) -> aes_gcm::aead::Nonce<Aes256Gcm> {
    aes_gcm::aead::Nonce::<Aes256Gcm>::try_from(nonce.as_slice()).expect("nonce length is fixed")
}

/// Seal a message: returns `header || ciphertext || tag` as one datagram.
pub fn seal(key: &KeyBytes, header: &Header, body: &Body) -> Vec<u8> {
    let header_bytes = proto::encode_header(header);
    let body_bytes = proto::encode_body(body);
    let ciphertext = cipher(key)
        .encrypt(
            &nonce(&header.nonce),
            Payload {
                msg: &body_bytes,
                aad: &header_bytes,
            },
        )
        .expect("AES-256-GCM encryption cannot fail for valid inputs");
    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&header_bytes);
    out.extend_from_slice(&ciphertext);
    out
}

/// Open a datagram: validates magic/version, verifies the AEAD tag over the
/// header as AAD, and decodes the body. Any failure yields [`CryptoError::OpenFailed`].
pub fn open(key: &KeyBytes, datagram: &[u8]) -> Result<(Header, Body), CryptoError> {
    let header = proto::decode_header(datagram).map_err(|_| CryptoError::OpenFailed)?;
    let header_bytes = proto::encode_header(&header);
    let ciphertext = &datagram[HEADER_LEN..];
    let body_bytes = cipher(key)
        .decrypt(
            &nonce(&header.nonce),
            Payload {
                msg: ciphertext,
                aad: &header_bytes,
            },
        )
        .map_err(|_| CryptoError::OpenFailed)?;
    let body = proto::decode_body(&body_bytes).map_err(|_| CryptoError::OpenFailed)?;
    Ok((header, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::{CONTENT_TEXT, MSG_CLIP_UPDATE};

    fn test_key() -> KeyBytes {
        [0x42; KEY_LEN]
    }

    fn test_header() -> Header {
        Header {
            version: proto::VERSION,
            msg_type: MSG_CLIP_UPDATE,
            device_id: [0x11; DEVICE_ID_LEN],
            nonce: [0x22; NONCE_LEN],
        }
    }

    fn test_body() -> Body {
        Body {
            lamport: 7,
            timestamp_ms: 123,
            content_type: CONTENT_TEXT,
            payload: b"round trip".to_vec(),
        }
    }

    #[test]
    fn seal_open_round_trip() {
        let key = test_key();
        let header = test_header();
        let body = test_body();
        let datagram = seal(&key, &header, &body);
        assert_eq!(datagram.len(), HEADER_LEN + 21 + 10 + 16);
        let (h, b) = open(&key, &datagram).unwrap();
        assert_eq!(h, header);
        assert_eq!(b, body);
    }

    #[test]
    fn open_rejects_wrong_key() {
        let datagram = seal(&test_key(), &test_header(), &test_body());
        let wrong = [0x99; KEY_LEN];
        assert_eq!(open(&wrong, &datagram), Err(CryptoError::OpenFailed));
    }

    #[test]
    fn open_rejects_truncated_datagram() {
        let key = test_key();
        let datagram = seal(&key, &test_header(), &test_body());
        for len in [0, 10, HEADER_LEN, HEADER_LEN + 20, datagram.len() - 1] {
            assert_eq!(
                open(&key, &datagram[..len]),
                Err(CryptoError::OpenFailed),
                "len {len}"
            );
        }
    }

    #[test]
    fn tampering_with_any_header_byte_fails() {
        let key = test_key();
        let header = test_header();
        let body = test_body();
        for index in 0..HEADER_LEN {
            let mut datagram = seal(&key, &header, &body);
            datagram[index] ^= 0x01;
            assert_eq!(
                open(&key, &datagram),
                Err(CryptoError::OpenFailed),
                "header byte {index}"
            );
        }
    }

    #[test]
    fn tampering_with_any_ciphertext_byte_fails() {
        let key = test_key();
        let header = test_header();
        let body = test_body();
        let datagram = seal(&key, &header, &body);
        for index in HEADER_LEN..datagram.len() {
            let mut broken = datagram.clone();
            broken[index] ^= 0x01;
            assert_eq!(
                open(&key, &broken),
                Err(CryptoError::OpenFailed),
                "ciphertext byte {index}"
            );
        }
    }

    #[test]
    fn tampering_with_magic_or_version_fails() {
        let key = test_key();
        let mut datagram = seal(&key, &test_header(), &test_body());
        datagram[0] = b'X';
        assert_eq!(open(&key, &datagram), Err(CryptoError::OpenFailed));
        let mut datagram = seal(&key, &test_header(), &test_body());
        datagram[4] = 99;
        assert_eq!(open(&key, &datagram), Err(CryptoError::OpenFailed));
    }

    #[test]
    fn seal_is_deterministic_for_fixed_header() {
        // seal() uses the nonce carried in the header; the caller (engine)
        // must supply a fresh nonce per message. Same inputs => same output,
        // which is what makes the documented test vectors reproducible.
        let key = test_key();
        let header = test_header();
        let body = test_body();
        let a = seal(&key, &header, &body);
        let b = seal(&key, &header, &body);
        assert_eq!(a, b);
    }

    #[test]
    fn content_hash_is_stable_and_distinguishes() {
        assert_eq!(content_hash("same"), content_hash("same"));
        assert_ne!(content_hash("a"), content_hash("b"));
    }
}

#[cfg(test)]
mod vector_tests {
    use super::*;
    use crate::proto::{CONTENT_TEXT, MSG_CLIP_UPDATE};

    /// The exact values documented in docs/test-vectors.md. The Android client
    /// uses this file; the Rust implementation must match it byte for byte.
    #[test]
    fn test_vector_matches_documented_hex() {
        let key: KeyBytes = (0u8..32).collect::<Vec<u8>>().try_into().unwrap();
        let header = Header {
            version: proto::VERSION,
            msg_type: MSG_CLIP_UPDATE,
            device_id: (0u8..16).collect::<Vec<u8>>().try_into().unwrap(),
            nonce: (0u8..12).collect::<Vec<u8>>().try_into().unwrap(),
        };
        let body = Body {
            lamport: 1_234_567_890,
            timestamp_ms: 1_700_000_000_000,
            content_type: CONTENT_TEXT,
            payload: b"Hello, clipcast!".to_vec(),
        };
        let datagram = seal(&key, &header, &body);
        let expected = "43434c500101000102030405060708090a0b0c0d0e0f000102030405060708090a0b4702d61b8c73c0c98d4196007e0c106d82d68734e0333a105408c9a57e0569c26271dd888e5679466764a2bc9c4f767b639625c652";
        let actual: String = datagram.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(actual, expected);
        assert_eq!(datagram.len(), 87);

        // And it opens back to the documented fields.
        let (h, b) = open(&key, &datagram).unwrap();
        assert_eq!(h.device_id, header.device_id);
        assert_eq!(h.nonce, header.nonce);
        assert_eq!(b.lamport, 1_234_567_890);
        assert_eq!(b.timestamp_ms, 1_700_000_000_000);
        assert_eq!(b.content_type, CONTENT_TEXT);
        assert_eq!(b.payload, b"Hello, clipcast!");
    }
}
