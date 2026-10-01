# clipcast cross-implementation test vectors

These vectors are the contract between the Rust daemon and the Kotlin Android
client. They were produced by the Rust implementation (`clipcast` v0.1.0) and
are verified by `crypto::tests::test_vector_matches_documented_hex`.

## Vector 1: CLIP_UPDATE with text "Hello, clipcast!"

Fixed inputs:

| Field | Value |
|---|---|
| key (hex) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| key (base64) | `AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=` |
| device_id (hex) | `000102030405060708090a0b0c0d0e0f` |
| nonce (hex) | `000102030405060708090a0b` |
| lamport | `1234567890` |
| timestamp_ms | `1700000000000` |
| content_type | `0x01` (text/plain UTF-8) |
| payload | `Hello, clipcast!` (16 bytes, UTF-8) |

Header (34 bytes, hex):

```
43434c500101000102030405060708090a0b0c0d0e0f000102030405060708090a0b
```

Breakdown: magic `43434c50` ("CCLP"), version `01`, msg_type `01`,
device_id `000102030405060708090a0b0c0d0e0f`, nonce `000102030405060708090a0b`.

Expected plaintext body (21 + 16 = 37 bytes, hex) — for reference only; it is
sealed with AES-256-GCM under the nonce above and the header as AAD:

```
00000000499602d2 0000018c73c0c98d 01 00000010 48656c6c6f2c20636c69706361737421
```

(lamport, timestamp_ms, content_type, payload_len, "Hello, clipcast!")

Expected full datagram (87 bytes, hex):

```
43434c500101000102030405060708090a0b0c0d0e0f000102030405060708090a0b4702d61b8c73c0c98d4196007e0c106d82d68734e0333a105408c9a57e0569c26271dd888e5679466764a2bc9c4f767b639625c652
```

The datagram is `header (34) || ciphertext+tag (37 + 16 = 53) = 87` bytes.
The Rust test `crypto::tests::test_vector_matches_documented_hex` asserts
byte equality with the value above.

## Verification

```
cargo test test_vector_matches_documented_hex
```

The Android client should be able to:
1. Decode the header, check magic/version.
2. AES-256-GCM-decrypt the remainder with the key above, nonce from the
   header, AAD = the 34 header bytes.
3. Parse the body and recover lamport `1234567890`, timestamp
   `1700000000000`, content_type `0x01`, payload `Hello, clipcast!`.
