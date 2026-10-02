# clipcast cross-implementation test vectors: image sync

These vectors are the contract between the Rust daemon and the Kotlin
Android client for image clipboard sync. They were produced by the Rust
implementation and are verified by `tests/image_vectors.rs`. The v1 UDP
vectors still live in [`test-vectors.md`](test-vectors.md), the large-text
TCP vectors in [`test-vectors-v2.md`](test-vectors-v2.md); both are
unchanged. Images reuse the v2 TCP channel byte-for-byte — only the UDP
announce payload gains a MIME suffix.

## Fixed inputs

| Field | Value |
|---|---|
| shared key (hex) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| device_id (hex) | `202122232425262728292a2b2c2d2e2f` |
| UDP nonce (hex) | `e0e1e2e3e4e5e6e7e8e9eaeb` |
| transfer_id (hex) | `b0b1b2b3b4b5b6b7b8b9babbbcbdbebf` |
| lamport | `987654321` (`0x3ade68b1`) |
| timestamp_ms | `1700000000000` (`0x18bcfe56800`) |
| MIME type | `image/png` (9 bytes, UTF-8) |
| tcp_port | `47475` (`0xb973`) |
| TCP client_device_id (hex) | `303132333435363738393a3b3c3d3e3f` |
| TCP client_nonce (hex) | `d0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef` |

## Test image

A deterministic 1×1-pixel PNG (opaque red, 69 bytes — not a real photo):

```
89504e470d0a1a0a0000000d4948445200000001000000010802000000907753de0000000c4944415408d763f8cfc00000000300010005fed40000000049454e44ae426082
```

SHA-256 of the image bytes:

```
167a2b4b202a5c05e6fb5ac9f45b52d7bc5c5f8a0f94679362fd8a86912ee397
```

## 1. IMAGE_ANNOUNCE UDP payload (69 bytes, hex)

Same v1 framing (`content_type = 0x80` announce). The payload is the
59-byte base announce with `inner = 0x02`, followed by `mime_len u8` and
the MIME bytes — `inner(1) || transfer_id(16) || image_len u64(8) ||
sha256(32) || tcp_port u16(2) || mime_len(1) || mime`:

```
02b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000045167a2b4b202a5c05e6fb5ac9f45b52d7bc5c5f8a0f94679362fd8a86912ee397b97309696d6167652f706e67
```

Breakdown: inner `02` (image), transfer_id `b0..bf`, image_len
`0000000000000045` (69), sha256 as above, tcp_port `b973` (47475),
mime_len `09`, mime `image/png` in UTF-8.

## 2. UDP body plaintext (90 bytes, hex)

`lamport u64 || timestamp_ms u64 || content_type u8 || payload_len u32 ||
payload`:

```
000000003ade68b10000018bcfe56800800000004502b0b1b2b3b4b5b6b7b8b9babbbcbdbebf0000000000000045167a2b4b202a5c05e6fb5ac9f45b52d7bc5c5f8a0f94679362fd8a86912ee397b97309696d6167652f706e67
```

Breakdown: lamport `000000003ade68b1`, timestamp `0000018bcfe56800`,
content_type `80`, payload_len `00000045` (69), then the payload from §1.

## 3. UDP header (34 bytes, hex)

Cleartext, authenticated as AES-GCM AAD:

```
43434c500101202122232425262728292a2b2c2d2e2fe0e1e2e3e4e5e6e7e8e9eaeb
```

Breakdown: magic `43434c50` ("CCLP"), version `01`, msg_type `01`,
device_id `20..2f`, nonce `e0..eb`.

## 4. Sealed UDP datagram (34 + 90 + 16 = 140 bytes, hex)

`header || AES-256-GCM(key, nonce, aad = header, plaintext = body)`:

```
43434c500101202122232425262728292a2b2c2d2e2fe0e1e2e3e4e5e6e7e8e9eaeb34c2c983cf1ee29ac0037fc591f9908345a53be7bb867da92e32dec8ba869033e9595d4fc71af86031cea5b03b1f15fb4f19f06d41e6fd6b99704dfca0603671abb8e643ad67538b64042af5a96af97411cd8a5b9b52c7c208b1318b2f099155055c7ab27e12c9bb2a59
```

## 5. TCP request header (70 bytes, hex)

Identical framing to the large-text channel: magic `43434c54`
("CCLT"), version `01`, msg_type `01` (FETCH), client_device_id,
transfer_id, client_nonce:

```
43434c540101303132333435363738393a3b3c3d3e3fb0b1b2b3b4b5b6b7b8b9babbbcbdbebfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef
```

## 6. Derived session key (32 bytes, hex)

HKDF-SHA256 with IKM = shared key, salt = client_nonce,
info = ASCII `clipcast tcp v1` followed by the 16 transfer_id bytes
(unchanged from v2):

```
bbc21c6ef3429aee544715ec07e690b5aa507e443d6491a431b260a8b68b25a4
```

## 7. Handshake tag (16 bytes, hex)

AES-256-GCM of the empty plaintext, client nonce counter 0, AAD = the
70-byte header above:

```
8d44bb79dc2471ab93c9b0745a6cc9da
```

The client sends `header (70) || tag (16)` = 86 bytes to open a connection.

## 8. Image data frame (counter 0, FINAL, hex)

`len u32 (4) || ciphertext`. Plaintext = flags `01` (FINAL) followed by
the 69 image bytes; nonce = server direction counter 0, AAD = header.
The whole image fits in one frame, so the first frame carries FINAL:

```
000000565db649ebbc31786690ba9dc1eb582893d667c4f8859b069f707e41a4b770bea27eefb9b96a9e7cb0ca8275eab6e5fe99a5287365e2c0594edf3d80a073217af6984184dcb2ae9096d4032c0b08c3971e012d77b3be6b
```

`len = 0x56` (86) = 1 flag + 69 data + 16 tag.

## Verification

```
cargo test --test image_vectors
```

The Android client must be able to:

1. Open the sealed datagram, check `content_type == 0x80`, parse the
   image announce (inner `0x02`), and validate MIME + length.
2. Rebuild the request header, derive the session key with HKDF-SHA256,
   and verify the handshake tag.
3. Open the FINAL data frame, check the byte count against `image_len`,
   verify SHA-256, and only then apply the image to the clipboard.
