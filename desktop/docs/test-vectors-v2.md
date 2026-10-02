# clipcast cross-implementation test vectors, v2 (large-text TCP side channel)

These vectors are the contract between the Rust daemon and the Kotlin Android
client for the v2 TCP fetch protocol. They were produced by the Rust
implementation and are verified by
`tcp::tests::test_vectors_match_documented_hex`. The v1 UDP vectors still
live in [`test-vectors.md`](test-vectors.md) and are unchanged.

## Fixed inputs

| Field | Value |
|---|---|
| shared key (hex) | `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f` |
| client_device_id (hex) | `101112131415161718191a1b1c1d1e1f` |
| transfer_id (hex) | `a0a1a2a3a4a5a6a7a8a9aaabacadaeaf` |
| client_nonce (hex) | `c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf` |
| payload | `Hello, TCP!` (11 bytes, UTF-8) |
| tcp_port | `47475` (`0xb973`) |

SHA-256 of the payload:

```
b36a2ee430d07013c9c7ef342543b572c2ef92669d488fb12f73a3d101435205
```

## 1. UDP announce payload (59 bytes, hex)

`content_type = 0x80` datagram body layout is unchanged v1 framing; the
payload is `inner_content_type(1) || transfer_id(16) || total_len u64(8) ||
sha256(32) || tcp_port u16(2)`:

```
01a0a1a2a3a4a5a6a7a8a9aaabacadaeaf000000000000000bb36a2ee430d07013c9c7ef342543b572c2ef92669d488fb12f73a3d101435205b973
```

Breakdown: inner `01` (text/plain UTF-8), transfer_id `a0..af`,
total_len `000000000000000b` (11), sha256 as above, tcp_port `b973` (47475).

## 2. TCP request header (70 bytes, hex)

magic `43434c54` ("CCLT"), version `01`, msg_type `01` (FETCH),
client_device_id `1011..1f`, transfer_id `a0..af`, client_nonce `c0..df`:

```
43434c540101101112131415161718191a1b1c1d1e1fa0a1a2a3a4a5a6a7a8a9aaabacadaeafc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf
```

## 3. Derived session key (32 bytes, hex)

HKDF-SHA256 with IKM = shared key, salt = client_nonce,
info = ASCII `clipcast tcp v1` followed by the 16 transfer_id bytes:

```
cf6b9ebc804d61664134e76523191238880695fac7ba90bd1a335c15426fdbf2
```

## 4. Handshake tag (16 bytes, hex)

AES-256-GCM of the empty plaintext, nonce = `00 000000 counter(0)`,
AAD = the 70-byte header above:

```
e8841cef663f999d1af67e72d89da38d
```

The client sends `header (70) || tag (16)` = 86 bytes to open a connection.

## 5. First server data frame (counter 0, FINAL, hex)

`len u32 (4) || ciphertext`. Plaintext = flags `01` (FINAL) followed by
the 11 payload bytes; nonce = `01 000000 counter(0)`, AAD = header:

```
0000001c54623749f5569e27af8f598c61e0be85e0e311e42e20271f489f757b
```

`len = 0x1c` (28) = 1 flag + 11 data + 16 tag. The 11-byte payload fits in
one frame, so the first frame already carries FINAL.

## 6. Empty FINAL frame (counter 1, hex)

Sent after an exact multiple of 65536 data bytes (or whenever a transfer
ends on a chunk boundary): flags `01`, zero data bytes, nonce counter 1,
same session key and AAD:

```
000000110655f730879b22e1c9305ece6894f4383f
```

`len = 0x11` (17) = 1 flag + 0 data + 16 tag.

## Verification

```
cargo test test_vectors_match_documented_hex
```

The Android client should be able to:

1. Parse the announce payload, check `inner_content_type == 0x01`.
2. Rebuild the request header, derive the session key with HKDF-SHA256
   (salt = client_nonce, info = `clipcast tcp v1` + transfer_id).
3. Seal/verify the handshake tag (empty plaintext, client nonce counter 0).
4. Seal/open data frames (flags + data, server nonce counters 0, 1, ...).
