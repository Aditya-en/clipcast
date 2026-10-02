# Clipcast wire protocol (v1 + TCP side channel + image sync)

This document is the source of truth for both implementations (Rust
`desktop/`, Kotlin `android/`). All integers are big-endian. One UDP
datagram carries exactly one message. Deterministic byte vectors live in
[`test-vectors.md`](test-vectors.md) (v1 text),
[`test-vectors-v2.md`](test-vectors-v2.md) (large-text TCP), and
[`test-vectors-image.md`](test-vectors-image.md) (image sync).

Protocol version stays **1**. Images are an additive extension: old clients
ignore image announces (wrong payload length) and never see image bytes.

## 0. Notation

`u8/u16/u32/u64` = unsigned big-endian. `||` = concatenation.
`AES-GCM(key, nonce, aad, plaintext)` = AES-256-GCM, 12-byte nonce,
16-byte tag appended to the ciphertext.

The pre-shared key is 32 random bytes, shared out of band (base64 file on
desktop, pasted string on Android).

## 1. UDP datagram

### 1.1 Header (34 bytes, cleartext, AEAD AAD)

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `43 43 4c 50` ("CCLP") |
| 4 | 1 | version | `01` |
| 5 | 1 | msg_type | `01` = CLIP_UPDATE (others: ignore datagram) |
| 6 | 16 | device_id | random per install, stable |
| 22 | 12 | nonce | fresh CSPRNG bytes per datagram |

### 1.2 Body plaintext (sealed; AAD = the 34 header bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | lamport `u64` (ordering — §4) |
| 8 | 8 | timestamp_ms `u64` (informational only, never ordering) |
| 16 | 1 | content_type `u8` |
| 17 | 4 | payload_len `u32` (authoritative; trailing bytes ignored) |
| 21 | payload_len | payload |

`content_type`: `0x01` = text (payload is UTF-8, max 1200 bytes inline),
`0x80` = announce (payload is §2 or §3). Anything else: ignore the
datagram. `payload_len > available`: drop. Text with invalid UTF-8: drop.

## 2. Text announce payload (59 bytes)

For text larger than the inline limit (up to 64 MiB):

`inner(1) || transfer_id(16) || total_len u64(8) || sha256(32) ||
tcp_port u16(2)`, with `inner = 0x01` (UTF-8 text).

## 3. Image announce payload (60..123 bytes)

For images (up to 16 MiB default): the 59-byte base announce with
`inner = 0x02`, followed by a MIME suffix:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | inner = `0x02` (image) |
| 1 | 16 | transfer_id (16 random bytes, hex filename in sender cache) |
| 17 | 8 | image_len `u64` (exact byte count to be transferred) |
| 25 | 32 | sha256 of the exact image bytes |
| 57 | 2 | tcp_port `u16` (where the sender listens; default UDP+1) |
| 59 | 1 | mime_len `u8` (`<= 63`) |
| 60 | mime_len | mime_type UTF-8 (exactly `mime_len` bytes; no trailing bytes) |

MIME allowlist: `image/png`, `image/jpeg`, `image/webp` (exact,
lowercase). Anything else: reject the announce. `image_len >
max_image_bytes`: never fetch. The sender MUST have the bytes stored and
hashed BEFORE broadcasting.

Old (pre-image) clients require exactly 59 payload bytes and therefore
ignore every image announce.

## 4. Ordering (shared by text and images)

Each node keeps `last_applied = (lamport, device_id)`. Local copies bump
`lamport = max(lamport, unix_ms) + 1`. A remote update is accepted only if
`(remote_lamport, remote_device_id) > last_applied` (tuple compare;
device_id compared as unsigned bytes). Accepted announces advance
`last_applied` immediately; text→image and image→text are ordinary
successor updates. Own `device_id`: always ignored.

## 5. TCP side channel (large text AND images)

Default ports: UDP 47474, TCP 47475 (both configurable; the announce
carries the sender's TCP port). The receiver dials ONLY the announce
datagram's source IP at the announced port. One channel, identical
framing for text and images; the `inner` type only changes final
validation (UTF-8 check for `0x01`, skipped for `0x02`).

### 5.1 Request header (70 bytes, cleartext, AEAD AAD)

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `43 43 4c 54` ("CCLT") |
| 4 | 1 | version `01` |
| 5 | 1 | msg_type `01` = GET_IMAGE (fetch request) |
| 6 | 16 | client_device_id |
| 22 | 16 | transfer_id |
| 38 | 32 | client_nonce (fresh CSPRNG bytes per fetch) |

### 5.2 Session key

`HKDF-SHA256(IKM = shared key, salt = client_nonce, info = "clipcast
tcp v1" || transfer_id)`, first 32 bytes. Per-fetch key: nonces never
repeat across fetches.

### 5.3 Handshake

Client sends `header (70) || tag (16)` = 86 bytes, where `tag =
AES-GCM(session_key, nonce = 00 000000 0000000000000000, aad = header,
plaintext = empty)`. The server reads exactly 86 bytes under a 3 s
deadline, derives the key, and verifies. ANY failure (magic, version,
tag, unknown/expired/exhausted transfer id) closes the connection
silently with no response. Nothing attacker-sized is allocated before
the tag verifies.

### 5.4 Data frames (server → client)

Each frame: `len u32 (4) || ciphertext`. Plaintext = `flags u8 ||
data (<= 65536 bytes)`; ciphertext includes the 16-byte tag, so
`len <= 65553`. Nonce per frame: `direction(1) || 00 00 00(3) ||
counter u64(8)` with direction `0x01` (server→client), counters
0, 1, 2, … (enforced by the AEAD nonce — a reused/skipped counter fails
authentication). AAD for every frame = the 70-byte request header.

`flags`: `0x01` = FINAL (this is the last frame). All other bits MUST be
0. Non-final frames carry exactly 65536 data bytes. Exactly one FINAL
frame; nothing may follow it (the server closes; extra bytes =
violation). Empty content or exact multiples of 65536 get a trailing
empty FINAL frame.

### 5.5 Client validation (in order)

1. `total_len <=` the per-kind ceiling (64 MiB text, 16 MiB image)
   BEFORE connecting — nothing larger is ever fetched.
2. Frame lengths `<= 65553`; tags verify; counters increment; exactly one
   FINAL; received bytes `== total_len`.
3. SHA-256 over the bytes equals the announced hash.
4. UTF-8 valid, iff `inner == 0x01`.

Any failure: apply nothing, discard bytes. Images additionally require
the fetch's `(lamport, device_id)` to still equal `last_applied` (a
newer update that arrived mid-download wins; the stale image is
discarded) and publish via the platform image clipboard under the
announced MIME type.

## 6. Limits (defaults)

| Setting | Default | Meaning |
|---|---|---|
| inline text | 1200 B | above → TCP announce |
| max_transfer_bytes (text) | 64 MiB | above → never sent/fetched |
| max_image_bytes | 16 MiB | above → never announced/fetched |
| max frame | 65553 B | larger TCP frame → abort |
| sender text store | 4 newest, 128 MiB, 120 s TTL, 16 serves each | |
| sender image cache | 20 newest, 600 s TTL | disk, `0600` files |
| concurrent fetches | 2 outbound, 8 inbound connections | extras refused/cancelled-oldest |
| UDP rate limit | 20 packets/s | beyond → dropped |

## 7. Failure rules (both implementations)

- Malformed/untrusted fields never panic, never allocate proportionally
  to attacker values, and never touch the clipboard.
- Partial/corrupt/over-limit/unsupported content: discard, delete temp
  files, record (type, MIME, size, hash prefix, device, transfer id,
  duration, outcome) in logs — never content bytes.
- Echo suppression: applied content (hash of text UTF-8 or image bytes)
  suppresses the local clipboard event it generates (~1 s window); device
  id alone is not sufficient; received content is never forwarded.
- Image comparison is by content hash, never by URI/path string.

## 8. Known architectural note

The original image-sync sketch proposed a second TCP protocol ("CCTP"
with GET_IMAGE/IMAGE_META/chunk message types and the long-term PSK used
directly per message). The shipped design instead reuses the existing
authenticated TCP channel (§5): it already provides per-fetch HKDF
session keys, AEAD framing with monotonic nonces, length/hash checks,
and silent-drop-on-failure — strictly stronger than the sketch and one
protocol instead of two. The UDP IMAGE_ANNOUNCE sketch fields
(lamport/timestamp/transfer_id/len/port/mime/sha256) all survive,
layered on the existing announce framing (§3) so old clients keep
ignoring them.
