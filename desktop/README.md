# clipcast

A small LAN clipboard sync daemon for Linux desktops. Each device runs the
same service: it watches the local text clipboard, broadcasts changes over
UDP to the local network, and applies packets received from peers. Content
is encrypted and authenticated with a shared key (AES-256-GCM). Plain text
only, X11 and Wayland, one binary. Text past the inline limit syncs over an
encrypted TCP side channel (announce + fetch, protocol v2 below).

A Kotlin Android client targets the same wire protocols (sections
[Wire protocol v1](#wire-protocol-v1) and
[Large-text transfer v2](#large-text-transfer-v2)); the byte-level contracts
live in this README and [`docs/test-vectors.md`](docs/test-vectors.md) /
[`docs/test-vectors-v2.md`](docs/test-vectors-v2.md).

## Quick start

```sh
cargo build --release

# once per machine: create the shared key (0600, refuses to overwrite)
./target/release/clipcast keygen

# copy the key file to every other device, identical bytes:
#   ~/.config/clipcast/key

# run in the foreground
./target/release/clipcast run

# diagnostics: session, backend, interfaces, key, device_id
./target/release/clipcast doctor
```

Two devices sync as soon as both are running and can reach each other's
broadcasts on UDP port 47474. Large texts additionally need TCP port 47475
reachable between the machines (see [Large-text transfer](#large-text-transfer-v2)
and [Troubleshooting](#troubleshooting)).

## Architecture

```
proto      wire format encode/decode (pure functions, no I/O)
crypto     AES-256-GCM seal/open, key/device-id handling
tcp        v2 TCP session protocol: header, HKDF key, frames, reassembly
transfer   pending outbound large-text store (TTL, caps, fetch budgets)
tcp_server TCP listener serving pending transfers (sync workers)
fetch      TCP fetch client (timeouts, strict validation, cancellation)
engine     sync state machine, generic over two traits:
             ClipboardBackend { get_text, set_text, subscribe_changes }
             Transport        { send, recv }
           tests use in-memory fakes of both
clipboard/ real backends behind the trait:
             wayland   wlr/ext data-control (wl-clipboard-rs), event-driven
             x11       XFixes selection-notify (x11rb), event-driven
             polling   arboard snapshots (default 300 ms), fallback
net/       UDP transport (SO_REUSEADDR/SO_REUSEPORT), interface discovery
config, keys, paths, cli, doctor
```

Backend selection is automatic (`backend = "auto"`), with an override in
the config. `clipcast doctor` prints what would be chosen and why.

### Ordering and loop prevention

- Lamport clock + device-id tuple decides what wins; wall-clock time only
  seeds the clock so it stays monotonic across restarts.
- A received packet is applied only if `(lamport, device_id)` beats the
  last applied tuple; duplicates and stale packets fall out naturally.
- A received packet is never forwarded (no routing), so content travels
  exactly one hop.
- Our own broadcasts loop back on the wire and are dropped by device id.
- Remote text we wrote to the local clipboard is recognized by content
  hash inside a ~1 s suppression window and never rebroadcast.
- Outgoing changes are debounced (100 ms); incoming packets are rate
  limited (20/s).

## Wire protocol v1

All integers big-endian. One UDP datagram per message. Destination port
**47474** (configurable). Max datagram **1400** bytes; default
`max_text_bytes` is 1200.

Header — 34 bytes, sent in the clear and authenticated as AES-GCM AAD:

| offset | size | field        | value                                   |
|-------:|-----:|--------------|-----------------------------------------|
|      0 |    4 | magic        | ASCII `CCLP`                            |
|      4 |    1 | version      | `1`                                     |
|      5 |    1 | msg_type     | `0x01` = CLIP_UPDATE (others ignored)   |
|      6 |   16 | device_id    | random, once per install                |
|     22 |   12 | nonce        | random, fresh per message               |

Body — plaintext after decryption:

| size | field        | notes                                  |
|-----:|--------------|----------------------------------------|
|    8 | lamport      | ordering clock                         |
|    8 | timestamp_ms | informational only, never ordering     |
|    1 | content_type | `0x01` text/plain UTF-8; `0x02` image and `0x80` announce reserved |
|    4 | payload_len  | bytes of payload that follow           |
|  ... | payload      | UTF-8 text                             |

`ciphertext = AES-256-GCM(key, nonce, aad = header, plaintext = body)`
including the 16-byte tag; `key` is 32 bytes shared by all devices as
base64.

Receive rules: silently drop (log at debug) wrong magic, unsupported
version, failed tag, invalid UTF-8, or `payload_len` inconsistent with the
datagram. Unknown `content_type` is ignored. Nothing panics on malformed
input. Local text at or below the inline limit (`inline_max_bytes`,
default 1200) sends exactly as above; larger text (up to
`max_transfer_bytes`, default 64 MiB) sends as a v2 announce instead (next
section); larger text is not sent (warning with length only).

Cross-implementation test vectors (fixed key/nonce/device_id → exact
datagram hex) are in `docs/test-vectors.md`, asserted by a unit test. The
Android client should verify against that file first.

## Large-text transfer v2

Text longer than the UDP limit syncs via announce + TCP fetch. The sender
keeps the plaintext in a pending-transfer store (newest 4 transfers, 128 MiB
global cap, 120 s TTL, each fetchable up to 16 times) and serves it on TCP
port **47475** (configurable) bound to 0.0.0.0 for the daemon's lifetime.

Sender: text longer than `inline_max_bytes` but within `max_transfer_bytes`
registers a pending transfer (`transfer_id` = 16 random bytes) and broadcasts
one UDP announce. The receiver validates the announce through the same UDP
checks and ordering rule, then fetches the bytes over TCP.

### UDP announce

A normal v1 UDP message (existing header, nonce, AES-GCM, body layout) with
content_type = `0x80` and this 59-byte payload (all integers big-endian):

| size | field              | notes                                    |
|-----:|--------------------|------------------------------------------|
|    1 | inner_content_type | `0x01` = text/plain UTF-8; `0x02` = image (payload gains a MIME suffix, § Image sync); other values: ignore the announce |
|   16 | transfer_id        | random per transfer                      |
|    8 | total_len          | plaintext bytes (u64)                    |
|   32 | sha256             | SHA-256 of the plaintext content bytes   |
|    2 | tcp_port           | sender's TCP port (u16)                  |

The announce's lamport field is the message's lamport as usual: an accepted
announce advances `last_applied` immediately, exactly like a v1 message.
Over-limit announces, announces matching the local clipboard hash, and
announces with unknown inner types are not fetched. A newer accepted message
(announce or inline) cancels an in-flight older fetch; at most 2 fetches run
at once.

### TCP session

Magic `CCLT` identifies TCP traffic; separate protocol, version 1. The
receiver dials **only** the announce datagram's UDP source IP at the
announce's `tcp_port` — never any address from inside the payload.

Client request header (70 bytes, sent in the clear, used as AEAD AAD):

| size | field            | value                        |
|-----:|------------------|------------------------------|
|    4 | magic            | ASCII `CCLT`                 |
|    1 | version          | `1`                          |
|    1 | msg_type         | `0x01` = FETCH               |
|   16 | client_device_id | receiver's device id         |
|   16 | transfer_id      | from the announce            |
|   32 | client_nonce     | random per connection        |

Session key (32 bytes): HKDF-SHA256 (RFC 5869) with IKM = the shared
32-byte clipcast key, salt = `client_nonce`, info = ASCII
`clipcast tcp v1` followed by the 16 `transfer_id` bytes.

AEAD nonces (12 bytes): byte 0 = direction (`0x00` client-to-server, `0x01`
server-to-client), bytes 1..3 = zero, bytes 4..11 = u64 frame counter
(big-endian), starting at 0 per direction. Each connection has its own
session key, so nonce reuse across connections is impossible. AAD for every
sealed frame in both directions = the 70-byte request header.

Handshake: right after the header the client sends one sealed frame —
AES-256-GCM of the empty plaintext with direction `0x00`, counter 0 (exactly
a 16-byte tag, no length prefix). The server reads exactly 70 + 16 bytes
(3 s deadline), derives the key, verifies the tag, looks up the transfer,
and only then starts sending. On ANY failure (bad magic, version, tag,
unknown/expired/exhausted transfer, deadline) it closes silently with no
response and allocates nothing proportional to attacker input.

Server data frames (direction `0x01`, counters 0, 1, 2, …): `len` u32 =
ciphertext length including the 16-byte tag (rejected if over
65536 + 1 + 16), then the ciphertext of `flags` (u8) + up to 65536 data
bytes. Flag bit 0 = FINAL (last frame); other bits must be zero. Frames carry
65536 data bytes except the last, which carries FINAL (an empty final frame
covers exact multiples of 65536 and empty content). The client requires
exactly one FINAL, nothing after it (server closes), total data bytes ==
`total_len`, matching SHA-256, and valid UTF-8 for inner type `0x01` —
anything else aborts with nothing applied.

Limits/timeouts: connect 3 s, 10 s idle between frames, overall
`fetch_timeout_secs` (default 120); at most 8 concurrent server connections
(extras closed immediately); each transfer served at most 16 times.

Byte-exact vectors for a fixed key/ids/nonce/payload (announce payload,
header, session key, handshake tag, first and final frames) are in
`docs/test-vectors-v2.md`, asserted by a unit test.

## Image sync

Copying an image syncs it the same way large text syncs — UDP stays the
control plane, image bytes never touch a UDP datagram:

1. The clipboard backend reports an image (`image/png`, `image/jpeg`, or
   `image/webp`; the image wins when several representations exist).
2. The daemon stores the bytes in `~/.local/state/clipcast/images/` (files
   `0600`, kept `image_cache_ttl_secs`, at most `max_cached_images`) and
   hashes them.
3. It broadcasts one UDP image announce (content_type `0x80`, inner `0x02`,
   plus a MIME suffix — old clients see a wrong-length payload and ignore
   it).
4. Receivers run the same ordering check, fetch over the same TCP channel,
   verify length + SHA-256, confirm the update is still current (a newer
   text/image that arrived mid-download wins; the stale image is dropped),
   and publish the image to the local clipboard. Echo suppression is by
   content hash, so a received image is never rebroadcast.
5. Publish normalization: received JPEGs are transcoded to PNG before
   they reach the local clipboard, because some paste targets
   (notably Chromium-based browsers) silently ignore JPEG clipboard
   content while accepting PNG — regardless of which peer offered it.
   The wire bytes, hashes, and sender cache are untouched; only the
   locally published copy is PNG, and echo suppression follows the
   published bytes. Undecodable JPEGs, and transcoded PNGs that would
   exceed `max_image_bytes`, fall back to the original bytes (best
   effort, logged).

Oversize images (`max_image_bytes`, default 16 MiB) are logged by MIME type
and size only, never sent. The exact byte layout is specified in
[`docs/protocol.md`](docs/protocol.md); deterministic vectors are in
[`docs/test-vectors-image.md`](docs/test-vectors-image.md).

Backend notes: X11 reads/serves the native `image/png`/`image/jpeg`/
`image/webp` selection targets (INCR transfers are skipped, never
partially synced). Wayland reads/serves the same MIME types through
data-control. The polling fallback syncs PNG only (arboard exposes raw
pixels, encoded/decoded with the `png` crate) — JPEG/WebP copied under
the polling backend are left alone.

## Security model and limits — read this

- **No forward secrecy.** One long-term symmetric key encrypts everything,
  on UDP and on TCP. Anyone holding the key file can read and inject
  clipboard content on your LAN, forever, for that key.
- **TCP content is encrypted and authenticated** with per-connection keys
  derived from the shared key (HKDF-SHA256 over a fresh 32-byte client
  nonce): an attacker without the key can neither fetch transfers nor
  inject frames. Replaying a captured request only yields the same
  ciphertext back; without the key it decrypts to nothing.
- **Metadata is visible on the wire:** packet sizes, timing, the 16-byte
  device_id of every sender, transfer sizes, and the fact a transfer
  happened. The announce hash and length ride inside the encrypted UDP
  body; the TCP header (magic, device ids, transfer id) is cleartext.
  Content itself is not visible.
- **Replay of the latest packet is a no-op** (Lamport/tuple ordering
  rejects it), but an attacker who captured older distinct content can
  replay *that* packet and win if no newer change happened since. The same
  holds for captured announces (a replayed announce only re-triggers a
  fetch of content the sender still holds).
- **Key compromise is total compromise.** Anyone holding the key can read
  and inject clipboard content on your LAN, forever, for that key.
- Images are encrypted with the same shared key: every peer holding the
  key can decrypt clipboard images as well as text. Image sizes and timing
  remain visible as metadata, and sent images sit temporarily in
  `~/.local/state/clipcast/images/` (0600 files, 10-minute TTL by
  default) so peers can fetch them — never retained indefinitely, but
  present on disk while fetchable.
- Clipboard content never appears in logs by default (only length and a
  short hash prefix). `--log-content` disables that protection — debug use
  only.
- Key file `~/.config/clipcast/key` must be mode 0600; the daemon refuses
  to start if group/other bits are set.
- Device id `~/.local/state/clipcast/device_id` (16 bytes, 0600) identifies
  the machine on the wire.
- Sensitive content: if the local clipboard advertises
  `x-kde-passwordManagerHint` with value `secret`, it is not broadcast
  (`skip_sensitive = true`, default). The polling backend cannot see MIME
  types, so it cannot detect this — one more reason it is a fallback.
- v1 syncs plain text inline; larger text and images use the v2
  announce + TCP fetch above. No compression, no resumable transfers, no
  relays, no TLS.

## Configuration

`~/.config/clipcast/config.toml` (all keys optional; defaults shown):

```toml
port = 47474
max_text_bytes = 1200   # legacy inline limit; inline_max_bytes wins if set
inline_max_bytes = 1200 # text at/below this sends inline (UDP)
max_transfer_bytes = 67108864  # 64 MiB: larger local text is never sent
tcp_port = 47475        # large-text TCP listener + advertised port
transfer_ttl_secs = 120 # pending transfers stay fetchable this long
fetch_timeout_secs = 120# overall cap for one incoming TCP fetch
max_image_bytes = 16777216  # 16 MiB: larger images are never sent/fetched
image_cache_ttl_secs = 600  # sent images stay fetchable this long
max_cached_images = 20      # sender image cache cap (oldest evicted)
poll_interval_ms = 300     # polling backend only
skip_sensitive = true
backend = "auto"           # "auto" | "x11" | "wayland" | "polling"
device_name = "hostname"   # informational only, sent nowhere
interface_allow = []       # non-empty => only matching interfaces
interface_deny = ["lo", "docker*", "br-*", "veth*", "virbr*", "tun*", "tap*"]
```

## CLI

```
clipcast keygen [--force]      create the key file (refuses to overwrite)
clipcast run [--log-content]   the daemon, foreground, logs to stderr
clipcast doctor                environment diagnostics, read-only
```

`RUST_LOG` is respected (e.g. `RUST_LOG=clipcast=debug` for packet-level
detail); default level is `info`.

## systemd (user service)

The service must run as a **user** unit: it needs the graphical session's
`WAYLAND_DISPLAY`/`DISPLAY`/`XDG_SESSION_TYPE`.

```sh
cargo install --path .                       # -> ~/.cargo/bin/clipcast
mkdir -p ~/.config/systemd/user
cp contrib/clipcast.service ~/.config/systemd/user/

# make the session environment visible to systemd --user
systemctl --user import-environment WAYLAND_DISPLAY DISPLAY XDG_SESSION_TYPE
# (on Sway/Hyprland: also `dbus-update-activation-environment --systemd ...`
#  from your compositor startup, so new sessions are covered)

systemctl --user daemon-reload
systemctl --user enable --now clipcast
journalctl --user -u clipcast -f
```

The unit uses `Restart=on-failure`, `RestartSec=2`, and is wired into
`graphical-session.target` (`After`/`PartOf`/`WantedBy`). If your compositor
does not start `graphical-session.target`, enable the unit from your
session startup instead. Adjust `ExecStart` in the unit if the binary is
installed elsewhere.

## Troubleshooting

- **Sync works on one machine but not between machines:**
  - Firewall: allow the UDP port (default 47474), e.g.
    `sudo ufw allow 47474/udp` or
    `sudo nft add rule inet filter input udp dport 47474 accept`.
    Repeat on **both** machines.
  - Firewall (large text): allow the TCP port too (default 47475), e.g.
    `sudo ufw allow 47475/tcp` or
    `sudo nft add rule inet filter input tcp dport 47475 accept`.
    Without it, short texts sync but anything over the inline limit stays
    local (fetch timeouts in the log). Repeat on **both** machines.
  - AP/client isolation: many Wi-Fi networks and guest networks block
    client-to-client traffic ("AP isolation", "client isolation", "peer
    isolation"). Disable it for your network, or test first with a cable /
    5 GHz network known to allow peer traffic.
  - Same key: peers must have byte-identical key files or every packet
    fails its AEAD tag (visible as debug-level drops).
  - Broadcast reachability: `clipcast doctor` prints the target broadcast
    address per interface; check it is the network you expect (VPN
    interfaces, dockers, etc. are denied by default).
- **Wrong backend / no events:** `clipcast doctor` shows session type,
  data-control support, and the planned backend. GNOME has no
  data-control, so clipcast falls back to polling (X11/Xwayland required).
- **Two instances on one machine:** receive sockets use
  `SO_REUSEADDR`/`SO_REUSEPORT`, so this works (it is how the manual test
  below runs).
- **Key permission errors:** `chmod 600 ~/.config/clipcast/key`.

## Manual test plan

1. **Two instances, one machine** (packet path, ordering, no loops):

   ```sh
   export XDG_CONFIG_HOME=/tmp/ccA/.config XDG_STATE_HOME=/tmp/ccA/.local/state
   clipcast keygen
   mkdir -p /tmp/ccB/.config/clipcast
   cp "$XDG_CONFIG_HOME/clipcast/key" /tmp/ccB/.config/clipcast/key

   RUST_LOG=clipcast=debug clipcast run &            # instance A
   XDG_CONFIG_HOME=/tmp/ccB/.config \
   XDG_STATE_HOME=/tmp/ccB/.local/state \
   RUST_LOG=clipcast=debug clipcast run &            # instance B

   wl-copy "hello"        # or copy something on X11
   # both logs show: one broadcast, one "applied remote", echo suppressed,
   # own-device packets ignored; no repeats after a second.
   ```

 2. **Two real machines:** install on both, place the same key file, run
    (or enable the user service) on both, copy text on A, paste on B, then
    the reverse. Confirm `doctor` output on both shows reachable broadcast
    addresses on the same subnet.

 3. **Large text, one machine** (TCP side channel, packet path, ordering,
    no loops): with two instances as in (1) (same key, `RUST_LOG=debug`),
    copy ~5 MB of text (e.g. `python3 -c "print('x'*5_000_000)" | wl-copy`).
    The sender log shows one announce broadcast; the receiver log shows the
    fetch completing and one "applied fetched transfer"; pasting yields the
    full text on both; no rebroadcast appears in either log. Note: both
    instances share TCP 47475, so only the instance that bound it serves —
    large texts copied on the *other* instance will not be fetchable in
    this setup. Use distinct `tcp_port` values in the two config files for
    full two-way large-text testing on one machine.

 4. **Large text, two real machines:** with the daemon running on both and
    TCP 47475 open both ways, copy ~5 MB on A, paste on B, then the reverse.
    Confirm `doctor` on both reports the TCP listener and matching ports.

## Testing status

`cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`
are clean. Unit tests cover proto round-trip and malformed input (v1 + v2
announce + image announce), crypto tampering, all three documented
test-vector files, HKDF (RFC 5869 case 1), TCP frame sealing/opening and
reassembly violations (truncated stream, missing FINAL, data after FINAL,
wrong length/hash), silent-drop of unauthenticated TCP connections, the
transfer store caps/TTL/budgets, the disk image cache (round-trip, expiry,
eviction, permissions, unknown ids), PNG encode/decode for the polling
backend, engine behaviors (a)–(h) against fakes (large-text announce,
exactly-one-fetch, apply-without-rebroadcast, stale/duplicate suppression,
fetch cancellation, over-limit and same-hash skips, failed fetch applies
nothing) plus image engine behaviors (exactly-one-announce,
fetchable-before-announce, loopback apply-once-without-rebroadcast,
duplicate-announce dedup, older-image drop, own-device ignore, newer-text-
wins race, corrupt-image rejection, over-limit skips, fetch-cap
cancel-newest-wins), interface discovery/filtering, UDP loopback with
source capture, config/keys/paths, backend planning, MIME/hint parsing.

Integration tests (`clipboard::gui_tests`) run against the real session:
Wayland set/observe including the password-manager hint, X11 XFixes
observation plus selection serving, and the polling backend. They skip
themselves when no display is reachable. A loopback integration test moves
5 MB of text through the real TCP server + fetch client with fake
clipboards (no display needed).

Ran here: the two-instance one-machine manual tests for small text
(verified broadcast delivery, apply, echo suppression, own-device
filtering, SIGINT shutdown), plus the automated 5 MB loopback test.
Not run here: the two-physical-machines tests (no second machine in this
environment) — items 2 and 4 above still need real hardware.
