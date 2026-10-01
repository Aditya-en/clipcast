# clipcast

A small LAN clipboard sync daemon for Linux desktops. Each device runs the
same service: it watches the local text clipboard, broadcasts changes over
UDP to the local network, and applies packets received from peers. Content
is encrypted and authenticated with a shared key (AES-256-GCM). Plain text
only, X11 and Wayland, one binary.

A Kotlin Android client targets the same wire protocol (section
[Wire protocol v1](#wire-protocol-v1)); the byte-level contract lives in
this README and [`docs/test-vectors.md`](docs/test-vectors.md).

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
broadcasts on UDP port 47474.

## Architecture

```
proto      wire format encode/decode (pure functions, no I/O)
crypto     AES-256-GCM seal/open, key/device-id handling
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
input. Oversize local text is not sent (warning with length only; TCP fetch
is a marked v2 extension point).

Cross-implementation test vectors (fixed key/nonce/device_id → exact
datagram hex) are in `docs/test-vectors.md`, asserted by a unit test. The
Android client should verify against that file first.

## Security model and limits — read this

- **No forward secrecy.** One long-term symmetric key encrypts everything.
- **Replay of the latest packet is a no-op** (Lamport/tuple ordering
  rejects it), but an attacker who captured older distinct content can
  replay *that* packet and win if no newer change happened since.
- **Key compromise is total compromise.** Anyone holding the key can read
  and inject clipboard content on your LAN, forever, for that key.
- **Metadata is visible on the wire:** packet sizes, timing, and the
  16-byte device_id of every sender. Content is not.
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
- v1 syncs plain text only. Images, files, rich text are out of scope;
  image/announce content types are reserved in the protocol but ignored.

## Configuration

`~/.config/clipcast/config.toml` (all keys optional; defaults shown):

```toml
port = 47474
max_text_bytes = 1200
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

## Testing status

`cargo fmt`, `cargo clippy --all-targets -- -D warnings`, and `cargo test`
are clean. Unit tests cover proto round-trip and malformed input, crypto
tampering, the documented test vector, engine behaviors (a)–(g) from the
spec against fakes, interface discovery/filtering, transport loopback,
config/keys/paths, backend planning, MIME/hint parsing.

Integration tests (`clipboard::gui_tests`) run against the real session:
Wayland set/observe including the password-manager hint, X11 XFixes
observation plus selection serving, and the polling backend. They skip
themselves when no display is reachable.

Ran here: the two-instance one-machine manual test above (verified
broadcast delivery, apply, echo suppression, own-device filtering, SIGINT
shutdown). Not run here: the two-physical-machines test (no second machine
in this environment).
