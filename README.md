# Clipcast Android

A lightweight LAN clipboard sync client for Android. Interoperates with the desktop `clipcast` Rust daemon.

## Features

- **Text sync** (v1 + v2 side channel): short text over UDP, large text (up to 16 MiB sends) over an encrypted TCP side channel
- **Minimal dependencies**: Android SDK + Kotlin stdlib only (no third-party libraries)
- **Tiny APK**: ~200KB release build with R8 shrinking
- **Low battery**: Foreground service with MulticastLock, no wake lock
- **Strict protocol compatibility**: Byte-exact implementation of wire protocols v1 and v2 (verified against the desktop test vectors)

## Protocol

Implements the clipcast wire protocol v1 plus the v2 large-text TCP side channel:

- UDP port 47474 (configurable)
- AES-256-GCM encryption with 32-byte shared key (base64)
- 16-byte device ID (generated per-install)
- Lamport clock for ordering with device ID tiebreak
- Max 1200 byte payload, 1400 byte datagram (v1 small text)

### Large text (v2 side channel)

Text over the 1200 byte UDP limit syncs via a TCP side channel:

- The sender registers a pending transfer (16-byte random `transfer_id`, kept 120 s, newest 4, 32 MiB total cap, served at most 16 times) and broadcasts **one UDP announce**: a normal v1 datagram with `content_type = 0x80` whose 59-byte payload is `inner_content_type(1) || transfer_id(16) || total_len u64(8) || sha256(32) || tcp_port u16(2)`. The announce carries the message's Lamport clock as usual, so ordering and echo rules are unchanged.
- The receiver fetches from the announce's UDP source address at the announce's `tcp_port`: it sends a 70-byte `CCLT` request header (`magic || version=1 || FETCH=0x01 || client_device_id(16) || transfer_id(16) || client_nonce(32)`) plus a 16-byte handshake tag (AES-256-GCM of empty plaintext), then reads sealed data frames.
- Session key: HKDF-SHA256 (RFC 5869) with IKM = shared key, salt = `client_nonce`, info = ASCII `clipcast tcp v1` + `transfer_id` (implemented with `HmacSHA256`; extract + one expand block for the 32-byte output). AEAD nonce: direction byte + 3 zero bytes + u64 frame counter; AAD = the 70-byte request header for every frame.
- Data frames: `len u32 || ciphertext(flags(1) + up to 65536 data bytes + 16-byte tag)`; bit 0 of flags = FINAL, others must be zero. The server sends 64 KiB frames, the last carrying FINAL (an empty FINAL frame terminates exact multiples). The client requires exactly one FINAL, nothing after it, exact `total_len`, matching SHA-256, and strict UTF-8 — otherwise it applies nothing.
- Timeouts: 3 s connect, 3 s handshake read, 10 s idle per read, 120 s overall per transfer. At most 2 concurrent fetches (a newer accepted message cancels an older one) and 4 concurrent inbound connections (extras closed immediately).

See [clipcast/docs/test-vectors.md](../clipcast/docs/test-vectors.md) and [clipcast/docs/test-vectors-v2.md](../clipcast/docs/test-vectors-v2.md) for cross-implementation test vectors.

## Build

```bash
cd clipshare
./gradlew assembleRelease
```

Output: `app/build/outputs/apk/release/app-release.apk`

Requires:
- JDK 17+
- Android SDK (API 34)
- Gradle 8.5+ (via wrapper)

## Installation

1. Build or download the APK
2. Install on Android 8.0+ (API 26+)
3. Grant notification permission (Android 13+)
4. Enter the encryption key from `clipcast keygen` (base64)
5. Tap "Start" to begin syncing

## Usage

### Sending clipboard text (5 paths)

| Path | How |
|------|-----|
| **Auto (foreground)** | App open → copy text → sent automatically (small and large) |
| **Share menu** | Select text → Share → "Clipcast Send" (small and large) |
| **Quick Settings tile** | Swipe down → "Clipcast Send" tile → reads clipboard → sends |
| **Notification action** | Pull notification shade → "Send clipboard" button |
| **Send now button** | In-app button → sends current clipboard |

Small text (≤ 1200 bytes) goes over UDP as before. Larger text (up to 16 MiB) is served from the phone over TCP: the app announces it once over UDP and serves fetches while the foreground service is alive. Past 16 MiB the app tells you the text is too large.

### Receiving

Works in background via foreground service. Remote text appears in clipboard automatically. Small text applies directly; large-text announces are fetched over TCP (max 2 at a time; a newer accepted message cancels an older fetch) and applied only after length, SHA-256, and UTF-8 verification. The status line shows the last transfer result (size and success/failure, never content).

## Android Clipboard (Binder) Limit

**Important**: `setPrimaryClip()` goes through Binder, which fails near 1 MB. The app therefore refuses to apply fetched text over **max applied text size** (default **512 KiB**, hard-capped at **900 KB** in the UI). An over-limit announce is skipped with a debug log and a brief status-line notice ("Text too large for the Android clipboard") — no toast storm, nothing applied.

## Settings

| Setting | Default | Notes |
|---------|---------|-------|
| UDP port | 47474 | Must match the daemon's UDP port |
| TCP port | 47475 | Our listener; peers learn it from our announces |
| Max applied text | 512 KiB | Cap on fetched text applied to the clipboard; hard-capped at 900 KB |

**Firewall implications (desktop side):** the desktop daemon must be reachable from the phone — allow inbound UDP on its UDP port *and* inbound TCP on its `tcp_port` in the desktop firewall. In the other direction, LAN peers must be able to open TCP to the phone's TCP port: guest Wi-Fi networks with client isolation, or Android hotspot/Tethering setups that block inbound connections, will break phone→desktop large sends (small UDP text may still work). If large sends fail while small text syncs, check isolation/firewall first.

## Android Clipboard Limitations

## Android Clipboard Limitations

**Important**: Android 10+ prevents background apps from reading the clipboard. This is a platform restriction, not a bug.

- ✅ **Receiving works in background**: Foreground service can *write* clipboard via `setPrimaryClip()`
- ❌ **Sending requires foreground**: Auto-send only works while app Activity is visible
- 📱 **Workarounds provided**: Share target, Quick Settings tile, notification action all bring app to foreground briefly to read clipboard

**No accessibility service, root, or ADB hacks are used** — these would violate Play Store policy and/or require user setup.

## Architecture

```
MainActivity (UI) ←→ LocalBroadcastManager ←→ ClipcastService (Foreground)
                                                     ↓
                         NetworkManager ←→ DatagramSocket (UDP recv loop)
                                                     ↓
                         SyncState (Lamport) + Crypto (AES-GCM)
                                                     ↓
                    Large text: AnnouncePolicy → TcpFetchClient (2-thread pool)
                                TransferStore ← TcpServer (ServerSocket + pool of 4)
```

- **MainActivity**: Settings (key, UDP/TCP ports, max applied text), status incl. TCP state + last transfer, manual send button
- **SendActivity**: Transparent activity for Share/QS tile/notification action
- **ClipcastService**: UDP receive, decrypt, apply to clipboard, send queue; announce handling + fetch pool + TCP listener lifecycle
- **NetworkManager**: Computes directed broadcast address from LinkProperties, tracks network changes
- **SyncState**: Lamport clock + device ID tiebreak (identical to desktop)
- **Crypto**: AES-256-GCM with header as AAD; 0x80 announce encode/decode (v1 path unchanged)
- **TcpCrypto**: HKDF-SHA256, CCLT header, handshake tag, frame seal/open, reassembly + content verification (pure JVM, unit-tested against the desktop vectors)
- **TransferStore / TcpServer / TcpFetchClient / AnnouncePolicy**: pending sends, inbound listener, outbound fetch, receive gate

## Permissions

| Permission | Purpose |
|------------|---------|
| `INTERNET` | UDP socket |
| `ACCESS_WIFI_STATE` | Read LinkProperties for broadcast addr |
| `CHANGE_WIFI_MULTICAST_STATE` | MulticastLock for broadcast reception |
| `FOREGROUND_SERVICE` | Background sync |
| `FOREGROUND_SERVICE_SPECIAL_USE` | Foreground service type (API 34+) |
| `POST_NOTIFICATIONS` | Foreground service notification (API 33+) |
| `RECEIVE_BOOT_COMPLETED` | Optional autostart |
| `WAKE_LOCK` | Not used (held for compatibility) |

## Foreground Service Type

Uses `specialUse` with property `android:foregroundServiceType="specialUse"` in manifest. This is the correct type for "custom use cases not covered by other types" per Android 14+ docs. The service performs periodic network I/O for clipboard sync.

## Battery & Doze

- Holds `WifiManager.MulticastLock` (required for broadcast reception on many devices)
- **No wake lock** — relies on Wi-Fi staying associated
- Doze mode / screen-off Wi-Fi power saving **may delay delivery** (device-dependent)
- Rate limits: 20 msg/s incoming, 100 ms debounce outgoing
- **Doze and the TCP listener**: the phone serves large-text fetches only while the foreground service is alive. Doze (screen off, stationary, unplugged) can suspend the service's network access and delay or break inbound TCP connections and outbound fetches; maintenance windows may let small UDP text through while a large transfer stalls. If large syncs fail with the screen off, wake the phone and retry. Exempting the app from battery optimization reduces (but does not eliminate) this on stock Android; OEM skins vary.

## Storage

- Encryption key + device ID stored in app-private `SharedPreferences`
- **Plaintext** — acceptable for v1; not hardware-backed
- Key validation: must be 32 bytes base64 on save

## Testing

### Unit tests (JVM)

```bash
./gradlew test
```

Tests cover:
- Test vector 1 encode/decode (byte-exact)
- Tamper rejection (tag, magic, version, msg_type)
- Ordering rules (Lamport + device ID tiebreak)
- Oversize payload handling
- Edge cases (empty, unicode, large lamport)
- v2 vectors (byte-exact): HKDF session key, request header, handshake tag, data + empty-FINAL frames
- v2 framing: tampered header/frame/flags/counter rejected; truncated stream, missing FINAL, data after FINAL, wrong length/hash/UTF-8 rejected
- Announce encode/decode round trip + malformed input; v1/announce cross-decode rejection
- Pending-transfer eviction (newest 4), TTL, memory cap, 16-fetch budget
- Fetch client: loopback (small, multiframe, ~5 MB), wrong key/hash, over-limit + pre-cancelled without connecting, mid-flight cancel, stub-server negative cases
- Announce policy: over-limit skip (incl. huge u64), unknown inner type, duplicate hash

### Manual test plan (against the desktop daemon)

Requires the desktop daemon on the same LAN with the same key.

1. **Desktop → Phone (~100 KB)**: copy ~100 KB text on desktop, verify it appears on the phone clipboard and the status line shows the received size.
2. **Desktop → Phone (~5 MB, refused)**: copy ~5 MB text on desktop, verify the phone shows "Text too large for the Android clipboard" in the status line and the clipboard is unchanged.
3. **Phone → Desktop (share sheet, ~100 KB)**: select ~100 KB text on the phone → Share → "Clipcast Send", verify it appears on the desktop.
4. **Wrong key**: enter a wrong key on the phone, copy on desktop, verify nothing arrives (and the daemon log shows auth failures, not crashes).
5. **Wi-Fi change mid-transfer**: start a large (~5 MB, with raised max-apply for the test) desktop→phone transfer, roam to another AP mid-transfer, verify the phone reports a failed transfer and applies nothing; re-copying after roaming syncs.
6. **Screen off**: turn the phone screen off, wait 5 min, copy ~100 KB on desktop, wake the phone, verify delivery or a failed-transfer status (Doze may delay it; retry with screen on).
7. **Small-text regression**: copy short text both ways, verify instant sync as before.
8. **Oversize send**: try to send > 16 MiB from the phone, verify the "too large" notice.

## Known Limitations

- Background auto-send impossible on Android 10+ without privileged access
- MulticastLock may not work on all OEM Wi-Fi implementations
- Directed broadcast requires correct subnet mask from LinkProperties
- Fetched text over max applied size (default 512 KiB, max 900 KB) is refused (Binder limit)
- Phone serves large-text fetches only while the foreground service is alive; Doze may delay or break transfers with the screen off
- No image/file support (text only)
- No QR code for key entry (manual paste only)

## License

MIT