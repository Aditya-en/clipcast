# Clipcast Android

A lightweight LAN clipboard sync client for Android. Interoperates with the desktop `clipcast` Rust daemon.

## Features

- **Text-only sync** (v1): Plain text clipboard synchronization over LAN
- **Minimal dependencies**: Android SDK + Kotlin stdlib only (no third-party libraries)
- **Tiny APK**: ~200KB release build with R8 shrinking
- **Low battery**: Foreground service with MulticastLock, no wake lock
- **Strict protocol compatibility**: Byte-exact implementation of wire protocol v1

## Protocol

Implements the clipcast wire protocol v1:
- UDP port 47474 (configurable)
- AES-256-GCM encryption with 32-byte shared key (base64)
- 16-byte device ID (generated per-install)
- Lamport clock for ordering with device ID tiebreak
- Max 1200 byte payload, 1400 byte datagram

See [clipcast/docs/test-vectors.md](../clipcast/docs/test-vectors.md) for cross-implementation test vectors.

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

### Sending clipboard text (4 paths)

| Path | How |
|------|-----|
| **Auto (foreground)** | App open → copy text → sent automatically |
| **Share menu** | Select text → Share → "Clipcast Send" |
| **Quick Settings tile** | Swipe down → "Clipcast Send" tile → reads clipboard → sends |
| **Notification action** | Pull notification shade → "Send clipboard" button |

### Receiving

Works in background via foreground service. Remote text appears in clipboard automatically.

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
```

- **MainActivity**: Settings, status, manual send button
- **SendActivity**: Transparent activity for Share/QS tile/notification action
- **ClipcastService**: UDP receive, decrypt, apply to clipboard, send queue
- **NetworkManager**: Computes directed broadcast address from LinkProperties, tracks network changes
- **SyncState**: Lamport clock + device ID tiebreak (identical to desktop)
- **Crypto**: AES-256-GCM with header as AAD

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

### Manual test plan

1. **Desktop → Phone**: Copy on desktop, verify appears on phone clipboard
2. **Phone → Desktop**: Share text on phone, verify appears on desktop
3. **Multi-device**: Desktop + 2 phones, verify convergence
4. **Wi-Fi change**: Move between APs, verify reconnect
5. **Screen off**: Wait 5 min, copy on desktop, wake phone, verify
6. **Oversize**: Copy 1500 char text, verify toast warning
7. **Wrong key**: Enter invalid key, verify service won't start

## Known Limitations

- Background auto-send impossible on Android 10+ without privileged access
- MulticastLock may not work on all OEM Wi-Fi implementations
- Directed broadcast requires correct subnet mask from LinkProperties
- No image/file support (v1 text only)
- No QR code for key entry (manual paste only)

## License

MIT