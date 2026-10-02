# Clipcast

LAN clipboard sync: copy on one device, paste on another. Encrypted
(AES-256-GCM), ordered (Lamport clock), no accounts, no cloud.

| Subproject | What | Stack |
|------------|------|-------|
| [`desktop/`](desktop/) | Daemon for Linux (X11/Wayland) and Windows | Rust, no async runtime |
| [`android/`](android/) | Android client (8.0+, framework UI only) | Kotlin, Android SDK only |

Both speak the same wire protocol: v1 UDP datagrams for short text plus a
v2 TCP side channel for large text and images (announce + encrypted fetch).
The cross-implementation test vectors in [`desktop/docs/`](desktop/docs/)
are the contract between them.

## Security limits (read before running)

- One shared 32-byte key (base64, `clipcast keygen`) encrypts everything.
  Anyone with the key — and LAN access — can read the clipboard traffic,
  text and images alike.
- Keys live in plaintext: `~/.config/clipcast/key` on desktop, app-private
  `SharedPreferences` on Android. Protect the machines, not just the key.
- No forward secrecy, no replay protection beyond Lamport ordering, no
  hardening against a malicious LAN peer beyond authentication.
- Image sizes and timing leak as metadata, and sent images sit temporarily
  on disk so peers can fetch them: `~/.local/state/clipcast/images/` on
  desktop (0600, 10-minute TTL), app-private cache on Android.
- Android applies at most ~512 KiB per text paste (Binder limit); larger
  transfers are refused, never partially applied. Images paste as content
  URIs, so the Binder limit does not apply to them (16 MiB sync limit).

## Layout

```
clipcast/
  desktop/    Rust daemon (Cargo.toml, src/, tests/, docs/, contrib/)
  android/    Gradle project (settings.gradle.kts, app/)
  README.md   this file
  LICENSE     MIT
```

## License

MIT — see [LICENSE](LICENSE).
