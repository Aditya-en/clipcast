//! clipcast: LAN clipboard sync daemon.
//!
//! Module layout:
//! - [`proto`]: wire format encode/decode (pure functions, no I/O)
//! - [`crypto`]: AES-256-GCM seal/open and key handling
//! - [`engine`]: sync state machine, generic over clipboard/transport traits
//! - [`clipboard`]: real clipboard backends (X11, Wayland, polling)
//! - [`net`]: real UDP transport and interface discovery
//! - [`config`], [`cli`], [`paths`]: configuration and entry points

pub mod crypto;
pub mod engine;
pub mod proto;
