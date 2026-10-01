//! clipcast: LAN clipboard sync daemon.
//!
//! Module layout:
//! - [`proto`]: wire format encode/decode (pure functions, no I/O)
//! - [`crypto`]: AES-256-GCM seal/open and key handling
//! - [`engine`]: sync state machine, generic over clipboard/transport traits
//! - [`clipboard`]: session detection, compositor probe, backend planning
//! - [`net`]: real UDP transport and interface discovery
//! - [`config`], [`paths`], [`keys`], [`cli`], [`doctor`]: configuration
//!   and entry points

pub mod cli;
pub mod clipboard;
pub mod config;
pub mod crypto;
pub mod doctor;
pub mod engine;
pub mod keys;
pub mod net;
pub mod paths;
pub mod proto;
