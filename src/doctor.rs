//! `clipcast doctor`: one-shot environment diagnostics.

use std::path::Path;

use crate::clipboard::{self, DataControlSupport, detect_session, plan_backend};
use crate::config::Config;
use crate::keys;
use crate::net::discover;

/// Render a full diagnostic report. Performs a read-only compositor probe.
pub fn report(cfg: &Config, config_path: &Path) -> String {
    let mut out = String::new();
    out.push_str("clipcast doctor\n");

    // Session
    let session = detect_session();
    let env_display = std::env::var("DISPLAY").unwrap_or_else(|_| "-".into());
    let env_wayland = std::env::var("WAYLAND_DISPLAY").unwrap_or_else(|_| "-".into());
    let env_type = std::env::var("XDG_SESSION_TYPE").unwrap_or_else(|_| "-".into());
    out.push_str(&format!("  session:        {session} (XDG_SESSION_TYPE={env_type}, WAYLAND_DISPLAY={env_wayland}, DISPLAY={env_display})\n"));

    // Data-control probe (Wayland only)
    let data_control = if session == clipboard::Session::Wayland {
        clipboard::probe_data_control()
    } else {
        DataControlSupport::NotApplicable
    };
    out.push_str(&format!("  data-control:   {data_control}\n"));

    // Planned backend
    let (plan, note) = plan_backend(cfg.backend, session, &data_control);
    out.push_str(&format!(
        "  backend:        {plan} (override: {:?})\n",
        cfg.backend
    ));
    if let Some(note) = note {
        out.push_str(&format!("  note:           {note}\n"));
    }

    // Interfaces
    out.push_str("  interfaces:\n");
    let targets = discover(&cfg.interface_allow, &cfg.interface_deny);
    if targets.is_empty() {
        out.push_str("    (none eligible; check allow/deny lists or network state)\n");
    }
    for t in &targets {
        out.push_str(&format!(
            "    {}  {} -> {}:{}\n",
            t.name, t.ip, t.broadcast, cfg.port
        ));
    }

    // Key
    match crate::paths::key_file() {
        Some(p) => out.push_str(&format!(
            "  key:            {} — {}\n",
            p.display(),
            keys::key_status(&p)
        )),
        None => out.push_str("  key:            cannot determine config dir ($HOME unset)\n"),
    }

    // Device id
    match crate::paths::device_id_file() {
        Some(p) => match keys::load_or_create_device_id(&p) {
            Ok(id) => {
                let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
                out.push_str(&format!("  device_id:      {hex} ({})\n", p.display()));
            }
            Err(e) => out.push_str(&format!("  device_id:      ERROR: {e}\n")),
        },
        None => out.push_str("  device_id:      cannot determine state dir ($HOME unset)\n"),
    }

    // Config
    let exists = config_path.exists();
    out.push_str(&format!(
        "  config:         {} ({})\n",
        config_path.display(),
        if exists {
            "loaded"
        } else {
            "absent, using defaults"
        }
    ));
    out.push_str(&format!(
        "  settings:       port={} max_text_bytes={} poll_interval_ms={} skip_sensitive={}\n",
        cfg.port, cfg.max_text_bytes, cfg.poll_interval_ms, cfg.skip_sensitive
    ));
    out.push_str(&format!(
        "  device_name:    {} (informational)\n",
        cfg.device_name
    ));

    out
}
