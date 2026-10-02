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

    // Clipboard capabilities
    out.push_str("  text_clipboard:  yes\n");
    let mimes = plan.image_mime_types();
    if mimes.is_empty() {
        out.push_str("  image_clipboard: no (backend cannot supply images)\n");
    } else {
        out.push_str("  image_clipboard: yes\n");
        out.push_str("  supported_image_mime_types:\n");
        for m in &mimes {
            out.push_str(&format!("    {m}\n"));
        }
    }

    // Image transfer
    let max_mib = cfg.max_image_bytes as f64 / (1024.0 * 1024.0);
    out.push_str(&format!(
        "  image_transfer: enabled (UDP announce + TCP fetch, same channel as large text)\n  max_image_size:  {cfg_max} bytes ({max_mib:.0} MiB)\n",
        cfg_max = cfg.max_image_bytes,
    ));
    match crate::paths::image_cache_dir() {
        Some(dir) => {
            let state = if dir.is_dir() {
                match std::fs::read_dir(&dir) {
                    Ok(entries) => format!("OK ({} cached)", entries.count()),
                    Err(e) => format!("ERROR: {e}"),
                }
            } else {
                "not created yet (created on first image send)".to_string()
            };
            out.push_str(&format!("  image_cache:    {} — {state}\n", dir.display()));
        }
        None => out.push_str("  image_cache:    cannot determine state dir ($HOME unset)\n"),
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
        "  transfer:       tcp_port={} inline_max_bytes={} (effective) max_transfer_bytes={} transfer_ttl_secs={} fetch_timeout_secs={}\n",
        cfg.tcp_port,
        cfg.effective_inline_max_bytes(),
        cfg.max_transfer_bytes,
        cfg.transfer_ttl_secs,
        cfg.fetch_timeout_secs
    ));
    if crate::tcp_server::can_bind(cfg.tcp_port) {
        out.push_str(&format!(
            "  tcp_listener:   0.0.0.0:{} is free (daemon not holding it)\n",
            cfg.tcp_port
        ));
    } else {
        out.push_str(&format!(
            "  tcp_listener:   0.0.0.0:{} is in use (daemon already running, or another process holds it)\n",
            cfg.tcp_port
        ));
    }
    out.push_str(&format!(
        "  firewall:       peers need TCP {} as well as UDP {} (e.g. `sudo ufw allow {}/tcp`)\n",
        cfg.tcp_port, cfg.port, cfg.tcp_port
    ));
    out.push_str(&format!(
        "  device_name:    {} (informational)\n",
        cfg.device_name
    ));

    out
}
