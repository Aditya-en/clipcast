//! Clipboard backends: session detection, compositor capability probing,
//! and backend planning. The concrete backends (`x11`, `wayland`, `polling`)
//! plug in behind `crate::engine::ClipboardBackend`.

use std::fmt;

use crate::config::BackendOverride;

/// What the environment says about the graphical session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Session {
    Wayland,
    X11,
    Unknown,
}

impl fmt::Display for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Session::Wayland => "wayland",
            Session::X11 => "x11",
            Session::Unknown => "unknown",
        })
    }
}

/// Detect the session: `XDG_SESSION_TYPE` first, else `WAYLAND_DISPLAY` /
/// `DISPLAY` heuristics.
pub fn detect_session() -> Session {
    match std::env::var("XDG_SESSION_TYPE") {
        Ok(t) if t.eq_ignore_ascii_case("wayland") => return Session::Wayland,
        Ok(t) if t.eq_ignore_ascii_case("x11") => return Session::X11,
        _ => {}
    }
    let non_empty = |var: &str| std::env::var(var).map(|v| !v.is_empty()).unwrap_or(false);
    if non_empty("WAYLAND_DISPLAY") {
        Session::Wayland
    } else if non_empty("DISPLAY") {
        Session::X11
    } else {
        Session::Unknown
    }
}

/// Result of probing for the `ext/wlr-data-control` family of protocols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataControlSupport {
    Supported,
    /// Wayland session, but no data-control manager global (GNOME, stock Sway
    /// without the feature, …) — fall back to polling.
    Unsupported,
    /// Not a Wayland session (or no compositor reachable): probing is
    /// pointless.
    NotApplicable,
    /// Wayland session but the connection failed for some other reason.
    Unavailable(String),
}

impl fmt::Display for DataControlSupport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataControlSupport::Supported => f.write_str("supported (ext/wlr-data-control)"),
            DataControlSupport::Unsupported => {
                f.write_str("NOT supported (no data-control manager; will poll)")
            }
            DataControlSupport::NotApplicable => f.write_str("n/a (not a wayland session)"),
            DataControlSupport::Unavailable(e) => write!(f, "unavailable ({e})"),
        }
    }
}

/// Probe the compositor for data-control support (read-only; one roundtrip).
pub fn probe_data_control() -> DataControlSupport {
    use wl_clipboard_rs::paste::{self, ClipboardType, Seat};
    match paste::get_mime_types(ClipboardType::Regular, Seat::Unspecified) {
        Ok(_) => DataControlSupport::Supported,
        Err(paste::Error::MissingProtocol { .. }) => DataControlSupport::Unsupported,
        Err(paste::Error::SocketOpenError(_)) | Err(paste::Error::WaylandConnection(_)) => {
            DataControlSupport::Unavailable("cannot connect to compositor".to_string())
        }
        // Other errors (empty clipboard, no seats, …) imply the manager
        // global exists: the protocol itself is present.
        Err(other) => {
            let _ = other;
            DataControlSupport::Supported
        }
    }
}

/// The backend the daemon will actually use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendPlan {
    /// X11, XFixes selection-notify driven.
    X11,
    /// Wayland data-control driven.
    Wayland,
    /// Generic polling fallback (arboard).
    Polling,
}

impl fmt::Display for BackendPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            BackendPlan::X11 => "x11 (xfixes event-driven)",
            BackendPlan::Wayland => "wayland (data-control, event-driven)",
            BackendPlan::Polling => "polling (arboard)",
        })
    }
}

/// Decide which backend runs, given the config override, the session, and
/// the data-control probe result. Returns the plan plus a note when the
/// result differs from what the config asked for.
pub fn plan_backend(
    override_backend: BackendOverride,
    session: Session,
    data_control: &DataControlSupport,
) -> (BackendPlan, Option<String>) {
    match override_backend {
        BackendOverride::X11 => (BackendPlan::X11, None),
        BackendOverride::Wayland => {
            let note = if *data_control == DataControlSupport::Unsupported {
                Some(
                    "config forces wayland backend but the compositor has no \
                     data-control; it will likely fail (consider backend = \"polling\")"
                        .to_string(),
                )
            } else {
                None
            };
            (BackendPlan::Wayland, note)
        }
        BackendOverride::Polling => (BackendPlan::Polling, None),
        BackendOverride::Auto => match session {
            Session::Wayland => match data_control {
                DataControlSupport::Supported => (BackendPlan::Wayland, None),
                DataControlSupport::Unsupported => (
                    BackendPlan::Polling,
                    Some("compositor lacks data-control; falling back to polling".to_string()),
                ),
                DataControlSupport::Unavailable(e) => (
                    BackendPlan::Polling,
                    Some(format!(
                        "wayland unreachable ({e}); falling back to polling"
                    )),
                ),
                DataControlSupport::NotApplicable => (BackendPlan::Polling, None),
            },
            Session::X11 => (BackendPlan::X11, None),
            Session::Unknown => (
                BackendPlan::Polling,
                Some("no display detected; polling will likely fail".to_string()),
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn session_prefers_xdg_session_type() {
        let _g = ENV_LOCK.lock().unwrap();
        let orig_type = std::env::var("XDG_SESSION_TYPE").ok();
        let orig_wl = std::env::var("WAYLAND_DISPLAY").ok();
        let orig_x11 = std::env::var("DISPLAY").ok();

        unsafe {
            std::env::set_var("XDG_SESSION_TYPE", "wayland");
            std::env::set_var("DISPLAY", ":0");
            std::env::remove_var("WAYLAND_DISPLAY");
        }
        assert_eq!(detect_session(), Session::Wayland);
        unsafe { std::env::set_var("XDG_SESSION_TYPE", "x11") };
        assert_eq!(detect_session(), Session::X11);
        unsafe { std::env::remove_var("XDG_SESSION_TYPE") };

        // Falls back to WAYLAND_DISPLAY / DISPLAY.
        unsafe {
            std::env::set_var("WAYLAND_DISPLAY", "wayland-0");
            std::env::set_var("DISPLAY", ":0");
        }
        assert_eq!(detect_session(), Session::Wayland);
        unsafe { std::env::remove_var("WAYLAND_DISPLAY") };
        assert_eq!(detect_session(), Session::X11); // DISPLAY=:0 remains
        unsafe { std::env::remove_var("DISPLAY") };
        assert_eq!(detect_session(), Session::Unknown);

        // Restore whatever the harness had.
        fn restore(name: &str, value: Option<String>) {
            unsafe {
                match value {
                    Some(v) => std::env::set_var(name, v),
                    None => std::env::remove_var(name),
                }
            }
        }
        restore("XDG_SESSION_TYPE", orig_type);
        restore("WAYLAND_DISPLAY", orig_wl);
        restore("DISPLAY", orig_x11);
    }

    #[test]
    fn auto_on_wayland_with_data_control_picks_wayland() {
        let (plan, note) = plan_backend(
            BackendOverride::Auto,
            Session::Wayland,
            &DataControlSupport::Supported,
        );
        assert_eq!(plan, BackendPlan::Wayland);
        assert!(note.is_none());
    }

    #[test]
    fn auto_on_wayland_without_data_control_falls_back_to_polling() {
        let (plan, note) = plan_backend(
            BackendOverride::Auto,
            Session::Wayland,
            &DataControlSupport::Unsupported,
        );
        assert_eq!(plan, BackendPlan::Polling);
        assert!(note.is_some());
    }

    #[test]
    fn auto_on_x11_picks_x11() {
        let (plan, _) = plan_backend(
            BackendOverride::Auto,
            Session::X11,
            &DataControlSupport::NotApplicable,
        );
        assert_eq!(plan, BackendPlan::X11);
    }

    #[test]
    fn overrides_win_over_environment() {
        let (plan, note) = plan_backend(
            BackendOverride::Polling,
            Session::Wayland,
            &DataControlSupport::Supported,
        );
        assert_eq!(plan, BackendPlan::Polling);
        assert!(note.is_none());

        let (plan, note) = plan_backend(
            BackendOverride::Wayland,
            Session::Wayland,
            &DataControlSupport::Unsupported,
        );
        assert_eq!(plan, BackendPlan::Wayland);
        assert!(
            note.is_some(),
            "warn about a forced but unsupported backend"
        );

        let (plan, _) = plan_backend(
            BackendOverride::X11,
            Session::Wayland,
            &DataControlSupport::Supported,
        );
        assert_eq!(plan, BackendPlan::X11);
    }
}
