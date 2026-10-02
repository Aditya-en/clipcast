//! Clipboard backends: session detection, compositor capability probing,
//! and backend planning. The concrete backends (`x11`, `wayland`, `polling`)
//! plug in behind `crate::engine::ClipboardBackend`.

use std::fmt;
use std::io;
use std::sync::Mutex;
use std::sync::mpsc::{Receiver, Sender, channel};

use crate::config::{BackendOverride, Config};
use crate::engine::{ClipboardBackend, ClipboardEvent};

mod polling;
mod wayland;
mod x11;

/// Fan-out of local clipboard change events to every active subscriber.
/// Backends own one of these for their lifetime; `subscribe_changes` may be
/// called any number of times.
#[derive(Default)]
pub(crate) struct Subscribers(Mutex<Vec<Sender<ClipboardEvent>>>);

impl Subscribers {
    pub(crate) fn subscribe(&self) -> Receiver<ClipboardEvent> {
        let (tx, rx) = channel();
        if let Ok(mut subs) = self.0.lock() {
            subs.push(tx);
        }
        rx
    }

    pub(crate) fn emit(&self, event: ClipboardEvent) {
        if let Ok(mut subs) = self.0.lock() {
            subs.retain(|s| s.send(event.clone()).is_ok());
        }
    }
}

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

impl BackendPlan {
    /// Instantiate the concrete backend for this plan. Failures (missing
    /// extension, compositor gone, no display) are returned to the caller,
    /// which may fall back to [`BackendPlan::Polling`].
    pub fn create(self, cfg: &Config) -> io::Result<Box<dyn ClipboardBackend>> {
        match self {
            BackendPlan::X11 => x11::create(),
            BackendPlan::Wayland => wayland::create(),
            BackendPlan::Polling => {
                polling::create(std::time::Duration::from_millis(cfg.poll_interval_ms))
            }
        }
    }

    /// Image MIME types this plan can supply, without instantiating a
    /// backend (for `doctor` diagnostics).
    pub fn image_mime_types(self) -> Vec<String> {
        match self {
            // Both native backends transfer the owner's original bytes.
            BackendPlan::X11 | BackendPlan::Wayland => crate::proto::SUPPORTED_IMAGE_MIMES
                .iter()
                .map(|m| m.to_string())
                .collect(),
            // arboard exposes pixels: this backend syncs PNG only.
            BackendPlan::Polling => vec!["image/png".to_string()],
        }
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

// GUI round-trip tests below use the real session clipboard. They are
// serialized (shared clipboard) and skip when no display is reachable.
#[cfg(test)]
mod gui_tests {
    use super::*;
    use std::sync::mpsc::RecvTimeoutError;
    use std::thread;
    use std::time::{Duration, Instant};

    static GUI_LOCK: Mutex<()> = Mutex::new(());

    fn lock_gui() -> std::sync::MutexGuard<'static, ()> {
        GUI_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn recv_matching(
        rx: &std::sync::mpsc::Receiver<ClipboardEvent>,
        timeout: Duration,
        want: &str,
    ) -> Option<ClipboardEvent> {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.checked_duration_since(Instant::now())?;
            match rx.recv_timeout(remaining) {
                Ok(ev) if matches!(&ev.content, crate::engine::ClipboardContent::Text(t) if t == want) =>
                {
                    return Some(ev);
                }
                Ok(_) => continue,
                Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    fn copy_text_externally(text: &str, sensitive: bool) -> io::Result<()> {
        let mut opts = wl_clipboard_rs::copy::Options::new();
        opts.trim_newline(false);
        opts.sensitive(sensitive);
        opts.copy(
            wl_clipboard_rs::copy::Source::Bytes(text.as_bytes().to_vec().into()),
            wl_clipboard_rs::copy::MimeType::Text,
        )
        .map_err(|e| io::Error::other(e.to_string()))
    }

    #[test]
    fn wayland_backend_roundtrip() {
        let _g = lock_gui();
        let backend = match wayland::create() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("skipping wayland backend roundtrip: {e}");
                return;
            }
        };
        let rx = backend.subscribe_changes();

        copy_text_externally("clipcast-wl-in", false).expect("external wayland copy");
        let ev = recv_matching(&rx, Duration::from_secs(5), "clipcast-wl-in")
            .expect("wayland watcher must observe external copy");
        assert!(!ev.sensitive);

        while rx.try_recv().is_ok() {}
        copy_text_externally("clipcast-wl-secret", true).expect("external sensitive copy");
        let ev = recv_matching(&rx, Duration::from_secs(5), "clipcast-wl-secret")
            .expect("wayland watcher must observe sensitive copy");
        assert!(ev.sensitive, "password-manager hint must be detected");

        backend
            .set_text("clipcast-wl-out")
            .expect("wayland set_text");
        assert_eq!(
            backend.get_text().expect("wayland get_text").as_deref(),
            Some("clipcast-wl-out")
        );
    }

    #[test]
    fn x11_backend_roundtrip() {
        let _g = lock_gui();
        let backend = match x11::create() {
            Ok(b) => b,
            Err(e) => {
                eprintln!("skipping x11 backend roundtrip: {e}");
                return;
            }
        };
        let rx = backend.subscribe_changes();

        // An independent X11 client takes ownership and serves content; the
        // backend must see the XFixes notification and read the text.
        let mut external = match arboard::Clipboard::new() {
            Ok(cb) => cb,
            Err(e) => {
                eprintln!("skipping x11 backend roundtrip: no X display: {e}");
                return;
            }
        };
        external
            .set_text("clipcast-x11-in")
            .expect("external x11 copy");
        let ev = recv_matching(&rx, Duration::from_secs(5), "clipcast-x11-in")
            .expect("x11 backend must observe external copy");
        assert!(!ev.sensitive);

        // Serve path: our set_text must satisfy an independent reader.
        backend.set_text("clipcast-x11-out").expect("x11 set_text");
        let mut reader = arboard::Clipboard::new().expect("second X11 client");
        assert_eq!(
            reader.get_text().expect("external read"),
            "clipcast-x11-out"
        );
        assert_eq!(
            backend.get_text().expect("backend get_text").as_deref(),
            Some("clipcast-x11-out")
        );
        drop(external);
    }

    #[test]
    fn polling_backend_roundtrip() {
        let _g = lock_gui();
        let backend = match polling::create(Duration::from_millis(50)) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("skipping polling backend roundtrip: {e}");
                return;
            }
        };
        let rx = backend.subscribe_changes();
        // Let the first ticks establish the baseline snapshot.
        thread::sleep(Duration::from_millis(300));

        let mut external = match arboard::Clipboard::new() {
            Ok(cb) => cb,
            Err(e) => {
                eprintln!("skipping polling backend roundtrip: no X display: {e}");
                return;
            }
        };
        external
            .set_text("clipcast-poll-in")
            .expect("external x11 copy");
        let ev = recv_matching(&rx, Duration::from_secs(3), "clipcast-poll-in")
            .expect("polling backend must observe the change");
        assert!(!ev.sensitive);
        drop(external);
    }
}
