//! X11 backend: XFixes selection-notify driven change detection (x11rb).
//!
//! The main connection runs an event loop that detects ownership changes,
//! reads the new selection content (UTF8_STRING, falling back to STRING, plus
//! the KDE password-manager hint), and serves paste requests for content we
//! applied ourselves. A second, private connection serves `get_text` so its
//! synchronous SelectionNotify replies are never consumed by the event loop.

use std::io;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread;

use tracing::{debug, warn};
use x11rb::connection::Connection;
use x11rb::protocol::Event;
use x11rb::protocol::xfixes::{self, SelectionEventMask};
use x11rb::protocol::xproto::{
    Atom, ConnectionExt as _, CreateWindowAux, EventMask, PropMode, SELECTION_NOTIFY_EVENT,
    SelectionNotifyEvent, SelectionRequestEvent, Timestamp, Window, WindowClass,
};
use x11rb::rust_connection::RustConnection;
use x11rb::wrapper::ConnectionExt as _;

use super::Subscribers;
use crate::engine::{ClipboardBackend, ClipboardEvent};

/// Cap selection reads at 256 KiB (units of 4 bytes). Anything larger is far
/// beyond `max_text_bytes`, so it would be dropped by the engine anyway; the
/// cap keeps a hostile or huge selection from ballooning memory.
const MAX_READ_UNITS: u32 = 65536;

x11rb::atom_manager! {
    Atoms: AtomsCookie {
        CLIPBOARD,
        UTF8_STRING,
        TARGETS,
        STRING,
        TEXT,
        ATOM,
        READ_PROP: b"CLIPCAST_READ",
        PASSWORD_HINT: b"x-kde-passwordManagerHint",
    }
}

fn xerr(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

fn make_window(conn: &impl Connection, screen_num: usize) -> io::Result<Window> {
    let screen = &conn.setup().roots[screen_num];
    let win = conn.generate_id().map_err(xerr)?;
    conn.create_window(
        x11rb::COPY_DEPTH_FROM_PARENT,
        win,
        screen.root,
        0,
        0,
        1,
        1,
        0,
        WindowClass::INPUT_OUTPUT,
        screen.root_visual,
        &CreateWindowAux::new().event_mask(EventMask::NO_EVENT),
    )
    .map_err(xerr)?
    .check()
    .map_err(xerr)?;
    Ok(win)
}

fn selection_owner(conn: &RustConnection, selection: Atom) -> Window {
    match conn
        .get_selection_owner(selection)
        .map_err(xerr)
        .and_then(|c| c.reply().map_err(xerr))
    {
        Ok(reply) => reply.owner,
        Err(_) => 0,
    }
}

pub(crate) fn create() -> io::Result<Box<dyn ClipboardBackend>> {
    let (conn, screen_num) =
        x11rb::connect(None).map_err(|e| io::Error::other(format!("x11 connect: {e}")))?;
    let conn = Arc::new(conn);
    let atoms = Arc::new(
        Atoms::new(&*conn)
            .map_err(|e| io::Error::other(format!("intern atoms: {e}")))?
            .reply()
            .map_err(|e| io::Error::other(format!("intern atoms: {e}")))?,
    );

    let ext = conn
        .query_extension(b"XFIXES")
        .map_err(xerr)?
        .reply()
        .map_err(xerr)?;
    if !ext.present {
        return Err(io::Error::other("XFixes extension unavailable"));
    }
    xfixes::query_version(&conn, 5, 0)
        .map_err(xerr)?
        .reply()
        .map_err(xerr)?;

    let win = make_window(&conn, screen_num)?;
    xfixes::select_selection_input(
        &conn,
        win,
        atoms.CLIPBOARD,
        SelectionEventMask::SET_SELECTION_OWNER,
    )
    .map_err(xerr)?
    .check()
    .map_err(xerr)?;
    conn.flush().map_err(xerr)?;

    // Private connection for synchronous get_text reads.
    let (conn_read, screen_read) =
        x11rb::connect(None).map_err(|e| io::Error::other(format!("x11 read connect: {e}")))?;
    let read_win = make_window(&conn_read, screen_read)?;

    let subs = Arc::new(Subscribers::default());
    let content = Arc::new(Mutex::new(String::new()));

    let thread_conn = Arc::clone(&conn);
    let thread_atoms = Arc::clone(&atoms);
    let thread_subs = Arc::clone(&subs);
    let thread_content = Arc::clone(&content);
    thread::Builder::new()
        .name("clipcast-x11".into())
        .spawn(move || event_loop(thread_conn, thread_atoms, thread_subs, thread_content, win))
        .map_err(|e| io::Error::other(format!("spawn x11 thread: {e}")))?;

    Ok(Box::new(X11Backend {
        subs,
        conn,
        conn_read,
        win,
        read_win,
        atoms,
        content,
    }))
}

#[derive(Default, PartialEq, Eq)]
enum Stage {
    #[default]
    Utf8,
    String,
    Hint,
}

#[derive(Default)]
struct ReadState {
    pending: bool,
    dirty: bool,
    stage: Stage,
    text: String,
    timestamp: Timestamp,
}

fn event_loop(
    conn: Arc<RustConnection>,
    atoms: Arc<Atoms>,
    subs: Arc<Subscribers>,
    content: Arc<Mutex<String>>,
    win: Window,
) {
    let mut state = ReadState::default();
    loop {
        let event = match conn.wait_for_event() {
            Ok(event) => event,
            Err(e) => {
                warn!("x11 event loop ended: {e}");
                break;
            }
        };
        match event {
            Event::XfixesSelectionNotify(e) if e.selection == atoms.CLIPBOARD => {
                let owner = selection_owner(&conn, atoms.CLIPBOARD);
                if owner == 0 || owner == win {
                    // Cleared, or our own set_text: nothing to read.
                    continue;
                }
                if state.pending {
                    // A newer change arrived mid-read; catch up after.
                    state.dirty = true;
                } else if let Err(e) = start_read(&conn, &atoms, win, e.timestamp, &mut state) {
                    debug!("selection read start failed: {e}");
                }
            }
            Event::SelectionNotify(e) if e.requestor == win && e.selection == atoms.CLIPBOARD => {
                if let Err(e) = advance_read(&conn, &atoms, &subs, win, &mut state, &e) {
                    debug!("selection read failed: {e}");
                    state.pending = false;
                }
            }
            Event::SelectionRequest(e) if e.selection == atoms.CLIPBOARD => {
                if let Err(e) = serve_request(&conn, &atoms, &content, &e) {
                    debug!("selection serve failed: {e}");
                }
            }
            _ => {}
        }
    }
}

fn start_read(
    conn: &RustConnection,
    atoms: &Atoms,
    win: Window,
    timestamp: Timestamp,
    state: &mut ReadState,
) -> io::Result<()> {
    state.pending = true;
    state.dirty = false;
    state.stage = Stage::Utf8;
    state.timestamp = timestamp;
    state.text.clear();
    conn.convert_selection(
        win,
        atoms.CLIPBOARD,
        atoms.UTF8_STRING,
        atoms.READ_PROP,
        timestamp,
    )
    .map_err(xerr)?;
    conn.flush().map_err(xerr)
}

fn finish_read(
    conn: &RustConnection,
    atoms: &Atoms,
    subs: &Subscribers,
    win: Window,
    state: &mut ReadState,
    sensitive: bool,
) -> io::Result<()> {
    state.pending = false;
    let text = std::mem::take(&mut state.text);
    if !text.is_empty() {
        subs.emit(ClipboardEvent { text, sensitive });
    }
    if state.dirty {
        state.dirty = false;
        let owner = selection_owner(conn, atoms.CLIPBOARD);
        if owner != 0 && owner != win {
            start_read(conn, atoms, win, x11rb::CURRENT_TIME, state)?;
        }
    }
    Ok(())
}

fn advance_read(
    conn: &RustConnection,
    atoms: &Atoms,
    subs: &Subscribers,
    win: Window,
    state: &mut ReadState,
    event: &SelectionNotifyEvent,
) -> io::Result<()> {
    match state.stage {
        Stage::Utf8 | Stage::String => {
            if event.property == 0 {
                if state.stage == Stage::Utf8 {
                    // UTF8_STRING refused; try the legacy STRING target.
                    state.stage = Stage::String;
                    conn.convert_selection(
                        win,
                        atoms.CLIPBOARD,
                        atoms.STRING,
                        atoms.READ_PROP,
                        state.timestamp,
                    )
                    .map_err(xerr)?;
                    return conn.flush().map_err(xerr);
                }
                // Both targets refused: nothing readable.
                return finish_read(conn, atoms, subs, win, state, false);
            }
            let reply = conn
                .get_property(true, win, event.property, 0u32, 0, MAX_READ_UNITS)
                .map_err(xerr)?
                .reply()
                .map_err(xerr)?;
            if reply.bytes_after != 0 || reply.value.is_empty() {
                // Oversize (beyond any syncable text) or empty: skip.
                return finish_read(conn, atoms, subs, win, state, false);
            }
            state.text = String::from_utf8_lossy(&reply.value).into_owned();
            state.stage = Stage::Hint;
            conn.convert_selection(
                win,
                atoms.CLIPBOARD,
                atoms.PASSWORD_HINT,
                atoms.READ_PROP,
                state.timestamp,
            )
            .map_err(xerr)?;
            conn.flush().map_err(xerr)
        }
        Stage::Hint => {
            let sensitive = if event.property == 0 {
                false
            } else {
                let reply = conn
                    .get_property(true, win, event.property, 0u32, 0, 16)
                    .map_err(xerr)?
                    .reply()
                    .map_err(xerr)?;
                String::from_utf8_lossy(&reply.value)
                    .trim()
                    .eq_ignore_ascii_case("secret")
            };
            finish_read(conn, atoms, subs, win, state, sensitive)
        }
    }
}

fn serve_request(
    conn: &RustConnection,
    atoms: &Atoms,
    content: &Mutex<String>,
    event: &SelectionRequestEvent,
) -> io::Result<()> {
    let text = content
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default();
    let property = if event.property == 0 {
        event.target
    } else {
        event.property
    };

    // 0 in the reply means "refused" (property None per ICCCM).
    let mut reply_property = 0;
    if event.target == atoms.TARGETS {
        conn.change_property32(
            PropMode::REPLACE,
            event.requestor,
            property,
            atoms.ATOM,
            &[atoms.TARGETS, atoms.UTF8_STRING, atoms.STRING, atoms.TEXT],
        )
        .map_err(xerr)?;
        reply_property = property;
    } else if event.target == atoms.UTF8_STRING || event.target == atoms.TEXT {
        conn.change_property8(
            PropMode::REPLACE,
            event.requestor,
            property,
            atoms.UTF8_STRING,
            text.as_bytes(),
        )
        .map_err(xerr)?;
        reply_property = property;
    } else if event.target == atoms.STRING {
        conn.change_property8(
            PropMode::REPLACE,
            event.requestor,
            property,
            atoms.STRING,
            text.as_bytes(),
        )
        .map_err(xerr)?;
        reply_property = property;
    }
    // Everything else — including the password-manager hint, which we never
    // claim for content we applied from the network — is refused.

    let notify = SelectionNotifyEvent {
        response_type: SELECTION_NOTIFY_EVENT,
        sequence: 0,
        time: event.time,
        requestor: event.requestor,
        selection: event.selection,
        target: event.target,
        property: reply_property,
    };
    conn.send_event(false, event.requestor, EventMask::NO_EVENT, notify)
        .map_err(xerr)?;
    conn.flush().map_err(xerr)
}

struct X11Backend {
    subs: Arc<Subscribers>,
    conn: Arc<RustConnection>,
    conn_read: RustConnection,
    win: Window,
    read_win: Window,
    atoms: Arc<Atoms>,
    content: Arc<Mutex<String>>,
}

impl ClipboardBackend for X11Backend {
    fn get_text(&self) -> io::Result<Option<String>> {
        for target in [self.atoms.UTF8_STRING, self.atoms.STRING] {
            self.conn_read
                .convert_selection(
                    self.read_win,
                    self.atoms.CLIPBOARD,
                    target,
                    self.atoms.READ_PROP,
                    x11rb::CURRENT_TIME,
                )
                .map_err(xerr)?
                .check()
                .map_err(xerr)?;
            loop {
                let event = self.conn_read.wait_for_event().map_err(xerr)?;
                let Event::SelectionNotify(e) = event else {
                    continue;
                };
                if e.requestor != self.read_win {
                    continue;
                }
                if e.property == 0 {
                    break; // Target refused; try the next one.
                }
                let reply = self
                    .conn_read
                    .get_property(true, self.read_win, e.property, 0u32, 0, MAX_READ_UNITS)
                    .map_err(xerr)?
                    .reply()
                    .map_err(xerr)?;
                if reply.value.is_empty() || reply.bytes_after != 0 {
                    return Ok(None);
                }
                return Ok(Some(String::from_utf8_lossy(&reply.value).into_owned()));
            }
        }
        Ok(None)
    }

    fn set_text(&self, text: &str) -> io::Result<()> {
        {
            let mut guard = self
                .content
                .lock()
                .map_err(|_| io::Error::other("selection content poisoned"))?;
            *guard = text.to_owned();
        }
        // Publish content before taking ownership so a paste racing us sees
        // the new text.
        self.conn
            .set_selection_owner(self.win, self.atoms.CLIPBOARD, x11rb::CURRENT_TIME)
            .map_err(|e| io::Error::other(format!("take selection ownership: {e}")))?
            .check()
            .map_err(|e| io::Error::other(format!("take selection ownership: {e}")))
    }

    fn subscribe_changes(&self) -> Receiver<ClipboardEvent> {
        self.subs.subscribe()
    }
}
