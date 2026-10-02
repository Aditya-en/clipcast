//! X11 backend: XFixes selection-notify driven change detection (x11rb).
//!
//! The main connection runs an event loop that detects ownership changes,
//! reads the new selection content, and serves paste requests for content we
//! applied ourselves. Text is read as UTF8_STRING (falling back to STRING,
//! plus the KDE password-manager hint); images are read from the
//! `image/png`, `image/jpeg`, or `image/webp` targets when the owner offers
//! them (PNG preferred), and served back the same way. A second, private
//! connection serves `get_text`/`get_image` so its synchronous
//! SelectionNotify replies are never consumed by the event loop.

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
use crate::engine::{ClipboardBackend, ClipboardEvent, ClipboardImage};

/// Cap text selection reads at 256 KiB (units of 4 bytes). Anything larger
/// is far beyond `max_text_bytes`, so it would be dropped by the engine
/// anyway; the cap keeps a hostile or huge selection from ballooning memory.
const MAX_READ_UNITS: u32 = 65536;
/// Cap image selection reads at 16 MiB (units of 4 bytes), matching the
/// default `max_image_bytes`. Owners demanding INCR (`bytes_after != 0`)
/// are skipped: we never hold a partial image.
const MAX_IMAGE_READ_UNITS: u32 = 4 * 1024 * 1024;

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
        IMAGE_PNG: b"image/png",
        IMAGE_JPEG: b"image/jpeg",
        IMAGE_WEBP: b"image/webp",
    }
}

/// Content we own and serve to pasting applications.
#[derive(Default, Clone)]
enum SelectionContent {
    #[default]
    Empty,
    Text(String),
    Image {
        mime: String,
        bytes: Vec<u8>,
    },
}

/// Image targets in preference order (PNG first: lossless and universal).
fn image_targets(atoms: &Atoms) -> [(Atom, &'static str); 3] {
    [
        (atoms.IMAGE_PNG, "image/png"),
        (atoms.IMAGE_JPEG, "image/jpeg"),
        (atoms.IMAGE_WEBP, "image/webp"),
    ]
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
    let content = Arc::new(Mutex::new(SelectionContent::default()));

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
    Targets,
    Utf8,
    String,
    Hint,
    Image,
}

#[derive(Default)]
struct ReadState {
    pending: bool,
    dirty: bool,
    stage: Stage,
    text: String,
    timestamp: Timestamp,
    image_mime: Option<String>,
    image_target: Atom,
}

fn event_loop(
    conn: Arc<RustConnection>,
    atoms: Arc<Atoms>,
    subs: Arc<Subscribers>,
    content: Arc<Mutex<SelectionContent>>,
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
    state.stage = Stage::Targets;
    state.timestamp = timestamp;
    state.text.clear();
    state.image_mime = None;
    // Ask what the owner offers first: an image target wins over text.
    conn.convert_selection(
        win,
        atoms.CLIPBOARD,
        atoms.TARGETS,
        atoms.READ_PROP,
        timestamp,
    )
    .map_err(xerr)?;
    conn.flush().map_err(xerr)
}

fn start_text_read(
    conn: &RustConnection,
    atoms: &Atoms,
    win: Window,
    state: &mut ReadState,
) -> io::Result<()> {
    state.stage = Stage::Utf8;
    state.text.clear();
    conn.convert_selection(
        win,
        atoms.CLIPBOARD,
        atoms.UTF8_STRING,
        atoms.READ_PROP,
        state.timestamp,
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
        subs.emit(ClipboardEvent::text(text, sensitive));
    }
    restart_if_dirty(conn, atoms, win, state)
}

/// Nothing readable came back: clear the read without emitting, then catch
/// up if a newer change arrived mid-read.
fn finish_empty(
    conn: &RustConnection,
    atoms: &Atoms,
    win: Window,
    state: &mut ReadState,
) -> io::Result<()> {
    state.pending = false;
    state.text.clear();
    restart_if_dirty(conn, atoms, win, state)
}

fn restart_if_dirty(
    conn: &RustConnection,
    atoms: &Atoms,
    win: Window,
    state: &mut ReadState,
) -> io::Result<()> {
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
        Stage::Targets => {
            if event.property == 0 {
                // Owner refuses TARGETS (old client): fall back to text.
                return start_text_read(conn, atoms, win, state);
            }
            let reply = conn
                .get_property(true, win, event.property, 0u32, 0, 1024)
                .map_err(xerr)?
                .reply()
                .map_err(xerr)?;
            let offered: Vec<Atom> = reply.value32().into_iter().flatten().collect();
            if let Some((target, mime)) = image_targets(atoms)
                .into_iter()
                .find(|(t, _)| offered.contains(t))
            {
                state.stage = Stage::Image;
                state.image_mime = Some(mime.to_string());
                state.image_target = target;
                conn.convert_selection(
                    win,
                    atoms.CLIPBOARD,
                    target,
                    atoms.READ_PROP,
                    state.timestamp,
                )
                .map_err(xerr)?;
                return conn.flush().map_err(xerr);
            }
            start_text_read(conn, atoms, win, state)
        }
        Stage::Image => {
            if event.property == 0 {
                // Image target refused after all: give up quietly.
                return finish_empty(conn, atoms, win, state);
            }
            let reply = conn
                .get_property(true, win, event.property, 0u32, 0, MAX_IMAGE_READ_UNITS)
                .map_err(xerr)?
                .reply()
                .map_err(xerr)?;
            let mime = state.image_mime.clone().unwrap_or_default();
            if reply.bytes_after != 0 || reply.value.is_empty() {
                // INCR-size or empty: never emit a partial image.
                debug!("skipping x11 image: oversize or empty ({mime})");
                return finish_empty(conn, atoms, win, state);
            }
            state.pending = false;
            subs.emit(ClipboardEvent::image(mime, reply.value));
            restart_if_dirty(conn, atoms, win, state)
        }
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
    content: &Mutex<SelectionContent>,
    event: &SelectionRequestEvent,
) -> io::Result<()> {
    let content = content
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
        let mut targets = vec![atoms.TARGETS, atoms.UTF8_STRING, atoms.STRING, atoms.TEXT];
        if let SelectionContent::Image { .. } = content {
            targets.extend(image_targets(atoms).iter().map(|(t, _)| *t));
        }
        conn.change_property32(
            PropMode::REPLACE,
            event.requestor,
            property,
            atoms.ATOM,
            &targets,
        )
        .map_err(xerr)?;
        reply_property = property;
    }
    match (&content, event.target) {
        (SelectionContent::Text(text), t) if t == atoms.UTF8_STRING || t == atoms.TEXT => {
            conn.change_property8(
                PropMode::REPLACE,
                event.requestor,
                property,
                atoms.UTF8_STRING,
                text.as_bytes(),
            )
            .map_err(xerr)?;
            reply_property = property;
        }
        (SelectionContent::Text(text), t) if t == atoms.STRING => {
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
        (SelectionContent::Image { mime, bytes }, t)
            if image_targets(atoms).iter().any(|(a, _)| *a == t) =>
        {
            let target_atom = image_targets(atoms)
                .into_iter()
                .find(|(a, _)| *a == t)
                .map(|(a, _)| a)
                .unwrap_or(atoms.IMAGE_PNG);
            debug!("serving x11 image ({mime}) for paste");
            conn.change_property8(
                PropMode::REPLACE,
                event.requestor,
                property,
                target_atom,
                bytes,
            )
            .map_err(xerr)?;
            reply_property = property;
        }
        _ => {}
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
    content: Arc<Mutex<SelectionContent>>,
}

/// Convert a selection on the private read connection and return the raw
/// property bytes, or `None` when the target is refused/empty/oversize.
fn read_target_once(
    conn: &RustConnection,
    atoms: &Atoms,
    read_win: Window,
    target: Atom,
    max_units: u32,
) -> io::Result<Option<Vec<u8>>> {
    conn.convert_selection(
        read_win,
        atoms.CLIPBOARD,
        target,
        atoms.READ_PROP,
        x11rb::CURRENT_TIME,
    )
    .map_err(xerr)?
    .check()
    .map_err(xerr)?;
    loop {
        let event = conn.wait_for_event().map_err(xerr)?;
        let Event::SelectionNotify(e) = event else {
            continue;
        };
        if e.requestor != read_win {
            continue;
        }
        if e.property == 0 {
            return Ok(None);
        }
        let reply = conn
            .get_property(true, read_win, e.property, 0u32, 0, max_units)
            .map_err(xerr)?
            .reply()
            .map_err(xerr)?;
        if reply.value.is_empty() || reply.bytes_after != 0 {
            return Ok(None);
        }
        return Ok(Some(reply.value));
    }
}

/// List the atoms the current selection owner offers, if it cooperates.
fn read_offered_targets(
    conn: &RustConnection,
    atoms: &Atoms,
    read_win: Window,
) -> io::Result<Vec<Atom>> {
    match read_target_once(conn, atoms, read_win, atoms.TARGETS, 1024)? {
        Some(bytes) => {
            let (chunks, rest) = bytes.as_chunks::<4>();
            if !rest.is_empty() {
                return Ok(Vec::new());
            }
            Ok(chunks.iter().copied().map(Atom::from_ne_bytes).collect())
        }
        None => Ok(Vec::new()),
    }
}

impl ClipboardBackend for X11Backend {
    fn get_text(&self) -> io::Result<Option<String>> {
        for target in [self.atoms.UTF8_STRING, self.atoms.STRING] {
            match read_target_once(
                &self.conn_read,
                &self.atoms,
                self.read_win,
                target,
                MAX_READ_UNITS,
            )? {
                Some(bytes) => return Ok(Some(String::from_utf8_lossy(&bytes).into_owned())),
                None => continue,
            }
        }
        Ok(None)
    }

    fn get_image(&self) -> io::Result<Option<ClipboardImage>> {
        let offered = read_offered_targets(&self.conn_read, &self.atoms, self.read_win)?;
        for (target, mime) in image_targets(&self.atoms) {
            if !offered.contains(&target) {
                continue;
            }
            match read_target_once(
                &self.conn_read,
                &self.atoms,
                self.read_win,
                target,
                MAX_IMAGE_READ_UNITS,
            )? {
                Some(bytes) => {
                    return Ok(Some(ClipboardImage {
                        mime_type: mime.to_string(),
                        bytes,
                    }));
                }
                None => continue,
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
            *guard = SelectionContent::Text(text.to_owned());
        }
        self.take_ownership()
    }

    fn set_image(&self, image: &ClipboardImage) -> io::Result<()> {
        if !crate::proto::is_supported_image_mime(&image.mime_type) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported image MIME {}", image.mime_type),
            ));
        }
        {
            let mut guard = self
                .content
                .lock()
                .map_err(|_| io::Error::other("selection content poisoned"))?;
            *guard = SelectionContent::Image {
                mime: image.mime_type.clone(),
                bytes: image.bytes.clone(),
            };
        }
        // Publish content before taking ownership so a paste racing us sees
        // the new image.
        self.take_ownership()
    }

    fn image_mime_types(&self) -> Vec<String> {
        image_targets(&self.atoms)
            .into_iter()
            .map(|(_, m)| m.to_string())
            .collect()
    }

    fn subscribe_changes(&self) -> Receiver<ClipboardEvent> {
        self.subs.subscribe()
    }
}

impl X11Backend {
    fn take_ownership(&self) -> io::Result<()> {
        self.conn
            .set_selection_owner(self.win, self.atoms.CLIPBOARD, x11rb::CURRENT_TIME)
            .map_err(|e| io::Error::other(format!("take selection ownership: {e}")))?
            .check()
            .map_err(|e| io::Error::other(format!("take selection ownership: {e}")))
    }
}
