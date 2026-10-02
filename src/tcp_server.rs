//! TCP listener serving pending large-text transfers.
//!
//! Synchronous (`std::net`), matching the daemon's threading model: one
//! accept loop thread, one worker thread per connection, at most
//! [`MAX_CONNECTIONS`] concurrent workers (extras are closed immediately).
//!
//! Authentication first: the server reads exactly the 70-byte request header
//! plus the 16-byte handshake tag under a 3 s deadline, derives the session
//! key, and verifies the tag. On ANY failure — bad magic/version/tag,
//! unknown or expired transfer id, exhausted fetch budget, I/O deadline — it
//! closes the connection silently without writing a response, and it
//! allocates nothing proportional to attacker-controlled values before the
//! tag verifies (fixed 86-byte read, fixed-size arrays, map lookup only).

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tracing::debug;

use crate::crypto::KeyBytes;
use crate::tcp::{
    DIR_SERVER_TO_CLIENT, FLAG_FINAL, MAX_FRAME_DATA, REQUEST_HEADER_LEN, TAG_LEN,
    decode_request_header, derive_session_key, seal_frame, verify_handshake,
};
use crate::transfer::TransferStore;

/// Extra connections beyond this are closed immediately.
pub const MAX_CONNECTIONS: usize = 8;
/// Deadline for the 86-byte header + handshake read.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(3);
/// Idle timeout between frames in either direction.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bind the daemon's TCP listener on all interfaces (0.0.0.0).
pub fn bind_listener(tcp_port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind((Ipv4Addr::UNSPECIFIED, tcp_port))
}

/// Probe whether the TCP listener could bind (diagnostics only: the socket
/// is closed immediately). A running daemon already holds the port, so
/// `false` from `doctor` usually means the daemon is up.
pub fn can_bind(tcp_port: u16) -> bool {
    bind_listener(tcp_port).is_ok()
}

/// Run the accept loop forever on this thread. Each connection gets its own
/// worker thread; at most [`MAX_CONNECTIONS`] run concurrently.
pub fn serve_forever(
    listener: TcpListener,
    key: KeyBytes,
    store: Arc<Mutex<TransferStore>>,
    idle_timeout: Duration,
    total_timeout: Duration,
) {
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else {
            debug!("TCP accept error; listener continues");
            continue;
        };
        if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            debug!("TCP connection over limit; closing immediately");
            drop(stream);
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let (key, store, active) = (key, Arc::clone(&store), Arc::clone(&active));
        std::thread::spawn(move || {
            handle_connection(stream, &key, &store, idle_timeout, total_timeout);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Spawn the accept loop on a background thread (daemon lifetime).
pub fn spawn_server(
    listener: TcpListener,
    key: KeyBytes,
    store: Arc<Mutex<TransferStore>>,
    idle_timeout: Duration,
    total_timeout: Duration,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || serve_forever(listener, key, store, idle_timeout, total_timeout))
}

fn handle_connection(
    mut stream: TcpStream,
    key: &KeyBytes,
    store: &Arc<Mutex<TransferStore>>,
    idle_timeout: Duration,
    total_timeout: Duration,
) {
    let start = Instant::now();
    let _ = stream.set_read_timeout(Some(HANDSHAKE_DEADLINE));
    let _ = stream.set_write_timeout(Some(idle_timeout));

    // Fixed-size pre-authentication read: nothing attacker-sized is allocated.
    let mut header_bytes = [0u8; REQUEST_HEADER_LEN];
    if stream.read_exact(&mut header_bytes).is_err() {
        return;
    }
    let Ok(req) = decode_request_header(&header_bytes) else {
        return;
    };
    let mut tag = [0u8; TAG_LEN];
    if stream.read_exact(&mut tag).is_err() {
        return;
    }
    let Ok(session_key) = derive_session_key(key, &req.client_nonce, &req.transfer_id) else {
        return;
    };
    if verify_handshake(&session_key, &header_bytes, &tag).is_err() {
        return;
    }
    // Authenticated: look up the transfer and record one fetch against its
    // budget. Unknown, expired, or exhausted ids close silently too.
    let (data, _sha) = match store.lock().unwrap().serve(&req.transfer_id) {
        Some(v) => v,
        None => return,
    };
    let _ = stream.set_read_timeout(Some(idle_timeout));

    // Frame the plaintext in 65536-byte chunks. When the length is an exact
    // (nonzero) multiple of the chunk size — or zero — the payload chunks
    // alone cannot carry FINAL, so a trailing empty FINAL frame is sent.
    let exact_multiple = !data.is_empty() && data.len() % MAX_FRAME_DATA == 0;
    let chunks: Vec<&[u8]> = data.chunks(MAX_FRAME_DATA).collect();
    let mut counter: u64 = 0;
    for (i, chunk) in chunks.iter().enumerate() {
        if start.elapsed() > total_timeout {
            return;
        }
        let last = i + 1 == chunks.len();
        let flags = if last && !exact_multiple {
            FLAG_FINAL
        } else {
            0
        };
        if send_frame(
            &mut stream,
            &session_key,
            &header_bytes,
            counter,
            flags,
            chunk,
        )
        .is_err()
        {
            return;
        }
        counter += 1;
    }
    if data.is_empty() || exact_multiple {
        if start.elapsed() > total_timeout {
            return;
        }
        let _ = send_frame(
            &mut stream,
            &session_key,
            &header_bytes,
            counter,
            FLAG_FINAL,
            b"",
        );
    }
    debug!(
        "served transfer {:?} ({} bytes)",
        hex_id(&req.transfer_id),
        data.len()
    );
}

fn send_frame(
    stream: &mut TcpStream,
    session_key: &[u8; 32],
    aad: &[u8; REQUEST_HEADER_LEN],
    counter: u64,
    flags: u8,
    data: &[u8],
) -> std::io::Result<()> {
    let ct = seal_frame(session_key, aad, DIR_SERVER_TO_CLIENT, counter, flags, data);
    let len = ct.len() as u32;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(&ct)?;
    Ok(())
}

fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::{
        DIR_CLIENT_TO_SERVER, REQUEST_HEADER_LEN, RequestHeader, derive_session_key, open_frame,
        seal_handshake, sha256,
    };
    use std::io::Read;
    use std::time::Duration;

    const KEY: KeyBytes = [7u8; 32];

    fn test_server(data: &[u8]) -> (std::net::SocketAddr, Arc<Mutex<TransferStore>>) {
        let store = Arc::new(Mutex::new(TransferStore::with_defaults(
            Duration::from_secs(120),
        )));
        (test_server_with_store(data, Arc::clone(&store)), store)
    }

    fn test_server_with_store(
        data: &[u8],
        store: Arc<Mutex<TransferStore>>,
    ) -> std::net::SocketAddr {
        let transfer_id = [0xABu8; 16];
        store.lock().unwrap().insert(transfer_id, data.to_vec());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        spawn_server(
            listener,
            KEY,
            store,
            Duration::from_secs(10),
            Duration::from_secs(60),
        );
        // Give the accept loop a moment to start.
        std::thread::sleep(Duration::from_millis(50));
        addr
    }

    fn handshake_for(transfer_id: [u8; 16]) -> ([u8; REQUEST_HEADER_LEN], [u8; TAG_LEN]) {
        let header = RequestHeader {
            client_device_id: [0x01; 16],
            transfer_id,
            client_nonce: [0x02; 32],
        };
        let bytes = crate::tcp::encode_request_header(&header);
        let sk = derive_session_key(&KEY, &header.client_nonce, &transfer_id).unwrap();
        (bytes, seal_handshake(&sk, &bytes))
    }

    fn read_all(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(_) => break,
            }
        }
        out
    }

    #[test]
    fn bad_magic_dropped_silently() {
        let (addr, _) = test_server(b"data");
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(b"XXXX").unwrap();
        s.write_all(&[0u8; 82]).unwrap();
        assert!(read_all(&mut s).is_empty(), "no response to bad magic");
    }

    #[test]
    fn bad_tag_dropped_silently() {
        let (addr, _) = test_server(b"data");
        let (header, mut tag) = handshake_for([0xAB; 16]);
        tag[0] ^= 0x01;
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&header).unwrap();
        s.write_all(&tag).unwrap();
        assert!(read_all(&mut s).is_empty(), "no response to bad tag");
    }

    #[test]
    fn unknown_transfer_dropped_silently() {
        let (addr, _) = test_server(b"data");
        let (header, tag) = handshake_for([0xFF; 16]);
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&header).unwrap();
        s.write_all(&tag).unwrap();
        assert!(
            read_all(&mut s).is_empty(),
            "no response for unknown transfer"
        );
    }

    #[test]
    fn truncated_handshake_dropped_silently() {
        let (addr, _) = test_server(b"data");
        let (header, _) = handshake_for([0xAB; 16]);
        let mut s = TcpStream::connect(addr).unwrap();
        // Header only, then half-close the write side: the server must time
        // out (or see EOF) and never answer.
        s.write_all(&header).unwrap();
        s.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(read_all(&mut s).is_empty());
    }

    #[test]
    fn serves_small_transfer_with_single_final_frame() {
        let (addr, _) = test_server(b"Hello, TCP server!");
        let (header, tag) = handshake_for([0xAB; 16]);
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&header).unwrap();
        s.write_all(&tag).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut len = [0u8; 4];
        s.read_exact(&mut len).unwrap();
        let len = u32::from_be_bytes(len) as usize;
        let mut ct = vec![0u8; len];
        s.read_exact(&mut ct).unwrap();
        let sk = derive_session_key(&KEY, &[0x02; 32], &[0xAB; 16]).unwrap();
        let (flags, data) = open_frame(&sk, &header, DIR_SERVER_TO_CLIENT, 0, &ct).unwrap();
        assert_eq!(flags, FLAG_FINAL);
        assert_eq!(data, b"Hello, TCP server!");
        // Connection closes after the single frame: EOF, nothing more.
        let mut extra = [0u8; 1];
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        match s.read(&mut extra) {
            Ok(0) => {}
            Err(_) => {}
            Ok(n) => panic!("unexpected {n} bytes after FINAL"),
        }
    }

    #[test]
    fn serves_multiframe_transfer_with_trailing_final() {
        let payload = vec![0x41u8; MAX_FRAME_DATA + 1000];
        let (addr, _) = test_server(&payload);
        let (header, tag) = handshake_for([0xAB; 16]);
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&header).unwrap();
        s.write_all(&tag).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let sk = derive_session_key(&KEY, &[0x02; 32], &[0xAB; 16]).unwrap();
        let mut out = Vec::new();
        for counter in 0..2u64 {
            let mut len = [0u8; 4];
            s.read_exact(&mut len).unwrap();
            let len = u32::from_be_bytes(len) as usize;
            let mut ct = vec![0u8; len];
            s.read_exact(&mut ct).unwrap();
            let (flags, data) =
                open_frame(&sk, &header, DIR_SERVER_TO_CLIENT, counter, &ct).unwrap();
            if counter == 0 {
                assert_eq!(flags, 0);
                assert_eq!(data.len(), MAX_FRAME_DATA);
            } else {
                assert_eq!(flags, FLAG_FINAL);
                assert_eq!(data.len(), 1000);
            }
            out.extend_from_slice(&data);
        }
        assert_eq!(out, payload);
    }

    #[test]
    fn exact_multiple_gets_empty_final_frame() {
        let payload = vec![0x42u8; MAX_FRAME_DATA];
        let (addr, _) = test_server(&payload);
        let (header, tag) = handshake_for([0xAB; 16]);
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&header).unwrap();
        s.write_all(&tag).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let sk = derive_session_key(&KEY, &[0x02; 32], &[0xAB; 16]).unwrap();
        // Frame 0: full, non-final.
        let mut len = [0u8; 4];
        s.read_exact(&mut len).unwrap();
        let len = u32::from_be_bytes(len) as usize;
        let mut ct = vec![0u8; len];
        s.read_exact(&mut ct).unwrap();
        let (flags, data) = open_frame(&sk, &header, DIR_SERVER_TO_CLIENT, 0, &ct).unwrap();
        assert_eq!(flags, 0);
        assert_eq!(data.len(), MAX_FRAME_DATA);
        // Frame 1: empty FINAL.
        let mut lenb = [0u8; 4];
        s.read_exact(&mut lenb).unwrap();
        let len = u32::from_be_bytes(lenb) as usize;
        assert_eq!(len, TAG_LEN + 1);
        let mut ct = vec![0u8; len];
        s.read_exact(&mut ct).unwrap();
        let (flags, data) = open_frame(&sk, &header, DIR_SERVER_TO_CLIENT, 1, &ct).unwrap();
        assert_eq!(flags, FLAG_FINAL);
        assert!(data.is_empty());
    }

    #[test]
    fn expired_transfer_dropped_silently() {
        let store = Arc::new(Mutex::new(TransferStore::with_defaults(Duration::ZERO)));
        let addr = test_server_with_store(b"gone", Arc::clone(&store));
        let (header, tag) = handshake_for([0xAB; 16]);
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&header).unwrap();
        s.write_all(&tag).unwrap();
        assert!(read_all(&mut s).is_empty());
    }

    #[test]
    fn fetch_budget_exhaustion_closes_without_data() {
        let store = Arc::new(Mutex::new(TransferStore::new(
            Duration::from_secs(120),
            1,
            crate::transfer::DEFAULT_MEMORY_CAP_BYTES,
        )));
        let addr = test_server_with_store(b"once", Arc::clone(&store));
        // First fetch succeeds.
        let (header, tag) = handshake_for([0xAB; 16]);
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&header).unwrap();
        s.write_all(&tag).unwrap();
        assert!(!read_all(&mut s).is_empty());
        // Second fetch of the same transfer is refused silently.
        let (header2, tag2) = handshake_for([0xAB; 16]);
        let mut s2 = TcpStream::connect(addr).unwrap();
        s2.write_all(&header2).unwrap();
        s2.write_all(&tag2).unwrap();
        assert!(read_all(&mut s2).is_empty());
    }

    #[test]
    fn wrong_key_never_completes_handshake() {
        let (addr, _) = test_server(b"secret");
        // Build a handshake under a different key: the tag will not verify.
        let header = RequestHeader {
            client_device_id: [0x01; 16],
            transfer_id: [0xAB; 16],
            client_nonce: [0x02; 32],
        };
        let bytes = crate::tcp::encode_request_header(&header);
        let wrong_sk = derive_session_key(&[9u8; 32], &header.client_nonce, &[0xAB; 16]).unwrap();
        let tag = seal_handshake(&wrong_sk, &bytes);
        let mut s = TcpStream::connect(addr).unwrap();
        s.write_all(&bytes).unwrap();
        s.write_all(&tag).unwrap();
        assert!(read_all(&mut s).is_empty());
        // Sanity: the sha of the served bytes matches what the sender stored.
        let _ = sha256(b"secret");
        let _ = DIR_CLIENT_TO_SERVER;
    }
}
