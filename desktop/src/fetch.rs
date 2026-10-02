//! TCP fetch client (receiver side of a large-text transfer).
//!
//! Synchronous (`std::net`), matching the daemon's threading model. The
//! caller supplies the announce's UDP source IP — never any other address —
//! and the transfer metadata from the (already authenticated and ordered)
//! announce. Timeouts: 3 s connect, 10 s idle between frames, overall
//! `fetch_timeout_secs` (default 120 s). Cancellation is cooperative via an
//! atomic flag set by the engine when a newer message wins.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use rand::TryRng as _;
use rand::rngs::SysRng;
use tracing::debug;

use crate::crypto::KeyBytes;
use crate::tcp::{
    CLIENT_NONCE_LEN, DIR_SERVER_TO_CLIENT, MAX_FRAME_CIPHERTEXT, REQUEST_HEADER_LEN,
    RequestHeader, TcpError, derive_session_key, encode_request_header, open_frame, seal_handshake,
};
use crate::tcp::{FrameAssembler, verify_content};

/// Deadline for TCP connect.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Idle timeout between frames.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone)]
pub struct FetchParams {
    pub key: KeyBytes,
    pub client_device_id: [u8; 16],
    /// The announce datagram's source IP. Nothing else is ever dialed.
    pub server_ip: IpAddr,
    pub tcp_port: u16,
    pub transfer_id: [u8; 16],
    pub total_len: u64,
    pub expected_sha256: [u8; 32],
    pub inner_content_type: u8,
    pub max_transfer_bytes: u64,
    pub total_timeout: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error("transfer len {0} exceeds max_transfer_bytes {1}")]
    OverLimit(u64, u64),
    #[error("cancelled: a newer message was accepted")]
    Cancelled,
    #[error("connect to {0} failed: {1}")]
    Connect(SocketAddr, std::io::Error),
    #[error("I/O during fetch: {0}")]
    Io(#[from] std::io::Error),
    #[error("fetch timed out")]
    Timeout,
    #[error("frame protocol violation: {0}")]
    Protocol(#[from] TcpError),
}

impl FetchParams {
    /// 64 MiB default ceiling for one transfer.
    pub const DEFAULT_MAX_TRANSFER_BYTES: u64 = 64 * 1024 * 1024;
}

/// Fetch one transfer to completion. Returns the plaintext content bytes on
/// success; on any failure returns an error and the caller applies nothing.
pub fn fetch_transfer(params: &FetchParams, cancel: &AtomicBool) -> Result<Vec<u8>, FetchError> {
    if params.total_len > params.max_transfer_bytes {
        return Err(FetchError::OverLimit(
            params.total_len,
            params.max_transfer_bytes,
        ));
    }
    if cancel.load(Ordering::SeqCst) {
        return Err(FetchError::Cancelled);
    }
    let start = Instant::now();
    let addr = SocketAddr::new(params.server_ip, params.tcp_port);

    let mut client_nonce = [0u8; CLIENT_NONCE_LEN];
    SysRng
        .try_fill_bytes(&mut client_nonce)
        .expect("getrandom failed");
    let header = RequestHeader {
        client_device_id: params.client_device_id,
        transfer_id: params.transfer_id,
        client_nonce,
    };
    let header_bytes: [u8; REQUEST_HEADER_LEN] = encode_request_header(&header);
    let session_key = derive_session_key(&params.key, &client_nonce, &params.transfer_id)?;
    let tag = seal_handshake(&session_key, &header_bytes);

    let mut stream = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
        .map_err(|e| FetchError::Connect(addr, e))?;
    stream.set_read_timeout(Some(IDLE_TIMEOUT))?;
    stream.set_write_timeout(Some(IDLE_TIMEOUT))?;
    stream.write_all(&header_bytes)?;
    stream.write_all(&tag)?;
    debug!("TCP fetch started: {addr} total_len={}", params.total_len);

    // Pre-sized buffer: total_len was capped above, and the assembler never
    // lets the buffer grow past it.
    let mut assembler = FrameAssembler::new(params.total_len);
    let mut counter: u64 = 0;
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(FetchError::Cancelled);
        }
        if start.elapsed() > params.total_timeout {
            return Err(FetchError::Timeout);
        }
        let mut lenb = [0u8; 4];
        read_exact_or(&mut stream, &mut lenb, &start, params.total_timeout)?;
        let len = u32::from_be_bytes(lenb) as usize;
        if len > MAX_FRAME_CIPHERTEXT {
            return Err(TcpError::FrameTooLong(len).into());
        }
        let mut ct = vec![0u8; len];
        read_exact_or(&mut stream, &mut ct, &start, params.total_timeout)?;
        let (flags, data) = open_frame(
            &session_key,
            &header_bytes,
            DIR_SERVER_TO_CLIENT,
            counter,
            &ct,
        )?;
        counter += 1;
        if assembler.feed(flags, &data, counter - 1)? {
            break;
        }
    }
    let data = assembler.finish()?;

    // Exactly one FINAL frame and nothing after it: the server must close.
    // Our own server always closes; a lingering connection is suspicious.
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut extra = [0u8; 1];
    match stream.read(&mut extra) {
        Ok(0) => {}
        Ok(_) => return Err(TcpError::DataAfterFinal.into()),
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e)
            if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::WouldBlock =>
        {
            return Err(FetchError::Timeout);
        }
        Err(e) => return Err(FetchError::Io(e)),
    }

    verify_content(
        &data,
        params.total_len,
        &params.expected_sha256,
        params.inner_content_type,
    )?;
    debug!("TCP fetch complete: {} bytes verified", data.len());
    Ok(data)
}

fn read_exact_or(
    stream: &mut TcpStream,
    mut buf: &mut [u8],
    start: &Instant,
    total: Duration,
) -> Result<(), FetchError> {
    while !buf.is_empty() {
        if start.elapsed() > total {
            return Err(FetchError::Timeout);
        }
        match stream.read(buf) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-frame",
                )
                .into());
            }
            Ok(n) => buf = &mut buf[n..],
            Err(e)
                if e.kind() == std::io::ErrorKind::Interrupted
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                return Err(FetchError::Timeout);
            }
            Err(e) => return Err(FetchError::Io(e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tcp::{FLAG_FINAL, MAX_FRAME_DATA, seal_frame, sha256};
    use crate::transfer::TransferStore;
    use std::net::{Ipv4Addr, TcpListener};
    use std::sync::{Arc, Mutex};

    const KEY: KeyBytes = [7u8; 32];

    fn serving_store(data: &[u8], id: [u8; 16]) -> Arc<Mutex<TransferStore>> {
        let store = Arc::new(Mutex::new(TransferStore::with_defaults(
            Duration::from_secs(120),
        )));
        store.lock().unwrap().insert(id, data.to_vec());
        store
    }

    fn params_for(addr: SocketAddr, id: [u8; 16], total_len: u64, sha: [u8; 32]) -> FetchParams {
        FetchParams {
            key: KEY,
            client_device_id: [0x01; 16],
            server_ip: addr.ip(),
            tcp_port: addr.port(),
            transfer_id: id,
            total_len,
            expected_sha256: sha,
            inner_content_type: crate::proto::INNER_TEXT,
            max_transfer_bytes: FetchParams::DEFAULT_MAX_TRANSFER_BYTES,
            total_timeout: Duration::from_secs(30),
        }
    }

    /// Raw stub server: performs the real handshake, then replays canned
    /// *plaintext* frames sealed under the live session key (wrong-hash /
    /// truncation / extra-data scenarios). Frames are (flags, data).
    fn stub_server(frames: Vec<(u8, Vec<u8>)>, key: KeyBytes) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut pre = [0u8; REQUEST_HEADER_LEN + 16];
            if s.read_exact(&mut pre).is_err() {
                return;
            }
            let header: [u8; REQUEST_HEADER_LEN] = pre[..REQUEST_HEADER_LEN].try_into().unwrap();
            let Ok(req) = crate::tcp::decode_request_header(&header) else {
                return;
            };
            let Ok(sk) = derive_session_key(&key, &req.client_nonce, &req.transfer_id) else {
                return;
            };
            if crate::tcp::verify_handshake(&sk, &header, &pre[REQUEST_HEADER_LEN..]).is_err() {
                return;
            }
            for (counter, (flags, data)) in frames.into_iter().enumerate() {
                let f = seal_frame(
                    &sk,
                    &header,
                    DIR_SERVER_TO_CLIENT,
                    counter as u64,
                    flags,
                    &data,
                );
                if s.write_all(&(f.len() as u32).to_be_bytes()).is_err() {
                    return;
                }
                if s.write_all(&f).is_err() {
                    return;
                }
            }
            // Hold the connection briefly so "data after FINAL" is observable,
            // then close.
            std::thread::sleep(Duration::from_millis(300));
        });
        addr
    }

    #[test]
    fn fetch_small_transfer_loopback() {
        let id = [0xABu8; 16];
        let data = b"fetch me over TCP";
        let store = serving_store(data, id);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let (images, _dir) = crate::image_cache::temp_image_cache(Duration::from_secs(120), 20);
        crate::tcp_server::spawn_server(
            listener,
            KEY,
            store,
            Some(images),
            Duration::from_secs(10),
            Duration::from_secs(30),
        );
        std::thread::sleep(Duration::from_millis(50));
        let params = params_for(addr, id, data.len() as u64, sha256(data));
        let cancel = AtomicBool::new(false);
        assert_eq!(fetch_transfer(&params, &cancel).unwrap(), data);
    }

    #[test]
    fn fetch_multiframe_transfer_loopback() {
        let id = [0xCDu8; 16];
        let data = vec![0x41u8; MAX_FRAME_DATA + 5000];
        let sha = sha256(&data);
        let store = serving_store(&data, id);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let (images, _dir) = crate::image_cache::temp_image_cache(Duration::from_secs(120), 20);
        crate::tcp_server::spawn_server(
            listener,
            KEY,
            store,
            Some(images),
            Duration::from_secs(10),
            Duration::from_secs(60),
        );
        std::thread::sleep(Duration::from_millis(50));
        let params = params_for(addr, id, data.len() as u64, sha);
        let cancel = AtomicBool::new(false);
        assert_eq!(fetch_transfer(&params, &cancel).unwrap(), data);
    }

    #[test]
    fn wrong_key_never_completes() {
        let id = [0xABu8; 16];
        let data = b"secret bytes";
        let store = serving_store(data, id);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let (images, _dir) = crate::image_cache::temp_image_cache(Duration::from_secs(120), 20);
        crate::tcp_server::spawn_server(
            listener,
            KEY,
            store,
            Some(images),
            Duration::from_secs(10),
            Duration::from_secs(30),
        );
        std::thread::sleep(Duration::from_millis(50));
        let mut params = params_for(addr, id, data.len() as u64, sha256(data));
        params.key = [9u8; 32];
        let cancel = AtomicBool::new(false);
        let err = fetch_transfer(&params, &cancel).unwrap_err();
        assert!(
            matches!(err, FetchError::Io(_) | FetchError::Timeout),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn wrong_hash_rejected_after_full_receipt() {
        let id = [0xABu8; 16];
        let data = b"real bytes";
        let store = serving_store(data, id);
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let (images, _dir) = crate::image_cache::temp_image_cache(Duration::from_secs(120), 20);
        crate::tcp_server::spawn_server(
            listener,
            KEY,
            store,
            Some(images),
            Duration::from_secs(10),
            Duration::from_secs(30),
        );
        std::thread::sleep(Duration::from_millis(50));
        let params = params_for(addr, id, data.len() as u64, [0xFF; 32]);
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            fetch_transfer(&params, &cancel),
            Err(FetchError::Protocol(TcpError::HashMismatch))
        ));
    }

    #[test]
    fn over_limit_rejected_without_connecting() {
        // Nothing listens here; an over-limit fetch must fail before dialing.
        let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), 9);
        let params = FetchParams {
            max_transfer_bytes: 100,
            ..params_for(addr, [0xABu8; 16], 101, [0u8; 32])
        };
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            fetch_transfer(&params, &cancel),
            Err(FetchError::OverLimit(101, 100))
        ));
    }

    #[test]
    fn pre_cancelled_fetch_does_not_connect() {
        let addr = SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), 9);
        let params = params_for(addr, [0xABu8; 16], 10, [0u8; 32]);
        let cancel = AtomicBool::new(true);
        assert!(matches!(
            fetch_transfer(&params, &cancel),
            Err(FetchError::Cancelled)
        ));
    }

    #[test]
    fn missing_final_aborts() {
        // Stub sends one full non-final frame for a 65536+5 transfer, then
        // closes: the client must abort, never returning partial data.
        let total = MAX_FRAME_DATA as u64 + 5;
        let key = KEY;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut pre = [0u8; REQUEST_HEADER_LEN + 16];
            if s.read_exact(&mut pre).is_err() {
                return;
            }
            let hb: [u8; REQUEST_HEADER_LEN] = pre[..REQUEST_HEADER_LEN].try_into().unwrap();
            let req = crate::tcp::decode_request_header(&hb).unwrap();
            let sk = derive_session_key(&key, &req.client_nonce, &req.transfer_id).unwrap();
            assert!(crate::tcp::verify_handshake(&sk, &hb, &pre[REQUEST_HEADER_LEN..]).is_ok());
            // One non-final full frame, then EOF with no FINAL.
            let ct = seal_frame(
                &sk,
                &hb,
                DIR_SERVER_TO_CLIENT,
                0,
                0,
                &vec![7u8; MAX_FRAME_DATA],
            );
            s.write_all(&(ct.len() as u32).to_be_bytes()).unwrap();
            s.write_all(&ct).unwrap();
            // Close without FINAL.
        });
        let params = params_for(addr, [0xEE; 16], total, [0u8; 32]);
        let cancel = AtomicBool::new(false);
        let err = fetch_transfer(&params, &cancel).unwrap_err();
        assert!(
            matches!(
                err,
                FetchError::Io(_) | FetchError::Protocol(TcpError::MissingFinal)
            ),
            "unexpected: {err:?}"
        );
    }

    #[test]
    fn data_after_final_aborts() {
        let data = b"exact";
        let sha = sha256(data);
        // Stub sends a FINAL frame followed by one extra byte on the wire.
        let key = KEY;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut pre = [0u8; REQUEST_HEADER_LEN + 16];
            if s.read_exact(&mut pre).is_err() {
                return;
            }
            let hb: [u8; REQUEST_HEADER_LEN] = pre[..REQUEST_HEADER_LEN].try_into().unwrap();
            let req = crate::tcp::decode_request_header(&hb).unwrap();
            let sk = derive_session_key(&key, &req.client_nonce, &req.transfer_id).unwrap();
            assert!(crate::tcp::verify_handshake(&sk, &hb, &pre[REQUEST_HEADER_LEN..]).is_ok());
            let ct = seal_frame(&sk, &hb, DIR_SERVER_TO_CLIENT, 0, FLAG_FINAL, data);
            s.write_all(&(ct.len() as u32).to_be_bytes()).unwrap();
            s.write_all(&ct).unwrap();
            s.write_all(b"X").unwrap();
            std::thread::sleep(Duration::from_millis(500));
        });
        let params = params_for(addr, [0xEF; 16], data.len() as u64, sha);
        let cancel = AtomicBool::new(false);
        assert!(matches!(
            fetch_transfer(&params, &cancel),
            Err(FetchError::Protocol(TcpError::DataAfterFinal))
        ));
    }

    #[test]
    fn stub_server_helper_serves_canned_frames() {
        // Exercises the shared canned-frame stub used for negative tests.
        let data = b"canned";
        let addr = stub_server(vec![(FLAG_FINAL, data.to_vec())], KEY);
        let total = data.len() as u64;
        let mut params = params_for(addr, [0xF0; 16], total, sha256(data));
        params.total_timeout = Duration::from_secs(10);
        let cancel = AtomicBool::new(false);
        assert_eq!(fetch_transfer(&params, &cancel).unwrap(), data);
    }
}
