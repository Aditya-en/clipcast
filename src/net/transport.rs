//! UDP transport: broadcast send per interface, one shared receive socket.
//!
//! The receive socket binds `0.0.0.0:port` with SO_REUSEADDR + SO_REUSEPORT
//! so several instances can run on one machine for testing (Linux delivers
//! broadcast datagrams to every socket in the reuse group).
//!
//! Sending enumerates interfaces every ~30 s (laptops roam), binds one socket
//! per eligible interface IP and sends to that interface's directed broadcast
//! address. Per-interface send errors are logged at debug and never fatal.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing::debug;

use crate::net::interfaces::discover;

pub const REFRESH_INTERVAL: Duration = Duration::from_secs(30);
const RECV_BUF: usize = 2048;

struct SendTarget {
    iface: String,
    socket: Socket,
    dest: SocketAddrV4,
}

struct Inner {
    port: u16,
    allow: Vec<String>,
    deny: Vec<String>,
    targets: Mutex<Vec<SendTarget>>,
    rx: Mutex<Option<Receiver<Vec<u8>>>>,
    refresh: Duration,
}

pub struct UdpTransport {
    inner: Arc<Inner>,
}

impl UdpTransport {
    pub fn new(port: u16, allow: Vec<String>, deny: Vec<String>) -> std::io::Result<Self> {
        Self::with_refresh(port, allow, deny, REFRESH_INTERVAL)
    }

    pub fn with_refresh(
        port: u16,
        allow: Vec<String>,
        deny: Vec<String>,
        refresh: Duration,
    ) -> std::io::Result<Self> {
        // Receive socket: one per process, shareable across instances.
        let recv_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
        recv_sock.set_reuse_address(true)?;
        recv_sock.set_reuse_port(true)?;
        recv_sock.set_broadcast(true)?;
        recv_sock.bind(&SockAddr::from(SocketAddr::from((
            Ipv4Addr::UNSPECIFIED,
            port,
        ))))?;
        let recv_sock: std::net::UdpSocket = recv_sock.into();

        let (tx, rx) = channel::<Vec<u8>>();
        std::thread::spawn(move || {
            let mut buf = [0u8; RECV_BUF];
            loop {
                match recv_sock.recv(&mut buf) {
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break;
                        }
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        debug!("receive socket closed: {e}");
                        break;
                    }
                }
            }
        });

        let inner = Arc::new(Inner {
            port,
            allow,
            deny,
            targets: Mutex::new(Vec::new()),
            rx: Mutex::new(Some(rx)),
            refresh,
        });
        rebuild_targets(&inner);

        let refresh_inner = Arc::clone(&inner);
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(refresh_inner.refresh);
                rebuild_targets(&refresh_inner);
            }
        });

        Ok(Self { inner })
    }
}

impl crate::engine::Transport for UdpTransport {
    fn send(&self, bytes: &[u8]) {
        let targets = self.inner.targets.lock().unwrap();
        for target in targets.iter() {
            let dest = SockAddr::from(target.dest);
            if let Err(e) = target.socket.send_to(bytes, &dest) {
                debug!("send via {} to {} failed: {e}", target.iface, target.dest);
            }
        }
    }

    fn recv(&self) -> Receiver<Vec<u8>> {
        self.inner
            .rx
            .lock()
            .unwrap()
            .take()
            .expect("UdpTransport::recv called twice")
    }
}

/// Re-enumerate interfaces and replace the send sockets. Send errors for
/// individual interfaces are logged at debug and never fatal.
fn rebuild_targets(inner: &Inner) {
    let fresh = discover(&inner.allow, &inner.deny);
    let mut targets = Vec::with_capacity(fresh.len());
    for t in fresh {
        let socket = match Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)) {
            Ok(s) => s,
            Err(e) => {
                debug!("cannot create send socket for {}: {e}", t.name);
                continue;
            }
        };
        if let Err(e) = socket.set_broadcast(true) {
            debug!("set_broadcast on {}: {e}", t.name);
            continue;
        }
        if let Err(e) = socket.bind(&SockAddr::from(SocketAddr::from((t.ip, 0)))) {
            debug!("cannot bind {} to {}: {e}", t.name, t.ip);
            continue;
        }
        targets.push(SendTarget {
            iface: t.name,
            socket,
            dest: SocketAddrV4::new(t.broadcast, inner.port),
        });
    }
    *inner.targets.lock().unwrap() = targets;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::Transport;

    fn test_transport(port: u16) -> UdpTransport {
        UdpTransport::new(port, vec!["lo".into()], vec![]).expect("bind loopback test port")
    }

    /// Two instances on one machine: SO_REUSEPORT + broadcast delivers the
    /// same datagram to every socket in the group (verified on Linux).
    #[test]
    fn loopback_send_reaches_both_instances() {
        let port = 47481;
        let a = test_transport(port);
        let b = test_transport(port);
        let rx_a = a.recv();
        let rx_b = b.recv();

        a.send(b"ping-from-a");

        let got_b = rx_b
            .recv_timeout(Duration::from_secs(2))
            .expect("b receives");
        assert_eq!(got_b, b"ping-from-a");
        let got_a = rx_a
            .recv_timeout(Duration::from_secs(2))
            .expect("a receives own broadcast");
        assert_eq!(got_a, b"ping-from-a");
    }

    #[test]
    fn discovery_error_is_not_fatal_to_send() {
        let port = 47482;
        // No eligible interface in an empty-filter setup is fine: send is a no-op.
        let t = UdpTransport::new(port, vec!["this-iface-does-not-exist".into()], vec![])
            .expect("transport constructs");
        t.send(b"nobody-listens"); // must not panic or block
    }
}
