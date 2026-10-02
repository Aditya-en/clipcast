//! IPv4 interface discovery and allow/deny filtering.

use std::net::Ipv4Addr;

use if_addrs::{IfAddr, get_if_addrs};

/// An IPv4 interface we can send broadcast datagrams from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IfaceTarget {
    pub name: String,
    /// Address the sending socket binds to.
    pub ip: Ipv4Addr,
    /// Directed broadcast address for the configured UDP port.
    pub broadcast: Ipv4Addr,
}

/// Simple glob matching supporting `*` (any run of characters).
/// Case-sensitive; `?` and character classes are not supported.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi = usize::MAX;
    let mut star_ti = 0usize;
    while ti < t.len() {
        if pi < p.len() && p[pi] == '*' {
            star_pi = pi;
            pi += 1;
            star_ti = ti;
        } else if pi < p.len() && p[pi] == t[ti] {
            pi += 1;
            ti += 1;
        } else if star_pi != usize::MAX {
            pi = star_pi + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// An interface is used iff (allow is empty or it matches an allow glob)
/// and it matches no deny glob. The deny list wins on conflict.
pub fn interface_allowed(name: &str, allow: &[String], deny: &[String]) -> bool {
    if !allow.is_empty() && !allow.iter().any(|p| glob_match(p, name)) {
        return false;
    }
    !deny.iter().any(|p| glob_match(p, name))
}

/// Enumerate IPv4 interfaces eligible for broadcast, each with its directed
/// broadcast address. Interfaces without a broadcast address (e.g. /32
/// point-to-point links) are skipped. If the kernel reports no broadcast
/// flag (loopback), the directed broadcast is computed from ip+netmask so a
/// `lo` allow-list entry works for same-machine testing.
pub fn discover(allow: &[String], deny: &[String]) -> Vec<IfaceTarget> {
    let mut targets = Vec::new();
    let Ok(ifaces) = get_if_addrs() else {
        return targets;
    };
    for iface in ifaces {
        if !interface_allowed(&iface.name, allow, deny) {
            continue;
        }
        let IfAddr::V4(v4) = iface.addr else {
            continue;
        };
        let broadcast = v4
            .broadcast
            .or_else(|| directed_broadcast(v4.ip, v4.netmask, v4.prefixlen));
        let Some(broadcast) = broadcast else {
            continue;
        };
        targets.push(IfaceTarget {
            name: iface.name,
            ip: v4.ip,
            broadcast,
        });
    }
    targets
}

/// ip | !netmask, only for prefixes that define a directed broadcast.
fn directed_broadcast(ip: Ipv4Addr, netmask: Ipv4Addr, prefixlen: u8) -> Option<Ipv4Addr> {
    if prefixlen >= 31 {
        return None;
    }
    let ip = u32::from(ip);
    let mask = u32::from(netmask);
    Some(Ipv4Addr::from(ip | !mask))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn glob_basics() {
        assert!(glob_match("lo", "lo"));
        assert!(!glob_match("lo", "eth0"));
        assert!(glob_match("docker*", "docker0"));
        assert!(glob_match("docker*", "docker"));
        assert!(!glob_match("docker*", "br-abc"));
        assert!(glob_match("br-*", "br-1a2b3c"));
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
        assert!(glob_match("veth*", "veth123"));
        assert!(glob_match("tun*", "tun0"));
        assert!(glob_match("tap*", "tap7"));
        assert!(glob_match("virbr*", "virbr0"));
        assert!(glob_match("*br*", "virbr0"));
        assert!(glob_match("wlp*", "wlp4s0"));
        assert!(!glob_match("wlp*", "wlan0"));
        assert!(glob_match("a*b*c", "axxbyyc"));
        assert!(!glob_match("a*b*c", "axxc"));
    }

    #[test]
    fn default_deny_blocks_virtual_interfaces() {
        let deny = strings(&["lo", "docker*", "br-*", "veth*", "virbr*", "tun*", "tap*"]);
        let allow: Vec<String> = vec![];
        assert!(!interface_allowed("lo", &allow, &deny));
        assert!(!interface_allowed("docker0", &allow, &deny));
        assert!(!interface_allowed("br-9f3e2d", &allow, &deny));
        assert!(!interface_allowed("veth77ab", &allow, &deny));
        assert!(!interface_allowed("virbr1", &allow, &deny));
        assert!(!interface_allowed("tun0", &allow, &deny));
        assert!(!interface_allowed("tap0", &allow, &deny));
        assert!(interface_allowed("wlp4s0", &allow, &deny));
        assert!(interface_allowed("enp3s0", &allow, &deny));
    }

    #[test]
    fn allow_list_restricts_to_matches() {
        let deny: Vec<String> = vec![];
        let allow = strings(&["wlp*", "en*"]);
        assert!(interface_allowed("wlp4s0", &allow, &deny));
        assert!(interface_allowed("enp3s0", &allow, &deny));
        assert!(!interface_allowed("eth1", &allow, &deny));
    }

    #[test]
    fn deny_wins_over_allow() {
        let allow = strings(&["docker*"]);
        let deny = strings(&["docker*"]);
        assert!(!interface_allowed("docker0", &allow, &deny));
    }

    #[test]
    fn discovery_targets_pass_the_filter() {
        let allow: Vec<String> = vec![];
        let deny = strings(&["lo", "docker*", "br-*", "veth*", "virbr*", "tun*", "tap*"]);
        let targets = discover(&allow, &deny);
        for t in &targets {
            assert!(!t.broadcast.is_unspecified());
            assert!(interface_allowed(&t.name, &allow, &deny));
            assert_ne!(t.name, "lo", "default deny must exclude loopback");
        }
    }

    #[test]
    fn discovery_finds_loopback_when_allowed() {
        // Used by the two-instances-on-one-machine manual test setup: loopback
        // has no IFF_BROADCAST, so the directed broadcast must be computed.
        let allow = strings(&["lo"]);
        let deny: Vec<String> = vec![];
        let targets = discover(&allow, &deny);
        let lo = targets
            .iter()
            .find(|t| t.name == "lo")
            .expect("loopback listed when allowed");
        assert_eq!(lo.ip, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(lo.broadcast, Ipv4Addr::new(127, 255, 255, 255));
    }

    #[test]
    fn directed_broadcast_computation() {
        assert_eq!(
            directed_broadcast(
                Ipv4Addr::new(10, 0, 0, 5),
                Ipv4Addr::new(255, 255, 255, 0),
                24
            ),
            Some(Ipv4Addr::new(10, 0, 0, 255))
        );
        assert_eq!(
            directed_broadcast(
                Ipv4Addr::new(192, 168, 1, 7),
                Ipv4Addr::new(255, 255, 0, 0),
                16
            ),
            Some(Ipv4Addr::new(192, 168, 255, 255))
        );
        // /31 and /32 have no directed broadcast.
        assert_eq!(
            directed_broadcast(
                Ipv4Addr::new(100, 64, 0, 1),
                Ipv4Addr::new(255, 255, 255, 255),
                32
            ),
            None
        );
        assert_eq!(
            directed_broadcast(
                Ipv4Addr::new(100, 64, 0, 1),
                Ipv4Addr::new(255, 255, 255, 254),
                31
            ),
            None
        );
    }
}
