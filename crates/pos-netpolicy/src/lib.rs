//! Text-only generator for a per-UID nftables OUTPUT allow-list.
//!
//! This crate only builds strings. It never runs `nft`, `systemctl` or any
//! other program, never reads or writes a file, and never touches the network.
//! See `docs/NETPOLICY.md` for exactly what the output does and does not do.
#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Name of the one nftables table this crate ever mentions.
pub const TABLE: &str = "passaura_netpolicy";
/// Upper bound on allowed destinations in one policy.
pub const MAX_TARGETS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// UID 0, or the 32-bit "no uid" value.
    InvalidUid(u32),
    /// Not an IP address or CIDR. Host names are never accepted.
    NotAnIpOrCidr(String),
    /// Prefix length missing a number, out of range, or 0.
    BadPrefix(String),
    /// The address has bits set below the prefix (for example 10.0.0.1/8).
    HostBitsSet(String),
    /// Loopback, unspecified, multicast, broadcast, 240.0.0.0/4 or IPv4-mapped IPv6 destination in the allow list.
    ReservedTarget(String),
    TooManyTargets(usize),
    /// Resolver is loopback, unspecified or multicast.
    BadResolver(String),
    /// A path for the systemd unit is not absolute or has unsafe characters.
    BadPath(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::InvalidUid(u) => write!(f, "invalid dedicated uid {u}: it must be a numeric uid other than 0 and 4294967295"),
            PolicyError::NotAnIpOrCidr(s) => write!(f, "not an IP address or CIDR (host names are not accepted): {s:?}"),
            PolicyError::BadPrefix(s) => write!(f, "bad prefix length (1..=32 for IPv4, 1..=128 for IPv6): {s:?}"),
            PolicyError::HostBitsSet(s) => write!(f, "address has host bits set below the prefix: {s:?}"),
            PolicyError::ReservedTarget(s) => write!(f, "loopback, unspecified and multicast targets are not allowed in the list (use the explicit exceptions): {s:?}"),
            PolicyError::TooManyTargets(n) => write!(f, "too many targets: {n} (maximum {MAX_TARGETS})"),
            PolicyError::BadResolver(s) => write!(f, "resolver must be a unicast, non-loopback IP address: {s:?}"),
            PolicyError::BadPath(s) => write!(f, "path must be absolute and only use letters, digits and / . _ -: {s:?}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// One allowed destination network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Target {
    V4(Ipv4Addr, u8),
    V6(Ipv6Addr, u8),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::V4(a, p) => write!(f, "{a}/{p}"),
            Target::V6(a, p) => write!(f, "{a}/{p}"),
        }
    }
}

fn mask4(p: u8) -> u32 {
    if p == 0 {
        0
    } else {
        u32::MAX << (32 - p as u32)
    }
}
fn mask6(p: u8) -> u128 {
    if p == 0 {
        0
    } else {
        u128::MAX << (128 - p as u32)
    }
}

/// Parses `a.b.c.d`, `a.b.c.d/len`, an IPv6 address, or `addr/len`.
/// A bare address means /32 or /128. Host names are rejected.
pub fn parse_target(s: &str) -> Result<Target, PolicyError> {
    let (addr_s, prefix_s) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    let addr: IpAddr = addr_s
        .parse()
        .map_err(|_| PolicyError::NotAnIpOrCidr(s.to_string()))?;
    let max = if addr.is_ipv4() { 32u8 } else { 128u8 };
    let prefix = match prefix_s {
        None => max,
        Some(p) => {
            if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.len() > 3 {
                return Err(PolicyError::BadPrefix(s.to_string()));
            }
            let n: u16 = p
                .parse()
                .map_err(|_| PolicyError::BadPrefix(s.to_string()))?;
            if n == 0 || n > max as u16 {
                return Err(PolicyError::BadPrefix(s.to_string()));
            }
            n as u8
        }
    };
    match addr {
        IpAddr::V4(a) => {
            if a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_broadcast() {
                return Err(PolicyError::ReservedTarget(s.to_string()));
            }
            if u32::from(a) & !mask4(prefix) != 0 {
                return Err(PolicyError::HostBitsSet(s.to_string()));
            }
            // A network that overlaps loopback or multicast (for example 0.0.0.0/1) is also refused.
            let net = u32::from(a);
            let last = net | !mask4(prefix);
            if overlaps4(net, last, 0x7f00_0000, 0x7fff_ffff)
                || overlaps4(net, last, 0xe000_0000, 0xefff_ffff)
                || overlaps4(net, last, 0, 0)
                // 240.0.0.0/4 (reserved, includes 255.255.255.255)
                || overlaps4(net, last, 0xf000_0000, 0xffff_ffff)
            {
                return Err(PolicyError::ReservedTarget(s.to_string()));
            }
            Ok(Target::V4(a, prefix))
        }
        IpAddr::V6(a) => {
            if a.is_loopback() || a.is_unspecified() || a.is_multicast() {
                return Err(PolicyError::ReservedTarget(s.to_string()));
            }
            if u128::from(a) & !mask6(prefix) != 0 {
                return Err(PolicyError::HostBitsSet(s.to_string()));
            }
            let net = u128::from(a);
            let last = net | !mask6(prefix);
            // ::ffff:0:0/96 (IPv4-mapped) is refused too: it is not a real IPv6 destination.
            let mapped0 = 0xffffu128 << 32;
            let mapped1 = mapped0 | 0xffff_ffff;
            if overlaps6(net, last, 1, 1)
                || overlaps6(net, last, 0, 0)
                || overlaps6(net, last, 0xff00u128 << 112, u128::MAX)
                || overlaps6(net, last, mapped0, mapped1)
            {
                return Err(PolicyError::ReservedTarget(s.to_string()));
            }
            Ok(Target::V6(a, prefix))
        }
    }
}

fn overlaps4(a0: u32, a1: u32, b0: u32, b1: u32) -> bool {
    a0 <= b1 && b0 <= a1
}
fn overlaps6(a0: u128, a1: u128, b0: u128, b1: u128) -> bool {
    a0 <= b1 && b0 <= a1
}

/// The policy for ONE dedicated numeric uid. Every exception is off by default.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Numeric uid whose OUTPUT traffic is restricted. Never a user name.
    pub uid: u32,
    /// Allowed destination networks. Everything else from this uid is dropped.
    pub allow: Vec<Target>,
    /// The ONE named DNS resolver (udp/53 and tcp/53 only). None = no DNS exception.
    pub dns_resolver: Option<IpAddr>,
    /// Allow this uid's packets out of the `lo` interface.
    pub allow_loopback: bool,
    /// IPv6 neighbor/router discovery packets (types 133, 135, 136, hop limit 255)
    /// to fe80::/10 and ff02::/16 only.
    pub allow_ipv6_nd: bool,
    /// DHCPv4 client discovery/request to the broadcast address (udp 68 to 67,
    /// 255.255.255.255 only) and DHCPv6 client (udp 546 to 547, ff02::1:2 only).
    /// Unicast renewals to a server are NOT covered.
    pub allow_dhcp: bool,
}

impl Policy {
    /// A policy with no exceptions and no allowed destinations.
    pub fn new(uid: u32) -> Policy {
        Policy {
            uid,
            allow: Vec::new(),
            dns_resolver: None,
            allow_loopback: false,
            allow_ipv6_nd: false,
            allow_dhcp: false,
        }
    }

    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.uid == 0 || self.uid == u32::MAX {
            return Err(PolicyError::InvalidUid(self.uid));
        }
        if self.allow.len() > MAX_TARGETS {
            return Err(PolicyError::TooManyTargets(self.allow.len()));
        }
        if let Some(r) = self.dns_resolver {
            let bad = match r {
                IpAddr::V4(a) => {
                    a.is_loopback() || a.is_unspecified() || a.is_multicast() || a.is_broadcast()
                }
                IpAddr::V6(a) => a.is_loopback() || a.is_unspecified() || a.is_multicast(),
            };
            if bad {
                return Err(PolicyError::BadResolver(r.to_string()));
            }
        }
        Ok(())
    }
}

fn sorted_unique(allow: &[Target]) -> Vec<Target> {
    let mut v = allow.to_vec();
    v.sort();
    v.dedup();
    v
}

/// Renders the nftables script. Loading it replaces ONLY table
/// `inet passaura_netpolicy` (one atomic transaction); it never flushes or
/// deletes anything else. Output is deterministic.
pub fn render_nft(p: &Policy) -> Result<String, PolicyError> {
    p.validate()?;
    let uid = p.uid;
    let targets = sorted_unique(&p.allow);
    let v4: Vec<String> = targets
        .iter()
        .filter_map(|t| {
            if let Target::V4(..) = t {
                Some(t.to_string())
            } else {
                None
            }
        })
        .collect();
    let v6: Vec<String> = targets
        .iter()
        .filter_map(|t| {
            if let Target::V6(..) = t {
                Some(t.to_string())
            } else {
                None
            }
        })
        .collect();

    let mut o = String::new();
    o.push_str("# Generated by pos-netpolicy. Not applied by this crate. Review before loading.\n");
    o.push_str(&format!("# Restricts OUTPUT traffic of numeric uid {uid} only. No INPUT rules. No global default-drop.\n"));
    o.push_str("# Replaces only the table below; other tables and rules are untouched.\n");
    o.push_str("# FAIL-OPEN: if this script fails to load, or is never loaded, the uid is NOT restricted.\n");
    o.push_str(&format!("add table inet {TABLE}\n"));
    o.push_str(&format!("delete table inet {TABLE}\n"));
    o.push_str(&format!("table inet {TABLE} {{\n"));
    o.push_str(&format!("\tchain uid_{uid}_out {{\n"));
    if p.allow_loopback {
        o.push_str("\t\t# exception: loopback, this uid only\n");
        o.push_str("\t\toifname \"lo\" accept\n");
    }
    if let Some(r) = p.dns_resolver {
        o.push_str("\t\t# exception: the named DNS resolver only\n");
        match r {
            IpAddr::V4(a) => {
                o.push_str(&format!("\t\tip daddr {a} udp dport 53 accept\n"));
                o.push_str(&format!("\t\tip daddr {a} tcp dport 53 accept\n"));
            }
            IpAddr::V6(a) => {
                o.push_str(&format!("\t\tip6 daddr {a} udp dport 53 accept\n"));
                o.push_str(&format!("\t\tip6 daddr {a} tcp dport 53 accept\n"));
            }
        }
    }
    if p.allow_ipv6_nd {
        o.push_str("\t\t# exception: IPv6 neighbor and router discovery\n");
        o.push_str("\t\tip6 hoplimit 255 ip6 daddr { fe80::/10, ff02::/16 } icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n");
    }
    if p.allow_dhcp {
        o.push_str("\t\t# exception: DHCP client\n");
        o.push_str("\t\tip daddr 255.255.255.255 udp sport 68 udp dport 67 accept\n");
        o.push_str("\t\tip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept\n");
    }
    if !v4.is_empty() {
        o.push_str(&format!("\t\tip daddr {{ {} }} accept\n", v4.join(", ")));
    }
    if !v6.is_empty() {
        o.push_str(&format!("\t\tip6 daddr {{ {} }} accept\n", v6.join(", ")));
    }
    o.push_str("\t\t# everything else from this uid\n");
    o.push_str("\t\tdrop\n");
    o.push_str("\t}\n\n");
    o.push_str("\tchain output {\n");
    o.push_str("\t\ttype filter hook output priority 0; policy accept;\n");
    o.push_str(&format!("\t\tmeta skuid {uid} jump uid_{uid}_out\n"));
    o.push_str("\t}\n}\n");
    Ok(o)
}

/// Script that removes only our table (and is harmless when it is absent).
pub fn render_nft_remove() -> String {
    format!(
        "# Generated by pos-netpolicy. Removes only table inet {TABLE}.\nadd table inet {TABLE}\ndelete table inet {TABLE}\n"
    )
}

fn safe_path(p: &str) -> Result<(), PolicyError> {
    let ok = p.starts_with('/')
        && p.len() > 1
        && !p.split('/').any(|c| c == "..")
        && p.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(PolicyError::BadPath(p.to_string()))
    }
}

/// Text of a oneshot systemd unit that loads and removes the generated files.
/// Text only: this crate never installs, enables or starts it, and the unit
/// has not been boot-tested.
pub fn render_systemd_unit(
    nft_binary: &str,
    rules_path: &str,
    remove_path: &str,
) -> Result<String, PolicyError> {
    safe_path(nft_binary)?;
    safe_path(rules_path)?;
    safe_path(remove_path)?;
    Ok(format!(
        "# Generated by pos-netpolicy. Not installed or enabled by this crate.\n\
[Unit]\n\
Description=PassAura per-uid OUTPUT network policy (table inet {TABLE})\n\
Wants=network-pre.target\n\
Before=network-pre.target\n\
\n\
[Service]\n\
Type=oneshot\n\
RemainAfterExit=yes\n\
ExecStart={nft_binary} -f {rules_path}\n\
ExecStop={nft_binary} -f {remove_path}\n\
\n\
[Install]\n\
WantedBy=multi-user.target\n"
    ))
}
