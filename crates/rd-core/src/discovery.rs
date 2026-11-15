//! Finding hosts on the local network, and telling clients how to reach them later.
//!
//! The app broadcasts a small UDP query to the host port ([`crate::DEFAULT_PORT`]) on every
//! local network; each host answers with an [`Announce`] sent back to the sender's
//! address. Replies to a broadcast are let through by the Windows firewall without a rule.
//!
//! * The query is padded to [`QUERY_LEN`] bytes and replies never exceed it, so a host
//!   can't be used to amplify traffic.
//! * Hosts only answer private, link-local and loopback senders.
//! * An announce is not authenticated. The client pins the certificate fingerprint it
//!   carries and checks it in the TLS handshake, so a forged announce can only point the
//!   client at a host that will fail that check (or, on first contact, ask for a PIN).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

pub const QUERY_MAGIC: &[u8; 4] = b"RDQ1";
pub const REPLY_MAGIC: &[u8; 4] = b"RDA1";
/// Query size, and the largest reply.
pub const QUERY_LEN: usize = 600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Announce {
    /// The name chosen when remote access was set up.
    pub name: String,
    /// SHA-256 fingerprint of the host certificate (`AB:CD:...`, as `tls::fingerprint`).
    pub fingerprint: String,
    /// TCP port for sessions.
    pub port: u16,
    pub protocol: u32,
    /// `ip:port` reachable from the internet (a router port mapped with UPnP), if any.
    pub public: Option<String>,
    /// Why there is no public address, for display ("router has UPnP turned off", ...).
    pub public_note: Option<String>,
    /// `ID@relay:port`, when the host is registered with a relay.
    pub relay: Option<String>,
}

pub fn query() -> Vec<u8> {
    let mut q = vec![0u8; QUERY_LEN];
    q[..4].copy_from_slice(QUERY_MAGIC);
    q
}

pub fn is_query(b: &[u8]) -> bool {
    b.len() == QUERY_LEN && &b[..4] == QUERY_MAGIC
}

/// Encoded reply, or None if it would be larger than the query.
pub fn encode_reply(a: &Announce) -> Option<Vec<u8>> {
    let mut out = REPLY_MAGIC.to_vec();
    out.extend(postcard::to_allocvec(a).ok()?);
    (out.len() <= QUERY_LEN).then_some(out)
}

pub fn parse_reply(b: &[u8]) -> Option<Announce> {
    if b.len() < 4 || &b[..4] != REPLY_MAGIC {
        return None;
    }
    let mut a: Announce = postcard::from_bytes(&b[4..]).ok()?;
    a.fingerprint = canonical_fingerprint(&a.fingerprint)?;
    (!a.name.is_empty() && a.name.len() <= 64).then_some(a)
}

/// `AB:CD:...` (upper case, colon separated) from any spelling of a SHA-256 fingerprint.
pub fn canonical_fingerprint(fp: &str) -> Option<String> {
    let hex: String = fp.chars().filter(|c| *c != ':').collect();
    if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let hex = hex.to_ascii_uppercase();
    Some(hex.as_bytes().chunks(2).map(|p| std::str::from_utf8(p).unwrap()).collect::<Vec<_>>().join(":"))
}

/// Addresses a host answers discovery queries from.
pub fn is_local_sender(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
                || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_private() || v4.is_loopback())
        }
    }
}

/// An address that can't be reached from the internet (private or carrier-grade NAT).
pub fn is_non_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || (o[0] == 100 && (o[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xe000) != 0x2000,
    }
}

/// Computer names: 1-40 visible characters.
pub fn clean_name(name: &str) -> Option<String> {
    let n: String = name.trim().chars().filter(|c| !c.is_control()).collect();
    (!n.is_empty() && n.chars().count() <= 40).then_some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_round_trip_and_size() {
        let a = Announce {
            name: "x".repeat(40),
            fingerprint: vec!["AB"; 32].join(":"),
            port: 47800,
            protocol: 6,
            public: Some("203.0.113.9:47800".into()),
            public_note: Some("y".repeat(120)),
            relay: Some(format!("123-456-789@{}:47900", "r".repeat(60))),
        };
        let b = encode_reply(&a).expect("fits");
        assert!(b.len() <= QUERY_LEN);
        assert_eq!(parse_reply(&b), Some(a));
        assert!(is_query(&query()));
        assert!(parse_reply(b"RDA1garbage").is_none());
        assert_eq!(canonical_fingerprint(&"ab".repeat(32)), Some(vec!["AB"; 32].join(":")));
        assert!(canonical_fingerprint("AB:CD").is_none());
    }

    #[test]
    fn address_classes() {
        assert!(is_local_sender("192.168.1.4".parse().unwrap()));
        assert!(!is_local_sender("8.8.8.8".parse().unwrap()));
        assert!(is_non_public("100.72.1.1".parse().unwrap()));
        assert!(!is_non_public("203.0.113.9".parse().unwrap()));
        assert!(!is_non_public("2001:db8::1".parse().unwrap()));
        assert!(is_non_public("fd00::1".parse().unwrap()));
    }
}
