//! Relay ("rendezvous") protocol, for hosts that aren't directly reachable (NAT,
//! firewalls, CGNAT).
//!
//! Both the host and the client make *outbound* TCP connections to a public `rd-relay`
//! server, which splices them together. The client <-> host TLS session runs end-to-end
//! through the splice, and the client pins the host certificate, so the relay only
//! ever sees ciphertext and cannot impersonate the host.
//!
//! ```text
//! host  --control--> relay   RelayHello::Host{id, secret}         <- RelayReply::Ok
//! client ---------> relay    RelayHello::Client{id, candidates, token}
//!                   relay -> host (control): RelayNotice::Connect{session, client_addr, candidates, token}
//! host  --data----> relay    RelayHello::Accept{id, secret, session, candidates} <- RelayReply::Ok
//!                   relay -> client: RelayReply::Peer{candidates}, then raw byte splice both ways
//! ```
//!
//! **Peer-to-peer.** Before connecting, each side asks the relay's UDP port (same number
//! as the TCP port) for its public address ([`probe_request`] / [`parse_probe_reply`]),
//! and sends it plus its LAN address as `candidates`. Both then punch UDP holes towards
//! each other and the client tries a direct QUIC connection (`rd_core::p2p`). If that
//! works the relayed TCP connection is dropped; otherwise the session simply runs over
//! it. Either way the same end-to-end TLS session and sign-in happen inside.
//!
//! **UDP relaying.** If hole punching fails but UDP to the relay works, the QUIC
//! connection can also run *through* the relay's UDP port: each datagram is prefixed
//! with [`udp_relay_header`] (magic, the session's allocation id, the sender's role) and
//! the relay forwards it, unchanged and never larger, to the other side's last-seen
//! address. That avoids TCP's head-of-line stalls; the relayed TCP stream remains the
//! last resort.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

pub const DEFAULT_RELAY_PORT: u16 = 47801;
pub const RELAY_VERSION: u32 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayHello {
    /// Host control connection: register (or re-attach to) `id`. `key` is the relay's
    /// optional registration key.
    Host { version: u32, id: String, secret: String, key: Option<String> },
    /// Client wants to reach host `id`. `candidates` are UDP addresses to try for a direct
    /// connection (empty = relay only); the host only accepts one presenting `token`.
    Client { version: u32, id: String, candidates: Vec<SocketAddr>, token: String },
    /// Host data connection answering `Connect { session }`, with the host's own
    /// candidates (empty if it won't try peer-to-peer).
    Accept { version: u32, id: String, secret: String, session: String, candidates: Vec<SocketAddr> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayReply {
    Ok,
    /// To a client: the host answered; here are its candidates. The relayed stream
    /// follows.
    /// `udp_relay`: the relay will also forward UDP for this session.
    Peer { candidates: Vec<SocketAddr>, udp_relay: bool },
    Error(String),
}

/// Messages from the relay on a host's control connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayNotice {
    /// `udp_relay`: the relay has set up UDP forwarding for `token`.
    Connect { session: String, client_addr: String, candidates: Vec<SocketAddr>, token: String, udp_relay: bool },
    Ping,
}

/// Most candidates accepted from either side.
pub const MAX_CANDIDATES: usize = 8;

// ---------------------------------------------------------------- UDP address probe

const PROBE_MAGIC: &[u8; 4] = b"RDP1";
/// Requests are padded to this size so a reply is never larger than the request.
pub const PROBE_LEN: usize = 64;

/// "What is my public address?" request, identified by `nonce`.
pub fn probe_request(nonce: &[u8; 16]) -> [u8; PROBE_LEN] {
    let mut b = [0u8; PROBE_LEN];
    b[..4].copy_from_slice(PROBE_MAGIC);
    b[4..20].copy_from_slice(nonce);
    b
}

/// The relay's answer to a probe from `from`, or `None` if `req` isn't a valid probe.
pub fn probe_reply(req: &[u8], from: SocketAddr) -> Option<Vec<u8>> {
    if req.len() < PROBE_LEN || &req[..4] != PROBE_MAGIC {
        return None;
    }
    let mut out = req[..20].to_vec();
    match from.ip() {
        IpAddr::V4(ip) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&from.port().to_be_bytes());
    Some(out)
}

/// Public address from a probe reply matching `nonce`.
pub fn parse_probe_reply(b: &[u8], nonce: &[u8; 16]) -> Option<SocketAddr> {
    if b.len() < 21 || &b[..4] != PROBE_MAGIC || &b[4..20] != nonce {
        return None;
    }
    let (ip, rest): (IpAddr, &[u8]) = match b[20] {
        4 if b.len() >= 27 => (<[u8; 4]>::try_from(&b[21..25]).ok()?.into(), &b[25..]),
        6 if b.len() >= 39 => (<[u8; 16]>::try_from(&b[21..37]).ok()?.into(), &b[37..]),
        _ => return None,
    };
    Some(SocketAddr::new(ip, u16::from_be_bytes([rest[0], rest[1]])))
}

// ---------------------------------------------------------------- UDP relaying

const UDP_RELAY_MAGIC: &[u8; 4] = b"RDU1";
/// Bytes in front of every relayed datagram.
pub const UDP_RELAY_HDR: usize = 21;
pub const ROLE_CLIENT: u8 = b'c';
pub const ROLE_HOST: u8 = b'h';

/// Allocation id for a peer-to-peer token (32 hex digits), or `None` if it isn't one.
pub fn allocation_id(token: &str) -> Option<[u8; 16]> {
    if token.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(token.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(id)
}

/// Header for datagrams sent through the relay by `role` ([`ROLE_CLIENT`]/[`ROLE_HOST`]).
pub fn udp_relay_header(id: &[u8; 16], role: u8) -> [u8; UDP_RELAY_HDR] {
    let mut h = [0u8; UDP_RELAY_HDR];
    h[..4].copy_from_slice(UDP_RELAY_MAGIC);
    h[4..20].copy_from_slice(id);
    h[20] = role;
    h
}

/// `(allocation id, role)` of a relayed datagram.
pub fn parse_udp_relay_header(b: &[u8]) -> Option<([u8; 16], u8)> {
    if b.len() < UDP_RELAY_HDR || &b[..4] != UDP_RELAY_MAGIC || !matches!(b[20], ROLE_CLIENT | ROLE_HOST) {
        return None;
    }
    Some((b[4..20].try_into().ok()?, b[20]))
}

/// Where to connect: directly, or through a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Direct(String),
    Relay { id: String, relay: String },
}

impl Target {
    /// `host[:port]` or `HOST-ID@relay[:port]`.
    pub fn parse(s: &str) -> Target {
        match s.split_once('@') {
            Some((id, relay)) if !id.is_empty() && !relay.is_empty() => {
                Target::Relay { id: id.to_string(), relay: with_port(relay, DEFAULT_RELAY_PORT) }
            }
            _ => Target::Direct(with_port(s, crate::DEFAULT_PORT)),
        }
    }

    /// Canonical string (used as the key for saved hosts).
    pub fn key(&self) -> String {
        match self {
            Target::Direct(a) => a.clone(),
            Target::Relay { id, relay } => format!("{id}@{relay}"),
        }
    }
}

pub fn with_port(host: &str, port: u16) -> String {
    let has_port = host.rsplit_once(':').is_some_and(|(h, p)| p.parse::<u16>().is_ok() && !h.ends_with(':'))
        && !host.ends_with(']');
    // Bare IPv6 literal (several colons, no brackets) has no port.
    let bare_v6 = host.matches(':').count() > 1 && !host.starts_with('[');
    if has_port && !bare_v6 {
        host.to_string()
    } else if bare_v6 {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Human-friendly host id like `482-913-077`.
pub fn new_host_id(random: &[u8; 8]) -> String {
    let n = u64::from_le_bytes(*random) % 1_000_000_000;
    format!("{:03}-{:03}-{:03}", n / 1_000_000, n / 1000 % 1000, n % 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(Target::parse("pc"), Target::Direct("pc:47800".into()));
        assert_eq!(Target::parse("pc:9000"), Target::Direct("pc:9000".into()));
        assert_eq!(Target::parse("10.0.0.5"), Target::Direct("10.0.0.5:47800".into()));
        assert_eq!(Target::parse("::1"), Target::Direct("[::1]:47800".into()));
        assert_eq!(Target::parse("[::1]:5"), Target::Direct("[::1]:5".into()));
        assert_eq!(
            Target::parse("123-456-789@relay.example.com"),
            Target::Relay { id: "123-456-789".into(), relay: "relay.example.com:47801".into() }
        );
        assert_eq!(new_host_id(&[0; 8]), "000-000-000");
    }

    #[test]
    fn probe_round_trip() {
        let nonce = [7u8; 16];
        let req = probe_request(&nonce);
        for from in ["203.0.113.9:40001", "[2001:db8::5]:443"] {
            let from: SocketAddr = from.parse().unwrap();
            let reply = probe_reply(&req, from).unwrap();
            assert!(reply.len() <= req.len(), "no amplification");
            assert_eq!(parse_probe_reply(&reply, &nonce), Some(from));
            assert_eq!(parse_probe_reply(&reply, &[8u8; 16]), None, "wrong nonce");
        }
        assert!(probe_reply(&req[..10], "1.2.3.4:5".parse().unwrap()).is_none());
        assert!(probe_reply(&[0u8; 64], "1.2.3.4:5".parse().unwrap()).is_none());
    }

    #[test]
    fn udp_relay_header_round_trip() {
        let id = allocation_id("00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(id[1], 0x11);
        assert!(allocation_id("short").is_none());
        assert!(allocation_id("zz112233445566778899aabbccddeeff").is_none());
        let mut pkt = udp_relay_header(&id, ROLE_HOST).to_vec();
        pkt.extend_from_slice(b"payload");
        assert_eq!(parse_udp_relay_header(&pkt), Some((id, ROLE_HOST)));
        pkt[20] = b'x';
        assert_eq!(parse_udp_relay_header(&pkt), None);
        assert_eq!(parse_udp_relay_header(b"RDU1"), None);
    }
}
