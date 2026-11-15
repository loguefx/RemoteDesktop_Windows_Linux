//! Finding computers on the local network (see `rd_core::discovery`).

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use rd_core::discovery::{self, Announce};
use tokio::net::UdpSocket;

#[derive(Debug, Clone)]
pub struct Found {
    pub announce: Announce,
    /// Where it answered from (`ip:port` for sessions).
    pub addr: SocketAddr,
    /// It is this computer.
    pub local: bool,
}

/// Local IPv4 addresses and the broadcast address of each network.
fn interfaces() -> (Vec<Ipv4Addr>, Vec<Ipv4Addr>) {
    let mut ips = Vec::new();
    let mut bcast = Vec::new();
    for i in if_addrs::get_if_addrs().unwrap_or_default() {
        if let if_addrs::IfAddr::V4(v4) = i.addr {
            ips.push(v4.ip);
            if v4.ip.is_loopback() || v4.ip.is_link_local() {
                continue;
            }
            let b = v4
                .broadcast
                .unwrap_or_else(|| Ipv4Addr::from(u32::from(v4.ip) | !u32::from(v4.netmask)));
            if !bcast.contains(&b) {
                bcast.push(b);
            }
        }
    }
    (ips, bcast)
}

/// Ask every local network (and this computer) for hosts, collecting answers for `wait`.
pub async fn scan(port: u16, wait: Duration) -> Vec<Found> {
    let sock = match bind() {
        Ok(s) => s,
        Err(e) => {
            log::debug!("discovery socket: {e}");
            return Vec::new();
        }
    };
    let (my_ips, bcast) = interfaces();
    let mut targets: Vec<SocketAddr> = bcast.iter().map(|b| SocketAddr::new(IpAddr::V4(*b), port)).collect();
    targets.push(SocketAddr::from(([255, 255, 255, 255], port)));
    targets.push(SocketAddr::from(([127, 0, 0, 1], port)));
    let q = discovery::query();

    let mut found: BTreeMap<String, Found> = BTreeMap::new();
    let deadline = tokio::time::Instant::now() + wait;
    let resend = tokio::time::Instant::now() + wait / 3;
    let mut resent = false;
    for t in &targets {
        let _ = sock.send_to(&q, t).await;
    }
    let mut buf = vec![0u8; 2048];
    loop {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            break;
        }
        if !resent && now >= resend {
            // Broadcasts can be dropped; ask once more.
            resent = true;
            for t in &targets {
                let _ = sock.send_to(&q, t).await;
            }
        }
        let until = if resent { deadline } else { resend.min(deadline) };
        let Ok(Ok((n, from))) = tokio::time::timeout_at(until, sock.recv_from(&mut buf)).await else { continue };
        let Some(a) = discovery::parse_reply(&buf[..n]) else { continue };
        let ip = match from.ip() {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            ip => ip,
        };
        let local = ip.is_loopback() || matches!(ip, IpAddr::V4(v4) if my_ips.contains(&v4));
        let addr = SocketAddr::new(ip, a.port);
        let key = a.fingerprint.to_ascii_lowercase();
        match found.get_mut(&key) {
            Some(f) => {
                f.local |= local;
                // Prefer a LAN address over loopback, so it can be saved for other devices.
                if f.addr.ip().is_loopback() && !ip.is_loopback() {
                    f.addr = addr;
                }
            }
            None => {
                found.insert(key, Found { announce: a, addr, local });
            }
        }
    }
    found.into_values().collect()
}

fn bind() -> std::io::Result<UdpSocket> {
    let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    s.set_broadcast(true)?;
    s.bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())?;
    s.set_nonblocking(true)?;
    UdpSocket::from_std(s.into())
}
