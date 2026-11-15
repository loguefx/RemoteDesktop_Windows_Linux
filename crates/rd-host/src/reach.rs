//! Making the host findable and reachable without typing addresses.
//!
//! * **Discovery:** answer the app's UDP broadcast on the host port with an
//!   [`Announce`] (name, certificate fingerprint, public address).
//! * **Router port mapping:** with internet access turned on, ask the router (UPnP IGD)
//!   to forward a TCP port to this computer, and learn the router's public address. The
//!   app saves that address while it is on the same network, so it can connect later
//!   from anywhere.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rd_core::discovery::{self, Announce};
use tokio::net::UdpSocket;

/// How long a router mapping lasts; renewed at half that.
const LEASE_SECS: u32 = 3600;
const DESCRIPTION: &str = "RD Remote Desktop";

#[derive(Default, Clone)]
pub struct Reach {
    pub public: Option<String>,
    pub note: Option<String>,
    /// External port currently mapped on the router.
    pub mapped: Option<u16>,
}

pub type SharedReach = Arc<Mutex<Reach>>;

/// The local address used to reach `dest` (no packets are sent).
fn local_ip_toward(dest: SocketAddr) -> Option<IpAddr> {
    let bind: SocketAddr = if dest.is_ipv4() { "0.0.0.0:0".parse().ok()? } else { "[::]:0".parse().ok()? };
    let s = std::net::UdpSocket::bind(bind).ok()?;
    s.connect(dest).ok()?;
    s.local_addr().ok().map(|a| a.ip())
}

/// Answer discovery queries until the process exits.
pub async fn answer_discovery(port: u16, base: Announce, reach: SharedReach) {
    let sock = match bind_discovery(port) {
        Ok(s) => s,
        Err(e) => {
            log::warn!("discovery: can't listen on UDP {port}: {e:#}; computers on this network won't see this one");
            return;
        }
    };
    log::info!("answering discovery on UDP {port}");
    let mut buf = vec![0u8; 2048];
    // Simple flood guard: at most 50 replies per second.
    let mut window = tokio::time::Instant::now();
    let mut sent = 0u32;
    loop {
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                log::debug!("discovery recv: {e}");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if !discovery::is_query(&buf[..n]) || !discovery::is_local_sender(from.ip()) {
            continue;
        }
        if window.elapsed() >= Duration::from_secs(1) {
            window = tokio::time::Instant::now();
            sent = 0;
        }
        sent += 1;
        if sent > 50 {
            continue;
        }
        let mut a = base.clone();
        {
            let r = reach.lock().unwrap();
            a.public = r.public.clone();
            a.public_note = r.note.clone();
        }
        if let Some(reply) = discovery::encode_reply(&a) {
            let _ = sock.send_to(&reply, from).await;
        }
    }
}

fn bind_discovery(port: u16) -> anyhow::Result<UdpSocket> {
    let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_broadcast(true)?;
    s.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
    s.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(s.into())?)
}

/// Keep a router port mapping for `port` alive and report the public address.
pub async fn keep_port_mapped(port: u16, reach: SharedReach) {
    let mut external: Option<u16> = None;
    let mut last_err = String::new();
    loop {
        let wait = match map_once(port, &mut external).await {
            Ok((ip, ext, vpn)) => {
                let (public, note) = if discovery::is_non_public(ip) {
                    (None, Some(format!("your router's internet address {ip} is shared by your provider (carrier-grade NAT), so this computer can't be reached directly from the internet")))
                } else {
                    let note = vpn.then(|| "a VPN is carrying this computer's internet traffic, so connections from the internet may fail while it is on".to_string());
                    (Some(SocketAddr::new(ip, ext).to_string()), note)
                };
                let mut r = reach.lock().unwrap();
                if r.public != public {
                    match &public {
                        Some(p) => log::info!("router forwards {p} to this computer (UPnP)"),
                        None => log::warn!("{}", note.as_deref().unwrap_or_default()),
                    }
                }
                *r = Reach { public, note, mapped: Some(ext) };
                last_err.clear();
                Duration::from_secs(LEASE_SECS as u64 / 2)
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if msg != last_err {
                    log::warn!("router port mapping: {msg}");
                    last_err = msg.clone();
                }
                *reach.lock().unwrap() = Reach { public: None, note: Some(msg), mapped: None };
                Duration::from_secs(120)
            }
        };
        tokio::time::sleep(wait).await;
    }
}

type Gateway = igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>;

/// Private IPv4 addresses of this computer's network adapters, the one carrying
/// internet traffic first. A VPN often carries the default route, while the router sits
/// on the Ethernet or Wi-Fi network, so every adapter is searched.
fn lan_addresses() -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    if let Some(ip) = local_ip_toward("1.1.1.1:80".parse().unwrap()) {
        out.push(ip);
    }
    for i in if_addrs::get_if_addrs().unwrap_or_default() {
        if let if_addrs::IfAddr::V4(v4) = i.addr {
            let ip = IpAddr::V4(v4.ip);
            if v4.ip.is_private() && !out.contains(&ip) {
                out.push(ip);
            }
        }
    }
    out
}

/// Find the router: search from every adapter at once and take the first answer, with
/// the adapter it answered on (the address the port is forwarded to).
async fn find_router() -> anyhow::Result<(Gateway, IpAddr)> {
    use igd_next::{aio::tokio::search_gateway, SearchOptions};
    let ips = lan_addresses();
    if ips.is_empty() {
        anyhow::bail!("no network connection");
    }
    let mut set = tokio::task::JoinSet::new();
    for ip in ips {
        set.spawn(async move {
            let opts = SearchOptions {
                bind_addr: SocketAddr::new(ip, 0),
                timeout: Some(Duration::from_secs(5)),
                ..Default::default()
            };
            search_gateway(opts).await.map(|gw| (gw, ip))
        });
    }
    let mut last = String::from("no answer");
    while let Some(r) = set.join_next().await {
        match r {
            Ok(Ok(found)) => {
                set.abort_all();
                return Ok(found);
            }
            Ok(Err(e)) => last = e.to_string(),
            Err(_) => {}
        }
    }
    anyhow::bail!("no UPnP router found ({last}); turn on UPnP in the router to reach this computer from the internet")
}

/// `rd-host router-check`: find the router and ask for its address, changing nothing.
pub async fn router_check() -> anyhow::Result<(SocketAddr, IpAddr)> {
    let (gw, _) = find_router().await?;
    let ip = gw.get_external_ip().await.map_err(|e| anyhow::anyhow!("the router answered but didn't give its address: {e}"))?;
    Ok((gw.addr, ip))
}

/// Remove the router mapping (when the service stops).
pub async fn release(reach: &SharedReach) {
    let Some(ext) = reach.lock().unwrap().mapped.take() else { return };
    let r = tokio::time::timeout(Duration::from_secs(5), async {
        let (gw, _) = find_router().await?;
        gw.remove_port(igd_next::PortMappingProtocol::TCP, ext).await?;
        anyhow::Ok(())
    })
    .await;
    match r {
        Ok(Ok(())) => log::info!("removed the router port mapping {ext}"),
        Ok(Err(e)) => log::warn!("could not remove the router port mapping {ext}: {e:#}"),
        Err(_) => log::warn!("could not remove the router port mapping {ext}: timed out"),
    }
}

/// Returns the router's address, the external port, and whether internet traffic
/// leaves through another adapter (a VPN), which breaks replies to forwarded connections.
async fn map_once(port: u16, external: &mut Option<u16>) -> anyhow::Result<(IpAddr, u16, bool)> {
    use igd_next::PortMappingProtocol;
    let (gw, lan_ip) = find_router().await?;
    let local = SocketAddr::new(lan_ip, port);
    let want = external.unwrap_or(port);
    let ext = match gw.add_port(PortMappingProtocol::TCP, want, local, LEASE_SECS, DESCRIPTION).await {
        Ok(()) => want,
        Err(e) => {
            log::debug!("router refused port {want} ({e}); asking for any port");
            gw.add_any_port(PortMappingProtocol::TCP, local, LEASE_SECS, DESCRIPTION)
                .await
                .map_err(|e| anyhow::anyhow!("the router refused a port mapping: {e}"))?
        }
    };
    *external = Some(ext);
    let ip = gw.get_external_ip().await.map_err(|e| anyhow::anyhow!("router didn't give its address: {e}"))?;
    let vpn = local_ip_toward("1.1.1.1:80".parse().unwrap()).is_some_and(|d| d != lan_ip);
    Ok((ip, ext, vpn))
}
