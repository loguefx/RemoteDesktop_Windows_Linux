//! Making the host findable and reachable without typing addresses.
//!
//! * **Discovery:** answer the app's UDP broadcast on the host port with an
//!   [`Announce`] (name, certificate fingerprint, public address).
//! * **Router port mapping:** with internet access turned on, ask the router (UPnP IGD)
//!   to forward a TCP port to this computer, and learn the router's public address. The
//!   app saves that address while it is on the same network, so it can connect later
//!   from anywhere.
//! * **Dynamic DNS:** optionally keep a name (e.g. `home.duckdns.org`) pointing at the
//!   router's address, so the app still finds this computer after the internet provider
//!   changes that address while you're away.
//! * **Wake-on-LAN:** the announce carries the network adapters' hardware addresses.

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
    /// `name:port` when dynamic DNS is set up and the name was updated.
    pub public_name: Option<String>,
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
            a.public_name = r.public_name.clone();
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

/// How often the router is asked again: renews the mapping and notices a changed
/// internet address quickly (for dynamic DNS).
const CHECK_EVERY: Duration = Duration::from_secs(300);

/// Keep a router port mapping for `port` alive and report the public address. With
/// `ddns` = (name, update URL), keep that name pointing at the router's address.
pub async fn keep_port_mapped(port: u16, reach: SharedReach, ddns: Option<(String, String)>) {
    let mut external: Option<u16> = None;
    let mut last_err = String::new();
    // Address the dynamic DNS name was last set to, and when.
    let mut ddns_ip: Option<(IpAddr, std::time::Instant)> = None;
    loop {
        let wait = match map_once(port, &mut external).await {
            Ok((ip, ext, vpn)) => {
                let mut ddns_note = None;
                let mut public_name = None;
                if let (Some((name, url)), false) = (&ddns, discovery::is_non_public(ip)) {
                    // Update when the address changed, and once a day anyway.
                    let stale = ddns_ip.is_none_or(|(old, at)| old != ip || at.elapsed() > Duration::from_secs(86_400));
                    if stale {
                        match update_ddns(url, ip).await {
                            Ok(()) => {
                                log::info!("dynamic DNS: {name} -> {ip}");
                                ddns_ip = Some((ip, std::time::Instant::now()));
                            }
                            Err(e) => {
                                log::warn!("dynamic DNS update for {name} failed: {e:#}");
                                ddns_note = Some(format!("couldn't update {name}: {e:#}"));
                            }
                        }
                    }
                    if ddns_ip.is_some_and(|(old, _)| old == ip) {
                        public_name = Some(format!("{name}:{ext}"));
                    }
                }
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
                let note = note.or(ddns_note);
                *r = Reach { public, public_name, note, mapped: Some(ext) };
                last_err.clear();
                CHECK_EVERY
            }
            Err(e) => {
                let msg = format!("{e:#}");
                if msg != last_err {
                    log::warn!("router port mapping: {msg}");
                    last_err = msg.clone();
                }
                *reach.lock().unwrap() = Reach { public: None, public_name: None, note: Some(msg), mapped: None };
                Duration::from_secs(120)
            }
        };
        tokio::time::sleep(wait).await;
    }
}

/// Point the dynamic DNS name at `ip`: fetch the provider's update URL, with `{ip}`
/// replaced. Providers answer "OK"/"good"/"nochg" on success, "KO"/"bad..."/"911" on errors.
async fn update_ddns(url: &str, ip: IpAddr) -> anyhow::Result<()> {
    let r = rd_core::http::get(&url.replace("{ip}", &ip.to_string()), &[]).await?;
    let body = r.body.trim().to_ascii_lowercase();
    if r.status != 200 || body.starts_with("ko") || body.starts_with("bad") || body.starts_with("911") || body.starts_with("nohost") {
        anyhow::bail!("the provider answered {} {}", r.status, r.body.trim().chars().take(80).collect::<String>());
    }
    Ok(())
}

/// Hardware addresses of the wired/wireless adapters, for Wake-on-LAN.
pub fn mac_addresses() -> Vec<[u8; 6]> {
    let mut out: Vec<[u8; 6]> = Vec::new();
    let mut push = |m: [u8; 6]| {
        // Skip all-zero and locally administered (virtual, VPN, Docker...) addresses.
        if m != [0; 6] && m[0] & 0x02 == 0 && !out.contains(&m) && out.len() < discovery::MAX_MACS {
            out.push(m);
        }
    };
    #[cfg(target_os = "linux")]
    if let Ok(rd) = std::fs::read_dir("/sys/class/net") {
        let mut ifs: Vec<std::path::PathBuf> = rd.flatten().map(|e| e.path()).collect();
        // Physical adapters have a `device` link; wired ones first ("en..."/"eth...").
        ifs.retain(|p| p.join("device").exists());
        ifs.sort_by_key(|p| {
            let n = p.file_name().unwrap_or_default().to_string_lossy().to_string();
            (!(n.starts_with("en") || n.starts_with("eth")), n)
        });
        for p in ifs {
            if let Some(m) = std::fs::read_to_string(p.join("address")).ok().and_then(|s| parse_mac(s.trim())) {
                push(m);
            }
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // getmac: "Connection","Adapter","AA-BB-CC-DD-EE-FF","\\Device\\Tcpip_{...}" or "Media disconnected".
        if let Ok(o) = std::process::Command::new("getmac").args(["/fo", "csv", "/nh", "/v"]).creation_flags(0x0800_0000).output() {
            let text = String::from_utf8_lossy(&o.stdout).to_string();
            let mut rows: Vec<(bool, [u8; 6])> = text
                .lines()
                .filter_map(|l| {
                    let cols: Vec<&str> = l.split("\",\"").map(|c| c.trim_matches('"')).collect();
                    let mac = parse_mac(cols.get(2)?)?;
                    let connected = cols.get(3).is_some_and(|t| t.contains("Tcpip"));
                    Some((connected, mac))
                })
                .collect();
            rows.sort_by_key(|(connected, _)| !connected);
            for (_, m) in rows {
                push(m);
            }
        }
    }
    out
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<u8> = s.split([':', '-']).filter_map(|p| u8::from_str_radix(p, 16).ok()).collect();
    (parts.len() == 6 && s.len() == 17).then(|| parts.try_into().ok()).flatten()
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
