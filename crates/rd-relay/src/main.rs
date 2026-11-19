//! `rd-relay` - rendezvous relay for hosts that can't accept inbound connections.
//!
//! Run it on any machine both sides can reach (a small VPS is plenty):
//!
//! ```text
//! rd-relay --bind 0.0.0.0:47801 --state /var/lib/rd-relay/hosts.json [--registration-key K]
//! ```
//!
//! Hosts keep an outbound control connection; when a client asks for a host id the
//! relay tells the host to open a data connection and splices the two TCP streams.
//! Client <-> host traffic is TLS end-to-end with a pinned host certificate, so the
//! relay can't read or tamper with sessions. Host ids are claimed trust-on-first-use
//! with a secret (stored hashed); `--registration-key` restricts who may register.
//!
//! The same port number on UDP answers "what is my public address?" probes, which hosts
//! and clients use to set up direct peer-to-peer connections. When those succeed the
//! relay carries nothing but the initial handshake. Open both TCP and UDP.
//!
//! When hole punching fails, the UDP port also forwards the session's QUIC datagrams
//! between the two sides (an allocation per session, keyed by its one-time token, which
//! only the client, host and relay know). Datagrams are forwarded unchanged, so the
//! relay still only sees ciphertext. `--no-udp-relay` turns this off.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use rd_core::framing::{read_msg_max, write_msg, MAX_HELLO};
use rd_core::relay::{
    allocation_id, parse_udp_relay_header, probe_reply, RelayHello, RelayNotice, RelayReply, DEFAULT_RELAY_PORT,
    MAX_CANDIDATES, RELAY_VERSION, ROLE_HOST,
};
use sha2::{Digest, Sha256};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};

#[derive(Parser)]
#[command(name = "rd-relay", version, about = "Relay server for RD remote desktop")]
struct Cli {
    #[arg(long, default_value_t = SocketAddr::from(([0, 0, 0, 0], DEFAULT_RELAY_PORT)))]
    bind: SocketAddr,
    /// Where claimed host ids (and their hashed secrets) are stored.
    #[arg(long, default_value = "rd-relay-hosts.json")]
    state: PathBuf,
    /// If set, hosts must present this key to register (keeps strangers off your relay).
    #[arg(long, env = "RD_RELAY_KEY")]
    registration_key: Option<String>,
    /// Client connection attempts allowed per IP per minute.
    #[arg(long, default_value_t = 30)]
    client_rate: u32,
    /// Don't forward UDP for sessions whose direct connection fails (they then use TCP
    /// through the relay).
    #[arg(long)]
    no_udp_relay: bool,
}

/// UDP forwarding state for one session.
struct Alloc {
    /// Last address seen from the client [0] and the host [1].
    peers: [Option<SocketAddr>; 2],
    last: Instant,
    bytes: u64,
    label: String,
}

/// Most host ids the relay will hold claims for (each claim rewrites the state file).
const MAX_CLAIMS: usize = 100_000;
/// Most UDP relay allocations at once.
const MAX_ALLOCS: usize = 10_000;
/// An allocation with no traffic for this long is dropped.
const ALLOC_IDLE: Duration = Duration::from_secs(60);

struct Online {
    notices: mpsc::UnboundedSender<RelayNotice>,
    generation: u64,
}

struct Relay {
    cli: Cli,
    /// host id -> sha256(secret)
    claims: Mutex<HashMap<String, String>>,
    online: Mutex<HashMap<String, Online>>,
    /// session -> (host id, where to deliver the host's data connection and candidates)
    pending: Mutex<HashMap<String, (String, oneshot::Sender<(TcpStream, Vec<SocketAddr>)>)>>,
    rate: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    generation: Mutex<u64>,
    allocs: Mutex<HashMap<[u8; 16], Alloc>>,
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn sha(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

fn token() -> String {
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl Relay {
    fn save_claims(&self) {
        let claims = self.claims.lock().unwrap().clone();
        let tmp = self.cli.state.with_extension("tmp");
        let r = std::fs::write(&tmp, serde_json::to_vec_pretty(&claims).unwrap_or_default())
            .and_then(|_| std::fs::rename(&tmp, &self.cli.state));
        if let Err(e) = r {
            log::error!("saving {}: {e}", self.cli.state.display());
        }
    }

    /// Check (or, with `may_claim`, claim) `id` with `secret`.
    fn verify_host(&self, id: &str, secret: &str, may_claim: bool) -> Result<()> {
        if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            bail!("invalid host id");
        }
        if secret.len() < 16 {
            bail!("secret too short");
        }
        let mut claims = self.claims.lock().unwrap();
        match claims.get(id) {
            Some(h) if constant_time_eq(h.as_bytes(), sha(secret).as_bytes()) => Ok(()),
            Some(_) => bail!("host id '{id}' is registered to another host"),
            None if !may_claim => bail!("unknown host id"),
            None if claims.len() >= MAX_CLAIMS => bail!("this relay is full"),
            None => {
                claims.insert(id.to_string(), sha(secret));
                drop(claims);
                self.save_claims();
                log::info!("host id {id} claimed");
                Ok(())
            }
        }
    }

    fn client_allowed(&self, ip: IpAddr) -> bool {
        let mut r = self.rate.lock().unwrap();
        if r.len() > 100_000 {
            r.retain(|_, (_, t)| t.elapsed() <= Duration::from_secs(60));
        }
        let e = r.entry(ip).or_insert((0, Instant::now()));
        if e.1.elapsed() > Duration::from_secs(60) {
            *e = (0, Instant::now());
        }
        e.0 += 1;
        e.0 <= self.cli.client_rate
    }

    /// Set up UDP forwarding for a session's token; false if it can't be relayed.
    fn allocate(&self, token: &str, label: String) -> bool {
        let Some(id) = allocation_id(token) else { return false };
        if self.cli.no_udp_relay {
            return false;
        }
        let mut allocs = self.allocs.lock().unwrap();
        if allocs.len() >= MAX_ALLOCS {
            allocs.retain(|_, a| a.last.elapsed() < ALLOC_IDLE);
            if allocs.len() >= MAX_ALLOCS {
                return false;
            }
        }
        allocs.insert(id, Alloc { peers: [None, None], last: Instant::now(), bytes: 0, label });
        true
    }

    fn release(&self, token: &str) {
        if let Some(id) = allocation_id(token) {
            self.allocs.lock().unwrap().remove(&id);
        }
    }
}

/// The relay's UDP sockets: the one on `--bind`, plus IPv6 when bound to all IPv4
/// interfaces and the system has IPv6.
struct UdpSockets {
    main: UdpSocket,
    v6: Option<UdpSocket>,
}

impl UdpSockets {
    fn for_dest(&self, to: &SocketAddr) -> &UdpSocket {
        match (&self.v6, to.is_ipv6()) {
            (Some(v6), true) => v6,
            _ => &self.main,
        }
    }
}

/// An IPv6-only UDP socket on `port` (alongside the IPv4 one).
fn bind_v6(port: u16) -> Option<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).ok()?;
    s.set_only_v6(true).ok()?;
    s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into()).ok()?;
    s.set_nonblocking(true).ok()?;
    UdpSocket::from_std(s.into()).ok()
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cli = Cli::parse();
    let claims: HashMap<String, String> =
        std::fs::read(&cli.state).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    let listener = TcpListener::bind(cli.bind).await.with_context(|| format!("bind {}", cli.bind))?;
    let udp = UdpSocket::bind(cli.bind).await.with_context(|| format!("bind UDP {}", cli.bind))?;
    // Also answer (and relay) over IPv6 when bound to all IPv4 interfaces.
    let v6 = match cli.bind.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => bind_v6(cli.bind.port()),
        _ => None,
    };
    log::info!(
        "relay listening on {} TCP+UDP{} ({} known host ids{})",
        cli.bind,
        if v6.is_some() { ", and UDP on IPv6" } else { "" },
        claims.len(),
        if cli.no_udp_relay { ", UDP relaying off" } else { "" }
    );
    let socks = Arc::new(UdpSockets { main: udp, v6 });
    let relay = Arc::new(Relay {
        cli,
        claims: Mutex::new(claims),
        online: Mutex::new(HashMap::new()),
        pending: Mutex::new(HashMap::new()),
        rate: Mutex::new(HashMap::new()),
        generation: Mutex::new(0),
        allocs: Mutex::new(HashMap::new()),
    });
    tokio::spawn(udp_service(relay.clone(), socks.clone(), false));
    if socks.v6.is_some() {
        tokio::spawn(udp_service(relay.clone(), socks.clone(), true));
    }
    tokio::spawn(sweep_allocs(relay.clone()));
    loop {
        let (sock, peer) = listener.accept().await?;
        let _ = sock.set_nodelay(true);
        let relay = relay.clone();
        tokio::spawn(async move {
            if let Err(e) = connection(relay, sock, peer).await {
                log::debug!("{peer}: {e:#}");
            }
        });
    }
}

/// Answer "what is my public address?" probes (for peer-to-peer setup) and forward
/// relayed session datagrams. Probe replies are never larger than requests, and each
/// address gets at most 20 answers per 10 s. Relayed datagrams are forwarded unchanged
/// (so never larger) and only between the two addresses of a live allocation.
async fn udp_service(relay: Arc<Relay>, socks: Arc<UdpSockets>, v6: bool) {
    let udp = if v6 { socks.v6.as_ref().expect("v6 socket") } else { &socks.main };
    let mut buf = vec![0u8; 65536];
    let mut budget: HashMap<IpAddr, (u32, Instant)> = HashMap::new();
    loop {
        let Ok((n, from)) = udp.recv_from(&mut buf).await else { continue };
        if let Some((id, role)) = parse_udp_relay_header(&buf[..n]) {
            let to = {
                let mut allocs = relay.allocs.lock().unwrap();
                let Some(a) = allocs.get_mut(&id) else { continue };
                let me = (role == ROLE_HOST) as usize;
                a.peers[me] = Some(from);
                a.last = Instant::now();
                a.bytes += n as u64;
                a.peers[1 - me]
            };
            if let Some(to) = to {
                let _ = socks.for_dest(&to).send_to(&buf[..n], to).await;
            }
            continue;
        }
        let Some(reply) = probe_reply(&buf[..n], from) else { continue };
        if budget.len() > 100_000 {
            budget.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(10));
        }
        let e = budget.entry(from.ip()).or_insert((0, Instant::now()));
        if e.1.elapsed() > Duration::from_secs(10) {
            *e = (0, Instant::now());
        }
        e.0 += 1;
        if e.0 <= 20 {
            let _ = udp.send_to(&reply, from).await;
        }
    }
}

async fn sweep_allocs(relay: Arc<Relay>) {
    let mut tick = tokio::time::interval(Duration::from_secs(10));
    loop {
        tick.tick().await;
        relay.allocs.lock().unwrap().retain(|_, a| {
            let keep = a.last.elapsed() < ALLOC_IDLE;
            if !keep && a.bytes > 0 {
                log::info!("{}: UDP relay ended ({} KiB)", a.label, a.bytes / 1024);
            }
            keep
        });
    }
}

fn clean(mut c: Vec<SocketAddr>) -> Vec<SocketAddr> {
    c.truncate(MAX_CANDIDATES);
    c
}

async fn connection(relay: Arc<Relay>, mut sock: TcpStream, peer: SocketAddr) -> Result<()> {
    let hello: RelayHello = tokio::time::timeout(Duration::from_secs(10), read_msg_max(&mut sock, MAX_HELLO)).await??;
    match hello {
        RelayHello::Host { version, id, secret, key } => {
            if version != RELAY_VERSION {
                return refuse(&mut sock, "relay protocol mismatch").await;
            }
            if let Some(required) = &relay.cli.registration_key {
                if !key.is_some_and(|k| constant_time_eq(k.as_bytes(), required.as_bytes())) {
                    return refuse(&mut sock, "registration key required").await;
                }
            }
            if let Err(e) = relay.verify_host(&id, &secret, true) {
                return refuse(&mut sock, &e.to_string()).await;
            }
            host_control(relay, sock, id, peer).await
        }
        RelayHello::Client { version, id, candidates, token } => {
            if version != RELAY_VERSION {
                return refuse(&mut sock, "relay protocol mismatch").await;
            }
            if !relay.client_allowed(peer.ip()) {
                return refuse(&mut sock, "too many connection attempts; slow down").await;
            }
            if token.len() > 64 {
                return refuse(&mut sock, "bad token").await;
            }
            client(relay, sock, id, peer, clean(candidates), token).await
        }
        RelayHello::Accept { version, id, secret, session, candidates } => {
            // Only a host that already registered (with the key, if one is required) may
            // answer; this never claims a new id.
            if version != RELAY_VERSION || relay.verify_host(&id, &secret, false).is_err() {
                return refuse(&mut sock, "not authorised").await;
            }
            let entry = relay.pending.lock().unwrap().remove(&session);
            match entry {
                Some((owner, deliver)) if owner == id => {
                    write_msg(&mut sock, &RelayReply::Ok).await?;
                    let _ = deliver.send((sock, clean(candidates)));
                    Ok(())
                }
                _ => refuse(&mut sock, "unknown session").await,
            }
        }
    }
}

async fn refuse(sock: &mut TcpStream, why: &str) -> Result<()> {
    let _ = write_msg(sock, &RelayReply::Error(why.to_string())).await;
    bail!("refused: {why}")
}

async fn host_control(relay: Arc<Relay>, mut sock: TcpStream, id: String, peer: SocketAddr) -> Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    let generation = {
        let mut g = relay.generation.lock().unwrap();
        *g += 1;
        *g
    };
    // A reconnecting host replaces its stale registration.
    relay.online.lock().unwrap().insert(id.clone(), Online { notices: tx, generation });
    write_msg(&mut sock, &RelayReply::Ok).await?;
    log::info!("host {id} online from {peer}");

    let mut ping = tokio::time::interval(Duration::from_secs(30));
    let result = loop {
        tokio::select! {
            _ = ping.tick() => {
                if let Err(e) = write_msg(&mut sock, &RelayNotice::Ping).await { break Err(e); }
            }
            n = rx.recv() => match n {
                Some(n) => if let Err(e) = write_msg(&mut sock, &n).await { break Err(e); },
                None => break Ok(()),
            }
        }
    };
    let mut online = relay.online.lock().unwrap();
    if online.get(&id).is_some_and(|o| o.generation == generation) {
        online.remove(&id);
        log::info!("host {id} offline");
    }
    result
}

async fn client(
    relay: Arc<Relay>,
    mut sock: TcpStream,
    id: String,
    peer: SocketAddr,
    candidates: Vec<SocketAddr>,
    p2p_token: String,
) -> Result<()> {
    let notices = relay.online.lock().unwrap().get(&id).map(|o| o.notices.clone());
    let Some(notices) = notices else {
        return refuse(&mut sock, &format!("host {id} is offline")).await;
    };
    let session = token();
    let (deliver, delivered) = oneshot::channel();
    relay.pending.lock().unwrap().insert(session.clone(), (id.clone(), deliver));
    let udp_relay = !candidates.is_empty() && relay.allocate(&p2p_token, format!("{peer} <-> host {id}"));
    let _ = notices.send(RelayNotice::Connect {
        session: session.clone(),
        client_addr: peer.to_string(),
        candidates,
        token: p2p_token.clone(),
        udp_relay,
    });

    let (host, host_candidates) = match tokio::time::timeout(Duration::from_secs(15), delivered).await {
        Ok(Ok(h)) => h,
        _ => {
            relay.pending.lock().unwrap().remove(&session);
            relay.release(&p2p_token);
            return refuse(&mut sock, &format!("host {id} did not answer")).await;
        }
    };
    let p2p = !host_candidates.is_empty();
    if udp_relay && !p2p {
        relay.release(&p2p_token);
    }
    let udp_relay = udp_relay && p2p;
    write_msg(&mut sock, &RelayReply::Peer { candidates: host_candidates, udp_relay }).await?;
    log::info!(
        "{peer} <-> host {id}: session started{}",
        match (p2p, udp_relay) {
            (true, true) => " (peer-to-peer and UDP relay offered)",
            (true, false) => " (peer-to-peer offered)",
            _ => "",
        }
    );
    let (mut a, mut b) = (sock, host);
    let r = tokio::io::copy_bidirectional(&mut a, &mut b).await;
    match r {
        Ok((up, down)) => log::info!("{peer} <-> host {id}: closed ({} KiB up, {} KiB down)", up / 1024, down / 1024),
        Err(e) => log::info!("{peer} <-> host {id}: closed ({e})"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(args: &[&str]) -> Relay {
        let state = std::env::temp_dir().join(format!("rd-relay-test-{}-{}.json", std::process::id(), token()));
        let mut argv = vec!["rd-relay", "--state", state.to_str().unwrap()];
        argv.extend_from_slice(args);
        Relay {
            cli: Cli::parse_from(argv),
            claims: Mutex::new(HashMap::new()),
            online: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            rate: Mutex::new(HashMap::new()),
            generation: Mutex::new(0),
            allocs: Mutex::new(HashMap::new()),
        }
    }

    #[test]
    fn host_ids_are_claimed_once() {
        let r = relay(&[]);
        let secret = "a-long-enough-secret";
        assert!(r.verify_host("office", secret, false).is_err(), "answering never claims an id");
        assert!(r.verify_host("office", secret, true).is_ok(), "first registration claims it");
        assert!(r.verify_host("office", secret, false).is_ok(), "then the same host may answer");
        assert!(r.verify_host("office", "another-long-secret!", true).is_err(), "nobody else can take it");
        assert!(r.verify_host("office", "short", true).is_err());
        assert!(r.verify_host("bad id!", secret, true).is_err());
        let _ = std::fs::remove_file(&r.cli.state);
    }

    #[test]
    fn client_rate_limit() {
        let r = relay(&["--client-rate", "3"]);
        let ip: IpAddr = "203.0.113.7".parse().unwrap();
        assert!((0..3).all(|_| r.client_allowed(ip)));
        assert!(!r.client_allowed(ip));
        assert!(r.client_allowed("203.0.113.8".parse().unwrap()), "other addresses are unaffected");
    }

    #[test]
    fn constant_time_compare() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }
}
