//! Direct (peer-to-peer) connections through NAT, with the relay as rendezvous.
//!
//! 1. [`prepare`] binds a fresh UDP socket (dual-stack IPv6 + IPv4 where the OS allows)
//!    and asks the relay's UDP port, over each address family the relay has, what public
//!    address it maps to. Those addresses, plus the LAN addresses, are the *candidates*
//!    exchanged through the relay.
//! 2. Both sides punch: they send small UDP packets to each other's candidates from that
//!    same socket, so each NAT sees outbound traffic and lets the other side's packets in.
//! 3. The host runs a QUIC server on the socket ([`listen`]); the client races QUIC
//!    connections to all host candidates ([`connect`]) and opens one stream, starting
//!    with a one-time token the host received through the relay.
//! 4. If the relay offers UDP relaying, the client also tries (half a second later, so a
//!    direct path wins when there is one) the same QUIC connection *through* the relay's
//!    UDP port. [`RelayedSocket`] adds and strips the relay header for datagrams to and
//!    from the relay's address; everything else on the socket is untouched.
//!
//! The resulting [`P2pStream`] is a plain byte stream: the usual end-to-end TLS session
//! (pinned host certificate) and sign-in run inside it, exactly as over TCP. QUIC's own
//! TLS layer therefore uses a throwaway certificate and doesn't verify it.
//!
//! Direct paths work through most home and office NATs; two "symmetric" NATs (some
//! carrier-grade NAT) usually defeat them, and then the UDP relay path (or, failing that,
//! the caller's relayed TCP connection) carries the session.

use std::fmt;
use std::io::{self, IoSliceMut};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::relay::{
    allocation_id, parse_probe_reply, probe_request, udp_relay_header, MAX_CANDIDATES, ROLE_CLIENT, ROLE_HOST,
    UDP_RELAY_HDR,
};

const ALPN: &[u8] = b"rd-p2p/1";
const STREAM_MAGIC: &[u8; 4] = b"RDS1";
const PUNCH: &[u8] = b"rd-punch";
/// Head start the direct candidates get over the relayed path.
const RELAY_DELAY: Duration = Duration::from_millis(500);

/// A bound UDP socket and the addresses the other side should try.
pub struct Prepared {
    socket: UdpSocket,
    /// The socket is IPv6 and also carries IPv4 (as v4-mapped addresses).
    dual: bool,
    /// The relay's UDP address that answered our probe (where relayed datagrams go).
    relay: Option<SocketAddr>,
    pub candidates: Vec<SocketAddr>,
}

impl Prepared {
    /// The relay answered over UDP, so the relayed path can be tried.
    pub fn relay_reachable(&self) -> bool {
        self.relay.is_some()
    }
}

/// `::ffff:a.b.c.d` -> `a.b.c.d`; everything else unchanged.
pub fn canonical(a: SocketAddr) -> SocketAddr {
    match a {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(IpAddr::V4(v4), v6.port()),
            None => a,
        },
        _ => a,
    }
}

/// The form of `a` that a socket of the given kind can send to.
fn for_socket(a: SocketAddr, dual: bool) -> SocketAddr {
    match a {
        SocketAddr::V4(v4) if dual => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        _ => a,
    }
}

/// Dual-stack `[::]:0` if possible, else `0.0.0.0:0`. Non-blocking.
fn bind_socket() -> Result<(UdpSocket, bool)> {
    use socket2::{Domain, Protocol, Socket, Type};
    if let Ok(s) = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)) {
        if s.set_only_v6(false).is_ok() && s.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into()).is_ok() {
            s.set_nonblocking(true)?;
            return Ok((s.into(), true));
        }
    }
    let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
    s.set_nonblocking(true)?;
    Ok((s, false))
}

/// The local address the OS would use to reach `toward` (no packet is sent).
fn local_ip_toward(toward: SocketAddr) -> Option<IpAddr> {
    let any: SocketAddr = if toward.is_ipv4() { (Ipv4Addr::UNSPECIFIED, 0).into() } else { (Ipv6Addr::UNSPECIFIED, 0).into() };
    let s = UdpSocket::bind(any).ok()?;
    s.connect(toward).ok()?;
    let ip = s.local_addr().ok()?.ip();
    (!ip.is_unspecified()).then_some(ip)
}

fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// Bind a UDP socket and learn its public address(es) from the relay (`host:port`; the
/// UDP probe uses the same port). Takes at most about a second.
pub async fn prepare(relay: &str) -> Result<Prepared> {
    let relay_addrs: Vec<SocketAddr> =
        tokio::net::lookup_host(relay).await.with_context(|| format!("resolve {relay}"))?.collect();
    let (std_sock, dual) = bind_socket()?;
    let v4 = relay_addrs.iter().find(|a| a.is_ipv4()).copied();
    let v6 = relay_addrs.iter().find(|a| a.is_ipv6()).copied().filter(|_| dual);
    let targets: Vec<SocketAddr> = [v4, v6].into_iter().flatten().collect();
    if targets.is_empty() {
        bail!("{relay} has no usable address");
    }
    let sock = tokio::net::UdpSocket::from_std(std_sock)?;
    let port = sock.local_addr()?.port();
    let mut candidates = Vec::new();
    let mut answered: Vec<SocketAddr> = Vec::new();

    let mut nonce = [0u8; 16];
    getrandom(&mut nonce);
    let req = probe_request(&nonce);
    let mut buf = [0u8; 128];
    for _ in 0..4 {
        for t in targets.iter().filter(|t| !answered.contains(t)) {
            // An unreachable family (no IPv6 route) just fails to send.
            let _ = sock.send_to(&req, for_socket(*t, dual)).await;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_millis(250);
        while answered.len() < targets.len() {
            let Ok(r) = tokio::time::timeout_at(deadline, sock.recv_from(&mut buf)).await else { break };
            let Ok((n, from)) = r else { continue };
            let from = canonical(from);
            if targets.contains(&from) && !answered.contains(&from) {
                if let Some(public) = parse_probe_reply(&buf[..n], &nonce) {
                    answered.push(from);
                    let public = canonical(public);
                    if !candidates.contains(&public) {
                        candidates.push(public);
                    }
                }
            }
        }
        if answered.len() == targets.len() {
            break;
        }
    }
    if answered.is_empty() {
        log::debug!("no UDP answer from relay {relay}; only LAN addresses will be offered");
    }
    // LAN addresses: the interface used to reach the relay (or, for IPv6, the internet).
    let mut lan_targets = vec![v4];
    if dual {
        lan_targets.push(v6.or_else(|| "[2001:4860:4860::8888]:53".parse().ok()));
    }
    for t in lan_targets.into_iter().flatten() {
        if let Some(ip) = local_ip_toward(t) {
            if matches!(ip, IpAddr::V6(v6) if is_link_local_v6(&v6) || v6.to_ipv4_mapped().is_some()) {
                continue;
            }
            let lan = SocketAddr::new(ip, port);
            if !candidates.contains(&lan) {
                candidates.push(lan);
            }
        }
    }
    // Prefer IPv4 for relaying (it's what nearly every peer can also reach).
    answered.sort_by_key(|a| a.is_ipv6());
    Ok(Prepared { socket: sock.into_std()?, dual, relay: answered.first().copied(), candidates })
}

/// Keep only plausible peer candidates (no unspecified/multicast/broadcast/link-local).
pub fn sanitize(c: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in c.into_iter().map(canonical) {
        let ok = a.port() != 0
            && !a.ip().is_unspecified()
            && !a.ip().is_multicast()
            && a.ip() != IpAddr::V4(Ipv4Addr::BROADCAST)
            && !matches!(a.ip(), IpAddr::V6(v6) if is_link_local_v6(&v6));
        if ok && !out.contains(&a) {
            out.push(a);
        }
    }
    out.truncate(MAX_CANDIDATES);
    out
}

fn getrandom(buf: &mut [u8]) {
    let _ = rustls::crypto::ring::default_provider().secure_random.fill(buf);
}

/// A fresh random token for one connection attempt (32 hex digits).
pub fn new_token() -> String {
    let mut b = [0u8; 16];
    getrandom(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Send punch packets to `peers` (and, framed for relaying, to the relay so it learns
/// our address) every 100 ms for `dur`, from a clone of the socket the QUIC endpoint
/// uses, so they leave from the same NAT mapping.
fn punch(socket: UdpSocket, peers: Vec<SocketAddr>, relayed: Option<(SocketAddr, [u8; UDP_RELAY_HDR])>, dual: bool, dur: Duration) {
    std::thread::spawn(move || {
        let end = std::time::Instant::now() + dur;
        let relay_punch = relayed.map(|(addr, hdr)| {
            let mut p = hdr.to_vec();
            p.extend_from_slice(PUNCH);
            (for_socket(addr, dual), p)
        });
        while std::time::Instant::now() < end {
            for p in &peers {
                let _ = socket.send_to(PUNCH, for_socket(*p, dual));
            }
            if let Some((addr, p)) = &relay_punch {
                let _ = socket.send_to(p, addr);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(5)));
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    // Room for a few 1080p lossless keyframes in flight on fast links.
    t.stream_receive_window((8u32 << 20).into());
    t.receive_window((16u32 << 20).into());
    t.send_window(16 << 20);
    Arc::new(t)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn server_config() -> Result<quinn::ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["rd-p2p".into()])?;
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key)?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    cfg.transport_config(transport());
    Ok(cfg)
}

/// QUIC's outer TLS isn't what authenticates the host (the inner, pinned TLS session
/// is), so any certificate is accepted here.
#[derive(Debug)]
struct AnyCert(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for AnyCert {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config() -> Result<quinn::ClientConfig> {
    let mut tls = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AnyCert(provider())))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut cfg = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
    cfg.transport_config(transport());
    Ok(cfg)
}

/// Wraps the endpoint's UDP socket: datagrams to the relay's address get the relay
/// header, and the header is stripped from datagrams coming back from it.
struct RelayedSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    relay: SocketAddr,
    header: [u8; UDP_RELAY_HDR],
}

impl fmt::Debug for RelayedSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayedSocket").field("relay", &self.relay).finish()
    }
}

impl AsyncUdpSocket for RelayedSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, t: &Transmit) -> io::Result<()> {
        if canonical(t.destination) != self.relay {
            return self.inner.try_send(t);
        }
        // max_transmit_segments() is 1, so this is a single datagram.
        let mut buf = Vec::with_capacity(UDP_RELAY_HDR + t.contents.len());
        buf.extend_from_slice(&self.header);
        buf.extend_from_slice(t.contents);
        self.inner.try_send(&Transmit {
            destination: t.destination,
            ecn: t.ecn,
            contents: &buf,
            segment_size: None,
            src_ip: t.src_ip,
        })
    }

    fn poll_recv(&self, cx: &mut TaskContext, bufs: &mut [IoSliceMut<'_>], meta: &mut [RecvMeta]) -> Poll<io::Result<usize>> {
        let n = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        for (buf, m) in bufs.iter_mut().zip(meta.iter_mut()).take(n) {
            if canonical(m.addr) == self.relay {
                strip_relay_headers(&mut buf[..m.len], m);
            }
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }
    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }
}

/// Remove the relay header from every datagram in `buf` (several when the OS coalesced
/// them, `m.stride` apart), compacting the payloads. Datagrams without a valid header
/// (probe answers, stray packets) are dropped.
fn strip_relay_headers(buf: &mut [u8], m: &mut RecvMeta) {
    let stride = m.stride.max(1);
    let mut out = 0;
    let mut new_stride = 0;
    let mut start = 0;
    while start < buf.len() {
        let end = (start + stride).min(buf.len());
        if crate::relay::parse_udp_relay_header(&buf[start..end]).is_some() {
            let payload = end - start - UDP_RELAY_HDR;
            buf.copy_within(start + UDP_RELAY_HDR..end, out);
            if new_stride == 0 {
                new_stride = payload;
            } else if payload != new_stride && end != buf.len() {
                // A dropped datagram broke the equal spacing; keep what we have.
                break;
            }
            out += payload;
        }
        start = end;
    }
    m.len = out;
    m.stride = new_stride.max(1);
}

fn endpoint(
    socket: UdpSocket,
    server: Option<quinn::ServerConfig>,
    relayed: Option<(SocketAddr, [u8; UDP_RELAY_HDR])>,
) -> Result<quinn::Endpoint> {
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime"))?;
    let inner = runtime.wrap_udp_socket(socket)?;
    let sock: Arc<dyn AsyncUdpSocket> = match relayed {
        Some((relay, header)) => Arc::new(RelayedSocket { inner, relay, header }),
        None => inner,
    };
    Ok(quinn::Endpoint::new_with_abstract_socket(quinn::EndpointConfig::default(), server, sock, runtime)?)
}

/// The relay path for this session: relay address and our header, if usable.
fn relay_path(p: &Prepared, token: &str, udp_relay: bool, role: u8) -> Option<(SocketAddr, [u8; UDP_RELAY_HDR])> {
    if !udp_relay {
        return None;
    }
    let relay = p.relay?;
    let id = allocation_id(token)?;
    Some((relay, udp_relay_header(&id, role)))
}

fn usable(peers: Vec<SocketAddr>, dual: bool) -> Vec<SocketAddr> {
    sanitize(peers).into_iter().filter(|a| dual || a.is_ipv4()).collect()
}

/// Host side: wait up to `wait` for the client presenting `token` to connect, directly
/// or (when `udp_relay`) through the relay.
pub async fn listen(
    p: Prepared,
    peers: Vec<SocketAddr>,
    token: &str,
    udp_relay: bool,
    wait: Duration,
) -> Result<(P2pStream, SocketAddr)> {
    let peers = usable(peers, p.dual);
    let relayed = relay_path(&p, token, udp_relay, ROLE_HOST);
    if peers.is_empty() && relayed.is_none() {
        bail!("no peer candidates");
    }
    punch(p.socket.try_clone()?, peers, relayed, p.dual, wait);
    let ep = endpoint(p.socket, Some(server_config()?), relayed)?;
    let relay = relayed.map(|r| r.0);
    let token = token.to_string();
    let result = tokio::time::timeout(wait, async {
        // Several connections may arrive (one per candidate pair); the one whose stream
        // presents the token wins.
        let mut tries = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                incoming = ep.accept() => {
                    let Some(incoming) = incoming else { bail!("endpoint closed") };
                    let token = token.clone();
                    tries.spawn(async move {
                        let conn = incoming.await?;
                        let (send, mut recv) = conn.accept_bi().await?;
                        let mut hello = vec![0u8; 4 + token.len()];
                        recv.read_exact(&mut hello).await?;
                        if &hello[..4] != STREAM_MAGIC || hello[4..] != *token.as_bytes() {
                            conn.close(1u32.into(), b"bad token");
                            bail!("peer presented a wrong token");
                        }
                        let addr = canonical(conn.remote_address());
                        let relayed = Some(addr) == relay;
                        anyhow::Ok((P2pStream { send, recv, conn, relayed }, addr))
                    });
                }
                Some(done) = tries.join_next() => match done {
                    Ok(Ok(found)) => break anyhow::Ok(found),
                    Ok(Err(e)) => log::debug!("p2p attempt: {e:#}"),
                    Err(e) => log::debug!("p2p attempt: {e}"),
                }
            }
        }
    })
    .await;
    match result {
        Ok(Ok((s, addr))) => Ok((s.with_endpoint(ep), addr)),
        Ok(Err(e)) => Err(e),
        Err(_) => bail!("no direct connection within {} s", wait.as_secs()),
    }
}

/// Client side: try every host candidate at once (and, when `udp_relay`, the relay path
/// half a second later); the first QUIC connection wins.
pub async fn connect(
    p: Prepared,
    peers: Vec<SocketAddr>,
    token: &str,
    udp_relay: bool,
    wait: Duration,
) -> Result<(P2pStream, SocketAddr)> {
    let peers = usable(peers, p.dual);
    let relayed = relay_path(&p, token, udp_relay, ROLE_CLIENT);
    if peers.is_empty() && relayed.is_none() {
        bail!("host offered no candidates");
    }
    punch(p.socket.try_clone()?, peers.clone(), relayed, p.dual, wait);
    let mut ep = endpoint(p.socket, None, relayed)?;
    ep.set_default_client_config(client_config()?);
    let relay = relayed.map(|r| r.0);
    let result = tokio::time::timeout(wait, async {
        let mut tries = tokio::task::JoinSet::new();
        let mut last = anyhow!("no candidate answered");
        let attempts = peers.iter().map(|a| (*a, Duration::ZERO)).chain(relay.map(|r| (r, RELAY_DELAY)));
        for (addr, delay) in attempts {
            match ep.connect(addr, "rd-p2p") {
                Ok(connecting) => {
                    tries.spawn(async move {
                        tokio::time::sleep(delay).await;
                        connecting.await
                    });
                }
                Err(e) => last = e.into(),
            }
        }
        while let Some(done) = tries.join_next().await {
            match done {
                Ok(Ok(conn)) => return Ok(conn),
                Ok(Err(e)) => last = e.into(),
                Err(e) => last = e.into(),
            }
        }
        Err(last)
    })
    .await;
    let conn = match result {
        Ok(r) => r?,
        Err(_) => bail!("no direct connection within {} s", wait.as_secs()),
    };
    let (mut send, recv) = conn.open_bi().await?;
    send.write_all(STREAM_MAGIC).await?;
    send.write_all(token.as_bytes()).await?;
    let addr = canonical(conn.remote_address());
    let relayed = Some(addr) == relay;
    Ok((P2pStream { send, recv, conn, relayed }.with_endpoint(ep), addr))
}

/// One QUIC stream, usable like a TCP stream.
pub struct P2pStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    conn: quinn::Connection,
    relayed: bool,
}

impl P2pStream {
    fn with_endpoint(self, ep: quinn::Endpoint) -> P2pStream {
        // The endpoint's driver keeps running while the connection is alive; close it
        // once the connection is gone so the socket is released.
        let conn = self.conn.clone();
        tokio::spawn(async move {
            conn.closed().await;
            ep.close(0u32.into(), b"");
            ep.wait_idle().await;
        });
        self
    }

    /// Smoothed round-trip time of the connection.
    pub fn rtt(&self) -> Duration {
        self.conn.rtt()
    }

    /// The connection runs through the relay's UDP port rather than directly.
    pub fn is_relayed(&self) -> bool {
        self.relayed
    }
}

impl Drop for P2pStream {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"bye");
    }
}

impl AsyncRead for P2pStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for P2pStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf).map_err(std::io::Error::from)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// Any byte stream a session can run over (TCP, relayed TCP or a P2P QUIC stream).
pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{parse_udp_relay_header, probe_reply};
    use std::collections::HashMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A relay stand-in that answers address probes and forwards relayed datagrams.
    async fn relay_server() -> SocketAddr {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = s.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut seen: HashMap<u8, SocketAddr> = HashMap::new();
            while let Ok((n, from)) = s.recv_from(&mut buf).await {
                if let Some(r) = probe_reply(&buf[..n], from) {
                    let _ = s.send_to(&r, from).await;
                } else if let Some((_, role)) = parse_udp_relay_header(&buf[..n]) {
                    seen.insert(role, from);
                    let other = if role == ROLE_HOST { ROLE_CLIENT } else { ROLE_HOST };
                    if let Some(to) = seen.get(&other) {
                        let _ = s.send_to(&buf[..n], to).await;
                    }
                }
            }
        });
        addr
    }

    async fn exchange(mut c: P2pStream, mut s: P2pStream) {
        c.write_all(b"hello host").await.unwrap();
        let mut buf = [0u8; 10];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello host");
        // Enough to need many packets (and so many relayed datagrams).
        let big = vec![7u8; 300_000];
        s.write_all(&big).await.unwrap();
        let mut got = vec![0u8; big.len()];
        c.read_exact(&mut got).await.unwrap();
        assert_eq!(got, big);
    }

    #[tokio::test]
    async fn direct_stream_end_to_end() {
        let relay = relay_server().await.to_string();
        let host = prepare(&relay).await.unwrap();
        let client = prepare(&relay).await.unwrap();
        assert!(host.candidates.iter().any(|a| a.ip().is_loopback()), "{:?}", host.candidates);
        assert!(host.relay_reachable());
        let (hc, cc) = (host.candidates.clone(), client.candidates.clone());
        let token = new_token();
        let t2 = token.clone();
        let h = tokio::spawn(async move { listen(host, cc, &t2, true, Duration::from_secs(5)).await });
        let (c, _) = connect(client, hc, &token, true, Duration::from_secs(5)).await.unwrap();
        let (s, _) = h.await.unwrap().unwrap();
        assert!(!c.is_relayed() && !s.is_relayed(), "direct path should win");
        exchange(c, s).await;
    }

    #[tokio::test]
    async fn relayed_udp_when_direct_fails() {
        let relay = relay_server().await.to_string();
        let host = prepare(&relay).await.unwrap();
        let client = prepare(&relay).await.unwrap();
        let token = new_token();
        let t2 = token.clone();
        // Neither side gets usable direct candidates, as with two symmetric NATs.
        let h = tokio::spawn(async move { listen(host, vec![], &t2, true, Duration::from_secs(5)).await });
        let (c, addr) = connect(client, vec![], &token, true, Duration::from_secs(5)).await.unwrap();
        assert_eq!(addr.to_string(), relay);
        let (s, _) = h.await.unwrap().unwrap();
        assert!(c.is_relayed() && s.is_relayed());
        exchange(c, s).await;
    }

    #[tokio::test]
    async fn unreachable_peer_gives_up_in_time() {
        let relay = relay_server().await.to_string();
        let client = prepare(&relay).await.unwrap();
        // Nothing listens there (TEST-NET-1 address, never routed).
        let t = std::time::Instant::now();
        let r = connect(client, vec!["192.0.2.1:9".parse().unwrap()], "x", false, Duration::from_secs(1)).await;
        assert!(r.is_err());
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
    }

    #[test]
    fn sanitize_drops_junk() {
        let c = sanitize(vec![
            "0.0.0.0:5".parse().unwrap(),
            "1.2.3.4:0".parse().unwrap(),
            "224.0.0.1:5".parse().unwrap(),
            "255.255.255.255:5".parse().unwrap(),
            "[fe80::1]:5".parse().unwrap(),
            "1.2.3.4:5".parse().unwrap(),
            "[::ffff:1.2.3.4]:5".parse().unwrap(),
            "[2001:db8::1]:5".parse().unwrap(),
        ]);
        assert_eq!(c, vec!["1.2.3.4:5".parse::<SocketAddr>().unwrap(), "[2001:db8::1]:5".parse().unwrap()]);
    }

    #[test]
    fn strips_coalesced_relay_datagrams() {
        let hdr = udp_relay_header(&[1; 16], ROLE_HOST);
        let mut buf = Vec::new();
        for (i, len) in [(1u8, 10usize), (2, 10), (3, 4)] {
            buf.extend_from_slice(&hdr);
            buf.extend(std::iter::repeat(i).take(len));
        }
        let mut m = RecvMeta { addr: "1.2.3.4:5".parse().unwrap(), len: buf.len(), stride: UDP_RELAY_HDR + 10, ecn: None, dst_ip: None };
        strip_relay_headers(&mut buf, &mut m);
        assert_eq!((m.len, m.stride), (24, 10));
        assert_eq!(&buf[..24], &[[1u8; 10].as_slice(), &[2u8; 10], &[3u8; 4]].concat()[..]);
    }

    #[tokio::test]
    async fn wrong_token_is_refused() {
        let relay = relay_server().await.to_string();
        let host = prepare(&relay).await.unwrap();
        let client = prepare(&relay).await.unwrap();
        let (hc, cc) = (host.candidates.clone(), client.candidates.clone());
        let h = tokio::spawn(async move { listen(host, cc, "right", false, Duration::from_secs(2)).await });
        let _c = connect(client, hc, "wrong", false, Duration::from_secs(2)).await;
        assert!(h.await.unwrap().is_err());
    }
}
