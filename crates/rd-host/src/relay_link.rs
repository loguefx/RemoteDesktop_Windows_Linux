//! Host side of the relay: keep a control connection registered with the relay and
//! open a data connection for every client that asks for us. Each data connection is
//! handed to the normal TLS/login path, so the relay only ever carries ciphertext.
//!
//! When the client offers peer-to-peer candidates (and `p2p` is on), the host also
//! offers its own and listens for a direct QUIC connection for a few seconds. If the
//! client gets through, that stream goes through the same TLS/login path and the relayed
//! connection is simply dropped by the client.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rd_core::framing::{read_msg, write_msg};
use rd_core::p2p::{self, AsyncStream};
use rd_core::relay::{RelayHello, RelayNotice, RelayReply, RELAY_VERSION};
use tokio::net::TcpStream;

/// How long the host waits for a direct connection after answering through the relay.
const P2P_WAIT: Duration = Duration::from_secs(8);

#[derive(Clone, Debug)]
pub struct RelayConfig {
    /// `relay.example.com:47801`
    pub addr: String,
    /// Public host id, e.g. `482-913-077`.
    pub id: String,
    /// Proves to the relay that we own `id` (registered on first use).
    pub secret: String,
    /// Registration key, if the relay requires one.
    pub key: Option<String>,
    /// Offer direct peer-to-peer connections.
    pub p2p: bool,
}

pub type Conn = Box<dyn AsyncStream>;

/// How a connection reached us, for logs and rate limiting.
pub struct Origin {
    /// The client's public address as the relay saw it.
    pub client_addr: String,
    /// "via relay", "peer-to-peer" or "relayed (UDP)".
    pub path: &'static str,
}

pub async fn run<F>(cfg: RelayConfig, on_connection: F)
where
    F: Fn(Conn, Origin) + Send + Sync + 'static,
{
    let on_connection = Arc::new(on_connection);
    let mut backoff = Duration::from_secs(1);
    loop {
        match control(&cfg, &on_connection).await {
            Ok(()) => backoff = Duration::from_secs(1),
            Err(e) => log::warn!("relay {}: {e:#}", cfg.addr),
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(Duration::from_secs(30));
    }
}

async fn control<F>(cfg: &RelayConfig, on_connection: &Arc<F>) -> Result<()>
where
    F: Fn(Conn, Origin) + Send + Sync + 'static,
{
    let mut ctl = TcpStream::connect(&cfg.addr).await.context("connect")?;
    ctl.set_nodelay(true)?;
    let hello = RelayHello::Host {
        version: RELAY_VERSION,
        id: cfg.id.clone(),
        secret: cfg.secret.clone(),
        key: cfg.key.clone(),
    };
    write_msg(&mut ctl, &hello).await?;
    match read_msg::<_, RelayReply>(&mut ctl).await? {
        RelayReply::Ok => log::info!("registered with relay {} as {}", cfg.addr, cfg.id),
        RelayReply::Error(e) => bail!("relay refused registration: {e}"),
        RelayReply::Peer { .. } => bail!("unexpected reply from relay"),
    }
    loop {
        // The relay pings every 30 s; silence for 90 s means the link is dead.
        let notice = tokio::time::timeout(Duration::from_secs(90), read_msg::<_, RelayNotice>(&mut ctl))
            .await
            .context("relay went silent")??;
        match notice {
            RelayNotice::Ping => {}
            RelayNotice::Connect { session, client_addr, candidates, token, udp_relay } => {
                let (cfg, cb) = (cfg.clone(), on_connection.clone());
                tokio::spawn(answer(cfg, cb, session, client_addr, candidates, token, udp_relay));
            }
        }
    }
}

async fn answer<F>(
    cfg: RelayConfig,
    on_connection: Arc<F>,
    session: String,
    client_addr: String,
    candidates: Vec<std::net::SocketAddr>,
    token: String,
    udp_relay: bool,
) where
    F: Fn(Conn, Origin) + Send + Sync + 'static,
{
    let prepared = if cfg.p2p && !candidates.is_empty() && !token.is_empty() {
        match tokio::time::timeout(Duration::from_millis(1500), p2p::prepare(&cfg.addr)).await {
            Ok(Ok(p)) => Some(p),
            Ok(Err(e)) => {
                log::info!("peer-to-peer setup failed: {e:#}");
                None
            }
            Err(_) => None,
        }
    } else {
        None
    };
    let mine = prepared.as_ref().map(|p| p.candidates.clone()).unwrap_or_default();
    match accept(&cfg, session, mine).await {
        Ok(stream) => on_connection(Box::new(stream), Origin { client_addr: client_addr.clone(), path: "via relay" }),
        Err(e) => {
            log::warn!("relay data connection failed: {e:#}");
            return;
        }
    }
    if let Some(p) = prepared {
        match p2p::listen(p, candidates, &token, udp_relay, P2P_WAIT).await {
            Ok((stream, addr)) => {
                let path = if stream.is_relayed() { "relayed (UDP)" } else { "peer-to-peer" };
                log::info!("{path} connection with {addr} ({client_addr} via relay)");
                on_connection(Box::new(stream), Origin { client_addr, path });
            }
            Err(e) => log::info!("{client_addr}: no direct connection ({e:#}); the session stays on the relay"),
        }
    }
}

async fn accept(cfg: &RelayConfig, session: String, candidates: Vec<std::net::SocketAddr>) -> Result<TcpStream> {
    let mut s = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(&cfg.addr)).await??;
    s.set_nodelay(true)?;
    let hello = RelayHello::Accept {
        version: RELAY_VERSION,
        id: cfg.id.clone(),
        secret: cfg.secret.clone(),
        session,
        candidates,
    };
    write_msg(&mut s, &hello).await?;
    match read_msg::<_, RelayReply>(&mut s).await? {
        RelayReply::Ok => Ok(s),
        RelayReply::Error(e) => bail!("{e}"),
        RelayReply::Peer { .. } => bail!("unexpected reply from relay"),
    }
}
