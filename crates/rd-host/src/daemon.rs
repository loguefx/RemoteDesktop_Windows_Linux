//! The network-facing daemon (runs as the Windows service / systemd unit).
//!
//! Per connection: TLS handshake -> `ClientHello` -> authenticate against SQLite ->
//! either an admin RPC loop, or a desktop session.
//!
//! Desktop sessions share one **desk**: a single agent in the user's desktop session
//! plus a tile canvas holding the latest compressed version of every 64x64 tile. Each
//! viewer has a watermark; whenever the canvas changes it is sent just the tiles newer
//! than its watermark. A slow viewer therefore skips intermediate frames instead of
//! delaying everyone else, and a new viewer simply gets every tile (a keyframe).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rd_core::audio::AudioChunk;
use rd_core::codec::{EncodedFrame, Tile, TILE};
use rd_core::framing::{read_msg, read_msg_max, write_msg, MAX_HELLO};
use rd_core::proto::*;
use rd_core::tls::TlsAcceptor;
use rd_core::PROTOCOL_VERSION;
use rd_platform::Backend;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Notify};

use crate::db::Db;
use crate::relay_link::RelayConfig;
use crate::spawn::{self, AgentArgs, AgentProcess, SpawnMode};
use crate::video_pipe::VideoPipe;

pub struct Config {
    pub data_dir: PathBuf,
    /// Direct listening address; `None` = relay only.
    pub bind: Option<SocketAddr>,
    pub backend: Backend,
    pub fps: u32,
    pub spawn_mode: SpawnMode,
    pub agent_log: Option<PathBuf>,
    pub max_viewers: usize,
    /// Highest H.264 bitrate per viewer (kbit/s).
    pub video_kbps: u32,
    /// Hardware H.264 encoder when available, or always OpenH264.
    pub video_encoder: rd_core::video::EncoderChoice,
    pub relay: Option<RelayConfig>,
    /// Name shown in the app (chosen at setup; defaults to the computer name).
    pub name: String,
    /// Account used when the app signs in with just a PIN (set up from the app).
    pub owner: Option<String>,
    /// Ask the router to forward the port (UPnP) for access from the internet.
    pub upnp: bool,
    /// Dynamic DNS: (name, update URL with `{ip}`), so the app finds this computer after
    /// the router's internet address changes.
    pub ddns: Option<(String, String)>,
    /// Ask the person at the computer before anyone connects.
    pub ask_to_allow: bool,
    /// Serve the browser viewer on the same port.
    pub web: bool,
}

pub(crate) struct Shared {
    cfg: Config,
    db: Mutex<Db>,
    host_name: String,
    acceptor: TlsAcceptor,
    desk: tokio::sync::Mutex<Option<Arc<Desk>>>,
    /// Failed logins per source IP: (count, window start).
    failures: Mutex<HashMap<IpAddr, (u32, Instant)>>,
    next_client: AtomicU32,
}

impl Shared {
    pub(crate) fn web_enabled(&self) -> bool {
        self.cfg.web
    }
}

/// How long the person at the computer has to answer "Allow ... to connect?".
const ASK_TIMEOUT: Duration = Duration::from_secs(60);

const IP_MAX_FAILURES: u32 = 10;
const IP_WINDOW: Duration = Duration::from_secs(600);

/// Run until `shutdown` flips to true.
pub async fn serve(cfg: Config, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    rd_core::tls::ensure_host_cert(&cfg.data_dir, &crate::paths::host_name())?;
    let host_name = cfg.name.clone();
    let (acceptor, fingerprint) = rd_core::tls::host_acceptor(&cfg.data_dir)?;
    let db = Db::open(&cfg.data_dir)?;
    if db.user_count()? == 0 {
        log::warn!("no user accounts exist yet - create the admin with `rd-host user add <name>`");
    }
    log::info!("certificate fingerprint {fingerprint}");
    let listener = match cfg.bind {
        Some(addr) => {
            let l = TcpListener::bind(addr).await.with_context(|| format!("bind {addr}"))?;
            log::info!("listening on {addr}");
            Some(l)
        }
        None => None,
    };
    let relay = cfg.relay.clone();
    let reach = crate::reach::SharedReach::default();
    if let Some(addr) = cfg.bind {
        let base = rd_core::discovery::Announce {
            name: cfg.name.clone(),
            fingerprint: fingerprint.clone(),
            port: addr.port(),
            protocol: PROTOCOL_VERSION,
            public: None,
            public_note: (!cfg.upnp).then(|| "access from the internet is turned off".to_string()),
            relay: cfg.relay.as_ref().map(|r| format!("{}@{}", r.id, r.addr)),
            os: std::env::consts::OS.to_string(),
            public_name: None,
            macs: crate::reach::mac_addresses(),
            ask_to_allow: cfg.ask_to_allow,
        };
        if cfg.upnp {
            tokio::spawn(crate::reach::keep_port_mapped(addr.port(), reach.clone(), cfg.ddns.clone()));
        } else {
            reach.lock().unwrap().note = base.public_note.clone();
        }
        tokio::spawn(crate::reach::answer_discovery(addr.port(), base, reach.clone()));
    }
    let shared = Arc::new(Shared {
        cfg,
        db: Mutex::new(db),
        host_name,
        acceptor,
        desk: tokio::sync::Mutex::new(None),
        failures: Mutex::new(HashMap::new()),
        next_client: AtomicU32::new(1),
    });

    if let Some(relay) = relay {
        let shared = shared.clone();
        tokio::spawn(crate::relay_link::run(relay, move |stream, origin| {
            let shared = shared.clone();
            tokio::spawn(async move {
                let ip = origin.client_addr.parse::<SocketAddr>().map(|a| a.ip()).unwrap_or(IpAddr::from([0, 0, 0, 0]));
                let peer = format!("{} {}", origin.client_addr, origin.path);
                if let Err(e) = handle(shared, stream, peer.clone(), ip).await {
                    let msg = format!("{e:#}");
                    if origin.path == "via relay" && msg.contains("handshake eof") {
                        // The client went peer-to-peer and dropped its relayed fallback.
                        log::debug!("{peer}: relayed fallback unused");
                    } else {
                        log::info!("{peer}: {msg}");
                    }
                }
            });
        }));
    }
    if listener.is_none() && shared.cfg.relay.is_none() {
        bail!("neither direct listening nor a relay is configured");
    }

    loop {
        tokio::select! {
            _ = shutdown.changed() => { if *shutdown.borrow() { break; } }
            r = async { listener.as_ref().unwrap().accept().await }, if listener.is_some() => {
                let (sock, peer) = match r {
                    Ok(x) => x,
                    Err(e) => { log::warn!("accept: {e}"); continue; }
                };
                let _ = sock.set_nodelay(true);
                let shared = shared.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle(shared, sock, peer.to_string(), peer.ip()).await {
                        log::info!("{peer}: {e:#}");
                    }
                });
            }
        }
    }
    log::info!("daemon stopping");
    crate::reach::release(&reach).await;
    if let Some(desk) = shared.desk.lock().await.take() {
        desk.shutdown("host is shutting down");
    }
    Ok(())
}

async fn handle<S>(shared: Arc<Shared>, sock: S, peer: String, ip: IpAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut tls = tokio::time::timeout(Duration::from_secs(10), shared.acceptor.accept(sock))
        .await
        .map_err(|_| anyhow!("TLS handshake timeout"))?
        .context("TLS handshake")?;
    // A browser speaks HTTP here (the browser viewer); the app sends a length prefix.
    let mut first = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(60), tls.read_exact(&mut first))
        .await
        .map_err(|_| anyhow!("login timeout"))??;
    let stream = Prefixed { head: first.to_vec(), inner: tls };
    if crate::web::is_http(&first) {
        return crate::web::serve(shared, stream, peer, ip).await;
    }
    session(shared, stream, peer, ip).await
}

/// A stream with some bytes already read off the front, put back.
struct Prefixed<S> {
    head: Vec<u8>,
    inner: S,
}

impl<S: AsyncRead + Unpin> AsyncRead for Prefixed<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !self.head.is_empty() {
            let n = self.head.len().min(buf.remaining());
            buf.put_slice(&self.head[..n]);
            self.head.drain(..n);
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Prefixed<S> {
    fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, b: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, b)
    }
    fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Sign-in and the session that follows, on an established (decrypted) stream. Also used
/// by the browser viewer, over an in-memory pipe.
pub(crate) async fn session<S>(shared: Arc<Shared>, mut tls: S, peer: String, ip: IpAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let hello: ClientHello = tokio::time::timeout(Duration::from_secs(60), read_msg_max(&mut tls, MAX_HELLO))
        .await
        .map_err(|_| anyhow!("login timeout"))??;

    let deny = |msg: String| LoginResult::Denied(msg);
    if hello.version != PROTOCOL_VERSION {
        write_msg(&mut tls, &deny(format!("protocol mismatch: host v{PROTOCOL_VERSION}, client v{}", hello.version))).await?;
        return Ok(());
    }
    if ip_blocked(&shared, ip) {
        write_msg(&mut tls, &deny("too many failed attempts from your address; try again later".into())).await?;
        return Ok(());
    }

    // The app signs in with just a PIN: no username means the owner set up from the app.
    let mut hello = hello;
    if hello.username.is_empty() {
        match &shared.cfg.owner {
            Some(o) => hello.username = o.clone(),
            None => {
                write_msg(&mut tls, &deny("this computer has no owner account; sign in with a username".into())).await?;
                return Ok(());
            }
        }
    }

    // Argon2 is deliberately slow: keep it off the async workers.
    let auth = {
        let shared = shared.clone();
        let (username, cred, code) = (hello.username.clone(), hello.credential.clone(), hello.code.clone());
        tokio::task::spawn_blocking(move || shared.db.lock().unwrap().authenticate(&username, &cred, code.as_deref())).await??
    };
    let method = match hello.credential {
        Credential::Password(_) => "password",
        Credential::Pin(_) => "pin",
        Credential::DeviceToken(_) => "device",
    };
    let user = match auth {
        Ok(u) => u,
        Err(crate::db::AuthError::NeedCode) => {
            write_msg(&mut tls, &LoginResult::NeedCode).await?;
            return Ok(());
        }
        Err(e) => {
            note_failure(&shared, ip);
            shared.db.lock().unwrap().audit(Some(&hello.username), &peer, &format!("login failed ({method}): {e}"));
            write_msg(&mut tls, &deny(e.to_string())).await?;
            return Ok(());
        }
    };
    let perms = user.effective();
    if hello.mode == Mode::Desktop && !perms.view {
        write_msg(&mut tls, &deny("your account is not allowed to view this computer".into())).await?;
        return Ok(());
    }

    let device_token = match &hello.remember_device_as {
        Some(name) if !matches!(hello.credential, Credential::DeviceToken(_)) => {
            Some(shared.db.lock().unwrap().add_device(&user.username, name)?)
        }
        _ => None,
    };
    shared.db.lock().unwrap().audit(
        Some(&user.username),
        &peer,
        &format!("login ok ({method}, {:?}){}", hello.mode, if device_token.is_some() { ", device remembered" } else { "" }),
    );
    log::info!("{peer}: '{}' signed in from {:?} ({method}, {:?})", user.username, hello.device, hello.mode);
    write_msg(&mut tls, &LoginResult::Ok { user: user.clone(), host_name: shared.host_name.clone(), device_token }).await?;

    match hello.mode {
        Mode::Admin => admin_loop(&shared, &user, &mut tls).await,
        Mode::Desktop => {
            let label = viewer_label(&user.username, &hello.device);
            let r = viewer_session(&shared, &user, label, tls).await;
            shared.db.lock().unwrap().audit(Some(&user.username), &peer, "session ended");
            r
        }
    }
}

/// "owner on Laptop (windows)", for the host's on-screen notice and other viewers.
fn viewer_label(username: &str, device: &str) -> String {
    let device: String = device.chars().filter(|c| !c.is_control()).take(60).collect();
    let device = device.trim();
    if device.is_empty() {
        username.to_string()
    } else {
        format!("{username} on {device}")
    }
}

fn ip_blocked(shared: &Shared, ip: IpAddr) -> bool {
    let mut f = shared.failures.lock().unwrap();
    match f.get(&ip) {
        Some((n, start)) if start.elapsed() < IP_WINDOW => *n >= IP_MAX_FAILURES,
        Some(_) => {
            f.remove(&ip);
            false
        }
        None => false,
    }
}

fn note_failure(shared: &Shared, ip: IpAddr) {
    let mut f = shared.failures.lock().unwrap();
    // Forget old entries now and then, so addresses that stopped trying don't pile up.
    if f.len() > 10_000 {
        f.retain(|_, (_, start)| start.elapsed() < IP_WINDOW);
    }
    let e = f.entry(ip).or_insert((0, Instant::now()));
    if e.1.elapsed() >= IP_WINDOW {
        *e = (0, Instant::now());
    }
    e.0 += 1;
}

fn is_disconnect(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>().is_some_and(|io| {
        matches!(
            io.kind(),
            std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe
        )
    })
}

// ================================================================== tile canvas

#[derive(Default)]
struct Canvas {
    width: u32,
    height: u32,
    cols: u32,
    /// (version, tile) per grid cell.
    tiles: Vec<Option<(u64, Tile)>>,
    /// When each cell last changed.
    stamps: Vec<Instant>,
    /// Bumped whenever the size changes; viewers on an older generation get a keyframe.
    gen: u64,
    version: u64,
}

impl Canvas {
    fn apply(&mut self, f: EncodedFrame) {
        if f.width != self.width || f.height != self.height || self.tiles.is_empty() {
            self.width = f.width;
            self.height = f.height;
            self.cols = f.width.div_ceil(TILE);
            let rows = f.height.div_ceil(TILE);
            self.tiles = vec![None; (self.cols * rows) as usize];
            self.stamps = vec![Instant::now(); self.tiles.len()];
            self.gen += 1;
        }
        let now = Instant::now();
        for t in f.tiles {
            let idx = ((t.y / TILE) * self.cols + t.x / TILE) as usize;
            if let Some(slot) = self.tiles.get_mut(idx) {
                self.version += 1;
                *slot = Some((self.version, t));
                self.stamps[idx] = now;
            }
        }
    }

    /// Tiles newer than `since` (or all of them for a viewer on an old generation).
    fn delta(&self, since: u64, gen: u64) -> Option<(EncodedFrame, u64, u64)> {
        if self.width == 0 {
            return None;
        }
        let keyframe = gen != self.gen;
        let tiles: Vec<Tile> = self
            .tiles
            .iter()
            .flatten()
            .filter(|(v, _)| keyframe || *v > since)
            .map(|(_, t)| t.clone())
            .collect();
        if tiles.is_empty() && !keyframe {
            return None;
        }
        Some((EncodedFrame { width: self.width, height: self.height, keyframe, tiles }, self.version, self.gen))
    }
}

/// For H.264 viewers: once the picture stops moving, the areas H.264 drew are resent
/// as exact lossless tiles, a slice at a time so the link is never hogged and new motion
/// takes over immediately. Each grid cell remembers which canvas version it last got
/// losslessly, so progress survives small changes elsewhere and a slice always carries
/// the newest content (never a stale tile).
const SHARPEN_TICK: Duration = Duration::from_millis(250);

struct Sharpener {
    gen: u64,
    sent: Vec<u64>,
    cursor: usize,
}

impl Default for Sharpener {
    fn default() -> Self {
        Sharpener { gen: u64::MAX, sent: Vec::new(), cursor: 0 }
    }
}

impl Sharpener {
    fn reset(&mut self) {
        *self = Sharpener::default();
    }

    /// Next slice of at most about `budget` bytes, or `None` when everything is sharp.
    /// Only cells unchanged for `settle` are included, so parts of the screen that keep
    /// moving (a video, a spinner) don't stop the rest from being sharpened.
    fn next(&mut self, canvas: &Canvas, budget: usize, settle: Duration) -> Option<EncodedFrame> {
        if canvas.width == 0 || canvas.width % 2 == 1 || canvas.height % 2 == 1 {
            // (H.264 drops the last column/row of odd sizes; tiles would not line up.)
            return None;
        }
        if self.gen != canvas.gen || self.sent.len() != canvas.tiles.len() {
            self.gen = canvas.gen;
            self.sent = vec![0; canvas.tiles.len()];
            self.cursor = 0;
        }
        let n = canvas.tiles.len();
        let mut tiles = Vec::new();
        let mut bytes = 0;
        for k in 0..n {
            let i = (self.cursor + k) % n;
            if let Some((v, t)) = &canvas.tiles[i] {
                if *v > self.sent[i] && canvas.stamps[i].elapsed() >= settle {
                    self.sent[i] = *v;
                    bytes += t.data.len() + 16;
                    tiles.push(t.clone());
                    if bytes >= budget {
                        self.cursor = (i + 1) % n;
                        break;
                    }
                }
            }
        }
        (!tiles.is_empty()).then(|| EncodedFrame { width: canvas.width, height: canvas.height, keyframe: false, tiles })
    }
}

// ================================================================== desk (shared desktop)

struct Viewer {
    /// "user on device".
    label: String,
    perms: Permissions,
    tx: mpsc::UnboundedSender<HostMsg>,
    audio_tx: mpsc::Sender<AudioChunk>,
    wants_audio: bool,
    /// Lock the computer if this viewer is the last to leave.
    lock_on_leave: bool,
    /// Asked for the privacy screen.
    privacy: bool,
}

pub(crate) struct Desk {
    agent_tx: mpsc::UnboundedSender<AgentCmd>,
    canvas: Mutex<Canvas>,
    changed: watch::Sender<u64>,
    viewers: Mutex<HashMap<u32, Viewer>>,
    displays: Mutex<Option<(Vec<DisplayInfo>, u32)>>,
    status: Mutex<String>,
    process: Mutex<Option<AgentProcess>>,
    audio_on: Mutex<bool>,
    /// The pointer's current look, for viewers that join later.
    cursor: Mutex<Option<CursorShape>>,
    /// Privacy screen requested of the agent.
    privacy_on: Mutex<bool>,
    /// Viewer whose "fit to window" changed the resolution.
    fit_owner: Mutex<Option<u32>>,
    /// "Allow ... to connect?" questions waiting for the person at the computer.
    asks: Mutex<HashMap<u32, tokio::sync::oneshot::Sender<bool>>>,
}

impl Desk {
    fn broadcast(&self, msg: HostMsg, filter: impl Fn(&Viewer) -> bool) {
        for v in self.viewers.lock().unwrap().values() {
            if filter(v) {
                let _ = v.tx.send(msg.clone());
            }
        }
    }

    fn viewer_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.viewers.lock().unwrap().values().map(|v| v.label.clone()).collect();
        names.sort();
        names
    }

    /// Tell every viewer, and the notice on the host's screen, who is connected.
    fn viewers_changed(&self) {
        let names = self.viewer_names();
        let _ = self.agent_tx.send(AgentCmd::Viewers(names.clone()));
        self.broadcast(HostMsg::Viewers(names), |_| true);
    }

    fn update_audio(&self) {
        let want = self.viewers.lock().unwrap().values().any(|v| v.wants_audio && v.perms.view);
        let mut on = self.audio_on.lock().unwrap();
        if *on != want {
            *on = want;
            let _ = self.agent_tx.send(AgentCmd::SetAudio(want));
        }
    }

    /// Privacy screen on while any viewer with control wants it.
    fn update_privacy(&self) {
        let want = self.viewers.lock().unwrap().values().any(|v| v.privacy && v.perms.control);
        let mut on = self.privacy_on.lock().unwrap();
        if *on != want {
            *on = want;
            let _ = self.agent_tx.send(AgentCmd::Privacy(want));
        }
    }

    fn shutdown(&self, why: &str) {
        self.broadcast(HostMsg::Bye(why.to_string()), |_| true);
        let _ = self.agent_tx.send(AgentCmd::Input(InputEvent::ReleaseAll));
        let _ = self.agent_tx.send(AgentCmd::Stop);
        if let Some(mut p) = self.process.lock().unwrap().take() {
            // Let the agent release keys, lock the screen and exit on its own first.
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(1500));
                p.kill();
            });
        }
    }
}

/// Start the agent if no desk is running, else return the running one.
async fn join_desk(shared: &Arc<Shared>) -> Result<Arc<Desk>> {
    let mut slot = shared.desk.lock().await;
    if let Some(d) = slot.as_ref() {
        return Ok(d.clone());
    }

    let token = crate::db::random_token();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let mut args = vec![
        "agent".to_string(),
        "--connect".into(),
        format!("127.0.0.1:{port}"),
        "--fps".into(),
        shared.cfg.fps.to_string(),
    ];
    if shared.cfg.backend != Backend::Auto {
        args.extend(["--backend".into(), shared.cfg.backend.to_string()]);
    }
    if let Some(log) = &shared.cfg.agent_log {
        args.extend(["--log-file".into(), log.to_string_lossy().into_owned()]);
    }
    if cfg!(windows) && shared.cfg.spawn_mode == SpawnMode::UserSession {
        args.push("--impersonate-console-user".into());
    }
    let mode = shared.cfg.spawn_mode;
    let spawn_args = AgentArgs { exe: std::env::current_exe()?, args, token: token.clone() };
    let mut process = tokio::task::spawn_blocking(move || spawn::spawn(mode, &spawn_args))
        .await?
        .context("could not start desktop agent")?;

    let sock = match tokio::time::timeout(Duration::from_secs(30), accept_agent(&listener, &token)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            process.kill();
            return Err(e.context("desktop agent did not connect"));
        }
        Err(_) => {
            process.kill();
            bail!("desktop agent did not connect (timed out)");
        }
    };
    drop(listener);
    let (mut a_rd, mut a_wr) = sock.into_split();
    let (agent_tx, mut agent_rx) = mpsc::unbounded_channel::<AgentCmd>();
    let desk = Arc::new(Desk {
        agent_tx,
        canvas: Mutex::new(Canvas::default()),
        changed: watch::channel(0).0,
        viewers: Mutex::new(HashMap::new()),
        displays: Mutex::new(None),
        status: Mutex::new("starting desktop agent...".into()),
        process: Mutex::new(Some(process)),
        audio_on: Mutex::new(false),
        cursor: Mutex::new(None),
        privacy_on: Mutex::new(false),
        fit_owner: Mutex::new(None),
        asks: Mutex::new(HashMap::new()),
    });

    // daemon -> agent
    tokio::spawn(async move {
        while let Some(cmd) = agent_rx.recv().await {
            let stop = matches!(cmd, AgentCmd::Stop);
            if write_msg(&mut a_wr, &cmd).await.is_err() || stop {
                break;
            }
        }
    });

    // agent -> viewers
    {
        let (desk, shared) = (desk.clone(), shared.clone());
        tokio::spawn(async move {
            let why = loop {
                let ev = match read_msg::<_, AgentEvent>(&mut a_rd).await {
                    Ok(ev) => ev,
                    Err(e) => break if is_disconnect(&e) { "desktop agent exited".to_string() } else { format!("{e:#}") },
                };
                match ev {
                    AgentEvent::Ready { backend, width, height } => {
                        log::info!("agent ready: {backend} {width}x{height}");
                        let s = format!("connected ({backend})");
                        *desk.status.lock().unwrap() = s.clone();
                        desk.broadcast(HostMsg::Status(s), |_| true);
                    }
                    AgentEvent::Frame(f) => {
                        desk.canvas.lock().unwrap().apply(f);
                        desk.changed.send_modify(|v| *v += 1);
                    }
                    AgentEvent::Displays { list, current } => {
                        *desk.displays.lock().unwrap() = Some((list.clone(), current));
                        desk.broadcast(HostMsg::Displays { list, current }, |_| true);
                    }
                    AgentEvent::Clipboard(data) => {
                        // Copied files also need the files permission.
                        let files = data.is_files();
                        desk.broadcast(HostMsg::Clipboard(data), |v| v.perms.clipboard && (!files || v.perms.files));
                    }
                    AgentEvent::Audio(chunk) => {
                        for v in desk.viewers.lock().unwrap().values() {
                            if v.wants_audio {
                                // Drop audio for viewers that can't keep up.
                                let _ = v.audio_tx.try_send(chunk.clone());
                            }
                        }
                    }
                    AgentEvent::Files { client, reply } => {
                        if let Some(v) = desk.viewers.lock().unwrap().get(&client) {
                            let _ = v.tx.send(HostMsg::Files(reply));
                        }
                    }
                    AgentEvent::Cursor(c) if c.is_valid() => {
                        *desk.cursor.lock().unwrap() = Some(c.clone());
                        desk.broadcast(HostMsg::Cursor(c), |_| true);
                    }
                    AgentEvent::Cursor(_) => {}
                    AgentEvent::Privacy { on, note } => {
                        if !on {
                            *desk.privacy_on.lock().unwrap() = false;
                            for v in desk.viewers.lock().unwrap().values_mut() {
                                v.privacy = false;
                            }
                        }
                        desk.broadcast(HostMsg::Privacy { on, note }, |_| true);
                    }
                    AgentEvent::Resolution(note) => desk.broadcast(HostMsg::Status(note), |_| true),
                    AgentEvent::Chat(text) => {
                        let from = format!("{} (at the computer)", shared.host_name);
                        desk.broadcast(HostMsg::Chat { from, text }, |_| true);
                    }
                    AgentEvent::Answer { id, allow } => {
                        if let Some(tx) = desk.asks.lock().unwrap().remove(&id) {
                            let _ = tx.send(allow);
                        }
                    }
                    AgentEvent::EndSessions => {
                        log::info!("the person at this computer ended the session");
                        shared.db.lock().unwrap().audit(None, "local", "sessions ended from the host screen");
                        break format!("The person at {} ended the session.", shared.host_name);
                    }
                    AgentEvent::Error(e) => break format!("host error: {e}"),
                }
            };
            log::info!("desk closed: {why}");
            let mut slot = shared.desk.lock().await;
            if slot.as_ref().is_some_and(|d| Arc::ptr_eq(d, &desk)) {
                *slot = None;
            }
            drop(slot);
            desk.shutdown(&why);
        });
    }

    *slot = Some(desk.clone());
    Ok(desk)
}

async fn accept_agent(listener: &TcpListener, token: &str) -> Result<TcpStream> {
    loop {
        let (mut s, peer) = listener.accept().await?;
        if !peer.ip().is_loopback() {
            continue;
        }
        let hello: AgentHello = match tokio::time::timeout(Duration::from_secs(5), read_msg_max(&mut s, MAX_HELLO)).await {
            Ok(Ok(h)) => h,
            _ => continue,
        };
        if constant_time_eq(hello.token.as_bytes(), token.as_bytes()) && hello.version == PROTOCOL_VERSION {
            s.set_nodelay(true)?;
            return Ok(s);
        }
        log::warn!("rejected agent connection with bad token from {peer}");
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ================================================================== one viewer

async fn viewer_session<S>(shared: &Arc<Shared>, user: &UserInfo, label: String, client: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut c_rd, mut c_wr) = tokio::io::split(client);
    let perms = user.effective();

    let desk = {
        // Admission: limit the number of simultaneous viewers.
        let current = shared.desk.lock().await.as_ref().map(|d| d.viewers.lock().unwrap().len()).unwrap_or(0);
        if current >= shared.cfg.max_viewers {
            write_msg(&mut c_wr, &HostMsg::Bye(format!("host busy: {current} viewer(s) already connected"))).await?;
            return Ok(());
        }
        write_msg(&mut c_wr, &HostMsg::Status("starting desktop agent...".into())).await?;
        match join_desk(shared).await {
            Ok(d) => d,
            Err(e) => {
                write_msg(&mut c_wr, &HostMsg::Bye(format!("{e:#}"))).await?;
                return Err(e);
            }
        }
    };

    let id = shared.next_client.fetch_add(1, Ordering::Relaxed);

    // Ask the person at the computer first, if this computer is set up that way.
    if shared.cfg.ask_to_allow {
        let (ans_tx, ans_rx) = tokio::sync::oneshot::channel();
        desk.asks.lock().unwrap().insert(id, ans_tx);
        let _ = desk.agent_tx.send(AgentCmd::Ask { id, label: label.clone() });
        write_msg(&mut c_wr, &HostMsg::Status(format!("Waiting for the person at {} to allow the connection...", shared.host_name)))
            .await?;
        let answer = tokio::time::timeout(ASK_TIMEOUT, ans_rx).await;
        desk.asks.lock().unwrap().remove(&id);
        let _ = desk.agent_tx.send(AgentCmd::AskDone(id));
        let refused = match answer {
            Ok(Ok(true)) => None,
            Ok(Ok(false)) => Some(format!("The person at {} didn't allow the connection.", shared.host_name)),
            Ok(Err(_)) => Some(format!("Nobody at {} could be asked (is anyone signed in there?).", shared.host_name)),
            Err(_) => Some(format!("Nobody at {} answered.", shared.host_name)),
        };
        if let Some(why) = refused {
            shared.db.lock().unwrap().audit(Some(&user.username), "local", "connection not allowed at the computer");
            write_msg(&mut c_wr, &HostMsg::Bye(why)).await?;
            // Stop the agent if nobody else is using it.
            let mut slot = shared.desk.lock().await;
            if desk.viewers.lock().unwrap().is_empty() && desk.asks.lock().unwrap().is_empty() {
                if slot.as_ref().is_some_and(|d| Arc::ptr_eq(d, &desk)) {
                    *slot = None;
                }
                drop(slot);
                desk.shutdown("connection not allowed");
            }
            return Ok(());
        }
    }

    let (tx, mut rx) = mpsc::unbounded_channel::<HostMsg>();
    let (audio_tx, mut audio_rx) = mpsc::channel::<AudioChunk>(16);
    desk.viewers.lock().unwrap().insert(
        id,
        Viewer { label: label.clone(), perms, tx: tx.clone(), audio_tx, wants_audio: false, lock_on_leave: true, privacy: false },
    );
    if *desk.privacy_on.lock().unwrap() {
        let _ = tx.send(HostMsg::Privacy { on: true, note: None });
    }
    desk.viewers_changed();
    let _ = tx.send(HostMsg::Status(desk.status.lock().unwrap().clone()));
    if let Some((list, current)) = desk.displays.lock().unwrap().clone() {
        let _ = tx.send(HostMsg::Displays { list, current });
    }
    if let Some(c) = desk.cursor.lock().unwrap().clone() {
        let _ = tx.send(HostMsg::Cursor(c));
    }
    if !perms.control {
        let _ = tx.send(HostMsg::Status("view-only session".into()));
    }

    let keyframe = Arc::new(Notify::new());
    let (codec_tx, mut codec_rx) = mpsc::unbounded_channel::<VideoCodec>();

    // desk -> this viewer
    let down = {
        let desk = desk.clone();
        let keyframe = keyframe.clone();
        let (fps, host_kbps, enc_choice) = (shared.cfg.fps, shared.cfg.video_kbps, shared.cfg.video_encoder);
        let username = user.username.clone();
        async move {
            let mut changed = desk.changed.subscribe();
            // Canvas watermark: what this viewer's picture (tiles or H.264) is based on.
            let (mut since, mut gen) = (0u64, u64::MAX);
            // H.264 only: lossless refresh once the picture stops moving.
            let mut sharp = Sharpener::default();
            let mut sharpen_at: Option<tokio::time::Instant> = None;
            let mut last_video = Instant::now();
            let mut pipe: Option<Box<VideoPipe>> = None;
            let mut codec = VideoCodec::Tiles;
            let mut send_delta = true;
            loop {
                if send_delta {
                    send_delta = false;
                    let delta = desk.canvas.lock().unwrap().delta(since, gen);
                    if let Some((frame, v, g)) = delta {
                        since = v;
                        gen = g;
                        match pipe.take() {
                            None => write_msg(&mut c_wr, &HostMsg::Frame(frame)).await?,
                            Some(mut p) => {
                                let (mut p, r) = tokio::task::spawn_blocking(move || {
                                    let r = p.push(&frame);
                                    (p, r)
                                })
                                .await?;
                                match r {
                                    Ok(h) => {
                                        let t0 = Instant::now();
                                        write_msg(&mut c_wr, &HostMsg::Video(h)).await?;
                                        if let Some(kbps) = p.sent(t0.elapsed()) {
                                            write_msg(&mut c_wr, &HostMsg::Codec { codec, kbps }).await?;
                                        }
                                        pipe = Some(p);
                                        last_video = Instant::now();
                                        if sharpen_at.is_none() {
                                            sharpen_at = Some(tokio::time::Instant::now() + SHARPEN_TICK);
                                        }
                                    }
                                    Err(e) => {
                                        log::info!("'{username}': H.264 not possible ({e:#}); using lossless tiles");
                                        codec = VideoCodec::Tiles;
                                        (since, gen) = (0, u64::MAX);
                                        send_delta = true;
                                        sharpen_at = None;
                                        write_msg(&mut c_wr, &HostMsg::Codec { codec, kbps: 0 }).await?;
                                    }
                                }
                            }
                        }
                    }
                }
                let sharpen = async {
                    match sharpen_at {
                        Some(t) => tokio::time::sleep_until(t).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    r = changed.changed() => { r?; send_delta = true; }
                    _ = keyframe.notified() => {
                        // Tiles: resend everything. H.264: restart the stream (new IDR).
                        if let VideoCodec::H264 { max_kbps } = codec {
                            pipe = VideoPipe::new(max_kbps, fps, enc_choice).ok().map(Box::new);
                            sharp.reset();
                        }
                        (since, gen) = (0, u64::MAX);
                        send_delta = true;
                    }
                    Some(want) = codec_rx.recv() => {
                        pipe = None;
                        codec = VideoCodec::Tiles;
                        if let VideoCodec::H264 { max_kbps } = want {
                            let kbps = if max_kbps == 0 { host_kbps } else { max_kbps.min(host_kbps) };
                            match VideoPipe::new(kbps, fps, enc_choice) {
                                Ok(p) => {
                                    pipe = Some(Box::new(p));
                                    codec = VideoCodec::H264 { max_kbps: kbps };
                                }
                                Err(e) => log::warn!("H.264 encoder unavailable: {e:#}"),
                            }
                        }
                        log::info!("'{username}' video: {codec:?}");
                        (since, gen) = (0, u64::MAX);
                        sharp.reset();
                        sharpen_at = None;
                        send_delta = true;
                        let kbps = pipe.as_ref().map(|p| p.kbps()).unwrap_or(0);
                        write_msg(&mut c_wr, &HostMsg::Codec { codec, kbps }).await?;
                    }
                    _ = sharpen => {
                        sharpen_at = None;
                        if let Some(p) = &pipe {
                            // Per tick: a whole tick's worth of the link when nothing is
                            // moving, a quarter of it while video frames are flowing.
                            let tick_bytes = p.bitrate() as usize / 8 / (1000 / SHARPEN_TICK.as_millis() as usize);
                            let moving = last_video.elapsed() < Duration::from_millis(300);
                            let budget = (if moving { tick_bytes / 4 } else { tick_bytes }).max(8 * 1024);
                            let slice = sharp.next(&desk.canvas.lock().unwrap(), budget, Duration::from_millis(300));
                            let more = slice.is_some();
                            if let Some(f) = slice {
                                write_msg(&mut c_wr, &HostMsg::Frame(f)).await?;
                            }
                            // Keep ticking while there is work or motion that may settle.
                            if more || last_video.elapsed() < Duration::from_secs(2) {
                                sharpen_at = Some(tokio::time::Instant::now() + SHARPEN_TICK);
                            }
                        }
                    }
                    Some(msg) = rx.recv() => {
                        let bye = matches!(msg, HostMsg::Bye(_));
                        write_msg(&mut c_wr, &msg).await?;
                        if bye { break; }
                    }
                    Some(chunk) = audio_rx.recv() => write_msg(&mut c_wr, &HostMsg::Audio(chunk)).await?,
                }
            }
            anyhow::Ok(())
        }
    };

    // this viewer -> desk
    let up = {
        let desk = desk.clone();
        let keyframe = keyframe.clone();
        let label = label.clone();
        async move {
            // Virtual controllers, unplugged when the viewer leaves.
            let mut pads: HashMap<u8, crate::gamepad::Pad> = HashMap::new();
            let mut pad_failed = false;
            loop {
                match read_msg::<_, ClientMsg>(&mut c_rd).await? {
                    ClientMsg::Input(ev) if perms.control => {
                        let _ = desk.agent_tx.send(AgentCmd::Input(ev));
                    }
                    ClientMsg::Input(_) => {}
                    ClientMsg::RequestKeyframe => keyframe.notify_one(),
                    ClientMsg::SelectDisplay(i) if perms.control => {
                        let _ = desk.agent_tx.send(AgentCmd::SelectDisplay(i));
                    }
                    ClientMsg::SelectDisplay(_) => {}
                    ClientMsg::Clipboard(data)
                        if perms.clipboard && (perms.files || !data.is_files()) && data.within_limits() =>
                    {
                        let files = data.is_files();
                        let _ = desk.agent_tx.send(AgentCmd::SetClipboard(data.clone()));
                        desk.broadcast(HostMsg::Clipboard(data), |v| {
                            v.perms.clipboard && (!files || v.perms.files) && !v.tx.same_channel(&tx)
                        });
                    }
                    ClientMsg::Clipboard(_) => {}
                    ClientMsg::SecureAttention if perms.control => secure_attention(&desk).await,
                    ClientMsg::SecureAttention => {}
                    ClientMsg::SetAudio(on) => {
                        if let Some(v) = desk.viewers.lock().unwrap().get_mut(&id) {
                            v.wants_audio = on;
                        }
                        desk.update_audio();
                    }
                    ClientMsg::Files(req) if perms.files => {
                        let _ = desk.agent_tx.send(AgentCmd::Files { client: id, req });
                    }
                    ClientMsg::Files(req) => {
                        let req_id = match &req {
                            FileRequest::ListDir { req, .. }
                            | FileRequest::Download { req, .. }
                            | FileRequest::Ack { req }
                            | FileRequest::UploadStart { req, .. }
                            | FileRequest::UploadChunk { req, .. }
                            | FileRequest::UploadEnd { req }
                            | FileRequest::Cancel { req } => *req,
                        };
                        let _ = tx.send(HostMsg::Files(FileReply::Error {
                            req: req_id,
                            message: "your account is not allowed to transfer files".into(),
                        }));
                    }
                    ClientMsg::SetCodec(c) => {
                        let _ = codec_tx.send(c);
                    }
                    ClientMsg::Ping(v) => {
                        let _ = tx.send(HostMsg::Pong(v));
                    }
                    ClientMsg::LockOnLeave(on) => {
                        if let Some(v) = desk.viewers.lock().unwrap().get_mut(&id) {
                            v.lock_on_leave = on;
                        }
                    }
                    ClientMsg::Privacy(on) if perms.control => {
                        if let Some(v) = desk.viewers.lock().unwrap().get_mut(&id) {
                            v.privacy = on;
                        }
                        // Report "off" right away when someone else still keeps it on.
                        desk.update_privacy();
                        if !on && *desk.privacy_on.lock().unwrap() {
                            let _ = tx.send(HostMsg::Privacy { on: true, note: Some("another viewer still has the privacy screen on".into()) });
                        }
                    }
                    ClientMsg::Privacy(_) => {}
                    ClientMsg::FitResolution(size) if perms.control => {
                        let size = size.map(|(w, h)| (w.clamp(640, 7680), h.clamp(480, 4320)));
                        *desk.fit_owner.lock().unwrap() = size.map(|_| id);
                        let _ = desk.agent_tx.send(AgentCmd::SetResolution(size));
                    }
                    ClientMsg::FitResolution(_) => {}
                    ClientMsg::Chat(text) => {
                        let text: String = text.chars().filter(|c| !c.is_control() || *c == '\n').take(MAX_CHAT).collect();
                        let text = text.trim().to_string();
                        if !text.is_empty() {
                            let _ = desk.agent_tx.send(AgentCmd::Chat { from: label.clone(), text: text.clone() });
                            desk.broadcast(HostMsg::Chat { from: label.clone(), text }, |v| !v.tx.same_channel(&tx));
                        }
                    }
                    ClientMsg::Gamepad { pad, state } if perms.control && pad < MAX_PADS => match state {
                        None => {
                            pads.remove(&pad);
                        }
                        Some(s) => {
                            if !pads.contains_key(&pad) && !pad_failed {
                                let who = label.clone();
                                match tokio::task::spawn_blocking(move || crate::gamepad::Pad::plug(&who)).await? {
                                    Ok(p) => {
                                        pads.insert(pad, p);
                                    }
                                    Err(e) => {
                                        pad_failed = true;
                                        let _ = tx.send(HostMsg::Status(format!("controller: {e:#}")));
                                    }
                                }
                            }
                            if let Some(p) = pads.get(&pad) {
                                p.update(s);
                            }
                        }
                    },
                    ClientMsg::Gamepad { .. } => {}
                    ClientMsg::Disconnect => break,
                }
            }
            anyhow::Ok(())
        }
    };

    let result = tokio::select! {
        r = down => r,
        r = up => r,
    };

    // Leave the desk; stop the agent when the last viewer goes.
    let _ = desk.agent_tx.send(AgentCmd::Input(InputEvent::ReleaseAll));
    let mut slot = shared.desk.lock().await;
    let (empty, lock) = {
        let mut viewers = desk.viewers.lock().unwrap();
        let me = viewers.remove(&id);
        (viewers.is_empty(), me.is_some_and(|v| v.lock_on_leave && v.perms.control))
    };
    if desk.fit_owner.lock().unwrap().take_if(|o| *o == id).is_some() {
        let _ = desk.agent_tx.send(AgentCmd::SetResolution(None));
    }
    if empty {
        if slot.as_ref().is_some_and(|d| Arc::ptr_eq(d, &desk)) {
            *slot = None;
        }
        drop(slot);
        // Not when the person at the computer ended it: they're right there.
        let ended_locally = result.as_ref().is_ok() && desk.process.lock().unwrap().is_none();
        if lock && !ended_locally {
            log::info!("locking the computer: the last viewer left");
            let _ = desk.agent_tx.send(AgentCmd::Lock);
        }
        desk.shutdown("session ended");
    } else {
        drop(slot);
        desk.update_audio();
        desk.update_privacy();
        desk.viewers_changed();
    }
    log::info!("viewer '{}' left", user.username);
    result.or_else(|e| if is_disconnect(&e) { Ok(()) } else { Err(e) })
}

/// Ctrl+Alt+Del. On Windows only the SAS service API can produce the real secure
/// attention sequence; elsewhere it's an ordinary key chord.
async fn secure_attention(desk: &Desk) {
    #[cfg(windows)]
    {
        let _ = desk;
        let _ = tokio::task::spawn_blocking(|| unsafe {
            // FALSE = as a service. Requires the SoftwareSASGeneration policy set at install.
            windows::Win32::Security::Authentication::Identity::SendSAS(false);
        })
        .await;
        log::info!("sent secure attention sequence");
    }
    #[cfg(not(windows))]
    {
        let _ = desk.agent_tx.send(AgentCmd::CtrlAltDel);
    }
}

// ================================================================== admin RPC

async fn admin_loop<S>(shared: &Arc<Shared>, me: &UserInfo, s: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let req: AdminRequest = match read_msg(s).await {
            Ok(r) => r,
            Err(e) if is_disconnect(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        let shared2 = shared.clone();
        let me2 = me.clone();
        let resp = tokio::task::spawn_blocking(move || {
            let mut db = shared2.db.lock().unwrap();
            // Re-read our own record so a demotion mid-session takes effect.
            let me = match db.get_user(&me2.username) {
                Ok(Some(u)) if !u.disabled => u,
                _ => return AdminResponse::Error("your account no longer exists or is disabled".into()),
            };
            match admin_request(&mut db, &me, &shared2.host_name, req) {
                Ok(r) => r,
                Err(e) => AdminResponse::Error(format!("{e:#}")),
            }
        })
        .await?;
        write_msg(s, &resp).await?;
    }
}

fn admin_request(db: &mut Db, me: &UserInfo, host_name: &str, req: AdminRequest) -> Result<AdminResponse> {
    let admin = me.role == Role::Admin;
    let need_admin = || -> Result<()> {
        if admin {
            Ok(())
        } else {
            bail!("permission denied: admin role required")
        }
    };
    let self_or_admin = |who: &str| -> Result<()> {
        if admin || who.eq_ignore_ascii_case(&me.username) {
            Ok(())
        } else {
            bail!("permission denied: you can only change your own account")
        }
    };
    let who = me.username.clone();
    let audit = |db: &Db, what: String| db.audit(Some(&who), "admin", &what);
    Ok(match req {
        AdminRequest::WhoAmI => AdminResponse::User(me.clone()),
        AdminRequest::ListUsers => {
            need_admin()?;
            AdminResponse::Users(db.list_users()?)
        }
        AdminRequest::AddUser { username, password, role, perms } => {
            need_admin()?;
            let assigned = db.create_user(&username, &password, role, perms)?;
            audit(db, format!("added user {username} ({}, {perms})", assigned.as_str()));
            AdminResponse::Ok
        }
        AdminRequest::RemoveUser { username } => {
            need_admin()?;
            if username.eq_ignore_ascii_case(&me.username) {
                bail!("you cannot remove your own account");
            }
            db.remove_user(&username)?;
            audit(db, format!("removed user {username}"));
            AdminResponse::Ok
        }
        AdminRequest::SetRole { username, role } => {
            need_admin()?;
            db.set_role(&username, role)?;
            audit(db, format!("set role of {username} to {}", role.as_str()));
            AdminResponse::Ok
        }
        AdminRequest::SetPermissions { username, perms } => {
            need_admin()?;
            db.set_permissions(&username, perms)?;
            audit(db, format!("set permissions of {username} to {perms}"));
            AdminResponse::Ok
        }
        AdminRequest::SetDisabled { username, disabled } => {
            need_admin()?;
            db.set_disabled(&username, disabled)?;
            audit(db, format!("{} {username}", if disabled { "disabled" } else { "enabled" }));
            AdminResponse::Ok
        }
        AdminRequest::SetPassword { username, password } => {
            self_or_admin(&username)?;
            db.set_password(&username, &password)?;
            audit(db, format!("changed password of {username}"));
            AdminResponse::Ok
        }
        AdminRequest::SetPin { username, pin } => {
            self_or_admin(&username)?;
            db.set_pin(&username, pin.as_deref())?;
            audit(db, format!("{} PIN of {username}", if pin.is_some() { "set" } else { "cleared" }));
            AdminResponse::Ok
        }
        AdminRequest::ListDevices => {
            AdminResponse::Devices(db.list_devices(if admin { None } else { Some(&me.username) })?)
        }
        AdminRequest::RevokeDevice { id } => {
            db.revoke_device(id, if admin { None } else { Some(&me.username) })?;
            audit(db, format!("revoked device {id}"));
            AdminResponse::Ok
        }
        AdminRequest::TotpSetup => {
            let secret = db.totp_begin(&me.username)?;
            AdminResponse::Totp { secret: crate::totp::base32(&secret), uri: crate::totp::uri(&secret, &me.username, host_name) }
        }
        AdminRequest::TotpEnable { code } => {
            db.totp_enable(&me.username, &code)?;
            audit(db, format!("turned on two-step sign-in for {}", me.username));
            AdminResponse::Ok
        }
        AdminRequest::TotpDisable { username } => {
            self_or_admin(&username)?;
            db.totp_disable(&username)?;
            audit(db, format!("turned off two-step sign-in for {username}"));
            AdminResponse::Ok
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tile(x: u32, y: u32, byte: u8) -> Tile {
        Tile { x, y, w: 64, h: 64, data: vec![byte] }
    }

    #[test]
    fn sharpener_slices_and_tracks_versions() {
        let mut c = Canvas::default();
        c.apply(EncodedFrame { width: 128, height: 128, keyframe: true, tiles: vec![tile(0, 0, 1), tile(64, 0, 2), tile(0, 64, 3), tile(64, 64, 4)] });
        let mut s = Sharpener::default();
        // Tiny budget: one tile per slice.
        let a = s.next(&c, 1, Duration::ZERO).unwrap();
        assert_eq!(a.tiles.len(), 1);
        assert_eq!((a.width, a.height, a.keyframe), (128, 128, false));
        assert_eq!(s.next(&c, 1, Duration::ZERO).unwrap().tiles.len(), 1);
        // A change to an already-sharp tile mid-refresh doesn't restart the others.
        c.apply(EncodedFrame { width: 128, height: 128, keyframe: false, tiles: vec![tile(0, 0, 7)] });
        let rest: Vec<(u32, u32, u8)> =
            std::iter::from_fn(|| s.next(&c, 1, Duration::ZERO)).flat_map(|f| f.tiles).map(|t| (t.x, t.y, t.data[0])).collect();
        assert_eq!(rest.len(), 3, "{rest:?}");
        assert!(rest.contains(&(0, 0, 7)), "changed tile resent with its newest content");
        assert!(s.next(&c, 1, Duration::ZERO).is_none(), "all sharp now");
        // A resize starts over.
        c.apply(EncodedFrame { width: 64, height: 64, keyframe: true, tiles: vec![tile(0, 0, 5)] });
        assert_eq!(s.next(&c, usize::MAX, Duration::ZERO).unwrap().tiles.len(), 1);
        assert!(s.next(&c, usize::MAX, Duration::ZERO).is_none());
        // Cells that changed too recently wait until they have settled.
        c.apply(EncodedFrame { width: 64, height: 64, keyframe: false, tiles: vec![tile(0, 0, 6)] });
        assert!(s.next(&c, usize::MAX, Duration::from_secs(60)).is_none());
        assert_eq!(s.next(&c, usize::MAX, Duration::ZERO).unwrap().tiles[0].data[0], 6);
    }

    #[test]
    fn canvas_deltas_per_viewer() {
        let mut c = Canvas::default();
        c.apply(EncodedFrame { width: 128, height: 64, keyframe: true, tiles: vec![tile(0, 0, 1), tile(64, 0, 2)] });
        // New viewer: keyframe with both tiles.
        let (f, v1, g) = c.delta(0, u64::MAX).unwrap();
        assert!(f.keyframe);
        assert_eq!(f.tiles.len(), 2);
        // Nothing new.
        assert!(c.delta(v1, g).is_none());
        // Two updates to the same tile collapse into its latest version.
        c.apply(EncodedFrame { width: 128, height: 64, keyframe: false, tiles: vec![tile(64, 0, 3)] });
        c.apply(EncodedFrame { width: 128, height: 64, keyframe: false, tiles: vec![tile(64, 0, 4)] });
        let (f, _, _) = c.delta(v1, g).unwrap();
        assert!(!f.keyframe);
        assert_eq!(f.tiles.len(), 1);
        assert_eq!(f.tiles[0].data, vec![4]);
        // Resolution change forces a keyframe for everyone.
        c.apply(EncodedFrame { width: 64, height: 64, keyframe: true, tiles: vec![tile(0, 0, 9)] });
        let (f, _, _) = c.delta(v1, g).unwrap();
        assert!(f.keyframe);
        assert_eq!((f.width, f.tiles.len()), (64, 1));
    }
}
