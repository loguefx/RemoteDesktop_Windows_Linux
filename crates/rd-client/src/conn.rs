//! Connecting + signing in, shared by the GUI and the CLI.
//!
//! [`connect_flow`] is non-interactive: it reports what it needs next (trust the
//! certificate, credentials) and the caller - a dialog or a terminal prompt - supplies it.

use std::io::Write;

use anyhow::{anyhow, bail, Context, Result};
use rd_core::framing::{read_msg, write_msg};
use rd_core::proto::{ClientHello, Credential, LoginResult, Mode, UserInfo};
use rd_core::p2p::{self, AsyncStream};
use rd_core::relay::{RelayHello, RelayReply, Target, RELAY_VERSION};
use rd_core::tls::{client_connector, ServerName, TlsStream};
use rd_core::PROTOCOL_VERSION;
use tokio::net::TcpStream;

use crate::config::{Computer, HostEntry, Store};

pub type Stream = TlsStream<Box<dyn AsyncStream>>;

/// How long to try for a direct connection before using the relayed one.
const P2P_WAIT: std::time::Duration = std::time::Duration::from_secs(3);

pub struct Session {
    pub stream: Stream,
    pub user: UserInfo,
    pub host_name: String,
    /// How the connection runs: "direct", "peer-to-peer", "relayed (UDP)" or "via relay".
    pub route: String,
    /// Saved-host key (`host:port` or `id@relay:port`).
    #[allow(dead_code)]
    pub key: String,
}

#[derive(Clone, Debug)]
pub enum Creds {
    /// Use the saved device token for this user (or the last user).
    Saved(Option<String>),
    /// `code`: from an authenticator app, for accounts with two-step sign-in.
    Password { username: String, password: String, code: Option<String> },
    Pin { username: String, pin: String, code: Option<String> },
}

pub enum Outcome {
    Ok(Session),
    /// First connection: show this fingerprint and ask the user to trust it.
    NeedTrust(String),
    /// No saved sign-in (or it was rejected); `message` explains why.
    NeedCredentials { username: Option<String>, message: Option<String> },
    /// Two-step sign-in: try again with the same credential and a code.
    NeedCode,
    Denied(String),
}

pub fn device_name() -> String {
    let host = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()))
        .unwrap_or_else(|| "unknown".into());
    format!("{host} ({})", std::env::consts::OS)
}

fn p2p_disabled() -> bool {
    std::env::var("RD_NO_P2P").is_ok_and(|v| !v.is_empty() && v != "0")
}

/// A byte stream to the host: direct TCP, or through a relay. Through a relay a direct
/// peer-to-peer connection is tried first; the relayed stream is the fallback.
async fn open_transport(target: &Target) -> Result<(Box<dyn AsyncStream>, String)> {
    match target {
        Target::Direct(addr) => {
            let s = TcpStream::connect(addr).await.with_context(|| format!("connect to {addr}"))?;
            s.set_nodelay(true)?;
            Ok((Box::new(s), "direct".into()))
        }
        Target::Relay { id, relay } => {
            let prepared = if p2p_disabled() {
                None
            } else {
                match tokio::time::timeout(std::time::Duration::from_millis(1500), p2p::prepare(relay)).await {
                    Ok(Ok(p)) => Some(p),
                    Ok(Err(e)) => {
                        log::info!("peer-to-peer setup failed: {e:#}");
                        None
                    }
                    Err(_) => None,
                }
            };
            let token = p2p::new_token();
            let candidates = prepared.as_ref().map(|p| p.candidates.clone()).unwrap_or_default();
            let mut s = TcpStream::connect(relay).await.with_context(|| format!("connect to relay {relay}"))?;
            s.set_nodelay(true)?;
            write_msg(&mut s, &RelayHello::Client { version: RELAY_VERSION, id: id.clone(), candidates, token: token.clone() })
                .await?;
            let (mut host_candidates, udp_relay) = match read_msg::<_, RelayReply>(&mut s).await? {
                RelayReply::Peer { candidates, udp_relay } => (candidates, udp_relay),
                RelayReply::Ok => (Vec::new(), false),
                RelayReply::Error(e) => bail!("relay: {e}"),
            };
            // Testing aid: behave as if no direct path existed (two symmetric NATs).
            if std::env::var("RD_P2P_RELAY_ONLY").is_ok_and(|v| v == "1") {
                host_candidates.clear();
            }
            let worth_trying = !host_candidates.is_empty() || (udp_relay && prepared.as_ref().is_some_and(|p| p.relay_reachable()));
            if let (Some(p), true) = (prepared, worth_trying) {
                match p2p::connect(p, host_candidates, &token, udp_relay, P2P_WAIT).await {
                    Ok((direct, addr)) => {
                        let route = if direct.is_relayed() { "relayed (UDP)" } else { "peer-to-peer" };
                        log::info!("{route} connection to {addr} (rtt {} ms)", direct.rtt().as_millis());
                        drop(s);
                        return Ok((Box::new(direct), route.into()));
                    }
                    Err(e) => log::info!("no direct connection ({e:#}); using the relay"),
                }
            }
            Ok((Box::new(s), "via relay".into()))
        }
    }
}

async fn open_tls(target: &Target, pinned: Option<String>) -> Result<(Stream, String, String)> {
    let (transport, route) = open_transport(target).await?;
    let (stream, fp) = tls_over(transport, pinned).await?;
    Ok((stream, fp, route))
}

async fn tls_over(transport: Box<dyn AsyncStream>, pinned: Option<String>) -> Result<(Stream, String)> {
    let (connector, verifier) = client_connector(pinned)?;
    let name = ServerName::try_from("rd-host").map_err(|e| anyhow!("{e}"))?;
    let stream = connector.connect(name, transport).await.context("TLS handshake")?;
    let fp = verifier.seen_fingerprint().ok_or_else(|| anyhow!("no certificate presented"))?;
    Ok((stream, fp))
}

/// Connect to a saved computer: race its local and internet addresses (local first),
/// then fall back to its relay. The certificate must match the saved fingerprint.
async fn open_computer(c: &Computer) -> Result<(Stream, String)> {
    let pinned = c.auth.fingerprint.clone().ok_or_else(|| anyhow!("no saved certificate for {}", c.name))?;
    let mut cands: Vec<(String, &'static str)> = Vec::new();
    if let Some(a) = &c.lan {
        cands.push((a.clone(), "direct"));
    }
    if let Some(a) = c.public.as_ref().filter(|p| Some(*p) != c.lan.as_ref()) {
        cands.push((a.clone(), "over the internet"));
    }
    // A dynamic DNS name still works after the router's address changed.
    if let Some(a) = &c.public_name {
        cands.push((a.clone(), "over the internet"));
    }
    let mut set = tokio::task::JoinSet::new();
    for (i, (addr, label)) in cands.into_iter().enumerate() {
        set.spawn(async move {
            // Give earlier (closer) addresses a head start.
            tokio::time::sleep(std::time::Duration::from_millis(300 * i as u64)).await;
            let s = tokio::time::timeout(std::time::Duration::from_secs(4), TcpStream::connect(&addr))
                .await
                .map_err(|_| anyhow!("{addr}: timed out"))?
                .with_context(|| addr.clone())?;
            s.set_nodelay(true)?;
            Ok::<_, anyhow::Error>((s, label))
        });
    }
    let mut errors = Vec::new();
    while let Some(r) = set.join_next().await {
        match r {
            Ok(Ok((s, label))) => {
                set.abort_all();
                let (stream, _) = tls_over(Box::new(s), Some(pinned)).await?;
                return Ok((stream, label.to_string()));
            }
            Ok(Err(e)) => errors.push(format!("{e:#}")),
            Err(_) => {}
        }
    }
    if let Some(relay) = &c.relay {
        let (stream, _, route) = open_tls(&Target::parse(relay), Some(pinned)).await?;
        return Ok((stream, route));
    }
    if errors.is_empty() {
        bail!("{} has no known address yet; connect once while on the same network", c.name);
    }
    bail!(
        "{} isn't reachable right now. Check that it is switched on and online. ({})",
        c.name,
        errors.join("; ")
    )
}

#[allow(clippy::large_enum_variant)]
enum SignIn {
    Ok { stream: Stream, user: UserInfo, host_name: String },
    NeedCredentials { username: Option<String>, message: Option<String> },
    NeedCode,
    Denied(String),
}

/// Sign in on an open connection, updating `entry` (saved user and device tokens).
async fn sign_in(mut stream: Stream, entry: &mut HostEntry, mode: Mode, creds: Creds, remember: bool) -> Result<SignIn> {
    let (username, credential, used_token, code) = match creds {
        Creds::Saved(user) => {
            let user = user.or_else(|| entry.username.clone());
            match user.as_deref().and_then(|u| entry.token(u).cloned()) {
                Some(tok) => (user.unwrap(), Credential::DeviceToken(tok), true, None),
                None => return Ok(SignIn::NeedCredentials { username: user, message: None }),
            }
        }
        Creds::Password { username, password, code } => (username, Credential::Password(password), false, code),
        Creds::Pin { username, pin, code } => (username, Credential::Pin(pin), false, code),
    };
    let hello = ClientHello {
        version: PROTOCOL_VERSION,
        username: username.clone(),
        credential,
        remember_device_as: (remember && !used_token).then(device_name),
        mode,
        device: device_name(),
        code,
    };
    write_msg(&mut stream, &hello).await?;
    match read_msg::<_, LoginResult>(&mut stream).await? {
        LoginResult::Ok { user, host_name, device_token } => {
            entry.username = Some(user.username.clone());
            if let Some(t) = device_token {
                entry.set_token(&user.username, Some(t));
            }
            Ok(SignIn::Ok { stream, user, host_name })
        }
        LoginResult::Denied(why) if used_token => {
            entry.set_token(&username, None);
            Ok(SignIn::NeedCredentials {
                username: Some(username),
                message: Some(format!("Saved sign-in no longer accepted ({why}). Please sign in again.")),
            })
        }
        LoginResult::Denied(why) => Ok(SignIn::Denied(why)),
        LoginResult::NeedCode => Ok(SignIn::NeedCode),
    }
}

/// Connect to a computer from "My computers" (keyed by fingerprint).
pub async fn connect_computer(key: &str, mode: Mode, creds: Creds, remember: bool) -> Result<Outcome> {
    let c = Store::load().computers.get(key).cloned().ok_or_else(|| anyhow!("unknown computer"))?;
    let (stream, route) = open_computer(&c).await?;
    let mut auth = c.auth.clone();
    let r = sign_in(stream, &mut auth, mode, creds, remember).await?;
    // Reload: a network scan may have updated the addresses meanwhile.
    let mut store = Store::load();
    let saved = store.computers.entry(key.to_string()).or_insert_with(|| c.clone());
    saved.auth = auth;
    if matches!(r, SignIn::Ok { .. }) {
        saved.last_connected = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs());
    }
    store.save()?;
    Ok(match r {
        SignIn::Ok { stream, user, host_name } => {
            Outcome::Ok(Session { stream, user, host_name, route, key: key.to_string() })
        }
        SignIn::NeedCredentials { username, message } => Outcome::NeedCredentials { username, message },
        SignIn::NeedCode => Outcome::NeedCode,
        SignIn::Denied(why) => Outcome::Denied(why),
    })
}

/// One sign-in attempt. `trust` = fingerprint the user has just approved.
pub async fn connect_flow(
    target_str: &str,
    mode: Mode,
    creds: Creds,
    remember: bool,
    trust: Option<String>,
) -> Result<Outcome> {
    let target = Target::parse(target_str.trim());
    let key = target.key();
    let mut store = Store::load();
    let mut entry = store.hosts.get(&key).cloned().unwrap_or_default();

    let (stream, fp, route) = open_tls(&target, entry.fingerprint.clone()).await?;
    if entry.fingerprint.is_none() {
        match trust {
            Some(t) if t.eq_ignore_ascii_case(&fp) => {
                entry.fingerprint = Some(fp);
                store.hosts.insert(key.clone(), entry.clone());
                store.save()?;
            }
            Some(_) => bail!("host fingerprint {fp} does not match the one you approved"),
            None => return Ok(Outcome::NeedTrust(fp)),
        }
    }

    let r = sign_in(stream, &mut entry, mode, creds, remember).await?;
    store.hosts.insert(key.clone(), entry);
    store.save()?;
    Ok(match r {
        SignIn::Ok { stream, user, host_name } => Outcome::Ok(Session { stream, user, host_name, route, key }),
        SignIn::NeedCredentials { username, message } => Outcome::NeedCredentials { username, message },
        SignIn::NeedCode => Outcome::NeedCode,
        SignIn::Denied(why) => Outcome::Denied(why),
    })
}

// ------------------------------------------------------------------ terminal flavour

#[derive(Clone, Default)]
pub struct LoginOptions {
    pub username: Option<String>,
    pub use_pin: bool,
    /// None = ask; Some(b) = don't ask.
    pub remember: Option<bool>,
    /// Ignore any saved device token.
    pub fresh: bool,
    /// Trust this certificate fingerprint without prompting (scripted first connect).
    pub accept_fingerprint: Option<String>,
}

fn ask(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

fn yes(prompt: &str, default_yes: bool) -> Result<bool> {
    let a = ask(prompt)?.to_ascii_lowercase();
    Ok(if a.is_empty() { default_yes } else { a.starts_with('y') })
}

/// Secret from an environment variable (for scripts), else an interactive prompt.
pub fn secret(env: &str, prompt: &str) -> Result<String> {
    match std::env::var(env) {
        Ok(v) if !v.is_empty() => Ok(v),
        _ => Ok(rpassword::prompt_password(prompt)?),
    }
}

/// Interactive terminal sign-in built on [`connect_flow`].
pub async fn login(target: &str, mode: Mode, opts: &LoginOptions) -> Result<Session> {
    let mut trust = opts.accept_fingerprint.clone();
    let mut creds = if opts.fresh || opts.use_pin { None } else { Some(Creds::Saved(opts.username.clone())) };
    let mut username = opts.username.clone();
    for _ in 0..4 {
        let attempt = match &creds {
            Some(c) => c.clone(),
            None => {
                let user = match &username {
                    Some(u) => u.clone(),
                    None => ask("Username: ")?,
                };
                username = Some(user.clone());
                if opts.use_pin {
                    Creds::Pin { pin: secret("RD_PIN", &format!("PIN for {user}: "))?, username: user, code: None }
                } else {
                    Creds::Password { password: secret("RD_PASSWORD", &format!("Password for {user}: "))?, username: user, code: None }
                }
            }
        };
        let remember = match (&attempt, opts.remember) {
            (Creds::Saved(_), _) => false,
            (_, Some(r)) => r,
            (_, None) => yes("Remember this device so you don't need to sign in next time? [Y/n] ", true)?,
        };
        match connect_flow(target, mode, attempt.clone(), remember, trust.clone()).await? {
            Outcome::Ok(s) => {
                if remember {
                    println!("This device is now remembered for '{}' on {}.", s.user.username, s.host_name);
                }
                return Ok(s);
            }
            Outcome::NeedTrust(fp) => {
                println!("First connection to {target}.\nHost certificate fingerprint:\n  {fp}");
                println!("Check that it matches the output of `rd-host info` on that computer.");
                if !yes("Trust this host? [y/N] ", false)? {
                    bail!("host not trusted");
                }
                trust = Some(fp);
                creds = Some(attempt);
            }
            Outcome::NeedCredentials { username: u, message } => {
                if let Some(m) = message {
                    println!("{m}");
                }
                username = username.or(u);
                creds = None;
            }
            Outcome::NeedCode => {
                let code = match std::env::var("RD_CODE") {
                    Ok(c) if !c.is_empty() => c,
                    _ => ask("Code from your authenticator app: ")?,
                };
                creds = Some(match attempt {
                    Creds::Pin { username, pin, .. } => Creds::Pin { username, pin, code: Some(code) },
                    Creds::Password { username, password, .. } => Creds::Password { username, password, code: Some(code) },
                    saved => saved,
                });
            }
            Outcome::Denied(why) => bail!("sign-in refused: {why}"),
        }
    }
    bail!("sign-in failed")
}

/// Forget a host. With `keep_trust`, only drop saved sign-ins (for `user`, or all users).
pub fn forget(target: &str, keep_trust: bool, user: Option<&str>) -> Result<bool> {
    let key = Target::parse(target).key();
    let mut store = Store::load();
    let found = if keep_trust {
        store.hosts.get_mut(&key).map(|e| match user {
            Some(u) => e.set_token(u, None),
            None => e.tokens.clear(),
        })
    } else {
        store.hosts.remove(&key).map(|_| ())
    }
    .is_some();
    store.save()?;
    Ok(found)
}

pub fn normalize(target: &str) -> String {
    Target::parse(target).key()
}
