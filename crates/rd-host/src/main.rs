//! `rd-host` - remote desktop host.
//!
//! ```text
//! rd-host install            install + start the OS service, create the first admin
//! rd-host uninstall [--purge]
//! rd-host run                run the daemon in the foreground (no service; dev/testing)
//! rd-host user ...           manage accounts directly in the local database
//! rd-host devices ...        list / revoke remembered devices
//! rd-host info               show port, data dir, certificate fingerprint
//! rd-host snapshot out.bmp   capture one frame (backend diagnostics)
//! rd-host service            (internal) entry point used by the SCM / systemd
//! rd-host agent              (internal) desktop agent spawned by the daemon
//! ```

mod agent;
mod audio_cap;
mod clip;
mod daemon;
mod db;
mod files;
mod notice;
mod paths;
mod prompt;
mod reach;
mod relay_link;
mod service;
mod spawn;
mod video_pipe;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rd_core::proto::{Permissions, Role};
use rd_platform::Backend;

#[derive(Parser)]
#[command(name = "rd-host", version, about = "Remote desktop host (Windows / Linux X11 / Linux Wayland)")]
struct Cli {
    /// State directory (database, TLS key, logs).
    #[arg(long, global = true)]
    data_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Install and start the background service (needs Administrator / root).
    Install {
        #[arg(long, default_value_t = rd_core::DEFAULT_PORT)]
        port: u16,
        /// Address to listen on.
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,
        /// Desktop backend: auto, windows, x11, wayland.
        #[arg(long, default_value = "auto")]
        backend: Backend,
        /// Frame-rate cap.
        #[arg(long, default_value_t = 30)]
        fps: u32,
        /// Don't add a firewall rule (Windows) / print firewall hints (Linux).
        #[arg(long)]
        no_firewall: bool,
        /// Username for the first admin account (prompted if omitted). The password is
        /// prompted, or taken from RD_ADMIN_PASSWORD for unattended installs.
        #[arg(long)]
        admin_user: Option<String>,
        /// Also register with this relay server (host[:port]) for access from anywhere.
        #[arg(long)]
        relay: Option<String>,
        /// Only accept connections through the relay (no listening port).
        #[arg(long, requires = "relay")]
        relay_only: bool,
        /// Maximum simultaneous viewers.
        #[arg(long, default_value_t = 4)]
        max_viewers: u32,
        /// Highest H.264 bitrate per viewer, in kbit/s (viewers that pick H.264 adapt below it).
        #[arg(long, default_value_t = 8000)]
        video_kbps: u32,
        /// H.264 encoder: `auto` uses the GPU's hardware encoder when there is one
        /// (falling back to OpenH264), `software` always uses OpenH264.
        #[arg(long, default_value = "auto")]
        video_encoder: String,
        /// Name shown in the app's computer list (defaults to the computer name).
        #[arg(long)]
        name: Option<String>,
        /// Owner account for PIN-only sign-in from the app (created if missing, admin).
        /// Needs --pin-file.
        #[arg(long, requires = "pin_file")]
        owner: Option<String>,
        /// File holding the owner's PIN (4-12 digits); deleted after reading.
        #[arg(long, requires = "owner")]
        pin_file: Option<PathBuf>,
        /// Ask the router to forward the port (UPnP) so the app can connect from the internet.
        #[arg(long)]
        upnp: bool,
        /// Dynamic DNS, so the app finds this computer after the router's internet address
        /// changes. File with two lines: the name (e.g. home.duckdns.org) and the update URL,
        /// with {ip} where the address goes. Deleted after reading (the URL holds a secret).
        #[arg(long, conflicts_with = "ddns_off")]
        ddns_file: Option<PathBuf>,
        /// Stop updating a dynamic DNS name.
        #[arg(long)]
        ddns_off: bool,
        /// Let the network adapter wake this computer from sleep (Wake-on-LAN).
        #[arg(long)]
        wake_on_lan: bool,
        /// Don't copy the app (rd-client) or add it to the Start menu / application menu.
        #[arg(long)]
        no_app: bool,
        /// Write "ok" or "error: ..." here when done (used by the app, which can't see
        /// the output of an elevated process).
        #[arg(long)]
        result_file: Option<PathBuf>,
    },
    /// Configure access through a relay server.
    Relay {
        #[command(subcommand)]
        cmd: RelayCmd,
    },
    /// Stop and remove the service.
    Uninstall {
        /// Also delete the user database and host key.
        #[arg(long)]
        purge: bool,
        /// Write "ok" or "error: ..." here when done (used by the app).
        #[arg(long)]
        result_file: Option<PathBuf>,
    },
    /// Run the daemon in the foreground, agent in this same desktop session.
    Run {
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        bind: Option<String>,
        #[arg(long)]
        backend: Option<Backend>,
        #[arg(long)]
        fps: Option<u32>,
        /// Name shown in the app.
        #[arg(long)]
        name: Option<String>,
        /// Owner account for PIN-only sign-in (needs --pin-file).
        #[arg(long, requires = "pin_file")]
        owner: Option<String>,
        /// File holding the owner's PIN; deleted after reading.
        #[arg(long, requires = "owner")]
        pin_file: Option<PathBuf>,
        /// Forward the port on the router (UPnP): on or off.
        #[arg(long)]
        upnp: Option<String>,
        /// Dynamic DNS file (name, then update URL with {ip}); deleted after reading.
        #[arg(long, conflicts_with = "ddns_off")]
        ddns_file: Option<PathBuf>,
        /// Stop updating a dynamic DNS name.
        #[arg(long)]
        ddns_off: bool,
    },
    /// Check whether the router supports automatic port forwarding (UPnP). Only asks
    /// the router for its internet address; changes nothing.
    RouterCheck,
    /// Manage user accounts in the local database.
    User {
        #[command(subcommand)]
        cmd: UserCmd,
    },
    /// Manage remembered devices.
    Devices {
        #[command(subcommand)]
        cmd: DeviceCmd,
    },
    /// Show configuration, certificate fingerprint and recent audit log.
    Info,
    /// Capture a single frame to a BMP file using the selected backend.
    Snapshot {
        out: PathBuf,
        #[arg(long, default_value = "auto")]
        backend: Backend,
        /// Display index (see the list printed by this command).
        #[arg(long)]
        display: Option<u32>,
    },
    #[command(hide = true)]
    Service,
    #[command(hide = true)]
    Agent {
        #[arg(long)]
        connect: SocketAddr,
        #[arg(long, default_value = "auto")]
        backend: Backend,
        #[arg(long, default_value_t = 30)]
        fps: u32,
        #[arg(long)]
        log_file: Option<PathBuf>,
        #[arg(long)]
        impersonate_console_user: bool,
    },
}

#[derive(Subcommand)]
enum UserCmd {
    /// Add an account (the very first account is always made admin).
    Add {
        username: String,
        #[arg(long, default_value = "user")]
        role: Role,
        /// full | view | none | view,control
        #[arg(long, default_value = "full")]
        perms: Permissions,
    },
    List,
    Remove { username: String },
    /// Change a password (also signs out that user's remembered devices).
    Passwd { username: String },
    /// Set or clear the quick-login PIN.
    Pin {
        username: String,
        #[arg(long)]
        clear: bool,
    },
    Role { username: String, role: Role },
    Perms { username: String, perms: Permissions },
    Disable { username: String },
    Enable { username: String },
    /// Clear a lockout caused by failed logins.
    Unlock { username: String },
}

#[derive(Subcommand)]
enum RelayCmd {
    /// Register with a relay (host[:port]); keeps the existing host id.
    Set {
        addr: String,
        /// Only accept connections through the relay (close the direct port).
        #[arg(long)]
        relay_only: bool,
        /// Registration key, if the relay was started with --registration-key.
        #[arg(long, env = "RD_RELAY_KEY")]
        key: Option<String>,
        /// Never try direct peer-to-peer connections; always carry sessions through the relay.
        #[arg(long)]
        no_p2p: bool,
    },
    /// Stop using the relay (and re-enable the direct port).
    Off,
    /// Show the relay address and this host's id.
    Show,
}

#[derive(Subcommand)]
enum DeviceCmd {
    List,
    Revoke { id: i64 },
}

fn init_logging(file: Option<&std::path::Path>) {
    let mut b = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    if let Some(path) = file {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
            b.target(env_logger::Target::Pipe(Box::new(f)));
        }
    }
    let _ = b.try_init();
}

/// Daemon configuration from the settings saved at install time.
pub(crate) fn load_config(data_dir: PathBuf, spawn_mode: spawn::SpawnMode, agent_logs_to_file: bool) -> Result<daemon::Config> {
    let db = db::Db::open(&data_dir)?;
    let get = |k: &str| db.setting(k).ok().flatten();
    let port: u16 = get("port").and_then(|v| v.parse().ok()).unwrap_or(rd_core::DEFAULT_PORT);
    let bind = get("bind").unwrap_or_else(|| "0.0.0.0".into());
    let backend: Backend = get("backend").and_then(|v| v.parse().ok()).unwrap_or(Backend::Auto);
    let fps: u32 = get("fps").and_then(|v| v.parse().ok()).unwrap_or(30);
    let max_viewers: usize = get("max_viewers").and_then(|v| v.parse().ok()).unwrap_or(4);
    let video_kbps: u32 = get("video_kbps").and_then(|v| v.parse().ok()).unwrap_or(8000).clamp(300, 100_000);
    // RD_VIDEO_ENCODER overrides the saved choice (handy for testing).
    let video_encoder = std::env::var("RD_VIDEO_ENCODER")
        .ok()
        .or_else(|| get("video_encoder"))
        .and_then(|v| v.parse().ok())
        .unwrap_or(rd_core::video::EncoderChoice::Auto);
    let bind: Option<SocketAddr> = if get("listen").as_deref() == Some("off") {
        None
    } else {
        Some(format!("{bind}:{port}").parse().context("invalid bind address")?)
    };
    let relay = match (get("relay_addr").filter(|a| !a.is_empty()), get("relay_id"), get("relay_secret")) {
        (Some(addr), Some(id), Some(secret)) => {
            Some(relay_link::RelayConfig {
                addr,
                id,
                secret,
                key: get("relay_key").filter(|k| !k.is_empty()),
                p2p: get("p2p").as_deref() != Some("off"),
            })
        }
        _ => None,
    };
    let agent_log = agent_logs_to_file.then(|| data_dir.join("logs").join("agent.log"));
    let name = get("name").and_then(|n| rd_core::discovery::clean_name(&n)).unwrap_or_else(paths::host_name);
    let owner = get("owner").filter(|o| !o.is_empty());
    let upnp = get("upnp").as_deref() == Some("on");
    let ddns = match (get("ddns_host").filter(|h| !h.is_empty()), get("ddns_url").filter(|u| !u.is_empty())) {
        (Some(h), Some(u)) => Some((h, u)),
        _ => None,
    };
    Ok(daemon::Config {
        data_dir,
        bind,
        backend,
        fps,
        spawn_mode,
        agent_log,
        max_viewers,
        video_kbps,
        video_encoder,
        relay,
        name,
        owner,
        upnp,
        ddns,
    })
}

/// Read a dynamic DNS file (name, update URL) and delete it.
pub(crate) fn read_ddns_file(f: &std::path::Path) -> Result<(String, String)> {
    let text = std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()));
    let _ = std::fs::remove_file(f);
    let text = text?;
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let (Some(host), Some(url)) = (lines.next(), lines.next()) else {
        anyhow::bail!("the dynamic DNS file needs two lines: the name and the update URL");
    };
    let valid_host = host.len() <= 253
        && host.contains('.')
        && host.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'));
    if !valid_host {
        anyhow::bail!("'{host}' isn't a valid name");
    }
    if !url.starts_with("https://") || !url.contains("{ip}") {
        anyhow::bail!("the update URL must start with https:// and contain {{ip}}");
    }
    Ok((host.to_ascii_lowercase(), url.to_string()))
}

/// Save (or with `off`, remove) the dynamic DNS settings.
pub(crate) fn save_ddns(db: &db::Db, ddns: Option<&(String, String)>, off: bool) -> Result<()> {
    if off {
        db.set_setting("ddns_host", "")?;
        db.set_setting("ddns_url", "")?;
    } else if let Some((h, u)) = ddns {
        db.set_setting("ddns_host", h)?;
        db.set_setting("ddns_url", u)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let data_dir = cli.data_dir.clone().unwrap_or_else(paths::default_data_dir);

    match cli.cmd {
        Cmd::Service => {
            // The Windows SCM gives us no console: log to a file.
            #[cfg(windows)]
            init_logging(Some(&data_dir.join("logs").join("rd-host.log")));
            #[cfg(not(windows))]
            init_logging(None);
            service::run_service(data_dir)
        }
        Cmd::Agent { connect, backend, fps, log_file, impersonate_console_user } => {
            init_logging(log_file.as_deref());
            let rt = tokio::runtime::Runtime::new()?;
            let r = rt.block_on(agent::run(agent::AgentOptions { connect, backend, fps, impersonate_console_user }));
            if let Err(e) = &r {
                log::error!("agent: {e:#}");
            }
            // Capture/input threads may be blocked in OS calls; don't wait for them.
            std::process::exit(if r.is_ok() { 0 } else { 1 });
        }
        Cmd::Run { port, bind, backend, fps, name, owner, pin_file, upnp, ddns_file, ddns_off } => {
            init_logging(None);
            {
                let mut db = db::Db::open(&data_dir)?;
                let ddns = ddns_file.as_deref().map(read_ddns_file).transpose()?;
                save_ddns(&db, ddns.as_ref(), ddns_off)?;
                if let Some(n) = &name {
                    db.set_setting("name", &rd_core::discovery::clean_name(n).context("the name must be 1-40 characters")?)?;
                }
                if let Some(u) = &upnp {
                    db.set_setting("upnp", if u == "on" { "on" } else { "off" })?;
                }
                if let (Some(owner), Some(f)) = (&owner, &pin_file) {
                    let pin = std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()));
                    let _ = std::fs::remove_file(f);
                    service::set_owner(&mut db, owner, pin?.trim())?;
                }
                if let Some(p) = port {
                    db.set_setting("port", &p.to_string())?;
                }
                if let Some(b) = &bind {
                    db.set_setting("bind", b)?;
                }
                if let Some(b) = backend {
                    db.set_setting("backend", &b.to_string())?;
                }
                if let Some(f) = fps {
                    db.set_setting("fps", &f.to_string())?;
                }
                if db.user_count()? == 0 {
                    println!("No accounts yet - create the administrator account first.");
                    service::create_admin_interactive(&mut db, None)?;
                }
            }
            let cfg = load_config(data_dir, spawn::SpawnMode::Child, false)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let (tx, rx) = tokio::sync::watch::channel(false);
                tokio::spawn(async move {
                    let _ = tokio::signal::ctrl_c().await;
                    let _ = tx.send(true);
                });
                daemon::serve(cfg, rx).await
            })
        }
        Cmd::Install {
            port,
            bind,
            backend,
            fps,
            no_firewall,
            admin_user,
            relay,
            relay_only,
            max_viewers,
            video_kbps,
            video_encoder,
            name,
            owner,
            pin_file,
            upnp,
            ddns_file,
            ddns_off,
            wake_on_lan,
            no_app,
            result_file,
        } => {
            init_logging(None);
            let r = (|| {
                video_encoder.parse::<rd_core::video::EncoderChoice>().map_err(|e| anyhow::anyhow!(e))?;
                let pin = match &pin_file {
                    Some(f) => {
                        let p = std::fs::read_to_string(f).with_context(|| format!("read {}", f.display()));
                        let _ = std::fs::remove_file(f);
                        Some(p?.trim().to_string())
                    }
                    None => None,
                };
                let name = match name {
                    Some(n) => Some(rd_core::discovery::clean_name(&n).context("the name must be 1-40 characters")?),
                    None => None,
                };
                let ddns = ddns_file.as_deref().map(read_ddns_file).transpose()?;
                service::install(service::InstallOptions {
                    data_dir,
                    port,
                    bind,
                    backend: backend.to_string(),
                    fps,
                    firewall: !no_firewall && !relay_only,
                    udp_firewall: !no_firewall,
                    admin_user,
                    relay,
                    relay_only,
                    max_viewers,
                    video_kbps,
                    video_encoder,
                    name,
                    owner,
                    pin,
                    upnp,
                    ddns,
                    ddns_off,
                    wake_on_lan,
                    app: !no_app,
                })
            })();
            if let Some(f) = &result_file {
                let text = match &r {
                    Ok(()) => "ok".to_string(),
                    Err(e) => format!("error: {e:#}"),
                };
                let _ = std::fs::write(f, text);
            }
            r
        }
        Cmd::Relay { cmd } => {
            let db = db::Db::open(&data_dir)?;
            match cmd {
                RelayCmd::Set { addr, relay_only, key, no_p2p } => {
                    db.set_setting("relay_key", key.as_deref().unwrap_or(""))?;
                    db.set_setting("p2p", if no_p2p { "off" } else { "on" })?;
                    let id = configure_relay(&db, &addr, relay_only)?;
                    println!("Relay set to {addr}. This computer's id: {id}");
                    println!("Connect with:  rd-client connect {id}@{addr}");
                    println!("Restart the service to apply (it picks up the change on its next start).");
                }
                RelayCmd::Off => {
                    db.set_setting("relay_addr", "")?;
                    db.set_setting("listen", "on")?;
                    println!("Relay disabled; direct listening enabled. Restart the service to apply.");
                }
                RelayCmd::Show => match (db.setting("relay_addr")?, db.setting("relay_id")?) {
                    (Some(a), Some(id)) if !a.is_empty() => {
                        println!("relay:  {a}\nid:     {id}\nconnect with: rd-client connect {id}@{a}");
                        if db.setting("listen")?.as_deref() == Some("off") {
                            println!("direct port: off (relay only)");
                        }
                        let p2p = db.setting("p2p")?.as_deref() != Some("off");
                        println!("peer-to-peer: {}", if p2p { "on (direct when NATs allow, else relayed)" } else { "off (always relayed)" });
                    }
                    _ => println!("No relay configured."),
                },
            }
            Ok(())
        }
        Cmd::Uninstall { purge, result_file } => {
            let r = service::uninstall(&data_dir, purge);
            if let Some(f) = &result_file {
                let _ = std::fs::write(f, match &r {
                    Ok(()) => "ok".to_string(),
                    Err(e) => format!("error: {e:#}"),
                });
            }
            r
        }
        Cmd::User { cmd } => user_cmd(&data_dir, cmd),
        Cmd::Devices { cmd } => {
            let db = db::Db::open(&data_dir)?;
            match cmd {
                DeviceCmd::List => {
                    println!("{:>4}  {:<16} {:<24} {:<20} last used", "id", "user", "device", "created");
                    for d in db.list_devices(None)? {
                        println!(
                            "{:>4}  {:<16} {:<24} {:<20} {}",
                            d.id,
                            d.username,
                            d.name,
                            d.created,
                            d.last_used.unwrap_or_else(|| "-".into())
                        );
                    }
                }
                DeviceCmd::Revoke { id } => {
                    db.revoke_device(id, None)?;
                    println!("Revoked device {id}.");
                }
            }
            Ok(())
        }
        Cmd::Info => {
            let db = db::Db::open(&data_dir)?;
            println!("data dir:     {}", data_dir.display());
            for k in ["name", "owner", "upnp", "port", "bind", "listen", "backend", "fps", "max_viewers", "video_kbps", "video_encoder", "relay_addr", "relay_id"] {
                println!("{k:<13} {}", db.setting(k)?.unwrap_or_else(|| "(default)".into()));
            }
            #[cfg(windows)]
            {
                let hw = rd_core::video_mf::describe_hardware();
                println!("hw encoders:  {}", if hw.is_empty() { "none (OpenH264 is used)".into() } else { hw.join(", ") });
            }
            match rd_core::tls::host_fingerprint(&data_dir) {
                Ok(fp) => println!("fingerprint:  {fp}"),
                Err(_) => println!("fingerprint:  (no certificate yet)"),
            }
            println!("accounts:     {}", db.user_count()?);
            println!("\nrecent activity:");
            for (ts, user, peer, ev) in db.recent_audit(15)? {
                println!("  {ts}  {:<14} {:<22} {ev}", user.unwrap_or_default(), peer.unwrap_or_default());
            }
            Ok(())
        }
        Cmd::RouterCheck => {
            init_logging(None);
            let rt = tokio::runtime::Runtime::new()?;
            match rt.block_on(reach::router_check()) {
                Ok((gw, ip)) => {
                    println!("router:           {gw} (UPnP works)");
                    println!("internet address: {ip}");
                    if rd_core::discovery::is_non_public(ip) {
                        println!("This address is shared by your provider (carrier-grade NAT): the router can't");
                        println!("forward a port from the internet. Use a relay to reach this computer from outside.");
                    } else {
                        println!("Computers set up with internet access can be reached from outside this network.");
                    }
                }
                Err(e) => println!("{e:#}"),
            }
            Ok(())
        }
        Cmd::Snapshot { out, backend, display } => {
            init_logging(None);
            agent::snapshot(backend, display, &out)
        }
    }
}

fn user_cmd(data_dir: &std::path::Path, cmd: UserCmd) -> Result<()> {
    let mut db = db::Db::open(data_dir)?;
    match cmd {
        UserCmd::Add { username, role, perms } => {
            let first = db.user_count()? == 0;
            let password = match std::env::var("RD_PASSWORD") {
                Ok(p) if !p.is_empty() => p,
                _ => prompt::new_password()?,
            };
            let role = db.create_user(&username, &password, role, perms)?;
            if first {
                println!("'{username}' is the first account, so it was made admin.");
            } else {
                println!("Added '{username}' ({}).", role.as_str());
            }
        }
        UserCmd::List => {
            println!("{:<20} {:<6} {:<28} {:<4} status", "username", "role", "permissions", "pin");
            for u in db.list_users()? {
                let perms = if u.role == Role::Admin { "all".to_string() } else { u.perms.to_string() };
                println!(
                    "{:<20} {:<6} {:<28} {:<4} {}",
                    u.username,
                    u.role.as_str(),
                    perms,
                    if u.has_pin { "yes" } else { "no" },
                    if u.disabled { "disabled" } else { "active" }
                );
            }
        }
        UserCmd::Remove { username } => {
            db.remove_user(&username)?;
            println!("Removed '{username}'.");
        }
        UserCmd::Passwd { username } => {
            let p = prompt::new_password()?;
            db.set_password(&username, &p)?;
            println!("Password changed; remembered devices for '{username}' were signed out.");
        }
        UserCmd::Pin { username, clear } => {
            if clear {
                db.set_pin(&username, None)?;
                println!("PIN cleared.");
            } else if let Some(pin) = prompt::optional_pin()? {
                db.set_pin(&username, Some(&pin))?;
                println!("PIN set.");
            }
        }
        UserCmd::Role { username, role } => {
            db.set_role(&username, role)?;
            println!("'{username}' is now {}.", role.as_str());
        }
        UserCmd::Perms { username, perms } => {
            db.set_permissions(&username, perms)?;
            println!("'{username}' permissions: {perms}.");
        }
        UserCmd::Disable { username } => {
            db.set_disabled(&username, true)?;
            println!("Disabled '{username}'.");
        }
        UserCmd::Enable { username } => {
            db.set_disabled(&username, false)?;
            println!("Enabled '{username}'.");
        }
        UserCmd::Unlock { username } => {
            db.unlock(&username)?;
            println!("Unlocked '{username}'.");
        }
    }
    Ok(())
}

/// Save relay settings, generating this host's id and relay secret on first use.
pub(crate) fn configure_relay(db: &db::Db, addr: &str, relay_only: bool) -> Result<String> {
    let addr = rd_core::relay::with_port(addr, rd_core::relay::DEFAULT_RELAY_PORT);
    let id = match db.setting("relay_id")? {
        Some(id) if !id.is_empty() => id,
        _ => {
            let mut b = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
            rd_core::relay::new_host_id(&b)
        }
    };
    if db.setting("relay_secret")?.filter(|s| !s.is_empty()).is_none() {
        db.set_setting("relay_secret", &db::random_token())?;
    }
    db.set_setting("relay_id", &id)?;
    db.set_setting("relay_addr", &addr)?;
    db.set_setting("listen", if relay_only { "off" } else { "on" })?;
    Ok(id)
}
