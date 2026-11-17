//! `rd-client` - remote desktop viewer and account tool.
//!
//! ```text
//! rd-client                            open the app (saved computers, sign-in, accounts)
//! rd-client connect myhost             open the app connected to myhost
//! rd-client connect 482-913-077@relay.example.com      ... through a relay
//! rd-client find                      list computers on this network
//! rd-client setup [--name N]          turn on remote access for this computer (like the app)
//! rd-client uninstall                  remove the app (and remote access) from this computer
//! rd-client saved                      list hosts you have trusted / saved sign-ins for
//! rd-client forget myhost [--keep-trust]
//! rd-client account myhost passwd|set-pin|devices|revoke <id>|whoami
//! rd-client users myhost list|add|remove|role|perms|disable|enable|passwd   (admins)
//! ```

#![cfg_attr(all(not(debug_assertions), windows), windows_subsystem = "windows")]

mod audio_out;
mod config;
mod discover;
mod conn;
mod gui;
mod installer;
mod keyhook;
mod keymap;
mod notice;
mod pads;
mod session;
mod setup;
mod update;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rd_core::framing::{read_msg, write_msg};
use rd_core::proto::{AdminRequest, AdminResponse, ClipData, ClipImage, Mode, Permissions, Role, VideoCodec};

use crate::conn::{LoginOptions, Session};
#[allow(unused_imports)]
use rd_core::proto::ClientMsg as _;

#[derive(Parser)]
#[command(name = "rd-client", version, about = "Remote desktop client")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(clap::Args, Clone)]
struct Auth {
    /// `host[:port]`, or `HOST-ID@relay[:port]` to go through a relay.
    host: String,
    /// Sign in as this user (defaults to the saved one).
    #[arg(short, long)]
    user: Option<String>,
    /// Use your PIN instead of your password.
    #[arg(long)]
    pin: bool,
    /// Never save a device token for this host.
    #[arg(long, conflicts_with = "remember")]
    no_remember: bool,
    /// Save a device token without asking.
    #[arg(long)]
    remember: bool,
    /// Ignore the saved sign-in and ask for credentials.
    #[arg(long)]
    fresh: bool,
    /// Trust this host certificate fingerprint without asking (for scripted setups).
    #[arg(long)]
    accept_fingerprint: Option<String>,
}

impl Auth {
    fn options(&self) -> LoginOptions {
        LoginOptions {
            username: self.user.clone(),
            use_pin: self.pin,
            remember: if self.no_remember {
                Some(false)
            } else if self.remember {
                Some(true)
            } else {
                None
            },
            fresh: self.fresh,
            accept_fingerprint: self.accept_fingerprint.clone(),
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// List computers on this network that have remote access set up.
    Find,
    /// (internal) The "your screen is being shared" window, opened by the host service.
    #[command(hide = true)]
    Notice {
        #[arg(long)]
        connect: String,
    },
    /// Turn on remote access for this computer, like "Set up remote access" in the app
    /// (asks for administrator rights). The PIN is asked for, or taken from RD_PIN.
    Setup {
        /// Name shown in your other devices' lists (default: the computer name).
        #[arg(long)]
        name: Option<String>,
        /// Don't ask the router to forward a port; reachable on this network only.
        #[arg(long)]
        no_internet: bool,
        /// Ask the person at this computer before anyone connects.
        #[arg(long)]
        ask_to_allow: bool,
        /// Turn remote access off instead.
        #[arg(long, conflicts_with_all = ["name", "no_internet"])]
        off: bool,
    },
    /// Remove the app and remote access from this computer (opens a window).
    Uninstall,
    /// (packaging) Make the one-file installer: this program with rd-host inside.
    #[command(hide = true, name = "make-installer")]
    MakeInstaller {
        /// The rd-host program to put inside.
        #[arg(long)]
        host: std::path::PathBuf,
        /// The installer to write.
        out: std::path::PathBuf,
    },
    /// Open the app connected to a host (sign-in happens in the window).
    Connect {
        /// `host[:port]` or `HOST-ID@relay[:port]`.
        host: String,
    },
    /// List saved hosts.
    Saved,
    /// Forget a host (trust + saved sign-in).
    Forget {
        host: String,
        /// Only drop the saved sign-in; keep the pinned certificate.
        #[arg(long)]
        keep_trust: bool,
    },
    /// Manage your own account on a host.
    Account {
        #[command(flatten)]
        auth: Auth,
        #[command(subcommand)]
        cmd: AccountCmd,
    },
    /// Save one remote frame to a BMP without opening a window (diagnostics).
    Snapshot {
        #[command(flatten)]
        auth: Auth,
        out: std::path::PathBuf,
        /// Move the remote mouse to X,Y first (input injection check).
        #[arg(long, value_parser = parse_xy)]
        move_mouse: Option<(u32, u32)>,
    },
    /// Connect without a window and test the session features (diagnostics).
    Check {
        #[command(flatten)]
        auth: Auth,
        /// Send this text to the remote clipboard.
        #[arg(long)]
        clipboard: Option<String>,
        /// Send this PNG image to the remote clipboard.
        #[arg(long)]
        clipboard_image: Option<std::path::PathBuf>,
        /// Save an image received from the remote clipboard (during --hold) to this PNG file.
        #[arg(long)]
        save_clipboard_image: Option<std::path::PathBuf>,
        /// Copy these local files/folders to the remote clipboard.
        #[arg(long, num_args = 1..)]
        clipboard_files: Option<Vec<std::path::PathBuf>>,
        /// List the remote home folder.
        #[arg(long)]
        list: bool,
        /// Upload this local file (lands in the remote Downloads folder).
        #[arg(long)]
        upload: Option<std::path::PathBuf>,
        /// Download REMOTE_PATH to LOCAL_PATH.
        #[arg(long, num_args = 2, value_names = ["REMOTE", "LOCAL"])]
        download: Option<Vec<String>>,
        /// Stream audio for this many seconds and count the chunks received.
        #[arg(long)]
        audio_seconds: Option<u64>,
        /// Switch to this display index.
        #[arg(long)]
        display: Option<u32>,
        /// Stay connected this many seconds before disconnecting.
        #[arg(long, default_value_t = 0)]
        hold: u64,
        /// Picture mode: `tiles` (lossless) or `h264`, optionally with a cap: `h264:2000` (kbit/s).
        #[arg(long)]
        codec: Option<String>,
        /// Count picture frames and bytes for this many seconds.
        #[arg(long)]
        measure: Option<u64>,
        /// Save the final remote picture as a BMP.
        #[arg(long)]
        save_frame: Option<std::path::PathBuf>,
    },
    /// Manage users on a host (admin only).
    Users {
        #[command(flatten)]
        auth: Auth,
        #[command(subcommand)]
        cmd: UsersCmd,
    },
}

#[derive(Subcommand)]
enum AccountCmd {
    Whoami,
    /// Change your password.
    Passwd,
    /// Set (or --clear) your quick-login PIN.
    SetPin {
        #[arg(long)]
        clear: bool,
    },
    /// List your remembered devices (admins: all devices).
    Devices,
    /// Revoke a remembered device.
    Revoke { id: i64 },
}

#[derive(Subcommand)]
enum UsersCmd {
    List,
    Add {
        username: String,
        #[arg(long, default_value = "user")]
        role: Role,
        /// full | view | none | view,control
        #[arg(long, default_value = "full")]
        perms: Permissions,
    },
    Remove { username: String },
    Role { username: String, role: Role },
    Perms { username: String, perms: Permissions },
    Disable { username: String },
    Enable { username: String },
    /// Reset another user's password.
    Passwd { username: String },
}

fn parse_xy(s: &str) -> Result<(u32, u32), String> {
    let (x, y) = s.split_once(',').ok_or("expected X,Y")?;
    Ok((x.trim().parse().map_err(|_| "bad X")?, y.trim().parse().map_err(|_| "bad Y")?))
}

fn new_secret(what: &str, validate: impl Fn(&str) -> Result<(), String>) -> Result<String> {
    if let Ok(v) = std::env::var(if what == "PIN" { "RD_NEW_PIN" } else { "RD_NEW_PASSWORD" }) {
        validate(&v).map_err(|e| anyhow::anyhow!(e))?;
        return Ok(v);
    }
    for _ in 0..3 {
        let a = rpassword::prompt_password(format!("New {what}: "))?;
        if let Err(e) = validate(&a) {
            println!("{e}");
            continue;
        }
        if a == rpassword::prompt_password(format!("Repeat {what}: "))? {
            return Ok(a);
        }
        println!("They do not match.");
    }
    bail!("{what} not changed")
}

fn password_rule(p: &str) -> Result<(), String> {
    if p.chars().count() < 8 {
        Err("must be at least 8 characters".into())
    } else {
        Ok(())
    }
}

fn pin_rule(p: &str) -> Result<(), String> {
    if (4..=12).contains(&p.len()) && p.chars().all(|c| c.is_ascii_digit()) {
        Ok(())
    } else {
        Err("PIN must be 4-12 digits".into())
    }
}

async fn admin(session: &mut Session, req: AdminRequest) -> Result<AdminResponse> {
    write_msg(&mut session.stream, &req).await?;
    match read_msg(&mut session.stream).await? {
        AdminResponse::Error(e) => bail!("{e}"),
        r => Ok(r),
    }
}

fn print_users(users: &[rd_core::proto::UserInfo]) {
    println!("{:<20} {:<6} {:<14} {:<4} status", "username", "role", "permissions", "pin");
    for u in users {
        let perms = if u.role == Role::Admin { "all".into() } else { u.perms.to_string() };
        println!(
            "{:<20} {:<6} {:<14} {:<4} {}",
            u.username,
            u.role.as_str(),
            perms,
            if u.has_pin { "yes" } else { "no" },
            if u.disabled { "disabled" } else { "active" }
        );
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let cli = Cli::parse();
    let rt = tokio::runtime::Runtime::new()?;

    let Some(cmd) = cli.cmd else {
        // The one-file installer is this program with rd-host attached.
        if let Some(payload) = installer::embedded() {
            return gui::run_installer(rt, installer::Installer::install(payload));
        }
        return gui::run(rt, None);
    };
    match cmd {
        Cmd::Connect { host } => gui::run(rt, Some(host)),
        Cmd::Uninstall => {
            if installer::relaunch_outside_install_dir()? {
                return Ok(());
            }
            gui::run_installer(rt, installer::Installer::uninstall())
        }
        Cmd::MakeInstaller { host, out } => installer::make(&host, &out),
        Cmd::Notice { connect } => gui::run_notice(rt, &connect),
        Cmd::Setup { name, no_internet, ask_to_allow, off } => {
            if off {
                setup::turn_off()?;
                println!("Remote access is off for this computer.");
                return Ok(());
            }
            let pin = match std::env::var("RD_PIN") {
                Ok(p) if !p.is_empty() => p,
                _ => new_secret("PIN", pin_rule)?,
            };
            let req = setup::SetupRequest {
                name: name.unwrap_or_else(setup::default_name),
                pin,
                internet: !no_internet,
                ddns: None,
                ddns_off: false,
                wake_on_lan: true,
                ask_to_allow,
            };
            setup::validate(&req).map_err(|e| anyhow::anyhow!(e))?;
            setup::set_up(&req)?;
            println!("Remote access is on. This computer is called \"{}\".", req.name.trim());
            Ok(())
        }
        Cmd::Find => {
            let found = rt.block_on(discover::scan(rd_core::DEFAULT_PORT, std::time::Duration::from_millis(1500)));
            if found.is_empty() {
                println!("No computers with remote access found on this network.");
            }
            for f in found {
                let a = &f.announce;
                println!("{}{}", a.name, if f.local { "  (this computer)" } else { "" });
                println!("  address:     {}", f.addr);
                println!("  internet:    {}", a.public.clone().or_else(|| a.public_note.clone()).unwrap_or_else(|| "-".into()));
                if let Some(n) = &a.public_name {
                    println!("  name:        {n}");
                }
                if let Some(r) = &a.relay {
                    println!("  relay:       {r}");
                }
                println!("  system:      {}", a.os);
                println!("  fingerprint: {}", a.fingerprint);
            }
            Ok(())
        }
        Cmd::Snapshot { auth, out, move_mouse } => rt.block_on(snapshot(auth, out, move_mouse)),
        Cmd::Check { auth, clipboard, clipboard_image, save_clipboard_image, clipboard_files, codec, measure, save_frame, list, upload, download, audio_seconds, display, hold } => rt.block_on(check(
            auth,
            CheckOpts { clipboard, clipboard_image, save_clipboard_image, clipboard_files, codec, measure, save_frame, list, upload, download, audio_seconds, display, hold },
        )),
        Cmd::Saved => {
            let store = config::Store::load();
            println!("{}", config::Store::location().display());
            for (host, e) in &store.hosts {
                let _ = host;
                let auto: Vec<&str> = e.tokens.keys().map(String::as_str).collect();
                println!(
                    "  {host:<28} last user={:<14} auto sign-in for: {}",
                    e.username.as_deref().unwrap_or("-"),
                    if auto.is_empty() { "-".to_string() } else { auto.join(", ") }
                );
            }
            Ok(())
        }
        Cmd::Forget { host, keep_trust } => {
            if conn::forget(&host, keep_trust, None)? {
                println!("Forgot {}.", conn::normalize(&host));
            } else {
                println!("{} was not saved.", conn::normalize(&host));
            }
            Ok(())
        }
        Cmd::Account { auth, cmd } => rt.block_on(async {
            let mut s = conn::login(&auth.host, Mode::Admin, &auth.options()).await?;
            let me = s.user.username.clone();
            match cmd {
                AccountCmd::Whoami => {
                    if let AdminResponse::User(u) = admin(&mut s, AdminRequest::WhoAmI).await? {
                        print_users(&[u]);
                    }
                }
                AccountCmd::Passwd => {
                    let password = new_secret("password", password_rule)?;
                    admin(&mut s, AdminRequest::SetPassword { username: me.clone(), password }).await?;
                    println!("Password changed. Remembered devices were signed out.");
                    conn::forget(&auth.host, true, Some(&me))?;
                }
                AccountCmd::SetPin { clear } => {
                    let pin = if clear { None } else { Some(new_secret("PIN", pin_rule)?) };
                    admin(&mut s, AdminRequest::SetPin { username: me, pin }).await?;
                    println!("{}", if clear { "PIN cleared." } else { "PIN set. Use `--pin` to sign in with it." });
                }
                AccountCmd::Devices => {
                    if let AdminResponse::Devices(ds) = admin(&mut s, AdminRequest::ListDevices).await? {
                        println!("{:>4}  {:<16} {:<28} {:<20} last used", "id", "user", "device", "created");
                        for d in ds {
                            println!(
                                "{:>4}  {:<16} {:<28} {:<20} {}",
                                d.id,
                                d.username,
                                d.name,
                                d.created,
                                d.last_used.unwrap_or_else(|| "-".into())
                            );
                        }
                    }
                }
                AccountCmd::Revoke { id } => {
                    admin(&mut s, AdminRequest::RevokeDevice { id }).await?;
                    println!("Revoked device {id}.");
                }
            }
            Ok(())
        }),
        Cmd::Users { auth, cmd } => rt.block_on(async {
            let mut s = conn::login(&auth.host, Mode::Admin, &auth.options()).await?;
            let req = match cmd {
                UsersCmd::List => {
                    if let AdminResponse::Users(us) = admin(&mut s, AdminRequest::ListUsers).await? {
                        print_users(&us);
                    }
                    return Ok(());
                }
                UsersCmd::Add { username, role, perms } => {
                    println!("Choose a password for '{username}'.");
                    let password = new_secret("password", password_rule)?;
                    AdminRequest::AddUser { username, password, role, perms }
                }
                UsersCmd::Remove { username } => AdminRequest::RemoveUser { username },
                UsersCmd::Role { username, role } => AdminRequest::SetRole { username, role },
                UsersCmd::Perms { username, perms } => AdminRequest::SetPermissions { username, perms },
                UsersCmd::Disable { username } => AdminRequest::SetDisabled { username, disabled: true },
                UsersCmd::Enable { username } => AdminRequest::SetDisabled { username, disabled: false },
                UsersCmd::Passwd { username } => {
                    let password = new_secret("password", password_rule)?;
                    AdminRequest::SetPassword { username, password }
                }
            };
            admin(&mut s, req).await?;
            println!("Done.");
            Ok(())
        }),
    }
}

async fn snapshot(auth: Auth, out: std::path::PathBuf, move_mouse: Option<(u32, u32)>) -> Result<()> {
    use rd_core::codec::{Decoder, Frame};
    use rd_core::proto::{ClientMsg, HostMsg, InputEvent};
    use std::time::Duration;

    let mut s = conn::login(&auth.host, Mode::Desktop, &auth.options()).await?;
    let mut dec = Decoder::default();
    let mut moved = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        let msg = tokio::time::timeout_at(deadline, read_msg::<_, HostMsg>(&mut s.stream))
            .await
            .map_err(|_| anyhow::anyhow!("no frame within 60 s"))??;
        match msg {
            HostMsg::Status(st) => println!("host: {st}"),
            HostMsg::Bye(why) => bail!("host closed the session: {why}"),
            HostMsg::Displays { list, current } => {
                for d in &list {
                    let mark = if d.index == current { " (shown)" } else { "" };
                    println!("display {}: {} {}x{}{mark}", d.index, d.name, d.width, d.height);
                }
            }
            HostMsg::Viewers(v) => println!("viewers: {}", v.join(", ")),
            HostMsg::Clipboard(_) | HostMsg::Audio(_) | HostMsg::Files(_) | HostMsg::Video(_) | HostMsg::Codec { .. } | HostMsg::Pong(_) | HostMsg::Cursor(_) | HostMsg::Privacy { .. } => {}
            HostMsg::Chat { from, text } => println!("chat from {from}: {text}"),
            HostMsg::Frame(f) => {
                dec.apply(&f)?;
                if let (Some((x, y)), false) = (move_mouse, moved) {
                    write_msg(&mut s.stream, &ClientMsg::Input(InputEvent::MouseMove { x, y })).await?;
                    moved = true;
                    println!("sent mouse move to {x},{y}");
                }
                if dec.width > 0 {
                    let data: Vec<u8> = dec.pixels.iter().flat_map(|p| p.to_le_bytes()).collect();
                    let frame = Frame { width: dec.width, height: dec.height, stride: dec.width as usize * 4, data };
                    std::fs::write(&out, frame.to_bmp())?;
                    println!("saved {}x{} frame to {}", dec.width, dec.height, out.display());
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    write_msg(&mut s.stream, &ClientMsg::Disconnect).await?;
                    return Ok(());
                }
            }
        }
    }
}

struct CheckOpts {
    clipboard: Option<String>,
    clipboard_image: Option<std::path::PathBuf>,
    save_clipboard_image: Option<std::path::PathBuf>,
    clipboard_files: Option<Vec<std::path::PathBuf>>,
    list: bool,
    upload: Option<std::path::PathBuf>,
    download: Option<Vec<String>>,
    audio_seconds: Option<u64>,
    display: Option<u32>,
    hold: u64,
    codec: Option<String>,
    measure: Option<u64>,
    save_frame: Option<std::path::PathBuf>,
}

/// Poll the session state until `f` returns Some or `secs` pass.
async fn wait_for<T>(
    h: &session::Handle,
    secs: u64,
    mut f: impl FnMut(&mut session::State) -> Option<T>,
) -> Result<T> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    loop {
        {
            let mut s = h.state.lock().unwrap();
            if let Some(why) = &s.closed {
                bail!("session closed: {why}");
            }
            if let Some(v) = f(&mut s) {
                return Ok(v);
            }
        }
        if std::time::Instant::now() > deadline {
            bail!("timed out");
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

fn transfer_result(s: &mut session::State, idx: usize) -> Option<Result<String, String>> {
    match &s.transfers.get(idx)?.state {
        session::TransferState::Active => None,
        session::TransferState::Done(m) => Some(Ok(m.clone())),
        session::TransferState::Failed(m) => Some(Err(m.clone())),
    }
}

async fn check(auth: Auth, o: CheckOpts) -> Result<()> {
    use rd_core::proto::ClientMsg;
    let s = conn::login(&auth.host, Mode::Desktop, &auth.options()).await?;
    let perms = s.user.effective();
    println!("signed in as {} ({}, permissions: {perms})", s.user.username, s.user.role.as_str());
    println!("connection: {}", s.route);
    let h = session::Handle::start(&tokio::runtime::Handle::current(), s, || {});

    let (w, hgt) = wait_for(&h, 30, |s| (s.decoder.width > 0).then_some((s.decoder.width, s.decoder.height))).await?;
    println!("video: {w}x{hgt}");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    {
        let s = h.state.lock().unwrap();
        println!("status: {}", s.status);
        println!("viewers: {}", s.viewers.join(", "));
        for d in &s.displays {
            let mark = if d.index == s.current_display { "  <- shown" } else { "" };
            println!("display {}: {} {}x{} at {},{}{mark}", d.index, d.name, d.width, d.height, d.x, d.y);
        }
    }
    if let Some(c) = &o.codec {
        let want = match c.split_once(':') {
            None if c == "tiles" => VideoCodec::Tiles,
            None if c == "h264" => VideoCodec::H264 { max_kbps: 0 },
            Some(("h264", k)) => VideoCodec::H264 { max_kbps: k.parse().context("bad kbit/s value")? },
            _ => bail!("--codec must be tiles, h264 or h264:KBPS"),
        };
        h.send(ClientMsg::SetCodec(want));
        let is_h264 = matches!(want, VideoCodec::H264 { .. });
        let r = wait_for(&h, 10, |s| (matches!(s.codec, VideoCodec::H264 { .. }) == is_h264).then_some((s.codec, s.kbps))).await;
        match r {
            Ok((c, kbps)) => println!("codec: {c:?}, {kbps} kbit/s"),
            Err(_) => println!("codec: host did not switch"),
        }
    }
    if let Some(secs) = o.measure {
        let (b0, f0) = {
            let s = h.state.lock().unwrap();
            (s.video_bytes, s.video_frames)
        };
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        let s = h.state.lock().unwrap();
        let (b, f) = (s.video_bytes - b0, s.video_frames - f0);
        println!(
            "measure: {f} frames in {secs} s ({:.1} fps), {:.2} MB, {:.2} Mbit/s; codec {:?} at {} kbit/s",
            f as f64 / secs as f64,
            b as f64 / 1e6,
            b as f64 * 8.0 / 1e6 / secs as f64,
            s.codec,
            s.kbps
        );
    }
    if let Some(i) = o.display {
        h.send(ClientMsg::SelectDisplay(i));
        let r = wait_for(&h, 10, |s| (s.current_display == i).then_some(())).await;
        println!("select display {i}: {}", if r.is_ok() { "ok" } else { "no change" });
    }
    if let Some(text) = &o.clipboard {
        h.send(ClientMsg::Clipboard(ClipData::Text(text.clone())));
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        println!("clipboard: sent {} chars", text.len());
    }
    if let Some(path) = &o.clipboard_image {
        let png = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let (width, height, _) = rd_core::clipboard::decode_png(&png).context("not a usable PNG")?;
        let data = ClipData::Image(ClipImage { width, height, png });
        println!("clipboard: sending {}", data.describe());
        h.send(ClientMsg::Clipboard(data));
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    }
    if let Some(paths) = &o.clipboard_files {
        let data = ClipData::Files(rd_core::clipboard::collect_files(paths)?);
        println!("clipboard: sending {}", data.describe());
        h.send(ClientMsg::Clipboard(data));
        tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    }
    if o.list {
        h.list_dir("");
        let r = wait_for(&h, 15, |s| {
            if let Some(e) = s.dir_error.take() {
                return Some(Err(e));
            }
            s.dir.as_ref().map(|d| Ok((d.path.clone(), d.entries.len(), d.entries.iter().take(5).map(|e| e.name.clone()).collect::<Vec<_>>())))
        })
        .await?;
        match r {
            Ok((path, n, first)) => println!("files: {path} has {n} entries (first: {})", first.join(", ")),
            Err(e) => println!("files: error: {e}"),
        }
    }
    if let Some(path) = &o.upload {
        let idx = h.state.lock().unwrap().transfers.len();
        h.upload(path.clone());
        match wait_for(&h, 120, |s| transfer_result(s, idx)).await? {
            Ok(m) => println!("upload: {m}"),
            Err(e) => println!("upload: FAILED: {e}"),
        }
    }
    if let Some(d) = &o.download {
        let idx = h.state.lock().unwrap().transfers.len();
        let name = std::path::Path::new(&d[0]).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        h.download(d[0].clone(), name, 0, std::path::PathBuf::from(&d[1]));
        match wait_for(&h, 120, |s| transfer_result(s, idx)).await? {
            Ok(m) => println!("download: {m}"),
            Err(e) => println!("download: FAILED: {e}"),
        }
    }
    if let Some(secs) = o.audio_seconds {
        h.send(ClientMsg::SetAudio(true));
        tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
        h.send(ClientMsg::SetAudio(false));
        let n = h.state.lock().unwrap().audio_chunks;
        println!("audio: {n} chunks in {secs} s (~{} ms of sound)", n * 20);
    }
    if o.hold > 0 {
        println!("holding the session for {} s...", o.hold);
        tokio::time::sleep(std::time::Duration::from_secs(o.hold)).await;
        let s = h.state.lock().unwrap();
        println!("viewers now: {}", s.viewers.join(", "));
        match &s.cursor {
            Some(rd_core::proto::CursorShape::Image { width, height, hot_x, hot_y, rgba }) => {
                let opaque = rgba.chunks_exact(4).filter(|p| p[3] > 0).count();
                println!("pointer: {width}x{height} image, hotspot {hot_x},{hot_y}, {opaque} visible pixels ({} changes)", s.cursor_seq);
            }
            Some(other) => println!("pointer: {other:?}"),
            None => println!("pointer: not reported"),
        }
        match &s.incoming_clipboard {
            Some(ClipData::Text(t)) => println!("clipboard received from host: {t:?}"),
            Some(c @ ClipData::Image(img)) => {
                println!("clipboard received from host: {}", c.describe());
                if let Some(p) = &o.save_clipboard_image {
                    std::fs::write(p, &img.png)?;
                    println!("saved to {}", p.display());
                }
            }
            Some(c @ ClipData::Files(files)) => {
                println!("clipboard received from host: {}", c.describe());
                for p in rd_core::clipboard::write_received(files)? {
                    println!("  saved {}", p.display());
                }
            }
            None => {}
        }
    }
    if let Some(p) = &o.save_frame {
        let s = h.state.lock().unwrap();
        let d = &s.decoder;
        let data: Vec<u8> = d.pixels.iter().flat_map(|px| px.to_le_bytes()).collect();
        let f = rd_core::codec::Frame { width: d.width, height: d.height, stride: d.width as usize * 4, data };
        std::fs::write(p, f.to_bmp())?;
        println!("saved picture to {}", p.display());
    }
    drop(h);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    Ok(())
}
