//! Installing / running as an OS service.
//!
//! * Windows: SCM service `rd-host` (LocalSystem, auto-start), binary copied to
//!   `%ProgramFiles%\RDHost`, data dir ACL'd to SYSTEM + Administrators, inbound
//!   firewall rule for the port.
//! * Linux: systemd unit `rd-host.service`, binary copied to `/usr/local/bin`,
//!   data dir `/var/lib/rd-host` (0700).
//!
//! The app (`rd-client`, when it sits next to rd-host) is installed alongside, with a
//! Start menu shortcut / application-menu entry. The service also uses it to show the
//! "your screen is being shared" notice. Turning remote access off keeps the app;
//! `uninstall --purge` removes it too.

use std::path::{Path, PathBuf};

#[allow(unused_imports)] // bail/Context are used by the Linux half
use anyhow::{bail, Context, Result};
use rd_core::proto::{Permissions, Role};

use crate::db::Db;

pub const SERVICE_NAME: &str = "rd-host";

pub struct InstallOptions {
    pub data_dir: PathBuf,
    pub port: u16,
    pub bind: String,
    pub backend: String,
    pub fps: u32,
    pub firewall: bool,
    /// Allow inbound UDP for rd-host.exe (direct peer-to-peer connections via a relay).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub udp_firewall: bool,
    pub admin_user: Option<String>,
    pub relay: Option<String>,
    pub relay_only: bool,
    pub max_viewers: u32,
    pub video_kbps: u32,
    pub video_encoder: String,
    pub name: Option<String>,
    /// Owner account for PIN-only sign-in from the app; `pin` is its PIN.
    pub owner: Option<String>,
    pub pin: Option<String>,
    pub upnp: bool,
    /// Dynamic DNS (name, update URL) to save; `ddns_off` removes it.
    pub ddns: Option<(String, String)>,
    pub ddns_off: bool,
    /// Let the network adapter wake the computer (Wake-on-LAN).
    pub wake_on_lan: bool,
    /// Install the app next to the service, with a menu entry.
    pub app: bool,
}

/// rd-client next to this program, if it's there.
fn app_beside_me() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?.with_file_name(if cfg!(windows) { "rd-client.exe" } else { "rd-client" });
    exe.exists().then_some(exe)
}

/// Save settings, create the first admin if needed, generate the TLS cert.
fn prepare_data(opts: &InstallOptions) -> Result<String> {
    std::fs::create_dir_all(&opts.data_dir)?;
    restrict_dir(&opts.data_dir)?;
    let mut db = Db::open(&opts.data_dir)?;
    db.set_setting("port", &opts.port.to_string())?;
    db.set_setting("bind", &opts.bind)?;
    db.set_setting("backend", &opts.backend)?;
    db.set_setting("fps", &opts.fps.to_string())?;
    db.set_setting("max_viewers", &opts.max_viewers.to_string())?;
    db.set_setting("video_kbps", &opts.video_kbps.to_string())?;
    db.set_setting("video_encoder", &opts.video_encoder)?;
    if let Some(relay) = &opts.relay {
        let id = crate::configure_relay(&db, relay, opts.relay_only)?;
        println!("Relay: {relay}  -  this computer's id is {id}");
    }
    if let Some(name) = &opts.name {
        db.set_setting("name", name)?;
    }
    db.set_setting("upnp", if opts.upnp { "on" } else { "off" })?;
    crate::save_ddns(&db, opts.ddns.as_ref(), opts.ddns_off)?;
    if let Some(owner) = &opts.owner {
        let pin = opts.pin.as_deref().context("a PIN is required")?;
        set_owner(&mut db, owner, pin)?;
    } else if db.user_count()? == 0 {
        println!();
        println!("== Create the administrator account ==");
        println!("This is the first account on this host, so it becomes the admin.");
        println!("You will use it to sign in from rd-client and to manage other users.");
        create_admin_interactive(&mut db, opts.admin_user.clone())?;
    } else {
        println!("Existing user database found ({} account(s)); keeping it.", db.user_count()?);
    }
    rd_core::tls::ensure_host_cert(&opts.data_dir, &crate::paths::host_name())?;
    rd_core::tls::host_fingerprint(&opts.data_dir)
}

/// Set up from the app: an owner account signed into with just the PIN. Its password
/// is random; set one with `rd-host user passwd` if ever needed.
pub fn set_owner(db: &mut Db, owner: &str, pin: &str) -> Result<()> {
    crate::db::validate_username(owner)?;
    crate::db::validate_pin(pin)?;
    match db.get_user(owner)? {
        None => {
            db.create_user(owner, &crate::db::random_token(), Role::Admin, Permissions::FULL)?;
            println!("Created the owner account '{owner}'.");
        }
        Some(u) if u.role != Role::Admin => db.set_role(owner, Role::Admin)?,
        Some(_) => {}
    }
    db.set_disabled(owner, false)?;
    db.set_pin(owner, Some(pin))?;
    db.set_setting("owner", owner)?;
    println!("PIN set for '{owner}'.");
    Ok(())
}

pub fn create_admin_interactive(db: &mut Db, username: Option<String>) -> Result<()> {
    let username = match username {
        Some(u) => u,
        None => crate::prompt::line("Admin username: ")?,
    };
    crate::db::validate_username(&username)?;
    let password = match std::env::var("RD_ADMIN_PASSWORD") {
        Ok(p) if !p.is_empty() => p,
        _ => crate::prompt::new_password()?,
    };
    let role = db.create_user(&username, &password, Role::Admin, Permissions::FULL)?;
    println!("Created '{username}' ({}).", role.as_str());
    if std::env::var_os("RD_ADMIN_PASSWORD").is_none() {
        if let Some(pin) = crate::prompt::optional_pin()? {
            db.set_pin(&username, Some(&pin))?;
            println!("PIN set.");
        }
    }
    Ok(())
}

fn print_summary(opts: &InstallOptions, fp: &str) {
    println!();
    println!("Installed and started the '{SERVICE_NAME}' service.");
    println!("  port:         {}", opts.port);
    println!("  data dir:     {}", opts.data_dir.display());
    println!("  fingerprint:  {fp}");
    println!();
    println!("Connect from another machine with:");
    if !opts.relay_only {
        println!("  rd-client connect <this-host>:{}", opts.port);
    }
    if let Some(relay) = &opts.relay {
        if let Ok(db) = Db::open(&opts.data_dir) {
            if let Ok(Some(id)) = db.setting("relay_id") {
                println!("  rd-client connect {id}@{relay}        (from anywhere, through the relay)");
            }
        }
    }
    println!("Compare the fingerprint above with what the client shows on first connect.");
}

// ====================================================================== Windows

#[cfg(windows)]
pub use self::win::*;

#[cfg(windows)]
mod win {
    use std::ffi::OsString;
    use std::process::Command;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use tokio::sync::watch;
    use windows_service::service::{
        ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode, ServiceInfo,
        ServiceStartType, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    use windows_service::{define_windows_service, service_dispatcher};

    use super::*;

    fn install_dir() -> PathBuf {
        let base = std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files"));
        base.join("RDHost")
    }

    pub(super) fn restrict_dir(dir: &Path) -> Result<()> {
        // Only SYSTEM and Administrators may read the DB (password hashes) and TLS key.
        let status = Command::new("icacls")
            .arg(dir)
            .args(["/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/Q"])
            .status()
            .context("run icacls")?;
        if !status.success() {
            anyhow::bail!("icacls failed to restrict {}", dir.display());
        }
        Ok(())
    }

    fn stop_and_delete_existing(manager: &ServiceManager) -> Result<bool> {
        let Ok(svc) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)
        else {
            return Ok(false);
        };
        if svc.query_status()?.current_state != ServiceState::Stopped {
            let _ = svc.stop();
            for _ in 0..50 {
                if svc.query_status()?.current_state == ServiceState::Stopped {
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        svc.delete()?;
        drop(svc);
        // SCM deletes asynchronously once all handles are closed.
        std::thread::sleep(Duration::from_millis(500));
        Ok(true)
    }

    pub fn install(opts: InstallOptions) -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)
            .context("cannot open the Service Control Manager - run this from an elevated (Administrator) terminal")?;
        if stop_and_delete_existing(&manager)? {
            println!("Replacing existing '{SERVICE_NAME}' service.");
        }

        let dir = install_dir();
        std::fs::create_dir_all(&dir)?;
        let exe = dir.join("rd-host.exe");
        let me = std::env::current_exe()?;
        if !same_file(&me, &exe) {
            std::fs::copy(&me, &exe).with_context(|| format!("copy binary to {}", exe.display()))?;
        }

        if opts.app {
            install_app(&dir);
        }

        let fp = prepare_data(&opts)?;

        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from("RD Remote Desktop Host"),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe.clone(),
            launch_arguments: vec![
                OsString::from("--data-dir"),
                opts.data_dir.clone().into_os_string(),
                OsString::from("service"),
            ],
            dependencies: vec![],
            account_name: None, // LocalSystem: required to launch the agent into the console session
            account_password: None,
        };
        let svc = manager
            .create_service(&info, ServiceAccess::CHANGE_CONFIG | ServiceAccess::START)
            .context("create service")?;
        svc.set_description("Remote desktop host: accepts authenticated remote control connections.")?;

        if opts.firewall {
            let _ = Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", "name=RD Remote Desktop Host"])
                .output();
            let ok = Command::new("netsh")
                .args(["advfirewall", "firewall", "add", "rule", "name=RD Remote Desktop Host", "dir=in", "action=allow", "protocol=TCP"])
                .arg(format!("localport={}", opts.port))
                .arg(format!("program={}", exe.display()))
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !ok {
                println!("warning: could not add the Windows Firewall rule; allow TCP {} manually", opts.port);
            }
        }
        if opts.udp_firewall {
            // Peer-to-peer sessions use a fresh random UDP port each time, so this rule
            // is scoped to the program rather than a port.
            let _ = Command::new("netsh")
                .args(["advfirewall", "firewall", "delete", "rule", "name=RD Remote Desktop Host (P2P)"])
                .output();
            let ok = Command::new("netsh")
                .args(["advfirewall", "firewall", "add", "rule", "name=RD Remote Desktop Host (P2P)", "dir=in", "action=allow", "protocol=UDP"])
                .arg(format!("program={}", exe.display()))
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !ok {
                println!("warning: could not add the Windows Firewall UDP rule; direct peer-to-peer connections may fall back to the relay");
            }
        }

        // Allow services to generate Ctrl+Alt+Del (SendSAS). 1 = services, 3 = services + apps.
        let sas = Command::new("reg")
            .args([
                "add",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "/v",
                "SoftwareSASGeneration",
                "/t",
                "REG_DWORD",
                "/d",
                "1",
                "/f",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !sas {
            println!("warning: could not enable SoftwareSASGeneration; Ctrl+Alt+Del from viewers won't work");
        }

        if opts.wake_on_lan {
            // Every adapter that supports it: wake on a magic packet only.
            let ok = Command::new("powershell.exe")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-NetAdapter -Physical | Set-NetAdapterPowerManagement -WakeOnMagicPacket Enabled -ErrorAction SilentlyContinue",
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            println!("{}", if ok { "Wake-on-LAN enabled on the network adapters." } else { "note: couldn't enable Wake-on-LAN on the network adapters" });
        }

        svc.start::<&str>(&[]).context("start service")?;
        print_summary(&opts, &fp);
        Ok(())
    }

    fn start_menu_link() -> PathBuf {
        let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join(r"Microsoft\Windows\Start Menu\Programs\RD Remote Desktop.lnk")
    }

    /// Copy the app next to the service and add a Start menu shortcut. Failures only
    /// warn: the service works without it (e.g. the app is open and can't be replaced).
    fn install_app(dir: &Path) {
        let Some(src) = app_beside_me() else { return };
        let dst = dir.join("rd-client.exe");
        if !same_file(&src, &dst) {
            if let Err(e) = std::fs::copy(&src, &dst) {
                println!("note: couldn't copy the app to {} ({e}); close it there and set up again to update it", dst.display());
                if !dst.exists() {
                    return;
                }
            }
        }
        let ps = format!(
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{}'); $s.TargetPath = '{}'; $s.WorkingDirectory = '{}'; $s.Description = 'Connect to your computers'; $s.Save()",
            start_menu_link().display().to_string().replace('\'', "''"),
            dst.display().to_string().replace('\'', "''"),
            dir.display().to_string().replace('\'', "''"),
        );
        let ok = Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .output()
            .is_ok_and(|o| o.status.success());
        if ok {
            println!("Added \"RD Remote Desktop\" to the Start menu.");
        }
    }

    pub fn uninstall(data_dir: &Path, purge: bool) -> Result<()> {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
            .context("cannot open the Service Control Manager - run this from an elevated terminal")?;
        if stop_and_delete_existing(&manager)? {
            println!("Removed service '{SERVICE_NAME}'.");
        } else {
            println!("Service '{SERVICE_NAME}' was not installed.");
        }
        for rule in ["name=RD Remote Desktop Host", "name=RD Remote Desktop Host (P2P)"] {
            let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", rule]).output();
        }
        let exe = install_dir().join("rd-host.exe");
        if same_file(&std::env::current_exe()?, &exe) {
            println!("Note: delete {} manually after this process exits.", exe.display());
        } else if purge {
            // Everything, including the app and its shortcut.
            let _ = std::fs::remove_file(start_menu_link());
            let _ = std::fs::remove_dir_all(install_dir());
        } else {
            // Keep the app: it's also how you connect to your other computers.
            let _ = std::fs::remove_file(&exe);
        }
        if purge {
            std::fs::remove_dir_all(data_dir).ok();
            println!("Deleted {} (users, devices, certificate).", data_dir.display());
        } else {
            println!("Kept {} (use --purge to delete users and keys).", data_dir.display());
        }
        Ok(())
    }

    fn same_file(a: &Path, b: &Path) -> bool {
        match (a.canonicalize(), b.canonicalize()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    }

    // ------------------------------------------------------------ SCM entry point

    define_windows_service!(ffi_service_main, service_main);

    static DATA_DIR: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

    pub fn run_service(data_dir: PathBuf) -> Result<()> {
        let _ = DATA_DIR.set(data_dir);
        service_dispatcher::start(SERVICE_NAME, ffi_service_main).context("not started by the Service Control Manager")?;
        Ok(())
    }

    fn service_main(_args: Vec<OsString>) {
        if let Err(e) = service_body() {
            log::error!("service failed: {e:#}");
        }
    }

    fn service_body() -> Result<()> {
        let (tx, rx) = watch::channel(false);
        let handler = move |ev| match ev {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = tx.send(true);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let status = service_control_handler::register(SERVICE_NAME, handler)?;
        let set = |state, accept| {
            status.set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: state,
                controls_accepted: accept,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::from_secs(5),
                process_id: None,
            })
        };
        set(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN)?;

        let data_dir = DATA_DIR.get().cloned().unwrap_or_else(crate::paths::default_data_dir);
        let cfg = crate::load_config(data_dir, crate::spawn::SpawnMode::UserSession, true)?;
        let rt = tokio::runtime::Runtime::new()?;
        let r = rt.block_on(crate::daemon::serve(cfg, rx));
        if let Err(e) = &r {
            log::error!("daemon error: {e:#}");
        }
        set(ServiceState::Stopped, ServiceControlAccept::empty())?;
        r
    }
}

// ====================================================================== Linux

#[cfg(target_os = "linux")]
pub use self::linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use std::process::Command;

    use super::*;

    const BIN: &str = "/usr/local/bin/rd-host";
    const UNIT: &str = "/etc/systemd/system/rd-host.service";

    pub(super) fn restrict_dir(dir: &Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(())
    }

    fn systemctl(args: &[&str]) -> Result<()> {
        let st = Command::new("systemctl").args(args).status().context("run systemctl")?;
        if !st.success() {
            bail!("systemctl {} failed", args.join(" "));
        }
        Ok(())
    }

    pub fn install(opts: InstallOptions) -> Result<()> {
        if !crate::paths::is_root() {
            bail!("run the installer as root (sudo rd-host install)");
        }
        let me = std::env::current_exe()?;
        if me != Path::new(BIN) {
            let _ = Command::new("systemctl").args(["stop", SERVICE_NAME]).status();
            // Copy to a temp name then rename, so a running binary isn't overwritten in place.
            let tmp = format!("{BIN}.new");
            std::fs::copy(&me, &tmp).with_context(|| format!("copy binary to {BIN}"))?;
            std::fs::rename(&tmp, BIN)?;
        }
        if opts.app {
            install_app();
        }
        let fp = prepare_data(&opts)?;
        let unit = format!(
            "[Unit]\n\
             Description=RD remote desktop host\n\
             After=network-online.target systemd-logind.service\n\
             Wants=network-online.target\n\n\
             [Service]\n\
             ExecStart={BIN} --data-dir {} service\n\
             Restart=on-failure\n\
             RestartSec=3\n\n\
             [Install]\n\
             WantedBy=multi-user.target\n",
            opts.data_dir.display()
        );
        std::fs::write(UNIT, unit).with_context(|| format!("write {UNIT}"))?;
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", SERVICE_NAME])?;
        systemctl(&["restart", SERVICE_NAME])?;
        print_summary(&opts, &fp);
        if opts.firewall {
            open_firewall(opts.port);
        }
        if opts.wake_on_lan {
            enable_wake_on_lan();
        }
        println!();
        println!("Wayland note: the first remote session shows a screen-sharing prompt on this");
        println!("computer's screen; approve it once locally and later sessions start unattended.");
        Ok(())
    }

    const APP: &str = "/usr/local/bin/rd-client";
    const DESKTOP_FILE: &str = "/usr/share/applications/rd-remote-desktop.desktop";

    /// Copy the app to /usr/local/bin and add it to the application menu.
    fn install_app() {
        let Some(src) = app_beside_me() else { return };
        if src != Path::new(APP) {
            let tmp = format!("{APP}.new");
            if let Err(e) = std::fs::copy(&src, &tmp).and_then(|_| std::fs::rename(&tmp, APP)) {
                println!("note: couldn't install the app to {APP}: {e}");
                return;
            }
        }
        let entry = format!(
            "[Desktop Entry]\n\
             Type=Application\n\
             Name=RD Remote Desktop\n\
             Comment=Connect to your computers\n\
             Exec={APP}\n\
             Icon=preferences-desktop-remote-desktop\n\
             Terminal=false\n\
             Categories=Network;RemoteAccess;\n"
        );
        // Leave a menu entry that a package installed alone.
        let ours = std::fs::read_to_string(DESKTOP_FILE).map(|t| t.contains(APP)).unwrap_or(true);
        if ours && std::fs::write(DESKTOP_FILE, entry).is_ok() {
            println!("Added \"RD Remote Desktop\" to the application menu.");
        }
    }

    /// Wake-on-LAN for wired connections managed by NetworkManager (kept across reboots).
    fn enable_wake_on_lan() {
        let Ok(out) = Command::new("nmcli").args(["-t", "-f", "NAME,TYPE", "connection", "show"]).output() else {
            println!("note: NetworkManager not found; enable Wake-on-LAN with ethtool (wol g) if you want it");
            return;
        };
        let mut done = 0;
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            // NAME may contain escaped colons; TYPE is the last field.
            let Some((name, kind)) = line.rsplit_once(':') else { continue };
            if kind == "802-3-ethernet" {
                let name = name.replace("\\:", ":");
                if quiet("nmcli", &["connection", "modify", &name, "802-3-ethernet.wake-on-lan", "magic"]) {
                    done += 1;
                }
            }
        }
        if done > 0 {
            println!("Wake-on-LAN enabled for {done} wired connection(s); it takes effect the next time they connect.");
        } else {
            println!("note: no wired connection found for Wake-on-LAN (it needs an Ethernet cable)");
        }
    }

    fn ufw_active() -> bool {
        Command::new("ufw")
            .arg("status")
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("Status: active"))
    }

    fn firewalld_running() -> bool {
        Command::new("firewall-cmd").arg("--state").output().is_ok_and(|o| o.status.success())
    }

    fn quiet(cmd: &str, args: &[&str]) -> bool {
        Command::new(cmd).args(args).output().is_ok_and(|o| o.status.success())
    }

    /// Open the session port (TCP), discovery (UDP) and the app's discovery-answer port
    /// (UDP) in ufw or firewalld, if active.
    fn open_firewall(port: u16) {
        let (tcp, udp) = (format!("{port}/tcp"), format!("{port}/udp"));
        let reply = format!("{}/udp", rd_core::discovery::REPLY_PORT);
        let opened = if ufw_active() {
            Some(("ufw", quiet("ufw", &["allow", &tcp]) && quiet("ufw", &["allow", &udp]) && quiet("ufw", &["allow", &reply])))
        } else if firewalld_running() {
            let ok = quiet("firewall-cmd", &["--permanent", &format!("--add-port={tcp}")])
                && quiet("firewall-cmd", &["--permanent", &format!("--add-port={udp}")])
                && quiet("firewall-cmd", &["--permanent", &format!("--add-port={reply}")])
                && quiet("firewall-cmd", &["--reload"]);
            Some(("firewalld", ok))
        } else {
            None
        };
        match opened {
            Some((fw, true)) => println!("Opened {tcp}, {udp} and {reply} in {fw}."),
            Some((fw, false)) => println!("warning: could not open {tcp}, {udp} and {reply} in {fw}"),
            None => {}
        }
    }

    fn close_firewall(port: u16) {
        let (tcp, udp) = (format!("{port}/tcp"), format!("{port}/udp"));
        let reply = format!("{}/udp", rd_core::discovery::REPLY_PORT);
        if ufw_active() {
            quiet("ufw", &["delete", "allow", &tcp]);
            quiet("ufw", &["delete", "allow", &udp]);
            quiet("ufw", &["delete", "allow", &reply]);
        } else if firewalld_running() {
            quiet("firewall-cmd", &["--permanent", &format!("--remove-port={tcp}")]);
            quiet("firewall-cmd", &["--permanent", &format!("--remove-port={udp}")]);
            quiet("firewall-cmd", &["--permanent", &format!("--remove-port={reply}")]);
            quiet("firewall-cmd", &["--reload"]);
        }
    }

    pub fn uninstall(data_dir: &Path, purge: bool) -> Result<()> {
        if !crate::paths::is_root() {
            bail!("run as root (sudo rd-host uninstall)");
        }
        let port = Db::open(data_dir)
            .ok()
            .and_then(|db| db.setting("port").ok().flatten())
            .and_then(|p| p.parse().ok())
            .unwrap_or(rd_core::DEFAULT_PORT);
        close_firewall(port);
        let _ = Command::new("systemctl").args(["disable", "--now", SERVICE_NAME]).status();
        let _ = std::fs::remove_file(UNIT);
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
        let _ = std::fs::remove_file(BIN);
        println!("Removed service and {BIN}.");
        if purge {
            if std::fs::read_to_string(DESKTOP_FILE).is_ok_and(|t| t.contains(APP)) {
                let _ = std::fs::remove_file(DESKTOP_FILE);
            }
            let _ = std::fs::remove_file(APP);
            std::fs::remove_dir_all(data_dir).ok();
            println!("Deleted {} (users, devices, certificate).", data_dir.display());
        } else {
            println!("Kept {} (use --purge to delete users and keys).", data_dir.display());
        }
        Ok(())
    }

    /// systemd runs `rd-host service` directly; it just needs SIGTERM handling.
    pub fn run_service(data_dir: PathBuf) -> Result<()> {
        let cfg = crate::load_config(data_dir, crate::spawn::SpawnMode::UserSession, false)?;
        let rt = tokio::runtime::Runtime::new()?;
        rt.block_on(async {
            let (tx, rx) = tokio::sync::watch::channel(false);
            tokio::spawn(async move {
                let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM");
                tokio::select! {
                    _ = term.recv() => {}
                    _ = tokio::signal::ctrl_c() => {}
                }
                let _ = tx.send(true);
            });
            crate::daemon::serve(cfg, rx).await
        })
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
compile_error!("rd-host supports Windows and Linux");
