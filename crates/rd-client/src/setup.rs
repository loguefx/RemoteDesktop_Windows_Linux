//! "Set up remote access" for this computer, from the app.
//!
//! Runs `rd-host install` (found next to this program) with administrator rights: a UAC
//! prompt on Windows, the polkit password dialog (pkexec) on Linux. The PIN goes through
//! a private temporary file, never the command line, and the installer reports back
//! through a result file because an elevated process's output can't be read.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, Result};

pub struct SetupRequest {
    pub name: String,
    pub pin: String,
    /// Forward a router port (UPnP) for access from the internet.
    pub internet: bool,
    /// Dynamic DNS to set: (name, update URL with `{ip}`).
    pub ddns: Option<(String, String)>,
    /// Stop using dynamic DNS.
    pub ddns_off: bool,
    /// Let the network adapter wake the computer (Wake-on-LAN).
    pub wake_on_lan: bool,
    /// Ask the person at the computer before anyone connects.
    pub ask_to_allow: bool,
}

pub const DUCKDNS_SUFFIX: &str = ".duckdns.org";

/// A DuckDNS subdomain from what was typed ("home" or "home.duckdns.org").
pub fn duckdns_subdomain(typed: &str) -> Result<String, String> {
    let t = typed.trim().to_ascii_lowercase();
    let sub = t.strip_suffix(DUCKDNS_SUFFIX).unwrap_or(&t).to_string();
    if sub.is_empty() || sub.len() > 63 || !sub.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("Enter your DuckDNS name, like \"myhome\" (from myhome.duckdns.org).".into());
    }
    Ok(sub)
}

/// (name, update URL) for a DuckDNS subdomain and token.
pub fn duckdns(sub: &str, token: &str) -> Result<(String, String), String> {
    let token = token.trim();
    if token.len() < 20 || !token.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("That doesn't look like a DuckDNS token (copy it from duckdns.org after signing in).".into());
    }
    Ok((format!("{sub}{DUCKDNS_SUFFIX}"), format!("https://www.duckdns.org/update?domains={sub}&token={token}&ip={{ip}}")))
}

pub fn host_exe() -> Result<PathBuf> {
    let me = std::env::current_exe()?;
    let exe = me.with_file_name(if cfg!(windows) { "rd-host.exe" } else { "rd-host" });
    if !exe.exists() {
        bail!("{} wasn't found; keep rd-host next to rd-client", exe.display());
    }
    Ok(exe)
}

/// The signed-in user's name, as an account name the host accepts.
pub fn owner_name() -> String {
    let raw = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_default();
    let clean: String = raw
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || "._-@".contains(c) { c } else { '_' })
        .take(64)
        .collect();
    if clean.trim_matches('_').is_empty() {
        "owner".into()
    } else {
        clean
    }
}

pub fn default_name() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "My computer".into())
}

pub fn validate(req: &SetupRequest) -> Result<(), String> {
    let n = req.name.trim();
    if n.is_empty() || n.chars().count() > 40 {
        return Err("The name must be 1-40 characters.".into());
    }
    if n.chars().any(|c| c.is_control() || c == '"') {
        return Err("The name can't contain quotes.".into());
    }
    if !(4..=12).contains(&req.pin.len()) || !req.pin.chars().all(|c| c.is_ascii_digit()) {
        return Err("The PIN must be 4 to 12 digits.".into());
    }
    Ok(())
}

/// A private scratch folder for the PIN and result files.
pub(crate) struct Scratch(pub(crate) PathBuf);

impl Scratch {
    pub(crate) fn new() -> Result<Self> {
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        let dir = std::env::temp_dir().join(format!("rd-setup-{}-{stamp}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(Scratch(dir))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Install (or update) the host service with this name and PIN. Blocks until the
/// installer finishes; call it off the UI thread.
pub fn set_up(req: &SetupRequest) -> Result<()> {
    validate(req).map_err(|e| anyhow!(e))?;
    let exe = host_exe()?;
    let scratch = Scratch::new()?;
    let pin_file = scratch.0.join("pin");
    let result_file = scratch.0.join("result");
    std::fs::write(&pin_file, &req.pin)?;
    let mut args: Vec<String> = vec![
        "install".into(),
        "--name".into(),
        req.name.trim().into(),
        "--owner".into(),
        owner_name(),
        "--pin-file".into(),
        pin_file.display().to_string(),
        "--result-file".into(),
        result_file.display().to_string(),
    ];
    if req.internet {
        args.push("--upnp".into());
    }
    if let Some((host, url)) = &req.ddns {
        // The update URL holds the account token: a private file, not the command line.
        let f = scratch.0.join("ddns");
        std::fs::write(&f, format!("{host}\n{url}\n"))?;
        args.push("--ddns-file".into());
        args.push(f.display().to_string());
    } else if req.ddns_off {
        args.push("--ddns-off".into());
    }
    if req.wake_on_lan {
        args.push("--wake-on-lan".into());
    }
    args.push("--ask-to-allow".into());
    args.push(if req.ask_to_allow { "on" } else { "off" }.into());
    run_elevated(&exe, &args, &result_file)
}

/// Replace the installed service and app with `host` (a newer rd-host, with rd-client
/// beside it), keeping all settings.
pub fn update_service(host: &Path) -> Result<()> {
    let scratch = Scratch::new()?;
    let result_file = scratch.0.join("result");
    let args = vec!["install".into(), "--update".into(), "--result-file".into(), result_file.display().to_string()];
    run_elevated(host, &args, &result_file)
}

/// Stop and remove the host service (keeps its accounts and certificate).
pub fn turn_off() -> Result<()> {
    let exe = host_exe()?;
    let scratch = Scratch::new()?;
    let result_file = scratch.0.join("result");
    let args = vec!["uninstall".into(), "--result-file".into(), result_file.display().to_string()];
    run_elevated(&exe, &args, &result_file)
}

fn read_result(result_file: &Path) -> Result<()> {
    match std::fs::read_to_string(result_file) {
        Ok(r) if r.trim() == "ok" => Ok(()),
        Ok(r) => Err(anyhow!("{}", r.trim().trim_start_matches("error:").trim())),
        Err(_) => Err(anyhow!("cancelled: administrator permission is needed to change remote access")),
    }
}

#[cfg(windows)]
pub(crate) fn run_elevated(exe: &Path, args: &[String], result_file: &Path) -> Result<()> {
    use anyhow::Context;
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    // Windows command-line quoting for each argument, then PowerShell single-quote escaping.
    let quoted: Vec<String> = args.iter().map(|a| format!("\"{}\"", a.replace('"', ""))).collect();
    let ps = format!(
        "$p = Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs -Wait -PassThru -WindowStyle Hidden; exit $p.ExitCode",
        exe.display().to_string().replace('\'', "''"),
        quoted.join(" ").replace('\'', "''"),
    );
    let utf16: Vec<u8> = ps.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let status = Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &base64(&utf16)])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .context("run PowerShell")?;
    let _ = status;
    read_result(result_file)
}

#[cfg(not(windows))]
pub(crate) fn run_elevated(exe: &Path, args: &[String], result_file: &Path) -> Result<()> {
    let out = match Command::new("pkexec").arg(exe).args(args).output() {
        Ok(o) => o,
        Err(_) => bail!("pkexec isn't available; run `sudo {} {}` in a terminal instead", exe.display(), args.join(" ")),
    };
    // 126: the password dialog was dismissed; 127: not authorized.
    if matches!(out.status.code(), Some(126) | Some(127)) && !result_file.exists() {
        bail!("cancelled: administrator permission is needed to change remote access");
    }
    read_result(result_file)
}

#[cfg(windows)]
fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation() {
        let req = || SetupRequest {
            name: "Office PC".into(),
            pin: "4821".into(),
            internet: true,
            ddns: None,
            ddns_off: false,
            wake_on_lan: true,
            ask_to_allow: false,
        };
        assert!(validate(&req()).is_ok());
        assert!(validate(&SetupRequest { pin: "123".into(), ..req() }).is_err());
        assert!(validate(&SetupRequest { name: "a\"b".into(), ..req() }).is_err());
        assert_eq!(duckdns_subdomain(" MyHome.duckdns.org ").unwrap(), "myhome");
        assert!(duckdns_subdomain("my home").is_err());
        let (host, url) = duckdns("myhome", "a7c4d9e2-1111-2222-3333-444455556666").unwrap();
        assert_eq!(host, "myhome.duckdns.org");
        assert!(url.starts_with("https://www.duckdns.org/update?domains=myhome&token=a7c4") && url.ends_with("&ip={ip}"));
        assert!(duckdns("myhome", "short").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn base64_matches_reference() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
    }
}
