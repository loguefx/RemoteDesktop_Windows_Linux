//! One-click updates from GitHub releases.
//!
//! The newest release's download for this system is fetched, checked against the SHA-256
//! GitHub publishes for it, unpacked into a private temporary folder, and its `rd-host
//! install --update` is run with administrator rights. That replaces the service and the
//! app and keeps every setting, account and the certificate. Then the new app starts.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};

/// Where new versions are published.
pub const RELEASES_API: &str = "https://api.github.com/repos/loguefx/RemoteDesktop_Windows_Linux/releases/latest";

/// The download for this system in a release.
const ASSET: &str = if cfg!(windows) { "rd-remote-desktop-windows-x64.zip" } else { "rd-remote-desktop-linux-x86_64.tar.gz" };

/// Biggest download accepted.
const MAX_DOWNLOAD: usize = 200 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    /// The release page.
    pub page: String,
    /// Download for this system, and its SHA-256 (hex), when the release has one.
    pub asset: Option<(String, String)>,
}

/// `1.2.10` > `1.2.9`; non-numeric parts count as 0.
pub fn newer(candidate: &str, current: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> { v.trim_start_matches('v').split(['.', '-']).take(3).map(|p| p.parse().unwrap_or(0)).collect() };
    parse(candidate) > parse(current)
}

/// The latest release, if it's newer than this program.
pub async fn check() -> Result<Option<Release>> {
    let r = rd_core::http::get(RELEASES_API, &[("Accept", "application/vnd.github+json")]).await?;
    if r.status != 200 {
        return Ok(None); // no release yet, or the repository is private
    }
    let v: serde_json::Value = serde_json::from_str(&r.body)?;
    let (Some(tag), Some(page)) = (v["tag_name"].as_str(), v["html_url"].as_str()) else { return Ok(None) };
    if !newer(tag, env!("CARGO_PKG_VERSION")) || !page.starts_with("https://github.com/") {
        return Ok(None);
    }
    let asset = v["assets"].as_array().and_then(|list| {
        list.iter().find(|a| a["name"].as_str() == Some(ASSET)).and_then(|a| {
            let url = a["browser_download_url"].as_str()?;
            let digest = a["digest"].as_str()?.strip_prefix("sha256:")?;
            url.starts_with("https://github.com/").then(|| (url.to_string(), digest.to_ascii_lowercase()))
        })
    });
    Ok(Some(Release { version: tag.trim_start_matches('v').to_string(), page: page.to_string(), asset }))
}

/// Download, check, unpack and install `r`, then start the new app. Blocking; call it
/// off the UI thread. Returns a message for the user if it didn't exit the program.
pub fn install(rt: &tokio::runtime::Handle, r: &Release) -> Result<String> {
    let (url, sha) = r.asset.clone().ok_or_else(|| anyhow!("this release has no checked download for this system"))?;
    let data = rt.block_on(rd_core::http::download(&url, MAX_DOWNLOAD)).context("download the update")?;
    let got: String = Sha256::digest(&data).iter().map(|b| format!("{b:02x}")).collect();
    if got != sha {
        bail!("the download is damaged or was changed (checksum mismatch); nothing was installed");
    }
    let dir = private_dir()?;
    let archive = dir.join(ASSET);
    std::fs::write(&archive, &data)?;
    unpack(&archive, &dir)?;
    let host = find(&dir, if cfg!(windows) { "rd-host.exe" } else { "rd-host" })
        .ok_or_else(|| anyhow!("the download doesn't contain rd-host"))?;
    let app = host.with_file_name(if cfg!(windows) { "rd-client.exe" } else { "rd-client" });
    if !app.exists() {
        bail!("the download doesn't contain rd-client");
    }
    crate::setup::update_service(&host)?;
    // Start the new app from where the installer put it, then leave.
    let installed = if cfg!(windows) {
        PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_else(|| "C:\\Program Files".into())).join("RDHost").join("rd-client.exe")
    } else {
        PathBuf::from("/usr/local/bin/rd-client")
    };
    let _ = std::fs::remove_dir_all(&dir);
    if std::process::Command::new(&installed).spawn().is_ok() {
        std::process::exit(0);
    }
    Ok(format!("Updated to version {}. Restart the app to use it.", r.version))
}

fn private_dir() -> Result<PathBuf> {
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
    let dir = std::env::temp_dir().join(format!("rd-update-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

fn unpack(archive: &Path, into: &Path) -> Result<()> {
    let ok = if cfg!(windows) {
        let ps = format!(
            "Expand-Archive -LiteralPath '{}' -DestinationPath '{}' -Force",
            archive.display().to_string().replace('\'', "''"),
            into.display().to_string().replace('\'', "''")
        );
        std::process::Command::new("powershell.exe").args(["-NoProfile", "-NonInteractive", "-Command", &ps]).status()
    } else {
        std::process::Command::new("tar").arg("-xzf").arg(archive).arg("-C").arg(into).status()
    }
    .context("unpack the update")?
    .success();
    if !ok {
        bail!("couldn't unpack the update");
    }
    Ok(())
}

/// `name` in `dir` or one folder down.
fn find(dir: &Path, name: &str) -> Option<PathBuf> {
    let direct = dir.join(name);
    if direct.exists() {
        return Some(direct);
    }
    std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path().join(name)).find(|p| p.exists())
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_compare() {
        assert!(super::newer("v0.2.0", "0.1.0"));
        assert!(super::newer("0.1.10", "0.1.9"));
        assert!(!super::newer("v0.1.0", "0.1.0"));
        assert!(!super::newer("0.0.9", "0.1.0"));
    }
}
