//! Where the host keeps its state (database, TLS key, logs).
//!
//! * Windows service: `%ProgramData%\RDHost` (ACL'd to SYSTEM + Administrators at install)
//! * Linux service (root): `/var/lib/rd-host` (mode 0700)
//! * Non-root / dev runs on Linux: `$XDG_DATA_HOME/rd-host` or `~/.local/share/rd-host`
//!
//! Override with `--data-dir` or `RD_DATA_DIR`.

use std::path::PathBuf;

pub fn default_data_dir() -> PathBuf {
    if let Some(d) = std::env::var_os("RD_DATA_DIR") {
        return PathBuf::from(d);
    }
    #[cfg(windows)]
    {
        let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("RDHost")
    }
    #[cfg(unix)]
    {
        if unsafe { libc::geteuid() } == 0 {
            return PathBuf::from("/var/lib/rd-host");
        }
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
            .unwrap_or_else(|| PathBuf::from("."));
        base.join("rd-host")
    }
}

pub fn host_name() -> String {
    std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "rd-host".into())
}

#[cfg(unix)]
pub fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
