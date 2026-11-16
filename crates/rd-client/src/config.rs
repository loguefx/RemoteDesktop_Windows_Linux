//! Per-user client state: pinned host certificates and remembered sign-ins.
//!
//! Stored as JSON in `%APPDATA%\rd-client\hosts.json` (Windows) or
//! `$XDG_CONFIG_HOME/rd-client/hosts.json` (Linux, mode 0600). A device token grants
//! access to the host as that user, so treat this file like an SSH private key.

use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
pub struct Store {
    #[serde(default)]
    pub hosts: BTreeMap<String, HostEntry>,
    /// Picture mode: "h264" (default) or "tiles".
    #[serde(default)]
    pub video: Option<String>,
    /// Computers found on the network or connected to before, by certificate fingerprint.
    #[serde(default)]
    pub computers: BTreeMap<String, Computer>,
}

/// A computer in "My computers": how to find it and how to sign in.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Computer {
    pub name: String,
    /// `ip:port` on its local network (from discovery).
    #[serde(default)]
    pub lan: Option<String>,
    /// `ip:port` reachable from the internet (router port mapping).
    #[serde(default)]
    pub public: Option<String>,
    /// `ID@relay:port`, if the host uses a relay.
    #[serde(default)]
    pub relay: Option<String>,
    /// Pinned fingerprint, saved sign-ins.
    #[serde(default)]
    pub auth: HostEntry,
    /// Name given on this device ("Rename"); the computer's own name otherwise.
    #[serde(default)]
    pub alias: Option<String>,
    /// `windows` or `linux`, from its announce.
    #[serde(default)]
    pub os: Option<String>,
    /// Unix time of the last successful connection from this device.
    #[serde(default)]
    pub last_connected: Option<u64>,
    /// Network adapter addresses, for Wake-on-LAN.
    #[serde(default)]
    pub macs: Vec<[u8; 6]>,
    /// `name:port` of its dynamic DNS name, which follows its internet address.
    #[serde(default)]
    pub public_name: Option<String>,
}

impl Computer {
    /// What to call it in the list.
    pub fn label(&self) -> &str {
        self.alias.as_deref().filter(|a| !a.trim().is_empty()).unwrap_or(&self.name)
    }

    /// Refresh what the computer announced about itself.
    pub fn update_from(&mut self, a: &rd_core::discovery::Announce, lan: std::net::SocketAddr) {
        self.name = a.name.clone();
        self.lan = Some(lan.to_string());
        if a.public.is_some() {
            self.public = a.public.clone();
        }
        if a.public_name.is_some() {
            self.public_name = a.public_name.clone();
        }
        if a.relay.is_some() {
            self.relay = a.relay.clone();
        }
        if !a.os.is_empty() {
            self.os = Some(a.os.clone());
        }
        if !a.macs.is_empty() {
            self.macs = a.macs.clone();
        }
    }
}

impl Store {
    pub fn video_codec(&self) -> rd_core::proto::VideoCodec {
        match self.video.as_deref() {
            Some("tiles") => rd_core::proto::VideoCodec::Tiles,
            _ => rd_core::proto::VideoCodec::H264 { max_kbps: 0 },
        }
    }

    pub fn set_video_codec(&mut self, c: rd_core::proto::VideoCodec) {
        self.video = Some(match c {
            rd_core::proto::VideoCodec::Tiles => "tiles".into(),
            rd_core::proto::VideoCodec::H264 { .. } => "h264".into(),
        });
    }
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    /// Pinned SHA-256 certificate fingerprint (trust on first use).
    pub fingerprint: Option<String>,
    /// Last user who signed in here (the default next time).
    pub username: Option<String>,
    /// "Remember this device" tokens for automatic sign-in, per (lower-cased) username.
    #[serde(default)]
    pub tokens: BTreeMap<String, String>,
}

impl HostEntry {
    pub fn token(&self, user: &str) -> Option<&String> {
        self.tokens.get(&user.to_lowercase())
    }
    pub fn set_token(&mut self, user: &str, token: Option<String>) {
        match token {
            Some(t) => self.tokens.insert(user.to_lowercase(), t),
            None => self.tokens.remove(&user.to_lowercase()),
        };
    }
}

fn path() -> PathBuf {
    let base = if cfg!(windows) {
        std::env::var_os("APPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    };
    base.unwrap_or_else(|| PathBuf::from(".")).join("rd-client").join("hosts.json")
}

impl Store {
    pub fn load() -> Store {
        std::fs::read(path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        let p = path();
        std::fs::create_dir_all(p.parent().unwrap())?;
        let tmp = p.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(self)?).context("write client config")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &p)?;
        Ok(())
    }

    pub fn location() -> PathBuf {
        path()
    }
}
