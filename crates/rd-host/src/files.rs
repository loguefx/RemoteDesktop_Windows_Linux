//! File transfer, run by the agent inside the desktop session.
//!
//! * Browsing / downloads read files as the desktop user.
//! * Uploads land in that user's Downloads folder, never overwriting an existing file.
//! * On a Windows service install the agent is SYSTEM, so every operation impersonates
//!   the signed-in console user (`WTSQueryUserToken` + `ImpersonateLoggedOnUser`); with
//!   nobody signed in, file transfer is refused rather than running as SYSTEM.
//! * Downloads are flow-controlled: at most `FILE_WINDOW` chunks in flight, each
//!   acknowledged by the viewer, so a slow viewer never stalls the shared session.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError};

use anyhow::{bail, Context, Result};
use rd_core::proto::{AgentEvent, FileEntry, FileReply, FileRequest, FILE_CHUNK, FILE_WINDOW};

use crate::agent::EventTx;

type Key = (u32, u32); // (client, req)

struct Download {
    file: File,
    credits: usize,
}

struct Upload {
    file: File,
    path: PathBuf,
    expected: u64,
    written: u64,
}

pub fn spawn(rx: Receiver<(u32, FileRequest)>, tx: EventTx, impersonate: bool) {
    let _ = std::thread::Builder::new().name("files".into()).spawn(move || {
        let mut w = Worker { tx, impersonate, downloads: HashMap::new(), uploads: HashMap::new() };
        loop {
            // Block only when no download has credit left to spend.
            let msg = if w.downloads.values().any(|d| d.credits > 0) {
                match rx.try_recv() {
                    Ok(m) => Some(m),
                    Err(TryRecvError::Empty) => None,
                    Err(TryRecvError::Disconnected) => break,
                }
            } else {
                match rx.recv() {
                    Ok(m) => Some(m),
                    Err(_) => break,
                }
            };
            if let Some((client, req)) = msg {
                w.handle(client, req);
            }
            if !w.pump() {
                break;
            }
        }
    });
}

struct Worker {
    tx: EventTx,
    impersonate: bool,
    downloads: HashMap<Key, Download>,
    uploads: HashMap<Key, Upload>,
}

impl Worker {
    fn send(&self, client: u32, reply: FileReply) -> bool {
        self.tx.send(AgentEvent::Files { client, reply }).is_ok()
    }

    fn handle(&mut self, client: u32, req: FileRequest) {
        let id = req_id(&req);
        let result = user::as_desktop_user(self.impersonate, || self.handle_inner(client, req));
        if let Err(e) = result {
            self.downloads.remove(&(client, id));
            self.uploads.remove(&(client, id));
            self.send(client, FileReply::Error { req: id, message: format!("{e:#}") });
        }
    }

    fn handle_inner(&mut self, client: u32, req: FileRequest) -> Result<()> {
        match req {
            FileRequest::ListDir { req, path } => {
                let dir = if path.trim().is_empty() { user::home_dir()? } else { PathBuf::from(path) };
                let dir = dir.canonicalize().with_context(|| format!("open {}", dir.display()))?;
                let mut entries = Vec::new();
                for e in std::fs::read_dir(&dir).with_context(|| format!("list {}", dir.display()))? {
                    let Ok(e) = e else { continue };
                    let Ok(meta) = e.metadata() else { continue };
                    let modified = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    entries.push(FileEntry {
                        name: e.file_name().to_string_lossy().into_owned(),
                        is_dir: meta.is_dir(),
                        size: if meta.is_dir() { 0 } else { meta.len() },
                        modified,
                    });
                }
                entries.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
                self.send(
                    client,
                    FileReply::Dir {
                        req,
                        path: display_path(&dir),
                        parent: dir.parent().map(display_path),
                        entries,
                    },
                );
            }
            FileRequest::Download { req, path } => {
                let path = PathBuf::from(path);
                let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
                let meta = file.metadata()?;
                if meta.is_dir() {
                    bail!("{} is a folder", path.display());
                }
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                self.send(client, FileReply::DownloadStart { req, name, size: meta.len() });
                self.downloads.insert((client, req), Download { file, credits: FILE_WINDOW });
            }
            FileRequest::Ack { req } => {
                if let Some(d) = self.downloads.get_mut(&(client, req)) {
                    d.credits += 1;
                }
            }
            FileRequest::UploadStart { req, name, size } => {
                let dir = user::downloads_dir()?;
                std::fs::create_dir_all(&dir).ok();
                let path = unique_path(&dir, &sanitize(&name));
                let file = File::create_new(&path).with_context(|| format!("create {}", path.display()))?;
                self.uploads.insert((client, req), Upload { file, path, expected: size, written: 0 });
            }
            FileRequest::UploadChunk { req, data } => {
                let up = self.uploads.get_mut(&(client, req)).context("unknown upload")?;
                up.written += data.len() as u64;
                if up.written > up.expected {
                    bail!("upload larger than announced");
                }
                up.file.write_all(&data)?;
            }
            FileRequest::UploadEnd { req } => {
                let mut up = self.uploads.remove(&(client, req)).context("unknown upload")?;
                up.file.flush()?;
                if up.written != up.expected {
                    let _ = std::fs::remove_file(&up.path);
                    bail!("upload incomplete ({} of {} bytes)", up.written, up.expected);
                }
                log::info!("received upload {}", up.path.display());
                self.send(client, FileReply::UploadDone { req, saved_as: display_path(&up.path) });
            }
            FileRequest::Cancel { req } => {
                self.downloads.remove(&(client, req));
                if let Some(up) = self.uploads.remove(&(client, req)) {
                    drop(up.file);
                    let _ = std::fs::remove_file(&up.path);
                }
            }
        }
        Ok(())
    }

    /// Send one chunk for every download that has credit. Returns false on shutdown.
    fn pump(&mut self) -> bool {
        let keys: Vec<Key> = self.downloads.iter().filter(|(_, d)| d.credits > 0).map(|(k, _)| *k).collect();
        for (client, req) in keys {
            let d = self.downloads.get_mut(&(client, req)).unwrap();
            let mut buf = vec![0u8; FILE_CHUNK];
            let reply = match d.file.read(&mut buf) {
                Ok(0) => {
                    self.downloads.remove(&(client, req));
                    FileReply::DownloadEnd { req }
                }
                Ok(n) => {
                    d.credits -= 1;
                    buf.truncate(n);
                    FileReply::Chunk { req, data: buf }
                }
                Err(e) => {
                    self.downloads.remove(&(client, req));
                    FileReply::Error { req, message: format!("read failed: {e}") }
                }
            };
            if !self.send(client, reply) {
                return false;
            }
        }
        true
    }
}

fn req_id(r: &FileRequest) -> u32 {
    match r {
        FileRequest::ListDir { req, .. }
        | FileRequest::Download { req, .. }
        | FileRequest::Ack { req }
        | FileRequest::UploadStart { req, .. }
        | FileRequest::UploadChunk { req, .. }
        | FileRequest::UploadEnd { req }
        | FileRequest::Cancel { req } => *req,
    }
}

fn display_path(p: &Path) -> String {
    let s = p.to_string_lossy().into_owned();
    // Windows canonicalize() yields \\?\C:\...; show the familiar form.
    s.strip_prefix(r"\\?\").map(str::to_string).unwrap_or(s)
}

/// Keep only a plain file name: no directories, no reserved characters.
pub fn sanitize(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .map(|c| if c.is_control() || "<>:\"|?*".contains(c) { '_' } else { c })
        .collect();
    let cleaned = cleaned.trim().trim_matches('.').to_string();
    if cleaned.is_empty() {
        "upload.bin".into()
    } else {
        cleaned
    }
}

fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let p = dir.join(name);
    if !p.exists() {
        return p;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    (1..)
        .map(|i| dir.join(format!("{stem} ({i}){ext}")))
        .find(|p| !p.exists())
        .unwrap()
}

// ------------------------------------------------------------------ desktop user

#[cfg(windows)]
mod user {
    use std::path::PathBuf;

    use anyhow::{Context, Result};
    use windows::core::GUID;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::System::RemoteDesktop::{WTSGetActiveConsoleSessionId, WTSQueryUserToken};
    use windows::Win32::UI::Shell::{FOLDERID_Downloads, FOLDERID_Profile, SHGetKnownFolderPath, KF_FLAG_DEFAULT};

    thread_local! {
        static TOKEN: std::cell::Cell<HANDLE> = const { std::cell::Cell::new(HANDLE(std::ptr::null_mut())) };
    }

    /// Run `f` as the signed-in console user (when `impersonate`), else as ourselves.
    pub fn as_desktop_user<T>(impersonate: bool, f: impl FnOnce() -> Result<T>) -> Result<T> {
        if !impersonate {
            return f();
        }
        unsafe {
            let mut token = HANDLE::default();
            WTSQueryUserToken(WTSGetActiveConsoleSessionId(), &mut token)
                .context("file transfer needs a user signed in on the remote computer")?;
            if let Err(e) = ImpersonateLoggedOnUser(token) {
                let _ = CloseHandle(token);
                return Err(e).context("impersonate desktop user");
            }
            TOKEN.with(|t| t.set(token));
            let r = f();
            let _ = RevertToSelf();
            TOKEN.with(|t| t.set(HANDLE::default()));
            let _ = CloseHandle(token);
            r
        }
    }

    fn known_folder(id: &GUID) -> Result<PathBuf> {
        unsafe {
            let token = TOKEN.with(|t| t.get());
            let p = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, token).context("SHGetKnownFolderPath")?;
            let s = p.to_string();
            CoTaskMemFree(Some(p.0 as *const _));
            Ok(PathBuf::from(s?))
        }
    }

    pub fn home_dir() -> Result<PathBuf> {
        known_folder(&FOLDERID_Profile)
    }

    pub fn downloads_dir() -> Result<PathBuf> {
        known_folder(&FOLDERID_Downloads)
    }
}

#[cfg(not(windows))]
mod user {
    use std::path::PathBuf;

    use anyhow::{Context, Result};

    /// The Linux agent already runs as the desktop user.
    pub fn as_desktop_user<T>(_impersonate: bool, f: impl FnOnce() -> Result<T>) -> Result<T> {
        f()
    }

    pub fn home_dir() -> Result<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from).context("HOME not set")
    }

    pub fn downloads_dir() -> Result<PathBuf> {
        // Honour ~/.config/user-dirs.dirs (localised folder names) when present.
        let home = home_dir()?;
        if let Ok(cfg) = std::fs::read_to_string(home.join(".config/user-dirs.dirs")) {
            for line in cfg.lines() {
                if let Some(v) = line.strip_prefix("XDG_DOWNLOAD_DIR=") {
                    let v = v.trim_matches('"').replace("$HOME", &home.to_string_lossy());
                    return Ok(PathBuf::from(v));
                }
            }
        }
        Ok(home.join("Downloads"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_strips_paths() {
        assert_eq!(sanitize("../../etc/passwd"), "passwd");
        assert_eq!(sanitize(r"C:\Windows\evil.exe"), "evil.exe");
        assert_eq!(sanitize("a<b>.txt"), "a_b_.txt");
        assert_eq!(sanitize(".."), "upload.bin");
    }

    #[test]
    fn unique_names() {
        let dir = std::env::temp_dir().join(format!("rd-files-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.txt"), b"x").unwrap();
        assert_eq!(unique_path(&dir, "a.txt"), dir.join("a (1).txt"));
        assert_eq!(unique_path(&dir, "b.txt"), dir.join("b.txt"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
