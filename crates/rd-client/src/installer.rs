//! The one-file installer, and the uninstaller.
//!
//! `RD-Remote-Desktop-Setup.exe` (Windows) / `RD-Remote-Desktop-Setup` (Linux) is this
//! program with rd-host appended, LZ4-compressed, made by `rd-client make-installer`:
//!
//! ```text
//! [rd-client][lz4(rd-host)][rd-client length: u64 LE][payload length: u64 LE]["RDSETUP1"]
//! ```
//!
//! Started without arguments it shows the installer window instead of the app. Install
//! writes both programs to a private temporary folder and runs `rd-host install-app`
//! there with administrator rights (UAC / polkit): that copies them to Program Files or
//! /usr/local/bin, adds the Start menu / application menu entry (and on Windows the
//! Installed apps entry), and updates the service if remote access is already on.
//! Remote access itself is turned on from the app ("Set up remote access").
//!
//! `rd-client uninstall` (what Installed apps and the menu entry's *Uninstall* run) shows
//! the uninstaller, which runs `rd-host uninstall --app` the same way.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context, Result};
use egui::{Color32, RichText};

use crate::setup;

const MAGIC: &[u8; 8] = b"RDSETUP1";
const FOOTER: u64 = 24;

/// Where the payload sits in this program's file.
#[derive(Clone, Copy)]
pub struct Embedded {
    stub_len: u64,
    payload_len: u64,
}

fn parse_footer(file_len: u64, footer: &[u8; 24]) -> Option<Embedded> {
    if &footer[16..] != MAGIC {
        return None;
    }
    let stub_len = u64::from_le_bytes(footer[0..8].try_into().ok()?);
    let payload_len = u64::from_le_bytes(footer[8..16].try_into().ok()?);
    (stub_len.checked_add(payload_len)?.checked_add(FOOTER)? == file_len).then_some(Embedded { stub_len, payload_len })
}

/// The installer payload, when this program is the installer.
pub fn embedded() -> Option<Embedded> {
    embedded_in(&std::env::current_exe().ok()?)
}

fn embedded_in(path: &Path) -> Option<Embedded> {
    let mut f = File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if len < FOOTER {
        return None;
    }
    f.seek(SeekFrom::Start(len - FOOTER)).ok()?;
    let mut footer = [0u8; 24];
    f.read_exact(&mut footer).ok()?;
    parse_footer(len, &footer)
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_string()
    }
}

fn write_exe(path: &Path, data: &[u8]) -> Result<()> {
    std::fs::write(path, data).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// Build an installer at `out` from this program and the rd-host at `host`.
pub fn make(host: &Path, out: &Path) -> Result<()> {
    make_from(&std::env::current_exe()?, host, out)
}

fn make_from(app: &Path, host: &Path, out: &Path) -> Result<()> {
    let mut data = std::fs::read(app)?;
    if let Some(e) = embedded_in(app) {
        data.truncate(e.stub_len as usize);
    }
    let host = std::fs::read(host).with_context(|| format!("read {}", host.display()))?;
    let payload = lz4_flex::compress_prepend_size(&host);
    let stub_len = data.len() as u64;
    data.extend_from_slice(&payload);
    data.extend_from_slice(&stub_len.to_le_bytes());
    data.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    data.extend_from_slice(MAGIC);
    write_exe(out, &data)?;
    println!("{} ({} MB)", out.display(), data.len() / 1_000_000);
    Ok(())
}

/// Write the app (without the payload) and rd-host into `dir`.
fn extract(e: Embedded, dir: &Path) -> Result<()> {
    extract_from(&std::env::current_exe()?, e, dir)
}

fn extract_from(installer: &Path, e: Embedded, dir: &Path) -> Result<()> {
    let mut f = File::open(installer)?;
    let mut stub = vec![0u8; e.stub_len as usize];
    f.read_exact(&mut stub)?;
    let mut payload = vec![0u8; e.payload_len as usize];
    f.read_exact(&mut payload)?;
    let host = lz4_flex::decompress_size_prepended(&payload).map_err(|_| anyhow!("this installer is damaged; download it again"))?;
    write_exe(&dir.join(exe_name("rd-client")), &stub)?;
    write_exe(&dir.join(exe_name("rd-host")), &host)?;
    Ok(())
}

fn install_dir() -> PathBuf {
    if cfg!(windows) {
        std::env::var_os("ProgramFiles").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Program Files")).join("RDHost")
    } else {
        PathBuf::from("/usr/local/bin")
    }
}

pub fn installed_app() -> PathBuf {
    install_dir().join(exe_name("rd-client"))
}

fn installed_host() -> PathBuf {
    install_dir().join(exe_name("rd-host"))
}

fn run_host(host: &Path, mut args: Vec<String>, scratch: &setup::Scratch) -> Result<()> {
    let result = scratch.0.join("result");
    args.push("--result-file".into());
    args.push(result.display().to_string());
    setup::run_elevated(host, &args, &result)
}

fn install(e: Embedded, desktop: bool) -> Result<()> {
    let scratch = setup::Scratch::new()?;
    extract(e, &scratch.0)?;
    run_host(&scratch.0.join(exe_name("rd-host")), vec!["install-app".into()], &scratch)?;
    if desktop {
        if let Err(err) = desktop_shortcut(true) {
            log::warn!("desktop shortcut: {err:#}");
        }
    }
    Ok(())
}

fn uninstall(purge: bool) -> Result<()> {
    let host = installed_host();
    if !host.exists() {
        bail!("RD Remote Desktop isn't installed on this computer ({} is missing)", host.display());
    }
    // Run a copy, so the installed one can be deleted.
    let scratch = setup::Scratch::new()?;
    let copy = scratch.0.join(exe_name("rd-host"));
    std::fs::copy(&host, &copy).with_context(|| format!("copy {}", host.display()))?;
    let mut args = vec!["uninstall".to_string(), "--app".into()];
    if purge {
        args.push("--purge".into());
    }
    let r = run_host(&copy, args, &scratch);
    let _ = desktop_shortcut(false);
    r
}

/// Windows: the uninstaller can't delete the folder it runs from, so `rd-client uninstall`
/// started there (from Installed apps) starts a temporary copy and exits. True if it did.
pub fn relaunch_outside_install_dir() -> Result<bool> {
    if !cfg!(windows) {
        return Ok(false);
    }
    let me = std::env::current_exe()?;
    let here = me.parent().map(|p| p.display().to_string().to_lowercase());
    if here != Some(install_dir().display().to_string().to_lowercase()) {
        return Ok(false);
    }
    let tmp = std::env::temp_dir().join(format!("rd-uninstall-{}.exe", std::process::id()));
    std::fs::copy(&me, &tmp)?;
    std::process::Command::new(&tmp).arg("uninstall").spawn().context("start the uninstaller")?;
    Ok(true)
}

// ------------------------------------------------------------------ desktop shortcut

#[cfg(windows)]
fn desktop_shortcut(add: bool) -> Result<()> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let q = |p: &Path| p.display().to_string().replace('\'', "''");
    let link = "(Join-Path ([Environment]::GetFolderPath('Desktop')) 'RD Remote Desktop.lnk')";
    let ps = if add {
        format!(
            "$s = (New-Object -ComObject WScript.Shell).CreateShortcut({link}); $s.TargetPath = '{}'; $s.WorkingDirectory = '{}'; $s.Description = 'Connect to your computers'; $s.Save()",
            q(&installed_app()),
            q(&install_dir()),
        )
    } else {
        format!("Remove-Item -LiteralPath {link} -ErrorAction SilentlyContinue")
    };
    let ok = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok && add {
        bail!("couldn't add the desktop shortcut");
    }
    Ok(())
}

#[cfg(not(windows))]
fn desktop_shortcut(add: bool) -> Result<()> {
    let dir = std::process::Command::new("xdg-user-dir")
        .arg("DESKTOP")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|d| !d.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Desktop")))
        .ok_or_else(|| anyhow!("no desktop folder"))?;
    let file = dir.join("rd-remote-desktop.desktop");
    if !add {
        let _ = std::fs::remove_file(&file);
        return Ok(());
    }
    if !dir.is_dir() {
        bail!("no desktop folder");
    }
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=RD Remote Desktop\nComment=Connect to your computers\nExec={}\nIcon=preferences-desktop-remote-desktop\nTerminal=false\n",
        installed_app().display()
    );
    write_exe(&file, entry.as_bytes())?;
    // GNOME runs desktop launchers only once they're marked trusted.
    let _ = std::process::Command::new("gio").arg("set").arg(&file).args(["metadata::trusted", "true"]).output();
    Ok(())
}

// ------------------------------------------------------------------ window

#[derive(Clone)]
enum State {
    Ready,
    Working,
    Done,
    Failed(String),
}

pub struct Installer {
    /// Some: install from this payload; None: uninstall.
    payload: Option<Embedded>,
    already: bool,
    desktop: bool,
    purge: bool,
    state: Arc<Mutex<State>>,
}

impl Installer {
    pub fn install(payload: Embedded) -> Installer {
        Installer { payload: Some(payload), already: installed_app().exists(), desktop: true, purge: false, state: Arc::new(Mutex::new(State::Ready)) }
    }

    pub fn uninstall() -> Installer {
        Installer { payload: None, already: true, desktop: false, purge: false, state: Arc::new(Mutex::new(State::Ready)) }
    }

    pub fn title(&self) -> String {
        if self.payload.is_some() {
            "RD Remote Desktop Setup".into()
        } else {
            "Uninstall RD Remote Desktop".into()
        }
    }

    fn start(&self, ctx: &egui::Context) {
        *self.state.lock().unwrap() = State::Working;
        let (state, ctx) = (self.state.clone(), ctx.clone());
        let (payload, desktop, purge) = (self.payload, self.desktop, self.purge);
        std::thread::spawn(move || {
            let r = match payload {
                Some(p) => install(p, desktop),
                None => uninstall(purge),
            };
            *state.lock().unwrap() = match r {
                Ok(()) => State::Done,
                Err(e) => State::Failed(format!("{e:#}")),
            };
            ctx.request_repaint();
        });
    }

    pub fn ui(&mut self, ctx: &egui::Context) {
        let state = self.state.lock().unwrap().clone();
        let installing = self.payload.is_some();
        let menu = if cfg!(windows) { "Start menu" } else { "application menu" };
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(10.0);
            ui.label(RichText::new("RD Remote Desktop").strong().size(22.0));
            ui.add_space(10.0);
            match state {
                State::Ready if installing => {
                    ui.label("Connect to your other computers, and let them connect to this one.");
                    ui.add_space(6.0);
                    if self.already {
                        ui.label("It's already installed here. This replaces it with this version and keeps your settings, accounts and saved computers.");
                    } else {
                        ui.label(format!("It's installed for everyone on this computer, in {}, and added to the {menu}.", install_dir().display()));
                    }
                    ui.add_space(8.0);
                    ui.checkbox(&mut self.desktop, "Add a shortcut on the desktop");
                    ui.add_space(12.0);
                    let b = egui::Button::new(RichText::new(if self.already { "Update" } else { "Install" }).color(Color32::WHITE).size(16.0))
                        .fill(crate::theme::ACCENT)
                        .min_size(egui::vec2(120.0, 32.0));
                    if ui.add(b).clicked() {
                        self.start(ctx);
                    }
                    ui.add_space(6.0);
                    ui.label(RichText::new("You'll be asked for administrator permission.").color(Color32::GRAY));
                }
                State::Ready => {
                    ui.label("Remove RD Remote Desktop from this computer?");
                    ui.add_space(6.0);
                    ui.label("Remote access to this computer is turned off and the app is removed.");
                    ui.add_space(8.0);
                    ui.checkbox(&mut self.purge, "Also delete its accounts, PINs and certificate");
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        let b = egui::Button::new(RichText::new("Remove").color(Color32::WHITE).size(16.0))
                            .fill(crate::theme::DANGER)
                            .min_size(egui::vec2(110.0, 32.0));
                        if ui.add(b).clicked() {
                            self.start(ctx);
                        }
                        if ui.add(egui::Button::new(RichText::new("Cancel").size(16.0)).min_size(egui::vec2(90.0, 32.0))).clicked() {
                            std::process::exit(0);
                        }
                    });
                }
                State::Working => {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label(if installing { "Installing..." } else { "Removing..." });
                    });
                    ui.label(RichText::new("Approve the administrator prompt if one is waiting.").color(Color32::GRAY));
                }
                State::Done if installing => {
                    ui.label(RichText::new(if self.already { "Updated." } else { "Installed." }).strong().size(16.0));
                    ui.add_space(6.0);
                    ui.label(format!("RD Remote Desktop is in the {menu}."));
                    ui.label("To reach this computer from your others, choose Set up remote access in the app.");
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        let b = egui::Button::new(RichText::new("Open RD Remote Desktop").color(Color32::WHITE).size(16.0))
                            .fill(crate::theme::ACCENT)
                            .min_size(egui::vec2(180.0, 32.0));
                        if ui.add(b).clicked() {
                            let _ = std::process::Command::new(installed_app()).current_dir(install_dir()).spawn();
                            std::process::exit(0);
                        }
                        if ui.add(egui::Button::new(RichText::new("Close").size(16.0)).min_size(egui::vec2(90.0, 32.0))).clicked() {
                            std::process::exit(0);
                        }
                    });
                }
                State::Done => {
                    ui.label(RichText::new("RD Remote Desktop was removed.").strong().size(16.0));
                    ui.add_space(12.0);
                    if ui.add(egui::Button::new(RichText::new("Close").size(16.0)).min_size(egui::vec2(90.0, 32.0))).clicked() {
                        std::process::exit(0);
                    }
                }
                State::Failed(e) => {
                    ui.label(RichText::new(if installing { "It wasn't installed." } else { "It wasn't removed." }).strong().size(16.0));
                    ui.add_space(4.0);
                    ui.label(RichText::new(e).color(crate::theme::DANGER));
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui.add(egui::Button::new(RichText::new("Try again").size(16.0)).min_size(egui::vec2(100.0, 32.0))).clicked() {
                            *self.state.lock().unwrap() = State::Ready;
                        }
                        if ui.add(egui::Button::new(RichText::new("Close").size(16.0)).min_size(egui::vec2(90.0, 32.0))).clicked() {
                            std::process::exit(0);
                        }
                    });
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn footer_round_trip() {
        let mut f = [0u8; 24];
        f[0..8].copy_from_slice(&100u64.to_le_bytes());
        f[8..16].copy_from_slice(&50u64.to_le_bytes());
        f[16..].copy_from_slice(MAGIC);
        let e = parse_footer(174, &f).unwrap();
        assert_eq!((e.stub_len, e.payload_len), (100, 50));
        assert!(parse_footer(175, &f).is_none(), "length must match exactly");
        f[16] = b'X';
        assert!(parse_footer(174, &f).is_none());
    }

    #[test]
    fn make_and_extract() {
        let dir = std::env::temp_dir().join(format!("rd-installer-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("out")).unwrap();
        let app: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
        let host: Vec<u8> = (0..500_000u32).map(|i| (i * 7 % 253) as u8).collect();
        std::fs::write(dir.join("app"), &app).unwrap();
        std::fs::write(dir.join("host"), &host).unwrap();
        assert!(embedded_in(&dir.join("app")).is_none());
        make_from(&dir.join("app"), &dir.join("host"), &dir.join("setup")).unwrap();
        // Making one from an installer keeps a single payload.
        make_from(&dir.join("setup"), &dir.join("host"), &dir.join("setup2")).unwrap();
        assert_eq!(std::fs::read(dir.join("setup")).unwrap(), std::fs::read(dir.join("setup2")).unwrap());
        let e = embedded_in(&dir.join("setup")).unwrap();
        extract_from(&dir.join("setup"), e, &dir.join("out")).unwrap();
        assert_eq!(std::fs::read(dir.join("out").join(exe_name("rd-client"))).unwrap(), app);
        assert_eq!(std::fs::read(dir.join("out").join(exe_name("rd-host"))).unwrap(), host);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
