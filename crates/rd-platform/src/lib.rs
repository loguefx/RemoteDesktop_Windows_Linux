//! Platform backends: screen capture + input injection.
//!
//! | OS      | Display protocol | Capture                                  | Input                         |
//! |---------|------------------|------------------------------------------|-------------------------------|
//! | Windows | –                | DXGI Desktop Duplication (GDI fallback)  | `SendInput` (scan codes)      |
//! | Linux   | X11              | MIT-SHM `GetImage` (plain `GetImage` fb) | XTest `FakeInput`             |
//! | Linux   | Wayland          | xdg-desktop-portal ScreenCast → PipeWire | xdg-desktop-portal RemoteDesktop |
//!
//! [`open`] returns a capturer and an injector that share one desktop session (on
//! Wayland both come from the same portal session, so they must be created together).

use std::collections::HashSet;
use std::time::Duration;

use anyhow::Result;
pub use rd_core::codec::Frame;
pub use rd_core::proto::{CursorShape, DisplayInfo};
use rd_core::proto::{InputEvent, MouseButton};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(windows)]
mod windows;

pub trait Capturer: Send {
    /// Wait up to `timeout` for a new frame. `Ok(None)` means "nothing new".
    fn capture(&mut self, timeout: Duration) -> Result<Option<&Frame>>;

    /// Monitors that can be captured.
    fn displays(&self) -> Vec<DisplayInfo>;

    /// Index (into [`Capturer::displays`]) of the monitor being captured.
    fn current_display(&self) -> u32;

    /// Switch to another monitor. Input injection follows automatically.
    fn select_display(&mut self, index: u32) -> Result<()>;

    /// The pointer's look, if it changed since the last call. Called from the capture
    /// thread before every capture.
    fn cursor(&mut self) -> Option<CursorShape> {
        None
    }

    /// Change the captured display's resolution to the largest mode that fits in
    /// `size`, or put the original back with `None`. Returns the size now in use.
    fn set_resolution(&mut self, _size: Option<(u32, u32)>) -> Result<(u32, u32)> {
        anyhow::bail!("this desktop can't change its resolution remotely")
    }
}

pub trait InputInjector: Send {
    fn inject(&mut self, ev: &InputEvent) -> Result<()>;

    /// Ignore the computer's own keyboard and mouse (privacy screen); injected input
    /// still works. Undone by `false` and when the injector is dropped.
    fn block_local_input(&mut self, _on: bool) -> Result<()> {
        anyhow::bail!("this desktop can't block its own keyboard and mouse")
    }
}

/// Keeps the monitor dark (or covered) while it exists; the captured picture is unaffected.
pub trait PrivacyScreen: Send {}

/// Darken the monitor of the desktop being captured (privacy screen). On Windows a
/// black window that screen capture leaves out; on X11 the monitor is switched off.
pub fn privacy_screen(backend: Backend) -> Result<Box<dyn PrivacyScreen>> {
    let backend = if backend == Backend::Auto { detect()? } else { backend };
    match backend {
        #[cfg(windows)]
        Backend::Windows => windows::privacy_screen(),
        #[cfg(target_os = "linux")]
        Backend::X11 => linux::x11::privacy_screen(),
        Backend::Wayland => anyhow::bail!("Wayland desktops don't allow blanking the screen remotely"),
        other => anyhow::bail!("backend {other} is not available on this OS"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Pick based on the OS / session environment.
    Auto,
    Windows,
    X11,
    Wayland,
}

impl std::str::FromStr for Backend {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "auto" => Ok(Backend::Auto),
            "windows" => Ok(Backend::Windows),
            "x11" => Ok(Backend::X11),
            "wayland" => Ok(Backend::Wayland),
            o => Err(format!("unknown backend '{o}' (auto, windows, x11, wayland)")),
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Backend::Auto => "auto",
            Backend::Windows => "windows",
            Backend::X11 => "x11",
            Backend::Wayland => "wayland",
        })
    }
}

/// Resolve `Auto` to a concrete backend for this machine / session.
pub fn detect() -> Result<Backend> {
    #[cfg(windows)]
    {
        Ok(Backend::Windows)
    }
    #[cfg(target_os = "linux")]
    {
        linux::detect()
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        anyhow::bail!("unsupported operating system")
    }
}

pub struct Session {
    pub backend: Backend,
    pub capturer: Box<dyn Capturer>,
    pub injector: Box<dyn InputInjector>,
}

/// Open a capture + input session on the current desktop.
pub fn open(backend: Backend) -> Result<Session> {
    let backend = if backend == Backend::Auto { detect()? } else { backend };
    log::info!("opening {backend} desktop backend");
    let (capturer, injector): (Box<dyn Capturer>, Box<dyn InputInjector>) = match backend {
        #[cfg(windows)]
        Backend::Windows => windows::open()?,
        #[cfg(target_os = "linux")]
        Backend::X11 => linux::x11::open()?,
        #[cfg(all(target_os = "linux", feature = "wayland"))]
        Backend::Wayland => linux::wayland::open()?,
        #[cfg(all(target_os = "linux", not(feature = "wayland")))]
        Backend::Wayland => anyhow::bail!("this build has no Wayland support (rebuild with --features wayland)"),
        other => anyhow::bail!("backend {other} is not available on this OS"),
    };
    Ok(Session { backend, capturer, injector: Box::new(Tracking::new(injector)) })
}

/// Wraps an injector and remembers what is held down, so `ReleaseAll` (sent when the
/// viewer loses focus or disconnects) never leaves a stuck Ctrl or mouse button.
struct Tracking {
    inner: Box<dyn InputInjector>,
    keys: HashSet<u16>,
    buttons: HashSet<ButtonKey>,
    /// Local input is blocked (privacy screen); undone on drop.
    blocked: bool,
}

#[derive(Hash, PartialEq, Eq, Clone, Copy)]
struct ButtonKey(u8);

fn button_key(b: MouseButton) -> ButtonKey {
    ButtonKey(b as u8)
}

fn button_from_key(k: ButtonKey) -> MouseButton {
    match k.0 {
        0 => MouseButton::Left,
        1 => MouseButton::Right,
        2 => MouseButton::Middle,
        3 => MouseButton::Back,
        _ => MouseButton::Forward,
    }
}

impl Tracking {
    fn new(inner: Box<dyn InputInjector>) -> Self {
        Self { inner, keys: HashSet::new(), buttons: HashSet::new(), blocked: false }
    }
}

impl InputInjector for Tracking {
    fn block_local_input(&mut self, on: bool) -> Result<()> {
        self.inner.block_local_input(on)?;
        self.blocked = on;
        Ok(())
    }

    fn inject(&mut self, ev: &InputEvent) -> Result<()> {
        match ev {
            InputEvent::Key { code, down } => {
                if *down {
                    self.keys.insert(*code);
                } else {
                    self.keys.remove(code);
                }
            }
            InputEvent::MouseButton { button, down } => {
                if *down {
                    self.buttons.insert(button_key(*button));
                } else {
                    self.buttons.remove(&button_key(*button));
                }
            }
            InputEvent::ReleaseAll => {
                for code in std::mem::take(&mut self.keys) {
                    self.inner.inject(&InputEvent::Key { code, down: false })?;
                }
                for b in std::mem::take(&mut self.buttons) {
                    self.inner.inject(&InputEvent::MouseButton { button: button_from_key(b), down: false })?;
                }
                return Ok(());
            }
            _ => {}
        }
        self.inner.inject(ev)
    }
}

impl Drop for Tracking {
    fn drop(&mut self) {
        let _ = self.inject(&InputEvent::ReleaseAll);
        if self.blocked {
            let _ = self.inner.block_local_input(false);
        }
    }
}

/// Converts 1/120-notch wheel deltas into whole notches for backends that only
/// understand discrete scroll steps (X11 buttons 4–7, portal discrete axis).
#[derive(Default)]
#[allow(dead_code)]
pub(crate) struct WheelAccumulator {
    x: i32,
    y: i32,
}

#[allow(dead_code)]
impl WheelAccumulator {
    /// Returns whole notches (dx, dy) to emit now.
    pub fn push(&mut self, dx: i32, dy: i32) -> (i32, i32) {
        self.x += dx;
        self.y += dy;
        let (nx, ny) = (self.x / 120, self.y / 120);
        self.x -= nx * 120;
        self.y -= ny * 120;
        (nx, ny)
    }
}
