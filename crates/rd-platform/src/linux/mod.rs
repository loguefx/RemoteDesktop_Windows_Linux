//! Linux backends. The display protocol is chosen per session:
//!
//! * **X11**: talk to the X server directly (MIT-SHM capture, XTest input). Works for
//!   any X session, including the login greeter on X11 display managers.
//! * **Wayland**: compositors don't let clients read the screen or inject input, so we
//!   go through `xdg-desktop-portal` (RemoteDesktop + ScreenCast). Frames arrive over
//!   PipeWire; input goes back over D-Bus. Works on GNOME, KDE Plasma, and wlroots
//!   compositors with a portal backend that implements RemoteDesktop.

use anyhow::{bail, Result};

use crate::Backend;

pub mod x11;
#[cfg(feature = "wayland")]
pub mod wayland;

pub fn detect() -> Result<Backend> {
    let session_type = std::env::var("XDG_SESSION_TYPE").unwrap_or_default();
    let wayland = session_type == "wayland" || std::env::var_os("WAYLAND_DISPLAY").is_some();
    let x11 = std::env::var_os("DISPLAY").is_some();
    if wayland {
        if cfg!(feature = "wayland") {
            return Ok(Backend::Wayland);
        }
        if x11 {
            log::warn!(
                "Wayland session but this build lacks Wayland support; falling back to XWayland \
                 (only X11 windows will be visible and input will not reach Wayland apps)"
            );
            return Ok(Backend::X11);
        }
        bail!("Wayland session but this build lacks Wayland support");
    }
    if x11 {
        return Ok(Backend::X11);
    }
    bail!("no graphical session found (neither WAYLAND_DISPLAY nor DISPLAY is set)")
}
