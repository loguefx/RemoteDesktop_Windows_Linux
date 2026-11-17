//! "Send system shortcuts": keys the local system would act on itself (the Windows /
//! Super key, Alt+Tab, Alt+F4, Ctrl+Esc...) go to the remote computer instead while the
//! session window is in front.
//!
//! * Windows: a low-level keyboard hook on the UI thread swallows those keys and sends
//!   them to the host directly (the window never sees them).
//! * Linux X11: the window grabs the keyboard while it has focus, so the window manager's
//!   shortcuts don't fire and the keys arrive as normal key events.
//! * Linux Wayland: compositors don't let applications do this.

use rd_core::proto::ClientMsg;
use tokio::sync::mpsc::UnboundedSender;

#[cfg(windows)]
mod imp {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
    use std::sync::Mutex;

    use rd_core::proto::{ClientMsg, InputEvent};
    use tokio::sync::mpsc::UnboundedSender;
    use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
    use windows::Win32::UI::Input::KeyboardAndMouse::*;
    use windows::Win32::UI::WindowsAndMessaging::*;

    static ENABLED: AtomicBool = AtomicBool::new(false);
    static WINDOW: AtomicIsize = AtomicIsize::new(0);
    static CTRL: AtomicBool = AtomicBool::new(false);
    static SINK: Mutex<Option<UnboundedSender<ClientMsg>>> = Mutex::new(None);
    /// Keys swallowed on the way down, so their release is swallowed too.
    static HELD: Mutex<Option<HashSet<u32>>> = Mutex::new(None);
    static INSTALLED: AtomicBool = AtomicBool::new(false);

    unsafe extern "system" fn hook(code: i32, wp: WPARAM, lp: LPARAM) -> LRESULT {
        if code == HC_ACTION as i32 {
            let k = &*(lp.0 as *const KBDLLHOOKSTRUCT);
            let down = matches!(wp.0 as u32, WM_KEYDOWN | WM_SYSKEYDOWN);
            let vk = k.vkCode;
            if vk == VK_LCONTROL.0 as u32 || vk == VK_RCONTROL.0 as u32 || vk == VK_CONTROL.0 as u32 {
                CTRL.store(down, Ordering::Relaxed);
            }
            let injected = k.flags.0 & LLKHF_INJECTED.0 != 0;
            if ENABLED.load(Ordering::Relaxed) && !injected && GetForegroundWindow().0 as isize == WINDOW.load(Ordering::Relaxed) {
                let alt = k.flags.0 & LLKHF_ALTDOWN.0 != 0;
                let ctrl = CTRL.load(Ordering::Relaxed);
                let is = |v: VIRTUAL_KEY| vk == v.0 as u32;
                let system = is(VK_LWIN)
                    || is(VK_RWIN)
                    || (alt && (is(VK_TAB) || is(VK_ESCAPE) || is(VK_F4) || is(VK_SPACE)))
                    || (ctrl && is(VK_ESCAPE));
                let mut held = HELD.lock().unwrap();
                let held = held.get_or_insert_with(HashSet::new);
                if (down && system) || (!down && held.contains(&vk)) {
                    if down {
                        held.insert(vk);
                    } else {
                        held.remove(&vk);
                    }
                    let extended = k.flags.0 & LLKHF_EXTENDED.0 != 0;
                    if let Some(code) = rd_core::keys::win_scancode_to_evdev(k.scanCode as u16, extended) {
                        if let Some(tx) = SINK.lock().unwrap().as_ref() {
                            let _ = tx.send(ClientMsg::Input(InputEvent::Key { code, down }));
                        }
                    }
                    return LRESULT(1);
                }
            }
        }
        CallNextHookEx(HHOOK::default(), code, wp, lp)
    }

    /// Install the hook once, on the UI thread (which pumps the messages it needs).
    fn install() {
        if INSTALLED.swap(true, Ordering::Relaxed) {
            return;
        }
        unsafe {
            let module = windows::Win32::System::LibraryLoader::GetModuleHandleW(None).unwrap_or_default();
            if let Err(e) = SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook), module, 0) {
                log::warn!("keyboard hook: {e}");
                INSTALLED.store(false, Ordering::Relaxed);
            }
        }
    }

    pub fn set(window: isize, sink: Option<UnboundedSender<ClientMsg>>) -> Result<(), String> {
        let on = sink.is_some();
        if on {
            install();
        }
        *SINK.lock().unwrap() = sink;
        WINDOW.store(window, Ordering::Relaxed);
        ENABLED.store(on && INSTALLED.load(Ordering::Relaxed), Ordering::Relaxed);
        if on && !INSTALLED.load(Ordering::Relaxed) {
            return Err("couldn't install the keyboard hook".into());
        }
        let _ = HWND::default();
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::sync::Mutex;

    use rd_core::proto::ClientMsg;
    use tokio::sync::mpsc::UnboundedSender;
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{ConnectionExt as _, GrabMode, GrabStatus};
    use x11rb::rust_connection::RustConnection;

    static CONN: Mutex<Option<RustConnection>> = Mutex::new(None);

    /// Grab (or release) the keyboard for X11 window `window`; 0 = not an X11 window.
    pub fn set(window: isize, sink: Option<UnboundedSender<ClientMsg>>) -> Result<(), String> {
        let on = sink.is_some();
        if window == 0 {
            return if on { Err("Wayland desktops don't let apps take over system shortcuts".into()) } else { Ok(()) };
        }
        let mut g = CONN.lock().unwrap();
        if g.is_none() {
            *g = Some(x11rb::connect(None).map_err(|e| format!("X11: {e}"))?.0);
        }
        let c = g.as_ref().unwrap();
        if on {
            let r = c
                .grab_keyboard(true, window as u32, x11rb::CURRENT_TIME, GrabMode::ASYNC, GrabMode::ASYNC)
                .map_err(|e| e.to_string())?
                .reply()
                .map_err(|e| e.to_string())?;
            if r.status != GrabStatus::SUCCESS {
                return Err(format!("the keyboard couldn't be grabbed ({:?})", r.status));
            }
        } else {
            let _ = c.ungrab_keyboard(x11rb::CURRENT_TIME);
        }
        let _ = c.flush();
        Ok(())
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod imp {
    pub fn set(_: isize, sink: Option<tokio::sync::mpsc::UnboundedSender<rd_core::proto::ClientMsg>>) -> Result<(), String> {
        if sink.is_some() { Err("not supported on this system".into()) } else { Ok(()) }
    }
}

/// The native window id winit gives us: HWND on Windows, the X11 window on Linux (0 on
/// Wayland).
pub fn native_window(w: &winit::window::Window) -> isize {
    use winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match w.window_handle().map(|h| h.as_raw()) {
        #[cfg(windows)]
        Ok(RawWindowHandle::Win32(h)) => h.hwnd.get(),
        Ok(RawWindowHandle::Xlib(h)) => h.window as isize,
        Ok(RawWindowHandle::Xcb(h)) => h.window.get() as isize,
        _ => 0,
    }
}

/// Turn system-shortcut capture on (keys go to `sink`) or off.
pub fn set(window: isize, sink: Option<UnboundedSender<ClientMsg>>) -> Result<(), String> {
    imp::set(window, sink)
}
