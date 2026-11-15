//! X11 backend: MIT-SHM (or plain GetImage) capture of one RandR monitor, XTest input.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rd_core::proto::{DisplayInfo, InputEvent, MouseButton};
use x11rb::connection::{Connection, RequestConnection};
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::shm::ConnectionExt as _;
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat, Window};
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use crate::{Capturer, Frame, InputInjector, WheelAccumulator};

/// Origin of the captured monitor on the X screen, shared with the injector.
type Origin = Arc<Mutex<(i32, i32)>>;

pub fn open() -> Result<(Box<dyn Capturer>, Box<dyn InputInjector>)> {
    let origin: Origin = Arc::new(Mutex::new((0, 0)));
    let cap = X11Capturer::new(origin.clone())?;
    let inj = X11Injector::new(origin)?;
    Ok((Box::new(cap), Box::new(inj)))
}

fn connect() -> Result<(RustConnection, Window)> {
    let (conn, screen) = x11rb::connect(None).context("connect to X server (is DISPLAY/XAUTHORITY set?)")?;
    let root = conn.setup().roots[screen].root;
    Ok((conn, root))
}

/// RandR monitors, primary first; falls back to the whole screen.
fn query_displays(conn: &RustConnection, root: Window) -> Result<Vec<DisplayInfo>> {
    let mut out = Vec::new();
    if let Ok(reply) = conn.randr_get_monitors(root, true).map_err(anyhow::Error::from).and_then(|c| Ok(c.reply()?)) {
        for m in reply.monitors {
            let name = conn
                .get_atom_name(m.name)
                .ok()
                .and_then(|c| c.reply().ok())
                .map(|r| String::from_utf8_lossy(&r.name).into_owned())
                .unwrap_or_else(|| "monitor".into());
            out.push(DisplayInfo {
                index: 0,
                name,
                x: m.x as i32,
                y: m.y as i32,
                width: m.width as u32,
                height: m.height as u32,
                primary: m.primary,
            });
        }
    }
    if out.is_empty() {
        let geo = conn.get_geometry(root)?.reply()?;
        out.push(DisplayInfo {
            index: 0,
            name: "screen".into(),
            x: 0,
            y: 0,
            width: geo.width as u32,
            height: geo.height as u32,
            primary: true,
        });
    }
    out.sort_by_key(|d| (!d.primary, d.x, d.y));
    for (i, d) in out.iter_mut().enumerate() {
        d.index = i as u32;
    }
    Ok(out)
}

// ------------------------------------------------------------------ capture

struct Shm {
    seg: u32,
    addr: *mut u8,
    size: usize,
}

// The mapping is only touched by the capture thread.
unsafe impl Send for Shm {}

struct X11Capturer {
    conn: RustConnection,
    root: Window,
    shm: Option<Shm>,
    shm_supported: bool,
    frame: Frame,
    next_due: Instant,
    displays: Vec<DisplayInfo>,
    current: u32,
    origin: Origin,
    refreshed: Instant,
}

impl X11Capturer {
    fn new(origin: Origin) -> Result<Self> {
        let (conn, root) = connect()?;
        let depth_ok = conn
            .setup()
            .pixmap_formats
            .iter()
            .any(|f| (f.depth == 24 || f.depth == 32) && f.bits_per_pixel == 32);
        if !depth_ok {
            bail!("unsupported X visual: need 24/32-bit depth with 32 bits per pixel");
        }
        let shm_supported = conn.shm_query_version().ok().and_then(|c| c.reply().ok()).is_some();
        if !shm_supported {
            log::warn!("MIT-SHM unavailable (remote X server?); using slower GetImage");
        }
        let displays = query_displays(&conn, root)?;
        let me = Self {
            conn,
            root,
            shm: None,
            shm_supported,
            frame: Frame::default(),
            next_due: Instant::now(),
            displays,
            current: 0,
            origin,
            refreshed: Instant::now(),
        };
        me.publish_origin();
        Ok(me)
    }

    fn target(&self) -> &DisplayInfo {
        &self.displays[(self.current as usize).min(self.displays.len() - 1)]
    }

    fn publish_origin(&self) {
        let t = self.target();
        *self.origin.lock().unwrap() = (t.x, t.y);
    }

    /// Monitors can be added/resized at runtime (xrandr); re-check every few seconds.
    fn maybe_refresh(&mut self) {
        if self.refreshed.elapsed() < Duration::from_secs(3) {
            return;
        }
        self.refreshed = Instant::now();
        if let Ok(list) = query_displays(&self.conn, self.root) {
            if list != self.displays {
                let name = self.target().name.clone();
                self.displays = list;
                self.current = self.displays.iter().position(|d| d.name == name).unwrap_or(0) as u32;
                self.publish_origin();
            }
        }
    }

    fn ensure_shm(&mut self, size: usize) -> Result<()> {
        if self.shm.as_ref().is_some_and(|s| s.size == size) {
            return Ok(());
        }
        self.drop_shm();
        unsafe {
            let shmid = libc::shmget(libc::IPC_PRIVATE, size, libc::IPC_CREAT | 0o600);
            if shmid < 0 {
                bail!("shmget: {}", std::io::Error::last_os_error());
            }
            let addr = libc::shmat(shmid, std::ptr::null(), 0);
            if addr as isize == -1 {
                libc::shmctl(shmid, libc::IPC_RMID, std::ptr::null_mut());
                bail!("shmat: {}", std::io::Error::last_os_error());
            }
            let seg = self.conn.generate_id()?;
            let attached = self.conn.shm_attach(seg, shmid as u32, false)?.check();
            // Mark for deletion now; it disappears once both we and the server detach.
            libc::shmctl(shmid, libc::IPC_RMID, std::ptr::null_mut());
            if let Err(e) = attached {
                libc::shmdt(addr);
                bail!("XShmAttach: {e}");
            }
            self.shm = Some(Shm { seg, addr: addr.cast(), size });
        }
        Ok(())
    }

    fn drop_shm(&mut self) {
        if let Some(s) = self.shm.take() {
            let _ = self.conn.shm_detach(s.seg).map(|c| c.check());
            unsafe {
                libc::shmdt(s.addr.cast());
            }
        }
    }

    fn grab(&mut self) -> Result<()> {
        let t = self.target().clone();
        let (x, y, w, h) = (t.x as i16, t.y as i16, t.width as u16, t.height as u16);
        let size = w as usize * h as usize * 4;
        self.frame.width = w as u32;
        self.frame.height = h as u32;
        self.frame.stride = w as usize * 4;

        if self.shm_supported {
            match self.ensure_shm(size) {
                Ok(()) => {
                    let s = self.shm.as_ref().unwrap();
                    self.conn
                        .shm_get_image(self.root, x, y, w, h, !0, ImageFormat::Z_PIXMAP.into(), s.seg, 0)?
                        .reply()
                        .context("XShmGetImage")?;
                    let src = unsafe { std::slice::from_raw_parts(s.addr, size) };
                    self.frame.data.clear();
                    self.frame.data.extend_from_slice(src);
                    return Ok(());
                }
                Err(e) => {
                    log::warn!("MIT-SHM setup failed ({e:#}); falling back to GetImage");
                    self.shm_supported = false;
                }
            }
        }
        let reply = self.conn.get_image(ImageFormat::Z_PIXMAP, self.root, x, y, w, h, !0)?.reply()?;
        if reply.data.len() < size {
            bail!("short GetImage reply");
        }
        self.frame.data = reply.data;
        self.frame.data.truncate(size);
        Ok(())
    }
}

impl Drop for X11Capturer {
    fn drop(&mut self) {
        self.drop_shm();
    }
}

impl Capturer for X11Capturer {
    fn capture(&mut self, timeout: Duration) -> Result<Option<&Frame>> {
        // No damage-driven wait: poll at most every ~16 ms. The encoder drops identical
        // frames, so polling only costs a memcpy.
        let now = Instant::now();
        if now < self.next_due {
            std::thread::sleep((self.next_due - now).min(timeout));
        }
        self.next_due = Instant::now() + Duration::from_millis(16);
        self.maybe_refresh();
        self.grab()?;
        Ok(Some(&self.frame))
    }

    fn displays(&self) -> Vec<DisplayInfo> {
        self.displays.clone()
    }

    fn current_display(&self) -> u32 {
        self.current
    }

    fn select_display(&mut self, index: u32) -> Result<()> {
        self.displays = query_displays(&self.conn, self.root)?;
        if index as usize >= self.displays.len() {
            bail!("no display {index}");
        }
        self.current = index;
        self.publish_origin();
        Ok(())
    }
}

// ------------------------------------------------------------------ input

const KEY_PRESS: u8 = 2;
const KEY_RELEASE: u8 = 3;
const BUTTON_PRESS: u8 = 4;
const BUTTON_RELEASE: u8 = 5;
const MOTION_NOTIFY: u8 = 6;

struct X11Injector {
    conn: RustConnection,
    root: Window,
    wheel: WheelAccumulator,
    origin: Origin,
}

impl X11Injector {
    fn new(origin: Origin) -> Result<Self> {
        let (conn, root) = connect()?;
        conn.extension_information(x11rb::protocol::xtest::X11_EXTENSION_NAME)?
            .ok_or_else(|| anyhow!("X server lacks the XTEST extension"))?;
        Ok(Self { conn, root, wheel: WheelAccumulator::default(), origin })
    }

    fn fake(&self, kind: u8, detail: u8, x: i16, y: i16) -> Result<()> {
        self.conn.xtest_fake_input(kind, detail, x11rb::CURRENT_TIME, self.root, x, y, 0)?;
        Ok(())
    }

    fn click(&self, button: u8, n: i32) -> Result<()> {
        for _ in 0..n.unsigned_abs() {
            self.fake(BUTTON_PRESS, button, 0, 0)?;
            self.fake(BUTTON_RELEASE, button, 0, 0)?;
        }
        Ok(())
    }
}

fn x_button(b: MouseButton) -> u8 {
    // X core buttons: 1 left, 2 middle, 3 right, 8 back, 9 forward.
    match b {
        MouseButton::Left => 1,
        MouseButton::Middle => 2,
        MouseButton::Right => 3,
        MouseButton::Back => 8,
        MouseButton::Forward => 9,
    }
}

impl InputInjector for X11Injector {
    fn inject(&mut self, ev: &InputEvent) -> Result<()> {
        match *ev {
            InputEvent::MouseMove { x, y } => {
                let (ox, oy) = *self.origin.lock().unwrap();
                let px = (ox + x.min(i16::MAX as u32) as i32).clamp(0, i16::MAX as i32) as i16;
                let py = (oy + y.min(i16::MAX as u32) as i32).clamp(0, i16::MAX as i32) as i16;
                self.fake(MOTION_NOTIFY, 0, px, py)?
            }
            InputEvent::MouseButton { button, down } => {
                self.fake(if down { BUTTON_PRESS } else { BUTTON_RELEASE }, x_button(button), 0, 0)?
            }
            InputEvent::Wheel { dx, dy } => {
                let (nx, ny) = self.wheel.push(dx, dy);
                // 4 = up, 5 = down, 6 = left, 7 = right.
                self.click(if ny > 0 { 4 } else { 5 }, ny)?;
                self.click(if nx > 0 { 7 } else { 6 }, nx)?;
            }
            InputEvent::Key { code, down } => {
                let keycode =
                    code.checked_add(8).filter(|k| *k <= 255).ok_or_else(|| anyhow!("key {code} out of X range"))?;
                self.fake(if down { KEY_PRESS } else { KEY_RELEASE }, keycode as u8, 0, 0)?;
            }
            InputEvent::ReleaseAll => {}
        }
        self.conn.flush()?;
        Ok(())
    }
}
