//! X11 backend: MIT-SHM (or plain GetImage) capture of one RandR monitor, XTest input.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rd_core::proto::{DisplayInfo, InputEvent, MouseButton};
use x11rb::connection::{Connection, RequestConnection};
use x11rb::protocol::randr::ConnectionExt as _;
use x11rb::protocol::shm::ConnectionExt as _;
use x11rb::protocol::xproto::{ConnectionExt as _, ImageFormat, Window};
use x11rb::protocol::xfixes::ConnectionExt as _;
use x11rb::protocol::xtest::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

use crate::{Capturer, CursorShape, Frame, InputInjector, WheelAccumulator};

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
    /// XFixes is available (pointer image), and the serial of the last pointer sent.
    xfixes: bool,
    cursor_serial: Option<u32>,
    /// The monitor's mode before "fit to window" changed it.
    saved_mode: Option<SavedMode>,
}

#[derive(Clone)]
struct SavedMode {
    crtc: u32,
    x: i16,
    y: i16,
    mode: u32,
    rotation: x11rb::protocol::randr::Rotation,
    outputs: Vec<u32>,
    /// Screen (width, height, mm width, mm height) when it is resized with the monitor.
    screen: Option<(u16, u16, u32, u32)>,
}

fn refresh(m: &x11rb::protocol::randr::ModeInfo) -> u32 {
    let total = m.htotal as u64 * m.vtotal as u64;
    if total == 0 { 0 } else { (m.dot_clock as u64 * 1000 / total) as u32 }
}

/// Set a CRTC's mode, resizing the X screen around it when it's the only monitor
/// (grow the screen first, shrink it after, so the CRTC always fits).
fn apply_mode(conn: &RustConnection, root: Window, m: &SavedMode) -> Result<()> {
    let res = conn.randr_get_screen_resources_current(root)?.reply()?;
    let mode = res.modes.iter().find(|x| x.id == m.mode).ok_or_else(|| anyhow!("mode is gone"))?;
    let geo = conn.get_geometry(root)?.reply()?;
    let grow = m.screen.is_some_and(|(w, h, _, _)| w > geo.width || h > geo.height);
    if let (true, Some((w, h, mw, mh))) = (grow, m.screen) {
        conn.randr_set_screen_size(root, w.max(geo.width), h.max(geo.height), mw, mh)?.check()?;
    }
    let r = conn
        .randr_set_crtc_config(m.crtc, x11rb::CURRENT_TIME, res.config_timestamp, m.x, m.y, m.mode, m.rotation, &m.outputs)?
        .reply()?;
    if r.status != x11rb::protocol::randr::SetConfig::SUCCESS {
        bail!("the X server refused {}x{} ({:?})", mode.width, mode.height, r.status);
    }
    if let Some((w, h, mw, mh)) = m.screen {
        conn.randr_set_screen_size(root, w, h, mw, mh)?.check()?;
    }
    conn.flush()?;
    Ok(())
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
        let xfixes = conn.xfixes_query_version(4, 0).ok().and_then(|c| c.reply().ok()).is_some();
        if !xfixes {
            log::info!("XFixes unavailable: viewers see their own pointer shape");
        }
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
            xfixes,
            cursor_serial: None,
            saved_mode: None,
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
        if let Some(saved) = self.saved_mode.take() {
            let _ = apply_mode(&self.conn, self.root, &saved);
        }
    }
}

impl Capturer for X11Capturer {
    fn set_resolution(&mut self, size: Option<(u32, u32)>) -> Result<(u32, u32)> {
        match size {
            None => {
                if let Some(saved) = self.saved_mode.take() {
                    apply_mode(&self.conn, self.root, &saved)?;
                }
            }
            Some((w, h)) => {
                let t = self.target().clone();
                let res = self.conn.randr_get_screen_resources_current(self.root)?.reply()?;
                let mut active = Vec::new();
                for c in &res.crtcs {
                    let info = self.conn.randr_get_crtc_info(*c, res.config_timestamp)?.reply()?;
                    if info.mode != 0 {
                        active.push((*c, info));
                    }
                }
                let (crtc, info) = active
                    .iter()
                    .find(|(_, i)| i.x as i32 == t.x && i.y as i32 == t.y)
                    .cloned()
                    .ok_or_else(|| anyhow!("couldn't find this monitor's RandR output"))?;
                let output = *info.outputs.first().ok_or_else(|| anyhow!("monitor without an output"))?;
                let out = self.conn.randr_get_output_info(output, res.config_timestamp)?.reply()?;
                let alone = active.len() == 1;
                // Only grow past the current size when this is the only monitor (the
                // screen is resized to match); beside others, fit inside the current area.
                let (mw, mh) = if alone { (w, h) } else { (w.min(t.width), h.min(t.height)) };
                let best = res
                    .modes
                    .iter()
                    .filter(|m| out.modes.contains(&m.id))
                    .filter(|m| (m.width as u32) <= mw && (m.height as u32) <= mh && m.width >= 800 && m.height >= 600)
                    .max_by_key(|m| (m.width as u32 * m.height as u32, refresh(m)))
                    .ok_or_else(|| anyhow!("the monitor has no mode that fits {w}x{h}"))?;
                if self.saved_mode.is_none() {
                    let geo = self.conn.get_geometry(self.root)?.reply()?;
                    let mm = self.conn.randr_get_screen_info(self.root)?.reply().ok();
                    let (mmw, mmh) = mm
                        .and_then(|i| i.sizes.get(i.size_id as usize).map(|s| (s.mwidth as u32, s.mheight as u32)))
                        .unwrap_or((geo.width as u32 * 254 / 960, geo.height as u32 * 254 / 960));
                    self.saved_mode = Some(SavedMode {
                        crtc,
                        x: info.x,
                        y: info.y,
                        mode: info.mode,
                        rotation: info.rotation,
                        outputs: info.outputs.clone(),
                        screen: alone.then_some((geo.width, geo.height, mmw, mmh)),
                    });
                }
                let target = SavedMode {
                    crtc,
                    x: info.x,
                    y: info.y,
                    mode: best.id,
                    rotation: info.rotation,
                    outputs: info.outputs.clone(),
                    // Keep roughly 96 dpi when resizing the screen.
                    screen: alone.then_some((best.width, best.height, best.width as u32 * 254 / 960, best.height as u32 * 254 / 960)),
                };
                apply_mode(&self.conn, self.root, &target)?;
            }
        }
        self.refreshed = Instant::now() - Duration::from_secs(10);
        std::thread::sleep(Duration::from_millis(300));
        self.maybe_refresh();
        let t = self.target();
        Ok((t.width, t.height))
    }

    fn cursor(&mut self) -> Option<CursorShape> {
        if !self.xfixes {
            return None;
        }
        let r = self.conn.xfixes_get_cursor_image().ok()?.reply().ok()?;
        if self.cursor_serial == Some(r.cursor_serial) {
            return None;
        }
        self.cursor_serial = Some(r.cursor_serial);
        let (w, h) = (r.width as u32, r.height as u32);
        if w == 0 || h == 0 || r.cursor_image.len() < (w * h) as usize {
            return Some(CursorShape::Hidden);
        }
        // Premultiplied ARGB -> straight RGBA.
        let mut rgba = Vec::with_capacity((w * h * 4) as usize);
        for p in &r.cursor_image[..(w * h) as usize] {
            let a = (p >> 24) as u8;
            let un = |c: u32| if a == 0 { 0 } else { ((c & 0xFF) * 255 / a as u32).min(255) as u8 };
            rgba.extend_from_slice(&[un(p >> 16), un(p >> 8), un(*p), a]);
        }
        let shape = CursorShape::Image {
            width: w,
            height: h,
            hot_x: (r.xhot as u32).min(w - 1),
            hot_y: (r.yhot as u32).min(h - 1),
            rgba,
        };
        shape.is_valid().then_some(shape)
    }

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
    /// Physical keyboards and mice switched off for the privacy screen.
    disabled: Vec<u16>,
}

/// Where the ids of switched-off devices are kept, so they come back on after a crash.
fn blocked_file() -> std::path::PathBuf {
    let dir = std::env::var_os("XDG_RUNTIME_DIR").map(std::path::PathBuf::from).unwrap_or_else(std::env::temp_dir);
    dir.join(format!("rd-privacy-devices-{}", unsafe { libc::getuid() }))
}

impl X11Injector {
    fn new(origin: Origin) -> Result<Self> {
        let (conn, root) = connect()?;
        conn.extension_information(x11rb::protocol::xtest::X11_EXTENSION_NAME)?
            .ok_or_else(|| anyhow!("X server lacks the XTEST extension"))?;
        let me = Self { conn, root, wheel: WheelAccumulator::default(), origin, disabled: Vec::new() };
        // A previous agent that died with the privacy screen on left devices off.
        if let Ok(ids) = std::fs::read_to_string(blocked_file()) {
            let ids: Vec<u16> = ids.split_whitespace().filter_map(|s| s.parse().ok()).collect();
            let _ = me.set_devices_enabled(&ids, true);
            let _ = std::fs::remove_file(blocked_file());
        }
        Ok(me)
    }

    /// Turn the X input devices `ids` on or off ("Device Enabled" property).
    fn set_devices_enabled(&self, ids: &[u16], on: bool) -> Result<()> {
        use x11rb::protocol::xinput::ConnectionExt as _;
        let prop = self.conn.intern_atom(false, b"Device Enabled")?.reply()?.atom;
        for id in ids {
            let _ = self.conn.xinput_xi_change_property(
                *id,
                x11rb::protocol::xproto::PropMode::REPLACE,
                prop,
                x11rb::protocol::xproto::AtomEnum::INTEGER.into(),
                1,
                &x11rb::protocol::xinput::XIChangePropertyAux::Data8(vec![on as u8]),
            )?;
        }
        self.conn.flush()?;
        Ok(())
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
    fn block_local_input(&mut self, on: bool) -> Result<()> {
        use x11rb::protocol::xinput::{ConnectionExt as _, DeviceType};
        if !on {
            let ids = std::mem::take(&mut self.disabled);
            self.set_devices_enabled(&ids, true)?;
            let _ = std::fs::remove_file(blocked_file());
            return Ok(());
        }
        if !self.disabled.is_empty() {
            return Ok(());
        }
        self.conn.xinput_xi_query_version(2, 0)?.reply().context("the X server has no XInput 2")?;
        // ALL_DEVICES = 0. Physical devices only: XTest's own devices keep working.
        let list = self.conn.xinput_xi_query_device(0u16)?.reply()?;
        let ids: Vec<u16> = list
            .infos
            .iter()
            .filter(|d| d.enabled && matches!(d.type_, DeviceType::SLAVE_POINTER | DeviceType::SLAVE_KEYBOARD))
            .filter(|d| !String::from_utf8_lossy(&d.name).contains("XTEST"))
            .map(|d| d.deviceid)
            .collect();
        let text: Vec<String> = ids.iter().map(|i| i.to_string()).collect();
        let _ = std::fs::write(blocked_file(), text.join(" "));
        self.set_devices_enabled(&ids, false)?;
        self.disabled = ids;
        Ok(())
    }

    fn inject(&mut self, ev: &InputEvent) -> Result<()> {
        match *ev {
            InputEvent::MouseMove { x, y } => {
                let (ox, oy) = *self.origin.lock().unwrap();
                let px = (ox + x.min(i16::MAX as u32) as i32).clamp(0, i16::MAX as i32) as i16;
                let py = (oy + y.min(i16::MAX as u32) as i32).clamp(0, i16::MAX as i32) as i16;
                self.fake(MOTION_NOTIFY, 0, px, py)?
            }
            InputEvent::MouseRelative { dx, dy } => {
                // XTest: detail 1 = relative motion.
                let c = |v: i32| v.clamp(i16::MIN as i32, i16::MAX as i32) as i16;
                self.conn.xtest_fake_input(MOTION_NOTIFY, 1, x11rb::CURRENT_TIME, x11rb::NONE, c(dx), c(dy), 0)?;
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


// ------------------------------------------------------------------ privacy screen

/// X11 privacy screen: the monitor is switched off (DPMS) and kept off. Pictures are
/// still captured from the X server.
struct X11Privacy {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl crate::PrivacyScreen for X11Privacy {}

impl Drop for X11Privacy {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

pub fn privacy_screen() -> Result<Box<dyn crate::PrivacyScreen>> {
    use x11rb::protocol::dpms::{ConnectionExt as _, DPMSMode};
    let (conn, _) = connect()?;
    let no_dpms = || anyhow!("this X server can't switch the monitor off (it has no DPMS power control)");
    let capable = conn.dpms_capable().map_err(|_| no_dpms())?.reply().map_err(|_| no_dpms())?;
    if !capable.capable {
        bail!("this monitor can't be switched off by the X server (no DPMS)");
    }
    let was_enabled = conn.dpms_info()?.reply()?.state;
    conn.dpms_enable()?.check()?;
    conn.dpms_force_level(DPMSMode::OFF)?.check()?;
    conn.flush()?;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s2 = stop.clone();
    let join = std::thread::Builder::new().name("privacy".into()).spawn(move || {
        // Remote input wakes the monitor; switch it off again shortly after.
        while !s2.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(700));
            if let Ok(Ok(i)) = conn.dpms_info().map(|c| c.reply()) {
                if i.power_level != DPMSMode::OFF {
                    let _ = conn.dpms_force_level(DPMSMode::OFF);
                    let _ = conn.flush();
                }
            }
        }
        let _ = conn.dpms_force_level(DPMSMode::ON);
        if !was_enabled {
            let _ = conn.dpms_disable();
        }
        let _ = conn.flush();
    })?;
    Ok(Box::new(X11Privacy { stop, join: Some(join) }))
}
