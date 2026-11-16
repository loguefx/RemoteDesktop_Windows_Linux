//! Windows backend.
//!
//! * Capture: DXGI Desktop Duplication of the selected monitor, falling back to GDI
//!   `BitBlt` whenever duplication is unavailable (secure desktop without SYSTEM rights,
//!   some virtual GPUs, RDP sessions).
//! * Input: `SendInput` with hardware scan codes, so the *host's* keyboard layout applies.
//! * Desktop switching: when Windows switches to the Winlogon desktop (lock screen,
//!   UAC prompt, Ctrl+Alt+Del screen), threads must re-attach to the new input desktop.
//!   The agent runs as SYSTEM in the console session (spawned by the service) so it is
//!   allowed to do that.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use rd_core::keys::{evdev_to_win_scancode, KEY_PAUSE};
use rd_core::proto::{DisplayInfo, InputEvent, MouseButton};
use windows::core::Interface;
use windows::Win32::Foundation::{BOOL, HMODULE, HWND, LPARAM, RECT, TRUE};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::*;
use windows::Win32::Graphics::Dxgi::Common::DXGI_SAMPLE_DESC;
use windows::Win32::Graphics::Dxgi::*;
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, OpenInputDesktop, SetThreadDesktop, DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS, HDESK,
};
use windows::Win32::UI::HiDpi::{SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2};
use windows::Win32::UI::Input::KeyboardAndMouse::*;
use windows::Win32::UI::WindowsAndMessaging::*;

use crate::{Capturer, CursorShape, Frame, InputInjector};

/// Screen rectangle being captured, in virtual-desktop coordinates. Shared so the
/// injector can map frame pixels to absolute mouse coordinates.
#[derive(Clone, Copy, Debug, Default)]
struct Rect {
    left: i32,
    top: i32,
    width: u32,
    height: u32,
}

pub fn open() -> Result<(Box<dyn Capturer>, Box<dyn InputInjector>)> {
    unsafe {
        // Physical pixels everywhere; otherwise GDI/SendInput coordinates get DPI-virtualised.
        let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    let displays = enumerate_displays();
    let current = displays.iter().position(|d| d.primary).unwrap_or(0) as u32;
    let rect = Arc::new(Mutex::new(rect_of(&displays[current as usize])));
    Ok((
        Box::new(WinCapturer {
            displays,
            current,
            dxgi: None,
            frame: Frame::default(),
            rect: rect.clone(),
            retry_dxgi_at: Instant::now(),
            seed_pending: true,
            desktop: DesktopSync::default(),
            cursor_last: None,
        }),
        Box::new(WinInjector { rect, desktop: DesktopSync::default() }),
    ))
}

fn rect_of(d: &DisplayInfo) -> Rect {
    Rect { left: d.x, top: d.y, width: d.width, height: d.height }
}

/// All monitors attached to the desktop, primary first.
fn enumerate_displays() -> Vec<DisplayInfo> {
    unsafe extern "system" fn cb(m: HMONITOR, _: HDC, _: *mut RECT, data: LPARAM) -> BOOL {
        let out = &mut *(data.0 as *mut Vec<DisplayInfo>);
        let mut mi = MONITORINFOEXW::default();
        mi.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
        if GetMonitorInfoW(m, &mut mi as *mut MONITORINFOEXW as *mut MONITORINFO).as_bool() {
            let r = mi.monitorInfo.rcMonitor;
            let len = mi.szDevice.iter().position(|c| *c == 0).unwrap_or(mi.szDevice.len());
            out.push(DisplayInfo {
                index: 0,
                name: String::from_utf16_lossy(&mi.szDevice[..len]),
                x: r.left,
                y: r.top,
                width: (r.right - r.left).max(1) as u32,
                height: (r.bottom - r.top).max(1) as u32,
                primary: mi.monitorInfo.dwFlags & 1 != 0, // MONITORINFOF_PRIMARY
            });
        }
        TRUE
    }
    let mut v: Vec<DisplayInfo> = Vec::new();
    unsafe {
        let _ = EnumDisplayMonitors(HDC::default(), None, Some(cb), LPARAM(&mut v as *mut Vec<DisplayInfo> as isize));
    }
    v.sort_by_key(|d| (!d.primary, d.x, d.y));
    if v.is_empty() {
        let (w, h) = unsafe { (GetSystemMetrics(SM_CXSCREEN).max(1) as u32, GetSystemMetrics(SM_CYSCREEN).max(1) as u32) };
        v.push(DisplayInfo { index: 0, name: "primary".into(), x: 0, y: 0, width: w, height: h, primary: true });
    }
    for (i, d) in v.iter_mut().enumerate() {
        d.index = i as u32;
    }
    v
}

// ------------------------------------------------------------------ desktop switching

/// Keeps the calling thread attached to the current *input* desktop.
#[derive(Default)]
struct DesktopSync {
    current: Option<HDESK>,
    last_check: Option<Instant>,
}

// HDESK is a plain handle; we only use it from the owning thread.
unsafe impl Send for DesktopSync {}

impl DesktopSync {
    /// Re-attach at most every 250 ms (or immediately when `force`).
    fn sync(&mut self, force: bool) {
        if !force && self.last_check.is_some_and(|t| t.elapsed() < Duration::from_millis(250)) {
            return;
        }
        self.last_check = Some(Instant::now());
        unsafe {
            // GENERIC_ALL: read for capture, journal playback for SendInput.
            let Ok(h) = OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_ACCESS_FLAGS(0x1000_0000)) else {
                return;
            };
            if SetThreadDesktop(h).is_ok() {
                if let Some(old) = self.current.replace(h) {
                    let _ = CloseDesktop(old);
                }
            } else {
                let _ = CloseDesktop(h);
            }
        }
    }
}

impl Drop for DesktopSync {
    fn drop(&mut self) {
        // The handle may still be the thread's desktop; closing it then fails harmlessly.
        if let Some(h) = self.current.take() {
            unsafe {
                let _ = CloseDesktop(h);
            }
        }
    }
}

// ------------------------------------------------------------------ capture

struct WinCapturer {
    displays: Vec<DisplayInfo>,
    current: u32,
    dxgi: Option<Dxgi>,
    frame: Frame,
    rect: Arc<Mutex<Rect>>,
    retry_dxgi_at: Instant,
    /// DXGI only delivers a frame when something on screen changes, and its very first
    /// frame can be blank. Seed every new duplication with one GDI grab.
    seed_pending: bool,
    desktop: DesktopSync,
    /// Last pointer seen: (cursor handle, showing).
    cursor_last: Option<(isize, bool)>,
}

impl WinCapturer {
    fn target(&self) -> &DisplayInfo {
        &self.displays[(self.current as usize).min(self.displays.len() - 1)]
    }

    /// Re-read the monitor layout (resolution / arrangement changes), keeping the
    /// selection on the same device if it still exists.
    fn refresh_displays(&mut self) {
        let name = self.target().name.clone();
        self.displays = enumerate_displays();
        self.current = self.displays.iter().position(|d| d.name == name).unwrap_or(0) as u32;
        *self.rect.lock().unwrap() = rect_of(self.target());
    }
}

impl Capturer for WinCapturer {
    fn cursor(&mut self) -> Option<CursorShape> {
        // Same thread as capture, so it follows the input desktop (lock screen, UAC) too.
        self.desktop.sync(false);
        poll_cursor(&mut self.cursor_last)
    }

    fn displays(&self) -> Vec<DisplayInfo> {
        self.displays.clone()
    }

    fn current_display(&self) -> u32 {
        self.current
    }

    fn select_display(&mut self, index: u32) -> Result<()> {
        self.displays = enumerate_displays();
        if index as usize >= self.displays.len() {
            bail!("no display {index}");
        }
        self.current = index;
        *self.rect.lock().unwrap() = rect_of(self.target());
        self.dxgi = None;
        self.retry_dxgi_at = Instant::now();
        self.seed_pending = true;
        Ok(())
    }

    fn capture(&mut self, timeout: Duration) -> Result<Option<&Frame>> {
        self.desktop.sync(false);
        if self.dxgi.is_none() && Instant::now() >= self.retry_dxgi_at {
            self.refresh_displays();
            match Dxgi::new(self.target()) {
                Ok(d) => {
                    log::info!("DXGI duplication of {} ({}x{})", self.target().name, d.rect.width, d.rect.height);
                    *self.rect.lock().unwrap() = d.rect;
                    self.dxgi = Some(d);
                    self.seed_pending = true;
                }
                Err(e) => {
                    log::debug!("DXGI unavailable, using GDI: {e:#}");
                    self.retry_dxgi_at = Instant::now() + Duration::from_secs(2);
                }
            }
        }
        if self.seed_pending {
            self.seed_pending = false;
            let rect = *self.rect.lock().unwrap();
            match gdi_capture(rect, &mut self.frame) {
                Ok(()) => return Ok(Some(&self.frame)),
                Err(e) => log::debug!("GDI seed capture failed: {e:#}"),
            }
        }
        if let Some(d) = &mut self.dxgi {
            match d.capture(timeout, &mut self.frame) {
                Ok(true) => return Ok(Some(&self.frame)),
                Ok(false) => return Ok(None),
                Err(e) => {
                    log::info!("DXGI duplication lost ({e:#}); re-attaching to input desktop");
                    self.dxgi = None;
                    self.seed_pending = true;
                    self.desktop.sync(true);
                    self.retry_dxgi_at = Instant::now();
                    return Ok(None);
                }
            }
        }
        let rect = *self.rect.lock().unwrap();
        gdi_capture(rect, &mut self.frame)?;
        std::thread::sleep(timeout.min(Duration::from_millis(15)));
        Ok(Some(&self.frame))
    }
}

// ------------------------------------------------------------------ pointer shape

/// The pointer's look, or `None` when it hasn't changed since the last call.
fn poll_cursor(last: &mut Option<(isize, bool)>) -> Option<CursorShape> {
    unsafe {
        let mut ci = CURSORINFO { cbSize: std::mem::size_of::<CURSORINFO>() as u32, ..Default::default() };
        if GetCursorInfo(&mut ci).is_err() {
            return None;
        }
        let showing = ci.flags.0 & CURSOR_SHOWING.0 != 0 && !ci.hCursor.is_invalid();
        let key = (ci.hCursor.0 as isize, showing);
        if *last == Some(key) {
            return None;
        }
        *last = Some(key);
        if !showing {
            return Some(CursorShape::Hidden);
        }
        match cursor_image(ci.hCursor) {
            Ok(c) => Some(c),
            Err(e) => {
                log::debug!("pointer image unavailable: {e:#}");
                None
            }
        }
    }
}

/// 32-bit top-down BGRA pixels of a bitmap (monochrome bitmaps come out black/white).
unsafe fn bitmap_bgra(hbm: HBITMAP) -> Result<(u32, u32, Vec<u8>)> {
    let mut bm = BITMAP::default();
    if GetObjectW(hbm, std::mem::size_of::<BITMAP>() as i32, Some(&mut bm as *mut BITMAP as *mut _)) == 0 {
        bail!("GetObject failed");
    }
    let (w, h) = (bm.bmWidth.max(0) as u32, bm.bmHeight.max(0) as u32);
    if w == 0 || h == 0 || w > 1024 || h > 2048 {
        bail!("unexpected cursor bitmap {w}x{h}");
    }
    let mut bmi = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: w as i32,
            biHeight: -(h as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut buf = vec![0u8; (w * h * 4) as usize];
    let dc = GetDC(HWND::default());
    let lines = GetDIBits(dc, hbm, 0, h, Some(buf.as_mut_ptr().cast()), &mut bmi, DIB_RGB_COLORS);
    ReleaseDC(HWND::default(), dc);
    if lines == 0 {
        bail!("GetDIBits failed");
    }
    Ok((w, h, buf))
}

/// RGBA image of a cursor handle: colour cursors (with or without alpha) and classic
/// monochrome ones (AND/XOR masks; "invert" pixels become black with a white edge).
unsafe fn cursor_image(cursor: HCURSOR) -> Result<CursorShape> {
    let mut ii = ICONINFO::default();
    GetIconInfo(HICON(cursor.0), &mut ii).context("GetIconInfo")?;
    let r = (|| {
        let (hot_x, hot_y) = (ii.xHotspot, ii.yHotspot);
        let (w, h, rgba) = if !ii.hbmColor.is_invalid() {
            let (w, h, mut px) = bitmap_bgra(ii.hbmColor)?;
            let has_alpha = px.chunks_exact(4).any(|p| p[3] != 0);
            let mask = if has_alpha { None } else { bitmap_bgra(ii.hbmMask).ok() };
            for (i, p) in px.chunks_exact_mut(4).enumerate() {
                p.swap(0, 2); // BGRA -> RGBA
                if let Some((_, _, m)) = &mask {
                    // AND mask: white = transparent.
                    p[3] = if m.get(i * 4).copied().unwrap_or(0) != 0 { 0 } else { 255 };
                }
            }
            (w, h, px)
        } else {
            let (w, h2, m) = bitmap_bgra(ii.hbmMask)?;
            let h = h2 / 2;
            let n = (w * h) as usize;
            let and = |i: usize| m[i * 4] != 0;
            let xor = |i: usize| m[(n + i) * 4] != 0;
            let mut px = vec![0u8; n * 4];
            let mut invert = vec![false; n];
            for i in 0..n {
                let (r, g, b, a) = match (and(i), xor(i)) {
                    (false, false) => (0, 0, 0, 255),
                    (false, true) => (255, 255, 255, 255),
                    (true, false) => (0, 0, 0, 0),
                    (true, true) => {
                        invert[i] = true;
                        (0, 0, 0, 255)
                    }
                };
                px[i * 4..i * 4 + 4].copy_from_slice(&[r, g, b, a]);
            }
            // A white edge around "invert" pixels keeps e.g. the text I-beam visible on dark backgrounds.
            for y in 0..h as i32 {
                for x in 0..w as i32 {
                    let i = (y * w as i32 + x) as usize;
                    if px[i * 4 + 3] != 0 {
                        continue;
                    }
                    let near = [(-1, 0), (1, 0), (0, -1), (0, 1)].iter().any(|(dx, dy)| {
                        let (nx, ny) = (x + dx, y + dy);
                        nx >= 0 && ny >= 0 && nx < w as i32 && ny < h as i32 && invert[(ny * w as i32 + nx) as usize]
                    });
                    if near {
                        px[i * 4..i * 4 + 4].copy_from_slice(&[255, 255, 255, 255]);
                    }
                }
            }
            (w, h, px)
        };
        let shape = CursorShape::Image { width: w, height: h, hot_x: hot_x.min(w - 1), hot_y: hot_y.min(h - 1), rgba };
        if !shape.is_valid() {
            bail!("cursor too large ({w}x{h})");
        }
        Ok(shape)
    })();
    if !ii.hbmColor.is_invalid() {
        let _ = DeleteObject(ii.hbmColor);
    }
    if !ii.hbmMask.is_invalid() {
        let _ = DeleteObject(ii.hbmMask);
    }
    r
}

#[cfg(test)]
mod cursor_tests {
    use super::*;

    /// Reads this desktop's pointer (skipped where there is no interactive desktop).
    #[test]
    fn reads_current_pointer() {
        let mut last = None;
        match poll_cursor(&mut last) {
            Some(CursorShape::Image { width, height, rgba, .. }) => {
                assert!(rgba.chunks_exact(4).any(|p| p[3] > 0), "pointer has visible pixels");
                println!("pointer {width}x{height}");
                assert!(poll_cursor(&mut last).is_none(), "unchanged pointer is not reported again");
            }
            other => println!("no pointer image here: {other:?}"),
        }
    }
}

struct Dxgi {
    ctx: ID3D11DeviceContext,
    dup: IDXGIOutputDuplication,
    staging: Option<(ID3D11Texture2D, u32, u32)>,
    rect: Rect,
    device: ID3D11Device,
}

impl Dxgi {
    /// Duplicate the output showing `target` (matched by GDI device name, falling back
    /// to desktop coordinates), using a D3D device on that output's own adapter.
    fn new(target: &DisplayInfo) -> Result<Self> {
        unsafe {
            let factory: IDXGIFactory1 = CreateDXGIFactory1().context("CreateDXGIFactory1")?;
            let mut found = None;
            let mut a = 0;
            while found.is_none() {
                let Ok(adapter) = factory.EnumAdapters1(a) else { break };
                a += 1;
                let mut o = 0;
                while let Ok(out) = adapter.EnumOutputs(o) {
                    o += 1;
                    let desc = out.GetDesc()?;
                    let len = desc.DeviceName.iter().position(|c| *c == 0).unwrap_or(32);
                    let name = String::from_utf16_lossy(&desc.DeviceName[..len]);
                    let r = desc.DesktopCoordinates;
                    if name == target.name || (r.left == target.x && r.top == target.y) {
                        found = Some((adapter.clone(), out, r));
                        break;
                    }
                }
            }
            let (adapter, output, r) = found.ok_or_else(|| anyhow!("no DXGI output for {}", target.name))?;
            let adapter: IDXGIAdapter = adapter.cast()?;
            let mut device = None;
            let mut ctx = None;
            D3D11CreateDevice(
                &adapter,
                D3D_DRIVER_TYPE_UNKNOWN,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                None,
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut ctx),
            )
            .context("D3D11CreateDevice")?;
            let device: ID3D11Device = device.ok_or_else(|| anyhow!("no D3D11 device"))?;
            let ctx = ctx.ok_or_else(|| anyhow!("no D3D11 context"))?;
            let dup = output.cast::<IDXGIOutput1>()?.DuplicateOutput(&device).context("DuplicateOutput")?;
            Ok(Self {
                device,
                ctx,
                dup,
                staging: None,
                rect: Rect {
                    left: r.left,
                    top: r.top,
                    width: (r.right - r.left) as u32,
                    height: (r.bottom - r.top) as u32,
                },
            })
        }
    }

    /// Returns Ok(true) when `frame` was updated.
    fn capture(&mut self, timeout: Duration, frame: &mut Frame) -> Result<bool> {
        unsafe {
            let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
            let mut res: Option<IDXGIResource> = None;
            match self.dup.AcquireNextFrame(timeout.as_millis() as u32, &mut info, &mut res) {
                Ok(()) => {}
                Err(e) if e.code() == DXGI_ERROR_WAIT_TIMEOUT => return Ok(false),
                Err(e) => bail!("AcquireNextFrame: {e}"),
            }
            let result = self.copy_frame(&info, res, frame);
            let _ = self.dup.ReleaseFrame();
            result
        }
    }

    unsafe fn copy_frame(
        &mut self,
        info: &DXGI_OUTDUPL_FRAME_INFO,
        res: Option<IDXGIResource>,
        frame: &mut Frame,
    ) -> Result<bool> {
        // LastPresentTime == 0 → no new desktop image (pointer-only update, or the
        // initial empty frame). The GDI seed covers the initial image.
        if info.LastPresentTime == 0 {
            return Ok(false);
        }
        let tex: ID3D11Texture2D = res.ok_or_else(|| anyhow!("no desktop resource"))?.cast()?;
        let mut desc = D3D11_TEXTURE2D_DESC::default();
        tex.GetDesc(&mut desc);
        let (w, h) = (desc.Width, desc.Height);
        if !matches!(&self.staging, Some((_, sw, sh)) if *sw == w && *sh == h) {
            let sdesc = D3D11_TEXTURE2D_DESC {
                Width: w,
                Height: h,
                MipLevels: 1,
                ArraySize: 1,
                Format: desc.Format,
                SampleDesc: DXGI_SAMPLE_DESC { Count: 1, Quality: 0 },
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
            };
            let mut staging = None;
            self.device.CreateTexture2D(&sdesc, None, Some(&mut staging))?;
            self.staging = Some((staging.ok_or_else(|| anyhow!("no staging texture"))?, w, h));
        }
        let staging = &self.staging.as_ref().unwrap().0;
        self.ctx.CopyResource(staging, &tex);
        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        self.ctx.Map(staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
        let pitch = mapped.RowPitch as usize;
        let row_bytes = w as usize * 4;
        frame.width = w;
        frame.height = h;
        frame.stride = row_bytes;
        frame.data.resize(row_bytes * h as usize, 0);
        let src = std::slice::from_raw_parts(mapped.pData as *const u8, pitch * h as usize);
        for y in 0..h as usize {
            frame.data[y * row_bytes..(y + 1) * row_bytes].copy_from_slice(&src[y * pitch..y * pitch + row_bytes]);
        }
        self.ctx.Unmap(staging, 0);
        Ok(true)
    }
}

fn gdi_capture(rect: Rect, frame: &mut Frame) -> Result<()> {
    let (w, h) = (rect.width as i32, rect.height as i32);
    unsafe {
        let screen = GetDC(HWND::default());
        if screen.is_invalid() {
            bail!("GetDC failed");
        }
        let mem = CreateCompatibleDC(screen);
        let bmp = CreateCompatibleBitmap(screen, w, h);
        let old = SelectObject(mem, bmp);
        let blt = BitBlt(mem, 0, 0, w, h, screen, rect.left, rect.top, SRCCOPY | CAPTUREBLT);
        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: w,
                biHeight: -h, // top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };
        frame.width = w as u32;
        frame.height = h as u32;
        frame.stride = w as usize * 4;
        frame.data.resize(frame.stride * h as usize, 0);
        let lines = GetDIBits(mem, bmp, 0, h as u32, Some(frame.data.as_mut_ptr().cast()), &mut bmi, DIB_RGB_COLORS);
        SelectObject(mem, old);
        let _ = DeleteObject(bmp);
        let _ = DeleteDC(mem);
        ReleaseDC(HWND::default(), screen);
        blt.context("BitBlt")?;
        if lines == 0 {
            bail!("GetDIBits failed");
        }
    }
    Ok(())
}

// ------------------------------------------------------------------ input

struct WinInjector {
    rect: Arc<Mutex<Rect>>,
    desktop: DesktopSync,
}

fn mouse(dx: i32, dy: i32, data: i32, flags: MOUSE_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT { dx, dy, mouseData: data as u32, dwFlags: flags, time: 0, dwExtraInfo: 0 },
        },
    }
}

fn key(vk: VIRTUAL_KEY, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: vk, wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: 0 } },
    }
}

impl InputInjector for WinInjector {
    fn inject(&mut self, ev: &InputEvent) -> Result<()> {
        self.desktop.sync(false);
        let input = match *ev {
            InputEvent::MouseMove { x, y } => {
                let r = *self.rect.lock().unwrap();
                let (vx, vy, vw, vh) = unsafe {
                    (
                        GetSystemMetrics(SM_XVIRTUALSCREEN),
                        GetSystemMetrics(SM_YVIRTUALSCREEN),
                        GetSystemMetrics(SM_CXVIRTUALSCREEN).max(2),
                        GetSystemMetrics(SM_CYVIRTUALSCREEN).max(2),
                    )
                };
                let px = r.left + x.min(r.width.saturating_sub(1)) as i32;
                let py = r.top + y.min(r.height.saturating_sub(1)) as i32;
                // Normalise to 0..=65535 across the whole virtual desktop.
                let nx = ((px - vx) as i64 * 65535 / (vw - 1) as i64) as i32;
                let ny = ((py - vy) as i64 * 65535 / (vh - 1) as i64) as i32;
                mouse(nx, ny, 0, MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK)
            }
            InputEvent::MouseButton { button, down } => {
                let (flags, data) = match (button, down) {
                    (MouseButton::Left, true) => (MOUSEEVENTF_LEFTDOWN, 0),
                    (MouseButton::Left, false) => (MOUSEEVENTF_LEFTUP, 0),
                    (MouseButton::Right, true) => (MOUSEEVENTF_RIGHTDOWN, 0),
                    (MouseButton::Right, false) => (MOUSEEVENTF_RIGHTUP, 0),
                    (MouseButton::Middle, true) => (MOUSEEVENTF_MIDDLEDOWN, 0),
                    (MouseButton::Middle, false) => (MOUSEEVENTF_MIDDLEUP, 0),
                    (MouseButton::Back, true) => (MOUSEEVENTF_XDOWN, 1),
                    (MouseButton::Back, false) => (MOUSEEVENTF_XUP, 1),
                    (MouseButton::Forward, true) => (MOUSEEVENTF_XDOWN, 2),
                    (MouseButton::Forward, false) => (MOUSEEVENTF_XUP, 2),
                };
                mouse(0, 0, data, flags)
            }
            InputEvent::Wheel { dx, dy } => {
                let mut ins = Vec::new();
                if dy != 0 {
                    ins.push(mouse(0, 0, dy, MOUSEEVENTF_WHEEL));
                }
                if dx != 0 {
                    ins.push(mouse(0, 0, dx, MOUSEEVENTF_HWHEEL));
                }
                send(&ins);
                return Ok(());
            }
            InputEvent::Key { code, down } => {
                let up = if down { KEYBD_EVENT_FLAGS(0) } else { KEYEVENTF_KEYUP };
                if code == KEY_PAUSE {
                    // Pause has no single scan code (E1 1D 45); use the virtual key.
                    key(VK_PAUSE, 0, up)
                } else {
                    let Some((sc, ext)) = evdev_to_win_scancode(code) else {
                        log::debug!("no Windows mapping for evdev key {code}");
                        return Ok(());
                    };
                    let ext = if ext { KEYEVENTF_EXTENDEDKEY } else { KEYBD_EVENT_FLAGS(0) };
                    key(VIRTUAL_KEY(0), sc, KEYEVENTF_SCANCODE | ext | up)
                }
            }
            InputEvent::ReleaseAll => return Ok(()),
        };
        send(&[input]);
        Ok(())
    }
}

fn send(inputs: &[INPUT]) {
    if inputs.is_empty() {
        return;
    }
    let n = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
    if n as usize != inputs.len() {
        // Typically UIPI blocking input into an elevated window when not running as SYSTEM.
        log::debug!("SendInput injected {n}/{} events", inputs.len());
    }
}
