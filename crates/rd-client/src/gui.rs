//! The windowed client: home screen (this computer + my computers), remote-access setup,
//! PIN sign-in, the remote desktop view with its toolbar and file panel, and the
//! account-management screen.
//!
//! Computers are found on the local network automatically (UDP discovery) and saved with
//! their certificate fingerprint and the addresses they announce, so they can be reached
//! later from anywhere without typing an address.
//!
//! Rendering is egui on OpenGL (glutin). Remote keyboard/mouse input is taken from the
//! raw winit events *before* egui sees them, so physical keys (left/right modifiers,
//! numpad, Caps Lock, ...) reach the host exactly.

use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use egui::{Color32, ColorImage, RichText, TextureHandle, TextureOptions};
use egui_winit::winit;
use rd_core::clipboard;
use rd_core::proto::{ClipData, VideoCodec,
    AdminRequest, AdminResponse, ClientMsg, DeviceInfo, InputEvent, Mode, MouseButton as RButton, Permissions, Role,
    UserInfo,
};
use tokio::sync::{mpsc, oneshot};
use winit::event::{ElementState, MouseButton, MouseScrollDelta, WindowEvent};
use winit::keyboard::PhysicalKey;
use winit::raw_window_handle::HasWindowHandle;

use crate::config::{Computer, HostEntry, Store};
use crate::conn::{self, Creds, Outcome};
use crate::discover::{self, Found};
use crate::setup::{self, SetupRequest};
use crate::keymap;
use crate::session::{self, Direction, TransferState};
use crate::{keyhook, pads, theme, update};

// ======================================================================== app state

/// Where to connect: a computer from "My computers", or an address typed on the
/// command line (`rd-client connect ADDR`).
#[derive(Clone, Debug)]
enum Dest {
    Addr(String),
    Computer(String),
}

impl Dest {
    fn label(&self) -> String {
        match self {
            Dest::Addr(a) => a.clone(),
            Dest::Computer(k) => {
                Store::load().computers.get(k).map(|c| c.name.clone()).unwrap_or_else(|| "the computer".into())
            }
        }
    }
}

struct Attempt {
    target: Dest,
    mode: Mode,
    creds: Creds,
    remember: bool,
}

struct SignInForm {
    target: Dest,
    mode: Mode,
    username: String,
    secret: String,
    use_pin: bool,
    /// Just the PIN (the computer's owner account), as set up from the app.
    pin_only: bool,
    remember: bool,
    message: Option<String>,
    /// Two-step sign-in: the code field is showing.
    need_code: bool,
    code: String,
}

#[derive(Clone)]
struct SetupForm {
    name: String,
    pin: String,
    pin2: String,
    internet: bool,
    /// DuckDNS name (optional), and the one already set up (when changing).
    ddns_name: String,
    ddns_was: String,
    ddns_token: String,
    wake_on_lan: bool,
    /// Ask the person at this computer before anyone connects.
    ask_to_allow: bool,
    /// Changing the name or PIN of a computer that is already set up.
    change: bool,
    error: Option<String>,
}

enum Screen {
    Home,
    Busy(String),
    Trust { fingerprint: String },
    SignIn(SignInForm),
    Setup(SetupForm),
    Session(Box<SessionView>),
    Admin(Box<AdminView>),
}

/// Results of the background network scan.
#[derive(Default)]
struct ScanState {
    found: Vec<Found>,
    /// At least one scan has finished.
    done_once: bool,
    running: bool,
    last: Option<Instant>,
}

type AdminTask = oneshot::Receiver<Result<String, String>>;

/// Seconds between network scans while the home screen is open.
const SCAN_EVERY: Duration = Duration::from_secs(5);

struct SessionView {
    handle: session::Handle,
    /// What was connected to, for Reconnect.
    dest: Dest,
    /// How the connection runs (see `conn::Session::route`).
    route: String,
    /// Frames per second shown in the badge: (since, frames then, rate).
    fps: (Instant, u64, f32),
    /// Full screen: the toolbar slid down (pointer at the top edge or on the bar).
    bar_shown: bool,
    title: String,
    user: UserInfo,
    texture: Option<TextureHandle>,
    image_rect: Option<egui::Rect>,
    remote_size: (u32, u32),
    remote_focus: bool,
    show_files: bool,
    audio_on: bool,
    path_input: String,
    fullscreen: bool,
    /// Pointer is currently over the remote image (and not over a panel).
    remote_hover: bool,
    show_chat: bool,
    chat_input: String,
    /// Lock the remote computer when this session ends.
    lock_on_leave: bool,
    /// System shortcuts (Windows key, Alt+Tab) go to the remote computer.
    shortcuts: bool,
    /// Fit the remote resolution to this window: on, the size last asked for, and when
    /// the window size last changed.
    fit: bool,
    fit_sent: Option<(u32, u32)>,
    view_px: (u32, u32),
    view_changed: Instant,
    /// Gaming mode: pointer locked in the window, relative mouse, controllers forwarded.
    gaming: bool,
    pads: Option<pads::Forwarder>,
    /// The remote computer's name, and its OS (`windows` / `linux`) when known.
    host_name: String,
    remote_os: Option<String>,
    /// Show the picture at its actual size (1:1) instead of fitting it to the window.
    actual_size: bool,
    /// The part of the picture visible in the window (in actual size it can be scrolled).
    image_clip: Option<egui::Rect>,
    /// Connection details shown over the picture.
    show_stats: bool,
    /// A short message shown over the picture (screenshot saved, sound unavailable).
    flash: Option<(String, Instant)>,
    /// The host's status text, and when it last changed (shown for a few seconds).
    status_seen: (String, Instant),
}

type AdminReply = oneshot::Receiver<Result<AdminResponse, String>>;

enum Purpose {
    Users,
    Devices,
    /// Our own account (after two-step sign-in changes).
    Me,
    /// A new two-step secret to show.
    Totp,
    /// A change; on success show the message and refresh lists.
    Change(String),
}

struct AdminView {
    title: String,
    me: UserInfo,
    tx: mpsc::UnboundedSender<(AdminRequest, oneshot::Sender<Result<AdminResponse, String>>)>,
    users: Vec<UserInfo>,
    devices: Vec<DeviceInfo>,
    new_user: (String, String, bool, Permissions),
    my_password: String,
    my_pin: String,
    reset: Option<(String, String)>,
    /// "Remove" was clicked for this user; waiting for the confirmation.
    confirm_remove: Option<String>,
    message: Option<(bool, String)>,
    pending: Vec<(Purpose, AdminReply)>,
    /// Setting up two-step sign-in: (secret, otpauth link), and the code typed.
    totp: Option<(String, String)>,
    totp_code: String,
}

impl AdminView {
    fn request(&mut self, req: AdminRequest, purpose: Purpose) {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send((req, tx));
        self.pending.push((purpose, rx));
    }

    fn refresh(&mut self) {
        if self.me.role == Role::Admin {
            self.request(AdminRequest::ListUsers, Purpose::Users);
        }
        self.request(AdminRequest::ListDevices, Purpose::Devices);
        self.request(AdminRequest::WhoAmI, Purpose::Me);
    }
}

pub struct Gui {
    rt: tokio::runtime::Handle,
    ctx: egui::Context,
    screen: Screen,
    scan: Arc<std::sync::Mutex<ScanState>>,
    /// Setting up / turning off remote access: the result, and the form to return to.
    admin_task: Option<(AdminTask, Option<SetupForm>)>,
    /// Green status message.
    notice: Option<(String, Instant)>,
    toast: Option<(String, Instant)>,
    attempt: Option<Attempt>,
    pending: Option<oneshot::Receiver<Result<Outcome, String>>>,
    /// Clipboard sync for the active session (runs on its own thread).
    clipboard: Option<(clipboard::Worker, std::sync::mpsc::Receiver<ClipData>)>,
    pending_fullscreen: Option<bool>,
    /// "Rename on this device": (computer key, text being edited).
    rename: Option<(String, String)>,
    /// A newer release.
    update: Arc<std::sync::Mutex<Option<update::Release>>>,
    /// Modifier keys held (for Ctrl+Alt+G, which leaves gaming mode).
    mods: winit::keyboard::ModifiersState,
}

/// Ask GitHub for the latest release once per start (set RD_NO_UPDATE_CHECK=1 to skip).
fn check_for_update(rt: &tokio::runtime::Handle, ctx: egui::Context, out: Arc<std::sync::Mutex<Option<update::Release>>>) {
    if std::env::var_os("RD_NO_UPDATE_CHECK").is_some() {
        return;
    }
    rt.spawn(async move {
        if let Ok(Some(r)) = update::check().await {
            *out.lock().unwrap() = Some(r);
            ctx.request_repaint();
        }
    });
}

impl Gui {
    fn new(rt: tokio::runtime::Handle, ctx: egui::Context, autoconnect: Option<String>) -> Self {
        let mut g = Gui {
            rt,
            ctx,
            screen: Screen::Home,
            scan: Arc::default(),
            admin_task: None,
            notice: None,
            toast: None,
            attempt: None,
            pending: None,
            clipboard: None,
            pending_fullscreen: None,
            rename: None,
            update: Arc::default(),
            mods: Default::default(),
        };
        check_for_update(&g.rt, g.ctx.clone(), g.update.clone());
        if let Some(t) = autoconnect {
            g.start(Attempt { target: Dest::Addr(t), mode: Mode::Desktop, creds: Creds::Saved(None), remember: false });
        }
        g
    }

    fn toast(&mut self, msg: impl Into<String>) {
        self.toast = Some((msg.into(), Instant::now()));
    }

    /// Kick off a connection attempt on the runtime.
    fn start(&mut self, attempt: Attempt) {
        self.start_with_trust(attempt, None);
    }

    fn start_with_trust(&mut self, attempt: Attempt, trust: Option<String>) {
        let (tx, rx) = oneshot::channel();
        let (target, mode, creds, remember) =
            (attempt.target.clone(), attempt.mode, attempt.creds.clone(), attempt.remember);
        let ctx = self.ctx.clone();
        self.rt.spawn(async move {
            let r = match &target {
                Dest::Addr(t) => conn::connect_flow(t, mode, creds, remember, trust).await,
                Dest::Computer(k) => conn::connect_computer(k, mode, creds, remember).await,
            }
            .map_err(|e| format!("{e:#}"));
            let _ = tx.send(r);
            ctx.request_repaint();
        });
        self.screen = Screen::Busy(format!("Connecting to {}...", attempt.target.label()));
        self.attempt = Some(attempt);
        self.pending = Some(rx);
    }

    fn poll_pending(&mut self) {
        let Some(rx) = self.pending.as_mut() else { return };
        let result = match rx.try_recv() {
            Ok(r) => r,
            Err(oneshot::error::TryRecvError::Empty) => return,
            Err(_) => Err("connection task failed".into()),
        };
        self.pending = None;
        let attempt = self.attempt.take().expect("attempt");
        match result {
            Err(e) => {
                self.screen = Screen::Home;
                self.toast(e);
            }
            Ok(Outcome::NeedTrust(fingerprint)) => {
                self.attempt = Some(attempt);
                self.screen = Screen::Trust { fingerprint };
            }
            Ok(Outcome::NeedCredentials { username, message }) => {
                let computer = matches!(attempt.target, Dest::Computer(_));
                self.screen = Screen::SignIn(SignInForm {
                    target: attempt.target,
                    mode: attempt.mode,
                    username: username.unwrap_or_default(),
                    secret: String::new(),
                    use_pin: computer,
                    pin_only: computer,
                    remember: true,
                    message,
                    need_code: false,
                    code: String::new(),
                });
            }
            Ok(Outcome::NeedCode) => {
                // Same sign-in again, now with the authenticator app's code.
                let (username, secret, use_pin, had_code) = match &attempt.creds {
                    Creds::Password { username, password, code } => (username.clone(), password.clone(), false, code.is_some()),
                    Creds::Pin { username, pin, code } => (username.clone(), pin.clone(), true, code.is_some()),
                    Creds::Saved(u) => (u.clone().unwrap_or_default(), String::new(), false, false),
                };
                let pin_only = use_pin && username.is_empty();
                self.screen = Screen::SignIn(SignInForm {
                    target: attempt.target,
                    mode: attempt.mode,
                    username,
                    secret,
                    use_pin,
                    pin_only,
                    remember: attempt.remember,
                    message: had_code.then(|| "Enter the code from your authenticator app.".to_string()),
                    need_code: true,
                    code: String::new(),
                });
            }
            Ok(Outcome::Denied(why)) => {
                let (username, use_pin) = match &attempt.creds {
                    Creds::Password { username, .. } => (username.clone(), false),
                    Creds::Pin { username, .. } => (username.clone(), true),
                    Creds::Saved(u) => (u.clone().unwrap_or_default(), false),
                };
                let pin_only = use_pin && matches!(attempt.target, Dest::Computer(_));
                let had_code = matches!(&attempt.creds, Creds::Pin { code: Some(_), .. } | Creds::Password { code: Some(_), .. });
                let why = if had_code && why == "invalid username or credentials" {
                    "The PIN, password or code is wrong. Use the newest code from your app.".to_string()
                } else {
                    why
                };
                self.screen = Screen::SignIn(SignInForm {
                    target: attempt.target,
                    mode: attempt.mode,
                    username,
                    secret: String::new(),
                    use_pin,
                    pin_only,
                    remember: attempt.remember,
                    message: Some(why),
                    need_code: had_code,
                    code: String::new(),
                });
            }
            Ok(Outcome::Ok(s)) => match attempt.mode {
                Mode::Desktop => {
                    let title = if s.route == "direct" {
                        format!("{} @ {}", s.user.username, s.host_name)
                    } else {
                        format!("{} @ {} · {}", s.user.username, s.host_name, s.route)
                    };
                    let user = s.user.clone();
                    let s_control = user.effective().control;
                    let route = s.route.clone();
                    let host_name = s.host_name.clone();
                    let ctx = self.ctx.clone();
                    let handle = session::Handle::start(&self.rt, s, move || ctx.request_repaint());
                    let store = Store::load();
                    handle.send(ClientMsg::SetCodec(store.video_codec()));
                    let lock_on_leave = store.lock_on_leave.unwrap_or(true);
                    handle.send(ClientMsg::LockOnLeave(lock_on_leave));
                    let remote_os = match &attempt.target {
                        Dest::Computer(k) => store.computers.get(k).and_then(|c| c.os.clone()),
                        _ => None,
                    };
                    self.screen = Screen::Session(Box::new(SessionView {
                        handle,
                        dest: attempt.target.clone(),
                        route,
                        fps: (Instant::now(), 0, 0.0),
                        bar_shown: false,
                        title,
                        user,
                        texture: None,
                        image_rect: None,
                        remote_size: (0, 0),
                        remote_focus: true,
                        show_files: false,
                        audio_on: false,
                        path_input: String::new(),
                        fullscreen: false,
                        remote_hover: false,
                        show_chat: false,
                        chat_input: String::new(),
                        lock_on_leave,
                        shortcuts: store.system_shortcuts && s_control,
                        fit: store.fit_resolution && s_control,
                        fit_sent: None,
                        view_px: (0, 0),
                        view_changed: Instant::now(),
                        gaming: false,
                        pads: None,
                        host_name,
                        remote_os,
                        actual_size: store.actual_size,
                        image_clip: None,
                        show_stats: store.show_stats,
                        flash: None,
                        status_seen: (String::new(), Instant::now()),
                    }));
                }
                Mode::Admin => {
                    let (tx, mut rx) =
                        mpsc::unbounded_channel::<(AdminRequest, oneshot::Sender<Result<AdminResponse, String>>)>();
                    let title = format!("{} @ {}", s.user.username, s.host_name);
                    let me = s.user.clone();
                    let mut stream = s.stream;
                    let ctx = self.ctx.clone();
                    self.rt.spawn(async move {
                        while let Some((req, reply)) = rx.recv().await {
                            let r = async {
                                rd_core::framing::write_msg(&mut stream, &req).await?;
                                rd_core::framing::read_msg::<_, AdminResponse>(&mut stream).await
                            }
                            .await
                            .map_err(|e| format!("{e:#}"));
                            let _ = reply.send(r);
                            ctx.request_repaint();
                        }
                    });
                    let mut view = AdminView {
                        title,
                        me,
                        tx,
                        users: vec![],
                        devices: vec![],
                        new_user: (String::new(), String::new(), false, Permissions::FULL),
                        my_password: String::new(),
                        my_pin: String::new(),
                        reset: None,
                        confirm_remove: None,
                        message: None,
                        pending: vec![],
                        totp: None,
                        totp_code: String::new(),
                    };
                    view.refresh();
                    self.screen = Screen::Admin(Box::new(view));
                }
            },
        }
    }

    /// Scan the network every few seconds while the home screen is showing.
    fn maybe_scan(&mut self) {
        if !matches!(self.screen, Screen::Home | Screen::Setup(_)) {
            return;
        }
        {
            let mut st = self.scan.lock().unwrap();
            if st.running || st.last.is_some_and(|t| t.elapsed() < SCAN_EVERY) {
                return;
            }
            st.running = true;
        }
        let scan = self.scan.clone();
        let ctx = self.ctx.clone();
        self.rt.spawn(async move {
            let found = discover::scan(rd_core::DEFAULT_PORT, Duration::from_millis(1200)).await;
            remember_found(&found);
            let mut st = scan.lock().unwrap();
            st.found = found;
            st.done_once = true;
            st.running = false;
            st.last = Some(Instant::now());
            ctx.request_repaint();
        });
        self.ctx.request_repaint_after(SCAN_EVERY);
    }

    /// Run the installer (or uninstaller) elevated, off the UI thread.
    fn run_admin_task(&mut self, busy: &str, back_to: Option<SetupForm>, f: impl FnOnce() -> anyhow::Result<String> + Send + 'static) {
        let (tx, rx) = oneshot::channel();
        let ctx = self.ctx.clone();
        self.rt.spawn_blocking(move || {
            let _ = tx.send(f().map_err(|e| format!("{e:#}")));
            ctx.request_repaint();
        });
        self.admin_task = Some((rx, back_to));
        self.screen = Screen::Busy(busy.into());
    }

    fn poll_admin_task(&mut self) {
        let Some((rx, _)) = self.admin_task.as_mut() else { return };
        let r = match rx.try_recv() {
            Ok(r) => r,
            Err(oneshot::error::TryRecvError::Empty) => return,
            Err(_) => Err("the setup task stopped unexpectedly".into()),
        };
        let (_, back_to) = self.admin_task.take().unwrap();
        // Rescan now so "This computer" reflects the change.
        self.scan.lock().unwrap().last = None;
        match (r, back_to) {
            (Ok(msg), _) => {
                self.notice = Some((msg, Instant::now()));
                self.screen = Screen::Home;
            }
            (Err(e), Some(mut form)) => {
                form.error = Some(e);
                self.screen = Screen::Setup(form);
            }
            (Err(e), None) => {
                self.toast(e);
                self.screen = Screen::Home;
            }
        }
    }

    /// Two-way clipboard sync for the active session.
    /// Text, images and copied files; the polling, PNG and file reading happen on the
    /// worker's thread so a large copy never stalls the UI.
    fn sync_clipboard(&mut self) {
        let Screen::Session(v) = &mut self.screen else {
            self.clipboard = None;
            return;
        };
        let open = v.handle.state.lock().unwrap().closed.is_none();
        if !v.user.effective().clipboard || !open {
            self.clipboard = None;
            return;
        }
        let (worker, local) = self.clipboard.get_or_insert_with(|| {
            let (tx, rx) = std::sync::mpsc::channel();
            let ctx = self.ctx.clone();
            let w = clipboard::Worker::spawn(false, move |d| {
                let ok = tx.send(d).is_ok();
                ctx.request_repaint();
                ok
            });
            (w, rx)
        });
        if let Some(data) = v.handle.state.lock().unwrap().incoming_clipboard.take() {
            worker.set(data);
        }
        let files_ok = v.user.effective().files;
        while let Ok(data) = local.try_recv() {
            // Copied files also need the files permission; the host would drop them.
            if files_ok || !data.is_files() {
                v.handle.send(ClientMsg::Clipboard(data));
            }
        }
    }

    // ------------------------------------------------------------------ raw input

    /// Returns true if the event was consumed by the remote session.
    fn remote_input(&mut self, event: &WindowEvent, ppp: f32, egui_wants_keyboard: bool) -> bool {
        let Screen::Session(v) = &mut self.screen else { return false };
        if v.handle.state.lock().unwrap().closed.is_some() {
            return false;
        }
        let control = v.user.effective().control;
        if let WindowEvent::ModifiersChanged(m) = event {
            self.mods = m.state();
        }
        // Ctrl+Alt+G leaves gaming mode (the pointer is locked in the window).
        if let WindowEvent::KeyboardInput { event: k, .. } = event {
            if v.gaming
                && k.state == ElementState::Pressed
                && k.physical_key == PhysicalKey::Code(winit::keyboard::KeyCode::KeyG)
                && self.mods.control_key()
                && self.mods.alt_key()
            {
                v.gaming = false;
                v.pads = None;
                return true;
            }
            // F11 leaves full screen even while the keyboard goes to the remote computer
            // (otherwise the remote side swallows it and the hint on the button is a lie).
            if v.fullscreen && k.physical_key == PhysicalKey::Code(winit::keyboard::KeyCode::F11) {
                if k.state == ElementState::Pressed && !k.repeat {
                    v.fullscreen = false;
                    v.bar_shown = false;
                    self.pending_fullscreen = Some(false);
                    self.ctx.request_repaint();
                }
                return true;
            }
        }
        if v.gaming {
            // Relative motion comes from raw device events (App::device_event).
            if matches!(event, WindowEvent::CursorMoved { .. }) {
                return true;
            }
            v.remote_hover = true;
            v.remote_focus = true;
        }
        let to_remote = |v: &SessionView, x: f64, y: f64| -> Option<(u32, u32)> {
            let r = v.image_rect?;
            let p = egui::pos2(x as f32 / ppp, y as f32 / ppp);
            if !r.contains(p) || !v.image_clip.is_none_or(|c| c.contains(p)) || v.remote_size.0 == 0 {
                return None;
            }
            let rx = ((p.x - r.min.x) / r.width() * v.remote_size.0 as f32).clamp(0.0, v.remote_size.0 as f32 - 1.0);
            let ry = ((p.y - r.min.y) / r.height() * v.remote_size.1 as f32).clamp(0.0, v.remote_size.1 as f32 - 1.0);
            Some((rx as u32, ry as u32))
        };
        match event {
            WindowEvent::CursorMoved { position, .. } => {
                if let Some((x, y)) = to_remote(v, position.x, position.y) {
                    if control {
                        v.handle.send(ClientMsg::Input(InputEvent::MouseMove { x, y }));
                    }
                }
                false // egui still tracks the pointer for hover effects
            }
            WindowEvent::MouseInput { state, button, .. } => {
                let over = v.last_pointer_over_image(ppp);
                if *state == ElementState::Pressed {
                    v.remote_focus = over;
                }
                if !over || !control {
                    return false;
                }
                let button = match button {
                    MouseButton::Left => RButton::Left,
                    MouseButton::Right => RButton::Right,
                    MouseButton::Middle => RButton::Middle,
                    MouseButton::Back => RButton::Back,
                    MouseButton::Forward => RButton::Forward,
                    MouseButton::Other(_) => return true,
                };
                v.handle.send(ClientMsg::Input(InputEvent::MouseButton { button, down: *state == ElementState::Pressed }));
                true
            }
            WindowEvent::MouseWheel { delta, .. } => {
                if !v.last_pointer_over_image(ppp) || !control {
                    return false;
                }
                let (dx, dy) = match delta {
                    MouseScrollDelta::LineDelta(x, y) => ((x * 120.0) as i32, (y * 120.0) as i32),
                    MouseScrollDelta::PixelDelta(p) => ((p.x * 3.0) as i32, (p.y * 3.0) as i32),
                };
                if dx != 0 || dy != 0 {
                    v.handle.send(ClientMsg::Input(InputEvent::Wheel { dx, dy }));
                }
                true
            }
            WindowEvent::KeyboardInput { event, .. } => {
                if !v.remote_focus || egui_wants_keyboard || !control {
                    return false;
                }
                // Windows doesn't repeat a key that is held down by injected input, so a held
                // key (Backspace, arrows) has to be repeated from here. Linux desktops repeat
                // held keys themselves, and repeating them here too would double the rate.
                let repeat_ok = v.remote_os.as_deref() == Some("windows") && event.state == ElementState::Pressed;
                if !event.repeat || repeat_ok {
                    if let PhysicalKey::Code(code) = event.physical_key {
                        if let Some(evdev) = keymap::evdev(code) {
                            v.handle.send(ClientMsg::Input(InputEvent::Key {
                                code: evdev,
                                down: event.state == ElementState::Pressed,
                            }));
                        }
                    }
                }
                true
            }
            WindowEvent::Focused(false) => {
                v.handle.send(ClientMsg::Input(InputEvent::ReleaseAll));
                false
            }
            WindowEvent::DroppedFile(path) => {
                if v.user.effective().files {
                    v.handle.upload(path.clone());
                    v.show_files = true;
                }
                true
            }
            _ => false,
        }
    }

    // ------------------------------------------------------------------ UI

    fn ui(&mut self, ctx: &egui::Context) {
        self.poll_pending();
        self.poll_admin_task();
        self.sync_clipboard();
        self.maybe_scan();
        // Messages float above the bottom edge and fade on their own (click to dismiss).
        show_toast(ctx, &mut self.notice, theme::SUCCESS, "notice", 0.0);
        let lift = if self.notice.is_some() { 56.0 } else { 0.0 };
        show_toast(ctx, &mut self.toast, theme::DANGER, "toast", lift);
        if matches!(self.screen, Screen::Home) {
            let release = self.update.lock().unwrap().clone();
            if let Some(r) = release {
                let mut go = false;
                egui::TopBottomPanel::top("update")
                    .frame(egui::Frame::new().fill(theme::ACCENT.gamma_multiply(0.18)).inner_margin(egui::Margin::symmetric(16, 8)))
                    .show(ctx, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("Version {} is available.", r.version)).strong());
                            if r.asset.is_some() {
                                go = ui
                                    .add(theme::primary("Update now"))
                                    .on_hover_text("Downloads it, checks it, and updates the app and this computer's service")
                                    .clicked();
                            }
                            ui.hyperlink_to("Release notes", &r.page);
                        });
                    });
                if go {
                    let rt = self.rt.clone();
                    let busy = if cfg!(windows) {
                        "Updating... approve the Windows administrator prompt."
                    } else {
                        "Updating... enter your password when asked."
                    };
                    *self.update.lock().unwrap() = None;
                    self.run_admin_task(busy, None, move || update::install(&rt, &r));
                }
            }
        }
        let mut next: Option<Screen> = None;
        let mut new_attempt: Option<(Attempt, Option<String>)> = None;
        let mut admin: Option<HomeAction> = None;

        match &mut self.screen {
            Screen::Home => {
                let scan = self.scan.lock().unwrap();
                match home_ui(ctx, &scan, &mut self.notice, &mut self.rename) {
                    Some(HomeAction::Connect(a)) => new_attempt = Some((a, None)),
                    Some(a) => admin = Some(a),
                    None => {}
                }
            }
            Screen::Setup(form) => match setup_ui(ctx, form) {
                Some(true) => {
                    admin = Some(HomeAction::RunSetup(form.clone()));
                }
                Some(false) => next = Some(Screen::Home),
                None => {}
            },
            Screen::Busy(msg) => {
                let msg = msg.clone();
                // A connection attempt can be abandoned; an elevated setup task can't.
                let cancellable = self.pending.is_some();
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(ui.available_height() / 3.0);
                        ui.add(egui::Spinner::new().size(32.0).color(theme::ACCENT));
                        ui.add_space(12.0);
                        ui.label(RichText::new(msg).size(16.0));
                        if cancellable {
                            ui.add_space(16.0);
                            if ui.button("Cancel").clicked() {
                                // Dropping the receiver abandons the attempt's result.
                                self.pending = None;
                                self.attempt = None;
                                next = Some(Screen::Home);
                            }
                        }
                    });
                });
            }
            Screen::Trust { fingerprint } => {
                let fp = fingerprint.clone();
                let target = self.attempt.as_ref().map(|a| a.target.label()).unwrap_or_default();
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.add_space(60.0);
                    dialog(ui, 480.0, |ui| {
                        theme::card().show(ui, |ui| {
                            ui.heading("Is this the right computer?");
                            ui.add_space(4.0);
                            ui.label(format!("This is the first time you connect to {target}."));
                            ui.add_space(8.0);
                            ui.label(theme::hint("Check that this fingerprint matches what `rd-host info` shows on that computer:"));
                            egui::Frame::new()
                                .fill(theme::BG)
                                .corner_radius(6)
                                .inner_margin(egui::Margin::same(10))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.add(egui::Label::new(RichText::new(&fp).monospace().strong()).wrap());
                                });
                            ui.add_space(12.0);
                            ui.horizontal(|ui| {
                                if ui.add(theme::primary("Trust and continue")).clicked() {
                                    if let Some(a) = self.attempt.take() {
                                        new_attempt = Some((a, Some(fp.clone())));
                                    }
                                }
                                if ui.button("Cancel").clicked() {
                                    self.attempt = None;
                                    next = Some(Screen::Home);
                                }
                            });
                        });
                    });
                });
            }
            Screen::SignIn(form) => {
                if let Some(action) = sign_in_ui(ctx, form) {
                    match action {
                        Some(a) => new_attempt = Some((a, None)),
                        None => next = Some(Screen::Home),
                    }
                }
            }
            Screen::Session(v) => match session_ui(ctx, v) {
                Some(SessionAction::Close) => next = Some(Screen::Home),
                Some(SessionAction::Fullscreen(on)) => self.pending_fullscreen = Some(on),
                Some(SessionAction::Reconnect) => {
                    let a = Attempt { target: v.dest.clone(), mode: Mode::Desktop, creds: Creds::Saved(None), remember: false };
                    self.pending_fullscreen = Some(false);
                    new_attempt = Some((a, None));
                }
                None => {}
            },
            Screen::Admin(v) => {
                if admin_ui(ctx, v) {
                    next = Some(Screen::Home);
                }
            }
        }

        if let Some((a, trust)) = new_attempt {
            self.start_with_trust(a, trust);
        }
        match admin {
            Some(HomeAction::OpenSetup(form)) => next = Some(Screen::Setup(form)),
            Some(HomeAction::RunSetup(form)) => {
                // (Checked in setup_ui already.)
                let (ddns, ddns_off) = setup_ddns(&form).unwrap_or((None, false));
                let req = SetupRequest {
                    name: form.name.trim().to_string(),
                    pin: form.pin.clone(),
                    internet: form.internet,
                    ddns,
                    ddns_off,
                    wake_on_lan: form.wake_on_lan,
                    ask_to_allow: form.ask_to_allow,
                };
                let mut back = form.clone();
                back.pin.clear();
                back.pin2.clear();
                back.ddns_token.clear();
                let what = if form.change { "Saved." } else { "Remote access is on." };
                let busy = if cfg!(windows) {
                    "Setting up remote access... approve the Windows administrator prompt."
                } else {
                    "Setting up remote access... enter your password when asked."
                };
                let name = req.name.clone();
                self.run_admin_task(busy, Some(back), move || {
                    setup::set_up(&req)?;
                    Ok(format!("{what} This computer is called \"{name}\"."))
                });
            }
            Some(HomeAction::TurnOff) => {
                self.run_admin_task("Turning off remote access...", None, || {
                    setup::turn_off()?;
                    Ok("Remote access is off for this computer.".into())
                });
            }
            Some(HomeAction::Connect(_)) | None => {}
        }
        if let Some(s) = next {
            if matches!(self.screen, Screen::Session(_)) {
                self.pending_fullscreen = Some(false);
            }
            self.screen = s;
        }
    }

    fn window_title(&self) -> String {
        match &self.screen {
            Screen::Session(v) => format!("{} - RD", v.title),
            Screen::Admin(v) => format!("Accounts: {} - RD", v.title),
            _ => "RD Remote Desktop".into(),
        }
    }
}

/// What the mouse pointer should look like right now.
#[derive(Clone)]
enum WantedCursor {
    /// The normal local pointer (egui decides).
    Os,
    /// Hidden: the remote pointer is drawn into the picture, or hidden on the host.
    Hidden,
    /// The remote pointer's shape: (change counter, scale, shape).
    Remote(u64, f32, Arc<rd_core::proto::CursorShape>),
}

impl Gui {
    /// Over the remote picture the pointer takes the remote computer's shape.
    fn wanted_cursor(&self) -> WantedCursor {
        let Screen::Session(v) = &self.screen else { return WantedCursor::Os };
        if !v.remote_hover {
            return WantedCursor::Os;
        }
        let s = v.handle.state.lock().unwrap();
        if s.closed.is_some() {
            return WantedCursor::Os;
        }
        match &s.cursor {
            None => WantedCursor::Os,
            Some(rd_core::proto::CursorShape::Image { .. }) => {
                // Scale with the picture, so the pointer keeps its size relative to the screen.
                let scale = match v.image_rect {
                    Some(r) if v.remote_size.0 > 0 => r.width() * self.ctx.pixels_per_point() / v.remote_size.0 as f32,
                    _ => 1.0,
                };
                WantedCursor::Remote(s.cursor_seq, scale.clamp(0.5, 2.0), Arc::new(s.cursor.clone().unwrap()))
            }
            Some(_) => WantedCursor::Hidden,
        }
    }
}

/// RGBA cursor scaled by `scale` (nearest neighbour), with its hotspot.
fn scaled_cursor(shape: &rd_core::proto::CursorShape, scale: f32) -> Option<(Vec<u8>, u16, u16, u16, u16)> {
    let rd_core::proto::CursorShape::Image { width, height, hot_x, hot_y, rgba } = shape else { return None };
    let s = if (scale - 1.0).abs() < 0.15 { 1.0 } else { scale };
    let (w, h) = (((*width as f32 * s).round() as u32).max(1), ((*height as f32 * s).round() as u32).max(1));
    let mut out = Vec::with_capacity((w * h * 4) as usize);
    for y in 0..h {
        let sy = ((y as f32 / s) as u32).min(height - 1);
        for x in 0..w {
            let sx = ((x as f32 / s) as u32).min(width - 1);
            let i = ((sy * width + sx) * 4) as usize;
            out.extend_from_slice(&rgba[i..i + 4]);
        }
    }
    let hx = ((*hot_x as f32 * s) as u32).min(w - 1);
    let hy = ((*hot_y as f32 * s) as u32).min(h - 1);
    Some((out, w as u16, h as u16, hx as u16, hy as u16))
}

impl SessionView {
    fn last_pointer_over_image(&self, _ppp: f32) -> bool {
        // Updated every frame from egui's pointer position (see session_ui).
        self.remote_hover
    }
}

#[derive(PartialEq)]
enum SessionAction {
    Close,
    Fullscreen(bool),
    Reconnect,
}

// ======================================================================== screens

enum HomeAction {
    Connect(Attempt),
    OpenSetup(SetupForm),
    RunSetup(SetupForm),
    TurnOff,
}

/// Save fresh addresses for computers already in "My computers".
fn remember_found(found: &[Found]) {
    let mut store = Store::load();
    let mut changed = false;
    for f in found.iter().filter(|f| !f.local) {
        let Some(c) = store.computers.get_mut(&f.announce.fingerprint.to_ascii_lowercase()) else { continue };
        let mut updated = c.clone();
        updated.update_from(&f.announce, f.addr);
        let before = serde_json::to_string(&*c).unwrap_or_default();
        if serde_json::to_string(&updated).unwrap_or_default() != before {
            *c = updated;
            changed = true;
        }
    }
    if changed {
        let _ = store.save();
    }
}

/// A computer found on the network becomes a saved computer the first time you connect.
fn save_found(f: &Found) -> String {
    let key = f.announce.fingerprint.to_ascii_lowercase();
    let mut store = Store::load();
    let c = store.computers.entry(key.clone()).or_insert_with(|| Computer {
        // Pinned exactly as the TLS verifier spells it.
        auth: HostEntry { fingerprint: Some(f.announce.fingerprint.clone()), ..Default::default() },
        ..Default::default()
    });
    c.update_from(&f.announce, f.addr);
    let _ = store.save();
    key
}

/// A small filled circle (the UI font has no bullet glyph).
fn status_dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, color);
}

/// A message card floating above the bottom of the window, gone after 8 seconds or a click.
fn show_toast(ctx: &egui::Context, slot: &mut Option<(String, Instant)>, color: Color32, id: &str, lift: f32) {
    let Some((msg, at)) = slot.as_ref() else { return };
    if at.elapsed() > Duration::from_secs(8) {
        *slot = None;
        return;
    }
    let r = egui::Area::new(egui::Id::new(id))
        .order(egui::Order::Foreground)
        .anchor(egui::Align2::CENTER_BOTTOM, [0.0, -20.0 - lift])
        .interactable(true)
        .show(ctx, |ui| {
            egui::Frame::new()
                .fill(theme::SURFACE_HI)
                .stroke(egui::Stroke::new(1.0, color.gamma_multiply(0.6)))
                .corner_radius(8)
                .inner_margin(egui::Margin::symmetric(14, 10))
                .shadow(egui::Shadow { offset: [0, 4], blur: 16, spread: 0, color: Color32::from_black_alpha(120) })
                .show(ui, |ui| {
                    ui.set_max_width((ctx.screen_rect().width() - 80.0).clamp(200.0, 560.0));
                    ui.horizontal(|ui| {
                        status_dot(ui, color);
                        ui.add(egui::Label::new(msg.as_str()).wrap());
                    });
                })
                .response
                .interact(egui::Sense::click())
                .on_hover_cursor(egui::CursorIcon::PointingHand)
        });
    if r.inner.clicked() {
        *slot = None;
    }
    ctx.request_repaint_after(Duration::from_secs(1));
}

/// A tiny folder, drawn (the UI font has no folder symbol).
fn folder_icon(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 14.0), egui::Sense::hover());
    let p = ui.painter();
    let c = theme::WARNING;
    p.rect_filled(egui::Rect::from_min_size(rect.min + egui::vec2(1.0, 2.0), egui::vec2(6.0, 3.0)), 1.0, c);
    p.rect_filled(egui::Rect::from_min_max(rect.min + egui::vec2(1.0, 4.0), rect.max - egui::vec2(1.0, 1.0)), 2.0, c);
}

/// "5 minutes ago".
fn ago(unix: u64) -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let s = now.saturating_sub(unix);
    let plural = |n: u64, unit: &str| format!("{n} {unit}{} ago", if n == 1 { "" } else { "s" });
    match s {
        0..=59 => "just now".into(),
        60..=3599 => plural(s / 60, "minute"),
        3600..=86_399 => plural(s / 3600, "hour"),
        86_400..=2_591_999 => plural(s / 86_400, "day"),
        _ => plural(s / 2_592_000, "month"),
    }
}

/// A small Windows or Linux mark (drawn, so it doesn't depend on the font's symbols).
fn os_icon(ui: &mut egui::Ui, os: Option<&str>) {
    if !matches!(os, Some("windows" | "linux")) {
        return; // no empty gap where the icon would be
    }
    let (rect, resp) = ui.allocate_exact_size(egui::vec2(16.0, 16.0), egui::Sense::hover());
    let p = ui.painter();
    let c = rect.center();
    match os {
        Some("windows") => {
            let blue = Color32::from_rgb(0, 120, 215);
            for (dx, dy) in [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
                let q = egui::Rect::from_center_size(c + egui::vec2(dx * 3.5, dy * 3.5), egui::vec2(6.0, 6.0));
                p.rect_filled(q, 0.0, blue);
            }
            resp.on_hover_text("Windows");
        }
        Some("linux") => {
            // A little penguin: dark body, white belly, orange beak.
            p.add(egui::Shape::ellipse_filled(c, egui::vec2(5.5, 7.0), Color32::from_gray(40)));
            p.add(egui::Shape::ellipse_filled(c + egui::vec2(0.0, 2.0), egui::vec2(3.5, 4.5), Color32::from_gray(235)));
            p.circle_filled(c + egui::vec2(0.0, -3.5), 1.5, Color32::from_rgb(240, 170, 40));
            resp.on_hover_text("Linux");
        }
        _ => {}
    }
}

fn home_ui(
    ctx: &egui::Context,
    scan: &ScanState,
    notice: &mut Option<(String, Instant)>,
    rename: &mut Option<(String, String)>,
) -> Option<HomeAction> {
    let mut out = None;
    let store = Store::load();
    let green = theme::SUCCESS;
    let grey = theme::MUTED;

    egui::TopBottomPanel::top("header")
        .frame(egui::Frame::new().fill(theme::SURFACE).inner_margin(egui::Margin::symmetric(20, 12)).stroke(egui::Stroke::new(1.0, theme::BORDER)))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                app_mark(ui);
                ui.label(RichText::new("RD Remote Desktop").size(18.0).strong().color(Color32::WHITE));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(theme::hint(format!("v{}", env!("CARGO_PKG_VERSION"))));
                });
            });
        });

    egui::CentralPanel::default().frame(egui::Frame::new().fill(theme::BG).inner_margin(egui::Margin::symmetric(16, 20))).show(ctx, |ui| {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            dialog(ui, 720.0, |ui| {
                // ---------------------------------------------------- this computer
                ui.label(theme::section("This computer"));
                ui.add_space(2.0);
                theme::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    let me = scan.found.iter().find(|f| f.local);
                    match me {
                        Some(f) => {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&f.announce.name).size(17.0).strong().color(Color32::WHITE));
                                theme::pill(ui, green, "Remote access on");
                            });
                            match (&f.announce.public, &f.announce.public_note) {
                                (Some(p), note) => {
                                    ui.label(theme::hint(format!("Reachable from the internet (router forwards {p}).")));
                                    if let Some(n) = note {
                                        ui.label(RichText::new(format!("Note: {n}.")).small().color(theme::WARNING));
                                    }
                                }
                                (None, Some(n)) => {
                                    ui.label(theme::hint(format!("Only reachable on this network: {n}.")));
                                }
                                (None, None) => {
                                    ui.label(theme::hint("Checking the router..."));
                                }
                            }
                            ui.add_space(6.0);
                            ui.horizontal(|ui| {
                                if ui.button("Change name or PIN").clicked() {
                                    let ddns = f
                                        .announce
                                        .public_name
                                        .as_deref()
                                        .and_then(|n| n.rsplit_once(':').map(|(h, _)| h))
                                        .map(|h| h.strip_suffix(setup::DUCKDNS_SUFFIX).unwrap_or(h).to_string())
                                        .unwrap_or_default();
                                    out = Some(HomeAction::OpenSetup(SetupForm {
                                        name: f.announce.name.clone(),
                                        pin: String::new(),
                                        pin2: String::new(),
                                        ddns_name: ddns.clone(),
                                        ddns_was: ddns,
                                        ddns_token: String::new(),
                                        wake_on_lan: true,
                                        ask_to_allow: f.announce.ask_to_allow,
                                        internet: f.announce.public_note.as_deref() != Some("access from the internet is turned off"),
                                        change: true,
                                        error: None,
                                    }));
                                }
                                if ui.button("Turn off").on_hover_text("Stop accepting remote connections to this computer").clicked() {
                                    out = Some(HomeAction::TurnOff);
                                }
                            });
                        }
                        None if !scan.done_once => {
                            ui.horizontal(|ui| {
                                ui.spinner();
                                ui.label(theme::hint("Checking..."));
                            });
                        }
                        None => {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(setup::default_name()).size(17.0).strong().color(Color32::WHITE));
                                theme::pill(ui, grey, "Remote access off");
                            });
                            ui.label(theme::hint("Set it up to connect to this computer from your other devices."));
                            ui.add_space(6.0);
                            if ui.add(theme::primary("Set up remote access")).clicked() {
                                out = Some(HomeAction::OpenSetup(SetupForm {
                                    name: setup::default_name(),
                                    pin: String::new(),
                                    pin2: String::new(),
                                    ddns_name: String::new(),
                                    ddns_was: String::new(),
                                    ddns_token: String::new(),
                                    wake_on_lan: true,
                                    ask_to_allow: false,
                                    internet: true,
                                    change: false,
                                    error: None,
                                }));
                            }
                        }
                    }
                });
                ui.add_space(22.0);

                // ---------------------------------------------------- my computers
                // Saved computers, plus ones found on the network that aren't saved yet.
                struct Row {
                    key: String,
                    /// Shown name (renamed on this device, or its own).
                    name: String,
                    /// Its own name.
                    real_name: String,
                    online: Option<Found>,
                    saved: Option<Computer>,
                }
                let mut rows: Vec<Row> = store
                    .computers
                    .iter()
                    .map(|(k, c)| Row {
                        key: k.clone(),
                        name: c.label().to_string(),
                        real_name: c.name.clone(),
                        online: scan.found.iter().find(|f| f.announce.fingerprint.eq_ignore_ascii_case(k)).cloned(),
                        saved: Some(c.clone()),
                    })
                    .collect();
                for f in &scan.found {
                    let k = f.announce.fingerprint.to_ascii_lowercase();
                    if !store.computers.contains_key(&k) {
                        let n = f.announce.name.clone();
                        rows.push(Row { key: k, name: n.clone(), real_name: n, online: Some(f.clone()), saved: None });
                    }
                }
                rows.retain(|r| !r.online.as_ref().is_some_and(|f| f.local));
                // A computer you tried but never got into, and that has gone away, isn't worth listing.
                rows.retain(|r| r.online.is_some() || r.saved.as_ref().is_some_and(|c| c.auth.username.is_some()));
                let online_names: Vec<String> =
                    rows.iter().filter(|r| r.online.is_some()).map(|r| r.real_name.to_lowercase()).collect();
                rows.sort_by_key(|r| (r.online.is_none(), r.name.to_lowercase()));

                ui.horizontal(|ui| {
                    ui.label(theme::section("My computers"));
                    if !rows.is_empty() {
                        ui.label(theme::hint(rows.len().to_string()));
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if scan.running {
                            ui.add(egui::Spinner::new().size(14.0).color(grey)).on_hover_text("Looking for computers on your network");
                        }
                    });
                });
                ui.add_space(2.0);
                if rows.is_empty() {
                    theme::card().show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.vertical_centered(|ui| {
                            ui.add_space(8.0);
                            if scan.done_once {
                                ui.label(RichText::new("No other computers yet").strong());
                                ui.label(theme::hint(
                                    "Set up remote access on another computer with this app. It shows up here while it's on the same network, and stays here afterwards.",
                                ));
                            } else {
                                ui.spinner();
                                ui.label(theme::hint("Looking for computers on your network..."));
                            }
                            ui.add_space(8.0);
                        });
                    });
                }
                for row in rows {
                    let (dot, status) = match (&row.online, &row.saved) {
                        (Some(_), _) => (green, "Online on this network".to_string()),
                        (None, _) if online_names.contains(&row.real_name.to_lowercase()) => {
                            (theme::WARNING, "Older setup of a computer with this name; remove it from the ... menu".to_string())
                        }
                        (None, Some(c)) if c.public.is_some() || c.public_name.is_some() || c.relay.is_some() => {
                            (theme::ACCENT, "Away; connects over the internet".to_string())
                        }
                        (None, _) => (grey, "Not found on this network".to_string()),
                    };
                    let os = row
                        .online
                        .as_ref()
                        .map(|f| f.announce.os.clone())
                        .filter(|o| !o.is_empty())
                        .or_else(|| row.saved.as_ref().and_then(|c| c.os.clone()));
                    theme::card().inner_margin(egui::Margin::symmetric(14, 10)).show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            status_dot(ui, dot);
                            os_icon(ui, os.as_deref());
                            ui.vertical(|ui| {
                                ui.spacing_mut().item_spacing.y = 2.0;
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new(&row.name).size(15.5).strong().color(Color32::WHITE));
                                    if row.name != row.real_name {
                                        ui.label(theme::hint(format!("({})", row.real_name)));
                                    }
                                });
                                let auto = row.saved.as_ref().is_some_and(|c| !c.auth.tokens.is_empty());
                                let mut line = status.clone();
                                if auto {
                                    line.push_str(" · signs in automatically");
                                }
                                if let Some(t) = row.saved.as_ref().and_then(|c| c.last_connected) {
                                    line.push_str(&format!(" · last connected {}", ago(t)));
                                }
                                ui.label(theme::hint(line));
                            });
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                if let Some(c) = &row.saved {
                                    ui.menu_button(RichText::new("...").strong(), |ui| {
                                        ui.set_min_width(200.0);
                                        if row.online.is_none() && !c.macs.is_empty() {
                                            if ui.button("Wake up").on_hover_text("Send a Wake-on-LAN signal (works on the same network as the computer)").clicked() {
                                                let lan = c.lan.as_deref().and_then(|a| a.parse().ok());
                                                let msg = match discover::wake(&c.macs, lan) {
                                                    Ok(_) => format!("Wake-up signal sent to {}. It can take a minute to start.", row.name),
                                                    Err(e) => format!("Couldn't send the wake-up signal: {e}"),
                                                };
                                                *notice = Some((msg, Instant::now()));
                                                ui.close_menu();
                                            }
                                        }
                                        if ui.button("Rename on this device").clicked() {
                                            *rename = Some((row.key.clone(), row.name.clone()));
                                            ui.close_menu();
                                        }
                                        if ui.button("Manage accounts").clicked() {
                                            out = Some(HomeAction::Connect(Attempt {
                                                target: Dest::Computer(row.key.clone()),
                                                mode: Mode::Admin,
                                                creds: Creds::Saved(None),
                                                remember: false,
                                            }));
                                            ui.close_menu();
                                        }
                                        if !c.auth.tokens.is_empty() && ui.button("Sign out on this device").clicked() {
                                            let mut st = Store::load();
                                            if let Some(c) = st.computers.get_mut(&row.key) {
                                                c.auth.tokens.clear();
                                            }
                                            let _ = st.save();
                                            *notice = Some((format!("Signed out of {} on this device.", row.name), Instant::now()));
                                            ui.close_menu();
                                        }
                                        ui.separator();
                                        if ui.button(RichText::new("Remove from my computers").color(theme::DANGER)).clicked() {
                                            let mut st = Store::load();
                                            st.computers.remove(&row.key);
                                            let _ = st.save();
                                            *notice = Some((format!("Removed {}", row.name), Instant::now()));
                                            ui.close_menu();
                                        }
                                    });
                                }
                                if ui.add(theme::primary("Connect").min_size(egui::vec2(96.0, 32.0))).clicked() {
                                    let key = match (&row.saved, &row.online) {
                                        (None, Some(f)) => save_found(f),
                                        _ => row.key.clone(),
                                    };
                                    out = Some(HomeAction::Connect(Attempt {
                                        target: Dest::Computer(key),
                                        mode: Mode::Desktop,
                                        creds: Creds::Saved(None),
                                        remember: false,
                                    }));
                                }
                            });
                        });
                    });
                    ui.add_space(4.0);
                }
            });
        });
    });
    rename_dialog(ctx, rename);
    out
}

/// The app's mark: a small monitor in the accent colour.
fn app_mark(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(22.0, 22.0), egui::Sense::hover());
    let p = ui.painter();
    let screen = egui::Rect::from_min_max(rect.min + egui::vec2(1.0, 3.0), rect.max - egui::vec2(1.0, 6.0));
    p.rect_filled(screen, 3.0, theme::ACCENT);
    p.rect_filled(screen.shrink(2.5), 1.5, theme::SURFACE);
    let base = rect.center_bottom();
    p.rect_filled(egui::Rect::from_center_size(base - egui::vec2(0.0, 4.0), egui::vec2(3.0, 3.0)), 0.0, theme::ACCENT);
    p.rect_filled(egui::Rect::from_center_size(base - egui::vec2(0.0, 1.5), egui::vec2(10.0, 2.0)), 1.0, theme::ACCENT);
}

/// "Rename on this device": a name used only in this device's list.
fn rename_dialog(ctx: &egui::Context, rename: &mut Option<(String, String)>) {
    let Some((key, text)) = rename.as_mut() else { return };
    let (mut save, mut close) = (false, false);
    egui::Window::new("Rename")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .show(ctx, |ui| {
            ui.label("Name shown for this computer on this device only:");
            let r = ui.add(egui::TextEdit::singleline(text).char_limit(40).desired_width(260.0));
            focus_if_free(ui, &r);
            if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                save = true;
            }
            ui.horizontal(|ui| {
                save |= ui.add(theme::primary("Save")).clicked();
                if ui.button("Use its own name").clicked() {
                    text.clear();
                    save = true;
                }
                close |= ui.button("Cancel").clicked();
            });
        });
    if save {
        let mut st = Store::load();
        if let Some(c) = st.computers.get_mut(key.as_str()) {
            let t = text.trim();
            c.alias = (!t.is_empty() && t != c.name).then(|| t.to_string());
            let _ = st.save();
        }
        close = true;
    }
    if close {
        *rename = None;
    }
}

/// A fixed-width column centred in the window, for dialog-like screens.
fn dialog(ui: &mut egui::Ui, width: f32, add: impl FnOnce(&mut egui::Ui)) {
    let width = width.min(ui.available_width());
    ui.horizontal(|ui| {
        ui.add_space(((ui.available_width() - width) / 2.0).max(0.0));
        ui.vertical(|ui| {
            ui.set_width(width);
            add(ui);
        });
    });
}

/// Put the cursor in `r` when nothing else has the keyboard (on open, after an error).
fn focus_if_free(ui: &egui::Ui, r: &egui::Response) {
    if ui.ctx().memory(|m| m.focused().is_none()) {
        r.request_focus();
    }
}

/// Some(true) = set up, Some(false) = cancel.
fn setup_ui(ctx: &egui::Context, f: &mut SetupForm) -> Option<bool> {
    let mut out = None;
    let grey = theme::MUTED;
    egui::CentralPanel::default().show(ctx, |ui| {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.add_space(30.0);
            dialog(ui, 480.0, |ui| {
                theme::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.heading(if f.change { "Change name or PIN" } else { "Set up remote access" });
                    ui.add_space(6.0);
                    ui.label(theme::hint("Choose a name for this computer and a PIN. You'll enter the PIN when you connect to this computer from another device."));
                    ui.add_space(12.0);
                    if let Some(e) = &f.error {
                        theme::banner(ui, theme::DANGER, e);
                        ui.add_space(6.0);
                    }
                    egui::Grid::new("setup").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                        ui.label("Name");
                        ui.add(egui::TextEdit::singleline(&mut f.name).desired_width(260.0).char_limit(40));
                        ui.end_row();
                        ui.label("PIN");
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut f.pin).password(true).hint_text("at least 4 digits").desired_width(260.0).char_limit(12),
                        );
                        if f.pin.is_empty() {
                            focus_if_free(ui, &r);
                        }
                        ui.end_row();
                        ui.label("Repeat PIN");
                        let r = ui.add(egui::TextEdit::singleline(&mut f.pin2).password(true).desired_width(260.0).char_limit(12));
                        if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            out = Some(true);
                        }
                        ui.end_row();
                    });
                    ui.add_space(8.0);
                    ui.checkbox(&mut f.internet, "Allow connections from outside this network");
                    ui.label(
                        RichText::new("Asks your router (UPnP) to forward a port to this computer, so your other devices can connect from anywhere.")
                            .small()
                            .color(grey),
                    );
                    if f.internet {
                        egui::CollapsingHeader::new("Keep working when your internet address changes (optional)")
                            .default_open(!f.ddns_was.is_empty())
                            .show(ui, |ui| {
                                ui.label(
                                    RichText::new("Internet providers change home addresses now and then. A free DuckDNS name follows the change, so your devices still find this computer while away. Sign in at duckdns.org, add a name, and copy your token.")
                                        .small()
                                        .color(grey),
                                );
                                egui::Grid::new("ddns").num_columns(2).spacing([10.0, 6.0]).show(ui, |ui| {
                                    ui.label("DuckDNS name");
                                    ui.horizontal(|ui| {
                                        ui.add(egui::TextEdit::singleline(&mut f.ddns_name).hint_text("myhome").desired_width(150.0));
                                        ui.label(".duckdns.org");
                                    });
                                    ui.end_row();
                                    ui.label("Token");
                                    let hint = if !f.ddns_was.is_empty() && f.ddns_name.trim() == f.ddns_was { "(unchanged)" } else { "" };
                                    ui.add(egui::TextEdit::singleline(&mut f.ddns_token).password(true).hint_text(hint).desired_width(260.0));
                                    ui.end_row();
                                });
                            });
                    }
                    ui.checkbox(&mut f.wake_on_lan, "Let my other devices wake this computer from sleep (Wake-on-LAN)");
                    ui.checkbox(&mut f.ask_to_allow, "Ask me before anyone connects");
                    ui.label(
                        RichText::new("Someone at this computer must click Allow first. Leave this off to connect to it while you're away.")
                            .small()
                            .color(grey),
                    );
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new("After 5 wrong PINs, sign-in pauses for a while; after 10 the PIN is switched off until you set it again here.")
                            .small()
                            .color(grey),
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        let label = if f.change { "Save" } else { "Set up" };
                        if ui.add(theme::primary(label)).clicked() {
                            out = Some(true);
                        }
                        if ui.button("Cancel").clicked() {
                            out = Some(false);
                        }
                    });
                    ui.add_space(6.0);
                    ui.label(
                        RichText::new(if cfg!(windows) {
                            "Windows will ask for administrator permission to install the background service."
                        } else {
                            "You'll be asked for your password to install the background service."
                        })
                        .small()
                        .color(grey),
                    );
                });
            });
        });
    });
    if out == Some(true) {
        let req = SetupRequest {
            name: f.name.trim().to_string(),
            pin: f.pin.clone(),
            internet: f.internet,
            ddns: None,
            ddns_off: false,
            wake_on_lan: false,
            ask_to_allow: false,
        };
        if let Err(e) = setup::validate(&req) {
            f.error = Some(e);
            return None;
        }
        if f.pin != f.pin2 {
            f.error = Some("The PINs don't match.".into());
            return None;
        }
        if let Err(e) = setup_ddns(f) {
            f.error = Some(e);
            return None;
        }
    }
    out
}

/// The dynamic DNS part of the setup form: (settings to save, turn it off).
fn setup_ddns(f: &SetupForm) -> Result<(Option<(String, String)>, bool), String> {
    let typed = f.ddns_name.trim();
    if !f.internet || typed.is_empty() {
        return Ok((None, !f.ddns_was.is_empty()));
    }
    let sub = setup::duckdns_subdomain(typed)?;
    if f.ddns_token.trim().is_empty() {
        if sub == f.ddns_was {
            return Ok((None, false)); // keep what's set up
        }
        return Err("Enter the DuckDNS token too (from duckdns.org).".into());
    }
    Ok((Some(setup::duckdns(&sub, &f.ddns_token)?), false))
}

/// Some(Some(attempt)) = submit, Some(None) = cancel, None = nothing yet.
fn sign_in_ui(ctx: &egui::Context, f: &mut SignInForm) -> Option<Option<Attempt>> {
    let mut out = None;
    let label = f.target.label();
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.add_space(60.0);
        dialog(ui, 440.0, |ui| {
            theme::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                if f.pin_only {
                    ui.heading(format!("Connect to {label}"));
                    ui.label(theme::hint("Enter the PIN chosen when remote access was set up on that computer."));
                } else {
                    ui.heading(if f.mode == Mode::Admin { "Sign in to manage accounts" } else { "Sign in" });
                    ui.label(RichText::new(&label).monospace().color(theme::MUTED));
                }
                ui.add_space(12.0);
                if let Some(m) = &f.message {
                    let m = if f.pin_only && m == "invalid username or credentials" { "Wrong PIN. Try again." } else { m.as_str() };
                    theme::banner(ui, theme::WARNING, m);
                    ui.add_space(6.0);
                }
                egui::Grid::new("signin").num_columns(2).spacing([10.0, 8.0]).show(ui, |ui| {
                    if !f.pin_only {
                        ui.label("Username");
                        let r = ui.add(egui::TextEdit::singleline(&mut f.username).desired_width(260.0));
                        if f.username.is_empty() {
                            focus_if_free(ui, &r);
                        }
                        ui.end_row();
                    }
                    ui.label(if f.use_pin { "PIN" } else { "Password" });
                    let r = ui.add(egui::TextEdit::singleline(&mut f.secret).password(true).desired_width(260.0));
                    if f.secret.is_empty() && (f.pin_only || !f.username.is_empty()) {
                        focus_if_free(ui, &r);
                    }
                    if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                        out = Some(true);
                    }
                    ui.end_row();
                    if f.need_code {
                        ui.label("Code");
                        let r = ui.add(
                            egui::TextEdit::singleline(&mut f.code).hint_text("from your authenticator app").desired_width(260.0).char_limit(7),
                        );
                        if f.code.is_empty() && !f.secret.is_empty() {
                            focus_if_free(ui, &r);
                        }
                        if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            out = Some(true);
                        }
                        ui.end_row();
                    }
                });
                ui.add_space(4.0);
                if !f.pin_only {
                    ui.checkbox(&mut f.use_pin, "Sign in with my PIN");
                }
                ui.checkbox(&mut f.remember, "Don't ask again on this device");
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.add(theme::primary(if f.pin_only { "Connect" } else { "Sign in" })).clicked() {
                        out = Some(true);
                    }
                    if ui.button("Cancel").clicked() {
                        out = Some(false);
                    }
                });
                if matches!(f.target, Dest::Computer(_)) {
                    ui.add_space(10.0);
                    let other = if f.pin_only { "Use a username and password instead" } else { "Use the computer's PIN instead" };
                    if ui.link(RichText::new(other).small()).clicked() {
                        f.pin_only = !f.pin_only;
                        f.use_pin = f.pin_only;
                        f.message = None;
                        if f.pin_only {
                            f.username.clear();
                        }
                    }
                }
            });
        });
    });
    match out {
        Some(true) if (f.pin_only || !f.username.trim().is_empty()) && !f.secret.is_empty() => {
            let username = if f.pin_only { String::new() } else { f.username.trim().to_string() };
            let secret = std::mem::take(&mut f.secret);
            let code = (f.need_code && !f.code.trim().is_empty()).then(|| f.code.trim().to_string());
            let creds = if f.use_pin { Creds::Pin { username, pin: secret, code } } else { Creds::Password { username, password: secret, code } };
            Some(Some(Attempt { target: f.target.clone(), mode: f.mode, creds, remember: f.remember }))
        }
        Some(false) => Some(None),
        _ => None,
    }
}

fn human(n: u64) -> String {
    match n {
        n if n >= 1 << 30 => format!("{:.1} GB", n as f64 / (1u64 << 30) as f64),
        n if n >= 1 << 20 => format!("{:.1} MB", n as f64 / (1u64 << 20) as f64),
        n if n >= 1 << 10 => format!("{:.0} KB", n as f64 / 1024.0),
        n => format!("{n} B"),
    }
}

fn session_ui(ctx: &egui::Context, v: &mut SessionView) -> Option<SessionAction> {
    let mut action = None;
    let (status, displays, current, viewers, closed) = {
        let s = v.handle.state.lock().unwrap();
        (s.status.clone(), s.displays.clone(), s.current_display, s.viewers.clone(), s.closed.clone())
    };

    if let Some(why) = closed {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(80.0);
            dialog(ui, 420.0, |ui| {
                theme::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.heading("Session ended");
                    ui.add_space(4.0);
                    ui.add(egui::Label::new(RichText::new(why).color(theme::MUTED)).wrap());
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui.add(theme::primary("Reconnect")).clicked() {
                            action = Some(SessionAction::Reconnect);
                        }
                        if ui.button("Back to my computers").clicked() {
                            action = Some(SessionAction::Close);
                        }
                    });
                });
            });
        });
        return action;
    }

    // Frames per second, for the connection badge.
    {
        let frames = v.handle.state.lock().unwrap().video_frames;
        let dt = v.fps.0.elapsed().as_secs_f32();
        if dt >= 1.0 {
            v.fps = (Instant::now(), frames, (frames - v.fps.1) as f32 / dt);
        }
        ctx.request_repaint_after(Duration::from_secs(1));
    }

    if !v.fullscreen {
        egui::TopBottomPanel::top("toolbar")
            .frame(egui::Frame::new().fill(theme::SURFACE).inner_margin(egui::Margin::symmetric(14, 8)).stroke(egui::Stroke::new(1.0, theme::BORDER)))
            .show(ctx, |ui| {
            if let Some(a) = toolbar(ui, v, &displays, current, &viewers) {
                action = Some(a);
            }
        });
    } else {
        // Full screen: the toolbar slides down when the pointer touches the top edge.
        let at_top = ctx.pointer_latest_pos().is_some_and(|p| p.y <= 3.0);
        if at_top {
            v.bar_shown = true;
        }
        if v.bar_shown {
            let screen = ctx.screen_rect();
            let r = egui::Area::new(egui::Id::new("fs-toolbar"))
                .order(egui::Order::Foreground)
                .fixed_pos(egui::pos2(screen.left() + 12.0, screen.top()))
                .show(ctx, |ui| {
                    egui::Frame::new()
                        .fill(theme::SURFACE)
                        .stroke(egui::Stroke::new(1.0, theme::BORDER))
                        .corner_radius(egui::CornerRadius { nw: 0, ne: 0, sw: 10, se: 10 })
                        .inner_margin(egui::Margin::symmetric(12, 8))
                        .shadow(egui::Shadow { offset: [0, 4], blur: 16, spread: 0, color: Color32::from_black_alpha(140) })
                        .show(ui, |ui| {
                            // The bar's margins and border sit outside this width.
                            ui.set_width(screen.width() - 24.0 - 26.0);
                            toolbar(ui, v, &displays, current, &viewers)
                        })
                    .inner
                });
            if let Some(a) = r.inner {
                action = Some(a);
            }
            // Hide again once the pointer leaves the bar (with a little slack).
            let keep = ctx.pointer_latest_pos().is_some_and(|p| r.response.rect.expand(24.0).contains(p)) || at_top;
            if !keep && !ctx.is_using_pointer() {
                v.bar_shown = false;
            }
        }
        if ctx.input(|i| i.key_pressed(egui::Key::F11)) {
            v.fullscreen = false;
            v.bar_shown = false;
            action = Some(SessionAction::Fullscreen(false));
        }
    }
    if let Some(SessionAction::Fullscreen(on)) = action {
        v.fullscreen = on;
        v.bar_shown = false;
    }

    if v.show_files && !v.fullscreen {
        files_panel(ctx, v);
    }
    if v.show_chat {
        chat_panel(ctx, v);
    }
    session_picture(ctx, v, &status);
    // Fit the remote resolution once the window has stopped changing size.
    if v.fit && v.view_px.0 > 0 && v.view_changed.elapsed() > Duration::from_millis(700) && v.fit_sent != Some(v.view_px) {
        v.fit_sent = Some(v.view_px);
        v.handle.send(ClientMsg::FitResolution(Some(v.view_px)));
    }
    if v.fit && v.fit_sent != Some(v.view_px) {
        ctx.request_repaint_after(Duration::from_millis(300));
    }
    action
}

fn chat_panel(ctx: &egui::Context, v: &mut SessionView) {
    egui::SidePanel::right("chat").default_width(300.0).show(ctx, |ui| {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(theme::section("Chat"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("Close").clicked() {
                    v.show_chat = false;
                }
            });
        });
        ui.label(theme::hint("With the person at the remote computer and anyone else connected."));
        ui.separator();
        let lines = {
            let mut s = v.handle.state.lock().unwrap();
            s.chat_unread = 0;
            s.chat.clone()
        };
        egui::ScrollArea::vertical()
            .max_height((ui.available_height() - 48.0).max(60.0))
            .auto_shrink([false, true])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if lines.is_empty() {
                    ui.label(theme::hint("No messages yet."));
                }
                for (from, text) in &lines {
                    let mine = from == "You";
                    let layout = egui::Layout::top_down(if mine { egui::Align::Max } else { egui::Align::Min });
                    ui.with_layout(layout, |ui| {
                        ui.label(theme::hint(from.as_str()));
                        egui::Frame::new()
                            .fill(if mine { theme::ACCENT.gamma_multiply(0.35) } else { theme::SURFACE_HI })
                            .corner_radius(8)
                            .inner_margin(egui::Margin::symmetric(10, 6))
                            .show(ui, |ui| {
                                ui.set_max_width(ui.available_width() * 0.85);
                                ui.add(egui::Label::new(text.as_str()).wrap());
                            });
                    });
                    ui.add_space(4.0);
                }
            });
        ui.separator();
        ui.horizontal(|ui| {
            let r = ui.add(egui::TextEdit::singleline(&mut v.chat_input).hint_text("Message").desired_width((ui.available_width() - 70.0).max(80.0)));
            let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (ui.add(theme::primary("Send")).clicked() || enter) && !v.chat_input.trim().is_empty() {
                let text: String = v.chat_input.trim().chars().take(rd_core::proto::MAX_CHAT).collect();
                v.chat_input.clear();
                v.handle.state.lock().unwrap().chat.push(("You".into(), text.clone()));
                v.handle.send(ClientMsg::Chat(text));
                r.request_focus();
            }
        });
    });
}

/// "Direct · this network · 12 ms · 30 fps", with a coloured dot (`compact` leaves out
/// the route; it's in the tooltip).
fn connection_badge(ui: &mut egui::Ui, v: &SessionView, compact: bool) {
    let rtt = v.handle.state.lock().unwrap().rtt_ms;
    let (kind, color, help) = match v.route.as_str() {
        "direct" => ("Direct · this network", theme::SUCCESS, "Connected straight to the computer on your local network."),
        "over the internet" => ("Direct · internet", theme::SUCCESS, "Connected straight to the computer over the internet (router port forwarding)."),
        "peer-to-peer" => ("Peer-to-peer", theme::SUCCESS, "A direct connection set up through the relay server."),
        "relayed (UDP)" => ("Relay (UDP)", theme::WARNING, "Carried by the relay server; a direct path wasn't possible."),
        _ => ("Relay", theme::WARNING, "Carried by the relay server over TCP; slower than a direct connection."),
    };
    let mut parts = Vec::new();
    if !compact {
        parts.push(kind.to_string());
    }
    match rtt {
        Some(0) => parts.push("<1 ms".to_string()),
        Some(ms) => parts.push(format!("{ms} ms")),
        None => {}
    }
    // Nothing is sent while the remote screen is still, so "0 fps" would look broken.
    if v.fps.2 >= 1.0 {
        parts.push(format!("{:.0} fps", v.fps.2));
    }
    theme::pill(ui, color, &parts.join(" · ")).on_hover_text(format!("{kind}\n{help}"));
}

/// "Monitor 2 (main)": the name shown for a remote monitor. Windows calls them
/// `\\.\DISPLAY1`, which says nothing, so they're numbered instead.
fn monitor_label(d: &rd_core::proto::DisplayInfo) -> String {
    if d.primary {
        format!("Monitor {} (main)", d.index + 1)
    } else {
        format!("Monitor {}", d.index + 1)
    }
}

/// A button that stays highlighted while its panel or feature is on.
fn toggle(ui: &mut egui::Ui, on: bool, text: &str, help: &str) -> egui::Response {
    ui.add(egui::Button::new(text).selected(on)).on_hover_text(help)
}

/// The session toolbar (top bar, or the slide-down bar in full screen): which computer
/// and how it's connected on the left, the session's controls on the right, in one row.
fn toolbar(
    ui: &mut egui::Ui,
    v: &mut SessionView,
    displays: &[rd_core::proto::DisplayInfo],
    current: u32,
    viewers: &[String],
) -> Option<SessionAction> {
    let mut action = None;
    let perms = v.user.effective();
    // Below this width the monitor picker moves into the View menu only, and the
    // connection badge drops the route, so the bar never wraps onto two rows.
    let narrow = ui.available_width() < 1000.0;
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        os_icon(ui, v.remote_os.as_deref());
        ui.label(RichText::new(&v.host_name).size(15.5).strong().color(Color32::WHITE))
            .on_hover_text(format!("Signed in as {}", v.user.username));
        connection_badge(ui, v, narrow);
        if !perms.control {
            theme::pill(ui, theme::MUTED, "View only").on_hover_text("This account can watch but not use the keyboard and mouse");
        }
        if viewers.len() > 1 {
            theme::pill(ui, theme::ACCENT, &format!("{} watching", viewers.len()))
                .on_hover_text(format!("Connected to this computer right now:\n{}", viewers.join("\n")));
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            if ui.add(theme::danger("Disconnect")).on_hover_text("End the session").clicked() {
                action = Some(SessionAction::Close);
            }
            if v.fullscreen {
                if ui.button("Exit full screen").on_hover_text("Or press F11").clicked() {
                    action = Some(SessionAction::Fullscreen(false));
                }
            } else if ui
                .button("Full screen")
                .on_hover_text("In full screen, touch the top edge of the screen for this bar; F11 leaves full screen")
                .clicked()
            {
                action = Some(SessionAction::Fullscreen(true));
            }
            ui.menu_button("More", |ui| {
                menu_style(ui);
                more_menu(ui, v)
            });
            if perms.control {
                ui.menu_button("Keys", |ui| {
                    menu_style(ui);
                    keys_menu(ui, v)
                });
            }
            ui.menu_button("View", |ui| {
                menu_style(ui);
                view_menu(ui, v, displays, current)
            });
            ui.separator();
            let unread = v.handle.state.lock().unwrap().chat_unread;
            let chat_label = if unread > 0 && !v.show_chat { format!("Chat ({unread})") } else { "Chat".to_string() };
            if toggle(ui, v.show_chat, &chat_label, "Chat with the person at the remote computer").clicked() {
                v.show_chat = !v.show_chat;
            }
            if perms.files && toggle(ui, v.show_files, "Files", "Browse the remote computer's files, download and upload").clicked() {
                v.show_files = !v.show_files;
                if v.show_files && v.handle.state.lock().unwrap().dir.is_none() {
                    v.handle.list_dir("");
                }
            }
            if toggle(ui, v.audio_on, "Sound", "Play the remote computer's sound here").clicked() {
                let want = !v.audio_on;
                match v.handle.set_audio(want) {
                    Ok(()) => v.audio_on = want,
                    Err(e) => v.flash = Some((format!("Sound isn't available: {e:#}"), Instant::now())),
                }
            }
            if !narrow && !displays.is_empty() {
                ui.separator();
                monitor_picker(ui, v, displays, current);
            }
        });
    });
    action
}

/// egui's menus drop the outline of unticked boxes and radio buttons, which leaves them
/// almost invisible on the dark menu; a lighter fill keeps them visible. Tighter corners
/// keep tick boxes square, so they don't look like the round choices next to them.
fn menu_style(ui: &mut egui::Ui) {
    let w = &mut ui.visuals_mut().widgets;
    w.inactive.bg_fill = Color32::from_rgb(62, 68, 82);
    w.hovered.bg_fill = Color32::from_rgb(78, 85, 102);
    for s in [&mut w.inactive, &mut w.hovered, &mut w.active] {
        s.corner_radius = egui::CornerRadius::same(4);
    }
}

/// Why the monitor can't be switched right now, if it can't.
fn monitor_switch_blocked(v: &SessionView, displays: &[rd_core::proto::DisplayInfo]) -> Option<&'static str> {
    if !v.user.effective().control {
        Some("Switching monitors needs control of the computer.")
    } else if displays.len() == 1 {
        Some(if v.remote_os.as_deref() == Some("windows") {
            "The remote computer has one monitor."
        } else {
            "Only one monitor is shared. On a Linux computer using Wayland, the screen-sharing \
             dialog there decides which monitors are shared: pick all of them the next time it asks."
        })
    } else {
        None
    }
}

fn monitor_picker(ui: &mut egui::Ui, v: &mut SessionView, displays: &[rd_core::proto::DisplayInfo], current: u32) {
    let cur = displays.iter().find(|d| d.index == current).map(monitor_label).unwrap_or_default();
    let why_not = monitor_switch_blocked(v, displays);
    ui.add_enabled_ui(why_not.is_none(), |ui| {
        egui::ComboBox::from_id_salt("display").selected_text(cur).show_ui(ui, |ui| {
            ui.set_min_width(220.0);
            for d in displays {
                let text = format!("{}  ·  {}×{}", monitor_label(d), d.width, d.height);
                if ui.selectable_label(d.index == current, text).clicked() && d.index != current {
                    v.handle.send(ClientMsg::SelectDisplay(d.index));
                }
            }
        });
    })
    .response
    .on_hover_text("Which of the remote computer's monitors to show")
    .on_disabled_hover_text(why_not.unwrap_or_default());
}

/// How the picture is shown: monitor, size, quality, resolution, details.
fn view_menu(ui: &mut egui::Ui, v: &mut SessionView, displays: &[rd_core::proto::DisplayInfo], current: u32) {
    ui.set_min_width(300.0);
    let control = v.user.effective().control;
    if !displays.is_empty() {
        ui.label(theme::hint("Monitor"));
        match monitor_switch_blocked(v, displays) {
            Some(why) if displays.len() == 1 || !control => {
                if let Some(d) = displays.first() {
                    ui.label(format!("{}  ·  {}×{}", monitor_label(d), d.width, d.height));
                }
                ui.add(egui::Label::new(theme::hint(why)).wrap());
            }
            _ => {
                for d in displays {
                    let text = format!("{}  ·  {}×{}", monitor_label(d), d.width, d.height);
                    if ui.radio(d.index == current, text).clicked() && d.index != current {
                        v.handle.send(ClientMsg::SelectDisplay(d.index));
                    }
                }
            }
        }
        ui.separator();
    }

    ui.label(theme::hint("Picture size"));
    let was = v.actual_size;
    if ui.radio(!v.actual_size, "Fit to the window").clicked() {
        v.actual_size = false;
    }
    if ui
        .radio(v.actual_size, "Actual size")
        .on_hover_text("One remote pixel per screen pixel, the sharpest; drag the scroll bars to move around (the mouse wheel goes to the remote computer)")
        .clicked()
    {
        v.actual_size = true;
    }
    if v.actual_size != was {
        let mut store = Store::load();
        store.actual_size = v.actual_size;
        let _ = store.save();
    }
    if control
        && ui
            .checkbox(&mut v.fit, "Change its resolution to fit this window")
            .on_hover_text("Switch the remote screen to the resolution closest to this window, for sharp text; it's put back when you disconnect")
            .changed()
    {
        v.fit_sent = None;
        v.view_changed = Instant::now() - Duration::from_secs(1);
        if !v.fit {
            v.handle.send(ClientMsg::FitResolution(None));
        }
        let mut store = Store::load();
        store.fit_resolution = v.fit;
        let _ = store.save();
    }
    ui.separator();

    ui.label(theme::hint("Picture quality"));
    let (codec, kbps) = {
        let s = v.handle.state.lock().unwrap();
        (s.codec, s.kbps)
    };
    let smooth = matches!(codec, VideoCodec::H264 { .. });
    let choices = [
        (true, VideoCodec::H264 { max_kbps: 0 }, "Smooth", "Best for video, games and slower connections"),
        (false, VideoCodec::Tiles, "Sharp", "Pixel-exact text and images; needs a fast connection"),
    ];
    for (is_smooth, c, text, help) in choices {
        if ui.radio(smooth == is_smooth, text).on_hover_text(help).clicked() && smooth != is_smooth {
            v.handle.send(ClientMsg::SetCodec(c));
            let mut store = Store::load();
            store.set_video_codec(c);
            let _ = store.save();
        }
    }
    if smooth && kbps > 0 {
        ui.label(theme::hint(format!("Now {:.1} Mbit/s; it adapts to the connection.", kbps as f32 / 1000.0)));
    }
    ui.separator();
    if ui.checkbox(&mut v.show_stats, "Show connection details").on_hover_text("Speed, delay and picture size over the picture").changed() {
        let mut store = Store::load();
        store.show_stats = v.show_stats;
        let _ = store.save();
    }
}

/// Press and release a key combination on the remote computer (evdev codes, held in
/// order and let go in reverse).
fn send_keys(v: &SessionView, codes: &[u16]) {
    for &code in codes {
        v.handle.send(ClientMsg::Input(InputEvent::Key { code, down: true }));
    }
    for &code in codes.iter().rev() {
        v.handle.send(ClientMsg::Input(InputEvent::Key { code, down: false }));
    }
}

/// Keys this computer would catch itself, and how the keyboard and mouse are sent.
fn keys_menu(ui: &mut egui::Ui, v: &mut SessionView) {
    ui.set_min_width(260.0);
    ui.label(theme::hint("Send to the remote computer"));
    if ui.button("Ctrl+Alt+Del").clicked() {
        v.handle.send(ClientMsg::SecureAttention);
        ui.close_menu();
    }
    let super_key = if v.remote_os.as_deref() == Some("linux") { "Super key" } else { "Windows key" };
    // evdev: LEFTMETA 125, LEFTALT 56, TAB 15, F4 62, SYSRQ (Print Screen) 99, LEFTCTRL 29, ESC 1.
    let combos: [(&str, &[u16]); 5] = [
        (super_key, &[125]),
        ("Alt+Tab", &[56, 15]),
        ("Alt+F4", &[56, 62]),
        ("Ctrl+Esc", &[29, 1]),
        ("Print Screen", &[99]),
    ];
    for (label, codes) in combos {
        if ui.button(label).clicked() {
            send_keys(v, codes);
            ui.close_menu();
        }
    }
    ui.separator();
    if ui
        .checkbox(&mut v.shortcuts, "Send system shortcuts")
        .on_hover_text("The Windows key, Alt+Tab, Alt+F4 and Ctrl+Esc go to the remote computer instead of this one")
        .changed()
    {
        let mut store = Store::load();
        store.system_shortcuts = v.shortcuts;
        let _ = store.save();
    }
    let was = v.gaming;
    ui.checkbox(&mut v.gaming, "Gaming mode")
        .on_hover_text("Locks the pointer in the window and sends raw mouse movement and game controllers. Press Ctrl+Alt+G to leave.");
    if v.gaming != was {
        v.pads = v.gaming.then(|| pads::start(v.handle.sender()));
        if v.gaming {
            v.flash = Some(("Gaming mode: press Ctrl+Alt+G to get the pointer back".into(), Instant::now()));
            ui.close_menu();
        }
    }
}

/// Session options: lock on leave, privacy screen, screenshot.
fn more_menu(ui: &mut egui::Ui, v: &mut SessionView) {
    ui.set_min_width(280.0);
    let control = v.user.effective().control;
    let (privacy, note) = {
        let s = v.handle.state.lock().unwrap();
        (s.privacy, s.privacy_note.clone())
    };
    if ui.button("Save a screenshot...").on_hover_text("Save what you see of the remote computer as a PNG picture").clicked() {
        ui.close_menu();
        v.flash = Some((save_screenshot(v), Instant::now()));
    }
    ui.separator();
    if ui.checkbox(&mut v.lock_on_leave, "Lock the computer when I disconnect").changed() {
        v.handle.send(ClientMsg::LockOnLeave(v.lock_on_leave));
        let mut store = Store::load();
        store.lock_on_leave = Some(v.lock_on_leave);
        let _ = store.save();
    }
    if !control {
        ui.label(theme::hint("The privacy screen needs control of the computer."));
        return;
    }
    let mut p = privacy;
    if ui
        .checkbox(&mut p, "Privacy screen")
        .on_hover_text("Black out the remote monitor and ignore its keyboard and mouse while you're connected")
        .changed()
    {
        v.handle.send(ClientMsg::Privacy(p));
    }
    if let Some(n) = note {
        ui.add(egui::Label::new(RichText::new(n).small().color(theme::WARNING)).wrap());
    }
}

/// Save the current remote picture as a PNG the user picks; returns what happened.
fn save_screenshot(v: &SessionView) -> String {
    let (w, h, rgba) = {
        let s = v.handle.state.lock().unwrap();
        let (w, h) = (s.decoder.width, s.decoder.height);
        let rgba: Vec<u8> = s.decoder.pixels.iter().flat_map(|p| [(p >> 16) as u8, (p >> 8) as u8, *p as u8, 255]).collect();
        (w, h, rgba)
    };
    if w == 0 || h == 0 {
        return "There's no picture yet to save.".into();
    }
    let safe: String = v.host_name.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let Some(path) = rfd::FileDialog::new().set_file_name(format!("{safe}-{stamp}.png")).add_filter("PNG picture", &["png"]).save_file() else {
        return "Screenshot not saved.".into();
    };
    match clipboard::encode_png(w, h, &rgba).map_err(|e| format!("{e:#}")).and_then(|png| std::fs::write(&path, png).map_err(|e| e.to_string())) {
        Ok(()) => format!("Screenshot saved to {}", path.display()),
        Err(e) => format!("Couldn't save the screenshot: {e}"),
    }
}

/// The remote picture, filling the rest of the window: fitted to it, or at its actual
/// size with scroll bars. Connection details and short messages float over it.
fn session_picture(ctx: &egui::Context, v: &mut SessionView, status: &str) {
    // Mipmaps keep text readable when a large screen is shown smaller than it is.
    let tex_opts = TextureOptions { mipmap_mode: Some(egui::TextureFilter::Linear), ..TextureOptions::LINEAR };
    // Upload changed regions of the remote framebuffer into the texture.
    {
        let mut s = v.handle.state.lock().unwrap();
        let (w, h) = (s.decoder.width as usize, s.decoder.height as usize);
        if w > 0 {
            let to_color = |p: u32| Color32::from_rgb((p >> 16) as u8, (p >> 8) as u8, p as u8);
            let need_full = s.full_dirty || v.texture.is_none() || v.remote_size != (w as u32, h as u32);
            if need_full {
                let img = ColorImage { size: [w, h], pixels: s.decoder.pixels.iter().map(|p| to_color(*p)).collect() };
                match &mut v.texture {
                    Some(t) => t.set(img, tex_opts),
                    None => v.texture = Some(ctx.load_texture("remote", img, tex_opts)),
                }
                v.remote_size = (w as u32, h as u32);
                s.full_dirty = false;
                s.dirty.clear();
            } else if let Some(tex) = &mut v.texture {
                for [x, y, tw, th] in std::mem::take(&mut s.dirty) {
                    let (x, y, tw, th) = (x as usize, y as usize, tw as usize, th as usize);
                    let mut px = Vec::with_capacity(tw * th);
                    for row in y..y + th {
                        px.extend(s.decoder.pixels[row * w + x..row * w + x + tw].iter().map(|p| to_color(*p)));
                    }
                    tex.set_partial([x, y], ColorImage { size: [tw, th], pixels: px }, tex_opts);
                }
            }
        }
    }

    let backdrop = Color32::from_rgb(12, 13, 16);
    egui::CentralPanel::default().frame(egui::Frame::NONE.fill(backdrop)).show(ctx, |ui| {
        let avail = ui.available_rect_before_wrap();
        let ppp = ctx.pixels_per_point();
        let px = ((avail.width() * ppp) as u32, (avail.height() * ppp) as u32);
        if px != v.view_px {
            v.view_px = px;
            v.view_changed = Instant::now();
        }
        let uv = egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0));
        match &v.texture {
            Some(tex) if v.remote_size.0 > 0 => {
                let (rw, rh) = (v.remote_size.0 as f32, v.remote_size.1 as f32);
                let tex_id = tex.id();
                if v.actual_size {
                    // One remote pixel per physical pixel; scroll bars when it doesn't fit.
                    let size = egui::vec2(rw / ppp, rh / ppp);
                    // Solid scroll bars beside the picture, not floating over it, so a click on
                    // them never reaches the remote computer.
                    ui.style_mut().spacing.scroll = egui::style::ScrollStyle::solid();
                    let out = egui::ScrollArea::both().auto_shrink([false, false]).id_salt("picture").show(ui, |ui| {
                        let free = ui.available_size();
                        // Centre it while it's smaller than the window.
                        let pad = egui::vec2(((free.x - size.x) / 2.0).max(0.0), ((free.y - size.y) / 2.0).max(0.0));
                        let (outer, _) = ui.allocate_exact_size(size + pad * 2.0, egui::Sense::hover());
                        let rect = egui::Rect::from_min_size(outer.min + pad, size);
                        ui.painter().image(tex_id, rect, uv, Color32::WHITE);
                        rect
                    });
                    v.image_rect = Some(out.inner);
                    v.image_clip = Some(out.inner_rect);
                } else {
                    let scale = (avail.width() / rw).min(avail.height() / rh);
                    // Snap to whole physical pixels so the picture isn't blurred by half-pixel offsets.
                    let size = egui::vec2((rw * scale * ppp).floor() / ppp, (rh * scale * ppp).floor() / ppp);
                    let min = ((avail.center() - size / 2.0) * ppp).round() / ppp;
                    let rect = egui::Rect::from_min_size(min, size);
                    ui.painter().image(tex_id, rect, uv, Color32::WHITE);
                    v.image_rect = Some(rect);
                    v.image_clip = Some(avail);
                }
                let clip = v.image_clip.unwrap_or(avail);
                // Not while over the slide-down toolbar, a menu or a toast: clicks there are ours.
                v.remote_hover = ctx
                    .pointer_latest_pos()
                    .is_some_and(|p| v.image_rect.is_some_and(|r| r.contains(p)) && clip.contains(p))
                    && !ctx.is_pointer_over_area();
            }
            _ => {
                ui.vertical_centered(|ui| {
                    ui.add_space((ui.available_height() / 2.0 - 40.0).max(0.0));
                    ui.add(egui::Spinner::new().size(32.0).color(theme::ACCENT));
                    ui.add_space(10.0);
                    ui.label(RichText::new(format!("Connecting to {}", v.host_name)).size(16.0).strong().color(Color32::WHITE));
                    ui.label(RichText::new(friendly_status(status, &v.host_name)).color(theme::MUTED));
                });
            }
        }
        picture_overlays(ui, v, avail, status);
    });
}

/// Connection details (top right) and short messages (bottom centre) over the picture.
fn picture_overlays(ui: &mut egui::Ui, v: &mut SessionView, area: egui::Rect, status: &str) {
    let chip = |ui: &mut egui::Ui, pos: egui::Align2, at: egui::Pos2, lines: &[(String, Color32)]| {
        let font = egui::FontId::proportional(12.5);
        let galleys: Vec<_> = lines.iter().map(|(t, c)| ui.painter().layout_no_wrap(t.clone(), font.clone(), *c)).collect();
        let w = galleys.iter().map(|g| g.size().x).fold(0.0, f32::max);
        let h: f32 = galleys.iter().map(|g| g.size().y + 2.0).sum();
        let rect = pos.anchor_size(at, egui::vec2(w + 20.0, h + 12.0));
        ui.painter().rect_filled(rect, 8.0, Color32::from_rgba_unmultiplied(14, 16, 20, 225));
        ui.painter().rect_stroke(rect, 8.0, egui::Stroke::new(1.0, theme::BORDER), egui::StrokeKind::Inside);
        let mut y = rect.top() + 6.0;
        for g in galleys {
            let gh = g.size().y;
            ui.painter().galley(egui::pos2(rect.left() + 10.0, y), g, Color32::WHITE);
            y += gh + 2.0;
        }
    };

    if v.show_stats && v.remote_size.0 > 0 {
        let (rtt, codec, kbps) = {
            let s = v.handle.state.lock().unwrap();
            (s.rtt_ms, s.codec, s.kbps)
        };
        let mut lines = vec![
            (format!("{}×{}  ·  {:.0} fps", v.remote_size.0, v.remote_size.1, v.fps.2), Color32::WHITE),
            (
                match codec {
                    VideoCodec::H264 { .. } if kbps > 0 => format!("Smooth (H.264)  ·  {:.1} Mbit/s", kbps as f32 / 1000.0),
                    VideoCodec::H264 { .. } => "Smooth (H.264)".to_string(),
                    VideoCodec::Tiles => "Sharp (lossless)".to_string(),
                },
                theme::TEXT,
            ),
            (format!("{}{}", route_name(&v.route), rtt.map(|ms| format!("  ·  {ms} ms")).unwrap_or_default()), theme::TEXT),
        ];
        if !status.is_empty() {
            lines.push((status.to_string(), theme::MUTED)); // the raw text, with the capture method
        }
        chip(ui, egui::Align2::RIGHT_TOP, area.right_top() + egui::vec2(-12.0, 12.0), &lines);
    }

    // A changed status from the host ("connected (x11)", a resolution note) shows for a few seconds.
    if status != v.status_seen.0 {
        v.status_seen = (status.to_string(), Instant::now());
        // Connected by address rather than from the list, the OS isn't known yet; the
        // capture backend in "connected (windows)" tells it (key repeat depends on it).
        if v.remote_os.is_none() {
            v.remote_os = match status.strip_prefix("connected (").and_then(|b| b.strip_suffix(')')) {
                Some("windows") => Some("windows".into()),
                Some("x11" | "wayland") => Some("linux".into()),
                _ => None,
            };
        }
    }
    let msg = match &v.flash {
        Some((m, t)) if t.elapsed() < Duration::from_secs(6) => Some(m.clone()),
        _ => {
            v.flash = None;
            (v.remote_size.0 > 0 && !status.is_empty() && v.status_seen.1.elapsed() < Duration::from_secs(4))
                .then(|| friendly_status(status, &v.host_name))
        }
    };
    if let Some(m) = msg {
        chip(ui, egui::Align2::CENTER_BOTTOM, area.center_bottom() - egui::vec2(0.0, 20.0), &[(m, Color32::WHITE)]);
        ui.ctx().request_repaint_after(Duration::from_millis(500));
    }
}

/// The host's status for people: "connected (wgc)" names the capture method, which
/// only matters in the connection details.
fn friendly_status(status: &str, host: &str) -> String {
    if status.starts_with("connected") {
        return format!("Connected to {host}");
    }
    let mut c = status.chars();
    match c.next() {
        Some(f) => f.to_uppercase().chain(c).collect(),
        None => String::new(),
    }
}

/// "Direct · this network" and the like, for a connection route.
fn route_name(route: &str) -> &'static str {
    match route {
        "direct" => "Direct · this network",
        "over the internet" => "Direct · internet",
        "peer-to-peer" => "Peer-to-peer",
        "relayed (UDP)" => "Relay (UDP)",
        _ => "Relay",
    }
}

fn files_panel(ctx: &egui::Context, v: &mut SessionView) {
    egui::SidePanel::right("files").default_width(360.0).show(ctx, |ui| {
        ui.add_space(6.0);
        ui.label(theme::section("Files on the remote computer"));
        let (dir_path, parent, entries, err, transfers) = {
            let s = v.handle.state.lock().unwrap();
            (
                s.dir.as_ref().map(|d| d.path.clone()),
                s.dir.as_ref().and_then(|d| d.parent.clone()),
                s.dir.as_ref().map(|d| d.entries.clone()).unwrap_or_default(),
                s.dir_error.clone(),
                s.transfers.clone(),
            )
        };
        if let Some(p) = &dir_path {
            if v.path_input.is_empty() {
                v.path_input = p.clone();
            }
        }
        ui.horizontal(|ui| {
            if ui.button("Home").clicked() {
                v.path_input.clear();
                v.handle.list_dir("");
            }
            if let Some(parent) = &parent {
                if ui.button("Up").clicked() {
                    v.path_input = parent.clone();
                    v.handle.list_dir(parent);
                }
            }
            let r = ui.add(egui::TextEdit::singleline(&mut v.path_input).desired_width((ui.available_width() - 50.0).max(80.0)));
            if ui.button("Go").clicked() || (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                v.handle.list_dir(&v.path_input);
            }
        });
        if let Some(e) = err {
            theme::banner(ui, theme::DANGER, &e);
        }
        if ui.add(theme::primary("Upload a file...")).on_hover_text("Or drop files onto the window").clicked() {
            if let Some(path) = rfd::FileDialog::new().pick_file() {
                v.handle.upload(path);
            }
        }
        ui.label(theme::hint("Uploads go to the remote user's Downloads folder."));
        ui.separator();
        egui::ScrollArea::vertical().max_height(ui.available_height() * 0.6).id_salt("entries").show(ui, |ui| {
            for e in &entries {
                ui.horizontal(|ui| {
                    let base = dir_path.clone().unwrap_or_default();
                    let sep = if base.contains('\\') { "\\" } else { "/" };
                    let full = if base.ends_with(sep) { format!("{base}{}", e.name) } else { format!("{base}{sep}{}", e.name) };
                    if e.is_dir {
                        folder_icon(ui);
                        if ui.link(&e.name).clicked() {
                            v.path_input = full.clone();
                            v.handle.list_dir(&full);
                        }
                    } else {
                        ui.add_space(24.0);
                        ui.label(&e.name);
                        ui.label(theme::hint(human(e.size)));
                        if ui.small_button("Download").clicked() {
                            if let Some(local) = rfd::FileDialog::new().set_file_name(&e.name).save_file() {
                                v.handle.download(full, e.name.clone(), e.size, local);
                            }
                        }
                    }
                });
            }
        });
        if !transfers.is_empty() {
            ui.separator();
            ui.label(RichText::new("Transfers").strong());
            for t in transfers.iter().rev().take(8) {
                let arrow = if t.direction == Direction::Download { "Download" } else { "Upload" };
                ui.horizontal(|ui| {
                    ui.label(theme::hint(arrow));
                    ui.label(&t.name);
                });
                match &t.state {
                    TransferState::Active => {
                        let frac = if t.total > 0 { t.done as f32 / t.total as f32 } else { 0.0 };
                        ui.add(egui::ProgressBar::new(frac).text(format!("{} / {}", human(t.done), human(t.total))));
                    }
                    TransferState::Done(m) => {
                        ui.label(RichText::new(m).small().color(theme::SUCCESS));
                    }
                    TransferState::Failed(m) => {
                        ui.label(RichText::new(m).small().color(theme::DANGER));
                    }
                }
            }
        }
    });
}

/// Returns true when the user leaves the screen.
fn admin_ui(ctx: &egui::Context, v: &mut AdminView) -> bool {
    // Collect finished requests.
    let mut done = Vec::new();
    v.pending.retain_mut(|(purpose, rx)| match rx.try_recv() {
        Ok(r) => {
            done.push((std::mem::replace(purpose, Purpose::Devices), r));
            false
        }
        Err(oneshot::error::TryRecvError::Empty) => true,
        Err(_) => false,
    });
    let mut refresh = false;
    for (purpose, r) in done {
        match (purpose, r) {
            (Purpose::Users, Ok(AdminResponse::Users(u))) => v.users = u,
            (Purpose::Devices, Ok(AdminResponse::Devices(d))) => v.devices = d,
            (Purpose::Me, Ok(AdminResponse::User(u))) => v.me = u,
            (Purpose::Totp, Ok(AdminResponse::Totp { secret, uri })) => {
                v.totp = Some((secret, uri));
                v.totp_code.clear();
            }
            (Purpose::Change(msg), Ok(AdminResponse::Ok)) => {
                v.message = Some((true, msg));
                refresh = true;
            }
            (_, Ok(AdminResponse::Error(e))) | (_, Err(e)) => v.message = Some((false, e)),
            _ => {}
        }
    }
    if refresh {
        v.refresh();
    }

    let mut leave = false;
    let is_admin = v.me.role == Role::Admin;
    egui::TopBottomPanel::top("admin_top")
        .frame(egui::Frame::new().fill(theme::SURFACE).inner_margin(egui::Margin::symmetric(20, 12)).stroke(egui::Stroke::new(1.0, theme::BORDER)))
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("< Back").clicked() {
                    leave = true;
                }
                ui.label(RichText::new("Accounts").size(18.0).strong().color(Color32::WHITE));
                ui.label(theme::hint(&v.title));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Refresh").clicked() {
                        v.refresh();
                    }
                    if !v.pending.is_empty() {
                        ui.add(egui::Spinner::new().size(14.0).color(theme::MUTED));
                    }
                });
            });
            if let Some((ok, m)) = &v.message {
                ui.add_space(4.0);
                theme::banner(ui, if *ok { theme::SUCCESS } else { theme::DANGER }, m);
            }
        });
    egui::CentralPanel::default().frame(egui::Frame::new().fill(theme::BG).inner_margin(egui::Margin::symmetric(20, 16))).show(ctx, |ui| {
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            if is_admin {
                theme::card().show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(theme::section("Users"));
                    ui.add_space(4.0);
                    let mut actions: Vec<(AdminRequest, String)> = Vec::new();
                    egui::Grid::new("users").striped(true).num_columns(9).spacing([14.0, 6.0]).show(ui, |ui| {
                        for h in ["User", "Role", "View", "Control", "Clipboard", "Files", "PIN", "2-step", ""] {
                            ui.label(RichText::new(h).small().strong().color(theme::MUTED));
                        }
                        ui.end_row();
                        for u in &v.users {
                            if u.disabled {
                                ui.label(RichText::new(format!("{} (disabled)", u.username)).color(theme::MUTED));
                            } else {
                                ui.label(RichText::new(&u.username).strong());
                            }
                            let mut role = u.role;
                            egui::ComboBox::from_id_salt(format!("role-{}", u.username))
                                .selected_text(role.as_str())
                                .show_ui(ui, |ui| {
                                    ui.selectable_value(&mut role, Role::Admin, "admin");
                                    ui.selectable_value(&mut role, Role::User, "user");
                                });
                            if role != u.role {
                                actions.push((
                                    AdminRequest::SetRole { username: u.username.clone(), role },
                                    format!("{} is now {}", u.username, role.as_str()),
                                ));
                            }
                            let mut p = u.perms;
                            let enabled = u.role != Role::Admin;
                            ui.add_enabled(enabled, egui::Checkbox::without_text(&mut p.view));
                            ui.add_enabled(enabled, egui::Checkbox::without_text(&mut p.control));
                            ui.add_enabled(enabled, egui::Checkbox::without_text(&mut p.clipboard));
                            ui.add_enabled(enabled, egui::Checkbox::without_text(&mut p.files));
                            if p != u.perms {
                                actions.push((
                                    AdminRequest::SetPermissions { username: u.username.clone(), perms: p },
                                    format!("updated permissions of {}", u.username),
                                ));
                            }
                            ui.label(if u.has_pin { "yes" } else { "no" });
                            ui.horizontal(|ui| {
                                ui.label(if u.has_totp { "on" } else { "off" });
                                if u.has_totp && u.username != v.me.username && ui.small_button("Turn off").clicked() {
                                    actions.push((
                                        AdminRequest::TotpDisable { username: u.username.clone() },
                                        format!("two-step sign-in turned off for {}", u.username),
                                    ));
                                }
                            });
                            ui.horizontal(|ui| {
                                let label = if u.disabled { "Enable" } else { "Disable" };
                                if ui.small_button(label).clicked() {
                                    actions.push((
                                        AdminRequest::SetDisabled { username: u.username.clone(), disabled: !u.disabled },
                                        format!("{} {}", label.to_lowercase() + "d", u.username),
                                    ));
                                }
                                if ui.small_button("Reset password").clicked() {
                                    v.reset = Some((u.username.clone(), String::new()));
                                }
                                if u.username != v.me.username && ui.small_button(RichText::new("Remove").color(theme::DANGER)).clicked() {
                                    v.confirm_remove = Some(u.username.clone());
                                }
                            });
                            ui.end_row();
                        }
                    });
                    for (req, msg) in actions {
                        v.request(req, Purpose::Change(msg));
                    }
                    if let Some(who) = v.confirm_remove.clone() {
                        ui.add_space(4.0);
                        theme::banner(ui, theme::DANGER, &format!("Remove {who}? Their account, PIN and remembered devices are deleted."));
                        ui.horizontal(|ui| {
                            if ui.add(theme::danger(&format!("Remove {who}"))).clicked() {
                                v.confirm_remove = None;
                                v.request(AdminRequest::RemoveUser { username: who.clone() }, Purpose::Change(format!("removed {who}")));
                            }
                            if ui.button("Cancel").clicked() {
                                v.confirm_remove = None;
                            }
                        });
                    }
                    if let Some((who, pw)) = &mut v.reset {
                        let who = who.clone();
                        let mut submit = false;
                        let mut cancel = false;
                        ui.horizontal(|ui| {
                            ui.label(format!("New password for {who}:"));
                            ui.add(egui::TextEdit::singleline(pw).password(true));
                            submit = ui.add(theme::primary("Set")).clicked();
                            cancel = ui.button("Cancel").clicked();
                        });
                        if submit {
                            let password = pw.clone();
                            v.reset = None;
                            v.request(
                                AdminRequest::SetPassword { username: who.clone(), password },
                                Purpose::Change(format!("password of {who} changed")),
                            );
                        } else if cancel {
                            v.reset = None;
                        }
                    }

                    ui.add_space(10.0);
                    ui.separator();
                    ui.label(RichText::new("Add a user").strong());
                    let (name, pw, admin, perms) = &mut v.new_user;
                    let mut add = false;
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(name).hint_text("username").desired_width(140.0));
                        ui.add(egui::TextEdit::singleline(pw).hint_text("password (8+)").password(true).desired_width(140.0));
                        ui.checkbox(admin, "admin");
                        ui.add_enabled_ui(!*admin, |ui| {
                            ui.checkbox(&mut perms.view, "view");
                            ui.checkbox(&mut perms.control, "control");
                            ui.checkbox(&mut perms.clipboard, "clipboard");
                            ui.checkbox(&mut perms.files, "files");
                        });
                        add = ui.add(theme::primary("Add")).clicked();
                    });
                    if add {
                        let req = AdminRequest::AddUser {
                            username: name.trim().to_string(),
                            password: std::mem::take(pw),
                            role: if *admin { Role::Admin } else { Role::User },
                            perms: *perms,
                        };
                        let msg = format!("added {}", name.trim());
                        name.clear();
                        v.request(req, Purpose::Change(msg));
                    }
                });
                ui.add_space(12.0);
            }

            theme::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(theme::section("My account"));
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.label("New password:");
                    ui.add(egui::TextEdit::singleline(&mut v.my_password).password(true).desired_width(160.0));
                    if ui.button("Change").clicked() {
                        let password = std::mem::take(&mut v.my_password);
                        let username = v.me.username.clone();
                        v.request(
                            AdminRequest::SetPassword { username, password },
                            Purpose::Change("password changed (remembered devices were signed out)".into()),
                        );
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("Quick-login PIN:");
                    ui.add(egui::TextEdit::singleline(&mut v.my_pin).password(true).hint_text("4-12 digits").desired_width(100.0));
                    if ui.button("Set PIN").clicked() {
                        let pin = Some(std::mem::take(&mut v.my_pin));
                        let username = v.me.username.clone();
                        v.request(AdminRequest::SetPin { username, pin }, Purpose::Change("PIN set".into()));
                    }
                    if ui.button("Remove PIN").clicked() {
                        let username = v.me.username.clone();
                        v.request(AdminRequest::SetPin { username, pin: None }, Purpose::Change("PIN removed".into()));
                    }
                });
                two_step_ui(ui, v);
            });
            ui.add_space(12.0);
            theme::card().show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(theme::section(if is_admin { "Remembered devices (all users)" } else { "My remembered devices" }));
                ui.add_space(4.0);
                if v.devices.is_empty() {
                    ui.label(theme::hint("None yet. Devices appear here when someone ticks \"Don't ask again on this device\"."));
                }
                let mut revoke = None;
                egui::Grid::new("devices").striped(true).num_columns(5).spacing([14.0, 6.0]).show(ui, |ui| {
                    for h in ["User", "Device", "Added", "Last used", ""] {
                        ui.label(RichText::new(h).small().strong().color(theme::MUTED));
                    }
                    ui.end_row();
                    for d in &v.devices {
                        ui.label(&d.username);
                        ui.label(&d.name);
                        ui.label(&d.created);
                        ui.label(d.last_used.as_deref().unwrap_or("-"));
                        if ui.small_button("Revoke").clicked() {
                            revoke = Some(d.id);
                        }
                        ui.end_row();
                    }
                });
                if let Some(id) = revoke {
                    v.request(AdminRequest::RevokeDevice { id }, Purpose::Change(format!("revoked device {id}")));
                }
            });
        });
    });
    leave
}

/// "Two-step sign-in" in My account: turn it on (QR code, then a code to confirm) or off.
fn two_step_ui(ui: &mut egui::Ui, v: &mut AdminView) {
    ui.add_space(6.0);
    ui.label(RichText::new("Two-step sign-in").strong());
    let grey = theme::MUTED;
    if v.me.has_totp {
        ui.horizontal(|ui| {
            ui.label("On: signing in also needs a code from your authenticator app (remembered devices don't).");
            if ui.button("Turn off").clicked() {
                let username = v.me.username.clone();
                v.request(AdminRequest::TotpDisable { username }, Purpose::Change("two-step sign-in turned off".into()));
            }
        });
        return;
    }
    match v.totp.clone() {
        None => {
            ui.horizontal(|ui| {
                ui.label("Off. Turn it on to also ask for a code from an app like Google Authenticator or Microsoft Authenticator.");
                if ui.button("Turn on").clicked() {
                    v.request(AdminRequest::TotpSetup, Purpose::Totp);
                }
            });
        }
        Some((secret, uri)) => {
            ui.label("1. Scan this with your authenticator app (or type the key below):");
            qr_code(ui, &uri, 4.0);
            ui.label(RichText::new(group(&secret)).monospace());
            ui.label(RichText::new("Keep this key private: anyone with it can make codes.").small().color(grey));
            ui.horizontal(|ui| {
                ui.label("2. Enter the code it shows:");
                let r = ui.add(egui::TextEdit::singleline(&mut v.totp_code).desired_width(90.0).char_limit(7));
                let enter = r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Turn on").clicked() || enter {
                    let code = v.totp_code.trim().to_string();
                    v.totp = None;
                    v.request(AdminRequest::TotpEnable { code }, Purpose::Change("two-step sign-in is on".into()));
                }
                if ui.button("Cancel").clicked() {
                    v.totp = None;
                }
            });
        }
    }
}

/// "ABCD EFGH ..." for reading a key aloud or typing it.
fn group(s: &str) -> String {
    s.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ")
}

/// Draw `text` as a QR code, `module` points per square.
fn qr_code(ui: &mut egui::Ui, text: &str, module: f32) {
    let Ok(code) = qrcode::QrCode::new(text.as_bytes()) else {
        ui.label("(couldn't make a QR code; type the key instead)");
        return;
    };
    let n = code.width();
    let quiet = 4.0;
    let side = (n as f32 + 2.0 * quiet) * module;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(side, side), egui::Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, 0.0, Color32::WHITE);
    let colors = code.to_colors();
    for y in 0..n {
        for x in 0..n {
            if colors[y * n + x] == qrcode::Color::Dark {
                let min = rect.min + egui::vec2((x as f32 + quiet) * module, (y as f32 + quiet) * module);
                p.rect_filled(egui::Rect::from_min_size(min, egui::vec2(module, module)), 0.0, Color32::BLACK);
            }
        }
    }
}

// ======================================================================== window / GL glue

struct GlWindow {
    window: winit::window::Window,
    gl_context: glutin::context::PossiblyCurrentContext,
    gl_display: glutin::display::Display,
    gl_surface: glutin::surface::Surface<glutin::surface::WindowSurface>,
}

impl GlWindow {
    unsafe fn new(event_loop: &winit::event_loop::ActiveEventLoop, attrs: winit::window::WindowAttributes) -> Result<Self> {
        use glutin::context::NotCurrentGlContext;
        use glutin::display::{GetGlDisplay, GlDisplay};
        use glutin::prelude::GlSurface;
        let template = glutin::config::ConfigTemplateBuilder::new()
            .prefer_hardware_accelerated(None)
            .with_depth_size(0)
            .with_stencil_size(0)
            .with_transparency(false);
        let (mut window, gl_config) = glutin_winit::DisplayBuilder::new()
            .with_preference(glutin_winit::ApiPreference::FallbackEgl)
            .with_window_attributes(Some(attrs.clone()))
            .build(event_loop, template, |mut configs| configs.next().expect("no GL config"))
            .map_err(|e| anyhow::anyhow!("create GL config: {e}"))?;
        let gl_display = gl_config.display();
        let raw = window.as_ref().map(|w| w.window_handle().expect("window handle").as_raw());
        let ctx_attrs = glutin::context::ContextAttributesBuilder::new().build(raw);
        let fallback = glutin::context::ContextAttributesBuilder::new()
            .with_context_api(glutin::context::ContextApi::Gles(None))
            .build(raw);
        let not_current = gl_display
            .create_context(&gl_config, &ctx_attrs)
            .or_else(|_| gl_display.create_context(&gl_config, &fallback))?;
        let window = match window.take() {
            Some(w) => w,
            None => glutin_winit::finalize_window(event_loop, attrs, &gl_config)?,
        };
        let (w, h): (u32, u32) = window.inner_size().into();
        let surface_attrs = glutin::surface::SurfaceAttributesBuilder::<glutin::surface::WindowSurface>::new().build(
            window.window_handle()?.as_raw(),
            NonZeroU32::new(w).unwrap_or(NonZeroU32::MIN),
            NonZeroU32::new(h).unwrap_or(NonZeroU32::MIN),
        );
        let gl_surface = gl_display.create_window_surface(&gl_config, &surface_attrs)?;
        let gl_context = not_current.make_current(&gl_surface)?;
        let _ = gl_surface.set_swap_interval(&gl_context, glutin::surface::SwapInterval::Wait(NonZeroU32::MIN));
        Ok(Self { window, gl_context, gl_display, gl_surface })
    }

    fn resize(&self, size: winit::dpi::PhysicalSize<u32>) {
        use glutin::surface::GlSurface;
        if let (Some(w), Some(h)) = (NonZeroU32::new(size.width), NonZeroU32::new(size.height)) {
            self.gl_surface.resize(&self.gl_context, w, h);
        }
    }

    fn swap(&self) {
        use glutin::surface::GlSurface;
        let _ = self.gl_surface.swap_buffers(&self.gl_context);
    }
}

enum UserEvent {
    Repaint(Duration),
}

/// What the window shows: the app, or the host's "screen is being shared" notice.
enum Start {
    Main(Option<String>),
    Notice(crate::notice::Notice),
    Installer(crate::installer::Installer),
}

enum Content {
    Main(Gui),
    Notice(crate::notice::Notice),
    Installer(crate::installer::Installer),
}

impl Content {
    fn ui(&mut self, ctx: &egui::Context) {
        match self {
            Content::Main(g) => g.ui(ctx),
            Content::Notice(n) => n.ui(ctx),
            Content::Installer(i) => i.ui(ctx),
        }
    }

    fn title(&self) -> String {
        match self {
            Content::Main(g) => g.window_title(),
            Content::Notice(n) => n.title(),
            Content::Installer(i) => i.title(),
        }
    }
}

struct App {
    proxy: winit::event_loop::EventLoopProxy<UserEvent>,
    rt: tokio::runtime::Handle,
    attrs: winit::window::WindowAttributes,
    start: Option<Start>,
    gl_window: Option<GlWindow>,
    gl: Option<Arc<glow::Context>>,
    egui_glow: Option<egui_glow::EguiGlow>,
    content: Option<Content>,
    repaint_at: Option<Instant>,
    title: String,
    /// Remote pointer made into a window cursor: ((change counter, scale), cursor).
    remote_cursor: Option<((u64, u32), winit::window::CustomCursor)>,
    /// The pointer is currently overridden (remote shape or hidden).
    cursor_overridden: bool,
    /// The window has keyboard focus.
    focused: bool,
    /// Gaming mode's pointer lock and system-shortcut capture as last applied.
    grabbed: bool,
    shortcuts_on: bool,
    /// Sub-pixel remainder of raw mouse motion.
    motion_rest: (f64, f64),
}

impl App {
    /// Pointer lock (gaming mode) and system-shortcut capture follow the session
    /// options and window focus.
    fn apply_grabs(&mut self) {
        let (Some(gw), Some(Content::Main(gui))) = (self.gl_window.as_ref(), self.content.as_mut()) else { return };
        let (gaming, shortcuts, sender) = match &gui.screen {
            Screen::Session(v) if v.handle.state.lock().unwrap().closed.is_none() => {
                (v.gaming && self.focused, v.shortcuts && self.focused, Some(v.handle.sender()))
            }
            _ => (false, false, None),
        };
        if gaming != self.grabbed {
            self.grabbed = gaming;
            if gaming {
                use winit::window::CursorGrabMode;
                if gw.window.set_cursor_grab(CursorGrabMode::Locked).is_err() {
                    let _ = gw.window.set_cursor_grab(CursorGrabMode::Confined);
                }
                gw.window.set_cursor_visible(false);
            } else {
                let _ = gw.window.set_cursor_grab(winit::window::CursorGrabMode::None);
                gw.window.set_cursor_visible(true);
                self.cursor_overridden = true; // let the pointer logic restore its shape
            }
        }
        if shortcuts != self.shortcuts_on {
            self.shortcuts_on = shortcuts;
            let window = keyhook::native_window(&gw.window);
            if let Err(e) = keyhook::set(window, if shortcuts { sender } else { None }) {
                if let Screen::Session(v) = &mut gui.screen {
                    v.shortcuts = false;
                    v.flash = Some((format!("System shortcuts unavailable: {e}"), Instant::now()));
                }
                self.shortcuts_on = false;
            }
        }
    }
    fn redraw(&mut self, event_loop: &winit::event_loop::ActiveEventLoop) {
        let (Some(gw), Some(eg), Some(content)) = (self.gl_window.as_mut(), self.egui_glow.as_mut(), self.content.as_mut()) else {
            return;
        };
        eg.run(&gw.window, |ctx| content.ui(ctx));
        if let Content::Main(gui) = content {
            if let Some(fs) = gui.pending_fullscreen.take() {
                gw.window.set_fullscreen(fs.then_some(winit::window::Fullscreen::Borderless(None)));
            }
            // After egui has set its own pointer: over the picture, show the remote one.
            // (Gaming mode keeps it hidden and locked.)
            let wanted = if self.grabbed { WantedCursor::Hidden } else { gui.wanted_cursor() };
            match wanted {
                WantedCursor::Os => {
                    if self.cursor_overridden {
                        self.cursor_overridden = false;
                        gw.window.set_cursor_visible(true);
                        gw.window.set_cursor(winit::window::CursorIcon::Default);
                    }
                }
                WantedCursor::Hidden => {
                    self.cursor_overridden = true;
                    gw.window.set_cursor_visible(false);
                }
                WantedCursor::Remote(seq, scale, shape) => {
                    let key = (seq, (scale * 100.0) as u32);
                    if self.remote_cursor.as_ref().is_none_or(|(k, _)| *k != key) {
                        self.remote_cursor = scaled_cursor(&shape, scale)
                            .and_then(|(rgba, w, h, hx, hy)| winit::window::CustomCursor::from_rgba(rgba, w, h, hx, hy).ok())
                            .map(|src| (key, event_loop.create_custom_cursor(src)));
                    }
                    if let Some((_, c)) = &self.remote_cursor {
                        self.cursor_overridden = true;
                        gw.window.set_cursor_visible(true);
                        gw.window.set_cursor(c.clone());
                    }
                }
            }
        }
        let title = content.title();
        if title != self.title {
            gw.window.set_title(&title);
            self.title = title;
        }
        unsafe {
            use glow::HasContext as _;
            let gl = self.gl.as_ref().unwrap();
            gl.clear_color(19.0 / 255.0, 21.0 / 255.0, 26.0 / 255.0, 1.0);
            gl.clear(glow::COLOR_BUFFER_BIT);
        }
        eg.paint(&gw.window);
        gw.swap();
        gw.window.set_visible(true);
        let _ = event_loop;
        self.apply_grabs();
    }
}

impl winit::application::ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, event_loop: &winit::event_loop::ActiveEventLoop) {
        if self.gl_window.is_some() {
            return;
        }
        let gw = match unsafe { GlWindow::new(event_loop, self.attrs.clone()) } {
            Ok(w) => w,
            Err(e) => {
                eprintln!("could not create an OpenGL window: {e:#}");
                event_loop.exit();
                return;
            }
        };
        let gl = Arc::new(unsafe {
            glow::Context::from_loader_function(|s| {
                use glutin::display::GlDisplay;
                let s = std::ffi::CString::new(s).unwrap();
                gw.gl_display.get_proc_address(&s)
            })
        });
        let eg = egui_glow::EguiGlow::new(event_loop, gl.clone(), None, None, true);
        crate::theme::apply(&eg.egui_ctx);
        let proxy = egui::mutex::Mutex::new(self.proxy.clone());
        eg.egui_ctx.set_request_repaint_callback(move |info| {
            let _ = proxy.lock().send_event(UserEvent::Repaint(info.delay));
        });
        gw.window.set_ime_allowed(false);
        self.content = Some(match self.start.take() {
            Some(Start::Notice(n)) => {
                // Bottom-right corner, clear of the taskbar (the compositor decides on Wayland).
                if let Some(m) = gw.window.current_monitor() {
                    let (mp, ms, ws) = (m.position(), m.size(), gw.window.outer_size());
                    let margin = (24.0 * m.scale_factor()) as i32;
                    let x = mp.x + ms.width as i32 - ws.width as i32 - margin;
                    let y = mp.y + ms.height as i32 - ws.height as i32 - margin * 3;
                    gw.window.set_outer_position(winit::dpi::PhysicalPosition::new(x.max(mp.x), y.max(mp.y)));
                }
                Content::Notice(n)
            }
            Some(Start::Installer(i)) => Content::Installer(i),
            Some(Start::Main(autoconnect)) => Content::Main(Gui::new(self.rt.clone(), eg.egui_ctx.clone(), autoconnect)),
            None => Content::Main(Gui::new(self.rt.clone(), eg.egui_ctx.clone(), None)),
        });
        // Hidden windows never get WM_PAINT on Windows, so show it before the first frame.
        gw.window.set_visible(true);
        gw.window.request_redraw();
        self.gl_window = Some(gw);
        self.gl = Some(gl);
        self.egui_glow = Some(eg);
    }

    fn window_event(&mut self, event_loop: &winit::event_loop::ActiveEventLoop, _id: winit::window::WindowId, event: WindowEvent) {
        match &event {
            WindowEvent::CloseRequested if matches!(self.content, Some(Content::Notice(_))) => {
                // The notice stays while someone is connected; Disconnect ends it.
                if let Some(gw) = &self.gl_window {
                    gw.window.set_minimized(true);
                }
                return;
            }
            WindowEvent::CloseRequested | WindowEvent::Destroyed => {
                // Dropping the GUI disconnects any session cleanly.
                self.content = None;
                event_loop.exit();
                return;
            }
            WindowEvent::RedrawRequested => {
                self.redraw(event_loop);
                return;
            }
            WindowEvent::Resized(size) => {
                if let Some(gw) = &self.gl_window {
                    gw.resize(*size);
                }
            }
            WindowEvent::Focused(f) => {
                self.focused = *f;
                self.apply_grabs();
            }
            _ => {}
        }
        let (Some(gw), Some(eg)) = (self.gl_window.as_ref(), self.egui_glow.as_mut()) else { return };
        if let Some(Content::Main(gui)) = self.content.as_mut() {
            let ppp = eg.egui_ctx.pixels_per_point();
            let wants_kb = eg.egui_ctx.wants_keyboard_input();
            if gui.remote_input(&event, ppp, wants_kb) {
                return;
            }
        }
        let r = eg.on_window_event(&gw.window, &event);
        if r.repaint {
            gw.window.request_redraw();
        }
    }

    fn device_event(&mut self, _: &winit::event_loop::ActiveEventLoop, _: winit::event::DeviceId, event: winit::event::DeviceEvent) {
        // Gaming mode: raw mouse movement, as relative motion.
        let winit::event::DeviceEvent::MouseMotion { delta } = event else { return };
        if !self.grabbed {
            return;
        }
        let Some(Content::Main(gui)) = self.content.as_ref() else { return };
        let Screen::Session(v) = &gui.screen else { return };
        let (x, y) = (delta.0 + self.motion_rest.0, delta.1 + self.motion_rest.1);
        let (dx, dy) = (x.trunc() as i32, y.trunc() as i32);
        self.motion_rest = (x - dx as f64, y - dy as f64);
        if dx != 0 || dy != 0 {
            v.handle.send(ClientMsg::Input(InputEvent::MouseRelative { dx, dy }));
        }
    }

    fn user_event(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop, event: UserEvent) {
        let UserEvent::Repaint(delay) = event;
        if delay.is_zero() {
            if let Some(gw) = &self.gl_window {
                gw.window.request_redraw();
            }
        } else if let Some(at) = Instant::now().checked_add(delay) {
            self.repaint_at = Some(self.repaint_at.map_or(at, |cur| cur.min(at)));
        }
    }

    fn about_to_wait(&mut self, event_loop: &winit::event_loop::ActiveEventLoop) {
        match self.repaint_at {
            Some(at) if at <= Instant::now() => {
                self.repaint_at = None;
                if let Some(gw) = &self.gl_window {
                    gw.window.request_redraw();
                }
                event_loop.set_control_flow(winit::event_loop::ControlFlow::Wait);
            }
            Some(at) => event_loop.set_control_flow(winit::event_loop::ControlFlow::WaitUntil(at)),
            None => event_loop.set_control_flow(winit::event_loop::ControlFlow::Wait),
        }
    }

    fn exiting(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop) {
        self.content = None;
        if let Some(eg) = self.egui_glow.as_mut() {
            eg.destroy();
        }
    }
}

/// Open the GUI. `autoconnect` immediately connects to a saved/typed target.
pub fn run(rt: tokio::runtime::Runtime, autoconnect: Option<String>) -> Result<()> {
    let attrs = winit::window::WindowAttributes::default()
        .with_resizable(true)
        .with_inner_size(winit::dpi::LogicalSize { width: 1100.0, height: 700.0 })
        .with_title("RD Remote Desktop")
        .with_visible(false);
    run_window(rt, attrs, Start::Main(autoconnect))
}

/// The "your screen is being shared" window on the host (`rd-client notice`).
pub fn run_notice(rt: tokio::runtime::Runtime, connect: &str) -> Result<()> {
    let notice = crate::notice::Notice::connect(connect)?;
    let attrs = winit::window::WindowAttributes::default()
        .with_resizable(true)
        .with_inner_size(winit::dpi::LogicalSize { width: 400.0, height: 360.0 })
        .with_title("RD Remote Desktop - screen shared")
        .with_window_level(winit::window::WindowLevel::AlwaysOnTop)
        .with_enabled_buttons(winit::window::WindowButtons::MINIMIZE)
        .with_visible(false);
    run_window(rt, attrs, Start::Notice(notice))
}

/// The installer or uninstaller window.
pub fn run_installer(rt: tokio::runtime::Runtime, installer: crate::installer::Installer) -> Result<()> {
    let attrs = winit::window::WindowAttributes::default()
        .with_resizable(true)
        .with_inner_size(winit::dpi::LogicalSize { width: 540.0, height: 340.0 })
        .with_title(installer.title())
        .with_visible(false);
    run_window(rt, attrs, Start::Installer(installer))
}

fn run_window(rt: tokio::runtime::Runtime, attrs: winit::window::WindowAttributes, start: Start) -> Result<()> {
    let event_loop = winit::event_loop::EventLoop::<UserEvent>::with_user_event().build()?;
    let mut app = App {
        proxy: event_loop.create_proxy(),
        rt: rt.handle().clone(),
        attrs,
        start: Some(start),
        gl_window: None,
        gl: None,
        egui_glow: None,
        content: None,
        repaint_at: None,
        title: String::new(),
        remote_cursor: None,
        cursor_overridden: false,
        focused: true,
        grabbed: false,
        shortcuts_on: false,
        motion_rest: (0.0, 0.0),
    };
    {
        // The file dialogs (xdg-desktop-portal on Linux) need a tokio context on this
        // thread; they block only for as long as the dialog is open.
        let _rt = rt.enter();
        event_loop.run_app(&mut app)?;
        drop(app);
    }
    rt.shutdown_timeout(Duration::from_millis(500));
    Ok(())
}
