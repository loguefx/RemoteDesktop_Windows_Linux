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
}

#[derive(Clone)]
struct SetupForm {
    name: String,
    pin: String,
    pin2: String,
    internet: bool,
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
}

type AdminReply = oneshot::Receiver<Result<AdminResponse, String>>;

enum Purpose {
    Users,
    Devices,
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
    message: Option<(bool, String)>,
    pending: Vec<(Purpose, AdminReply)>,
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
        };
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
                });
            }
            Ok(Outcome::Denied(why)) => {
                let (username, use_pin) = match &attempt.creds {
                    Creds::Password { username, .. } => (username.clone(), false),
                    Creds::Pin { username, .. } => (username.clone(), true),
                    Creds::Saved(u) => (u.clone().unwrap_or_default(), false),
                };
                let pin_only = use_pin && matches!(attempt.target, Dest::Computer(_));
                self.screen = Screen::SignIn(SignInForm {
                    target: attempt.target,
                    mode: attempt.mode,
                    username,
                    secret: String::new(),
                    use_pin,
                    pin_only,
                    remember: attempt.remember,
                    message: Some(why),
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
                    let ctx = self.ctx.clone();
                    let handle = session::Handle::start(&self.rt, s, move || ctx.request_repaint());
                    handle.send(ClientMsg::SetCodec(Store::load().video_codec()));
                    self.screen = Screen::Session(Box::new(SessionView {
                        handle,
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
                        message: None,
                        pending: vec![],
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
        let to_remote = |v: &SessionView, x: f64, y: f64| -> Option<(u32, u32)> {
            let r = v.image_rect?;
            let p = egui::pos2(x as f32 / ppp, y as f32 / ppp);
            if !r.contains(p) || v.remote_size.0 == 0 {
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
                if !event.repeat {
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
        // Message bars first: egui panels must be added before the central area.
        if let Some((msg, at)) = &self.notice {
            if at.elapsed() > Duration::from_secs(8) {
                self.notice = None;
            } else {
                let msg = msg.clone();
                egui::TopBottomPanel::top("notice").show(ctx, |ui| {
                    ui.colored_label(Color32::from_rgb(90, 170, 90), msg);
                });
                ctx.request_repaint_after(Duration::from_secs(1));
            }
        }
        if let Some((msg, at)) = &self.toast {
            if at.elapsed() > Duration::from_secs(8) {
                self.toast = None;
            } else {
                let msg = msg.clone();
                egui::TopBottomPanel::top("toast").show(ctx, |ui| {
                    ui.colored_label(Color32::from_rgb(230, 90, 90), msg);
                });
                ctx.request_repaint_after(Duration::from_secs(1));
            }
        }
        let mut next: Option<Screen> = None;
        let mut new_attempt: Option<(Attempt, Option<String>)> = None;
        let mut admin: Option<HomeAction> = None;

        match &mut self.screen {
            Screen::Home => {
                let scan = self.scan.lock().unwrap();
                match home_ui(ctx, &scan, &mut self.notice) {
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
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(ui.available_height() / 3.0);
                        ui.spinner();
                        ui.label(msg);
                    });
                });
            }
            Screen::Trust { fingerprint } => {
                let fp = fingerprint.clone();
                let target = self.attempt.as_ref().map(|a| a.target.label()).unwrap_or_default();
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.add_space(60.0);
                        ui.heading("New host");
                        ui.add_space(8.0);
                        ui.label(format!("This is the first time you connect to {target}."));
                        ui.label("Check that this fingerprint matches `rd-host info` on that computer:");
                        ui.add_space(8.0);
                        ui.label(RichText::new(&fp).monospace().strong());
                        ui.add_space(16.0);
                        ui.horizontal(|ui| {
                            if ui.button("Trust and continue").clicked() {
                                if let Some(a) = self.attempt.take() {
                                    new_attempt = Some((a, Some(fp.clone())));
                                }
                            }
                            if ui.button("Cancel").clicked() {
                                next = Some(Screen::Home);
                            }
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
            Screen::Session(v) => {
                if let Some(fs) = session_ui(ctx, v) {
                    if fs == SessionAction::Close {
                        next = Some(Screen::Home);
                    } else if let SessionAction::Fullscreen(on) = fs {
                        self.pending_fullscreen = Some(on);
                    }
                }
            }
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
                let req = SetupRequest { name: form.name.trim().to_string(), pin: form.pin.clone(), internet: form.internet };
                let mut back = form.clone();
                back.pin.clear();
                back.pin2.clear();
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
        let lan = Some(f.addr.to_string());
        let updated = Computer {
            name: f.announce.name.clone(),
            lan: lan.clone(),
            public: f.announce.public.clone().or_else(|| c.public.clone()),
            relay: f.announce.relay.clone().or_else(|| c.relay.clone()),
            auth: c.auth.clone(),
        };
        if updated.name != c.name || updated.lan != c.lan || updated.public != c.public || updated.relay != c.relay {
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
    c.name = f.announce.name.clone();
    c.lan = Some(f.addr.to_string());
    if f.announce.public.is_some() {
        c.public = f.announce.public.clone();
    }
    if f.announce.relay.is_some() {
        c.relay = f.announce.relay.clone();
    }
    let _ = store.save();
    key
}

/// A small filled circle (the UI font has no bullet glyph).
fn status_dot(ui: &mut egui::Ui, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, color);
}

fn home_ui(ctx: &egui::Context, scan: &ScanState, notice: &mut Option<(String, Instant)>) -> Option<HomeAction> {
    let mut out = None;
    let store = Store::load();
    let green = Color32::from_rgb(90, 170, 90);
    let grey = Color32::from_gray(140);
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.heading("RD Remote Desktop");
        ui.add_space(10.0);

        // ---------------------------------------------------- this computer
        ui.group(|ui| {
            ui.set_width(ui.available_width().min(640.0));
            ui.label(RichText::new("This computer").strong().size(16.0));
            let me = scan.found.iter().find(|f| f.local);
            match me {
                Some(f) => {
                    ui.horizontal(|ui| {
                        status_dot(ui, green);
                        ui.label(RichText::new(&f.announce.name).strong());
                        ui.label("- remote access is on");
                    });
                    match (&f.announce.public, &f.announce.public_note) {
                        (Some(p), note) => {
                            ui.label(RichText::new(format!("Reachable from the internet (router forwards {p}).")).small());
                            if let Some(n) = note {
                                ui.label(RichText::new(format!("Note: {n}.")).small().color(Color32::from_rgb(220, 150, 60)));
                            }
                            ui.label("")
                        }
                        (None, Some(n)) => ui.label(RichText::new(format!("Only reachable on this network: {n}.")).small().color(grey)),
                        (None, None) => ui.label(RichText::new("Checking the router...").small().color(grey)),
                    };
                    ui.horizontal(|ui| {
                        if ui.button("Change name or PIN").clicked() {
                            out = Some(HomeAction::OpenSetup(SetupForm {
                                name: f.announce.name.clone(),
                                pin: String::new(),
                                pin2: String::new(),
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
                        ui.label("Checking...");
                    });
                }
                None => {
                    ui.label("Remote access is off. Set it up to connect to this computer from your other devices.");
                    if ui.button("Set up remote access").clicked() {
                        out = Some(HomeAction::OpenSetup(SetupForm {
                            name: setup::default_name(),
                            pin: String::new(),
                            pin2: String::new(),
                            internet: true,
                            change: false,
                            error: None,
                        }));
                    }
                }
            }
        });
        ui.add_space(14.0);

        // ---------------------------------------------------- my computers
        ui.horizontal(|ui| {
            ui.label(RichText::new("My computers").strong().size(16.0));
            if scan.running {
                ui.spinner();
            }
        });
        ui.add_space(4.0);
        // Saved computers, plus ones found on the network that aren't saved yet.
        struct Row {
            key: String,
            name: String,
            online: Option<Found>,
            saved: Option<Computer>,
        }
        let mut rows: Vec<Row> = store
            .computers
            .iter()
            .map(|(k, c)| Row {
                key: k.clone(),
                name: c.name.clone(),
                online: scan.found.iter().find(|f| f.announce.fingerprint.eq_ignore_ascii_case(k)).cloned(),
                saved: Some(c.clone()),
            })
            .collect();
        for f in &scan.found {
            let k = f.announce.fingerprint.to_ascii_lowercase();
            if !store.computers.contains_key(&k) {
                rows.push(Row { key: k, name: f.announce.name.clone(), online: Some(f.clone()), saved: None });
            }
        }
        rows.retain(|r| !r.online.as_ref().is_some_and(|f| f.local));
        // A computer you tried but never got into, and that has gone away, isn't worth listing.
        rows.retain(|r| r.online.is_some() || r.saved.as_ref().is_some_and(|c| c.auth.username.is_some()));
        let online_names: Vec<String> =
            rows.iter().filter(|r| r.online.is_some()).map(|r| r.name.to_lowercase()).collect();
        rows.sort_by_key(|r| (r.online.is_none(), r.name.to_lowercase()));
        if rows.is_empty() {
            ui.label(RichText::new(if scan.done_once {
                "No other computers yet. Set up remote access on another computer with this app; it shows up here while it is on the same network, and stays here afterwards."
            } else {
                "Looking for computers on your network..."
            }).color(grey));
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            for row in rows {
                ui.group(|ui| {
                    ui.set_width(ui.available_width().min(640.0));
                    ui.horizontal(|ui| {
                        let (dot, status) = match (&row.online, &row.saved) {
                            (Some(_), _) => (green, "Online on this network".to_string()),
                            (None, _) if online_names.contains(&row.name.to_lowercase()) => {
                                (grey, "Older setup of a computer with this name; remove it from the ... menu".to_string())
                            }
                            (None, Some(c)) if c.public.is_some() || c.relay.is_some() => {
                                (grey, "Not on this network; will connect over the internet".to_string())
                            }
                            (None, _) => (grey, "Not found on this network".to_string()),
                        };
                        status_dot(ui, dot);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&row.name).strong());
                            let auto = row.saved.as_ref().is_some_and(|c| !c.auth.tokens.is_empty());
                            let extra = if auto { " · signs in automatically" } else { "" };
                            ui.label(RichText::new(format!("{status}{extra}")).small().color(grey));
                        });
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let saved = row.saved.is_some();
                            if saved {
                                ui.menu_button("...", |ui| {
                                    if ui.button("Manage accounts").clicked() {
                                        out = Some(HomeAction::Connect(Attempt {
                                            target: Dest::Computer(row.key.clone()),
                                            mode: Mode::Admin,
                                            creds: Creds::Saved(None),
                                            remember: false,
                                        }));
                                        ui.close_menu();
                                    }
                                    if ui.button("Sign out on this device").clicked() {
                                        let mut st = Store::load();
                                        if let Some(c) = st.computers.get_mut(&row.key) {
                                            c.auth.tokens.clear();
                                        }
                                        let _ = st.save();
                                        ui.close_menu();
                                    }
                                    if ui.button("Remove from my computers").clicked() {
                                        let mut st = Store::load();
                                        st.computers.remove(&row.key);
                                        let _ = st.save();
                                        *notice = Some((format!("Removed {}", row.name), Instant::now()));
                                        ui.close_menu();
                                    }
                                });
                            }
                            if ui.button("Connect").clicked() {
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
            }
        });
    });
    out
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
    let grey = Color32::from_gray(140);
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.add_space(30.0);
        dialog(ui, 440.0, |ui| {
            ui.heading(if f.change { "Change name or PIN" } else { "Set up remote access" });
            ui.add_space(6.0);
            ui.label("Choose a name for this computer and a PIN. You'll enter the PIN when you connect to this computer from another device.");
            ui.add_space(12.0);
            if let Some(e) = &f.error {
                ui.colored_label(Color32::from_rgb(230, 90, 90), e);
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
            ui.add_space(6.0);
            ui.label(
                RichText::new("After 5 wrong PINs, sign-in pauses for a while; after 10 the PIN is switched off until you set it again here.")
                    .small()
                    .color(grey),
            );
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let label = if f.change { "Save" } else { "Set up" };
                if ui.button(label).clicked() {
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
    if out == Some(true) {
        let req = SetupRequest { name: f.name.trim().to_string(), pin: f.pin.clone(), internet: f.internet };
        if let Err(e) = setup::validate(&req) {
            f.error = Some(e);
            return None;
        }
        if f.pin != f.pin2 {
            f.error = Some("The PINs don't match.".into());
            return None;
        }
    }
    out
}

/// Some(Some(attempt)) = submit, Some(None) = cancel, None = nothing yet.
fn sign_in_ui(ctx: &egui::Context, f: &mut SignInForm) -> Option<Option<Attempt>> {
    let mut out = None;
    let label = f.target.label();
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.add_space(40.0);
        dialog(ui, 400.0, |ui| {
            if f.pin_only {
                ui.heading(format!("Connect to {label}"));
                ui.label("Enter the PIN chosen when remote access was set up on that computer.");
            } else {
                ui.heading(if f.mode == Mode::Admin { "Sign in to manage accounts" } else { "Sign in" });
                ui.label(RichText::new(&label).monospace());
            }
            ui.add_space(12.0);
            if let Some(m) = &f.message {
                let m = if f.pin_only && m == "invalid username or credentials" { "Wrong PIN. Try again." } else { m.as_str() };
                ui.colored_label(Color32::from_rgb(230, 120, 80), m);
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
            });
            ui.add_space(4.0);
            if !f.pin_only {
                ui.checkbox(&mut f.use_pin, "Sign in with my PIN");
            }
            ui.checkbox(&mut f.remember, "Don't ask again on this device");
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                if ui.button(if f.pin_only { "Connect" } else { "Sign in" }).clicked() {
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
    match out {
        Some(true) if (f.pin_only || !f.username.trim().is_empty()) && !f.secret.is_empty() => {
            let username = if f.pin_only { String::new() } else { f.username.trim().to_string() };
            let secret = std::mem::take(&mut f.secret);
            let creds = if f.use_pin { Creds::Pin { username, pin: secret } } else { Creds::Password { username, password: secret } };
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
    let perms = v.user.effective();
    let (status, displays, current, viewers, closed) = {
        let s = v.handle.state.lock().unwrap();
        (s.status.clone(), s.displays.clone(), s.current_display, s.viewers.clone(), s.closed.clone())
    };

    if let Some(why) = closed {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(80.0);
                ui.heading("Session ended");
                ui.label(why);
                if ui.button("Back").clicked() {
                    action = Some(SessionAction::Close);
                }
            });
        });
        return action;
    }

    if !v.fullscreen {
        egui::TopBottomPanel::top("toolbar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&v.title).strong());
                ui.separator();
                if displays.len() > 1 && perms.control {
                    let label = |d: &rd_core::proto::DisplayInfo| format!("{} {}x{}", d.name, d.width, d.height);
                    let cur = displays.iter().find(|d| d.index == current).map(label).unwrap_or_default();
                    egui::ComboBox::from_id_salt("display").selected_text(cur).show_ui(ui, |ui| {
                        for d in &displays {
                            if ui.selectable_label(d.index == current, label(d)).clicked() {
                                v.handle.send(ClientMsg::SelectDisplay(d.index));
                            }
                        }
                    });
                }
                {
                    let (codec, kbps) = {
                        let s = v.handle.state.lock().unwrap();
                        (s.codec, s.kbps)
                    };
                    let smooth = matches!(codec, VideoCodec::H264 { .. });
                    let label = |smooth: bool| if smooth { "Picture: smooth" } else { "Picture: sharp" };
                    egui::ComboBox::from_id_salt("codec").selected_text(label(smooth)).show_ui(ui, |ui| {
                        let choices = [
                            (true, VideoCodec::H264 { max_kbps: 0 }, "Smooth (H.264): best for video and slow connections"),
                            (false, VideoCodec::Tiles, "Sharp (lossless): pixel-exact, needs a fast connection"),
                        ];
                        for (is_smooth, c, text) in choices {
                            if ui.selectable_label(smooth == is_smooth, text).clicked() && smooth != is_smooth {
                                v.handle.send(ClientMsg::SetCodec(c));
                                let mut store = Store::load();
                                store.set_video_codec(c);
                                let _ = store.save();
                            }
                        }
                    });
                    if smooth && kbps > 0 {
                        ui.label(format!("{:.1} Mbit/s", kbps as f32 / 1000.0))
                            .on_hover_text("Current H.264 bitrate; it adapts to the connection");
                    }
                }
                if perms.control && ui.button("Ctrl+Alt+Del").clicked() {
                    v.handle.send(ClientMsg::SecureAttention);
                }
                let audio_label = if v.audio_on { "Sound: on" } else { "Sound: off" };
                if ui.button(audio_label).clicked() {
                    let want = !v.audio_on;
                    match v.handle.set_audio(want) {
                        Ok(()) => v.audio_on = want,
                        Err(e) => v.handle.state.lock().unwrap().status = format!("audio unavailable: {e:#}"),
                    }
                }
                if perms.files && ui.selectable_label(v.show_files, "Files").clicked() {
                    v.show_files = !v.show_files;
                    if v.show_files && v.handle.state.lock().unwrap().dir.is_none() {
                        v.handle.list_dir("");
                    }
                }
                if ui.button("Full screen").on_hover_text("Press F11 to leave full screen").clicked() {
                    v.fullscreen = true;
                    action = Some(SessionAction::Fullscreen(true));
                }
                if ui.button("Disconnect").clicked() {
                    action = Some(SessionAction::Close);
                }
                ui.separator();
                ui.label(&status);
                if viewers.len() > 1 {
                    ui.label(format!("| viewers: {}", viewers.join(", ")));
                }
            });
        });
    } else if ctx.input(|i| i.key_pressed(egui::Key::F11)) {
        v.fullscreen = false;
        action = Some(SessionAction::Fullscreen(false));
    }

    if v.show_files && !v.fullscreen {
        files_panel(ctx, v);
    }

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
                    Some(t) => t.set(img, TextureOptions::LINEAR),
                    None => v.texture = Some(ctx.load_texture("remote", img, TextureOptions::LINEAR)),
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
                    tex.set_partial([x, y], ColorImage { size: [tw, th], pixels: px }, TextureOptions::LINEAR);
                }
            }
        }
    }

    egui::CentralPanel::default().frame(egui::Frame::NONE.fill(Color32::from_gray(24))).show(ctx, |ui| {
        let avail = ui.available_rect_before_wrap();
        match &v.texture {
            Some(tex) if v.remote_size.0 > 0 => {
                let (rw, rh) = (v.remote_size.0 as f32, v.remote_size.1 as f32);
                let scale = (avail.width() / rw).min(avail.height() / rh);
                let size = egui::vec2(rw * scale, rh * scale);
                let rect = egui::Rect::from_center_size(avail.center(), size);
                ui.painter().image(
                    tex.id(),
                    rect,
                    egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                    Color32::WHITE,
                );
                v.image_rect = Some(rect);
                let hover = ctx.pointer_latest_pos().is_some_and(|p| rect.contains(p)) && !ctx.is_pointer_over_area();
                v.remote_hover = hover || (v.fullscreen && ctx.pointer_latest_pos().is_some_and(|p| rect.contains(p)));
            }
            _ => {
                ui.centered_and_justified(|ui| {
                    ui.label(RichText::new(&status).color(Color32::LIGHT_GRAY));
                });
            }
        }
    });
    action
}

fn files_panel(ctx: &egui::Context, v: &mut SessionView) {
    egui::SidePanel::right("files").default_width(360.0).show(ctx, |ui| {
        ui.heading("Files on the remote computer");
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
            let r = ui.add(egui::TextEdit::singleline(&mut v.path_input).desired_width(180.0));
            if ui.button("Go").clicked() || (r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                v.handle.list_dir(&v.path_input);
            }
        });
        if let Some(e) = err {
            ui.colored_label(Color32::from_rgb(230, 90, 90), e);
        }
        if ui.button("Upload a file...").on_hover_text("Or drop files onto the window").clicked() {
            if let Some(path) = rfd::FileDialog::new().pick_file() {
                v.handle.upload(path);
            }
        }
        ui.label(RichText::new("Uploads go to the remote user's Downloads folder.").small());
        ui.separator();
        egui::ScrollArea::vertical().max_height(ui.available_height() * 0.6).id_salt("entries").show(ui, |ui| {
            for e in &entries {
                ui.horizontal(|ui| {
                    let base = dir_path.clone().unwrap_or_default();
                    let sep = if base.contains('\\') { "\\" } else { "/" };
                    let full = if base.ends_with(sep) { format!("{base}{}", e.name) } else { format!("{base}{sep}{}", e.name) };
                    if e.is_dir {
                        if ui.link(format!("[dir] {}", e.name)).clicked() {
                            v.path_input = full.clone();
                            v.handle.list_dir(&full);
                        }
                    } else {
                        ui.label(&e.name);
                        ui.label(RichText::new(human(e.size)).small());
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
                let arrow = if t.direction == Direction::Download { "down" } else { "up" };
                ui.label(format!("{arrow}: {}", t.name));
                match &t.state {
                    TransferState::Active => {
                        let frac = if t.total > 0 { t.done as f32 / t.total as f32 } else { 0.0 };
                        ui.add(egui::ProgressBar::new(frac).text(format!("{} / {}", human(t.done), human(t.total))));
                    }
                    TransferState::Done(m) => {
                        ui.label(RichText::new(m).small().color(Color32::from_rgb(110, 190, 110)));
                    }
                    TransferState::Failed(m) => {
                        ui.label(RichText::new(m).small().color(Color32::from_rgb(230, 90, 90)));
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
    egui::TopBottomPanel::top("admin_top").show(ctx, |ui| {
        ui.horizontal(|ui| {
            ui.heading(format!("Accounts - {}", v.title));
            if ui.button("Back").clicked() {
                leave = true;
            }
            if ui.button("Refresh").clicked() {
                v.refresh();
            }
        });
        if let Some((ok, m)) = &v.message {
            let color = if *ok { Color32::from_rgb(110, 190, 110) } else { Color32::from_rgb(230, 90, 90) };
            ui.colored_label(color, m);
        }
    });
    egui::CentralPanel::default().show(ctx, |ui| {
        egui::ScrollArea::vertical().show(ui, |ui| {
            if is_admin {
                ui.heading("Users");
                let mut actions: Vec<(AdminRequest, String)> = Vec::new();
                egui::Grid::new("users").striped(true).num_columns(8).show(ui, |ui| {
                    for h in ["User", "Role", "View", "Control", "Clipboard", "Files", "PIN", ""] {
                        ui.label(RichText::new(h).strong());
                    }
                    ui.end_row();
                    for u in &v.users {
                        ui.label(if u.disabled { format!("{} (disabled)", u.username) } else { u.username.clone() });
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
                            if u.username != v.me.username && ui.small_button("Remove").clicked() {
                                actions.push((
                                    AdminRequest::RemoveUser { username: u.username.clone() },
                                    format!("removed {}", u.username),
                                ));
                            }
                        });
                        ui.end_row();
                    }
                });
                for (req, msg) in actions {
                    v.request(req, Purpose::Change(msg));
                }
                if let Some((who, pw)) = &mut v.reset {
                    let who = who.clone();
                    let mut submit = false;
                    let mut cancel = false;
                    ui.horizontal(|ui| {
                        ui.label(format!("New password for {who}:"));
                        ui.add(egui::TextEdit::singleline(pw).password(true));
                        submit = ui.button("Set").clicked();
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
                    add = ui.button("Add").clicked();
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
                ui.separator();
            }

            ui.heading("My account");
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
            ui.separator();
            ui.heading(if is_admin { "Remembered devices (all users)" } else { "My remembered devices" });
            let mut revoke = None;
            egui::Grid::new("devices").striped(true).num_columns(5).show(ui, |ui| {
                for h in ["User", "Device", "Added", "Last used", ""] {
                    ui.label(RichText::new(h).strong());
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
    leave
}

// ======================================================================== window / GL glue

struct GlWindow {
    window: winit::window::Window,
    gl_context: glutin::context::PossiblyCurrentContext,
    gl_display: glutin::display::Display,
    gl_surface: glutin::surface::Surface<glutin::surface::WindowSurface>,
}

impl GlWindow {
    unsafe fn new(event_loop: &winit::event_loop::ActiveEventLoop) -> Result<Self> {
        use glutin::context::NotCurrentGlContext;
        use glutin::display::{GetGlDisplay, GlDisplay};
        use glutin::prelude::GlSurface;
        let attrs = winit::window::WindowAttributes::default()
            .with_resizable(true)
            .with_inner_size(winit::dpi::LogicalSize { width: 1100.0, height: 700.0 })
            .with_title("RD Remote Desktop")
            .with_visible(false);
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

struct App {
    proxy: winit::event_loop::EventLoopProxy<UserEvent>,
    rt: tokio::runtime::Handle,
    autoconnect: Option<String>,
    gl_window: Option<GlWindow>,
    gl: Option<Arc<glow::Context>>,
    egui_glow: Option<egui_glow::EguiGlow>,
    gui: Option<Gui>,
    repaint_at: Option<Instant>,
    title: String,
}

impl App {
    fn redraw(&mut self, event_loop: &winit::event_loop::ActiveEventLoop) {
        let (Some(gw), Some(eg), Some(gui)) = (self.gl_window.as_mut(), self.egui_glow.as_mut(), self.gui.as_mut()) else {
            return;
        };
        eg.run(&gw.window, |ctx| gui.ui(ctx));
        if let Some(fs) = gui.pending_fullscreen.take() {
            gw.window.set_fullscreen(fs.then_some(winit::window::Fullscreen::Borderless(None)));
        }
        let title = gui.window_title();
        if title != self.title {
            gw.window.set_title(&title);
            self.title = title;
        }
        unsafe {
            use glow::HasContext as _;
            let gl = self.gl.as_ref().unwrap();
            gl.clear_color(0.1, 0.1, 0.1, 1.0);
            gl.clear(glow::COLOR_BUFFER_BIT);
        }
        eg.paint(&gw.window);
        gw.swap();
        gw.window.set_visible(true);
        let _ = event_loop;
    }
}

impl winit::application::ApplicationHandler<UserEvent> for App {
    fn resumed(&mut self, event_loop: &winit::event_loop::ActiveEventLoop) {
        if self.gl_window.is_some() {
            return;
        }
        let gw = match unsafe { GlWindow::new(event_loop) } {
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
        let proxy = egui::mutex::Mutex::new(self.proxy.clone());
        eg.egui_ctx.set_request_repaint_callback(move |info| {
            let _ = proxy.lock().send_event(UserEvent::Repaint(info.delay));
        });
        gw.window.set_ime_allowed(false);
        self.gui = Some(Gui::new(self.rt.clone(), eg.egui_ctx.clone(), self.autoconnect.take()));
        // Hidden windows never get WM_PAINT on Windows, so show it before the first frame.
        gw.window.set_visible(true);
        gw.window.request_redraw();
        self.gl_window = Some(gw);
        self.gl = Some(gl);
        self.egui_glow = Some(eg);
    }

    fn window_event(&mut self, event_loop: &winit::event_loop::ActiveEventLoop, _id: winit::window::WindowId, event: WindowEvent) {
        match &event {
            WindowEvent::CloseRequested | WindowEvent::Destroyed => {
                // Dropping the GUI disconnects any session cleanly.
                self.gui = None;
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
            _ => {}
        }
        let (Some(gw), Some(eg)) = (self.gl_window.as_ref(), self.egui_glow.as_mut()) else { return };
        if let Some(gui) = self.gui.as_mut() {
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
        self.gui = None;
        if let Some(eg) = self.egui_glow.as_mut() {
            eg.destroy();
        }
    }
}

/// Open the GUI. `autoconnect` immediately connects to a saved/typed target.
pub fn run(rt: tokio::runtime::Runtime, autoconnect: Option<String>) -> Result<()> {
    let event_loop = winit::event_loop::EventLoop::<UserEvent>::with_user_event().build()?;
    let mut app = App {
        proxy: event_loop.create_proxy(),
        rt: rt.handle().clone(),
        autoconnect,
        gl_window: None,
        gl: None,
        egui_glow: None,
        gui: None,
        repaint_at: None,
        title: String::new(),
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
