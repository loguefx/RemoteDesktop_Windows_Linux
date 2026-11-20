//! Desktop agent: runs inside the interactive desktop session. Captures + encodes the
//! screen, injects input, syncs the clipboard, captures system audio and serves file
//! transfers. It only talks to the local daemon over loopback, which authenticates it
//! with a one-time token passed in `RD_AGENT_TOKEN`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rd_core::codec::{Encoder, Frame};
use rd_core::framing::{read_msg, write_msg};
use rd_core::proto::{AgentCmd, AgentEvent, AgentHello, DisplayInfo, DisplayPart, FileRequest, InputEvent};
use rd_core::PROTOCOL_VERSION;
use rd_platform::Backend;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::{audio_cap, clip, files, notice};

pub const TOKEN_ENV: &str = "RD_AGENT_TOKEN";

pub struct AgentOptions {
    pub connect: SocketAddr,
    pub backend: Backend,
    pub fps: u32,
    /// Windows service mode: the agent is SYSTEM, so file access impersonates the
    /// signed-in console user.
    pub impersonate_console_user: bool,
}

/// Events other than frames (clipboard, audio, files, display list). Unbounded so the
/// audio callback never blocks; file downloads are bounded by their ack window.
pub type EventTx = mpsc::UnboundedSender<AgentEvent>;

/// Work for the input thread: it owns the injector, so blocking local input for the
/// privacy screen happens there too (Windows only lets the blocking thread inject).
enum InputCmd {
    Event(InputEvent),
    Privacy(bool),
    /// Undo the privacy screen and answer, before the agent exits.
    Finish(std_mpsc::Sender<()>),
}

pub async fn run(opts: AgentOptions) -> Result<()> {
    let token = std::env::var(TOKEN_ENV).context("RD_AGENT_TOKEN not set (the agent is started by the host service)")?;
    std::env::remove_var(TOKEN_ENV);
    let stream = TcpStream::connect(opts.connect).await.context("connect to daemon")?;
    stream.set_nodelay(true)?;
    let (mut rd, mut wr) = stream.into_split();
    write_msg(&mut wr, &AgentHello { version: PROTOCOL_VERSION, token }).await?;

    // Frames get a tiny bounded queue: back-pressure lowers the frame rate instead of
    // adding latency. Everything else goes through the unbounded side channel.
    let (frame_tx, mut frame_rx) = mpsc::channel::<AgentEvent>(2);
    let (evt_tx, mut evt_rx) = mpsc::unbounded_channel::<AgentEvent>();
    let (input_tx, input_rx) = std_mpsc::channel::<InputCmd>();
    let (display_tx, display_rx) = std_mpsc::channel::<u32>();
    let (res_tx, res_rx) = std_mpsc::channel::<Option<(u32, u32)>>();
    let (file_tx, file_rx) = std_mpsc::channel::<(u32, FileRequest)>();
    let keyframe = Arc::new(AtomicBool::new(true));
    let stop = Arc::new(AtomicBool::new(false));

    {
        let (keyframe, stop, frame_tx, evt_tx) = (keyframe.clone(), stop.clone(), frame_tx.clone(), evt_tx.clone());
        let (backend, fps) = (opts.backend, opts.fps);
        std::thread::Builder::new().name("capture".into()).spawn(move || {
            if let Err(e) = capture_thread(backend, fps, keyframe, stop, frame_tx, evt_tx.clone(), input_rx, display_rx, res_rx) {
                log::error!("capture failed: {e:#}");
                let _ = evt_tx.send(AgentEvent::Error(format!("{e:#}")));
            }
        })?;
    }
    drop(frame_tx);
    let clip = clip::spawn(evt_tx.clone());
    files::spawn(file_rx, evt_tx.clone(), opts.impersonate_console_user);
    let mut audio: Option<audio_cap::Capture> = None;
    // "Your screen is being shared" window on this computer's screen.
    let mut notice = notice::Notice::new(evt_tx.clone(), opts.impersonate_console_user);

    let writer = tokio::spawn(async move {
        loop {
            let ev = tokio::select! {
                Some(ev) = frame_rx.recv() => ev,
                Some(ev) = evt_rx.recv() => ev,
                else => break,
            };
            let fatal = matches!(ev, AgentEvent::Error(_));
            write_msg(&mut wr, &ev).await?;
            if fatal {
                break;
            }
        }
        anyhow::Ok(())
    });

    let reader = async {
        loop {
            match read_msg::<_, AgentCmd>(&mut rd).await? {
                AgentCmd::Input(ev) => {
                    if input_tx.send(InputCmd::Event(ev)).is_err() {
                        break;
                    }
                }
                AgentCmd::CtrlAltDel => {
                    // Non-Windows hosts: it's just a key chord.
                    for (code, down) in [(29, true), (56, true), (111, true), (111, false), (56, false), (29, false)] {
                        let _ = input_tx.send(InputCmd::Event(InputEvent::Key { code, down }));
                    }
                }
                AgentCmd::Privacy(on) => {
                    let _ = input_tx.send(InputCmd::Privacy(on));
                }
                AgentCmd::SetResolution(size) => {
                    let _ = res_tx.send(size);
                }
                AgentCmd::Lock => {
                    let as_user = opts.impersonate_console_user;
                    let _ = tokio::task::spawn_blocking(move || lock_screen(as_user)).await;
                }
                AgentCmd::Chat { from, text } => notice.chat(&from, &text),
                AgentCmd::Ask { id, label } => notice.ask(id, &label),
                AgentCmd::AskDone(id) => notice.ask_done(id),
                AgentCmd::RequestKeyframe => keyframe.store(true, Ordering::Relaxed),
                AgentCmd::SelectDisplay(i) => {
                    let _ = display_tx.send(i);
                }
                AgentCmd::SetClipboard(data) => {
                    clip.set(data);
                }
                AgentCmd::SetAudio(on) => {
                    if on && audio.is_none() {
                        match audio_cap::Capture::start(evt_tx.clone()) {
                            Ok(c) => audio = Some(c),
                            Err(e) => log::warn!("audio capture unavailable: {e:#}"),
                        }
                    } else if !on {
                        audio = None;
                    }
                }
                AgentCmd::Files { client, req } => {
                    let _ = file_tx.send((client, req));
                }
                AgentCmd::Viewers(list) => notice.update(list),
                AgentCmd::Stop => break,
            }
        }
        anyhow::Ok(())
    };

    tokio::select! {
        r = reader => { if let Err(e) = r { log::debug!("daemon link closed: {e:#}"); } }
        r = writer => { if let Ok(Err(e)) = r { log::debug!("daemon link write failed: {e:#}"); } }
    }
    // Give the keyboard and mouse back (privacy screen) before the process exits.
    let (done_tx, done_rx) = std_mpsc::channel();
    if input_tx.send(InputCmd::Finish(done_tx)).is_ok() {
        let _ = tokio::task::spawn_blocking(move || done_rx.recv_timeout(Duration::from_secs(2))).await;
    }
    stop.store(true, Ordering::Relaxed);
    log::info!("agent session ended");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn capture_thread(
    backend: Backend,
    fps: u32,
    keyframe: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    frames: mpsc::Sender<AgentEvent>,
    events: EventTx,
    input_rx: std_mpsc::Receiver<InputCmd>,
    display_rx: std_mpsc::Receiver<u32>,
    res_rx: std_mpsc::Receiver<Option<(u32, u32)>>,
) -> Result<()> {
    let session = rd_platform::open(backend)?;
    let backend_name = session.backend.to_string();
    let mut capturer = session.capturer;
    let mut injector = session.injector;

    // Left edge of the shown slice when only part of a wide monitor is shown: pointer
    // positions from viewers are relative to the slice.
    let crop_x = Arc::new(AtomicU32::new(0));

    // Input runs on its own thread so a slow capture never delays clicks/keys.
    let input_stop = stop.clone();
    let input_crop_x = crop_x.clone();
    let input_events = events.clone();
    let resolved = session.backend;
    std::thread::Builder::new().name("input".into()).spawn(move || {
        let mut screen: Option<Box<dyn rd_platform::PrivacyScreen>> = None;
        while let Ok(cmd) = input_rx.recv() {
            match cmd {
                InputCmd::Event(mut ev) => {
                    if input_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    if let InputEvent::MouseMove { x, .. } = &mut ev {
                        *x = x.saturating_add(input_crop_x.load(Ordering::Relaxed));
                    }
                    if let Err(e) = injector.inject(&ev) {
                        log::warn!("input injection failed: {e:#}");
                    }
                }
                InputCmd::Privacy(true) => {
                    let mut notes = Vec::new();
                    if screen.is_none() {
                        match rd_platform::privacy_screen(resolved) {
                            Ok(s) => screen = Some(s),
                            Err(e) => notes.push(format!("{e:#}")),
                        }
                    }
                    if let Err(e) = injector.block_local_input(true) {
                        notes.push(format!("{e:#}"));
                    }
                    let on = screen.is_some();
                    if !on {
                        let _ = injector.block_local_input(false);
                    }
                    log::info!("privacy screen {}", if on { "on" } else { "unavailable" });
                    let note = (!notes.is_empty()).then(|| {
                        if on { format!("Privacy screen on, but: {}", notes.join("; ")) } else { format!("Privacy screen unavailable: {}", notes.join("; ")) }
                    });
                    let _ = input_events.send(AgentEvent::Privacy { on, note });
                }
                InputCmd::Privacy(false) => {
                    screen = None;
                    let _ = injector.block_local_input(false);
                    let _ = input_events.send(AgentEvent::Privacy { on: false, note: None });
                }
                InputCmd::Finish(done) => {
                    screen = None;
                    let _ = injector.inject(&InputEvent::ReleaseAll);
                    let _ = injector.block_local_input(false);
                    let _ = done.send(());
                    break;
                }
            }
        }
        drop(screen);
        // Dropping the injector releases anything still held.
    })?;

    // The monitors offered to viewers: the real ones, then slices of wide ones.
    let mut listed: Vec<DisplayInfo> = Vec::new();
    // The slice being shown, if any (the capturer shows its whole parent monitor).
    let mut part: Option<DisplayPart> = None;
    let mut cropped = Frame::default();
    let send_displays = |c: &dyn rd_platform::Capturer, listed: &mut Vec<DisplayInfo>, part: Option<DisplayPart>| {
        *listed = rd_core::proto::with_display_parts(&c.displays());
        let current = part
            .and_then(|p| listed.iter().find(|d| d.part() == Some(p)).map(|d| d.index))
            .unwrap_or(c.current_display());
        let _ = events.send(AgentEvent::Displays { list: listed.clone(), current });
    };
    send_displays(capturer.as_ref(), &mut listed, part);

    let interval = Duration::from_secs_f64(1.0 / fps.clamp(1, 120) as f64);
    let mut encoder = Encoder::new();
    let mut announced = false;
    let mut last_sent = Instant::now() - interval;
    let mut stats = (Instant::now(), 0u32, 0usize);

    while !stop.load(Ordering::Relaxed) {
        if let Some(c) = capturer.cursor() {
            let _ = events.send(AgentEvent::Cursor(c));
        }
        let res = res_rx.try_iter().last();
        if let (Some(Some(_)), Some(_)) = (res, part) {
            // A window-sized mode for the whole monitor would make no sense for a slice.
            log::info!("not fitting the resolution while part of a monitor is shown");
        } else if let Some(size) = res {
            match capturer.set_resolution(size) {
                Ok((w, h)) => {
                    log::info!("display resolution now {w}x{h}");
                    encoder.force_keyframe();
                    send_displays(capturer.as_ref(), &mut listed, part);
                }
                Err(e) => {
                    let _ = events.send(AgentEvent::Resolution(format!("Couldn't fit the resolution: {e:#}")));
                }
            }
        }
        if let Some(index) = display_rx.try_iter().last() {
            let want = listed.get(index as usize).and_then(|d| d.part());
            let real = want.map(|p| p.parent).unwrap_or(index);
            let r = if real == capturer.current_display() { Ok(()) } else { capturer.select_display(real) };
            match r {
                Ok(()) => {
                    part = want;
                    encoder.force_keyframe();
                    send_displays(capturer.as_ref(), &mut listed, part);
                }
                Err(e) => log::warn!("select display {index}: {e:#}"),
            }
        }
        let Some(frame) = capturer.capture(Duration::from_millis(100))? else {
            continue;
        };
        let frame = match part.map(|p| p.span(frame.width)) {
            Some((x0, w)) if w >= 16 => {
                crop(&mut cropped, frame, x0, w);
                crop_x.store(x0, Ordering::Relaxed);
                &cropped
            }
            _ => {
                crop_x.store(0, Ordering::Relaxed);
                frame
            }
        };
        if !announced {
            announced = true;
            let ready = AgentEvent::Ready { backend: backend_name.clone(), width: frame.width, height: frame.height };
            if frames.blocking_send(ready).is_err() {
                break;
            }
        }
        if keyframe.swap(false, Ordering::Relaxed) {
            encoder.force_keyframe();
        }
        if let Some(enc) = encoder.encode(frame) {
            stats.1 += 1;
            stats.2 += enc.byte_len();
            if frames.blocking_send(AgentEvent::Frame(enc)).is_err() {
                break;
            }
        }
        if stats.0.elapsed() >= Duration::from_secs(10) {
            log::debug!("{} frames, {} KiB/s", stats.1, stats.2 / 1024 / 10);
            stats = (Instant::now(), 0, 0);
        }
        let elapsed = last_sent.elapsed();
        if elapsed < interval {
            std::thread::sleep(interval - elapsed);
        }
        last_sent = Instant::now();
    }
    Ok(())
}

/// Copy columns `x0..x0 + w` of `src` into `dst`.
fn crop(dst: &mut Frame, src: &Frame, x0: u32, w: u32) {
    dst.width = w;
    dst.height = src.height;
    dst.stride = w as usize * 4;
    dst.data.clear();
    let (a, b) = (x0 as usize * 4, (x0 + w) as usize * 4);
    for y in 0..src.height {
        dst.data.extend_from_slice(&src.row(y)[a..b]);
    }
}

/// One-shot capture for diagnostics: `rd-host snapshot out.bmp`.
pub fn snapshot(backend: Backend, display: Option<u32>, out: &std::path::Path) -> Result<()> {
    let mut s = rd_platform::open(backend)?;
    for d in s.capturer.displays() {
        println!(
            "display {}: {} {}x{} at {},{}{}",
            d.index,
            d.name,
            d.width,
            d.height,
            d.x,
            d.y,
            if d.primary { " (primary)" } else { "" }
        );
    }
    if let Some(i) = display {
        s.capturer.select_display(i)?;
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(f) = s.capturer.capture(Duration::from_millis(500))? {
            std::fs::write(out, f.to_bmp())?;
            println!("captured {}x{} via {} -> {}", f.width, f.height, s.backend, out.display());
            return Ok(());
        }
        if Instant::now() > deadline {
            anyhow::bail!("no frame within 30 s");
        }
    }
}

/// Lock the computer (the last viewer left). Windows: as the signed-in user, since
/// only their own process can lock their session. Linux: the session's screen locker.
fn lock_screen(as_console_user: bool) {
    #[cfg(windows)]
    {
        let exe = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into()))
            .join("System32")
            .join("rundll32.exe");
        let args = vec!["user32.dll,LockWorkStation".to_string()];
        match crate::spawn::spawn_ui(&exe, &args, &[], as_console_user) {
            // rundll32 exits by itself; don't kill it.
            Ok(p) => std::mem::forget(p),
            Err(e) => log::warn!("couldn't lock the computer: {e:#}"),
        }
    }
    #[cfg(not(windows))]
    {
        let _ = as_console_user;
        let session = std::env::var("XDG_SESSION_ID").ok().filter(|s| !s.is_empty());
        let mut tries: Vec<Vec<String>> = vec![vec![
            "dbus-send".into(),
            "--session".into(),
            // Wait for the answer, so "no screen locker" counts as a failure.
            "--print-reply".into(),
            "--type=method_call".into(),
            "--dest=org.freedesktop.ScreenSaver".into(),
            "/ScreenSaver".into(),
            "org.freedesktop.ScreenSaver.Lock".into(),
        ]];
        if let Some(s) = session {
            tries.push(vec!["loginctl".into(), "lock-session".into(), s]);
        }
        tries.push(vec!["loginctl".into(), "lock-sessions".into()]);
        tries.push(vec!["xdg-screensaver".into(), "lock".into()]);
        for t in tries {
            let ok = std::process::Command::new(&t[0])
                .args(&t[1..])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .is_ok_and(|s| s.success());
            if ok {
                log::info!("locked the screen with {}", t[0]);
                return;
            }
        }
        log::warn!("couldn't lock the screen (no screen locker answered)");
    }
}
