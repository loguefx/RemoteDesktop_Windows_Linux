//! Desktop agent: runs inside the interactive desktop session. Captures + encodes the
//! screen, injects input, syncs the clipboard, captures system audio and serves file
//! transfers. It only talks to the local daemon over loopback, which authenticates it
//! with a one-time token passed in `RD_AGENT_TOKEN`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rd_core::codec::Encoder;
use rd_core::framing::{read_msg, write_msg};
use rd_core::proto::{AgentCmd, AgentEvent, AgentHello, FileRequest, InputEvent};
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
    let (input_tx, input_rx) = std_mpsc::channel::<InputEvent>();
    let (display_tx, display_rx) = std_mpsc::channel::<u32>();
    let (file_tx, file_rx) = std_mpsc::channel::<(u32, FileRequest)>();
    let keyframe = Arc::new(AtomicBool::new(true));
    let stop = Arc::new(AtomicBool::new(false));

    {
        let (keyframe, stop, frame_tx, evt_tx) = (keyframe.clone(), stop.clone(), frame_tx.clone(), evt_tx.clone());
        let (backend, fps) = (opts.backend, opts.fps);
        std::thread::Builder::new().name("capture".into()).spawn(move || {
            if let Err(e) = capture_thread(backend, fps, keyframe, stop, frame_tx, evt_tx.clone(), input_rx, display_rx) {
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
                    if input_tx.send(ev).is_err() {
                        break;
                    }
                }
                AgentCmd::CtrlAltDel => {
                    // Non-Windows hosts: it's just a key chord.
                    for (code, down) in [(29, true), (56, true), (111, true), (111, false), (56, false), (29, false)] {
                        let _ = input_tx.send(InputEvent::Key { code, down });
                    }
                }
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
    input_rx: std_mpsc::Receiver<InputEvent>,
    display_rx: std_mpsc::Receiver<u32>,
) -> Result<()> {
    let session = rd_platform::open(backend)?;
    let backend_name = session.backend.to_string();
    let mut capturer = session.capturer;
    let mut injector = session.injector;

    // Input runs on its own thread so a slow capture never delays clicks/keys.
    let input_stop = stop.clone();
    std::thread::Builder::new().name("input".into()).spawn(move || {
        while let Ok(ev) = input_rx.recv() {
            if input_stop.load(Ordering::Relaxed) {
                break;
            }
            if let Err(e) = injector.inject(&ev) {
                log::warn!("input injection failed: {e:#}");
            }
        }
        // Dropping the injector releases anything still held.
    })?;

    let send_displays = |c: &dyn rd_platform::Capturer| {
        let _ = events.send(AgentEvent::Displays { list: c.displays(), current: c.current_display() });
    };
    send_displays(capturer.as_ref());

    let interval = Duration::from_secs_f64(1.0 / fps.clamp(1, 120) as f64);
    let mut encoder = Encoder::new();
    let mut announced = false;
    let mut last_sent = Instant::now() - interval;
    let mut stats = (Instant::now(), 0u32, 0usize);

    while !stop.load(Ordering::Relaxed) {
        if let Some(index) = display_rx.try_iter().last() {
            match capturer.select_display(index) {
                Ok(()) => {
                    encoder.force_keyframe();
                    send_displays(capturer.as_ref());
                }
                Err(e) => log::warn!("select display {index}: {e:#}"),
            }
        }
        let Some(frame) = capturer.capture(Duration::from_millis(100))? else {
            continue;
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
