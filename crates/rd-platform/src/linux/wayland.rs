//! Wayland backend via xdg-desktop-portal.
//!
//! Two threads:
//! * **portal thread** (tokio current-thread runtime): creates a RemoteDesktop session
//!   with a monitor ScreenCast source attached, starts it, hands the PipeWire fd + node
//!   id to the capture side, then forwards input events as `Notify*` D-Bus calls.
//! * **pipewire thread**: consumes the screencast stream and publishes the latest frame.
//!
//! The first start shows the compositor's consent dialog on the host screen. We ask
//! for `PersistMode::ExplicitlyRevoked` and save the restore token, so after it has
//! been approved once, later sessions start without a prompt (GNOME ≥ 43, KDE ≥ 5.27).

use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use ashpd::desktop::remote_desktop::{Axis, DeviceType, KeyState, RemoteDesktop};
use ashpd::desktop::screencast::{CursorMode, Screencast, SourceType};
use ashpd::desktop::PersistMode;
use pipewire as pw;
use pw::spa;
use rd_core::keys::{BTN_EXTRA, BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BTN_SIDE};
use rd_core::proto::{DisplayInfo, InputEvent, MouseButton};
use tokio::sync::mpsc;

use crate::{Capturer, CursorShape, Frame, InputInjector, WheelAccumulator};

pub fn open() -> Result<(Box<dyn Capturer>, Box<dyn InputInjector>)> {
    let (setup_tx, setup_rx) = std::sync::mpsc::channel::<Result<PortalStreams>>();
    let (input_tx, input_rx) = mpsc::unbounded_channel::<(u32, InputEvent)>();

    std::thread::Builder::new().name("portal".into()).spawn(move || {
        let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                let _ = setup_tx.send(Err(e.into()));
                return;
            }
        };
        rt.block_on(portal_main(setup_tx, input_rx));
    })?;

    // The consent dialog may sit on screen for a while.
    let ps = setup_rx
        .recv_timeout(Duration::from_secs(120))
        .map_err(|_| anyhow!("timed out waiting for the screen-sharing permission dialog"))??;
    log::info!("portal session started with {} stream(s)", ps.streams.len());

    let shared = Arc::new(Shared::default());
    let current = Arc::new(Mutex::new(ps.streams[0].clone()));
    let mut cap = PortalCapturer {
        shared: shared.clone(),
        seen: 0,
        frame: Frame::default(),
        quit: None,
        fd: ps.fd,
        streams: ps.streams,
        index: 0,
        current: current.clone(),
        // The compositor draws the pointer into the stream (or hides it).
        cursor_note: Some(if ps.cursor_embedded { CursorShape::InPicture } else { CursorShape::Hidden }),
    };
    cap.start_stream()?;
    Ok((Box::new(cap), Box::new(PortalInjector { tx: input_tx, shared, current })))
}

#[derive(Clone, Debug)]
struct StreamInfo {
    node_id: u32,
    /// Stream size in compositor logical pixels (differs from frame size with scaling).
    logical: Option<(i32, i32)>,
    position: Option<(i32, i32)>,
}

struct PortalStreams {
    fd: OwnedFd,
    streams: Vec<StreamInfo>,
    /// The pointer is drawn into the frames (otherwise it isn't shown at all).
    cursor_embedded: bool,
}

fn token_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("rd-host").join("portal-restore-token"))
}

async fn portal_main(
    setup_tx: std::sync::mpsc::Sender<Result<PortalStreams>>,
    mut input_rx: mpsc::UnboundedReceiver<(u32, InputEvent)>,
) {
    let rd = match RemoteDesktop::new().await {
        Ok(rd) => rd,
        Err(e) => {
            let _ = setup_tx.send(Err(anyhow!("RemoteDesktop portal unavailable: {e}")));
            return;
        }
    };
    let started = async {
        let sc = Screencast::new().await.context("ScreenCast portal unavailable")?;
        let session = rd.create_session().await.context("CreateSession")?;
        let saved = token_path().and_then(|p| std::fs::read_to_string(p).ok());
        rd.select_devices(
            &session,
            DeviceType::Keyboard | DeviceType::Pointer,
            saved.as_deref().map(str::trim),
            PersistMode::ExplicitlyRevoked,
        )
        .await
        .context("SelectDevices")?;
        // Persistence is controlled by SelectDevices for remote-desktop sessions.
        let sel = sc
            .select_sources(&session, CursorMode::Embedded, SourceType::Monitor.into(), true, None, PersistMode::DoNot)
            .await;
        let cursor_embedded = sel.is_ok();
        if sel.is_err() {
            sc.select_sources(&session, CursorMode::Hidden, SourceType::Monitor.into(), true, None, PersistMode::DoNot)
                .await
                .context("SelectSources")?;
        }
        let selected = rd.start(&session, None).await.context("Start")?.response().context("permission denied")?;
        if let (Some(tok), Some(path)) = (selected.restore_token(), token_path()) {
            let _ = std::fs::create_dir_all(path.parent().unwrap());
            let _ = std::fs::write(&path, tok);
        }
        let mut streams: Vec<StreamInfo> = selected
            .streams()
            .unwrap_or_default()
            .iter()
            .map(|s| StreamInfo { node_id: s.pipe_wire_node_id(), logical: s.size(), position: s.position() })
            .collect();
        if streams.is_empty() {
            bail!("portal returned no screencast stream");
        }
        streams.sort_by_key(|s| s.position.unwrap_or_default());
        let fd = sc.open_pipe_wire_remote(&session).await.context("OpenPipeWireRemote")?;
        anyhow::Ok((session, PortalStreams { fd, streams, cursor_embedded }))
    }
    .await;

    let session = match started {
        Ok((session, ps)) => {
            let _ = setup_tx.send(Ok(ps));
            session
        }
        Err(e) => {
            let _ = setup_tx.send(Err(e));
            return;
        }
    };

    let mut wheel = WheelAccumulator::default();
    while let Some((node_id, ev)) = input_rx.recv().await {
        let r = match ev {
            InputEvent::MouseMove { x, y } => {
                rd.notify_pointer_motion_absolute(&session, node_id, x as f64, y as f64).await
            }
            InputEvent::MouseRelative { dx, dy } => rd.notify_pointer_motion(&session, dx as f64, dy as f64).await,
            InputEvent::MouseButton { button, down } => {
                let code = match button {
                    MouseButton::Left => BTN_LEFT,
                    MouseButton::Right => BTN_RIGHT,
                    MouseButton::Middle => BTN_MIDDLE,
                    MouseButton::Back => BTN_SIDE,
                    MouseButton::Forward => BTN_EXTRA,
                };
                rd.notify_pointer_button(&session, code as i32, key_state(down)).await
            }
            InputEvent::Wheel { dx, dy } => {
                let (nx, ny) = wheel.push(dx, dy);
                // Portal: positive steps scroll down/right; our dy>0 means "up".
                let mut r = Ok(());
                if ny != 0 {
                    r = rd.notify_pointer_axis_discrete(&session, Axis::Vertical, -ny).await;
                }
                if nx != 0 && r.is_ok() {
                    r = rd.notify_pointer_axis_discrete(&session, Axis::Horizontal, nx).await;
                }
                r
            }
            InputEvent::Key { code, down } => {
                rd.notify_keyboard_keycode(&session, code as i32, key_state(down)).await
            }
            InputEvent::ReleaseAll => Ok(()),
        };
        if let Err(e) = r {
            log::warn!("portal input call failed: {e}");
        }
    }
    let _ = session.close().await;
}

fn key_state(down: bool) -> KeyState {
    if down {
        KeyState::Pressed
    } else {
        KeyState::Released
    }
}

// ------------------------------------------------------------------ pipewire

#[derive(Default)]
struct State {
    frame: Frame,
    seq: u64,
    error: Option<String>,
}

#[derive(Default)]
struct Shared {
    state: Mutex<State>,
    cv: Condvar,
}

#[derive(Default)]
struct StreamData {
    format: spa::param::video::VideoInfoRaw,
}

fn pipewire_main(fd: OwnedFd, node: u32, shared: Arc<Shared>, quit: pw::channel::Receiver<()>) -> Result<()> {
    pw::init();
    let mainloop = pw::main_loop::MainLoopRc::new(None)?;
    let context = pw::context::ContextRc::new(&mainloop, None)?;
    let core = context.connect_fd_rc(fd, None)?;

    let ml = mainloop.clone();
    let _quit = quit.attach(mainloop.loop_(), move |()| ml.quit());

    let stream = pw::stream::StreamRc::new(
        core,
        "rd-host-capture",
        pw::properties::properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )?;

    let shared_cb = shared.clone();
    let _listener = stream
        .add_local_listener_with_user_data(StreamData::default())
        .state_changed(|_, _, old, new| log::debug!("pipewire stream {old:?} -> {new:?}"))
        .param_changed(|_, data, id, param| {
            let Some(param) = param else { return };
            if id != spa::param::ParamType::Format.as_raw() {
                return;
            }
            if data.format.parse(param).is_ok() {
                let s = data.format.size();
                log::info!("pipewire format {:?} {}x{}", data.format.format(), s.width, s.height);
            }
        })
        .process(move |stream, data| {
            let Some(mut buffer) = stream.dequeue_buffer() else { return };
            let datas = buffer.datas_mut();
            let Some(d) = datas.first_mut() else { return };
            let size = data.format.size();
            let (w, h) = (size.width, size.height);
            let (offset, chunk_size, stride) =
                (d.chunk().offset() as usize, d.chunk().size() as usize, d.chunk().stride());
            let stride = if stride > 0 { stride as usize } else { w as usize * 4 };
            let Some(bytes) = d.data() else { return };
            if w == 0 || h == 0 || chunk_size == 0 || bytes.len() < offset + stride * h as usize {
                return; // cursor-only/empty buffer
            }
            let swap_rb = matches!(
                data.format.format(),
                spa::param::video::VideoFormat::RGBx | spa::param::video::VideoFormat::RGBA
            );
            let (lock, cv) = (&shared_cb.state, &shared_cb.cv);
            let mut st = lock.lock().unwrap();
            let f = &mut st.frame;
            f.width = w;
            f.height = h;
            f.stride = w as usize * 4;
            f.data.resize(f.stride * h as usize, 0);
            for y in 0..h as usize {
                let src = &bytes[offset + y * stride..offset + y * stride + f.stride];
                let dst = &mut f.data[y * f.stride..(y + 1) * f.stride];
                dst.copy_from_slice(src);
                if swap_rb {
                    for px in dst.chunks_exact_mut(4) {
                        px.swap(0, 2);
                    }
                }
            }
            st.seq += 1;
            cv.notify_all();
        })
        .register()?;

    use spa::param::format::{FormatProperties, MediaSubtype, MediaType};
    use spa::param::video::VideoFormat;
    let obj = spa::pod::object!(
        spa::utils::SpaTypes::ObjectParamFormat,
        spa::param::ParamType::EnumFormat,
        spa::pod::property!(FormatProperties::MediaType, Id, MediaType::Video),
        spa::pod::property!(FormatProperties::MediaSubtype, Id, MediaSubtype::Raw),
        spa::pod::property!(
            FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            VideoFormat::BGRx,
            VideoFormat::BGRx,
            VideoFormat::BGRA,
            VideoFormat::RGBx,
            VideoFormat::RGBA
        ),
        spa::pod::property!(
            FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            spa::utils::Rectangle { width: 1920, height: 1080 },
            spa::utils::Rectangle { width: 1, height: 1 },
            spa::utils::Rectangle { width: 8192, height: 8192 }
        ),
        spa::pod::property!(
            FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            spa::utils::Fraction { num: 30, denom: 1 },
            spa::utils::Fraction { num: 0, denom: 1 },
            spa::utils::Fraction { num: 144, denom: 1 }
        ),
    );
    let values: Vec<u8> = spa::pod::serialize::PodSerializer::serialize(
        std::io::Cursor::new(Vec::new()),
        &spa::pod::Value::Object(obj),
    )
    .map_err(|e| anyhow!("serialize format pod: {e:?}"))?
    .0
    .into_inner();
    let mut params = [spa::pod::Pod::from_bytes(&values).ok_or_else(|| anyhow!("bad format pod"))?];
    stream.connect(
        spa::utils::Direction::Input,
        Some(node),
        pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
        &mut params,
    )?;
    mainloop.run();
    Ok(())
}

struct PortalCapturer {
    shared: Arc<Shared>,
    seen: u64,
    frame: Frame,
    quit: Option<pw::channel::Sender<()>>,
    /// PipeWire remote from the portal; cloned for every stream (re)connection.
    fd: OwnedFd,
    streams: Vec<StreamInfo>,
    index: u32,
    current: Arc<Mutex<StreamInfo>>,
    /// How the pointer is shown, reported once.
    cursor_note: Option<CursorShape>,
}

impl PortalCapturer {
    fn stop_stream(&mut self) {
        if let Some(q) = self.quit.take() {
            let _ = q.send(());
        }
    }

    fn start_stream(&mut self) -> Result<()> {
        self.stop_stream();
        let info = self.streams[self.index as usize].clone();
        *self.current.lock().unwrap() = info.clone();
        {
            let mut st = self.shared.state.lock().unwrap();
            st.error = None;
        }
        let fd = self.fd.try_clone().context("dup pipewire fd")?;
        let (quit_tx, quit_rx) = pw::channel::channel::<()>();
        let shared = self.shared.clone();
        std::thread::Builder::new().name("pipewire".into()).spawn(move || {
            if let Err(e) = pipewire_main(fd, info.node_id, shared.clone(), quit_rx) {
                log::error!("pipewire stream failed: {e:#}");
                let (lock, cv) = (&shared.state, &shared.cv);
                lock.lock().unwrap().error = Some(format!("{e:#}"));
                cv.notify_all();
            }
        })?;
        self.quit = Some(quit_tx);
        Ok(())
    }
}

impl Capturer for PortalCapturer {
    fn cursor(&mut self) -> Option<CursorShape> {
        self.cursor_note.take()
    }

    fn capture(&mut self, timeout: Duration) -> Result<Option<&Frame>> {
        let (lock, cv) = (&self.shared.state, &self.shared.cv);
        let st = lock.lock().unwrap();
        let (mut st, _) = cv.wait_timeout_while(st, timeout, |s| s.seq == self.seen && s.error.is_none()).unwrap();
        if let Some(e) = &st.error {
            bail!("screencast stream ended: {e}");
        }
        if st.seq == self.seen {
            return Ok(None);
        }
        self.seen = st.seq;
        std::mem::swap(&mut self.frame, &mut st.frame);
        drop(st);
        Ok(Some(&self.frame))
    }

    fn displays(&self) -> Vec<DisplayInfo> {
        self.streams
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let (w, h) = s.logical.unwrap_or((0, 0));
                let (x, y) = s.position.unwrap_or((0, 0));
                DisplayInfo {
                    index: i as u32,
                    name: format!("Monitor {}", i + 1),
                    x,
                    y,
                    width: w.max(0) as u32,
                    height: h.max(0) as u32,
                    primary: i == 0,
                }
            })
            .collect()
    }

    fn current_display(&self) -> u32 {
        self.index
    }

    fn select_display(&mut self, index: u32) -> Result<()> {
        if index as usize >= self.streams.len() {
            bail!("no display {index} (pick more monitors in the screen-sharing dialog to switch)");
        }
        if index != self.index {
            self.index = index;
            self.start_stream()?;
        }
        Ok(())
    }
}

impl Drop for PortalCapturer {
    fn drop(&mut self) {
        self.stop_stream();
    }
}

// The pipewire Sender is only used to signal shutdown.
unsafe impl Send for PortalCapturer {}

struct PortalInjector {
    tx: mpsc::UnboundedSender<(u32, InputEvent)>,
    shared: Arc<Shared>,
    current: Arc<Mutex<StreamInfo>>,
}

impl InputInjector for PortalInjector {
    fn inject(&mut self, ev: &InputEvent) -> Result<()> {
        let cur = self.current.lock().unwrap().clone();
        let ev = match (*ev).clone() {
            InputEvent::MouseMove { x, y } => {
                let (fw, fh) = {
                    let st = self.shared.state.lock().unwrap();
                    (st.frame.width.max(1), st.frame.height.max(1))
                };
                match cur.logical {
                    Some((lw, lh)) if lw > 0 && lh > 0 && (lw as u32 != fw || lh as u32 != fh) => InputEvent::MouseMove {
                        x: (x as u64 * lw as u64 / fw as u64) as u32,
                        y: (y as u64 * lh as u64 / fh as u64) as u32,
                    },
                    _ => InputEvent::MouseMove { x, y },
                }
            }
            other => other,
        };
        self.tx.send((cur.node_id, ev)).map_err(|_| anyhow!("portal session closed"))
    }
}
