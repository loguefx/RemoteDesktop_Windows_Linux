//! A live desktop session: network I/O on the tokio runtime, state shared with the UI.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use rd_core::codec::Decoder;
use rd_core::framing::{read_msg, write_msg};
use rd_core::proto::{ClipData, VideoCodec, ClientMsg, DisplayInfo, FileEntry, FileReply, FileRequest, HostMsg, FILE_CHUNK};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

use crate::audio_out::AudioOut;
use crate::conn::Session;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Download,
    Upload,
}

#[derive(Clone)]
pub enum TransferState {
    Active,
    Done(String),
    Failed(String),
}

#[derive(Clone)]
pub struct Transfer {
    pub id: u32,
    pub name: String,
    pub direction: Direction,
    pub total: u64,
    pub done: u64,
    pub state: TransferState,
}

pub struct DirListing {
    pub path: String,
    pub parent: Option<String>,
    pub entries: Vec<FileEntry>,
}

#[derive(Default)]
pub struct State {
    pub decoder: Decoder,
    /// Rectangles (x, y, w, h) changed since the UI last uploaded the texture.
    pub dirty: Vec<[u32; 4]>,
    pub full_dirty: bool,
    /// Codec the host is actually using, and its current H.264 bitrate (kbit/s).
    pub codec: VideoCodec,
    pub kbps: u32,
    /// Picture bytes / frames received (tiles and H.264), for diagnostics.
    pub video_bytes: u64,
    pub video_frames: u64,
    pub status: String,
    pub displays: Vec<DisplayInfo>,
    pub current_display: u32,
    pub viewers: Vec<String>,
    pub incoming_clipboard: Option<ClipData>,
    pub dir: Option<DirListing>,
    pub dir_error: Option<String>,
    pub transfers: Vec<Transfer>,
    pub audio_chunks: u64,
    pub closed: Option<String>,
    /// Latest round-trip time to the host.
    pub rtt_ms: Option<u64>,
}

impl State {
    fn transfer(&mut self, id: u32) -> Option<&mut Transfer> {
        self.transfers.iter_mut().find(|t| t.id == id)
    }
}

pub struct Handle {
    pub state: Arc<Mutex<State>>,
    tx: mpsc::UnboundedSender<ClientMsg>,
    upload_tx: mpsc::Sender<ClientMsg>,
    next_req: Arc<AtomicU32>,
    /// req -> local destination of a pending/active download.
    downloads: Arc<Mutex<HashMap<u32, (PathBuf, Option<std::fs::File>)>>>,
    audio: Arc<Mutex<Option<AudioOut>>>,
    rt: tokio::runtime::Handle,
}

impl Handle {
    pub fn start(rt: &tokio::runtime::Handle, session: Session, repaint: impl Fn() + Send + Sync + 'static) -> Handle {
        let state = Arc::new(Mutex::new(State { status: "connecting...".into(), ..Default::default() }));
        let (tx, rx) = mpsc::unbounded_channel();
        let (upload_tx, upload_rx) = mpsc::channel(4);
        let downloads = Arc::new(Mutex::new(HashMap::new()));
        let audio: Arc<Mutex<Option<AudioOut>>> = Arc::new(Mutex::new(None));
        rt.spawn(network(session, state.clone(), tx.clone(), rx, upload_rx, downloads.clone(), audio.clone(), Arc::new(repaint)));
        Handle { state, tx, upload_tx, next_req: Arc::new(AtomicU32::new(1)), downloads, audio, rt: rt.clone() }
    }

    pub fn send(&self, msg: ClientMsg) {
        let _ = self.tx.send(msg);
    }

    fn req(&self) -> u32 {
        self.next_req.fetch_add(1, Ordering::Relaxed)
    }

    pub fn list_dir(&self, path: &str) {
        let req = self.req();
        self.send(ClientMsg::Files(FileRequest::ListDir { req, path: path.to_string() }));
    }

    pub fn download(&self, remote_path: String, name: String, size: u64, local: PathBuf) {
        let req = self.req();
        self.downloads.lock().unwrap().insert(req, (local, None));
        self.state.lock().unwrap().transfers.push(Transfer {
            id: req,
            name,
            direction: Direction::Download,
            total: size,
            done: 0,
            state: TransferState::Active,
        });
        self.send(ClientMsg::Files(FileRequest::Download { req, path: remote_path }));
    }

    pub fn upload(&self, local: PathBuf) {
        let req = self.req();
        let name = local.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "file".into());
        let size = std::fs::metadata(&local).map(|m| m.len()).unwrap_or(0);
        self.state.lock().unwrap().transfers.push(Transfer {
            id: req,
            name: name.clone(),
            direction: Direction::Upload,
            total: size,
            done: 0,
            state: TransferState::Active,
        });
        let (up, state) = (self.upload_tx.clone(), self.state.clone());
        self.rt.spawn(async move {
            let r = async {
                let mut f = tokio::fs::File::open(&local).await?;
                up.send(ClientMsg::Files(FileRequest::UploadStart { req, name, size })).await?;
                let mut buf = vec![0u8; FILE_CHUNK];
                loop {
                    let n = f.read(&mut buf).await?;
                    if n == 0 {
                        break;
                    }
                    up.send(ClientMsg::Files(FileRequest::UploadChunk { req, data: buf[..n].to_vec() })).await?;
                    if let Some(t) = state.lock().unwrap().transfer(req) {
                        t.done += n as u64;
                    }
                }
                up.send(ClientMsg::Files(FileRequest::UploadEnd { req })).await?;
                anyhow::Ok(())
            }
            .await;
            if let Err(e) = r {
                if let Some(t) = state.lock().unwrap().transfer(req) {
                    t.state = TransferState::Failed(format!("{e:#}"));
                }
            }
        });
    }

    pub fn set_audio(&self, on: bool) -> anyhow::Result<()> {
        let mut a = self.audio.lock().unwrap();
        if on {
            if a.is_none() {
                *a = Some(AudioOut::new()?);
            }
        } else {
            *a = None;
        }
        self.send(ClientMsg::SetAudio(on));
        Ok(())
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = self.tx.send(ClientMsg::Input(rd_core::proto::InputEvent::ReleaseAll));
        let _ = self.tx.send(ClientMsg::Disconnect);
    }
}

#[allow(clippy::too_many_arguments)]
async fn network(
    session: Session,
    state: Arc<Mutex<State>>,
    tx: mpsc::UnboundedSender<ClientMsg>,
    mut rx: mpsc::UnboundedReceiver<ClientMsg>,
    mut upload_rx: mpsc::Receiver<ClientMsg>,
    downloads: Arc<Mutex<HashMap<u32, (PathBuf, Option<std::fs::File>)>>>,
    audio: Arc<Mutex<Option<AudioOut>>>,
    repaint: Arc<dyn Fn() + Send + Sync>,
) {
    let (mut rd, mut wr) = tokio::io::split(session.stream);
    // Round-trip time: a Ping every 2 s carrying the time since `epoch`.
    let epoch = std::time::Instant::now();
    let writer = async move {
        let mut ping = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            let msg = tokio::select! {
                Some(m) = rx.recv() => m,
                Some(m) = upload_rx.recv() => m,
                _ = ping.tick() => ClientMsg::Ping(epoch.elapsed().as_millis() as u64),
                else => break,
            };
            let last = matches!(msg, ClientMsg::Disconnect);
            write_msg(&mut wr, &msg).await?;
            if last {
                break;
            }
        }
        anyhow::Ok(())
    };

    let st = state.clone();
    let rp = repaint.clone();
    let reader = async move {
        let mut h264: Option<rd_core::video::H264Decoder> = None;
        loop {
            let msg: HostMsg = read_msg(&mut rd).await?;
            if let HostMsg::Video(f) = &msg {
                // Decode before taking the state lock so the UI never waits on it.
                if h264.is_none() {
                    h264 = rd_core::video::H264Decoder::new().map_err(|e| log::warn!("{e:#}")).ok();
                }
                let decoded = match h264.as_mut() {
                    Some(d) => d.decode(f),
                    None => Err(anyhow::anyhow!("no H.264 decoder")),
                };
                let mut s = st.lock().unwrap();
                s.video_bytes += f.data.len() as u64;
                s.video_frames += 1;
                match decoded {
                    Ok(true) => {
                        let d = h264.as_mut().unwrap();
                        match d.merge_into(&mut s.decoder, f.keyframe) {
                            rd_core::video::Changed::Nothing => {}
                            rd_core::video::Changed::All => {
                                s.full_dirty = true;
                                s.dirty.clear();
                            }
                            rd_core::video::Changed::Rects(r) => {
                                if r.len() > 200 {
                                    s.full_dirty = true;
                                    s.dirty.clear();
                                } else if !s.full_dirty {
                                    s.dirty.extend(r);
                                }
                            }
                        }
                    }
                    Ok(false) => {}
                    Err(e) => {
                        log::warn!("{e:#}; requesting keyframe");
                        h264 = None;
                        let _ = tx.send(ClientMsg::RequestKeyframe);
                    }
                }
                drop(s);
                rp();
                continue;
            }
            let mut s = st.lock().unwrap();
            match msg {
                HostMsg::Video(_) => unreachable!(),
                HostMsg::Codec { codec, kbps } => {
                    s.codec = codec;
                    s.kbps = kbps;
                }
                HostMsg::Frame(f) => {
                    s.video_bytes += f.byte_len() as u64;
                    s.video_frames += 1;
                    let resized = f.width != s.decoder.width || f.height != s.decoder.height;
                    match s.decoder.apply(&f) {
                        Ok(()) => {
                            if resized || f.keyframe || f.tiles.len() > 200 {
                                s.full_dirty = true;
                                s.dirty.clear();
                            } else if !s.full_dirty {
                                let rects: Vec<[u32; 4]> = f.tiles.iter().map(|t| [t.x, t.y, t.w, t.h]).collect();
                                s.dirty.extend(rects);
                            }
                        }
                        Err(e) => {
                            log::warn!("frame decode error: {e}; requesting keyframe");
                            let _ = tx.send(ClientMsg::RequestKeyframe);
                        }
                    }
                }
                HostMsg::Status(t) => s.status = t,
                HostMsg::Displays { list, current } => {
                    s.displays = list;
                    s.current_display = current;
                }
                HostMsg::Viewers(v) => s.viewers = v,
                HostMsg::Pong(sent) => {
                    s.rtt_ms = Some((epoch.elapsed().as_millis() as u64).saturating_sub(sent));
                    drop(s);
                    continue; // nothing to redraw until the UI's next frame
                }
                HostMsg::Clipboard(t) => s.incoming_clipboard = Some(t),
                HostMsg::Audio(chunk) => {
                    s.audio_chunks += 1;
                    drop(s);
                    if let Some(a) = audio.lock().unwrap().as_ref() {
                        a.push(&chunk);
                    }
                    continue;
                }
                HostMsg::Files(reply) => file_reply(&mut s, reply, &downloads, &tx),
                HostMsg::Bye(why) => {
                    s.closed = Some(why);
                    drop(s);
                    rp();
                    return anyhow::Ok(());
                }
            }
            drop(s);
            rp();
        }
    };

    let why = tokio::select! {
        r = reader => match r { Ok(()) => None, Err(e) => Some(format!("connection lost: {e:#}")) },
        _ = writer => Some("disconnected".to_string()),
    };
    let mut s = state.lock().unwrap();
    if s.closed.is_none() {
        s.closed = Some(why.unwrap_or_else(|| "disconnected".into()));
    }
    drop(s);
    repaint();
}

fn file_reply(
    s: &mut State,
    reply: FileReply,
    downloads: &Mutex<HashMap<u32, (PathBuf, Option<std::fs::File>)>>,
    tx: &mpsc::UnboundedSender<ClientMsg>,
) {
    let fail = |s: &mut State, req: u32, msg: String| {
        if let Some(t) = s.transfer(req) {
            t.state = TransferState::Failed(msg);
        } else {
            s.dir_error = Some(msg);
        }
    };
    match reply {
        FileReply::Dir { path, parent, entries, .. } => {
            s.dir_error = None;
            s.dir = Some(DirListing { path, parent, entries });
        }
        FileReply::DownloadStart { req, size, .. } => {
            let mut d = downloads.lock().unwrap();
            if let Some((path, file)) = d.get_mut(&req) {
                match std::fs::File::create(&*path) {
                    Ok(f) => {
                        *file = Some(f);
                        if let Some(t) = s.transfer(req) {
                            t.total = size;
                        }
                    }
                    Err(e) => {
                        let msg = format!("cannot create {}: {e}", path.display());
                        d.remove(&req);
                        let _ = tx.send(ClientMsg::Files(FileRequest::Cancel { req }));
                        fail(s, req, msg);
                    }
                }
            }
        }
        FileReply::Chunk { req, data } => {
            let mut d = downloads.lock().unwrap();
            let ok = match d.get_mut(&req) {
                Some((_, Some(f))) => f.write_all(&data).map_err(|e| e.to_string()),
                _ => Err("download not active".into()),
            };
            match ok {
                Ok(()) => {
                    let _ = tx.send(ClientMsg::Files(FileRequest::Ack { req }));
                    if let Some(t) = s.transfer(req) {
                        t.done += data.len() as u64;
                    }
                }
                Err(e) => {
                    d.remove(&req);
                    let _ = tx.send(ClientMsg::Files(FileRequest::Cancel { req }));
                    fail(s, req, e);
                }
            }
        }
        FileReply::DownloadEnd { req } => {
            if let Some((path, _)) = downloads.lock().unwrap().remove(&req) {
                if let Some(t) = s.transfer(req) {
                    t.state = TransferState::Done(format!("saved to {}", path.display()));
                }
            }
        }
        FileReply::UploadDone { req, saved_as } => {
            if let Some(t) = s.transfer(req) {
                t.done = t.total;
                t.state = TransferState::Done(format!("saved on host as {saved_as}"));
            }
        }
        FileReply::Error { req, message } => {
            downloads.lock().unwrap().remove(&req);
            fail(s, req, message);
        }
    }
}
