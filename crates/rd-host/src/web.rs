//! Browser viewer: the host's own port also answers HTTPS, so any modern browser (a
//! phone, a borrowed computer) can connect without installing anything.
//!
//! * `GET /` serves one self-contained page (`web/index.html`).
//! * `GET /ws` upgrades to a WebSocket. The page signs in with a JSON message; the
//!   gateway turns it into a normal [`ClientHello`] and runs an ordinary session on an
//!   in-memory pipe, translating messages both ways: pictures as binary messages (lossless
//!   tiles, or H.264 that the page decodes with WebCodecs), everything else as JSON.
//!
//! Same accounts, PINs, two-step codes, lockouts and permissions as the app. The
//! browser can't pin the host's self-signed certificate, so it shows a warning the
//! first time: compare the fingerprint it shows with `rd-host info`.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use rd_core::framing::{read_msg, write_msg};
use rd_core::proto::*;
use rd_core::PROTOCOL_VERSION;
use serde::Deserialize;
use serde_json::json;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::daemon::Shared;

const PAGE: &str = include_str!("web/index.html");
/// Largest message accepted from the page (clipboard text is the biggest).
const MAX_IN: usize = MAX_CLIP_TEXT + 64 * 1024;

/// The first bytes of a connection look like an HTTP request.
pub fn is_http(first: &[u8]) -> bool {
    first.starts_with(b"GET ") || first.starts_with(b"HEAD") || first.starts_with(b"POST")
}

pub async fn serve<S>(shared: Arc<Shared>, mut s: S, peer: String, ip: IpAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let head = tokio::time::timeout(Duration::from_secs(10), read_head(&mut s)).await.map_err(|_| anyhow!("request timeout"))??;
    let mut lines = head.split("\r\n");
    let request = lines.next().unwrap_or("");
    let mut parts = request.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let header = |k: &str| headers.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());

    if !shared.web_enabled() {
        return respond(&mut s, "404 Not Found", "text/plain", b"The browser viewer is turned off on this computer.").await;
    }
    match (method, path.split('?').next().unwrap_or("")) {
        ("GET", "/") | ("GET", "/index.html") => respond(&mut s, "200 OK", "text/html; charset=utf-8", PAGE.as_bytes()).await,
        ("GET", "/ws") => {
            let key = header("sec-websocket-key").ok_or_else(|| anyhow!("not a WebSocket request"))?;
            // Only the page this host served may open the socket (no cross-site use).
            let host = header("host").unwrap_or("");
            if header("origin").is_some_and(|o| o != format!("https://{host}")) {
                return respond(&mut s, "403 Forbidden", "text/plain", b"wrong origin").await;
            }
            let accept = base64(&Sha1::digest(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes()));
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            );
            s.write_all(resp.as_bytes()).await?;
            s.flush().await?;
            websocket(shared, s, peer, ip).await
        }
        ("GET", _) | ("HEAD", _) => respond(&mut s, "404 Not Found", "text/plain", b"not found").await,
        _ => respond(&mut s, "405 Method Not Allowed", "text/plain", b"method not allowed").await,
    }
}

async fn read_head<S: AsyncRead + Unpin>(s: &mut S) -> Result<String> {
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await? == 0 {
            bail!("connection closed");
        }
        buf.push(b[0]);
        if buf.len() > 16 * 1024 {
            bail!("request too large");
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

async fn respond<S: AsyncWrite + Unpin>(s: &mut S, status: &str, ctype: &str, body: &[u8]) -> Result<()> {
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\n\
         Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data: blob:\r\n\
         X-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes()).await?;
    s.write_all(body).await?;
    s.flush().await?;
    let _ = s.shutdown().await;
    Ok(())
}

// ------------------------------------------------------------------ WebSocket framing

const OP_TEXT: u8 = 1;
const OP_BINARY: u8 = 2;
const OP_CLOSE: u8 = 8;
const OP_PING: u8 = 9;
const OP_PONG: u8 = 10;

/// Next complete message from the browser: (opcode, payload). Pings are answered by
/// the caller; fragments are joined.
async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<(u8, Vec<u8>)> {
    let mut message: Option<(u8, Vec<u8>)> = None;
    loop {
        let mut h = [0u8; 2];
        r.read_exact(&mut h).await?;
        let (fin, op, masked) = (h[0] & 0x80 != 0, h[0] & 0x0f, h[1] & 0x80 != 0);
        let mut len = (h[1] & 0x7f) as u64;
        if len == 126 {
            let mut b = [0u8; 2];
            r.read_exact(&mut b).await?;
            len = u16::from_be_bytes(b) as u64;
        } else if len == 127 {
            let mut b = [0u8; 8];
            r.read_exact(&mut b).await?;
            len = u64::from_be_bytes(b);
        }
        if !masked {
            bail!("unmasked frame from the browser");
        }
        let total = len as usize + message.as_ref().map_or(0, |m| m.1.len());
        if len as usize > MAX_IN || total > MAX_IN {
            bail!("message too large");
        }
        let mut mask = [0u8; 4];
        r.read_exact(&mut mask).await?;
        let mut data = vec![0u8; len as usize];
        r.read_exact(&mut data).await?;
        for (i, b) in data.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
        match op {
            // Control frames can arrive between fragments.
            OP_CLOSE | OP_PING | OP_PONG => return Ok((op, data)),
            0 => match message.as_mut() {
                Some(m) => m.1.extend_from_slice(&data),
                None => bail!("continuation without a message"),
            },
            _ => message = Some((op, data)),
        }
        if fin {
            if let Some(m) = message.take() {
                return Ok(m);
            }
        }
    }
}

fn frame(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 10);
    out.push(0x80 | op);
    match payload.len() {
        n if n < 126 => out.push(n as u8),
        n if n <= u16::MAX as usize => {
            out.push(126);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            out.push(127);
            out.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    out
}

pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { T[(n >> (18 - 6 * i)) as usize & 63] as char } else { '=' });
        }
    }
    out
}

// ------------------------------------------------------------------ messages from the page

#[derive(Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum WebIn {
    Login {
        #[serde(default)]
        user: String,
        pin: Option<String>,
        password: Option<String>,
        code: Option<String>,
        #[serde(default)]
        device: String,
    },
    Move { x: u32, y: u32 },
    Rel { dx: i32, dy: i32 },
    Btn { b: u8, down: bool },
    Wheel { dx: i32, dy: i32 },
    Key { code: u16, down: bool },
    Release,
    Codec { h264: bool },
    Keyframe,
    Display { i: u32 },
    Clip { text: String },
    Chat { text: String },
    Cad,
    Ping { v: u64 },
    Privacy { on: bool },
    Lock { on: bool },
    Bye,
}

fn to_client(m: WebIn) -> Option<ClientMsg> {
    let input = |e| Some(ClientMsg::Input(e));
    match m {
        WebIn::Login { .. } => None,
        WebIn::Move { x, y } => input(InputEvent::MouseMove { x, y }),
        WebIn::Rel { dx, dy } => input(InputEvent::MouseRelative { dx, dy }),
        WebIn::Btn { b, down } => {
            let button = match b {
                0 => MouseButton::Left,
                1 => MouseButton::Right,
                2 => MouseButton::Middle,
                3 => MouseButton::Back,
                _ => MouseButton::Forward,
            };
            input(InputEvent::MouseButton { button, down })
        }
        WebIn::Wheel { dx, dy } => input(InputEvent::Wheel { dx, dy }),
        WebIn::Key { code, down } => input(InputEvent::Key { code, down }),
        WebIn::Release => input(InputEvent::ReleaseAll),
        WebIn::Codec { h264 } => Some(ClientMsg::SetCodec(if h264 { VideoCodec::H264 { max_kbps: 0 } } else { VideoCodec::Tiles })),
        WebIn::Keyframe => Some(ClientMsg::RequestKeyframe),
        WebIn::Display { i } => Some(ClientMsg::SelectDisplay(i)),
        WebIn::Clip { text } => Some(ClientMsg::Clipboard(ClipData::Text(text))),
        WebIn::Chat { text } => Some(ClientMsg::Chat(text)),
        WebIn::Cad => Some(ClientMsg::SecureAttention),
        WebIn::Ping { v } => Some(ClientMsg::Ping(v)),
        WebIn::Privacy { on } => Some(ClientMsg::Privacy(on)),
        WebIn::Lock { on } => Some(ClientMsg::LockOnLeave(on)),
        WebIn::Bye => Some(ClientMsg::Disconnect),
    }
}

/// A host message for the page: binary for pictures, JSON text for the rest.
fn to_web(m: HostMsg) -> Option<(u8, Vec<u8>)> {
    let text = |v: serde_json::Value| Some((OP_TEXT, v.to_string().into_bytes()));
    match m {
        HostMsg::Frame(f) => {
            let mut b = Vec::with_capacity(f.byte_len() + 16);
            b.push(1u8);
            b.extend_from_slice(&f.width.to_le_bytes());
            b.extend_from_slice(&f.height.to_le_bytes());
            b.push(f.keyframe as u8);
            b.extend_from_slice(&(f.tiles.len() as u32).to_le_bytes());
            for t in &f.tiles {
                for v in [t.x, t.y, t.w, t.h, t.data.len() as u32] {
                    b.extend_from_slice(&v.to_le_bytes());
                }
                b.extend_from_slice(&t.data);
            }
            Some((OP_BINARY, b))
        }
        HostMsg::Video(v) => {
            let mut b = Vec::with_capacity(v.data.len() + 10);
            b.push(2u8);
            b.extend_from_slice(&v.width.to_le_bytes());
            b.extend_from_slice(&v.height.to_le_bytes());
            b.push(v.keyframe as u8);
            b.extend_from_slice(&v.data);
            Some((OP_BINARY, b))
        }
        HostMsg::Codec { codec, kbps } => text(json!({"t": "codec", "h264": matches!(codec, VideoCodec::H264 { .. }), "kbps": kbps})),
        HostMsg::Status(s) => text(json!({"t": "status", "text": s})),
        HostMsg::Displays { list, current } => {
            let l: Vec<_> = list.iter().map(|d| json!({"i": d.index, "name": d.name, "w": d.width, "h": d.height})).collect();
            text(json!({"t": "displays", "list": l, "current": current}))
        }
        HostMsg::Clipboard(ClipData::Text(t)) => text(json!({"t": "clip", "text": t})),
        HostMsg::Clipboard(_) | HostMsg::Audio(_) | HostMsg::Files(_) => None,
        HostMsg::Viewers(v) => text(json!({"t": "viewers", "list": v})),
        HostMsg::Pong(v) => text(json!({"t": "pong", "v": v})),
        HostMsg::Cursor(CursorShape::Image { width, height, hot_x, hot_y, rgba }) => {
            text(json!({"t": "cursor", "w": width, "h": height, "hx": hot_x, "hy": hot_y, "rgba": base64(&rgba)}))
        }
        HostMsg::Cursor(_) => text(json!({"t": "cursor", "hidden": true})),
        HostMsg::Privacy { on, note } => text(json!({"t": "privacy", "on": on, "note": note})),
        HostMsg::Chat { from, text: t } => text(json!({"t": "chat", "from": from, "text": t})),
        HostMsg::Bye(why) => text(json!({"t": "bye", "why": why})),
    }
}

// ------------------------------------------------------------------ the session

async fn websocket<S>(shared: Arc<Shared>, s: S, peer: String, ip: IpAddr) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut ws_rd, mut ws_wr) = tokio::io::split(s);
    // Everything to the browser goes through one writer; bounded so a slow browser
    // slows the picture down instead of piling it up.
    let (out_tx, mut out_rx) = mpsc::channel::<(u8, Vec<u8>)>(8);
    let writer = tokio::spawn(async move {
        while let Some((op, data)) = out_rx.recv().await {
            ws_wr.write_all(&frame(op, &data)).await?;
            if op == OP_CLOSE {
                break;
            }
        }
        let _ = ws_wr.shutdown().await;
        anyhow::Ok(())
    });
    let send_json = |v: serde_json::Value| (OP_TEXT, v.to_string().into_bytes());

    // Sign in (several tries: wrong PIN, two-step code).
    let pipe = loop {
        let (op, data) = tokio::time::timeout(Duration::from_secs(300), read_frame(&mut ws_rd))
            .await
            .map_err(|_| anyhow!("sign-in timeout"))??;
        match op {
            OP_CLOSE => return Ok(()),
            OP_PING => {
                let _ = out_tx.send((OP_PONG, data)).await;
                continue;
            }
            OP_TEXT => {}
            _ => continue,
        }
        let Ok(WebIn::Login { user, pin, password, code, device }) = serde_json::from_slice::<WebIn>(&data) else {
            continue;
        };
        let credential = match (pin, password) {
            (_, Some(p)) => Credential::Password(p),
            (Some(p), None) => Credential::Pin(p),
            (None, None) => continue,
        };
        let device: String = device.chars().filter(|c| !c.is_control()).take(40).collect();
        let hello = ClientHello {
            version: PROTOCOL_VERSION,
            username: user,
            credential,
            remember_device_as: None,
            mode: Mode::Desktop,
            device: if device.is_empty() { "web browser".into() } else { format!("{device} (browser)") },
            code: code.filter(|c| !c.trim().is_empty()),
        };
        let (mut ours, theirs) = tokio::io::duplex(1 << 20);
        {
            let (shared, peer) = (shared.clone(), format!("{peer} (browser)"));
            tokio::spawn(async move {
                if let Err(e) = crate::daemon::session(shared, theirs, peer.clone(), ip).await {
                    log::info!("{peer}: {e:#}");
                }
            });
        }
        write_msg(&mut ours, &hello).await?;
        match read_msg::<_, LoginResult>(&mut ours).await? {
            LoginResult::Ok { user, host_name, .. } => {
                let p = user.effective();
                let _ = out_tx
                    .send(send_json(json!({"t": "ok", "user": user.username, "host": host_name,
                        "control": p.control, "clipboard": p.clipboard})))
                    .await;
                break ours;
            }
            LoginResult::Denied(why) => {
                let _ = out_tx.send(send_json(json!({"t": "denied", "why": why}))).await;
            }
            LoginResult::NeedCode => {
                let _ = out_tx.send(send_json(json!({"t": "needcode"}))).await;
            }
        }
    };

    let (mut p_rd, mut p_wr) = tokio::io::split(pipe);
    let down = {
        let out_tx = out_tx.clone();
        async move {
            loop {
                let m: HostMsg = read_msg(&mut p_rd).await?;
                let bye = matches!(m, HostMsg::Bye(_));
                if let Some(x) = to_web(m) {
                    if out_tx.send(x).await.is_err() {
                        break;
                    }
                }
                if bye {
                    break;
                }
            }
            anyhow::Ok(())
        }
    };
    let up = {
        let out_tx = out_tx.clone();
        async move {
            loop {
                let (op, data) = read_frame(&mut ws_rd).await?;
                match op {
                    OP_CLOSE => break,
                    OP_PING => {
                        let _ = out_tx.send((OP_PONG, data)).await;
                    }
                    OP_TEXT => {
                        let msg = serde_json::from_slice::<WebIn>(&data).context("bad message from the page")?;
                        let bye = matches!(msg, WebIn::Bye);
                        if let Some(c) = to_client(msg) {
                            write_msg(&mut p_wr, &c).await?;
                        }
                        if bye {
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let _ = write_msg(&mut p_wr, &ClientMsg::Disconnect).await;
            anyhow::Ok(())
        }
    };
    let r = tokio::select! { r = down => r, r = up => r };
    let _ = out_tx.send((OP_CLOSE, Vec::new())).await;
    drop(out_tx);
    let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_accept_key() {
        // RFC 6455 section 1.3 example.
        let accept = base64(&Sha1::digest(b"dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11"));
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[tokio::test]
    async fn frames_round_trip() {
        // A masked client frame, as a browser sends it.
        let payload = br#"{"t":"key","code":30,"down":true}"#;
        let mask = [1u8, 2, 3, 4];
        let mut raw = vec![0x81, 0x80 | payload.len() as u8];
        raw.extend_from_slice(&mask);
        raw.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        let (op, data) = read_frame(&mut raw.as_slice()).await.unwrap();
        assert_eq!((op, data.as_slice()), (OP_TEXT, &payload[..]));
        assert!(matches!(serde_json::from_slice::<WebIn>(&data).unwrap(), WebIn::Key { code: 30, down: true }));
        assert_eq!(frame(OP_BINARY, &[0u8; 300])[..4], [0x82, 126, 1, 44]);
        assert!(is_http(b"GET / HTTP/1.1") && !is_http(&[0, 0, 0, 40]));
    }
}
