//! Wire protocol (v2).
//!
//! Client <-> host daemon (inside end-to-end TLS, possibly tunnelled through a relay):
//! 1. client sends [`ClientHello`]
//! 2. daemon answers [`LoginResult`]
//! 3. `Mode::Desktop`: daemon streams [`HostMsg`], client sends [`ClientMsg`]
//!    `Mode::Admin`:   client sends [`AdminRequest`], daemon answers [`AdminResponse`]
//!
//! Daemon <-> desktop agent (loopback TCP, authenticated by a one-time token):
//! [`AgentHello`], then [`AgentCmd`] down / [`AgentEvent`] up.
//!
//! Several clients may share one desktop at once; the daemon fans frames out to all of
//! them and routes file-transfer replies back to the client that asked.

use serde::{Deserialize, Serialize};

use crate::audio::AudioChunk;
use crate::codec::{EncodedFrame, H264Frame};

// ---------------------------------------------------------------- accounts

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Role {
    Admin,
    User,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::User => "user",
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "admin" => Ok(Role::Admin),
            "user" => Ok(Role::User),
            other => Err(format!("unknown role '{other}' (expected admin|user)")),
        }
    }
}

/// What a signed-in user may do. Admins implicitly have everything.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions {
    /// See the remote screen (and hear its audio).
    pub view: bool,
    /// Send keyboard / mouse input, Ctrl+Alt+Del, switch displays.
    pub control: bool,
    /// Two-way clipboard sync.
    pub clipboard: bool,
    /// Browse, download and upload files (as the signed-in desktop user).
    pub files: bool,
}

impl Permissions {
    pub const FULL: Permissions = Permissions { view: true, control: true, clipboard: true, files: true };
    pub const VIEW_ONLY: Permissions = Permissions { view: true, control: false, clipboard: false, files: false };
    pub const NONE: Permissions = Permissions { view: false, control: false, clipboard: false, files: false };

    /// Effective permissions for a role (admins get everything).
    pub fn effective(self, role: Role) -> Permissions {
        if role == Role::Admin {
            Self::FULL
        } else {
            self
        }
    }
}

impl std::str::FromStr for Permissions {
    type Err = String;
    /// `full`, `view`, `none`, or a comma list of `view,control,clipboard,files`.
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "full" | "all" => return Ok(Self::FULL),
            "view-only" => return Ok(Self::VIEW_ONLY),
            "none" => return Ok(Self::NONE),
            _ => {}
        }
        let mut p = Self::NONE;
        for part in s.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match part {
                "view" => p.view = true,
                "control" => p.control = true,
                "clipboard" => p.clipboard = true,
                "files" => p.files = true,
                other => {
                    return Err(format!(
                        "unknown permission '{other}' (view, control, clipboard, files, full, none)"
                    ))
                }
            }
        }
        Ok(p)
    }
}

impl std::fmt::Display for Permissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if *self == Self::FULL {
            return f.write_str("full");
        }
        let parts: Vec<&str> = [
            (self.view, "view"),
            (self.control, "control"),
            (self.clipboard, "clipboard"),
            (self.files, "files"),
        ]
        .into_iter()
        .filter_map(|(on, n)| on.then_some(n))
        .collect();
        f.write_str(if parts.is_empty() { "none" } else { "" })?;
        f.write_str(&parts.join(","))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserInfo {
    pub username: String,
    pub role: Role,
    pub perms: Permissions,
    pub has_pin: bool,
    pub disabled: bool,
}

impl UserInfo {
    pub fn effective(&self) -> Permissions {
        self.perms.effective(self.role)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: i64,
    pub username: String,
    pub name: String,
    pub created: String,
    pub last_used: Option<String>,
}

// ---------------------------------------------------------------- login

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Credential {
    Password(String),
    Pin(String),
    /// Token issued earlier by `LoginResult::Ok { device_token }` ("remember this device").
    DeviceToken(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    /// Interactive remote desktop session.
    Desktop,
    /// Account management only, no screen.
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHello {
    pub version: u32,
    pub username: String,
    pub credential: Credential,
    /// If set, the host issues a device token so future logins need no password/PIN.
    pub remember_device_as: Option<String>,
    pub mode: Mode,
    /// This device's name, shown on the host while connected ("Laptop (windows)").
    pub device: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LoginResult {
    Ok {
        user: UserInfo,
        host_name: String,
        device_token: Option<String>,
    },
    Denied(String),
}

// ---------------------------------------------------------------- desktop session

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
    Back,
    Forward,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InputEvent {
    /// Absolute position in pixels of the currently selected display.
    MouseMove { x: u32, y: u32 },
    MouseButton { button: MouseButton, down: bool },
    /// Scroll in 1/120-notch units (Windows WHEEL_DELTA convention). Positive dy = away from user.
    Wheel { dx: i32, dy: i32 },
    /// `code` is a Linux evdev key code (see [`crate::keys`]).
    Key { code: u16, down: bool },
    /// Release every key / button currently held (sent on focus loss).
    ReleaseAll,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayInfo {
    pub index: u32,
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    /// Unix seconds.
    pub modified: i64,
}

/// File operations. `req` ids are chosen by the client and echoed in replies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileRequest {
    /// Empty path = the desktop user's home directory.
    ListDir { req: u32, path: String },
    Download { req: u32, path: String },
    /// Acknowledge one received download chunk (flow control).
    Ack { req: u32 },
    /// Uploaded files land in the desktop user's Downloads folder.
    UploadStart { req: u32, name: String, size: u64 },
    UploadChunk { req: u32, data: Vec<u8> },
    UploadEnd { req: u32 },
    Cancel { req: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FileReply {
    Dir { req: u32, path: String, parent: Option<String>, entries: Vec<FileEntry> },
    DownloadStart { req: u32, name: String, size: u64 },
    Chunk { req: u32, data: Vec<u8> },
    DownloadEnd { req: u32 },
    UploadDone { req: u32, saved_as: String },
    Error { req: u32, message: String },
}

pub const FILE_CHUNK: usize = 128 * 1024;
// ---------------------------------------------------------------- clipboard

/// Largest clipboard text that is synced (bytes).
pub const MAX_CLIP_TEXT: usize = 1024 * 1024;
/// Largest clipboard image that is synced (pixels, about 8K resolution).
pub const MAX_CLIP_PIXELS: u64 = 7680 * 4320;
/// Largest encoded clipboard image (bytes).
pub const MAX_CLIP_PNG: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClipImage {
    pub width: u32,
    pub height: u32,
    /// PNG-encoded pixels.
    pub png: Vec<u8>,
}

/// Most bytes of file content copied through the clipboard at once (larger copies
/// go through the Files panel).
pub const MAX_CLIP_FILE_BYTES: u64 = 32 * 1024 * 1024;
/// Most files and folders copied through the clipboard at once.
pub const MAX_CLIP_FILE_ENTRIES: usize = 256;

/// One copied file or folder. `path` is relative, with `/` separators; the first
/// component is the item that was copied, deeper ones are inside a copied folder.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ClipFile {
    pub path: String,
    pub is_dir: bool,
    pub data: Vec<u8>,
}

impl ClipFile {
    /// The path is relative and every component is a plain name (no `..`, drive
    /// letters, separators or control characters).
    pub fn path_is_safe(&self) -> bool {
        !self.path.is_empty()
            && self.path.len() <= 1024
            && self.path.split('/').all(|c| {
                !c.is_empty()
                    && c != "."
                    && c != ".."
                    && c.len() <= 255
                    && !c.chars().any(|ch| ch.is_control() || matches!(ch, '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'))
                    && !is_windows_device_name(c)
            })
    }
}

/// `CON`, `nul.txt`, `COM1`... name devices on Windows, not files.
fn is_windows_device_name(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ClipData {
    Text(String),
    Image(ClipImage),
    /// Copied files and folders, with their contents.
    Files(Vec<ClipFile>),
}

impl ClipData {
    pub fn within_limits(&self) -> bool {
        match self {
            ClipData::Text(t) => t.len() <= MAX_CLIP_TEXT,
            ClipData::Image(i) => i.png.len() <= MAX_CLIP_PNG && (i.width as u64 * i.height as u64) <= MAX_CLIP_PIXELS,
            ClipData::Files(f) => {
                !f.is_empty()
                    && f.len() <= MAX_CLIP_FILE_ENTRIES
                    && f.iter().map(|x| x.data.len() as u64).sum::<u64>() <= MAX_CLIP_FILE_BYTES
                    && f.iter().all(|x| x.path_is_safe() && (!x.is_dir || x.data.is_empty()))
            }
        }
    }

    /// Short human description, for logs and the CLI.
    pub fn describe(&self) -> String {
        match self {
            ClipData::Text(t) => format!("text ({} chars)", t.chars().count()),
            ClipData::Image(i) => format!("image {}x{} ({} KiB PNG)", i.width, i.height, i.png.len() / 1024),
            ClipData::Files(f) => {
                let files = f.iter().filter(|x| !x.is_dir).count();
                let bytes: usize = f.iter().map(|x| x.data.len()).sum();
                let top: Vec<&str> = f.iter().filter(|x| !x.path.contains('/')).map(|x| x.path.as_str()).take(3).collect();
                format!("{files} file(s), {} KiB: {}", bytes / 1024, top.join(", "))
            }
        }
    }

    /// Needs the files permission as well as the clipboard one.
    pub fn is_files(&self) -> bool {
        matches!(self, ClipData::Files(_))
    }
}

/// Largest cursor image sent (pixels per side).
pub const MAX_CURSOR_SIDE: u32 = 256;

/// What the remote mouse pointer looks like. The viewer shows it as its own pointer
/// while over the picture, so the shape (I-beam, hand, resize arrows...) matches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CursorShape {
    /// Straight (not premultiplied) RGBA, `width * height * 4` bytes; `hot_*` is the
    /// pixel that points.
    Image { width: u32, height: u32, hot_x: u32, hot_y: u32, rgba: Vec<u8> },
    /// The pointer is hidden on the host (e.g. while typing in some apps).
    Hidden,
    /// The host draws the pointer into the picture itself (Wayland): hide the local one.
    InPicture,
}

impl CursorShape {
    pub fn is_valid(&self) -> bool {
        match self {
            CursorShape::Image { width, height, hot_x, hot_y, rgba } => {
                (1..=MAX_CURSOR_SIDE).contains(width)
                    && (1..=MAX_CURSOR_SIDE).contains(height)
                    && hot_x < width
                    && hot_y < height
                    && rgba.len() == (*width * *height * 4) as usize
            }
            _ => true,
        }
    }
}

/// Download chunks in flight before the agent waits for `Ack`s.
pub const FILE_WINDOW: usize = 8;

/// How the host should send this viewer's picture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum VideoCodec {
    /// Lossless 64x64 tiles: pixel-exact, best for text on fast links (the default).
    #[default]
    Tiles,
    /// H.264 with a bitrate that adapts to the link, capped at `max_kbps` (0 = host default).
    H264 { max_kbps: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMsg {
    Input(InputEvent),
    RequestKeyframe,
    SelectDisplay(u32),
    Clipboard(ClipData),
    /// Ctrl+Alt+Del (Windows secure attention sequence).
    SecureAttention,
    /// Turn audio streaming on/off for this viewer.
    SetAudio(bool),
    Files(FileRequest),
    /// Choose the video codec for this viewer.
    SetCodec(VideoCodec),
    /// Round-trip measurement; the host answers `Pong` with the same value.
    Ping(u64),
    Disconnect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HostMsg {
    Frame(EncodedFrame),
    /// H.264 picture (only after the viewer asked for it with `SetCodec`).
    Video(H264Frame),
    /// The codec actually in use, and the current H.264 bitrate in kbit/s.
    Codec { codec: VideoCodec, kbps: u32 },
    /// Human readable status line (e.g. "starting desktop agent").
    Status(String),
    Displays { list: Vec<DisplayInfo>, current: u32 },
    Clipboard(ClipData),
    Audio(AudioChunk),
    Files(FileReply),
    /// Who is connected to this desktop ("user on device").
    Viewers(Vec<String>),
    /// Answer to `Ping`.
    Pong(u64),
    /// The remote pointer's look changed (also sent when a viewer joins).
    Cursor(CursorShape),
    /// Session ended by the host.
    Bye(String),
}

// ---------------------------------------------------------------- admin

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminRequest {
    WhoAmI,
    ListUsers,
    AddUser { username: String, password: String, role: Role, perms: Permissions },
    RemoveUser { username: String },
    SetRole { username: String, role: Role },
    SetPermissions { username: String, perms: Permissions },
    SetDisabled { username: String, disabled: bool },
    /// Non-admins may only change their own password.
    SetPassword { username: String, password: String },
    /// Non-admins may only change their own PIN. `None` clears it.
    SetPin { username: String, pin: Option<String> },
    /// Admins see every device; users see their own.
    ListDevices,
    RevokeDevice { id: i64 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminResponse {
    Ok,
    User(UserInfo),
    Users(Vec<UserInfo>),
    Devices(Vec<DeviceInfo>),
    Error(String),
}

// ---------------------------------------------------------------- daemon <-> agent

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentHello {
    pub version: u32,
    pub token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentCmd {
    Input(InputEvent),
    RequestKeyframe,
    SelectDisplay(u32),
    SetClipboard(ClipData),
    SetAudio(bool),
    /// File request from viewer `client`; replies carry the same id.
    Files { client: u32, req: FileRequest },
    /// Send Ctrl+Alt+Del as ordinary keys (non-Windows hosts).
    CtrlAltDel,
    /// Who is connected ("user on device"); empty = nobody. Shown on the host's screen.
    Viewers(Vec<String>),
    Stop,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentEvent {
    Ready { backend: String, width: u32, height: u32 },
    Frame(EncodedFrame),
    Displays { list: Vec<DisplayInfo>, current: u32 },
    Clipboard(ClipData),
    Audio(AudioChunk),
    Files { client: u32, reply: FileReply },
    /// The person at the host pressed Disconnect: end every session.
    EndSessions,
    /// The pointer's look changed.
    Cursor(CursorShape),
    Error(String),
}
