//! Shared building blocks for the remote desktop host, agent and client.
//!
//! * [`proto`]   - every message exchanged on the wire (client<->daemon, daemon<->agent)
//! * [`framing`] - length-prefixed postcard framing over any async byte stream
//! * `tls`       - self-signed host certificates + trust-on-first-use client verification
//! * [`codec`]   - dirty-tile + LZ4 frame codec
//! * [`keys`]    - key code helpers (wire format uses Linux evdev key codes)
//! * [`audio`]   - IMA ADPCM audio chunks
//! * [`discovery`] - finding hosts on the local network
//! * [`relay`]   - relay/rendezvous protocol and connection targets
//! * `p2p`       - direct QUIC connections through NAT, relay as rendezvous (feature `p2p`)
//! * `video`     - H.264 encoder/decoder (feature `h264`)
//! * `clipboard` - text + image clipboard sync worker (feature `clipboard`)

pub mod audio;
#[cfg(feature = "clipboard")]
pub mod clipboard;
pub mod codec;
pub mod discovery;
pub mod framing;
pub mod keys;
pub mod proto;
pub mod relay;
#[cfg(feature = "tls")]
pub mod tls;
#[cfg(feature = "h264")]
pub mod video;
#[cfg(all(feature = "h264", windows))]
pub mod video_mf;
#[cfg(feature = "p2p")]
pub mod p2p;

/// Default TCP port the host service listens on.
pub const DEFAULT_PORT: u16 = 47800;
/// Bumped whenever the wire protocol changes incompatibly.
pub const PROTOCOL_VERSION: u32 = 5;
