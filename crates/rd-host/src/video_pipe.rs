//! Per-viewer H.264 pipeline.
//!
//! The desk's canvas holds lossless tiles; an H.264 viewer gets its own tile decoder fed
//! with the same deltas a tile viewer would receive, and its own encoder. Because the
//! viewer's send loop pulls the newest canvas state whenever it is ready, a slow link
//! simply gets fewer frames (each one a valid P-frame against what it last received)
//! instead of a backlog.
//!
//! The bitrate adapts: when sending a frame takes much longer than a frame interval
//! (the socket is backing up), it drops by 30%; after a second without trouble it
//! climbs again by 25% toward the configured maximum, so a fast home network reaches full
//! quality within a few seconds.

use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use rd_core::codec::{Decoder, EncodedFrame, H264Frame};
use rd_core::video::{self, EncoderChoice, VideoEncoder};

const MIN_BPS: u32 = 300_000;

pub struct VideoPipe {
    tiles: Decoder,
    enc: VideoEncoder,
    max_bps: u32,
    interval: Duration,
    last_change: Option<Instant>,
    good_since: Instant,
    good_frames: u32,
}

impl VideoPipe {
    pub fn new(max_kbps: u32, fps: u32, choice: EncoderChoice) -> Result<Self> {
        let max_bps = max_kbps.saturating_mul(1000).max(MIN_BPS);
        let start = (max_bps / 2).max(MIN_BPS);
        Ok(VideoPipe {
            tiles: Decoder::default(),
            enc: VideoEncoder::new(start, fps, choice)?,
            max_bps,
            interval: Duration::from_secs_f64(1.0 / fps.max(1) as f64),
            last_change: None,
            good_since: Instant::now(),
            good_frames: 0,
        })
    }

    pub fn kbps(&self) -> u32 {
        self.enc.bitrate() / 1000
    }

    /// Bits per second the encoder is currently aiming for.
    pub fn bitrate(&self) -> u32 {
        self.enc.bitrate()
    }

    /// Apply a canvas delta and encode the resulting picture. Fails if the picture can't
    /// be sent as H.264 (e.g. larger than 4K); the caller falls back to tiles.
    pub fn push(&mut self, delta: &EncodedFrame) -> Result<H264Frame> {
        self.tiles.apply(delta)?;
        let (w, h) = (self.tiles.width, self.tiles.height);
        if !video::supported(w, h) {
            bail!("{w}x{h} is outside H.264's limits");
        }
        self.enc.encode(w, h, &self.tiles.pixels)
    }

    /// Record how long writing a frame took. Returns the new bitrate (kbit/s) when it
    /// changed. Keyframes (a new monitor, a new viewer) are many times larger than other
    /// frames and naturally take longer to send, so they never count as congestion.
    pub fn sent(&mut self, took: Duration, keyframe: bool) -> Option<u32> {
        let now = Instant::now();
        let congested = !keyframe && took > (self.interval * 2).max(Duration::from_millis(40));
        let old = self.enc.bitrate();
        let new = if congested {
            self.good_since = now;
            self.good_frames = 0;
            if self.last_change.is_some_and(|t| now - t < Duration::from_millis(500)) {
                return None;
            }
            (old as f64 * 0.7) as u32
        } else {
            self.good_frames += 1;
            if now - self.good_since < Duration::from_secs(1) || self.good_frames < 10 {
                return None;
            }
            self.good_since = now;
            self.good_frames = 0;
            (old as f64 * 1.25) as u32
        };
        let new = new.clamp(MIN_BPS, self.max_bps);
        if new == old {
            return None;
        }
        self.last_change = Some(now);
        self.enc.set_bitrate(new);
        log::debug!("H.264 bitrate {} -> {} kbit/s", old / 1000, new / 1000);
        Some(new / 1000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitrate_adapts() {
        let mut p = VideoPipe::new(8000, 30, EncoderChoice::Software).unwrap();
        assert_eq!(p.kbps(), 4000);
        // A slow keyframe is expected, not congestion.
        assert_eq!(p.sent(Duration::from_millis(500), true), None);
        // A stalled write cuts the rate...
        assert_eq!(p.sent(Duration::from_millis(500), false), Some(2800));
        // ...but not twice within half a second.
        assert_eq!(p.sent(Duration::from_millis(500), false), None);
        // Quick writes alone don't raise it before a second has passed.
        for _ in 0..20 {
            assert_eq!(p.sent(Duration::from_millis(1), false), None);
        }
    }
}
