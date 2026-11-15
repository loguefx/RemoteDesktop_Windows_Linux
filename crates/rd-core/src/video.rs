//! H.264 video (OpenH264), as an alternative to the lossless tile codec for motion-heavy
//! content and slow links.
//!
//! Both sides work on the same `0x00RRGGBB` framebuffer the tile [`Decoder`] produces:
//! the host keeps one per H.264 viewer (fed by tile deltas) and encodes it; the client
//! decodes into its own. On little-endian machines those `u32`s are BGRA bytes.

use anyhow::{bail, Context, Result};
use openh264::encoder::{BitRate, Complexity, EncoderConfig, FrameRate, FrameType, QpRange, RateControlMode, UsageType};
use openh264::formats::{BgraSliceU8, YUVBuffer, YUVSource};
use openh264::OpenH264API;

use crate::codec::{Decoder, H264Frame};

/// OpenH264's largest supported picture.
pub const MAX_WIDTH: u32 = 3840;
pub const MAX_HEIGHT: u32 = 2160;

/// Whether a picture of this size can be sent as H.264.
pub fn supported(width: u32, height: u32) -> bool {
    let (big, small) = (width.max(height), width.min(height));
    width >= 16 && height >= 16 && big <= MAX_WIDTH && small <= MAX_HEIGHT
}

fn as_bytes(px: &[u32]) -> &[u8] {
    // SAFETY: u8 has no alignment requirement and every bit pattern is valid.
    unsafe { std::slice::from_raw_parts(px.as_ptr().cast(), px.len() * 4) }
}

pub struct H264Encoder {
    enc: openh264::encoder::Encoder,
    yuv: Option<YUVBuffer>,
    /// Even-sized copy, used only when the source has an odd width or height.
    crop: Vec<u32>,
    bitrate: u32,
}

impl H264Encoder {
    pub fn new(bitrate: u32, fps: u32) -> Result<Self> {
        let cfg = EncoderConfig::new()
            // OpenH264's screen-content mode is ~5x slower without its assembly
            // (48 vs 10 ms per 1080p frame here); real-time camera mode keeps 30 fps on
            // one core, and the lossless sharpening pass restores text afterwards.
            .usage_type(UsageType::CameraVideoRealTime)
            .rate_control_mode(RateControlMode::Bitrate)
            .bitrate(BitRate::from_bps(bitrate))
            .max_frame_rate(FrameRate::from_hz(fps.max(1) as f32))
            // Never drop a frame to save bits: the last change before the screen goes
            // still must always reach the viewer.
            .skip_frames(false)
            .complexity(Complexity::Low)
            .qp(QpRange::new(10, 40));
        let enc = openh264::encoder::Encoder::with_api_config(OpenH264API::from_source(), cfg)
            .context("start H.264 encoder")?;
        Ok(H264Encoder { enc, yuv: None, crop: Vec::new(), bitrate })
    }

    pub fn bitrate(&self) -> u32 {
        self.bitrate
    }

    /// Change the target bitrate without restarting the stream.
    pub fn set_bitrate(&mut self, bps: u32) {
        if bps == self.bitrate || self.yuv.is_none() {
            self.bitrate = bps;
            return;
        }
        self.bitrate = bps;
        let mut info = openh264_sys2::SBitrateInfo { iLayer: openh264_sys2::SPATIAL_LAYER_ALL, iBitrate: bps as i32 };
        // SAFETY: ENCODER_OPTION_BITRATE takes a pointer to an SBitrateInfo, which lives
        // for the duration of the call.
        unsafe {
            let api = self.enc.raw_api();
            let _ = api.set_option(openh264_sys2::ENCODER_OPTION_BITRATE, (&raw mut info).cast());
        }
    }

    pub fn force_keyframe(&mut self) {
        if self.yuv.is_some() {
            self.enc.force_intra_frame();
        }
    }

    /// Encode a `0x00RRGGBB` framebuffer. Odd sizes lose their last column/row.
    pub fn encode(&mut self, width: u32, height: u32, pixels: &[u32]) -> Result<H264Frame> {
        if !supported(width, height) {
            bail!("{width}x{height} is too large for H.264");
        }
        let (w, h) = ((width & !1) as usize, (height & !1) as usize);
        let src: &[u32] = if (w, h) == (width as usize, height as usize) {
            pixels
        } else {
            self.crop.clear();
            for row in pixels.chunks_exact(width as usize).take(h) {
                self.crop.extend_from_slice(&row[..w]);
            }
            &self.crop
        };
        let bgra = BgraSliceU8::new(as_bytes(src), (w, h));
        match &mut self.yuv {
            Some(y) if y.dimensions() == (w, h) => y.read_bgra8(bgra),
            slot => *slot = Some(YUVBuffer::from_bgra8_source(bgra)),
        }
        let bits = self.enc.encode(self.yuv.as_ref().unwrap()).context("H.264 encode")?;
        let keyframe = matches!(bits.frame_type(), FrameType::IDR | FrameType::I);
        Ok(H264Frame { width: w as u32, height: h as u32, keyframe, data: bits.to_vec() })
    }
}

/// Which H.264 encoder to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncoderChoice {
    /// The GPU's hardware encoder when there is one (Windows: Media Foundation), else
    /// OpenH264.
    Auto,
    /// Always OpenH264 on the CPU.
    Software,
}

impl std::str::FromStr for EncoderChoice {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s {
            "auto" | "hardware" => Ok(EncoderChoice::Auto),
            "software" | "openh264" => Ok(EncoderChoice::Software),
            other => Err(format!("unknown video encoder '{other}' (auto, software)")),
        }
    }
}

/// H.264 encoder that uses the hardware encoder when available and falls back to
/// OpenH264 (for good, with a fresh keyframe) the first time the hardware fails.
pub struct VideoEncoder {
    sw: H264Encoder,
    #[cfg(windows)]
    hw: Option<crate::video_mf::MfEncoder>,
    #[cfg_attr(not(windows), allow(dead_code))]
    try_hw: bool,
    #[cfg_attr(not(windows), allow(dead_code))]
    fps: u32,
}

impl VideoEncoder {
    pub fn new(bitrate: u32, fps: u32, choice: EncoderChoice) -> Result<Self> {
        Ok(VideoEncoder {
            sw: H264Encoder::new(bitrate, fps)?,
            #[cfg(windows)]
            hw: None,
            try_hw: choice == EncoderChoice::Auto && cfg!(windows),
            fps,
        })
    }

    /// "hardware (NAME)" or "software".
    pub fn kind(&self) -> String {
        #[cfg(windows)]
        if let Some(hw) = &self.hw {
            return format!("hardware ({})", hw.name());
        }
        "software".into()
    }

    pub fn bitrate(&self) -> u32 {
        self.sw.bitrate()
    }

    pub fn set_bitrate(&mut self, bps: u32) {
        self.sw.set_bitrate(bps);
        #[cfg(windows)]
        if let Some(hw) = &mut self.hw {
            hw.set_bitrate(bps);
        }
    }

    pub fn force_keyframe(&mut self) {
        self.sw.force_keyframe();
        #[cfg(windows)]
        if let Some(hw) = &mut self.hw {
            hw.force_keyframe();
        }
    }

    pub fn encode(&mut self, width: u32, height: u32, pixels: &[u32]) -> Result<H264Frame> {
        #[cfg(windows)]
        if self.try_hw && supported(width, height) {
            match self.encode_hw(width, height, pixels) {
                Ok(f) => return Ok(f),
                Err(e) => {
                    log::warn!("hardware H.264 encoder unavailable ({e:#}); using OpenH264");
                    self.try_hw = false;
                    self.hw = None;
                    self.sw.force_keyframe();
                }
            }
        }
        self.sw.encode(width, height, pixels)
    }

    #[cfg(windows)]
    fn encode_hw(&mut self, width: u32, height: u32, pixels: &[u32]) -> Result<H264Frame> {
        let (w, h) = (width & !1, height & !1);
        if self.hw.as_ref().map(|e| e.size()) != Some((w, h)) {
            // New size: a new encoder (its first frame is a keyframe).
            self.hw = None;
            self.hw = Some(crate::video_mf::MfEncoder::new(w, h, self.sw.bitrate(), self.fps)?);
        }
        let hw = self.hw.as_mut().unwrap();
        if (w, h) == (width, height) {
            hw.encode(pixels)
        } else {
            let crop: Vec<u32> =
                pixels.chunks_exact(width as usize).take(h as usize).flat_map(|row| &row[..w as usize]).copied().collect();
            hw.encode(&crop)
        }
    }
}

/// What [`H264Decoder::merge_into`] changed in the viewer's framebuffer.
#[derive(Debug, PartialEq)]
pub enum Changed {
    Nothing,
    All,
    /// `(x, y, w, h)` rectangles.
    Rects(Vec<[u32; 4]>),
}

/// Merge granularity: one H.264 macroblock.
const BLOCK: usize = 16;

/// H.264 decoder that only copies the parts of each picture that actually changed into
/// the viewer's framebuffer. Static areas therefore keep whatever sharper lossless tiles
/// the host sent after motion stopped, instead of being repainted from the (lossy)
/// reference picture on every frame.
pub struct H264Decoder {
    dec: openh264::decoder::Decoder,
    rgb: Vec<u8>,
    cur: Vec<u32>,
    prev: Vec<u32>,
    size: (usize, usize),
    prev_size: (usize, usize),
}

impl H264Decoder {
    pub fn new() -> Result<Self> {
        Ok(H264Decoder {
            dec: openh264::decoder::Decoder::new().context("start H.264 decoder")?,
            rgb: Vec::new(),
            cur: Vec::new(),
            prev: Vec::new(),
            size: (0, 0),
            prev_size: (0, 0),
        })
    }

    /// Decode one access unit into an internal buffer (call outside any UI lock).
    /// Returns false if the decoder produced no picture yet.
    pub fn decode(&mut self, frame: &H264Frame) -> Result<bool> {
        let Some(yuv) = self.dec.decode(&frame.data).context("H.264 decode")? else {
            return Ok(false);
        };
        let (w, h) = yuv.dimensions();
        self.rgb.resize(w * h * 3, 0);
        yuv.write_rgb8(&mut self.rgb);
        self.cur.resize(w * h, 0);
        for (d, p) in self.cur.iter_mut().zip(self.rgb.chunks_exact(3)) {
            *d = (p[0] as u32) << 16 | (p[1] as u32) << 8 | p[2] as u32;
        }
        self.size = (w, h);
        Ok(true)
    }

    /// Copy the last decoded picture into `out`: everything when `all` (keyframes) or the
    /// size changed, otherwise only the 16x16 blocks that differ from the previous picture.
    pub fn merge_into(&mut self, out: &mut Decoder, all: bool) -> Changed {
        let (w, h) = self.size;
        if w == 0 {
            return Changed::Nothing;
        }
        let resized = (out.width as usize, out.height as usize) != (w, h);
        let changed = if all || resized || self.prev_size != (w, h) {
            out.width = w as u32;
            out.height = h as u32;
            out.pixels.clear();
            out.pixels.extend_from_slice(&self.cur);
            Changed::All
        } else {
            let mut rects: Vec<[u32; 4]> = Vec::new();
            for by in (0..h).step_by(BLOCK) {
                let bh = BLOCK.min(h - by);
                // Runs of changed blocks along this block row become one rectangle.
                let mut run: Option<usize> = None;
                for bx in (0..w).step_by(BLOCK).chain(std::iter::once(w)) {
                    let differs = bx < w && {
                        let bw = BLOCK.min(w - bx);
                        (by..by + bh).any(|y| self.cur[y * w + bx..y * w + bx + bw] != self.prev[y * w + bx..y * w + bx + bw])
                    };
                    match (differs, run) {
                        (true, None) => run = Some(bx),
                        (false, Some(x0)) => {
                            for y in by..by + bh {
                                out.pixels[y * w + x0..y * w + bx].copy_from_slice(&self.cur[y * w + x0..y * w + bx]);
                            }
                            rects.push([x0 as u32, by as u32, (bx - x0) as u32, bh as u32]);
                            run = None;
                        }
                        _ => {}
                    }
                }
            }
            if rects.is_empty() {
                Changed::Nothing
            } else {
                Changed::Rects(rects)
            }
        };
        std::mem::swap(&mut self.cur, &mut self.prev);
        self.prev_size = (w, h);
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn picture(w: u32, h: u32, t: u32) -> Vec<u32> {
        (0..w * h)
            .map(|i| {
                let (x, y) = (i % w, i / w);
                // Smooth gradient plus a moving block.
                let r = (x * 255 / w) as u32;
                let g = (y * 255 / h) as u32;
                let inside = (x / 16 + t) % 8 == 0 && y > h / 3 && y < 2 * h / 3;
                let b = if inside { 255 } else { 40 };
                r << 16 | g << 8 | b
            })
            .collect()
    }

    fn close(a: u32, b: u32) -> bool {
        (0..3).all(|s| ((a >> (s * 8)) & 0xFF).abs_diff((b >> (s * 8)) & 0xFF) <= 40)
    }

    #[test]
    fn round_trip_and_sizes() {
        let (w, h) = (161u32, 97u32); // odd on purpose
        let mut enc = H264Encoder::new(2_000_000, 30).unwrap();
        let mut dec = H264Decoder::new().unwrap();
        let mut out = Decoder::default();
        for t in 0..5 {
            let src = picture(w, h, t);
            let f = enc.encode(w, h, &src).unwrap();
            assert_eq!((f.width, f.height), (160, 96));
            assert_eq!(f.keyframe, t == 0, "frame {t}");
            assert!(dec.decode(&f).unwrap());
            let ch = dec.merge_into(&mut out, f.keyframe);
            if t == 0 {
                assert_eq!(ch, Changed::All);
            } else {
                assert!(matches!(ch, Changed::Rects(_)), "frame {t}: {ch:?}");
            }
            assert_eq!((out.width, out.height), (160, 96));
            let good = (0..96).flat_map(|y| (0..160).map(move |x| (x, y)))
                .filter(|&(x, y)| close(out.pixels[(y * 160 + x) as usize], src[(y * w + x) as usize]))
                .count();
            assert!(good * 100 / (160 * 96) >= 95, "frame {t}: only {good} close pixels");
        }
        enc.set_bitrate(500_000);
        enc.force_keyframe();
        let f = enc.encode(w, h, &picture(w, h, 9)).unwrap();
        assert!(f.keyframe);
        assert!(dec.decode(&f).unwrap());
        assert_eq!(dec.merge_into(&mut out, true), Changed::All);
    }

    #[test]
    fn merge_keeps_static_areas() {
        let (w, h) = (128u32, 64u32);
        let mut enc = H264Encoder::new(4_000_000, 30).unwrap();
        let mut dec = H264Decoder::new().unwrap();
        let mut out = Decoder::default();
        let a = vec![0x00336699u32; (w * h) as usize];
        let f = enc.encode(w, h, &a).unwrap();
        dec.decode(&f).unwrap();
        dec.merge_into(&mut out, true);
        // Paint a "sharp" marker into the viewer's buffer, as a lossless refresh would.
        out.pixels[5] = 0x00ABCDEF;
        // Change only the bottom-right corner.
        let mut b = a.clone();
        for y in 48..64 {
            for x in 112..128 {
                b[(y * w + x) as usize] = 0x00FF0000;
            }
        }
        let f = enc.encode(w, h, &b).unwrap();
        dec.decode(&f).unwrap();
        match dec.merge_into(&mut out, false) {
            Changed::Rects(r) => assert!(r.iter().all(|r| r[0] >= 96 && r[1] >= 32), "{r:?}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(out.pixels[5], 0x00ABCDEF, "untouched block must keep the sharp pixel");
        assert!(close(out.pixels[(60 * w + 120) as usize], 0x00FF0000));
    }

    #[test]
    fn size_limits() {
        assert!(supported(1920, 1080));
        assert!(supported(2160, 3840));
        assert!(!supported(5120, 1440));
        assert!(!supported(8, 8));
    }
}

#[cfg(test)]
mod bench {
    use super::*;
    use openh264::encoder::Encoder;

    fn run(name: &str, cfg: EncoderConfig) {
        let (w, h) = (1920usize, 1080usize);
        let mut enc = Encoder::with_api_config(OpenH264API::from_source(), cfg).unwrap();
        let mut px: Vec<u32> = (0..w * h).map(|i| (i % w) as u32 * 0x010101 / 8).collect();
        let mut yuv = YUVBuffer::new(w, h);
        let (mut conv, mut code) = (std::time::Duration::ZERO, std::time::Duration::ZERO);
        let mut bytes = 0;
        for f in 0..60usize {
            for y in 200..500 {
                for x in 0..300 {
                    px[y * w + (x + f * 20) % w] = 0x00FF8800 ^ f as u32;
                }
            }
            let t = std::time::Instant::now();
            yuv.read_bgra8(BgraSliceU8::new(as_bytes(&px), (w, h)));
            conv += t.elapsed();
            let t = std::time::Instant::now();
            bytes += enc.encode(&yuv).unwrap().to_vec().len();
            code += t.elapsed();
        }
        println!("{name}: convert {:.1} ms, encode {:.1} ms per frame, {} KB", conv.as_secs_f64() * 1000.0 / 60.0, code.as_secs_f64() * 1000.0 / 60.0, bytes / 1024);
    }

    /// `cargo test -p rd-core --features h264 --release encode_speed -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn encode_speed() {
        let base = || EncoderConfig::new().bitrate(BitRate::from_bps(4_000_000)).max_frame_rate(FrameRate::from_hz(30.0)).skip_frames(false).complexity(Complexity::Low);
        run("screen", base().usage_type(UsageType::ScreenContentRealTime));
        run("camera", base().usage_type(UsageType::CameraVideoRealTime));
    }
}
