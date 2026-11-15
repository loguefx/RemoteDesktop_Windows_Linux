//! Audio playback of the host's sound: decode ADPCM, resample to the output device's
//! rate, and keep at most ~200 ms buffered so audio never drifts far behind video.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Context, Result};
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use rd_core::audio::{decode, AudioChunk};

pub struct AudioOut {
    _stream: cpal::Stream,
    buf: Arc<Mutex<VecDeque<f32>>>,
    rate: u32,
    channels: usize,
}

// The stream handle is only kept alive here; samples cross threads via `buf`.
unsafe impl Send for AudioOut {}

impl AudioOut {
    pub fn new() -> Result<Self> {
        let dev = cpal::default_host().default_output_device().ok_or_else(|| anyhow!("no audio output device"))?;
        let cfg = dev.default_output_config().context("audio output config")?;
        let channels = cfg.channels() as usize;
        let rate = cfg.sample_rate().0;
        let buf: Arc<Mutex<VecDeque<f32>>> = Arc::new(Mutex::new(VecDeque::new()));
        let b = buf.clone();
        let err = |e| log::warn!("audio output error: {e}");
        let stream = match cfg.sample_format() {
            cpal::SampleFormat::F32 => dev.build_output_stream(
                &cfg.config(),
                move |out: &mut [f32], _: &_| {
                    let mut q = b.lock().unwrap();
                    for s in out.iter_mut() {
                        *s = q.pop_front().unwrap_or(0.0);
                    }
                },
                err,
                None,
            )?,
            cpal::SampleFormat::I16 => dev.build_output_stream(
                &cfg.config(),
                move |out: &mut [i16], _: &_| {
                    let mut q = b.lock().unwrap();
                    for s in out.iter_mut() {
                        *s = (q.pop_front().unwrap_or(0.0) * 32767.0) as i16;
                    }
                },
                err,
                None,
            )?,
            other => return Err(anyhow!("unsupported output sample format {other:?}")),
        };
        stream.play()?;
        Ok(Self { _stream: stream, buf, rate, channels })
    }

    pub fn push(&self, chunk: &AudioChunk) {
        let pcm = decode(chunk);
        let src_ch = chunk.channels.max(1) as usize;
        let frames = pcm.len() / src_ch;
        if frames == 0 {
            return;
        }
        let ratio = chunk.sample_rate as f64 / self.rate as f64;
        let out_frames = (frames as f64 / ratio) as usize;
        let mut q = self.buf.lock().unwrap();
        for i in 0..out_frames {
            // Linear interpolation between neighbouring source frames.
            let pos = i as f64 * ratio;
            let i0 = (pos as usize).min(frames - 1);
            let i1 = (i0 + 1).min(frames - 1);
            let frac = (pos - i0 as f64) as f32;
            for c in 0..self.channels {
                let sc = c.min(src_ch - 1);
                let a = pcm[i0 * src_ch + sc] as f32;
                let b = pcm[i1 * src_ch + sc] as f32;
                q.push_back((a + (b - a) * frac) / 32768.0);
            }
        }
        let max = self.rate as usize * self.channels / 5; // 200 ms
        while q.len() > max {
            q.pop_front();
        }
    }
}
