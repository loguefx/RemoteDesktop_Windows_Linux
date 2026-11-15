//! System audio capture ("what you hear"), encoded as IMA ADPCM chunks of 20 ms.
//!
//! * Windows: WASAPI loopback on the default output device (via cpal).
//! * Linux: `parec` on the default sink's monitor - works with PulseAudio and with
//!   PipeWire (pipewire-pulse). Needs `pulseaudio-utils` / `pipewire-pulse`.

use rd_core::audio::AdpcmEncoder;
use rd_core::proto::AgentEvent;

use crate::agent::EventTx;

/// Collects interleaved stereo i16 and emits fixed-size encoded chunks.
struct Chunker {
    enc: AdpcmEncoder,
    buf: Vec<i16>,
    frames_per_chunk: usize,
    tx: EventTx,
}

impl Chunker {
    fn new(rate: u32, tx: EventTx) -> Self {
        Self { enc: AdpcmEncoder::new(rate, 2), buf: Vec::new(), frames_per_chunk: (rate / 50) as usize, tx }
    }

    /// Returns false once the agent is shutting down.
    fn push(&mut self, stereo: &[i16]) -> bool {
        self.buf.extend_from_slice(stereo);
        let n = self.frames_per_chunk * 2;
        while self.buf.len() >= n {
            let chunk = self.enc.encode(&self.buf[..n]);
            self.buf.drain(..n);
            if self.tx.send(AgentEvent::Audio(chunk)).is_err() {
                return false;
            }
        }
        true
    }
}

pub use imp::Capture;

#[cfg(windows)]
mod imp {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    use anyhow::{anyhow, bail, Context, Result};
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};

    use super::{Chunker, EventTx};

    /// Capture runs on its own thread (cpal streams are !Send); dropping stops it.
    pub struct Capture {
        stop: Arc<AtomicBool>,
    }

    impl Capture {
        pub fn start(tx: EventTx) -> Result<Capture> {
            let stop = Arc::new(AtomicBool::new(false));
            let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<()>>();
            let stop2 = stop.clone();
            std::thread::Builder::new().name("audio".into()).spawn(move || {
                let started = (|| -> Result<cpal::Stream> {
                    let dev = cpal::default_host().default_output_device().ok_or_else(|| anyhow!("no output device"))?;
                    let cfg = dev.default_output_config().context("output config")?;
                    let ch = cfg.channels() as usize;
                    let mut chunker = Chunker::new(cfg.sample_rate().0, tx);
                    let mut scratch: Vec<i16> = Vec::new();
                    let mut convert = move |frames: &mut dyn Iterator<Item = (i16, i16)>| {
                        scratch.clear();
                        for (l, r) in frames {
                            scratch.push(l);
                            scratch.push(r);
                        }
                        chunker.push(&scratch);
                    };
                    let err = |e| log::warn!("audio stream error: {e}");
                    // Building an *input* stream on an *output* device = WASAPI loopback.
                    let stream = match cfg.sample_format() {
                        cpal::SampleFormat::F32 => dev.build_input_stream(
                            &cfg.config(),
                            move |data: &[f32], _: &_| {
                                let to = |v: f32| (v.clamp(-1.0, 1.0) * 32767.0) as i16;
                                let mut it = data.chunks_exact(ch).map(|f| (to(f[0]), to(*f.get(1).unwrap_or(&f[0]))));
                                convert(&mut it);
                            },
                            err,
                            None,
                        )?,
                        cpal::SampleFormat::I16 => dev.build_input_stream(
                            &cfg.config(),
                            move |data: &[i16], _: &_| {
                                let mut it = data.chunks_exact(ch).map(|f| (f[0], *f.get(1).unwrap_or(&f[0])));
                                convert(&mut it);
                            },
                            err,
                            None,
                        )?,
                        other => bail!("unsupported sample format {other:?}"),
                    };
                    stream.play()?;
                    Ok(stream)
                })();
                match started {
                    Ok(stream) => {
                        let _ = ready_tx.send(Ok(()));
                        while !stop2.load(Ordering::Relaxed) {
                            std::thread::sleep(std::time::Duration::from_millis(100));
                        }
                        drop(stream);
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                    }
                }
            })?;
            ready_rx.recv().map_err(|_| anyhow!("audio thread died"))??;
            log::info!("audio loopback capture started");
            Ok(Capture { stop })
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::io::Read;
    use std::process::{Child, Command, Stdio};

    use anyhow::{Context, Result};

    use super::{Chunker, EventTx};

    pub struct Capture {
        child: Child,
    }

    impl Capture {
        pub fn start(tx: EventTx) -> Result<Capture> {
            let mut child = Command::new("parec")
                .args(["--raw", "--format=s16le", "--rate=48000", "--channels=2", "--latency-msec=20", "-d", "@DEFAULT_MONITOR@"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .context("start parec (install pulseaudio-utils, or pipewire-pulse)")?;
            let mut out = child.stdout.take().context("parec stdout")?;
            std::thread::Builder::new().name("audio".into()).spawn(move || {
                let mut chunker = Chunker::new(48000, tx);
                // 20 ms of 48 kHz stereo s16; read_exact keeps L/R frames aligned.
                let mut buf = [0u8; 3840];
                let mut samples = Vec::with_capacity(1920);
                while out.read_exact(&mut buf).is_ok() {
                    samples.clear();
                    samples.extend(buf.chunks_exact(2).map(|b| i16::from_le_bytes([b[0], b[1]])));
                    if !chunker.push(&samples) {
                        break;
                    }
                }
            })?;
            log::info!("audio monitor capture started (parec)");
            Ok(Capture { child })
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
