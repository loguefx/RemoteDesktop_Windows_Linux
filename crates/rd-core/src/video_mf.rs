//! Hardware H.264 encoding on Windows through Media Foundation (NVIDIA NVENC, AMD AMF,
//! Intel Quick Sync - whatever hardware encoder MFT the GPU driver registers).
//!
//! The stream matches what the OpenH264 path produces, so any client can decode it:
//! Annex-B, Baseline profile, no B-frames, SPS/PPS in front of every keyframe. The
//! encoder runs in low-latency CBR mode; its bitrate can change at any time and
//! keyframes are forced through `ICodecAPI`.
//!
//! Frames are converted to NV12 (limited-range BT.601, the same matrix OpenH264 uses)
//! in system memory. Hardware encoder MFTs are asynchronous: they ask for input and
//! announce output through events, which [`MfEncoder::encode`] waits for (bounded), so
//! the call is still one frame in, one frame out.

#![allow(non_upper_case_globals)] // Media Foundation event constants

use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use windows::core::{Interface, GUID, VARIANT};
use windows::Win32::Media::MediaFoundation::*;
use windows::Win32::System::Com::{CoInitializeEx, CoTaskMemFree, COINIT_MULTITHREADED};

use crate::codec::H264Frame;

/// How long to wait for the encoder to ask for input or deliver output.
const EVENT_TIMEOUT: Duration = Duration::from_millis(500);

pub struct MfEncoder {
    mft: IMFTransform,
    codec: ICodecAPI,
    events: Option<IMFMediaEventGenerator>,
    width: u32,
    height: u32,
    bitrate: u32,
    fps: u32,
    start: Instant,
    /// Input requests received but not yet served (async MFTs).
    need_input: u32,
    /// Output announcements not yet collected (async MFTs).
    have_output: u32,
    provides_samples: bool,
    out_size: u32,
    seq_header: Vec<u8>,
    nv12: Vec<u8>,
    name: String,
}

// SAFETY: the transform and its interfaces are free-threaded COM objects created in
// the multithreaded apartment; the encoder is used from one thread at a time.
unsafe impl Send for MfEncoder {}

fn startup() -> Result<()> {
    use std::sync::OnceLock;
    static STARTED: OnceLock<bool> = OnceLock::new();
    // SAFETY: plain initialisation calls; MFStartup is reference-counted.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }
    let ok = *STARTED.get_or_init(|| unsafe { MFStartup(MF_VERSION, MFSTARTUP_FULL).is_ok() });
    if !ok {
        bail!("Media Foundation is not available");
    }
    Ok(())
}

/// The hardware H.264 encoders the system offers, best first.
fn hardware_encoders() -> Result<Vec<IMFActivate>> {
    startup()?;
    let input = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: MFVideoFormat_NV12 };
    let output = MFT_REGISTER_TYPE_INFO { guidMajorType: MFMediaType_Video, guidSubtype: MFVideoFormat_H264 };
    let mut list: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: MFTEnumEx fills a CoTaskMem array of `count` activation objects, which we
    // take ownership of and free.
    unsafe {
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
            Some(&input),
            Some(&output),
            &mut list,
            &mut count,
        )?;
        let mut out = Vec::new();
        for i in 0..count as usize {
            if let Some(a) = std::ptr::read(list.add(i)) {
                out.push(a);
            }
        }
        if !list.is_null() {
            CoTaskMemFree(Some(list as *const _));
        }
        Ok(out)
    }
}

/// Names of the hardware H.264 encoders found (for `rd-host info`).
pub fn describe_hardware() -> Vec<String> {
    hardware_encoders().map(|l| l.iter().map(friendly_name).collect()).unwrap_or_default()
}

fn friendly_name(a: &IMFActivate) -> String {
    // SAFETY: GetAllocatedString returns a CoTaskMem string we free.
    unsafe {
        let mut p = windows::core::PWSTR::null();
        let mut len = 0u32;
        if a.GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut p, &mut len).is_ok() && !p.is_null() {
            let s = p.to_string().unwrap_or_default();
            CoTaskMemFree(Some(p.0 as *const _));
            return s;
        }
    }
    "hardware encoder".into()
}

fn size_pair(a: u32, b: u32) -> u64 {
    (a as u64) << 32 | b as u64
}

fn set_u32(codec: &ICodecAPI, api: &GUID, v: u32) -> windows::core::Result<()> {
    let v = VARIANT::from(v);
    // SAFETY: both pointers are valid for the duration of the call.
    unsafe { codec.SetValue(api, &v) }
}

fn set_bool(codec: &ICodecAPI, api: &GUID, v: bool) -> windows::core::Result<()> {
    let v = VARIANT::from(v);
    // SAFETY: as above.
    unsafe { codec.SetValue(api, &v) }
}

impl MfEncoder {
    /// Open the first hardware encoder that accepts this size. `width` and `height`
    /// must be even.
    pub fn new(width: u32, height: u32, bitrate: u32, fps: u32) -> Result<Self> {
        if width % 2 != 0 || height % 2 != 0 {
            bail!("odd picture size");
        }
        let mut encoders = hardware_encoders()?;
        // RD_HW_ENCODER=nvidia (any part of the name) picks one GPU's encoder.
        if let Ok(want) = std::env::var("RD_HW_ENCODER") {
            let want = want.to_lowercase();
            encoders.retain(|a| friendly_name(a).to_lowercase().contains(&want));
        }
        if encoders.is_empty() {
            bail!("no hardware H.264 encoder");
        }
        let mut last = anyhow!("no hardware H.264 encoder");
        for a in &encoders {
            let name = friendly_name(a);
            match Self::open(a, &name, width, height, bitrate, fps) {
                Ok(e) => return Ok(e),
                Err(e) => {
                    log::debug!("{name}: {e:#}");
                    // SAFETY: releases the object ActivateObject created, if any.
                    unsafe {
                        let _ = a.ShutdownObject();
                    }
                    last = e.context(name);
                }
            }
        }
        Err(last)
    }

    fn open(a: &IMFActivate, name: &str, width: u32, height: u32, bitrate: u32, fps: u32) -> Result<Self> {
        // SAFETY: standard Media Foundation setup on objects we own; every pointer passed
        // lives for the duration of its call.
        unsafe {
            let mft: IMFTransform = a.ActivateObject().context("activate")?;
            let attrs = mft.GetAttributes().ok();
            let is_async = attrs.as_ref().and_then(|at| at.GetUINT32(&MF_TRANSFORM_ASYNC).ok()).unwrap_or(0) != 0;
            if is_async {
                attrs.as_ref().unwrap().SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1).context("unlock async MFT")?;
            }
            if let Some(at) = &attrs {
                let _ = at.SetUINT32(&MF_LOW_LATENCY, 1);
            }
            let codec: ICodecAPI = mft.cast().context("encoder has no ICodecAPI")?;
            // Settings that must precede the media types. Variable bitrate capped at the
            // target: a still screen then costs almost nothing, where CBR would pad
            // every frame up to the full rate.
            let rc = [
                // (AMD's encoder pads low-delay VBR like CBR, so that comes later.)
                (eAVEncCommonRateControlMode_PeakConstrainedVBR, "peak-constrained VBR"),
                (eAVEncCommonRateControlMode_UnconstrainedVBR, "unconstrained VBR"),
                (eAVEncCommonRateControlMode_LowDelayVBR, "low-delay VBR"),
                (eAVEncCommonRateControlMode_CBR, "CBR"),
            ]
            .into_iter()
            .filter(|(m, _)| std::env::var("RD_MF_RC").map_or(true, |v| v == m.0.to_string()))
            .find(|(m, _)| set_u32(&codec, &CODECAPI_AVEncCommonRateControlMode, m.0 as u32).is_ok())
            .map(|(_, n)| n)
            .unwrap_or("default");
            let _ = set_u32(&codec, &CODECAPI_AVEncCommonMeanBitRate, bitrate);
            let _ = set_u32(&codec, &CODECAPI_AVEncCommonMaxBitRate, bitrate);
            let _ = set_bool(&codec, &CODECAPI_AVLowLatencyMode, true);
            let _ = set_u32(&codec, &CODECAPI_AVEncMPVDefaultBPictureCount, 0);
            // A keyframe every 10 minutes at most; the host forces them when needed.
            let _ = set_u32(&codec, &CODECAPI_AVEncMPVGOPSize, fps.max(1) * 600);

            let out = MFCreateMediaType()?;
            out.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            out.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)?;
            out.SetUINT32(&MF_MT_AVG_BITRATE, bitrate)?;
            out.SetUINT64(&MF_MT_FRAME_SIZE, size_pair(width, height))?;
            out.SetUINT64(&MF_MT_FRAME_RATE, size_pair(fps.max(1), 1))?;
            out.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, size_pair(1, 1))?;
            out.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            out.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Base.0 as u32)?;
            mft.SetOutputType(0, &out, 0).context("set output type")?;

            let inp = MFCreateMediaType()?;
            inp.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
            inp.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)?;
            inp.SetUINT64(&MF_MT_FRAME_SIZE, size_pair(width, height))?;
            inp.SetUINT64(&MF_MT_FRAME_RATE, size_pair(fps.max(1), 1))?;
            inp.SetUINT64(&MF_MT_PIXEL_ASPECT_RATIO, size_pair(1, 1))?;
            inp.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            inp.SetUINT32(&MF_MT_DEFAULT_STRIDE, width)?;
            mft.SetInputType(0, &inp, 0).context("set input type (NV12 in system memory)")?;

            let info = mft.GetOutputStreamInfo(0)?;
            let provides_samples = info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 != 0;
            let events = if is_async { Some(mft.cast::<IMFMediaEventGenerator>().context("async MFT without events")?) } else { None };
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            mft.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
            log::info!("hardware H.264 encoder: {name} ({width}x{height}, {rc})");
            Ok(MfEncoder {
                mft,
                codec,
                events,
                width,
                height,
                bitrate,
                fps,
                start: Instant::now(),
                need_input: 0,
                have_output: 0,
                provides_samples,
                out_size: info.cbSize.max(width * height),
                seq_header: Vec::new(),
                nv12: Vec::new(),
                name: format!("{name}, {rc}"),
            })
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    pub fn bitrate(&self) -> u32 {
        self.bitrate
    }

    pub fn set_bitrate(&mut self, bps: u32) {
        if bps != self.bitrate && set_u32(&self.codec, &CODECAPI_AVEncCommonMeanBitRate, bps).is_ok() {
            let _ = set_u32(&self.codec, &CODECAPI_AVEncCommonMaxBitRate, bps);
            self.bitrate = bps;
        }
    }

    pub fn force_keyframe(&mut self) {
        let _ = set_u32(&self.codec, &CODECAPI_AVEncVideoForceKeyFrame, 1);
    }

    /// Collect pending events; with `want`, keep waiting (bounded) until one of that
    /// kind has arrived.
    fn pump(&mut self, want: Option<MF_EVENT_TYPE>) -> Result<()> {
        let Some(gen) = &self.events else { return Ok(()) };
        let deadline = Instant::now() + EVENT_TIMEOUT;
        loop {
            let satisfied = match want {
                Some(METransformNeedInput) => self.need_input > 0,
                Some(METransformHaveOutput) => self.have_output > 0,
                _ => true,
            };
            // SAFETY: GetEvent with NO_WAIT returns immediately.
            match unsafe { gen.GetEvent(MF_EVENT_FLAG_NO_WAIT) } {
                Ok(ev) => {
                    // SAFETY: plain getter.
                    let kind = MF_EVENT_TYPE(unsafe { ev.GetType()? } as i32);
                    match kind {
                        METransformNeedInput => self.need_input += 1,
                        METransformHaveOutput => self.have_output += 1,
                        METransformDrainComplete | METransformMarker => {}
                        other => log::debug!("{}: event {}", self.name, other.0),
                    }
                    continue;
                }
                Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => {}
                Err(e) => return Err(e).context("encoder event"),
            }
            if satisfied {
                return Ok(());
            }
            if Instant::now() > deadline {
                bail!("{}: timed out waiting for the encoder", self.name);
            }
            std::thread::sleep(Duration::from_micros(500));
        }
    }

    /// Encode one `0x00RRGGBB` picture of exactly the encoder's (even) size.
    pub fn encode(&mut self, pixels: &[u32]) -> Result<H264Frame> {
        let (w, h) = (self.width as usize, self.height as usize);
        if pixels.len() != w * h {
            bail!("picture size does not match the encoder");
        }
        bgrx_to_nv12(pixels, w, h, &mut self.nv12);
        // SAFETY: Media Foundation calls on objects we own; buffer pointers come from
        // Lock and are used only before the matching Unlock.
        unsafe {
            let buf = MFCreateMemoryBuffer(self.nv12.len() as u32)?;
            {
                let mut p = std::ptr::null_mut();
                buf.Lock(&mut p, None, None)?;
                std::ptr::copy_nonoverlapping(self.nv12.as_ptr(), p, self.nv12.len());
                buf.Unlock()?;
            }
            buf.SetCurrentLength(self.nv12.len() as u32)?;
            let sample = MFCreateSample()?;
            sample.AddBuffer(&buf)?;
            let t = self.start.elapsed().as_nanos() as i64 / 100;
            sample.SetSampleTime(t)?;
            sample.SetSampleDuration(10_000_000 / self.fps.max(1) as i64)?;

            self.pump(Some(METransformNeedInput))?;
            self.mft.ProcessInput(0, &sample, 0).context("ProcessInput")?;
            self.need_input = self.need_input.saturating_sub(1);
            self.pump(Some(METransformHaveOutput))?;
            let data = self.collect_output()?;
            self.have_output = self.have_output.saturating_sub(1);
            let keyframe = has_nal(&data, 5);
            let mut out = data;
            if keyframe && !has_nal(&out, 7) {
                if self.seq_header.is_empty() {
                    if let Ok(t) = self.mft.GetOutputCurrentType(0) {
                        self.seq_header = blob(&t, &MF_MT_MPEG_SEQUENCE_HEADER).unwrap_or_default();
                    }
                }
                let mut v = self.seq_header.clone();
                v.extend_from_slice(&out);
                out = v;
            }
            Ok(H264Frame { width: self.width, height: self.height, keyframe, data: out })
        }
    }

    unsafe fn collect_output(&mut self) -> Result<Vec<u8>> {
        loop {
            let sample = if self.provides_samples {
                None
            } else {
                let s = MFCreateSample()?;
                s.AddBuffer(&MFCreateMemoryBuffer(self.out_size)?)?;
                Some(s)
            };
            let mut ob = [MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: std::mem::ManuallyDrop::new(sample),
                dwStatus: 0,
                pEvents: std::mem::ManuallyDrop::new(None),
            }];
            let mut status = 0u32;
            let r = self.mft.ProcessOutput(0, &mut ob, &mut status);
            let sample = std::mem::ManuallyDrop::take(&mut ob[0].pSample);
            drop(std::mem::ManuallyDrop::take(&mut ob[0].pEvents));
            match r {
                Ok(()) => {
                    let s = sample.ok_or_else(|| anyhow!("encoder returned no sample"))?;
                    let buf = s.ConvertToContiguousBuffer()?;
                    let mut p = std::ptr::null_mut();
                    let mut len = 0u32;
                    buf.Lock(&mut p, None, Some(&mut len))?;
                    let v = std::slice::from_raw_parts(p, len as usize).to_vec();
                    buf.Unlock()?;
                    return Ok(v);
                }
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    // The encoder re-announces its output format (with the sequence
                    // header); accept it and try again.
                    let t = self.mft.GetOutputAvailableType(0, 0)?;
                    self.mft.SetOutputType(0, &t, 0)?;
                    self.seq_header = blob(&t, &MF_MT_MPEG_SEQUENCE_HEADER).unwrap_or_default();
                }
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => bail!("{}: encoder buffered the frame", self.name),
                Err(e) => return Err(e).context("ProcessOutput"),
            }
        }
    }
}

impl Drop for MfEncoder {
    fn drop(&mut self) {
        // SAFETY: tells the transform the stream is over; errors don't matter here.
        unsafe {
            let _ = self.mft.ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self.mft.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
            if let Some(gen) = &self.events {
                if let Ok(s) = gen.cast::<IMFShutdown>() {
                    let _ = s.Shutdown();
                }
            }
        }
    }
}

unsafe fn blob(t: &IMFMediaType, key: &GUID) -> Option<Vec<u8>> {
    let size = t.GetBlobSize(key).ok()?;
    let mut v = vec![0u8; size as usize];
    t.GetBlob(key, &mut v, None).ok()?;
    Some(v)
}

/// Whether an Annex-B stream contains a NAL unit of `kind` (5 = IDR slice, 7 = SPS).
pub fn has_nal(data: &[u8], kind: u8) -> bool {
    let mut i = 0;
    while i + 3 < data.len() {
        if data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 1 {
            if data[i + 3] & 0x1F == kind {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

/// `0x00RRGGBB` -> NV12, limited-range BT.601 (the matrix OpenH264 uses both ways).
pub fn bgrx_to_nv12(px: &[u32], w: usize, h: usize, out: &mut Vec<u8>) {
    out.resize(w * h * 3 / 2, 0);
    let (y_plane, uv_plane) = out.split_at_mut(w * h);
    let rgb = |p: u32| ((p >> 16 & 0xFF) as i32, (p >> 8 & 0xFF) as i32, (p & 0xFF) as i32);
    for (y_row, src) in y_plane.chunks_exact_mut(w).zip(px.chunks_exact(w)) {
        for (d, &p) in y_row.iter_mut().zip(src) {
            let (r, g, b) = rgb(p);
            // 0.2578125, 0.50390625, 0.09765625 in 1/256 units.
            *d = ((66 * r + 129 * g + 25 * b + 128) >> 8).wrapping_add(16) as u8;
        }
    }
    for (cy, uv_row) in uv_plane.chunks_exact_mut(w).enumerate() {
        let (r0, r1) = (&px[2 * cy * w..][..w], &px[(2 * cy + 1) * w..][..w]);
        for cx in 0..w / 2 {
            let (mut r, mut g, mut b) = (0, 0, 0);
            for p in [r0[2 * cx], r0[2 * cx + 1], r1[2 * cx], r1[2 * cx + 1]] {
                let c = rgb(p);
                r += c.0;
                g += c.1;
                b += c.2;
            }
            let (r, g, b) = (r / 4, g / 4, b / 4);
            // -0.1484375, -0.2890625, 0.4375 and 0.4375, -0.3671875, -0.0703125.
            uv_row[2 * cx] = (((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128).clamp(0, 255) as u8;
            uv_row[2 * cx + 1] = (((112 * r - 94 * g - 18 * b + 128) >> 8) + 128).clamp(0, 255) as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nal_scan() {
        assert!(has_nal(&[0, 0, 0, 1, 0x67, 1, 2, 0, 0, 1, 0x65, 9], 5));
        assert!(has_nal(&[0, 0, 0, 1, 0x67, 1], 7));
        assert!(!has_nal(&[0, 0, 1, 0x41, 1, 2, 3], 5));
    }

    #[test]
    fn nv12_matches_reference_colours() {
        let mut out = Vec::new();
        bgrx_to_nv12(&[0x00FFFFFF; 4], 2, 2, &mut out);
        assert_eq!(out, [235, 235, 235, 235, 128, 128]);
        bgrx_to_nv12(&[0; 4], 2, 2, &mut out);
        assert_eq!(out, [16, 16, 16, 16, 128, 128]);
        bgrx_to_nv12(&[0x00FF0000; 4], 2, 2, &mut out);
        assert_eq!(&out[4..], &[90, 240]);
    }

    /// `cargo test -p rd-core --features h264 --release hardware_speed -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn hardware_speed() {
        let (w, h) = (1920usize, 1080usize);
        let mut hw = MfEncoder::new(w as u32, h as u32, 4_000_000, 30).unwrap();
        let mut sw = crate::video::H264Encoder::new(4_000_000, 30).unwrap();
        let mut px: Vec<u32> = (0..w * h).map(|i| (i % w) as u32 * 0x010101 / 8).collect();
        let (mut t_hw, mut t_sw, mut b_hw, mut b_sw) = (Duration::ZERO, Duration::ZERO, 0, 0);
        for f in 0..90usize {
            for y in 200..500 {
                for x in 0..300 {
                    px[y * w + (x + f * 20) % w] = 0x00FF8800 ^ f as u32;
                }
            }
            let t = Instant::now();
            b_hw += hw.encode(&px).unwrap().data.len();
            t_hw += t.elapsed();
            let t = Instant::now();
            b_sw += sw.encode(w as u32, h as u32, &px).unwrap().data.len();
            t_sw += t.elapsed();
        }
        let t = Instant::now();
        let mut nv12 = Vec::new();
        for _ in 0..10 {
            bgrx_to_nv12(&px, w, h, &mut nv12);
        }
        println!("NV12 conversion (CPU): {:.1} ms/frame", t.elapsed().as_secs_f64() * 100.0);
        println!("{}: {:.1} ms/frame, {} KB", hw.name(), t_hw.as_secs_f64() * 1000.0 / 90.0, b_hw / 1024);
        println!("OpenH264: {:.1} ms/frame, {} KB", t_sw.as_secs_f64() * 1000.0 / 90.0, b_sw / 1024);
    }

    /// Runs only where a hardware encoder exists (prints and passes otherwise).
    #[test]
    fn hardware_round_trip() {
        let names = describe_hardware();
        println!("hardware encoders: {names:?}");
        let (w, h) = (640u32, 360u32);
        let mut enc = match MfEncoder::new(w, h, 2_000_000, 30) {
            Ok(e) => e,
            Err(e) => {
                println!("skipped: {e:#}");
                return;
            }
        };
        let mut dec = crate::video::H264Decoder::new().unwrap();
        let mut out = crate::codec::Decoder::default();
        for t in 0..10u32 {
            let px: Vec<u32> = (0..w * h).map(|i| ((i % w + t * 8) % 256) << 16 | (i / w % 256) << 8 | 0x40).collect();
            if t == 5 {
                enc.force_keyframe();
                enc.set_bitrate(1_000_000);
            }
            let f = enc.encode(&px).unwrap();
            if t == 0 || t == 5 {
                assert!(f.keyframe, "frame {t} should be a keyframe");
            }
            assert!(dec.decode(&f).unwrap(), "frame {t} did not decode");
            dec.merge_into(&mut out, f.keyframe);
            assert_eq!((out.width, out.height), (w, h));
            let close = out
                .pixels
                .iter()
                .zip(&px)
                .filter(|(a, b)| (0..3).all(|s| ((**a >> (s * 8)) & 0xFF).abs_diff((**b >> (s * 8)) & 0xFF) <= 40))
                .count();
            assert!(close * 100 / px.len() >= 90, "frame {t}: only {close} close pixels");
        }
    }
}
