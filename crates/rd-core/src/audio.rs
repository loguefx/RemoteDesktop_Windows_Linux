//! Audio transport: 16-bit PCM compressed 4:1 with IMA ADPCM.
//!
//! 48 kHz stereo becomes ~384 kbit/s - fine for LAN and relays, pure Rust, no codec
//! library to build. Every chunk carries its own predictor state, so a dropped chunk
//! (slow viewer) never corrupts the following ones.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioChunk {
    pub sample_rate: u32,
    pub channels: u16,
    /// Frames (samples per channel) in this chunk.
    pub frames: u32,
    /// Per channel: i16 predictor (LE) + u8 step index, then 4-bit codes,
    /// interleaved by frame, two codes per byte (low nibble first).
    pub data: Vec<u8>,
}

const STEPS: [i32; 89] = [
    7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 19, 21, 23, 25, 28, 31, 34, 37, 41, 45, 50, 55, 60, 66, 73, 80, 88, 97, 107,
    118, 130, 143, 157, 173, 190, 209, 230, 253, 279, 307, 337, 371, 408, 449, 494, 544, 598, 658, 724, 796, 876, 963,
    1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066, 2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358, 5894,
    6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899, 15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794,
    32767,
];
const INDEX_ADJ: [i32; 16] = [-1, -1, -1, -1, 2, 4, 6, 8, -1, -1, -1, -1, 2, 4, 6, 8];

#[derive(Clone, Copy, Default)]
struct State {
    pred: i32,
    index: i32,
}

impl State {
    fn decode(&mut self, code: u8) -> i16 {
        let step = STEPS[self.index as usize];
        let mut diff = step >> 3;
        if code & 1 != 0 {
            diff += step >> 2;
        }
        if code & 2 != 0 {
            diff += step >> 1;
        }
        if code & 4 != 0 {
            diff += step;
        }
        if code & 8 != 0 {
            self.pred -= diff;
        } else {
            self.pred += diff;
        }
        self.pred = self.pred.clamp(-32768, 32767);
        self.index = (self.index + INDEX_ADJ[code as usize]).clamp(0, 88);
        self.pred as i16
    }

    fn encode(&mut self, sample: i16) -> u8 {
        let step = STEPS[self.index as usize];
        let mut diff = sample as i32 - self.pred;
        let mut code = 0u8;
        if diff < 0 {
            code = 8;
            diff = -diff;
        }
        let mut s = step;
        if diff >= s {
            code |= 4;
            diff -= s;
        }
        s >>= 1;
        if diff >= s {
            code |= 2;
            diff -= s;
        }
        s >>= 1;
        if diff >= s {
            code |= 1;
        }
        // Keep the encoder's state identical to what the decoder will compute.
        self.decode(code);
        code
    }
}

/// Stateful encoder (state continues across chunks for best quality, but is written
/// into each chunk header so chunks decode independently).
pub struct AdpcmEncoder {
    channels: u16,
    sample_rate: u32,
    states: Vec<State>,
}

impl AdpcmEncoder {
    pub fn new(sample_rate: u32, channels: u16) -> Self {
        Self { channels, sample_rate, states: vec![State::default(); channels as usize] }
    }

    /// `pcm` is interleaved; its length must be a multiple of `channels`.
    pub fn encode(&mut self, pcm: &[i16]) -> AudioChunk {
        let ch = self.channels as usize;
        let frames = pcm.len() / ch;
        let mut data = Vec::with_capacity(ch * 3 + (frames * ch).div_ceil(2));
        for s in &self.states {
            data.extend_from_slice(&(s.pred as i16).to_le_bytes());
            data.push(s.index as u8);
        }
        let mut half: Option<u8> = None;
        for (i, &sample) in pcm[..frames * ch].iter().enumerate() {
            let code = self.states[i % ch].encode(sample);
            match half.take() {
                None => half = Some(code),
                Some(lo) => data.push(lo | (code << 4)),
            }
        }
        if let Some(lo) = half {
            data.push(lo);
        }
        AudioChunk { sample_rate: self.sample_rate, channels: self.channels, frames: frames as u32, data }
    }
}

/// Decode a chunk to interleaved i16. Returns an empty vec for malformed input.
pub fn decode(chunk: &AudioChunk) -> Vec<i16> {
    let ch = chunk.channels as usize;
    let total = chunk.frames as usize * ch;
    if ch == 0 || chunk.data.len() < ch * 3 + total.div_ceil(2) {
        return Vec::new();
    }
    let mut states: Vec<State> = (0..ch)
        .map(|c| State {
            pred: i16::from_le_bytes([chunk.data[c * 3], chunk.data[c * 3 + 1]]) as i32,
            index: (chunk.data[c * 3 + 2] as i32).clamp(0, 88),
        })
        .collect();
    let codes = &chunk.data[ch * 3..];
    let mut out = Vec::with_capacity(total);
    for i in 0..total {
        let byte = codes[i / 2];
        let code = if i % 2 == 0 { byte & 0x0F } else { byte >> 4 };
        out.push(states[i % ch].decode(code));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sine_roundtrip_is_close() {
        let mut pcm = Vec::new();
        for i in 0..4800 {
            let t = i as f32 / 48000.0;
            let l = (t * 440.0 * std::f32::consts::TAU).sin() * 12000.0;
            let r = (t * 660.0 * std::f32::consts::TAU).sin() * 8000.0;
            pcm.push(l as i16);
            pcm.push(r as i16);
        }
        let mut enc = AdpcmEncoder::new(48000, 2);
        let a = enc.encode(&pcm[..4800]);
        let b = enc.encode(&pcm[4800..]);
        assert!(a.data.len() < 4800 * 2 / 3, "~4:1 compression");
        let mut out = decode(&a);
        out.extend(decode(&b));
        assert_eq!(out.len(), pcm.len());
        // Skip warm-up; ADPCM error should be small relative to amplitude.
        let err: f64 = pcm[400..].iter().zip(&out[400..]).map(|(x, y)| (*x as f64 - *y as f64).abs()).sum::<f64>()
            / (pcm.len() - 400) as f64;
        assert!(err < 300.0, "mean abs error {err}");
    }
}
