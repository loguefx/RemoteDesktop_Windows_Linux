//! Dirty-tile codec.
//!
//! Frames are split into 64×64 tiles; only tiles that changed since the previous frame
//! are sent, each as LZ4-compressed BGR. Simple, lossless and very good for desktop
//! content (text, windows). For motion and slow links the host can instead send
//! H.264 ([`H264Frame`], see `rd_core::video`).

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

pub const TILE: u32 = 64;

/// A captured frame: 32-bit BGRA/BGRX pixels, `stride` bytes per row.
#[derive(Clone, Default)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub stride: usize,
    pub data: Vec<u8>,
}

impl Frame {
    pub fn row(&self, y: u32) -> &[u8] {
        let start = y as usize * self.stride;
        &self.data[start..start + self.width as usize * 4]
    }

    /// Write the frame as a 32-bit BMP (handy for `rd-host snapshot` diagnostics).
    pub fn to_bmp(&self) -> Vec<u8> {
        let row_bytes = self.width as usize * 4;
        let img = row_bytes * self.height as usize;
        let mut out = Vec::with_capacity(54 + img);
        out.extend_from_slice(b"BM");
        out.extend_from_slice(&((54 + img) as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&54u32.to_le_bytes());
        out.extend_from_slice(&40u32.to_le_bytes());
        out.extend_from_slice(&(self.width as i32).to_le_bytes());
        out.extend_from_slice(&(-(self.height as i32)).to_le_bytes()); // top-down
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&32u16.to_le_bytes());
        out.extend_from_slice(&[0u8; 24]);
        for y in 0..self.height {
            out.extend_from_slice(self.row(y));
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tile {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    /// `lz4_flex::compress_prepend_size` of w*h*3 bytes of BGR.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncodedFrame {
    pub width: u32,
    pub height: u32,
    pub keyframe: bool,
    pub tiles: Vec<Tile>,
}

impl EncodedFrame {
    pub fn byte_len(&self) -> usize {
        self.tiles.iter().map(|t| t.data.len() + 16).sum()
    }
}

/// One H.264 access unit (Annex B), produced per viewer by the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct H264Frame {
    pub width: u32,
    pub height: u32,
    pub keyframe: bool,
    pub data: Vec<u8>,
}

#[derive(Default)]
pub struct Encoder {
    prev: Option<Frame>,
    scratch: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Next `encode` call emits every tile.
    pub fn force_keyframe(&mut self) {
        self.prev = None;
    }

    /// Returns `None` if nothing changed since the last encoded frame.
    pub fn encode(&mut self, f: &Frame) -> Option<EncodedFrame> {
        let keyframe = match &self.prev {
            Some(p) => p.width != f.width || p.height != f.height,
            None => true,
        };
        let mut tiles = Vec::new();
        let mut ty = 0;
        while ty < f.height {
            let th = TILE.min(f.height - ty);
            let mut tx = 0;
            while tx < f.width {
                let tw = TILE.min(f.width - tx);
                if keyframe || self.tile_changed(f, tx, ty, tw, th) {
                    tiles.push(self.encode_tile(f, tx, ty, tw, th));
                }
                tx += TILE;
            }
            ty += TILE;
        }
        if !keyframe && tiles.is_empty() {
            return None;
        }
        // Keep a packed copy as the reference for the next diff.
        let prev = self.prev.get_or_insert_with(Frame::default);
        prev.width = f.width;
        prev.height = f.height;
        prev.stride = f.width as usize * 4;
        prev.data.clear();
        for y in 0..f.height {
            prev.data.extend_from_slice(f.row(y));
        }
        Some(EncodedFrame { width: f.width, height: f.height, keyframe, tiles })
    }

    fn tile_changed(&self, f: &Frame, tx: u32, ty: u32, tw: u32, th: u32) -> bool {
        let p = self.prev.as_ref().unwrap();
        let (a, b) = (tx as usize * 4, (tx + tw) as usize * 4);
        // Ignore the X/alpha byte: compare BGR only would need per-pixel work; full
        // compare is a memcmp and capture backends write a stable 4th byte.
        (ty..ty + th).any(|y| f.row(y)[a..b] != p.row(y)[a..b])
    }

    fn encode_tile(&mut self, f: &Frame, tx: u32, ty: u32, tw: u32, th: u32) -> Tile {
        self.scratch.clear();
        for y in ty..ty + th {
            let row = &f.row(y)[tx as usize * 4..(tx + tw) as usize * 4];
            for px in row.chunks_exact(4) {
                self.scratch.extend_from_slice(&px[..3]);
            }
        }
        Tile { x: tx, y: ty, w: tw, h: th, data: lz4_flex::compress_prepend_size(&self.scratch) }
    }
}

/// Client-side reconstruction into a `0x00RRGGBB` framebuffer.
#[derive(Default)]
pub struct Decoder {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u32>,
}

impl Decoder {
    pub fn apply(&mut self, f: &EncodedFrame) -> Result<()> {
        if f.width != self.width || f.height != self.height {
            if !f.keyframe {
                bail!("size changed without keyframe");
            }
            self.width = f.width;
            self.height = f.height;
            self.pixels = vec![0; f.width as usize * f.height as usize];
        }
        for t in &f.tiles {
            if t.x + t.w > self.width || t.y + t.h > self.height {
                bail!("tile out of bounds");
            }
            let raw = lz4_flex::decompress_size_prepended(&t.data)?;
            if raw.len() != (t.w * t.h * 3) as usize {
                bail!("bad tile size");
            }
            for (row_i, row) in raw.chunks_exact(t.w as usize * 3).enumerate() {
                let start = (t.y as usize + row_i) * self.width as usize + t.x as usize;
                let dst = &mut self.pixels[start..start + t.w as usize];
                for (d, px) in dst.iter_mut().zip(row.chunks_exact(3)) {
                    *d = (px[2] as u32) << 16 | (px[1] as u32) << 8 | px[0] as u32;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(w: u32, h: u32, seed: u8) -> Frame {
        let mut data = vec![0u8; (w * h * 4) as usize];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(seed);
        }
        Frame { width: w, height: h, stride: w as usize * 4, data }
    }

    #[test]
    fn roundtrip_and_diff() {
        let mut enc = Encoder::new();
        let mut dec = Decoder::default();
        let f1 = frame(130, 70, 7);
        let e1 = enc.encode(&f1).unwrap();
        assert!(e1.keyframe);
        assert_eq!(e1.tiles.len(), 3 * 2);
        dec.apply(&e1).unwrap();
        assert!(enc.encode(&f1).is_none(), "unchanged frame must produce nothing");

        let mut f2 = f1.clone();
        let off = 65 * f2.stride + 4 * 100; // a pixel in tile (64, 64)
        f2.data[off] ^= 0xFF;
        let e2 = enc.encode(&f2).unwrap();
        assert_eq!(e2.tiles.len(), 1);
        assert_eq!((e2.tiles[0].x, e2.tiles[0].y), (64, 64));
        dec.apply(&e2).unwrap();

        for y in 0..f2.height {
            for x in 0..f2.width {
                let p = &f2.row(y)[x as usize * 4..];
                let want = (p[2] as u32) << 16 | (p[1] as u32) << 8 | p[0] as u32;
                assert_eq!(dec.pixels[(y * f2.width + x) as usize], want);
            }
        }
    }

    #[test]
    fn padded_stride() {
        let mut f = frame(10, 3, 3);
        // Re-pack with 8 bytes of row padding.
        let mut padded = Vec::new();
        for y in 0..3 {
            padded.extend_from_slice(f.row(y));
            padded.extend_from_slice(&[0xAA; 8]);
        }
        f.data = padded;
        f.stride = 48;
        let e = Encoder::new().encode(&f).unwrap();
        let mut d = Decoder::default();
        d.apply(&e).unwrap();
        assert_eq!(d.pixels.len(), 30);
    }
}
