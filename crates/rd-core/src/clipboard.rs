//! Clipboard sync worker shared by the host agent and the client: text, images and
//! copied files.
//!
//! A background thread polls the local clipboard twice a second and reports changes
//! through a callback; [`Worker::set`] applies data that arrived from the other side.
//! Whatever we set ourselves is remembered (as read back from the clipboard) so it doesn't
//! bounce straight back. Images travel as PNG.
//!
//! Copied files (and folders) travel with their contents, up to
//! [`MAX_CLIP_FILE_BYTES`]. The receiving side writes them under
//! `<temp>/rd-clipboard/` and puts those paths on its clipboard, so pasting in a file
//! manager copies them as usual. Only the latest received set is kept there.

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};

use crate::proto::{ClipData, ClipFile, ClipImage, MAX_CLIP_FILE_BYTES, MAX_CLIP_FILE_ENTRIES, MAX_CLIP_PIXELS};

/// Encode RGBA8 pixels as PNG.
pub fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Result<Vec<u8>> {
    if rgba.len() != width as usize * height as usize * 4 {
        bail!("image buffer size does not match {width}x{height}");
    }
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, width, height);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        enc.set_compression(png::Compression::Fast);
        let mut w = enc.write_header()?;
        w.write_image_data(rgba)?;
    }
    Ok(out)
}

/// Decode a PNG to `(width, height, RGBA8)`. The size is checked against
/// [`MAX_CLIP_PIXELS`] before any pixel buffer is allocated.
pub fn decode_png(data: &[u8]) -> Result<(u32, u32, Vec<u8>)> {
    let limits = png::Limits { bytes: MAX_CLIP_PIXELS as usize * 8 + (1 << 20) };
    let mut dec = png::Decoder::new_with_limits(Cursor::new(data), limits);
    dec.set_transformations(png::Transformations::normalize_to_color8());
    let mut reader = dec.read_info()?;
    let (w, h) = {
        let i = reader.info();
        (i.width, i.height)
    };
    if w == 0 || h == 0 || w as u64 * h as u64 > MAX_CLIP_PIXELS {
        bail!("clipboard image {w}x{h} is too large");
    }
    let mut buf = vec![0; reader.output_buffer_size().ok_or_else(|| anyhow::anyhow!("image too large"))?];
    let frame = reader.next_frame(&mut buf)?;
    buf.truncate(frame.buffer_size());
    let px = w as usize * h as usize;
    let rgba = match frame.color_type {
        png::ColorType::Rgba => buf,
        png::ColorType::Rgb => buf.chunks_exact(3).flat_map(|p| [p[0], p[1], p[2], 255]).collect(),
        png::ColorType::Grayscale => buf.iter().flat_map(|&g| [g, g, g, 255]).collect(),
        png::ColorType::GrayscaleAlpha => buf.chunks_exact(2).flat_map(|p| [p[0], p[0], p[0], p[1]]).collect(),
        png::ColorType::Indexed => bail!("unexpected indexed PNG after expansion"),
    };
    if rgba.len() != px * 4 {
        bail!("PNG decoded to an unexpected size");
    }
    Ok((w, h, rgba))
}

fn image_hash(width: usize, height: usize, rgba: &[u8]) -> u64 {
    let mut h = DefaultHasher::new();
    (width, height).hash(&mut h);
    rgba.hash(&mut h);
    h.finish()
}

/// What we last saw on (or put on) the clipboard.
#[derive(PartialEq)]
enum Seen {
    Nothing,
    Text(String),
    Image(u64),
    Files(u64),
}

/// The clipboard's content, as read.
enum Local {
    Text,
    Image(arboard::ImageData<'static>),
    Files(Vec<PathBuf>),
}

/// Identity of a file list: paths, sizes and modification times (contents aren't read
/// until the list is known to be new).
fn files_hash(paths: &[PathBuf]) -> u64 {
    let mut h = DefaultHasher::new();
    for p in paths {
        p.hash(&mut h);
        if let Ok(m) = std::fs::metadata(p) {
            m.len().hash(&mut h);
            m.modified().ok().hash(&mut h);
        }
    }
    h.finish()
}

/// Read the clipboard. Files win, then text (rich copies from browsers and office apps
/// often carry an image rendering as well), then images.
fn read(cb: &mut arboard::Clipboard) -> Option<(Seen, Local)> {
    if let Ok(paths) = cb.get().file_list() {
        if !paths.is_empty() {
            return Some((Seen::Files(files_hash(&paths)), Local::Files(paths)));
        }
    }
    if let Ok(t) = cb.get_text() {
        if !t.is_empty() {
            return Some((Seen::Text(t), Local::Text));
        }
    }
    let img = cb.get_image().ok()?;
    let hash = image_hash(img.width, img.height, &img.bytes);
    Some((Seen::Image(hash), Local::Image(img)))
}

/// Read copied files and folders (recursively, not following links) within the limits.
pub fn collect_files(paths: &[PathBuf]) -> Result<Vec<ClipFile>> {
    let mut out = Vec::new();
    let mut bytes = 0u64;
    for p in paths {
        let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
            bail!("{} has no usable name", p.display());
        };
        add_entry(p, name.to_string(), &mut out, &mut bytes)?;
    }
    Ok(out)
}

fn add_entry(p: &Path, rel: String, out: &mut Vec<ClipFile>, bytes: &mut u64) -> Result<()> {
    if out.len() >= MAX_CLIP_FILE_ENTRIES {
        bail!("more than {MAX_CLIP_FILE_ENTRIES} files");
    }
    let meta = std::fs::symlink_metadata(p)?;
    if meta.is_dir() {
        out.push(ClipFile { path: rel.clone(), is_dir: true, data: Vec::new() });
        let mut children: Vec<_> = std::fs::read_dir(p)?.filter_map(|e| e.ok()).collect();
        children.sort_by_key(|e| e.file_name());
        for e in children {
            if let Some(n) = e.file_name().to_str() {
                add_entry(&e.path(), format!("{rel}/{n}"), out, bytes)?;
            }
        }
    } else if meta.is_file() {
        *bytes += meta.len();
        if *bytes > MAX_CLIP_FILE_BYTES {
            bail!("more than {} MiB", MAX_CLIP_FILE_BYTES >> 20);
        }
        out.push(ClipFile { path: rel, is_dir: false, data: std::fs::read(p)? });
    }
    // Links and special files are skipped.
    Ok(())
}

/// Where received clipboard files are written.
fn received_root() -> PathBuf {
    std::env::temp_dir().join("rd-clipboard")
}

/// Write received files into a fresh folder (removing earlier ones) and return the
/// top-level paths to put on the clipboard.
pub fn write_received(files: &[ClipFile]) -> Result<Vec<PathBuf>> {
    let root = received_root();
    if let Ok(old) = std::fs::read_dir(&root) {
        for e in old.flatten() {
            let _ = std::fs::remove_dir_all(e.path());
        }
    }
    let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis();
    let dir = root.join(stamp.to_string());
    std::fs::create_dir_all(&dir)?;
    let mut tops = Vec::new();
    for f in files {
        if !f.path_is_safe() {
            bail!("unsafe path in received files: {:?}", f.path);
        }
        let target = f.path.split('/').fold(dir.clone(), |p, c| p.join(c));
        if f.is_dir {
            std::fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&target, &f.data)?;
        }
        if !f.path.contains('/') && !tops.contains(&target) {
            tops.push(target);
        }
    }
    Ok(tops)
}

/// Cheap "has anything changed?" check, where the OS offers one.
#[cfg(windows)]
fn change_counter() -> Option<u32> {
    clipboard_win::raw::seq_num().map(|n| n.get())
}
#[cfg(not(windows))]
fn change_counter() -> Option<u32> {
    None
}

pub struct Worker {
    tx: Option<Sender<ClipData>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Worker {
    /// Start the clipboard thread. `on_change` gets every local change and returns
    /// `false` to stop. With `announce_initial`, whatever is on the clipboard at start
    /// is reported too.
    pub fn spawn(announce_initial: bool, on_change: impl FnMut(ClipData) -> bool + Send + 'static) -> Worker {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let s = stop.clone();
        let thread = std::thread::Builder::new()
            .name("clipboard".into())
            .spawn(move || run(rx, s, announce_initial, on_change))
            .ok();
        Worker { tx: Some(tx), stop, thread }
    }

    /// Put data from the other side onto the local clipboard.
    pub fn set(&self, data: ClipData) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(data);
        }
    }
}

impl Drop for Worker {
    /// Stops the thread and waits for it, so the clipboard is released properly. On X11
    /// that hands what we put there to the desktop's clipboard manager, so it survives
    /// this process (otherwise X11 clipboard contents vanish with their owner).
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        // Closing the channel wakes the thread at once.
        self.tx = None;
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

fn run(rx: Receiver<ClipData>, stop: Arc<AtomicBool>, announce_initial: bool, mut on_change: impl FnMut(ClipData) -> bool) {
    let mut cb = None;
    let mut last = Seen::Nothing;
    let mut counter = None;
    let mut first = true;
    while !stop.load(Ordering::Relaxed) {
        if cb.is_none() {
            match arboard::Clipboard::new() {
                Ok(c) => cb = Some(c),
                Err(e) => {
                    log::debug!("clipboard unavailable: {e}");
                    // Retry in 2 s, but notice a stop request promptly.
                    for _ in 0..20 {
                        if stop.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    continue;
                }
            }
        }
        let c = cb.as_mut().unwrap();
        if first {
            first = false;
            if !announce_initial {
                // Don't announce whatever was already there when we started.
                counter = change_counter();
                last = read(c).map(|(s, _)| s).unwrap_or(Seen::Nothing);
            }
        }
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(data) => {
                if let Err(e) = apply(c, data) {
                    log::debug!("set clipboard: {e:#}");
                }
                // Remember what the clipboard now holds as *we* read it, so a lossy
                // round trip (e.g. an image converted by the OS) doesn't echo back.
                counter = change_counter();
                last = read(c).map(|(s, _)| s).unwrap_or(Seen::Nothing);
            }
            Err(RecvTimeoutError::Timeout) => {
                let now = change_counter();
                if now.is_some() && now == counter {
                    continue;
                }
                counter = now;
                let Some((seen, local)) = read(c) else { continue };
                if seen == last {
                    continue;
                }
                let data = match (&seen, local) {
                    (Seen::Text(t), _) => ClipData::Text(t.clone()),
                    (Seen::Files(_), Local::Files(paths)) => match collect_files(&paths) {
                        Ok(files) if !files.is_empty() => ClipData::Files(files),
                        Ok(_) => {
                            last = seen;
                            continue;
                        }
                        Err(e) => {
                            log::info!("copied files not synced ({e:#}); use the Files panel for large copies");
                            last = seen;
                            continue;
                        }
                    },
                    (Seen::Image(_), Local::Image(img)) => {
                        if img.width as u64 * img.height as u64 > MAX_CLIP_PIXELS {
                            log::info!("clipboard image {}x{} too large to sync", img.width, img.height);
                            last = seen;
                            continue;
                        }
                        match encode_png(img.width as u32, img.height as u32, &img.bytes) {
                            Ok(png) => ClipData::Image(ClipImage { width: img.width as u32, height: img.height as u32, png }),
                            Err(e) => {
                                log::debug!("encode clipboard image: {e:#}");
                                last = seen;
                                continue;
                            }
                        }
                    }
                    _ => continue,
                };
                last = seen;
                if !data.within_limits() {
                    log::info!("clipboard content too large to sync");
                    continue;
                }
                if !on_change(data) {
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn apply(cb: &mut arboard::Clipboard, data: ClipData) -> Result<()> {
    if !data.within_limits() {
        bail!("clipboard content too large");
    }
    match data {
        ClipData::Text(t) => cb.set_text(t)?,
        ClipData::Image(img) => {
            let (w, h, rgba) = decode_png(&img.png)?;
            cb.set_image(arboard::ImageData { width: w as usize, height: h as usize, bytes: rgba.into() })?;
        }
        ClipData::Files(files) => {
            let paths = write_received(&files)?;
            cb.set().file_list(&paths)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_round_trip() {
        let (w, h) = (37u32, 21u32);
        let rgba: Vec<u8> = (0..w * h * 4).map(|i| (i * 7 % 251) as u8).collect();
        let png = encode_png(w, h, &rgba).unwrap();
        let (w2, h2, back) = decode_png(&png).unwrap();
        assert_eq!((w2, h2), (w, h));
        assert_eq!(back, rgba);
    }

    #[test]
    fn files_round_trip_through_disk() {
        let src = std::env::temp_dir().join(format!("rd-clip-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(src.join("folder/sub")).unwrap();
        std::fs::write(src.join("a.txt"), b"alpha").unwrap();
        std::fs::write(src.join("folder/sub/b.bin"), [1u8, 2, 3]).unwrap();
        std::fs::create_dir_all(src.join("folder/empty")).unwrap();
        let files = collect_files(&[src.join("a.txt"), src.join("folder")]).unwrap();
        let data = ClipData::Files(files.clone());
        assert!(data.within_limits(), "{}", data.describe());
        let paths: Vec<&str> = files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["a.txt", "folder", "folder/empty", "folder/sub", "folder/sub/b.bin"]);

        let tops = write_received(&files).unwrap();
        assert_eq!(tops.len(), 2);
        assert_eq!(std::fs::read(&tops[0]).unwrap(), b"alpha");
        assert_eq!(std::fs::read(tops[1].join("sub").join("b.bin")).unwrap(), [1, 2, 3]);
        assert!(tops[1].join("empty").is_dir());
        let _ = std::fs::remove_dir_all(&src);
        let _ = std::fs::remove_dir_all(tops[0].parent().unwrap());
    }

    #[test]
    fn unsafe_paths_are_refused() {
        for bad in ["../x", "a/../../x", "/etc/passwd", "CON", "dir/nul.txt", "com1", "C:\\x", "a\\b", "", "a//b", "con:"] {
            let f = ClipFile { path: bad.into(), is_dir: false, data: vec![] };
            assert!(!f.path_is_safe(), "{bad:?}");
            assert!(!ClipData::Files(vec![f]).within_limits());
        }
        assert!(ClipFile { path: "ok dir/file.txt".into(), is_dir: false, data: vec![] }.path_is_safe());
        let big = ClipFile { path: "big".into(), is_dir: false, data: vec![0; MAX_CLIP_FILE_BYTES as usize + 1] };
        assert!(!ClipData::Files(vec![big]).within_limits());
    }

    #[test]
    fn rejects_huge_png() {
        // Header claims 100k x 100k; must be refused before allocating.
        let mut out = Vec::new();
        {
            let mut enc = png::Encoder::new(&mut out, 100_000, 100_000);
            enc.set_color(png::ColorType::Grayscale);
            let _ = enc.write_header().unwrap();
        }
        assert!(decode_png(&out).is_err());
    }
}
