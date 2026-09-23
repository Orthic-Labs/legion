//! Port of `src/lib/review/vision_input.py` (vision input prep: extract
//! image/video paths from an auto-jury `input.md`, base64-encode images,
//! and extract video keyframes via `ffmpeg`/`ffprobe`).
//!
//! **Ported faithfully:**
//! - `MAX_IMAGES`, `VIDEO_KEYFRAMES`, `MAX_IMAGE_BYTES` constants —
//!   [`MAX_IMAGES`], [`VIDEO_KEYFRAMES`], [`MAX_IMAGE_BYTES`]
//! - the absolute-path regex (`_PATH_RE`) and dedup-preserving-order
//!   extraction (`_extract_paths`) — [`extract_paths`]
//! - the Git-Bash/MSYS drive-path fallback (`_resolve_path`: `/d/foo` →
//!   `D:/foo` when the raw path does not exist but the Windows form does)
//!   — [`resolve_path`]
//! - the even-timestamp keyframe sampling schedule (`_extract_video_keyframes`'s
//!   `timestamps` computation, `n == 1` → midpoint, else `step * (i + 1)`)
//!   — [`keyframe_timestamps`]
//! - the full `prepare_vision_payload` orchestration: extract paths, resolve
//!   each, classify by extension, apply the `max_images`/`MAX_IMAGE_BYTES`
//!   caps, invoke image base64-encoding or video keyframe extraction (via
//!   injected [`ImageSource`]) — [`prepare_vision_payload`]
//!
//! **Live-transport boundary:** actual `ffmpeg`/`ffprobe` subprocess
//! invocation (`_ffmpeg_available`, `_video_duration`,
//! `_extract_video_keyframes`'s `subprocess.run` calls) and real filesystem
//! reads (`_b64`, `os.path.getsize`, `os.path.exists`) are abstracted behind
//! the [`ImageSource`] trait so [`prepare_vision_payload`]'s selection,
//! capping, and payload-shaping logic is exercised without a real `ffmpeg`
//! binary or filesystem. [`FsImageSource`] is the faithful real-filesystem
//! implementation, ported line-for-line from `_b64`/`_extract_video_keyframes`/
//! `_video_duration`, for a caller that wants the exact original behaviour.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use regex::Regex;

/// Port of `MAX_IMAGES`.
pub const MAX_IMAGES: usize = 6;
/// Port of `VIDEO_KEYFRAMES`.
pub const VIDEO_KEYFRAMES: usize = 4;
/// Port of `MAX_IMAGE_BYTES` (5 MB).
pub const MAX_IMAGE_BYTES: u64 = 5 * 1024 * 1024;

const IMAGE_EXTS: &[&str] = &["png", "jpg", "jpeg", "webp"];
const VIDEO_EXTS: &[&str] = &["mp4", "mov", "webm"];

fn mime_for_image_ext(ext: &str) -> Option<&'static str> {
    match ext {
        "png" => Some("image/png"),
        "jpg" | "jpeg" => Some("image/jpeg"),
        "webp" => Some("image/webp"),
        _ => None,
    }
}

fn path_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        // Port of `_PATH_RE`: a drive letter (Windows) or absolute slash
        // (Unix) prefix, no whitespace/quote/angle-bracket bytes, ending in
        // one of the recognized media extensions.
        Regex::new(r#"(?i)(?:[A-Za-z]:[\\/]|/)[^\s"'`<>]+\.(?:png|jpg|jpeg|webp|mp4|mov|webm)"#)
            .expect("static regex is valid")
    })
}

/// Port of `_extract_paths(text)`: order-preserving, dedup-by-normalized-slashes.
pub fn extract_paths(text: &str) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for m in path_re().find_iter(text) {
        let raw = m.as_str().trim_end_matches([',', '.', ';']);
        let normalized = raw.replace('\\', "/");
        if seen.insert(normalized) {
            out.push(raw.to_string());
        }
    }
    out
}

/// Port of `_resolve_path(p)`. `exists` is injected so this is testable
/// without touching the real filesystem; [`FsImageSource`] wires it to
/// `Path::exists`.
pub fn resolve_path(p: &str, exists: impl Fn(&str) -> bool) -> Option<String> {
    if exists(p) {
        return Some(p.to_string());
    }
    // Port of `re.match(r"^/([a-zA-Z])/(.*)$", p)`.
    let bytes = p.as_bytes();
    if bytes.len() >= 3 && bytes[0] == b'/' && bytes[1].is_ascii_alphabetic() && bytes[2] == b'/' {
        let drive = (bytes[1] as char).to_ascii_uppercase();
        let rest = &p[3..];
        let win = format!("{drive}:/{rest}");
        if exists(&win) {
            return Some(win);
        }
    }
    None
}

/// Port of `_extract_video_keyframes`'s `timestamps` computation (the
/// deterministic part; the actual `ffmpeg` invocation per timestamp is
/// [`ImageSource`]'s concern).
pub fn keyframe_timestamps(duration_s: f64, n: usize) -> Vec<f64> {
    if duration_s <= 0.0 || n == 0 {
        return Vec::new();
    }
    if n == 1 {
        return vec![duration_s / 2.0];
    }
    let step = duration_s / (n as f64 + 1.0);
    (0..n).map(|i| (step * (i as f64 + 1.0) * 100.0).round() / 100.0).collect()
}

/// One prepared vision payload item, matching the JSON shape
/// `{"mime": ..., "b64": ..., "source": ...}`.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct VisionItem {
    pub mime: &'static str,
    pub b64: String,
    pub source: String,
}

/// Abstracts the filesystem/subprocess boundary `prepare_vision_payload`
/// crosses, so its selection/capping logic is unit-testable.
pub trait ImageSource {
    /// Port of `os.path.getsize(p)`; `None` mirrors the `OSError` catch
    /// (file missing/unreadable), which the Python source treats as "skip".
    fn size(&self, path: &str) -> Option<u64>;
    /// Port of `_b64(path)`.
    fn base64(&self, path: &str) -> Option<String>;
    /// Port of `_extract_video_keyframes(video_path)`: returns extracted
    /// frame paths (possibly empty, e.g. no `ffmpeg`/zero duration).
    fn video_keyframes(&self, video_path: &str) -> Vec<String>;
}

/// Port of `prepare_vision_payload(text, max_images)`.
pub fn prepare_vision_payload(
    text: &str,
    max_images: usize,
    source: &impl ImageSource,
    exists: impl Fn(&str) -> bool,
) -> Vec<VisionItem> {
    let paths = extract_paths(text);
    if paths.is_empty() {
        return Vec::new();
    }

    let mut payload: Vec<VisionItem> = Vec::new();
    for p in paths {
        if payload.len() >= max_images {
            break;
        }
        let resolved = match resolve_path(&p, &exists) {
            Some(r) => r,
            None => continue,
        };
        let ext = Path::new(&resolved)
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase())
            .unwrap_or_default();
        let size = match source.size(&resolved) {
            Some(s) => s,
            None => continue,
        };
        if IMAGE_EXTS.contains(&ext.as_str()) {
            if size == 0 || size > MAX_IMAGE_BYTES {
                continue;
            }
            let mime = mime_for_image_ext(&ext).expect("ext checked against IMAGE_EXTS");
            if let Some(b64) = source.base64(&resolved) {
                payload.push(VisionItem { mime, b64, source: resolved.clone() });
            }
        } else if VIDEO_EXTS.contains(&ext.as_str()) {
            for fp in source.video_keyframes(&resolved) {
                if payload.len() >= max_images {
                    break;
                }
                let fsize = match source.size(&fp) {
                    Some(s) => s,
                    None => continue,
                };
                if fsize == 0 || fsize > MAX_IMAGE_BYTES {
                    continue;
                }
                if let Some(b64) = source.base64(&fp) {
                    let frame_name = Path::new(&fp)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(&fp)
                        .to_string();
                    payload.push(VisionItem {
                        mime: "image/png",
                        b64,
                        source: format!("{resolved} (keyframe {frame_name})"),
                    });
                }
            }
        }
    }
    payload
}

/// Faithful real-filesystem/real-`ffmpeg` implementation of [`ImageSource`],
/// porting `_b64`, `_video_duration`, and `_extract_video_keyframes`
/// line-for-line.
pub struct FsImageSource;

impl FsImageSource {
    fn ffmpeg_available() -> bool {
        which("ffmpeg").is_some()
    }

    fn video_duration(video_path: &str) -> Option<f64> {
        which("ffprobe")?;
        let out = Command::new("ffprobe")
            .args([
                "-v",
                "error",
                "-show_entries",
                "format=duration",
                "-of",
                "default=noprint_wrappers=1:nokey=1",
                video_path,
            ])
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout).trim().parse::<f64>().ok()
    }
}

/// Standard (RFC 4648, padded) base64 encode, matching Python's
/// `base64.b64encode(...).decode("ascii")`. Hand-rolled to avoid adding a
/// `base64` crate dependency (see the chunk report for the suggested
/// `Cargo.toml` patch if a caller prefers a crate implementation).
fn base64_standard_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(ALPHABET[((n >> 18) & 0x3F) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3F) as usize] as char);
        out.push(if chunk.len() > 1 { ALPHABET[((n >> 6) & 0x3F) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[(n & 0x3F) as usize] as char } else { '=' });
    }
    out
}

fn which(bin: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var).find_map(|dir| {
        let candidate = dir.join(bin);
        candidate.is_file().then_some(candidate)
    })
}

impl ImageSource for FsImageSource {
    fn size(&self, path: &str) -> Option<u64> {
        std::fs::metadata(path).ok().map(|m| m.len())
    }

    fn base64(&self, path: &str) -> Option<String> {
        let bytes = std::fs::read(path).ok()?;
        Some(base64_standard_encode(&bytes))
    }

    fn video_keyframes(&self, video_path: &str) -> Vec<String> {
        if !Self::ffmpeg_available() {
            return Vec::new();
        }
        let duration = Self::video_duration(video_path).unwrap_or(0.0);
        if duration <= 0.0 {
            return Vec::new();
        }
        let timestamps = keyframe_timestamps(duration, VIDEO_KEYFRAMES);
        let tmpdir = std::env::temp_dir().join(format!("council-frames-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmpdir);
        let mut out_paths = Vec::new();
        for (i, ts) in timestamps.iter().enumerate() {
            let out_path = tmpdir.join(format!("frame-{i:02}-t{ts:.2}s.png"));
            let args: Vec<String> = vec![
                "-y".to_string(),
                "-ss".to_string(),
                ts.to_string(),
                "-i".to_string(),
                video_path.to_string(),
                "-vframes".to_string(),
                "1".to_string(),
                "-vf".to_string(),
                "scale=512:-1:flags=lanczos".to_string(),
                "-loglevel".to_string(),
                "error".to_string(),
            ];
            let status = Command::new("ffmpeg").args(&args).arg(&out_path).status();
            if status.is_ok()
                && out_path.exists()
                && std::fs::metadata(&out_path).map(|m| m.len() > 0).unwrap_or(false)
            {
                out_paths.push(out_path.to_string_lossy().into_owned());
            }
        }
        out_paths
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn extract_paths_matches_unix_and_windows_forms() {
        let text = "see /tmp/shot.png and D:\\out\\clip.mp4, also /tmp/shot.png again";
        let paths = extract_paths(text);
        assert_eq!(paths, vec!["/tmp/shot.png", "D:\\out\\clip.mp4"]);
    }

    #[test]
    fn extract_paths_trims_trailing_punctuation() {
        let paths = extract_paths("frame at /tmp/a.png.");
        assert_eq!(paths, vec!["/tmp/a.png"]);
    }

    #[test]
    fn extract_paths_ignores_non_media_extensions() {
        let paths = extract_paths("/tmp/notes.txt has nothing");
        assert!(paths.is_empty());
    }

    #[test]
    fn resolve_path_prefers_existing_raw_path() {
        let resolved = resolve_path("/tmp/x.png", |p| p == "/tmp/x.png");
        assert_eq!(resolved.as_deref(), Some("/tmp/x.png"));
    }

    #[test]
    fn resolve_path_falls_back_to_windows_drive_form() {
        let resolved = resolve_path("/d/out/clip.mp4", |p| p == "D:/out/clip.mp4");
        assert_eq!(resolved.as_deref(), Some("D:/out/clip.mp4"));
    }

    #[test]
    fn resolve_path_returns_none_when_neither_exists() {
        assert_eq!(resolve_path("/d/missing.png", |_| false), None);
    }

    #[test]
    fn keyframe_timestamps_single_frame_uses_midpoint() {
        assert_eq!(keyframe_timestamps(10.0, 1), vec![5.0]);
    }

    #[test]
    fn keyframe_timestamps_multi_frame_evenly_spaced() {
        // duration=10, n=4 -> step=2.0 -> [2.0, 4.0, 6.0, 8.0]
        assert_eq!(keyframe_timestamps(10.0, 4), vec![2.0, 4.0, 6.0, 8.0]);
    }

    #[test]
    fn keyframe_timestamps_zero_duration_is_empty() {
        assert!(keyframe_timestamps(0.0, 4).is_empty());
    }

    struct FakeSource {
        sizes: HashMap<String, u64>,
        frames: HashMap<String, Vec<String>>,
    }

    impl ImageSource for FakeSource {
        fn size(&self, path: &str) -> Option<u64> {
            self.sizes.get(path).copied()
        }
        fn base64(&self, path: &str) -> Option<String> {
            self.sizes.get(path).map(|_| format!("b64:{path}"))
        }
        fn video_keyframes(&self, video_path: &str) -> Vec<String> {
            self.frames.get(video_path).cloned().unwrap_or_default()
        }
    }

    #[test]
    fn prepare_vision_payload_encodes_images_within_cap() {
        let mut sizes = HashMap::new();
        sizes.insert("/tmp/a.png".to_string(), 100);
        let source = FakeSource { sizes, frames: HashMap::new() };
        let payload =
            prepare_vision_payload("/tmp/a.png", MAX_IMAGES, &source, |p| p == "/tmp/a.png");
        assert_eq!(payload.len(), 1);
        assert_eq!(payload[0].mime, "image/png");
        assert_eq!(payload[0].b64, "b64:/tmp/a.png");
        assert_eq!(payload[0].source, "/tmp/a.png");
    }

    #[test]
    fn prepare_vision_payload_skips_oversized_image() {
        let mut sizes = HashMap::new();
        sizes.insert("/tmp/a.png".to_string(), MAX_IMAGE_BYTES + 1);
        let source = FakeSource { sizes, frames: HashMap::new() };
        let payload =
            prepare_vision_payload("/tmp/a.png", MAX_IMAGES, &source, |p| p == "/tmp/a.png");
        assert!(payload.is_empty());
    }

    #[test]
    fn prepare_vision_payload_skips_unresolvable_path() {
        let source = FakeSource { sizes: HashMap::new(), frames: HashMap::new() };
        let payload = prepare_vision_payload("/tmp/a.png", MAX_IMAGES, &source, |_| false);
        assert!(payload.is_empty());
    }

    #[test]
    fn prepare_vision_payload_expands_video_to_keyframes() {
        let mut sizes = HashMap::new();
        sizes.insert("/tmp/clip.mp4".to_string(), 10);
        sizes.insert("/tmp/frame-00.png".to_string(), 50);
        sizes.insert("/tmp/frame-01.png".to_string(), 50);
        let mut frames = HashMap::new();
        frames.insert(
            "/tmp/clip.mp4".to_string(),
            vec!["/tmp/frame-00.png".to_string(), "/tmp/frame-01.png".to_string()],
        );
        let source = FakeSource { sizes, frames };
        let exists = |p: &str| p == "/tmp/clip.mp4";
        let payload = prepare_vision_payload("/tmp/clip.mp4", MAX_IMAGES, &source, exists);
        assert_eq!(payload.len(), 2);
        assert_eq!(payload[0].mime, "image/png");
        assert_eq!(payload[0].source, "/tmp/clip.mp4 (keyframe frame-00.png)");
    }

    #[test]
    fn prepare_vision_payload_respects_max_images_cap() {
        let mut sizes = HashMap::new();
        sizes.insert("/tmp/a.png".to_string(), 10);
        sizes.insert("/tmp/b.png".to_string(), 10);
        let source = FakeSource { sizes, frames: HashMap::new() };
        let text = "/tmp/a.png /tmp/b.png";
        let payload = prepare_vision_payload(text, 1, &source, |_| true);
        assert_eq!(payload.len(), 1);
        assert_eq!(payload[0].source, "/tmp/a.png");
    }

    #[test]
    fn prepare_vision_payload_empty_text_is_empty() {
        let source = FakeSource { sizes: HashMap::new(), frames: HashMap::new() };
        assert!(prepare_vision_payload("", MAX_IMAGES, &source, |_| true).is_empty());
    }
}
