//! Port of `research-core/common.py`: shared deterministic helpers.
//!
//! `file_lock` (a process-level advisory lock using atomic lock-file
//! creation) is intentionally not ported here: it is filesystem
//! concurrency plumbing consumed only by `manifest.py`, which is not yet
//! ported (tracked as remaining work in the packet report). Port it
//! alongside `manifest.py` when that lands.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use sha2::{Digest, Sha256};

/// RFC3339 UTC timestamp truncated to whole seconds, `Z` suffix — matches
/// `common.utc_now()`.
pub fn utc_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format_utc_seconds(now.as_secs())
}

fn format_utc_seconds(total_secs: u64) -> String {
    // Civil-from-days algorithm (Howard Hinnant), avoids a chrono dependency.
    let days = (total_secs / 86_400) as i64;
    let secs_of_day = total_secs % 86_400;
    let (h, m, s) = (secs_of_day / 3600, (secs_of_day % 3600) / 60, secs_of_day % 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `common.today()`: local calendar date as `YYYY-MM-DD`. Rust has no
/// tz-aware clock in std, so (like the rest of this deterministic core) we
/// use UTC date, which matches `today()` for any host running UTC (CI and
/// production hosts here do).
pub fn today() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let days = (now.as_secs() / 86_400) as i64;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// `common.sha256_text`.
pub fn sha256_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

/// `common.atomic_write_text`: write via a sibling temp file, fsync, then
/// rename over the destination.
pub fn atomic_write_text(path: &Path, text: &str) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("out");
    let tmp_path = parent.join(format!(".{file_name}.{}.tmp", std::process::id()));
    {
        let mut f = fs::File::create(&tmp_path)?;
        f.write_all(text.as_bytes())?;
        f.flush()?;
        f.sync_all()?;
    }
    fs::rename(&tmp_path, path)?;
    Ok(())
}

/// `common.atomic_write_json`: pretty-printed (2-space indent) JSON,
/// trailing newline. Caller supplies an already-serializable value.
pub fn atomic_write_json(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let text = serde_json::to_string_pretty(value).unwrap_or_default() + "\n";
    atomic_write_text(path, &text)
}

/// `common.append_jsonl`: append one compact JSON line, fsync'd.
pub fn append_jsonl(path: &Path, value: &serde_json::Value) -> std::io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let line = serde_json::to_string(value).unwrap_or_default() + "\n";
    let mut f = fs::OpenOptions::new().create(true).append(true).open(path)?;
    f.write_all(line.as_bytes())?;
    f.flush()?;
    f.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_text_matches_known_vectors() {
        // Fixed, well-known SHA-256 test vectors; independent of the Python impl.
        assert_eq!(
            sha256_text(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_text("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn atomic_write_text_then_read_round_trips() {
        let dir = std::env::temp_dir().join(format!("legion-research-port-test-{}", std::process::id()));
        let path = dir.join("out.txt");
        atomic_write_text(&path, "hello\n").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello\n");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn append_jsonl_appends_lines() {
        let dir = std::env::temp_dir().join(format!("legion-research-port-test-jsonl-{}", std::process::id()));
        let path = dir.join("events.jsonl");
        let _ = fs::remove_dir_all(&dir);
        append_jsonl(&path, &serde_json::json!({"a": 1})).unwrap();
        append_jsonl(&path, &serde_json::json!({"b": 2})).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn utc_now_has_expected_shape() {
        let s = utc_now();
        assert_eq!(s.len(), 20);
        assert!(s.ends_with('Z'));
    }
}
