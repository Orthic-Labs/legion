//! Shared deterministic helpers reimplemented for wf028, mirroring
//! `src/lib/research-core/common.py` (`utc_now`, `today`, `sha256_text`,
//! `read_json`, `atomic_write_text`/`atomic_write_json`, `append_jsonl`,
//! `file_lock`). `common.py` is not one of this packet's owned files, so
//! this module is a self-contained reimplementation of the exact behaviour
//! `receipt.py` (via `manifest.finalize`) and `resource_guard.py` (via
//! `manifest.load_run`) exercise, against the identical on-disk shapes.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct IoError(pub String);
impl fmt::Display for IoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for IoError {}

pub fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// Days since the Unix epoch to a proleptic-Gregorian (year, month, day)
/// civil date. Howard Hinnant's public-domain `civil_from_days` algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn now_duration() -> Duration {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
}

/// Port of `common.today()`: `YYYY-MM-DD` in local system clock terms.
/// `common.py` uses `datetime.date.today()` (naive/local); this port uses
/// the same UTC-vs-local distinction is not observable in the Python
/// original's use sites (all downstream comparisons are same-process), so
/// UTC is used here for determinism.
pub fn today() -> String {
    let secs = now_duration().as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Port of `common.utc_now()`: second-precision ISO 8601 with a literal `Z`.
pub fn utc_now() -> String {
    let dur = now_duration();
    let secs = dur.as_secs() as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

pub fn read_json(path: &Path) -> Result<Value, IoError> {
    let text = fs::read_to_string(path).map_err(|e| IoError(format!("cannot read {}: {e}", path.display())))?;
    serde_json::from_str(&text).map_err(|e| IoError(format!("invalid JSON in {}: {e}", path.display())))
}

/// Port of `common.atomic_write_text`/`atomic_write_json`: write to a sibling
/// temp file, fsync, then rename over the destination.
pub fn atomic_write_json(path: &Path, value: &Value) -> Result<(), IoError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| IoError(e.to_string()))?;
    }
    let text = serde_json::to_string_pretty(value).map_err(|e| IoError(e.to_string()))? + "\n";
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension().and_then(|e| e.to_str()).unwrap_or("json")
    ));
    let mut file = fs::File::create(&tmp).map_err(|e| IoError(e.to_string()))?;
    file.write_all(text.as_bytes()).map_err(|e| IoError(e.to_string()))?;
    file.sync_all().map_err(|e| IoError(e.to_string()))?;
    fs::rename(&tmp, path).map_err(|e| IoError(e.to_string()))?;
    Ok(())
}

/// Port of `common.append_jsonl`.
pub fn append_jsonl(path: &Path, value: &Value) -> Result<(), IoError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| IoError(e.to_string()))?;
    }
    let line = serde_json::to_string(value).map_err(|e| IoError(e.to_string()))? + "\n";
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| IoError(e.to_string()))?;
    file.write_all(line.as_bytes()).map_err(|e| IoError(e.to_string()))?;
    file.sync_all().map_err(|e| IoError(e.to_string()))?;
    Ok(())
}

/// Port of `common.file_lock`: an atomic-create lock file, stale locks older
/// than 300s reclaimed, polling every 50ms up to `timeout_s`.
pub struct FileLock {
    path: PathBuf,
}

impl FileLock {
    pub fn acquire(target: &Path, timeout_s: Duration) -> Result<Self, IoError> {
        let lock_path = {
            let mut s = target.as_os_str().to_owned();
            s.push(".lock");
            PathBuf::from(s)
        };
        let deadline = SystemTime::now() + timeout_s;
        loop {
            match fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&lock_path)
            {
                Ok(mut f) => {
                    let _ = write!(f, "{} {}\n", std::process::id(), utc_now());
                    return Ok(FileLock { path: lock_path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    if let Ok(meta) = fs::metadata(&lock_path) {
                        if let Ok(modified) = meta.modified() {
                            if let Ok(age) = SystemTime::now().duration_since(modified) {
                                if age > Duration::from_secs(300) {
                                    let _ = fs::remove_file(&lock_path);
                                    continue;
                                }
                            }
                        }
                    }
                    if SystemTime::now() >= deadline {
                        return Err(IoError(format!("timed out acquiring lock: {}", lock_path.display())));
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(IoError(e.to_string())),
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}
