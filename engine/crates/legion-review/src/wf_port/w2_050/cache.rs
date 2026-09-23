//! Port of `src/lib/review/cache.py`.
//!
//! Content-hash cache for juror responses. Hash includes: rubric content +
//! normalized input + model + provider + prompt_version. Failed responses are
//! stored under `.errors/` so retries don't poison the cache.

use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Content-hash cache for juror responses, mirroring the Python `Cache` class.
#[derive(Debug, Clone)]
pub struct Cache {
    dir: PathBuf,
    errors_dir: PathBuf,
}

impl Cache {
    /// Create (or reuse) a cache rooted at `cache_dir`, ensuring both the
    /// cache directory and its `.errors/` subdirectory exist.
    pub fn new(cache_dir: impl AsRef<Path>) -> io::Result<Self> {
        let dir = cache_dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        let errors_dir = dir.join(".errors");
        fs::create_dir_all(&errors_dir)?;
        Ok(Self { dir, errors_dir })
    }

    /// Directory the cache is rooted at.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `.errors/` subdirectory used for failed-response storage.
    pub fn errors_dir(&self) -> &Path {
        &self.errors_dir
    }

    /// Compute the 32-hex-character cache key for a juror invocation.
    ///
    /// Matches the Python implementation exactly: SHA-256 over
    /// `rubric \0 user_input.strip() \0 provider \0 model \0 prompt_version`,
    /// truncated to the first 32 hex characters of the digest.
    pub fn make_key(
        rubric: &str,
        user_input: &str,
        provider: &str,
        model: &str,
        prompt_version: i64,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(rubric.as_bytes());
        hasher.update([0u8]);
        hasher.update(user_input.trim().as_bytes());
        hasher.update([0u8]);
        hasher.update(provider.as_bytes());
        hasher.update([0u8]);
        hasher.update(model.as_bytes());
        hasher.update([0u8]);
        hasher.update(prompt_version.to_string().as_bytes());
        let digest = hasher.finalize();
        let hex = hex::encode(digest);
        hex[..32].to_string()
    }

    fn entry_path(&self, key: &str) -> PathBuf {
        self.dir.join(format!("{key}.json"))
    }

    fn error_path(&self, key: &str) -> PathBuf {
        self.errors_dir.join(format!("{key}.json"))
    }

    /// Look up a cached value. Matches the Python `get`: any read or parse
    /// failure is treated as a cache miss (`None`), never an error.
    pub fn get(&self, key: &str) -> Option<serde_json::Value> {
        let path = self.entry_path(key);
        let raw = fs::read_to_string(path).ok()?;
        serde_json::from_str(&raw).ok()
    }

    /// Store a value under `key`, pretty-printed like `json.dumps(..., indent=2)`.
    pub fn set(&self, key: &str, value: &serde_json::Value) -> io::Result<()> {
        let path = self.entry_path(key);
        let serialized = serde_json::to_string_pretty(value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, serialized)
    }

    /// Store a failed-response value under `.errors/<key>.json`.
    pub fn set_error(&self, key: &str, value: &serde_json::Value) -> io::Result<()> {
        let path = self.error_path(key);
        let serialized = serde_json::to_string_pretty(value)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(path, serialized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tmp_dir(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "legion-review-wf_w2_050-cache-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        p
    }

    #[test]
    fn make_key_is_deterministic_and_32_hex_chars() {
        let k1 = Cache::make_key("rubric", "input", "openai", "gpt-5", 3);
        let k2 = Cache::make_key("rubric", "input", "openai", "gpt-5", 3);
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), 32);
        assert!(k1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn make_key_strips_user_input_whitespace() {
        let k1 = Cache::make_key("r", "  hello  ", "p", "m", 1);
        let k2 = Cache::make_key("r", "hello", "p", "m", 1);
        assert_eq!(k1, k2);
    }

    #[test]
    fn make_key_changes_with_any_field() {
        let base = Cache::make_key("r", "i", "p", "m", 1);
        assert_ne!(base, Cache::make_key("r2", "i", "p", "m", 1));
        assert_ne!(base, Cache::make_key("r", "i2", "p", "m", 1));
        assert_ne!(base, Cache::make_key("r", "i", "p2", "m", 1));
        assert_ne!(base, Cache::make_key("r", "i", "p", "m2", 1));
        assert_ne!(base, Cache::make_key("r", "i", "p", "m", 2));
    }

    #[test]
    fn set_then_get_round_trips() {
        let dir = tmp_dir("roundtrip");
        let cache = Cache::new(&dir).unwrap();
        let key = Cache::make_key("r", "i", "p", "m", 1);
        let value = json!({"verdict": "pass", "score": 9});
        cache.set(&key, &value).unwrap();
        let got = cache.get(&key).unwrap();
        assert_eq!(got, value);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn get_missing_key_is_none() {
        let dir = tmp_dir("missing");
        let cache = Cache::new(&dir).unwrap();
        assert!(cache.get("does-not-exist").is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn set_error_writes_under_errors_subdir() {
        let dir = tmp_dir("errors");
        let cache = Cache::new(&dir).unwrap();
        let key = "deadbeef";
        cache
            .set_error(key, &json!({"error": "timeout"}))
            .unwrap();
        let path = cache.errors_dir().join(format!("{key}.json"));
        assert!(path.is_file());
        // Errors never poison the regular cache lookup.
        assert!(cache.get(key).is_none());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn new_creates_dir_and_errors_subdir() {
        let dir = tmp_dir("mkdir");
        assert!(!dir.exists());
        let cache = Cache::new(&dir).unwrap();
        assert!(cache.dir().is_dir());
        assert!(cache.errors_dir().is_dir());
        fs::remove_dir_all(&dir).ok();
    }
}
