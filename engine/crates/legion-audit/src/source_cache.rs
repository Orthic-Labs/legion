//! Content-addressed Audit source storage. Durable run history is deliberately outside this cache.
//!
//! Worktree cleanliness is not inferred here: callers must hash dirty, racy, filtered,
//! assume-unchanged & skip-worktree bytes before using `verified_source`.
use rightkit_cache::{Config, DiskCache, Key, PutOutcome};
use rightkit_fs::state::StateDir;
use rightkit_fs::{FileLock, LockOptions};
use serde::{Deserialize, Serialize};
use sha1::Digest as Sha1Digest;
use sha2::{Digest as Sha2Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::Path;

pub const CACHE_SCHEMA: &str = "legion-audit-source/1";
pub const DEFAULT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub fn bytes_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Every semantic dependency must be supplied explicitly. Empty optional identities mean absent,
/// never "use whatever is current". Ordered maps make serialization canonical.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FactIdentity {
    pub source_digest: String,
    pub tree_digest: String,
    pub dirty_digest: String,
    pub extractor_id: String,
    pub extractor_version: String,
    pub schema_version: String,
    pub config_digest: String,
    pub resolver_digest: String,
    pub prompt_digest: String,
    pub tool_digest: String,
    pub redaction_version: String,
    pub advisory_db_digest: String,
    pub extra: BTreeMap<String, String>,
}
impl FactIdentity {
    pub fn digest(&self) -> io::Result<String> {
        if self.source_digest.is_empty()
            || self.extractor_id.is_empty()
            || self.extractor_version.is_empty()
            || self.schema_version.is_empty()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "incomplete cache identity",
            ));
        }
        Ok(bytes_digest(
            &serde_json::to_vec(self).map_err(io::Error::other)?,
        ))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SourceCacheStats {
    pub mode: String,
    pub immutable_blob_hits: u64,
    pub misses: u64,
    /// Bytes revalidated by caller, even when corresponding content object already exists.
    pub verified_bytes: u64,
    pub content_hits: u64,
    pub fact_hits: u64,
    pub rejected_entries: u64,
    pub skipped_writes: u64,
    pub max_bytes: u64,
    pub storage_bytes: u64,
    pub storage_entries: u64,
    pub evictions: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    schema: String,
    identity: String,
    content_digest: String,
    bytes: Vec<u8>,
}

/// A single writer lease covers RightKit's in-memory directory index. OS releases lease on exit;
/// an abandoned LOCK file cannot permanently block later writers. Object storage stays separate
/// from LOCK and durable `.audit/state` history. Live objects are pinned until this handle drops.
pub struct SourceCache {
    cache: Option<DiskCache>,
    lease: Option<FileLock>,
    _root: StateDir,
    pins: HashSet<String>,
    pinned_keys: Vec<Key>,
    pub stats: SourceCacheStats,
}
impl SourceCache {
    pub fn open(root: impl AsRef<Path>, max_bytes: u64) -> io::Result<Self> {
        let root = root.as_ref();
        let pinned_root = StateDir::create(root).map_err(io::Error::other)?;
        let (cache, lease, mode) = match FileLock::acquire(
            &root.join("LOCK"),
            &LockOptions::default().labeled("legion-audit-source-cache"),
        ) {
            Ok(lock) => {
                let objects = pinned_root.child("objects").map_err(io::Error::other)?;
                (
                    Some(DiskCache::open(
                        objects.path(),
                        Config::new(max_bytes)
                            .owner_only()
                            .max_entry_bytes(max_bytes),
                    )?),
                    Some(lock),
                    "writable",
                )
            }
            Err(rightkit_fs::FsError::Locked { .. } | rightkit_fs::FsError::LockTimeout { .. }) => {
                if root.join("objects").exists() {
                    StateDir::open(&root.join("objects")).map_err(io::Error::other)?;
                }
                let reader = match DiskCache::open_read_only(root.join("objects")) {
                    Ok(reader) => Some(reader),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error),
                };
                (reader, None, "read-only-contention")
            }
            Err(error) => return Err(io::Error::other(error)),
        };
        let mut result = Self {
            cache,
            lease,
            _root: pinned_root,
            pins: HashSet::new(),
            pinned_keys: Vec::new(),
            stats: SourceCacheStats {
                mode: mode.into(),
                max_bytes,
                ..Default::default()
            },
        };
        result.refresh_metrics();
        Ok(result)
    }

    fn refresh_metrics(&mut self) {
        if let Some(cache) = &self.cache {
            let current = cache.stats();
            self.stats.storage_bytes = current.bytes;
            self.stats.storage_entries = current.entries as u64;
            self.stats.evictions = current.evictions;
        }
    }
    fn key(kind: &str, identity: &str) -> Key {
        Key::new(&[CACHE_SCHEMA, kind, identity])
    }
    fn pin(&mut self, key: &Key) {
        if self.lease.is_some() && !self.pins.contains(key.hash()) {
            if let Some(cache) = &self.cache {
                if cache.pin(key).unwrap_or(false) {
                    self.pins.insert(key.hash().to_owned());
                    self.pinned_keys.push(key.clone());
                }
            }
        }
    }
    fn read(&mut self, kind: &str, identity: &str) -> Option<Vec<u8>> {
        let key = Self::key(kind, identity);
        let raw = self.cache.as_ref()?.get(&key)?;
        let entry: Envelope = match serde_json::from_slice(&raw) {
            Ok(entry) => entry,
            Err(_) => {
                self.stats.rejected_entries += 1;
                return None;
            }
        };
        if entry.schema != CACHE_SCHEMA
            || entry.identity != identity
            || entry.content_digest != bytes_digest(&entry.bytes)
        {
            self.stats.rejected_entries += 1;
            return None;
        }
        self.pin(&key);
        self.refresh_metrics();
        Some(entry.bytes)
    }
    fn store(&mut self, kind: &str, identity: &str, bytes: &[u8]) -> io::Result<()> {
        let key = Self::key(kind, identity);
        let Some(cache) = &self.cache else {
            self.stats.skipped_writes += 1;
            return Ok(());
        };
        if self.lease.is_none() {
            self.stats.skipped_writes += 1;
            return Ok(());
        }
        let entry = Envelope {
            schema: CACHE_SCHEMA.into(),
            identity: identity.into(),
            content_digest: bytes_digest(bytes),
            bytes: bytes.to_vec(),
        };
        match cache.put_pinned(&key, &serde_json::to_vec(&entry).map_err(io::Error::other)?) {
            Ok(PutOutcome::Stored) => {
                if self.pins.insert(key.hash().to_owned()) {
                    self.pinned_keys.push(key);
                }
            }
            // Cache pressure must not change source availability or snapshot identity.
            Ok(PutOutcome::TooLarge) | Err(_) => self.stats.skipped_writes += 1,
        }
        self.refresh_metrics();
        Ok(())
    }

    /// Immutable *raw Git blob* only. Do not pass a worktree path or transformed/smudged bytes.
    /// The object format/repository identity is part of `git_identity` (e.g. `sha1:<OID>`).
    pub fn immutable_blob(
        &mut self,
        git_identity: &str,
        load: impl FnOnce() -> io::Result<Vec<u8>>,
    ) -> io::Result<Vec<u8>> {
        if !valid_git_identity(git_identity) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected immutable Git object identity",
            ));
        }
        if let Some(bytes) = self.read("git-blob", git_identity) {
            if matches_git_blob(git_identity, &bytes) {
                self.stats.immutable_blob_hits += 1;
                return Ok(bytes);
            }
            self.stats.rejected_entries += 1;
        }
        self.stats.misses += 1;
        let bytes = load()?;
        if !matches_git_blob(git_identity, &bytes) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Git blob bytes do not match object identity",
            ));
        }
        self.store("git-blob", git_identity, &bytes)?;
        Ok(bytes)
    }
    /// Caller has read/hash-verified exact worktree bytes this run. This records reusable content,
    /// but never claims avoiding that verification read.
    pub fn verified_source(&mut self, bytes: &[u8]) -> io::Result<Vec<u8>> {
        self.stats.verified_bytes += bytes.len() as u64;
        let identity = bytes_digest(bytes);
        if let Some(cached) = self.read("source", &identity) {
            if cached == bytes {
                self.stats.content_hits += 1;
                return Ok(cached);
            }
            self.stats.rejected_entries += 1;
        }
        self.stats.misses += 1;
        self.store("source", &identity, bytes)?;
        Ok(bytes.to_vec())
    }
    /// Only deterministic source facts. This deliberately offers no provider/model result cache.
    pub fn fact(
        &mut self,
        identity: &FactIdentity,
        extract: impl FnOnce() -> io::Result<Vec<u8>>,
    ) -> io::Result<Vec<u8>> {
        let identity = identity.digest()?;
        if let Some(bytes) = self.read("fact", &identity) {
            self.stats.fact_hits += 1;
            return Ok(bytes);
        }
        self.stats.misses += 1;
        let bytes = extract()?;
        self.store("fact", &identity, &bytes)?;
        Ok(bytes)
    }
    /// Redacted excerpts require explicit redaction & selected-region identities.
    pub fn redacted_excerpt(
        &mut self,
        identity: &FactIdentity,
        extract_and_redact: impl FnOnce() -> io::Result<Vec<u8>>,
    ) -> io::Result<Vec<u8>> {
        if identity.redaction_version.is_empty() || !identity.extra.contains_key("regionsDigest") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "excerpt lacks redaction/region identity",
            ));
        }
        self.fact(identity, extract_and_redact)
    }
}
impl Drop for SourceCache {
    fn drop(&mut self) {
        if let Some(cache) = &self.cache {
            for key in &self.pinned_keys {
                let _ = cache.unpin(key);
            }
        }
        // Keep lease alive until all RightKit operations, including unpin, have finished.
        self.cache.take();
        self.lease.take();
    }
}
fn git_blob_digest(format: &str, bytes: &[u8]) -> String {
    let header = format!("blob {}\0", bytes.len());
    if format == "sha1" {
        let mut digest = sha1::Sha1::new();
        digest.update(header.as_bytes());
        digest.update(bytes);
        hex::encode(digest.finalize())
    } else {
        let mut digest = Sha256::new();
        digest.update(header.as_bytes());
        digest.update(bytes);
        hex::encode(digest.finalize())
    }
}
fn matches_git_blob(identity: &str, bytes: &[u8]) -> bool {
    identity
        .split_once(':')
        .is_some_and(|(format, oid)| git_blob_digest(format, bytes).eq_ignore_ascii_case(oid))
}
fn valid_git_identity(identity: &str) -> bool {
    let Some((format, oid)) = identity.split_once(':') else {
        return false;
    };
    let length = match format {
        "sha1" => 40,
        "sha256" => 64,
        _ => return false,
    };
    oid.len() == length && oid.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Temp(std::path::PathBuf);
    impl Temp {
        fn new() -> Self {
            let root = std::env::var_os("LEGION_TEST_TMP")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::env::temp_dir().canonicalize().expect("test temp root"))
                .join(format!(
                    "legion-source-cache-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            Self(root)
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn identity() -> FactIdentity {
        FactIdentity {
            source_digest: bytes_digest(b"source"),
            extractor_id: "lexical".into(),
            extractor_version: "1".into(),
            schema_version: "1".into(),
            config_digest: "none".into(),
            resolver_digest: "none".into(),
            redaction_version: "r1".into(),
            ..Default::default()
        }
    }
    #[test]
    fn warm_blob_avoids_loader_and_dirty_bytes_still_verified() {
        let temp = Temp::new();
        let oid = format!("sha1:{}", git_blob_digest("sha1", b"source"));
        let first = {
            let mut cache = SourceCache::open(&temp.0, 1024 * 1024).unwrap();
            cache
                .immutable_blob(&oid, || Ok(b"source".to_vec()))
                .unwrap()
        };
        let mut warm = SourceCache::open(&temp.0, 1024 * 1024).unwrap();
        let second = warm
            .immutable_blob(&oid, || panic!("warm raw blob re-read"))
            .unwrap();
        assert_eq!(first, second);
        assert_eq!(warm.stats.immutable_blob_hits, 1);
        assert_eq!(warm.verified_source(b"dirty").unwrap(), b"dirty");
        assert_eq!(warm.verified_source(b"dirty").unwrap(), b"dirty");
        assert_eq!(warm.stats.verified_bytes, 10);
        assert_eq!(warm.stats.content_hits, 1);
        assert_eq!(warm.verified_source(b"moved").unwrap(), b"moved");
    }
    #[test]
    fn poisoned_or_corrupt_entry_is_miss_and_loader_must_match_oid() {
        let temp = Temp::new();
        let mut cache = SourceCache::open(&temp.0, 1024 * 1024).unwrap();
        let oid = format!("sha1:{}", git_blob_digest("sha1", b"trusted"));
        let poisoned = Envelope {
            schema: CACHE_SCHEMA.into(),
            identity: oid.clone(),
            content_digest: bytes_digest(b"poison"),
            bytes: b"poison".to_vec(),
        };
        cache
            .cache
            .as_ref()
            .unwrap()
            .put(
                &SourceCache::key("git-blob", &oid),
                &serde_json::to_vec(&poisoned).unwrap(),
            )
            .unwrap();
        assert_eq!(
            cache
                .immutable_blob(&oid, || Ok(b"trusted".to_vec()))
                .unwrap(),
            b"trusted"
        );
        assert_eq!(cache.stats.rejected_entries, 1);
        assert_eq!(cache.stats.immutable_blob_hits, 0);
        let other = format!("sha256:{}", git_blob_digest("sha256", b"another"));
        assert!(cache
            .immutable_blob(&other, || Ok(b"wrong".to_vec()))
            .is_err());
        cache
            .cache
            .as_ref()
            .unwrap()
            .put(&SourceCache::key("git-blob", &other), b"broken-json")
            .unwrap();
        assert_eq!(
            cache
                .immutable_blob(&other, || Ok(b"another".to_vec()))
                .unwrap(),
            b"another"
        );
        assert_eq!(cache.stats.rejected_entries, 2);
    }
    #[test]
    fn every_semantic_dependency_invalidates_fact_key() {
        let baseline = identity();
        let original = baseline.digest().unwrap();
        let value = serde_json::to_value(&baseline).unwrap();
        for field in [
            "sourceDigest",
            "treeDigest",
            "dirtyDigest",
            "extractorId",
            "extractorVersion",
            "schemaVersion",
            "configDigest",
            "resolverDigest",
            "promptDigest",
            "toolDigest",
            "redactionVersion",
            "advisoryDbDigest",
        ] {
            let mut changed = value.clone();
            changed[field] = serde_json::json!("changed");
            let changed: FactIdentity = serde_json::from_value(changed).unwrap();
            assert_ne!(original, changed.digest().unwrap(), "{field}");
        }
    }
    #[test]
    fn stale_lock_file_recovers_and_live_writer_gets_read_only_fallback() {
        let temp = Temp::new();
        let writer = SourceCache::open(&temp.0, 1024 * 1024).unwrap();
        let mut reader = SourceCache::open(&temp.0, 1024 * 1024).unwrap();
        assert_eq!(reader.stats.mode, "read-only-contention");
        assert_eq!(
            reader.verified_source(b"memory-only").unwrap(),
            b"memory-only"
        );
        assert_eq!(reader.stats.skipped_writes, 1);
        drop(reader);
        drop(writer);
        assert!(temp.0.join("LOCK").is_file());
        let recovered = SourceCache::open(&temp.0, 1024 * 1024).unwrap();
        assert_eq!(recovered.stats.mode, "writable");
    }
    #[test]
    fn pin_pressure_keeps_live_objects_and_cache_miss_still_returns_source() {
        let temp = Temp::new();
        let mut cache = SourceCache::open(&temp.0, 500).unwrap();
        let first = cache.verified_source(&vec![1; 100]).unwrap();
        let second = cache.verified_source(&vec![2; 100]).unwrap();
        assert_eq!(first, vec![1; 100]);
        assert_eq!(second, vec![2; 100]);
        assert!(cache.stats.skipped_writes > 0);
        assert_eq!(cache.verified_source(&first).unwrap(), first);
        assert!(cache.stats.content_hits > 0);
    }
    #[test]
    fn excerpts_refuse_incomplete_identity_and_cache_never_touches_history() {
        let temp = Temp::new();
        let mut cache = SourceCache::open(&temp.0, 1024 * 1024).unwrap();
        assert!(cache
            .redacted_excerpt(&identity(), || Ok(b"redacted".to_vec()))
            .is_err());
        let mut complete = identity();
        complete
            .extra
            .insert("regionsDigest".into(), "lines1-2".into());
        assert_eq!(
            cache
                .redacted_excerpt(&complete, || Ok(b"redacted".to_vec()))
                .unwrap(),
            b"redacted"
        );
        assert!(!temp.0.join("state").exists());
    }
}
