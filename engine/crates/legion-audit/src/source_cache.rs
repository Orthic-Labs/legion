//! Content-addressed Audit source storage. Durable run history is deliberately outside this cache.
//!
//! Worktree cleanliness is not inferred here: callers must hash dirty, racy, filtered,
//! assume-unchanged & skip-worktree bytes before using `verified_source`.
use rightkit_cache::{Config, DiskCache, Key, PutOutcome};
use rightkit_fs::state::StateDir;
use rightkit_fs::{FileLock, LockOptions};
use serde::{Deserialize, Serialize};
use sha1::Digest as Sha1Digest;
use sha2::Sha256;
use std::collections::{BTreeMap, HashSet};
use std::io;
use std::path::{Component, Path, PathBuf};

pub const CACHE_SCHEMA: &str = "legion-audit-source/1";
pub const DEFAULT_MAX_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Preserve descriptor-relative children on Unix; Windows path consumers require RightKit's
/// identity-checked reopen without the child-creation handle's DELETE cleanup access.
/// Callers supply a single known child name.
pub(crate) fn cache_child(parent: &StateDir, name: &str) -> rightkit_fs::Result<StateDir> {
    #[cfg(windows)]
    {
        StateDir::create(&parent.path().join(name))
    }
    #[cfg(not(windows))]
    {
        parent.child(name)
    }
}

/// Reuse Legion's platform state owner, in a separate namespace beside repository receipts.
/// Resolving storage must not create anything beneath an audited worktree, including through
/// an existing symlink or an override containing parent traversal.
pub fn audit_cache_root(repository: &Path) -> io::Result<PathBuf> {
    let repository = repository.canonicalize()?;
    let override_root = std::env::var_os(rightkit_evidence_contracts::state_root::state_root_env())
        .filter(|value| !value.is_empty());
    if let Some(root) = &override_root {
        // The receipts owner appends a child. On Windows a verbatim prefix makes that
        // operation normalize away `..`, so reject lexical traversal before delegation.
        validate_state_root(Path::new(root))?;
    }
    let receipts = rightkit_evidence_contracts::state_root::receipts_root_for_cwd(&repository)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "Legion user state root unavailable",
            )
        })?;
    let overridden = override_root.is_some();
    audit_cache_root_in(
        &repository,
        state_root_from_receipts(&receipts, overridden)?,
    )
}

fn state_root_from_receipts(receipts: &Path, overridden: bool) -> io::Result<&Path> {
    // Canonical owner layouts: override/state/receipts; default/state/receipts/<repo key>.
    let parent = receipts.parent().and_then(|parent| {
        if overridden {
            Some(parent)
        } else {
            parent.parent()
        }
    });
    parent.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "Legion receipts state parent unavailable",
        )
    })
}

fn validate_state_root(state_root: &Path) -> io::Result<()> {
    if !state_root.is_absolute()
        || state_root
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Legion state root must be absolute without parent traversal",
        ));
    }
    Ok(())
}

fn audit_cache_root_in(repository: &Path, state_root: &Path) -> io::Result<PathBuf> {
    validate_state_root(state_root)?;
    let root = state_root
        .join("audit-cache")
        .join(bytes_digest(repository.to_string_lossy().as_bytes()));
    // The leaf normally does not exist. Resolve its nearest existing ancestor to detect an
    // override alias into the repository without creating that leaf as a side effect.
    // The resolved form is returned: a configured root under a platform alias
    // (macOS `/tmp`, `/var`) must not trip the link-refusing state directories.
    let mut ancestor = root.as_path();
    let mut suffix = Vec::new();
    loop {
        match ancestor.canonicalize() {
            Ok(mut resolved) => {
                for name in suffix.iter().rev() {
                    resolved.push(name);
                }
                if resolved.starts_with(repository) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Audit cache root must be outside audited repository",
                    ));
                }
                // Windows keeps drive spelling; its pinned state dirs resolve
                // verbatim paths themselves (`snapshot::directory_location`).
                return Ok(if cfg!(windows) {
                    root.clone()
                } else {
                    resolved
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                suffix.push(
                    ancestor
                        .file_name()
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::InvalidInput,
                                "Legion state ancestor unavailable",
                            )
                        })?
                        .to_os_string(),
                );
                ancestor = ancestor.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Legion state ancestor unavailable",
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }
}

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
    /// Optional cache initialization failed; source reads & identity validation continue uncached.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
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
    _root: Option<StateDir>,
    _objects: Option<StateDir>,
    pins: HashSet<String>,
    pinned_keys: Vec<Key>,
    pub stats: SourceCacheStats,
}
impl SourceCache {
    pub fn open(root: impl AsRef<Path>, max_bytes: u64) -> io::Result<Self> {
        match Self::open_available(root.as_ref(), max_bytes) {
            Ok(cache) => Ok(cache),
            // Storage is optional. Never retry an unsafe/unavailable directory through a weaker
            // path API; skip all cache reads/writes while preserving source identity checks.
            Err(error) => Ok(Self {
                cache: None,
                lease: None,
                _root: None,
                _objects: None,
                pins: HashSet::new(),
                pinned_keys: Vec::new(),
                stats: SourceCacheStats {
                    mode: "disabled-unavailable".into(),
                    unavailable_reason: Some(error.to_string()),
                    max_bytes,
                    ..Default::default()
                },
            }),
        }
    }

    fn open_available(root: &Path, max_bytes: u64) -> io::Result<Self> {
        let pinned_root = StateDir::create(root).map_err(io::Error::other)?;
        let (cache, lease, objects, mode) = match FileLock::acquire(
            &root.join("LOCK"),
            &LockOptions::default().labeled("legion-audit-source-cache"),
        ) {
            Ok(lock) => {
                // StateDir::child retains Windows creation cleanup rights (DELETE). A
                // path-based owner-only cache must reopen this parent without those rights.
                // StateDir::create performs that reopen with its own no-reparse identity check.
                let objects = cache_child(&pinned_root, "objects").map_err(io::Error::other)?;
                let cache = DiskCache::open(
                    objects.path(),
                    Config::new(max_bytes)
                        .owner_only()
                        .max_entry_bytes(max_bytes),
                )?;
                (Some(cache), Some(lock), Some(objects), "writable")
            }
            Err(rightkit_fs::FsError::Locked { .. } | rightkit_fs::FsError::LockTimeout { .. }) => {
                let objects = match StateDir::open(&root.join("objects")) {
                    Ok(objects) => Some(objects),
                    Err(error) if error.is_not_found() => None,
                    Err(error) => return Err(io::Error::other(error)),
                };
                let reader = match DiskCache::open_read_only(root.join("objects")) {
                    Ok(reader) => Some(reader),
                    Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error),
                };
                (reader, None, objects, "read-only-contention")
            }
            Err(error) => return Err(io::Error::other(error)),
        };
        let mut result = Self {
            cache,
            lease,
            _root: Some(pinned_root),
            _objects: objects,
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
