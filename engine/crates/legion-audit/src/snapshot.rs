//! Immutable cold snapshots & durable completed-run history. Cache policy belongs
//! to RightKit; this module defines Audit content & identity contracts.
use crate::source_cache::{SourceCache, SourceCacheStats, DEFAULT_MAX_BYTES};
use crate::{
    scope::{self, GitRunner, ResolvedScope},
    AuditError,
};
use rightkit_fs::state::StateDir;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
const MAX_FILE_BYTES: usize = 32 * 1024 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 512 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
fn invalid(message: impl Into<String>) -> AuditError {
    AuditError::Invalid(message.into())
}
fn io(error: impl std::fmt::Display) -> AuditError {
    invalid(error.to_string())
}
fn hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotChange {
    pub path: String,
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotSide {
    Selected,
    Base,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotFile {
    pub digest: String,
    pub bytes: usize,
    pub mode: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SnapshotManifest {
    pub schema_version: u32,
    pub scope: ResolvedScope,
    pub key: String,
    pub files: BTreeMap<String, SnapshotFile>,
    pub base_files: BTreeMap<String, SnapshotFile>,
    pub execution_root: PathBuf,
    pub baseline_root: PathBuf,
    pub gaps: Vec<String>,
    pub dirty_digest: String,
    #[serde(default)]
    pub source_cache: SourceCacheStats,
    /// User-controlled repository code has no execution authority. Host providers
    /// must present independently verified isolation before project execution.
    pub execution_policy: String,
}
#[derive(Debug, Clone)]
pub struct FrozenSnapshot {
    pub manifest: SnapshotManifest,
    pub manifest_path: PathBuf,
}
/// Retain no-reparse directory pins for the cache lifetime. Windows pins also
/// deny directory replacement; Unix permits rename, so compare device/inode.
struct ReaderBinding {
    _pins: Vec<StateDir>,
    #[cfg(unix)]
    identities: Vec<(u64, u64)>,
    #[cfg(unix)]
    _identity_pins: Vec<std::fs::File>,
}
impl ReaderBinding {
    fn pin(snapshot: &FrozenSnapshot) -> Result<Self, AuditError> {
        let parent = snapshot
            .manifest_path
            .parent()
            .ok_or_else(|| invalid("snapshot parent missing"))?;
        let mut pins = Vec::new();
        #[cfg(unix)]
        let mut identities = Vec::new();
        #[cfg(unix)]
        let mut identity_pins = Vec::new();
        for root in [
            parent,
            snapshot.manifest.execution_root.as_path(),
            snapshot.manifest.baseline_root.as_path(),
        ] {
            pins.push(StateDir::open(root).map_err(io)?);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let file = std::fs::File::open(root).map_err(io)?;
                let pinned = file.metadata().map_err(io)?;
                let metadata = std::fs::symlink_metadata(root).map_err(io)?;
                if !metadata.is_dir()
                    || !pinned.is_dir()
                    || (metadata.dev(), metadata.ino()) != (pinned.dev(), pinned.ino())
                {
                    return Err(invalid("snapshot root identity changed while pinning"));
                }
                identities.push((pinned.dev(), pinned.ino()));
                identity_pins.push(file);
            }
        }
        #[cfg(not(any(unix, windows)))]
        return Err(invalid("snapshot reader root identity unavailable"));
        #[cfg(any(unix, windows))]
        Ok(Self {
            _pins: pins,
            #[cfg(unix)]
            identities,
            #[cfg(unix)]
            _identity_pins: identity_pins,
        })
    }
    fn validate(&self, snapshot: &FrozenSnapshot) -> Result<(), AuditError> {
        let current = Self::pin(snapshot)?;
        #[cfg(unix)]
        if current.identities != self.identities {
            return Err(AuditError::SourceDrift(
                "snapshot root identity changed".into(),
            ));
        }
        let _ = current;
        Ok(())
    }
}
struct VerifiedReader {
    snapshot: std::sync::Arc<FrozenSnapshot>,
    manifest_bytes: Vec<u8>,
    binding: ReaderBinding,
}
#[cfg(test)]
thread_local! {
    static FULL_VERIFICATIONS: std::cell::RefCell<BTreeMap<PathBuf, usize>> =
        std::cell::RefCell::new(BTreeMap::new());
}
#[cfg(test)]
pub(crate) fn full_verification_count(path: &Path) -> usize {
    FULL_VERIFICATIONS.with(|counts| counts.borrow().get(path).copied().unwrap_or(0))
}
/// Windows canonical paths use a verbatim prefix even when the owner state
/// locator used drive syntax. Resolve that spelling through the filesystem only
/// after a no-reparse pin; keep it alive so Windows cannot swap any ancestor.
fn directory_location(path: &Path) -> Result<PathBuf, AuditError> {
    #[cfg(windows)]
    {
        let pinned = StateDir::open(path).map_err(io)?;
        std::fs::canonicalize(pinned.path()).map_err(io)
    }
    #[cfg(not(windows))]
    {
        Ok(path.into())
    }
}
fn read_safe(root: &Path, path: &str, cap: usize) -> Result<Vec<u8>, AuditError> {
    scope::safe_path(path)?;
    let joined = root.join(path);
    let parent = joined
        .parent()
        .ok_or_else(|| invalid("snapshot path has no parent"))?;
    let name = joined
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| invalid("invalid snapshot filename"))?;
    // StateDir pins every directory component & refuses links/reparse points,
    // then opens this child relative to that pinned descriptor.
    StateDir::open(parent)
        .map_err(io)?
        .read(name, cap as u64)
        .map_err(io)
}
fn write_safe(root: &Path, path: &str, bytes: &[u8]) -> Result<(), AuditError> {
    scope::safe_path(path)?;
    let mut dir = StateDir::open(root).map_err(io)?;
    let mut pieces = path.split('/').peekable();
    while let Some(piece) = pieces.next() {
        if pieces.peek().is_some() {
            dir = crate::source_cache::cache_child(&dir, piece).map_err(io)?;
        } else {
            dir.write_new(piece, bytes).map_err(io)?;
        }
    }
    Ok(())
}
fn add_bytes(
    path: &str,
    mode: &str,
    bytes: Vec<u8>,
    map: &mut BTreeMap<String, SnapshotFile>,
    objects: &mut BTreeMap<String, Vec<u8>>,
    total: &mut usize,
    gaps: &mut Vec<String>,
) -> Result<(), AuditError> {
    *total = total
        .checked_add(bytes.len())
        .ok_or_else(|| invalid("snapshot size overflow"))?;
    if *total > MAX_SNAPSHOT_BYTES {
        return Err(invalid("scope materialization exceeds snapshot byte cap"));
    }
    match mode {
        "120000" => {
            gaps.push(format!("scope-symlink-unavailable:{path}"));
            return Ok(());
        }
        "160000" => {
            gaps.push(format!("scope-submodule-unavailable:{path}"));
            return Ok(());
        }
        "100644" | "100755" => {}
        _ => return Err(invalid(format!("unsupported Git file mode {mode}:{path}"))),
    }
    if bytes.starts_with(b"version https://git-lfs.github.com/spec/v1\n") {
        gaps.push(format!("scope-lfs-content-unavailable:{path}"));
    }
    let digest = hash(&bytes);
    map.insert(
        path.into(),
        SnapshotFile {
            digest: digest.clone(),
            bytes: bytes.len(),
            mode: mode.into(),
        },
    );
    objects.insert(digest, bytes);
    Ok(())
}
impl FrozenSnapshot {
    pub fn capture(scope: ResolvedScope) -> Result<Self, AuditError> {
        let git = GitRunner::new(scope.object_root.as_deref().unwrap_or(&scope.source_root));
        let cache_root = crate::source_cache::audit_cache_root(&scope.source_root).map_err(io)?;
        let mut source_cache =
            SourceCache::open(cache_root.join("audit-source"), DEFAULT_MAX_BYTES).map_err(io)?;
        let mut paths: BTreeSet<String> = scope.selected_entries.keys().cloned().collect();
        if scope.head_kind == "worktree" {
            paths.extend(scope::names(&git.run(&[
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
            ])?)?);
        }
        let mut files = BTreeMap::new();
        let mut base_files = BTreeMap::new();
        let mut objects = BTreeMap::new();
        let mut gaps = Vec::new();
        let mut total = 0;
        for path in paths {
            if scope::excluded(&path) {
                continue;
            }
            let entry = scope.selected_entries.get(&path);
            let mode = entry.map(|e| e.mode.as_str()).unwrap_or("100644");
            if mode == "160000" || mode == "120000" {
                gaps.push(format!(
                    "scope-{}-unavailable:{path}",
                    if mode == "160000" {
                        "submodule"
                    } else {
                        "symlink"
                    }
                ));
                continue;
            }
            let bytes = if scope.head_kind == "worktree" {
                let meta = match std::fs::symlink_metadata(scope.source_root.join(&path)) {
                    Ok(meta) => meta,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(io(e)),
                };
                if meta.file_type().is_symlink() {
                    gaps.push(format!("scope-symlink-unavailable:{path}"));
                    continue;
                }
                source_cache
                    .verified_source(&read_safe(&scope.source_root, &path, MAX_FILE_BYTES)?)
                    .map_err(io)?
            } else {
                let entry = entry.ok_or_else(|| invalid("selected Git blob missing"))?;
                source_cache
                    .immutable_blob(
                        &format!(
                            "{}:{}",
                            if entry.oid.len() == 40 {
                                "sha1"
                            } else {
                                "sha256"
                            },
                            entry.oid
                        ),
                        || {
                            git.run(&["cat-file", "blob", &entry.oid])
                                .map_err(std::io::Error::other)
                        },
                    )
                    .map_err(io)?
            };
            if bytes.len() > MAX_FILE_BYTES {
                return Err(invalid(format!("scope file exceeds byte cap:{path}")));
            }
            add_bytes(
                &path,
                mode,
                bytes,
                &mut files,
                &mut objects,
                &mut total,
                &mut gaps,
            )?;
        }
        for (path, entry) in &scope.baseline_entries {
            if entry.mode == "120000" || entry.mode == "160000" {
                gaps.push(format!("scope-base-special-file-unavailable:{path}"));
                continue;
            }
            let bytes = source_cache
                .immutable_blob(
                    &format!(
                        "{}:{}",
                        if entry.oid.len() == 40 {
                            "sha1"
                        } else {
                            "sha256"
                        },
                        entry.oid
                    ),
                    || {
                        git.run(&["cat-file", "blob", &entry.oid])
                            .map_err(std::io::Error::other)
                    },
                )
                .map_err(io)?;
            if bytes.len() > MAX_FILE_BYTES {
                return Err(invalid(format!("scope base file exceeds byte cap:{path}")));
            }
            add_bytes(
                path,
                &entry.mode,
                bytes,
                &mut base_files,
                &mut objects,
                &mut total,
                &mut gaps,
            )?;
        }
        gaps.sort();
        gaps.dedup();
        // Re-read every worktree byte before publication. No mixed generation is
        // accepted if tracked state, untracked membership, index or refs moved.
        let refreshed = ResolvedScope::resolve(
            &scope.source_root,
            scope.spec.clone(),
            scope.path_prefix.clone(),
        )?;
        if crate::digest(&refreshed)? != crate::digest(&scope)? {
            return Err(AuditError::SourceDrift(
                "scope changed during snapshot capture".into(),
            ));
        }
        if scope.head_kind == "worktree" {
            for (path, file) in &files {
                if hash(&read_safe(&scope.source_root, path, MAX_FILE_BYTES)?) != file.digest {
                    return Err(AuditError::SourceDrift(format!(
                        "worktree bytes moved during snapshot capture:{path}"
                    )));
                }
            }
        }
        let dirty_digest = crate::digest(&(&files, &scope.index_digest, &scope.status_digest))?;
        let key = crate::digest(&(
            1u32,
            &scope,
            &files,
            &base_files,
            &dirty_digest,
            &gaps,
            "read-only-no-project-execution",
        ))?;
        let cache = StateDir::create(&cache_root.join("audit-snapshots")).map_err(io)?;
        // Unique immutable run object. No speculative reuse or writable shared
        // cache lease; RightKit cache integration can deduplicate this contract.
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(io)?;
        let object =
            crate::source_cache::cache_child(&cache, &format!("cold-{}", hex::encode(nonce)))
                .map_err(io)?;
        let selected_dir = crate::source_cache::cache_child(&object, "selected").map_err(io)?;
        let base_dir = crate::source_cache::cache_child(&object, "base").map_err(io)?;
        for (path, file) in &files {
            write_safe(selected_dir.path(), path, &objects[&file.digest])?;
        }
        for (path, file) in &base_files {
            write_safe(base_dir.path(), path, &objects[&file.digest])?;
        }
        // Inventory must not discover parent Git state for this independent tree.
        selected_dir
            .write_new(".legion-audit-snapshot", b"1\n")
            .map_err(io)?;
        base_dir
            .write_new(".legion-audit-snapshot", b"1\n")
            .map_err(io)?;
        // A deliberately invalid Git marker prevents Git-based tools walking
        // upward into source refs/index. History tools need an explicit host
        // read capability pinned to scope OIDs instead.
        selected_dir
            .write_new(".git", b"immutable-audit-snapshot\n")
            .map_err(io)?;
        base_dir
            .write_new(".git", b"immutable-audit-snapshot\n")
            .map_err(io)?;
        let manifest = SnapshotManifest {
            schema_version: 1,
            scope,
            key,
            files,
            base_files,
            execution_root: directory_location(selected_dir.path())?,
            baseline_root: directory_location(base_dir.path())?,
            gaps,
            dirty_digest,
            source_cache: source_cache.stats.clone(),
            execution_policy: "read-only-no-project-execution-without-host-isolation".into(),
        };
        object
            .write_new("manifest.json", &serde_json::to_vec(&manifest).map_err(io)?)
            .map_err(io)?;
        let manifest_path = directory_location(object.path())?.join("manifest.json");
        let snapshot = Self {
            manifest,
            manifest_path,
        };
        snapshot.verify()?;
        for root in [
            &snapshot.manifest.execution_root,
            &snapshot.manifest.baseline_root,
        ] {
            for entry in walkdir::WalkDir::new(root)
                .contents_first(true)
                .follow_links(false)
            {
                let entry = entry.map_err(io)?;
                let mut permissions = entry.metadata().map_err(io)?.permissions();
                permissions.set_readonly(true);
                std::fs::set_permissions(entry.path(), permissions).map_err(io)?;
            }
        }
        let mut permissions = std::fs::metadata(&snapshot.manifest_path)
            .map_err(io)?
            .permissions();
        permissions.set_readonly(true);
        std::fs::set_permissions(&snapshot.manifest_path, permissions).map_err(io)?;
        Ok(snapshot)
    }
    /// Reuse cold verification, never source bytes. Each admission rechecks the
    /// exact sealed manifest, markers, roots & inventory; consumed bytes hash.
    pub(crate) fn verified_reader(
        manifest_path: &Path,
    ) -> Result<std::sync::Arc<Self>, AuditError> {
        use std::sync::{Arc, Mutex, OnceLock};
        static PINNED: OnceLock<Mutex<BTreeMap<PathBuf, VerifiedReader>>> = OnceLock::new();
        let cache = PINNED.get_or_init(|| Mutex::new(BTreeMap::new()));
        let mut cache = cache
            .lock()
            .map_err(|_| invalid("snapshot reader lock poisoned"))?;
        let (snapshot, manifest_bytes) = Self::load_manifest(manifest_path)?;
        let locator = snapshot.manifest_path.clone();
        if let Some(reader) = cache.get(&locator) {
            if reader.manifest_bytes != manifest_bytes {
                return Err(AuditError::SourceDrift("snapshot manifest changed".into()));
            }
            reader.binding.validate(&snapshot)?;
            snapshot.verify_structure()?;
            reader.binding.validate(&snapshot)?;
            return Ok(reader.snapshot.clone());
        }
        let binding = ReaderBinding::pin(&snapshot)?;
        snapshot.verify()?;
        binding.validate(&snapshot)?;
        // Do not admit a manifest that changed while cold verification ran.
        if Self::load_manifest(manifest_path)?.1 != manifest_bytes {
            return Err(AuditError::SourceDrift("snapshot manifest changed".into()));
        }
        snapshot.verify_structure()?;
        binding.validate(&snapshot)?;
        let snapshot = Arc::new(snapshot);
        if cache.len() >= 32 {
            if let Some(oldest) = cache.keys().next().cloned() {
                cache.remove(&oldest);
            }
        }
        cache.insert(
            locator,
            VerifiedReader {
                snapshot: snapshot.clone(),
                manifest_bytes,
                binding,
            },
        );
        Ok(snapshot)
    }
    /// Resolve both selected & baseline readers through the same sealed entry.
    pub fn for_execution_root(root: &Path) -> Result<std::sync::Arc<Self>, AuditError> {
        let manifest = root
            .parent()
            .ok_or_else(|| invalid("snapshot root parent missing"))?
            .join("manifest.json");
        let snapshot = Self::verified_reader(&manifest)?;
        let root_location = directory_location(root)?;
        if directory_location(&snapshot.manifest.execution_root)? != root_location
            && directory_location(&snapshot.manifest.baseline_root)? != root_location
        {
            return Err(invalid("execution root is not bound to snapshot"));
        }
        Ok(snapshot)
    }
    pub fn source_for_root(
        root: &Path,
        path: &str,
        max_bytes: usize,
    ) -> Result<(Vec<u8>, SnapshotSide), AuditError> {
        let snapshot = Self::for_execution_root(root)?;
        let side = if directory_location(root)?
            == directory_location(&snapshot.manifest.baseline_root)?
            || !snapshot.manifest.files.contains_key(path)
                && snapshot.manifest.scope.changed_paths.contains(path)
                && snapshot.manifest.base_files.contains_key(path)
        {
            SnapshotSide::Base
        } else {
            SnapshotSide::Selected
        };
        Ok((snapshot.read(path, side, max_bytes)?, side))
    }
    /// Durable derived context kept beside sealed source, never inside its tree.
    pub fn write_context_artifact(&self, name: &str, bytes: &[u8]) -> Result<PathBuf, AuditError> {
        if !matches!(name, "graph-context.json") {
            return Err(invalid("unsupported snapshot context artifact"));
        }
        let parent = self
            .manifest_path
            .parent()
            .ok_or_else(|| invalid("snapshot parent missing"))?;
        let directory = StateDir::open(parent).map_err(io)?;
        if let Some(existing) = directory.read_opt(name, MAX_MANIFEST_BYTES).map_err(io)? {
            if existing != bytes {
                return Err(invalid("snapshot context artifact content changed"));
            }
        } else {
            directory.write_new(name, bytes).map_err(io)?;
        }
        Ok(parent.join(name))
    }
    pub fn open(manifest_path: &Path) -> Result<Self, AuditError> {
        let (snapshot, _) = Self::load_manifest(manifest_path)?;
        snapshot.verify()?;
        Ok(snapshot)
    }
    fn load_manifest(manifest_path: &Path) -> Result<(Self, Vec<u8>), AuditError> {
        let parent = manifest_path
            .parent()
            .ok_or_else(|| invalid("manifest parent missing"))?;
        let name = manifest_path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| invalid("manifest filename invalid"))?;
        let directory = StateDir::open(parent).map_err(io)?;
        let bytes = directory.read(name, MAX_MANIFEST_BYTES).map_err(io)?;
        let manifest: SnapshotManifest = serde_json::from_slice(&bytes).map_err(io)?;
        if manifest.schema_version != 1 || manifest.scope.schema_version != 1 {
            return Err(invalid("unsupported snapshot schema"));
        }
        // Roots are derived, never accepted as arbitrary paths from JSON. The
        // locator pin remains alive while Windows resolves equivalent spellings;
        // each declared root receives its own no-reparse pin before resolution.
        let parent_location = directory_location(directory.path())?;
        if directory_location(&manifest.execution_root)? != parent_location.join("selected")
            || directory_location(&manifest.baseline_root)? != parent_location.join("base")
        {
            return Err(invalid("snapshot roots do not match manifest location"));
        }
        let snapshot = Self {
            manifest,
            manifest_path: parent_location.join(name),
        };
        Ok((snapshot, bytes))
    }
    pub fn verify(&self) -> Result<(), AuditError> {
        #[cfg(test)]
        FULL_VERIFICATIONS.with(|counts| {
            *counts
                .borrow_mut()
                .entry(self.manifest_path.clone())
                .or_default() += 1;
        });
        self.verify_structure()?;
        for (side, files) in [
            (SnapshotSide::Selected, &self.manifest.files),
            (SnapshotSide::Base, &self.manifest.base_files),
        ] {
            for path in files.keys() {
                self.read(path, side, MAX_FILE_BYTES)?;
            }
        }
        Ok(())
    }
    /// Admission checks structure only. It is not fresh cryptographic proof of
    /// unread source; read() always validates bytes before returning them.
    fn verify_structure(&self) -> Result<(), AuditError> {
        let m = &self.manifest;
        let key = crate::digest(&(
            1u32,
            &m.scope,
            &m.files,
            &m.base_files,
            &m.dirty_digest,
            &m.gaps,
            "read-only-no-project-execution",
        ))?;
        if key != m.key {
            return Err(invalid("snapshot identity mismatch"));
        }
        if m.execution_policy != "read-only-no-project-execution-without-host-isolation" {
            return Err(invalid("snapshot execution policy changed"));
        }
        for root in [&m.execution_root, &m.baseline_root] {
            let pinned = StateDir::open(root).map_err(io)?;
            if pinned.read(".git", 128).map_err(io)? != b"immutable-audit-snapshot\n"
                || pinned.read(".legion-audit-snapshot", 16).map_err(io)? != b"1\n"
            {
                return Err(invalid("snapshot Git isolation marker changed"));
            }
        }
        for (side, files) in [
            (SnapshotSide::Selected, &m.files),
            (SnapshotSide::Base, &m.base_files),
        ] {
            let root = match side {
                SnapshotSide::Selected => &m.execution_root,
                SnapshotSide::Base => &m.baseline_root,
            };
            let mut actual = BTreeSet::new();
            let mut directories = BTreeSet::new();
            let expected_directories: BTreeSet<_> = files
                .keys()
                .flat_map(|path| {
                    path.match_indices('/')
                        .map(|(index, _)| path[..index].to_owned())
                })
                .collect();
            for entry in walkdir::WalkDir::new(root).follow_links(false) {
                let entry = entry.map_err(io)?;
                if entry.depth() == 0 {
                    continue;
                }
                if !entry.file_type().is_file() && !entry.file_type().is_dir() {
                    return Err(invalid("snapshot contains non-regular entry"));
                }
                let relative = entry
                    .path()
                    .strip_prefix(root)
                    .map_err(io)?
                    .to_str()
                    .ok_or_else(|| invalid("snapshot path is not UTF-8"))?
                    .replace('\\', "/");
                if entry.file_type().is_dir() {
                    directories.insert(relative);
                    continue;
                }
                if matches!(relative.as_str(), ".git" | ".legion-audit-snapshot") {
                    continue;
                }
                if let Some(file) = files.get(&relative) {
                    if entry.metadata().map_err(io)?.len() != file.bytes as u64 {
                        return Err(AuditError::SourceDrift(format!(
                            "snapshot length changed:{relative}"
                        )));
                    }
                }
                actual.insert(relative);
            }
            if actual != files.keys().cloned().collect() || directories != expected_directories {
                return Err(invalid("snapshot path set differs from sealed manifest"));
            }
        }
        Ok(())
    }
    pub fn read(
        &self,
        path: &str,
        side: SnapshotSide,
        max_bytes: usize,
    ) -> Result<Vec<u8>, AuditError> {
        scope::safe_path(path)?;
        let (root, files) = match side {
            SnapshotSide::Selected => (&self.manifest.execution_root, &self.manifest.files),
            SnapshotSide::Base => (&self.manifest.baseline_root, &self.manifest.base_files),
        };
        let file = files
            .get(path)
            .ok_or_else(|| invalid(format!("denied:snapshot-path-not-present:{path}")))?;
        if file.bytes > max_bytes {
            return Err(invalid("denied:snapshot-read-byte-cap"));
        }
        let bytes = read_safe(root, path, max_bytes)?;
        if bytes.len() != file.bytes || hash(&bytes) != file.digest {
            return Err(AuditError::SourceDrift(format!(
                "snapshot bytes changed:{path}"
            )));
        }
        Ok(bytes)
    }
    /// Exact before/after source for changed paths, including deletion/addition.
    /// No synthesized live Git diff, config interpretation or lossy text conversion.
    pub fn changed_source(
        &self,
        path: &str,
        max_bytes: usize,
    ) -> Result<SnapshotChange, AuditError> {
        if !self.manifest.scope.changed_paths.contains(path) {
            return Err(invalid("denied:path-not-in-frozen-change-set"));
        }
        let before = if self.manifest.base_files.contains_key(path) {
            Some(self.read(path, SnapshotSide::Base, max_bytes)?)
        } else {
            None
        };
        let after = if self.manifest.files.contains_key(path) {
            Some(self.read(path, SnapshotSide::Selected, max_bytes)?)
        } else {
            None
        };
        if before
            .as_ref()
            .map_or(0, Vec::len)
            .saturating_add(after.as_ref().map_or(0, Vec::len))
            > max_bytes
        {
            return Err(invalid("denied:diff-byte-cap"));
        }
        Ok(SnapshotChange {
            path: path.into(),
            before,
            after,
        })
    }
    /// Resume compares complete scope & bytes, including dirty edits whose
    /// porcelain status remains unchanged. Never silently adopt a new snapshot.
    pub fn verify_source_current(&self) -> Result<(), AuditError> {
        let m = &self.manifest;
        let current = ResolvedScope::resolve(
            &m.scope.source_root,
            m.scope.spec.clone(),
            m.scope.path_prefix.clone(),
        )?;
        if crate::digest(&current)? != crate::digest(&m.scope)? {
            return Err(AuditError::SourceDrift(
                "resume scope identity changed".into(),
            ));
        }
        if m.scope.head_kind == "worktree" {
            for (path, file) in &m.files {
                if hash(&read_safe(&m.scope.source_root, path, MAX_FILE_BYTES)?) != file.digest {
                    return Err(AuditError::SourceDrift(format!(
                        "resume dirty bytes changed:{path}"
                    )));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompletedAudit {
    pub schema_version: u32,
    pub source_root: PathBuf,
    pub scope_key: String,
    pub head_oid: String,
    pub plan_digest: String,
    pub report_digest: String,
    pub report_path: PathBuf,
    pub prev_entry_digest: Option<String>,
}
fn history_path(root: &Path) -> PathBuf {
    root.join(".audit/state/audited.jsonl")
}
pub fn read_last_completed(root: &Path) -> Result<Option<CompletedAudit>, AuditError> {
    let path = history_path(root);
    // Distinguish absent state from dangling links or non-directory state. A
    // failed `exists()` test follows links & would silently hide malformed state.
    for directory in [root.join(".audit"), root.join(".audit/state")] {
        match std::fs::symlink_metadata(&directory) {
            Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {}
            Ok(_) => return Err(invalid("completed Audit state directory is not regular")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(io(error)),
        }
    }
    let state = StateDir::open(
        path.parent()
            .ok_or_else(|| invalid("history parent missing"))?,
    )
    .map_err(io)?;
    let Some(bytes) = state
        .read_opt("audited.jsonl", MAX_MANIFEST_BYTES)
        .map_err(io)?
    else {
        return Ok(None);
    };
    let mut previous = None;
    let mut last = None;
    for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
        let entry: CompletedAudit = serde_json::from_slice(line)
            .map_err(|_| invalid("malformed completed Audit history"))?;
        if entry.schema_version != 1
            || entry.source_root != root
            || !scope::valid_oid(&entry.head_oid)
            || !entry
                .report_digest
                .strip_prefix("sha256:")
                .is_some_and(|digest| {
                    digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            || entry.report_path
                != root.join(".audit/state/reports").join(format!(
                    "{}.json",
                    entry.report_digest.trim_start_matches("sha256:")
                ))
            || entry.prev_entry_digest != previous
        {
            return Err(invalid("completed Audit history identity/chain invalid"));
        }
        let report = read_report(&entry.report_path)?;
        if hash(&report) != entry.report_digest {
            return Err(invalid("completed Audit report digest mismatch"));
        }
        validate_completed_report(&report)?;
        validate_report_binding(&report, &entry.plan_digest, &entry.scope_key)?;
        previous = Some(crate::digest(&entry)?);
        last = Some(entry);
    }
    Ok(last)
}
fn read_report(path: &Path) -> Result<Vec<u8>, AuditError> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid("report parent missing"))?;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| invalid("report filename invalid"))?;
    StateDir::open(parent)
        .map_err(io)?
        .read(name, MAX_MANIFEST_BYTES)
        .map_err(io)
}
fn validate_completed_report(bytes: &[u8]) -> Result<(), AuditError> {
    let report: serde_json::Value = serde_json::from_slice(bytes).map_err(io)?;
    let status = report.get("status").and_then(|v| v.as_str()).unwrap_or("");
    if !matches!(status, "clean" | "findings")
        || report
            .get("gaps")
            .and_then(|v| v.as_array())
            .is_some_and(|g| !g.is_empty())
    {
        return Err(invalid(
            "since-last requires completed clean/findings report without gaps",
        ));
    }
    Ok(())
}
fn validate_report_binding(
    bytes: &[u8],
    plan_digest: &str,
    snapshot_key: &str,
) -> Result<(), AuditError> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(io)?;
    let report = legion_contracts::ReportV2::read_any(&value).map_err(io)?;
    if report.claims.get("planDigest").and_then(|v| v.as_str()) != Some(plan_digest)
        || report.scope.snapshot_key.as_deref() != Some(snapshot_key)
    {
        return Err(invalid(
            "completed report does not bind supplied plan & snapshot",
        ));
    }
    Ok(())
}
/// Call only after final reconciliation writes a validated completed report.
/// Per-repository integration owner serializes writers; not disposable cache.
pub fn record_completed(
    snapshot: &FrozenSnapshot,
    plan_digest: &str,
    report_path: &Path,
) -> Result<(), AuditError> {
    snapshot.verify()?;
    let report_path = std::fs::canonicalize(report_path).map_err(io)?;
    let bytes = read_report(&report_path)?;
    validate_completed_report(&bytes)?;
    validate_report_binding(&bytes, plan_digest, &snapshot.manifest.key)?;
    let root = &snapshot.manifest.scope.source_root;
    let audit = StateDir::create(&root.join(".audit")).map_err(io)?;
    let state = crate::source_cache::cache_child(&audit, "state").map_err(io)?;
    let _writer = rightkit_fs::FileLock::acquire(
        &state.path().join("history.lock"),
        &rightkit_fs::LockOptions::default().labeled("audit-completed-history"),
    )
    .map_err(io)?;
    let previous = read_last_completed(root)?;
    let report_digest = hash(&bytes);
    if previous.as_ref().is_some_and(|p| {
        p.scope_key == snapshot.manifest.key
            && p.plan_digest == plan_digest
            && p.report_digest == report_digest
    }) {
        return Ok(());
    }
    // Durable content copy survives mutable run directories & disposable caches.
    let reports = crate::source_cache::cache_child(&state, "reports").map_err(io)?;
    let report_name = format!("{}.json", report_digest.trim_start_matches("sha256:"));
    if let Some(stored) = reports
        .read_opt(&report_name, MAX_MANIFEST_BYTES)
        .map_err(io)?
    {
        if stored != bytes {
            return Err(invalid("durable completed report content conflict"));
        }
    } else {
        reports.write_new(&report_name, &bytes).map_err(io)?;
    }
    let entry = CompletedAudit {
        schema_version: 1,
        source_root: root.clone(),
        scope_key: snapshot.manifest.key.clone(),
        head_oid: if snapshot.manifest.scope.head_kind == "commit" {
            snapshot.manifest.scope.selected_oid.clone()
        } else {
            snapshot.manifest.scope.head_oid.clone()
        },
        plan_digest: plan_digest.into(),
        report_digest,
        report_path: reports.path().join(report_name),
        prev_entry_digest: previous.as_ref().map(crate::digest).transpose()?,
    };
    let mut history = state
        .read_opt("audited.jsonl", MAX_MANIFEST_BYTES)
        .map_err(io)?
        .unwrap_or_default();
    history.extend(serde_json::to_vec(&entry).map_err(io)?);
    history.push(b'\n');
    state.write("audited.jsonl", &history).map_err(io)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[test]
    fn completion_history_never_accepts_partial_or_malformed_reports() {
        assert!(validate_completed_report(br#"{"status":"incomplete","gaps":[]}"#).is_err());
        assert!(validate_completed_report(br#"{"status":"clean","gaps":["missing"]}"#).is_err());
        assert!(validate_completed_report(br#"{"status":"findings","gaps":[]}"#).is_ok());
        assert!(validate_completed_report(b"not-json").is_err());
    }
    #[test]
    fn raw_byte_digest_is_not_json_string_digest() {
        assert_ne!(
            hash(b"source\n"),
            crate::digest(&b"source\n".to_vec()).unwrap()
        );
    }
    pub(crate) struct Fixture(PathBuf);
    impl Fixture {
        pub(crate) fn new() -> Self {
            let mut nonce = [0u8; 8];
            getrandom::fill(&mut nonce).unwrap();
            let path =
                std::env::temp_dir().join(format!("legion-snapshot-test-{}", hex::encode(nonce)));
            std::fs::create_dir_all(&path).unwrap();
            let fixture = Self(std::fs::canonicalize(path).unwrap());
            fixture.git(&["init", "-q"]);
            fixture.git(&["config", "user.name", "Audit Test"]);
            fixture.git(&["config", "user.email", "audit@example.invalid"]);
            std::fs::write(fixture.0.join("file.rs"), b"base\n").unwrap();
            fixture.git(&["add", "."]);
            fixture.git(&["commit", "-qm", "base"]);
            fixture
        }
        fn git(&self, args: &[&str]) {
            let mut command = rightkit_child_process::OwnedCommand::new("git");
            command
                .command_mut()
                .current_dir(&self.0)
                .args(args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            let mut child = command.spawn().unwrap();
            assert!(child
                .wait_timeout(std::time::Duration::from_secs(10))
                .unwrap()
                .unwrap()
                .success());
        }
        pub(crate) fn capture(&self, spec: scope::ScopeSpec) -> FrozenSnapshot {
            FrozenSnapshot::capture(ResolvedScope::resolve(&self.0, spec, None).unwrap()).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            for entry in walkdir::WalkDir::new(&self.0)
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
            {
                if let Ok(meta) = entry.metadata() {
                    let mut p = meta.permissions();
                    p.set_readonly(false);
                    let _ = std::fs::set_permissions(entry.path(), p);
                }
            }
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    #[test]
    fn partially_staged_bytes_and_deleted_baseline_are_frozen() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("file.rs"), b"staged\n").unwrap();
        fixture.git(&["add", "file.rs"]);
        std::fs::write(fixture.0.join("file.rs"), b"unstaged\n").unwrap();
        let before_index = std::fs::read(fixture.0.join(".git/index")).unwrap();
        let staged = fixture.capture(scope::ScopeSpec::Staged);
        assert_eq!(
            staged.read("file.rs", SnapshotSide::Selected, 100).unwrap(),
            b"staged\n"
        );
        let unstaged = fixture.capture(scope::ScopeSpec::Uncommitted);
        assert_eq!(
            unstaged
                .read("file.rs", SnapshotSide::Selected, 100)
                .unwrap(),
            b"unstaged\n"
        );
        assert_eq!(
            unstaged.read("file.rs", SnapshotSide::Base, 100).unwrap(),
            b"staged\n"
        );
        assert_eq!(
            std::fs::read(fixture.0.join(".git/index")).unwrap(),
            before_index
        );
        std::fs::remove_file(fixture.0.join("file.rs")).unwrap();
        let deleted = fixture.capture(scope::ScopeSpec::Local);
        assert!(deleted.manifest.scope.changed_paths.contains("file.rs"));
        assert!(deleted
            .changed_source("file.rs", 100)
            .unwrap()
            .after
            .is_none());
        assert_eq!(
            deleted.read("file.rs", SnapshotSide::Base, 100).unwrap(),
            b"base\n"
        );
        assert!(!deleted.manifest.execution_root.join("file.rs").exists());
        let (bytes, side) =
            FrozenSnapshot::source_for_root(&deleted.manifest.execution_root, "file.rs", 100)
                .unwrap();
        assert_eq!(bytes, b"base\n");
        assert_eq!(side, SnapshotSide::Base);
        let baseline = deleted.manifest.baseline_root.join("file.rs");
        let mut writable = std::fs::metadata(&baseline).unwrap().permissions();
        writable.set_readonly(false);
        std::fs::set_permissions(&baseline, writable).unwrap();
        std::fs::write(&baseline, b"fake\n").unwrap();
        assert!(
            FrozenSnapshot::source_for_root(&deleted.manifest.execution_root, "file.rs", 100,)
                .is_err()
        );
    }
    #[test]
    fn newly_staged_files_are_present_in_default_local_and_range_worktrees() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("added.rs"), b"staged new defect\n").unwrap();
        fixture.git(&["add", "added.rs"]);
        for spec in [
            scope::ScopeSpec::Repo,
            scope::ScopeSpec::Local,
            scope::ScopeSpec::Range {
                base: "HEAD".into(),
                head: "WORKTREE".into(),
            },
        ] {
            let snapshot = fixture.capture(spec);
            assert_eq!(
                snapshot
                    .read("added.rs", SnapshotSide::Selected, 100)
                    .unwrap(),
                b"staged new defect\n"
            );
            assert!(snapshot
                .manifest
                .scope
                .selected_entries
                .contains_key("added.rs"));
            if snapshot.manifest.scope.spec.is_diff() {
                assert!(snapshot.manifest.scope.changed_paths.contains("added.rs"));
            }
        }
    }
    #[test]
    fn branch_scope_reads_committed_head_and_excludes_dirty_changes() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("file.rs"), b"dirty content\n").unwrap();
        std::fs::write(fixture.0.join("added.rs"), b"staged new content\n").unwrap();
        fixture.git(&["add", "added.rs"]);
        let snapshot = fixture.capture(scope::ScopeSpec::Branch("HEAD".into()));
        assert_eq!(snapshot.manifest.scope.head_kind, "commit");
        assert_eq!(
            snapshot
                .read("file.rs", SnapshotSide::Selected, 100)
                .unwrap(),
            b"base\n"
        );
        assert!(snapshot.manifest.scope.changed_paths.is_empty());
        assert!(!snapshot.manifest.files.contains_key("added.rs"));
    }
    #[cfg(windows)]
    fn drive_spelling(path: &Path) -> PathBuf {
        use std::path::{Component, Prefix};
        let mut components = path.components();
        let Some(Component::Prefix(prefix)) = components.next() else {
            panic!("canonical fixture path requires drive prefix");
        };
        let Prefix::VerbatimDisk(drive) = prefix.kind() else {
            panic!("canonical local fixture path requires verbatim drive prefix");
        };
        let mut ordinary = PathBuf::from(format!("{}:\\", drive as char));
        for component in components {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => ordinary.push(name),
                _ => panic!("unexpected canonical fixture component"),
            }
        }
        ordinary
    }
    #[cfg(windows)]
    #[test]
    fn manifest_reopens_with_drive_and_verbatim_locators() {
        let fixture = Fixture::new();
        let snapshot = fixture.capture(scope::ScopeSpec::Local);
        assert_eq!(
            snapshot.manifest.execution_root,
            std::fs::canonicalize(&snapshot.manifest.execution_root).unwrap()
        );
        let ordinary_manifest = drive_spelling(&snapshot.manifest_path);
        assert_ne!(ordinary_manifest, snapshot.manifest_path);
        let reopened = FrozenSnapshot::open(&ordinary_manifest).unwrap();
        assert_eq!(reopened.manifest.key, snapshot.manifest.key);
        let ordinary_selected = drive_spelling(&snapshot.manifest.execution_root);
        let ordinary_base = drive_spelling(&snapshot.manifest.baseline_root);
        assert_eq!(
            FrozenSnapshot::source_for_root(&ordinary_selected, "file.rs", 100).unwrap(),
            (b"base\n".to_vec(), SnapshotSide::Selected)
        );
        assert_eq!(
            FrozenSnapshot::source_for_root(&ordinary_base, "file.rs", 100).unwrap(),
            (b"base\n".to_vec(), SnapshotSide::Base)
        );
    }
    #[test]
    fn manifest_rejects_another_snapshot_root() {
        let fixture = Fixture::new();
        let snapshot = fixture.capture(scope::ScopeSpec::Repo);
        let other = fixture.capture(scope::ScopeSpec::Repo);
        let mut substituted = snapshot.manifest.clone();
        substituted.execution_root = other.manifest.execution_root;
        let parent = StateDir::open(snapshot.manifest_path.parent().unwrap()).unwrap();
        parent
            .write_new(
                "manifest-wrong-root.json",
                &serde_json::to_vec(&substituted).unwrap(),
            )
            .unwrap();
        assert!(
            FrozenSnapshot::open(&parent.path().join("manifest-wrong-root.json"))
                .unwrap_err()
                .to_string()
                .contains("snapshot roots do not match manifest location")
        );
    }
    #[test]
    fn publication_reopens_nested_source_while_creation_pins_live() {
        let fixture = Fixture::new();
        std::fs::create_dir_all(fixture.0.join("src/nested")).unwrap();
        std::fs::write(fixture.0.join("src/nested/file.rs"), b"nested source\n").unwrap();
        // capture() verifies both trees before dropping its directory pins. This
        // must permit fresh no-reparse readers even on Windows sharing rules.
        let snapshot = fixture.capture(scope::ScopeSpec::Repo);
        assert_eq!(
            snapshot
                .read("src/nested/file.rs", SnapshotSide::Selected, 100)
                .unwrap(),
            b"nested source\n"
        );
        FrozenSnapshot::open(&snapshot.manifest_path).unwrap();
    }
    #[test]
    fn immutable_context_artifact_reuse_requires_identical_bytes() {
        let fixture = Fixture::new();
        let snapshot = fixture.capture(scope::ScopeSpec::Repo);
        let path = snapshot
            .write_context_artifact("graph-context.json", b"{}")
            .unwrap();
        assert_eq!(
            snapshot
                .write_context_artifact("graph-context.json", b"{}")
                .unwrap(),
            path
        );
        assert!(snapshot
            .write_context_artifact("graph-context.json", b"{\"changed\":true}")
            .is_err());
    }
    #[test]
    fn dirty_bytes_ref_moves_and_untracked_membership_invalidate_resume() {
        let fixture = Fixture::new();
        std::fs::write(fixture.0.join("file.rs"), b"dirty one\n").unwrap();
        let snapshot = fixture.capture(scope::ScopeSpec::Repo);
        assert!(snapshot.verify_source_current().is_ok());
        std::fs::write(fixture.0.join("file.rs"), b"dirty two\n").unwrap();
        assert!(snapshot.verify_source_current().is_err());
        assert_eq!(
            snapshot
                .read("file.rs", SnapshotSide::Selected, 100)
                .unwrap(),
            b"dirty one\n"
        );
        let next = fixture.capture(scope::ScopeSpec::Repo);
        std::fs::write(fixture.0.join("new.rs"), b"new\n").unwrap();
        assert!(next.verify_source_current().is_err());
        let moved = fixture.capture(scope::ScopeSpec::Repo);
        fixture.git(&["add", "file.rs", "new.rs"]);
        fixture.git(&["commit", "-qm", "moved head"]);
        assert!(moved.verify_source_current().is_err());
    }
    #[test]
    fn malformed_history_never_becomes_incremental_baseline() {
        let fixture = Fixture::new();
        std::fs::create_dir_all(fixture.0.join(".audit/state")).unwrap();
        std::fs::write(fixture.0.join(".audit/state/audited.jsonl"), b"broken\n").unwrap();
        assert!(read_last_completed(&fixture.0).is_err());
    }
    fn writable(path: &Path) {
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_readonly(false);
        std::fs::set_permissions(path, permissions).unwrap();
    }
    fn replace_bytes(path: &Path, bytes: &[u8]) {
        writable(path);
        std::fs::write(path, bytes).unwrap();
    }
    #[test]
    fn verified_reader_reuses_one_cold_verification_for_both_roots() {
        let fixture = Fixture::new();
        let snapshot = fixture.capture(scope::ScopeSpec::Local);
        let before = full_verification_count(&snapshot.manifest_path);
        let reader = FrozenSnapshot::verified_reader(&snapshot.manifest_path).unwrap();
        for root in [
            &snapshot.manifest.execution_root,
            &snapshot.manifest.baseline_root,
        ] {
            let repeated = FrozenSnapshot::for_execution_root(root).unwrap();
            assert!(std::sync::Arc::ptr_eq(&reader, &repeated));
        }
        assert_eq!(full_verification_count(&snapshot.manifest_path) - before, 1);
    }
    #[test]
    fn cached_reader_checks_same_length_bytes_even_with_restored_mtime() {
        let fixture = Fixture::new();
        let snapshot = fixture.capture(scope::ScopeSpec::Local);
        let reader = FrozenSnapshot::verified_reader(&snapshot.manifest_path).unwrap();
        let path = snapshot.manifest.execution_root.join("file.rs");
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        replace_bytes(&path, b"fake\n");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            modified
        );
        // Admission proves structure, not unread bytes. Consumption must fail.
        FrozenSnapshot::verified_reader(&snapshot.manifest_path).unwrap();
        assert!(matches!(
            reader.read("file.rs", SnapshotSide::Selected, 100),
            Err(AuditError::SourceDrift(_))
        ));
    }
    #[test]
    fn cached_reader_rejects_manifest_markers_inventory_and_lengths() {
        let fixture = Fixture::new();
        for mutation in [
            "manifest",
            "marker",
            "git",
            "added",
            "directory",
            "deleted",
            "length",
        ] {
            let snapshot = fixture.capture(scope::ScopeSpec::Local);
            FrozenSnapshot::verified_reader(&snapshot.manifest_path).unwrap();
            let root = &snapshot.manifest.execution_root;
            match mutation {
                "manifest" => {
                    let mut bytes = std::fs::read(&snapshot.manifest_path).unwrap();
                    bytes.push(b'\n'); // Same parsed manifest/key, different sealed bytes.
                    replace_bytes(&snapshot.manifest_path, &bytes);
                }
                "marker" => replace_bytes(&root.join(".legion-audit-snapshot"), b"2\n"),
                "git" => replace_bytes(&root.join(".git"), b"changed\n"),
                "added" => {
                    writable(root);
                    std::fs::write(root.join("extra.rs"), b"extra\n").unwrap();
                }
                "directory" => {
                    writable(root);
                    std::fs::create_dir(root.join("extra")).unwrap();
                }
                "deleted" => {
                    writable(root);
                    writable(&root.join("file.rs"));
                    std::fs::remove_file(root.join("file.rs")).unwrap();
                }
                "length" => replace_bytes(&root.join("file.rs"), b"longer content\n"),
                _ => unreachable!(),
            }
            assert!(
                FrozenSnapshot::verified_reader(&snapshot.manifest_path).is_err(),
                "{mutation}"
            );
        }
    }
    #[cfg(unix)]
    #[test]
    fn cached_reader_rejects_symlink_paths_and_root_replacement() {
        let fixture = Fixture::new();
        for mutation in ["symlink", "root", "manifest-symlink"] {
            let snapshot = fixture.capture(scope::ScopeSpec::Local);
            FrozenSnapshot::verified_reader(&snapshot.manifest_path).unwrap();
            let root = &snapshot.manifest.execution_root;
            match mutation {
                "symlink" => {
                    writable(root);
                    std::fs::remove_file(root.join("file.rs")).unwrap();
                    std::os::unix::fs::symlink(fixture.0.join("file.rs"), root.join("file.rs"))
                        .unwrap();
                }
                "root" => {
                    let renamed = root.with_file_name("selected-old");
                    std::fs::rename(root, &renamed).unwrap();
                    std::fs::create_dir(root).unwrap();
                    for entry in std::fs::read_dir(&renamed).unwrap() {
                        let entry = entry.unwrap();
                        std::fs::copy(entry.path(), root.join(entry.file_name())).unwrap();
                    }
                }
                "manifest-symlink" => {
                    let other = snapshot.manifest_path.with_file_name("manifest-copy.json");
                    std::fs::copy(&snapshot.manifest_path, &other).unwrap();
                    std::fs::remove_file(&snapshot.manifest_path).unwrap();
                    std::os::unix::fs::symlink(other, &snapshot.manifest_path).unwrap();
                }
                _ => unreachable!(),
            }
            assert!(
                FrozenSnapshot::verified_reader(&snapshot.manifest_path).is_err(),
                "{mutation}"
            );
        }
    }
    #[cfg(windows)]
    #[test]
    fn cached_reader_pins_windows_roots_against_replacement() {
        let fixture = Fixture::new();
        let snapshot = fixture.capture(scope::ScopeSpec::Local);
        FrozenSnapshot::verified_reader(&snapshot.manifest_path).unwrap();
        let root = &snapshot.manifest.execution_root;
        assert!(std::fs::rename(root, root.with_file_name("selected-old")).is_err());
        FrozenSnapshot::verified_reader(&snapshot.manifest_path).unwrap();
    }
    #[test]
    fn failed_cold_verification_is_never_cached() {
        let fixture = Fixture::new();
        let snapshot = fixture.capture(scope::ScopeSpec::Local);
        let path = snapshot.manifest.execution_root.join("file.rs");
        replace_bytes(&path, b"fake\n");
        let before = full_verification_count(&snapshot.manifest_path);
        for _ in 0..2 {
            assert!(matches!(
                FrozenSnapshot::verified_reader(&snapshot.manifest_path),
                Err(AuditError::SourceDrift(_))
            ));
        }
        assert_eq!(full_verification_count(&snapshot.manifest_path) - before, 2);
        replace_bytes(&path, b"base\n");
        FrozenSnapshot::verified_reader(&snapshot.manifest_path).unwrap();
        assert_eq!(full_verification_count(&snapshot.manifest_path) - before, 3);
    }
}
