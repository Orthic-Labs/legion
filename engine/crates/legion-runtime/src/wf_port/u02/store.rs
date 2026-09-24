//! Literal port of `src/lib/artifacts/run-store.mjs`.

use sha2::{Digest, Sha256};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

/// `digestBytes(bytes)`: `sha256:<hex>`.
pub fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Filesystem seam so [`RunArtifactStore`] can be exercised with a fake in
/// tests, matching the porting brief's "I/O behind a trait" rule.
pub trait ArtifactFs {
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;
    /// `open(temp, 'wx', 0o600)` + `writeFile` + `sync` + `close`: create a
    /// new file exclusively (fails if it already exists) and write `bytes`.
    fn write_new_exclusive(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
}

/// Production filesystem, mirroring the Node `fs/promises` calls the
/// original module makes. `#![forbid(unsafe_code)]`-compatible: directory
/// mode is best-effort via `std::fs::set_permissions` on Unix and a no-op
/// on other platforms (there is no unsafe permission API in stable std).
pub struct StdFs;

impl ArtifactFs for StdFs {
    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::create_dir_all(path)?;
        set_mode_0700(path);
        Ok(())
    }

    fn write_new_exclusive(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        use std::fs::OpenOptions;
        use std::io::Write;
        let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        set_mode_0600(path);
        Ok(())
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        std::fs::rename(from, to)
    }

    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        std::fs::read(path)
    }
}

#[cfg(unix)]
fn set_mode_0700(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}
#[cfg(not(unix))]
fn set_mode_0700(_path: &Path) {}

#[cfg(unix)]
fn set_mode_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn set_mode_0600(_path: &Path) {}

/// One registered artifact record (frozen in the JS original).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRecord {
    pub kind: String,
    pub path: String,
    pub digest: String,
    pub bytes: usize,
    pub producer: String,
    pub producer_version: String,
    pub schema_version: Option<String>,
    pub media_type: String,
    pub binding: Option<String>,
    pub denominator_digest: Option<String>,
}

/// `writeBytes(spec)` input. `binding`/`denominator_digest`/`schema_version`
/// carry the Python/JS `binding` object and digest opaquely as JSON-encoded
/// strings so this module stays generic over the caller's schema, matching
/// how `records()` only ever round-trips them.
pub struct WriteBytesSpec {
    pub path: String,
    pub kind: String,
    pub producer: String,
    pub producer_version: Option<String>,
    pub schema_version: Option<String>,
    pub binding: Option<String>,
    pub denominator_digest: Option<String>,
    pub media_type: String,
    pub bytes: Vec<u8>,
}

/// `writeJson(spec)` input; `value` is the pre-serialized JSON text (caller
/// serializes with `serde_json::to_string_pretty`, matching `JSON.stringify(value, null, 2)`).
pub struct WriteJsonSpec {
    pub path: String,
    pub kind: String,
    pub producer: String,
    pub producer_version: Option<String>,
    pub schema_version: Option<String>,
    pub binding: Option<String>,
    pub denominator_digest: Option<String>,
    pub value_json: String,
}

/// Port of the `RunArtifactStore` class.
pub struct RunArtifactStore<F: ArtifactFs = StdFs> {
    root: PathBuf,
    records: Mutex<std::collections::BTreeMap<String, ArtifactRecord>>,
    fs: F,
    temp_counter: AtomicU64,
}

/// `lexical_resolve`: join + normalize `..`/`.` components without touching
/// the filesystem (Node's `path.resolve` semantics), so path-escape checks
/// work identically whether or not the target exists yet.
fn lexical_resolve(root: &Path, rel: &str) -> PathBuf {
    let mut out = root.to_path_buf();
    for component in Path::new(rel).components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                // An absolute-looking `rel` replaces the accumulated path,
                // matching `path.resolve(root, rel)`.
                out = PathBuf::from(component.as_os_str());
            }
            Component::Normal(part) => out.push(part),
        }
    }
    out
}

/// Component-wise "is `target` inside `root`" check (the brief's "compare
/// paths component-wise" pitfall — no `canonicalize`, which would add a
/// Windows `\\?\` prefix and break a naive string-prefix comparison).
fn is_within(root: &Path, target: &Path) -> bool {
    let root_components: Vec<_> = root.components().collect();
    let target_components: Vec<_> = target.components().collect();
    target_components.len() > root_components.len()
        && target_components[..root_components.len()] == root_components[..]
}

impl RunArtifactStore<StdFs> {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::with_fs(root, StdFs)
    }
}

impl<F: ArtifactFs> RunArtifactStore<F> {
    pub fn with_fs(root: impl Into<PathBuf>, fs: F) -> Self {
        Self {
            root: root.into(),
            records: Mutex::new(std::collections::BTreeMap::new()),
            fs,
            temp_counter: AtomicU64::new(0),
        }
    }

    /// `init()`.
    pub fn init(&self) -> io::Result<()> {
        self.fs.create_dir_all(&self.root)
    }

    /// `writeJson(spec)`.
    pub fn write_json(&self, spec: WriteJsonSpec) -> io::Result<ArtifactRecord> {
        let mut body = spec.value_json.into_bytes();
        body.push(b'\n');
        self.write_bytes(WriteBytesSpec {
            path: spec.path,
            kind: spec.kind,
            producer: spec.producer,
            producer_version: spec.producer_version,
            schema_version: spec.schema_version,
            binding: spec.binding,
            denominator_digest: spec.denominator_digest,
            media_type: "application/json".to_string(),
            bytes: body,
        })
    }

    /// `writeBytes(spec)`.
    pub fn write_bytes(&self, spec: WriteBytesSpec) -> io::Result<ArtifactRecord> {
        let target = lexical_resolve(&self.root, &spec.path);
        if !is_within(&self.root, &target) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("artifact path escapes run root: {}", spec.path),
            ));
        }
        let parent = target.parent().unwrap_or(&self.root).to_path_buf();
        self.fs.create_dir_all(&parent)?;

        let pid = std::process::id();
        let seq = self.temp_counter.fetch_add(1, Ordering::SeqCst);
        let temp = target.with_file_name(format!(
            "{}.{}.{}.tmp",
            target.file_name().and_then(|n| n.to_str()).unwrap_or("artifact"),
            pid,
            seq
        ));
        self.fs.write_new_exclusive(&temp, &spec.bytes)?;
        self.fs.rename(&temp, &target)?;
        let bytes = self.fs.read(&target)?;

        let relative_path = target
            .strip_prefix(&self.root)
            .unwrap_or(&target)
            .to_string_lossy()
            .replace('\\', "/");

        let record = ArtifactRecord {
            kind: spec.kind,
            path: relative_path,
            digest: digest_bytes(&bytes),
            bytes: bytes.len(),
            producer: spec.producer,
            producer_version: spec.producer_version.unwrap_or_else(|| "1.0.0".to_string()),
            schema_version: spec.schema_version,
            media_type: spec.media_type,
            binding: spec.binding,
            denominator_digest: spec.denominator_digest,
        };
        self.records
            .lock()
            .expect("run-store records mutex poisoned")
            .insert(record.path.clone(), record.clone());
        Ok(record)
    }

    /// `records()`: path-sorted snapshot (a `BTreeMap` keeps insertion order
    /// sorted by key already, matching `[...records.values()].sort(...)`).
    pub fn records(&self) -> Vec<ArtifactRecord> {
        self.records
            .lock()
            .expect("run-store records mutex poisoned")
            .values()
            .cloned()
            .collect()
    }

    /// `readVerified(path)`.
    pub fn read_verified(&self, path: &str) -> io::Result<Vec<u8>> {
        let record = self
            .records
            .lock()
            .expect("run-store records mutex poisoned")
            .get(path)
            .cloned()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, format!("unregistered artifact: {path}"))
            })?;
        let bytes = self.fs.read(&self.root.join(path))?;
        if digest_bytes(&bytes) != record.digest {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("artifact digest mismatch: {path}"),
            ));
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex as StdMutex;

    /// In-memory fake filesystem so tests need no real disk access.
    #[derive(Default)]
    struct FakeFs {
        files: StdMutex<HashMap<PathBuf, Vec<u8>>>,
        dirs: StdMutex<Vec<PathBuf>>,
    }

    impl ArtifactFs for FakeFs {
        fn create_dir_all(&self, path: &Path) -> io::Result<()> {
            self.dirs.lock().unwrap().push(path.to_path_buf());
            Ok(())
        }
        fn write_new_exclusive(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
            let mut files = self.files.lock().unwrap();
            if files.contains_key(path) {
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "exists"));
            }
            files.insert(path.to_path_buf(), bytes.to_vec());
            Ok(())
        }
        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            let mut files = self.files.lock().unwrap();
            let bytes = files
                .remove(from)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing temp file"))?;
            files.insert(to.to_path_buf(), bytes);
            Ok(())
        }
        fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing"))
        }
    }

    fn spec(path: &str, bytes: &[u8]) -> WriteBytesSpec {
        WriteBytesSpec {
            path: path.to_string(),
            kind: "test-artifact".to_string(),
            producer: "unit-test".to_string(),
            producer_version: None,
            schema_version: Some("1".to_string()),
            binding: None,
            denominator_digest: None,
            media_type: "text/plain".to_string(),
            bytes: bytes.to_vec(),
        }
    }

    #[test]
    fn write_bytes_registers_a_digested_record() {
        let store = RunArtifactStore::with_fs("/run/root", FakeFs::default());
        let record = store.write_bytes(spec("out/hello.txt", b"hi")).unwrap();
        assert_eq!(record.path, "out/hello.txt");
        assert_eq!(record.digest, digest_bytes(b"hi"));
        assert_eq!(record.bytes, 2);
        assert_eq!(record.producer_version, "1.0.0");
        assert_eq!(store.records().len(), 1);
    }

    #[test]
    fn write_json_appends_trailing_newline_and_sets_media_type() {
        let store = RunArtifactStore::with_fs("/run/root", FakeFs::default());
        let record = store
            .write_json(WriteJsonSpec {
                path: "out/data.json".to_string(),
                kind: "json-artifact".to_string(),
                producer: "unit-test".to_string(),
                producer_version: None,
                schema_version: None,
                binding: None,
                denominator_digest: None,
                value_json: "{\n  \"a\": 1\n}".to_string(),
            })
            .unwrap();
        assert_eq!(record.media_type, "application/json");
        assert_eq!(record.digest, digest_bytes(b"{\n  \"a\": 1\n}\n"));
    }

    #[test]
    fn write_bytes_rejects_path_escaping_root() {
        let store = RunArtifactStore::with_fs("/run/root", FakeFs::default());
        let err = store.write_bytes(spec("../escape.txt", b"x")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("escapes run root"));
    }

    #[test]
    fn records_are_sorted_by_path() {
        let store = RunArtifactStore::with_fs("/run/root", FakeFs::default());
        store.write_bytes(spec("b.txt", b"b")).unwrap();
        store.write_bytes(spec("a.txt", b"a")).unwrap();
        let paths: Vec<_> = store.records().into_iter().map(|r| r.path).collect();
        assert_eq!(paths, vec!["a.txt".to_string(), "b.txt".to_string()]);
    }

    #[test]
    fn read_verified_returns_bytes_for_matching_digest() {
        let store = RunArtifactStore::with_fs("/run/root", FakeFs::default());
        store.write_bytes(spec("out/hello.txt", b"hi")).unwrap();
        let bytes = store.read_verified("out/hello.txt").unwrap();
        assert_eq!(bytes, b"hi");
    }

    #[test]
    fn read_verified_rejects_unregistered_path() {
        let store = RunArtifactStore::with_fs("/run/root", FakeFs::default());
        let err = store.read_verified("never/written.txt").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
        assert!(err.to_string().contains("unregistered artifact"));
    }

    #[test]
    fn read_verified_rejects_digest_mismatch() {
        let store = RunArtifactStore::with_fs("/run/root", FakeFs::default());
        let record = store.write_bytes(spec("out/hello.txt", b"hi")).unwrap();
        // Tamper with the stored bytes behind the store's back.
        store
            .fs
            .files
            .lock()
            .unwrap()
            .insert(PathBuf::from("/run/root").join(&record.path), b"tampered".to_vec());
        let err = store.read_verified("out/hello.txt").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("digest mismatch"));
    }
}
