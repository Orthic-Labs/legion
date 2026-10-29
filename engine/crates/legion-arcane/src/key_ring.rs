use crate::error::ArcaneError;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Environment override for the host key ring directory.
pub const KEY_DIR_ENV: &str = "ARCANE_KEY_DIR";
/// The one command that provisions a missing ring.
pub const KEYS_INIT_COMMAND: &str = "legion keys init";
/// Key id minted by `legion keys init`. Fixed so that exclusive creation of
/// the key file serialises concurrent initialisations.
pub const INIT_KEY_ID: &str = "host-primary";

/// Where a resolved key directory came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyDirSource {
    Explicit,
    Environment,
    Canonical,
}

/// The canonical host ring: `$HOME/.codex/arcane-keys` (`%USERPROFILE%` on
/// Windows). Keep identical to Node's `loadCanonicalHostKeyRing`.
pub fn canonical_key_dir() -> Result<PathBuf, ArcaneError> {
    let home = std::env::var_os("USERPROFILE")
        .filter(|value| !value.is_empty())
        .or_else(|| std::env::var_os("HOME").filter(|value| !value.is_empty()))
        .ok_or_else(|| ArcaneError::typed("ARC_AUTH_KEY_UNAVAILABLE", "host home unavailable"))?;
    Ok(PathBuf::from(home).join(".codex").join("arcane-keys"))
}

/// The single key-directory resolution used by `keys init`, `doctor`,
/// `contract seal`, `run open` and the canonical loader. Precedence: explicit
/// path (e.g. `--key-dir`), then `ARCANE_KEY_DIR`, then the canonical ring.
pub fn resolve_key_dir(explicit: Option<&Path>) -> Result<(PathBuf, KeyDirSource), ArcaneError> {
    if let Some(path) = explicit.filter(|path| !path.as_os_str().is_empty()) {
        return Ok((path.to_path_buf(), KeyDirSource::Explicit));
    }
    if let Some(value) = std::env::var_os(KEY_DIR_ENV).filter(|value| !value.is_empty()) {
        return Ok((PathBuf::from(value), KeyDirSource::Environment));
    }
    Ok((canonical_key_dir()?, KeyDirSource::Canonical))
}

/// Exact prerequisite text for a ring that is missing, empty or unreadable.
pub fn missing_ring_message(dir: &Path, reason: &str) -> String {
    format!(
        "host key ring unavailable at {} ({reason}); initialize it with `{KEYS_INIT_COMMAND}`",
        dir.display()
    )
}

/// Result of a successful `init_ring`.
#[derive(Debug, Clone)]
pub struct InitializedRing {
    pub dir: PathBuf,
    pub key_id: String,
    pub key_path: PathBuf,
}

fn key_error(message: impl Into<String>) -> ArcaneError {
    ArcaneError::typed("ARC_AUTH_KEY_UNAVAILABLE", message)
}

#[derive(Clone)]
pub struct KeyRing {
    keys: RefCell<BTreeMap<String, KeyRecord>>,
}

#[derive(Clone)]
struct KeyRecord {
    key: Vec<u8>,
    created_at: String,
    custody: String,
    status: String,
}

impl KeyRing {
    /// Load the single host-custody ring used when a caller does not provide
    /// an adapter-specific directory.  Keep this path identical to Node's
    /// `loadCanonicalHostKeyRing` on every supported host.
    pub fn load_canonical() -> Result<Self, ArcaneError> {
        let (dir, _) = resolve_key_dir(None)?;
        Self::load_dir(&dir)
    }

    pub fn load_dir(dir: &Path) -> Result<Self, ArcaneError> {
        match std::fs::symlink_metadata(dir) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(key_error(format!(
                    "host key directory is a symlink and is refused: {}",
                    dir.display()
                )));
            }
            Ok(meta) if meta.is_dir() => {}
            _ => {
                return Err(key_error(missing_ring_message(
                    dir,
                    "host key directory not found",
                )));
            }
        }
        let mut ring = Self {
            keys: RefCell::new(BTreeMap::new()),
        };
        let entries = std::fs::read_dir(dir).map_err(|error| ArcaneError::Io(error.to_string()))?;
        let mut found = false;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|ext| ext.to_str()) != Some("key") {
                continue;
            }
            found = true;
            check_key_file(&path)?;
            let key_id = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or_default()
                .to_owned();
            let hex = std::fs::read_to_string(&path)
                .map_err(|error| ArcaneError::Io(error.to_string()))?
                .trim()
                .to_owned();
            let key_material = hex::decode(hex).map_err(|_| {
                ArcaneError::typed(
                    "ARC_AUTH_KEY_UNAVAILABLE",
                    format!("key material unreadable for {key_id}"),
                )
            })?;
            if key_material.is_empty() {
                return Err(ArcaneError::typed(
                    "ARC_AUTH_KEY_UNAVAILABLE",
                    format!("key material unreadable for {key_id}"),
                ));
            }
            let meta_path = dir.join(format!("{key_id}.json"));
            let custody = format!("host-file:{key_id}.key");
            let (created_at, status) = if meta_path.is_file() {
                let meta = std::fs::read_to_string(&meta_path)
                    .map_err(|error| ArcaneError::Io(error.to_string()))?;
                let value: serde_json::Value = serde_json::from_str(&meta)
                    .map_err(|error| ArcaneError::Io(error.to_string()))?;
                (
                    value
                        .get("createdAt")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_owned(),
                    value
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("active")
                        .to_owned(),
                )
            } else {
                (String::new(), "active".into())
            };
            ring.add(key_id, key_material, created_at, custody, status)?;
        }
        if !found {
            return Err(key_error(missing_ring_message(
                dir,
                "no host key material found",
            )));
        }
        Ok(ring)
    }

    /// Create the ring at `dir` with one new key. Never overwrites: a ring
    /// that already holds any `*.key` file, or a symlinked directory or key
    /// path, is refused. Unix: directory 0700, files 0600. Other platforms
    /// fail closed (no owner-only ACL helper exists in this workspace).
    /// `key_material` must come from a cryptographic RNG (>= 32 bytes).
    pub fn init_ring(
        dir: &Path,
        key_material: &[u8],
        created_at: &str,
    ) -> Result<InitializedRing, ArcaneError> {
        init_ring_impl(dir, key_material, created_at)
    }

    pub fn add(
        &self,
        key_id: impl Into<String>,
        key_material: Vec<u8>,
        created_at: impl Into<String>,
        custody: impl Into<String>,
        status: impl Into<String>,
    ) -> Result<(), ArcaneError> {
        let key_id = key_id.into();
        if key_id.is_empty() {
            return Err(ArcaneError::typed(
                "ARC_AUTH_KEY_UNAVAILABLE",
                "keyId must be a non-empty string",
            ));
        }
        if key_material.is_empty() {
            return Err(ArcaneError::typed(
                "ARC_AUTH_KEY_UNAVAILABLE",
                format!("keyMaterial must be a non-empty buffer for {key_id}"),
            ));
        }
        self.keys.borrow_mut().insert(
            key_id,
            KeyRecord {
                key: key_material,
                created_at: created_at.into(),
                custody: custody.into(),
                status: status.into(),
            },
        );
        Ok(())
    }

    pub fn has(&self, key_id: &str) -> bool {
        self.keys.borrow().contains_key(key_id)
    }

    pub fn get(&self, key_id: &str) -> Result<KeyHandle, ArcaneError> {
        if !self.has(key_id) {
            if let Some((root_key_id, role, purpose)) = parse_derived_key_id(key_id) {
                let root = self.keys.borrow().get(&root_key_id).cloned();
                if let Some(root) = root {
                    if root.status != "revoked" {
                        let mac_domain = format!("arcane-authority-proof:v1:{role}:{purpose}");
                        let material = derive_key(&root.key, &mac_domain);
                        self.add(
                            key_id,
                            material,
                            root.created_at.clone(),
                            format!("derived:{root_key_id}:{mac_domain}"),
                            "active",
                        )?;
                    }
                }
            }
        }
        let record = self.keys.borrow().get(key_id).cloned().ok_or_else(|| {
            ArcaneError::typed(
                "ARC_AUTH_KEY_UNAVAILABLE",
                format!("key unavailable: {key_id}"),
            )
        })?;
        if record.status == "revoked" {
            return Err(ArcaneError::typed(
                "ARC_AUTH_KEY_UNAVAILABLE",
                format!("key unavailable: {key_id}"),
            ));
        }
        Ok(KeyHandle {
            key_id: key_id.to_owned(),
            key: record.key,
        })
    }

    pub fn active_key_id(&self) -> Result<String, ArcaneError> {
        let active = self
            .keys
            .borrow()
            .iter()
            .filter(|(_, record)| record.status != "revoked")
            .max_by(|left, right| left.1.created_at.cmp(&right.1.created_at))
            .map(|(key_id, _)| key_id.clone());
        active.ok_or_else(|| {
            ArcaneError::typed("ARC_AUTH_KEY_UNAVAILABLE", "no active key available")
        })
    }
}

/// Refuse a key file that is a symlink, not a regular file, or (unix) readable
/// by group or others.
fn check_key_file(path: &Path) -> Result<(), ArcaneError> {
    let meta =
        std::fs::symlink_metadata(path).map_err(|error| ArcaneError::Io(error.to_string()))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(key_error(format!(
            "key file is a symlink or not a regular file and is refused: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(key_error(format!(
                "key file {} is accessible by group or others (mode {mode:03o}); refusing to load it. Fix with `chmod 600 {}` (and `chmod 700` on its directory), or re-provision with `{KEYS_INIT_COMMAND}`",
                path.display(),
                path.display()
            )));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn init_ring_impl(
    dir: &Path,
    _key_material: &[u8],
    _created_at: &str,
) -> Result<InitializedRing, ArcaneError> {
    Err(key_error(format!(
        "{KEYS_INIT_COMMAND} is unsupported on this platform: owner-only ACL provisioning is not implemented, so no key was written to {}",
        dir.display()
    )))
}

#[cfg(unix)]
fn init_ring_impl(
    dir: &Path,
    key_material: &[u8],
    created_at: &str,
) -> Result<InitializedRing, ArcaneError> {
    use std::io::Write;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    if key_material.len() < 32 {
        return Err(key_error("key material must be at least 32 bytes"));
    }
    let io = |error: std::io::Error| ArcaneError::Io(error.to_string());
    if let Some(parent) = dir.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(io)?;
    }
    // Create the final component exclusively with 0700. `mkdir` fails on an
    // existing path including a symlink, so a planted link is never followed.
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let meta = std::fs::symlink_metadata(dir).map_err(io)?;
            if meta.file_type().is_symlink() {
                return Err(key_error(format!(
                    "key directory is a symlink and is refused: {}",
                    dir.display()
                )));
            }
            if !meta.is_dir() {
                return Err(key_error(format!(
                    "key directory path is not a directory: {}",
                    dir.display()
                )));
            }
            for entry in std::fs::read_dir(dir).map_err(io)?.flatten() {
                if entry.path().extension().and_then(|ext| ext.to_str()) == Some("key") {
                    return Err(key_error(format!(
                        "key ring already initialized at {}; existing keys are never overwritten",
                        dir.display()
                    )));
                }
            }
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
        }
        Err(error) => return Err(io(error)),
    }

    let key_path = dir.join(format!("{INIT_KEY_ID}.key"));
    let meta_path = dir.join(format!("{INIT_KEY_ID}.json"));
    let exclusive = |path: &Path| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
    };
    let describe = json_meta(created_at);
    let mut meta_file = exclusive(&meta_path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            key_error(format!(
                "key ring already initialized at {}; existing keys are never overwritten",
                dir.display()
            ))
        } else {
            io(error)
        }
    })?;
    let wrote_meta = meta_file
        .write_all(describe.as_bytes())
        .and_then(|_| meta_file.sync_all());
    let mut key_file = match wrote_meta.and_then(|_| exclusive(&key_path)) {
        Ok(file) => file,
        Err(error) => {
            let _ = std::fs::remove_file(&meta_path);
            return Err(if error.kind() == std::io::ErrorKind::AlreadyExists {
                key_error(format!(
                    "key ring already initialized at {}; existing keys are never overwritten",
                    dir.display()
                ))
            } else {
                io(error)
            });
        }
    };
    if let Err(error) = key_file
        .write_all(hex::encode(key_material).as_bytes())
        .and_then(|_| key_file.sync_all())
    {
        drop(key_file);
        let _ = std::fs::remove_file(&key_path);
        let _ = std::fs::remove_file(&meta_path);
        return Err(io(error));
    }
    Ok(InitializedRing {
        dir: dir.to_path_buf(),
        key_id: INIT_KEY_ID.to_owned(),
        key_path,
    })
}

#[cfg(unix)]
fn json_meta(created_at: &str) -> String {
    serde_json::json!({"keyId": INIT_KEY_ID, "createdAt": created_at, "status": "active"})
        .to_string()
}

pub struct KeyHandle {
    pub key_id: String,
    pub key: Vec<u8>,
}

fn parse_derived_key_id(key_id: &str) -> Option<(String, String, String)> {
    let (root_key_id, rest) = key_id.split_once(":authority-proof:")?;
    let (role, purpose) = rest.split_once(':')?;
    if root_key_id.is_empty() || role.is_empty() || purpose.is_empty() {
        return None;
    }
    Some((root_key_id.to_owned(), role.to_owned(), purpose.to_owned()))
}

fn derive_key(root: &[u8], mac_domain: &str) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(root).expect("hmac key");
    mac.update(b"arcane-key-derivation:v1\0");
    mac.update(mac_domain.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn scratch(label: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "legion-key-ring-{}-{}-{}",
            std::process::id(),
            n,
            label
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn init_creates_ring_with_owner_only_permissions() {
        let root = scratch("init");
        let dir = root.join("arcane-keys");
        let out = KeyRing::init_ring(&dir, &[9u8; 32], "2026-10-30T00:00:00Z").unwrap();
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&out.key_path), 0o600);
        assert_eq!(mode(&dir.join(format!("{INIT_KEY_ID}.json"))), 0o600);
        let ring = KeyRing::load_dir(&dir).unwrap();
        assert_eq!(ring.active_key_id().unwrap(), INIT_KEY_ID);
        assert!(ring.get(INIT_KEY_ID).is_ok());
    }

    #[test]
    fn second_init_refuses_and_keeps_existing_key() {
        let root = scratch("twice");
        let dir = root.join("arcane-keys");
        let first = KeyRing::init_ring(&dir, &[1u8; 32], "t1").unwrap();
        let before = std::fs::read_to_string(&first.key_path).unwrap();
        let error = KeyRing::init_ring(&dir, &[2u8; 32], "t2").unwrap_err();
        assert!(error.to_string().contains("already initialized"));
        assert_eq!(std::fs::read_to_string(&first.key_path).unwrap(), before);
    }

    #[test]
    fn init_refuses_symlinked_directory() {
        let root = scratch("symlink-dir");
        let target = root.join("elsewhere");
        std::fs::create_dir_all(&target).unwrap();
        let dir = root.join("arcane-keys");
        symlink(&target, &dir).unwrap();
        let error = KeyRing::init_ring(&dir, &[3u8; 32], "t").unwrap_err();
        assert!(error.to_string().contains("symlink"));
        assert!(std::fs::read_dir(&target).unwrap().next().is_none());
    }

    #[test]
    fn init_refuses_dangling_symlink_key_path() {
        let root = scratch("symlink-key");
        let dir = root.join("arcane-keys");
        std::fs::create_dir_all(&dir).unwrap();
        let victim = root.join("victim");
        symlink(
            &victim,
            dir.join(format!("{INIT_KEY_ID}.key"))
                .with_extension("json"),
        )
        .unwrap();
        assert!(KeyRing::init_ring(&dir, &[4u8; 32], "t").is_err());
        assert!(!victim.exists());
    }

    #[test]
    fn init_rejects_short_key_material() {
        let root = scratch("short");
        assert!(KeyRing::init_ring(&root.join("k"), &[1u8; 8], "t").is_err());
    }

    #[test]
    fn loader_refuses_group_or_world_readable_key() {
        let root = scratch("loose");
        let dir = root.join("arcane-keys");
        KeyRing::init_ring(&dir, &[5u8; 32], "t").unwrap();
        let key = dir.join(format!("{INIT_KEY_ID}.key"));
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let message = KeyRing::load_dir(&dir).err().unwrap().to_string();
        assert!(message.contains("chmod 600"), "{message}");
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(KeyRing::load_dir(&dir).is_ok());
    }

    #[test]
    fn loader_refuses_symlinked_key_file_and_directory() {
        let root = scratch("loader-symlink");
        let real = root.join("real");
        KeyRing::init_ring(&real, &[6u8; 32], "t").unwrap();
        let link = root.join("link");
        symlink(&real, &link).unwrap();
        assert!(KeyRing::load_dir(&link)
            .err()
            .unwrap()
            .to_string()
            .contains("symlink"));
        let other = root.join("other");
        std::fs::create_dir_all(&other).unwrap();
        symlink(real.join(format!("{INIT_KEY_ID}.key")), other.join("x.key")).unwrap();
        assert!(KeyRing::load_dir(&other).is_err());
    }

    #[test]
    fn missing_ring_message_names_init_command() {
        let root = scratch("missing");
        let message = KeyRing::load_dir(&root.join("absent"))
            .err()
            .unwrap()
            .to_string();
        assert!(message.contains("legion keys init"), "{message}");
        let empty = root.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let message = KeyRing::load_dir(&empty).err().unwrap().to_string();
        assert!(message.contains("legion keys init"), "{message}");
    }

    #[test]
    fn explicit_key_dir_wins_over_canonical() {
        let (path, source) = resolve_key_dir(Some(Path::new("/x/y"))).unwrap();
        assert_eq!(path, PathBuf::from("/x/y"));
        assert_eq!(source, KeyDirSource::Explicit);
    }
}
