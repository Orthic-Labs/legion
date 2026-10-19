//! Protected host state for explicit scope freezes. Production has no path/env override.
//! Root-owned storage is the trust boundary, not serialized role/model claims.
//! Host administrators remain trusted. Callers hold `lock()` across read/modify/write.

#[cfg(unix)]
mod platform {
    use serde::{de::DeserializeOwned, Serialize};
    use std::{
        fs::{self, File, Metadata, OpenOptions},
        io::{Read, Write},
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
        process::Command,
        sync::{
            atomic::{AtomicBool, AtomicU64, Ordering},
            Arc,
        },
    };

    const LIMIT: usize = 8 * 1024 * 1024;
    static NEXT: AtomicU64 = AtomicU64::new(0);

    pub struct ProtectedStore {
        root: PathBuf,
        boundary: PathBuf,
        expected_uid: u32,
        held: Arc<AtomicBool>,
    }
    pub struct StoreLock {
        path: PathBuf,
        file: File,
        held: Arc<AtomicBool>,
    }
    fn fail(e: impl std::fmt::Display) -> String {
        e.to_string()
    }
    fn effective_uid() -> Result<u32, String> {
        let out = Command::new("/usr/bin/id")
            .arg("-u")
            .env_clear()
            .output()
            .map_err(fail)?;
        if !out.status.success() {
            return Err("cannot resolve effective identity".into());
        }
        String::from_utf8(out.stdout)
            .map_err(fail)?
            .trim()
            .parse()
            .map_err(fail)
    }
    fn slug(id: &str) -> Result<(), String> {
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("invalid freeze store id".into());
        }
        Ok(())
    }
    fn authority_root() -> Result<PathBuf, String> {
        if cfg!(target_os = "macos") {
            Ok("/Library/Application Support/Orthic Labs/Legion/authority".into())
        } else if cfg!(target_os = "linux") {
            Ok("/var/lib/legion/authority".into())
        } else {
            Err("native authority broker unavailable on this platform".into())
        }
    }
    impl ProtectedStore {
        pub fn directory(&self) -> &Path {
            &self.root
        }
        fn at(root: PathBuf, boundary: PathBuf, expected_uid: u32) -> Self {
            Self {
                root,
                boundary,
                expected_uid,
                held: Arc::new(AtomicBool::new(false)),
            }
        }
        pub fn open_existing(id: &str) -> Result<Self, String> {
            slug(id)?;
            let s = Self::at(authority_root()?.join(id), "/".into(), 0);
            s.validate_existing()?;
            Ok(s)
        }
        pub fn create_enrollment<T: Serialize, S: Serialize>(
            id: &str,
            config: &T,
            state: &S,
        ) -> Result<Self, String> {
            slug(id)?;
            let base = Self::at(authority_root()?, "/".into(), 0);
            base.require_writer()?;
            base.create_chain()?;
            base.enroll(id, config, state)
        }
        fn enroll<T: Serialize, S: Serialize>(
            &self,
            id: &str,
            config: &T,
            state: &S,
        ) -> Result<Self, String> {
            self.require_writer()?;
            slug(id)?;
            self.validate_chain()?;
            let s = Self::at(self.root.join(id), self.boundary.clone(), self.expected_uid);
            // Never reopen, reset, or replace an existing enrollment/tombstone.
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&s.root)
                .map_err(fail)?;
            s.create_file("config.json", config)?;
            s.create_file("state.json", state)?;
            File::open(&s.root)
                .and_then(|d| d.sync_all())
                .map_err(fail)?;
            File::open(&self.root)
                .and_then(|d| d.sync_all())
                .map_err(fail)?;
            Ok(s)
        }
        fn require_writer(&self) -> Result<(), String> {
            if effective_uid()? != self.expected_uid {
                return Err("authority mutation requires root identity".into());
            }
            Ok(())
        }
        fn secure(&self, path: &Path, directory: bool) -> Result<Metadata, String> {
            let m = fs::symlink_metadata(path).map_err(fail)?;
            if m.file_type().is_symlink()
                || m.uid() != self.expected_uid
                || m.mode() & 0o022 != 0
                || (directory && !m.is_dir())
                || (!directory && !m.is_file())
            {
                return Err(format!("unprotected authority path: {}", path.display()));
            }
            if !directory && m.nlink() != 1 {
                return Err("authority files must not be hard-linked".into());
            }
            Ok(m)
        }
        fn validate_chain(&self) -> Result<(), String> {
            if !self.root.is_absolute() || !self.root.starts_with(&self.boundary) {
                return Err("invalid authority root".into());
            }
            self.secure(&self.boundary, true)?;
            let relative = self.root.strip_prefix(&self.boundary).map_err(fail)?;
            let mut path = self.boundary.clone();
            for c in relative.components() {
                if !matches!(c, std::path::Component::Normal(_)) {
                    return Err("invalid authority component".into());
                }
                path.push(c);
                self.secure(&path, true)?;
            }
            Ok(())
        }
        fn create_chain(&self) -> Result<(), String> {
            self.require_writer()?;
            let mut path = self.boundary.clone();
            self.secure(&path, true)?;
            for c in self
                .root
                .strip_prefix(&self.boundary)
                .map_err(fail)?
                .components()
            {
                path.push(c);
                match fs::symlink_metadata(&path) {
                    Ok(_) => (),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        fs::DirBuilder::new()
                            .mode(0o700)
                            .create(&path)
                            .map_err(fail)?;
                        File::open(path.parent().ok_or("missing authority parent")?)
                            .and_then(|d| d.sync_all())
                            .map_err(fail)?;
                    }
                    Err(e) => return Err(fail(e)),
                }
                self.secure(&path, true)?;
            }
            Ok(())
        }
        fn validate_existing(&self) -> Result<(), String> {
            self.validate_chain()?;
            self.secure(&self.root.join("config.json"), false)?;
            self.secure(&self.root.join("state.json"), false)?;
            Ok(())
        }
        fn create_file<T: Serialize>(&self, name: &str, value: &T) -> Result<(), String> {
            let bytes = serde_json::to_vec(value).map_err(fail)?;
            if bytes.len() > LIMIT {
                return Err("authority state exceeds size limit".into());
            }
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(self.root.join(name))
                .map_err(fail)?;
            f.write_all(&bytes).and_then(|_| f.sync_all()).map_err(fail)
        }
        fn load<T: DeserializeOwned>(&self, name: &str) -> Result<T, String> {
            self.validate_existing()?;
            let path = self.root.join(name);
            let before = self.secure(&path, false)?;
            if before.len() > LIMIT as u64 {
                return Err("authority state exceeds size limit".into());
            }
            let file = File::open(&path).map_err(fail)?;
            let opened = file.metadata().map_err(fail)?;
            if (before.dev(), before.ino()) != (opened.dev(), opened.ino()) {
                return Err("authority file changed while opening".into());
            }
            let mut bytes = Vec::new();
            file.take(LIMIT as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(fail)?;
            if bytes.len() > LIMIT {
                return Err("authority state exceeds size limit".into());
            }
            serde_json::from_slice(&bytes).map_err(fail)
        }
        pub fn load_config<T: DeserializeOwned>(&self) -> Result<T, String> {
            self.load("config.json")
        }
        pub fn load_state<T: DeserializeOwned>(&self) -> Result<T, String> {
            self.load("state.json")
        }
        pub fn write_state<T: Serialize>(&self, state: &T) -> Result<(), String> {
            self.require_writer()?;
            self.validate_existing()?;
            if !self.held.load(Ordering::Acquire) {
                return Err("authority transaction lock required".into());
            }
            let bytes = serde_json::to_vec(state).map_err(fail)?;
            if bytes.len() > LIMIT {
                return Err("authority state exceeds size limit".into());
            }
            let name = format!(
                "state.tmp.{}.{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            );
            let tmp = self.root.join(&name);
            // A collision must not delete or replace somebody else's temporary file.
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(fail)?;
            let result = (|| {
                file.write_all(&bytes)
                    .and_then(|_| file.sync_all())
                    .map_err(fail)?;
                self.secure(&tmp, false)?;
                fs::rename(&tmp, self.root.join("state.json")).map_err(fail)?;
                File::open(&self.root)
                    .and_then(|d| d.sync_all())
                    .map_err(fail)
            })();
            if result.is_err() {
                let _ = fs::remove_file(&tmp);
            }
            result
        }
        pub fn lock(&self) -> Result<StoreLock, String> {
            self.require_writer()?;
            self.validate_existing()?;
            let path = self.root.join("transaction.lock");
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .map_err(fail)?;
            self.held.store(true, Ordering::Release);
            Ok(StoreLock {
                path,
                file,
                held: Arc::clone(&self.held),
            })
        }
    }
    impl Drop for StoreLock {
        fn drop(&mut self) {
            self.held.store(false, Ordering::Release);
            if let (Ok(open), Ok(now)) = (self.file.metadata(), fs::symlink_metadata(&self.path)) {
                if (open.dev(), open.ino()) == (now.dev(), now.ino()) {
                    let _ = fs::remove_file(&self.path);
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::os::unix::fs::{symlink, PermissionsExt};
        struct Temp(PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        fn fixture() -> (Temp, ProtectedStore) {
            let base = if cfg!(target_os = "macos")
                && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
            {
                PathBuf::from("/Volumes/D/scratch")
            } else {
                std::env::temp_dir()
            };
            let path = base.join(format!(
                "legion-freeze-store-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            let root = ProtectedStore::at(path.clone(), path.clone(), effective_uid().unwrap());
            (Temp(path), root)
        }
        #[test]
        fn enrollment_preserves_state_and_requires_transaction() {
            let (_temp, base) = fixture();
            let s = base.enroll("freeze", &"config", &1u64).unwrap();
            assert_eq!(s.load_config::<String>().unwrap(), "config");
            assert!(s.write_state(&2u64).is_err());
            let lock = s.lock().unwrap();
            assert!(s.lock().is_err());
            s.write_state(&2u64).unwrap();
            drop(lock);
            assert_eq!(s.load_state::<u64>().unwrap(), 2);
            assert!(base.enroll("freeze", &"reset", &0u64).is_err());
            assert!(s.lock().is_ok());
        }
        #[test]
        fn rejects_missing_state_symlink_writable_paths_and_wrong_owner() {
            let (temp, base) = fixture();
            let s = base.enroll("freeze", &0u64, &1u64).unwrap();
            let state = s.root.join("state.json");
            fs::remove_file(&state).unwrap();
            assert!(s.load_state::<u64>().is_err());
            assert!(base.enroll("freeze", &0u64, &0u64).is_err());
            symlink(s.root.join("config.json"), &state).unwrap();
            assert!(s.load_state::<u64>().is_err());
            fs::remove_file(&state).unwrap();
            s.create_file("state.json", &1u64).unwrap();
            fs::set_permissions(&state, fs::Permissions::from_mode(0o666)).unwrap();
            assert!(s.load_state::<u64>().is_err());
            fs::set_permissions(&state, fs::Permissions::from_mode(0o600)).unwrap();
            let other = ProtectedStore::at(
                s.root.clone(),
                temp.0.clone(),
                base.expected_uid.wrapping_add(1),
            );
            assert!(other.load_state::<u64>().is_err());
            assert!(other.write_state(&2u64).is_err());
            fs::set_permissions(&s.root, fs::Permissions::from_mode(0o777)).unwrap();
            assert!(s.lock().is_err());
        }
        #[test]
        fn rejects_ancestor_symlink_stale_lock_and_path_escape() {
            let (temp, base) = fixture();
            assert!(base.enroll("../escape", &0u64, &0u64).is_err());
            let s = base.enroll("freeze", &0u64, &1u64).unwrap();
            File::create(s.root.join("transaction.lock")).unwrap();
            assert!(s.lock().is_err());
            symlink(&s.root, temp.0.join("alias")).unwrap();
            let alias = ProtectedStore::at(temp.0.join("alias"), temp.0.clone(), base.expected_uid);
            assert!(alias.load_state::<u64>().is_err());
        }
    }
}

#[cfg(not(unix))]
mod platform {
    use serde::{de::DeserializeOwned, Serialize};
    pub struct ProtectedStore;
    pub struct StoreLock;
    fn unavailable<T>() -> Result<T, String> {
        Err("native authority broker unavailable; use authenticated SSH to Unix broker".into())
    }
    impl ProtectedStore {
        pub fn directory(&self) -> &std::path::Path {
            std::path::Path::new("")
        }
        pub fn open_existing(_: &str) -> Result<Self, String> {
            unavailable()
        }
        pub fn create_enrollment<T: Serialize, S: Serialize>(
            _: &str,
            _: &T,
            _: &S,
        ) -> Result<Self, String> {
            unavailable()
        }
        pub fn load_config<T: DeserializeOwned>(&self) -> Result<T, String> {
            unavailable()
        }
        pub fn load_state<T: DeserializeOwned>(&self) -> Result<T, String> {
            unavailable()
        }
        pub fn write_state<T: Serialize>(&self, _: &T) -> Result<(), String> {
            unavailable()
        }
        pub fn lock(&self) -> Result<StoreLock, String> {
            unavailable()
        }
    }
}
pub use platform::{ProtectedStore, StoreLock};
