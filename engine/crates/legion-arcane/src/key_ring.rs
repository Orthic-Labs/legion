use crate::error::ArcaneError;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::Path;

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
        let home = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .ok_or_else(|| {
                ArcaneError::typed("ARC_AUTH_KEY_UNAVAILABLE", "host home unavailable")
            })?;
        Self::load_dir(
            &std::path::PathBuf::from(home)
                .join(".codex")
                .join("arcane-keys"),
        )
    }

    pub fn load_dir(dir: &Path) -> Result<Self, ArcaneError> {
        if !dir.is_dir() {
            return Err(ArcaneError::typed(
                "ARC_AUTH_KEY_UNAVAILABLE",
                format!("host key directory not found: {}", dir.display()),
            ));
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
            return Err(ArcaneError::typed(
                "ARC_AUTH_KEY_UNAVAILABLE",
                format!("no host key material found in {}", dir.display()),
            ));
        }
        Ok(ring)
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
