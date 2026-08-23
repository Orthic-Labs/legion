use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FixtureError {
    Io(String),
    InvalidManifest(String),
    PathNotListed(String),
    HashMismatch {
        path: String,
        expected: String,
        actual: String,
    },
}
impl std::fmt::Display for FixtureError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(value) | Self::InvalidManifest(value) | Self::PathNotListed(value) => {
                output.write_str(value)
            }
            Self::HashMismatch {
                path,
                expected,
                actual,
            } => write!(
                output,
                "fixture hash mismatch for {path}: expected {expected}, got {actual}"
            ),
        }
    }
}
impl std::error::Error for FixtureError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureManifest {
    pub schema_version: u64,
    pub files: BTreeMap<String, String>,
}

impl FixtureManifest {
    pub fn from_json(value: &Value) -> Result<Self, FixtureError> {
        let object = value
            .as_object()
            .ok_or_else(|| FixtureError::InvalidManifest("manifest must be an object".into()))?;
        let schema_version = object
            .get("schemaVersion")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                FixtureError::InvalidManifest("schemaVersion must be an integer".into())
            })?;
        let entries = object
            .get("files")
            .and_then(Value::as_object)
            .ok_or_else(|| FixtureError::InvalidManifest("files must be an object".into()))?;
        let mut files = BTreeMap::new();
        for (path, hash) in entries {
            let hash = hash.as_str().ok_or_else(|| {
                FixtureError::InvalidManifest(format!("hash for {path} must be a string"))
            })?;
            let digest = hash.strip_prefix("sha256:").ok_or_else(|| {
                FixtureError::InvalidManifest(format!("hash for {path} must use sha256"))
            })?;
            if digest.len() != 64
                || !digest
                    .chars()
                    .all(|character| character.is_ascii_hexdigit())
            {
                return Err(FixtureError::InvalidManifest(format!(
                    "invalid SHA-256 for {path}"
                )));
            }
            if path.starts_with('/') || path.split('/').any(|part| part == "..") {
                return Err(FixtureError::InvalidManifest(format!(
                    "unsafe fixture path: {path}"
                )));
            }
            files.insert(path.replace('\\', "/"), digest.to_ascii_lowercase());
        }
        Ok(Self {
            schema_version,
            files,
        })
    }
}

#[derive(Clone, Debug)]
pub struct FixtureSet {
    root: PathBuf,
    manifest: FixtureManifest,
}

impl FixtureSet {
    pub fn load(root: impl AsRef<Path>, manifest_name: &str) -> Result<Self, FixtureError> {
        let root = root.as_ref().to_path_buf();
        let manifest_path = root.join(manifest_name);
        let bytes =
            fs::read(&manifest_path).map_err(|error| FixtureError::Io(error.to_string()))?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|error| FixtureError::InvalidManifest(error.to_string()))?;
        let manifest = FixtureManifest::from_json(&value)?;
        let set = Self { root, manifest };
        for path in set.manifest.files.keys() {
            set.read_verified(path)?;
        }
        Ok(set)
    }

    pub fn manifest(&self) -> &FixtureManifest {
        &self.manifest
    }

    pub fn read(&self, path: &str) -> Result<Vec<u8>, FixtureError> {
        self.read_verified(path)
    }

    pub fn json(&self, path: &str) -> Result<Value, FixtureError> {
        let bytes = self.read_verified(path)?;
        serde_json::from_slice(&bytes)
            .map_err(|error| FixtureError::InvalidManifest(error.to_string()))
    }

    fn read_verified(&self, path: &str) -> Result<Vec<u8>, FixtureError> {
        let path = path.replace('\\', "/");
        let expected = self
            .manifest
            .files
            .get(&path)
            .ok_or_else(|| FixtureError::PathNotListed(path.clone()))?;
        let bytes =
            fs::read(self.root.join(&path)).map_err(|error| FixtureError::Io(error.to_string()))?;
        let actual = hex_digest(&bytes);
        if &actual != expected {
            return Err(FixtureError::HashMismatch {
                path,
                expected: expected.clone(),
                actual,
            });
        }
        Ok(bytes)
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
