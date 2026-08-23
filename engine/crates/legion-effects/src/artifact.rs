use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::error::EffectError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactRecord {
    pub path: String,
    pub digest: String,
    pub bytes: usize,
    pub immutable: bool,
}

pub trait ArtifactSink: Send + Sync {
    fn reserve(&self, paths: &[&str]) -> Result<(), EffectError> {
        for path in paths {
            validate_path(path)?;
        }
        Ok(())
    }
    fn write(&self, path: &str, bytes: &[u8]) -> Result<ArtifactRecord, EffectError>;
}

#[derive(Clone, Debug)]
pub struct ArtifactWriter {
    root: PathBuf,
}

impl ArtifactWriter {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    pub fn root(&self) -> &Path {
        &self.root
    }
    pub fn write_immutable(&self, path: &str, bytes: &[u8]) -> Result<ArtifactRecord, EffectError> {
        validate_path(path)?;
        let target = self.root.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(io_message)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(io_message)?;
        file.write_all(bytes).map_err(io_message)?;
        file.sync_all().map_err(io_message)?;
        let digest = format!("sha256:{}", hex_encode(&Sha256::digest(bytes)));
        Ok(ArtifactRecord {
            path: path.into(),
            digest,
            bytes: bytes.len(),
            immutable: true,
        })
    }
}

impl ArtifactSink for ArtifactWriter {
    fn write(&self, path: &str, bytes: &[u8]) -> Result<ArtifactRecord, EffectError> {
        self.write_immutable(path, bytes)
    }
}

fn validate_path(path: &str) -> Result<(), EffectError> {
    if path.is_empty() || Path::new(path).is_absolute() || path.split('/').any(|part| part == "..")
    {
        return Err(EffectError::ArtifactFailed(
            "artifact path escapes sink".into(),
        ));
    }
    Ok(())
}

fn io_message(error: io::Error) -> EffectError {
    EffectError::ArtifactFailed(error.to_string())
}
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
