use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};
use walkdir::{DirEntry, WalkDir};

use crate::{error::AuditError, integrity::digest};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryEntry {
    pub path: String,
    #[serde(default)]
    pub symbols: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InventoryEnvelope {
    pub schema_version: u32,
    pub repository_id: String,
    pub generation: String,
    pub entries: Vec<InventoryEntry>,
    pub digest: String,
}

pub trait BlueprintInventorySource: Send + Sync {
    fn inventory(&self, repository_id: &str) -> Result<InventoryEnvelope, AuditError>;
}

/// Audit-owned read-only repository inventory used when Blueprint is absent.
#[derive(Clone, Debug)]
pub struct FilesystemInventorySource {
    root: PathBuf,
}

/// Read-only source for a host-published Membrane Blueprint audit projection.
///
/// The host owns Blueprint lifecycle and publication. Legion only consumes one
/// packet path, rereading it on every inventory request so generation changes
/// between plan compilation and execution fail closed through the normal audit
/// binding checks.
#[derive(Clone, Debug)]
pub struct FileBlueprintInventorySource {
    packet_path: PathBuf,
    expected_generation: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BlueprintPacket {
    schema: String,
    status: String,
    state: String,
    generation_id: String,
    #[serde(default)]
    pinned_generation: Option<String>,
    manifest_digest: String,
    files: Vec<String>,
    file_count: usize,
    source_file_count: usize,
    parsed_extensions: Vec<String>,
    unsupported_extensions: Vec<String>,
}

pub type BlueprintSource = dyn BlueprintInventorySource;
pub type InventorySnapshot = InventoryEnvelope;

impl FilesystemInventorySource {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, AuditError> {
        let root = std::fs::canonicalize(root.as_ref()).map_err(|error| {
            AuditError::Invalid(format!("could not resolve Audit root: {error}"))
        })?;
        if !root.is_dir() {
            return Err(AuditError::Invalid("Audit root must be a directory".into()));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl BlueprintInventorySource for FilesystemInventorySource {
    fn inventory(&self, repository_id: &str) -> Result<InventoryEnvelope, AuditError> {
        let mut entries = Vec::new();
        let walker = WalkDir::new(&self.root)
            .follow_links(false)
            .into_iter()
            .filter_entry(included_entry);
        for entry in walker {
            let entry = entry.map_err(|error| {
                AuditError::Invalid(format!("could not inventory repository: {error}"))
            })?;
            if entry.depth() == 0 {
                continue;
            }
            let file_type = entry.file_type();
            if !file_type.is_file() && !file_type.is_symlink() {
                continue;
            }
            let relative = entry.path().strip_prefix(&self.root).map_err(|error| {
                AuditError::Invalid(format!("inventory path escaped Audit root: {error}"))
            })?;
            let path = relative.to_string_lossy().replace('\\', "/");
            let bytes = if file_type.is_symlink() {
                std::fs::read_link(entry.path())
                    .map_err(|error| {
                        AuditError::Invalid(format!(
                            "could not read inventory symlink {}: {error}",
                            entry.path().display()
                        ))
                    })?
                    .to_string_lossy()
                    .into_owned()
                    .into_bytes()
            } else {
                std::fs::read(entry.path()).map_err(|error| {
                    AuditError::Invalid(format!(
                        "could not read inventory file {}: {error}",
                        entry.path().display()
                    ))
                })?
            };
            entries.push(InventoryEntry {
                path,
                symbols: Vec::new(),
                dependencies: Vec::new(),
                digest: Some(format!("sha256:{:x}", Sha256::digest(bytes))),
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        let content_digest = legion_contracts::canonical_digest(&entries)
            .map_err(|error| AuditError::Invalid(error.to_string()))?;
        InventoryEnvelope::new(
            repository_id,
            format!("filesystem:{content_digest}"),
            entries,
        )
    }
}

fn included_entry(entry: &DirEntry) -> bool {
    if !entry.file_type().is_dir() || entry.depth() == 0 {
        return true;
    }
    !matches!(
        entry.file_name().to_str(),
        Some(".git" | ".audit" | "node_modules" | "target")
    )
}

impl FileBlueprintInventorySource {
    pub fn new(
        packet_path: impl Into<PathBuf>,
        expected_generation: Option<String>,
    ) -> Result<Self, AuditError> {
        let source = Self {
            packet_path: packet_path.into(),
            expected_generation,
        };
        if !source.packet_path.is_absolute() {
            return Err(AuditError::Invalid(
                "Blueprint packet path must be absolute".into(),
            ));
        }
        if source
            .expected_generation
            .as_deref()
            .is_some_and(|generation| generation.trim().is_empty())
        {
            return Err(AuditError::Invalid(
                "expected Blueprint generation must be non-empty".into(),
            ));
        }
        source.load_packet()?;
        Ok(source)
    }

    pub fn packet_path(&self) -> &Path {
        &self.packet_path
    }

    fn load_packet(&self) -> Result<BlueprintPacket, AuditError> {
        let input = std::fs::read_to_string(&self.packet_path).map_err(|error| {
            AuditError::SourceDrift(format!(
                "could not read Blueprint packet {}: {error}",
                self.packet_path.display()
            ))
        })?;
        let packet: BlueprintPacket = serde_json::from_str(&input).map_err(|error| {
            AuditError::SourceDrift(format!(
                "could not parse Blueprint packet {}: {error}",
                self.packet_path.display()
            ))
        })?;
        packet.validate(self.expected_generation.as_deref())?;
        Ok(packet)
    }
}

impl BlueprintPacket {
    fn validate(&self, expected_generation: Option<&str>) -> Result<(), AuditError> {
        if self.schema != "membrane.blueprint-packet.v1"
            || self.status != "ready"
            || self.state != "ready"
        {
            return Err(AuditError::SourceDrift(
                "Blueprint packet is not a ready membrane.blueprint-packet.v1 projection".into(),
            ));
        }
        if self.generation_id.trim().is_empty() {
            return Err(AuditError::SourceDrift(
                "Blueprint packet generation is missing".into(),
            ));
        }
        if let Some(expected) = expected_generation {
            if expected != self.generation_id {
                return Err(AuditError::SourceDrift(format!(
                    "Blueprint generation mismatch: expected {expected}, observed {}",
                    self.generation_id
                )));
            }
        }
        if self
            .pinned_generation
            .as_deref()
            .is_some_and(|pinned| pinned != self.generation_id)
        {
            return Err(AuditError::SourceDrift(
                "Blueprint pinned generation does not match packet generation".into(),
            ));
        }
        let digest = self
            .manifest_digest
            .strip_prefix("sha256:")
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
        if digest.is_none() {
            return Err(AuditError::SourceDrift(
                "Blueprint manifest digest must be canonical sha256".into(),
            ));
        }
        if self.file_count != self.files.len() || self.source_file_count > self.file_count {
            return Err(AuditError::SourceDrift(
                "Blueprint packet file counts do not reconcile".into(),
            ));
        }
        validate_sorted_unique(&self.files, "files")?;
        validate_sorted_unique(&self.parsed_extensions, "parsed extensions")?;
        validate_sorted_unique(&self.unsupported_extensions, "unsupported extensions")?;
        for path in &self.files {
            let mut components = path.split('/');
            let first = components.next().unwrap_or_default();
            if path.starts_with('/')
                || path.contains('\\')
                || path.contains('\0')
                || first.ends_with(':')
                || first.is_empty()
                || std::iter::once(first)
                    .chain(components)
                    .any(|component| component.is_empty() || component == "." || component == "..")
            {
                return Err(AuditError::SourceDrift(format!(
                    "Blueprint packet contains non-canonical path {path}"
                )));
            }
        }
        Ok(())
    }
}

fn validate_sorted_unique(values: &[String], label: &str) -> Result<(), AuditError> {
    if values
        .windows(2)
        .any(|pair| pair[0].as_str() >= pair[1].as_str())
    {
        return Err(AuditError::SourceDrift(format!(
            "Blueprint packet {label} must be sorted and unique"
        )));
    }
    Ok(())
}

impl BlueprintInventorySource for FileBlueprintInventorySource {
    fn inventory(&self, repository_id: &str) -> Result<InventoryEnvelope, AuditError> {
        let packet = self.load_packet()?;
        let entries = packet
            .files
            .into_iter()
            .map(|path| InventoryEntry {
                path,
                symbols: Vec::new(),
                dependencies: Vec::new(),
                digest: None,
            })
            .collect();
        InventoryEnvelope::new(repository_id, packet.generation_id, entries)
    }
}

impl InventoryEnvelope {
    pub fn new(
        repository_id: impl Into<String>,
        generation: impl Into<String>,
        mut entries: Vec<InventoryEntry>,
    ) -> Result<Self, AuditError> {
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let envelope = Self {
            schema_version: 1,
            repository_id: repository_id.into(),
            generation: generation.into(),
            entries,
            digest: String::new(),
        };
        envelope.validate_without_digest()?;
        let digest = digest(&envelope.without_digest())?;
        Ok(Self { digest, ..envelope })
    }

    fn without_digest(&self) -> impl Serialize + '_ {
        (
            &self.schema_version,
            &self.repository_id,
            &self.generation,
            &self.entries,
        )
    }

    fn validate_without_digest(&self) -> Result<(), AuditError> {
        if self.schema_version != 1 {
            return Err(AuditError::Invalid("unsupported inventory schema".into()));
        }
        if self.repository_id.trim().is_empty() || self.generation.trim().is_empty() {
            return Err(AuditError::Invalid(
                "repository and generation are required".into(),
            ));
        }
        let mut paths = BTreeSet::new();
        for entry in &self.entries {
            if entry.path.trim().is_empty() || !paths.insert(&entry.path) {
                return Err(AuditError::Invalid(
                    "inventory paths must be unique and non-empty".into(),
                ));
            }
            if entry.symbols.windows(2).any(|pair| pair[0] > pair[1])
                || entry.dependencies.windows(2).any(|pair| pair[0] > pair[1])
            {
                return Err(AuditError::Invalid("inventory lists must be sorted".into()));
            }
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), AuditError> {
        self.validate_without_digest()?;
        if self.digest != digest(&self.without_digest())? {
            return Err(AuditError::SourceDrift("inventory digest mismatch".into()));
        }
        Ok(())
    }

    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.path.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet_path(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "legion-blueprint-packet-{}-{tag}.json",
            std::process::id()
        ))
    }

    fn write_packet(path: &Path, generation: &str, files: &[&str]) {
        let packet = serde_json::json!({
            "schema": "membrane.blueprint-packet.v1",
            "status": "ready",
            "state": "ready",
            "generationId": generation,
            "manifestDigest": format!("sha256:{}", "1".repeat(64)),
            "sourceObservation": {"kind": "fixture"},
            "files": files,
            "fileCount": files.len(),
            "sourceFileCount": files.len(),
            "parsedExtensions": ["rs"],
            "unsupportedExtensions": [],
            "overlay": {"state": "ready", "dirtyTracked": 0, "untracked": 0}
        });
        std::fs::write(path, serde_json::to_vec(&packet).unwrap()).unwrap();
    }

    #[test]
    fn file_blueprint_source_projects_sorted_inventory() {
        let path = packet_path("ready");
        write_packet(&path, "generation-1", &["src/a.rs", "src/b.rs"]);
        let source = FileBlueprintInventorySource::new(&path, Some("generation-1".into())).unwrap();
        let inventory = source.inventory("repo").unwrap();
        assert_eq!(inventory.generation, "generation-1");
        assert_eq!(
            inventory.paths().collect::<Vec<_>>(),
            ["src/a.rs", "src/b.rs"]
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn file_blueprint_source_fails_closed_after_generation_changes() {
        let path = packet_path("drift");
        write_packet(&path, "generation-1", &["src/a.rs"]);
        let source = FileBlueprintInventorySource::new(&path, Some("generation-1".into())).unwrap();
        write_packet(&path, "generation-2", &["src/a.rs"]);
        assert!(matches!(
            source.inventory("repo"),
            Err(AuditError::SourceDrift(message)) if message.contains("generation mismatch")
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn file_blueprint_source_rejects_noncanonical_paths() {
        let path = packet_path("path");
        write_packet(&path, "generation-1", &["../outside.rs"]);
        assert!(matches!(
            FileBlueprintInventorySource::new(&path, None),
            Err(AuditError::SourceDrift(message)) if message.contains("non-canonical path")
        ));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn filesystem_source_is_deterministic_and_detects_content_drift() {
        let root = std::env::temp_dir().join(format!(
            "legion-filesystem-inventory-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join(".audit")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "fn one() {}\n").unwrap();
        std::fs::write(root.join(".audit/report.json"), "ignored").unwrap();
        let source = FilesystemInventorySource::new(&root).unwrap();
        let first = source.inventory("repo").unwrap();
        let repeated = source.inventory("repo").unwrap();
        assert_eq!(first, repeated);
        assert_eq!(first.paths().collect::<Vec<_>>(), ["src/lib.rs"]);

        std::fs::write(root.join("src/lib.rs"), "fn two() {}\n").unwrap();
        let changed = source.inventory("repo").unwrap();
        assert_ne!(first.generation, changed.generation);
        assert_ne!(first.digest, changed.digest);
        std::fs::remove_dir_all(root).unwrap();
    }
}
