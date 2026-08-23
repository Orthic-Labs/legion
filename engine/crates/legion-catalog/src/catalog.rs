use std::{collections::BTreeSet, path::Path};

use serde::{Deserialize, Serialize};

use crate::{
    error::CatalogError,
    frontmatter::{parse, parse_agent, source_hash},
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CatalogKind {
    Skill,
    Agent,
    Lens,
    Recipe,
    Roster,
    Document,
}

impl CatalogKind {
    pub fn from_path(path: &str) -> Self {
        match path.split('/').next().unwrap_or_default() {
            "skills" => Self::Skill,
            "agents" => Self::Agent,
            "lenses" => Self::Lens,
            "recipes" => Self::Recipe,
            "roster" => Self::Roster,
            _ => Self::Document,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub canonical_id: String,
    pub kind: CatalogKind,
    pub source_path: String,
    pub package_identity: String,
    pub source_hash: String,
    pub body: Vec<u8>,
    pub source_bytes: Vec<u8>,
    pub frontmatter: serde_json::Value,
}

impl CatalogEntry {
    pub fn from_bytes(path: impl AsRef<Path>, bytes: &[u8]) -> Result<Self, CatalogError> {
        let source_path = normalize_path(path.as_ref())?;
        let kind = CatalogKind::from_path(&source_path);
        let document = parse(bytes)?;
        let mut values = document.values.clone();
        if values.is_empty()
            && !matches!(
                Path::new(&source_path)
                    .extension()
                    .and_then(|value| value.to_str()),
                Some("md" | "markdown")
            )
        {
            let value: serde_json::Value = match Path::new(&source_path)
                .extension()
                .and_then(|item| item.to_str())
            {
                Some("json") => serde_json::from_slice(bytes)?,
                Some("yaml" | "yml") => {
                    serde_json::to_value(serde_yaml::from_slice::<serde_yaml::Value>(bytes)?)?
                }
                _ => serde_json::Value::Null,
            };
            if let Some(object) = value.as_object() {
                values.extend(
                    object
                        .iter()
                        .map(|(key, value)| (key.clone(), value.clone())),
                );
            }
        }
        let frontmatter = serde_json::to_value(&values)?;
        let canonical_id = values
            .get("id")
            .and_then(serde_json::Value::as_str)
            .or_else(|| values.get("name").and_then(serde_json::Value::as_str))
            .map(str::to_owned)
            .unwrap_or_else(|| fallback_id(&source_path));
        validate_id(&canonical_id)?;
        let package_identity = package_identity(&source_path);
        Ok(Self {
            canonical_id,
            kind,
            source_path,
            package_identity,
            source_hash: source_hash(bytes),
            body: document.body,
            source_bytes: bytes.to_vec(),
            frontmatter,
        })
    }

    pub fn agent_definition(&self) -> Result<legion_contracts::AgentDefinition, CatalogError> {
        if self.kind != CatalogKind::Agent {
            return Err(CatalogError::InvalidCatalog {
                path: self.source_path.clone(),
                reason: "entry is not an agent".into(),
            });
        }
        let (definition, _) = parse_agent(&self.source_bytes)?;
        definition.to_v2(&self.canonical_id)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Catalog {
    pub schema_version: u32,
    pub entries: Vec<CatalogEntry>,
}

impl Catalog {
    pub fn discover(root: impl AsRef<Path>) -> Result<Self, CatalogError> {
        crate::discovery::discover(root)
    }

    pub fn new(mut entries: Vec<CatalogEntry>) -> Result<Self, CatalogError> {
        entries.sort_by(|left, right| {
            left.source_path
                .cmp(&right.source_path)
                .then_with(|| left.canonical_id.cmp(&right.canonical_id))
        });
        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for entry in &entries {
            if !ids.insert(entry.canonical_id.clone()) {
                return Err(CatalogError::OwnershipCollision {
                    identity: format!("canonical id `{}`", entry.canonical_id),
                });
            }
            if !paths.insert(entry.source_path.clone()) {
                return Err(CatalogError::OwnershipCollision {
                    identity: format!("source path `{}`", entry.source_path),
                });
            }
        }
        Ok(Self {
            schema_version: 1,
            entries,
        })
    }

    pub fn get(&self, id: &str) -> Option<&CatalogEntry> {
        self.entries.iter().find(|entry| entry.canonical_id == id)
    }
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.entries.iter().map(|entry| entry.canonical_id.as_str())
    }
    pub fn validate(&self) -> Result<(), CatalogError> {
        Self::new(self.entries.clone()).map(|_| ())
    }
}

pub fn normalize_path(path: &Path) -> Result<String, CatalogError> {
    if path.is_absolute() {
        return Err(CatalogError::InvalidCatalog {
            path: path.display().to_string(),
            reason: "path must be relative".into(),
        });
    }
    let mut parts = Vec::new();
    for part in path.to_string_lossy().replace('\\', "/").split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(CatalogError::InvalidCatalog {
                        path: path.display().to_string(),
                        reason: "path escapes catalog root".into(),
                    });
                }
            }
            value => parts.push(value.to_owned()),
        }
    }
    if parts.is_empty() {
        return Err(CatalogError::InvalidCatalog {
            path: path.display().to_string(),
            reason: "path must be non-empty".into(),
        });
    }
    Ok(parts.join("/"))
}

fn fallback_id(path: &str) -> String {
    let stem = path.rsplit('/').next().unwrap_or(path);
    stem.strip_suffix(".md")
        .or_else(|| stem.strip_suffix(".yaml"))
        .or_else(|| stem.strip_suffix(".yml"))
        .or_else(|| stem.strip_suffix(".json"))
        .unwrap_or(stem)
        .to_owned()
}

fn package_identity(path: &str) -> String {
    let mut parts = path.split('/');
    let kind = parts.next().unwrap_or_default();
    let package = parts
        .next()
        .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path));
    let package = package
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(package);
    format!("{kind}/{package}")
}

fn validate_id(id: &str) -> Result<(), CatalogError> {
    if id.trim().is_empty() || id.chars().any(char::is_control) {
        return Err(CatalogError::InvalidCatalog {
            path: "canonical_id".into(),
            reason: "must be non-empty and free of control characters".into(),
        });
    }
    Ok(())
}
