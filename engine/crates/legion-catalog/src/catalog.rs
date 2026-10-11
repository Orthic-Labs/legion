use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

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

/// The routing-sized representation of a capability. It deliberately carries
/// no source body: selection only needs compact catalog metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostRequirementDetail {
    pub id: String,
    #[serde(default)]
    pub degradation: String,
    #[serde(default)]
    pub remedy: String,
    #[serde(default)]
    pub probe: Option<serde_json::Value>,
}

/// A host requirement that binds only inside a named route or adapter scope —
/// never a gate on the capability as a whole.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScopedRequirementDetail {
    pub scope: String,
    #[serde(default)]
    pub scope_kind: String,
    #[serde(flatten)]
    pub requirement: HostRequirementDetail,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompactCatalogEntry {
    pub canonical_id: String,
    pub source_path: String,
    pub manifest_path: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub kind: Option<String>,
    pub discoverability: Option<String>,
    #[serde(rename = "hostRequirementDetails", default)]
    pub host_requirement_details: Vec<HostRequirementDetail>,
    #[serde(rename = "scopedRequirementDetails", default)]
    pub scoped_requirement_details: Vec<ScopedRequirementDetail>,
}

/// A catalog index plus its content root. Bodies are read only by
/// [`CompactCatalog::resolve_body`], never while metadata is loaded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactCatalog {
    root: PathBuf,
    pub schema_version: u32,
    pub entries: Vec<CompactCatalogEntry>,
}

/// Exact aliases used by explicit M1 command invocation. The source document
/// is a release-bound asset; no natural-language classification happens here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExplicitCommandResolver {
    aliases: BTreeMap<String, String>,
}

/// Deterministic command resolution. `mode_tokens` contains fixed tokens from
/// alias targets in outer-to-inner chain order; `arguments` preserves caller
/// input order and contents.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedExplicitCommand {
    pub command: String,
    pub alias: Option<String>,
    pub capability_id: String,
    pub mode_tokens: Vec<String>,
    pub arguments: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExplicitAliasDocument {
    schema_version: u32,
    aliases: BTreeMap<String, String>,
}

impl ExplicitCommandResolver {
    /// Resolver for canonical slash ids when an older composition has no alias asset.
    pub fn empty() -> Self {
        Self {
            aliases: BTreeMap::new(),
        }
    }

    pub fn load(path: impl AsRef<Path>, catalog: &CompactCatalog) -> Result<Self, CatalogError> {
        let path = path.as_ref();
        let bytes = fs::read(path).map_err(|source| CatalogError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let document: ExplicitAliasDocument = serde_json::from_slice(&bytes)?;
        if document.schema_version != 1 {
            return Err(CatalogError::InvalidCatalog {
                path: path.display().to_string(),
                reason: format!(
                    "unsupported alias schema version {}",
                    document.schema_version
                ),
            });
        }
        let resolver = Self {
            aliases: document.aliases,
        };
        for alias in resolver.aliases.keys() {
            if !valid_slash_token(alias) {
                return Err(CatalogError::InvalidCatalog {
                    path: path.display().to_string(),
                    reason: format!("invalid explicit alias {alias}"),
                });
            }
            resolver.resolve_target(alias, catalog, path)?;
        }
        Ok(resolver)
    }

    pub fn resolve(
        &self,
        catalog: &CompactCatalog,
        command: &str,
        arguments: Vec<String>,
    ) -> Result<ResolvedExplicitCommand, CatalogError> {
        if !valid_slash_token(command) {
            return Err(CatalogError::InvalidCatalog {
                path: command.into(),
                reason: "explicit command must be one slash-prefixed token".into(),
            });
        }
        if self.aliases.contains_key(command) {
            let (capability_id, mode_tokens) =
                self.resolve_target(command, catalog, Path::new(command))?;
            return Ok(ResolvedExplicitCommand {
                command: command.to_owned(),
                alias: Some(command.to_owned()),
                capability_id,
                mode_tokens,
                arguments,
            });
        }
        let capability_id = command.strip_prefix('/').unwrap_or_default();
        if catalog.get(capability_id).is_none() {
            return Err(CatalogError::InvalidCatalog {
                path: command.into(),
                reason: "unknown explicit command or compact catalog id".into(),
            });
        }
        Ok(ResolvedExplicitCommand {
            command: command.to_owned(),
            alias: None,
            capability_id: capability_id.to_owned(),
            mode_tokens: Vec::new(),
            arguments,
        })
    }

    fn resolve_target(
        &self,
        alias: &str,
        catalog: &CompactCatalog,
        path: &Path,
    ) -> Result<(String, Vec<String>), CatalogError> {
        let mut target = self
            .aliases
            .get(alias)
            .ok_or_else(|| CatalogError::InvalidCatalog {
                path: path.display().to_string(),
                reason: format!("unknown explicit alias {alias}"),
            })?;
        let mut seen = BTreeSet::from([alias.to_owned()]);
        let mut mode_tokens = Vec::new();
        loop {
            if target.trim() != target || target.contains('\t') || target.contains("  ") {
                return Err(CatalogError::InvalidCatalog {
                    path: path.display().to_string(),
                    reason: format!("malformed target for explicit alias {alias}"),
                });
            }
            let mut tokens = target.split(' ');
            let command = tokens.next().unwrap_or_default();
            let target_modes = tokens.collect::<Vec<_>>();
            if !valid_slash_token(command)
                || target_modes.iter().any(|mode| !valid_mode_token(mode))
            {
                return Err(CatalogError::InvalidCatalog {
                    path: path.display().to_string(),
                    reason: format!("malformed target for explicit alias {alias}: {target}"),
                });
            }
            mode_tokens.extend(target_modes.into_iter().map(str::to_owned));
            if let Some(next) = self.aliases.get(command) {
                if !seen.insert(command.to_owned()) {
                    return Err(CatalogError::InvalidCatalog {
                        path: path.display().to_string(),
                        reason: format!("explicit alias cycle at {command}"),
                    });
                }
                target = next;
                continue;
            }
            let capability_id = command.strip_prefix('/').unwrap_or_default();
            if catalog.get(capability_id).is_none() {
                return Err(CatalogError::InvalidCatalog {
                    path: path.display().to_string(),
                    reason: format!("alias {alias} targets missing catalog id {capability_id}"),
                });
            }
            return Ok((capability_id.to_owned(), mode_tokens));
        }
    }
}

fn valid_slash_token(token: &str) -> bool {
    let Some(name) = token.strip_prefix('/') else {
        return false;
    };
    valid_mode_token(name)
}

fn valid_mode_token(token: &str) -> bool {
    !token.is_empty()
        && token.as_bytes()[0].is_ascii_lowercase()
        && token.bytes().all(|byte| {
            (byte as char).is_ascii_lowercase() || (byte as char).is_ascii_digit() || byte == b'-'
        })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CompactCatalogDocument {
    pub schema_version: u32,
    pub bundles: Vec<CompactCatalogDocumentEntry>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CompactCatalogDocumentEntry {
    pub id: String,
    pub source: String,
    pub manifest: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub kind: Option<String>,
    pub discoverability: Option<String>,
    #[serde(default)]
    pub host_requirement_details: Vec<HostRequirementDetail>,
    #[serde(default)]
    pub scoped_requirement_details: Vec<ScopedRequirementDetail>,
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

impl CompactCatalog {
    /// Load only the generated compact index. Capability files are not opened.
    pub fn load(
        root: impl AsRef<Path>,
        index_path: impl AsRef<Path>,
    ) -> Result<Self, CatalogError> {
        crate::discovery::load_compact(root, index_path)
    }

    pub(crate) fn new(
        root: PathBuf,
        schema_version: u32,
        mut entries: Vec<CompactCatalogEntry>,
    ) -> Result<Self, CatalogError> {
        entries.sort_by(|left, right| left.canonical_id.cmp(&right.canonical_id));
        let mut ids = BTreeSet::new();
        let mut paths = BTreeSet::new();
        for entry in &entries {
            validate_id(&entry.canonical_id)?;
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
            let mut requirement_ids = BTreeSet::new();
            for requirement in &entry.host_requirement_details {
                if !requirement_ids.insert(requirement.id.clone()) {
                    return Err(CatalogError::OwnershipCollision {
                        identity: format!(
                            "duplicate host requirement `{}` for `{}`",
                            requirement.id, entry.canonical_id
                        ),
                    });
                }
                validate_id(&requirement.id)?;
            }
        }
        Ok(Self {
            root,
            schema_version,
            entries,
        })
    }

    pub fn get(&self, id: &str) -> Option<&CompactCatalogEntry> {
        self.entries.iter().find(|entry| entry.canonical_id == id)
    }

    /// Resolve one capability body on demand and reject index paths outside its root.
    pub fn resolve_body(&self, id: &str) -> Result<Vec<u8>, CatalogError> {
        let entry = self.get(id).ok_or_else(|| CatalogError::InvalidCatalog {
            path: id.into(),
            reason: "unknown compact catalog id".into(),
        })?;
        let path = self.root.join(&entry.source_path);
        fs::read(&path).map_err(|source| CatalogError::Io { path, source })
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

#[cfg(test)]
mod explicit_command_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn fixture(aliases: &str) -> (PathBuf, CompactCatalog, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "legion-explicit-alias-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("skills")).unwrap();
        fs::write(root.join("skills/demo.md"), "body").unwrap();
        fs::write(
            root.join("index.json"),
            r#"{"schemaVersion":2,"bundles":[{"id":"demo","source":"skills/demo.md"}]}"#,
        )
        .unwrap();
        let alias_path = root.join("aliases.json");
        fs::write(&alias_path, aliases).unwrap();
        let catalog = CompactCatalog::load(&root, "index.json").unwrap();
        (root, catalog, alias_path)
    }

    #[test]
    fn resolves_exact_alias_chain_and_preserves_caller_arguments() {
        let (root, catalog, path) = fixture(
            r#"{"schemaVersion":1,"aliases":{"/outer":"/inner preflight","/inner":"/demo implementation-plan"}}"#,
        );
        let resolver = ExplicitCommandResolver::load(path, &catalog).unwrap();
        let resolved = resolver
            .resolve(&catalog, "/outer", vec!["--raw".into(), "two words".into()])
            .unwrap();
        assert_eq!(resolved.capability_id, "demo");
        assert_eq!(resolved.mode_tokens, ["preflight", "implementation-plan"]);
        assert_eq!(resolved.arguments, ["--raw", "two words"]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn accepts_canonical_command_and_rejects_invalid_maps_and_unknown_commands() {
        let (root, catalog, path) = fixture(r#"{"schemaVersion":1,"aliases":{}}"#);
        let resolver = ExplicitCommandResolver::load(&path, &catalog).unwrap();
        let canonical = resolver.resolve(&catalog, "/demo", vec![]).unwrap();
        assert_eq!(canonical.capability_id, "demo");
        assert_eq!(canonical.alias, None);
        for command in ["/clear", "plain prose", "/missing"] {
            assert!(
                resolver.resolve(&catalog, command, vec![]).is_err(),
                "{command}"
            );
        }
        fs::write(&path, r#"{"schemaVersion":1,"aliases":{"/a":"/missing"}}"#).unwrap();
        assert!(ExplicitCommandResolver::load(&path, &catalog).is_err());
        fs::write(&path, r#"{"schemaVersion":1,"aliases":{"/a":"tool:run"}}"#).unwrap();
        assert!(ExplicitCommandResolver::load(&path, &catalog).is_err());
        fs::write(&path, r#"{"schemaVersion":1,"aliases":{"/a":"hook:run"}}"#).unwrap();
        assert!(ExplicitCommandResolver::load(&path, &catalog).is_err());
        fs::write(
            &path,
            r#"{"schemaVersion":1,"aliases":{"/a":"/b","/b":"/a"}}"#,
        )
        .unwrap();
        assert!(ExplicitCommandResolver::load(&path, &catalog).is_err());
        fs::write(&path, r#"{"schemaVersion":1,"aliases":{"/a":4}}"#).unwrap();
        assert!(ExplicitCommandResolver::load(&path, &catalog).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn resolves_exact_session_mode_alias_without_merging_arguments() {
        let (root, _catalog, path) = fixture(r#"{"schemaVersion":1,"aliases":{}}"#);
        fs::create_dir_all(root.join("skills/session")).unwrap();
        fs::write(root.join("skills/session/SKILL.md"), "session body").unwrap();
        fs::write(
            root.join("index.json"),
            r#"{"schemaVersion":2,"bundles":[{"id":"session","source":"skills/session/SKILL.md"}]}"#,
        )
        .unwrap();
        let catalog = CompactCatalog::load(&root, "index.json").unwrap();
        fs::write(
            &path,
            r#"{"schemaVersion":1,"aliases":{"/status":"/session status"}}"#,
        )
        .unwrap();
        let resolver = ExplicitCommandResolver::load(path, &catalog).unwrap();
        let resolved = resolver
            .resolve(&catalog, "/status", vec!["unchanged tail".into()])
            .unwrap();
        assert_eq!(resolved.capability_id, "session");
        assert_eq!(resolved.mode_tokens, ["status"]);
        assert_eq!(resolved.arguments, ["unchanged tail"]);
        fs::remove_dir_all(root).unwrap();
    }
}
