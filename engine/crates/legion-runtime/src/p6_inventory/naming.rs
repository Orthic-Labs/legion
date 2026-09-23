//! Port of `src/lib/naming/registry.mjs` and `src/lib/naming/migrations.mjs`.
//!
//! `src/lib/naming/check.mjs` (the whole-repository naming lint CLI) and
//! `src/lib/naming/index.mjs` (a pure re-export barrel) are intentionally
//! NOT ported here; see the P6 packet report.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;

use serde_json::Value;

#[derive(Debug)]
pub enum NamingRegistryError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Invalid(&'static str),
}

impl fmt::Display for NamingRegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NamingRegistryError::Io(err) => write!(f, "failed to read naming registry: {err}"),
            NamingRegistryError::Json(err) => write!(f, "invalid naming registry JSON: {err}"),
            NamingRegistryError::Invalid(msg) => write!(f, "invalid Legion naming registry: {msg}"),
        }
    }
}

impl std::error::Error for NamingRegistryError {}

impl From<std::io::Error> for NamingRegistryError {
    fn from(err: std::io::Error) -> Self {
        NamingRegistryError::Io(err)
    }
}

impl From<serde_json::Error> for NamingRegistryError {
    fn from(err: serde_json::Error) -> Self {
        NamingRegistryError::Json(err)
    }
}

/// The parsed `config/naming-registry.json` document, kept as a generic
/// JSON value (mirroring the JS `Object.freeze(registry)` behaviour: the
/// data is opaque configuration, not a fixed Rust schema).
#[derive(Debug, Clone)]
pub struct NamingRegistry(pub Value);

/// Port of `loadNamingRegistry` in `src/lib/naming/registry.mjs`.
pub fn load_naming_registry(path: &Path) -> Result<NamingRegistry, NamingRegistryError> {
    let raw = fs::read_to_string(path)?;
    let registry: Value = serde_json::from_str(&raw)?;

    let schema_version_ok = registry.get("schemaVersion").and_then(Value::as_i64) == Some(1);
    let product_id_ok = registry
        .get("product")
        .and_then(|p| p.get("id"))
        .and_then(Value::as_str)
        == Some("legion");

    if !schema_version_ok || !product_id_ok {
        return Err(NamingRegistryError::Invalid(
            "schemaVersion must be 1 and product.id must be 'legion'",
        ));
    }

    Ok(NamingRegistry(registry))
}

/// Port of `authorityAliases`: `{ aliasId: canonicalAuthorityId }`.
pub fn authority_aliases(registry: &NamingRegistry) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Some(authorities) = registry.0.get("authorities").and_then(Value::as_object) {
        for (canonical, value) in authorities {
            if let Some(aliases) = value.get("aliases").and_then(Value::as_array) {
                for alias in aliases {
                    if let Some(id) = alias.get("id").and_then(Value::as_str) {
                        out.insert(id.to_string(), canonical.clone());
                    }
                }
            }
        }
    }
    out
}

/// Port of `canonicalAuthority`.
pub fn canonical_authority(value: &str, registry: &NamingRegistry) -> String {
    let normalized = value.trim().to_lowercase().replace('_', "-");
    authority_aliases(registry)
        .get(&normalized)
        .cloned()
        .unwrap_or(normalized)
}

/// Port of `canonicalProduct`.
pub fn canonical_product(value: &str, registry: &NamingRegistry) -> String {
    let normalized = value.trim().to_lowercase();
    let is_legacy = registry
        .0
        .get("product")
        .and_then(|p| p.get("legacyIds"))
        .and_then(Value::as_array)
        .map(|ids| {
            ids.iter()
                .any(|entry| entry.get("id").and_then(Value::as_str) == Some(normalized.as_str()))
        })
        .unwrap_or(false);

    if is_legacy {
        registry
            .0
            .get("product")
            .and_then(|p| p.get("id"))
            .and_then(Value::as_str)
            .unwrap_or("legion")
            .to_string()
    } else {
        normalized
    }
}

/// Port of `canonicalAuthorityIds`: sorted authority ids.
pub fn canonical_authority_ids(registry: &NamingRegistry) -> Vec<String> {
    let mut ids: Vec<String> = registry
        .0
        .get("authorities")
        .and_then(Value::as_object)
        .map(|obj| obj.keys().cloned().collect())
        .unwrap_or_default();
    ids.sort();
    ids
}

const AUTHORITY_FIELDS: &[&str] = &[
    "authority",
    "assignedAuthority",
    "producerAuthority",
    "requestedBy",
    "claimingAuthority",
    "callerAuthority",
    "observedAuthority",
    "executionAuthority",
    "waiverAuthority",
    "riskAuthority",
    "acceptedRiskAuthority",
    "decision_authority",
    "actor_role",
    "role",
];

const AUTHORITY_ARRAY_FIELDS: &[&str] = &["authoritiesInvolved"];

/// Port of `canonicalizeAuthorityRecord`: recursively rewrites known
/// authority-bearing fields (and array items) to their canonical ids.
pub fn canonicalize_authority_record(value: &Value, registry: &NamingRegistry) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, val) in map {
                let new_val = if AUTHORITY_FIELDS.contains(&key.as_str()) {
                    if let Some(s) = val.as_str() {
                        Value::String(canonical_authority(s, registry))
                    } else {
                        canonicalize_authority_record(val, registry)
                    }
                } else if AUTHORITY_ARRAY_FIELDS.contains(&key.as_str()) {
                    if let Some(arr) = val.as_array() {
                        Value::Array(
                            arr.iter()
                                .map(|item| {
                                    if let Some(s) = item.as_str() {
                                        Value::String(canonical_authority(s, registry))
                                    } else {
                                        canonicalize_authority_record(item, registry)
                                    }
                                })
                                .collect(),
                        )
                    } else {
                        canonicalize_authority_record(val, registry)
                    }
                } else if let Some(arr) = val.as_array() {
                    Value::Array(
                        arr.iter()
                            .map(|item| canonicalize_authority_record(item, registry))
                            .collect(),
                    )
                } else {
                    canonicalize_authority_record(val, registry)
                };
                out.insert(key.clone(), new_val);
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

pub const NAMING_SCHEMA_VERSION: u64 = 3;

fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::with_capacity(map.len());
            for key in keys {
                out.insert(key.clone(), canonical_value(&map[key]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Port of `equivalentMcpBinding`: deep-equal via canonical (key-sorted)
/// JSON serialization.
pub fn equivalent_mcp_binding(left: &Value, right: &Value) -> bool {
    canonical_value(left) == canonical_value(right)
}

/// Port of `isLegionOwnedAssuranceBinding`.
pub fn is_legion_owned_assurance_binding(entry: &Value) -> bool {
    let command_ok = matches!(
        entry.get("command").and_then(Value::as_str),
        Some("python") | Some("python3")
    );
    let Some(args) = entry.get("args").and_then(Value::as_array) else {
        return false;
    };
    if !command_ok {
        return false;
    }
    let args_str: Vec<Option<&str>> = args.iter().map(Value::as_str).collect();
    args_str
        .iter()
        .position(|a| *a == Some("-m"))
        .map(|idx| args_str.get(idx + 1) == Some(&Some("legion_kernel.adapters.mcp_server")))
        .unwrap_or(false)
}

fn oracle_legacy_alias_id(registry: &NamingRegistry) -> Option<String> {
    let authorities = registry.0.get("authorities")?.as_object()?;
    for value in authorities.values() {
        if value.get("displayName").and_then(Value::as_str) == Some("Oracle") {
            let alias = value.get("aliases")?.as_array()?.first()?;
            return alias.get("id")?.as_str().map(str::to_string);
        }
    }
    None
}

/// Port of `migrateMcpServers`.
pub fn migrate_mcp_servers(input: &Value, registry: &NamingRegistry) -> Value {
    let mut output = input.clone();
    let obj = match output.as_object_mut() {
        Some(obj) => obj,
        None => return Value::Object(serde_json::Map::new()),
    };

    let container_key = if obj.get("mcp_servers").is_some_and(Value::is_object) {
        Some("mcp_servers")
    } else if obj.get("mcpServers").is_some_and(Value::is_object) {
        Some("mcpServers")
    } else {
        None
    };

    let Some(container_key) = container_key else {
        return output;
    };

    let Some(legacy_id) = oracle_legacy_alias_id(registry) else {
        return output;
    };

    let servers = obj.get_mut(container_key).unwrap();
    let servers_obj = servers.as_object_mut().unwrap();

    if !servers_obj.contains_key(&legacy_id) {
        return output;
    }
    let legacy = servers_obj.get(&legacy_id).unwrap().clone();
    if !is_legion_owned_assurance_binding(&legacy) {
        return output;
    }

    if !servers_obj.contains_key("oracle") {
        servers_obj.insert("oracle".to_string(), legacy);
        servers_obj.remove(&legacy_id);
    } else if equivalent_mcp_binding(servers_obj.get("oracle").unwrap(), &legacy) {
        servers_obj.remove(&legacy_id);
    }

    output
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpNamingLegacyEntry {
    pub id: String,
    pub owned: bool,
    pub conflict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpNamingStatus {
    pub status: &'static str, // "absent" | "legacy-present" | "canonical"
    pub legacy: Vec<McpNamingLegacyEntry>,
}

/// Port of `inspectMcpNaming`.
pub fn inspect_mcp_naming(input: &Value, registry: &NamingRegistry) -> McpNamingStatus {
    let servers = input
        .get("mcp_servers")
        .or_else(|| input.get("mcpServers"))
        .and_then(Value::as_object);

    let Some(servers) = servers else {
        return McpNamingStatus {
            status: "absent",
            legacy: Vec::new(),
        };
    };

    let legacy_ids: Vec<String> = registry
        .0
        .get("authorities")
        .and_then(Value::as_object)
        .map(|authorities| {
            authorities
                .values()
                .flat_map(|value| {
                    value
                        .get("aliases")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(|alias| alias.get("id").and_then(Value::as_str))
                        .map(str::to_string)
                })
                .collect()
        })
        .unwrap_or_default();

    let legacy: Vec<McpNamingLegacyEntry> = legacy_ids
        .into_iter()
        .filter(|id| servers.contains_key(id))
        .map(|id| {
            let entry = servers.get(&id).unwrap();
            let owned = is_legion_owned_assurance_binding(entry);
            let canonical = canonical_authority(&id, registry);
            let conflict = servers.contains_key(&canonical)
                && !equivalent_mcp_binding(entry, servers.get(&canonical).unwrap());
            McpNamingLegacyEntry {
                id,
                owned,
                conflict,
            }
        })
        .collect();

    McpNamingStatus {
        status: if legacy.is_empty() {
            "canonical"
        } else {
            "legacy-present"
        },
        legacy,
    }
}

pub type MigrationFn = fn(&Value, &NamingRegistry) -> Value;

pub struct NamedMigration {
    pub id: &'static str,
    pub apply: MigrationFn,
}

fn migration_v001(state: &Value, registry: &NamingRegistry) -> Value {
    let mut next = state.clone();
    if let Some(obj) = next.as_object_mut() {
        if let Some(Value::String(product)) = obj.get("product") {
            let canonical = canonical_product(product, registry);
            obj.insert("product".to_string(), Value::String(canonical));
        }
    }
    next
}

fn migration_v002(state: &Value, registry: &NamingRegistry) -> Value {
    let canonicalized = canonicalize_authority_record(state, registry);
    migrate_mcp_servers(&canonicalized, registry)
}

fn migration_v003(state: &Value, registry: &NamingRegistry) -> Value {
    canonicalize_authority_record(state, registry)
}

/// Port of `MIGRATIONS` in `src/lib/naming/migrations.mjs`.
pub const MIGRATIONS: &[NamedMigration] = &[
    NamedMigration {
        id: "v001_product_namespace_to_legion",
        apply: migration_v001,
    },
    NamedMigration {
        id: "v002_assurance_alias_to_oracle",
        apply: migration_v002,
    },
    NamedMigration {
        id: "v003_authority_alias_normalization",
        apply: migration_v003,
    },
];

/// Port of `migrateNamingState`.
pub fn migrate_naming_state(input: &Value, registry: &NamingRegistry) -> Value {
    let mut current = input.clone();
    if current.is_null() {
        current = Value::Object(serde_json::Map::new());
    }

    let prior_applied: BTreeSet<String> = current
        .get("namingMigration")
        .and_then(|m| m.get("applied"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let mut applied = prior_applied;
    for migration in MIGRATIONS {
        current = (migration.apply)(&current, registry);
        applied.insert(migration.id.to_string());
    }

    let mut applied_sorted: Vec<String> = applied.into_iter().collect();
    applied_sorted.sort();

    if let Some(obj) = current.as_object_mut() {
        obj.insert(
            "namingMigration".to_string(),
            serde_json::json!({
                "schemaVersion": NAMING_SCHEMA_VERSION,
                "applied": applied_sorted,
            }),
        );
    }

    current
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamingMigrationStatus {
    pub schema_version: u64,
    pub current: bool,
    pub applied: Vec<String>,
    pub canonical: bool,
}

/// Port of `namingMigrationStatus`.
pub fn naming_migration_status(input: &Value, registry: &NamingRegistry) -> NamingMigrationStatus {
    let migrated = migrate_naming_state(input, registry);

    let current = input
        .get("namingMigration")
        .and_then(|m| m.get("schemaVersion"))
        .and_then(Value::as_u64)
        == Some(NAMING_SCHEMA_VERSION);

    let applied: Vec<String> = migrated
        .get("namingMigration")
        .and_then(|m| m.get("applied"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();

    let twice_migrated = migrate_naming_state(&migrated, registry);
    let canonical = canonical_value(&migrated) == canonical_value(&twice_migrated);

    NamingMigrationStatus {
        schema_version: NAMING_SCHEMA_VERSION,
        current,
        applied,
        canonical,
    }
}

/// Port of `canonicalSerializedAuthority` (defaults to loading the registry
/// via the caller-supplied `registry`, unlike the JS default-argument
/// version which reloads from disk).
pub fn canonical_serialized_authority(value: &str, registry: &NamingRegistry) -> String {
    canonical_authority(value, registry)
}
