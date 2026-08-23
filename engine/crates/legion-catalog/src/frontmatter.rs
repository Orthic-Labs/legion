use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{AgentDefinition, AgentId, BudgetCeiling, RoutingCeiling, ToolCeiling};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};

use crate::error::CatalogError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FrontmatterDocument {
    pub raw: Vec<u8>,
    pub raw_frontmatter: Option<Vec<u8>>,
    pub body: Vec<u8>,
    pub values: BTreeMap<String, JsonValue>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct AgentFrontmatter {
    #[serde(default, alias = "schemaVersion")]
    pub schema_version: u32,
    #[serde(default)]
    pub id: Option<String>,
    pub name: String,
    pub description: String,
    #[serde(default, alias = "modelCeiling", alias = "model")]
    pub model_ceiling: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub tools: ToolCeiling,
    #[serde(default)]
    pub budget: BudgetCeiling,
    #[serde(default)]
    pub routing: RoutingCeiling,
    #[serde(default, alias = "escalationGraph")]
    pub escalation_graph: Vec<String>,
    #[serde(default, alias = "forwardCompatible")]
    pub forward_compatible: bool,
    #[serde(default)]
    pub extensions: BTreeMap<String, JsonValue>,
}

impl AgentFrontmatter {
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.schema_version != 1 && self.schema_version != 2 {
            return Err(CatalogError::InvalidCatalog {
                path: "schema_version".into(),
                reason: format!("unsupported version {}", self.schema_version),
            });
        }
        if self.name.trim().is_empty() {
            return Err(CatalogError::InvalidCatalog {
                path: "name".into(),
                reason: "must be non-empty".into(),
            });
        }
        if self.description.trim().is_empty() {
            return Err(CatalogError::InvalidCatalog {
                path: "description".into(),
                reason: "must be non-empty".into(),
            });
        }
        Ok(())
    }

    /// Project a legacy definition without inventing any ceiling or authority.
    pub fn project_v1(&self, id: &str) -> Result<AgentDefinition, CatalogError> {
        if self.schema_version != 1 {
            return Err(CatalogError::InvalidCatalog {
                path: "schema_version".into(),
                reason: "v1 projection requires schema version 1".into(),
            });
        }
        let agent_id =
            AgentId::new(self.id.clone().unwrap_or_else(|| id.to_owned())).map_err(|e| {
                CatalogError::InvalidCatalog {
                    path: "id".into(),
                    reason: e.to_string(),
                }
            })?;
        AgentDefinition::new(
            agent_id,
            self.name.clone(),
            self.description.clone(),
            BudgetCeiling::default(),
            ToolCeiling::default(),
            RoutingCeiling::default(),
        )
        .map_err(|e| CatalogError::InvalidCatalog {
            path: "agent".into(),
            reason: e.to_string(),
        })
    }

    pub fn to_v2(&self, id: &str) -> Result<AgentDefinition, CatalogError> {
        self.validate()?;
        let agent_id =
            AgentId::new(self.id.clone().unwrap_or_else(|| id.to_owned())).map_err(|e| {
                CatalogError::InvalidCatalog {
                    path: "id".into(),
                    reason: e.to_string(),
                }
            })?;
        if self.schema_version == 1 {
            return self.project_v1(id);
        }
        let definition = AgentDefinition {
            schema_version: 2,
            id: agent_id,
            name: self.name.clone(),
            description: self.description.clone(),
            model_ceiling: self.model_ceiling.clone(),
            capabilities: self.capabilities.clone(),
            tools: self.tools.clone(),
            budget: self.budget.clone(),
            routing: self.routing.clone(),
            escalation_graph: self
                .escalation_graph
                .iter()
                .map(|value| AgentId::new(value.clone()))
                .collect::<Result<_, _>>()
                .map_err(|e| CatalogError::InvalidCatalog {
                    path: "escalation_graph".into(),
                    reason: e.to_string(),
                })?,
        };
        definition
            .validate()
            .map_err(|e| CatalogError::InvalidCatalog {
                path: "agent".into(),
                reason: e.to_string(),
            })?;
        Ok(definition)
    }
}

pub fn source_hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_digest(bytes))
}

pub fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Parse only the first delimiter-bounded YAML block. Body bytes are untouched.
pub fn parse(bytes: &[u8]) -> Result<FrontmatterDocument, CatalogError> {
    let Some((yaml_start, yaml_end, body_start)) = delimiters(bytes) else {
        return Ok(FrontmatterDocument {
            raw: bytes.to_vec(),
            raw_frontmatter: None,
            body: bytes.to_vec(),
            values: BTreeMap::new(),
        });
    };
    let yaml =
        std::str::from_utf8(&bytes[yaml_start..yaml_end]).map_err(|_| CatalogError::Utf8 {
            path: "frontmatter".into(),
        })?;
    let value: serde_yaml::Value = serde_yaml::from_str(yaml)?;
    let json: JsonValue = serde_json::to_value(value)?;
    let object = json
        .as_object()
        .ok_or_else(|| CatalogError::InvalidFrontmatter("frontmatter must be a mapping".into()))?;
    let values = object
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    Ok(FrontmatterDocument {
        raw: bytes.to_vec(),
        raw_frontmatter: Some(bytes[yaml_start..yaml_end].to_vec()),
        body: bytes[body_start..].to_vec(),
        values,
    })
}

pub fn parse_agent(bytes: &[u8]) -> Result<(AgentFrontmatter, FrontmatterDocument), CatalogError> {
    let document = parse(bytes)?;
    let yaml = document
        .raw_frontmatter
        .as_ref()
        .ok_or_else(|| CatalogError::InvalidFrontmatter("agent requires frontmatter".into()))?;
    let value: serde_yaml::Value = serde_yaml::from_slice(yaml)?;
    let json: JsonValue = serde_json::to_value(value)?;
    let object = json
        .as_object()
        .ok_or_else(|| CatalogError::InvalidFrontmatter("frontmatter must be a mapping".into()))?;
    let schema_version = object
        .get("schema_version")
        .or_else(|| object.get("schemaVersion"))
        .or_else(|| object.get("version"))
        .and_then(JsonValue::as_u64)
        .unwrap_or(1) as u32;
    let known: BTreeSet<&str> = [
        "schema_version",
        "schemaVersion",
        "version",
        "id",
        "name",
        "description",
        "model",
        "model_ceiling",
        "modelCeiling",
        "capabilities",
        "tools",
        "budget",
        "routing",
        "escalation_graph",
        "escalationGraph",
        "forward_compatible",
        "forwardCompatible",
        "extensions",
    ]
    .into_iter()
    .collect();
    let unknown: BTreeMap<_, _> = object
        .iter()
        .filter(|(key, _)| !known.contains(key.as_str()))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    let forward = object
        .get("forward_compatible")
        .or_else(|| object.get("forwardCompatible"))
        .and_then(JsonValue::as_bool)
        .unwrap_or(false)
        || object.get("extensions").is_some();
    if !unknown.is_empty() && !forward {
        return Err(CatalogError::InvalidFrontmatter(format!(
            "unknown fields: {}",
            unknown.keys().cloned().collect::<Vec<_>>().join(", ")
        )));
    }
    let mut known_json = json.clone();
    if let Some(mapping) = known_json.as_object_mut() {
        for key in unknown.keys() {
            mapping.remove(key);
        }
        if let Some(version) = mapping.remove("version") {
            mapping.entry("schema_version").or_insert(version);
        }
    }
    let mut agent: AgentFrontmatter = serde_json::from_value(known_json)?;
    agent.schema_version = schema_version;
    if forward {
        agent.extensions.extend(unknown);
    }
    agent.forward_compatible = forward;
    agent.validate()?;
    Ok((agent, document))
}

fn delimiters(bytes: &[u8]) -> Option<(usize, usize, usize)> {
    let (first_end, first_line) = line(bytes, 0)?;
    if trim_cr(first_line) != b"---" {
        return None;
    }
    let mut cursor = first_end;
    while cursor < bytes.len() {
        let (next, current) = line(bytes, cursor)?;
        if trim_cr(current) == b"---" {
            return Some((first_end, cursor, next));
        }
        cursor = next;
    }
    None
}

fn line(bytes: &[u8], start: usize) -> Option<(usize, &[u8])> {
    if start >= bytes.len() {
        return None;
    }
    let end = bytes[start..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|offset| start + offset + 1)
        .unwrap_or(bytes.len());
    Some((end, &bytes[start..end]))
}

fn trim_cr(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n")
        .unwrap_or(line)
        .strip_suffix(b"\r")
        .unwrap_or_else(|| line.strip_suffix(b"\n").unwrap_or(line))
}
