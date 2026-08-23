use crate::error::HostError;
use legion_contracts::HostDescriptor as ContractHostDescriptor;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionRule {
    #[serde(default)]
    pub any_of: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mechanism {
    pub kind: String,
    pub path: Option<String>,
    pub table: Option<String>,
    pub key: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SurfaceDescriptor {
    pub fidelity: String,
    pub mechanism: Mechanism,
    pub note: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HostDescriptor {
    pub schema_version: u32,
    pub kind: String,
    pub id: String,
    pub display_name: String,
    pub install_owner: String,
    #[serde(default)]
    pub detect: DetectionRule,
    #[serde(default)]
    pub surfaces: BTreeMap<String, SurfaceDescriptor>,
}

impl HostDescriptor {
    pub fn validate(&self) -> Result<(), HostError> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(HostError::InvalidDescriptor {
                path: "schemaVersion".into(),
                reason: format!("unsupported version {}", self.schema_version),
            });
        }
        if self.kind != "legion-host-descriptor" {
            return Err(HostError::InvalidDescriptor {
                path: "kind".into(),
                reason: "must be legion-host-descriptor".into(),
            });
        }
        non_empty("id", &self.id)?;
        non_empty("displayName", &self.display_name)?;
        if !matches!(
            self.install_owner.as_str(),
            "adapter" | "plugin" | "external"
        ) {
            return Err(HostError::InvalidDescriptor {
                path: "installOwner".into(),
                reason: "must be adapter, plugin, or external".into(),
            });
        }
        for value in self.detect.any_of.iter().chain(self.detect.env.iter()) {
            non_empty("detect", value)?;
        }
        for (surface, descriptor) in &self.surfaces {
            if !matches!(
                surface.as_str(),
                "instructions" | "skills" | "agents" | "mcp" | "hooks"
            ) {
                return Err(HostError::InvalidDescriptor {
                    path: format!("surfaces.{surface}"),
                    reason: "unknown surface".into(),
                });
            }
            if !matches!(
                descriptor.fidelity.as_str(),
                "strong" | "degraded" | "unsupported"
            ) {
                return Err(HostError::InvalidDescriptor {
                    path: format!("surfaces.{surface}.fidelity"),
                    reason: "invalid fidelity".into(),
                });
            }
            non_empty(
                &format!("surfaces.{surface}.mechanism.kind"),
                &descriptor.mechanism.kind,
            )?;
            if let Some(path) = &descriptor.mechanism.path {
                non_empty("mechanism.path", path)?;
            }
        }
        Ok(())
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, HostError> {
        let descriptor: Self = serde_json::from_slice(bytes)?;
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub fn contract_view(&self) -> Result<ContractHostDescriptor, HostError> {
        let host_id = self
            .id
            .parse::<legion_contracts::id::HostId>()
            .map_err(|error| HostError::InvalidDescriptor {
                path: "id".into(),
                reason: error.to_string(),
            })?;
        Ok(ContractHostDescriptor {
            schema_version: 1,
            host_id,
            platform: self.id.clone(),
            version: self.schema_version.to_string(),
            surfaces: Vec::new(),
            capabilities: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct DescriptorRegistry {
    descriptors: BTreeMap<String, HostDescriptor>,
}

impl DescriptorRegistry {
    pub fn new(values: impl IntoIterator<Item = HostDescriptor>) -> Result<Self, HostError> {
        let mut descriptors = BTreeMap::new();
        for value in values {
            value.validate()?;
            if descriptors.insert(value.id.clone(), value).is_some() {
                return Err(HostError::OwnershipCollision {
                    path: "id".into(),
                    reason: "duplicate host descriptor".into(),
                });
            }
        }
        Ok(Self { descriptors })
    }
    pub fn lookup(&self, id: &str) -> Result<&HostDescriptor, HostError> {
        self.descriptors
            .get(id)
            .ok_or_else(|| HostError::SourceDrift {
                path: format!("descriptor:{id}"),
                reason: "host descriptor not found".into(),
            })
    }
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.descriptors.keys().map(String::as_str)
    }
}

fn non_empty(path: &str, value: &str) -> Result<(), HostError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(HostError::InvalidDescriptor {
            path: path.into(),
            reason: "must be non-empty and free of control characters".into(),
        })
    } else {
        Ok(())
    }
}

pub fn deterministic_lookup<'a>(
    descriptors: &'a [HostDescriptor],
    id: &str,
) -> Result<&'a HostDescriptor, HostError> {
    descriptors
        .iter()
        .filter(|descriptor| descriptor.id == id)
        .min_by(|left, right| left.id.cmp(&right.id))
        .ok_or_else(|| HostError::SourceDrift {
            path: format!("descriptor:{id}"),
            reason: "host descriptor not found".into(),
        })
}
