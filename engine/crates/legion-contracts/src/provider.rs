use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    canonical_digest,
    id::{FindingId, ProviderId},
    require_version, ContractError,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderStatus {
    Ok,
    Complete,
    Partial,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub denominator_digest: String,
    pub expected: u64,
    pub examined: u64,
    pub gaps: Vec<String>,
}

impl Coverage {
    pub fn complete(&self) -> bool {
        self.expected > 0 && self.gaps.is_empty() && self.examined >= self.expected
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderSpec {
    #[serde(deserialize_with = "crate::deserialize_schema_version_2")]
    pub schema_version: u32,
    pub id: ProviderId,
    pub provider_version: String,
    pub family: String,
    #[serde(default)]
    pub lens_ids: Vec<String>,
    pub role: String,
    pub phase: String,
    pub depends_on: Vec<ProviderId>,
    pub consumes: Vec<String>,
    pub produces: Vec<String>,
    pub selector: serde_json::Value,
    pub denominator_kind: String,
    pub runner: serde_json::Value,
    pub host_capabilities: Vec<String>,
    pub execution: serde_json::Value,
    pub reasoning: serde_json::Value,
    pub benchmark: serde_json::Value,
    pub clean_claim: String,
    pub control_ids: Vec<String>,
    pub scopes: Vec<String>,
    pub selectable: bool,
}

impl ProviderSpec {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 2)?;
        for (path, value) in [
            ("providerVersion", &self.provider_version),
            ("family", &self.family),
            ("role", &self.role),
            ("phase", &self.phase),
            ("denominatorKind", &self.denominator_kind),
            ("cleanClaim", &self.clean_claim),
        ] {
            if value.trim().is_empty() {
                return Err(ContractError::InvalidContract {
                    path: path.into(),
                    reason: "must be non-empty".into(),
                });
            }
        }
        if self.lens_ids.iter().any(|lens| lens.trim().is_empty()) {
            return Err(ContractError::InvalidContract {
                path: "lensIds".into(),
                reason: "must contain only non-empty lens identifiers".into(),
            });
        }
        for (path, value) in [
            ("selector", &self.selector),
            ("runner", &self.runner),
            ("execution", &self.execution),
            ("reasoning", &self.reasoning),
            ("benchmark", &self.benchmark),
        ] {
            if !value.is_object() {
                return Err(ContractError::InvalidContract {
                    path: path.into(),
                    reason: "must be an object".into(),
                });
            }
        }
        if self
            .runner
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
        {
            return Err(ContractError::InvalidContract {
                path: "runner.kind".into(),
                reason: "must be non-empty".into(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingRef {
    pub id: FindingId,
    pub severity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderResult {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub provider: ProviderId,
    pub applicable: bool,
    pub required: bool,
    pub status: ProviderStatus,
    pub complete: bool,
    pub coverage: Option<Coverage>,
    pub findings: Vec<FindingRef>,
    pub coverage_gaps: Vec<String>,
    pub degradation: Vec<String>,
    pub details: BTreeMap<String, serde_json::Value>,
}

impl ProviderResult {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)?;
        if self.complete
            && (!self.coverage_gaps.is_empty()
                || self
                    .coverage
                    .as_ref()
                    .map(|coverage| !coverage.complete())
                    .unwrap_or(true))
        {
            return Err(ContractError::InvalidContract {
                path: "complete".into(),
                reason: "complete requires proven coverage".into(),
            });
        }
        if self.complete && !matches!(self.status, ProviderStatus::Ok | ProviderStatus::Complete) {
            return Err(ContractError::InvalidContract {
                path: "status".into(),
                reason: "failed or cancelled result cannot be complete".into(),
            });
        }
        if !matches!(self.status, ProviderStatus::Ok | ProviderStatus::Complete) {
            return Ok(());
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, crate::canonical::CanonicalError> {
        canonical_digest(self)
    }
}

pub fn topological_provider_order(
    specs: &[ProviderSpec],
) -> Result<Vec<ProviderId>, ContractError> {
    let mut by_id = BTreeMap::new();
    for spec in specs {
        spec.validate()?;
        if by_id.insert(spec.id.clone(), spec).is_some() {
            return Err(ContractError::InvalidContract {
                path: "providers.id".into(),
                reason: "duplicate provider id".into(),
            });
        }
    }
    let mut remaining: BTreeSet<ProviderId> = by_id.keys().cloned().collect();
    let mut ordered = Vec::with_capacity(specs.len());
    while !remaining.is_empty() {
        let next = remaining
            .iter()
            .find(|id| {
                by_id[*id]
                    .depends_on
                    .iter()
                    .all(|dep| ordered.contains(dep))
            })
            .cloned();
        let Some(next) = next else {
            return Err(ContractError::InvalidContract {
                path: "providers.depends_on".into(),
                reason: "cycle or missing dependency".into(),
            });
        };
        remaining.remove(&next);
        ordered.push(next);
    }
    Ok(ordered)
}
