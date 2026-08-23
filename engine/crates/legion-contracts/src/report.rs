use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::{
    canonical_digest,
    id::{FindingId, ReportId},
    require_version, ContractError,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub id: FindingId,
    pub severity: String,
    pub title: String,
    pub message: String,
    pub provider: Option<String>,
    pub locations: Vec<String>,
    pub evidence: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportStatus {
    Clean,
    Findings,
    Incomplete,
    Failed,
    Blocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Report {
    #[serde(deserialize_with = "crate::deserialize_schema_version_1")]
    pub schema_version: u32,
    pub report_id: ReportId,
    pub status: ReportStatus,
    pub findings: Vec<Finding>,
    pub gaps: Vec<String>,
    pub claims: BTreeMap<String, serde_json::Value>,
    pub targets: Vec<String>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, serde_json::Value>,
}

impl Report {
    pub fn validate(&self) -> Result<(), ContractError> {
        require_version(self.schema_version, 1)?;
        let mut ids = std::collections::BTreeSet::new();
        for finding in &self.findings {
            if !ids.insert(&finding.id) {
                return Err(ContractError::InvalidContract {
                    path: "findings.id".into(),
                    reason: "duplicate finding id".into(),
                });
            }
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String, crate::canonical::CanonicalError> {
        canonical_digest(self)
    }
}
