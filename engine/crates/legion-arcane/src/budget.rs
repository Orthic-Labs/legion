use crate::error::ArcaneError;
use crate::key_ring::KeyRing;
use crate::receipt_auth::verify_record;
use crate::state_paths::state_file;
use serde_json::{json, Map, Value};
use std::path::{Path, PathBuf};

pub const BUDGET_BOUND_FIELDS: [&str; 11] = [
    "schemaVersion",
    "kind",
    "contractId",
    "version",
    "contractDigest",
    "objectiveLineageId",
    "objectiveDigest",
    "legionBlastMapCapMs",
    "sagePlanningCapMs",
    "maxContractVersions",
    "resumeEvidence",
];

pub const AMENDED_BUDGET_BOUND_FIELDS: [&str; 13] = [
    "schemaVersion",
    "kind",
    "contractId",
    "version",
    "contractDigest",
    "objectiveLineageId",
    "objectiveDigest",
    "legionBlastMapCapMs",
    "sagePlanningCapMs",
    "maxContractVersions",
    "resumeEvidence",
    "amendmentEvidence",
    "userScopeExpansionEvidence",
];

pub const TASK_BUDGET_SEAL_BOUND_FIELDS: [&str; 13] = [
    "schemaVersion",
    "kind",
    "contractId",
    "contractVersion",
    "contractDigest",
    "taskId",
    "taskDigest",
    "scopeDigest",
    "activeTimeCapMs",
    "progressDeadlineMs",
    "evidenceReferences",
    "sealedBy",
    "sealedAt",
];
pub const BUDGET_AMENDMENT_BOUND_FIELDS: [&str; 11] = [
    "schemaVersion",
    "kind",
    "priorContractDigest",
    "newContractDigest",
    "priorLegionBlastMapCapMs",
    "newLegionBlastMapCapMs",
    "priorSagePlanningCapMs",
    "newSagePlanningCapMs",
    "scopeExpanded",
    "invocationProofDigest",
    "observedAt",
];

pub struct BudgetGovernanceStore {
    root: PathBuf,
    key_ring: KeyRing,
}

pub struct TaskBudgetSealStore {
    root: PathBuf,
    key_ring: KeyRing,
}

impl BudgetGovernanceStore {
    pub fn new(root: PathBuf, key_ring: KeyRing) -> Self {
        Self { root, key_ring }
    }

    pub fn require(&self, contract_id: &str, version: u32) -> Result<Value, ArcaneError> {
        let path = state_file(
            &self.root,
            "arcane.budget-governance.v1",
            &[contract_id.to_owned(), version.to_string()],
        )?;
        self.read_budget(&path)
    }

    pub fn seal(&self, budget: &Value) -> Result<Value, ArcaneError> {
        validate_budget(budget)?;
        let amended = budget.get("amendmentEvidence").is_some();
        let fields = if amended {
            AMENDED_BUDGET_BOUND_FIELDS.as_slice()
        } else {
            BUDGET_BOUND_FIELDS.as_slice()
        };
        let auth = budget.get("authentication");
        let checked = verify_record(
            budget,
            auth,
            &self.key_ring,
            fields,
            &Map::new(),
            Some("arcane-budget-governance-v1"),
        )?;
        if !checked.allowed {
            return Err(ArcaneError::typed(
                checked.code.unwrap_or("ARC_AUTH_FORGED"),
                checked
                    .message
                    .unwrap_or_else(|| "budget authentication failed".into()),
            ));
        }
        std::fs::create_dir_all(&self.root).map_err(|e| ArcaneError::Io(e.to_string()))?;
        let path = state_file(
            &self.root,
            "arcane.budget-governance.v1",
            &[
                budget["contractId"].as_str().unwrap_or_default().into(),
                budget["version"].as_u64().unwrap_or_default().to_string(),
            ],
        )?;
        write_immutable(&path, budget)
    }

    fn read_budget(&self, path: &Path) -> Result<Value, ArcaneError> {
        let bytes = std::fs::read(path).map_err(|error| ArcaneError::Io(error.to_string()))?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| ArcaneError::typed("ARC_STORE_CORRUPT", "unreadable stored budget"))?;
        if value.get("kind").and_then(Value::as_str) != Some("arcane-budget-governance") {
            return Err(ArcaneError::typed(
                "ARC_STORE_CORRUPT",
                "invalid stored budget",
            ));
        }
        let bound_fields = if value.get("amendmentEvidence").is_some() {
            AMENDED_BUDGET_BOUND_FIELDS.as_slice()
        } else {
            BUDGET_BOUND_FIELDS.as_slice()
        };
        let auth = value.get("authentication");
        let decision = verify_record(
            &value,
            auth,
            &self.key_ring,
            bound_fields,
            &Map::new(),
            Some("arcane-budget-governance-v1"),
        )?;
        if !decision.allowed {
            return Err(ArcaneError::typed(
                decision.code.unwrap_or("ARC_STORE_CORRUPT"),
                decision
                    .message
                    .unwrap_or_else(|| "stored budget authentication failed".into()),
            ));
        }
        Ok(value)
    }
}

impl TaskBudgetSealStore {
    pub fn new(root: PathBuf, key_ring: KeyRing) -> Self {
        Self { root, key_ring }
    }

    /// Node `budget inspect` calls `require(contractId, taskId)` without a version,
    /// which resolves the legacy `undefined` contract-version segment.
    pub fn require(&self, contract_id: &str, task_id: &str) -> Result<Value, ArcaneError> {
        self.require_version(contract_id, task_id, "undefined")
    }

    pub fn require_version(
        &self,
        contract_id: &str,
        task_id: &str,
        contract_version: &str,
    ) -> Result<Value, ArcaneError> {
        let path = state_file(
            &self.root,
            "arcane.task-budget-seal.v1",
            &[
                contract_id.to_owned(),
                task_id.to_owned(),
                contract_version.to_owned(),
            ],
        )?;
        self.read_seal(&path)
    }

    pub fn seal(&self, record: &Value) -> Result<Value, ArcaneError> {
        validate_task_budget(record)?;
        let checked = verify_record(
            record,
            record.get("authentication"),
            &self.key_ring,
            &TASK_BUDGET_SEAL_BOUND_FIELDS,
            &Map::new(),
            Some("arcane-task-budget-seal-v1"),
        )?;
        if !checked.allowed {
            return Err(ArcaneError::typed(
                checked.code.unwrap_or("ARC_AUTH_FORGED"),
                checked
                    .message
                    .unwrap_or_else(|| "task budget authentication failed".into()),
            ));
        }
        std::fs::create_dir_all(&self.root).map_err(|e| ArcaneError::Io(e.to_string()))?;
        let path = state_file(
            &self.root,
            "arcane.task-budget-seal.v1",
            &[
                record["contractId"].as_str().unwrap_or_default().into(),
                record["taskId"].as_str().unwrap_or_default().into(),
                record["contractVersion"]
                    .as_u64()
                    .unwrap_or_default()
                    .to_string(),
            ],
        )?;
        write_immutable(&path, record)
    }

    fn read_seal(&self, path: &Path) -> Result<Value, ArcaneError> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(ArcaneError::typed(
                    "ARC_STORE_MISSING",
                    "no task budget seal",
                ));
            }
            Err(error) => return Err(ArcaneError::Io(error.to_string())),
        };
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| ArcaneError::typed("ARC_STORE_CORRUPT", "unreadable task budget seal"))?;
        if value.get("kind").and_then(Value::as_str) != Some("arcane-task-budget-seal") {
            return Err(ArcaneError::typed(
                "ARC_STORE_CORRUPT",
                "invalid task budget seal",
            ));
        }
        let auth = value.get("authentication");
        let decision = verify_record(
            &value,
            auth,
            &self.key_ring,
            TASK_BUDGET_SEAL_BOUND_FIELDS.as_slice(),
            &Map::new(),
            Some("arcane-task-budget-seal-v1"),
        )?;
        if !decision.allowed {
            return Err(ArcaneError::typed(
                decision.code.unwrap_or("ARC_STORE_CORRUPT"),
                decision
                    .message
                    .unwrap_or_else(|| "task budget seal authentication failed".into()),
            ));
        }
        Ok(value)
    }
}

fn write_immutable(path: &Path, value: &Value) -> Result<Value, ArcaneError> {
    let bytes = [
        legion_contracts::canonical_json_bytes(value)?,
        vec![b'\n'],
    ]
    .concat();
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
    {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(&bytes)
                .map_err(|e| ArcaneError::Io(e.to_string()))?;
            file.sync_all()
                .map_err(|e| ArcaneError::Io(e.to_string()))?;
            Ok(value.clone())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing: Value = serde_json::from_slice(
                &std::fs::read(path).map_err(|x| ArcaneError::Io(x.to_string()))?,
            )
            .map_err(|x| ArcaneError::typed("ARC_STORE_CORRUPT", x.to_string()))?;
            if existing == *value {
                Ok(existing)
            } else {
                Err(ArcaneError::typed(
                    "ARC_CONTRACT_VERSION_MISMATCH",
                    "immutable budget conflicts",
                ))
            }
        }
        Err(e) => Err(ArcaneError::Io(e.to_string())),
    }
}

fn validate_budget(value: &Value) -> Result<(), ArcaneError> {
    let o = value
        .as_object()
        .ok_or_else(|| ArcaneError::typed("ARC_SCHEMA_INVALID", "invalid budget binding"))?;
    for k in [
        "schemaVersion",
        "kind",
        "contractId",
        "version",
        "contractDigest",
        "objectiveLineageId",
        "objectiveDigest",
        "legionBlastMapCapMs",
        "sagePlanningCapMs",
        "maxContractVersions",
        "resumeEvidence",
        "authentication",
    ] {
        if !o.contains_key(k) {
            return Err(ArcaneError::typed(
                "ARC_SCHEMA_INVALID",
                format!("invalid budget binding: missing {k}"),
            ));
        }
    }
    if o["schemaVersion"] != 1
        || o["kind"] != "arcane-budget-governance"
        || o["version"].as_u64().unwrap_or(0) < 1
        || o["maxContractVersions"] != 2
    {
        return Err(ArcaneError::typed(
            "ARC_SCHEMA_INVALID",
            "invalid budget binding",
        ));
    }
    Ok(())
}

fn validate_task_budget(value: &Value) -> Result<(), ArcaneError> {
    let o = value
        .as_object()
        .ok_or_else(|| ArcaneError::typed("ARC_SCHEMA_INVALID", "invalid task budget seal"))?;
    for k in [
        "schemaVersion",
        "kind",
        "contractId",
        "contractVersion",
        "contractDigest",
        "taskId",
        "taskDigest",
        "scopeDigest",
        "activeTimeCapMs",
        "progressDeadlineMs",
        "evidenceReferences",
        "sealedBy",
        "sealedAt",
        "authentication",
    ] {
        if !o.contains_key(k) {
            return Err(ArcaneError::typed(
                "ARC_SCHEMA_INVALID",
                format!("invalid task budget seal: missing {k}"),
            ));
        }
    }
    if o["schemaVersion"] != 1
        || o["kind"] != "arcane-task-budget-seal"
        || o["contractVersion"].as_u64().unwrap_or(0) < 1
        || o["activeTimeCapMs"].as_u64().unwrap_or(0) < 1
        || o["progressDeadlineMs"].as_u64().unwrap_or(0) < 1
        || o["evidenceReferences"]
            .as_array()
            .map_or(true, |a| a.is_empty())
    {
        return Err(ArcaneError::typed(
            "ARC_SCHEMA_INVALID",
            "invalid task budget seal",
        ));
    }
    Ok(())
}

pub fn inspect_projection(
    _contract_id: &str,
    _version: u32,
    _task_id: &str,
    _run_id: Option<&str>,
) -> Value {
    json!({
        "allowed": true,
        "events": [],
        "stopped": null,
    })
}
