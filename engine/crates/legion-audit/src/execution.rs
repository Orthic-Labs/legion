use std::collections::{BTreeMap, BTreeSet};

use legion_contracts::{ProviderId, ProviderResult, ProviderStatus};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    error::AuditError,
    inventory::InventoryEnvelope,
    plan::{AuditProvider, FrozenPlan},
};

pub trait ProviderExecutor: Send + Sync {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError>;
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProviderExecution {
    pub provider: String,
    pub result: ProviderResult,
    pub skipped: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionReport {
    pub plan_digest: String,
    pub plan_signature: Option<String>,
    pub generation: String,
    pub inventory_digest: String,
    pub planned_providers: Vec<String>,
    pub results: Vec<ProviderExecution>,
    pub selected_lenses: Vec<String>,
    pub lenses_ran: Vec<String>,
    pub gaps: Vec<String>,
}

fn provider_id(value: &str) -> Result<ProviderId, AuditError> {
    ProviderId::new(value).map_err(AuditError::from)
}

pub fn execute(
    plan: &FrozenPlan,
    inventory: &InventoryEnvelope,
    executor: &dyn ProviderExecutor,
) -> Result<ExecutionReport, AuditError> {
    inventory.validate()?;
    if inventory.repository_id != plan.plan().repository_id
        || inventory.generation != plan.plan().inventory_generation
        || inventory.digest != plan.plan().inventory_digest
    {
        return Err(AuditError::SourceDrift(
            "inventory no longer matches frozen plan".into(),
        ));
    }
    let mut completed = BTreeSet::new();
    let mut failed = BTreeSet::new();
    let mut results = Vec::new();
    let mut gaps = Vec::new();
    let mut selected_lenses = plan
        .providers()
        .iter()
        .flat_map(|provider| provider.lens_ids.iter().cloned())
        .collect::<Vec<_>>();
    selected_lenses.sort();
    selected_lenses.dedup();
    let mut lenses_ran = Vec::new();
    let planned_providers = plan
        .providers()
        .iter()
        .map(|provider| provider.id.clone())
        .collect::<Vec<_>>();
    let candidate_denominators = plan
        .providers()
        .iter()
        .filter(|provider| provider.role == "candidate-generator")
        .map(|provider| {
            let selector = provider.configuration.get("selector").ok_or_else(|| {
                AuditError::Invalid(format!("provider {} is missing selector", provider.id))
            })?;
            inventory.denominator_entries(selector)
        })
        .collect::<Result<Vec<_>, _>>()?;
    for provider in plan.providers() {
        // Readiness is success of every dependency, not merely absence from
        // the failure set. This also blocks transitive dependents after a
        // skipped provider and keeps the frozen topological order intact.
        let blocked = provider
            .dependencies
            .iter()
            .any(|dependency| !completed.contains(dependency) || failed.contains(dependency));
        let execution = if blocked {
            let gap = format!("dependency-failed:{}", provider.id);
            gaps.push(gap.clone());
            failed.insert(provider.id.clone());
            failed_execution(provider, gap, "skipped-after-dependency-failure", true)?
        } else {
            match executor.execute(provider, inventory) {
                Ok(result) => {
                    let denominator =
                        provider_denominator(provider, inventory, &candidate_denominators)?;
                    let result_error = result
                        .validate()
                        .err()
                        .map(|error| error.to_string())
                        .or_else(|| {
                            (result.provider.to_string() != provider.id)
                                .then(|| "provider result identity mismatch".to_owned())
                        })
                        .or_else(|| {
                            (result.required != provider.required)
                                .then(|| "provider result required flag mismatch".to_owned())
                        })
                        .or_else(|| {
                            (!result.applicable)
                                .then(|| "selected provider reported not applicable".to_owned())
                        })
                        .or_else(|| validate_result(provider, &result, &denominator).err());
                    if let Some(error) = result_error {
                        let gap = format!("invalid-provider-result:{}:{error}", provider.id);
                        gaps.push(gap.clone());
                        failed.insert(provider.id.clone());
                        results.push(failed_execution(
                            provider,
                            gap,
                            "invalid-provider-result",
                            false,
                        )?);
                        continue;
                    }
                    if result.complete
                        && matches!(result.status, ProviderStatus::Ok | ProviderStatus::Complete)
                    {
                        completed.insert(provider.id.clone());
                        lenses_ran.extend(provider.lens_ids.iter().cloned());
                    } else {
                        failed.insert(provider.id.clone());
                        gaps.push(format!("provider-incomplete:{}", provider.id));
                        gaps.extend(result.coverage_gaps.iter().cloned());
                    }
                    ProviderExecution {
                        provider: provider.id.clone(),
                        result,
                        skipped: false,
                    }
                }
                Err(error) => {
                    failed.insert(provider.id.clone());
                    let gap = error.to_string();
                    gaps.push(gap.clone());
                    failed_execution(provider, gap, "provider-error", false)?
                }
            }
        };
        results.push(execution);
        if provider.benchmark_required_for_clean_claim
            && (provider.benchmark_status != "qualified" || provider.qualification_digest.is_none())
        {
            gaps.push(format!("provider-unqualified:{}", provider.id));
        }
    }
    gaps.sort();
    gaps.dedup();
    lenses_ran.sort();
    lenses_ran.dedup();
    if lenses_ran != selected_lenses {
        gaps.push("selected reasoning lenses did not complete".into());
    }
    gaps.sort();
    gaps.dedup();
    Ok(ExecutionReport {
        plan_digest: plan.digest().into(),
        plan_signature: plan.signature().map(ToOwned::to_owned),
        generation: inventory.generation.clone(),
        inventory_digest: inventory.digest.clone(),
        planned_providers,
        results,
        selected_lenses,
        lenses_ran,
        gaps,
    })
}

fn failed_execution(
    provider: &AuditProvider,
    gap: String,
    degradation: &str,
    skipped: bool,
) -> Result<ProviderExecution, AuditError> {
    Ok(ProviderExecution {
        provider: provider.id.clone(),
        skipped,
        result: ProviderResult {
            schema_version: 1,
            provider: provider_id(&provider.id)?,
            applicable: true,
            required: provider.required,
            status: if skipped {
                ProviderStatus::Cancelled
            } else {
                ProviderStatus::Failed
            },
            complete: false,
            coverage: None,
            findings: Vec::new(),
            coverage_gaps: vec![gap],
            degradation: vec![degradation.into()],
            details: BTreeMap::new(),
        },
    })
}

fn validate_result(
    provider: &AuditProvider,
    result: &ProviderResult,
    denominator: &ProviderDenominator,
) -> Result<(), String> {
    if provider.role.contains("candidate") && !result.findings.is_empty() {
        return Err("candidate-generator cannot emit findings".into());
    }
    if provider.role.contains("candidate")
        && ["selfCertifies", "closesFindings", "adjudicated"]
            .iter()
            .any(|field| result.details.get(*field).and_then(Value::as_bool) == Some(true))
    {
        return Err("candidate-generator cannot self-close or adjudicate findings".into());
    }
    if matches!(provider.kind, crate::plan::ProviderKind::HostService)
        && ["selfCertifies", "closesFindings"]
            .iter()
            .any(|field| result.details.get(*field).and_then(Value::as_bool) == Some(true))
    {
        return Err(
            "host-service result cannot self-certify without independent adjudication".into(),
        );
    }
    if let Some(coverage) = &result.coverage {
        if coverage.denominator_digest != denominator.digest {
            return Err("provider coverage denominator does not match frozen inventory".into());
        }
        if coverage.expected != denominator.count as u64 {
            return Err(
                "provider coverage expected count does not match frozen selector denominator"
                    .into(),
            );
        }
        if coverage.examined > coverage.expected {
            return Err("provider coverage examined count exceeds denominator".into());
        }
    }
    if result.complete {
        let coverage = result
            .coverage
            .as_ref()
            .ok_or_else(|| "complete provider result is missing coverage".to_owned())?;
        if coverage.expected != coverage.examined || !coverage.gaps.is_empty() {
            return Err("complete provider result lacks exact denominator reconciliation".into());
        }
    }
    for finding in &result.findings {
        let evidence = result
            .details
            .get("findingEvidence")
            .and_then(Value::as_object)
            .and_then(|items| items.get(finding.id.as_str()))
            .filter(|value| value.is_object() && !value.as_object().is_some_and(|o| o.is_empty()))
            .ok_or_else(|| format!("finding {} is missing evidence", finding.id))?;
        let _ = evidence;
        let locations = result
            .details
            .get("findingLocations")
            .and_then(Value::as_object)
            .and_then(|items| items.get(finding.id.as_str()))
            .and_then(Value::as_array)
            .filter(|items| !items.is_empty())
            .ok_or_else(|| format!("finding {} is missing source location", finding.id))?;
        if locations
            .iter()
            .any(|location| location.as_str().is_none_or(str::is_empty))
        {
            return Err(format!(
                "finding {} has invalid source location",
                finding.id
            ));
        }
        for location in locations.iter().filter_map(Value::as_str) {
            let path = location
                .rsplit_once(':')
                .map(|(path, _)| path)
                .unwrap_or(location)
                .replace('\\', "/");
            if !denominator.paths.contains(&path) {
                return Err(format!(
                    "finding {} location is outside frozen selector denominator: {path}",
                    finding.id
                ));
            }
        }
    }
    if matches!(
        provider.kind,
        crate::plan::ProviderKind::TypedExternalProjectTool
    ) {
        validate_external_receipt(provider, result)?;
    }
    Ok(())
}

fn provider_denominator(
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
    candidates: &[crate::inventory::InventoryDenominator],
) -> Result<ProviderDenominator, AuditError> {
    let selector = provider.configuration.get("selector").ok_or_else(|| {
        AuditError::Invalid(format!("provider {} is missing selector", provider.id))
    })?;
    let denominator = inventory.denominator_entries_with_candidates(selector, candidates)?;
    let expected_digest = provider
        .configuration
        .get("denominatorDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AuditError::Invalid(format!(
                "provider {} is missing frozen denominator digest",
                provider.id
            ))
        })?;
    let expected_count = provider
        .configuration
        .get("denominatorCount")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            AuditError::Invalid(format!(
                "provider {} is missing frozen denominator count",
                provider.id
            ))
        })?;
    if denominator.digest != expected_digest || denominator.entries.len() as u64 != expected_count {
        return Err(AuditError::SourceDrift(format!(
            "provider {} denominator changed after plan freeze",
            provider.id
        )));
    }
    Ok(ProviderDenominator {
        count: denominator.entries.len(),
        digest: denominator.digest,
        paths: denominator
            .entries
            .into_iter()
            .map(|entry| entry.path)
            .collect(),
    })
}

struct ProviderDenominator {
    count: usize,
    digest: String,
    paths: BTreeSet<String>,
}

fn validate_external_receipt(
    provider: &AuditProvider,
    result: &ProviderResult,
) -> Result<(), String> {
    let receipt = result
        .details
        .get("executionReceipt")
        .or_else(|| result.details.get("receipt"))
        .filter(|value| value.is_object())
        .ok_or_else(|| {
            "typed external project tool result is missing terminal execution receipt".to_owned()
        })?;
    let object = receipt.as_object().expect("object checked above");
    for field in [
        "schemaVersion",
        "receiptId",
        "requestId",
        "providerId",
        "planId",
        "policyId",
        "policy",
        "taskId",
        "state",
        "complete",
        "executable",
        "command",
        "cwd",
        "environmentNames",
        "sandbox",
        "processTree",
        "timing",
        "exitCode",
        "signal",
        "stdout",
        "stderr",
        "parser",
        "gaps",
    ] {
        if !object.contains_key(field) {
            return Err(format!("external execution receipt missing {field}"));
        }
    }
    if object.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || [
            "receiptId",
            "requestId",
            "providerId",
            "planId",
            "policyId",
            "state",
        ]
        .iter()
        .any(|field| {
            object
                .get(*field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
        || object.get("complete").and_then(Value::as_bool).is_none()
        || object
            .get("environmentNames")
            .and_then(Value::as_array)
            .is_none()
        || object.get("gaps").and_then(Value::as_array).is_none()
        || ["sandbox", "processTree", "timing", "parser"]
            .iter()
            .any(|field| !object.get(*field).is_some_and(Value::is_object))
    {
        return Err("malformed external execution receipt projection".into());
    }
    if object.get("providerId").and_then(Value::as_str) != Some(provider.id.as_str()) {
        return Err("external execution receipt provider identity mismatch".into());
    }
    if !matches!(
        object.get("state").and_then(Value::as_str),
        Some(
            "blocked"
                | "completed"
                | "failed"
                | "missing_executable"
                | "unsealed_executable"
                | "unauthorized_effect"
                | "sandbox_missing"
                | "spawn_failed"
                | "timeout"
                | "cancelled"
                | "output_limited"
                | "kill_failed"
                | "artifact_failed"
                | "internal"
        )
    ) {
        return Err("external execution receipt has unknown terminal state".into());
    }
    if let Some(policy) = object.get("policy").and_then(Value::as_object) {
        if policy.get("id").and_then(Value::as_str)
            != object.get("policyId").and_then(Value::as_str)
        {
            return Err("external execution receipt policy identity mismatch".into());
        }
    }
    validate_nested_projection(object)?;
    let state_completed = object.get("state").and_then(Value::as_str) == Some("completed");
    let gaps_empty = object
        .get("gaps")
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty);
    if state_completed != gaps_empty {
        return Err("external receipt completed state must match gap emptiness".into());
    }
    let receipt_complete = object
        .get("complete")
        .and_then(Value::as_bool)
        .expect("validated above");
    let terminal_complete = state_completed && gaps_empty;
    if receipt_complete != terminal_complete {
        return Err("external receipt complete must match completed state and empty gaps".into());
    }
    if receipt_complete {
        let process = object
            .get("processTree")
            .and_then(Value::as_object)
            .unwrap();
        if process.get("started") != Some(&Value::Bool(true))
            || process.get("terminated") != Some(&Value::Bool(true))
            || process.get("reaped") != Some(&Value::Bool(true))
        {
            return Err("completed external receipt lacks process termination evidence".into());
        }
    }
    if result.complete != receipt_complete {
        return Err("external provider result and receipt completion state disagree".into());
    }
    Ok(())
}

fn validate_nested_projection(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    let object_value = |field: &str| {
        object
            .get(field)
            .and_then(Value::as_object)
            .ok_or_else(|| format!("external receipt {field} must be an object"))
    };
    let policy = object.get("policy").expect("required above");
    if let Some(policy) = policy.as_object() {
        for field in ["id", "version", "digest", "allowed", "reason"] {
            if !policy.contains_key(field) {
                return Err(format!("external receipt policy missing {field}"));
            }
        }
        if policy
            .get("id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || policy.get("version").and_then(Value::as_u64).is_none()
            || policy
                .get("digest")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || policy.get("allowed").and_then(Value::as_bool).is_none()
            || (!policy.get("reason").is_some_and(Value::is_null)
                && policy.get("reason").and_then(Value::as_str).is_none())
        {
            return Err("malformed external receipt policy".into());
        }
    } else if !policy.is_null() {
        return Err("external receipt policy must be object or null".into());
    }
    if let Some(command) = object.get("command").filter(|value| !value.is_null()) {
        let command = command
            .as_object()
            .ok_or_else(|| "external receipt command must be object or null".to_owned())?;
        for field in [
            "executable",
            "args",
            "environmentNames",
            "redactedArgumentIndexes",
            "redactedEnvironmentNames",
        ] {
            if !command.contains_key(field) {
                return Err(format!("external receipt command missing {field}"));
            }
        }
        if command
            .get("executable")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || !string_array(command.get("args"))
            || !string_array(command.get("environmentNames"))
            || !string_array(command.get("redactedEnvironmentNames"))
            || !command.get("redactedArgumentIndexes").is_some_and(|value| {
                value
                    .as_array()
                    .is_some_and(|values| values.iter().all(Value::is_u64))
            })
        {
            return Err("malformed external receipt command".into());
        }
    }
    let sandbox = object_value("sandbox")?;
    if sandbox.get("required").and_then(Value::as_bool).is_none()
        || sandbox
            .get("networkEnabled")
            .and_then(Value::as_bool)
            .is_none()
        || (!sandbox.get("receiptId").is_some_and(Value::is_null)
            && sandbox.get("receiptId").and_then(Value::as_str).is_none())
    {
        return Err("malformed external receipt sandbox".into());
    }
    let process = object_value("processTree")?;
    if ["started", "terminated", "hardKilled", "reaped"]
        .iter()
        .any(|field| process.get(*field).and_then(Value::as_bool).is_none())
        || (!process.get("detail").is_some_and(Value::is_null)
            && process.get("detail").and_then(Value::as_str).is_none())
    {
        return Err("malformed external receipt processTree".into());
    }
    let timing = object_value("timing")?;
    let started = timing.get("startedAtMs").and_then(Value::as_u64);
    let completed = timing.get("completedAtMs").and_then(Value::as_u64);
    let duration = timing.get("durationMs").and_then(Value::as_u64);
    if started.is_none()
        || completed.is_none()
        || duration.is_none()
        || completed.unwrap() < started.unwrap()
        || completed.unwrap() - started.unwrap() != duration.unwrap()
    {
        return Err("malformed or inconsistent external receipt timing".into());
    }
    let parser = object_value("parser")?;
    let attempted = parser.get("attempted").and_then(Value::as_bool);
    let succeeded = parser.get("succeeded").and_then(Value::as_bool);
    if attempted.is_none()
        || succeeded.is_none()
        || (!parser.get("error").is_some_and(Value::is_null)
            && parser.get("error").and_then(Value::as_str).is_none())
        || (succeeded == Some(true)
            && (attempted != Some(true) || !parser.get("error").unwrap().is_null()))
        || (attempted == Some(false) && succeeded == Some(true))
    {
        return Err("malformed external receipt parser".into());
    }
    for field in ["stdout", "stderr"] {
        if let Some(artifact) = object.get(field).filter(|value| !value.is_null()) {
            let artifact = artifact
                .as_object()
                .ok_or_else(|| format!("external receipt {field} must be object or null"))?;
            if ["path", "digest", "bytes", "immutable"]
                .iter()
                .any(|key| !artifact.contains_key(*key))
                || artifact
                    .get("path")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                || artifact
                    .get("digest")
                    .and_then(Value::as_str)
                    .is_none_or(str::is_empty)
                || artifact.get("bytes").and_then(Value::as_u64).is_none()
                || artifact.get("immutable").and_then(Value::as_bool).is_none()
            {
                return Err(format!("malformed external receipt {field} artifact"));
            }
        }
    }
    if let Some(executable) = object.get("executable").filter(|value| !value.is_null()) {
        let executable = executable
            .as_object()
            .ok_or_else(|| "external receipt executable must be object or null".to_owned())?;
        for field in [
            "requestedPath",
            "canonicalPath",
            "digest",
            "digestState",
            "signature",
            "version",
        ] {
            if !executable.contains_key(field) {
                return Err(format!("external receipt executable missing {field}"));
            }
        }
        let version = object_value_from(executable, "version")?;
        if executable
            .get("requestedPath")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
            || (!executable.get("canonicalPath").is_some_and(Value::is_null)
                && executable
                    .get("canonicalPath")
                    .and_then(Value::as_str)
                    .is_none())
            || (!executable.get("digest").is_some_and(Value::is_null)
                && executable.get("digest").and_then(Value::as_str).is_none())
            || executable
                .get("digestState")
                .and_then(Value::as_str)
                .is_none()
            || executable
                .get("signature")
                .and_then(Value::as_str)
                .is_none()
            || !version.contains_key("args")
            || !version.contains_key("output")
            || !version.contains_key("exitCode")
            || !version.contains_key("qualified")
            || !string_array(version.get("args"))
            || (!version.get("output").is_some_and(Value::is_null)
                && version.get("output").and_then(Value::as_str).is_none())
            || (!version.get("exitCode").is_some_and(Value::is_null)
                && version.get("exitCode").and_then(Value::as_i64).is_none())
            || version.get("qualified").and_then(Value::as_bool).is_none()
        {
            return Err("malformed external receipt executable identity".into());
        }
    }
    for field in ["environmentNames", "gaps"] {
        if !string_array(object.get(field)) {
            return Err(format!("external receipt {field} must be a string array"));
        }
    }
    for field in ["taskId", "cwd"] {
        if !object.get(field).is_some_and(Value::is_null)
            && object.get(field).and_then(Value::as_str).is_none()
        {
            return Err(format!("external receipt {field} must be string or null"));
        }
    }
    for field in ["exitCode", "signal"] {
        if !object.get(field).is_some_and(Value::is_null)
            && object.get(field).and_then(Value::as_i64).is_none()
        {
            return Err(format!("external receipt {field} must be integer or null"));
        }
    }
    Ok(())
}

fn object_value_from<'a>(
    object: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    object
        .get(field)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("external receipt {field} must be an object"))
}

fn string_array(value: Option<&Value>) -> bool {
    value.is_some_and(|value| {
        value
            .as_array()
            .is_some_and(|values| values.iter().all(Value::is_string))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::ProviderKind;

    fn provider() -> AuditProvider {
        AuditProvider {
            id: "fixture-provider".into(),
            version: "1".into(),
            role: "deterministic".into(),
            phase: "source".into(),
            lens_ids: Vec::new(),
            dependencies: Vec::new(),
            kind: ProviderKind::TypedExternalProjectTool,
            configuration: BTreeMap::new(),
            bounds: BTreeMap::new(),
            clean_claim: "evidence-only".into(),
            benchmark_status: "qualified".into(),
            benchmark_required_for_clean_claim: false,
            qualification_digest: None,
            required: true,
        }
    }

    fn receipt(state: &str, complete: bool, gaps: Value) -> Value {
        serde_json::json!({
            "schemaVersion": 1,
            "receiptId": "receipt:fixture",
            "requestId": "request:fixture",
            "providerId": "fixture-provider",
            "planId": "plan:fixture",
            "policyId": "policy:fixture",
            "policy": null,
            "taskId": null,
            "state": state,
            "complete": complete,
            "executable": null,
            "command": null,
            "cwd": null,
            "environmentNames": [],
            "sandbox": {"required": false, "receiptId": null, "networkEnabled": false},
            "processTree": {"started": false, "terminated": false, "hardKilled": false, "reaped": false, "detail": null},
            "timing": {"startedAtMs": 0, "completedAtMs": 0, "durationMs": 0},
            "exitCode": null,
            "signal": null,
            "stdout": null,
            "stderr": null,
            "parser": {"attempted": false, "succeeded": false, "error": null},
            "gaps": gaps,
        })
    }

    #[test]
    fn terminal_receipt_state_matches_gap_emptiness() {
        let provider = provider();
        let inconsistent = receipt("completed", false, serde_json::json!(["incomplete"]));
        assert!(validate_external_receipt(
            &provider,
            &ProviderResult {
                schema_version: 1,
                provider: ProviderId::new(&provider.id).unwrap(),
                applicable: true,
                required: true,
                status: ProviderStatus::Partial,
                complete: false,
                coverage: None,
                findings: Vec::new(),
                coverage_gaps: vec!["incomplete".into()],
                degradation: Vec::new(),
                details: BTreeMap::from([("executionReceipt".into(), inconsistent)]),
            },
        )
        .is_err());
        let gapless_failure = receipt("failed", false, serde_json::json!([]));
        assert!(validate_external_receipt(
            &provider,
            &ProviderResult {
                schema_version: 1,
                provider: ProviderId::new(&provider.id).unwrap(),
                applicable: true,
                required: true,
                status: ProviderStatus::Partial,
                complete: false,
                coverage: None,
                findings: Vec::new(),
                coverage_gaps: vec!["incomplete".into()],
                degradation: Vec::new(),
                details: BTreeMap::from([("executionReceipt".into(), gapless_failure)]),
            },
        )
        .is_err());
    }
}
