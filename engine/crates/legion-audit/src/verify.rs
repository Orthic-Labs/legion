use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

use legion_contracts::ReportV1;
use legion_effects::artifact::ArtifactRecord;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    error::AuditError, execution::ExecutionReport, integrity::verify, inventory::InventoryEnvelope,
    plan::FrozenPlan,
};

const MAX_EFFECT_ARTIFACT_BYTES: usize = 8 * 1024 * 1024;

/// Provider `details` keys that hold an immutable `{path,digest,bytes}` artifact
/// reference outside the execution receipt (disposable-copy broker status).
pub const DETAILS_ARTIFACT_REF_KEYS: &[&str] = &["rustRightBrokerStatus"];

/// Validates retained stdout/stderr references from a persisted Audit run.
/// The legacy projection has no marker and is deliberately left untouched.
pub(crate) fn validate_effect_artifacts(
    run_dir: &Path,
    plan: &Value,
    stored_report: &ReportV1,
    execution: &ExecutionReport,
) -> Result<(), AuditError> {
    let plan_marker = plan
        .get("effectArtifactsRoot")
        .filter(|value| !value.is_null());
    let report_marker = stored_report
        .claims
        .get("effectArtifactsRoot")
        .filter(|value| !value.is_null());
    if plan_marker.is_none() && report_marker.is_none() {
        return Ok(());
    }
    if plan_marker.and_then(Value::as_str) != Some("artifacts")
        || report_marker.and_then(Value::as_str) != Some("artifacts")
    {
        return Err(AuditError::Invalid(
            "effect artifact root marker is missing, malformed, or unsafe".into(),
        ));
    }

    let mut references = BTreeMap::<String, ArtifactRecord>::new();
    for item in &execution.results {
        let receipt = item
            .result
            .details
            .get("executionReceipt")
            .filter(|value| !value.is_null())
            .or_else(|| {
                item.result
                    .details
                    .get("receipt")
                    .filter(|value| !value.is_null())
            });
        let mut refs: Vec<&Value> = Vec::new();
        if let Some(receipt) = receipt {
            let receipt = receipt.as_object().ok_or_else(|| {
                AuditError::Invalid("effect execution receipt is malformed".into())
            })?;
            if receipt.get("kind").and_then(Value::as_str) != Some("native-legacy-check-receipt") {
                for stream in ["stdout", "stderr", "brokerStatus"] {
                    if let Some(value) = receipt.get(stream).filter(|value| !value.is_null()) {
                        refs.push(value);
                    }
                }
            }
        }
        for key in DETAILS_ARTIFACT_REF_KEYS {
            if let Some(value) = item.result.details.get(*key).filter(|v| !v.is_null()) {
                refs.push(value);
            }
        }
        for value in refs {
            let record = parse_effect_artifact_ref(value).map_err(AuditError::Invalid)?;
            match references.entry(record.path.clone()) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(record);
                }
                std::collections::btree_map::Entry::Occupied(entry) if entry.get() == &record => {}
                std::collections::btree_map::Entry::Occupied(_) => {
                    return Err(AuditError::Invalid(
                        "conflicting effect artifact records share one path".into(),
                    ));
                }
            }
        }
    }

    let root = run_dir.join("artifacts");
    for record in references.values() {
        read_effect_artifact(&root, record).map_err(AuditError::Invalid)?;
    }
    Ok(())
}

pub fn parse_effect_artifact_ref(value: &Value) -> Result<ArtifactRecord, String> {
    let path = value
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| "artifact record has no path".to_owned())?;
    validate_effect_artifact_path(path)?;
    let digest = value
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "artifact record has no digest".to_owned())?;
    if digest.len() != 71
        || !digest.starts_with("sha256:")
        || !digest[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("artifact record digest is invalid".into());
    }
    let bytes = value
        .get("bytes")
        .and_then(Value::as_u64)
        .and_then(|bytes| usize::try_from(bytes).ok())
        .ok_or_else(|| "artifact record byte length is invalid".to_owned())?;
    if bytes > MAX_EFFECT_ARTIFACT_BYTES {
        return Err("artifact record exceeds retention size limit".into());
    }
    let immutable = value.get("immutable").and_then(Value::as_bool) == Some(true);
    if !immutable {
        return Err("artifact record is not immutable".into());
    }
    Ok(ArtifactRecord {
        path: path.to_owned(),
        digest: digest.to_owned(),
        bytes,
        immutable,
    })
}

pub fn validate_effect_artifact_path(path: &str) -> Result<PathBuf, String> {
    if path.is_empty() || path.len() > 512 || path.contains('\\') || path.contains(':') {
        return Err("artifact path is empty, oversized, or non-portable".into());
    }
    let relative = Path::new(path);
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || relative.to_string_lossy().as_ref() != path
    {
        return Err("artifact path escapes its artifact root".into());
    }
    Ok(relative.to_path_buf())
}

pub fn read_effect_artifact(root: &Path, record: &ArtifactRecord) -> Result<Vec<u8>, String> {
    if !record.immutable {
        return Err("artifact record is not immutable".into());
    }
    if record.bytes > MAX_EFFECT_ARTIFACT_BYTES {
        return Err("artifact record exceeds retention size limit".into());
    }
    if record.digest.len() != 71
        || !record.digest.starts_with("sha256:")
        || !record.digest[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("artifact record digest is invalid".into());
    }
    let relative = validate_effect_artifact_path(&record.path)?;
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("artifact root unavailable: {error}"))?;
    if !root_metadata.file_type().is_dir() {
        return Err("artifact root is not a real directory".into());
    }
    let canonical_root =
        fs::canonicalize(root).map_err(|error| format!("artifact root unavailable: {error}"))?;
    let components = relative.components().collect::<Vec<_>>();
    let mut current = canonical_root.clone();
    for (position, component) in components.iter().enumerate() {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)
            .map_err(|error| format!("artifact is missing or unreadable: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("artifact path contains a symlink".into());
        }
        if position + 1 == components.len() {
            if !metadata.is_file() || metadata.len() != record.bytes as u64 {
                return Err("artifact is not a regular file of the recorded size".into());
            }
        } else if !metadata.is_dir() {
            return Err("artifact parent is not a directory".into());
        }
    }
    if !current.starts_with(&canonical_root) {
        return Err("artifact path escapes its root".into());
    }
    let file =
        fs::File::open(&current).map_err(|error| format!("artifact is unreadable: {error}"))?;
    let mut bytes = Vec::with_capacity(record.bytes);
    file.take(record.bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("artifact is unreadable: {error}"))?;
    if bytes.len() != record.bytes
        || format!("sha256:{}", hex::encode(Sha256::digest(&bytes))) != record.digest
    {
        return Err("artifact digest or size does not match receipt".into());
    }
    Ok(bytes)
}

pub fn verify_binding(
    plan: &FrozenPlan,
    inventory: &InventoryEnvelope,
    key: Option<&[u8]>,
) -> Result<(), AuditError> {
    if inventory.repository_id != plan.plan().repository_id
        || inventory.generation != plan.plan().inventory_generation
    {
        return Err(AuditError::SourceDrift(
            "repository or inventory generation drift".into(),
        ));
    }
    if inventory.digest != plan.plan().inventory_digest {
        return Err(AuditError::SourceDrift("inventory digest drift".into()));
    }
    verify(plan.plan(), plan.digest(), plan.signature(), key)
}

pub fn verify_execution(report: &ExecutionReport) -> Result<(), AuditError> {
    if report.plan_signature.is_none() {
        return Err(AuditError::Invalid(
            "audit execution is not bound to a signed plan".into(),
        ));
    }
    verify_execution_structure(report)
}

/// Structural verification never turns an unsigned diagnostic into authenticated evidence.
/// An unsigned plan runs every provider; the explicit `unsigned-plan` gap is what keeps
/// the run non-clean, so the report must carry it and must not claim a signature.
pub fn verify_source_diagnostic(
    report: &ExecutionReport,
    plan: &FrozenPlan,
) -> Result<(), AuditError> {
    if report.plan_signature.is_some() || !report.gaps.iter().any(|gap| gap == "unsigned-plan") {
        return Err(AuditError::Invalid(
            "source diagnostic requires explicit unsigned-plan gap".into(),
        ));
    }
    if plan.signature().is_some()
        || report.plan_digest != plan.digest()
        || report.generation != plan.plan().inventory_generation
        || report.inventory_digest != plan.plan().inventory_digest
        || report.planned_providers
            != plan
                .providers()
                .iter()
                .map(|p| p.id.clone())
                .collect::<Vec<_>>()
    {
        return Err(AuditError::Invalid(
            "source diagnostic frozen plan mismatch".into(),
        ));
    }
    verify_execution_structure(report)
}

fn verify_execution_structure(report: &ExecutionReport) -> Result<(), AuditError> {
    if report.planned_providers.is_empty() {
        return Err(AuditError::Invalid(
            "audit execution has no planned providers".into(),
        ));
    }
    if report.inventory_digest.trim().is_empty() || report.generation.trim().is_empty() {
        return Err(AuditError::Invalid(
            "audit execution is missing frozen inventory identity".into(),
        ));
    }
    let mut ids = BTreeSet::new();
    for item in &report.results {
        if !ids.insert(item.provider.clone()) {
            return Err(AuditError::Invalid("duplicate provider execution".into()));
        }
        if item.result.provider.to_string() != item.provider {
            return Err(AuditError::Invalid(
                "provider result identity mismatch".into(),
            ));
        }
        if item.skipped
            && !matches!(
                item.result.status,
                legion_contracts::ProviderStatus::Cancelled
            )
        {
            return Err(AuditError::Invalid(
                "skipped provider execution must be cancelled".into(),
            ));
        }
        if item.result.complete
            && !matches!(
                item.result.status,
                legion_contracts::ProviderStatus::Ok | legion_contracts::ProviderStatus::Complete
            )
        {
            return Err(AuditError::Invalid(
                "failed or cancelled provider cannot be complete".into(),
            ));
        }
        if item.result.complete
            && (!item.result.coverage_gaps.is_empty()
                || item
                    .result
                    .coverage
                    .as_ref()
                    .map(|coverage| !coverage.complete())
                    .unwrap_or(true))
        {
            return Err(AuditError::Invalid(
                "complete provider result lacks coverage proof".into(),
            ));
        }
    }
    let planned = report
        .planned_providers
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if planned.len() != report.planned_providers.len()
        || planned != ids
        || report.results.len() != report.planned_providers.len()
    {
        return Err(AuditError::Invalid(
            "planned and executed provider sets do not reconcile".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod effect_artifact_tests {
    use std::{fs, path::PathBuf, time::SystemTime};

    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};

    use super::validate_effect_artifacts;
    use crate::execution::ExecutionReport;
    use legion_contracts::ReportV1;

    fn temp_run() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "legion-effect-artifacts-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(path.join("artifacts/original")).unwrap();
        path
    }

    fn record(bytes: &[u8]) -> Value {
        json!({
            "path": "original/stdout.bin",
            "digest": format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
            "bytes": bytes.len(),
            "immutable": true
        })
    }

    fn report(root: Value) -> ReportV1 {
        serde_json::from_value(json!({
            "schema_version": 1,
            "report_id": "effect-artifact-test",
            "status": "incomplete",
            "findings": [],
            "gaps": [],
            "claims": {"effectArtifactsRoot": root},
            "targets": []
        }))
        .unwrap()
    }

    fn execution(stdout: Value) -> ExecutionReport {
        serde_json::from_value(json!({
            "planDigest": "sha256:plan",
            "planSignature": null,
            "generation": "generation",
            "inventoryDigest": "sha256:inventory",
            "plannedProviders": ["fixture.provider"],
            "results": [{
                "provider": "fixture.provider",
                "skipped": false,
                "result": {
                    "schema_version": 1,
                    "provider": "fixture.provider",
                    "applicable": true,
                    "required": false,
                    "status": "partial",
                    "complete": false,
                    "coverage": null,
                    "findings": [],
                    "coverage_gaps": [],
                    "degradation": [],
                    "details": {"executionReceipt": {"stdout": stdout}}
                }
            }],
            "selectedLenses": [],
            "lensesRan": [],
            "selectedReasoningLenses": [],
            "pendingHost": [],
            "deterministicLensTags": {},
            "coverageNotes": [],
            "gaps": []
        }))
        .unwrap()
    }

    fn marked_plan() -> Value {
        json!({"effectArtifactsRoot":"artifacts"})
    }

    #[test]
    fn validates_retained_output_and_rejects_tampering_or_deletion() {
        let run = temp_run();
        let bytes = b"stdout evidence";
        fs::write(run.join("artifacts/original/stdout.bin"), bytes).unwrap();
        let stored = report(json!("artifacts"));
        let execution = execution(record(bytes));
        assert!(validate_effect_artifacts(&run, &marked_plan(), &stored, &execution).is_ok());

        fs::write(
            run.join("artifacts/original/stdout.bin"),
            b"tampered evidence",
        )
        .unwrap();
        assert!(validate_effect_artifacts(&run, &marked_plan(), &stored, &execution).is_err());
        fs::remove_file(run.join("artifacts/original/stdout.bin")).unwrap();
        assert!(validate_effect_artifacts(&run, &marked_plan(), &stored, &execution).is_err());
        fs::remove_dir_all(run).unwrap();
    }

    #[test]
    fn legacy_markers_skip_and_partial_or_unsafe_markers_fail() {
        let run = temp_run();
        let execution = execution(json!(null));
        let legacy_plan = json!({});
        assert!(
            validate_effect_artifacts(&run, &legacy_plan, &report(Value::Null), &execution).is_ok()
        );
        assert!(
            validate_effect_artifacts(&run, &marked_plan(), &report(Value::Null), &execution)
                .is_err()
        );
        assert!(validate_effect_artifacts(
            &run,
            &json!({"effectArtifactsRoot":"../outside"}),
            &report(json!("../outside")),
            &execution
        )
        .is_err());
        fs::remove_dir_all(run).unwrap();
    }

    #[test]
    fn native_legacy_summary_is_skipped_only_for_its_exact_receipt_kind() {
        let run = temp_run();
        let bytes = b"external output";
        fs::write(run.join("artifacts/original/stdout.bin"), bytes).unwrap();
        let stored = report(json!("artifacts"));
        let mut execution = execution(record(bytes));
        let native_provider = legion_contracts::ProviderId::new("legacy.native.fixture").unwrap();
        let mut native_result = execution.results[0].result.clone();
        native_result.provider = native_provider.clone();
        native_result.details.insert(
            "executionReceipt".into(),
            json!({
                "kind": "native-legacy-check-receipt",
                "stdout": {"path": null, "digest": "sha256:summary", "bytes": 7, "immutable": false},
                "stderr": {"path": null, "digest": "sha256:summary", "bytes": 0, "immutable": false}
            }),
        );
        execution.results.push(crate::execution::ProviderExecution {
            provider: native_provider.to_string(),
            result: native_result,
            skipped: false,
        });

        assert!(validate_effect_artifacts(&run, &marked_plan(), &stored, &execution).is_ok());

        execution.results[1]
            .result
            .details
            .get_mut("executionReceipt")
            .unwrap()["kind"] = json!("other-receipt");
        assert!(validate_effect_artifacts(&run, &marked_plan(), &stored, &execution).is_err());
        fs::remove_dir_all(run).unwrap();
    }

    #[test]
    fn details_level_broker_status_ref_must_exist_and_match() {
        let run = temp_run();
        let bytes = b"broker status";
        fs::write(run.join("artifacts/original/stdout.bin"), bytes).unwrap();
        let stored = report(json!("artifacts"));
        let mut execution = execution(json!(null));
        execution.results[0]
            .result
            .details
            .insert("rustRightBrokerStatus".into(), record(bytes));
        assert!(validate_effect_artifacts(&run, &marked_plan(), &stored, &execution).is_ok());
        fs::remove_file(run.join("artifacts/original/stdout.bin")).unwrap();
        assert!(validate_effect_artifacts(&run, &marked_plan(), &stored, &execution).is_err());
        fs::remove_dir_all(run).unwrap();
    }
}
