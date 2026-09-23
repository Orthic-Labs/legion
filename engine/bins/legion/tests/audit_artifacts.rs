use std::{collections::BTreeMap, process::Command, sync::Arc};

use legion_audit::{AuditError, FilesystemInventorySource, InventoryEnvelope, InventorySource};
use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderSpec, ProviderStatus};

/// Fixed-snapshot inventory fixture. Replaces the retired
/// `FileBlueprintInventorySource`: Legion (Rust) has no Blueprint/Membrane
/// packet to read, so a unit-level fixture that needs an exact, precomputed
/// inventory (independent of whatever else the test directory contains)
/// supplies it directly, the same way `StaticInventorySource` does inside
/// `legion_application`.
struct FixedInventorySource(InventoryEnvelope);

impl InventorySource for FixedInventorySource {
    fn inventory(&self, repository_id: &str) -> Result<InventoryEnvelope, AuditError> {
        if self.0.repository_id != repository_id {
            return Err(AuditError::SourceDrift(format!(
                "no configured inventory for repository {repository_id}"
            )));
        }
        Ok(self.0.clone())
    }
}

#[test]
fn configured_audit_writes_reconciled_json_and_sarif() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-audit-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    // Source files live in an isolated subdirectory so the frozen inventory
    // (and its digest) reflects exactly these two files, not whatever other
    // fixture artifacts (provider-plan.json, out/, ...) this test also
    // writes under `root`.
    let source_root = root.join("source");
    std::fs::create_dir_all(source_root.join("src")).unwrap();
    std::fs::write(source_root.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    std::fs::create_dir_all(source_root.join("docs")).unwrap();
    std::fs::write(source_root.join("docs/readme.md"), "fixture\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let source_root = std::fs::canonicalize(source_root).unwrap();
    let repository_id = source_root.to_string_lossy().into_owned();
    let provider_id = ProviderId::new("fixture-provider").unwrap();
    // Legion's own read-only filesystem walk is the sole inventory source;
    // use it here too so the fixture's digest matches exactly what the CLI
    // invocation below computes for the same `source_root`.
    let inventory = FilesystemInventorySource::new(&source_root)
        .unwrap()
        .inventory(&repository_id)
        .unwrap();
    let result = ProviderResult {
        schema_version: 1,
        provider: provider_id.clone(),
        applicable: true,
        required: true,
        status: ProviderStatus::Complete,
        complete: true,
        coverage: Some(Coverage {
            denominator_digest: inventory.digest.clone(),
            expected: inventory.entries.len() as u64,
            examined: inventory.entries.len() as u64,
            gaps: Vec::new(),
        }),
        findings: Vec::new(),
        coverage_gaps: Vec::new(),
        degradation: Vec::new(),
        details: BTreeMap::new(),
    };
    let specification = ProviderSpec {
        schema_version: 2,
        id: provider_id.clone(),
        provider_version: "1".into(),
        family: "fixture".into(),
        lens_ids: Vec::new(),
        role: "deterministic".into(),
        phase: "source".into(),
        depends_on: Vec::new(),
        consumes: vec!["repository-inventory".into()],
        produces: vec!["provider-result".into()],
        selector: serde_json::json!({"op": "always"}),
        denominator_kind: "selected-scope".into(),
        runner: serde_json::json!({"kind": "built-in"}),
        host_capabilities: Vec::new(),
        execution: serde_json::json!({}),
        reasoning: serde_json::json!({}),
        benchmark: serde_json::json!({
            "status": "qualified",
            "requiredForCleanClaim": true,
            "qualificationDigest": "sha256:fixture"
        }),
        clean_claim: "finding-producing".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    };
    let invalid_result = {
        let mut invalid = result.clone();
        invalid.coverage.as_mut().unwrap().denominator_digest =
            format!("sha256:{}", "0".repeat(64));
        invalid
    };
    let source: Arc<dyn InventorySource> = Arc::new(FixedInventorySource(inventory.clone()));
    assert!(
        legion_application::NativeApplicationConfig::for_audit_artifacts(
            repository_id.clone(),
            source,
            vec![specification.clone()],
            vec![invalid_result],
            Some(source_root.clone()),
        )
        .is_err()
    );
    let plan_path = root.join("provider-plan.json");
    std::fs::write(
        &plan_path,
        serde_json::to_vec_pretty(&serde_json::json!({"providers": [specification]})).unwrap(),
    )
    .unwrap();
    let result_path = root.join("provider-result.json");
    std::fs::write(
        &result_path,
        serde_json::to_vec_pretty(&serde_json::json!({"providerResult": result})).unwrap(),
    )
    .unwrap();
    let out = root.join("out");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "audit",
            "--out",
            out.to_str().unwrap(),
            "--json",
            "--provider-plan",
            plan_path.to_str().unwrap(),
            "--provider-result",
            result_path.to_str().unwrap(),
            &repository_id,
        ])
        .env("AUDIT_PLAN_SIGNING_KEY", "fixture-signing-key")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["auditStatus"], "pass");
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["status"], "clean");
    assert_eq!(report["claims"]["executedProviderCount"], 1);
    let sarif: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("report.sarif")).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert!(out.join("execution.json").is_file());
}
