//! Artifact accuracy controls use shipped specs, frozen plans & native dispatch.
//! This file keeps supply-chain absence controls outside native qualification.
//! Dedicated pinned Syft controls exercise SBOM/license behavior separately;
//! audited-target build provenance remains an explicit gap.

#[path = "support/accuracy_receipt.rs"]
mod accuracy_receipt;

use accuracy_receipt::CaseObservation;
use legion_audit::{
    execute, native_providers::security::producer::ArtifactProducer, AuditPlan,
    FilesystemInventorySource, FrozenPlan, InventoryEnvelope, InventorySource,
    NativeProviderRegistry,
};
use legion_contracts::{ProviderResult, ProviderSpec};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const KEY: &[u8] = b"artifact-provider-accuracy-fixture-key";
const FIXTURE: &[&str] = &["engine/crates/legion-audit/tests/artifact_provider_accuracy.rs"];
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);

impl Fixture {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "legion-artifact-accuracy-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self(fs::canonicalize(root).unwrap())
    }

    fn write(&self, path: &str, text: &str) {
        let path = self.0.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn shipped_spec(id: &str) -> ProviderSpec {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    serde_json::from_value(
        registry["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == id)
            .unwrap_or_else(|| panic!("{id} absent from shipped registry"))
            .clone(),
    )
    .unwrap()
}

fn inventory(root: &Path) -> InventoryEnvelope {
    FilesystemInventorySource::new(root)
        .unwrap()
        .inventory("artifact-accuracy")
        .unwrap()
}

fn plan(id: &str, root: &Path, inventory: &InventoryEnvelope) -> AuditPlan {
    AuditPlan::compile_with_root(Some(root), inventory, &[shipped_spec(id)]).unwrap()
}

fn run(
    id: &str,
    frozen: &FrozenPlan,
    inventory: &InventoryEnvelope,
    registry: &NativeProviderRegistry,
    complete: bool,
) -> ProviderResult {
    let provider = frozen.provider(id).expect("provider in frozen plan");
    let expected = provider.configuration["denominatorCount"].as_u64().unwrap();
    let digest = provider.configuration["denominatorDigest"]
        .as_str()
        .unwrap();
    assert!(expected > 0, "{id}: nonzero frozen denominator required");
    let execution = execute(frozen, inventory, registry).unwrap();
    assert_eq!(execution.planned_providers, vec![id]);
    assert_eq!(execution.results.len(), 1, "{id}: one dispatched result");
    let entry = &execution.results[0];
    assert_eq!(entry.provider, id);
    assert!(
        !entry.skipped,
        "{id}: skipped result is not accuracy evidence"
    );
    let result = &entry.result;
    assert!(result.applicable, "{id}: not-applicable is not clean");
    assert!(
        result.details.get("availability").is_none(),
        "{id}: unavailable"
    );
    let coverage = result.coverage.as_ref().expect("frozen coverage");
    assert_eq!(coverage.denominator_digest, digest, "{id}");
    assert_eq!(coverage.expected, expected, "{id}");
    assert_eq!(
        coverage.examined, expected,
        "{id}: frozen denominator unexamined"
    );
    assert_eq!(
        result.complete, complete,
        "{id}: {:?}",
        result.coverage_gaps
    );
    if complete {
        assert!(
            result.coverage_gaps.is_empty(),
            "{id}: {:?}",
            result.coverage_gaps
        );
        assert!(coverage.gaps.is_empty(), "{id}: {:?}", coverage.gaps);
        assert!(
            result.degradation.is_empty(),
            "{id}: {:?}",
            result.degradation
        );
        assert_eq!(result.details["analysis"]["complete"], true);
        assert_eq!(result.details["analysis"]["coverageGaps"], json!([]));
    }
    result.clone()
}

fn observation(id: &str, expected: &[&str], actual: Vec<String>) -> CaseObservation {
    CaseObservation {
        id: id.into(),
        expected: expected.iter().map(|label| (*label).into()).collect(),
        // Keep every emission: receipt helper counts duplicate labels as FPs.
        actual,
    }
}

fn suppression_case(case: &str, before: &str, after: &str, expected: &[&str]) -> CaseObservation {
    let id = "security.suppression-changes";
    let root = Fixture::new(case);
    root.write("src/app.py", after);
    let baseline = Fixture::new("baseline");
    baseline.write("app.py", before);
    let inventory = inventory(&root.0);
    let mut plan = plan(id, &root.0, &inventory);
    // This supported host-diff input is sealed before execution. Producer
    // verifies selected bytes against both source files & frozen inventory.
    plan.providers[0].configuration.insert(
        "suppressionChanges".into(),
        json!({
            "binding": {"repositoryRevision": inventory.generation, "digest": inventory.digest},
            "files": [{"path": "src/app.py", "before": fs::read_to_string(baseline.0.join("app.py")).unwrap(), "after": after}],
        }),
    );
    let frozen = plan.freeze(Some(KEY)).unwrap();
    let result = run(
        id,
        &frozen,
        &inventory,
        &NativeProviderRegistry::new(&root.0),
        true,
    );
    assert!(
        result.findings.is_empty(),
        "suppression candidates are unadjudicated"
    );
    assert_eq!(result.details["producer"]["mode"], "host-diff");
    let actual = result.details["candidates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|candidate| {
            assert_eq!(candidate["sourceSide"], "selected");
            assert_eq!(candidate["adjudication"], "required");
            format!(
                "{}|{}|{}|{}",
                candidate["ruleId"].as_str().unwrap(),
                candidate["path"].as_str().unwrap(),
                candidate["line"].as_u64().unwrap(),
                candidate["suppressedRuleId"].as_str().unwrap()
            )
        })
        .collect();
    observation(case, expected, actual)
}

fn sarif_case(case: &str, results: Value, expected: &[&str]) -> CaseObservation {
    let id = "imported.sarif";
    let root = Fixture::new(case);
    root.write("src/app.py", "value = 1\nvalue = 2\n");
    let report = Fixture::new("sarif-report");
    let raw = json!({
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "frozen-fixture-scanner", "version": "1.0.0"}}, "results": results}],
    }).to_string();
    report.write("results.sarif", &raw);
    let inventory = inventory(&root.0);
    let frozen = plan(id, &root.0, &inventory).freeze(Some(KEY)).unwrap();
    let mut registry = NativeProviderRegistry::new(&root.0);
    // Production --out/run-directory discovery, with real immutable SARIF
    // bytes outside audited source scope. No scanner or tool receipt is faked.
    registry.security = registry.security.with_producer(
        ArtifactProducer::new(&root.0)
            .with_search_path(Vec::new())
            .with_run_dir(&report.0),
    );
    let result = run(id, &frozen, &inventory, &registry, true);
    assert_eq!(
        fs::read_to_string(report.0.join("results.sarif")).unwrap(),
        raw
    );
    assert_eq!(result.details["producer"]["mode"], "file");
    assert_eq!(result.details["analysis"]["denominator"]["expected"], 1);
    assert_eq!(result.details["analysis"]["denominator"]["examined"], 1);
    assert_eq!(result.details["candidates"], json!([]));
    let actual = result
        .findings
        .iter()
        .map(|finding| {
            let evidence = &result.details["findingEvidence"][finding.id.to_string()];
            format!(
                "{}|{}|{}",
                evidence["ruleId"].as_str().unwrap(),
                evidence["path"].as_str().unwrap(),
                evidence["line"].as_u64().unwrap()
            )
        })
        .collect();
    observation(case, expected, actual)
}

fn governance_case(case: &str, status: &str, expected: &[&str]) -> CaseObservation {
    let id = "governance.policy";
    let root = Fixture::new(case);
    root.write("policy-scope.txt", "Release approval policy record\n");
    let artifacts = Fixture::new("policy-artifact");
    let policy = json!({"policies": [{
        "policy": "release-review", "owner": "release-owner", "authority": "project-policy",
        "status": status, "disposition": "reviewed", "expiresAt": "2030-01-01T00:00:00Z",
        "evidence": ["immutable-review-record:fixture-1"],
    }]});
    artifacts.write("policies.json", &policy.to_string());
    let inventory = inventory(&root.0);
    let frozen = plan(id, &root.0, &inventory).freeze(Some(KEY)).unwrap();
    let mut registry = NativeProviderRegistry::new(&root.0);
    registry.legacy = registry
        .legacy
        .with_artifacts(
            serde_json::from_slice(&fs::read(artifacts.0.join("policies.json")).unwrap()).unwrap(),
        )
        .with_now("2026-10-19T00:00:00Z");
    let result = run(id, &frozen, &inventory, &registry, true);
    assert_eq!(
        result.details["analysis"]["scope"],
        "policy-record-shape-expiry-and-evidence-refs"
    );
    assert_eq!(result.details["analysis"]["denominator"]["expected"], 1);
    assert_eq!(result.details["analysis"]["denominator"]["examined"], 1);
    let rows = result.details["policyFindings"].as_array().unwrap();
    assert_eq!(
        result.findings.len(),
        rows.len(),
        "retain every policy finding"
    );
    let actual = rows
        .iter()
        .map(|row| {
            assert_eq!(row["certificationClaim"], false);
            format!(
                "policy:{}|status:{}",
                row["policy"].as_str().unwrap(),
                row["status"].as_str().unwrap()
            )
        })
        .collect();
    observation(case, expected, actual)
}

#[test]
fn file_only_provider_accuracy_artifacts() {
    let suppression = [
        suppression_case(
            "suppression-added",
            "value = 1\nother = 2\n",
            "value = 1 # noqa: S101\nother = 2 # nosec B101\n",
            &[
                "suppression-rule-added|src/app.py|1|S101",
                "suppression-rule-added|src/app.py|2|B101",
            ],
        ),
        suppression_case(
            "suppression-unchanged",
            "value = 1 # noqa: S101\n",
            "value = 1 # noqa: S101\n",
            &[],
        ),
        suppression_case(
            "suppression-narrowed",
            "value = 1 # noqa\n",
            "value = 1 # noqa: S101\n",
            &[],
        ),
        suppression_case(
            "suppression-string",
            "value = 1\n",
            "value = '# noqa: S101'\n",
            &[],
        ),
    ];
    accuracy_receipt::emit(
        "security.suppression-changes",
        "candidate",
        &suppression,
        FIXTURE,
    );

    let sarif = [
        sarif_case(
            "sarif-planted",
            json!([
                {"ruleId": "fixture.unsafe-input", "message": {"text": "Unsafe input"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}, "region": {"startLine": 1}}}]},
                {"ruleId": "fixture.unchecked-result", "message": {"text": "Unchecked result"}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/app.py"}, "region": {"startLine": 2}}}]},
            ]),
            &[
                "fixture.unsafe-input|src/app.py|1",
                "fixture.unchecked-result|src/app.py|2",
            ],
        ),
        sarif_case("sarif-clean", json!([]), &[]),
    ];
    accuracy_receipt::emit("imported.sarif", "finding", &sarif, FIXTURE);

    let governance = [
        governance_case(
            "policy-pending",
            "pending",
            &["policy:release-review|status:pending"],
        ),
        governance_case("policy-verified", "verified", &[]),
    ];
    accuracy_receipt::emit("governance.policy", "finding", &governance, FIXTURE);

    let id = "supply-chain.license-sbom-provenance";
    let root = Fixture::new("supply-chain-unqualified");
    root.write(
        "Cargo.lock",
        "[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\n",
    );
    let inventory = inventory(&root.0);
    let frozen = plan(id, &root.0, &inventory).freeze(Some(KEY)).unwrap();
    let mut registry = NativeProviderRegistry::new(&root.0);
    registry.security = registry
        .security
        .with_producer(ArtifactProducer::new(&root.0).with_search_path(Vec::new()));
    // This is an exclusion control: no owner admitted Syft. Qualified file
    // cases above still require available, fully examined native results.
    let execution = execute(&frozen, &inventory, &registry).unwrap();
    assert_eq!(execution.planned_providers, vec![id]);
    assert_eq!(execution.results.len(), 1);
    let entry = &execution.results[0];
    assert_eq!(entry.provider, id);
    assert!(!entry.skipped);
    let result = &entry.result;
    assert!(result.applicable);
    assert!(!result.complete);
    assert_eq!(
        result.details["availability"],
        json!({"state": "unavailable", "reason": legion_audit::execution_policy::ADMISSION_UNAVAILABLE})
    );
    let coverage = result.coverage.as_ref().expect("frozen exclusion coverage");
    let provider = frozen.provider(id).unwrap();
    assert_eq!(
        coverage.denominator_digest,
        provider.configuration["denominatorDigest"]
            .as_str()
            .unwrap()
    );
    assert_eq!(
        coverage.expected,
        provider.configuration["denominatorCount"].as_u64().unwrap()
    );
    assert!(coverage.expected > 0);
    // Frozen source paths were observed; denied SBOM scans prove no license result.
    assert_eq!(coverage.examined, coverage.expected);
    assert!(!coverage.gaps.is_empty());
    let receipts = result.details["executionReceipts"].as_array().unwrap();
    assert_eq!(
        receipts.len(),
        2,
        "both SBOM formats must request admission"
    );
    for receipt in receipts {
        assert_eq!(receipt["providerId"], id);
        assert_eq!(receipt["planId"], inventory.digest);
        assert_eq!(receipt["taskId"], "syft");
        assert_eq!(receipt["state"], "unauthorized_effect");
        assert_eq!(receipt["policy"]["allowed"], false);
        assert_eq!(
            receipt["policy"]["reason"],
            legion_audit::execution_policy::ADMISSION_UNAVAILABLE
        );
        assert_eq!(receipt["processTree"]["started"], false);
        assert_eq!(receipt["executable"], Value::Null);
        assert_eq!(receipt["stdout"], Value::Null);
        assert_eq!(receipt["stderr"], Value::Null);
    }
    assert_eq!(result.details["producer"]["mode"], "tool");
    assert!(result.details["analysis"]["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["kind"] == "supply-chain-provenance-invalid"));
    assert!(!result.coverage_gaps.is_empty());
    assert!(result.findings.is_empty());
    assert_eq!(result.details["candidates"], json!([]));
    println!(
        "FILE_PROVIDER_ACCURACY_EXCLUSION {}",
        json!({"provider": id,
        "qualificationEligible": false, "reason": "Source-only absence controls; dedicated native Syft SBOM/license controls required, target provenance remains unproven",
        "coverageGaps": result.coverage_gaps})
    );
}
