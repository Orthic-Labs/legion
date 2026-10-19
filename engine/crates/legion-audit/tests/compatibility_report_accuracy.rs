//! Meaningful product report protocol controls; runtime certification remains unproven.
use legion_audit::native_providers::architecture::{
    report_compatibility::NativeReportObservation, ProviderExecutorAdapter,
};
use legion_audit::{
    AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry, ProviderExecutor,
};
use legion_contracts::ProviderSpec;
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

const README: &str = "# Usage\n\nSee `src/existing.rs` & `src/missing.rs`.\n";
const SOURCE: &str = "pub const VALUE: u32 = 3;\n";

fn write(path: &std::path::Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
#[ignore = "root integration runs through managed native CI with retained output"]
fn compatibility_report_native_known_answers() {
    let output = PathBuf::from(
        std::env::var_os("LEGION_COMPATIBILITY_REPORT_OUTPUT").expect("fresh retained output root"),
    );
    assert!(output.is_absolute() && !output.exists());
    fs::create_dir_all(&output).unwrap();
    let output = fs::canonicalize(output).unwrap();
    let root = output.join("fixture");
    write(&root.join("README.md"), README.as_bytes());
    write(&root.join("src/existing.rs"), SOURCE.as_bytes());
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory("compatibility-report-controls")
        .unwrap();
    assert_eq!(inventory.entries.len(), 2);
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    let specs = ["compatibility.core", "docs.contract"]
        .into_iter()
        .map(|id| {
            serde_json::from_value::<ProviderSpec>(
                registry["providers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|p| p["id"] == id)
                    .unwrap()
                    .clone(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let plan = AuditPlan::compile_with_root(Some(&root), &inventory, &specs)
        .unwrap()
        .freeze(Some(b"native-report-compatibility-controls"))
        .unwrap();
    assert_eq!(plan.providers().len(), 2);
    let provider = plan.provider("compatibility.core").unwrap();
    let fallback = NativeProviderRegistry::new(&root)
        .execute(provider, &inventory)
        .unwrap();
    assert!(!fallback.complete);
    assert_eq!(fallback.details["availability"]["state"], "unavailable");
    let observation = NativeReportObservation::capture(&root, &plan, &inventory).unwrap();
    let observed = observation.summary();
    assert_eq!(observed["protocolComplete"], true);
    assert_eq!(
        observed["execution"]["plannedProviders"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let report = &observed["reportV1"];
    assert_eq!(report["status"], "incomplete");
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    assert_eq!(report["findings"][0]["id"], "docs.contract:e73da6403495");
    assert_eq!(report["findings"][0]["locations"], json!(["README.md"]));
    assert_eq!(report["findings"][0]["severity"], "warning");
    assert_eq!(report["findings"][0]["title"], "Audit finding");
    assert_eq!(
        report["findings"][0]["message"],
        "Provider reported a finding"
    );
    assert_eq!(report["findings"][0]["provider"], "docs.contract");
    assert_eq!(
        report["findings"][0]["evidence"],
        json!({
        "claim":"README.md cites src/missing.rs","authority":"README.md","status":"contradicted",
        "evidence":[],"implementationInferred":false,"id":"docs.contract:e73da6403495","severity":"warning",
        "kind":"missing-cited-path","path":"README.md","line":3,"cited":"src/missing.rs"})
    );
    assert!(!report["gaps"].as_array().unwrap().is_empty());
    for name in ["schema-1", "schema-2"] {
        let case = &observed["cases"][name];
        assert_eq!(case["status"], "compatible");
        assert_eq!(case["expected"], case["observed"]);
        assert_eq!(case["observed"]["status"], "incomplete");
        assert_eq!(
            case["observed"]["findings"][0]["id"],
            "docs.contract:e73da6403495"
        );
    }
    for name in ["unsupported-schema", "missing-schema", "malformed-findings"] {
        assert_eq!(observed["controls"][name]["status"], "incompatible");
        assert!(observed["controls"][name]["error"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
    }
    let mut native = NativeProviderRegistry::new(&root);
    native.architecture = native
        .architecture
        .clone()
        .with_report_compatibility(observation.clone());
    let result = native.execute(provider, &inventory).unwrap();
    assert!(!result.complete);
    assert_eq!(
        result.coverage.as_ref().unwrap().denominator_digest,
        inventory.digest
    );
    assert_eq!(result.coverage.as_ref().unwrap().expected, 2);
    assert_eq!(result.coverage.as_ref().unwrap().examined, 2);
    assert_eq!(result.coverage_gaps, ["runtime-evidence-trust-unavailable"]);
    assert_eq!(
        result.details["nativeAnalysis"]["nativeReportCompatibility"],
        observed
    );
    // A copied JSON document never re-creates opaque producer provenance.
    let copied = ProviderExecutorAdapter::new().with_root(&root).with_input(
        "compatibility.core",
        json!({"nativeReportCompatibility":observed}),
    );
    let copied = copied.execute(provider, &inventory).unwrap();
    assert!(!copied.complete);
    assert!(copied.details["nativeAnalysis"]
        .get("nativeReportCompatibility")
        .is_none());
    // Same trusted observation cannot follow selected source changes.
    fs::write(
        root.join("src/existing.rs"),
        format!("{SOURCE}// source drift\n"),
    )
    .unwrap();
    let drifted = native.execute(provider, &inventory).unwrap();
    assert!(!drifted.complete);
    assert!(drifted
        .coverage_gaps
        .contains(&"report-protocol-observation-binding-invalid".into()));
    assert!(NativeReportObservation::capture(&root, &plan, &inventory).is_err());
    fs::write(root.join("src/existing.rs"), SOURCE).unwrap();
    let mut changed_provider = provider.clone();
    changed_provider
        .configuration
        .insert("denominatorCount".into(), json!(1));
    let binding = native.execute(&changed_provider, &inventory).unwrap();
    assert!(binding
        .coverage_gaps
        .contains(&"report-protocol-observation-binding-invalid".into()));
    let mut tampered = observed.clone();
    tampered["cases"]["schema-1"]["renderedBytes"] = json!("tampered");
    let controls = json!({"copiedJson":copied,"sourceDrift":drifted,"providerBinding":binding,
        "tamperedObservation":tampered});
    // A distinct file denominator proves two schema contracts are not file counts.
    let extra_root = output.join("three-file-fixture");
    write(&extra_root.join("README.md"), README.as_bytes());
    write(&extra_root.join("src/existing.rs"), SOURCE.as_bytes());
    write(
        &extra_root.join("src/additional.rs"),
        b"pub const EXTRA: u32 = 4;\n",
    );
    let extra_inventory = FilesystemInventorySource::new(&extra_root)
        .unwrap()
        .inventory("compatibility-report-three-files")
        .unwrap();
    assert_eq!(extra_inventory.entries.len(), 3);
    let extra_plan = AuditPlan::compile_with_root(Some(&extra_root), &extra_inventory, &specs)
        .unwrap()
        .freeze(Some(b"native-report-compatibility-controls"))
        .unwrap();
    let extra_observation =
        NativeReportObservation::capture(&extra_root, &extra_plan, &extra_inventory).unwrap();
    let mut extra_native = NativeProviderRegistry::new(&extra_root);
    extra_native.architecture = extra_native
        .architecture
        .clone()
        .with_report_compatibility(extra_observation.clone());
    let extra_result = extra_native
        .execute(
            extra_plan.provider("compatibility.core").unwrap(),
            &extra_inventory,
        )
        .unwrap();
    assert_eq!(extra_result.coverage.as_ref().unwrap().expected, 3);
    assert_eq!(extra_result.coverage.as_ref().unwrap().examined, 3);
    assert_eq!(
        extra_result.details["nativeAnalysis"]["denominator"]["kind"],
        "source-files"
    );
    assert_eq!(
        extra_result.details["nativeAnalysis"]["protocolDenominator"],
        json!({"kind":"report-schema-contracts","expected":2,"examined":2})
    );
    let non_two_files = json!({"inventory":extra_inventory,"plan":extra_plan.plan(),"observation":extra_observation.summary(),"result":extra_result});
    let source_manifest_path = PathBuf::from(
        std::env::var_os("LEGION_COMPATIBILITY_REPORT_SOURCE_MANIFEST")
            .expect("current source manifest"),
    );
    let source_manifest: Value =
        serde_json::from_slice(&fs::read(source_manifest_path).unwrap()).unwrap();
    let mut row = json!({"schema":"legion-compatibility-report-accuracy/1","provider":"compatibility.core","stage":"fact-output",
        "scope":"native Audit report v1/v2 v1-core preservation; excludes v2-only fields/extensions","productionQualification":false,"wholeProviderQualified":false,
        "auditCleanClaim":false,"qualificationEligible":true,"modelCalls":0,"sourceManifest":source_manifest,
        "inventory":inventory,"plan":plan.plan(),"planDigest":plan.digest(),"planSignature":plan.signature(),
        "fallback":fallback,"result":result,"observation":observed,"controls":controls,"nonTwoFiles":non_two_files});
    row["qualificationDigest"] = json!(legion_audit::digest(&row).unwrap());
    write(
        &output.join("compatibility.core.json"),
        &serde_json::to_vec_pretty(&row).unwrap(),
    );
    println!(
        "COMPATIBILITY_REPORT_PROVIDER_ACCURACY {}",
        serde_json::to_string(&row).unwrap()
    );
}
