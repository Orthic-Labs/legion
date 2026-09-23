use std::process::Command;

/// Rewritten from the retired `native_rules_evaluate_blueprint_bound_source`:
/// Legion (Rust) has no Blueprint/Membrane dependency, so `rules` evaluates
/// against its own local-filesystem inventory directly — there is no packet
/// to bind, so the `--blueprint-packet`/`--expected-generation` flags this
/// test used to pass are gone from the CLI entirely.
#[test]
fn native_rules_evaluate_local_inventory_bound_source() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-rules-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/service.rs"),
        "fn update() { let url = \"http://updates.example\"; }\n",
    )
    .unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "rules",
            "--manifest",
            manifest.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--provider",
            "native.security.rules",
            "--pack",
            "security.native-workspace",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "complete");
    assert_eq!(result["providerResult"]["complete"], true);
    assert_eq!(
        result["providerResult"]["findings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        result["providerResult"]["coverage"]["denominator_digest"],
        result["inventoryDigest"]
    );

    let result_path = root.join("rule-result.json");
    std::fs::write(&result_path, &output.stdout).unwrap();
    let plan = serde_json::json!({
        "providers": [{
            "schemaVersion": 2,
            "id": "native.security.rules",
            "providerVersion": "1",
            "family": "security",
            "lensIds": [],
            "role": "deterministic",
            "phase": "source",
            "dependsOn": [],
            "consumes": ["repository-inventory"],
            "produces": ["provider-result"],
            "selector": {"op": "always"},
            "denominatorKind": "repository-inventory",
            "runner": {"kind": "built-in"},
            "hostCapabilities": [],
            "execution": {},
            "reasoning": {},
            "benchmark": {
                "status": "qualified",
                "requiredForCleanClaim": true,
                "qualificationDigest": "sha256:fixture"
            },
            "cleanClaim": "finding-producing",
            "controlIds": [],
            "scopes": [],
            "selectable": true
        }]
    });
    let plan_path = root.join("provider-plan.json");
    std::fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
    let audit_out = root.join("audit");
    let audit = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "audit",
            "--out",
            audit_out.to_str().unwrap(),
            "--provider-plan",
            plan_path.to_str().unwrap(),
            "--provider-result",
            result_path.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .env("AUDIT_PLAN_SIGNING_KEY", "fixture-signing-key")
        .output()
        .unwrap();
    assert_eq!(
        audit.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&audit.stderr)
    );
    let audit_summary: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap();
    assert_eq!(audit_summary["auditStatus"], "findings");
    assert_eq!(audit_summary["findingCount"], 1);
    assert!(audit_out.join("report.json").is_file());
    assert!(audit_out.join("report.sarif").is_file());
}

/// Rewritten from the retired `native_audit_continues_without_blueprint`:
/// Legion (Rust) has no Blueprint/Membrane fallback path to exercise — its
/// filesystem inventory is the only source, not a degraded fallback — so
/// this now asserts the plain local-inventory run completes without any
/// blueprint-flavored context notice.
#[test]
fn native_audit_runs_on_local_filesystem_inventory_only() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-audit-fallback-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join(".audit/inputs")).unwrap();
    std::fs::write(root.join("src/service.rs"), "fn service() {}\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    let rules = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "rules",
            "--manifest",
            manifest.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--provider",
            "native.fixture",
        ])
        .output()
        .unwrap();
    assert_eq!(
        rules.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&rules.stderr)
    );
    let rules_summary: serde_json::Value = serde_json::from_slice(&rules.stdout).unwrap();
    assert_eq!(rules_summary["status"], "complete");
    // Legion has no external context engine to fall back from: the local
    // filesystem inventory is the only source, so there is nothing to notice.
    assert_eq!(rules_summary["contextNotices"], serde_json::json!([]));
    let plan = serde_json::json!({
        "providers": [{
            "schemaVersion": 2,
            "id": "native.fixture",
            "providerVersion": "1",
            "family": "security",
            "lensIds": [],
            "role": "deterministic",
            "phase": "source",
            "dependsOn": [],
            "consumes": ["repository-inventory"],
            "produces": ["provider-result"],
            "selector": {"op": "always"},
            "denominatorKind": "repository-inventory",
            "runner": {"kind": "built-in"},
            "hostCapabilities": [],
            "execution": {},
            "reasoning": {},
            "benchmark": {
                "status": "qualified",
                "requiredForCleanClaim": true,
                "qualificationDigest": "sha256:fixture"
            },
            "cleanClaim": "finding-producing",
            "controlIds": [],
            "scopes": [],
            "selectable": true
        }]
    });
    let plan_path = root.join(".audit/inputs/provider-plan.json");
    let result_path = root.join(".audit/inputs/provider-result.json");
    std::fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
    std::fs::write(&result_path, &rules.stdout).unwrap();
    let audit_out = root.join(".audit/output");
    let audit = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "audit",
            "--out",
            audit_out.to_str().unwrap(),
            "--provider-plan",
            plan_path.to_str().unwrap(),
            "--provider-result",
            result_path.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .env("AUDIT_PLAN_SIGNING_KEY", "fixture-signing-key")
        .output()
        .unwrap();
    assert_eq!(
        audit.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&audit.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap();
    assert_eq!(summary["auditStatus"], "pass");
    assert_eq!(summary["contextNotices"], serde_json::json!([]));
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit_out.join("report.json")).unwrap()).unwrap();
    // No degraded-context notice is recorded on the report claims either —
    // there is no external context engine for Legion to have fallen back from.
    assert!(report["claims"].get("contextNotices").is_none());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_audit_composes_builtin_rule_executor_without_host_config() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-audit-composed-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/service.rs"), "fn service() {}\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    let out = root.join("audit");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "audit",
            "--out",
            out.to_str().unwrap(),
            "--native-rule-manifest",
            manifest.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
        .env("AUDIT_PLAN_SIGNING_KEY", "fixture-signing-key")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["auditStatus"], "incomplete");
    assert_eq!(summary["qualityGate"], "unproven");
    assert!(summary["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap == "native-provider-composition-partial"));
    assert_eq!(
        summary["plannedProviders"],
        serde_json::json!(["security.native-rules"])
    );
    assert_eq!(summary["resultCount"], 1);
    assert_eq!(summary["processExecution"], "complete");
    assert!(out.join("report.json").is_file());
    assert!(out.join("execution.json").is_file());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_rules_report_unproven_for_invalid_source_bytes() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-rules-invalid-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/binary.rs"), [0xff, 0xfe]).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "rules",
            "--manifest",
            manifest.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--provider",
            "native.fixture",
            "--pack",
            "security.native-workspace",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "incomplete");
    assert_eq!(result["providerResult"]["complete"], false);
    assert!(result["providerResult"]["coverage_gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap.as_str().unwrap().contains("source-invalid-utf8")));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_rules_emits_selector_bound_denominator() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-rules-selector-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("docs")).unwrap();
    std::fs::write(root.join("src/service.rs"), "fn service() {}\n").unwrap();
    std::fs::write(root.join("docs/readme.md"), "fixture\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "rules",
            "--manifest",
            manifest.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--provider",
            "native.fixture",
            "--selector",
            r#"{"op":"anyPath","patterns":["src/*.rs"]}"#,
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["providerResult"]["coverage"]["expected"], 1);
    assert_ne!(
        result["providerResult"]["coverage"]["denominator_digest"],
        result["inventoryDigest"]
    );
    assert_eq!(
        result["denominatorDigest"],
        result["providerResult"]["coverage"]["denominator_digest"]
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn native_audit_without_signing_material_runs_source_scan_as_unsigned_incomplete() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-audit-unsigned-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/service.rs"), "fn service() {}\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    let out = root.join("audit");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "audit",
            "--out",
            out.to_str().unwrap(),
            "--native-rule-manifest",
            manifest.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
        .env_remove("AUDIT_PLAN_SIGNING_KEY")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["auditStatus"], "incomplete");
    assert_eq!(summary["qualityGate"], "unproven");
    assert!(summary["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap == "native-provider-composition-partial"));
    assert_eq!(
        summary["plannedProviders"],
        serde_json::json!(["security.native-rules"])
    );
    assert_eq!(summary["resultCount"], 1);
    assert_eq!(summary["processExecution"], "complete");
    assert!(out.join("report.json").is_file());
    assert!(out.join("execution.json").is_file());
    assert!(summary["gaps"].as_array().unwrap().iter().any(|gap| gap == "unsigned-plan"));
    assert!(summary["planSignature"].is_null());
    let plan: serde_json::Value = serde_json::from_slice(&std::fs::read(out.join("plan.json")).unwrap()).unwrap();
    assert_eq!(plan["seal"]["authenticity"], "unsigned");
    std::fs::remove_dir_all(root).unwrap();
}
