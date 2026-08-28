use std::process::Command;

#[test]
fn native_rules_evaluate_blueprint_bound_source() {
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
    let packet = serde_json::json!({
        "schema": "membrane.blueprint-packet.v1",
        "status": "ready",
        "state": "ready",
        "generationId": "fixture-generation",
        "manifestDigest": format!("sha256:{}", "1".repeat(64)),
        "sourceObservation": {"kind": "fixture"},
        "files": ["src/service.rs"],
        "fileCount": 1,
        "sourceFileCount": 1,
        "parsedExtensions": ["rs"],
        "unsupportedExtensions": [],
        "overlay": {"state": "ready", "dirtyTracked": 0, "untracked": 0}
    });
    let packet_path = root.join("blueprint-packet.json");
    std::fs::write(&packet_path, serde_json::to_vec_pretty(&packet).unwrap()).unwrap();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "rules",
            "--manifest",
            manifest.to_str().unwrap(),
            "--blueprint-packet",
            packet_path.to_str().unwrap(),
            "--expected-generation",
            "fixture-generation",
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
            "consumes": ["blueprint-packet"],
            "produces": ["provider-result"],
            "selector": {"op": "always"},
            "denominatorKind": "blueprint-inventory",
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
            root.to_str().unwrap(),
            "--out",
            audit_out.to_str().unwrap(),
            "--blueprint-packet",
            packet_path.to_str().unwrap(),
            "--expected-generation",
            "fixture-generation",
            "--provider-plan",
            plan_path.to_str().unwrap(),
            "--provider-result",
            result_path.to_str().unwrap(),
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

#[test]
fn native_audit_continues_without_blueprint() {
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
    assert!(rules_summary["contextNotices"][0]
        .as_str()
        .unwrap()
        .contains("Audit continued"));
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
            root.to_str().unwrap(),
            "--out",
            audit_out.to_str().unwrap(),
            "--provider-plan",
            plan_path.to_str().unwrap(),
            "--provider-result",
            result_path.to_str().unwrap(),
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
    assert!(summary["contextNotices"][0]
        .as_str()
        .unwrap()
        .contains("Audit continued"));
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit_out.join("report.json")).unwrap()).unwrap();
    assert!(report["claims"]["contextNotices"][0]
        .as_str()
        .unwrap()
        .contains("Use Membrane as context engine"));
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
            root.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--native-rule-manifest",
            manifest.to_str().unwrap(),
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
