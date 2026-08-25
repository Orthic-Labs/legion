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
            "selector": {"op": "all"},
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
