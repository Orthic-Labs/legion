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
    assert_eq!(result["providerResult"]["findings"].as_array().unwrap().len(), 1);
    assert_eq!(
        result["providerResult"]["coverage"]["denominator_digest"],
        result["inventoryDigest"]
    );
}
