use std::process::Command;

fn legion(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(arguments)
        .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
        .output()
        .expect("native Legion CLI must execute")
}

#[test]
fn audit_help_lists_assurance_flags_and_gate() {
    let output = legion(&["audit", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "--runtime-policy",
        "--product-contract",
        "--artifact-manifest",
        "gate",
        "pre-pr",
    ] {
        assert!(text.contains(needle), "audit --help must mention {needle}");
    }
}

#[test]
fn gate_help_names_its_verdicts_and_requires_a_run() {
    let output = legion(&["audit", "gate", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("--run"));
    assert!(text.contains("blocked-findings"));
    let output = legion(&["audit", "gate"]);
    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn gate_on_a_missing_run_is_incomplete_never_success() {
    let output = legion(&["audit", "gate", "--run", "/nonexistent-legion-gate-run"]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn gate_rejects_an_unknown_required_profile() {
    let output = legion(&["audit", "gate", "--run", ".", "--profile", "standard"]);
    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn assurance_flags_require_a_new_profile() {
    let output = legion(&[
        "audit",
        ".",
        "--plan-only",
        "--profile",
        "standard",
        "--runtime-policy",
        "no-node-python",
    ]);
    // The legacy profile (named explicitly) rejects assurance-only flags; the
    // bare default is `repository`, which accepts them.
    assert_eq!(output.status.code(), Some(4));
    let output = legion(&[
        "audit",
        ".",
        "--runtime-policy",
        "unrestricted",
        "--profile",
        "release",
    ]);
    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn report_help_still_accepts_new_projection_kinds_as_text() {
    let output = legion(&[
        "report",
        "/nonexistent-report.json",
        "--report",
        "assurance",
    ]);
    assert_ne!(output.status.code(), Some(0));
}

/// Without a host-owned issuer enrollment (or with an untrustworthy one) an
/// imported manifest must stay unmet; only an enrolled issuer's Ed25519
/// signature can satisfy it (covered in legion-audit authenticated_artifacts).
#[test]
fn import_without_trusted_issuer_enrollment_stays_unmet() {
    use serde_json::{json, Value};
    let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/legion-audit/tests/fixtures/authenticated-artifacts/node-ci");
    let envelope: Value =
        serde_json::from_slice(&std::fs::read(fixtures.join("envelope.json")).unwrap()).unwrap();
    let subject = &envelope["subject"];
    let expected = json!({
        "kind": envelope["kind"], "repositories": subject["repositories"],
        "target": subject["target"], "variant": subject["variant"],
        "toolchain": subject["toolchain"], "configDigest": subject["configDigest"],
        "testSelectionDigest": subject["testSelectionDigest"],
        "dependencyGraphDigest": subject["dependencyGraphDigest"],
        "workloadDigest": subject["workloadDigest"], "command": subject["command"],
        "requiredScope": envelope["scope"]["examined"], "requiredArtifacts": envelope["artifacts"],
        "replayPolicy": "deny"
    });
    let dir = std::env::temp_dir().join(format!("legion-import-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut artifacts = serde_json::Map::new();
    for artifact in envelope["artifacts"].as_array().unwrap() {
        let name = artifact["path"].as_str().unwrap();
        if let Some(parent) = dir.join(name).parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        // Artifact paths are relative to the fixture set root (`node-ci/...`).
        std::fs::copy(fixtures.parent().unwrap().join(name), dir.join(name)).unwrap();
        artifacts.insert(name.into(), json!(name));
    }
    std::fs::copy(
        fixtures.join("attestation.json"),
        dir.join("attestation.json"),
    )
    .unwrap();
    let manifest = json!({
        "obligation": {
            "product": "p", "snapshots": [], "target": "web-production",
            "concern": "tests", "evidenceKind": "test",
            "ruleProfileRevision": "legion-audit-profile/1"
        },
        "envelope": envelope, "expected": expected,
        "attestationPath": "attestation.json", "artifacts": artifacts
    });
    let manifest_path = dir.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    // A repository-local enrollment with loose permissions: never honored.
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    std::fs::write(state.join("audit-evidence-issuers.json"), b"{}").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "audit",
            ".",
            "--plan-only",
            "--json",
            "--profile",
            "repository",
            "--artifact-manifest",
        ])
        .arg(&manifest_path)
        .current_dir(&dir)
        .env("LEGION_STATE_ROOT", &state)
        .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
        .output()
        .expect("legion executes");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!text.contains("\"verified\": true"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
}
