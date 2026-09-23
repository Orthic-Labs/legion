//! Integration tests for chunk w2_044
//! (`src/lib/dispatch-validator/{enforce_cheap_review_routing.py,
//! validate-dispatch.py (partial),validate-tasklist.py (partial)}`),
//! porting `test_enforce_cheap_review_routing.py` in full and
//! `test_validate_tasklist.py` for the paths inside the ported surface.
//! See `legion_runtime::wf_port::w2_044`'s module doc for what is and is
//! not ported.

use legion_runtime::wf_port::w2_044::routing::routing_errors;
use legion_runtime::wf_port::w2_044::tasklist::{validate_and_write_receipt, TasklistResult};
use std::path::PathBuf;
use std::process::Command;

fn git(dir: &std::path::Path, args: &[&str]) {
    let status = Command::new("git").arg("-C").arg(dir).args(args).status().unwrap();
    assert!(status.success(), "git {args:?} failed");
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// Builds the same fixture packet as both Python smoke tests'
/// `packet(root)` helper: a fresh git repo with a committed prompt +
/// route file, and a `packet.json` with `modelRouting.modelTier ==
/// "CHEAP_STRICT"` / `workerProfile == "strict"`.
fn fixture(dir: &std::path::Path) -> PathBuf {
    std::fs::create_dir_all(dir).unwrap();
    git(dir, &["init", "-q"]);
    git(dir, &["config", "user.email", "routing-test@example.test"]);
    git(dir, &["config", "user.name", "Routing Test"]);
    let prompt = dir.join("captured-prompt.txt");
    std::fs::write(&prompt, b"exact captured routing prompt").unwrap();
    let route = dir.join("sage-adjudication.json");
    std::fs::write(&route, b"{}").unwrap();
    git(dir, &["add", "."]);
    git(dir, &["commit", "-qm", "fixture source"]);
    let revision = String::from_utf8(
        Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["rev-parse", "HEAD"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_string();

    let value = serde_json::json!({
        "schemaVersion": 1,
        "kind": "legion-authority-dispatch",
        "packetType": "sage",
        "repositoryRoot": dir.to_string_lossy(),
        "sourceRevision": revision,
        "promptArtifact": prompt.to_string_lossy(),
        "promptDigest": format!("sha256:{}", sha256_hex(&std::fs::read(&prompt).unwrap())),
        "modelRouting": {
            "modelTier": "CHEAP_STRICT",
            "workerProfile": "strict",
            "routingRationale": "bounded execution",
        },
        "routeBundle": {
            "path": route.to_string_lossy(),
            "digest": format!("sha256:{}", sha256_hex(&std::fs::read(&route).unwrap())),
        },
    });
    let path = dir.join("packet.json");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    path
}

fn tmp_dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("w2_044-it-{name}-{}", std::process::id()))
}

/// Port of `test_enforce_cheap_review_routing.py::main()`.
#[test]
fn enforce_cheap_review_routing_tests() {
    let dir = tmp_dir("enforce");
    let path = fixture(&dir);

    // CHEAP_STRICT + strict passes.
    let packet: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let errors = routing_errors(&packet, &path);
    assert!(errors.is_empty(), "{errors:?}");

    // CHEAP_STRICT + standard fails with the doctrine message.
    let mut value = packet.clone();
    value["modelRouting"]["workerProfile"] = serde_json::json!("standard");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let errors = routing_errors(&value, &path);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("CHEAP_STRICT requires strict"), "{errors:?}");

    // Missing routingRationale fails on the base authority-packet check.
    let mut value = value;
    value["modelRouting"]
        .as_object_mut()
        .unwrap()
        .remove("routingRationale");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let errors = routing_errors(&value, &path);
    assert!(
        errors.iter().any(|e| e.contains("modelTier, workerProfile, routingRationale")),
        "{errors:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// Port of `test_validate_tasklist.py::main()`, scoped to the default
/// `--packet-type authority --receipt-mode write` path (the only mode this
/// chunk ports — see `legion_runtime::wf_port::w2_044`'s module doc).
#[test]
fn tasklist_tests() {
    let dir = tmp_dir("tasklist");
    let path = fixture(&dir);
    // The tasklist Python fixture uses FRONTIER/strict; align for parity.
    let mut value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    value["modelRouting"]["modelTier"] = serde_json::json!("FRONTIER");
    value["modelRouting"]["routingRationale"] = serde_json::json!("material ownership adjudication");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();

    let result = validate_and_write_receipt(&path, None).unwrap();
    let receipt_path = match result {
        TasklistResult::Pass { receipt_path } => receipt_path,
        TasklistResult::Fail { errors } => panic!("expected pass, got {errors:?}"),
    };
    assert!(receipt_path.is_file());

    // Missing routingRationale fails and reports the base authority-packet error.
    let mut value = value;
    value["modelRouting"]
        .as_object_mut()
        .unwrap()
        .remove("routingRationale");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    std::fs::remove_file(&receipt_path).ok();
    let result = validate_and_write_receipt(&path, None).unwrap();
    match result {
        TasklistResult::Fail { errors } => assert!(
            errors.iter().any(|e| e.contains("modelTier, workerProfile, routingRationale")),
            "{errors:?}"
        ),
        TasklistResult::Pass { .. } => panic!("expected failure"),
    }
    assert!(!receipt_path.exists(), "receipt must not be written on failure");

    std::fs::remove_dir_all(&dir).ok();
}
