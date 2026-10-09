use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "legion-minimize-cli-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        // Canonical (macOS temp is behind a /var symlink) so git and the CLI
        // agree on the fixture's path.
        Self(fs::canonicalize(&root).unwrap())
    }

    fn run(&self, args: &[&str]) -> Output {
        // Isolate from any installed Legion on the host: minimize resolves its
        // policy asset from an installed release when one exists under the
        // user's home, which differs from this checkout's copy.
        // Outside the fixture repository so it never shows up as untracked.
        let home = PathBuf::from(format!("{}-home", self.0.display()));
        Command::new(env!("CARGO_BIN_EXE_legion"))
            .current_dir(&self.0)
            .env("GIT_CEILING_DIRECTORIES", self.0.parent().unwrap())
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .env("LOCALAPPDATA", home.join("AppData/Local"))
            .env("XDG_DATA_HOME", home.join(".local/share"))
            .env_remove("MINIMIZE_BASE_REF")
            .args(args)
            .output()
            .unwrap()
    }

    fn git(&self, args: &[&str]) -> Output {
        Command::new("git")
            .current_dir(&self.0)
            .env("GIT_CEILING_DIRECTORIES", self.0.parent().unwrap())
            .args(args)
            .output()
            .unwrap()
    }

    fn git_pass(&self, args: &[&str]) {
        let output = self.git(args);
        assert!(
            output.status.success(),
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn pass(&self, args: &[&str]) {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "MINIMIZE PASS"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
        let _ = fs::remove_dir_all(format!("{}-home", self.0.display()));
    }
}

#[test]
fn native_minimize_decision_receipt_binds_executable_and_rejects_tampering() {
    let fixture = Fixture::new();
    let decision = json!({
        "schema": "minimize-decision.v1", "decision_id": "native-fixture",
        "state_a": "missing receipt", "state_b": "validated receipt",
        "selected_rung": "REUSE", "prior_rungs": [{"rung": "NOT_BUILD",
            "verdict": "REJECTED", "evidence": "requested native validation"}],
        "allowed_new_files": [], "allowed_new_dependencies": []
    });
    fs::write(fixture.0.join("decision.json"), decision.to_string()).unwrap();
    fixture.pass(&["minimize", "decision", "validate", "decision.json"]);
    fixture.pass(&[
        "minimize",
        "decision",
        "receipt",
        "decision.json",
        "receipt.json",
    ]);
    fixture.pass(&[
        "minimize",
        "decision",
        "verify",
        "decision.json",
        "receipt.json",
    ]);
    let path = fixture.0.join("receipt.json");
    let mut receipt: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let native_hash = Sha256::digest(fs::read(env!("CARGO_BIN_EXE_legion")).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(receipt["validator_sha256"], native_hash);
    receipt["validator_sha256"] = json!("0".repeat(64));
    fs::write(&path, receipt.to_string()).unwrap();
    let failed = fixture.run(&[
        "minimize",
        "decision",
        "verify",
        "decision.json",
        "receipt.json",
    ]);
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr).contains("validator_sha256 mismatch"));
}

#[test]
fn native_minimize_commit_receipt_rejects_staged_tree_drift() {
    let fixture = Fixture::new();
    fixture.git_pass(&["init", "-q"]);
    fixture.git_pass(&["config", "user.name", "Legion Test"]);
    fixture.git_pass(&["config", "user.email", "legion@example.test"]);
    fs::write(fixture.0.join("README.md"), "initial\n").unwrap();
    fixture.git_pass(&["add", "README.md"]);
    fixture.git_pass(&["commit", "-qm", "initial"]);

    fs::write(fixture.0.join("candidate.txt"), "candidate\n").unwrap();
    fixture.git_pass(&["add", "candidate.txt"]);
    fixture.pass(&["minimize", "commit", "init-review", "review.json"]);
    fixture.pass(&[
        "minimize",
        "commit",
        "receipt",
        "review.json",
        "receipt.json",
    ]);
    fixture.pass(&["minimize", "commit", "verify", "receipt.json"]);

    let review: Value =
        serde_json::from_slice(&fs::read(fixture.0.join("review.json")).unwrap()).unwrap();
    let receipt: Value =
        serde_json::from_slice(&fs::read(fixture.0.join("receipt.json")).unwrap()).unwrap();
    assert_eq!(review["schema"], "minimize-commit-review.v1");
    assert_eq!(receipt["schema"], "minimize-commit-receipt.v1");
    assert_eq!(receipt["candidate_tree"], review["candidate_tree"]);
    assert_eq!(receipt["scope_files"], json!(["candidate.txt"]));

    fs::write(fixture.0.join("candidate.txt"), "drifted\n").unwrap();
    fixture.git_pass(&["add", "candidate.txt"]);
    let failed = fixture.run(&["minimize", "commit", "verify", "receipt.json"]);
    assert!(!failed.status.success());
    assert!(String::from_utf8_lossy(&failed.stderr)
        .contains("stale commit receipt: candidate_tree mismatch"));
}
