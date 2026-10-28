//! Exercise shipped command behavior, including honest non-success exit states.
use serde_json::{json, Value};
use std::{path::{Path, PathBuf}, process::{Command, Output}, sync::atomic::{AtomicU64, Ordering}};

static NEXT_INPUT: AtomicU64 = AtomicU64::new(0);
struct InputFile(PathBuf);
impl InputFile {
    fn new(value: &Value) -> Self {
        let path = std::env::temp_dir().join(format!("legion-engineering-{}-{}.json",
            std::process::id(), NEXT_INPUT.fetch_add(1, Ordering::Relaxed)));
        std::fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        Self(path)
    }
}
impl Drop for InputFile {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
}
fn fixture(crate_name: &str, path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates").join(crate_name).join("tests").join(path)
}
fn read(path: &Path) -> Value { serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap() }
fn run(command: &str, subcommand: &str, input: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([command, subcommand, "--input"]).arg(input).output().unwrap()
}
fn json_output(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| panic!("{error}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)))
}

#[test]
fn plan_cli_reports_available_work_without_claiming_execution() {
    let output = run("work-plan", "validate", &fixture("legion-runtime", "workplan-ready.json"));
    assert_eq!(output.status.code(), Some(0));
    let value = json_output(&output);
    assert_eq!(value["assessment"]["readyUnits"], json!(["documentation", "implementation"]));
    assert_eq!(value["assessment"]["assertedCompleteUnits"], json!([]));
    assert_eq!(value["provenance"]["origin"], "imported");
    assert_eq!(value["provenance"]["authenticated"], false);
    assert_eq!(value["effectAuthority"], "none");
    assert_eq!(value["provenance"]["inputDigest"].as_str().unwrap().len(), 64);
}

#[test]
fn plan_cli_returns_a_structured_dependency_error() {
    let mut input = read(&fixture("legion-runtime", "workplan-ready.json"));
    input["units"][0]["dependsOn"] = json!(["missing-unit"]);
    let file = InputFile::new(&input);
    let output = run("work-plan", "validate", &file.0);
    assert_eq!(output.status.code(), Some(1));
    let value = json_output(&output);
    assert_eq!(value["valid"], false);
    assert_eq!(value["assessment"]["error"]["code"], "missing_dependency");
}

#[test]
fn stale_review_and_pr_observations_are_not_successful_cli_results() {
    let mut review = read(&fixture("legion-review", "rounds-approved.json"));
    review["currentDigest"] = json!("c".repeat(64));
    let file = InputFile::new(&review);
    let output = run("review-loop", "assess", &file.0);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(json_output(&output)["assessment"]["approved"], false);

    let mut delivery = read(&fixture("legion-runtime", "delivery-ready.json"));
    delivery["snapshot"]["headAfter"] = json!("c".repeat(40));
    let file = InputFile::new(&delivery);
    let output = run("delivery", "assess", &file.0);
    assert_eq!(output.status.code(), Some(2));
    let value = json_output(&output);
    assert_eq!(value["assessment"]["ready"], false);
    assert_eq!(value["assessment"]["effectAuthority"], "none");
}

#[test]
fn imported_delivery_cannot_spoof_an_authority_field() {
    let mut input = read(&fixture("legion-runtime", "delivery-ready.json"));
    input["mergeAuthorized"] = json!(true);
    let file = InputFile::new(&input);
    assert_eq!(run("delivery", "assess", &file.0).status.code(), Some(4));
}

#[test]
fn quality_cli_binds_the_original_report_bytes_and_preserves_measured_zero() {
    let input = fixture("legion-audit", "fixtures/quality-observation/example.json");
    let report = fixture("legion-audit", "fixtures/quality-observation/quality-raw-report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["quality", "summarize", "--input"]).arg(&input).arg("--report").arg(&report)
        .output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    let value = json_output(&output);
    assert_eq!(value["provenance"]["reportBytesMatched"], true);
    assert_eq!(value["assessment"]["authoritative"], false);
    assert_eq!(value["assessment"]["coverage"]["covered"], 0);
    let changed_report = InputFile::new(&json!({"changed": true}));
    let rejected = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["quality", "summarize", "--input"]).arg(&input).arg("--report").arg(&changed_report.0)
        .output().unwrap();
    assert_eq!(rejected.status.code(), Some(5));
}

#[test]
fn observation_without_host_credential_scope_stops_before_network_access() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["delivery", "observe", "--repository", "example/repository", "--pr", "1"])
        .env_remove("LEGION_AUTHORIZED_CREDENTIAL_PROVIDER")
        .env_remove("LEGION_GITHUB_TOKEN")
        .output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    let combined = format!("{}{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    assert!(combined.contains("credential scope unavailable"));
}
