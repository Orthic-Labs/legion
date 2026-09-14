use std::process::Command;

fn legion(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(arguments)
        .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
        .output()
        .expect("native Legion CLI must execute")
}

fn output_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("native Legion output must be JSON")
}

#[test]
fn bind_registrations_reports_host_state() {
    let output = legion(&["bind", "--registrations", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value = output_json(&output);
    assert_eq!(value["kind"], "legion-bind-registrations");
}

fn bind_explicit_claude_code_is_retired() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repository root")
        .join("tests/fixtures/minimal-repo");
    let output = legion(&["bind", "--harness", "claude-code", root.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value = output_json(&output);
    assert_eq!(value["kind"], "legion-bind-preview");
    let harnesses = value["harnesses"].as_array().expect("harnesses");
    let claude = harnesses
        .iter()
        .find(|entry| entry["name"] == "claude-code")
        .expect("claude-code harness");
    assert_eq!(claude["retired"], true);
}

fn hooks_install_reports_unimplemented_surface() {
    let output = legion(&["--json", "hooks", "install"]);
    assert_eq!(output.status.code(), Some(0));
    let value = output_json(&output);
    assert_eq!(value["kind"], "legion-hooks");
    assert_eq!(value["implemented"], false);
}

fn explain_missing_id_is_usage_exit() {
    let output = legion(&["explain", "--json"]);
    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn budget_inspect_requires_contract_version_and_task() {
    let output = legion(&["budget", "inspect"]);
    assert_eq!(output.status.code(), Some(4));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("budget inspect requires --contract"));
}

#[test]
fn governance_delivery_capacity_reaches_scheduler() {
    let output = legion(&[
        "governance",
        "delivery",
        "--json",
        r#"{"operation":"dispatch-capacity","input":{"readyTasks":[{"id":"t1"}],"constraints":[]}}"#,
    ]);
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert_eq!(value["outcome"], "CAPACITY_ADMITTED");
    assert!(value["admitted"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
}

#[test]
fn governance_execution_classify_is_diagnostic_without_capability() {
    let output = legion(&[
        "governance",
        "execution",
        "--json",
        r#"{"operation":"execution.retry.classify","input":{"failure_class":"AUTHENTICATION"}}"#,
    ]);
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert_eq!(value["kind"], "arcane-execution-control-decision");
    assert_eq!(value["consumable"], false);
}

#[test]
fn governance_requires_json_request() {
    let output = legion(&["governance", "execution"]);
    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn governance_judgment_verify_closure_without_host_is_internal_error() {
    let output = legion(&[
        "governance",
        "judgment",
        "--json",
        r#"{"operation":"finding.verify-closure","payload":{}}"#,
    ]);
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert_eq!(value["code"], "ARC_INTERNAL_ERROR");
}

#[test]
fn governance_judgment_deficit_classify_without_host_is_internal_error() {
    let output = legion(&[
        "governance",
        "judgment",
        "--json",
        r#"{"operation":"deficit.classify","payload":{}}"#,
    ]);
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert_eq!(value["code"], "ARC_INTERNAL_ERROR");
}

#[test]
fn governance_judgment_advisory_query_requires_key_dir() {
    let output = legion(&[
        "governance",
        "judgment",
        "--json",
        r#"{"operation":"advisory.query","payload":{"expected":{}}}"#,
    ]);
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert_eq!(value["code"], "ARC_AUTH_KEY_UNAVAILABLE");
}

#[test]
fn budget_inspect_requires_arcane_key_dir() {
    let output = legion(&[
        "budget",
        "inspect",
        "--contract",
        "EC-1",
        "--version",
        "1",
        "--task",
        "T-1",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ARC_AUTH_KEY_UNAVAILABLE"));
}

fn mcp_print_config_uses_current_executable() {
    let output = legion(&["mcp", "print-config", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value = output_json(&output);
    assert_eq!(value["kind"], "legion-mcp-config");
    assert_eq!(value["args"], serde_json::json!(["serve", "--stdio"]));
}

fn init_preview_reports_complete_without_installed_binding() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repository root")
        .join("tests/fixtures/minimal-repo");
    let output = legion(&["init", root.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value = output_json(&output);
    assert_eq!(value["kind"], "legion-init-preview");
    assert_eq!(value["dryRun"], true);
}

#[test]
fn topology_inspect_reports_unproven_on_empty_repository() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repository root")
        .join("tests/fixtures/minimal-repo");
    let output = legion(&["inspect", root.to_str().unwrap(), "--json"]);
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert_eq!(value["complete"], false);
    assert_eq!(value["status"], "unproven");
    assert_eq!(value["detail"], "target-denominator-zero");
    assert_eq!(
        value.pointer("/artifact/kind").and_then(|kind| kind.as_str()),
        Some("legion-product-inspection")
    );
}

#[test]
fn topology_slices_exit_incomplete_without_targets() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repository root")
        .join("tests/fixtures/minimal-repo");
    for command in ["targets", "components", "stacks", "controls"] {
        let output = legion(&[command, root.to_str().unwrap(), "--json"]);
        assert_eq!(output.status.code(), Some(2), "{command}");
        let value = output_json(&output);
        assert!(value.get("artifact").is_some(), "{command}");
    }
}

#[test]
fn default_doctor_cannot_make_clean_claim() {
    let output = legion(&["doctor", ".", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value = output_json(&output);
    assert!(value.get("status").is_none());
    assert_eq!(value["cleanClaimPossible"], false);
}

#[test]
fn doctor_json_output_carries_no_human_rendering_keys() {
    // The `--json` contract must stay byte-identical: the human table is only
    // added when `--json` is absent, never to the machine payload.
    let output = legion(&["doctor", ".", "--json"]);
    let value = output_json(&output);
    assert!(value.get("text").is_none(), "doctor --json must not embed text");
    assert!(
        value.get("json").is_none(),
        "doctor --json must not embed a json flag"
    );
}

#[test]
fn skills_json_output_carries_no_human_rendering_keys() {
    // Same contract as doctor: `--json` never carries the human table keys.
    // Without an installed release the command fails closed on stderr; when it
    // does emit a JSON payload it must be the machine shape only.
    let output = legion(&["skills", "--json"]);
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
        assert!(value.get("text").is_none(), "skills --json must not embed text");
        assert!(
            value.get("json").is_none(),
            "skills --json must not embed a json flag"
        );
    } else {
        assert_eq!(output.status.code(), Some(2));
    }
}

#[test]
fn plan_stays_fail_closed_without_native_composition() {
    let plan = legion(&["plan", ".", "--json"]);
    assert_eq!(plan.status.code(), Some(2));
    let plan_value = output_json(&plan);
    assert_eq!(plan_value["status"], "incomplete");
    assert!(plan_value["gaps"]
        .as_array()
        .is_some_and(|gaps| !gaps.is_empty()));
}

#[test]
fn cutoff_assurance_reports_remaining_legacy_runtime() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repository root");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["assurance", root.to_str().unwrap(), "--json"])
        .output()
        .expect("native Legion CLI must execute");
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert_eq!(value["status"], "incomplete");
    assert!(value["legacyExecutableCount"]
        .as_u64()
        .is_some_and(|count| count > 0));
}

#[test]
fn run_lifecycle_never_uses_default_provider_as_completion_evidence() {
    let output = legion(&["run", "open", "--contract", "fixture", "--version", "1"]);
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert_eq!(value["status"], "incomplete");
    assert!(value["gaps"]
        .as_array()
        .is_some_and(|gaps| !gaps.is_empty()));
}
