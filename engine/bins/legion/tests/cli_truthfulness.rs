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

#[test]
fn bind_explicit_claude_code_is_retired() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("repository root")
        .join("tests/fixtures/minimal-repo");
    let output = legion(&[
        "bind",
        "--harness",
        "claude-code",
        root.to_str().unwrap(),
        "--json",
    ]);
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

#[test]
fn hooks_status_reads_host_configs_from_an_isolated_home() {
    let home = std::env::temp_dir().join(format!("legion-hooks-status-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_legion"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .args(["--json", "hooks", "status"])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = output_json(&output);
    assert_eq!(value["kind"], "legion-hooks-status");
    assert_eq!(value["registered"], false);
    assert_eq!(value["hosts"].as_array().unwrap().len(), 3);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn fix_defaults_to_dry_run_and_mcp_install_previews() {
    let home = std::env::temp_dir().join(format!("legion-fix-dry-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_legion"))
            .env("HOME", &home)
            .env("USERPROFILE", &home)
            .args(args)
            .output()
            .unwrap()
    };
    let fix = run(&["--json", "fix"]);
    assert_eq!(
        fix.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&fix.stderr)
    );
    let value = output_json(&fix);
    assert_eq!(value["kind"], "legion-fix");
    assert_eq!(value["dryRun"], true);
    assert_eq!(value["mutationApplied"], false);
    let manual = value["classes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|class| class["status"] == "manual")
        .count();
    assert!(manual >= 1);
    let mcp = run(&["--json", "mcp", "install", "--client", "codex"]);
    assert_eq!(mcp.status.code(), Some(0));
    assert_eq!(output_json(&mcp)["dryRun"], true);
    assert!(!home.join(".codex").exists());
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
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

#[test]
fn mcp_print_config_uses_current_executable() {
    let output = legion(&["mcp", "print-config", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    let value = output_json(&output);
    assert_eq!(value["kind"], "legion-mcp-config");
    assert_eq!(value["args"], serde_json::json!(["serve", "--stdio"]));
}

#[test]
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
        value
            .pointer("/artifact/kind")
            .and_then(|kind| kind.as_str()),
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
    assert!(
        value.get("text").is_none(),
        "doctor --json must not embed text"
    );
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
        assert!(
            value.get("text").is_none(),
            "skills --json must not embed text"
        );
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
    let plan = legion(&["plan", "--json", "."]);
    assert_eq!(plan.status.code(), Some(2));
    let plan_value = output_json(&plan);
    assert_eq!(plan_value["status"], "incomplete");
    assert!(plan_value["gaps"]
        .as_array()
        .is_some_and(|gaps| !gaps.is_empty()));
}

// `assurance` was advertised by the retired Node CLI but never routed. It is no
// longer a command at all, so it answers like any other unknown command.
#[test]
fn assurance_is_an_unknown_command() {
    let output = legion(&["assurance", ".", "--json"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown command: assurance"));
}

/// A fresh, empty directory used as HOME and as the working directory, so no
/// installed release, state, or trigger store from the developer machine leaks
/// into the assertions.
fn isolated_home(label: &str) -> std::path::PathBuf {
    let home = std::env::temp_dir().join(format!("legion-truth-{label}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).unwrap();
    home
}

fn run_in(home: &std::path::Path, arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_legion"))
        .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
        .env_remove("LEGION_M1_CONFIG")
        .env("HOME", home)
        .env("USERPROFILE", home)
        .current_dir(home)
        .args(arguments)
        .output()
        .expect("native Legion CLI must execute")
}

#[test]
fn skills_verify_without_installed_release_is_unavailable_not_pass() {
    let home = isolated_home("skills-verify");
    let output = run_in(&home, &["skills", "verify"]);
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert_eq!(value["status"], "unavailable");
    assert_eq!(value["count"], 0);
    assert!(value["reason"]
        .as_str()
        .is_some_and(|reason| reason.contains("installed release")));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn init_dry_run_reports_would_write_and_writes_nothing() {
    let home = isolated_home("init-dry");
    let repo = home.join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let repo_arg = repo.to_str().unwrap();

    let preview = run_in(&home, &["init", repo_arg, "--json"]);
    assert_eq!(preview.status.code(), Some(0));
    let value = output_json(&preview);
    assert_eq!(value["dryRun"], true);
    assert_eq!(value["wouldWrite"].as_array().map(Vec::len), Some(2));
    assert!(value.get("wrote").is_none());
    assert!(!repo.join("legion.config.json").exists());
    assert!(!repo.join(".gitignore").exists());

    // --dry-run wins even when --write is also given.
    let forced = run_in(&home, &["init", repo_arg, "--write", "--dry-run", "--json"]);
    assert_eq!(output_json(&forced)["dryRun"], true);
    assert!(!repo.join("legion.config.json").exists());

    // A real write lists what it wrote; a second write changes nothing and
    // must report an empty `wrote` list.
    let written = run_in(&home, &["init", repo_arg, "--write", "--json"]);
    assert_eq!(written.status.code(), Some(0));
    let value = output_json(&written);
    assert_eq!(value["dryRun"], false);
    assert_eq!(value["wrote"].as_array().map(Vec::len), Some(2));
    assert!(repo.join("legion.config.json").is_file());

    let again = run_in(&home, &["init", repo_arg, "--write", "--json"]);
    assert_eq!(
        output_json(&again)["wrote"].as_array().map(Vec::len),
        Some(0)
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn state_verify_on_empty_snapshot_is_unproven_not_clean() {
    let home = isolated_home("state-empty");
    let snapshot = home.join("snapshot.json");
    std::fs::write(
        &snapshot,
        r#"{"schema":"legion-state-snapshot.v1","takenAt":"2026-01-01T00:00:00.000Z","surfaces":{}}"#,
    )
    .unwrap();
    let output = run_in(
        &home,
        &["state", "verify", "--snapshot", snapshot.to_str().unwrap()],
    );
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert_eq!(value["verdict"], "unproven");
    assert_eq!(value["complete"], false);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn authority_proof_inspect_unknown_invocation_is_not_found() {
    let home = isolated_home("authority");
    let output = run_in(
        &home,
        &[
            "authority",
            "proof",
            "inspect",
            "--invocation",
            "INV-missing",
        ],
    );
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert_eq!(value["status"], "not-found");
    assert_eq!(value["invocationId"], "INV-missing");
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn schedule_trigger_is_recorded_queued_and_states_no_workflow_started() {
    let home = isolated_home("schedule-trigger");
    let trigger = home.join("trigger.json");
    std::fs::write(
        &trigger,
        r#"{"triggerId":"TRG-1","type":"manual","source":"test","target":"example-workflow","idempotencyKey":"idem-1","runArgs":[]}"#,
    )
    .unwrap();
    let output = run_in(&home, &["schedule", "--trigger", trigger.to_str().unwrap()]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = output_json(&output);
    assert_eq!(value["state"], "QUEUED");
    assert_eq!(value["workflowStarted"], false);
    assert!(value["note"]
        .as_str()
        .is_some_and(|note| note.contains("no workflow was started")));
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn mcp_print_config_is_not_implemented_without_a_binding() {
    let home = isolated_home("mcp-config");
    let output = run_in(&home, &["mcp", "print-config", "--json"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output_json(&output)["implemented"], false);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn decision_draft_reports_not_persisted() {
    let output = legion(&["decision", "--task", "T-1", "--rationale", "test"]);
    assert_eq!(output.status.code(), Some(0));
    let value = output_json(&output);
    assert_eq!(value["kind"], "legion-decision");
    assert_eq!(value["persisted"], false);
}

#[test]
fn host_describe_does_not_report_an_empty_detection_list_as_fact() {
    let output = legion(&["host", "describe", ".", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert!(value["detected"].is_null());
    assert_eq!(value["status"], "not-implemented");
}

#[test]
fn handoff_help_states_structure_only_validation() {
    let output = legion(&["handoff", "--help"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("structure only"), "{stdout}");
}

#[test]
fn governance_rejects_key_dir_outside_judgment() {
    let output = legion(&[
        "governance",
        "delivery",
        "--json",
        r#"{"operation":"dispatch-capacity","input":{}}"#,
        "--key-dir",
        "keys",
    ]);
    assert_eq!(output.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("--key-dir applies only to governance judgment"));
}

#[test]
fn run_lifecycle_never_uses_default_provider_as_completion_evidence() {
    // Node parity (`src/lib/cli/commands/run.mjs`): a non-EC contract id is a
    // usage failure, exit 4 on stderr, before any completeness evaluation.
    let output = legion(&["run", "open", "--contract", "fixture", "--version", "1"]);
    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("run open requires --contract <EC-#>"),
        "{stderr}"
    );
}

#[test]
fn fix_apply_selecting_nothing_reports_nothing_to_apply() {
    // legacy-mcp-binding has no applier, so --apply on it selects nothing and
    // must not claim that anything was applied.
    let home = isolated_home("fix-nothing");
    let output = run_in(
        &home,
        &["--json", "fix", "--apply", "--class", "legacy-mcp-binding"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = output_json(&output);
    assert_eq!(value["dryRun"], false);
    assert_eq!(value["status"], "nothing-to-apply");
    assert_eq!(value["mutationApplied"], false);
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn bind_check_without_receipt_reports_unbound_not_clean() {
    // A repository with a Codex projection and no binding receipt has drift
    // that cannot be observed. The check must say so and fail, not report no drift.
    let home = isolated_home("bind-unbound");
    let repo = home.join("repo");
    std::fs::create_dir_all(repo.join(".codex")).unwrap();
    let output = run_in(
        &home,
        &["bind", "--check", repo.to_str().unwrap(), "--json"],
    );
    assert_eq!(output.status.code(), Some(1));
    let value = output_json(&output);
    assert_eq!(value["valid"], false);
    let codex = value["harnesses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "codex")
        .expect("codex harness");
    assert_eq!(codex["status"], "unbound");
    assert_eq!(codex["driftStatus"], "unknown");
    let _ = std::fs::remove_dir_all(&home);
}
