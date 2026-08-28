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
fn unconnected_projection_never_reports_complete() {
    for command in [
        "init",
        "bind",
        "inspect",
        "targets",
        "components",
        "stacks",
        "controls",
    ] {
        let output = legion(&[command, ".", "--json"]);
        assert_eq!(output.status.code(), Some(2), "{command}");
        let value = output_json(&output);
        assert_eq!(value["status"], "incomplete", "{command}");
        assert!(
            value["gaps"]
                .as_array()
                .is_some_and(|gaps| !gaps.is_empty()),
            "{command}"
        );
    }
}

#[test]
fn default_doctor_cannot_make_clean_claim() {
    let output = legion(&["doctor", ".", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    let value = output_json(&output);
    assert_eq!(value["status"], "incomplete");
    assert_eq!(value["cleanClaimPossible"], false);
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
