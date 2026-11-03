use serde_json::Value;
use std::process::Command;

fn apple(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_legion"))
        .arg("apple")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn catalog_is_available_without_xcode_or_account_credentials() {
    let output = apple(&["catalog"]);
    assert!(output.status.success(), "{output:?}");
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["backend"], "legion-apple");
    assert!(value["operations"]["mobile"]["operations"].is_array());
}

#[test]
fn structured_input_rejects_non_objects() {
    assert_eq!(
        apple(&["preflight", "--input", "[]"]).status.code(),
        Some(4)
    );
}

#[test]
fn account_request_defaults_to_inspectable_plan() {
    let output = apple(&["app-store", "--input", r#"{"action":"apps"}"#]);
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("api.appstoreconnect.apple.com"), "{text}");
    assert!(!text.contains("Bearer ey"), "plan must never emit a token");
}

#[test]
fn tool_preflight_aliases_have_identical_native_catalogs() {
    let outputs: Vec<_> = [
        "ios-development/tool_preflight",
        "macos-development/tool_preflight",
    ]
    .iter()
    .map(|name| {
        Command::new(env!("CARGO_BIN_EXE_legion"))
            .args(["script", name, "--list"])
            .output()
            .unwrap()
    })
    .collect();
    for output in &outputs {
        assert!(output.status.success(), "{output:?}");
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(!value["tools"].as_array().unwrap().is_empty());
    }
    assert_eq!(outputs[0].stdout, outputs[1].stdout);
}

#[test]
fn execution_cannot_promote_caller_context_to_host_authority() {
    let output = apple(&[
        "app-store",
        "--input",
        r#"{"action":"apps","execute":true}"#,
    ]);
    assert!(
        !output.status.success(),
        "unguarded effect must not run: {output:?}"
    );
}
