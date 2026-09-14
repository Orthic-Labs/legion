use super::CommandResult;
use crate::cli::CommonArgs;
use serde_json::json;

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let action = argv.first().map(String::as_str);
    if !matches!(action, Some("install") | Some("uninstall")) {
        return Err(super::CommandError::usage(
            "hooks requires install|uninstall [--pre-commit|--pre-push]",
        ));
    }
    let target = argv.get(1).cloned();
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-hooks",
        "action": action.unwrap(),
        "target": target,
        "implemented": false,
        "note": "hook generation lands in PR38",
    }))
}
