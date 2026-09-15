use super::CommandResult;
use crate::cli::CommonArgs;
use serde_json::{json, Value};
use std::path::Path;

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let mut index = 0;
    let mut sub = argv.get(index).map(String::as_str);
    if sub == Some("proof") {
        index += 1;
        sub = argv.get(index).map(String::as_str);
    }
    if matches!(sub, Some("help") | Some("--help")) {
        return Ok(json!({
            "__raw": "Usage: legion authority proof inspect [--invocation <id>]\n"
        }));
    }
    if sub != Some("inspect") {
        return Err(super::CommandError::usage("authority proof requires inspect"));
    }
    index += 1;
    let invocation_id = if argv.get(index) == Some(&"--invocation".to_string()) {
        argv.get(index + 1).cloned()
    } else {
        None
    };
    let root = std::env::current_dir().map_err(super::io_error)?;
    let proofs_dir = root.join(".audit/arcane/authority-invocations/proofs");
    let proofs = read_proofs(&proofs_dir, invocation_id.as_deref());
    Ok(compact(json!({ "proofs": proofs })))
}

fn compact(mut value: Value) -> Value {
    value["__compact"] = json!(true);
    value
}

fn read_proofs(root: &Path, invocation_id: Option<&str>) -> Vec<Value> {
    let entries = std::fs::read_dir(root);
    let Ok(entries) = entries else {
        return Vec::new();
    };
    let mut proofs = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(mut proof) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        if let Some(id) = invocation_id {
            let matches = proof
                .get("invocationId")
                .and_then(Value::as_str)
                .is_some_and(|value| value == id);
            if !matches {
                continue;
            }
        }
        if let Some(object) = proof.as_object_mut() {
            if let Some(auth) = object.get("authentication").cloned() {
                object.insert(
                    "authentication".into(),
                    json!({
                        "keyId": auth.get("keyId"),
                        "alg": auth.get("alg"),
                    }),
                );
            }
        }
        proofs.push(proof);
    }
    proofs
}
