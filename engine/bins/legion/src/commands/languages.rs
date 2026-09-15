use super::CommandResult;
use crate::cli::CommonArgs;
use serde_json::json;

/// Project the installed provider families as language coverage. Provider
/// `family` is the native composition's authoritative coverage dimension.
pub fn run(args: CommonArgs) -> CommandResult {
    let source: serde_json::Value = serde_json::from_str(PROVIDER_REGISTRY)
        .map_err(|error| super::CommandError::internal(format!("embedded provider registry invalid: {error}")))?;
    let provider_ids = source
        .get("providers")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|provider| provider.get("selectable").and_then(serde_json::Value::as_bool) != Some(false))
        .filter_map(|provider| provider["id"].as_str())
        .map(|id| id.strip_prefix("legacy.").unwrap_or(id).to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let languages = [
        ("framework.react", "framework", ["react.hooks-config"].as_slice()),
        ("framework.tauri", "framework", ["tauri.capabilities", "tauri.contract-mirror"].as_slice()),
    ]
    .into_iter()
    .map(|(id, kind, providers)| json!({
        "id": id,
        "kind": kind,
        "qualification": "unproven",
        "providers": providers.iter().filter(|provider| provider_ids.contains(**provider)).collect::<Vec<_>>(),
    }))
    .collect::<Vec<_>>();
    let output = json!({
        "schemaVersion": 1,
        "kind": "legion-languages",
        "languages": languages,
    });
    if args.json {
        return Ok(output);
    }
    let text = output["languages"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|language| {
            format!(
                "{}\t{}",
                language["id"].as_str().unwrap_or_default(),
                language["qualification"].as_str().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>();
    Ok(json!({"json": false, "text": text}))
}

const PROVIDER_REGISTRY: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/providers.json"));

#[cfg(test)]
mod tests {
    use super::PROVIDER_REGISTRY;

    #[test]
    fn canonical_families_are_projected() {
        assert!(PROVIDER_REGISTRY.contains("legacy.tauri"));
    }
}
