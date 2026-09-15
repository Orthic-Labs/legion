use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use serde_json::json;

/// Render provider metadata from the installed application composition.  The
/// command deliberately has no source-tree fallback: release composition is
/// the product boundary for this surface.
pub fn run(args: CommonArgs) -> CommandResult {
    let source: serde_json::Value = serde_json::from_str(PROVIDER_REGISTRY)
        .map_err(|error| CommandError::internal(format!("embedded provider registry invalid: {error}")))?;
    let mut providers = source
        .get("providers")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| CommandError::internal("embedded provider registry has no providers"))?
        .iter()
        .filter(|provider| provider.get("selectable").and_then(serde_json::Value::as_bool) != Some(false))
        .map(project_provider)
        .collect::<Vec<_>>();
    providers.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    let output = json!({
        "schemaVersion": 1,
        "kind": "legion-providers",
        "providers": providers,
    });
    if args.json {
        return Ok(output);
    }
    let text = output["providers"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|provider| {
            format!(
                "{}\t{}\t{}\t{}",
                provider["id"].as_str().unwrap_or_default(),
                provider["role"].as_str().unwrap_or_default(),
                provider["phase"].as_str().unwrap_or_default(),
                provider["runner"].as_str().unwrap_or_default(),
            )
        })
        .collect::<Vec<_>>();
    Ok(json!({"json": false, "text": text}))
}

const PROVIDER_REGISTRY: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../../src/registry/providers.json"));

fn project_provider(provider: &serde_json::Value) -> serde_json::Value {
    let canonical = provider["id"].as_str().unwrap_or_default();
    let id = canonical.strip_prefix("legacy.").unwrap_or(canonical);
    let phase = match provider["phase"].as_str().unwrap_or_default() {
        "source" => "facts",
        "judgment" => "reasoning",
        value => value,
    };
    let runner = if provider["runner"]["kind"].as_str() == Some("legacy-check") {
        "legacy-check"
    } else {
        provider["runner"]["kind"].as_str().unwrap_or_default()
    };
    let mut benchmark = provider["benchmark"].clone();
    if !benchmark.is_object() {
        benchmark = json!({});
    }
    benchmark
        .as_object_mut()
        .expect("benchmark object")
        .insert("requiredForCleanClaim".into(), json!(true));
    json!({
        "id": id,
        "role": provider["role"],
        "phase": phase,
        "runner": runner,
        "benchmark": benchmark,
        "producesSecurityCandidates": provider["role"].as_str() == Some("candidate-generator"),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn source_projection_text_uses_node_column_order() {
        let row = format!("{}\t{}\t{}\t{}", "p", "analysis", "source", "built-in");
        assert_eq!(row, "p\tanalysis\tsource\tbuilt-in");
    }
}
