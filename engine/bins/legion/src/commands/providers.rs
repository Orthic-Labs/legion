use super::{native_application_for, CommandResult};
use crate::cli::CommonArgs;
use serde_json::json;

/// Render provider metadata from the installed application composition.  The
/// command deliberately has no source-tree fallback: release composition is
/// the product boundary for this surface.
pub fn run(_args: CommonArgs) -> CommandResult {
    let app = native_application_for("providers")?;
    let mut providers = app
        .provider_specs()
        .into_iter()
        .map(|provider| {
            json!({
                "id": provider.id,
                "role": provider.role,
                "phase": provider.phase,
                "runner": provider.runner.get("kind").cloned().unwrap_or(serde_json::Value::Null),
                "benchmark": provider.benchmark,
                "producesSecurityCandidates": provider.produces.iter().any(|p| p == "security-candidate"),
            })
        })
        .collect::<Vec<_>>();
    providers.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-providers",
        "providers": providers,
    }))
}
