use super::{native_application_for, CommandResult};
use crate::cli::CommonArgs;
use serde_json::json;
use std::collections::BTreeMap;

/// Project the installed provider families as language coverage. Provider
/// `family` is the native composition's authoritative coverage dimension.
pub fn run(_args: CommonArgs) -> CommandResult {
    let app = native_application_for("languages")?;
    let mut families = BTreeMap::<String, Vec<String>>::new();
    for provider in app.provider_specs() {
        families
            .entry(provider.family)
            .or_default()
            .push(provider.id.to_string());
    }
    let languages = families
        .into_iter()
        .map(|(id, mut providers)| {
            providers.sort();
            json!({"id": id, "kind": "family", "qualification": "unproven", "providers": providers})
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-languages",
        "languages": languages,
    }))
}
