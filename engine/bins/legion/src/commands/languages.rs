use super::{coverage, CommandResult};
use crate::cli::CommonArgs;
use serde_json::json;

/// Report the languages and frameworks detected in the working directory from
/// repository manifests (Cargo.toml, package.json, Package.swift, *.xcodeproj,
/// pyproject.toml / requirements.txt, go.mod), each with the registry providers
/// that cover it. An empty list means no recognised manifest was found.
pub fn run(args: CommonArgs) -> CommandResult {
    let root = std::env::current_dir().map_err(super::io_error)?;
    let scan = coverage::scan(&root);
    let languages = coverage::rows(&scan)?;
    let output = json!({
        "schemaVersion": 1,
        "kind": "legion-languages",
        "repository": {"root": root},
        "languages": languages,
        "scan": {
            "entriesSeen": scan.entries_seen,
            "entriesTruncated": scan.entries_truncated,
            "depthLimited": scan.depth_limited,
        },
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
    if text.is_empty() {
        return Ok(json!({"json": false, "text": ["no recognised language or framework manifest found"]}));
    }
    Ok(json!({"json": false, "text": text}))
}
