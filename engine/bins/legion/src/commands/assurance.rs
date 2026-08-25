use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

#[derive(Debug, Args)]
pub struct AssuranceArgs {
    #[arg(default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: AssuranceArgs) -> CommandResult {
    let root = std::fs::canonicalize(&args.root).map_err(super::io_error)?;
    let ledger_path = root.join("migration/native-rust/legacy-path-ownership.json");
    let ledger: Value = serde_json::from_slice(&std::fs::read(&ledger_path).map_err(|error| {
        CommandError::incomplete(format!(
            "native cutoff ownership ledger is unavailable at {}: {error}",
            ledger_path.display()
        ))
    })?)
    .map_err(|error| {
        CommandError::incomplete(format!("invalid cutoff ownership ledger: {error}"))
    })?;
    let entries = ledger
        .get("entries")
        .and_then(Value::as_array)
        .ok_or_else(|| CommandError::incomplete("cutoff ownership ledger has no entries"))?;

    let mut legacy_paths = Vec::new();
    for entry in entries {
        let Some(path) = entry.get("currentPath").and_then(Value::as_str) else {
            continue;
        };
        let disposition = entry
            .get("targetDisposition")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        if matches!(disposition, "port" | "delete" | "dev-only")
            && std::fs::symlink_metadata(root.join(path)).is_ok()
        {
            legacy_paths.push(path.to_owned());
        }
    }
    legacy_paths.sort();

    let mut entrypoint_gaps = Vec::new();
    inspect_json_entrypoints(&root.join("package.json"), &mut entrypoint_gaps)?;
    inspect_text_entrypoints(&root.join("action.yml"), &mut entrypoint_gaps)?;
    inspect_json_entrypoints(
        &root.join(".claude-plugin/plugin.json"),
        &mut entrypoint_gaps,
    )?;

    let entrypoints_native = entrypoint_gaps.is_empty();
    let status = if legacy_paths.is_empty() && entrypoints_native {
        "complete"
    } else {
        "incomplete"
    };
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-native-cutoff-assurance",
        "status": status,
        "root": root,
        "legacyExecutableCount": legacy_paths.len(),
        "legacyExecutableSample": legacy_paths.into_iter().take(50).collect::<Vec<_>>(),
        "entrypointGaps": entrypoint_gaps,
        "checks": {
            "ownershipLedgerLoaded": true,
            "legacyExecutablePathsAbsent": status == "complete",
            "packageActionPluginEntrypointsNative": entrypoints_native,
        }
    }))
}

fn inspect_json_entrypoints(path: &Path, gaps: &mut Vec<String>) -> Result<(), CommandError> {
    if !path.is_file() {
        return Ok(());
    }
    let value: Value = serde_json::from_slice(&std::fs::read(path).map_err(super::io_error)?)
        .map_err(|error| {
            CommandError::incomplete(format!("invalid {}: {error}", path.display()))
        })?;
    inspect_value(path, &value, gaps);
    Ok(())
}

fn inspect_value(path: &Path, value: &Value, gaps: &mut Vec<String>) {
    match value {
        Value::String(text) => {
            let normalized = text.to_ascii_lowercase();
            if ["node", "nodejs", "python", "python3", "npm", "npx"]
                .iter()
                .any(|runtime| {
                    normalized == *runtime || normalized.contains(&format!("/{runtime}"))
                })
                || normalized.ends_with(".mjs")
                || normalized.ends_with(".cjs")
                || normalized.ends_with(".py")
            {
                gaps.push(format!(
                    "{} retains interpreter entrypoint `{text}`",
                    path.display()
                ));
            }
        }
        Value::Array(values) => {
            for value in values {
                inspect_value(path, value, gaps);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                inspect_value(path, value, gaps);
            }
        }
        _ => {}
    }
}

fn inspect_text_entrypoints(path: &Path, gaps: &mut Vec<String>) -> Result<(), CommandError> {
    if !path.is_file() {
        return Ok(());
    }
    let text = std::fs::read_to_string(path).map_err(super::io_error)?;
    for (line_number, line) in text.lines().enumerate() {
        let normalized = line.to_ascii_lowercase();
        if [" node ", "python", "npm ", "npx ", ".mjs", ".cjs", ".py"]
            .iter()
            .any(|marker| normalized.contains(marker))
        {
            gaps.push(format!(
                "{}:{} retains interpreter entrypoint",
                path.display(),
                line_number + 1
            ));
        }
    }
    Ok(())
}
