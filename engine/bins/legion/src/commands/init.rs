use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::json;
use std::path::{Path, PathBuf};

const IGNORE_ENTRIES: [&str; 2] = [".legion/", ".audit/"];

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(default_value = ".")]
    pub root: PathBuf,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub write: bool,
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

pub fn run(args: InitArgs) -> CommandResult {
    let requested_root = if args.root.is_absolute() {
        args.root.clone()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(&args.root)
            .components()
            .collect()
    };
    let root = std::fs::canonicalize(&requested_root).map_err(|_| {
        CommandError::usage(format!("root does not exist: {}", requested_root.display()))
    })?;
    let root = super::display_path(&root);
    let config_path = root.join("legion.config.json");
    let gitignore_path = root.join(".gitignore");
    // Match Node: preview unless --write; --dry-run is accepted for compatibility.
    let dry_run = !args.write;
    let would_write = json!([
        {
            "path": config_path,
            "reason": "repository audit configuration (profile, providers, policy, limits)"
        },
        {
            "path": gitignore_path,
            "reason": format!("append {}", IGNORE_ENTRIES.join(", "))
        }
    ]);
    let mut preview = json!({
        "schemaVersion": 1,
        "kind": "legion-init-preview",
        "root": root,
        "wouldWrite": would_write,
        "dryRun": dry_run,
    });
    if !dry_run {
        if !config_path.is_file() {
            let config = json!({
                "schemaVersion": 1,
                "profile": "standard",
                "providers": { "require": [], "disable": [] },
                "limits": {
                    "providerTimeoutMs": 120000,
                    "maxOutputBytes": 8388608,
                    "maxConcurrency": 4
                },
                "policy": {
                    "failOn": ["critical", "high"],
                    "baseline": null,
                    "acceptedRisk": null
                },
                "outputs": ["json", "sarif", "markdown"]
            });
            write_pretty_json(&config_path, &config)?;
        }
        let existing = std::fs::read_to_string(&gitignore_path).unwrap_or_default();
        let additions = IGNORE_ENTRIES
            .iter()
            .filter(|entry| !existing.contains(*entry))
            .collect::<Vec<_>>();
        if !additions.is_empty() {
            let mut payload = existing;
            if !payload.ends_with('\n') && !payload.is_empty() {
                payload.push('\n');
            }
            payload.push('\n');
            for entry in additions {
                payload.push_str(entry);
                payload.push('\n');
            }
            std::fs::write(&gitignore_path, payload).map_err(super::io_error)?;
        }
        preview["wrote"] = json!(would_write
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .filter_map(|item| item.get("path").cloned())
            .collect::<Vec<_>>());
    }
    Ok(preview)
}

fn write_pretty_json(path: &Path, value: &serde_json::Value) -> Result<(), CommandError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(super::io_error)?;
    let mut payload = bytes;
    payload.push(b'\n');
    std::fs::write(path, payload).map_err(super::io_error)
}
