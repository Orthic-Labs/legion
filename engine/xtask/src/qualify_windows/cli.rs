//! Argument parsing and process entry point, mirroring
//! `qualify-windows-release.mjs`'s `parseArguments`/`isMain` block.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::json;

use super::lifecycle::{qualify_windows_release, QualifyWindowsOptions};

fn usage() {
    eprintln!(
        "usage: xtask qualify-windows-release --current-zip <zip> [--prior-zip <zip>] --architecture x86_64|arm64 --source-revision <sha> --output <receipt.json> --work-root <isolated-dir> [--allow-downgrade]"
    );
}

/// Mirrors `parseArguments`: `--flag value` / `--flag=value`, plus the two
/// boolean flags `--help`/`-h` and `--allow-downgrade`.
fn parse_arguments(argv: &[String]) -> Result<(bool, bool, HashMap<String, String>), String> {
    let mut options = HashMap::new();
    let mut help = false;
    let mut allow_downgrade = false;
    let mut index = 0;
    while index < argv.len() {
        let raw = &argv[index];
        if raw == "--" {
            index += 1;
            continue;
        }
        if raw == "--help" || raw == "-h" {
            help = true;
            index += 1;
            continue;
        }
        if raw == "--allow-downgrade" {
            allow_downgrade = true;
            index += 1;
            continue;
        }
        if !raw.starts_with("--") {
            return Err(format!("unknown argument: {raw}"));
        }
        let (key, inline_value) = match raw.find('=') {
            Some(pos) => (&raw[2..pos], Some(raw[pos + 1..].to_string())),
            None => (&raw[2..], None),
        };
        if key.is_empty() {
            return Err(format!("unknown argument: {raw}"));
        }
        let normalized = key.replace('-', "").to_lowercase();
        let value = match inline_value {
            Some(v) => v,
            None => {
                index += 1;
                argv.get(index).cloned().ok_or_else(|| format!("--{key} requires a value"))?
            }
        };
        if value.is_empty() || value.starts_with("--") {
            return Err(format!("--{key} requires a value"));
        }
        options.insert(normalized, value);
        index += 1;
    }
    Ok((help, allow_downgrade, options))
}

pub fn run(argv: &[String]) -> ExitCode {
    let (help, allow_downgrade, options) = match parse_arguments(argv) {
        Ok(v) => v,
        Err(error) => {
            eprintln!("qualify-windows-release: {error}");
            return ExitCode::FAILURE;
        }
    };
    if help {
        usage();
        return ExitCode::SUCCESS;
    }
    let get = |keys: &[&str]| keys.iter().find_map(|k| options.get(*k).cloned());
    let current_zip = get(&["currentzip", "currentarchive", "current", "archive"]);
    let prior_zip = get(&["priorzip", "priorarchive", "prior", "previouszip", "previousarchive"]);
    let architecture = get(&["architecture", "expectedarchitecture"]);
    let source_revision = get(&["sourcerevision", "revision"]);
    let output = get(&["output", "outputreceipt", "receipt", "receiptpath"]);
    let work_root = get(&["workroot", "work", "isolatedworkroot", "isolatedroot"]);

    let result = qualify_windows_release(QualifyWindowsOptions {
        current_zip: current_zip.map(PathBuf::from),
        prior_zip: prior_zip.map(PathBuf::from),
        architecture,
        source_revision,
        output: output.map(PathBuf::from),
        work_root: work_root.map(PathBuf::from),
        allow_downgrade,
        ..Default::default()
    });

    match result {
        Ok(receipt) => {
            let summary = json!({
                "status": receipt.get("status"),
                "receiptPath": receipt.get("receiptPath"),
                "archiveSha256": receipt.get("archiveSha256"),
                "runtimeSha256": receipt.get("runtimeSha256"),
            });
            println!("{}", serde_json::to_string_pretty(&summary).unwrap_or_default());
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("qualify-windows-release: {error}");
            ExitCode::FAILURE
        }
    }
}
