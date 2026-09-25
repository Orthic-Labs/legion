//! Argument parsing and process entry point, mirroring
//! `package-windows-release.mjs`'s `parseArguments`/`isMain` block.

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;

use serde_json::Value;

use crate::windows_release_config::windows_architecture;

use super::finalize::{finalize_windows_direct_release, FinalizeOptions};
use super::prepare::{prepare_windows_archive, PrepareOptions};

fn usage() {
    eprintln!(
        "usage: xtask package-windows-release --architecture x86_64|arm64 --input <candidate-root> [--output <dir>] [--source-revision <sha>] [--finalize --candidate-receipt <json> --signature-receipt <json> --qualification <json> --provenance <json> [--publish-github] [--dry-run]] [--json]"
    );
}

/// Mirrors `parseArguments`: boolean flags (`--force`, `--finalize`,
/// `--publish-github`, `--dry-run`, `--json`) plus `--flag value`/`--flag=value`.
fn parse_arguments(argv: &[String]) -> Result<HashMap<String, String>, String> {
    const BOOLEAN_FLAGS: [&str; 5] = ["--force", "--finalize", "--publish-github", "--dry-run", "--json"];
    let mut options = HashMap::new();
    let mut index = 0;
    while index < argv.len() {
        let raw = &argv[index];
        if raw == "--" {
            index += 1;
            continue;
        }
        if BOOLEAN_FLAGS.contains(&raw.as_str()) {
            options.insert(raw[2..].replace('-', ""), "true".to_string());
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
        options.insert(key.replace('-', ""), value);
        index += 1;
    }
    Ok(options)
}

fn repo_root() -> PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        dir = PathBuf::from(manifest_dir);
    }
    dir.pop(); // engine
    dir.pop(); // repo root
    dir
}

pub fn run(argv: &[String]) -> ExitCode {
    if argv.iter().any(|a| a == "--help" || a == "-h") {
        usage();
        return ExitCode::SUCCESS;
    }
    let options = match parse_arguments(argv) {
        Ok(v) => v,
        Err(error) => {
            eprintln!("package-windows-release: {error}");
            return ExitCode::FAILURE;
        }
    };
    let repository_root = repo_root();
    let architecture = options
        .get("architecture")
        .cloned()
        .or_else(|| std::env::var("LEGION_WINDOWS_ARCH").ok())
        .unwrap_or_else(|| "x86_64".to_string());
    let normalized = match crate::windows_release_config::normalize_windows_architecture(&architecture) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("package-windows-release: {e}");
            return ExitCode::FAILURE;
        }
    };
    let configured = windows_architecture(&normalized).expect("normalized architecture is always configured");
    let default_input = repository_root.join("dist").join("native").join(format!("windows-{normalized}")).join(""); // assemblyRoot depends on version; caller should pass --input in practice
    let _ = configured;
    let input = options.get("input").map(PathBuf::from).unwrap_or(default_input);
    let output = options.get("output").or_else(|| options.get("out")).map(PathBuf::from);
    let force = options.get("force").is_some();
    let finalize = options.get("finalize").is_some();
    let publish_github = options.get("publishgithub").is_some();
    let dry_run = options.get("dryrun").is_some();
    let json_output = options.get("json").is_some();
    let source_revision = options.get("sourcerevision").cloned();

    let result = if finalize {
        finalize_windows_direct_release(FinalizeOptions {
            input: &input,
            output: output.as_deref(),
            architecture: &normalized,
            source_revision: source_revision.as_deref(),
            signature_receipt: options.get("signaturereceipt").map(PathBuf::from).as_deref(),
            candidate_receipt: options.get("candidatereceipt").map(PathBuf::from).as_deref(),
            qualification: options.get("qualification").map(PathBuf::from).as_deref(),
            provenance: options.get("provenance").map(PathBuf::from).as_deref(),
            publish_github,
            dry_run,
            repository_root: &repository_root,
            created_at: crate::chrono_like_now_iso(),
        })
    } else {
        prepare_windows_archive(PrepareOptions {
            input: &input,
            output: output.as_deref(),
            architecture: &normalized,
            source_revision: source_revision.as_deref(),
            force,
            repository_root: &repository_root,
        })
    };

    match result {
        Ok(value) => {
            if json_output {
                println!("{}", serde_json::to_string_pretty(&value).unwrap_or_default());
            } else {
                let status = value.get("status").and_then(|v| v.as_str()).unwrap_or("done");
                let archive = value.get("archive").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| format!("{:?}", value.get("archive").unwrap_or(&Value::Null)));
                println!("windows direct release {status}: {archive}");
            }
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("package-windows-release: {error}");
            ExitCode::FAILURE
        }
    }
}
