//! `run(argv)` CLI wrapper mirroring `skills/handoff/scripts/transcript-handoff.py`'s
//! `argparse` surface, matching stdout shape and exit codes byte-for-byte
//! where the underlying logic is pure Rust.
//!
//! The `continuity` subcommand is native and deterministic. It verifies the
//! supplied source prefix, adapts Claude/Codex rows, and writes typed JSON.

use std::path::PathBuf;

use sha2::Digest;

use super::continuity::{normalize, verify_context_receipt, ContinuityContext, ContinuityInput};
use super::pointer::{build_pointer, paste_prompt, Platform};

fn pointer_to_json(p: &super::pointer::SourcePointer) -> serde_json::Value {
    serde_json::json!({
        "schema": p.schema,
        "platform": p.platform,
        "session_id": p.session_id,
        "workspace": p.workspace,
        "source_path": p.source_path,
        "cutoff_bytes": p.cutoff_bytes,
        "sha256": p.sha256,
        "last_complete_row": p.last_complete_row,
        "last_complete_offset": p.last_complete_offset,
        "last_event_type": p.last_event_type,
        "last_event_timestamp": p.last_event_timestamp,
        "selection_method": p.selection_method,
        "created_at": p.created_at,
    })
}

/// I/O seam the CLI needs beyond argv parsing: stdout/stderr, cwd, home,
/// and today's date.
pub struct RunEnv {
    pub home: PathBuf,
    pub cwd: PathBuf,
    pub today: String,
}

/// Python: `main()`. Returns the process exit code; writes to `out`/`err`
/// exactly as the Python `print(...)` calls did (stdout unless noted).
pub fn run(argv: &[String], env: &RunEnv, out: &mut dyn std::io::Write) -> i32 {
    if argv.is_empty() {
        let _ = writeln!(out, "FAIL: a command is required (bootstrap)");
        return 2;
    }
    match argv[0].as_str() {
        "bootstrap" => run_bootstrap(&argv[1..], env, out),
        "continuity" => run_continuity(&argv[1..], out),
        other => {
            let _ = writeln!(out, "FAIL: unrecognized command: {other}");
            2
        }
    }
}

fn run_continuity(args: &[String], out: &mut dyn std::io::Write) -> i32 {
    let mut pointer_arg: Option<PathBuf> = None;
    let mut platform: Option<String> = None;
    let mut session_id: Option<String> = None;
    let mut workspace: Option<String> = None;
    let mut cutoff_bytes: Option<u64> = None;
    let mut sha256: Option<String> = None;
    let mut output: Option<PathBuf> = None;
    let mut write_receipt: Option<PathBuf> = None;
    let mut verify_receipt: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        let flag = args[i].as_str();
        let value = |index: &mut usize| -> Option<String> {
            *index += 1;
            args.get(*index).cloned()
        };
        match flag {
            "--pointer" => pointer_arg = value(&mut i).map(PathBuf::from),
            "--platform" => platform = value(&mut i),
            "--session-id" => session_id = value(&mut i),
            "--workspace" => workspace = value(&mut i),
            "--cutoff-bytes" => {
                let raw = value(&mut i);
                cutoff_bytes = raw.and_then(|value| value.parse::<u64>().ok());
            }
            "--sha256" => sha256 = value(&mut i),
            "--output" => output = value(&mut i).map(PathBuf::from),
            "--write-receipt" => write_receipt = value(&mut i).map(PathBuf::from),
            "--verify-receipt" => verify_receipt = value(&mut i).map(PathBuf::from),
            other => {
                let _ = writeln!(out, "FAIL: unrecognized argument: {other}");
                return 2;
            }
        }
        i += 1;
    }
    let Some(output) = output else {
        let _ = writeln!(out, "FAIL: --output is required");
        return 2;
    };

    // Verification is a read-only operation. Never regenerate context before
    // checking a supplied receipt, since that would hide a tampered artifact.
    if let Some(receipt_path) = verify_receipt {
        if write_receipt.is_some()
            || pointer_arg.is_some()
            || platform.is_some()
            || session_id.is_some()
            || workspace.is_some()
            || cutoff_bytes.is_some()
            || sha256.is_some()
        {
            let _ = writeln!(
                out,
                "FAIL: --write-receipt cannot be combined with --verify-receipt"
            );
            return 2;
        }
        if let Err(error) = verify_receipt_file(&output, &receipt_path) {
            let _ = writeln!(out, "FAIL: {error}");
            return 1;
        }
        let _ = writeln!(out, "RECEIPT_PASS: {}", receipt_path.display());
        return 0;
    }

    let Some(pointer_arg) = pointer_arg else {
        let _ = writeln!(out, "FAIL: --pointer is required");
        return 2;
    };

    let input = match continuity_input(
        &pointer_arg,
        platform,
        session_id,
        workspace,
        cutoff_bytes,
        sha256,
    ) {
        Ok(input) => input,
        Err(error) => {
            let _ = writeln!(out, "FAIL: {error}");
            return 2;
        }
    };
    let receipt_path = write_receipt
        .clone()
        .unwrap_or_else(|| default_receipt_path(&output));
    if let Err(error) = ensure_output_paths(&output, &receipt_path, &pointer_arg, &input.path) {
        let _ = writeln!(out, "FAIL: {error}");
        return 2;
    }
    let context = match normalize(&input) {
        Ok(context) => context,
        Err(error) => {
            let _ = writeln!(out, "FAIL: {error}");
            return 1;
        }
    };
    if let Err(error) = write_context(&output, &context) {
        let _ = writeln!(out, "FAIL: {error}");
        return 1;
    }
    if let Err(error) = write_receipt_file(&receipt_path, &output, &context) {
        let _ = writeln!(out, "FAIL: {error}");
        return 1;
    }
    let _ = writeln!(
        out,
        "PASS: continuity context written to {} (receipt {})",
        output.display(),
        receipt_path.display()
    );
    0
}

fn default_receipt_path(output: &std::path::Path) -> PathBuf {
    let stem = output
        .file_stem()
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| "context".into());
    output
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""))
        .join(format!("{stem}.receipt.json"))
}

fn ensure_output_paths(
    output: &std::path::Path,
    receipt: &std::path::Path,
    pointer: &std::path::Path,
    source: &std::path::Path,
) -> Result<(), String> {
    if same_path(output, receipt) {
        return Err("--output and receipt path must be different".into());
    }
    if same_path(output, pointer) || same_path(output, source) {
        return Err("--output must not overwrite pointer or transcript".into());
    }
    if same_path(receipt, pointer) || same_path(receipt, source) {
        return Err("receipt path must not overwrite pointer or transcript".into());
    }
    Ok(())
}

fn same_path(left: &std::path::Path, right: &std::path::Path) -> bool {
    fn resolved(path: &std::path::Path) -> PathBuf {
        if path.exists() {
            return path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        }
        let parent = path.parent().unwrap_or_else(|| std::path::Path::new(""));
        let parent = parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf());
        path.file_name()
            .map(|name| parent.join(name))
            .unwrap_or(parent)
    }
    resolved(left) == resolved(right)
}

fn continuity_input(
    pointer_arg: &std::path::Path,
    platform: Option<String>,
    session_id: Option<String>,
    workspace: Option<String>,
    cutoff_bytes: Option<u64>,
    sha256: Option<String>,
) -> Result<ContinuityInput, String> {
    let mut source_path = pointer_arg.to_path_buf();
    let mut pointer_values: Option<serde_json::Value> = None;
    let pointer_json_path = matches!(
        pointer_arg.extension().and_then(|value| value.to_str()),
        Some("json") | Some("pointer")
    );
    if pointer_json_path && pointer_arg.is_file() {
        if let Ok(text) = std::fs::read_to_string(pointer_arg) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                if value.get("schema").and_then(|value| value.as_str())
                    == Some("handoff.source-pointer.v1")
                    || value.get("source_path").is_some()
                {
                    pointer_values = Some(value);
                }
            }
        }
    }
    let (platform, session_id, workspace, cutoff_bytes, sha256) = if let Some(value) =
        pointer_values
    {
        let object = value
            .as_object()
            .ok_or_else(|| "pointer JSON must be an object".to_string())?;
        let pointer_parent = pointer_arg
            .parent()
            .unwrap_or_else(|| std::path::Path::new(""));
        let source = required_string(object, "source_path")?;
        source_path = std::path::PathBuf::from(source);
        if !source_path.is_absolute() {
            source_path = pointer_parent.join(source_path);
        }
        let parsed = (
            required_string(object, "platform")?,
            required_string(object, "session_id")?,
            required_string(object, "workspace")?,
            required_u64(object, "cutoff_bytes")?,
            required_string(object, "sha256")?,
        );
        ensure_optional_match("platform", platform.as_deref(), Some(&parsed.0))?;
        ensure_optional_match("session-id", session_id.as_deref(), Some(&parsed.1))?;
        ensure_optional_match("workspace", workspace.as_deref(), Some(&parsed.2))?;
        if cutoff_bytes.is_some() && cutoff_bytes != Some(parsed.3) {
            return Err("--cutoff-bytes does not match saved pointer".into());
        }
        if sha256.is_some() && sha256.as_deref() != Some(parsed.4.as_str()) {
            return Err("--sha256 does not match saved pointer".into());
        }
        parsed
    } else {
        (
            platform
                .ok_or_else(|| "--platform is required for a transcript pointer".to_string())?,
            session_id
                .ok_or_else(|| "--session-id is required for a transcript pointer".to_string())?,
            workspace
                .ok_or_else(|| "--workspace is required for a transcript pointer".to_string())?,
            cutoff_bytes
                .ok_or_else(|| "--cutoff-bytes is required for a transcript pointer".to_string())?,
            sha256.ok_or_else(|| "--sha256 is required for a transcript pointer".to_string())?,
        )
    };
    let platform = Platform::parse(&platform)?;
    if session_id.is_empty() || workspace.is_empty() {
        return Err("session ID and workspace must be non-empty".into());
    }
    Ok(ContinuityInput::new(
        source_path,
        platform,
        session_id,
        workspace,
        cutoff_bytes,
        sha256,
    ))
}

fn required_string(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<String, String> {
    object
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("saved pointer is missing {key}"))
}

fn required_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<u64, String> {
    object
        .get(key)
        .and_then(|value| value.as_u64())
        .ok_or_else(|| format!("saved pointer is missing {key}"))
}

fn ensure_optional_match(
    name: &str,
    supplied: Option<&str>,
    expected: Option<&str>,
) -> Result<(), String> {
    if let (Some(supplied), Some(expected)) = (supplied, expected) {
        if supplied != expected {
            return Err(format!("--{name} does not match saved pointer"));
        }
    }
    Ok(())
}

fn write_context(path: &std::path::Path, context: &ContinuityContext) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let body = serde_json::to_string_pretty(context).map_err(|error| error.to_string())? + "\n";
    std::fs::write(path, body).map_err(|error| error.to_string())
}

fn write_receipt_file(
    path: &std::path::Path,
    context_path: &std::path::Path,
    context: &ContinuityContext,
) -> Result<(), String> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let context_hash = sha256_file(context_path)?;
    let mut receipt = serde_json::to_value(&context.receipt).map_err(|error| error.to_string())?;
    receipt
        .as_object_mut()
        .expect("receipt serializes as object")
        .insert(
            "contextFileSha256".into(),
            serde_json::Value::String(context_hash),
        );
    let body = serde_json::to_string_pretty(&receipt).map_err(|error| error.to_string())? + "\n";
    std::fs::write(path, body).map_err(|error| error.to_string())
}

fn verify_receipt_file(
    output: &std::path::Path,
    receipt_path: &std::path::Path,
) -> Result<(), String> {
    let context_bytes =
        std::fs::read(output).map_err(|error| format!("cannot read context: {error}"))?;
    let context_file_sha256 = sha256_bytes(&context_bytes);
    let mut actual: serde_json::Value = serde_json::from_slice(
        &std::fs::read(receipt_path).map_err(|error| format!("cannot read receipt: {error}"))?,
    )
    .map_err(|error| format!("invalid receipt: {error}"))?;
    let declared_hash = actual
        .as_object()
        .and_then(|object| object.get("contextFileSha256"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| "receipt is missing contextFileSha256".to_string())?;
    if declared_hash != context_file_sha256 {
        return Err("context bytes do not match receipt".into());
    }
    let context: ContinuityContext = serde_json::from_slice(&context_bytes)
        .map_err(|error| format!("invalid context: {error}"))?;
    verify_context_receipt(&context)?;
    let expected = serde_json::to_value(&context.receipt).map_err(|error| error.to_string())?;
    actual
        .as_object_mut()
        .expect("receipt serializes as object")
        .remove("contextFileSha256");
    if expected != actual {
        return Err("receipt does not match context".into());
    }
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(sha2::Sha256::digest(bytes)))
}

fn sha256_file(path: &std::path::Path) -> Result<String, String> {
    Ok(sha256_bytes(
        &std::fs::read(path).map_err(|error| error.to_string())?,
    ))
}

fn run_bootstrap(args: &[String], env: &RunEnv, out: &mut dyn std::io::Write) -> i32 {
    let mut platform: Option<String> = None;
    let mut session_id: Option<String> = None;
    let mut workspace: Option<String> = None;
    let mut home: PathBuf = env.home.clone();
    let mut json = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--platform" => {
                i += 1;
                platform = args.get(i).cloned();
            }
            "--session-id" => {
                i += 1;
                session_id = args.get(i).cloned();
            }
            "--workspace" => {
                i += 1;
                workspace = args.get(i).cloned();
            }
            "--home" => {
                i += 1;
                if let Some(v) = args.get(i) {
                    home = PathBuf::from(v);
                }
            }
            "--json" => json = true,
            other => {
                let _ = writeln!(out, "FAIL: unrecognized argument: {other}");
                return 2;
            }
        }
        i += 1;
    }
    let platform = match platform.as_deref().map(Platform::parse) {
        Some(Ok(p)) => p,
        Some(Err(e)) => {
            let _ = writeln!(out, "FAIL: {e}");
            return 2;
        }
        None => {
            let _ = writeln!(out, "FAIL: --platform is required");
            return 2;
        }
    };
    match build_pointer(
        platform,
        session_id.as_deref(),
        workspace.as_deref(),
        &home,
        None,
    ) {
        Ok(pointer) => {
            if json {
                let v = pointer_to_json(&pointer);
                let _ = writeln!(out, "{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                let _ = writeln!(out, "{}", paste_prompt(&pointer, &env.cwd, &env.today));
            }
            0
        }
        Err(e) => {
            let _ = writeln!(out, "FAIL: {e}");
            1
        }
    }
}
