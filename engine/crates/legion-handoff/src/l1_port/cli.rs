//! `run(argv)` CLI wrapper mirroring `skills/handoff/scripts/transcript-handoff.py`'s
//! `argparse` surface, matching stdout shape and exit codes byte-for-byte
//! where the underlying logic is pure Rust.
//!
//! The `continuity` subcommand is native and deterministic. It verifies the
//! supplied source prefix, adapts Claude/Codex rows, and writes typed JSON.

use std::path::PathBuf;

use sha2::Digest;

use super::continuity::{normalize, verify_context_receipt, ContinuityContext, ContinuityInput};
use super::live_state::{
    append_note, bare_hex, check_reconciliation, verify_notes, NoteKind, Reconciliation,
    SourceBlock,
};
use super::pointer::{
    build_pointer, handoff_file, paste_prompt_with_live_state, LiveStateRef, Platform,
};

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
        "notes" => run_notes(&argv[1..], out),
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
    let mut source_block: Option<PathBuf> = None;
    let mut source_block_sha256: Option<String> = None;
    let mut reconciliation: Option<PathBuf> = None;
    let mut notes: Option<PathBuf> = None;
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
            "--source-block" => source_block = value(&mut i).map(PathBuf::from),
            "--source-block-sha256" => source_block_sha256 = value(&mut i),
            "--reconciliation" => reconciliation = value(&mut i).map(PathBuf::from),
            "--notes" => notes = value(&mut i).map(PathBuf::from),
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
            || source_block.is_some()
            || source_block_sha256.is_some()
        {
            let _ = writeln!(
                out,
                "FAIL: --write-receipt cannot be combined with --verify-receipt"
            );
            return 2;
        }
        let context = match verify_receipt_file(&output, &receipt_path) {
            Ok(context) => context,
            Err(error) => {
                let _ = writeln!(out, "FAIL: {error}");
                return 1;
            }
        };
        let _ = writeln!(out, "RECEIPT_PASS: {}", receipt_path.display());
        return report_live_state(&context, &output, reconciliation, notes, out);
    }
    if reconciliation.is_some() || notes.is_some() {
        let _ = writeln!(
            out,
            "FAIL: --reconciliation and --notes are only valid with --verify-receipt"
        );
        return 2;
    }

    let Some(pointer_arg) = pointer_arg else {
        let _ = writeln!(out, "FAIL: --pointer is required");
        return 2;
    };

    let mut input = match continuity_input(
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
    match load_source_block(source_block.as_deref(), source_block_sha256.as_deref()) {
        Ok(Some(block)) => input = input.with_source_block(block),
        Ok(None) => {}
        Err(error) => {
            let _ = writeln!(out, "FAIL: {error}");
            return 2;
        }
    }
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
) -> Result<ContinuityContext, String> {
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
    Ok(context)
}

/// Read a saved source block and require its canonical digest to match the
/// digest the source printed. Both flags must appear together.
fn load_source_block(
    path: Option<&std::path::Path>,
    declared: Option<&str>,
) -> Result<Option<SourceBlock>, String> {
    let (path, declared) = match (path, declared) {
        (None, None) => return Ok(None),
        (Some(path), Some(declared)) => (path, declared),
        _ => return Err("--source-block and --source-block-sha256 must be given together".into()),
    };
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read source block: {error}"))?;
    let block = SourceBlock::parse(&text)?;
    if bare_hex(&block.digest()?) != bare_hex(declared) {
        return Err("source block does not match --source-block-sha256".into());
    }
    Ok(Some(block))
}

/// After a passing receipt: print the source assertion (labelled), enforce
/// in-flight reconciliation when asked, and verify/fold post-cutoff notes.
fn report_live_state(
    context: &ContinuityContext,
    output: &std::path::Path,
    reconciliation: Option<PathBuf>,
    notes: Option<PathBuf>,
    out: &mut dyn std::io::Write,
) -> i32 {
    if let Some(block) = &context.source_assertion {
        let _ = writeln!(
            out,
            "SOURCE_ASSERTION (declared by source, hash-bound; NOT transcript evidence): {}",
            serde_json::to_string(block).unwrap_or_default()
        );
        match reconciliation {
            Some(path) => {
                let checked = std::fs::read_to_string(&path)
                    .map_err(|error| format!("cannot read reconciliation: {error}"))
                    .and_then(|text| {
                        serde_json::from_str::<Reconciliation>(&text)
                            .map_err(|error| format!("invalid reconciliation: {error}"))
                    })
                    .and_then(|rec| check_reconciliation(block, &rec));
                if let Err(error) = checked {
                    let _ = writeln!(out, "FAIL: {error}");
                    return 1;
                }
                let _ = writeln!(
                    out,
                    "RECONCILE_PASS: {} in-flight item(s)",
                    block.in_flight.len()
                );
            }
            None if !block.in_flight.is_empty() => {
                let _ = writeln!(
                    out,
                    "IN_FLIGHT_UNRECONCILED: {} item(s); rerun with --reconciliation before writing the packet",
                    block.in_flight.len()
                );
                return 1;
            }
            None => {}
        }
    } else if reconciliation.is_some() {
        let _ = writeln!(out, "RECONCILE_PASS: no source assertion declared");
    }
    let notes_path =
        notes.unwrap_or_else(|| default_notes_path(output, &context.receipt.session_id));
    match verify_notes(&notes_path, &context.source.sha256) {
        Ok(summary) => {
            let _ = writeln!(
                out,
                "NOTES_PASS: {} note(s), head {} ({})",
                summary.notes.len(),
                summary.head,
                notes_path.display()
            );
            for note in &summary.notes {
                let _ = writeln!(
                    out,
                    "POST_CUTOFF_NOTE (source assertion, untrusted) #{} {} {:?} {}: {}",
                    note.seq,
                    note.timestamp,
                    note.kind,
                    note.author,
                    note.text.replace('\n', " ")
                );
            }
            0
        }
        Err(error) => {
            let _ = writeln!(out, "FAIL: {error}");
            1
        }
    }
}

fn default_notes_path(output: &std::path::Path, session_id: &str) -> PathBuf {
    output
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""))
        .join(format!("{session_id}.notes.jsonl"))
}

/// `notes append|verify`: append-only, hash-chained post-cutoff notes keyed to
/// the frozen prefix hash.
fn run_notes(args: &[String], out: &mut dyn std::io::Write) -> i32 {
    let Some(action) = args.first().map(String::as_str) else {
        let _ = writeln!(out, "FAIL: notes requires append or verify");
        return 2;
    };
    let mut notes: Option<PathBuf> = None;
    let mut prefix: Option<String> = None;
    let mut kind = "other".to_string();
    let mut author: Option<String> = None;
    let mut text: Option<String> = None;
    let mut i = 1usize;
    while i < args.len() {
        let flag = args[i].as_str();
        i += 1;
        let value = args.get(i).cloned();
        match flag {
            "--notes" => notes = value.map(PathBuf::from),
            "--prefix-sha256" => prefix = value,
            "--kind" => kind = value.unwrap_or_default(),
            "--author" => author = value,
            "--text" => text = value,
            other => {
                let _ = writeln!(out, "FAIL: unrecognized argument: {other}");
                return 2;
            }
        }
        i += 1;
    }
    let (Some(notes), Some(prefix)) = (notes, prefix) else {
        let _ = writeln!(out, "FAIL: --notes and --prefix-sha256 are required");
        return 2;
    };
    match action {
        "verify" => match verify_notes(&notes, &prefix) {
            Ok(summary) => {
                let _ = writeln!(
                    out,
                    "NOTES_PASS: {} note(s), head {}",
                    summary.notes.len(),
                    summary.head
                );
                0
            }
            Err(error) => {
                let _ = writeln!(out, "FAIL: {error}");
                1
            }
        },
        "append" => {
            let (Some(author), Some(text)) = (author, text) else {
                let _ = writeln!(out, "FAIL: --author and --text are required");
                return 2;
            };
            let kind = match NoteKind::parse(&kind) {
                Ok(kind) => kind,
                Err(error) => {
                    let _ = writeln!(out, "FAIL: {error}");
                    return 2;
                }
            };
            match append_note(
                &notes,
                &prefix,
                kind,
                &author,
                &text,
                super::pointer::iso8601_now_utc(),
            ) {
                Ok(note) => {
                    let _ = writeln!(out, "NOTE_APPENDED: #{} {}", note.seq, note.hash);
                    0
                }
                Err(error) => {
                    let _ = writeln!(out, "FAIL: {error}");
                    1
                }
            }
        }
        other => {
            let _ = writeln!(out, "FAIL: unrecognized notes action: {other}");
            2
        }
    }
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
    let mut live_state: Option<PathBuf> = None;
    let mut live_state_out: Option<PathBuf> = None;
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
            "--live-state" => {
                i += 1;
                live_state = args.get(i).map(PathBuf::from);
            }
            "--live-state-out" => {
                i += 1;
                live_state_out = args.get(i).map(PathBuf::from);
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
            let live = match prepare_live_state(
                live_state.as_deref(),
                live_state_out,
                &handoff_file(&pointer, &env.cwd, &env.today, ".source-block.json"),
            ) {
                Ok(live) => live,
                Err(error) => {
                    let _ = writeln!(out, "FAIL: {error}");
                    return 2;
                }
            };
            let live_ref = live.as_ref().map(|(path, sha256, block)| LiveStateRef {
                path: path.display().to_string(),
                sha256: sha256.clone(),
                block,
            });
            if json {
                let mut v = pointer_to_json(&pointer);
                if let (Some(live), Some(object)) = (&live_ref, v.as_object_mut()) {
                    object.insert(
                        "source_assertion".into(),
                        serde_json::json!({
                            "trust": live.block.trust,
                            "path": live.path,
                            "sha256": live.sha256,
                            "in_flight": live.block.in_flight,
                        }),
                    );
                }
                let _ = writeln!(out, "{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                let _ = writeln!(
                    out,
                    "{}",
                    paste_prompt_with_live_state(&pointer, &env.cwd, &env.today, live_ref.as_ref())
                );
            }
            0
        }
        Err(e) => {
            let _ = writeln!(out, "FAIL: {e}");
            1
        }
    }
}

/// Validate the source's declared block and save its canonical form so the
/// target can verify the digest printed in the paste block.
fn prepare_live_state(
    input: Option<&std::path::Path>,
    out_path: Option<PathBuf>,
    default_out: &str,
) -> Result<Option<(PathBuf, String, SourceBlock)>, String> {
    let Some(input) = input else {
        return Ok(None);
    };
    let text = std::fs::read_to_string(input)
        .map_err(|error| format!("cannot read --live-state: {error}"))?;
    let block = SourceBlock::parse(&text)?;
    let digest = block.digest()?;
    let target = out_path.unwrap_or_else(|| PathBuf::from(default_out));
    if let Some(parent) = target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let body = serde_json::to_string_pretty(&block).map_err(|error| error.to_string())? + "\n";
    std::fs::write(&target, body).map_err(|error| error.to_string())?;
    Ok(Some((target, digest, block)))
}
