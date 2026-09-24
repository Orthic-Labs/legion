//! `run(argv)` CLI wrapper mirroring `skills/handoff/scripts/transcript-handoff.py`'s
//! `argparse` surface, matching stdout shape and exit codes byte-for-byte
//! where the underlying logic is pure Rust.
//!
//! The Python `continuity` subcommand shelled out to an external `membrane`
//! binary (`subprocess.run([bin, "continuity", "--json"], ...)`). Membrane
//! is gone from Legion (Blueprint/Membrane now live only in CodeRight), so
//! that lane is intentionally NOT ported here — only the `bootstrap` path
//! (`build_pointer`/`paste_prompt`) is. `continuity` is recognized as a
//! known-but-unsupported subcommand and fails fast with a clear message
//! instead of trying to spawn a binary that no longer exists in this
//! product. The skill doc (`skills/handoff/...`) should be updated to drop
//! the "hand off to membrane for live continuity" step and describe the
//! bootstrap pointer/paste-prompt flow as the only supported path.

use std::path::PathBuf;

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
/// and today's date. No subprocess runner: Membrane is gone from Legion,
/// so the `continuity` lane that used to shell out to it is not carried
/// forward (see module doc comment).
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
        "continuity" => {
            let _ = writeln!(
                out,
                "FAIL: continuity is not supported (Membrane is not part of Legion)"
            );
            2
        }
        other => {
            let _ = writeln!(out, "FAIL: unrecognized command: {other}");
            2
        }
    }
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

