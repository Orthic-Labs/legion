//! Controlled native transport. Unsupported host boundaries fail before launch.
use super::{invalid, RuntimeOptions};
use crate::{error::AuditError, next::UsageReceipt};
use rightkit_agents::{
    claude::{self, ClaudeOptions},
    event::AgentEvent,
};
use rightkit_child_process::OwnedCommand;
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::Stdio,
    sync::mpsc,
    thread,
    time::{Duration, SystemTime},
};

const MAX_STREAM: usize = 4 * 1024 * 1024;
const REQUIRED_FLAGS: &[&str] = &[
    "--tools",
    "--strict-mcp-config",
    "--mcp-config",
    "--safe-mode",
    "--restricted",
    "--disable-slash-commands",
    "--no-chrome",
    "--no-session-persistence",
    "--permission-prompts",
    "--json-schema",
    "--system-prompt",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelPolicyViolation {
    MissingObservation,
    UnauthorizedModel,
}

/// Only host-derived schema vocabulary & trusted-schema paths may reach a
/// correction prompt. Native error text & rejected actions never do.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemaRejection {
    pub keyword: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct Observation {
    pub context_id: String,
    pub process_id: u32,
    pub process_created: Option<u64>,
    pub process_creation_time: Option<SystemTime>,
    pub reply: Option<Value>,
    pub usage: UsageReceipt,
    pub raw_usage: Option<Value>,
    pub reported_api_cost_usd: Option<String>,
    pub sent: bool,
    pub error: Option<String>,
    pub response_digest: String,
    pub request_digest: String,
    pub request_bytes: u64,
    pub observed_models: Vec<String>,
    pub model_policy_violation: Option<ModelPolicyViolation>,
    pub schema_rejection: Option<SchemaRejection>,
}

fn reader<R: Read + Send + 'static>(mut input: R, cap: usize) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buf = [0u8; 8192];
        let mut truncated = false;
        loop {
            match input.read(&mut buf) {
                Ok(0) => break,
                Err(_) => {
                    truncated = true;
                    break;
                }
                Ok(n) => {
                    let room = cap.saturating_sub(kept.len());
                    kept.extend_from_slice(&buf[..n.min(room)]);
                    truncated |= n > room;
                }
            }
        }
        let _ = tx.send((kept, truncated));
    });
    rx
}

fn command(binary: &Path, cwd: &Path) -> OwnedCommand {
    let mut command = OwnedCommand::new(binary);
    // Retain only auth location & native OS process essentials; no NODE_OPTIONS,
    // CLAUDE_* overrides, injected hooks, proxy credentials or project settings.
    command.env_allowlist([
        "HOME",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PATH",
        "SystemRoot",
        "TEMP",
        "TMP",
        "TMPDIR",
        "USER",
        "LOGNAME",
    ]);
    command.windows_hide();
    // Normal OwnedCommand spawn retains process-group/job containment &
    // terminate-on-Drop on every supported host. Parent-death SIGTERM is an
    // additional Linux-only direct-child safeguard; macOS has no equivalent
    // hard-parent-exit guarantee in this owner, & rejects enabling this option.
    #[cfg(target_os = "linux")]
    command.kill_on_parent_exit(true);
    command
        .command_mut()
        .current_dir(cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

pub(super) fn admit_host(host: &str) -> Result<(), AuditError> {
    match host {
        "claude-code" => Ok(()),
        // Locked rightkit-agents 0.2.0 exposes Codex app-server protocol only.
        // It cannot establish Audit's no-settings/plugins/tools/persistence,
        // schema & hard output-token boundary. Never substitute Claude or guess
        // Codex flags/config; refusal precedes probe, budget admission & spawn.
        "codex" => Err(invalid("incomplete:host-capability:codex-controlled-generation-unavailable:required tool-less/schema/hard-output-token boundary unsupported by locked transport")),
        _ => Err(invalid("incomplete:host-capability:unsupported harness")),
    }
}

/// Leading bytes of a native executable: Mach-O (thin/fat), ELF or PE.
fn native_magic(head: &[u8]) -> bool {
    head.starts_with(&[0x7f, b'E', b'L', b'F'])
        || head.starts_with(b"MZ")
        || [
            [0xfe, 0xed, 0xfa, 0xce],
            [0xfe, 0xed, 0xfa, 0xcf],
            [0xce, 0xfa, 0xed, 0xfe],
            [0xcf, 0xfa, 0xed, 0xfe],
            [0xca, 0xfe, 0xba, 0xbe],
            [0xbe, 0xba, 0xfe, 0xca],
        ]
        .iter()
        .any(|magic| head.starts_with(magic))
}

fn temp_roots() -> Vec<PathBuf> {
    let mut roots = vec![std::env::temp_dir()];
    if let Some(tmp) = std::env::var_os("TMPDIR") {
        roots.push(PathBuf::from(tmp));
    }
    if cfg!(unix) {
        roots.extend(
            [
                "/tmp",
                "/var/tmp",
                "/private/tmp",
                "/private/var/folders",
                "/var/folders",
                "/dev/shm",
            ]
            .map(PathBuf::from),
        );
    }
    roots
        .into_iter()
        .filter(|root| !root.as_os_str().is_empty())
        .flat_map(|root| {
            let canonical = fs::canonicalize(&root).ok();
            std::iter::once(root).chain(canonical)
        })
        .collect()
}

/// Interpreter-manager directory components (shims and installs).
const INTERPRETER_DIRS: &[&str] = &[
    ".pyenv", "pyenv", ".nvm", "nvm", ".volta", "volta", ".fnm", "fnm", ".asdf", "asdf", ".bun",
    ".deno", "shims",
];

fn interpreter_location(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_ascii_lowercase();
    const PREFIXES: &[&str] = &[
        "/opt/homebrew/opt/node",
        "/opt/homebrew/opt/python",
        "/opt/homebrew/cellar/node",
        "/opt/homebrew/cellar/python",
        "/usr/local/opt/node",
        "/usr/local/opt/python",
        "/usr/local/cellar/node",
        "/usr/local/cellar/python",
        "/usr/local/lib/node_modules",
        "/opt/homebrew/lib/node_modules",
        "/usr/bin/python",
    ];
    PREFIXES.iter().any(|prefix| lower.starts_with(prefix))
        || path.components().any(|part| {
            part.as_os_str()
                .to_str()
                .is_some_and(|name| INTERPRETER_DIRS.contains(&name.to_ascii_lowercase().as_str()))
        })
}

/// Reject Node/Python-class launchers (no-node-python, the default run
/// constraint) by the name of the requested path, of every symlink hop and of
/// the canonical target, plus well-known interpreter install locations. Runs
/// before any spawn and before the file is opened.
fn reject_interpreter_runtime(absolute: &Path) -> Result<(), String> {
    use crate::execution_policy::runtime_class_of_name;
    use crate::profiles::RuntimeClass;
    let bad = |path: &Path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| runtime_class_of_name(name) != RuntimeClass::Native)
            || interpreter_location(path)
    };
    let mut current = absolute.to_path_buf();
    for _ in 0..40 {
        if bad(&current) {
            return Err("Claude executable is a Node/Python-class runtime (no-node-python)".into());
        }
        match fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let Ok(target) = fs::read_link(&current) else {
                    break;
                };
                current = if target.is_absolute() {
                    target
                } else {
                    current.parent().unwrap_or(Path::new("/")).join(target)
                };
            }
            _ => break,
        }
    }
    if let Ok(canonical) = fs::canonicalize(absolute) {
        if bad(&canonical) {
            return Err("Claude executable is a Node/Python-class runtime (no-node-python)".into());
        }
    }
    Ok(())
}

/// Validate the host executable BEFORE any spawn (including the `--help`
/// probe). The path must resolve to a regular native executable that does not
/// live in audited/attacker-writable locations: `forbidden` (snapshot
/// execution/baseline roots, audited source root, run dir) or any temp dir.
/// Scripts (`#!`) are refused because they would run an arbitrary interpreter.
pub(super) fn validate_executable(
    requested: &Path,
    forbidden: &[PathBuf],
) -> Result<PathBuf, AuditError> {
    let refuse = |why: &str| invalid(format!("incomplete:host-unavailable: {why}"));
    let absolute = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| refuse("invalid Claude executable"))?
            .join(requested)
    };
    reject_interpreter_runtime(&absolute).map_err(|why| refuse(&why))?;
    let canonical = fs::canonicalize(&absolute).map_err(|_| refuse("invalid Claude executable"))?;
    let inside = |roots: &[PathBuf]| {
        roots.iter().any(|root| {
            let canon = fs::canonicalize(root).ok();
            [&absolute, &canonical].iter().any(|path| {
                path.starts_with(root) || canon.as_ref().is_some_and(|c| path.starts_with(c))
            })
        })
    };
    if inside(forbidden) {
        return Err(refuse(
            "Claude executable cannot come from the audited source, snapshot or run directory",
        ));
    }
    let metadata = fs::metadata(&canonical).map_err(|_| refuse("invalid Claude executable"))?;
    if !metadata.is_file() {
        return Err(refuse("Claude executable must be a regular file"));
    }
    let mut head = [0u8; 8];
    let count = fs::File::open(&canonical)
        .and_then(|mut file| file.read(&mut head))
        .map_err(|_| refuse("Claude executable unreadable"))?;
    let head = &head[..count];
    if head.starts_with(b"#!") {
        return Err(refuse(
            "Claude executable is a script, not a native executable",
        ));
    }
    if !native_magic(head) {
        return Err(refuse(
            "Claude executable is not a native executable (Mach-O/ELF/PE)",
        ));
    }
    if inside(&temp_roots()) {
        return Err(refuse(
            "Claude executable cannot come from a temp or scratch directory",
        ));
    }
    // A renamed or copied interpreter passes name/location/magic checks; its
    // embedded runtime symbols do not. Bounded streaming scan, no spawn.
    if let Some(marker) = embedded_interpreter_marker(&canonical) {
        return Err(refuse(&format!(
            "Claude executable embeds a Node/Python runtime ({marker}) (no-node-python)"
        )));
    }
    Ok(canonical)
}

/// Runtime symbols that native Python and Node executables embed (the Claude
/// CLI, a Bun/JSC binary, carries none). Scans at most 1 GiB in 1 MiB chunks
/// with overlap so markers spanning a chunk boundary are found.
fn embedded_interpreter_marker(path: &Path) -> Option<String> {
    // Stored byte-reversed so no binary linking this crate carries the
    // forward symbols and so trips its own scan.
    const REVERSED: &[&str] = &[
        "ezilaitinI_yP",
        "niaMsetyB_yP",
        "tratS::edon",
        "etalosI::8v",
    ];
    let markers: Vec<Vec<u8>> = REVERSED
        .iter()
        .map(|marker| marker.bytes().rev().collect())
        .collect();
    const CHUNK: usize = 1 << 20;
    const LIMIT: u64 = 1 << 30;
    let overlap = markers.iter().map(Vec::len).max().unwrap_or(0);
    let mut file = fs::File::open(path).ok()?;
    let mut window: Vec<u8> = Vec::with_capacity(CHUNK + overlap);
    let mut buffer = vec![0u8; CHUNK];
    let mut read_total = 0u64;
    loop {
        let count = file.read(&mut buffer).ok()?;
        if count == 0 {
            return None;
        }
        if read_total >= LIMIT {
            // Too large to scan fully: fail closed rather than pass unscanned.
            return Some("unscannable-size".into());
        }
        read_total += count as u64;
        window.extend_from_slice(&buffer[..count]);
        if let Some(marker) = markers.iter().find(|marker| {
            window
                .windows(marker.len())
                .any(|candidate| candidate == marker.as_slice())
        }) {
            return Some(String::from_utf8_lossy(marker).into_owned());
        }
        let keep = window.len().saturating_sub(overlap);
        window.drain(..keep);
    }
}

pub fn resolve(
    options: &RuntimeOptions,
    cwd: &Path,
    forbidden: &[PathBuf],
) -> Result<PathBuf, AuditError> {
    let executable = if let Some(path) = &options.claude {
        path.clone()
    } else {
        let names: &[&str] = if cfg!(windows) {
            &["claude.exe"]
        } else {
            &["claude"]
        };
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .filter(|dir| dir.is_absolute())
            .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
            .find(|path| path.is_file())
            .ok_or_else(|| {
                invalid("incomplete:host-unavailable: native Claude executable missing")
            })?
    };
    // Validation precedes every spawn: a rejected path is never executed.
    let binary = validate_executable(&executable, forbidden)?;
    admit_host(super::model::current_host()?)?;
    let mut cmd = command(&binary, cwd);
    cmd.command_mut().arg("--help");
    let mut child = cmd
        .spawn()
        .map_err(|error| invalid(format!("incomplete:host-unavailable:{error}")))?;
    let out = reader(
        child
            .take_stdout()
            .ok_or_else(|| invalid("Claude help stdout unavailable"))?,
        512 * 1024,
    );
    let err = reader(
        child
            .take_stderr()
            .ok_or_else(|| invalid("Claude help stderr unavailable"))?,
        64 * 1024,
    );
    drop(child.take_stdin());
    if child
        .wait_timeout(Duration::from_secs(10))
        .map_err(|error| invalid(error.to_string()))?
        .is_none()
    {
        let _ = child.terminate_tree_bounded(Duration::from_secs(2));
        return Err(invalid("incomplete:host-capability-probe-timeout"));
    }
    let (help, truncated) = out
        .recv_timeout(Duration::from_secs(2))
        .map_err(|_| invalid("incomplete:host-help-unavailable"))?;
    let _ = err.recv_timeout(Duration::from_secs(2));
    let help = String::from_utf8_lossy(&help);
    if truncated || REQUIRED_FLAGS.iter().any(|flag| !help.contains(flag)) {
        return Err(invalid("incomplete:host-tool-boundary-unsupported"));
    }
    if !help.contains("--effort") {
        return Err(invalid("incomplete:host-reasoning-effort-unsupported"));
    }
    // These hidden controls are accepted only when present in actual installed
    // native binary, not merely asserted by a model or package version.
    let needles = [
        b"--max-turns".as_slice(),
        b"CLAUDE_CODE_MAX_OUTPUT_TOKENS".as_slice(),
    ];
    let mut found = [false; 2];
    let mut scanned = 0usize;
    let mut carry = Vec::new();
    let mut executable =
        fs::File::open(&binary).map_err(|_| invalid("incomplete:host-limit-probe-unavailable"))?;
    let mut block = [0u8; 65536];
    loop {
        let count = executable
            .read(&mut block)
            .map_err(|_| invalid("incomplete:host-limit-probe-unavailable"))?;
        if count == 0 {
            break;
        }
        scanned += count;
        if scanned > 512 * 1024 * 1024 {
            return Err(invalid("incomplete:host-limit-probe-byte-cap"));
        }
        carry.extend_from_slice(&block[..count]);
        for (index, needle) in needles.iter().enumerate() {
            found[index] |= carry.windows(needle.len()).any(|part| part == *needle);
        }
        if found.iter().all(|found| *found) {
            break;
        }
        if carry.len() > 128 {
            carry.drain(..carry.len() - 128);
        }
    }
    if !found.iter().all(|found| *found) {
        return Err(invalid("incomplete:host-output-limit-unsupported"));
    }
    Ok(binary)
}

pub fn rendered_input(prompt: &Value) -> Result<String, AuditError> {
    let canonical = rightkit_evidence_contracts::canonical_json_bytes(prompt)
        .map_err(|error| invalid(error.to_string()))?;
    Ok(claude::user_turn_frame(
        std::str::from_utf8(&canonical).map_err(|error| invalid(error.to_string()))?,
    ))
}

#[allow(clippy::too_many_arguments)]
pub fn invoke(
    binary: &Path,
    cwd: &Path,
    options: &RuntimeOptions,
    execution: &super::model::ExecutionSelection,
    call_id: &str,
    reservation_id: &str,
    output_limit: u64,
    system: &str,
    schema: &Value,
    frame: String,
) -> Observation {
    // Claude Code counts thinking tokens against CLAUDE_CODE_MAX_OUTPUT_TOKENS: the native cap is
    // the frozen text allowance plus an effort-sized thinking allowance (see thinking_allowance).
    let native_output_cap =
        output_limit.saturating_add(thinking_allowance(&execution.reasoning_effort));
    let mut usage = UsageReceipt {
        reservation_id: reservation_id.into(),
        receipt_id: format!("usage:{call_id}"),
        input_tokens: None,
        output_tokens: None,
        cached_input_tokens: None,
        retry_tokens: None,
        thinking_tokens: None,
        failed: true,
    };
    let mut observation = Observation {
        context_id: String::new(),
        process_id: 0,
        process_created: None,
        process_creation_time: None,
        reply: None,
        usage: usage.clone(),
        raw_usage: None,
        reported_api_cost_usd: None,
        sent: false,
        error: None,
        response_digest: String::new(),
        request_digest: String::new(),
        request_bytes: 0,
        observed_models: Vec::new(),
        model_policy_violation: None,
        schema_rejection: None,
    };
    let result = (|| -> Result<(), String> {
        super::model::validate_execution_host(execution).map_err(|error| error.to_string())?;
        admit_host(execution.host).map_err(|error| error.to_string())?;
        // Re-check at launch: the file may have been replaced since the probe.
        validate_executable(binary, &[]).map_err(|error| error.to_string())?;
        let mut cmd = command(binary, cwd);
        // Without the thinking allowance a high-effort author is cut at the text cap mid-JSON and
        // the CLI's structured-output retries repeat the truncation (observed: 4 x 4096, stop_sequence).
        // Installed --help defines safe-mode as disabling user/project
        // settings, hooks & plugins while retaining subscription auth. Bare
        // mode disables OAuth/keychain auth, so it is not interchangeable.
        // Explicit model/effort plus observed model checks prevent inherited
        // orchestrator defaults from silently becoming paid Audit execution.
        let args = claude::build_args(&ClaudeOptions {
            model: Some(execution.model.clone()),
            ..Default::default()
        })?;
        cmd.command_mut()
            .args(args)
            .args(["--effort", &execution.reasoning_effort])
            .args([
                "--tools",
                "",
                "--strict-mcp-config",
                "--mcp-config",
                "{\"mcpServers\":{}}",
                "--safe-mode",
                "--restricted",
                "--disable-slash-commands",
                "--no-chrome",
                "--no-session-persistence",
                "--permission-prompts",
                "none",
                // Three assistant turns: one structured answer plus at most two
                // in-process re-emits after the host rejects unparsable JSON.
                // The decoder admits nothing else, so this stays one physical
                // call with cumulative usage.
                "--max-turns",
                "3",
                "--system-prompt",
                system,
                "--json-schema",
                &schema.to_string(),
            ])
            .env(
                "CLAUDE_CODE_MAX_OUTPUT_TOKENS",
                native_output_cap.to_string(),
            );
        let mut child = cmd.spawn().map_err(|error| error.to_string())?;
        observation.process_id = child.id();
        observation.process_creation_time = child.creation_time();
        #[cfg(windows)]
        {
            observation.process_created = child.creation_time_ticks();
        }
        let stdout = reader(
            child.take_stdout().ok_or("native stdout missing")?,
            MAX_STREAM,
        );
        let stderr = reader(
            child.take_stderr().ok_or("native stderr missing")?,
            64 * 1024,
        );
        let mut input = child.take_stdin().ok_or("native stdin missing")?;
        let (sent_tx, sent_rx) = mpsc::channel();
        thread::spawn(move || {
            let result = input
                .write_all(frame.as_bytes())
                .and_then(|_| input.flush());
            drop(input);
            let _ = sent_tx.send(result.is_ok());
        });
        let exited = child
            .wait_timeout(Duration::from_secs(options.call_timeout_seconds))
            .map_err(|error| error.to_string())?;
        if exited.is_none() {
            let _ = child.terminate_tree_bounded(Duration::from_secs(3));
        }
        observation.sent = sent_rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or(false);
        let (bytes, truncated) = stdout
            .recv_timeout(Duration::from_secs(3))
            .map_err(|_| "native stream did not close")?;
        let stderr_complete = stderr
            .recv_timeout(Duration::from_secs(2))
            .is_ok_and(|(_, truncated)| !truncated);
        observation.response_digest = super::digest_bytes(&bytes);
        let decoded = decode_stream_with_schema(&bytes, &mut observation, &mut usage, schema);
        let process_failure = exited
            .as_ref()
            .filter(|status| !status.success())
            .map(|status| native_process_failure(status.code()));
        // A diagnostic decoded before a byte cap, timeout or abnormal exit
        // cannot authorize another paid call.
        if !schema_repair_capture_complete(
            truncated,
            stderr_complete,
            exited.as_ref().and_then(|status| status.code()),
        ) {
            observation.schema_rejection = None;
        }
        decoded.map_err(|error| match &process_failure {
            Some(process_failure) => format!("{error}; {process_failure}"),
            None => error,
        })?;
        if truncated {
            return Err("native response exceeded byte cap".into());
        }
        if exited.is_none() {
            return Err("native model call timed out".into());
        }
        if let Some(error) = process_failure {
            return Err(error);
        }
        if !observation.sent || observation.context_id.is_empty() || observation.reply.is_none() {
            return Err("native transport missing complete send/session/structured result".into());
        }
        validate_schema(
            observation
                .reply
                .as_ref()
                .ok_or("structured result missing")?,
            schema,
            0,
        )?;
        usage.failed = false;
        Ok(())
    })();
    observation.error = result.err();
    finalize_model_policy(&mut observation, &mut usage, execution);
    if !observation.sent
        || observation.context_id.is_empty()
        || observation.model_policy_violation.is_some()
        || usage.input_tokens.is_none()
        || usage.output_tokens.is_none()
        || usage.cached_input_tokens.is_none()
        || usage.retry_tokens.is_none()
        || usage
            .output_tokens
            .is_some_and(|tokens| tokens > native_output_cap)
        || crate::next::text_output_tokens(&usage) > output_limit
    {
        observation.schema_rejection = None;
    }
    observation.usage = usage;
    observation
}

// Finalize outside protocol decoding: refusals, malformed output, timeouts &
// process failures must never bypass model authorization or erase paid usage.
fn finalize_model_policy(
    observation: &mut Observation,
    usage: &mut UsageReceipt,
    execution: &super::model::ExecutionSelection,
) {
    observation.model_policy_violation = if observation.process_id == 0 {
        None
    } else if observation.observed_models.is_empty() {
        Some(ModelPolicyViolation::MissingObservation)
    } else if observation
        .observed_models
        .iter()
        .any(|model| !super::model::observed_model_matches(execution, model))
    {
        Some(ModelPolicyViolation::UnauthorizedModel)
    } else {
        None
    };
    if let Some(violation) = observation.model_policy_violation {
        usage.failed = true;
        observation.error.get_or_insert_with(|| {
            match violation {
                ModelPolicyViolation::MissingObservation => {
                    "native model observation missing; usage retained"
                }
                ModelPolicyViolation::UnauthorizedModel => {
                    "native observed model differs from authorized executor tier; usage retained"
                }
            }
            .into()
        });
    }
}

pub(super) fn repair_diagnostic(observation: &Observation) -> Option<&SchemaRejection> {
    if observation.process_id == 0
        || !observation.sent
        || observation.context_id.is_empty()
        || observation.error.is_none()
        || observation.reply.is_some()
        || observation.model_policy_violation.is_some()
        || observation.observed_models.is_empty()
        || !observation.usage.failed
        || observation.usage.input_tokens.is_none()
        || observation.usage.output_tokens.is_none()
        || observation.usage.cached_input_tokens.is_none()
        || observation.usage.retry_tokens.is_none()
    {
        return None;
    }
    observation.schema_rejection.as_ref()
}

fn capture_accounting(
    raw: &Value,
    line: &str,
    observation: &mut Observation,
    usage: &mut UsageReceipt,
) {
    observation.reported_api_cost_usd = super::cost::native_root_cost(line);
    if let Some(models) = raw.get("modelUsage").and_then(Value::as_object) {
        for model in models.keys() {
            if !observation.observed_models.contains(model) {
                observation.observed_models.push(model.clone());
            }
        }
    }
    if let Some(value) = raw.get("usage") {
        // Native final event is cumulative within this fresh one-turn
        // process; never add assistant snapshots or default absent to0.
        let count = |key: &str| value.get(key).and_then(Value::as_u64);
        let ordinary = count("input_tokens");
        let cache_read = count("cache_read_input_tokens");
        let cache_create = count("cache_creation_input_tokens");
        usage.input_tokens = match (ordinary, cache_read, cache_create) {
            (Some(input), Some(read), Some(create)) => {
                input.checked_add(read).and_then(|n| n.checked_add(create))
            }
            _ => None,
        };
        usage.cached_input_tokens = cache_read;
        usage.output_tokens = count("output_tokens");
        // Claude Code reports thinking inside output_tokens and itemizes it here;
        // absent itemization means no thinking was counted.
        usage.thinking_tokens = Some(
            value
                .get("output_tokens_details")
                .and_then(|details| details.get("thinking_tokens"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
        );
        // Final native usage is cumulative for this fresh process. This
        // field counts only ADDITIONAL spend absent from that total, not
        // retry attribution (which native transport does not report).
        if usage.input_tokens.is_some() && usage.output_tokens.is_some() {
            usage.retry_tokens = Some(0);
        }
        observation.raw_usage = Some(value.clone());
    }
}

fn native_process_failure(code: Option<i32>) -> String {
    match code {
        Some(code) => format!("native process failed; exit_status={code}"),
        None => "native process failed".into(),
    }
}

fn schema_repair_capture_complete(
    truncated: bool,
    stderr_complete: bool,
    exit_code: Option<i32>,
) -> bool {
    !truncated && stderr_complete && exit_code == Some(1)
}

fn native_terminal_failure(raw: &Value) -> String {
    // Keep protocol categories only: native errors/result bodies can contain
    // arbitrary model output, source, or credentials.
    let subtype = raw
        .get("subtype")
        .and_then(Value::as_str)
        .filter(|subtype| {
            matches!(
                *subtype,
                "error_during_execution"
                    | "error_max_turns"
                    | "error_max_budget_usd"
                    | "error_max_structured_output_retries"
            )
        })
        .unwrap_or("unknown");
    let turns = raw
        .get("num_turns")
        .and_then(Value::as_u64)
        .and_then(|turns| u32::try_from(turns).ok())
        .map(|turns| turns.to_string())
        .unwrap_or_else(|| "unknown".into());
    let stop_reason = raw
        .get("stop_reason")
        .and_then(Value::as_str)
        .filter(|reason| {
            matches!(
                *reason,
                "end_turn"
                    | "max_tokens"
                    | "stop_sequence"
                    | "tool_use"
                    | "pause_turn"
                    | "refusal"
                    | "model_context_window_exceeded"
            )
        })
        .unwrap_or("unknown");
    format!("native result failed/refused; subtype={subtype}; num_turns={turns}; stop_reason={stop_reason}; raw usage retained")
}

/// Thinking tokens the native CLI may spend above the frozen text output cap.
fn thinking_allowance(reasoning_effort: &str) -> u64 {
    match reasoning_effort {
        "low" => 2_048,
        "medium" => 6_144,
        _ => 12_288,
    }
}

fn decode_stream_with_schema(
    bytes: &[u8],
    observation: &mut Observation,
    usage: &mut UsageReceipt,
    schema: &Value,
) -> Result<(), String> {
    let mut parser = claude::StreamParser::new();
    let mut protocol_error = None;
    let mut terminal = None;
    let mut structured = Vec::new();
    let mut results: Vec<(Value, bool, bool, bool)> = Vec::new();
    let mut json_reemits = 0usize;
    let mut session = None;
    let mut strict_boundary = false;
    let mut repair_events_valid = true;
    for line in std::str::from_utf8(bytes)
        .map_err(|_| "invalid UTF-8 native output")?
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let raw: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
        let event_allowed = schema_repair_event_allowed(&raw);
        repair_events_valid &= event_allowed;
        if let Some(model) = raw.pointer("/message/model").and_then(Value::as_str) {
            if !observation
                .observed_models
                .iter()
                .any(|observed| observed == model)
            {
                observation.observed_models.push(model.to_owned());
            }
        }
        if terminal.is_some() {
            protocol_error = Some("native data after terminal result");
        }
        if let Some(id) = raw.get("session_id").and_then(Value::as_str) {
            if session.as_deref().is_some_and(|prior| prior != id) || id.is_empty() {
                protocol_error = Some("native session identity changed");
            }
            session = Some(id.to_owned());
        }
        if raw["type"] == "system" && raw["subtype"] == "init" {
            strict_boundary = raw["tools"] == json!(["StructuredOutput"])
                && raw["mcp_servers"] == json!([])
                && raw["slash_commands"] == json!([]);
        }
        if matches!(raw["type"].as_str(), Some("assistant" | "user" | "result"))
            && raw["session_id"].as_str().is_none()
        {
            strict_boundary = false;
        }
        if let Some(content) = raw.pointer("/message/content").and_then(Value::as_array) {
            for item in content {
                match item["type"].as_str() {
                    Some("tool_use") => {
                        if raw["type"] != "assistant" {
                            strict_boundary = false;
                        }
                        // A further tool use is admitted only as one of the two
                        // re-emits after the host could not parse the previous.
                        let reemit = !results.is_empty()
                            && results.len() == structured.len()
                            && results
                                .last()
                                .is_some_and(|(_, is_error, _, unparsed)| *is_error && *unparsed)
                            && json_reemits < 2;
                        if observation.context_id.is_empty() || (!results.is_empty() && !reemit) {
                            protocol_error = Some("native tool use outside initialized call order");
                        } else if reemit {
                            json_reemits += 1;
                        }
                        structured.push((
                            item["id"].clone(),
                            item["name"].clone(),
                            item["input"].clone(),
                        ));
                    }
                    Some("tool_result") => {
                        if raw["type"] != "user" {
                            strict_boundary = false;
                        }
                        if structured.len() != results.len() + 1
                            || structured.last().map(|entry| &entry.0) != Some(&item["tool_use_id"])
                        {
                            protocol_error = Some("native tool result correlation invalid");
                        }
                        results.push((
                            item["tool_use_id"].clone(),
                            item["is_error"] == true,
                            item["content"].as_str().is_some_and(|text| {
                                text.starts_with("Output does not match required schema: ")
                            }),
                            item["content"].as_str().is_some_and(|text| {
                                text.starts_with("<tool_use_error>InputValidationError: StructuredOutput was called with input that could not be parsed as JSON")
                            }),
                        ));
                    }
                    _ => {}
                }
            }
        }
        if raw.get("type").and_then(Value::as_str) == Some("result") {
            // Retain paid accounting even if later parser/protocol data fails.
            capture_accounting(&raw, line, observation, usage);
        }
        let events = parser.parse_line(line).map_err(|error| error.to_string())?;
        for event in events {
            match event {
                AgentEvent::Init {
                    session_id,
                    model,
                    tools,
                    ..
                } => {
                    if let Some(model) = model {
                        observation.observed_models.push(model);
                    }
                    if !observation.context_id.is_empty() {
                        protocol_error = Some("duplicate native session initialization");
                    }
                    observation.context_id = session_id;
                    if tools.iter().any(|tool| tool != "StructuredOutput") {
                        protocol_error =
                            Some("native host exposed tools despite disabled tool boundary");
                    }
                }
                // Qualified installed native tool factory is read-only,
                // data-only, endsTurn:true. It validates & returns its input;
                // it has no source/filesystem/shell/network handler.
                AgentEvent::ToolUse { name, .. } if name == "StructuredOutput" => {}
                AgentEvent::ToolUse { .. } | AgentEvent::SubagentStarted { .. } => {
                    protocol_error = Some("native tool/subagent use violates controlled boundary")
                }
                // The locked parser reports ui_invalidate as Unknown. Only
                // already-qualified passive telemetry may cross that boundary;
                // earlier order/session faults & all other unknowns stay fatal.
                AgentEvent::Unknown { .. }
                    if event_allowed
                        && (raw["type"] == "rate_limit_event"
                            || (raw["type"] == "system"
                                && matches!(
                                    raw["subtype"].as_str(),
                                    Some("ui_invalidate" | "thinking_tokens")
                                ))) => {}
                AgentEvent::Unknown { .. } => {
                    protocol_error = Some("native host stream contains unsupported protocol event")
                }
                _ => {}
            }
        }
        if raw.get("type").and_then(Value::as_str) == Some("result") {
            if terminal.is_some() {
                protocol_error = Some("duplicate native terminal result");
            }
            terminal = Some(raw);
        }
    }
    if let Some(error) = protocol_error {
        return Err(error.into());
    }
    if let Some(raw) = terminal {
        // A valid JSON body cannot prove semantic completion when native
        // terminal metadata explicitly reports exhausting its output cap.
        if raw.get("is_error").and_then(Value::as_bool) == Some(true)
            || raw.get("stop_reason").and_then(Value::as_str) == Some("max_tokens")
        {
            if strict_boundary
                && repair_events_valid
                && !observation.context_id.is_empty()
                && raw["subtype"] == "error_max_turns"
                && raw["is_error"] == true
                && raw["stop_reason"] == "tool_use"
                && (2..=4).contains(&raw["num_turns"].as_u64().unwrap_or(0))
                && raw.get("structured_output").is_none()
                && raw["permission_denials"] == json!([])
                && raw["safety_stops"] == 0
                && !structured.is_empty()
                && structured.len() == results.len()
                && structured.last().is_some_and(|entry| {
                    entry.1 == "StructuredOutput"
                        && entry
                            .0
                            .as_str()
                            .is_some_and(|id| !id.is_empty() && id.len() <= 256)
                })
                && results
                    .last()
                    .zip(structured.last())
                    .is_some_and(|(result, entry)| result.0 == entry.0 && result.1 && result.2)
                && usage.input_tokens.is_some()
                && usage.output_tokens.is_some()
                && usage.cached_input_tokens.is_some()
                && usage.retry_tokens.is_some()
            {
                if let Some(entry) = structured.last() {
                    observation.schema_rejection = schema_rejection(&entry.2, schema, "", 0);
                }
            }
            return Err(native_terminal_failure(&raw));
        }
        observation.reply = raw
            .get("structured_output")
            .filter(|value| value.is_object())
            .cloned()
            .or_else(|| {
                raw.get("result")
                    .and_then(Value::as_str)
                    .and_then(|text| serde_json::from_str(text).ok())
            });
    }
    Ok(())
}

fn schema_repair_event_allowed(raw: &Value) -> bool {
    // StreamParser intentionally ignores several native control messages.
    // That compatibility must not authorize another paid process after an
    // approval/policy/error exchange. Only qualified passive telemetry passes.
    if raw["is_error"] == true && raw["type"] != "result" {
        return false;
    }
    if raw.get("error").is_some_and(|error| !error.is_null()) {
        return false;
    }
    if raw.get("errorCode").is_some_and(|error| !error.is_null()) {
        return false;
    }
    match raw["type"].as_str() {
        Some("system") => matches!(
            raw["subtype"].as_str(),
            Some("init" | "ui_invalidate" | "thinking_tokens")
        ),
        Some("assistant") => raw
            .pointer("/message/content")
            .and_then(Value::as_array)
            .is_some_and(|content| {
                content.iter().all(|item| {
                    matches!(
                        item["type"].as_str(),
                        Some("text" | "thinking" | "redacted_thinking" | "tool_use")
                    )
                })
            }),
        Some("user") => raw
            .pointer("/message/content")
            .and_then(Value::as_array)
            .is_some_and(|content| content.iter().all(|item| item["type"] == "tool_result")),
        Some("result") => true,
        Some("rate_limit_event") => {
            raw.pointer("/rate_limit_info/status")
                .and_then(Value::as_str)
                == Some("allowed")
                && raw
                    .pointer("/rate_limit_info/errorCode")
                    .is_none_or(Value::is_null)
                && raw
                    .pointer("/rate_limit_info/error")
                    .is_none_or(Value::is_null)
        }
        _ => false,
    }
}

fn schema_rejection(
    value: &Value,
    schema: &Value,
    path: &str,
    depth: usize,
) -> Option<SchemaRejection> {
    if depth > 64 || path.len() > 256 || validate_schema(value, schema, depth).is_ok() {
        return None;
    }
    let found = |keyword: &str| {
        Some(SchemaRejection {
            keyword: keyword.into(),
            path: path.into(),
        })
    };
    if let Some(kind) = schema["type"].as_str() {
        let matches = match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            "number" => value.is_number(),
            _ => return None,
        };
        if !matches {
            return found("type");
        }
    }
    if schema["enum"]
        .as_array()
        .is_some_and(|allowed| !allowed.contains(value))
    {
        return found("enum");
    }
    if let Some(variants) = schema["oneOf"].as_array() {
        if variants
            .iter()
            .filter(|variant| validate_schema(value, variant, depth + 1).is_ok())
            .count()
            != 1
        {
            return found("oneOf");
        }
    }
    if let Some(fields) = value.as_object() {
        if schema["required"].as_array().is_some_and(|required| {
            required
                .iter()
                .any(|key| key.as_str().is_none_or(|key| !fields.contains_key(key)))
        }) {
            return found("required");
        }
        let properties = schema["properties"].as_object();
        if schema["additionalProperties"] == false
            && fields
                .keys()
                .any(|key| properties.is_none_or(|properties| !properties.contains_key(key)))
        {
            return found("additionalProperties");
        }
        // Paths come from trusted schema keys only; unknown model keys never
        // enter diagnostics. Array positions use a fixed wildcard.
        if let Some(properties) = properties {
            for (key, constraint) in properties {
                if let Some(item) = fields.get(key) {
                    let child = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
                    if let Some(error) = schema_rejection(item, constraint, &child, depth + 1) {
                        return Some(error);
                    }
                }
            }
        }
    }
    if let (Some(items), Some(constraint)) = (value.as_array(), schema.get("items")) {
        for item in items {
            if let Some(error) = schema_rejection(item, constraint, &format!("{path}/*"), depth + 1)
            {
                return Some(error);
            }
        }
    }
    None
}

// Validate the exact small JSON-schema vocabulary used by host action &
// independent-verifier transports. Unknown constraints fail closed.
fn validate_schema(value: &Value, schema: &Value, depth: usize) -> Result<(), String> {
    if depth > 64 {
        return Err("structured schema nesting exceeds bound".into());
    }
    let object = schema.as_object().ok_or("host schema must be object")?;
    for key in object.keys() {
        if ![
            "type",
            "properties",
            "required",
            "additionalProperties",
            "oneOf",
            "enum",
            "items",
        ]
        .contains(&key.as_str())
        {
            return Err(format!("unsupported host schema constraint:{key}"));
        }
    }
    if let Some(kind) = schema.get("type").and_then(Value::as_str) {
        let matches = match kind {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" => value.is_i64() || value.is_u64(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            "number" => value.is_number(),
            _ => return Err("unsupported host schema type".into()),
        };
        if !matches {
            return Err(format!("structured output expected {kind}"));
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
        if !allowed.contains(value) {
            return Err("structured output enum mismatch".into());
        }
    }
    if let Some(variants) = schema.get("oneOf").and_then(Value::as_array) {
        if variants
            .iter()
            .filter(|variant| validate_schema(value, variant, depth + 1).is_ok())
            .count()
            != 1
        {
            return Err("structured output must match exactly one action".into());
        }
    }
    if let Some(fields) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            if required
                .iter()
                .any(|key| key.as_str().is_none_or(|key| !fields.contains_key(key)))
            {
                return Err("structured output required field missing".into());
            }
        }
        let properties = schema.get("properties").and_then(Value::as_object);
        for (key, item) in fields {
            if let Some(constraint) = properties.and_then(|properties| properties.get(key)) {
                validate_schema(item, constraint, depth + 1)?;
            } else if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
                return Err(format!("unexpected structured field:{key}"));
            }
        }
    }
    if let (Some(items), Some(constraint)) = (value.as_array(), schema.get("items")) {
        for item in items {
            validate_schema(item, constraint, depth + 1)?;
        }
    }
    Ok(())
}

fn creation_time_value(time: Option<SystemTime>) -> Value {
    // RightKit captures OS process start on macOS/Windows. Its other Unix
    // implementation captures host spawn time; label that weaker observation.
    let source = if cfg!(windows) {
        "windows-process-start"
    } else if cfg!(target_os = "macos") {
        "macos-process-start"
    } else {
        "host-spawn-observation"
    };
    time.and_then(|time|time.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|elapsed|json!({"source":source,"unixSeconds":elapsed.as_secs(),"nanoseconds":elapsed.subsec_nanos()}))
        .unwrap_or(Value::Null)
}
pub fn observation_value(observation: &Observation) -> Value {
    json!({"contextId": observation.context_id, "processId": observation.process_id, "processCreated": observation.process_id > 0, "processCreationTicks": observation.process_created, "processCreationTime":creation_time_value(observation.process_creation_time), "responseDigest": observation.response_digest, "sent": observation.sent, "error": observation.error, "usage": observation.usage, "rawUsage": observation.raw_usage, "reportedApiEquivalentCostUsd": observation.reported_api_cost_usd, "invoiceChargeUsd": null, "physicalRequestDigest": observation.request_digest, "physicalRequestBytes": observation.request_bytes,"observedModels":observation.observed_models,"modelPolicyViolation":observation.model_policy_violation,"schemaRejection":observation.schema_rejection})
}

// Keep only the decision needed to diagnose another paid turn. Finding bodies
// already have their own retained result path; never copy arbitrary model
// output or unbounded source into call diagnostics.
pub(super) fn action_diagnostic(observation: &Observation) -> Value {
    fn redact(value: &Value) -> Value {
        match value {
            Value::String(text) => json!(
                crate::native_providers::reasoning::excerpts::redact_lines(text)
                    .into_iter()
                    .map(|line| line.text)
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
            Value::Array(items) => Value::Array(items.iter().map(redact).collect()),
            Value::Object(items) => Value::Object(
                items
                    .iter()
                    .map(|(key, item)| {
                        let safe_key =
                            crate::native_providers::reasoning::excerpts::redact_lines(key)
                                .into_iter()
                                .map(|line| line.text)
                                .collect::<Vec<_>>()
                                .join("\n");
                        let safe_value = if let Some(text) = item.as_str() {
                            let assignment = format!("{key}={text}");
                            if crate::native_providers::reasoning::excerpts::redact_secrets(
                                &assignment,
                            )
                            .1
                            {
                                json!("[REDACTED]")
                            } else {
                                redact(item)
                            }
                        } else {
                            redact(item)
                        };
                        (safe_key, safe_value)
                    })
                    .collect(),
            ),
            other => other.clone(),
        }
    }
    let Some(reply) = &observation.reply else {
        return json!({"kind":"unavailable"});
    };
    if let Some(tool) = reply.get("toolRequest") {
        let diagnostic = json!({"kind":"toolRequest","toolRequest":redact(tool),"truncated":false});
        if diagnostic.to_string().len() <= 8192 {
            return diagnostic;
        }
        return json!({"kind":"toolRequest","tool":tool.get("tool").and_then(Value::as_str).filter(|name|name.len()<=128),"truncated":true});
    }
    if let Some(result) = reply.get("finalResult") {
        return json!({"kind":"finalResult","complete":result.get("complete").and_then(Value::as_bool),"findingCount":result.get("findings").and_then(Value::as_array).map(Vec::len)});
    }
    json!({"kind":"other-structured-result"})
}
