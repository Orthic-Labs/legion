//! Tool-less native Claude transport. No repository executable or shell is invoked.
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
}

fn reader<R: Read + Send + 'static>(mut input: R, cap: usize) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut kept = Vec::new();
        let mut buf = [0u8; 8192];
        let mut truncated = false;
        loop {
            match input.read(&mut buf) {
                Ok(0) | Err(_) => break,
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

pub fn resolve(options: &RuntimeOptions, cwd: &Path) -> Result<PathBuf, AuditError> {
    let executable = if let Some(path) = &options.claude {
        path.clone()
    } else {
        let names: &[&str] = if cfg!(windows) {
            &["claude.exe"]
        } else {
            &["claude"]
        };
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .flat_map(|dir| names.iter().map(move |name| dir.join(name)))
            .find(|path| path.is_file())
            .ok_or_else(|| {
                invalid("incomplete:host-unavailable: native Claude executable missing")
            })?
    };
    let binary = fs::canonicalize(&executable)
        .map_err(|_| invalid("incomplete:host-unavailable: invalid Claude executable"))?;
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
    let canonical = legion_contracts::canonical_json_bytes(prompt)
        .map_err(|error| invalid(error.to_string()))?;
    Ok(claude::user_turn_frame(
        std::str::from_utf8(&canonical).map_err(|error| invalid(error.to_string()))?,
    ))
}

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
    let mut usage = UsageReceipt {
        reservation_id: reservation_id.into(),
        receipt_id: format!("usage:{call_id}"),
        input_tokens: None,
        output_tokens: None,
        cached_input_tokens: None,
        retry_tokens: None,
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
    };
    let result = (|| -> Result<(), String> {
        let mut cmd = command(binary, cwd);
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
                "--max-turns",
                "1",
                "--system-prompt",
                system,
                "--json-schema",
                &schema.to_string(),
            ])
            .env("CLAUDE_CODE_MAX_OUTPUT_TOKENS", output_limit.to_string());
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
        let _ = stderr.recv_timeout(Duration::from_secs(2));
        observation.response_digest = super::digest_bytes(&bytes);
        decode_stream(&bytes, &mut observation, &mut usage)?;
        if truncated {
            return Err("native response exceeded byte cap".into());
        }
        if exited.is_none() {
            return Err("native model call timed out".into());
        }
        if exited.is_some_and(|status| !status.success()) {
            return Err("native process failed".into());
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
        // Final native usage is cumulative for this fresh process. This
        // field counts only ADDITIONAL spend absent from that total, not
        // retry attribution (which native transport does not report).
        if usage.input_tokens.is_some() && usage.output_tokens.is_some() {
            usage.retry_tokens = Some(0);
        }
        observation.raw_usage = Some(value.clone());
    }
}

fn decode_stream(
    bytes: &[u8],
    observation: &mut Observation,
    usage: &mut UsageReceipt,
) -> Result<(), String> {
    let mut parser = claude::StreamParser::new();
    let mut protocol_error = None;
    let mut terminal = None;
    for line in std::str::from_utf8(&bytes)
        .map_err(|_| "invalid UTF-8 native output")?
        .lines()
        .filter(|line| !line.trim().is_empty())
    {
        let raw: Value = serde_json::from_str(line).map_err(|error| error.to_string())?;
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
    if let Some(raw) = terminal {
        if raw.get("is_error").and_then(Value::as_bool) == Some(true) {
            return Err("native result failed/refused; raw usage retained".into());
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
    if let Some(error) = protocol_error {
        return Err(error.into());
    }
    Ok(())
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
    json!({"contextId": observation.context_id, "processId": observation.process_id, "processCreated": observation.process_id > 0, "processCreationTicks": observation.process_created, "processCreationTime":creation_time_value(observation.process_creation_time), "responseDigest": observation.response_digest, "sent": observation.sent, "error": observation.error, "usage": observation.usage, "rawUsage": observation.raw_usage, "reportedApiEquivalentCostUsd": observation.reported_api_cost_usd, "invoiceChargeUsd": null, "physicalRequestDigest": observation.request_digest, "physicalRequestBytes": observation.request_bytes,"observedModels":observation.observed_models,"modelPolicyViolation":observation.model_policy_violation})
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn paid_action_diagnostic_is_redacted_and_bounded() {
        let (mut observation, _) = empty();
        observation.reply = Some(
            json!({"toolRequest":{"tool":"audit.read_file","arguments":{"path":"source.rs","startLine":1,"query":"password = abcdefghijklmnop","password":"abcdefghijklmnop"}}}),
        );
        let diagnostic = action_diagnostic(&observation);
        assert_eq!(diagnostic["toolRequest"]["arguments"]["path"], "source.rs");
        assert!(!diagnostic.to_string().contains("abcdefghijklmnop"));
        observation.reply = Some(
            json!({"toolRequest":{"tool":"audit.search_code","arguments":{"query":"x".repeat(16384)}}}),
        );
        let diagnostic = action_diagnostic(&observation);
        assert_eq!(diagnostic["truncated"], true);
        assert!(diagnostic.to_string().len() <= 8192);
    }
    #[test]
    fn owned_native_launcher_supports_current_platform_without_model_call() {
        // Exercise production launch policy using this Rust test executable,
        // never installed Claude. In particular, macOS must not request the
        // Linux-only parent-death primitive before its first capability probe.
        let binary = std::env::current_exe().unwrap();
        let cwd = std::env::current_dir().unwrap();
        let mut launch = command(&binary, &cwd);
        assert!(launch.env_is_cleared());
        launch
            .command_mut()
            .arg("--help")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = launch
            .spawn()
            .expect("owned native launch must support current platform");
        assert!(child.id() > 0);
        let status = child
            .wait_timeout(Duration::from_secs(5))
            .unwrap()
            .expect("simulated native help must finish within bound");
        assert!(status.success());
    }
    fn empty() -> (Observation, UsageReceipt) {
        let usage = UsageReceipt {
            reservation_id: "reservation".into(),
            receipt_id: "receipt".into(),
            input_tokens: None,
            output_tokens: None,
            cached_input_tokens: None,
            retry_tokens: None,
            failed: true,
        };
        (
            Observation {
                context_id: String::new(),
                process_id: 1,
                process_created: None,
                process_creation_time: None,
                reply: None,
                usage: usage.clone(),
                raw_usage: None,
                reported_api_cost_usd: None,
                sent: true,
                error: None,
                response_digest: String::new(),
                request_digest: String::new(),
                request_bytes: 0,
                observed_models: Vec::new(),
                model_policy_violation: None,
            },
            usage,
        )
    }
    #[test]
    fn creation_time_preserves_observed_precision_and_missing_identity() {
        let elapsed = Duration::new(123, 456);
        let time = SystemTime::UNIX_EPOCH.checked_add(elapsed).unwrap();
        let captured = time.duration_since(SystemTime::UNIX_EPOCH).unwrap();
        // Serialize actual host observation: Windows SystemTime stores 100ns
        // ticks, so constructing 456ns captures 400ns rather than inventing 56ns.
        #[cfg(windows)]
        assert_eq!(captured.subsec_nanos(), elapsed.subsec_nanos() / 100 * 100);
        #[cfg(unix)]
        assert_eq!(captured, elapsed);
        let observed = creation_time_value(Some(time));
        assert_eq!(observed["unixSeconds"], captured.as_secs());
        assert_eq!(observed["nanoseconds"], captured.subsec_nanos());
        assert!(observed["source"].is_string());
        assert_eq!(creation_time_value(None), Value::Null);
        let (mut observation, _) = empty();
        assert_eq!(
            observation_value(&observation)["processCreationTime"],
            Value::Null
        );
        assert_eq!(
            observation_value(&observation)["processCreationTicks"],
            Value::Null
        );
        observation.process_creation_time = Some(time);
        assert_eq!(
            observation_value(&observation)["processCreationTime"],
            observed
        );
    }
    #[test]
    fn native_stream_preserves_missing_usage_instead_of_zero() {
        let (mut observation, mut usage) = empty();
        let fixture = concat!(
            r#"{"type":"system","subtype":"init","session_id":"fresh","tools":[]}"#,
            "\n",
            r#"{"type":"result","subtype":"success","is_error":false,"structured_output":{"finalResult":{"complete":true}},"usage":{"input_tokens":7,"output_tokens":3}}"#
        );
        decode_stream(fixture.as_bytes(), &mut observation, &mut usage).unwrap();
        assert_eq!(usage.input_tokens, None);
        assert_eq!(usage.output_tokens, Some(3));
        assert_eq!(usage.cached_input_tokens, None);
        assert_eq!(usage.retry_tokens, None);
        assert_eq!(observation.raw_usage.unwrap()["input_tokens"], 7);
    }
    #[test]
    fn native_refusal_retains_observed_provider_usage() {
        let (mut observation, mut usage) = empty();
        let fixture = r#"{"type":"result","subtype":"error_during_execution","is_error":true,"total_cost_usd":0.1234567890123456789,"usage":{"input_tokens":7,"cache_read_input_tokens":2,"cache_creation_input_tokens":1,"output_tokens":3}}"#;
        assert!(decode_stream(fixture.as_bytes(), &mut observation, &mut usage).is_err());
        assert_eq!(usage.input_tokens, Some(10));
        assert_eq!(usage.output_tokens, Some(3));
        assert_eq!(
            observation.reported_api_cost_usd.as_deref(),
            Some("0.1234567890123456789")
        );
        assert!(usage.failed);
    }
    #[test]
    fn model_policy_finalization_survives_refusal_and_malformed_output() {
        let execution = super::super::model::verifier(&RuntimeOptions::default()).unwrap();
        for (terminal, suffix) in [(true, ""), (false, "\nmalformed")] {
            let (mut observation, mut usage) = empty();
            let fixture = format!(
                "{}\n{}{suffix}",
                json!({"type":"system","subtype":"init","session_id":"fresh","model":"claude-opus-5","tools":[]}),
                json!({"type":"result","is_error":terminal,"modelUsage":{"claude-opus-5":{}},"total_cost_usd":0.125,"usage":{"input_tokens":7,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"output_tokens":3}})
            );
            observation.error =
                decode_stream(fixture.as_bytes(), &mut observation, &mut usage).err();
            let original_error = observation.error.clone();
            assert!(original_error.is_some());
            finalize_model_policy(&mut observation, &mut usage, &execution);
            assert_eq!(observation.error, original_error);
            assert_eq!(
                observation.model_policy_violation,
                Some(ModelPolicyViolation::UnauthorizedModel)
            );
            assert_eq!(observation.reported_api_cost_usd.as_deref(), Some("0.125"));
            assert_eq!(usage.input_tokens, Some(7));
            assert_eq!(usage.output_tokens, Some(3));
            assert!(usage.failed);
        }
    }
    #[test]
    fn started_native_process_requires_model_observation_for_every_outcome() {
        let execution = super::super::model::verifier(&RuntimeOptions::default()).unwrap();
        let (mut observation, mut usage) = empty();
        observation.error = Some("native process failed".into());
        finalize_model_policy(&mut observation, &mut usage, &execution);
        assert_eq!(
            observation.model_policy_violation,
            Some(ModelPolicyViolation::MissingObservation)
        );
        assert_eq!(observation.error.as_deref(), Some("native process failed"));
        observation.process_id = 0;
        finalize_model_policy(&mut observation, &mut usage, &execution);
        assert_eq!(observation.model_policy_violation, None);
        observation.process_id = 1;
        observation.observed_models = vec![execution.model.clone()];
        finalize_model_policy(&mut observation, &mut usage, &execution);
        assert_eq!(observation.model_policy_violation, None);
    }
    #[test]
    fn unexpected_native_tool_exposure_is_rejected() {
        let (mut observation, mut usage) = empty();
        let fixture = concat!(
            r#"{"type":"system","subtype":"init","session_id":"fresh","tools":["Bash"]}"#,
            "\n",
            r#"{"type":"result","subtype":"success","is_error":false,"structured_output":{"finalResult":{}}}"#
        );
        assert!(decode_stream(fixture.as_bytes(), &mut observation, &mut usage).is_err());
    }
    #[test]
    fn native_accounting_survives_later_malformed_protocol_data() {
        let (mut observation, mut usage) = empty();
        let fixture = concat!(
            r#"{"type":"result","is_error":false,"total_cost_usd":0.125,"usage":{"input_tokens":7,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"output_tokens":3}}"#,
            "\nmalformed"
        );
        assert!(decode_stream(fixture.as_bytes(), &mut observation, &mut usage).is_err());
        assert_eq!(observation.reported_api_cost_usd.as_deref(), Some("0.125"));
        assert_eq!(usage.input_tokens, Some(7));
        assert_eq!(usage.output_tokens, Some(3));
    }
    #[test]
    fn data_only_native_structured_output_is_allowed_but_bash_is_not() {
        let (mut observation, mut usage) = empty();
        let fixture = concat!(
            r#"{"type":"system","subtype":"init","session_id":"fresh","tools":["StructuredOutput"]}"#,
            "\n",
            r#"{"type":"assistant","message":{"content":[{"type":"tool_use","name":"StructuredOutput","id":"one","input":{"finalResult":{}}}]}}"#,
            "\n",
            r#"{"type":"result","is_error":false,"structured_output":{"finalResult":{}},"usage":{"input_tokens":7,"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"output_tokens":3}}"#
        );
        decode_stream(fixture.as_bytes(), &mut observation, &mut usage).unwrap();
        assert_eq!(usage.retry_tokens, Some(0));
        validate_schema(
            observation.reply.as_ref().unwrap(),
            &super::super::action_schema(),
            0,
        )
        .unwrap();
        let (mut observation, mut usage) = empty();
        assert!(decode_stream(
            fixture
                .replace("\"name\":\"StructuredOutput\"", "\"name\":\"Bash\"")
                .as_bytes(),
            &mut observation,
            &mut usage
        )
        .is_err());
        assert!(validate_schema(
            &json!({"finalResult":{},"shell":"x"}),
            &super::super::action_schema(),
            0
        )
        .is_err());
    }
}
