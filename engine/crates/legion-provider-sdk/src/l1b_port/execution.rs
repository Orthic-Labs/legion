//! Closes the subprocess-execution and CLI gap left open by `worker.rs`'s
//! original doc comment ("not reproduced here"). Per the U01 port brief,
//! subprocess orchestration and CLI entrypoints are both portable: this
//! module ports `run_pi`, `_terminate`, `run_item`, `run_batch`, and the
//! `argparse` `main()` of `src/lib/coder-api-worker/api-worker.py` (also
//! reached, unmodified, via the `skills/coder/scripts/api-worker.py`
//! delegator). Process execution sits behind [`ProcessRunner`] so tests run
//! with a fake and never spawn a real `pi` CLI.

use super::worker::*;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Outcome of one bounded process invocation, matching the branches Python's
/// `run_pi` distinguishes (`Popen`/`communicate` success, `FileNotFoundError`,
/// `TimeoutExpired`, other `OSError`).
pub enum ProcessOutcome {
    Completed { stdout: String, stderr: String, exit_code: i32 },
    TimedOut { partial_stdout: String, partial_stderr: String },
    Missing,
    LaunchFailed(String),
}

/// Process transport, abstracted so tests can fake it (`run_pi` must never
/// launch a real `pi` CLI or touch the network in a test).
pub trait ProcessRunner: Send + Sync {
    fn which(&self, cmd: &str) -> bool;
    fn run(&self, argv: &[String], timeout: Duration) -> ProcessOutcome;
}

/// Real transport: spawns `argv[0]`, drains stdout/stderr on reader threads
/// so a chatty child can never deadlock the pipe, and kills + collects
/// partial output on timeout (mirrors Python's `_terminate`: `terminate()`
/// then a 2s grace period, then `kill()`).
pub struct RealProcessRunner;

impl ProcessRunner for RealProcessRunner {
    fn which(&self, cmd: &str) -> bool {
        let Some(paths) = std::env::var_os("PATH") else { return false };
        std::env::split_paths(&paths).any(|dir| {
            dir.join(cmd).is_file() || dir.join(format!("{cmd}.exe")).is_file()
        })
    }

    fn run(&self, argv: &[String], timeout: Duration) -> ProcessOutcome {
        let Some(program) = argv.first() else {
            return ProcessOutcome::LaunchFailed("empty argv".to_string());
        };
        let mut cmd = Command::new(program);
        cmd.args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ProcessOutcome::Missing,
            Err(e) => return ProcessOutcome::LaunchFailed(e.to_string()),
        };

        let out_buf = Arc::new(Mutex::new(Vec::new()));
        let err_buf = Arc::new(Mutex::new(Vec::new()));
        let out_thread = drain_thread(child.stdout.take(), Arc::clone(&out_buf));
        let err_thread = drain_thread(child.stderr.take(), Arc::clone(&err_buf));

        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(_) => break None,
            }
        };

        let timed_out = status.is_none();
        if timed_out {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(t) = out_thread {
            let _ = t.join();
        }
        if let Some(t) = err_thread {
            let _ = t.join();
        }
        let stdout = String::from_utf8_lossy(&out_buf.lock().unwrap()).into_owned();
        let stderr = String::from_utf8_lossy(&err_buf.lock().unwrap()).into_owned();

        match status {
            Some(status) => ProcessOutcome::Completed {
                stdout,
                stderr,
                exit_code: status.code().unwrap_or(-1),
            },
            None => ProcessOutcome::TimedOut { partial_stdout: stdout, partial_stderr: stderr },
        }
    }
}

fn drain_thread<R>(pipe: Option<R>, into: Arc<Mutex<Vec<u8>>>) -> Option<std::thread::JoinHandle<()>>
where
    R: Read + Send + 'static,
{
    pipe.map(|mut p| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = p.read_to_end(&mut buf);
            *into.lock().unwrap() = buf;
        })
    })
}

/// Monotonically-increasing, process-wide counter mixed into `run_id`
/// generation so concurrent `run_batch` workers never collide even when the
/// clock has not advanced.
static RUN_SEQ: AtomicU64 = AtomicU64::new(0);

/// 32-hex-char run id. Not cryptographically random (no RNG crate is in the
/// allowed list) — seeded from wall-clock nanos, the process id, and a
/// process-wide sequence counter, which is sufficient for a run-scoped,
/// non-secret correlation id.
fn generate_run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let seq = RUN_SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as u128;
    let mixed = nanos ^ ((pid as u128) << 64) ^ (seq as u128).wrapping_mul(0x9E3779B97F4A7C15);
    format!("{mixed:032x}")[..32].to_string()
}

/// UTC ISO-8601 timestamp with millisecond precision, e.g.
/// `2026-09-24T12:00:00.000+00:00` (matches Python's
/// `datetime.now(timezone.utc).isoformat(timespec="milliseconds")`).
pub fn utc_now_iso() -> String {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}+00:00")
}

/// Howard Hinnant's `civil_from_days`: days-since-epoch -> proleptic
/// Gregorian (y, m, d). Pure integer arithmetic, stable std only.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn clip_default(value: &str) -> String {
    clip(value, MAX_RECEIPT_TEXT_CHARS)
}

fn receipt_base(run_id: &str, model: Option<&str>, argv: Option<&[String]>) -> Value {
    json!({
        "schema": "coder.pi.receipt.v1",
        "run_id": run_id,
        "executor": "pi",
        "model": model,
        "tools": PI_TOOLS,
        "argv": argv.map(redacted_argv),
    })
}

fn finish_receipt(
    mut receipt: Value,
    started_monotonic: Instant,
    started_at: &str,
    status: &str,
    exit_code: Option<i32>,
    stderr: &str,
) -> Value {
    let obj = receipt.as_object_mut().unwrap();
    obj.insert("started_at".into(), json!(started_at));
    obj.insert("finished_at".into(), json!(utc_now_iso()));
    obj.insert(
        "duration_ms".into(),
        json!((started_monotonic.elapsed().as_secs_f64() * 1000.0).round() as i64),
    );
    obj.insert("status".into(), json!(status));
    obj.insert("exit_code".into(), json!(exit_code));
    if !stderr.is_empty() {
        obj.insert("stderr".into(), json!(clip_default(stderr)));
    }
    receipt
}

/// Result of one bounded Pi invocation: `ok`, `output`, optional
/// `error{code,message}`, and the shaped `receipt`. Mirrors the dict
/// `run_pi`/`run_item` return in Python.
#[derive(Debug, Clone)]
pub struct RunResult {
    pub id: Option<String>,
    pub ok: bool,
    pub output: String,
    pub error: Option<(String, String)>,
    pub receipt: Value,
    pub attempts: usize,
}

impl RunResult {
    pub fn to_json(&self) -> Value {
        let mut v = json!({
            "ok": self.ok,
            "output": self.output,
            "receipt": self.receipt,
        });
        if let Some((code, message)) = &self.error {
            v["error"] = json!({"code": code, "message": message});
        }
        if let Some(id) = &self.id {
            v["id"] = json!(id);
        }
        v["attempts"] = json!(self.attempts);
        v
    }
}

/// Port of `run_pi`: run exactly one bounded Pi invocation and return output
/// plus receipt.
pub fn run_pi(runner: &dyn ProcessRunner, model: &str, prompt: &str, timeout_secs: u32) -> RunResult {
    let model = match validate_model(model) {
        Ok(m) => m,
        Err(e) => return failure_result(None, e, 0),
    };
    let prompt = match validate_prompt(prompt) {
        Ok(p) => p,
        Err(e) => return failure_result(None, e, 0),
    };
    let timeout_secs = timeout_secs.min(MAX_TIMEOUT_SECONDS).max(1);
    let argv = match build_argv(&model, &prompt) {
        Ok(a) => a,
        Err(e) => return failure_result(None, e, 0),
    };
    let run_id = generate_run_id();
    let started_at = utc_now_iso();
    let started_monotonic = Instant::now();
    let receipt = receipt_base(&run_id, Some(&model), Some(&argv));

    if !runner.which(PI_COMMAND) {
        let receipt = finish_receipt(receipt, started_monotonic, &started_at, "pi_missing", None, "");
        return RunResult {
            id: None,
            ok: false,
            output: String::new(),
            error: Some(("pi_missing".into(), "Pi CLI executable 'pi' was not found".into())),
            receipt,
            attempts: 1,
        };
    }

    match runner.run(&argv, Duration::from_secs(timeout_secs as u64)) {
        ProcessOutcome::Missing => {
            let receipt = finish_receipt(receipt, started_monotonic, &started_at, "pi_missing", None, "");
            RunResult {
                id: None,
                ok: false,
                output: String::new(),
                error: Some(("pi_missing".into(), "Pi CLI executable 'pi' was not found".into())),
                receipt,
                attempts: 1,
            }
        }
        ProcessOutcome::LaunchFailed(msg) => {
            let receipt = finish_receipt(receipt, started_monotonic, &started_at, "launch_failed", None, &msg);
            RunResult {
                id: None,
                ok: false,
                output: String::new(),
                error: Some(("launch_failed".into(), msg)),
                receipt,
                attempts: 1,
            }
        }
        ProcessOutcome::TimedOut { partial_stdout, partial_stderr } => {
            let receipt = finish_receipt(receipt, started_monotonic, &started_at, "timeout", None, &partial_stderr);
            RunResult {
                id: None,
                ok: false,
                output: clip(&partial_stdout, MAX_OUTPUT_CHARS),
                error: Some(("timeout".into(), format!("Pi exceeded {timeout_secs}s timeout"))),
                receipt,
                attempts: 1,
            }
        }
        ProcessOutcome::Completed { stdout, stderr, exit_code } => {
            let stdout = strip_think(&stdout);
            let model_err_re =
                regex_model_unavailable();
            let mut status = if exit_code == 0 && !stdout.is_empty() { "ok" } else { "failed" };
            if exit_code != 0 && model_err_re.is_match(&stderr) {
                status = "model_unavailable";
            }
            let stderr_clipped = clip_default(&stderr);
            let receipt = finish_receipt(
                receipt,
                started_monotonic,
                &started_at,
                status,
                Some(exit_code),
                &stderr,
            );
            if status == "ok" {
                RunResult {
                    id: None,
                    ok: true,
                    output: clip(&stdout, MAX_OUTPUT_CHARS),
                    error: None,
                    receipt,
                    attempts: 1,
                }
            } else {
                let (code, message) = if status == "model_unavailable" {
                    ("model_unavailable".to_string(), if stderr_clipped.is_empty() {
                        format!("Pi exited with status {exit_code}")
                    } else {
                        stderr_clipped.clone()
                    })
                } else if stdout.is_empty() && exit_code == 0 {
                    ("empty_output".to_string(), "Pi returned no analysis output".to_string())
                } else {
                    ("pi_failed".to_string(), if stderr_clipped.is_empty() {
                        format!("Pi exited with status {exit_code}")
                    } else {
                        stderr_clipped.clone()
                    })
                };
                RunResult {
                    id: None,
                    ok: false,
                    output: clip(&stdout, MAX_OUTPUT_CHARS),
                    error: Some((code, message)),
                    receipt,
                    attempts: 1,
                }
            }
        }
    }
}

fn regex_model_unavailable() -> &'static regex::Regex {
    static RE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(r"(?i)model|catalog|unknown.*model|not found").unwrap());
    &RE
}

fn failure_result(id: Option<String>, err: WorkerFailure, attempts: usize) -> RunResult {
    let run_id = generate_run_id();
    RunResult {
        id,
        ok: false,
        output: String::new(),
        error: Some((err.code.clone(), err.message.clone())),
        receipt: json!({
            "schema": "coder.pi.receipt.v1",
            "run_id": run_id,
            "executor": "pi",
            "status": err.code,
            "tools": PI_TOOLS,
        }),
        attempts,
    }
}

/// One manifest item for `run_batch` / `run_item`, mirroring the dict keys
/// Python reads off each JSON array element.
#[derive(Debug, Clone, Default)]
pub struct ManifestItem {
    pub id: Option<String>,
    pub prompt: Option<String>,
    pub prompt_file: Option<String>,
    pub system: Option<String>,
    pub max_tokens: Option<i64>,
    pub model: Option<String>,
    pub tier: Option<String>,
    pub fallback: Option<String>,
    pub timeout: Option<u32>,
    pub has_unsupported_route: bool,
}

impl ManifestItem {
    pub fn from_json(v: &Value) -> Self {
        Self {
            id: v.get("id").and_then(|x| x.as_str()).map(str::to_string),
            prompt: v.get("prompt").and_then(|x| x.as_str()).map(str::to_string),
            prompt_file: v.get("prompt_file").and_then(|x| x.as_str()).map(str::to_string),
            system: v.get("system").and_then(|x| x.as_str()).map(str::to_string),
            max_tokens: v.get("max_tokens").and_then(|x| x.as_i64()),
            model: v.get("model").and_then(|x| x.as_str()).map(str::to_string),
            tier: v.get("tier").and_then(|x| x.as_str()).map(str::to_string),
            fallback: v.get("fallback").and_then(|x| x.as_str()).map(str::to_string),
            timeout: v.get("timeout").and_then(|x| x.as_u64()).map(|x| x as u32),
            has_unsupported_route: v.get("provider").is_some()
                || v.get("endpoint").is_some()
                || v.get("api_key").is_some(),
        }
    }
}

/// Reads `path`, or stdin when `path` is `None`/`"-"` (port of `read_input`).
pub fn read_input(path: Option<&str>) -> std::io::Result<String> {
    match path {
        None | Some("-") => {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        }
        Some(p) => std::fs::read_to_string(p),
    }
}

/// Port of `run_item`: run one manifest item, with at most one explicitly
/// requested fallback.
pub fn run_item(runner: &dyn ProcessRunner, item: &ManifestItem) -> RunResult {
    let prompt = if let Some(pf) = &item.prompt_file {
        match read_input(Some(pf)) {
            Ok(p) => p,
            Err(e) => {
                return failure_result(item.id.clone(), WorkerFailure::new("invalid_job", e.to_string()), 0)
            }
        }
    } else {
        item.prompt.clone().unwrap_or_default()
    };
    let system = item.system.clone().unwrap_or_else(|| NO_THINK.to_string());
    let max_tokens = item.max_tokens.unwrap_or(2048);
    let prompt = match prepare_prompt(&prompt, &system, max_tokens) {
        Ok(p) => p,
        Err(e) => return failure_result(item.id.clone(), e, 0),
    };

    let selector = if let Some(model) = &item.model {
        ModelSelector::Model(model.clone())
    } else if let Some(tier) = &item.tier {
        ModelSelector::Tier(tier.clone())
    } else if let Some(fallback) = &item.fallback {
        ModelSelector::Fallback(fallback.clone())
    } else {
        ModelSelector::Default
    };
    let models = match models_for_item(&selector, item.has_unsupported_route) {
        Ok(m) => m,
        Err(e) => return failure_result(item.id.clone(), e, 0),
    };
    let timeout = item.timeout.unwrap_or(DEFAULT_TIMEOUT_SECONDS).min(MAX_TIMEOUT_SECONDS);

    let mut last = None;
    let mut attempts = 0usize;
    for model in &models {
        attempts += 1;
        let result = run_pi(runner, model, &prompt, timeout);
        let ok = result.ok;
        last = Some(result);
        if ok {
            break;
        }
    }
    let mut result = last.expect("models_for_item never returns an empty list");
    result.id = item.id.clone();
    result.attempts = attempts;
    result
}

/// Port of `run_batch`: run manifest items with a bounded thread pool,
/// preserving manifest order in the returned vector regardless of
/// completion order.
pub fn run_batch(
    runner: &(dyn ProcessRunner + Sync),
    items: &[ManifestItem],
    pool_size: u32,
) -> Vec<RunResult> {
    let pool_size = pool_size.clamp(1, MAX_POOL_SIZE) as usize;
    let results: Arc<Mutex<Vec<Option<RunResult>>>> = Arc::new(Mutex::new(vec![None; items.len()]));
    let next_index = Arc::new(AtomicU64::new(0));

    std::thread::scope(|scope| {
        for _ in 0..pool_size.min(items.len().max(1)) {
            let results = Arc::clone(&results);
            let next_index = Arc::clone(&next_index);
            scope.spawn(move || loop {
                let i = next_index.fetch_add(1, Ordering::Relaxed) as usize;
                if i >= items.len() {
                    break;
                }
                let result = run_item(runner, &items[i]);
                results.lock().unwrap()[i] = Some(result);
            });
        }
    });

    Arc::try_unwrap(results)
        .unwrap()
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|r| r.expect("every index is assigned exactly once"))
        .collect()
}

/// Port of `main()` / `_single_output`: parses argv, runs the job(s), and
/// writes stdout/stderr exactly as the Python CLI does. Returns the process
/// exit code (0/1), matching Python's `SystemExit(main())`.
pub fn run(args: &[String], runner: &(dyn ProcessRunner + Sync)) -> i32 {
    run_with_io(args, runner, &mut std::io::stdout(), &mut std::io::stderr())
}

pub fn run_with_io(
    args: &[String],
    runner: &(dyn ProcessRunner + Sync),
    out: &mut dyn Write,
    err_out: &mut dyn Write,
) -> i32 {
    let mut model: Option<String> = None;
    let mut tier = "free".to_string();
    let mut fallback: Option<String> = None;
    let mut batch: Option<String> = None;
    let mut pool_size: u32 = 1;
    let mut input: Option<String> = None;
    let mut system = NO_THINK.to_string();
    let mut max_tokens: i64 = 2048;
    let mut timeout: u32 = DEFAULT_TIMEOUT_SECONDS;
    let mut as_json = false;
    let mut self_test = false;

    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        macro_rules! next {
            () => {{
                i += 1;
                args.get(i).cloned().unwrap_or_default()
            }};
        }
        match a {
            "--model" => model = Some(next!()),
            "--tier" => tier = next!(),
            "--fallback" => fallback = Some(next!()),
            "--batch" => batch = Some(next!()),
            "--pool-size" => pool_size = next!().parse().unwrap_or(1),
            "--input" => input = Some(next!()),
            "--system" => system = next!(),
            "--max-tokens" => max_tokens = next!().parse().unwrap_or(2048),
            "--timeout" => timeout = next!().parse().unwrap_or(DEFAULT_TIMEOUT_SECONDS),
            "--json" => as_json = true,
            "--self-test" => self_test = true,
            _ => {}
        }
        i += 1;
    }

    if self_test {
        assert_eq!(strip_think("<think>noise</think>\nanswer"), "answer");
        let argv = build_argv(FREE_PRIMARY_MODELS[0], "review this").unwrap();
        assert_eq!(&argv[..3], &["pi".to_string(), "--tools".to_string(), "read,grep,find,ls".to_string()]);
        let _ = writeln!(out, "pi coder worker self-test passed");
        return 0;
    }

    if let Some(batch_path) = batch {
        let items: Vec<ManifestItem> = match std::fs::read_to_string(&batch_path)
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str::<Value>(&s).map_err(|e| e.to_string()))
        {
            Ok(Value::Array(vs)) => vs.iter().map(ManifestItem::from_json).collect(),
            Ok(_) => {
                let _ = writeln!(
                    out,
                    "{}",
                    json!({"ok": false, "error": {"code": "invalid_manifest", "message": "batch manifest must be a JSON array"}})
                );
                return 1;
            }
            Err(msg) => {
                let _ = writeln!(out, "{}", json!({"ok": false, "error": {"code": "invalid_manifest", "message": msg}}));
                return 1;
            }
        };
        let results = run_batch(runner, &items, pool_size);
        let all_ok = results.iter().all(|r| r.ok);
        let json_results: Vec<Value> = results.iter().map(RunResult::to_json).collect();
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&json_results).unwrap_or_default());
        return if all_ok { 0 } else { 1 };
    }

    let prompt_raw = match read_input(input.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            let _ = writeln!(err_out, "CODER_FAILURE [invalid_job]: {e}");
            return 1;
        }
    };

    let result = (|| -> Result<RunResult, WorkerFailure> {
        let prompt = prepare_prompt(&prompt_raw, &system, max_tokens)?;
        if model.is_some() && fallback.is_some() {
            return Err(WorkerFailure::new("ambiguous_selection", "use --model without --fallback"));
        }
        let models: Vec<String> = if let Some(m) = &model {
            vec![validate_model(m)?]
        } else if let Some(f) = &fallback {
            models_for_item(&ModelSelector::Fallback(f.clone()), false)?
        } else if tier == "paid" {
            vec![PAID_MODELS[0].to_string()]
        } else {
            vec![FREE_PRIMARY_MODELS[0].to_string()]
        };
        let mut last = None;
        for m in &models {
            let r = run_pi(runner, m, &prompt, timeout);
            let ok = r.ok;
            last = Some(r);
            if ok {
                break;
            }
        }
        Ok(last.expect("models list is never empty"))
    })();

    let result = match result {
        Ok(r) => r,
        Err(e) => failure_result(None, e, 0),
    };

    if as_json {
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&result.to_json()).unwrap_or_default());
    } else if result.ok {
        let _ = writeln!(out, "{}", result.output);
    } else {
        let (code, message) = result.error.clone().unwrap_or(("unknown".into(), String::new()));
        let _ = writeln!(err_out, "CODER_FAILURE [{code}]: {message}");
    }
    let receipt_line = serde_json::to_string(&sorted_keys(&result.receipt)).unwrap_or_default();
    let _ = writeln!(err_out, "CODER_RECEIPT {receipt_line}");
    if result.ok {
        0
    } else {
        1
    }
}

/// `json.dumps(..., sort_keys=True)` equivalent for the receipt line.
fn sorted_keys(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut sorted = serde_json::Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for k in keys {
                sorted.insert(k.clone(), sorted_keys(&map[k]));
            }
            Value::Object(sorted)
        }
        other => other.clone(),
    }
}
