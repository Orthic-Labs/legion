//! Bounded, read-only analysis for Apple diagnostic artifacts.
//!
//! Operations consume an explicit path and return deterministic aggregates.
//! Text analysis is pure; binary memgraph capture uses explicit, bounded,
//! typed `/usr/bin/leaks` argv only when `execute: true` is supplied. The
//! accepted formats intentionally mirror useful portions of bundled iOS review
//! helpers without claiming parser parity with those tools.

use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Command;
use tokio::time;

const MAX_INPUT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_NODES: usize = 200_000;
const MAX_ROWS: usize = 1_000;
const MAX_DEPTH: usize = 2_048;
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_OUTPUT_BYTES: usize = 16 * 1024 * 1024;

const IDLE_FRAMES: &[&str] = &[
    "mach_msg_trap", "__psynch_cvwait", "semaphore_wait_trap", "kevent_id",
    "__ulock_wait", "__workq_kernreturn", "__semwait_signal", "nanosleep", "poll",
    "select", "start_wqthread",
];
const WRAPPER_FRAMES: &[&str] = &[
    "start", "main", "libsystem_kernel.dylib", "UIApplicationMain", "-[UIApplication _run]",
    "GSEventRunModal", "_CFRunLoopRunSpecificWithOptions", "__CFRunLoopRun",
    "__CFRunLoopDoSource0", "__CFRunLoopDoSource1", "__CFRunLoopServiceMachPort",
    "__CFMachPortPerform", "__CFRUNLOOP_IS_CALLING_OUT_TO_A_SOURCE0_PERFORM_FUNCTION__",
    "__CFRUNLOOP_IS_CALLING_OUT_TO_A_SOURCE1_PERFORM_FUNCTION__",
    "__CFRunLoop_IS_SERVICING_THE_MAIN_DISPATCH_QUEUE__", "__CFRunLoop_IS_CALLING_OUT_TO_A_TIMER_CALLBACK_FUNCTION__",
    "_dispatch_client_callout",
    "_dispatch_main_queue_callback_4CF", "_dispatch_main_queue_drain",
];

/// Invoke one diagnostic operation: `flamegraph`, `memgraph.parse`,
/// `memgraph`, or `build-log`. Arguments must contain explicit `path` (or
/// `inputPath`). `memgraph` requires `execute: true` before it runs `/usr/bin/leaks`.
pub async fn invoke(operation: &str, arguments: &Value) -> Result<Value, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;
    match operation.to_ascii_lowercase().as_str() {
        "memgraph" | "memgraph-leaks" => capture_memgraph(object).await,
        "memgraph.parse" | "memgraph-text" => {
            let path = input_path(object)?;
            let text = read_bounded_text(&path)?;
            summarize_memgraph(&path, &text)
        }
        "flamegraph" | "flamegraph-json" | "build-log" | "build_log" => {
            let path = input_path(object)?;
            let text = read_bounded_text(&path)?;
            match operation.to_ascii_lowercase().as_str() {
                "flamegraph" | "flamegraph-json" => summarize_flamegraph(&path, &text, object),
                "build-log" | "build_log" => summarize_build_log(&path, &text, object),
                _ => unreachable!(),
            }
        }
        other => Err(format!("unknown diagnostic operation: {other}")),
    }
}

fn input_path(object: &Map<String, Value>) -> Result<std::path::PathBuf, String> {
    let value = object
        .get("path")
        .or_else(|| object.get("inputPath"))
        .ok_or_else(|| "diagnostic input requires explicit path".to_string())?;
    let path = value
        .as_str()
        .ok_or_else(|| "diagnostic path must be a string".to_string())?;
    if path.is_empty() {
        return Err("diagnostic path must not be empty".to_string());
    }
    Ok(std::path::PathBuf::from(path))
}

fn read_bounded_text(path: &Path) -> Result<String, String> {
    let metadata = fs::metadata(path).map_err(|error| format!("cannot inspect diagnostic input: {error}"))?;
    if !metadata.is_file() {
        return Err("diagnostic input must be a regular file".to_string());
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(format!("diagnostic input exceeds {MAX_INPUT_BYTES} bytes"));
    }
    let bytes = fs::read(path).map_err(|error| format!("cannot read diagnostic input: {error}"))?;
    String::from_utf8(bytes).map_err(|_| "diagnostic input must be UTF-8".to_string())
}

async fn capture_memgraph(object: &Map<String, Value>) -> Result<Value, String> {
    if object.get("execute").and_then(Value::as_bool) != Some(true) {
        return Err("memgraph capture requires execute=true; use memgraph.parse for text".to_string());
    }
    if !cfg!(target_os = "macos") {
        return Err("memgraph capture requires macOS leaks tool".to_string());
    }
    let path = input_path(object)?;
    let metadata = fs::metadata(&path).map_err(|error| format!("cannot inspect memgraph input: {error}"))?;
    if !metadata.is_file() {
        return Err("memgraph input must be a regular file".to_string());
    }
    if metadata.len() > 512 * 1024 * 1024 {
        return Err("memgraph input exceeds 512 MiB bound".to_string());
    }
    let timeout = bounded_timeout(object)?;
    let output_limit = bounded_output(object)?;
    let path_text = path.to_string_lossy().into_owned();
    let list = run_tool(
        &["--list".to_string(), path_text.clone()],
        timeout,
        output_limit,
    )
    .await?;
    if list.timed_out {
        return Err("leaks --list timed out".to_string());
    }
    let raw = if list.stdout.is_empty() { list.stderr.clone() } else { list.stdout.clone() };
    let mut result = summarize_memgraph(&path, &raw)?;
    if let Some(map) = result.as_object_mut() {
        map.insert("source".to_string(), json!("/usr/bin/leaks --list"));
        map.insert("exitStatus".to_string(), list.status.map(Value::from).unwrap_or(Value::Null));
        map.insert("outputTruncated".to_string(), json!(list.truncated));
    }
    let include_trace = object.get("includeTrace").map_or(Ok(false), value_bool_named("includeTrace"))?;
    let include_grouped = object.get("includeGrouped").map_or(Ok(false), value_bool_named("includeGrouped"))?;
    if include_trace {
        let trace_limit = bounded_count(object, "traceLimit", 5, 50)?;
        let trace_lines = bounded_count(object, "traceLines", 80, 500)?;
        let entries = result
            .get("entries")
            .and_then(Value::as_array)
            .ok_or_else(|| "memgraph parser returned invalid entries".to_string())?;
        let mut traces = Vec::new();
        for entry in entries.iter().take(trace_limit) {
            let address = entry.get("address").and_then(Value::as_str).unwrap_or("");
            let trace = run_tool(
                &[format!("--traceTree={address}"), path_text.clone()],
                timeout,
                output_limit,
            )
            .await?;
            let raw_trace = if trace.stdout.is_empty() { trace.stderr } else { trace.stdout };
            traces.push(json!({
                "address": address,
                "type": entry.get("type").cloned().unwrap_or(Value::Null),
                "text": excerpt_lines(&raw_trace, trace_lines),
                "exitStatus": trace.status.map(Value::from).unwrap_or(Value::Null),
                "available": trace.status == Some(0) && !raw_trace.trim().is_empty(),
                "truncated": trace.truncated
            }));
        }
        if let Some(map) = result.as_object_mut() {
            let available = traces.iter().any(|trace| trace.get("available") == Some(&Value::Bool(true)));
            map.insert("traceTree".to_string(), Value::Array(traces));
            map.insert("traceRequested".to_string(), Value::Bool(true));
            map.insert("traceAvailable".to_string(), Value::Bool(available));
        }
    }
    if include_grouped {
        let grouped = run_tool(
            &["--groupByType".to_string(), path_text],
            timeout,
            output_limit,
        )
        .await?;
        let raw_grouped = if grouped.stdout.is_empty() { grouped.stderr } else { grouped.stdout };
        if let Some(map) = result.as_object_mut() {
            map.insert("groupedLeakTree".to_string(), json!({
                "text": excerpt_lines(&raw_grouped, bounded_count(object, "groupedLines", 80, 500)?),
                "exitStatus": grouped.status.map(Value::from).unwrap_or(Value::Null),
                "available": grouped.status == Some(0) && !raw_grouped.trim().is_empty(),
                "truncated": grouped.truncated
            }));
            map.insert("groupedLeakTreeRequested".to_string(), Value::Bool(true));
            map.insert("groupedLeakTreeAvailable".to_string(), Value::Bool(grouped.status == Some(0) && !raw_grouped.trim().is_empty()));
        }
    }
    Ok(result)
}

fn bounded_timeout(object: &Map<String, Value>) -> Result<Duration, String> {
    let value = match object.get("timeoutMs") {
        None => DEFAULT_TIMEOUT_MS,
        Some(value) => value.as_u64().ok_or_else(|| "timeoutMs must be a non-negative integer".to_string())?,
    };
    if value == 0 || value > MAX_TIMEOUT_MS {
        return Err(format!("timeoutMs must be between 1 and {MAX_TIMEOUT_MS}"));
    }
    Ok(Duration::from_millis(value))
}

fn bounded_output(object: &Map<String, Value>) -> Result<usize, String> {
    let value = match object.get("maxOutputBytes") {
        None => DEFAULT_OUTPUT_BYTES,
        Some(value) => value.as_u64().ok_or_else(|| "maxOutputBytes must be a non-negative integer".to_string())? as usize,
    };
    if value == 0 || value > MAX_OUTPUT_BYTES {
        return Err(format!("maxOutputBytes must be between 1 and {MAX_OUTPUT_BYTES}"));
    }
    Ok(value)
}

fn bounded_count(object: &Map<String, Value>, key: &str, default: usize, max: usize) -> Result<usize, String> {
    let value = match object.get(key) {
        None => default as u64,
        Some(value) => value.as_u64().ok_or_else(|| format!("{key} must be a non-negative integer"))?,
    };
    if value == 0 || value > max as u64 {
        return Err(format!("{key} must be between 1 and {max}"));
    }
    Ok(value as usize)
}

fn value_bool_named<'a>(name: &'a str) -> impl Fn(&Value) -> Result<bool, String> + 'a {
    move |value| value.as_bool().ok_or_else(|| format!("{name} must be a boolean"))
}

fn excerpt_lines(text: &str, limit: usize) -> String {
    text.lines().filter(|line| !line.trim().is_empty()).take(limit).map(str::trim_end).collect::<Vec<_>>().join("\n")
}

struct ToolOutput {
    status: Option<i32>,
    stdout: String,
    stderr: String,
    timed_out: bool,
    truncated: bool,
}

async fn run_tool(arguments: &[String], timeout: Duration, max_output: usize) -> Result<ToolOutput, String> {
    let mut command = Command::new("/usr/bin/leaks");
    command.args(arguments).stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = command.spawn().map_err(|error| format!("failed to start /usr/bin/leaks: {error}"))?;
    let mut stdout = child.stdout.take().ok_or_else(|| "leaks stdout was not piped".to_string())?;
    let mut stderr = child.stderr.take().ok_or_else(|| "leaks stderr was not piped".to_string())?;
    let stdout_future = read_limited(&mut stdout, max_output);
    let stderr_future = read_limited(&mut stderr, max_output);
    let wait_future = child.wait();
    let joined = time::timeout(timeout, async { tokio::join!(stdout_future, stderr_future, wait_future) }).await;
    match joined {
        Ok((stdout, stderr, status)) => {
            let (stdout, stdout_truncated) = stdout?;
            let (stderr, stderr_truncated) = stderr?;
            let status = status.map_err(|error| format!("failed waiting for leaks: {error}"))?;
            Ok(ToolOutput { status: status.code(), stdout, stderr, timed_out: false, truncated: stdout_truncated || stderr_truncated })
        }
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Ok(ToolOutput { status: None, stdout: String::new(), stderr: String::new(), timed_out: true, truncated: false })
        }
    }
}

async fn read_limited<R: AsyncRead + Unpin>(reader: &mut R, limit: usize) -> Result<(String, bool), String> {
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8 * 1024];
    let mut truncated = false;
    loop {
        let count = reader.read(&mut buffer).await.map_err(|error| format!("failed reading leaks output: {error}"))?;
        if count == 0 { break; }
        let keep = limit.saturating_sub(bytes.len()).min(count);
        bytes.extend_from_slice(&buffer[..keep]);
        if keep < count { truncated = true; }
    }
    Ok((String::from_utf8_lossy(&bytes).into_owned(), truncated))
}

#[derive(Default)]
struct FlamegraphTotals {
    self_weights: BTreeMap<String, f64>,
    inclusive_weights: BTreeMap<String, f64>,
    total: f64,
    idle: f64,
    unattributed: f64,
    nodes: usize,
}

fn summarize_flamegraph(path: &Path, text: &str, args: &Map<String, Value>) -> Result<Value, String> {
    let payload: Value = serde_json::from_str(text).map_err(|error| format!("invalid flamegraph JSON: {error}"))?;
    let object = payload
        .as_object()
        .ok_or_else(|| "processed flamegraph JSON must be an object".to_string())?;
    if object.contains_key("threadNodes") {
        return Err("unsupported legacy flamegraph shape: threadNodes".to_string());
    }
    if object.contains_key("threads") && object.contains_key("libraryInfo") {
        return Err("raw ETTrace capture is not processed flamegraph JSON".to_string());
    }
    let root = object
        .get("nodes")
        .ok_or_else(|| "missing processed flamegraph nodes".to_string())?;
    let mut totals = FlamegraphTotals::default();
    let (total, _) = visit_node(root, &mut totals, 0)?;
    totals.total = total;
    let active = totals.total - totals.idle - totals.unattributed;
    let top = bounded_top(args)?;
    let patterns = optional_patterns(args)?;
    let show_wrappers = args.get("showWrappers").map_or(Ok(false), value_bool)?;
    let mut self_rows: Vec<(String, f64)> = totals
        .self_weights
        .iter()
        .filter(|(name, _)| !is_idle(name) && !is_unattributed(name))
        .map(|(name, weight)| (name.clone(), *weight))
        .collect();
    sort_rows(&mut self_rows);
    let mut inclusive_rows: Vec<(String, f64)> = totals
        .inclusive_weights
        .iter()
        .filter(|(name, _)| (show_wrappers || !is_wrapper(name)) && matches_patterns(name, &patterns))
        .map(|(name, weight)| (name.clone(), *weight))
        .collect();
    sort_rows(&mut inclusive_rows);
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("trace");
    let threads = vec![json!({"name": stem, "duration": totals.total})];
    Ok(json!({
        "trace": path.to_string_lossy(),
        "totalDuration": totals.total,
        "idleSelfTotal": totals.idle,
        "unattributedTotal": totals.unattributed,
        "activeTotal": active,
        "threads": threads,
        "topActiveSelfFrames": frame_rows(&self_rows, top, active),
        "topInclusiveFrames": frame_rows(&inclusive_rows, top, active),
        "parser": "processed-flamegraph-v1"
    }))
}

fn visit_node(node: &Value, totals: &mut FlamegraphTotals, depth: usize) -> Result<(f64, f64), String> {
    if depth > MAX_DEPTH {
        return Err(format!("flamegraph exceeds {MAX_DEPTH} recursive depth"));
    }
    totals.nodes += 1;
    if totals.nodes > MAX_NODES {
        return Err(format!("flamegraph exceeds {MAX_NODES} nodes"));
    }
    let object = node
        .as_object()
        .ok_or_else(|| "flamegraph node must be an object".to_string())?;
    let name = object.get("name").and_then(Value::as_str).unwrap_or("");
    let weight = object
        .get("duration")
        .and_then(Value::as_f64)
        .ok_or_else(|| "flamegraph node has invalid duration".to_string())?;
    if !weight.is_finite() || weight < 0.0 {
        return Err("flamegraph node has invalid duration".to_string());
    }
    let children = object
        .get("children")
        .ok_or_else(|| "processed flamegraph node is missing children".to_string())?;
    let child_values: Vec<&Value> = match children {
        Value::Object(_) => vec![children],
        Value::Array(values) => values.iter().collect(),
        _ => return Err("processed flamegraph node has invalid children".to_string()),
    };
    let mut children_weight = 0.0;
    let mut child_active = 0.0;
    for child in child_values {
        let (child_weight, child_active_weight) = visit_node(child, totals, depth + 1)?;
        children_weight += child_weight;
        child_active += child_active_weight;
    }
    let self_weight = if child_values.is_empty() { weight } else { (weight - children_weight).max(0.0) };
    let active_weight = if name.is_empty() || name == "<root>" {
        child_active
    } else {
        if self_weight > 0.0 {
            *totals.self_weights.entry(name.to_string()).or_default() += self_weight;
        }
        if is_unattributed(name) {
            totals.unattributed += self_weight;
        }
        if is_idle(name) {
            totals.idle += self_weight;
        }
        let active_self = if is_idle(name) || is_unattributed(name) { 0.0 } else { self_weight };
        let active_weight = child_active + active_self;
        if active_weight > 0.0 {
            *totals.inclusive_weights.entry(name.to_string()).or_default() += active_weight;
        }
        active_weight
    };
    if name.is_empty() || name == "<root>" {
        totals.total += self_weight;
    }
    Ok((weight, active_weight))
}

fn bounded_top(args: &Map<String, Value>) -> Result<usize, String> {
    let value = match args.get("top") {
        None => 40,
        Some(value) => value.as_u64().ok_or_else(|| "top must be an integer".to_string())?,
    };
    if !(1..=MAX_ROWS as u64).contains(&value) {
        return Err(format!("top must be between 1 and {MAX_ROWS}"));
    }
    Ok(value as usize)
}

fn optional_patterns(args: &Map<String, Value>) -> Result<Vec<String>, String> {
    match args.get("patterns") {
        None => Ok(Vec::new()),
        Some(Value::Array(values)) => values
            .iter()
            .map(|value| value.as_str().map(str::to_ascii_lowercase).ok_or_else(|| "patterns must contain strings".to_string()))
            .collect(),
        Some(_) => Err("patterns must be an array of strings".to_string()),
    }
}

fn value_bool(value: &Value) -> Result<bool, String> {
    value.as_bool().ok_or_else(|| "showWrappers must be a boolean".to_string())
}

fn frame_rows(rows: &[(String, f64)], limit: usize, denominator: f64) -> Vec<Value> {
    rows.iter()
        .take(limit)
        .map(|(frame, weight)| json!({"frame": frame, "weight": weight, "percent": if denominator > 0.0 { weight / denominator * 100.0 } else { 0.0 }}))
        .collect()
}

fn sort_rows(rows: &mut [(String, f64)]) {
    rows.sort_by(|(left_name, left_weight), (right_name, right_weight)| {
        right_weight
            .partial_cmp(left_weight)
            .unwrap_or(Ordering::Equal)
            .then_with(|| left_name.cmp(right_name))
    });
}

fn matches_patterns(name: &str, patterns: &[String]) -> bool {
    patterns.is_empty() || patterns.iter().any(|pattern| name.to_ascii_lowercase().contains(pattern))
}

fn is_idle(name: &str) -> bool { IDLE_FRAMES.contains(&name) }
fn is_unattributed(name: &str) -> bool { name == "<unattributed>" }
fn is_wrapper(name: &str) -> bool {
    WRAPPER_FRAMES.contains(&name)
        || name.starts_with("runApp<")
        || name.starts_with("closure #1 in App.")
        || (name.starts_with("static ") && [".$main()", ".main()", ".mainApp()"].iter().any(|suffix| name.ends_with(suffix)))
}

fn summarize_memgraph(path: &Path, text: &str) -> Result<Value, String> {
    let mut total = None;
    let mut entries = Vec::new();
    for line in text.lines() {
        if total.is_none() {
            if let Some(parsed) = parse_total(line) {
                total = Some(parsed);
            }
        }
        if let Some(entry) = parse_leak(line) {
            entries.push(entry);
            if entries.len() > MAX_ROWS {
                return Err(format!("memgraph leak entries exceed {MAX_ROWS}"));
            }
        }
    }
    if total.is_none() && entries.is_empty() {
        return Err("unrecognized memgraph leaks text".to_string());
    }
    let mut by_type: BTreeMap<String, u64> = BTreeMap::new();
    let mut by_image: BTreeMap<String, u64> = BTreeMap::new();
    for entry in &entries {
        *by_type.entry(entry["type"].as_str().unwrap_or("<unknown>").to_string()).or_default() += 1;
        *by_image.entry(entry["image"].as_str().unwrap_or("<unknown>").to_string()).or_default() += 1;
    }
    Ok(json!({
        "input": path.to_string_lossy(),
        "total": total,
        "parsedEntries": entries.len(),
        "topTypes": ranked_counts(by_type),
        "topImages": ranked_counts(by_image),
        "entries": entries,
        "traceAvailable": false,
        "groupedLeakTreeAvailable": false,
        "parser": "memgraph-leaks-text-v1"
    }))
}

fn parse_total(line: &str) -> Option<Value> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let process = parts.iter().position(|part| *part == "Process")?;
    let count: u64 = parts.get(process + 2)?.parse().ok()?;
    if !parts.get(process + 3)?.starts_with("leak") || *parts.get(process + 4)? != "for" {
        return None;
    }
    let bytes: u64 = parts.get(process + 5)?.parse().ok()?;
    Some(json!({"count": count, "bytes": bytes, "display": format!("{count} leaks / {bytes} bytes")}))
}

fn parse_leak(line: &str) -> Option<Value> {
    let rest = line.strip_prefix("Leak:")?.trim_start();
    let mut fields = rest.splitn(3, char::is_whitespace);
    let address = fields.next()?;
    if !address.starts_with("0x") || !address[2..].chars().all(|character| character.is_ascii_hexdigit()) {
        return None;
    }
    let size_field = fields.next()?.trim();
    let size = size_field.strip_prefix("size=")?.parse::<u64>().ok()?;
    let remainder = fields.next().unwrap_or("").trim();
    let remainder = remainder.strip_prefix("zone:").map(|zone| zone.trim_start_matches(char::is_whitespace).split_once(char::is_whitespace).map(|(_, rest)| rest).unwrap_or("")).unwrap_or(remainder).trim();
    let parts: Vec<&str> = remainder.splitn(3, |character: char| character.is_whitespace()).filter(|part| !part.is_empty()).collect();
    let (kind, language, image) = match parts.as_slice() {
        [kind, language, image] => (*kind, *language, *image),
        [kind, image] => (*kind, "<unknown>", *image),
        [kind] => (*kind, "<unknown>", "<unknown>"),
        [] => ("<unknown>", "<unknown>", "<unknown>"),
        _ => unreachable!(),
    };
    Some(json!({"address": address, "size": size, "type": kind, "language": language, "image": image}))
}

fn ranked_counts(counts: BTreeMap<String, u64>) -> Vec<Value> {
    let mut rows: Vec<(String, u64)> = counts.into_iter().collect();
    rows.sort_by(|(left_name, left_count), (right_name, right_count)| right_count.cmp(left_count).then_with(|| left_name.cmp(right_name)));
    rows.into_iter().take(20).map(|(name, count)| json!({"name": name, "count": count})).collect()
}

fn summarize_build_log(path: &Path, text: &str, args: &Map<String, Value>) -> Result<Value, String> {
    let mut errors = 0_u64;
    let mut warnings = 0_u64;
    let mut diagnostics = Vec::new();
    let max_diagnostics = bounded_count(args, "maxDiagnostics", 100, 1_000)?;
    for (index, line) in text.lines().enumerate() {
        let lowered = line.to_ascii_lowercase();
        let is_error = lowered.contains("error:") || lowered.contains("build failed");
        let is_warning = lowered.contains("warning:");
        if is_error { errors += 1; }
        if is_warning { warnings += 1; }
        if (is_error || is_warning) && diagnostics.len() < max_diagnostics {
            diagnostics.push(json!({"line": index + 1, "text": line}));
        }
    }
    let exit_status = match args.get("exit_status").or_else(|| args.get("exitStatus")) {
        None => None,
        Some(value) => Some(value.as_i64().ok_or_else(|| "exit_status must be an integer" )?),
    };
    let status = match exit_status {
        Some(0) if errors == 0 => "success",
        Some(_) => "failed",
        None => "unknown",
    };
    let success = exit_status.map(|value| value == 0 && errors == 0);
    Ok(json!({
        "input": path.to_string_lossy(),
        "lineCount": text.lines().count(),
        "errorCount": errors,
        "warningCount": warnings,
        "status": status,
        "success": success,
        "exitStatus": exit_status,
        "diagnosticFailure": errors > 0,
        "diagnostics": diagnostics,
        "parser": "build-log-text-v1"
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;

    fn fixture(name: &str, content: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("legion-diagnostics-{}-{}", std::process::id(), name));
        fs::write(&path, content).unwrap();
        path
    }

    #[tokio::test]
    async fn flamegraph_aggregates_idle_unattributed_patterns_and_wrappers() {
        let path = fixture("trace.json", r#"{"nodes":{"name":"<root>","duration":10,"children":[{"name":"main","duration":10,"children":[{"name":"work","duration":4,"children":[]},{"name":"mach_msg_trap","duration":6,"children":[]}]},{"name":"<unattributed>","duration":0,"children":[]}]}}"#);
        let result = invoke("flamegraph", &json!({"path": path.to_string_lossy(), "top": 10})).await.unwrap();
        assert_eq!(result["totalDuration"], 10.0);
        assert_eq!(result["idleSelfTotal"], 6.0);
        assert_eq!(result["activeTotal"], 4.0);
        assert_eq!(result["topActiveSelfFrames"][0]["frame"], "work");
        assert!(result["topInclusiveFrames"].as_array().unwrap().iter().all(|row| row["frame"] != "main"));
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn flamegraph_rejects_raw_and_malformed_shapes() {
        let raw = fixture("raw.json", r#"{"threads":[],"libraryInfo":{}}"#);
        assert!(invoke("flamegraph", &json!({"path": raw.to_string_lossy()})).await.is_err());
        let malformed = fixture("bad.json", r#"{"nodes":{"name":"x","duration":1}}"#);
        assert!(invoke("flamegraph", &json!({"path": malformed.to_string_lossy()})).await.is_err());
        let _ = fs::remove_file(raw);
        let _ = fs::remove_file(malformed);
    }

    #[tokio::test]
    async fn memgraph_parses_totals_entries_and_deterministic_groups() {
        let path = fixture("leaks.txt", "Process Demo: 2 leaks for 128 total leaked bytes\nLeak: 0x1 size=64 NSObject  Swift  Demo\nLeak: 0x2 size=64 NSObject  Swift  Demo\n");
        let result = invoke("memgraph.parse", &json!({"path": path.to_string_lossy()})).await.unwrap();
        assert_eq!(result["total"]["count"], 2);
        assert_eq!(result["parsedEntries"], 2);
        assert_eq!(result["topTypes"][0]["name"], "NSObject");
        assert_eq!(result["traceAvailable"], false);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn unknown_formats_and_operations_are_negative_controls() {
        let path = fixture("unknown.txt", "not a leaks report\n");
        assert!(invoke("memgraph.parse", &json!({"path": path.to_string_lossy()})).await.is_err());
        assert!(invoke("unknown", &json!({"path": path.to_string_lossy()})).await.is_err());
        assert!(invoke("build-log", &json!({})).await.is_err());
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn build_log_counts_bounded_diagnostics() {
        let path = fixture("build.log", "Compile ok\nwarning: old API\nerror: no such module\n");
        let result = invoke("build-log", &json!({"path": path.to_string_lossy()})).await.unwrap();
        assert_eq!(result["errorCount"], 1);
        assert_eq!(result["warningCount"], 1);
        assert_eq!(result["status"], "unknown");
        assert_eq!(result["success"], Value::Null);
        assert!(invoke("build-log", &json!({"path": path.to_string_lossy(), "maxDiagnostics": 0})).await.is_err());
        assert!(invoke("build-log", &json!({"path": path.to_string_lossy(), "maxDiagnostics": -1})).await.is_err());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn flamegraph_depth_bound_rejects_deep_fixture() {
        let mut root = json!({"name":"leaf","duration":1,"children":[]});
        for _ in 0..=MAX_DEPTH {
            root = json!({"name":"frame","duration":1,"children":[root]});
        }
        let mut totals = FlamegraphTotals::default();
        assert!(visit_node(&root, &mut totals, 0).is_err());
    }
}
