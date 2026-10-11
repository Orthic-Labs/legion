//! Runtime capture for `legacy.runtime.app`.
//!
//! The historical `audit-runtime` tool is not shipped. This module replaces it
//! with the running Legion executable's own browser route (`legion script
//! qa/qa-functional`): one authorized external-tool invocation per requested
//! surface, each carrying a real process receipt. Per surface the route loads
//! the URL at the requested viewport, verifies the document actually loaded
//! (not a browser error page, no HTTP error status), writes a screenshot into
//! the run's scratch (or `--out`) directory and reports console errors and
//! exceptions seen during the load.
//!
//! Each surface captures navigation, viewport screenshot, console output,
//! navigation/paint metrics, and axe WCAG 2 A/AA findings. Metrics and axe
//! output come from `[qa] N:eval value <json>` lines before `actions complete`,
//! so console text cannot fake evidence. Missing or invalid results become
//! typed gaps; a failed axe action does not discard completed screenshot or
//! performance evidence. Findings are bounded, with excess axe output marked
//! as truncated rather than clean.
//!
//! `wf_port::wf064::runtime::ChromeRuntimeDriver` is deliberately not used:
//! it holds an in-process browser outside the process-receipt path, types
//! and clicks into the audited app, and injects its instrumentation before
//! navigation, where it does not survive.
//!
//! - a11y: axe-core 4.14.0 is bundled as the default; a project-installed copy
//!   overrides it. Both run the historical WCAG 2 A/AA tag set.
//!
//! Inputs (`--url`, `--surfaces`, `--width`, `--height`) arrive through the
//! provider's frozen `runner.runtime` object, so they are covered by the plan
//! seal. Without a URL the provider is `unavailable:runtime-url-not-supplied`.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderStatus};
use legion_provider_sdk::{
    ExecutionReceipt, ExecutionState, ExternalProjectTool, ExternalToolRequest,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::{
    audit_environment, command_parts, empty_output, push_finding, readable_artifact,
    resolver::RUNTIME_CAPTURE_TOOL, safe_location, spec, LegacyCheckInput,
    NativeLegacyCheckExecutor, AUDIT_ARTIFACT_SEQUENCE,
};
use crate::{error::AuditError, native_providers::availability, plan::AuditProvider};

/// Reason reported when the operator supplied no `--url`.
pub(super) const UNAVAILABLE_URL: &str = "runtime-url-not-supplied";

const MAX_EXTRA_SURFACES: usize = 32;
const MAX_DIMENSION: u64 = 16_384;
const DEFAULT_WIDTH: u32 = 1280;
const DEFAULT_HEIGHT: u32 = 800;
const BUNDLED_AXE_VERSION: &str = "4.14.0";
const BUNDLED_AXE_SOURCE: &str = include_str!("../../../assets/axe-core-4.14.0.min.js");

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Evaluated in the loaded page before the screenshot. It fails the run when
/// the browser is showing its own error page (connection refused, DNS, TLS)
/// or the navigation response carried an HTTP error status.
const LOAD_CHECK: &str = "(() => { const nav = performance.getEntriesByType('navigation')[0]; const status = nav && nav.responseStatus ? nav.responseStatus : 0; return { ok: !location.href.startsWith('chrome-error:') && !(status >= 400), href: location.href, status: status }; })()";

/// The route's 1-based label for the performance action: the third action
/// of every surface (see `capture_surface`), printed as `[qa] 3:eval value`.
const PERFORMANCE_ACTION_LABEL: usize = 3;
/// The fourth action runs axe after screenshot capture, preserving legacy
/// action indices for load, screenshot, and performance.
const A11Y_ACTION_LABEL: usize = 4;

/// Evaluated after the screenshot. It returns
/// one object of numbers, with `null` for entries the browser did not expose. It
/// never throws (a throw would fail the whole surface, screenshot included), and
/// it carries no `ok` key, so the route never treats it as a failed assertion.
const PERFORMANCE_METRICS: &str = "(() => { try { const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? Math.round(v * 100) / 100 : null); const nav = performance.getEntriesByType('navigation')[0]; const fcp = performance.getEntriesByType('paint').find((e) => e.name === 'first-contentful-paint'); const resources = performance.getEntriesByType('resource'); let transfer = 0; for (const e of resources) { transfer += typeof e.transferSize === 'number' ? e.transferSize : 0; } return { domContentLoaded: nav ? num(nav.domContentLoadedEventEnd) : null, loadEventEnd: nav ? num(nav.loadEventEnd) : null, responseStart: nav ? num(nav.responseStart) : null, ttfb: nav ? num(nav.responseStart) : null, firstContentfulPaint: fcp ? num(fcp.startTime) : null, transferSize: num(transfer), resourceCount: resources.length }; } catch (e) { return null; } })()";

/// Validated inputs of one runtime capture (`runner.runtime`).
#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeParams {
    url: String,
    /// Additional surfaces beyond the entry URL: `(label, url)`.
    surfaces: Vec<(String, String)>,
    width: u32,
    height: u32,
    unsupported: Vec<String>,
    artifact_dir: Option<PathBuf>,
}

impl RuntimeParams {
    /// `Ok(None)` when no URL was supplied; `Err(reason)` for invalid inputs.
    fn from_value(value: &Value) -> Result<Option<Self>, String> {
        let Some(object) = value.as_object() else {
            return Ok(None);
        };
        let url = match object.get("url").and_then(Value::as_str) {
            Some(url) if !url.trim().is_empty() => url.trim().to_owned(),
            _ => return Ok(None),
        };
        check_url(&url)?;
        let width = dimension(object.get("width"), DEFAULT_WIDTH, "width")?;
        let height = dimension(object.get("height"), DEFAULT_HEIGHT, "height")?;
        let mut surfaces = Vec::new();
        if let Some(items) = object.get("surfaces") {
            let items = items
                .as_array()
                .ok_or_else(|| "surfaces-not-an-array".to_owned())?;
            if items.len() > MAX_EXTRA_SURFACES {
                return Err("too-many-surfaces".into());
            }
            for item in items {
                let label = item
                    .get("label")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|label| !label.is_empty())
                    .ok_or_else(|| "surface-label-missing".to_owned())?;
                let surface_url = item
                    .get("url")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .ok_or_else(|| "surface-url-missing".to_owned())?;
                check_url(surface_url)?;
                surfaces.push((label.to_owned(), surface_url.to_owned()));
            }
        }
        let unsupported = match object.get("unsupportedSurfaces") {
            None | Some(Value::Null) => Vec::new(),
            Some(items) => items
                .as_array()
                .ok_or_else(|| "unsupported-surfaces-not-an-array".to_owned())?
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        };
        let artifact_dir = match object.get("artifactDir") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let path = PathBuf::from(
                    value
                        .as_str()
                        .ok_or_else(|| "artifact-dir-not-a-string".to_owned())?,
                );
                if !path.is_absolute() {
                    return Err("artifact-dir-not-absolute".into());
                }
                Some(path)
            }
        };
        Ok(Some(Self {
            url,
            surfaces,
            width,
            height,
            unsupported,
            artifact_dir,
        }))
    }

    fn from_provider(provider: &AuditProvider) -> Result<Option<Self>, String> {
        match provider
            .configuration
            .get("runner")
            .and_then(|runner| runner.get("runtime"))
        {
            Some(value) => Self::from_value(value),
            None => Ok(None),
        }
    }

    /// Entry surface first, then the requested extras, in order.
    fn all_surfaces(&self) -> Vec<(String, String)> {
        let mut all = vec![("entry".to_owned(), self.url.clone())];
        all.extend(self.surfaces.iter().cloned());
        all
    }

    fn to_value(&self) -> Value {
        json!({
            "url": self.url,
            "width": self.width,
            "height": self.height,
            "surfaces": self.surfaces.iter().map(|(label, url)| json!({"label": label, "url": url})).collect::<Vec<_>>(),
            "unsupportedSurfaces": self.unsupported,
            "artifactDir": self.artifact_dir.as_ref().map(|path| path.to_string_lossy().into_owned()),
        })
    }
}

fn check_url(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    let rest = if lower.starts_with("http://") {
        &url[7..]
    } else if lower.starts_with("https://") {
        &url[8..]
    } else {
        return Err("url-scheme-not-http".into());
    };
    if rest.is_empty() || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("url-malformed".into());
    }
    Ok(())
}

fn dimension(value: Option<&Value>, default: u32, name: &str) -> Result<u32, String> {
    match value {
        None | Some(Value::Null) => Ok(default),
        Some(value) => match value.as_u64() {
            Some(number) if (1..=MAX_DIMENSION).contains(&number) => Ok(number as u32),
            _ => Err(format!("{name}-invalid")),
        },
    }
}

/// Validate the CLI inputs and build the `runner.runtime` object that is
/// frozen into the plan. `surfaces` are the extra `(label, url)` pairs beyond
/// the entry URL; `unsupported` names requested surfaces that cannot be
/// captured by URL navigation (click targets).
pub fn runtime_inputs(
    url: &str,
    surfaces: &[(String, String)],
    unsupported: &[String],
    width: u32,
    height: u32,
    artifact_dir: Option<&str>,
) -> Result<Value, String> {
    let candidate = json!({
        "url": url,
        "width": width,
        "height": height,
        "surfaces": surfaces.iter().map(|(label, surface_url)| json!({"label": label, "url": surface_url})).collect::<Vec<_>>(),
        "unsupportedSurfaces": unsupported,
        "artifactDir": artifact_dir,
    });
    match RuntimeParams::from_value(&candidate)? {
        Some(params) => Ok(params.to_value()),
        None => Err("runtime-url-empty".into()),
    }
}

/// What the QA route printed for one invocation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct QaOutput {
    screenshot: Option<String>,
    actions_complete: bool,
    no_console_issues: bool,
    console_total: Option<usize>,
    console_entries: Vec<String>,
    gaps: Vec<String>,
    /// `(action index, JSON text)` of each `[qa] N:eval value <json>` line printed
    /// before `actions complete`.
    eval_values: Vec<(usize, String)>,
}

/// Matches `N:eval value <json>` at the start of a `[qa] ` line body, returning the
/// 1-based action label and the JSON text that follows.
fn eval_value_line(rest: &str) -> Option<(usize, &str)> {
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let (number, tail) = rest.split_at(digits);
    let json = tail.strip_prefix(":eval value ")?;
    Some((number.parse().ok()?, json))
}

/// The metrics object of a performance line. Anything else is rejected: unparsable
/// JSON, a non-object, an empty object, a value that is not a number or `null`, and
/// the route's `{"truncated":true,...}` marker.
fn parse_performance(json: &str) -> Option<Value> {
    let value: Value = serde_json::from_str(json).ok()?;
    let object = value.as_object()?;
    if object.is_empty() || object.contains_key("truncated") {
        return None;
    }
    if !object.values().all(|v| v.is_number() || v.is_null()) {
        return None;
    }
    Some(value)
}

/// Parse the `[qa] ...` lines the route prints (see `wf_port::r54::run`).
fn parse_qa_output(text: &str) -> QaOutput {
    let mut out = QaOutput::default();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("[qa] ") else {
            continue;
        };
        if let Some((index, json)) = eval_value_line(rest) {
            // The route prints action output before `actions complete`; console text
            // comes after it, so a forged line there is never a metric.
            if !out.actions_complete {
                out.eval_values.push((index, json.to_owned()));
            }
        } else if let Some(path) = rest.strip_prefix("screenshot ") {
            if out.screenshot.is_none() {
                out.screenshot = Some(path.trim().to_owned());
            }
        } else if rest.starts_with("actions complete") {
            out.actions_complete = true;
        } else if rest.starts_with("no console errors or warnings") {
            out.no_console_issues = true;
        } else if rest.contains("console error/warning(s)") {
            out.console_total = rest
                .split_whitespace()
                .next()
                .and_then(|count| count.parse::<usize>().ok());
        } else if let Some(name) = rest.strip_prefix("gap ") {
            let name = name.trim();
            if !name.is_empty() {
                out.gaps.push(name.to_owned());
            }
        } else if rest.starts_with("  ") {
            let entry = rest.trim();
            if entry.starts_with("console.") || entry.starts_with("exception:") {
                out.console_entries.push(entry.to_owned());
            }
        }
    }
    out
}

fn is_console_warning(entry: &str) -> bool {
    entry.starts_with("console.warning")
}

/// Classify a failed invocation from the route's own messages. Returns an
/// `unavailable:<reason>` reason when the browser itself is missing, and the
/// gap to record.
fn classify_failure(label: &str, state: &str, text: &str) -> (Option<String>, String) {
    if text.contains("No Chrome/Edge executable found")
        || text.contains("CHROME_PATH/QA_BROWSER set but not found")
    {
        return (
            Some("browser-not-found".to_owned()),
            format!("runtime-browser-not-found:{label}"),
        );
    }
    if text.contains("eval returned not ok") || text.contains("Timed out loading") {
        return (None, format!("runtime-surface-load-failed:{label}"));
    }
    (
        None,
        format!("runtime-surface-capture-failed:{label}:{state}"),
    )
}

fn first_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.chars().take(200).collect())
}

fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Same projection `execution_from_receipt` records; the external-receipt
/// validator in `execution.rs` requires exactly these fields.
fn receipt_json(receipt: &ExecutionReceipt) -> Value {
    json!({
        "schemaVersion": receipt.schema_version, "receiptId": receipt.receipt_id,
        "requestId": receipt.request_id, "providerId": receipt.provider_id,
        "planId": receipt.plan_id, "policyId": receipt.policy_id,
        "policy": receipt.policy.as_ref().map(|p| json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
        "taskId": receipt.task_id, "state": receipt.state.as_str(), "complete": receipt.complete,
        "executable": receipt.executable.as_ref().map(|e| json!({"requestedPath":e.requested_path,"canonicalPath":e.canonical_path,"digest":e.digest,"digestState":format!("{:?}", e.digest_state).to_ascii_lowercase(),"signature":format!("{:?}", e.signature).to_ascii_lowercase(),"version":{"args":e.version.args,"output":e.version.output,"exitCode":e.version.exit_code,"qualified":e.version.qualified}})),
        "command": receipt.command.as_ref().map(|c| json!({"executable":c.executable,"args":c.args,"environmentNames":c.environment_names,"redactedArgumentIndexes":c.redacted_argument_indexes,"redactedEnvironmentNames":c.redacted_environment_names})),
        "cwd": receipt.cwd, "environmentNames": receipt.environment_names,
        "sandbox": {"required":receipt.sandbox.required,"receiptId":receipt.sandbox.receipt_id,"networkEnabled":receipt.sandbox.network_enabled},
        "processTree": {"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,"hardKilled":receipt.process_tree.hard_killed,"reaped":receipt.process_tree.reaped,"detail":receipt.process_tree.detail},
        "timing": {"startedAtMs":receipt.timing.started_at_ms,"completedAtMs":receipt.timing.completed_at_ms,"durationMs":receipt.timing.duration_ms},
        "exitCode": receipt.exit_code, "signal": receipt.signal,
        "stdout": receipt.stdout.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "stderr": receipt.stderr.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "parser": {"attempted":receipt.parser.attempted,"succeeded":receipt.parser.succeeded,"error":receipt.parser.error}, "gaps": receipt.gaps,
    })
}

fn bound_u64(provider: &AuditProvider, key: &str) -> Option<u64> {
    provider.bounds.get(key).and_then(Value::as_u64)
}

/// Request for one invocation. Legion's own executable is the tool, so the
/// origin is `LegionOwned`; nothing here executes target-project code, and the
/// working directory is a scratch directory, never the audited tree.
fn base_request(
    provider: &AuditProvider,
    plan_digest: &str,
    input: &LegacyCheckInput,
    suffix: &str,
    cwd: &Path,
    args: Vec<String>,
) -> ExternalToolRequest {
    ExternalToolRequest {
        request_id: format!(
            "audit:{}:{}:{}:{}",
            provider.id, plan_digest, input.inventory_digest, suffix
        ),
        provider_id: provider.id.clone(),
        plan_id: plan_digest.to_owned(),
        policy_id: provider
            .configuration
            .get("policyId")
            .and_then(Value::as_str)
            .unwrap_or("audit")
            .into(),
        task_id: Some("runtime".into()),
        executable: RUNTIME_CAPTURE_TOOL.into(),
        args,
        cwd: cwd.to_string_lossy().into_owned(),
        origin: legion_effects::ToolOrigin::LegionOwned,
        shell: false,
        accepted_exit_codes: [0].into_iter().collect(),
        timeout_ms: bound_u64(provider, "timeoutMs").unwrap_or(120_000),
        stdout_limit: bound_u64(provider, "stdoutLimit").unwrap_or(8 * 1024 * 1024) as usize,
        stderr_limit: bound_u64(provider, "stderrLimit").unwrap_or(8 * 1024 * 1024) as usize,
        ..ExternalToolRequest::default()
    }
}

/// Everything one surface invocation produced.
struct SurfaceOutcome {
    index: usize,
    label: String,
    url: String,
    /// `captured` | `failed` | `unavailable`
    status: &'static str,
    screenshot: Option<Value>,
    /// Page performance metrics, when the surface's metric line was valid.
    performance: Option<Value>,
    /// `ran` with compact axe violations, or typed `unavailable`/`error`.
    accessibility: Value,
    console_errors: Vec<String>,
    console_warnings: Vec<String>,
    gaps: Vec<String>,
    failure: Option<String>,
    unavailable: Option<String>,
    receipt: Value,
    receipt_complete: bool,
    process_state: String,
    exit_code: Option<i32>,
}

impl SurfaceOutcome {
    fn new(index: usize, label: &str, url: &str, receipt: &ExecutionReceipt) -> Self {
        Self {
            index,
            label: label.to_owned(),
            url: url.to_owned(),
            status: "failed",
            screenshot: None,
            performance: None,
            accessibility: json!({"status": "unavailable", "reason": "surface-not-captured"}),
            console_errors: Vec::new(),
            console_warnings: Vec::new(),
            gaps: Vec::new(),
            failure: None,
            unavailable: None,
            receipt: receipt_json(receipt),
            receipt_complete: receipt.is_complete(),
            process_state: receipt.state.as_str().to_owned(),
            exit_code: receipt.exit_code,
        }
    }
}

struct Ctx<'a> {
    tool: &'a dyn ExternalProjectTool,
    provider: &'a AuditProvider,
    input: &'a LegacyCheckInput,
    plan_digest: &'a str,
    params: &'a RuntimeParams,
    axe_expression: String,
    base_args: &'a [String],
    environment: &'a BTreeMap<String, String>,
    allowlist: &'a BTreeSet<String>,
    work_dir: &'a Path,
    shot_dir: &'a Path,
    roots: &'a [&'a Path],
    cancellation: &'a CancellationToken,
}

/// Prefer axe-core from the audited project's Node dependency tree, then use
/// Legion's pinned bundled copy so runtime a11y remains available by default.
fn load_axe_source(root: &Path) -> (String, String) {
    let mut current = Some(root);
    while let Some(dir) = current {
        let candidate = dir.join("node_modules/axe-core/axe.min.js");
        if candidate.exists() {
            if let Ok(source) = std::fs::read_to_string(&candidate) {
                return (source, "project node_modules/axe-core".into());
            }
        }
        current = dir.parent();
    }
    (
        BUNDLED_AXE_SOURCE.to_owned(),
        format!("Legion bundled axe-core@{BUNDLED_AXE_VERSION}"),
    )
}

/// Evaluate axe WCAG 2 A/AA and return compact, actionable evidence.
fn axe_expression(source: Option<&str>, unavailable_reason: &str) -> String {
    let Some(source) = source else {
        let reason = serde_json::to_string(unavailable_reason)
            .unwrap_or_else(|_| "\"axe-core-not-installed\"".into());
        return format!("({{status:'unavailable',reason:{reason}}})");
    };
    format!(
        "(async()=>{{try{{{source}\n;const r=await window.axe.run(document,{{resultTypes:['violations'],runOnly:{{type:'tag',values:['wcag2a','wcag2aa']}}}});const total=r.violations.length;const violations=r.violations.slice(0,32).map(v=>({{id:String(v.id||'unknown').slice(0,80),impact:String(v.impact||'unknown').slice(0,20),help:String(v.help||'axe violation').slice(0,240),count:v.nodes.length,target:String(((v.nodes[0]||{{}}).target||[])[0]||'document').slice(0,320),helpUrl:String(v.helpUrl||'').slice(0,320)}}));const truncated=total>violations.length;return {{status:truncated?'error':'ran',reason:truncated?'axe-results-truncated':undefined,totalViolations:total,truncated,violations}}}}catch(e){{return {{status:'error',reason:String((e&&e.message)||e).slice(0,160)}}}}}})()"
    )
}

/// Validate bounded QA eval output before treating any accessibility count as
/// evidence. The QA engine's oversize marker and malformed payloads are typed
/// failures; truncated results retain their bounded violations for findings.
fn parse_accessibility_result(text: &str) -> Value {
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => return json!({"status": "error", "reason": "axe-result-malformed"}),
    };
    if value.get("truncated").and_then(Value::as_bool) == Some(true)
        && value.get("status").is_none()
    {
        return json!({
            "status": "error",
            "reason": "axe-result-truncated",
            "reportedBytes": value.get("bytes").and_then(Value::as_u64),
        });
    }
    let Some(status) = value.get("status").and_then(Value::as_str) else {
        return json!({"status": "error", "reason": "axe-result-status-missing"});
    };
    if matches!(status, "error" | "unavailable") {
        let Some(reason) = value.get("reason").and_then(Value::as_str) else {
            return json!({"status": "error", "reason": "axe-result-reason-missing"});
        };
        if status == "unavailable" {
            return json!({"status": "unavailable", "reason": reason});
        }
        if value.get("violations").is_none() {
            return json!({"status": "error", "reason": reason});
        }
        if reason != "axe-results-truncated" {
            return json!({"status": "error", "reason": "axe-result-error-with-violations"});
        }
    }
    let is_truncated_error = status == "error"
        && value.get("reason").and_then(Value::as_str) == Some("axe-results-truncated");
    if (status != "ran" && !is_truncated_error)
        || (status == "ran" && value.get("reason").is_some())
    {
        return json!({"status": "error", "reason": "axe-result-status-invalid"});
    }
    let Some(violations) = value.get("violations").and_then(Value::as_array) else {
        return json!({"status": "error", "reason": "axe-violations-not-an-array"});
    };
    let Some(total) = value.get("totalViolations").and_then(Value::as_u64) else {
        return json!({"status": "error", "reason": "axe-total-invalid"});
    };
    let Some(truncated) = value.get("truncated").and_then(Value::as_bool) else {
        return json!({"status": "error", "reason": "axe-truncated-flag-invalid"});
    };
    if total < violations.len() as u64
        || truncated != (total > violations.len() as u64)
        || truncated != is_truncated_error
    {
        return json!({"status": "error", "reason": "axe-total-inconsistent"});
    }
    for violation in violations {
        let valid = violation.is_object()
            && violation
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            && violation
                .get("impact")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            && violation.get("help").and_then(Value::as_str).is_some()
            && violation.get("target").and_then(Value::as_str).is_some()
            && violation.get("helpUrl").and_then(Value::as_str).is_some()
            && violation
                .get("count")
                .and_then(Value::as_u64)
                .is_some_and(|count| count > 0);
        if !valid {
            return json!({"status": "error", "reason": "axe-violation-invalid"});
        }
    }
    if truncated {
        json!({
            "status": "error",
            "reason": "axe-results-truncated",
            "totalViolations": total,
            "truncated": true,
            "violations": violations,
        })
    } else {
        value
    }
}

async fn capture_surface(ctx: &Ctx<'_>, index: usize, label: &str, url: &str) -> SurfaceOutcome {
    let dir = ctx.work_dir.join(format!("surface-{index}"));
    let shot_path = ctx.shot_dir.join(format!("runtime-shot-{index}.png"));
    let actions_path = dir.join("actions.json");
    let mut args: Vec<String> = ctx.base_args.to_vec();
    args.extend([
        "--url".to_owned(),
        url.to_owned(),
        "--actions".to_owned(),
        actions_path.to_string_lossy().into_owned(),
        "--width".to_owned(),
        ctx.params.width.to_string(),
        "--height".to_owned(),
        ctx.params.height.to_string(),
    ]);
    let mut request = base_request(
        ctx.provider,
        ctx.plan_digest,
        ctx.input,
        &format!("surface-{index}"),
        &dir,
        args,
    );
    request.environment = ctx.environment.clone();
    request.environment_allowlist = ctx.allowlist.clone();

    let setup = (|| -> Result<(), String> {
        std::fs::create_dir_all(&dir).map_err(|error| format!("work-dir: {error}"))?;
        std::fs::create_dir_all(ctx.shot_dir).map_err(|error| format!("artifact-dir: {error}"))?;
        // A stale file must never be mistaken for this run's capture.
        let _ = std::fs::remove_file(&shot_path);
        let actions = json!([
            {"type": "eval", "expression": LOAD_CHECK},
            {"type": "screenshot", "out": shot_path.to_string_lossy().into_owned()},
            {"type": "eval", "expression": PERFORMANCE_METRICS},
            {"type": "eval", "expression": ctx.axe_expression},
        ]);
        let bytes = serde_json::to_vec(&actions).map_err(|error| error.to_string())?;
        std::fs::write(&actions_path, bytes).map_err(|error| format!("actions-file: {error}"))
    })();
    if let Err(detail) = setup {
        let gap = format!("runtime-surface-setup-failed:{label}");
        let receipt = ExecutionReceipt::failure(&request, ExecutionState::Blocked, gap.clone());
        let mut outcome = SurfaceOutcome::new(index, label, url, &receipt);
        outcome.gaps.push(gap);
        outcome.failure = Some(detail);
        return outcome;
    }
    if ctx.cancellation.is_cancelled() {
        let gap = format!("runtime-surface-capture-failed:{label}:cancelled");
        let receipt = ExecutionReceipt::failure(&request, ExecutionState::Cancelled, "cancelled");
        let mut outcome = SurfaceOutcome::new(index, label, url, &receipt);
        outcome.gaps.push(gap);
        return outcome;
    }

    let receipt = ctx.tool.execute(request, ctx.cancellation.clone()).await;
    let mut outcome = SurfaceOutcome::new(index, label, url, &receipt);
    let stdout = receipt
        .stdout
        .as_ref()
        .and_then(|artifact| readable_artifact(ctx.roots, artifact))
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    let stderr = receipt
        .stderr
        .as_ref()
        .and_then(|artifact| readable_artifact(ctx.roots, artifact))
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    let qa = parse_qa_output(&stdout);
    for entry in &qa.console_entries {
        if is_console_warning(entry) {
            outcome.console_warnings.push(entry.clone());
        } else {
            outcome.console_errors.push(entry.clone());
        }
    }
    for gap in &qa.gaps {
        outcome.gaps.push(format!("runtime-qa-gap:{label}:{gap}"));
    }

    outcome.performance = qa
        .eval_values
        .iter()
        .find(|(index, _)| *index == PERFORMANCE_ACTION_LABEL)
        .and_then(|(_, json)| parse_performance(json));
    outcome.accessibility = qa
        .eval_values
        .iter()
        .find(|(index, _)| *index == A11Y_ACTION_LABEL)
        .map(|(_, text)| parse_accessibility_result(text))
        .unwrap_or_else(|| json!({"status": "error", "reason": "axe-result-not-reported"}));
    let a11y_status = outcome.accessibility.get("status").and_then(Value::as_str);
    if matches!(a11y_status, Some("unavailable" | "error")) {
        let reason = outcome
            .accessibility
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        outcome.gaps.push(format!(
            "runtime-a11y-{}:{}:{}",
            a11y_status.unwrap(),
            label,
            reason
        ));
    }

    let expected_shot = shot_path.to_string_lossy().into_owned();
    let load_succeeded = qa
        .eval_values
        .iter()
        .find(|(index, _)| *index == 1)
        .and_then(|(_, text)| serde_json::from_str::<Value>(text).ok())
        .and_then(|value| value.get("ok").and_then(Value::as_bool))
        == Some(true);
    let screenshot_valid = if qa.screenshot.as_deref() != Some(expected_shot.as_str()) {
        outcome
            .gaps
            .push(format!("runtime-screenshot-not-reported:{label}"));
        false
    } else {
        match std::fs::read(&shot_path) {
            Ok(bytes) if !bytes.is_empty() && bytes.starts_with(PNG_MAGIC) => {
                outcome.screenshot = Some(json!({
                    "path": expected_shot,
                    "sha256": sha256_label(&bytes),
                    "bytes": bytes.len(),
                }));
                true
            }
            Ok(_) => {
                outcome
                    .gaps
                    .push(format!("runtime-screenshot-invalid:{label}"));
                false
            }
            Err(error) => {
                outcome
                    .gaps
                    .push(format!("runtime-screenshot-missing:{label}"));
                outcome.failure = Some(error.to_string());
                false
            }
        }
    };
    let core_capture_succeeded = load_succeeded && screenshot_valid;

    let ran_clean = receipt.state == ExecutionState::Completed
        && receipt.complete
        && receipt.exit_code == Some(0);
    if !ran_clean {
        if receipt.state == ExecutionState::MissingExecutable {
            outcome.unavailable = Some("legion-executable-unavailable".to_owned());
            outcome.gaps.push(format!(
                "runtime-surface-capture-failed:{label}:missing_executable"
            ));
            outcome.status = "unavailable";
            outcome.failure = first_line(&receipt.gaps.join("\n"));
            return outcome;
        }
        let combined = format!("{stderr}\n{stdout}");
        let (unavailable, gap) = classify_failure(label, receipt.state.as_str(), &combined);
        outcome.gaps.push(gap);
        outcome.failure = first_line(&stderr)
            .or_else(|| first_line(&stdout))
            .or_else(|| first_line(&receipt.gaps.join("\n")));
        if let Some(reason) = unavailable {
            outcome.unavailable = Some(reason);
            outcome.status = "unavailable";
        }
        if !core_capture_succeeded {
            return outcome;
        }
        // An axe timeout or protocol failure must not erase the already
        // completed navigation, screenshot, and performance evidence.
        outcome.status = "captured";
    } else if !qa.actions_complete {
        outcome.gaps.push(format!(
            "runtime-surface-capture-failed:{label}:actions-incomplete"
        ));
        return outcome;
    }
    // The route prints at most 20 entries; a larger total is a truncated view.
    if let Some(total) = qa.console_total {
        if qa.console_entries.len() < total {
            outcome
                .gaps
                .push(format!("runtime-console-truncated:{label}:{total}"));
        }
    } else if !qa.no_console_issues {
        outcome
            .gaps
            .push(format!("runtime-console-report-missing:{label}"));
    }
    if core_capture_succeeded {
        outcome.status = "captured";
    }
    outcome
}

/// Result for a provider that could not run at all (`unavailable:<reason>`):
/// no process was started, so the terminal receipt is a non-started `blocked`
/// receipt carrying the reason, exactly as the effect layer reports a refused
/// request.
fn unavailable_result(
    executor: &NativeLegacyCheckExecutor,
    provider: &AuditProvider,
    input: &LegacyCheckInput,
    plan_digest: &str,
    reason: &str,
) -> Result<ProviderResult, AuditError> {
    let gap = availability::unavailable_gap(reason);
    let args = command_parts(spec(&provider.id).expect("validated above").command).1;
    let request = base_request(
        provider,
        plan_digest,
        input,
        "unavailable",
        &executor.root,
        args,
    );
    let receipt = ExecutionReceipt::failure(&request, ExecutionState::Blocked, gap.clone());
    let provider_id =
        ProviderId::new(&provider.id).map_err(|error| AuditError::Provider(error.to_string()))?;
    let mut details = BTreeMap::new();
    details.insert("check".to_owned(), Value::String("runtime".into()));
    details.insert("tool".to_owned(), Value::String("audit-runtime.mjs".into()));
    details.insert(
        "processState".to_owned(),
        Value::String(receipt.state.as_str().into()),
    );
    details.insert("exitCode".to_owned(), Value::Null);
    details.insert("commandShape".to_owned(), Value::String("named".into()));
    details.insert("candidates".to_owned(), Value::Array(Vec::new()));
    details.insert("executionReceipt".to_owned(), receipt_json(&receipt));
    details.insert(
        "receiptId".to_owned(),
        Value::String(receipt.receipt_id.clone()),
    );
    let mut result = ProviderResult {
        schema_version: 1,
        provider: provider_id,
        applicable: true,
        required: provider.required,
        status: ProviderStatus::Partial,
        complete: false,
        coverage: Some(Coverage {
            denominator_digest: input.denominator.digest.clone(),
            expected: input.denominator.entries.len() as u64,
            examined: 0,
            gaps: vec![gap.clone()],
        }),
        findings: Vec::new(),
        coverage_gaps: vec![gap],
        degradation: Vec::new(),
        details,
    };
    availability::mark_unavailable(&mut result, reason);
    result
        .validate()
        .map_err(|error| AuditError::Provider(error.to_string()))?;
    Ok(result)
}

/// Attach runtime observation metadata to a finding without promoting the
/// captured artifact into a repository source location or anchor.
fn push_runtime_finding(
    output: &mut super::LegacyCheckOutput,
    rule: &str,
    severity: &str,
    path: &str,
    line: usize,
    message: &str,
    outcome: &SurfaceOutcome,
) {
    push_finding(output, rule, severity, path, line, message);
    let Some(finding) = output.findings.last() else {
        return;
    };
    let finding_id = finding.id.to_string();
    let Some(evidence) = output
        .details
        .get_mut("findingEvidence")
        .and_then(Value::as_object_mut)
        .and_then(|findings| findings.get_mut(&finding_id))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    evidence.insert(
        "runtimeCapture".into(),
        json!({
            "surface": outcome.label.as_str(),
            "url": outcome.url.as_str(),
            "screenshot": outcome.screenshot.as_ref(),
        }),
    );
}

pub(super) async fn execute(
    executor: &NativeLegacyCheckExecutor,
    plan: &crate::FrozenPlan,
    provider: &AuditProvider,
    input: &LegacyCheckInput,
    cancellation: CancellationToken,
) -> Result<ProviderResult, AuditError> {
    let plan_digest = plan.digest().to_string();
    let params = match RuntimeParams::from_provider(provider) {
        Ok(Some(params)) => params,
        Ok(None) => {
            return unavailable_result(executor, provider, input, &plan_digest, UNAVAILABLE_URL);
        }
        Err(reason) => {
            return unavailable_result(
                executor,
                provider,
                input,
                &plan_digest,
                &format!("runtime-inputs-invalid:{reason}"),
            );
        }
    };
    let Some(tool) = executor.external_project_tool.clone() else {
        return unavailable_result(
            executor,
            provider,
            input,
            &plan_digest,
            "external-project-tool-capability-unavailable",
        );
    };
    let scratch = executor.scratch()?;
    let (mut environment, mut allowlist) = audit_environment(&scratch);
    // The route locates the browser from these, when the operator set them.
    for name in ["CHROME_PATH", "QA_BROWSER"] {
        if let Ok(value) = std::env::var(name) {
            environment.insert(name.to_owned(), value);
            allowlist.insert(name.to_owned());
        }
    }
    let sequence = AUDIT_ARTIFACT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let work_dir = scratch.tmp_dir().join(format!("runtime-{sequence}"));
    let shot_dir = params
        .artifact_dir
        .clone()
        .unwrap_or_else(|| work_dir.join("shots"));
    let artifacts_dir = scratch.artifacts_dir();
    let roots = [artifacts_dir.as_path(), executor.root.as_path()];
    let base_args = command_parts(spec(&provider.id).expect("validated above").command).1;

    let (axe_source, axe_source_label) = load_axe_source(&executor.root);
    let axe_expression = axe_expression(Some(&axe_source), "");
    let ctx = Ctx {
        tool: &*tool,
        provider,
        input,
        plan_digest: &plan_digest,
        params: &params,
        axe_expression,
        base_args: &base_args,
        environment: &environment,
        allowlist: &allowlist,
        work_dir: &work_dir,
        shot_dir: &shot_dir,
        roots: &roots,
        cancellation: &cancellation,
    };
    let mut outcomes = Vec::new();
    for (index, (label, url)) in params.all_surfaces().iter().enumerate() {
        outcomes.push(capture_surface(&ctx, index, label, url).await);
    }
    assemble(provider, input, &params, outcomes, &axe_source_label)
}

fn assemble(
    provider: &AuditProvider,
    input: &LegacyCheckInput,
    params: &RuntimeParams,
    mut outcomes: Vec<SurfaceOutcome>,
    axe_source: &str,
) -> Result<ProviderResult, AuditError> {
    let provider_id =
        ProviderId::new(&provider.id).map_err(|error| AuditError::Provider(error.to_string()))?;
    let expected_surfaces = outcomes.len();
    let captured = outcomes
        .iter()
        .filter(|outcome| outcome.status == "captured")
        .count();

    // Findings: console errors and exceptions of captured surfaces. Locations
    // must lie inside the frozen denominator, so they point at its first entry;
    // the surface and URL are in the message and in `details.runtime`.
    let mut output = empty_output(Vec::new());
    let location = safe_location(input, "");
    let mut seen = BTreeSet::new();
    let mut console_total = 0_usize;
    let a11y_observed_total: u64 = outcomes
        .iter()
        .map(|outcome| {
            outcome
                .accessibility
                .get("totalViolations")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        })
        .sum();
    for outcome in outcomes.iter().filter(|o| o.status == "captured") {
        console_total += outcome.console_errors.len() + outcome.console_warnings.len();
        for entry in &outcome.console_errors {
            let digest = hex::encode(Sha256::digest(entry.as_bytes()));
            let key = (outcome.index, digest.clone());
            if !seen.insert(key) {
                continue;
            }
            let rule = format!("runtime.console-error:{}:{}", outcome.index, &digest[..12]);
            let message = format!("{} ({}): {}", outcome.label, outcome.url, entry);
            push_runtime_finding(
                &mut output,
                &rule,
                "warning",
                &location,
                1,
                &message,
                outcome,
            );
        }
        if let Some(violations) = outcome
            .accessibility
            .get("violations")
            .and_then(Value::as_array)
        {
            for violation in violations {
                let id = violation
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let impact = violation
                    .get("impact")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let help = violation
                    .get("help")
                    .and_then(Value::as_str)
                    .unwrap_or("axe violation");
                let target = violation
                    .get("target")
                    .and_then(Value::as_str)
                    .unwrap_or("document");
                let count = violation.get("count").and_then(Value::as_u64).unwrap_or(1);
                let help_url = violation
                    .get("helpUrl")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let rule = format!("runtime.a11y:{id}:{}", outcome.index);
                let message = format!(
                    "{} ({}): {id} [{impact}] {help}; target {target}; {count} node(s){}",
                    outcome.label,
                    outcome.url,
                    if help_url.is_empty() {
                        String::new()
                    } else {
                        format!("; {help_url}")
                    }
                );
                let severity = if matches!(impact, "critical" | "serious") {
                    "error"
                } else {
                    "warning"
                };
                push_runtime_finding(
                    &mut output,
                    &rule,
                    severity,
                    &location,
                    1,
                    &message,
                    outcome,
                );
            }
        }
    }
    let findings = std::mem::take(&mut output.findings);
    let mut details: BTreeMap<String, Value> = std::mem::take(&mut output.details);

    let mut gaps: Vec<String> = Vec::new();
    for label in &params.unsupported {
        gaps.push(format!("runtime-surface-unsupported:{label}"));
    }
    for outcome in &mut outcomes {
        if outcome.performance.is_none() {
            outcome.gaps.push(format!(
                "runtime-performance-not-captured:{}",
                outcome.label
            ));
        }
    }
    for outcome in &outcomes {
        gaps.extend(outcome.gaps.iter().cloned());
    }
    let mut degradation: Vec<String> = Vec::new();
    for outcome in &outcomes {
        if outcome.status != "captured" || !outcome.receipt_complete {
            degradation.push(format!(
                "external-process:{}:{}",
                outcome.label, outcome.process_state
            ));
        }
    }
    let unavailable_reason = if captured == 0 {
        outcomes
            .iter()
            .find_map(|outcome| outcome.unavailable.clone())
    } else {
        None
    };
    gaps.sort();
    gaps.dedup();
    degradation.sort();
    degradation.dedup();

    let all_captured = captured == expected_surfaces && expected_surfaces > 0;
    let all_a11y_ran = outcomes
        .iter()
        .all(|o| o.accessibility.get("status").and_then(Value::as_str) == Some("ran"));
    let a11y_total = all_a11y_ran.then_some(a11y_observed_total);
    let any_a11y_ran = outcomes
        .iter()
        .any(|o| o.accessibility.get("status").and_then(Value::as_str) == Some("ran"));
    let any_a11y_error = outcomes
        .iter()
        .any(|o| o.accessibility.get("status").and_then(Value::as_str) == Some("error"));
    let a11y_status = if all_a11y_ran {
        "ran"
    } else if any_a11y_ran {
        "partial"
    } else if any_a11y_error {
        "error"
    } else {
        "unavailable"
    };
    let expected = input.denominator.entries.len() as u64;
    let status = if captured > 0 || unavailable_reason.is_some() {
        ProviderStatus::Partial
    } else {
        ProviderStatus::Failed
    };

    let surfaces_json: Vec<Value> = outcomes
        .iter()
        .map(|outcome| {
            json!({
                "index": outcome.index,
                "label": outcome.label,
                "url": outcome.url,
                "viewport": {"width": params.width, "height": params.height},
                "status": outcome.status,
                "screenshot": outcome.screenshot,
                "performance": outcome.performance.clone().unwrap_or(Value::Null),
                "accessibility": outcome.accessibility,
                "consoleErrors": outcome.console_errors,
                "consoleWarnings": outcome.console_warnings,
                "gaps": outcome.gaps,
                "failure": outcome.failure,
                "receiptId": outcome.receipt.get("receiptId"),
                "processState": outcome.process_state,
                "exitCode": outcome.exit_code,
            })
        })
        .collect();
    details.insert(
        "runtime".to_owned(),
        json!({
            "schemaVersion": 1,
            "kind": "audit-runtime",
            "source": "legion script qa/qa-functional",
            "url": params.url,
            "viewport": {"width": params.width, "height": params.height},
            "status": "unproven",
            "complete": false,
            "incomplete": true,
            "surfaces": surfaces_json,
            "unsupportedSurfaces": params.unsupported,
            "denominator": {
                "kind": "runtime-surfaces",
                "expected": expected_surfaces + params.unsupported.len(),
                "examined": captured,
            },
            "console_total": console_total,
            "a11y_axe": a11y_status,
            "axeCoreSource": axe_source,
            "a11y_violations_total": a11y_total,
            "a11y_violations_observed_total": a11y_observed_total,
            "coverageGaps": gaps,
            "degradation": degradation,
        }),
    );
    let representative = outcomes
        .iter()
        .find(|outcome| !outcome.receipt_complete)
        .or_else(|| outcomes.first());
    if let Some(outcome) = representative {
        details.insert("executionReceipt".to_owned(), outcome.receipt.clone());
        if let Some(id) = outcome.receipt.get("receiptId").and_then(Value::as_str) {
            details.insert("receiptId".to_owned(), Value::String(id.to_owned()));
        }
    }
    details.insert(
        "executionReceipts".to_owned(),
        Value::Array(outcomes.iter().map(|o| o.receipt.clone()).collect()),
    );
    details.insert("check".to_owned(), Value::String("runtime".into()));
    details.insert("tool".to_owned(), Value::String("audit-runtime.mjs".into()));
    details.insert("commandShape".to_owned(), Value::String("named".into()));
    details.insert("candidates".to_owned(), Value::Array(Vec::new()));
    let process_state = outcomes
        .iter()
        .find(|outcome| outcome.process_state != "completed")
        .map(|outcome| outcome.process_state.clone())
        .unwrap_or_else(|| "completed".to_owned());
    details.insert("processState".to_owned(), Value::String(process_state));
    details.insert(
        "exitCode".to_owned(),
        outcomes
            .first()
            .and_then(|outcome| outcome.exit_code)
            .map(Value::from)
            .unwrap_or(Value::Null),
    );

    let mut result = ProviderResult {
        schema_version: 1,
        provider: provider_id,
        applicable: true,
        required: provider.required,
        status,
        complete: false,
        coverage: Some(Coverage {
            denominator_digest: input.denominator.digest.clone(),
            expected,
            examined: if all_captured { expected } else { 0 },
            gaps: gaps.clone(),
        }),
        findings,
        coverage_gaps: gaps,
        degradation,
        details,
    };
    if let Some(reason) = &unavailable_reason {
        availability::mark_unavailable(&mut result, reason);
    }
    result
        .validate()
        .map_err(|error| AuditError::Provider(error.to_string()))?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_without_url_are_not_supplied() {
        assert_eq!(RuntimeParams::from_value(&Value::Null), Ok(None));
        assert_eq!(RuntimeParams::from_value(&json!({})), Ok(None));
        assert_eq!(RuntimeParams::from_value(&json!({"url": "  "})), Ok(None));
    }

    #[test]
    fn params_validate_url_viewport_and_surfaces() {
        let params = RuntimeParams::from_value(&json!({
            "url": "http://127.0.0.1:1422/?qa=1",
            "width": 390,
            "height": 844,
            "surfaces": [{"label": "settings", "url": "http://127.0.0.1:1422/settings"}],
            "unsupportedSurfaces": ["editor"],
        }))
        .unwrap()
        .unwrap();
        assert_eq!(params.width, 390);
        assert_eq!(params.height, 844);
        assert_eq!(
            params.all_surfaces(),
            vec![
                ("entry".to_owned(), "http://127.0.0.1:1422/?qa=1".to_owned()),
                (
                    "settings".to_owned(),
                    "http://127.0.0.1:1422/settings".to_owned()
                ),
            ]
        );
        assert_eq!(params.unsupported, vec!["editor".to_owned()]);
        // Defaults when the viewport is absent.
        let defaults = RuntimeParams::from_value(&json!({"url": "https://example.test/"}))
            .unwrap()
            .unwrap();
        assert_eq!((defaults.width, defaults.height), (1280, 800));
    }

    #[test]
    fn params_reject_invalid_inputs() {
        for (value, reason) in [
            (json!({"url": "file:///etc/passwd"}), "url-scheme-not-http"),
            (json!({"url": "http://"}), "url-malformed"),
            (json!({"url": "http://a b/"}), "url-malformed"),
            (json!({"url": "http://a/", "width": 0}), "width-invalid"),
            (
                json!({"url": "http://a/", "height": 99999}),
                "height-invalid",
            ),
            (
                json!({"url": "http://a/", "artifactDir": "relative/dir"}),
                "artifact-dir-not-absolute",
            ),
            (
                json!({"url": "http://a/", "surfaces": [{"label": "x", "url": "javascript:1"}]}),
                "url-scheme-not-http",
            ),
        ] {
            assert_eq!(
                RuntimeParams::from_value(&value),
                Err(reason.to_owned()),
                "{value}"
            );
        }
    }

    #[test]
    fn runtime_inputs_round_trip_through_the_validator() {
        let value = runtime_inputs(
            "http://127.0.0.1:3000/",
            &[("a".to_owned(), "http://127.0.0.1:3000/a".to_owned())],
            &["click-only".to_owned()],
            800,
            600,
            None,
        )
        .unwrap();
        let params = RuntimeParams::from_value(&value).unwrap().unwrap();
        assert_eq!(params.to_value(), value);
        assert!(runtime_inputs("ftp://x/", &[], &[], 800, 600, None).is_err());
        assert!(runtime_inputs("", &[], &[], 800, 600, None).is_err());
    }

    #[test]
    fn qa_output_is_parsed_into_screenshot_console_and_gaps() {
        let text = "[qa] 1:eval ok\n[qa] screenshot /tmp/a/shot.png\n[qa] 2:screenshot ok\n\
[qa] actions complete /tmp/a/actions.json\n[qa] 3 console error/warning(s) \u{2014} see /tmp/a/.cache/qa-console.log\n\
[qa]   console.error: \"boom\"\n[qa]   console.warning: \"careful\"\n[qa]   exception: Uncaught\n\
[qa] gap network-throttle-not-applied\n[qa] gaps: network-throttle-not-applied\n";
        let qa = parse_qa_output(text);
        assert_eq!(qa.screenshot.as_deref(), Some("/tmp/a/shot.png"));
        assert!(qa.actions_complete);
        assert!(!qa.no_console_issues);
        assert_eq!(qa.console_total, Some(3));
        assert_eq!(
            qa.console_entries,
            vec![
                "console.error: \"boom\"".to_owned(),
                "console.warning: \"careful\"".to_owned(),
                "exception: Uncaught".to_owned(),
            ]
        );
        assert_eq!(qa.gaps, vec!["network-throttle-not-applied".to_owned()]);
        assert!(is_console_warning(&qa.console_entries[1]));
        assert!(!is_console_warning(&qa.console_entries[0]));

        let clean = parse_qa_output(
            "[qa] screenshot /s.png\n[qa] actions complete /a.json\n[qa] no console errors or warnings\n",
        );
        assert!(clean.no_console_issues);
        assert_eq!(clean.console_total, None);
        assert!(clean.console_entries.is_empty());
    }

    #[test]
    fn failures_are_classified_from_the_routes_messages() {
        let (unavailable, gap) =
            classify_failure("entry", "failed", "[qa] No Chrome/Edge executable found.");
        assert_eq!(unavailable.as_deref(), Some("browser-not-found"));
        assert_eq!(gap, "runtime-browser-not-found:entry");
        let (unavailable, gap) = classify_failure(
            "entry",
            "failed",
            "[qa] 1:eval eval returned not ok: {\"ok\":false}",
        );
        assert_eq!(unavailable, None);
        assert_eq!(gap, "runtime-surface-load-failed:entry");
        let (unavailable, gap) = classify_failure("s", "timeout", "");
        assert_eq!(unavailable, None);
        assert_eq!(gap, "runtime-surface-capture-failed:s:timeout");
    }

    #[test]
    fn eval_value_lines_must_start_with_the_action_label() {
        assert_eq!(eval_value_line("3:eval value {}"), Some((3, "{}")));
        assert_eq!(eval_value_line("3:eval ok"), None);
        assert_eq!(eval_value_line(":eval value {}"), None);
        assert_eq!(eval_value_line("console.log: 3:eval value {}"), None);
    }

    #[test]
    fn performance_is_read_only_from_lines_printed_before_actions_complete() {
        let text = "[qa] 1:eval value {\"ok\":true}\n\
[qa] 3:eval value {\"domContentLoaded\":10,\"ttfb\":null}\n\
[qa] actions complete /a.json\n\
[qa] 2 console error/warning(s) \u{2014} see x\n\
[qa]   console.error: a [qa] 3:eval value {\"forged\":1}\n\
[qa] 3:eval value {\"domContentLoaded\":999}\n";
        let qa = parse_qa_output(text);
        let found: Vec<&str> = qa
            .eval_values
            .iter()
            .filter(|(index, _)| *index == PERFORMANCE_ACTION_LABEL)
            .map(|(_, json)| json.as_str())
            .collect();
        assert_eq!(found, vec!["{\"domContentLoaded\":10,\"ttfb\":null}"]);
        let metrics = parse_performance(found[0]).unwrap();
        assert_eq!(metrics["domContentLoaded"], 10);
        assert!(metrics["ttfb"].is_null());
    }

    #[test]
    fn performance_rejects_anything_but_a_metric_object() {
        for json in [
            "{not json",
            "[1,2]",
            "null",
            "\"text\"",
            "{}",
            "{\"truncated\":true,\"bytes\":70002}",
            "{\"ttfb\":\"slow\"}",
        ] {
            assert_eq!(parse_performance(json), None, "{json}");
        }
        assert!(parse_performance(
            "{\"ttfb\":12.5,\"resourceCount\":3,\"firstContentfulPaint\":null}"
        )
        .is_some());
    }

    #[test]
    fn axe_expression_separates_project_source_from_wrapper_after_line_comment() {
        let expression = axe_expression(Some("window.axe = {}; // project override"), "");
        assert!(expression.contains("// project override\n;const r="));
    }

    #[test]
    fn malformed_and_oversized_axe_results_never_become_clean() {
        for (raw, reason) in [
            ("{not json", "axe-result-malformed"),
            ("{\"status\":\"ran\"}", "axe-violations-not-an-array"),
            (
                "{\"status\":\"ran\",\"violations\":[],\"totalViolations\":1,\"truncated\":false}",
                "axe-total-inconsistent",
            ),
        ] {
            let parsed = parse_accessibility_result(raw);
            assert_eq!(parsed["status"], "error", "{raw}");
            assert_eq!(parsed["reason"], reason, "{raw}");
        }
        let oversized = parse_accessibility_result("{\"truncated\":true,\"bytes\":70002}");
        assert_eq!(oversized["status"], "error");
        assert_eq!(oversized["reason"], "axe-result-truncated");
        assert_eq!(oversized["reportedBytes"], 70002);
    }
}
