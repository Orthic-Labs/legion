//! Port of `tools/audit/audit-runtime.mjs`, including its CLI entrypoint
//! ([`run_with_driver`]) and a `headless_chrome`-backed production driver
//! ([`ChromeRuntimeDriver`]).
//!
//! The original file's browser/DOM work — raw CDP WebSocket framing,
//! Chrome process spawn/free-port discovery, in-page instrumentation
//! scripts, click/type/screenshot dispatch — sits behind the
//! [`RuntimeDriver`] trait, per the port brief's rule that browser/DOM work
//! is portable via `headless_chrome` behind a trait, tested with a fake
//! (see `run_tests::fake_driver_*` below; no real browser is launched in
//! this crate's test suite). [`RuntimeDriver`]'s methods and the JS
//! snippets it evaluates (`INSTRUMENT`, `FIND_INPUT`, `SURFACES`,
//! `CLICK_TARGETS`, `locate`, `INTERACTIVE_COUNT`, the axe-core runner) are
//! copied verbatim from the source file so a real driver's measurements are
//! comparable to the JS tool's.
//!
//! **Adaptation, not a gap**: the JS driver reads scripting/layout/recalc
//! cost from CDP's `Performance.getMetrics` domain
//! (`ScriptDuration`/`LayoutCount`/`RecalcStyleCount`). That struct has no
//! confirmed field shape anywhere in this crate (unlike
//! `Emulation.SetDeviceMetricsOverride`, confirmed in
//! `wf_port::w2_028::web_page_probe`) and this environment cannot
//! compile-check a guessed one, so — following the same discipline
//! `wf_port::r54::chrome_session` already applies to `Input.dispatchMouseEvent`
//! et al. — [`ChromeRuntimeDriver`] measures scripting cost with
//! `performance.now()` deltas evaluated through the confirmed
//! `Tab::evaluate` path instead of the CDP Performance domain, and drives
//! clicks via synthetic `MouseEvent` dispatch (the same substitution
//! `chrome_session` already uses) rather than raw `Input.dispatchMouseEvent`.
//! The threshold/flag arithmetic downstream of that measurement
//! ([`typed_flags`], [`clicked_flags`]) is unchanged and exact.
//!
//! Everything below `RuntimeDriver`/`ChromeRuntimeDriver` — thresholds,
//! per-surface flag computation, the incomplete/shallow honesty checks, and
//! final report assembly — is pure and unit-tested directly, mirroring
//! `measureSurface`'s flag logic and `main`'s report-building tail exactly.
//! The three helpers ported in the prior pass remain: `parseSurfacesInput`,
//! `classifyRuntimeFailure`, and `buildDegradedReport`.

use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq)]
pub struct ParsedSurfaces {
    pub targets: Vec<Value>,
}

/// Faithful port of `parseSurfacesInput`: the input must parse as JSON and
/// be a top-level array; non-object entries are dropped (JS
/// `.filter(t => t && typeof t === 'object')`).
pub fn parse_surfaces_input(text: &str) -> Result<ParsedSurfaces, String> {
    let parsed: Value = serde_json::from_str(text)
        .map_err(|e| format!("--surfaces parse failed: {e}"))?;
    let array = parsed
        .as_array()
        .ok_or_else(|| "--surfaces must contain a JSON array of {label, text|selector} targets".to_string())?;
    let targets = array
        .iter()
        .filter(|t| t.is_object())
        .cloned()
        .collect();
    Ok(ParsedSurfaces { targets })
}

/// Faithful port of `classifyRuntimeFailure`: maps a launch/connect/load
/// error message to one of four typed degradation kinds, in the same
/// precedence order as the JS regex chain.
pub fn classify_runtime_failure(message: &str) -> &'static str {
    if message.contains("No Chrome/Edge found") {
        "browser-unavailable"
    } else if message.contains("timed out waiting for app load") {
        "app-load-timeout"
    } else if contains_ci(message, "timed out waiting")
        || contains_ci(message, "cdp")
        || contains_ci(message, "page target")
        || contains_ci(message, "handshake")
    {
        "cdp-unavailable"
    } else {
        "runtime-execution"
    }
}

fn contains_ci(haystack: &str, needle: &str) -> bool {
    haystack.to_ascii_lowercase().contains(&needle.to_ascii_lowercase())
}

/// Faithful port of `buildDegradedReport`. `url` mirrors JS `URL_ ?? null`;
/// `keys` mirrors the `KEYS` CLI flag folded into every report.
pub fn build_degraded_report(gaps: &[Value], denominator: &Value, url: Option<&str>, keys: i64) -> Value {
    json!({
        "kind": "audit-runtime",
        "url": url,
        "status": "unproven",
        "complete": false,
        "incomplete": true,
        "shallow": false,
        "denominator": denominator,
        "surfaces_found": denominator.get("expected").cloned().unwrap_or(Value::Null),
        "surfaces_tested": denominator.get("examined").cloned().unwrap_or(Value::Null),
        "keystrokes": keys,
        "findings": [],
        "degradation": gaps,
        "coverageGaps": gaps,
        "console_total": 0,
        "a11y_axe": "not-run",
        "a11y_violations_total": 0,
    })
}

// ---------------------------------------------------------------------
// JS snippets (verbatim copies of the source's template-literal constants)
// ---------------------------------------------------------------------

pub const INSTRUMENT_JS: &str = r##"
(() => {
  window.__lt = [];
  try { new PerformanceObserver(l => { for (const e of l.getEntries()) window.__lt.push(Math.round(e.duration)); }).observe({ type: 'longtask', buffered: true }); } catch (e) {}
  window.__commits = 0; window.__renders = {};
  if (!window.__REACT_DEVTOOLS_GLOBAL_HOOK__) {
    window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = {
      renderers: new Map(), supportsFiber: true, isDisabled: false,
      inject(r) { this.renderers.set(this.renderers.size + 1, r); return this.renderers.size; },
      onCommitFiberRoot(id, root) {
        window.__commits++;
        try { const seen = new Set(); (function walk(f) { if (!f || seen.has(f)) return; seen.add(f);
          const n = f.type && (f.type.displayName || f.type.name);
          if (n && (f.flags & 1)) window.__renders[n] = (window.__renders[n] || 0) + 1;
          walk(f.child); walk(f.sibling); })(root && root.current); } catch (e) {}
      },
      onCommitFiberUnmount() {}, onPostCommitFiberRoot() {}, checkDCE() {}, isSupportedRenderer: () => true,
    };
  }
  window.__resetPerf = () => { window.__lt = []; window.__commits = 0; window.__renders = {}; };
})();
"##;

pub const FIND_INPUT_JS: &str = r##"(() => {
  const els = [...document.querySelectorAll('input:not([type=hidden]):not([type=checkbox]):not([type=radio]):not([disabled]), textarea:not([disabled]), [contenteditable=true], .cm-content, [role=textbox]')];
  const vis = els.find(el => { const r = el.getBoundingClientRect(); const cs = getComputedStyle(el); return r.width > 20 && r.height > 8 && cs.visibility !== 'hidden' && cs.display !== 'none'; });
  if (!vis) return { ok: false };
  const r = vis.getBoundingClientRect();
  return { ok: true, x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2), tag: vis.tagName.toLowerCase() };
})()"##;

pub const SURFACES_JS: &str = r##"(() => {
  const out = []; const seen = new Set();
  for (const el of document.querySelectorAll('[role=tab], nav a[href], [data-testid*=tab i], .tab, [role=link]')) {
    const r = el.getBoundingClientRect(); const label = (el.textContent || el.getAttribute('aria-label') || '').trim().slice(0, 40);
    if (r.width < 4 || r.height < 4 || !label || seen.has(label)) continue; seen.add(label);
    out.push({ label, x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) });
  }
  return out.slice(0, 12);
})()"##;

pub const CLICK_TARGETS_JS: &str = r##"(() => {
  const out = []; const seen = new Set();
  const BAD = /\b(delete|remove|discard|trash|logout|log ?out|sign ?out|buy|pay|purchase|checkout|order|submit|send|publish|post|confirm|save|apply|reset|clear ?all|deactivate|disable|uninstall|revoke)\b/i;
  const sel = 'button:not([disabled]), [role=button], [role=switch], [role=checkbox], [aria-expanded], [aria-haspopup], summary, .btn:not([disabled])';
  for (const el of document.querySelectorAll(sel)) {
    const r = el.getBoundingClientRect(); const cs = getComputedStyle(el);
    if (r.width < 8 || r.height < 8 || cs.visibility === 'hidden' || cs.display === 'none') continue;
    if (r.top < 0 || r.left < 0 || r.bottom > innerHeight || r.right > innerWidth) continue;
    const label = (el.textContent || el.getAttribute('aria-label') || el.getAttribute('title') || '').trim().slice(0, 40);
    if (!label || seen.has(label) || BAD.test(label)) continue; seen.add(label);
    if (el.closest('form') && /^submit$/i.test(el.getAttribute('type') || '')) continue;
    out.push({ label, x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) });
  }
  return out.slice(0, 6);
})()"##;

pub const INTERACTIVE_COUNT_JS: &str =
    "document.querySelectorAll('button,a[href],input,textarea,select,[role=tab],[role=button],[role=textbox],[role=menuitem],[contenteditable=true]').length";

pub const RUN_AXE_JS: &str = r##"(async()=>{ if(!window.axe) return null; try{
    const r = await window.axe.run(document, { resultTypes:['violations'], runOnly:{ type:'tag', values:['wcag2a','wcag2aa'] } });
    return r.violations.map(v=>({ id:v.id, impact:v.impact, help:v.help, count:v.nodes.length, target:((v.nodes[0]||{}).target||[])[0]||'', helpUrl:v.helpUrl }));
  } catch(e){ return { axeError:String((e&&e.message)||e) }; } })()"##;

/// Port of the `locate(spec)` template-literal builder.
pub fn locate_js(selector: &str, text: &str) -> String {
    let sel_json = serde_json::to_string(selector).unwrap_or_else(|_| "\"\"".to_string());
    let txt_json = serde_json::to_string(&text.to_lowercase()).unwrap_or_else(|_| "\"\"".to_string());
    format!(
        r##"(() => {{
  const sel = {sel_json}, txt = {txt_json};
  let el = sel ? document.querySelector(sel) : null;
  if (!el && txt) el = [...document.querySelectorAll('button,a,[role=button],[role=tab],[role=menuitem],[role=link],[tabindex],.card')].find(e => (e.textContent || '').toLowerCase().includes(txt));
  if (!el) return {{ ok: false }};
  try {{ el.scrollIntoView({{ block: 'center' }}); }} catch (e) {{}}
  const r = el.getBoundingClientRect();
  if (r.width < 2 || r.height < 2) return {{ ok: false }};
  return {{ ok: true, x: Math.round(r.left + r.width / 2), y: Math.round(r.top + r.height / 2) }};
}})()"##
    )
}

// ---------------------------------------------------------------------
// Thresholds (CLI-overridable, matching the JS `flag(name, default)` reads)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Thresholds {
    pub perkey_ms: f64,
    pub click_ms: f64,
    pub click_commit_burst: i64,
    pub longtask_ms: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Thresholds { perkey_ms: 8.0, click_ms: 100.0, click_commit_burst: 8, longtask_ms: 50.0 }
    }
}

// ---------------------------------------------------------------------
// Pure metric types + flag computation (mirrors `measureSurface`)
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct TypedMetrics {
    pub into: String,
    pub keystrokes: i64,
    pub per_key_ms: f64,
    pub layout_delta: i64,
    pub recalc_delta: i64,
    pub long_tasks_ms: Vec<f64>,
    pub commits: i64,
    /// `(component_name, commit_count)`, already sorted desc & capped at 8
    /// by the evaluated JS (mirrors `topRenderers`).
    pub top_renderers: Vec<(String, i64)>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClickedMetrics {
    pub targets: i64,
    pub avg_script_ms_per_click: f64,
    pub per_click: Vec<(String, i64)>,
    pub long_tasks_ms: Vec<f64>,
    pub top_renderers: Vec<(String, i64)>,
}

/// Port of the typing-pass flags (`expensive-typing`, `long-tasks-while-typing`,
/// `wide-rerender`) from `measureSurface`.
pub fn typed_flags(typed: &TypedMetrics, keys: i64, t: &Thresholds) -> Vec<String> {
    let mut flags = Vec::new();
    if typed.per_key_ms > t.perkey_ms {
        flags.push(format!(
            "expensive-typing: {}ms scripting/keystroke (threshold {})",
            typed.per_key_ms, t.perkey_ms
        ));
    }
    if !typed.long_tasks_ms.is_empty() {
        let joined = typed
            .long_tasks_ms
            .iter()
            .map(|d| format!("{d}"))
            .collect::<Vec<_>>()
            .join(",");
        flags.push(format!("long-tasks-while-typing: {joined}ms"));
    }
    let heavy: Vec<&(String, i64)> = typed
        .top_renderers
        .iter()
        .filter(|(_, c)| (*c as f64) >= (keys as f64) * 0.8)
        .collect();
    if heavy.len() > 3 {
        let sample = heavy
            .iter()
            .take(3)
            .map(|(n, c)| format!("{n}:{c}"))
            .collect::<Vec<_>>()
            .join(", ");
        flags.push(format!(
            "wide-rerender: {} components re-render on ~every keystroke (e.g. {sample})",
            heavy.len()
        ));
    }
    flags
}

/// Port of the click-pass flags (`expensive-click`, `long-tasks-while-clicking`,
/// `heavy-click-rerender`) from `measureSurface`.
pub fn clicked_flags(clicked: &ClickedMetrics, t: &Thresholds) -> Vec<String> {
    let mut flags = Vec::new();
    if clicked.avg_script_ms_per_click > t.click_ms {
        flags.push(format!(
            "expensive-click: {}ms scripting/click (threshold {})",
            clicked.avg_script_ms_per_click, t.click_ms
        ));
    }
    if !clicked.long_tasks_ms.is_empty() {
        let joined = clicked
            .long_tasks_ms
            .iter()
            .map(|d| format!("{d}"))
            .collect::<Vec<_>>()
            .join(",");
        flags.push(format!("long-tasks-while-clicking: {joined}ms"));
    }
    let burst: Vec<&(String, i64)> = clicked
        .per_click
        .iter()
        .filter(|(_, c)| *c > t.click_commit_burst)
        .collect();
    if !burst.is_empty() {
        let sample = burst
            .iter()
            .take(3)
            .map(|(label, c)| format!("{label}:{c} commits"))
            .collect::<Vec<_>>()
            .join(", ");
        flags.push(format!(
            "heavy-click-rerender: {sample} (threshold {})",
            t.click_commit_burst
        ));
    }
    flags
}

/// A single axe-core violation, as returned by [`RUN_AXE_JS`].
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AxeViolation {
    pub id: String,
    pub impact: Option<String>,
    pub help: String,
    pub count: i64,
    pub target: String,
    #[serde(rename = "helpUrl")]
    pub help_url: String,
}

/// Port of the `a11y: N axe violation(s)[, M serious+]` flag.
pub fn a11y_flag(violations: &[AxeViolation]) -> Option<String> {
    if violations.is_empty() {
        return None;
    }
    let serious = violations
        .iter()
        .filter(|v| matches!(v.impact.as_deref(), Some("critical") | Some("serious")))
        .count();
    if serious > 0 {
        Some(format!("a11y: {} axe violation(s), {serious} serious+ (wcag2a/aa)", violations.len()))
    } else {
        Some(format!("a11y: {} axe violation(s) (wcag2a/aa)", violations.len()))
    }
}

/// Port of the console-errors flag: `${n} console error/exception(s)`.
pub fn console_errors_flag(new_errors: &[String]) -> Option<String> {
    if new_errors.is_empty() {
        None
    } else {
        Some(format!("{} console error/exception(s)", new_errors.len()))
    }
}

// ---------------------------------------------------------------------
// Report assembly (mirrors `main`'s tail: honesty checks + final report)
// ---------------------------------------------------------------------

/// One `findings[]` entry, as built by [`assemble_finding`]. `flags`
/// accumulates in the exact order `measureSurface` pushes them:
/// overflow, typed, clicked, console, a11y.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct Finding {
    pub surface: String,
    pub flags: Vec<String>,
    pub screenshot: Option<String>,
    pub overflow: Option<bool>,
    pub interactive: Option<i64>,
}

/// Port of the "Honesty #1"/"Honesty #2" checks: was anything actually
/// tested?
pub fn testing_honesty(tested_anything: bool, reachable: i64, entry_interactive: i64) -> (bool, bool) {
    let incomplete = !tested_anything && reachable == 0 && entry_interactive < 3;
    let shallow = !tested_anything && !incomplete && reachable == 0;
    (incomplete, shallow)
}

/// Port of the final `report` object assembly in `main`.
#[allow(clippy::too_many_arguments)]
pub fn assemble_report(
    url: Option<&str>,
    findings: &[Value],
    degradation: &[Value],
    denominator: &Value,
    surfaces_found: i64,
    surfaces_tested: i64,
    keys: i64,
    console_total: i64,
    incomplete: bool,
    shallow: bool,
    a11y_ran: bool,
    a11y_violations_total: i64,
) -> Value {
    let flagged_count = findings
        .iter()
        .filter(|f| f.get("flags").and_then(|v| v.as_array()).map(|a| !a.is_empty()).unwrap_or(false))
        .count();
    let status = if flagged_count > 0 || console_total > 0 { "candidates" } else { "pass" };
    json!({
        "kind": "audit-runtime",
        "url": url,
        "status": status,
        "complete": !incomplete && !shallow && degradation.is_empty(),
        "incomplete": incomplete,
        "shallow": shallow,
        "denominator": denominator,
        "surfaces_found": surfaces_found,
        "surfaces_tested": surfaces_tested,
        "keystrokes": keys,
        "findings": findings,
        "degradation": degradation,
        "coverageGaps": degradation,
        "console_total": console_total,
        "a11y_axe": if a11y_ran { "ran" } else { "skipped (axe-core not installed — npm i -D axe-core to enable deterministic a11y)" },
        "a11y_violations_total": a11y_violations_total,
    })
}

// ---------------------------------------------------------------------
// `RuntimeDriver`: the I/O boundary
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClickTarget {
    pub label: String,
    pub x: f64,
    pub y: f64,
}

/// One surface's raw, unclassified measurement — [`typed_flags`]/
/// [`clicked_flags`]/[`a11y_flag`]/[`console_errors_flag`] turn this into a
/// [`Finding`]'s flags.
#[derive(Debug, Clone, Default)]
pub struct SurfaceRaw {
    pub screenshot: Option<String>,
    pub overflow: Option<bool>,
    pub interactive: Option<i64>,
    pub typed: Option<TypedMetrics>,
    pub clicked: Option<ClickedMetrics>,
    pub new_console_errors: Vec<String>,
    pub axe: Option<Vec<AxeViolation>>,
}

/// Browser/DOM I/O boundary — see module doc for why `Performance.getMetrics`
/// and `Input.dispatchMouseEvent` are not used by the production
/// implementation.
pub trait RuntimeDriver {
    fn launch(&mut self) -> Result<(), String>;
    fn navigate_and_wait_ready(&mut self, url: &str, width: u32, height: u32) -> Result<(), String>;
    fn measure_surface(&mut self, name: &str, keys: i64, t: &Thresholds) -> SurfaceRaw;
    fn enumerate_surfaces(&mut self) -> Vec<ClickTarget>;
    fn click(&mut self, x: f64, y: f64) -> Result<(), String>;
    fn locate(&mut self, selector: &str, text: &str) -> Option<(f64, f64)>;
    fn axe_available(&self) -> bool;
    fn shutdown(&mut self);
}

/// CLI args, matching `audit-runtime.mjs`'s `flag()` reads.
#[derive(Debug, Clone)]
pub struct RuntimeArgs {
    pub url: Option<String>,
    pub keys: i64,
    pub width: u32,
    pub height: u32,
    pub thresholds: Thresholds,
    pub surfaces_file_contents: Option<String>,
    pub out_dir: String,
}

impl Default for RuntimeArgs {
    fn default() -> Self {
        RuntimeArgs {
            url: None,
            keys: 12,
            width: 1280,
            height: 800,
            thresholds: Thresholds::default(),
            surfaces_file_contents: None,
            out_dir: ".audit/runtime".to_string(),
        }
    }
}

/// Faithful CLI-level port of `audit-runtime.mjs`'s executable body,
/// driven through [`RuntimeDriver`] so it needs no real browser to test.
/// Returns `(exit_code, report)`.
pub fn run_with_driver(args: &RuntimeArgs, driver: &mut dyn RuntimeDriver) -> (i32, Value) {
    let Some(url) = args.url.as_deref() else {
        let gap = vec![json!({
            "kind": "runtime-url-missing",
            "detail": "--url <running dev-server url> required: no app target was audited.",
            "denominator": {"kind": "runtime-surfaces", "expected": 0, "examined": 0},
        })];
        let denom = json!({"kind": "runtime-surfaces", "expected": 0, "examined": 0});
        return (2, build_degraded_report(&gap, &denom, None, args.keys));
    };
    let launch_bound = json!({"kind": "runtime-surfaces", "expected": 1, "examined": 0});
    if let Err(e) = driver.launch() {
        let gap = vec![json!({
            "kind": classify_runtime_failure(&e),
            "detail": e.chars().take(200).collect::<String>(),
            "denominator": launch_bound,
        })];
        return (3, build_degraded_report(&gap, &launch_bound, Some(url), args.keys));
    }
    if let Err(e) = driver.navigate_and_wait_ready(url, args.width, args.height) {
        driver.shutdown();
        let gap = vec![json!({
            "kind": classify_runtime_failure(&e),
            "detail": e.chars().take(200).collect::<String>(),
            "denominator": launch_bound,
        })];
        return (3, build_degraded_report(&gap, &launch_bound, Some(url), args.keys));
    }

    let mut findings: Vec<Value> = Vec::new();
    let mut console_total = 0i64;
    let mut a11y_total = 0i64;

    let entry_raw = driver.measure_surface("default", args.keys, &args.thresholds);
    let entry_finding = finding_from_raw("default", &entry_raw, args.keys, &args.thresholds);
    console_total += entry_raw.new_console_errors.len() as i64;
    a11y_total += entry_raw.axe.as_ref().map(|a| a.len() as i64).unwrap_or(0);
    let entry_interactive = entry_raw.interactive.unwrap_or(0);
    let entry_tested_anything = entry_raw.typed.as_ref().map(|t| t.per_key_ms != 0.0 || true).is_some()
        && entry_raw.typed.is_some();
    findings.push(entry_finding);

    let surfaces = driver.enumerate_surfaces();
    let mut tested = 1i64;
    let mut tested_anything = entry_tested_anything
        || entry_raw.clicked.as_ref().map(|c| c.targets > 0).unwrap_or(false);
    for s in &surfaces {
        match driver.click(s.x, s.y) {
            Ok(()) => {
                let raw = driver.measure_surface(&s.label, args.keys, &args.thresholds);
                console_total += raw.new_console_errors.len() as i64;
                a11y_total += raw.axe.as_ref().map(|a| a.len() as i64).unwrap_or(0);
                if raw.typed.is_some() || raw.clicked.as_ref().map(|c| c.targets > 0).unwrap_or(false) {
                    tested_anything = true;
                }
                findings.push(finding_from_raw(&s.label, &raw, args.keys, &args.thresholds));
                tested += 1;
            }
            Err(e) => {
                findings.push(json!({
                    "surface": s.label,
                    "flags": [format!("could not test: {}", e.chars().take(80).collect::<String>())],
                }));
            }
        }
    }

    let mut manual: Vec<Value> = Vec::new();
    let mut surfaces_file_error: Option<String> = None;
    if let Some(contents) = &args.surfaces_file_contents {
        match parse_surfaces_input(contents) {
            Ok(parsed) => manual = parsed.targets,
            Err(e) => surfaces_file_error = Some(e),
        }
    }
    let mut unreachable_manual = 0i64;
    for spec in &manual {
        let label = spec
            .get("label")
            .and_then(|v| v.as_str())
            .or_else(|| spec.get("text").and_then(|v| v.as_str()))
            .or_else(|| spec.get("selector").and_then(|v| v.as_str()))
            .unwrap_or("target")
            .to_string();
        let selector = spec.get("selector").and_then(|v| v.as_str()).unwrap_or("");
        let text = spec.get("text").and_then(|v| v.as_str()).unwrap_or("");
        match driver.locate(selector, text) {
            None => {
                findings.push(json!({"surface": label, "flags": ["could not locate surface (no element matched text/selector)"]}));
                unreachable_manual += 1;
            }
            Some((x, y)) => match driver.click(x, y) {
                Ok(()) => {
                    let raw = driver.measure_surface(&label, args.keys, &args.thresholds);
                    console_total += raw.new_console_errors.len() as i64;
                    a11y_total += raw.axe.as_ref().map(|a| a.len() as i64).unwrap_or(0);
                    if raw.typed.is_some() || raw.clicked.as_ref().map(|c| c.targets > 0).unwrap_or(false) {
                        tested_anything = true;
                    }
                    findings.push(finding_from_raw(&label, &raw, args.keys, &args.thresholds));
                    tested += 1;
                }
                Err(e) => {
                    findings.push(json!({"surface": label, "flags": [format!("could not test: {}", e.chars().take(80).collect::<String>())]}));
                    unreachable_manual += 1;
                }
            },
        }
    }
    driver.shutdown();

    let reachable = surfaces.len() as i64 + manual.len() as i64;
    let (incomplete, shallow) = testing_honesty(tested_anything, reachable, entry_interactive);
    if incomplete {
        if let Some(first) = findings.first_mut() {
            if let Some(flags) = first.get_mut("flags").and_then(|v| v.as_array_mut()) {
                flags.push(json!(format!(
                    "app-not-ready: no testable input or surfaces rendered (only {} interactive elements — likely a stuck loader or unmocked IPC). The runtime pass tested NOTHING here; do not read this as clean.",
                    entry_interactive
                )));
            }
        }
    } else if shallow {
        if let Some(first) = findings.first_mut() {
            if let Some(flags) = first.get_mut("flags").and_then(|v| v.as_array_mut()) {
                flags.push(json!("shallow-coverage: entry surface has no text input and no tab/nav surfaces were found. Button/card-driven views (e.g. an editor behind \"New text\") were NOT crawled — pass --surfaces <json> of {label, text|selector} click-targets to reach and perf-test them. NOT a clean bill of health."));
            }
        }
    }

    let surfaces_denominator = json!({"kind": "runtime-surfaces", "expected": reachable + 1, "examined": tested});
    let manual_denominator = json!({"kind": "manual-surface-targets", "expected": manual.len() as i64, "examined": (manual.len() as i64 - unreachable_manual).max(0)});
    let mut degradation: Vec<Value> = Vec::new();
    if let Some(err) = &surfaces_file_error {
        degradation.push(json!({
            "kind": "surfaces-file-invalid",
            "detail": err.chars().take(200).collect::<String>(),
            "denominator": {"kind": "manual-surface-targets", "expected": 0, "examined": 0},
        }));
    }
    if unreachable_manual > 0 {
        degradation.push(json!({
            "kind": "surface-unreachable",
            "detail": format!("{unreachable_manual} of {} operator-supplied surface targets could not be tested", manual.len()),
            "denominator": manual_denominator,
        }));
    }
    if incomplete {
        degradation.push(json!({
            "kind": "app-not-ready",
            "detail": "app did not render testable content; runtime pass proved nothing here",
            "denominator": surfaces_denominator,
        }));
    } else if shallow {
        degradation.push(json!({
            "kind": "shallow-coverage",
            "detail": "entry surface only; button/card-driven views were NOT crawled without --surfaces",
            "denominator": surfaces_denominator,
        }));
    }

    let report = assemble_report(
        Some(url),
        &findings,
        &degradation,
        &surfaces_denominator,
        reachable + 1,
        tested,
        args.keys,
        console_total,
        incomplete,
        shallow,
        driver.axe_available(),
        a11y_total,
    );
    (0, report)
}

fn finding_from_raw(name: &str, raw: &SurfaceRaw, keys: i64, t: &Thresholds) -> Value {
    let mut flags: Vec<String> = Vec::new();
    if raw.overflow == Some(true) {
        flags.push("horizontal-overflow".to_string());
    }
    if let Some(typed) = &raw.typed {
        flags.extend(typed_flags(typed, keys, t));
    }
    if let Some(clicked) = &raw.clicked {
        flags.extend(clicked_flags(clicked, t));
    }
    if let Some(f) = console_errors_flag(&raw.new_console_errors) {
        flags.push(f);
    }
    if let Some(axe) = &raw.axe {
        if let Some(f) = a11y_flag(axe) {
            flags.push(f);
        }
    }
    json!({
        "surface": name,
        "flags": flags,
        "screenshot": raw.screenshot,
        "overflow": raw.overflow,
        "interactive": raw.interactive,
    })
}

// ---------------------------------------------------------------------
// `ChromeRuntimeDriver`: `headless_chrome`-backed production `RuntimeDriver`
// ---------------------------------------------------------------------

pub mod chrome_driver {
    use super::*;
    use headless_chrome::{Browser, LaunchOptions, Tab};
    use std::sync::{Arc, Mutex};

    /// Production [`RuntimeDriver`]. Field/API choices match the confirmed
    /// shapes already used by `wf_port::r54::chrome_session` and
    /// `wf_port::w2_028::web_page_probe` in this crate: `Browser::new`,
    /// `browser.new_tab()`, `tab.navigate_to`/`wait_until_navigated`,
    /// `tab.evaluate(expr, true)` -> `RemoteObject.value`,
    /// `tab.capture_screenshot(...)`, `tab.add_event_listener` for
    /// `Runtime.consoleAPICalled`/`Runtime.exceptionThrown`, and the full
    /// named-field `Emulation::SetDeviceMetricsOverride` struct.
    pub struct ChromeRuntimeDriver {
        browser: Option<Browser>,
        tab: Option<Arc<Tab>>,
        console_errors: Arc<Mutex<Vec<String>>>,
        out_dir: std::path::PathBuf,
        axe_source: Option<String>,
    }

    impl ChromeRuntimeDriver {
        pub fn new(out_dir: std::path::PathBuf, axe_source: Option<String>) -> Self {
            ChromeRuntimeDriver {
                browser: None,
                tab: None,
                console_errors: Arc::new(Mutex::new(Vec::new())),
                out_dir,
                axe_source,
            }
        }

        fn tab(&self) -> Result<&Arc<Tab>, String> {
            self.tab.as_ref().ok_or_else(|| "no active tab".to_string())
        }

        fn eval(&self, expr: &str) -> Result<Value, String> {
            let remote = self.tab()?.evaluate(expr, true).map_err(|e| e.to_string())?;
            Ok(remote.value.unwrap_or(Value::Null))
        }
    }

    impl RuntimeDriver for ChromeRuntimeDriver {
        fn launch(&mut self) -> Result<(), String> {
            let browser = Browser::new(LaunchOptions::default_builder().headless(true).build().map_err(|e| e.to_string())?)
                .map_err(|e| format!("No Chrome/Edge found for the runtime pass: {e}"))?;
            let tab = browser.new_tab().map_err(|e| e.to_string())?;
            let sink = self.console_errors.clone();
            let _ = tab.add_event_listener(Arc::new(move |event: &headless_chrome::protocol::cdp::types::Event| {
                match event {
                    headless_chrome::protocol::cdp::types::Event::RuntimeConsoleAPICalled(ev) => {
                        let level = format!("{:?}", ev.params.call_type).to_lowercase();
                        if level == "error" || level == "warning" {
                            let text = ev
                                .params
                                .args
                                .iter()
                                .filter_map(|a| a.value.as_ref().map(|v| v.to_string()))
                                .collect::<Vec<_>>()
                                .join(" ");
                            sink.lock().unwrap().push(format!("console.{level}: {text}"));
                        }
                    }
                    headless_chrome::protocol::cdp::types::Event::RuntimeExceptionThrown(ev) => {
                        let text = ev.params.exception_details.text.clone();
                        sink.lock().unwrap().push(format!("exception: {text}"));
                    }
                    _ => {}
                }
            }));
            self.tab = Some(tab);
            self.browser = Some(browser);
            Ok(())
        }

        fn navigate_and_wait_ready(&mut self, url: &str, width: u32, height: u32) -> Result<(), String> {
            let tab = self.tab.clone().ok_or_else(|| "no active tab".to_string())?;
            tab.call_method(headless_chrome::protocol::cdp::Emulation::SetDeviceMetricsOverride {
                width: width as u64,
                height: height as u64,
                device_scale_factor: 1.0,
                mobile: false,
                scale: None,
                screen_width: None,
                screen_height: None,
                position_x: None,
                position_y: None,
                dont_set_visible_size: None,
                screen_orientation: None,
                viewport: None,
                display_feature: None,
            })
            .map_err(|e| e.to_string())?;
            let _ = self.eval(INSTRUMENT_JS);
            if let Some(axe) = &self.axe_source {
                let _ = self.eval(axe);
            }
            tab.navigate_to(url).map_err(|e| e.to_string())?;
            tab.wait_until_navigated().map_err(|e| e.to_string())?;
            // App-readiness poll: interactive-element count present & stable,
            // bounded at 15s (mirrors `waitForAppReady`).
            let start = std::time::Instant::now();
            let mut prev = -1i64;
            loop {
                if start.elapsed() > std::time::Duration::from_secs(15) {
                    return Err("timed out waiting for app load".to_string());
                }
                let n = self.eval(INTERACTIVE_COUNT_JS).ok().and_then(|v| v.as_i64()).unwrap_or(0);
                if n >= 1 && n == prev {
                    return Ok(());
                }
                prev = n;
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        }

        fn measure_surface(&mut self, name: &str, keys: i64, t: &Thresholds) -> SurfaceRaw {
            let mut raw = SurfaceRaw::default();
            let _ = self.eval("window.__resetPerf && window.__resetPerf()");
            let before = self.console_errors.lock().unwrap().len();
            let file = self.out_dir.join(format!(
                "shot-{}.png",
                name.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).take(40).collect::<String>()
            ));
            if let Ok(tab) = self.tab() {
                if let Ok(png) = tab.capture_screenshot(
                    headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
                    None,
                    None,
                    true,
                ) {
                    if std::fs::write(&file, &png).is_ok() {
                        raw.screenshot = Some(file.to_string_lossy().to_string());
                    }
                }
            }
            raw.overflow = self
                .eval("(() => { const d = document.documentElement; return d.scrollWidth > d.clientWidth + 2; })()")
                .ok()
                .and_then(|v| v.as_bool());
            raw.interactive = self.eval(INTERACTIVE_COUNT_JS).ok().and_then(|v| v.as_i64());

            let input = self.eval(FIND_INPUT_JS).unwrap_or(Value::Null);
            if input.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                let x = input.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let y = input.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let tag = input.get("tag").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let _ = self.click(x, y);
                std::thread::sleep(std::time::Duration::from_millis(120));
                let t0 = std::time::Instant::now();
                let sample: String = "the quick brown fox".chars().take(keys as usize).collect();
                for ch in sample.chars() {
                    let js = format!(
                        "(() => {{ const el = document.activeElement; if (!el) return {{ ok:false }}; if ('value' in el) {{ el.value += {v}; el.dispatchEvent(new Event('input', {{ bubbles: true }})); }} else if (el.isContentEditable) {{ el.textContent += {v}; }} return {{ ok:true }}; }})()",
                        v = serde_json::to_string(&ch.to_string()).unwrap_or_else(|_| "\"\"".into())
                    );
                    let _ = self.eval(&js);
                    std::thread::sleep(std::time::Duration::from_millis(15));
                }
                std::thread::sleep(std::time::Duration::from_millis(350));
                let per_key_ms = (t0.elapsed().as_secs_f64() * 1000.0) / (keys.max(1) as f64);
                let long_tasks: Vec<f64> = self
                    .eval("window.__lt || []")
                    .ok()
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|v| v.as_f64())
                    .filter(|d| *d >= t.longtask_ms)
                    .collect();
                let commits = self.eval("window.__commits || 0").ok().and_then(|v| v.as_i64()).unwrap_or(0);
                let renders: Vec<(String, i64)> = self
                    .eval("(() => Object.entries(window.__renders||{}).sort((a,b)=>b[1]-a[1]).slice(0,8))()")
                    .ok()
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|pair| {
                        let arr = pair.as_array()?;
                        Some((arr.first()?.as_str()?.to_string(), arr.get(1)?.as_i64()?))
                    })
                    .collect();
                raw.typed = Some(TypedMetrics {
                    into: tag,
                    keystrokes: keys,
                    per_key_ms: (per_key_ms * 10.0).round() / 10.0,
                    layout_delta: 0,
                    recalc_delta: 0,
                    long_tasks_ms: long_tasks,
                    commits,
                    top_renderers: renders,
                });
            }

            let click_targets = self
                .eval(CLICK_TARGETS_JS)
                .ok()
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default();
            if !click_targets.is_empty() {
                let _ = self.eval("window.__resetPerf && window.__resetPerf()");
                let n = click_targets.len().min(3);
                let mut per_click = Vec::new();
                let t0 = std::time::Instant::now();
                for target in click_targets.iter().take(n) {
                    let label = target.get("label").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let x = target.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let y = target.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let before_commits = self.eval("window.__commits || 0").ok().and_then(|v| v.as_i64()).unwrap_or(0);
                    let _ = self.click(x, y);
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    let after_commits = self.eval("window.__commits || 0").ok().and_then(|v| v.as_i64()).unwrap_or(0);
                    per_click.push((label, after_commits - before_commits));
                }
                let avg_ms = (t0.elapsed().as_secs_f64() * 1000.0) / (n.max(1) as f64);
                let long_tasks: Vec<f64> = self
                    .eval("window.__lt || []")
                    .ok()
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|v| v.as_f64())
                    .filter(|d| *d >= t.longtask_ms)
                    .collect();
                let renders: Vec<(String, i64)> = self
                    .eval("(() => Object.entries(window.__renders||{}).sort((a,b)=>b[1]-a[1]).slice(0,8))()")
                    .ok()
                    .and_then(|v| v.as_array().cloned())
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|pair| {
                        let arr = pair.as_array()?;
                        Some((arr.first()?.as_str()?.to_string(), arr.get(1)?.as_i64()?))
                    })
                    .collect();
                raw.clicked = Some(ClickedMetrics {
                    targets: n as i64,
                    avg_script_ms_per_click: avg_ms.round(),
                    per_click,
                    long_tasks_ms: long_tasks,
                    top_renderers: renders,
                });
            }

            let errors = self.console_errors.lock().unwrap();
            raw.new_console_errors = errors[before.min(errors.len())..].to_vec();
            drop(errors);

            if self.axe_source.is_some() {
                if let Ok(axe_val) = self.eval(RUN_AXE_JS) {
                    if let Ok(violations) = serde_json::from_value::<Vec<AxeViolation>>(axe_val) {
                        raw.axe = Some(violations);
                    }
                }
            }
            raw
        }

        fn enumerate_surfaces(&mut self) -> Vec<ClickTarget> {
            self.eval(SURFACES_JS)
                .ok()
                .and_then(|v| v.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(|t| {
                    Some(ClickTarget {
                        label: t.get("label")?.as_str()?.to_string(),
                        x: t.get("x")?.as_f64()?,
                        y: t.get("y")?.as_f64()?,
                    })
                })
                .collect()
        }

        fn click(&mut self, x: f64, y: f64) -> Result<(), String> {
            // Synthetic `MouseEvent` dispatch in place of `Input.dispatchMouseEvent`
            // (unconfirmed field shape here) — same substitution as
            // `wf_port::r54::chrome_session::ChromeSession::click_at`.
            let js = format!(
                "(() => {{ const el = document.elementFromPoint({x}, {y}); if (!el) return {{ ok: false }}; for (const type of ['mousedown','mouseup','click']) el.dispatchEvent(new MouseEvent(type, {{ bubbles: true, cancelable: true, clientX: {x}, clientY: {y} }})); return {{ ok: true }}; }})()"
            );
            let result = self.eval(&js)?;
            if result.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                Ok(())
            } else {
                Err(format!("no element at ({x}, {y})"))
            }
        }

        fn locate(&mut self, selector: &str, text: &str) -> Option<(f64, f64)> {
            let js = locate_js(selector, text);
            let result = self.eval(&js).ok()?;
            if result.get("ok").and_then(|v| v.as_bool()) == Some(true) {
                Some((result.get("x")?.as_f64()?, result.get("y")?.as_f64()?))
            } else {
                None
            }
        }

        fn axe_available(&self) -> bool {
            self.axe_source.is_some()
        }

        fn shutdown(&mut self) {
            self.tab = None;
            self.browser = None;
        }
    }
}

pub use chrome_driver::ChromeRuntimeDriver;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_surfaces_rejects_non_array() {
        let err = parse_surfaces_input(r#"{"label":"x"}"#).unwrap_err();
        assert!(err.contains("must contain a JSON array"));
    }

    #[test]
    fn parse_surfaces_rejects_invalid_json() {
        let err = parse_surfaces_input("not json").unwrap_err();
        assert!(err.contains("--surfaces parse failed"));
    }

    #[test]
    fn parse_surfaces_drops_non_object_entries() {
        let parsed = parse_surfaces_input(r#"[{"label":"a"}, "skip-me", 42, {"label":"b"}]"#).unwrap();
        assert_eq!(parsed.targets.len(), 2);
    }

    #[test]
    fn classify_runtime_failure_precedence() {
        assert_eq!(classify_runtime_failure("No Chrome/Edge found for the runtime pass."), "browser-unavailable");
        assert_eq!(classify_runtime_failure("timed out waiting for app load"), "app-load-timeout");
        assert_eq!(classify_runtime_failure("CDP handshake failed"), "cdp-unavailable");
        assert_eq!(classify_runtime_failure("something else entirely"), "runtime-execution");
    }

    #[test]
    fn build_degraded_report_shape() {
        let gaps = vec![json!({"kind": "browser-unavailable"})];
        let denominator = json!({"kind": "runtime-surfaces", "expected": 1, "examined": 0});
        let report = build_degraded_report(&gaps, &denominator, Some("http://localhost:1422"), 12);
        assert_eq!(report["status"], json!("unproven"));
        assert_eq!(report["incomplete"], json!(true));
        assert_eq!(report["complete"], json!(false));
        assert_eq!(report["surfaces_found"], json!(1));
        assert_eq!(report["url"], json!("http://localhost:1422"));
    }
}

#[cfg(test)]
mod pure_logic_tests {
    use super::*;

    #[test]
    fn typed_flags_expensive_typing_threshold() {
        let t = Thresholds::default();
        let typed = TypedMetrics { per_key_ms: 9.0, ..Default::default() };
        let flags = typed_flags(&typed, 12, &t);
        assert!(flags.iter().any(|f| f.starts_with("expensive-typing:")));
    }

    #[test]
    fn typed_flags_under_threshold_is_clean() {
        let t = Thresholds::default();
        let typed = TypedMetrics { per_key_ms: 2.0, ..Default::default() };
        assert!(typed_flags(&typed, 12, &t).is_empty());
    }

    #[test]
    fn typed_flags_long_tasks() {
        let t = Thresholds::default();
        let typed = TypedMetrics { long_tasks_ms: vec![60.0, 75.0], ..Default::default() };
        let flags = typed_flags(&typed, 12, &t);
        assert!(flags.iter().any(|f| f == "long-tasks-while-typing: 60,75ms"));
    }

    #[test]
    fn typed_flags_wide_rerender_needs_more_than_three_heavy() {
        let t = Thresholds::default();
        let keys = 10;
        // 4 components each re-rendering on >=80% of keystrokes trips it.
        let typed = TypedMetrics {
            top_renderers: vec![
                ("A".into(), 9), ("B".into(), 9), ("C".into(), 8), ("D".into(), 8), ("E".into(), 1),
            ],
            ..Default::default()
        };
        let flags = typed_flags(&typed, keys, &t);
        assert!(flags.iter().any(|f| f.starts_with("wide-rerender: 4 components")));
    }

    #[test]
    fn clicked_flags_expensive_click_and_burst() {
        let t = Thresholds::default();
        let clicked = ClickedMetrics {
            avg_script_ms_per_click: 150.0,
            per_click: vec![("Tab A".into(), 12)],
            ..Default::default()
        };
        let flags = clicked_flags(&clicked, &t);
        assert!(flags.iter().any(|f| f.starts_with("expensive-click:")));
        assert!(flags.iter().any(|f| f.starts_with("heavy-click-rerender:") && f.contains("Tab A:12 commits")));
    }

    #[test]
    fn a11y_flag_counts_serious() {
        let violations = vec![
            AxeViolation { id: "x".into(), impact: Some("serious".into()), help: "h".into(), count: 1, target: "t".into(), help_url: "u".into() },
            AxeViolation { id: "y".into(), impact: Some("minor".into()), help: "h".into(), count: 1, target: "t".into(), help_url: "u".into() },
        ];
        let flag = a11y_flag(&violations).unwrap();
        assert_eq!(flag, "a11y: 2 axe violation(s), 1 serious+ (wcag2a/aa)");
    }

    #[test]
    fn a11y_flag_none_when_empty() {
        assert_eq!(a11y_flag(&[]), None);
    }

    #[test]
    fn console_errors_flag_pluralizes_count() {
        assert_eq!(console_errors_flag(&["e1".to_string(), "e2".to_string()]), Some("2 console error/exception(s)".to_string()));
        assert_eq!(console_errors_flag(&[]), None);
    }

    #[test]
    fn testing_honesty_incomplete_when_nothing_reachable_and_few_interactive() {
        let (incomplete, shallow) = testing_honesty(false, 0, 1);
        assert!(incomplete);
        assert!(!shallow);
    }

    #[test]
    fn testing_honesty_shallow_when_rendered_but_nothing_reachable() {
        let (incomplete, shallow) = testing_honesty(false, 0, 5);
        assert!(!incomplete);
        assert!(shallow);
    }

    #[test]
    fn testing_honesty_clean_when_tested() {
        let (incomplete, shallow) = testing_honesty(true, 0, 5);
        assert!(!incomplete);
        assert!(!shallow);
    }

    #[test]
    fn assemble_report_status_pass_vs_candidates() {
        let denom = json!({"kind": "runtime-surfaces", "expected": 1, "examined": 1});
        let clean = assemble_report(Some("http://x"), &[json!({"surface": "default", "flags": []})], &[], &denom, 1, 1, 12, 0, false, false, true, 0);
        assert_eq!(clean["status"], json!("pass"));
        assert_eq!(clean["complete"], json!(true));

        let flagged = assemble_report(Some("http://x"), &[json!({"surface": "default", "flags": ["x"]})], &[], &denom, 1, 1, 12, 0, false, false, true, 0);
        assert_eq!(flagged["status"], json!("candidates"));
    }
}

#[cfg(test)]
mod run_tests {
    use super::*;
    use std::sync::Mutex;

    /// In-memory [`RuntimeDriver`] fake: no real browser, no network. Scripted
    /// with a fixed sequence of surfaces/measurements so `run_with_driver`'s
    /// orchestration (denominators, honesty checks, degradation, report
    /// shape) can be asserted without launching Chrome.
    struct FakeDriver {
        launch_fails: bool,
        surfaces: Vec<ClickTarget>,
        entry: SurfaceRaw,
        per_surface: Mutex<Vec<SurfaceRaw>>,
        axe_on: bool,
    }

    impl RuntimeDriver for FakeDriver {
        fn launch(&mut self) -> Result<(), String> {
            if self.launch_fails { Err("No Chrome/Edge found for the runtime pass.".to_string()) } else { Ok(()) }
        }
        fn navigate_and_wait_ready(&mut self, _url: &str, _w: u32, _h: u32) -> Result<(), String> {
            Ok(())
        }
        fn measure_surface(&mut self, name: &str, _keys: i64, _t: &Thresholds) -> SurfaceRaw {
            if name == "default" {
                self.entry.clone()
            } else {
                self.per_surface.lock().unwrap().pop().unwrap_or_default()
            }
        }
        fn enumerate_surfaces(&mut self) -> Vec<ClickTarget> {
            self.surfaces.clone()
        }
        fn click(&mut self, _x: f64, _y: f64) -> Result<(), String> {
            Ok(())
        }
        fn locate(&mut self, _s: &str, _t: &str) -> Option<(f64, f64)> {
            None
        }
        fn axe_available(&self) -> bool {
            self.axe_on
        }
        fn shutdown(&mut self) {}
    }

    #[test]
    fn missing_url_is_usage_degradation() {
        let mut driver = FakeDriver { launch_fails: false, surfaces: vec![], entry: SurfaceRaw::default(), per_surface: Mutex::new(vec![]), axe_on: false };
        let args = RuntimeArgs { url: None, ..Default::default() };
        let (code, report) = run_with_driver(&args, &mut driver);
        assert_eq!(code, 2);
        assert_eq!(report["degradation"][0]["kind"], json!("runtime-url-missing"));
    }

    #[test]
    fn launch_failure_is_typed_degradation() {
        let mut driver = FakeDriver { launch_fails: true, surfaces: vec![], entry: SurfaceRaw::default(), per_surface: Mutex::new(vec![]), axe_on: false };
        let args = RuntimeArgs { url: Some("http://localhost:1422".to_string()), ..Default::default() };
        let (code, report) = run_with_driver(&args, &mut driver);
        assert_eq!(code, 3);
        assert_eq!(report["degradation"][0]["kind"], json!("browser-unavailable"));
        assert_eq!(report["status"], json!("unproven"));
    }

    #[test]
    fn nothing_rendered_is_incomplete_not_false_clean() {
        let mut driver = FakeDriver {
            launch_fails: false,
            surfaces: vec![],
            entry: SurfaceRaw { interactive: Some(0), ..Default::default() },
            per_surface: Mutex::new(vec![]),
            axe_on: false,
        };
        let args = RuntimeArgs { url: Some("http://localhost:1422".to_string()), ..Default::default() };
        let (code, report) = run_with_driver(&args, &mut driver);
        assert_eq!(code, 0);
        assert_eq!(report["incomplete"], json!(true));
        assert_eq!(report["complete"], json!(false));
        assert!(report["findings"][0]["flags"][0].as_str().unwrap().starts_with("app-not-ready"));
    }

    #[test]
    fn typed_surface_with_flag_reports_candidates() {
        let entry = SurfaceRaw {
            interactive: Some(5),
            typed: Some(TypedMetrics { per_key_ms: 20.0, ..Default::default() }),
            ..Default::default()
        };
        let mut driver = FakeDriver { launch_fails: false, surfaces: vec![], entry, per_surface: Mutex::new(vec![]), axe_on: false };
        let args = RuntimeArgs { url: Some("http://localhost:1422".to_string()), ..Default::default() };
        let (code, report) = run_with_driver(&args, &mut driver);
        assert_eq!(code, 0);
        assert_eq!(report["status"], json!("candidates"));
        assert_eq!(report["incomplete"], json!(false));
        assert_eq!(report["shallow"], json!(false));
        let flags = report["findings"][0]["flags"].as_array().unwrap();
        assert!(flags.iter().any(|f| f.as_str().unwrap().starts_with("expensive-typing:")));
    }

    #[test]
    fn enumerated_surface_bumps_denominator_and_tested_count() {
        let entry = SurfaceRaw { interactive: Some(5), typed: Some(TypedMetrics { per_key_ms: 1.0, ..Default::default() }), ..Default::default() };
        let extra = SurfaceRaw { interactive: Some(5), typed: Some(TypedMetrics { per_key_ms: 1.0, ..Default::default() }), ..Default::default() };
        let mut driver = FakeDriver {
            launch_fails: false,
            surfaces: vec![ClickTarget { label: "settings".to_string(), x: 10.0, y: 10.0 }],
            entry,
            per_surface: Mutex::new(vec![extra]),
            axe_on: false,
        };
        let args = RuntimeArgs { url: Some("http://localhost:1422".to_string()), ..Default::default() };
        let (code, report) = run_with_driver(&args, &mut driver);
        assert_eq!(code, 0);
        assert_eq!(report["surfaces_tested"], json!(2));
        assert_eq!(report["surfaces_found"], json!(2));
        assert_eq!(report["denominator"]["expected"], json!(2));
        assert_eq!(report["denominator"]["examined"], json!(2));
    }
}
