//! Port of `tools/audit/render-report.mjs` — turns `facts.json` (+ optional
//! `report.json` reasoning-lens findings) into a Markdown audit report:
//! scanner-coverage proof table, NOT-SCANNED banners, top-10 triage,
//! findings grouped by remediation type, decomposition-assessment evidence
//! validation, the AU13 per-change coverage gate, the AU14 trajectory, and a
//! re-run appendix. No native counterpart existed anywhere in `engine/`
//! before this port.
//!
//! This is ported as a library, not a CLI: the JS file's `process.argv`
//! flag parsing (`--facts`, `--report`, `--out`, `--filter-dir`, `--agent`,
//! `--trajectory-history`) becomes the [`RenderOptions`] struct passed by
//! the caller, and the two JS output modes (`--agent` → a JSON summary on
//! stdout, else → a Markdown file write) become [`render_report`]'s two
//! return fields (`agent_summary`, `markdown`) so a caller gets both without
//! re-invoking. Trajectory history persistence (`computeTrajectory`'s
//! read/write of `<workspace>/.audit/audit-trajectory.json`) is ported with
//! the same read-merge-write behavior via `std::fs`, best-effort on write
//! exactly as JS never blocks the render on it.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

/// Options mirroring the JS CLI flags this renderer's caller would set.
#[derive(Debug, Clone, Default)]
pub struct RenderOptions {
    pub filter_dir: Option<String>,
    /// Override for `<workspace>/.audit/audit-trajectory.json`.
    pub trajectory_history: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum RenderReportError {
    #[error("facts.json is missing required field {0}")]
    MissingField(&'static str),
}

const SEV_ORDER_KEYS: [&str; 4] = ["critical", "high", "medium", "low"];
const CAP: usize = 5;
const HIGH_STAKES_MULTIPLIER: f64 = 3.0;
const AGE_THRESHOLD_DAYS: f64 = 30.0;
const DECISION_REF_ROOTS: [&str; 2] = [".audit/", "docs/plans/"];

fn security_checks() -> HashSet<&'static str> {
    ["secrets", "sast", "ci_lint", "docker", "deps_cve", "cargo_audit"]
        .into_iter()
        .collect()
}

fn remediation_label(category: &str) -> &'static str {
    match category {
        "security" => "Secure",
        "schema-drift" => "Schema-fix",
        "doc-drift" => "Docs",
        "architecture" => "Refactor",
        "naming" => "Standardize",
        "dead-file" => "Delete",
        "ai-slop" => "Delete",
        "minimize" => "Simplify",
        "correctness" => "Fix",
        "performance" => "Optimize",
        "a11y" => "Accessibility",
        "data-safety" => "Data-safety",
        "ui-ux" => "UI/UX",
        "resilience" => "Harden",
        "platform-parity" => "Parity",
        "release-readiness" => "Release",
        _ => "Other",
    }
}

fn sev_rank(sev: &str) -> i32 {
    SEV_ORDER_KEYS
        .iter()
        .position(|s| *s == sev)
        .map(|i| i as i32)
        .unwrap_or(9)
}

/// Mirrors JS `cleanPath`.
pub fn clean_path(p: Option<&str>) -> Option<String> {
    let p = p?;
    if p.is_empty() {
        return None;
    }
    let mut s = p.replace('\\', "/");
    while let Some(stripped) = s.strip_prefix("./") {
        s = stripped.to_string();
    }
    while s.ends_with('/') {
        s.pop();
    }
    Some(s)
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// Mirrors JS `inDir(file, dir)`.
fn in_dir(file: &str, dir: Option<&str>) -> bool {
    let Some(dir) = dir else { return true };
    let f = clean_path(Some(file)).unwrap_or_default();
    let d = clean_path(Some(dir)).unwrap_or_default();
    f == d || f.starts_with(&format!("{d}/"))
}

/// Mirrors JS `dedupe(findings)`. `line == null` findings merge by
/// `file::category::title`; line-specific findings merge by
/// `file::line::category`. Worse severity wins the merged record's
/// severity/title/detail; sources and caused_by union; `disputed`/
/// `interpretive` status/judgment stick once set.
pub fn dedupe(findings: &[Value]) -> Vec<Value> {
    fn evidence_rank(s: Option<&str>) -> i32 {
        match s {
            Some("verified") => 0,
            Some("strong-inference") => 1,
            Some("possible") => 2,
            _ => 9,
        }
    }
    let mut order: Vec<String> = Vec::new();
    let mut seen: HashMap<String, Value> = HashMap::new();
    for f in findings {
        let file = str_field(f, "file").unwrap_or("").to_string();
        let category = str_field(f, "category").unwrap_or("").to_string();
        let title = str_field(f, "title").unwrap_or("").to_string();
        let key = if !f.get("line").map(Value::is_null).unwrap_or(true) {
            let line = f.get("line").cloned().unwrap_or(Value::Null);
            format!("{file}::{line}::{category}")
        } else {
            format!("{file}::{category}::{title}")
        };
        if let Some(prev) = seen.get_mut(&key) {
            let mut sources: Vec<Value> = prev
                .get("sources")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for s in f.get("sources").and_then(Value::as_array).into_iter().flatten() {
                if !sources.contains(s) {
                    sources.push(s.clone());
                }
            }
            prev["sources"] = json!(sources);

            let mut caused_by: Vec<Value> = prev
                .get("caused_by")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for c in f.get("caused_by").and_then(Value::as_array).into_iter().flatten() {
                if !caused_by.contains(c) {
                    caused_by.push(c.clone());
                }
            }
            prev["caused_by"] = json!(caused_by);

            let f_strength = f.get("evidence_strength").and_then(Value::as_str);
            let prev_strength = prev.get("evidence_strength").and_then(Value::as_str);
            if evidence_rank(f_strength) < evidence_rank(prev_strength) {
                prev["evidence_strength"] = f.get("evidence_strength").cloned().unwrap_or(Value::Null);
            }
            if str_field(f, "status") == Some("disputed") {
                prev["status"] = json!("disputed");
            }
            if str_field(f, "judgment") == Some("interpretive") {
                prev["judgment"] = json!("interpretive");
            }
            let f_sev = str_field(f, "severity").unwrap_or("");
            let prev_sev = prev.get("severity").and_then(Value::as_str).unwrap_or("");
            if sev_rank(f_sev) < sev_rank(prev_sev) {
                prev["severity"] = f.get("severity").cloned().unwrap_or(Value::Null);
                prev["title"] = f.get("title").cloned().unwrap_or(Value::Null);
                prev["detail"] = f.get("detail").cloned().unwrap_or(Value::Null);
            }
        } else {
            let mut merged = f.clone();
            if merged.get("sources").is_none() {
                merged["sources"] = json!([]);
            }
            order.push(key.clone());
            seen.insert(key, merged);
        }
    }
    order.into_iter().filter_map(|k| seen.remove(&k)).collect()
}

/// Mirrors JS `qualityGate(facts)`.
pub fn quality_gate(facts: &Value) -> Value {
    let gate_checks: HashSet<&str> = ["lint", "types", "build"].into_iter().collect();
    let checks = facts.get("checks").and_then(Value::as_array).cloned().unwrap_or_default();
    let relevant: Vec<Value> = checks
        .into_iter()
        .filter(|c| gate_checks.contains(str_field(c, "check").unwrap_or("")))
        .collect();
    let failed: Vec<Value> = relevant
        .iter()
        .filter(|c| {
            str_field(c, "status") == Some("ran")
                && (c.get("findings_count").and_then(Value::as_i64).unwrap_or(0) > 0
                    || c.get("exit_code")
                        .and_then(Value::as_i64)
                        .map(|code| code != 0)
                        .unwrap_or(false))
        })
        .cloned()
        .collect();
    let unproven: Vec<Value> = relevant
        .iter()
        .filter(|c| {
            let status = str_field(c, "status").unwrap_or("");
            let skip_reason = str_field(c, "skip_reason").unwrap_or("");
            status == "error" || (status == "skipped" && !skip_reason.to_lowercase().starts_with("no "))
        })
        .cloned()
        .collect();
    let ran: Vec<Value> = relevant
        .iter()
        .filter(|c| str_field(c, "status") == Some("ran"))
        .cloned()
        .collect();
    let state = if !failed.is_empty() {
        "NOT CLEAN"
    } else if !unproven.is_empty() || ran.is_empty() {
        "UNPROVEN"
    } else {
        "CLEAN"
    };
    json!({ "state": state, "failed": failed, "unproven": unproven, "ran": ran })
}

/// Mirrors JS `coverageGate(coverage)`. Returns `null`/`None` when
/// `coverage.perFile` is absent or empty, exactly like the JS "not diff
/// scoped this run" short-circuit.
pub fn coverage_gate(coverage: Option<&Value>) -> Option<Value> {
    let coverage = coverage?;
    let per_file = coverage.get("perFile").and_then(Value::as_array)?;
    if per_file.is_empty() {
        return None;
    }
    let total_touched: i64 = per_file
        .iter()
        .map(|f| f.get("touched").and_then(Value::as_array).map(|a| a.len() as i64).unwrap_or(0))
        .sum();
    let total_covered: i64 = per_file
        .iter()
        .map(|f| f.get("covered").and_then(Value::as_array).map(|a| a.len() as i64).unwrap_or(0))
        .sum();
    let ratio = coverage
        .get("ratio")
        .and_then(Value::as_f64)
        .or_else(|| {
            if total_touched > 0 {
                Some(total_covered as f64 / total_touched as f64)
            } else {
                None
            }
        });
    let no_test_files: Vec<Value> = per_file
        .iter()
        .filter(|f| {
            let no_tests = f
                .get("tests")
                .and_then(Value::as_array)
                .map(|a| a.is_empty())
                .unwrap_or(true);
            let touched = f.get("touched").and_then(Value::as_array).map(|a| !a.is_empty()).unwrap_or(false);
            no_tests && touched
        })
        .cloned()
        .collect();
    let (state, severity) = match ratio {
        None => ("UNPROVEN", None),
        Some(r) if !no_test_files.is_empty() || r < 0.5 => ("NOT CLEAN", Some("critical")),
        Some(r) if r < 0.8 => ("NOT CLEAN", Some("high")),
        _ => ("CLEAN", None),
    };
    Some(json!({
        "state": state,
        "ratio": ratio,
        "severity": severity,
        "noTestFiles": no_test_files.iter().map(|f| f.get("file").cloned().unwrap_or(Value::Null)).collect::<Vec<_>>(),
        "perFile": per_file,
    }))
}

/// Mirrors JS `healthScore(report, facts, lensesRan)`. `None` (JS `null`)
/// when lenses did not run — a clean score would be a lie.
pub fn health_score(findings: &[Value], incomplete: bool, lenses_ran: bool) -> Option<i64> {
    if !lenses_ran {
        return None;
    }
    let weight = |sev: &str| -> i64 {
        match sev {
            "critical" => 25,
            "high" => 12,
            "medium" => 5,
            "low" => 1,
            _ => 1,
        }
    };
    let mut score: i64 = 100;
    for f in findings {
        score -= weight(str_field(f, "severity").unwrap_or(""));
    }
    if incomplete {
        score -= 10;
    }
    Some(score.clamp(0, 100))
}

/// A parsed `path:line` / `path:start-end` evidence locus.
struct Span {
    path: String,
    start: i64,
    end: Option<i64>,
}

fn parse_span(value: &str) -> Option<Span> {
    let value = value.trim();
    let idx = value.rfind(':')?;
    let (path_part, rest) = value.split_at(idx);
    let rest = &rest[1..];
    let (start_str, end_str) = match rest.split_once('-') {
        Some((a, b)) => (a, Some(b)),
        None => (rest, None),
    };
    let start: i64 = start_str.parse().ok()?;
    let end: Option<i64> = match end_str {
        Some(s) => Some(s.parse().ok()?),
        None => None,
    };
    Some(Span {
        path: clean_path(Some(path_part))?,
        start,
        end,
    })
}

/// Mirrors JS `evidenceProblems(candidate, verdict, evidence, label)`.
fn evidence_problems(candidate: &Value, kind: &str, verdict: &str, evidence: Option<&Value>, loc: Option<f64>, label: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let entries: Vec<&Value> = evidence.and_then(Value::as_array).map(|a| a.iter().collect()).unwrap_or_default();
    if entries.is_empty() {
        problems.push(format!("{label}missing evidence"));
        return problems;
    }
    let spans: Vec<Option<Span>> = entries
        .iter()
        .map(|e| e.as_str().and_then(parse_span))
        .collect();
    if spans.iter().any(|s| s.is_none()) {
        problems.push(format!("{label}evidence entries must be `path:line` or `path:start-end` loci"));
        return problems;
    }
    if kind == "file-size" && (verdict == "not-needed" || verdict == "confirmed") {
        let candidate_path = str_field(candidate, "candidate").unwrap_or("");
        let candidate_path = clean_path(Some(candidate_path)).unwrap_or_default();
        let own: Vec<&Span> = spans.iter().filter_map(|s| s.as_ref()).filter(|s| s.path == candidate_path).collect();
        if own.is_empty() {
            problems.push(format!("{label}no evidence anchored in the candidate file"));
        } else if let Some(loc) = loc {
            if own.iter().all(|s| s.start <= 1 && s.end.unwrap_or(s.start) as f64 >= loc) {
                problems.push(format!(
                    "{label}whole-file span is not symbol-level evidence — cite the specific responsibilities/symbols"
                ));
            }
        }
    }
    problems
}

/// Mirrors JS `assessmentProblemsFor(candidate, assessment)`.
fn assessment_problems_for(candidate: &Value, assessment: &Value, review_trigger: Option<f64>, second_assessor_incoming: i64) -> Vec<String> {
    let mut problems = Vec::new();
    let verdict = str_field(assessment, "verdict").unwrap_or("");
    let valid_verdicts: HashSet<&str> = ["not-needed", "confirmed", "undetermined"].into_iter().collect();
    if !valid_verdicts.contains(verdict) {
        problems.push(format!("invalid verdict {:?}", assessment.get("verdict").cloned().unwrap_or(Value::Null)));
    }
    if str_field(assessment, "rationale").unwrap_or("").trim().is_empty() {
        problems.push("missing rationale".to_string());
    }
    let kind = str_field(candidate, "kind").unwrap_or("");
    let loc = candidate.get("loc").and_then(Value::as_f64);
    problems.extend(evidence_problems(candidate, kind, verdict, assessment.get("evidence"), loc, ""));

    if verdict == "not-needed" {
        let size = if kind == "mechanical-split" {
            candidate.get("logical_loc").and_then(Value::as_f64)
        } else {
            candidate.get("loc").and_then(Value::as_f64)
        };
        let by_size = matches!((review_trigger, size), (Some(t), Some(s)) if s >= t * HIGH_STAKES_MULTIPLIER);
        let graph_available = str_field(candidate, "graphMetrics") == Some("available");
        let incoming = candidate.get("incomingRelationships").and_then(Value::as_i64);
        let by_incoming = graph_available && incoming.map(|i| i >= second_assessor_incoming).unwrap_or(false);
        if by_size || by_incoming {
            let trigger = if by_size {
                format!(
                    "{} LOC (>={}x trigger {})",
                    size.unwrap_or_default(),
                    HIGH_STAKES_MULTIPLIER as i64,
                    review_trigger.unwrap_or_default()
                )
            } else {
                format!("{} incoming relationships (>={})", incoming.unwrap_or_default(), second_assessor_incoming)
            };
            match assessment.get("second_assessor").filter(|v| v.is_object()) {
                None => problems.push(format!("not-needed at {trigger} requires second_assessor {{verdict,rationale,evidence}}")),
                Some(second) => {
                    if str_field(second, "verdict") != Some("not-needed") {
                        problems.push(format!(
                            "second assessor verdict {:?} — worse verdict wins, not-needed cannot stand",
                            second.get("verdict").cloned().unwrap_or(Value::Null)
                        ));
                    }
                    if str_field(second, "rationale").unwrap_or("").trim().is_empty() {
                        problems.push("second_assessor missing rationale".to_string());
                    }
                    problems.extend(evidence_problems(candidate, kind, "not-needed", second.get("evidence"), loc, "second_assessor: "));
                }
            }
        }
    }
    problems
}

/// The ADR/plan reference must be a real regular file inside one of the
/// documented decision-record roots, with both lexical and realpath
/// resolution staying inside the workspace. Mirrors JS
/// `architectDecisionRefExists`.
fn architect_decision_ref_exists(workspace: &Path, ref_path: &str) -> bool {
    if ref_path.trim().is_empty() || Path::new(ref_path).is_absolute() {
        return false;
    }
    let Some(norm) = clean_path(Some(ref_path)) else { return false };
    let Some(allowed) = DECISION_REF_ROOTS.iter().find(|root| norm.starts_with(**root)) else {
        return false;
    };
    let root = match fs::canonicalize(workspace) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let target = root.join(&norm);
    let allowed_root_lexical = root.join(allowed);
    if !target.starts_with(&allowed_root_lexical) {
        return false;
    }
    let real_root = match fs::canonicalize(&root) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let real_allowed_root = match fs::canonicalize(&allowed_root_lexical) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let real = match fs::canonicalize(&target) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if !real_allowed_root.starts_with(&real_root) || real_allowed_root == real_root {
        return false;
    }
    if !real.starts_with(&real_allowed_root) || real == real_allowed_root {
        return false;
    }
    match fs::metadata(&real) {
        Ok(meta) => meta.is_file(),
        Err(_) => false,
    }
}

/// Mirrors JS `validDecompositionPlan(plan)`.
fn valid_decomposition_plan(plan: Option<&Value>, workspace: &Path) -> bool {
    let Some(plan) = plan else { return false };
    if str_field(plan, "verdict") != Some("confirmed") {
        return false;
    }
    let responsibilities = match plan.get("current_responsibilities").and_then(Value::as_array) {
        Some(a) if a.len() > 1 => a,
        _ => return false,
    };
    for item in responsibilities {
        let has_name = item.get("name").map(|v| !v.is_null()).unwrap_or(false);
        let symbols_ok = item.get("symbols").and_then(Value::as_array).map(|a| !a.is_empty()).unwrap_or(false);
        let evidence_ok = item.get("evidence").and_then(Value::as_array).map(|a| !a.is_empty()).unwrap_or(false);
        if !has_name || !symbols_ok || !evidence_ok {
            return false;
        }
    }
    let keep = plan.get("keep_in_place").cloned().unwrap_or(Value::Null);
    if keep.get("component").map(|v| v.is_null()).unwrap_or(true) || keep.get("responsibility").map(|v| v.is_null()).unwrap_or(true) {
        return false;
    }
    let targets = match plan.get("target_components").and_then(Value::as_array) {
        Some(a) if !a.is_empty() => a,
        _ => return false,
    };
    for item in targets {
        let ok = item.get("component").map(|v| !v.is_null()).unwrap_or(false)
            && item.get("destination").map(|v| !v.is_null()).unwrap_or(false)
            && item.get("responsibility").map(|v| !v.is_null()).unwrap_or(false)
            && item.get("moves").and_then(Value::as_array).map(|a| !a.is_empty()).unwrap_or(false)
            && item.get("public_contract").map(|v| !v.is_null()).unwrap_or(false)
            && item.get("dependencies").and_then(Value::as_array).is_some();
        if !ok {
            return false;
        }
    }
    let steps = match plan.get("steps").and_then(Value::as_array) {
        Some(a) if !a.is_empty() => a,
        _ => return false,
    };
    for item in steps {
        if item.get("change").map(|v| v.is_null()).unwrap_or(true) || item.get("verification").map(|v| v.is_null()).unwrap_or(true) {
            return false;
        }
    }
    if plan.get("behavior_contracts").and_then(Value::as_array).map(|a| a.is_empty()).unwrap_or(true) {
        return false;
    }
    if plan.get("risks").and_then(Value::as_array).map(|a| a.is_empty()).unwrap_or(true) {
        return false;
    }
    let decision_ref = str_field(plan, "architect_decision_ref").unwrap_or("");
    architect_decision_ref_exists(workspace, decision_ref)
}

/// One computed AU14 trajectory result, plus the fresh fingerprint digest
/// this run should persist for the next one.
pub struct Trajectory {
    pub summary: Value,
    pub next_history: Value,
}

fn fingerprint(f: &Value) -> String {
    let file = clean_path(str_field(f, "file")).unwrap_or_else(|| "unknown".into());
    let line = f.get("line").cloned().unwrap_or(Value::Null);
    let category = str_field(f, "category").unwrap_or("unknown");
    let title = str_field(f, "title").unwrap_or("").trim().to_lowercase();
    format!("{file}:{line}::{category}::{title}")
}

fn loose_fingerprint(f: &Value) -> String {
    let category = str_field(f, "category").unwrap_or("unknown");
    let title = str_field(f, "title").unwrap_or("").trim().to_lowercase();
    let file = clean_path(str_field(f, "file")).unwrap_or_else(|| "unknown".into());
    let base = Path::new(&file).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or(file);
    format!("{category}::{title}::{base}")
}

fn bucket_for(age_days: f64) -> &'static str {
    if age_days <= 7.0 {
        "0-7d"
    } else if age_days <= 30.0 {
        "8-30d"
    } else if age_days <= 90.0 {
        "31-90d"
    } else {
        "90+d"
    }
}

fn now_unix_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

/// Mirrors JS `computeTrajectory(report, facts)`. `history_path` mirrors
/// `--trajectory-history` / `<workspace>/.audit/audit-trajectory.json`;
/// `prior_history` is the parsed contents of that file if the caller has
/// already read it (avoids a second disk read when the caller manages I/O
/// itself), else `None` to have this function read it.
pub fn compute_trajectory(findings: &[Value], history_path: &Path, prior_history: Option<Value>) -> Trajectory {
    let history = prior_history.or_else(|| fs::read_to_string(history_path).ok().and_then(|s| serde_json::from_str(&s).ok()));
    let prior_entries: Map<String, Value> = history
        .as_ref()
        .and_then(|h| h.get("fingerprints"))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let prior_run_at = history.as_ref().and_then(|h| str_field(h, "run_at")).map(String::from);
    let had_prior_run = prior_run_at.is_some() || !prior_entries.is_empty();

    let now = now_unix_secs();
    let parse_epoch = |s: &str| -> f64 {
        // Best-effort seconds-since-epoch parse of an RFC3339-ish timestamp
        // as produced by this crate's own `chrono_now_rfc3339` fallback
        // (`1970-01-01T00:00:00Z+<secs>s`) or a plain numeric string; any
        // other format falls back to "now" exactly like JS `Date.parse`
        // returning `NaN` (`Date.parse(...) || now`).
        if let Some(rest) = s.strip_prefix("1970-01-01T00:00:00Z+").and_then(|r| r.strip_suffix('s')) {
            if let Ok(v) = rest.parse::<f64>() {
                return v;
            }
        }
        s.parse::<f64>().unwrap_or(now)
    };

    struct Current<'a> {
        f: &'a Value,
        fp: String,
        loose: String,
    }
    let current: Vec<Current> = findings
        .iter()
        .map(|f| Current { f, fp: fingerprint(f), loose: loose_fingerprint(f) })
        .collect();

    let mut matched_prior: HashSet<String> = HashSet::new();
    let mut matched_current: HashSet<String> = HashSet::new();
    struct Match<'a> {
        fp: String,
        prior: Value,
        current_severity: Option<&'a str>,
    }
    let mut matches: Vec<Match> = Vec::new();

    for item in &current {
        if let Some(prior) = prior_entries.get(&item.fp) {
            if !matched_prior.contains(&item.fp) {
                matches.push(Match { fp: item.fp.clone(), prior: prior.clone(), current_severity: str_field(item.f, "severity") });
                matched_prior.insert(item.fp.clone());
                matched_current.insert(item.fp.clone());
            }
        }
    }
    let mut prior_by_loose: HashMap<String, Vec<String>> = HashMap::new();
    for (fp, entry) in &prior_entries {
        if matched_prior.contains(fp) {
            continue;
        }
        if let Some(loose) = str_field(entry, "loose") {
            prior_by_loose.entry(loose.to_string()).or_default().push(fp.clone());
        }
    }
    for item in &current {
        if matched_current.contains(&item.fp) {
            continue;
        }
        if let Some(candidates) = prior_by_loose.get(&item.loose) {
            if candidates.len() == 1 && !matched_prior.contains(&candidates[0]) {
                let fp = candidates[0].clone();
                let prior = prior_entries.get(&fp).cloned().unwrap_or(Value::Null);
                matches.push(Match { fp: item.fp.clone(), prior, current_severity: str_field(item.f, "severity") });
                matched_prior.insert(fp);
                matched_current.insert(item.fp.clone());
            }
        }
    }

    let mut aged = 0i64;
    let mut unchanged = 0i64;
    let mut newly_p0 = 0i64;
    let match_by_current_fp: HashMap<String, &Match> = matches.iter().map(|m| (m.fp.clone(), m)).collect();
    for m in &matches {
        let first_seen = str_field(&m.prior, "first_seen").map(parse_epoch).unwrap_or(now);
        let age_days = (now - first_seen) / 86400.0;
        if age_days > AGE_THRESHOLD_DAYS {
            aged += 1;
        } else {
            unchanged += 1;
        }
        let was_critical = str_field(&m.prior, "severity") == Some("critical");
        let is_critical = m.current_severity == Some("critical");
        if is_critical && !was_critical {
            newly_p0 += 1;
        }
    }
    let new_findings: Vec<&Current> = current.iter().filter(|item| !matched_current.contains(&item.fp)).collect();
    for item in &new_findings {
        if str_field(item.f, "severity") == Some("critical") {
            newly_p0 += 1;
        }
    }
    let resolved_count = (prior_entries.len() as i64) - (matched_prior.len() as i64);

    let mut bucket_counts: HashMap<&str, i64> = ["0-7d", "8-30d", "31-90d", "90+d"].iter().map(|b| (*b, 0)).collect();
    for item in &current {
        let m = match_by_current_fp.get(&item.fp);
        let first_seen = m.and_then(|m| str_field(&m.prior, "first_seen")).map(parse_epoch).unwrap_or(now);
        let age_days = (now - first_seen) / 86400.0;
        *bucket_counts.entry(bucket_for(age_days)).or_insert(0) += 1;
    }
    let aging_buckets: Vec<Value> = ["0-7d", "8-30d", "31-90d", "90+d"]
        .iter()
        .map(|b| json!({ "bucket": b, "count": bucket_counts.get(b).copied().unwrap_or(0) }))
        .collect();

    let vs_prior_run = if had_prior_run {
        json!({
            "prior_run_at": prior_run_at,
            "resolved": resolved_count,
            "new": new_findings.len() as i64,
            "aged": aged,
            "unchanged": unchanged,
            "newly_p0": newly_p0,
        })
    } else {
        Value::Null
    };

    let mut next_fingerprints = Map::new();
    for item in &current {
        let m = match_by_current_fp.get(&item.fp);
        let first_seen = m.and_then(|m| str_field(&m.prior, "first_seen")).map(String::from).unwrap_or_else(|| now.to_string());
        next_fingerprints.insert(
            item.fp.clone(),
            json!({
                "severity": str_field(item.f, "severity").unwrap_or("low"),
                "first_seen": first_seen,
                "last_seen": now.to_string(),
                "loose": item.loose,
            }),
        );
    }
    let next_history = json!({ "run_at": now.to_string(), "fingerprints": next_fingerprints });

    Trajectory {
        summary: json!({ "vs_prior_run": vs_prior_run, "aging_buckets": aging_buckets }),
        next_history,
    }
}

/// Best-effort persistence of the fresh trajectory digest, mirroring JS: a
/// write failure never blocks the render.
pub fn persist_trajectory(history_path: &Path, next_history: &Value) {
    if let Some(parent) = history_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(history_path, serde_json::to_string_pretty(next_history).unwrap_or_default());
}

/// Result of a full render: the Markdown report body and the JSON summary
/// JS's `--agent` mode prints instead.
pub struct RenderedReport {
    pub markdown: String,
    pub agent_summary: Value,
}

/// Mirrors JS `render-report.mjs` end to end. `facts` and `report` are the
/// parsed `facts.json` / `report.json` contents (`report` defaults to the
/// JS "scanner-only pass" shape when `None`, exactly like
/// `flag('--report') ? JSON.parse(...) : { findings: [], ... }`).
pub fn render_report(facts: &Value, report: Option<&Value>, options: &RenderOptions) -> Result<RenderedReport, RenderReportError> {
    let workspace = str_field(facts, "workspace").unwrap_or(".");
    let workspace_path = PathBuf::from(workspace);
    let filter_dir = options.filter_dir.as_deref();

    let empty_report = json!({ "findings": [], "constraints_surface": [], "triage_top": [], "summary": {} });
    let report = report.unwrap_or(&empty_report);
    let lenses_ran = report
        .get("lenses_ran")
        .and_then(Value::as_array)
        .map(|a| !a.is_empty())
        .unwrap_or(false);

    let checks = facts.get("checks").and_then(Value::as_array).cloned().ok_or(RenderReportError::MissingField("checks"))?;

    let constraints_surface: Vec<Value> = report
        .get("constraints_surface")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|c| {
            let evidence = str_field(&c, "evidence").unwrap_or("").trim().to_string();
            let constraint_raw = str_field(&c, "constraint").unwrap_or("").trim().to_string();
            let constraint = if constraint_raw.is_empty() { "unknown".to_string() } else { constraint_raw };
            let status = if evidence.is_empty() { "unknown".to_string() } else { str_field(&c, "status").unwrap_or("unknown").to_string() };
            let evidence = if evidence.is_empty() { "unknown".to_string() } else { evidence };
            let mut c = c;
            c["constraint"] = json!(constraint);
            c["status"] = json!(status);
            c["evidence"] = json!(evidence);
            c
        })
        .collect();

    // Decomposition candidates.
    let mut decomposition_candidates: Vec<Value> = Vec::new();
    for item in facts.pointer("/decomposition/oversized").and_then(Value::as_array).into_iter().flatten() {
        let mut item = item.clone();
        item["candidate"] = item.get("file").cloned().unwrap_or(Value::Null);
        item["kind"] = json!("file-size");
        decomposition_candidates.push(item);
    }
    for item in facts.pointer("/decomposition/mechanical_splits").and_then(Value::as_array).into_iter().flatten() {
        let mut item = item.clone();
        item["candidate"] = item.get("dir").cloned().unwrap_or(Value::Null);
        item["kind"] = json!("mechanical-split");
        decomposition_candidates.push(item);
    }
    let decomposition_candidates: Vec<Value> = decomposition_candidates
        .into_iter()
        .filter(|item| in_dir(str_field(item, "candidate").unwrap_or(""), filter_dir))
        .collect();
    let runtime_candidates: Vec<&Value> = decomposition_candidates
        .iter()
        .filter(|item| str_field(item, "class").unwrap_or("runtime") == "runtime")
        .collect();

    let decomposition_assessments: Vec<Value> = report
        .get("decomposition_assessments")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let assessment_by_file: HashMap<String, &Value> = decomposition_assessments
        .iter()
        .filter_map(|a| clean_path(str_field(a, "file")).map(|p| (p, a)))
        .collect();
    let candidate_paths: HashSet<String> = decomposition_candidates
        .iter()
        .filter_map(|c| clean_path(str_field(c, "candidate")))
        .collect();
    let missing_assessments: Vec<&Value> = runtime_candidates
        .iter()
        .filter(|c| !assessment_by_file.contains_key(&clean_path(str_field(c, "candidate")).unwrap_or_default()))
        .copied()
        .collect();

    let review_trigger = facts.pointer("/decomposition/threshold").and_then(Value::as_f64);
    let second_assessor_incoming = {
        let config_path = workspace_path.join(".agent").join("config.json");
        fs::read_to_string(&config_path)
            .ok()
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v.pointer("/hygiene/secondAssessorIncomingRelationships").and_then(Value::as_i64))
            .filter(|v| *v >= 1)
            .unwrap_or(25)
    };

    let mut invalid_assessments: Vec<Value> = Vec::new();
    for candidate in &runtime_candidates {
        let path = clean_path(str_field(candidate, "candidate")).unwrap_or_default();
        if let Some(assessment) = assessment_by_file.get(&path) {
            let problems = assessment_problems_for(candidate, assessment, review_trigger, second_assessor_incoming);
            if !problems.is_empty() {
                invalid_assessments.push(json!({ "candidate": candidate.get("candidate").cloned().unwrap_or(Value::Null), "problems": problems }));
            }
        }
    }
    let assessment_problems_by_file: HashMap<String, Vec<String>> = invalid_assessments
        .iter()
        .filter_map(|item| {
            clean_path(item.get("candidate").and_then(Value::as_str))
                .map(|p| (p, item.get("problems").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default()))
        })
        .collect();

    let findings_raw = report.get("findings").and_then(Value::as_array).cloned().unwrap_or_default();
    let invalid_confirmed: Vec<String> = decomposition_assessments
        .iter()
        .filter(|a| str_field(a, "verdict") == Some("confirmed"))
        .filter(|a| {
            let finding_id = str_field(a, "findingId");
            let finding = finding_id.and_then(|id| findings_raw.iter().find(|f| str_field(f, "id") == Some(id)));
            match finding {
                None => true,
                Some(f) => str_field(f, "subtype") != Some("decomposition") || !valid_decomposition_plan(f.get("decomposition_plan"), &workspace_path),
            }
        })
        .filter_map(|a| str_field(a, "file").map(String::from))
        .collect();
    let undetermined_assessments: Vec<&Value> = runtime_candidates
        .iter()
        .filter(|c| {
            let path = clean_path(str_field(c, "candidate")).unwrap_or_default();
            assessment_by_file.get(&path).map(|a| str_field(a, "verdict") == Some("undetermined")).unwrap_or(false)
        })
        .copied()
        .collect();
    let orphan_assessments: Vec<String> = decomposition_assessments
        .iter()
        .filter(|a| !clean_path(str_field(a, "file")).map(|p| candidate_paths.contains(&p)).unwrap_or(false))
        .filter_map(|a| str_field(a, "file").map(String::from))
        .collect();
    let decomposition_complete = missing_assessments.is_empty() && invalid_assessments.is_empty() && invalid_confirmed.is_empty();

    let decomposition_coverage = json!({
        "candidates": decomposition_candidates.len(),
        "runtime_candidates": runtime_candidates.len(),
        "assessed": runtime_candidates.len() as i64 - missing_assessments.len() as i64,
        "missing": missing_assessments.iter().map(|c| c.get("candidate").cloned().unwrap_or(Value::Null)).collect::<Vec<_>>(),
        "invalid_assessments": invalid_assessments,
        "invalid_confirmed": invalid_confirmed,
        "undetermined": undetermined_assessments.iter().map(|c| c.get("candidate").cloned().unwrap_or(Value::Null)).collect::<Vec<_>>(),
        "orphan_assessments": orphan_assessments,
        "complete": decomposition_complete,
    });

    // Findings: dedupe + filter-dir, then re-derive triage_top membership.
    let mut findings = dedupe(&findings_raw);
    findings.retain(|f| in_dir(str_field(f, "file").unwrap_or(""), filter_dir));
    let triage_top_ids: Vec<String> = report
        .get("triage_top")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
        .unwrap_or_default();
    let triage_top_ids: Vec<String> = if filter_dir.is_some() {
        triage_top_ids.into_iter().filter(|id| findings.iter().any(|f| str_field(f, "id") == Some(id))).collect()
    } else {
        triage_top_ids
    };

    let gate = quality_gate(facts);
    let coverage = coverage_gate(report.get("coverage"));
    let history_path = options
        .trajectory_history
        .clone()
        .unwrap_or_else(|| workspace_path.join(".audit").join("audit-trajectory.json"));
    let trajectory = compute_trajectory(&findings, &history_path, None);
    persist_trajectory(&history_path, &trajectory.next_history);

    let incomplete = facts.get("incomplete").and_then(Value::as_bool).unwrap_or(false);
    let score = health_score(&findings, incomplete, lenses_ran && decomposition_complete);

    // ---- Markdown ----
    let mut l: Vec<String> = Vec::new();
    let repo = Path::new(workspace).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "repo".into());
    let date: String = facts.get("generated_at").and_then(Value::as_str).unwrap_or("").chars().take(10).collect();
    let commit: String = checks
        .iter()
        .find(|c| str_field(c, "check") == Some("repo"))
        .and_then(|c| c.pointer("/meta/commit"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .chars()
        .take(10)
        .collect();
    l.push(format!("# Audit — {repo} · {date}{}", if commit.is_empty() { String::new() } else { format!(" · {commit}") }));
    if incomplete {
        l.push("\n> ⛔ **INCOMPLETE** — a required scanner did not run. Findings below are partial; see §1.".into());
    }
    if !lenses_ran {
        l.push("\n> ⛔ **REASONING LENSES NOT RUN** — scanner-only pass. Decomposition (beyond the deterministic LOC floor), architecture quality, AI-slop, correctness, and minimize were NOT assessed. Health score withheld; do NOT report this audit as clean.".into());
    }
    if lenses_ran && !decomposition_complete {
        l.push(format!(
            "\n> ⛔ **DECOMPOSITION REVIEW INCOMPLETE** — {} runtime size candidate(s) were not assessed, {} assessment(s) fail the evidence bar (verdict/rationale/symbol-level loci), and {} confirmed assessment(s) lack a complete, on-disk Architect target design. LOC is not a verdict; complete the evidence-backed architecture review.",
            missing_assessments.len(),
            invalid_assessments.len(),
            invalid_confirmed.len()
        ));
    }
    let ran_count = checks.iter().filter(|c| str_field(c, "status") == Some("ran")).count();
    l.push(format!(
        "\n**Repo health: {}** · {} findings · {}/{} checks ran{}",
        match score {
            None => "_withheld — lenses not run_".to_string(),
            Some(s) => format!("{s}/100 ({})", if s >= 85 { "good" } else if s >= 60 { "fair" } else { "poor" }),
        },
        findings.len(),
        ran_count,
        checks.len(),
        if lenses_ran { "" } else { " · ⚠️ lenses not run" }
    ));
    let gate_icon = match str_field(&gate, "state") {
        Some("CLEAN") => "✅",
        Some("NOT CLEAN") => "⛔",
        Some("UNPROVEN") => "⚠️",
        _ => "•",
    };
    l.push(format!(
        "\n**Quality gate: {gate_icon} {}** — clean requires 0 warnings/errors across `lint` · `types` · `build`.",
        str_field(&gate, "state").unwrap_or("")
    ));
    if let Some(failed) = gate.get("failed").and_then(Value::as_array) {
        if !failed.is_empty() {
            let parts: Vec<String> = failed
                .iter()
                .map(|c| {
                    let tool = str_field(c, "tool").map(|t| format!(" ({t})")).unwrap_or_default();
                    let count = c.get("findings_count").and_then(Value::as_i64).unwrap_or(0);
                    let val = if count > 0 { format!("{count} finding(s)") } else { format!("exit {}", c.get("exit_code").and_then(Value::as_i64).unwrap_or(0)) };
                    format!("`{}`{} = {}", str_field(c, "check").unwrap_or(""), tool, val)
                })
                .collect();
            l.push(format!("> ⛔ {} — must reach **0** to be called clean.", parts.join(" · ")));
        }
    }
    if str_field(&gate, "state") == Some("UNPROVEN") {
        if let Some(unproven) = gate.get("unproven").and_then(Value::as_array) {
            let parts: Vec<String> = unproven
                .iter()
                .map(|c| {
                    let tool = str_field(c, "tool").map(|t| format!(" ({t})")).unwrap_or_default();
                    format!("`{}` {}{}", str_field(c, "check").unwrap_or(""), str_field(c, "status").unwrap_or(""), tool)
                })
                .collect();
            l.push(format!("> ⚠️ Cannot certify clean — {} did not run. Install the tool / wire the linter, then re-audit.", parts.join(", ")));
        }
    }
    l.push(String::new());
    if let Some(v) = trajectory.summary.get("vs_prior_run").filter(|v| !v.is_null()) {
        let prior_at: String = str_field(v, "prior_run_at").unwrap_or("unknown").chars().take(10).collect();
        l.push(format!(
            "**Trajectory vs prior run** ({prior_at}): resolved {} · new {} · aged {} · unchanged {} · newly-P0 {}",
            v.get("resolved").and_then(Value::as_i64).unwrap_or(0),
            v.get("new").and_then(Value::as_i64).unwrap_or(0),
            v.get("aged").and_then(Value::as_i64).unwrap_or(0),
            v.get("unchanged").and_then(Value::as_i64).unwrap_or(0),
            v.get("newly_p0").and_then(Value::as_i64).unwrap_or(0),
        ));
    } else {
        l.push("**Trajectory:** first recorded run at this history path — no prior snapshot to diff against yet. Re-run to see `audit_diff`.".into());
    }
    if let Some(buckets) = trajectory.summary.get("aging_buckets").and_then(Value::as_array) {
        let parts: Vec<String> = buckets
            .iter()
            .map(|b| format!("{}={}", str_field(b, "bucket").unwrap_or(""), b.get("count").and_then(Value::as_i64).unwrap_or(0)))
            .collect();
        l.push(format!("_Aging: {}_", parts.join(" · ")));
    }
    l.push(String::new());
    if let Some(scope) = facts.get("scope").filter(|v| !v.is_null()) {
        l.push(format!(
            "Scope: {} · type={}{}{}{} · changed_files={}",
            str_field(scope, "mode").unwrap_or("whole-repo"),
            str_field(scope, "type").unwrap_or("all"),
            str_field(scope, "dir").map(|d| format!(" · dir={d}")).unwrap_or_default(),
            str_field(scope, "base").map(|b| format!(" · base={b}")).unwrap_or_default(),
            str_field(scope, "base_commit").map(|b| format!(" · base_commit={b}")).unwrap_or_default(),
            scope.get("changed_files").and_then(Value::as_array).map(|a| a.len()).unwrap_or(0),
        ));
        l.push(String::new());
    }
    if let Some(dir) = filter_dir {
        l.push(format!("Filter: findings under `{dir}`"));
        l.push(String::new());
    }

    if !constraints_surface.is_empty() {
        l.push("## 0 · Constraints surface".into());
        l.push("_Evidence-backed constraints that bound recommendations; `unknown` is explicit, never guessed._\n".into());
        l.push("| scope | constraint | evidence | status |".into());
        l.push("|---|---|---|---|".into());
        for c in &constraints_surface {
            l.push(format!(
                "| {} | {} | {} | {} |",
                cell(str_field(c, "scope").unwrap_or("general")),
                cell(str_field(c, "constraint").unwrap_or("unknown")),
                cell(str_field(c, "evidence").unwrap_or("unknown")),
                cell(str_field(c, "status").unwrap_or("unknown")),
            ));
        }
        l.push(String::new());
    }

    l.push("## 1 · Proof — scanner coverage".into());
    l.push("_Re-run any command to verify — the audit does not ask you to trust it._\n".into());
    l.push("| check | tool | command | status | exit | findings | candidates | log |".into());
    l.push("|---|---|---|---|---|---|---|---|".into());
    for c in &checks {
        let cmd = str_field(c, "command").map(|s| format!("`{s}`")).unwrap_or_else(|| "—".into());
        let status = str_field(c, "status").unwrap_or("");
        let reason = if status != "ran" {
            str_field(c, "skip_reason").map(|r| format!(" _({r})_")).unwrap_or_default()
        } else {
            String::new()
        };
        l.push(format!(
            "| {} | {} | {} | {} {}{} | {} | {} | {} | {} |",
            str_field(c, "check").unwrap_or(""),
            str_field(c, "tool").unwrap_or("—"),
            cmd,
            icon(status),
            status,
            reason,
            c.get("exit_code").map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
            c.get("findings_count").map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
            c.get("candidate_count").map(|v| v.to_string()).unwrap_or_else(|| "—".into()),
            str_field(c, "log").unwrap_or("—"),
        ));
    }
    l.push(String::new());
    let checks_set = security_checks();
    for c in checks.iter().filter(|c| {
        checks_set.contains(str_field(c, "check").unwrap_or(""))
            && str_field(c, "status") != Some("ran")
            && !str_field(c, "skip_reason").unwrap_or("").to_lowercase().starts_with("no ")
    }) {
        l.push(format!(
            "> ⚠️ **NOT SCANNED: {} ({}).** {}. Any {} statement below is an unverified LLM hint, **not** a scan result — treat as untriaged.",
            str_field(c, "check").unwrap_or(""),
            str_field(c, "tool").unwrap_or("n/a"),
            str_field(c, "skip_reason").unwrap_or("did not run"),
            str_field(c, "check").unwrap_or(""),
        ));
    }
    l.push(String::new());

    l.push("## 2 · Decomposition assessments".into());
    l.push("_LOC/bytes only trigger review. A confirmed verdict requires responsibility, dependency, state, caller, and test evidence plus an Architect target design._\n".into());
    if decomposition_candidates.is_empty() {
        l.push("_No size-triggered components._".into());
    }
    for candidate in &decomposition_candidates {
        let path = clean_path(str_field(candidate, "candidate")).unwrap_or_default();
        let assessment = assessment_by_file.get(&path);
        let size = if str_field(candidate, "kind") == Some("mechanical-split") {
            format!(
                "{} reconstructed LOC across {} parts",
                candidate.get("logical_loc").map(|v| v.to_string()).unwrap_or_default(),
                candidate.get("parts").map(|v| v.to_string()).unwrap_or_default()
            )
        } else {
            format!(
                "{} LOC{}",
                candidate.get("loc").map(|v| v.to_string()).unwrap_or_default(),
                candidate.get("bytes").map(|b| format!(" / {b} bytes")).unwrap_or_default()
            )
        };
        match assessment {
            None => l.push(format!("- `{}` — **unassessed** ({size}; review trigger only)", str_field(candidate, "candidate").unwrap_or(""))),
            Some(assessment) => {
                l.push(format!(
                    "- `{}` — **{}** ({size}) — {}{}",
                    str_field(candidate, "candidate").unwrap_or(""),
                    str_field(assessment, "verdict").unwrap_or(""),
                    str_field(assessment, "rationale").unwrap_or("no rationale supplied"),
                    str_field(assessment, "findingId").map(|id| format!(" · finding `{id}`")).unwrap_or_default(),
                ));
                if let Some(ev) = assessment.get("evidence").and_then(Value::as_array).filter(|a| !a.is_empty()) {
                    let items: Vec<String> = ev.iter().filter_map(|v| v.as_str()).map(|s| format!("`{s}`")).collect();
                    l.push(format!("  - evidence: {}", items.join(", ")));
                }
                if let Some(problems) = assessment_problems_by_file.get(&path) {
                    l.push(format!("  - ⛔ invalid assessment: {}", problems.join("; ")));
                }
            }
        }
    }
    if !undetermined_assessments.is_empty() {
        l.push(format!(
            "\n> ⚠️ {} runtime candidate(s) are **undetermined**. Honest in a read-only audit (the assessment must name the missing evidence); in audit-fix these are OPEN work — gather the evidence or report them OPEN, never fold them into \"clean\".",
            undetermined_assessments.len()
        ));
    }
    l.push(String::new());

    l.push("## 2A · Test coverage on the change".into());
    l.push("_Read of the diff against the test set — no test execution. Below 0.8 coverage ratio is high, below 0.5 (or any touched symbol with zero covering test) is critical. `UNPROVEN` when the repo has no test infrastructure to read against — never reported as clean._\n".into());
    match &coverage {
        None => l.push("_Not reported this run — coverage-on-the-change is diff-scoped lens output (see `/commit`, `references/coverage-and-trajectory.md`). A whole-repo `/audit` pass may have nothing to diff against._".into()),
        Some(coverage) => {
            let cov_icon = match str_field(coverage, "state") {
                Some("CLEAN") => "✅",
                Some("UNPROVEN") => "⚠️",
                _ => "⛔",
            };
            let ratio_str = coverage.get("ratio").and_then(Value::as_f64).map(|r| format!("{:.0}%", r * 100.0)).unwrap_or_else(|| "unproven (no test infrastructure)".into());
            l.push(format!(
                "**Coverage gate: {cov_icon} {}** — ratio {ratio_str}{}",
                str_field(coverage, "state").unwrap_or(""),
                str_field(coverage, "severity").map(|s| format!(" · severity: **{s}**")).unwrap_or_default(),
            ));
            if let Some(no_test) = coverage.get("noTestFiles").and_then(Value::as_array).filter(|a| !a.is_empty()) {
                let items: Vec<String> = no_test.iter().filter_map(|v| v.as_str()).map(|s| format!("`{s}`")).collect();
                l.push(format!("> ⛔ {} touched file(s) have **no covering test at all**: {}", no_test.len(), items.join(", ")));
            }
            l.push(String::new());
            l.push("| file | touched | covered | uncovered | tests | verdict |".into());
            l.push("|---|---|---|---|---|---|".into());
            for row in coverage.get("perFile").and_then(Value::as_array).into_iter().flatten() {
                let join_field = |k: &str| -> String {
                    row.get(k)
                        .and_then(Value::as_array)
                        .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "))
                        .filter(|s| !s.is_empty())
                        .unwrap_or_else(|| "—".into())
                };
                l.push(format!(
                    "| `{}` | {} | {} | {} | {} | {} |",
                    cell(str_field(row, "file").unwrap_or("")),
                    cell(&join_field("touched")),
                    cell(&join_field("covered")),
                    cell(&join_field("uncovered")),
                    cell(&join_field("tests")),
                    cell(str_field(row, "verdict").unwrap_or("unknown")),
                ));
            }
        }
    }
    l.push(String::new());

    let by_id: HashMap<&str, &Value> = findings.iter().filter_map(|f| str_field(f, "id").map(|id| (id, f))).collect();
    let mut top: Vec<&Value> = triage_top_ids.iter().filter_map(|id| by_id.get(id.as_str()).copied()).collect();
    if top.is_empty() {
        let mut sorted: Vec<&Value> = findings.iter().collect();
        sorted.sort_by_key(|f| sev_rank(str_field(f, "severity").unwrap_or("")));
        top = sorted.into_iter().take(10).collect();
    }
    l.push("## 3 · Top 10 that matter".into());
    if top.is_empty() {
        l.push("_No findings._".into());
    }
    for (i, f) in top.iter().take(10).enumerate() {
        l.push(format!(
            "{}. `[{}][{}]` **{}** — `{}{}` ({})",
            i + 1,
            str_field(f, "severity").unwrap_or(""),
            str_field(f, "tier").unwrap_or("MANUAL"),
            str_field(f, "title").unwrap_or(""),
            str_field(f, "file").unwrap_or(""),
            f.get("line").filter(|v| !v.is_null()).map(|line| format!(":{line}")).unwrap_or_default(),
            str_field(f, "id").unwrap_or(""),
        ));
    }
    l.push(String::new());

    l.push("## 4 · Findings by remediation type".into());
    let mut groups: Vec<(String, Vec<&Value>)> = Vec::new();
    for f in &findings {
        let label = remediation_label(str_field(f, "category").unwrap_or(""));
        match groups.iter_mut().find(|(g, _)| g == label) {
            Some((_, items)) => items.push(f),
            None => groups.push((label.to_string(), vec![f])),
        }
    }
    let mut overflow: Vec<&Value> = Vec::new();
    for (group, mut items) in groups {
        items.sort_by_key(|f| sev_rank(str_field(f, "severity").unwrap_or("")));
        let (body, rest) = if items.len() > CAP { items.split_at(CAP) } else { (&items[..], &items[items.len()..]) };
        overflow.extend(rest.iter().copied());
        l.push(format!(
            "\n### {group} ({}{})",
            items.len(),
            if rest.is_empty() { String::new() } else { format!(", {} shown", body.len()) }
        ));
        for f in body {
            render_finding(&mut l, f, &workspace_path);
        }
    }
    if findings.is_empty() {
        l.push("\n_No findings emitted by the reasoning lenses._".into());
    }
    l.push(String::new());

    l.push("## 5 · Skipped / not-scanned".into());
    let skipped: Vec<&Value> = checks.iter().filter(|c| str_field(c, "status") != Some("ran")).collect();
    if skipped.is_empty() {
        l.push("_Every check ran._".into());
    }
    for c in &skipped {
        l.push(format!(
            "- **{}** ({}): {} — {}",
            str_field(c, "check").unwrap_or(""),
            str_field(c, "tool").unwrap_or("n/a"),
            str_field(c, "status").unwrap_or(""),
            str_field(c, "skip_reason").unwrap_or(""),
        ));
    }
    l.push(String::new());

    l.push("## 6 · Appendix".into());
    if !overflow.is_empty() {
        l.push(format!("\n### Overflow findings ({})", overflow.len()));
        for f in &overflow {
            render_finding(&mut l, f, &workspace_path);
        }
    }
    l.push("\n### Re-run commands".into());
    for c in checks.iter().filter(|c| c.get("command").map(|v| !v.is_null()).unwrap_or(false)) {
        l.push(format!("- `{}`  → {}", str_field(c, "command").unwrap_or(""), str_field(c, "log").unwrap_or("(no log)")));
    }
    l.push("\n### Raw logs".into());
    l.push(format!("Evidence dir: `{}`", str_field(facts, "out_dir").unwrap_or("")));

    let markdown = l.join("\n");

    let agent_summary = json!({
        "kind": "audit-agent-summary",
        "schema_version": report.get("schema_version").and_then(Value::as_i64).unwrap_or(1),
        "workspace": facts.get("workspace").cloned().unwrap_or(Value::Null),
        "generated_at": facts.get("generated_at").cloned().unwrap_or(Value::Null),
        "scope": facts.get("scope").cloned().unwrap_or(Value::Null),
        "filter_dir": filter_dir,
        "incomplete": incomplete || !lenses_ran || !decomposition_complete,
        "lenses_ran": if lenses_ran { report.get("lenses_ran").cloned().unwrap_or(json!([])) } else { json!(false) },
        "quality_gate": str_field(&gate, "state"),
        "quality_gate_failed": gate.get("failed").and_then(Value::as_array).map(|a| a.iter().map(|c| json!({
            "check": c.get("check"), "tool": c.get("tool").cloned().unwrap_or(Value::Null),
            "findings": c.get("findings_count").cloned().unwrap_or(Value::Null),
            "exit": c.get("exit_code").cloned().unwrap_or(Value::Null),
        })).collect::<Vec<_>>()).unwrap_or_default(),
        "coverage_gate": coverage.as_ref().map(|c| json!({
            "state": c.get("state"), "ratio": c.get("ratio"), "severity": c.get("severity"), "no_test_files": c.get("noTestFiles"),
        })),
        "audit_diff": trajectory.summary,
        "constraints_surface": constraints_surface.iter().map(|c| json!({
            "scope": c.get("scope").cloned().unwrap_or(Value::Null),
            "constraint": c.get("constraint").cloned().unwrap_or(json!("unknown")),
            "evidence": c.get("evidence").cloned().unwrap_or(json!("unknown")),
            "status": c.get("status").cloned().unwrap_or(json!("unknown")),
        })).collect::<Vec<_>>(),
        "decomposition_coverage": decomposition_coverage,
        "decomposition_assessments": decomposition_assessments,
        "findings": findings.iter().map(|f| json!({
            "id": f.get("id").cloned().unwrap_or(Value::Null),
            "severity": f.get("severity").cloned().unwrap_or(Value::Null),
            "tier": str_field(f, "tier").unwrap_or("MANUAL"),
            "category": f.get("category").cloned().unwrap_or(Value::Null),
            "file": f.get("file").cloned().unwrap_or(Value::Null),
            "line": f.get("line").cloned().unwrap_or(Value::Null),
            "title": f.get("title").cloned().unwrap_or(Value::Null),
            "action": str_field(f, "action").unwrap_or(""),
            "evidence": str_field(f, "evidence").unwrap_or(""),
            "evidence_strength": f.get("evidence_strength").cloned().unwrap_or(Value::Null),
            "judgment": f.get("judgment").cloned().unwrap_or(Value::Null),
            "status": f.get("status").cloned().unwrap_or(Value::Null),
            "caused_by": f.get("caused_by").cloned().unwrap_or(json!([])),
            "sources": f.get("sources").cloned().unwrap_or(json!([])),
            "decomposition_plan": f.get("decomposition_plan").cloned().unwrap_or(Value::Null),
        })).collect::<Vec<_>>(),
    });

    Ok(RenderedReport { markdown, agent_summary })
}

fn icon(status: &str) -> &'static str {
    match status {
        "ran" => "✅",
        "skipped" => "⚠️",
        "error" => "⛔",
        _ => "•",
    }
}

fn cell(value: &str) -> String {
    value.replace('|', "\\|").replace("\r\n", " ").replace('\n', " ")
}

fn render_finding(l: &mut Vec<String>, f: &Value, workspace: &Path) {
    let mut meta = Vec::new();
    if let Some(s) = str_field(f, "evidence_strength") {
        meta.push(format!("evidence-strength: **{s}**"));
    }
    if let Some(s) = str_field(f, "judgment") {
        meta.push(format!("judgment: **{s}**"));
    }
    if let Some(s) = str_field(f, "status") {
        meta.push(format!("status: **{s}**"));
    }
    l.push(format!(
        "\n**[{}] {}**  `{}` · tier: **{}** · `{}{}`{}{}",
        str_field(f, "id").unwrap_or(""),
        str_field(f, "title").unwrap_or(""),
        str_field(f, "severity").unwrap_or(""),
        str_field(f, "tier").unwrap_or("MANUAL"),
        str_field(f, "file").unwrap_or(""),
        f.get("line").filter(|v| !v.is_null()).map(|line| format!(":{line}")).unwrap_or_default(),
        str_field(f, "evidence").map(|e| format!(" · evidence: `{e}`")).unwrap_or_default(),
        if meta.is_empty() { String::new() } else { format!(" · {}", meta.join(" · ")) },
    ));
    if let Some(caused_by) = f.get("caused_by").and_then(Value::as_array).filter(|a| !a.is_empty()) {
        let ids: Vec<String> = caused_by.iter().filter_map(|v| v.as_str()).map(|s| format!("`{s}`")).collect();
        l.push(format!("caused by: {}", ids.join(", ")));
    }
    if let Some(detail) = str_field(f, "detail") {
        l.push(format!("> {detail}"));
    }
    if let Some(action) = str_field(f, "action") {
        l.push(format!("**Fix:** {action}"));
    }
    if let Some(fix) = str_field(f, "fix") {
        let is_diff = fix.lines().any(|line| line.starts_with('+') || line.starts_with('-'));
        l.push(format!("```{}", if is_diff { "diff" } else { "" }));
        l.push(fix.to_string());
        l.push("```".to_string());
    }
    if str_field(f, "subtype") == Some("decomposition") {
        if let Some(plan) = f.get("decomposition_plan").filter(|v| !v.is_null()) {
            render_decomposition_plan(l, plan, workspace);
        }
    }
}

fn render_decomposition_plan(l: &mut Vec<String>, plan: &Value, _workspace: &Path) {
    l.push("\n#### Decomposition design".into());
    l.push(format!("**Verdict:** {}", str_field(plan, "verdict").unwrap_or("")));
    l.push("\n**Current responsibilities**".into());
    for item in plan.get("current_responsibilities").and_then(Value::as_array).into_iter().flatten() {
        let symbols: Vec<String> = item.get("symbols").and_then(Value::as_array).into_iter().flatten().filter_map(|v| v.as_str()).map(|s| format!("`{s}`")).collect();
        let evidence: Vec<String> = item.get("evidence").and_then(Value::as_array).into_iter().flatten().filter_map(|v| v.as_str()).map(|s| format!("`{s}`")).collect();
        l.push(format!(
            "- **{}** — symbols: {}; evidence: {}",
            str_field(item, "name").unwrap_or(""),
            if symbols.is_empty() { "unknown".into() } else { symbols.join(", ") },
            if evidence.is_empty() { "unknown".into() } else { evidence.join(", ") },
        ));
    }
    let keep = plan.get("keep_in_place").cloned().unwrap_or(Value::Null);
    let keep_symbols = keep.get("symbols").and_then(Value::as_array).filter(|a| !a.is_empty());
    l.push(format!(
        "\n**Keep in place:** **{}** — {}{}",
        str_field(&keep, "component").unwrap_or("unknown"),
        str_field(&keep, "responsibility").unwrap_or("unknown"),
        keep_symbols
            .map(|a| format!("; symbols: {}", a.iter().filter_map(|v| v.as_str()).map(|s| format!("`{s}`")).collect::<Vec<_>>().join(", ")))
            .unwrap_or_default(),
    ));
    l.push("\n**Target components**".into());
    l.push("| component | destination | responsibility | moves | public contract | dependencies |".into());
    l.push("|---|---|---|---|---|---|".into());
    for item in plan.get("target_components").and_then(Value::as_array).into_iter().flatten() {
        let moves: Vec<&str> = item.get("moves").and_then(Value::as_array).into_iter().flatten().filter_map(|v| v.as_str()).collect();
        let deps: Vec<&str> = item.get("dependencies").and_then(Value::as_array).into_iter().flatten().filter_map(|v| v.as_str()).collect();
        l.push(format!(
            "| {} | `{}` | {} | {} | `{}` | {} |",
            cell(str_field(item, "component").unwrap_or("")),
            cell(str_field(item, "destination").unwrap_or("")),
            cell(str_field(item, "responsibility").unwrap_or("")),
            cell(&moves.join(", ")),
            cell(str_field(item, "public_contract").unwrap_or("")),
            if deps.is_empty() { "none".to_string() } else { cell(&deps.join(", ")) },
        ));
    }
    l.push("\n**Implementation sequence**".into());
    for item in plan.get("steps").and_then(Value::as_array).into_iter().flatten() {
        l.push(format!(
            "{}. {} — verify: {}",
            item.get("order").and_then(Value::as_i64).unwrap_or(1),
            str_field(item, "change").unwrap_or(""),
            str_field(item, "verification").unwrap_or(""),
        ));
    }
    l.push("\n**Behavior-preservation contracts**".into());
    for item in plan.get("behavior_contracts").and_then(Value::as_array).into_iter().flatten() {
        if let Some(s) = item.as_str() {
            l.push(format!("- {s}"));
        }
    }
    if let Some(risks) = plan.get("risks").and_then(Value::as_array).filter(|a| !a.is_empty()) {
        l.push("\n**Risks**".into());
        for item in risks {
            if let Some(s) = item.as_str() {
                l.push(format!("- {s}"));
            }
        }
    }
    l.push(format!("\n**Architect decision:** `{}`", str_field(plan, "architect_decision_ref").unwrap_or("missing")));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn unique_scratch_path(prefix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{prefix}-{}-{}-{}",
            std::process::id(),
            now_unix_secs() as u64,
            NEXT_ID.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn quality_gate_clean_requires_all_relevant_checks_to_run_with_zero_findings() {
        let facts = json!({
            "checks": [
                { "check": "lint", "status": "ran", "findings_count": 0, "exit_code": 0 },
                { "check": "types", "status": "ran", "findings_count": 0, "exit_code": 0 },
                { "check": "build", "status": "ran", "findings_count": 0, "exit_code": 0 },
            ],
        });
        let gate = quality_gate(&facts);
        assert_eq!(gate["state"], json!("CLEAN"));
    }

    #[test]
    fn quality_gate_not_clean_on_findings() {
        let facts = json!({
            "checks": [
                { "check": "lint", "status": "ran", "findings_count": 3, "exit_code": 0 },
            ],
        });
        let gate = quality_gate(&facts);
        assert_eq!(gate["state"], json!("NOT CLEAN"));
    }

    #[test]
    fn quality_gate_unproven_when_tool_missing() {
        let facts = json!({
            "checks": [
                { "check": "lint", "status": "error", "skip_reason": "no eslint installed" },
            ],
        });
        let gate = quality_gate(&facts);
        assert_eq!(gate["state"], json!("UNPROVEN"));
    }

    #[test]
    fn quality_gate_structural_no_skip_is_not_a_gate_member() {
        let facts = json!({
            "checks": [
                { "check": "lint", "status": "skipped", "skip_reason": "no linter configured" },
            ],
        });
        let gate = quality_gate(&facts);
        // "no ..." skip is excluded from `unproven`, and with nothing `ran`, state is UNPROVEN
        // (never silently CLEAN) per the JS `!ran.length` branch.
        assert_eq!(gate["state"], json!("UNPROVEN"));
        assert!(gate["unproven"].as_array().unwrap().is_empty());
    }

    #[test]
    fn coverage_gate_none_when_no_perfile_rows() {
        assert!(coverage_gate(None).is_none());
        assert!(coverage_gate(Some(&json!({}))).is_none());
    }

    #[test]
    fn coverage_gate_critical_on_untested_touched_file() {
        let coverage = json!({
            "ratio": 0.9,
            "perFile": [{ "file": "a.rs", "touched": ["f"], "covered": [], "uncovered": ["f"], "tests": [] }],
        });
        let gate = coverage_gate(Some(&coverage)).unwrap();
        assert_eq!(gate["state"], json!("NOT CLEAN"));
        assert_eq!(gate["severity"], json!("critical"));
    }

    #[test]
    fn coverage_gate_clean_above_threshold() {
        let coverage = json!({
            "ratio": 0.85,
            "perFile": [{ "file": "a.rs", "touched": ["f"], "covered": ["f"], "uncovered": [], "tests": ["t"] }],
        });
        let gate = coverage_gate(Some(&coverage)).unwrap();
        assert_eq!(gate["state"], json!("CLEAN"));
    }

    #[test]
    fn health_score_withheld_when_lenses_not_run() {
        assert_eq!(health_score(&[], false, false), None);
    }

    #[test]
    fn health_score_deducts_by_severity_and_incompleteness() {
        let findings = vec![json!({ "severity": "critical" }), json!({ "severity": "low" })];
        let score = health_score(&findings, true, true).unwrap();
        assert_eq!(score, 100 - 25 - 1 - 10);
    }

    #[test]
    fn dedupe_merges_line_specific_findings_keeping_worse_severity() {
        let findings = vec![
            json!({ "file": "a.rs", "line": 10, "category": "security", "severity": "medium", "title": "m1", "sources": ["scanner-a"] }),
            json!({ "file": "a.rs", "line": 10, "category": "security", "severity": "critical", "title": "m2", "sources": ["scanner-b"] }),
        ];
        let merged = dedupe(&findings);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0]["severity"], json!("critical"));
        assert_eq!(merged[0]["title"], json!("m2"));
        let sources: HashSet<String> = merged[0]["sources"].as_array().unwrap().iter().filter_map(|v| v.as_str().map(String::from)).collect();
        assert_eq!(sources, HashSet::from(["scanner-a".to_string(), "scanner-b".to_string()]));
    }

    #[test]
    fn dedupe_keeps_distinct_file_level_findings_by_title() {
        let findings = vec![
            json!({ "file": "package.json", "category": "security", "severity": "high", "title": "CVE-1" }),
            json!({ "file": "package.json", "category": "security", "severity": "high", "title": "CVE-2" }),
        ];
        assert_eq!(dedupe(&findings).len(), 2);
    }

    #[test]
    fn evidence_problems_rejects_missing_and_whole_file_spans() {
        let candidate = json!({ "candidate": "src/big.rs", "loc": 500 });
        let missing = evidence_problems(&candidate, "file-size", "confirmed", None, Some(500.0), "");
        assert!(missing.iter().any(|p| p.contains("missing evidence")));

        let whole_file = json!(["src/big.rs:1-500"]);
        let problems = evidence_problems(&candidate, "file-size", "confirmed", Some(&whole_file), Some(500.0), "");
        assert!(problems.iter().any(|p| p.contains("whole-file span")));

        let sub_span = json!(["src/big.rs:10-20"]);
        let problems = evidence_problems(&candidate, "file-size", "confirmed", Some(&sub_span), Some(500.0), "");
        assert!(problems.is_empty());
    }

    #[test]
    fn assessment_problems_requires_second_assessor_at_high_stakes() {
        let candidate = json!({ "candidate": "src/huge.rs", "kind": "file-size", "loc": 1000 });
        let assessment = json!({
            "verdict": "not-needed",
            "rationale": "looked fine",
            "evidence": ["src/huge.rs:5-10"],
        });
        let problems = assessment_problems_for(&candidate, &assessment, Some(100.0), 25);
        assert!(problems.iter().any(|p| p.contains("requires second_assessor")));
    }

    #[test]
    fn assessment_problems_clean_when_second_assessor_agrees() {
        let candidate = json!({ "candidate": "src/huge.rs", "kind": "file-size", "loc": 1000 });
        let assessment = json!({
            "verdict": "not-needed",
            "rationale": "looked fine",
            "evidence": ["src/huge.rs:5-10"],
            "second_assessor": {
                "verdict": "not-needed",
                "rationale": "agreed",
                "evidence": ["src/huge.rs:15-20"],
            },
        });
        let problems = assessment_problems_for(&candidate, &assessment, Some(100.0), 25);
        assert!(problems.is_empty());
    }

    #[test]
    fn render_report_scanner_only_pass_withholds_score() {
        let facts = json!({
            "workspace": ".",
            "generated_at": "2026-01-01T00:00:00Z",
            "checks": [{ "check": "lint", "status": "ran", "findings_count": 0, "exit_code": 0 }],
        });
        let options = RenderOptions {
            trajectory_history: Some(unique_scratch_path("wf066-traj").with_extension("json")),
            ..Default::default()
        };
        let rendered = render_report(&facts, None, &options).unwrap();
        assert!(rendered.markdown.contains("REASONING LENSES NOT RUN"));
        assert!(rendered.markdown.contains("_withheld — lenses not run_"));
        let _ = fs::remove_file(options.trajectory_history.unwrap());
    }

    #[test]
    fn trajectory_first_run_has_no_prior_snapshot() {
        let findings = vec![json!({ "file": "a.rs", "line": 1, "category": "security", "severity": "high", "title": "t" })];
        let history_path = unique_scratch_path("wf066-traj-first").with_extension("json");
        let _ = fs::remove_file(&history_path);
        let trajectory = compute_trajectory(&findings, &history_path, Some(json!({})));
        assert!(trajectory.summary["vs_prior_run"].is_null());
    }

    #[test]
    fn trajectory_matches_by_exact_fingerprint() {
        let findings = vec![json!({ "file": "a.rs", "line": 1, "category": "security", "severity": "high", "title": "t" })];
        let fp = fingerprint(&findings[0]);
        let prior = json!({
            "run_at": "1000",
            "fingerprints": { fp.clone(): { "severity": "high", "first_seen": "500", "last_seen": "900", "loose": loose_fingerprint(&findings[0]) } },
        });
        let history_path = unique_scratch_path("wf066-traj-match").with_extension("json");
        let trajectory = compute_trajectory(&findings, &history_path, Some(prior));
        let v = &trajectory.summary["vs_prior_run"];
        assert_eq!(v["resolved"], json!(0));
        assert_eq!(v["new"], json!(0));
    }
}
