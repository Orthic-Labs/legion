//! `legion-dev audit-bench`: score an installed `legion audit` against the
//! planted-case fixtures in `evals/audit-bench/` (design ADR-6).
//!
//! It clones each fixture bundle, runs deterministic `legion audit`, and
//! optionally runs the installed host's bounded `audit run-reasoning` lifecycle.
//! Final finding locations are compared with human-ruled expectations in
//! `<fixture>.cases.json`; rows with `ruled: false` are never scored.

use rightkit_child_process::OwnedCommand;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::time::Duration;

const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const AUDIT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_GIT_STDOUT_BYTES: u64 = 64 * 1024;

fn run_bounded(
    command: &Path,
    args: &[String],
    cwd: &Path,
    stdout: Stdio,
    timeout: Duration,
) -> Result<ExitStatus, String> {
    let mut owned = OwnedCommand::new(command.as_os_str());
    owned
        .command_mut()
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(stdout)
        .stderr(Stdio::null());
    let mut child = owned
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", command.display()))?;
    match child.wait_timeout(timeout) {
        Ok(Some(status)) => Ok(status),
        Ok(None) => {
            let _ = child.terminate_tree_bounded(TERMINATION_TIMEOUT);
            Err(format!("{} exceeded {:?}", command.display(), timeout))
        }
        Err(error) => {
            let _ = child.terminate_tree_bounded(TERMINATION_TIMEOUT);
            Err(format!("cannot wait for {}: {error}", command.display()))
        }
    }
}

pub const CASES_SCHEMA: &str = "legion-audit-bench-cases/1";
pub const MAX_REPEATS: u32 = 10;
pub const DEFAULT_TOKEN_BUDGET: u64 = 100_000;
pub const DEFAULT_CASE_TOKEN_BUDGET: u64 = 10_000;
/// Hostless candidate generators measured by the deterministic `audit-behavior` sample.
/// This is a deliberately restricted stage, not a claim about full Audit completeness.
pub const AUDIT_BEHAVIOR_PROVIDERS: [&str; 2] =
    ["legacy.data.internal-suite", "legacy.security.binary-pins"];

fn valid_repeats(repeats: u32) -> bool {
    (1..=MAX_REPEATS).contains(&repeats)
}

fn default_true() -> bool {
    true
}

// ------------------------------------------------------------------ corpus

// `language`, `base`, `lens`, `severity`, `ruling` and `summary` are corpus
// documentation read by humans and by `deny_unknown_fields`, not by the scorer.
#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CaseFile {
    pub schema: String,
    pub fixture: String,
    #[serde(default)]
    pub split: Option<FixtureSplit>,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub base: String,
    pub cases: Vec<Case>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureSplit {
    Tuning,
    Heldout,
}

impl FixtureSplit {
    fn label(self) -> &'static str {
        match self {
            Self::Tuning => "tuning",
            Self::Heldout => "heldout",
        }
    }
}

impl CaseFile {
    fn split_label(&self) -> &'static str {
        self.split.map(FixtureSplit::label).unwrap_or("unknown")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Planted,
    Clean,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Category {
    Security,
    Correctness,
    Perf,
    Lean,
    CallerRegression,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    Right,
    Wrong,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Site {
    pub path: String,
    pub line_range: [u32; 2],
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Expected {
    pub path: String,
    pub line_range: [u32; 2],
    #[serde(default)]
    pub lens: String,
    #[serde(default)]
    pub severity: String,
    /// Other locations that also count as finding this item.
    #[serde(default)]
    pub alt: Vec<Site>,
}

/// A human ruling on one extra finding location in a planted case.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Ruling {
    pub path: String,
    pub line_range: [u32; 2],
    pub verdict: Verdict,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Case {
    pub id: String,
    pub kind: Kind,
    pub scope: String,
    #[serde(default)]
    pub category: Option<Category>,
    /// Rows without a ruling are never scored.
    #[serde(default = "default_true")]
    pub ruled: bool,
    #[serde(default)]
    pub ruling: Option<String>,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub expected: Vec<Expected>,
    #[serde(default)]
    pub rulings: Vec<Ruling>,
}

fn valid_ref(text: &str) -> bool {
    !text.is_empty()
        && text.starts_with(|c: char| c.is_ascii_alphanumeric())
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '@' | '-'))
}

/// What a case audits: a commit range or a single commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    Range { base: String, head: String },
    Commit(String),
}

pub fn parse_scope(text: &str) -> Result<Scope, String> {
    if let Some(rest) = text.strip_prefix("range:") {
        let (base, head) = rest
            .split_once("..")
            .ok_or_else(|| format!("range scope needs A..B: {text}"))?;
        if !valid_ref(base) || !valid_ref(head) || head.contains("..") {
            return Err(format!("invalid range scope: {text}"));
        }
        Ok(Scope::Range {
            base: base.to_string(),
            head: head.to_string(),
        })
    } else if let Some(rest) = text.strip_prefix("commit:") {
        if !valid_ref(rest) {
            return Err(format!("invalid commit scope: {text}"));
        }
        Ok(Scope::Commit(rest.to_string()))
    } else {
        Err(format!("scope must start with range: or commit: ({text})"))
    }
}

impl Scope {
    /// Ref checked out (detached) before the audit runs.
    pub fn head_ref(&self) -> &str {
        match self {
            Scope::Range { head, .. } => head,
            Scope::Commit(commit) => commit,
        }
    }

    /// Revision whose commit id becomes `legion audit --base`. `legion audit`
    /// accepts only plain refs, so the runner resolves this to a commit id.
    pub fn base_spec(&self) -> String {
        match self {
            Scope::Range { base, .. } => base.clone(),
            Scope::Commit(commit) => format!("{commit}^"),
        }
    }
}

fn range_ok(range: [u32; 2]) -> bool {
    range[0] >= 1 && range[0] <= range[1]
}

pub fn validate_case_file(file: &CaseFile) -> Result<(), String> {
    if file.schema != CASES_SCHEMA {
        return Err(format!(
            "{}: schema must be {CASES_SCHEMA}, got {}",
            file.fixture, file.schema
        ));
    }
    let mut seen = std::collections::BTreeSet::new();
    for case in &file.cases {
        let id = &case.id;
        if !seen.insert(id.clone()) {
            return Err(format!("duplicate case id {id}"));
        }
        parse_scope(&case.scope).map_err(|e| format!("{id}: {e}"))?;
        match case.kind {
            Kind::Planted => {
                if case.category.is_none() {
                    return Err(format!("{id}: planted case needs a category"));
                }
                if case.expected.is_empty() {
                    return Err(format!("{id}: planted case needs expected items"));
                }
            }
            Kind::Clean => {
                if !case.expected.is_empty() {
                    return Err(format!("{id}: clean case must not list expected items"));
                }
            }
        }
        for expected in &case.expected {
            let sites = std::iter::once(expected.line_range)
                .chain(expected.alt.iter().map(|site| site.line_range));
            for range in sites {
                if !range_ok(range) {
                    return Err(format!("{id}: bad line range {range:?}"));
                }
            }
        }
        for ruling in &case.rulings {
            if !range_ok(ruling.line_range) {
                return Err(format!("{id}: bad ruling line range"));
            }
        }
    }
    Ok(())
}

// ------------------------------------------------------------ observations

/// One reported location, `path`, `path:line` or `path:start-end`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loc {
    pub path: String,
    pub start: Option<u32>,
    pub end: Option<u32>,
}

/// One reported finding with all its locations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub locations: Vec<Loc>,
}

pub fn parse_location(text: &str) -> Loc {
    let text = text.replace('\\', "/");
    if let Some((path, tail)) = text.rsplit_once(':') {
        let numbers: Option<(u32, u32)> = match tail.split_once('-') {
            Some((a, b)) => a.parse().ok().zip(b.parse().ok()),
            None => tail.parse().ok().map(|n| (n, n)),
        };
        if let Some((start, end)) = numbers {
            return Loc {
                path: path.to_string(),
                start: Some(start),
                end: Some(end.max(start)),
            };
        }
    }
    Loc {
        path: text,
        start: None,
        end: None,
    }
}

/// Findings of a `report.json`: `findings[].locations[]`.
pub fn findings_from_report(report: &Value) -> Vec<Observed> {
    report
        .get("findings")
        .and_then(Value::as_array)
        .map(|findings| {
            findings
                .iter()
                .map(|finding| Observed {
                    locations: finding
                        .get("locations")
                        .and_then(Value::as_array)
                        .map(|locations| {
                            locations
                                .iter()
                                .filter_map(Value::as_str)
                                .map(parse_location)
                                .collect()
                        })
                        .unwrap_or_default(),
                })
                .collect()
        })
        .unwrap_or_default()
}

// ReportV1 & ReportV2 both flatten their Rust `extensions` map on the wire.
// Do not treat an absent canonical field as evidence of an empty provider set.
fn report_provider_results(report: &Value) -> Option<&Value> {
    report.get("providerResults")
}

fn report_metrics(report: &Value) -> Value {
    fn source_metric(details: Option<&Value>, key: &str, parent: &str, child: &str) -> Value {
        let value = details.and_then(|value| value.get(key)).or_else(|| {
            details
                .and_then(|value| value.get(parent))
                .and_then(|value| value.get(child))
        });
        match value {
            Some(value) => json!({"status": "reported", "value": value}),
            None => json!({"status": "unknown", "value": null}),
        }
    }
    let findings = report.get("findings").and_then(Value::as_array);
    let completeness = match report.get("status").and_then(Value::as_str) {
        Some("clean" | "findings") => json!({"status": "reported", "complete": true}),
        Some("incomplete" | "failed" | "blocked") => {
            json!({"status": "reported", "complete": false})
        }
        _ => json!({"status": "unknown", "complete": null}),
    };
    let provider_results = report_provider_results(report);
    let provider_rows = provider_results.and_then(Value::as_array);
    let candidate_arrays: Vec<&Vec<Value>> = provider_rows
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("result")?.get("details"))
        .filter_map(|details| {
            ["rawScannerCandidates", "scannerCandidates", "candidates"]
                .iter()
                .find_map(|key| details.get(*key).and_then(Value::as_array))
        })
        .collect();
    let candidate_providers: Vec<Value> = provider_rows
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let details = row.get("result")?.get("details")?;
            let candidates = ["rawScannerCandidates", "scannerCandidates", "candidates"]
                .iter()
                .find_map(|key| details.get(*key).and_then(Value::as_array))?;
            let source_field = ["rawScannerCandidates", "scannerCandidates", "candidates"]
                .iter()
                .find(|key| details.get(**key).and_then(Value::as_array).is_some())
                .copied()
                .unwrap_or("unknown");
            Some(json!({
                "provider": row.get("provider").cloned().unwrap_or(Value::Null),
                "count": candidates.len(),
                "sourceField": source_field
            }))
        })
        .collect();
    let candidate_malformed = provider_results.is_some()
        && (provider_rows.is_none()
            || provider_rows.is_some_and(|rows| {
                rows.iter().any(|row| {
                    !row.is_object()
                        || row
                            .get("result")
                            .and_then(|value| value.get("details"))
                            .is_some_and(|details| {
                                ["rawScannerCandidates", "scannerCandidates", "candidates"]
                                    .iter()
                                    .any(|key| {
                                        details.get(*key).is_some_and(|value| !value.is_array())
                                    })
                            })
                }) || candidate_arrays
                    .iter()
                    .any(|array| array.iter().any(|candidate| !candidate.is_object()))
            }));
    let raw_candidates = if candidate_malformed {
        json!({"status": "malformed", "count": null, "reason": "provider candidate evidence has invalid shape"})
    } else if !candidate_arrays.is_empty() {
        json!({
            "status": "available",
            "count": candidate_arrays.iter().map(|rows| rows.len()).sum::<usize>(),
            "candidateArrayCount": candidate_arrays.len(),
            "candidateProviders": candidate_providers,
            "source": "providerResults[].result.details"
        })
    } else {
        json!({
            "status": "unavailable",
            "count": null,
            "reason": "report has no pre-adjudication scanner candidate arrays"
        })
    };
    let telemetry = provider_rows
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    let details = row.get("result").and_then(|value| value.get("details"));
                    json!({
                        "provider": row.get("provider").cloned().unwrap_or(Value::Null),
                        "phase": row.get("phase").map(|value| json!({"status":"reported","value":value})).unwrap_or_else(|| json!({"status":"unknown","value":null})),
                        "actualInputTokens": source_metric(details, "actualInputTokens", "usage", "actualInputTokens"),
                        "actualOutputTokens": source_metric(details, "actualOutputTokens", "usage", "actualOutputTokens"),
                        "actualCachedInputTokens": source_metric(details, "actualCachedInputTokens", "usage", "actualCachedInputTokens"),
                        "actualCost": source_metric(details, "actualCost", "usage", "actualCost"),
                        "reportedTimingMs": source_metric(details, "timingMs", "timing", "durationMs"),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    json!({
        "rawScannerCandidates": raw_candidates,
        "finalReport": {
            "status": if findings.is_some() { "available" } else { "malformed" },
            "reportStatus": report.get("status").cloned().unwrap_or(Value::Null),
            "completeness": completeness,
            "findingCount": findings.map(Vec::len),
            "findings": findings.cloned().unwrap_or_default(),
        },
        "phaseTelemetry": {
            "status": if provider_rows.is_some() { "provider rows available; phase/usage/timing may be unknown" } else { "unavailable" },
            "phases": telemetry,
        }
    })
}

fn raw_candidate_observations(report: &Value) -> Option<(Vec<Observed>, u32)> {
    let rows = report_provider_results(report)?.as_array()?;
    let arrays: Vec<&Vec<Value>> = rows
        .iter()
        .filter_map(|row| row.get("result")?.get("details"))
        .filter_map(|details| {
            ["rawScannerCandidates", "scannerCandidates", "candidates"]
                .iter()
                .find_map(|key| details.get(*key).and_then(Value::as_array))
        })
        .collect();
    if arrays.is_empty() {
        return None;
    }
    let candidates: Vec<&Value> = arrays.iter().flat_map(|array| array.iter()).collect();
    let count = candidates.len() as u32;
    let observations = candidates
        .into_iter()
        .map(|candidate| {
            let location_status = candidate.get("locationStatus").and_then(Value::as_str);
            let anchor_invalid = matches!(location_status, Some("invalid" | "conflicting"));
            let anchor_unknown = location_status == Some("unknown");
            let path = if anchor_invalid || anchor_unknown {
                None
            } else {
                candidate
                    .get("path")
                    .or_else(|| candidate.get("file"))
                    .and_then(Value::as_str)
            };
            let start = if anchor_invalid || anchor_unknown {
                None
            } else {
                candidate
                    .get("line")
                    .or_else(|| candidate.get("startLine"))
                    .and_then(Value::as_u64)
                    .and_then(|line| u32::try_from(line).ok())
                    .filter(|line| *line > 0)
            };
            let end = candidate
                .get("endLine")
                .and_then(Value::as_u64)
                .and_then(|line| u32::try_from(line).ok())
                .filter(|line| start.is_some_and(|start| *line >= start))
                .or(start);
            Observed {
                locations: path
                    .map(|path| {
                        vec![Loc {
                            path: path.replace('\\', "/"),
                            start,
                            end,
                        }]
                    })
                    .unwrap_or_default(),
            }
        })
        .collect();
    Some((observations, count))
}

fn deterministic_stage_metrics(
    report: &Value,
    selected_providers: &[&str],
    plan: Option<&Value>,
) -> Value {
    let rows = report_provider_results(report).and_then(Value::as_array);
    let providers = selected_providers.iter().copied().map(|selected| {
        let matches = rows.map(|rows| rows.iter().filter(|row| row.get("provider").and_then(Value::as_str) == Some(selected)).collect::<Vec<_>>()).unwrap_or_default();
        let denominator = plan.and_then(|plan| plan.pointer("/nativePlan/plan/providers")).and_then(Value::as_array).and_then(|providers| {
            let matches = providers.iter().filter(|provider| provider.get("id").and_then(Value::as_str) == Some(selected)).collect::<Vec<_>>();
            (matches.len() == 1).then(|| matches[0].pointer("/configuration/denominatorCount").and_then(Value::as_u64)).flatten()
        });
        let execution = (matches.len() == 1).then(|| serde_json::from_value::<legion_audit::ProviderExecution>(matches[0].clone()).ok()).flatten();
        match execution {
            Some(execution) if execution.result.provider.as_str() == selected && !execution.skipped && execution.result.validate().is_ok() => {
                let result = execution.result;
                // Plan-level selector NA is distinct from missing host support or an
                // untyped applicable=false claim. It proves no inspection took place.
                let not_applicable = !result.applicable && !result.complete
                    && result.status == legion_contracts::ProviderStatus::Ok
                    && result.coverage.is_none() && result.findings.is_empty()
                    && result.coverage_gaps.is_empty() && result.degradation.is_empty()
                    && result.details.get("notApplicable") == Some(&Value::Bool(true))
                    && result.details.get("notApplicableReason").and_then(Value::as_str) == Some("selector-denominator-empty")
                    && denominator == Some(0)
                    && ["rawScannerCandidates", "scannerCandidates", "candidates"].iter().all(|field| !result.details.contains_key(*field));
                let inspected = result.applicable && result.complete && result.degradation.is_empty();
                json!({
                    "provider":selected, "status":result.status, "applicable":result.applicable,
                    "complete":result.complete, "coverage":result.coverage,
                    "eligibleDenominator":denominator,
                    "selectionComplete":inspected || not_applicable,
                    "selectionStatus":if not_applicable { "not-applicable" } else if inspected { "complete" } else { "incomplete" },
                    "inspection":if not_applicable { "not-inspected" } else if inspected { "inspected" } else { "unknown" },
                    "candidateCount":if not_applicable { Some(0) } else { result.details.get("candidates").and_then(Value::as_array).map(Vec::len) },
                })
            }
            _ => json!({"provider":selected,"status":if matches.is_empty() {"missing"} else {"malformed"},"applicable":null,"complete":null,"coverage":null,"candidateCount":null,"selectionComplete":false,"selectionStatus":"incomplete","inspection":"unknown"}),
        }
    }).collect::<Vec<_>>();
    let complete = !providers.is_empty()
        && providers
            .iter()
            .all(|provider| provider["selectionComplete"] == true);
    json!({
        "kind":"selected-provider-stage",
        "status":if complete { "complete" } else if rows.is_none() { "unknown" } else { "incomplete" },
        "complete":if rows.is_some() { Value::Bool(complete) } else { Value::Null },
        "selectedProviders":selected_providers, "providers":providers,
        "fullAuditCompleteness":"not-claimed-by-selected-stage",
    })
}

fn selected_stage_raw_metrics(report: &Value, stage: &Value) -> Value {
    let mut metrics = report_metrics(report);
    let all_not_applicable = stage["complete"] == true
        && stage["providers"].as_array().is_some_and(|providers| {
            !providers.is_empty()
                && providers
                    .iter()
                    .all(|provider| provider["selectionStatus"] == "not-applicable")
        });
    if all_not_applicable && metrics["rawScannerCandidates"]["status"] == "unavailable" {
        metrics["rawScannerCandidates"] = json!({
            "status":"available", "count":0, "candidateArrayCount":0, "candidateProviders":[],
            "inspection":"not-inspected", "evidenceState":"not-applicable",
            "source":"selected-provider-stage-zero-eligible-denominators",
        });
    }
    metrics
}

fn deterministic_provider_args(
    with_lenses: bool,
    selected_providers: Option<&[&str]>,
) -> Vec<String> {
    if with_lenses {
        Vec::new()
    } else if let Some(selected_providers) = selected_providers {
        selected_providers
            .iter()
            .flat_map(|provider| ["--only".to_owned(), (*provider).to_owned()])
            .collect()
    } else {
        Vec::new()
    }
}

fn on_path(loc: &Loc, path: &str) -> bool {
    loc.path == path
}

fn overlaps(loc: &Loc, path: &str, range: [u32; 2]) -> bool {
    on_path(loc, path)
        && match (loc.start, loc.end) {
            (Some(start), Some(end)) => start <= range[1] && end >= range[0],
            _ => false,
        }
}

fn any_loc(findings: &[Observed], test: impl Fn(&Loc) -> bool) -> bool {
    findings
        .iter()
        .any(|finding| finding.locations.iter().any(&test))
}

// ----------------------------------------------------------------- scoring

/// Counts for one run; ratios are derived so runs and fixtures add up.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunScore {
    /// Expected items in every ruled planted case in the first-attempt plan.
    pub items: u32,
    /// Items with a finding on the expected (or an alternate) path.
    pub path_hits: u32,
    /// Items with a finding overlapping the expected (or an alternate) range.
    pub location_hits: u32,
    /// Items of caller-regression cases.
    pub caller_items: u32,
    /// Caller-regression items found at the primary (unchanged caller) range.
    pub caller_hits: u32,
    pub clean_cases: u32,
    /// Clean cases with no finding.
    pub clean_passed: u32,
    /// Findings known right: on an expected site or ruled right.
    pub right: u32,
    /// Findings known wrong: any finding on a clean case or ruled wrong.
    pub wrong: u32,
    /// Findings with no ruling.
    pub unresolved: u32,
    /// Cases skipped because they are not ruled.
    pub unruled_skipped: u32,
    /// Cases that produced no usable observation; retained in planned denominators.
    pub failed_cases: Vec<String>,
    /// All planned ruled cases, including failures and cases that never started.
    pub planned_cases: u32,
    /// Cases that produced a usable report.
    pub completed_cases: u32,
}

fn ratio(numerator: u32, denominator: u32) -> Option<f64> {
    (denominator > 0).then(|| f64::from(numerator) / f64::from(denominator))
}

impl RunScore {
    pub fn recall(&self) -> Option<f64> {
        ratio(self.path_hits, self.items)
    }

    /// Label-based semantic match proxy. This does not certify correctness.
    pub fn semantic_recall_proxy(&self) -> Option<f64> {
        self.recall()
    }

    pub fn location_recall(&self) -> Option<f64> {
        ratio(self.location_hits, self.items)
    }

    /// Line-overlap localization proxy, reported apart from semantic labels.
    pub fn localization_proxy(&self) -> Option<f64> {
        self.location_recall()
    }

    pub fn caller_recall(&self) -> Option<f64> {
        ratio(self.caller_hits, self.caller_items)
    }

    pub fn clean_rate(&self) -> Option<f64> {
        ratio(self.clean_passed, self.clean_cases)
    }

    fn findings(&self) -> u32 {
        self.right + self.wrong + self.unresolved
    }

    /// Unresolved findings counted wrong.
    pub fn precision_lower(&self) -> Option<f64> {
        ratio(self.right, self.findings())
    }

    /// Unresolved findings counted right.
    pub fn precision_upper(&self) -> Option<f64> {
        ratio(self.right + self.unresolved, self.findings())
    }

    pub fn merge(&mut self, other: &RunScore) {
        self.items += other.items;
        self.path_hits += other.path_hits;
        self.location_hits += other.location_hits;
        self.caller_items += other.caller_items;
        self.caller_hits += other.caller_hits;
        self.clean_cases += other.clean_cases;
        self.clean_passed += other.clean_passed;
        self.planned_cases += other.planned_cases;
        self.completed_cases += other.completed_cases;
        self.right += other.right;
        self.wrong += other.wrong;
        self.unresolved += other.unresolved;
        self.unruled_skipped += other.unruled_skipped;
        self.failed_cases.extend(other.failed_cases.iter().cloned());
    }

    pub fn to_json(&self) -> Value {
        json!({
            "semanticRecallProxy": self.semantic_recall_proxy(),
            "localizationProxy": self.localization_proxy(),
            "callerRecall": self.caller_recall(),
            "cleanRate": self.clean_rate(),
            "precisionLower": self.precision_lower(),
            "precisionUpper": self.precision_upper(),
            "counts": {
                "items": self.items,
                "pathHits": self.path_hits,
                "locationHits": self.location_hits,
                "callerItems": self.caller_items,
                "callerHits": self.caller_hits,
                "cleanCases": self.clean_cases,
                "cleanPassed": self.clean_passed,
                "plannedCases": self.planned_cases,
                "completedCases": self.completed_cases,
                "failedCases": self.failed_cases.len(),
                "findingsRight": self.right,
                "findingsWrong": self.wrong,
                "findingsUnresolved": self.unresolved,
                "unruledSkipped": self.unruled_skipped,
            },
            "failedOrUnstartedCases": self.failed_cases,
        })
    }
}

/// Score one first attempt. Missing observations remain in applicable
/// denominators, so failures and unstarted cases cannot improve measured recall.
pub fn score_run(cases: &[Case], observed: &BTreeMap<String, Vec<Observed>>) -> RunScore {
    score_run_with_failures(cases, observed, &std::collections::BTreeSet::new())
}

/// Score usable first-attempt output while retaining explicit failures even
/// when a partial report contains findings. Failed cases still contribute all
/// planned items to recall denominators.
pub fn score_run_with_failures(
    cases: &[Case],
    observed: &BTreeMap<String, Vec<Observed>>,
    failed: &std::collections::BTreeSet<String>,
) -> RunScore {
    let mut score = RunScore::default();
    for case in cases {
        if !case.ruled {
            score.unruled_skipped += 1;
            continue;
        }
        score.planned_cases += 1;
        let Some(findings) = observed.get(&case.id) else {
            score.failed_cases.push(case.id.clone());
            match case.kind {
                Kind::Clean => score.clean_cases += 1,
                Kind::Planted => {
                    score.items += case.expected.len() as u32;
                    if case.category == Some(Category::CallerRegression) {
                        score.caller_items += case.expected.len() as u32;
                    }
                }
            }
            continue;
        };
        if failed.contains(&case.id) {
            score.failed_cases.push(case.id.clone());
        } else {
            score.completed_cases += 1;
        }
        match case.kind {
            Kind::Clean => {
                score.clean_cases += 1;
                if findings.is_empty() && !failed.contains(&case.id) {
                    score.clean_passed += 1;
                }
                score.wrong += findings.len() as u32;
            }
            Kind::Planted => {
                for expected in &case.expected {
                    score.items += 1;
                    let sites: Vec<(&str, [u32; 2])> =
                        std::iter::once((expected.path.as_str(), expected.line_range))
                            .chain(
                                expected
                                    .alt
                                    .iter()
                                    .map(|site| (site.path.as_str(), site.line_range)),
                            )
                            .collect();
                    if sites
                        .iter()
                        .any(|(path, _)| any_loc(findings, |loc| on_path(loc, path)))
                    {
                        score.path_hits += 1;
                    }
                    if sites
                        .iter()
                        .any(|(path, range)| any_loc(findings, |loc| overlaps(loc, path, *range)))
                    {
                        score.location_hits += 1;
                    }
                    if case.category == Some(Category::CallerRegression) {
                        score.caller_items += 1;
                        if any_loc(findings, |loc| {
                            overlaps(loc, &expected.path, expected.line_range)
                        }) {
                            score.caller_hits += 1;
                        }
                    }
                }
                for finding in findings {
                    let touches = |path: &str, range: [u32; 2]| {
                        finding
                            .locations
                            .iter()
                            .any(|loc| overlaps(loc, path, range))
                    };
                    // An explicit ruling overrides expectation matching.
                    let ruled = case
                        .rulings
                        .iter()
                        .find(|ruling| touches(&ruling.path, ruling.line_range))
                        .map(|ruling| ruling.verdict);
                    let expected_hit = case.expected.iter().any(|expected| {
                        touches(&expected.path, expected.line_range)
                            || expected
                                .alt
                                .iter()
                                .any(|site| touches(&site.path, site.line_range))
                    });
                    match (ruled, expected_hit) {
                        (Some(Verdict::Right), _) | (None, true) => score.right += 1,
                        (Some(Verdict::Wrong), _) => score.wrong += 1,
                        (None, false) => score.unresolved += 1,
                    }
                }
            }
        }
    }
    score
}

/// A/A noise estimate from two arms that ran the identical configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct AaBand {
    pub mean_a: f64,
    pub mean_b: f64,
    pub mean_delta: f64,
    /// Half of (max - min) over every per-run recall of both arms.
    pub half_width: f64,
}

pub fn mean(values: &[f64]) -> Option<f64> {
    (!values.is_empty()).then(|| values.iter().sum::<f64>() / values.len() as f64)
}

pub fn aa_band(a: &[f64], b: &[f64]) -> Option<AaBand> {
    let (mean_a, mean_b) = (mean(a)?, mean(b)?);
    let all = a.iter().chain(b.iter());
    let max = all.clone().cloned().fold(f64::NEG_INFINITY, f64::max);
    let min = all.cloned().fold(f64::INFINITY, f64::min);
    Some(AaBand {
        mean_a,
        mean_b,
        mean_delta: (mean_a - mean_b).abs(),
        half_width: (max - min) / 2.0,
    })
}

// ------------------------------------------------------------------ runner

pub struct Options {
    pub legion: PathBuf,
    pub fixtures: Vec<String>,
    pub cases: Vec<String>,
    pub repeat: u32,
    pub token_budget: u64,
    pub case_token_budget: u64,
    pub claude: Option<PathBuf>,
    pub model: Option<String>,
    pub aa: bool,
    pub with_lenses: bool,
    pub work_dir: Option<PathBuf>,
    pub keep: bool,
    pub json: bool,
}

#[derive(Debug, Clone)]
struct TokenBudget {
    limit: u64,
    case_limit: u64,
    remaining: u64,
    reserved: u64,
    actual: u64,
    unknown_cases: u32,
    overrun: u64,
    halted: bool,
    halt_reason: Option<String>,
}

impl TokenBudget {
    fn new(limit: u64, case_limit: u64) -> Self {
        Self {
            limit,
            case_limit,
            remaining: limit,
            reserved: 0,
            actual: 0,
            unknown_cases: 0,
            overrun: 0,
            halted: false,
            halt_reason: None,
        }
    }

    fn reserve_case(&mut self) -> Option<u64> {
        if self.remaining == 0 || self.halted {
            return None;
        }
        let allocation = self.remaining.min(self.case_limit);
        self.remaining -= allocation;
        self.reserved = self.reserved.saturating_add(allocation);
        Some(allocation)
    }

    /// Unknown usage burns reservation; measured unused tokens return to shared budget.
    fn settle_case(&mut self, allocation: u64, actual: Option<u64>) -> u64 {
        let Some(actual) = actual else {
            self.unknown_cases = self.unknown_cases.saturating_add(1);
            self.halted = true;
            self.halt_reason = Some("runtime-usage-unknown".into());
            return allocation;
        };
        self.actual = self.actual.saturating_add(actual);
        if actual < allocation {
            self.remaining = self.remaining.saturating_add(allocation - actual);
        } else if actual > allocation {
            let overrun = actual - allocation;
            self.overrun = self.overrun.saturating_add(overrun);
            self.remaining = self.remaining.saturating_sub(overrun);
            self.halted = true;
            self.halt_reason = Some("actual-usage-exceeded-case-reservation".into());
        }
        actual
    }

    fn to_json(&self) -> Value {
        json!({
            "limitTokens": self.limit,
            "perCaseLimitTokens": self.case_limit,
            "remainingTokens": self.remaining,
            "cumulativeCaseReservationsTokens": self.reserved,
            "actualTokens": if self.unknown_cases == 0 { Some(self.actual) } else { None },
            "knownActualTokens": self.actual,
            "unknownUsageCases": self.unknown_cases,
            "overrunTokens": self.overrun,
            "halted": self.halted,
            "haltReason": self.halt_reason,
            "unknownUsagePolicy": "burn-full-case-reservation-and-halt-subsequent-model-cases"
        })
    }
}

fn observed_runtime_tokens(metrics: &Value) -> Option<u64> {
    let usage = &metrics["runtime"]["usage"];
    if usage["status"] != "reported" {
        return None;
    }
    let input = usage["inputTokens"].as_u64()?;
    let output = usage["outputTokens"].as_u64()?;
    let retry = usage["retryTokens"].as_u64()?;
    Some(input.saturating_add(output).saturating_add(retry))
}

fn validate_case_filter(
    requested: &std::collections::BTreeSet<String>,
    known: &std::collections::BTreeSet<String>,
) -> Result<(), String> {
    let unknown: Vec<_> = requested.difference(known).cloned().collect();
    if unknown.is_empty() {
        Ok(())
    } else {
        Err(format!("unknown --case id(s): {}", unknown.join(", ")))
    }
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let capture_root = if dir.join(".git").is_dir() {
        dir.join(".git")
    } else {
        dir.to_path_buf()
    };
    let capture_path = capture_root.join(format!("audit-bench-git-stdout-{}", std::process::id()));
    let capture = File::create(&capture_path)
        .map_err(|error| format!("cannot create {}: {error}", capture_path.display()))?;
    let args_owned: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    let status = run_bounded(
        Path::new("git"),
        &args_owned,
        dir,
        Stdio::from(capture),
        GIT_TIMEOUT,
    );
    let result = match status {
        Err(error) => Err(error),
        Ok(status) if !status.success() => Err(format!(
            "git {} failed with exit {:?}",
            args.join(" "),
            status.code()
        )),
        Ok(_) => {
            let size = fs::metadata(&capture_path)
                .map(|meta| meta.len())
                .unwrap_or(0);
            if size > MAX_GIT_STDOUT_BYTES {
                Err(format!(
                    "git {} output exceeded {} bytes",
                    args.join(" "),
                    MAX_GIT_STDOUT_BYTES
                ))
            } else {
                let mut text = String::new();
                File::open(&capture_path)
                    .and_then(|mut file| file.read_to_string(&mut text))
                    .map_err(|error| format!("cannot read {}: {error}", capture_path.display()))
                    .map(|_| text.trim().to_owned())
            }
        }
    };
    let _ = fs::remove_file(capture_path);
    result
}

fn discover_fixtures(dir: &Path) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let path = entry.path();
            (path.extension().is_some_and(|ext| ext == "bundle"))
                .then(|| path.file_stem().map(|s| s.to_string_lossy().into_owned()))
                .flatten()
        })
        .collect();
    names.sort();
    Ok(names)
}

fn load_cases(dir: &Path, fixture: &str) -> Result<CaseFile, String> {
    let path = dir.join(format!("{fixture}.cases.json"));
    let text =
        fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let file: CaseFile =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    validate_case_file(&file)?;
    Ok(file)
}

fn runtime_usage(run: &Path, runtime: &Value) -> Value {
    let Some(mut calls) = runtime.get("calls").and_then(Value::as_u64) else {
        return json!({"status":"unknown","reason":"runtime call count is missing or malformed","callCount":null,"inputTokens":null,"outputTokens":null,"cachedInputTokens":null,"retryTokens":null,"actualCost":{"status":"unknown","value":null}});
    };
    let mut receipt_dirs = vec![(run.join("runtime-calls"), calls)];
    if runtime
        .get("followup")
        .is_some_and(|value| !value.is_null() && !value.is_object())
    {
        return json!({"status":"unknown","reason":"follow-up receipt is malformed","callCount":null,"inputTokens":null,"outputTokens":null,"cachedInputTokens":null,"retryTokens":null,"actualCost":{"status":"unknown","value":null}});
    }
    if let Some(followup) = runtime.get("followup").filter(|value| value.is_object()) {
        let Some(followup_calls) = followup.get("calls").and_then(Value::as_u64) else {
            return json!({"status":"unknown","reason":"follow-up call count is missing or malformed","callCount":null,"inputTokens":null,"outputTokens":null,"cachedInputTokens":null,"retryTokens":null,"actualCost":{"status":"unknown","value":null}});
        };
        calls = calls.saturating_add(followup_calls);
        if let Some(child_run) = followup.get("run").and_then(Value::as_str) {
            let child_run = PathBuf::from(child_run);
            let child_run = if child_run.is_absolute() {
                child_run
            } else {
                run.join(child_run)
            };
            receipt_dirs.push((child_run.join("runtime-calls"), followup_calls));
        } else if followup_calls > 0 {
            return json!({"status":"unknown","reason":"follow-up run path is missing","callCount":calls,"inputTokens":null,"outputTokens":null,"cachedInputTokens":null,"retryTokens":null,"actualCost":{"status":"unknown","value":null}});
        }
    }
    let mut paths = Vec::new();
    let mut receipt_error = None;
    for (dir, expected_calls) in &receipt_dirs {
        if *expected_calls == 0 {
            continue;
        }
        match fs::read_dir(dir) {
            Ok(entries) => paths.extend(
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.path())
                    .filter(|path| {
                        path.extension()
                            .is_some_and(|extension| extension == "json")
                    }),
            ),
            Err(error) => receipt_error = Some(format!("cannot read {}: {error}", dir.display())),
        }
    }
    if let Some(error) = receipt_error {
        return json!({"status":"unknown","reason":error,"callCount":calls,"inputTokens":null,"outputTokens":null,"cachedInputTokens":null,"retryTokens":null,"actualCost":{"status":"unknown","value":null}});
    }
    paths.sort();
    let mut totals = [0u64; 4];
    let mut complete = paths.len() as u64 == calls;
    let mut malformed = false;
    for path in &paths {
        let parsed = fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        let Some(usage) = parsed
            .as_ref()
            .and_then(|value| value.pointer("/observation/usage"))
        else {
            malformed = true;
            complete = false;
            continue;
        };
        for (index, key) in [
            "inputTokens",
            "outputTokens",
            "cachedInputTokens",
            "retryTokens",
        ]
        .into_iter()
        .enumerate()
        {
            if let Some(value) = usage.get(key).and_then(Value::as_u64) {
                totals[index] = totals[index].saturating_add(value);
            } else {
                complete = false;
            }
        }
    }
    json!({
        "status": if malformed { "malformed" } else if complete { "reported" } else { "unknown" },
        "callCount": calls,
        "receiptCount": paths.len(),
        "inputTokens": if complete { Some(totals[0]) } else { None },
        "outputTokens": if complete { Some(totals[1]) } else { None },
        "cachedInputTokens": if complete { Some(totals[2]) } else { None },
        "retryTokens": if complete { Some(totals[3]) } else { None },
        "knownInputTokens": totals[0],
        "knownOutputTokens": totals[1],
        "knownCachedInputTokens": totals[2],
        "knownRetryTokens": totals[3],
        "actualCost": {"status":"unknown","value":null}
    })
}

#[derive(Debug)]
struct AuditObservation {
    findings: Vec<Observed>,
    metrics: Value,
    wall_time_ms: u128,
    deterministic_wall_time_ms: u128,
    reasoning_wall_time_ms: Option<u128>,
    errors: Vec<String>,
    completed: bool,
}

/// Run `legion audit` for one case inside `clone`; returns findings and source metrics.
fn audit_case(
    legion: &Path,
    clone: &Path,
    case: &Case,
    out: &Path,
    with_lenses: bool,
    deterministic_providers: Option<&[&str]>,
    token_budget: Option<u64>,
    claude: Option<&Path>,
    model: Option<&str>,
) -> Result<AuditObservation, String> {
    let scope = parse_scope(&case.scope)?;
    git(clone, &["clean", "-fdxq"])?;
    git(clone, &["checkout", "-fq", "--detach", scope.head_ref()])?;
    let spec = format!("{}^{{commit}}", scope.base_spec());
    let base = git(clone, &["rev-parse", "--verify", &spec])?;
    let _ = fs::remove_dir_all(out);
    fs::create_dir_all(out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    let args = vec![
        "audit".to_owned(),
        clone.to_string_lossy().into_owned(),
        "--base".to_owned(),
        base,
        "--quiet".to_owned(),
        "--out".to_owned(),
        out.to_string_lossy().into_owned(),
    ];
    let mut args = args;
    args.extend(deterministic_provider_args(
        with_lenses,
        deterministic_providers,
    ));
    if let Some(token_budget) = token_budget {
        args.push("--run-token-budget".into());
        args.push(token_budget.to_string());
    }
    let started = std::time::Instant::now();
    let status = run_bounded(legion, &args, clone, Stdio::null(), AUDIT_TIMEOUT)?;
    let deterministic_wall_time_ms = started.elapsed().as_millis();
    // Findings make `legion audit` exit non-zero; only a missing report is a failure.
    let report_path = out.join("report.json");
    let text = fs::read_to_string(&report_path)
        .map_err(|_| format!("no report.json (exit {:?})", status.code()))?;
    let report: Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", report_path.display()))?;
    if report.get("findings").and_then(Value::as_array).is_none() {
        return Err(format!(
            "{}: missing or malformed findings array",
            report_path.display()
        ));
    }
    let plan = fs::read(out.join("plan.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let audit_scope = if with_lenses {
        json!({"kind":"full-audit-plan", "selectedProviders":null, "fullAuditCompleteness":"required"})
    } else if let Some(providers) = deterministic_providers {
        deterministic_stage_metrics(&report, providers, plan.as_ref())
    } else {
        json!({"kind":"full-audit-plan", "selectedProviders":null, "fullAuditCompleteness":"required"})
    };
    let mut metrics = json!({
        "rawAudit":selected_stage_raw_metrics(&report, &audit_scope),
        "finalReport":report_metrics(&report),
        "auditScope":audit_scope,
    });
    let mut errors = Vec::new();
    let full_audit_complete =
        metrics["rawAudit"]["finalReport"]["completeness"]["complete"].as_bool() == Some(true);
    if !with_lenses {
        let scope_complete = if metrics["auditScope"]["kind"] == "selected-provider-stage" {
            metrics["auditScope"]["complete"].as_bool() == Some(true)
        } else {
            full_audit_complete
        };
        if !scope_complete {
            errors.push("deterministic audit scope is incomplete or unknown".into());
        }
    }
    if metrics["rawAudit"]["rawScannerCandidates"]["status"] == "available" {
        let observations = raw_candidate_observations(&report).or_else(|| {
            (metrics["rawAudit"]["rawScannerCandidates"]["evidenceState"] == "not-applicable")
                .then(|| (Vec::new(), 0))
        });
        if let Some((candidates, candidate_count)) = observations {
            let raw_score = score_run(
                std::slice::from_ref(case),
                &BTreeMap::from([(case.id.clone(), candidates.clone())]),
            );
            let located = candidates
                .iter()
                .filter(|finding| !finding.locations.is_empty())
                .count();
            metrics["rawAudit"]["rawScannerCandidates"]["count"] = json!(candidate_count);
            metrics["rawAudit"]["rawScannerCandidates"]["locatedCandidateCount"] = json!(located);
            metrics["rawAudit"]["rawScannerCandidates"]["score"] = raw_score.to_json();
        }
    }
    let mut final_report = Some(report);
    let mut runtime_status = json!({"status": "not-requested", "complete": null});
    let mut runtime_wall_time_ms = None;
    if with_lenses {
        let started = std::time::Instant::now();
        let runtime_args = vec![
            "audit".to_owned(),
            "run-reasoning".to_owned(),
            "--run".to_owned(),
            out.to_string_lossy().into_owned(),
        ];
        let mut runtime_args = runtime_args;
        if let Some(claude) = claude {
            runtime_args.push("--claude".into());
            runtime_args.push(claude.to_string_lossy().into_owned());
        }
        if let Some(model) = model {
            runtime_args.push("--model".into());
            runtime_args.push(model.to_owned());
        }
        let runtime_execution =
            run_bounded(legion, &runtime_args, clone, Stdio::null(), AUDIT_TIMEOUT);
        let elapsed_runtime_ms = started.elapsed().as_millis();
        runtime_wall_time_ms = Some(elapsed_runtime_ms);
        let runtime_command = match runtime_execution {
            Ok(status) => {
                if !status.success() {
                    errors.push(format!("run-reasoning exited with {:?}", status.code()));
                }
                json!({"status":"exited","success":status.success(),"exitCode":status.code()})
            }
            Err(error) => {
                errors.push(format!("run-reasoning failed: {error}"));
                json!({"status":"failed","error":error})
            }
        };
        let runtime_path = out.join("review-runtime.json");
        match fs::read_to_string(&runtime_path) {
            Ok(text) => match serde_json::from_str::<Value>(&text) {
                Ok(value) => {
                    let status = value.get("status").and_then(Value::as_str);
                    let complete = value.get("complete").and_then(Value::as_bool);
                    runtime_status = json!({
                        "status": status,
                        "complete": complete,
                        "command": runtime_command,
                        "wallTimeMs": elapsed_runtime_ms,
                        "usage": runtime_usage(out, &value),
                        "output": runtime_path,
                        "reportStatus": value.get("reportStatus"),
                        "gaps": value.get("gaps"),
                    });
                    if status != Some("done") || complete != Some(true) {
                        errors.push(format!(
                            "run-reasoning incomplete: status={}, complete={}",
                            status.unwrap_or("unknown"),
                            complete
                                .map_or_else(|| "unknown".to_owned(), |value| value.to_string())
                        ));
                    }
                }
                Err(error) => errors.push(format!("{}: {error}", runtime_path.display())),
            },
            Err(error) => {
                errors.push(format!("cannot read {}: {error}", runtime_path.display()));
                runtime_status = json!({
                    "status":"unavailable",
                    "complete":null,
                    "command":runtime_command,
                    "wallTimeMs":elapsed_runtime_ms,
                    "output":runtime_path,
                    "error":error.to_string(),
                });
            }
        }
        let final_report_path = out.join("report.json");
        final_report = match fs::read_to_string(&final_report_path)
            .map_err(|error| format!("cannot read {}: {error}", final_report_path.display()))
            .and_then(|text| {
                serde_json::from_str::<Value>(&text)
                    .map_err(|error| format!("{}: {error}", final_report_path.display()))
            }) {
            Ok(report) if report.get("findings").and_then(Value::as_array).is_some() => {
                Some(report)
            }
            Ok(_) => {
                errors.push(format!(
                    "{}: missing or malformed findings array",
                    final_report_path.display()
                ));
                None
            }
            Err(error) => {
                errors.push(error);
                None
            }
        };
        metrics["runtime"] = runtime_status;
        metrics["finalReport"] = final_report
            .as_ref()
            .map(report_metrics)
            .unwrap_or_else(|| json!({"status":"unavailable","reportStatus":null,"findingCount":null,"findings":null}));
        if metrics["finalReport"]["finalReport"]["completeness"]["complete"].as_bool() != Some(true)
        {
            errors.push("reconciled report is incomplete or has unknown completeness".into());
        }
    }
    let completed = errors.is_empty();
    let wall_time_ms = deterministic_wall_time_ms + runtime_wall_time_ms.unwrap_or(0);
    Ok(AuditObservation {
        findings: final_report
            .as_ref()
            .map(findings_from_report)
            .unwrap_or_default(),
        metrics,
        wall_time_ms,
        deterministic_wall_time_ms,
        reasoning_wall_time_ms: runtime_wall_time_ms,
        errors,
        completed,
    })
}

struct FixtureRun {
    score: RunScore,
    split: String,
    telemetry: BenchTelemetry,
    errors: Vec<String>,
    case_metrics: BTreeMap<String, Value>,
    case_outcomes: BTreeMap<String, Value>,
}

#[derive(Debug, Clone)]
struct BenchTelemetry {
    planned_cases: u32,
    timed_cases: u32,
    wall_time_ms: u128,
    runtime_requested: bool,
    runtime_usage_known: bool,
    runtime_calls: u64,
    runtime_tokens: [u64; 4],
}

impl BenchTelemetry {
    fn new(planned_cases: u32, runtime_requested: bool) -> Self {
        Self {
            planned_cases,
            timed_cases: 0,
            wall_time_ms: 0,
            runtime_requested,
            runtime_usage_known: runtime_requested && planned_cases > 0,
            runtime_calls: 0,
            runtime_tokens: [0; 4],
        }
    }

    fn observe(&mut self, metrics: &Value) {
        self.timed_cases += 1;
        self.wall_time_ms = self.wall_time_ms.saturating_add(
            metrics
                .get("wallTimeMs")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u128,
        );
        if !self.runtime_requested {
            return;
        }
        let usage = &metrics["report"]["runtime"]["usage"];
        let fields = [
            "inputTokens",
            "outputTokens",
            "cachedInputTokens",
            "retryTokens",
        ];
        let values: Option<Vec<u64>> = fields
            .iter()
            .map(|field| usage.get(*field).and_then(Value::as_u64))
            .collect();
        if usage["status"] != "reported" {
            self.runtime_usage_known = false;
            return;
        }
        let Some(values) = values else {
            self.runtime_usage_known = false;
            return;
        };
        self.runtime_calls = self
            .runtime_calls
            .saturating_add(usage.get("callCount").and_then(Value::as_u64).unwrap_or(0));
        for (total, value) in self.runtime_tokens.iter_mut().zip(values) {
            *total = total.saturating_add(value);
        }
    }

    fn mark_missing(&mut self) {
        if self.runtime_requested {
            self.runtime_usage_known = false;
        }
    }

    fn merge(&mut self, other: &Self) {
        self.planned_cases += other.planned_cases;
        self.timed_cases += other.timed_cases;
        self.wall_time_ms = self.wall_time_ms.saturating_add(other.wall_time_ms);
        self.runtime_requested |= other.runtime_requested;
        self.runtime_usage_known &= other.runtime_usage_known;
        self.runtime_calls = self.runtime_calls.saturating_add(other.runtime_calls);
        for (total, value) in self.runtime_tokens.iter_mut().zip(other.runtime_tokens) {
            *total = total.saturating_add(value);
        }
    }

    fn to_json(&self) -> Value {
        let latency_known = self.planned_cases > 0 && self.timed_cases == self.planned_cases;
        let usage = if !self.runtime_requested {
            json!({"status":"not-requested","callCount":null,"inputTokens":null,"outputTokens":null,"cachedInputTokens":null,"retryTokens":null,"actualCost":{"status":"unknown","value":null}})
        } else {
            json!({
                "status": if self.runtime_usage_known { "reported" } else { "unknown" },
                "callCount": if self.runtime_usage_known { Some(self.runtime_calls) } else { None },
                "inputTokens": if self.runtime_usage_known { Some(self.runtime_tokens[0]) } else { None },
                "outputTokens": if self.runtime_usage_known { Some(self.runtime_tokens[1]) } else { None },
                "cachedInputTokens": if self.runtime_usage_known { Some(self.runtime_tokens[2]) } else { None },
                "retryTokens": if self.runtime_usage_known { Some(self.runtime_tokens[3]) } else { None },
                "actualCost":{"status":"unknown","value":null}
            })
        };
        json!({
            "wallTimeMs": {
                "status": if latency_known { "reported" } else { "unknown" },
                "value": if latency_known { Some(self.wall_time_ms) } else { None },
                "measuredCases": self.timed_cases,
                "plannedCases": self.planned_cases
            },
            "runtimeUsage": usage
        })
    }
}

fn run_fixture(
    opts: &Options,
    bench: &Path,
    work: &Path,
    label: &str,
    fixture: &str,
    token_budget: &mut TokenBudget,
) -> Result<FixtureRun, String> {
    let fixtures = bench.join("fixtures");
    let file = load_cases(&fixtures, fixture)?;
    let cases: Vec<Case> = file
        .cases
        .iter()
        .filter(|case| opts.cases.is_empty() || opts.cases.contains(&case.id))
        .cloned()
        .collect();
    if !cases.iter().any(|case| case.ruled) {
        return Ok(FixtureRun {
            score: score_run_with_failures(
                &cases,
                &BTreeMap::new(),
                &std::collections::BTreeSet::new(),
            ),
            split: file.split_label().to_owned(),
            telemetry: BenchTelemetry::new(0, opts.with_lenses),
            errors: Vec::new(),
            case_metrics: BTreeMap::new(),
            case_outcomes: BTreeMap::new(),
        });
    }
    let bundle = fixtures.join(format!("{fixture}.bundle"));
    let clone = work.join(label).join(fixture);
    if clone.exists() {
        return Err(format!(
            "{} already exists; use a fresh --work-dir",
            clone.display()
        ));
    }
    fs::create_dir_all(clone.parent().unwrap_or(work)).map_err(|e| e.to_string())?;
    let bundle_arg = bundle.to_string_lossy().into_owned();
    let clone_arg = clone.to_string_lossy().into_owned();
    let clone_result = git(work, &["clone", "-q", &bundle_arg, &clone_arg]);
    let clone_ok = clone_result.is_ok();
    let mut observed = BTreeMap::new();
    let mut failed_ids = std::collections::BTreeSet::new();
    let mut errors = Vec::new();
    let mut case_metrics = BTreeMap::new();
    let mut case_outcomes = BTreeMap::new();
    let mut telemetry = BenchTelemetry::new(
        cases.iter().filter(|case| case.ruled).count() as u32,
        opts.with_lenses,
    );
    if let Err(error) = clone_result {
        for case in cases.iter().filter(|case| case.ruled) {
            telemetry.mark_missing();
            errors.push(format!("{fixture}/{}: clone failed: {error}", case.id));
            case_outcomes.insert(
                case.id.clone(),
                json!({
                    "attempt": 1,
                    "status": "unstarted",
                    "reason": "fixture clone failed",
                }),
            );
        }
    }
    for case in cases.iter().filter(|case| case.ruled && clone_ok) {
        let out = work.join(label).join(format!("{fixture}.{}.out", case.id));
        let deterministic_providers = if !opts.with_lenses && fixture == "audit-behavior" {
            Some(AUDIT_BEHAVIOR_PROVIDERS.as_slice())
        } else {
            None
        };
        let allocation = if opts.with_lenses {
            token_budget.reserve_case()
        } else {
            None
        };
        if opts.with_lenses && allocation.is_none() {
            telemetry.mark_missing();
            failed_ids.insert(case.id.clone());
            let reason = token_budget
                .halt_reason
                .as_deref()
                .unwrap_or("benchmark token budget exhausted before case start");
            errors.push(format!("{fixture}/{}: {reason}", case.id));
            case_outcomes.insert(case.id.clone(), json!({
                "attempt":1,
                "status":"unstarted",
                "reason":reason,
                "benchmarkTokenBudget":{"status":if token_budget.halted { "halted-fail-closed" } else { "exhausted" },"allocationTokens":0}
            }));
            continue;
        }
        match audit_case(
            &opts.legion,
            &clone,
            case,
            &out,
            opts.with_lenses,
            deterministic_providers,
            allocation,
            opts.claude.as_deref(),
            opts.model.as_deref(),
        ) {
            Ok(result) => {
                let actual_tokens = if opts.with_lenses {
                    observed_runtime_tokens(&result.metrics)
                } else {
                    None
                };
                let budget_overrun = allocation
                    .zip(actual_tokens)
                    .is_some_and(|(allocated, actual)| actual > allocated);
                if let Some(allocation) = allocation {
                    token_budget.settle_case(allocation, actual_tokens);
                }
                observed.insert(case.id.clone(), result.findings);
                if !result.completed || budget_overrun {
                    failed_ids.insert(case.id.clone());
                }
                let mut result_errors = result.errors.clone();
                if budget_overrun {
                    result_errors.push("actual runtime tokens exceeded case reservation".into());
                    errors.push(format!(
                        "{fixture}/{}: actual runtime tokens exceeded case reservation",
                        case.id
                    ));
                }
                let runtime_wall_time = result
                    .reasoning_wall_time_ms
                    .map(|value| json!({"status":"reported","value":value}))
                    .unwrap_or_else(|| json!({"status":"not-requested","value":null}));
                let final_report_available =
                    result.metrics["finalReport"]["status"] != "unavailable";
                let metric = json!({
                    "report": result.metrics,
                    "wallTimeMs": result.wall_time_ms,
                    "phaseWallTimeMs": {
                        "deterministicAudit": {"status":"reported","value":result.deterministic_wall_time_ms},
                        "reasoningRuntime": runtime_wall_time
                    },
                    "phaseWallTimeStatus": if opts.with_lenses { "runtime wall time measured; other phases unknown unless provider reports them" } else { "unknown: report does not expose per-phase durations" },
                    "benchmarkTokenBudget": allocation.map(|allocated| json!({"status":if budget_overrun {"overrun"} else if actual_tokens.is_some(){"reconciled"}else{"unknown-burned-reservation"},"allocationTokens":allocated,"reportedActualTokens":actual_tokens}))
                });
                telemetry.observe(&metric);
                case_outcomes.insert(
                    case.id.clone(),
                    json!({
                        "attempt": 1,
                        "status": if result.completed && !budget_overrun { "completed" } else { "failed" },
                        "finalReportAvailable": final_report_available,
                        "errors": result_errors,
                    }),
                );
                errors.extend(
                    result
                        .errors
                        .iter()
                        .map(|error| format!("{fixture}/{}: {error}", case.id)),
                );
                case_metrics.insert(case.id.clone(), json!({
                    "ablationIdentity": if opts.with_lenses { "deterministic-plus-reasoning" } else { "deterministic-only" },
                    "report": metric["report"].clone(),
                    "wallTimeMs": metric["wallTimeMs"].clone(),
                    "phaseWallTimeMs": metric["phaseWallTimeMs"].clone(),
                    "phaseWallTimeStatus": metric["phaseWallTimeStatus"].clone(),
                    "benchmarkTokenBudget": metric["benchmarkTokenBudget"].clone()
                }));
            }
            Err(error) => {
                if let Some(allocation) = allocation {
                    // audit_case returns errors only before the separate model runtime starts.
                    token_budget.settle_case(allocation, Some(0));
                }
                telemetry.mark_missing();
                errors.push(format!("{fixture}/{}: {error}", case.id));
                failed_ids.insert(case.id.clone());
                case_outcomes.insert(
                    case.id.clone(),
                    json!({
                        "attempt": 1,
                        "status": "failed",
                        "error": error,
                    }),
                );
            }
        }
    }
    Ok(FixtureRun {
        score: score_run_with_failures(&cases, &observed, &failed_ids),
        split: file.split_label().to_owned(),
        telemetry,
        errors,
        case_metrics,
        case_outcomes,
    })
}

fn fmt_ratio(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |v| format!("{:.1}%", v * 100.0))
}

fn arm_json(runs: &[RunScore]) -> Value {
    let recalls: Vec<f64> = runs.iter().filter_map(RunScore::recall).collect();
    json!({
        "runs": runs.iter().map(RunScore::to_json).collect::<Vec<_>>(),
        "meanSemanticRecallProxy": mean(&recalls),
    })
}

fn repeat_interval(samples: &[Option<u128>], repeats: u32) -> Value {
    let missing = samples.iter().filter(|sample| sample.is_none()).count();
    if repeats < 2 {
        return json!({"status":"insufficient-repeat-evidence","repeatCount":repeats,"sampleCount":samples.len()});
    }
    if missing > 0 {
        return json!({"status":"unknown","repeatCount":repeats,"sampleCount":samples.len(),"missingSamples":missing});
    }
    let values: Vec<u128> = samples.iter().filter_map(|value| *value).collect();
    if values.len() < 2 {
        return json!({"status":"insufficient-repeat-evidence","repeatCount":repeats,"sampleCount":values.len()});
    }
    let min = *values.iter().min().unwrap_or(&0);
    let max = *values.iter().max().unwrap_or(&0);
    json!({
        "status":"reported-empirical-range",
        "repeatCount":repeats,
        "sampleCount":values.len(),
        "min":min,
        "max":max,
        "range":max-min,
        "halfRange":(max-min) as f64/2.0
    })
}

fn telemetry_intervals(runs: &[BenchTelemetry], repeats: u32) -> Value {
    let wall: Vec<Option<u128>> = runs
        .iter()
        .map(|run| {
            (run.planned_cases > 0 && run.timed_cases == run.planned_cases)
                .then_some(run.wall_time_ms)
        })
        .collect();
    let token = |index: usize| -> Vec<Option<u128>> {
        runs.iter()
            .map(|run| {
                (run.runtime_requested && run.runtime_usage_known)
                    .then_some(run.runtime_tokens[index] as u128)
            })
            .collect()
    };
    let token_interval = |index: usize| {
        if !runs.is_empty() && runs.iter().all(|run| !run.runtime_requested) {
            json!({"status":"not-requested","repeatCount":repeats,"sampleCount":0})
        } else {
            repeat_interval(&token(index), repeats)
        }
    };
    json!({
        "wallTimeMs": repeat_interval(&wall, repeats),
        "runtimeInputTokens": token_interval(0),
        "runtimeOutputTokens": token_interval(1),
        "runtimeCachedInputTokens": token_interval(2),
        "runtimeRetryTokens": token_interval(3)
    })
}

pub fn run(root: &Path, mut opts: Options) -> bool {
    if !valid_repeats(opts.repeat) {
        eprintln!("legion-dev audit-bench: --repeats must be between 1 and {MAX_REPEATS}");
        return false;
    }
    if opts.with_lenses && opts.token_budget == 0 {
        eprintln!("legion-dev audit-bench: --token-budget must be positive with --with-lenses");
        return false;
    }
    if opts.with_lenses && opts.case_token_budget == 0 {
        eprintln!(
            "legion-dev audit-bench: --case-token-budget must be positive with --with-lenses"
        );
        return false;
    }
    if !opts.with_lenses && (opts.claude.is_some() || opts.model.is_some()) {
        eprintln!("legion-dev audit-bench: --claude and --model require --with-lenses");
        return false;
    }
    if opts
        .model
        .as_deref()
        .is_some_and(|model| model.trim().is_empty())
    {
        eprintln!("legion-dev audit-bench: --model must not be empty");
        return false;
    }
    if !opts.legion.is_file() {
        eprintln!(
            "legion-dev audit-bench: --legion {} is not a file",
            opts.legion.display()
        );
        return false;
    }
    match fs::canonicalize(&opts.legion) {
        Ok(path) => opts.legion = path,
        Err(error) => {
            eprintln!(
                "legion-dev audit-bench: cannot resolve {}: {error}",
                opts.legion.display()
            );
            return false;
        }
    }
    if let Some(claude) = opts.claude.clone() {
        if !claude.is_file() {
            eprintln!(
                "legion-dev audit-bench: --claude {} is not a file",
                claude.display()
            );
            return false;
        }
        match fs::canonicalize(&claude) {
            Ok(path) => opts.claude = Some(path),
            Err(error) => {
                eprintln!(
                    "legion-dev audit-bench: cannot resolve --claude {}: {error}",
                    claude.display()
                );
                return false;
            }
        }
    }
    match run_inner(root, &opts) {
        Ok(ok) => ok,
        Err(error) => {
            eprintln!("legion-dev audit-bench: {error}");
            false
        }
    }
}

fn run_inner(root: &Path, opts: &Options) -> Result<bool, String> {
    let bench = root.join("evals").join("audit-bench");
    let fixtures = if opts.fixtures.is_empty() {
        discover_fixtures(&bench.join("fixtures"))?
    } else {
        opts.fixtures.clone()
    };
    if fixtures.is_empty() {
        return Err("no fixture bundles found".into());
    }
    let requested_cases: std::collections::BTreeSet<String> = opts.cases.iter().cloned().collect();
    let mut fixture_splits = BTreeMap::new();
    let mut known_cases = std::collections::BTreeSet::new();
    for fixture in &fixtures {
        let file = load_cases(&bench.join("fixtures"), fixture)?;
        fixture_splits.insert(fixture.clone(), file.split_label().to_owned());
        known_cases.extend(file.cases.into_iter().map(|case| case.id));
    }
    validate_case_filter(&requested_cases, &known_cases)?;
    let work_root = opts
        .work_dir
        .clone()
        .unwrap_or_else(|| root.join(".cache").join("audit-bench"));
    let work = work_root.join(format!("run-{}", std::process::id()));
    fs::create_dir_all(&work).map_err(|e| format!("cannot create {}: {e}", work.display()))?;
    // Absolute paths: git runs with its own current directory.
    let work =
        fs::canonicalize(&work).map_err(|e| format!("cannot resolve {}: {e}", work.display()))?;

    let arms: &[&str] = if opts.aa { &["A", "B"] } else { &["A"] };
    let mut arm_scores: Vec<Vec<RunScore>> = Vec::new();
    let mut split_arm_scores: Vec<BTreeMap<String, Vec<RunScore>>> = Vec::new();
    let mut split_arm_telemetry: Vec<BTreeMap<String, Vec<BenchTelemetry>>> = Vec::new();
    let mut errors = Vec::new();
    let mut case_metrics = serde_json::Map::new();
    let mut case_outcomes = serde_json::Map::new();
    let mut token_budget = TokenBudget::new(opts.token_budget, opts.case_token_budget);
    for arm in arms {
        let mut runs = Vec::new();
        let mut split_runs: BTreeMap<String, Vec<RunScore>> = BTreeMap::new();
        let mut split_telemetry_runs: BTreeMap<String, Vec<BenchTelemetry>> = BTreeMap::new();
        for index in 1..=opts.repeat {
            let label = format!("{arm}{index}");
            let mut total = RunScore::default();
            let mut per_split_scores: BTreeMap<String, RunScore> = BTreeMap::new();
            let mut per_split_telemetry: BTreeMap<String, BenchTelemetry> = BTreeMap::new();
            for fixture in &fixtures {
                let result = run_fixture(opts, &bench, &work, &label, fixture, &mut token_budget)?;
                total.merge(&result.score);
                per_split_scores
                    .entry(result.split.clone())
                    .or_default()
                    .merge(&result.score);
                per_split_telemetry
                    .entry(result.split.clone())
                    .and_modify(|telemetry| telemetry.merge(&result.telemetry))
                    .or_insert(result.telemetry.clone());
                errors.extend(result.errors);
                case_metrics.insert(format!("{label}/{fixture}"), json!(result.case_metrics));
                case_outcomes.insert(format!("{label}/{fixture}"), json!(result.case_outcomes));
            }
            runs.push(total);
            for (split, score) in per_split_scores {
                split_runs.entry(split).or_default().push(score);
            }
            for (split, telemetry) in per_split_telemetry {
                split_telemetry_runs
                    .entry(split)
                    .or_default()
                    .push(telemetry);
            }
        }
        arm_scores.push(runs);
        split_arm_scores.push(split_runs);
        split_arm_telemetry.push(split_telemetry_runs);
    }

    fn recalls(runs: &[RunScore]) -> Vec<f64> {
        runs.iter()
            .filter(|run| run.planned_cases > 0 && run.completed_cases == run.planned_cases)
            .filter_map(RunScore::recall)
            .collect()
    }
    let band = if opts.aa {
        aa_band(&recalls(&arm_scores[0]), &recalls(&arm_scores[1]))
    } else {
        None
    };
    let mut split_results = serde_json::Map::new();
    let split_names: std::collections::BTreeSet<String> = split_arm_scores
        .iter()
        .flat_map(|arm| arm.keys().cloned())
        .collect();
    let split_count = split_names.len();
    for split in split_names {
        let a_runs = split_arm_scores[0]
            .get(&split)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let b_runs = split_arm_scores
            .get(1)
            .and_then(|arm| arm.get(&split))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let a_telemetry = split_arm_telemetry[0]
            .get(&split)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let b_telemetry = split_arm_telemetry
            .get(1)
            .and_then(|arm| arm.get(&split))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let split_band = if opts.aa {
            aa_band(&recalls(a_runs), &recalls(b_runs))
        } else {
            None
        };
        let mut both_telemetry = a_telemetry.to_vec();
        both_telemetry.extend_from_slice(b_telemetry);
        split_results.insert(split, json!({
            "armA": arm_json(a_runs),
            "armB": if opts.aa { Some(arm_json(b_runs)) } else { None },
            "aaBand": split_band.as_ref().map(|b| json!({"metric":"semanticRecallProxy","meanA":b.mean_a,"meanB":b.mean_b,"meanDelta":b.mean_delta,"halfWidth":b.half_width})),
            "repeatIntervals": {
                "armA": telemetry_intervals(a_telemetry, opts.repeat),
                "armB": if opts.aa { Some(telemetry_intervals(b_telemetry, opts.repeat)) } else { None },
                "combinedArms": if opts.aa { Some(telemetry_intervals(&both_telemetry, opts.repeat)) } else { None }
            }
        }));
    }
    let summary = json!({
        "legion": opts.legion,
        "fixtures": fixtures,
        "repeat": opts.repeat,
        "repeats": opts.repeat,
        "caseFilter": if requested_cases.is_empty() { None::<Vec<String>> } else { Some(requested_cases.iter().cloned().collect()) },
        "benchmarkTokenBudget": if opts.with_lenses { token_budget.to_json() } else { json!({"status":"not-requested"}) },
        "runtimeIdentity": if opts.with_lenses { json!({
            "claude": opts.claude.as_ref().map(|path| path.to_string_lossy().into_owned()).unwrap_or_else(|| "PATH-default".into()),
            "model": opts.model.as_deref().unwrap_or("host-default")
        }) } else { Value::Null },
        "fixtureSplits": fixture_splits,
        "aggregateScope": "all selected fixtures across splits; use splitResults for split-specific comparisons",
        "ablationIdentity": if opts.with_lenses { "deterministic-plus-reasoning" } else { "deterministic-only" },
        "splitResults": Value::Object(split_results),
        "armA": arm_json(&arm_scores[0]),
        "armB": arm_scores.get(1).map(|runs| arm_json(runs)),
        "caseMetrics": Value::Object(case_metrics),
        "caseOutcomes": Value::Object(case_outcomes),
        "aaBand": if split_count <= 1 { band.as_ref().map(|b| json!({
            "metric": "semanticRecallProxy",
            "meanA": b.mean_a,
            "meanB": b.mean_b,
            "meanDelta": b.mean_delta,
            "halfWidth": b.half_width,
        })) } else { None },
        "caseErrors": errors,
    });
    if opts.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&summary).map_err(|e| e.to_string())?
        );
    } else {
        for (arm, runs) in arms.iter().zip(&arm_scores) {
            for (index, run) in runs.iter().enumerate() {
                println!(
                    "{arm}{} all selected splits: semantic proxy {} | localization proxy {} | caller {} | clean {} | precision {}..{} ({} unresolved)",
                    index + 1,
                    fmt_ratio(run.semantic_recall_proxy()),
                    fmt_ratio(run.localization_proxy()),
                    fmt_ratio(run.caller_recall()),
                    fmt_ratio(run.clean_rate()),
                    fmt_ratio(run.precision_lower()),
                    fmt_ratio(run.precision_upper()),
                    run.unresolved
                );
            }
        }
        for (split, runs) in &split_arm_scores[0] {
            for (index, run) in runs.iter().enumerate() {
                println!(
                    "{split} A{}: semantic proxy {} | localization proxy {} | clean {}",
                    index + 1,
                    fmt_ratio(run.semantic_recall_proxy()),
                    fmt_ratio(run.localization_proxy()),
                    fmt_ratio(run.clean_rate())
                );
            }
        }
        if let Some(second_arm) = split_arm_scores.get(1) {
            for (split, runs) in second_arm {
                for (index, run) in runs.iter().enumerate() {
                    println!(
                        "{split} B{}: semantic proxy {} | localization proxy {} | clean {}",
                        index + 1,
                        fmt_ratio(run.semantic_recall_proxy()),
                        fmt_ratio(run.localization_proxy()),
                        fmt_ratio(run.clean_rate())
                    );
                }
            }
        }
        if split_count <= 1 {
            if let Some(band) = &band {
                println!(
                    "A/A band: +/-{:.1} pp (arm means {:.1}% vs {:.1}%)",
                    band.half_width * 100.0,
                    band.mean_a * 100.0,
                    band.mean_b * 100.0
                );
            }
        } else {
            for (split, a_runs) in &split_arm_scores[0] {
                if let Some(b_runs) = split_arm_scores.get(1).and_then(|arm| arm.get(split)) {
                    if let Some(split_band) = aa_band(&recalls(a_runs), &recalls(b_runs)) {
                        println!(
                            "{split} A/A band: +/-{:.1} pp (arm means {:.1}% vs {:.1}%)",
                            split_band.half_width * 100.0,
                            split_band.mean_a * 100.0,
                            split_band.mean_b * 100.0
                        );
                    }
                }
            }
        }
        for error in &errors {
            eprintln!("case error: {error}");
        }
    }
    if !opts.keep {
        let _ = fs::remove_dir_all(&work);
    }
    Ok(errors.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_provider_selection_is_fixture_scoped_and_model_mode_stays_full() {
        assert!(deterministic_provider_args(false, None).is_empty());
        assert!(deterministic_provider_args(true, Some(&AUDIT_BEHAVIOR_PROVIDERS)).is_empty());
        assert_eq!(
            deterministic_provider_args(false, Some(&AUDIT_BEHAVIOR_PROVIDERS)),
            vec![
                "--only",
                "legacy.data.internal-suite",
                "--only",
                "legacy.security.binary-pins"
            ]
        );
    }

    fn selected_result(provider: &str, applicable: bool) -> Value {
        json!({"provider":provider,"skipped":false,"result":{
            "schema_version":1,"provider":provider,"required":true,
            "status":"ok","applicable":applicable,"complete":applicable,
            "coverage":if applicable {json!({"denominator_digest":"sha256:fixture","expected":1,"examined":1,"gaps":[]})} else {Value::Null},
            "findings":[],"coverage_gaps":[],"degradation":[],
            "details":if applicable {json!({"candidates":[]})} else {json!({"notApplicable":true,"notApplicableReason":"selector-denominator-empty"})}
        }})
    }

    fn zero_denominator_plan() -> Value {
        json!({"nativePlan":{"plan":{"providers":AUDIT_BEHAVIOR_PROVIDERS.iter().map(|provider| json!({"id":provider,"configuration":{"denominatorCount":0}})).collect::<Vec<_>>()}}})
    }

    #[test]
    fn actual_report_serializers_preserve_flat_provider_evidence_for_benchmark_readers() {
        let mut candidate = selected_result(AUDIT_BEHAVIOR_PROVIDERS[0], true);
        candidate["result"]["details"]["candidates"] = json!([{"path":"src/session.ts","line":4}]);
        let report = legion_contracts::ReportV1 {
            schema_version: 1,
            report_id: legion_contracts::ReportId::new("benchmark-wire-fixture").unwrap(),
            status: legion_contracts::ReportStatus::Clean,
            findings: Vec::new(),
            gaps: Vec::new(),
            claims: BTreeMap::new(),
            targets: vec!["repo".into()],
            extensions: BTreeMap::from([(
                "providerResults".into(),
                json!([
                    candidate,
                    selected_result(AUDIT_BEHAVIOR_PROVIDERS[1], true)
                ]),
            )]),
        };
        let serialized = serde_json::to_value(&report).unwrap();
        assert!(serialized.get("extensions").is_none());
        let view = legion_contracts::Report::read_any(&serialized).unwrap();
        for schema in [1, 2] {
            let wire = view.to_value_for_schema(schema).unwrap();
            assert!(wire.get("extensions").is_none());
            let stage = deterministic_stage_metrics(&wire, &AUDIT_BEHAVIOR_PROVIDERS, None);
            assert_eq!(stage["complete"], true, "schema {schema}: {stage}");
            let metrics = report_metrics(&wire);
            assert_eq!(metrics["rawScannerCandidates"]["count"], 1);
            assert_eq!(
                metrics["rawScannerCandidates"]["candidateProviders"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
            assert_eq!(
                metrics["rawScannerCandidates"]["source"],
                "providerResults[].result.details"
            );
            let (candidates, count) = raw_candidate_observations(&wire).unwrap();
            assert_eq!(count, 1);
            assert_eq!(candidates[0].locations[0].path, "src/session.ts");
            let mut missing = wire.clone();
            missing.as_object_mut().unwrap().remove("providerResults");
            assert_eq!(
                deterministic_stage_metrics(&missing, &AUDIT_BEHAVIOR_PROVIDERS, None)["status"],
                "unknown"
            );
            assert_eq!(
                report_metrics(&missing)["rawScannerCandidates"]["status"],
                "unavailable"
            );
            let mut malformed = wire;
            malformed["providerResults"] = json!("not-an-array");
            assert_eq!(
                deterministic_stage_metrics(&malformed, &AUDIT_BEHAVIOR_PROVIDERS, None)["status"],
                "unknown"
            );
            assert_eq!(
                report_metrics(&malformed)["rawScannerCandidates"]["status"],
                "malformed"
            );
        }
    }

    #[test]
    fn selected_stage_completeness_does_not_claim_full_audit_completeness() {
        let mut first = selected_result(AUDIT_BEHAVIOR_PROVIDERS[0], true);
        first["result"]["details"]["candidates"] = json!([{"path":"src/session.ts","line":4}]);
        let report =
            json!({"providerResults":[first,selected_result(AUDIT_BEHAVIOR_PROVIDERS[1],true)]});
        let stage = deterministic_stage_metrics(&report, &AUDIT_BEHAVIOR_PROVIDERS, None);
        assert_eq!(stage["complete"], true);
        assert_eq!(stage["selectedProviders"].as_array().unwrap().len(), 2);
        assert_eq!(stage["providers"][0]["candidateCount"], 1);
        assert_eq!(
            stage["fullAuditCompleteness"],
            "not-claimed-by-selected-stage"
        );
        let missing = deterministic_stage_metrics(
            &json!({"providerResults":[]}),
            &AUDIT_BEHAVIOR_PROVIDERS,
            None,
        );
        assert_eq!(missing["complete"], false);
        assert_eq!(missing["providers"][0]["status"], "missing");
    }

    #[test]
    fn zero_eligible_selection_is_not_inspected_and_has_known_zero_candidates() {
        let report = json!({"providerResults":AUDIT_BEHAVIOR_PROVIDERS.iter().map(|provider| selected_result(provider,false)).collect::<Vec<_>>()});
        let stage = deterministic_stage_metrics(
            &report,
            &AUDIT_BEHAVIOR_PROVIDERS,
            Some(&zero_denominator_plan()),
        );
        assert_eq!(stage["complete"], true);
        for provider in stage["providers"].as_array().unwrap() {
            assert_eq!(provider["complete"], false);
            assert_eq!(provider["selectionStatus"], "not-applicable");
            assert_eq!(provider["inspection"], "not-inspected");
        }
        assert_eq!(
            report_metrics(&report)["rawScannerCandidates"]["status"],
            "unavailable"
        );
        let raw = selected_stage_raw_metrics(&report, &stage);
        assert_eq!(raw["rawScannerCandidates"]["count"], 0);
        assert_eq!(raw["rawScannerCandidates"]["candidateProviders"], json!([]));
        assert_eq!(
            raw["rawScannerCandidates"]["evidenceState"],
            "not-applicable"
        );

        let mixed = json!({"providerResults":[selected_result(AUDIT_BEHAVIOR_PROVIDERS[0],false),selected_result(AUDIT_BEHAVIOR_PROVIDERS[1],true)]});
        let stage = deterministic_stage_metrics(
            &mixed,
            &AUDIT_BEHAVIOR_PROVIDERS,
            Some(&zero_denominator_plan()),
        );
        assert_eq!(stage["complete"], true);
        let raw = selected_stage_raw_metrics(&mixed, &stage);
        assert_eq!(
            raw["rawScannerCandidates"]["candidateProviders"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            raw["rawScannerCandidates"]["candidateProviders"][0]["provider"],
            AUDIT_BEHAVIOR_PROVIDERS[1]
        );
    }

    #[test]
    fn not_applicable_requires_typed_zero_denominator_evidence() {
        let valid = json!({"providerResults":AUDIT_BEHAVIOR_PROVIDERS.iter().map(|provider| selected_result(provider,false)).collect::<Vec<_>>()});
        let plan = zero_denominator_plan();
        let mut invalid = Vec::new();
        let mut malformed = valid.clone();
        malformed["providerResults"][0]["result"]
            .as_object_mut()
            .unwrap()
            .remove("schema_version");
        invalid.push((malformed, Some(plan.clone())));
        let mut missing = valid.clone();
        missing["providerResults"].as_array_mut().unwrap().remove(0);
        invalid.push((missing, Some(plan.clone())));
        let mut duplicate = valid.clone();
        duplicate["providerResults"]
            .as_array_mut()
            .unwrap()
            .push(selected_result(AUDIT_BEHAVIOR_PROVIDERS[0], false));
        invalid.push((duplicate, Some(plan.clone())));
        let mut nonzero = plan.clone();
        nonzero["nativePlan"]["plan"]["providers"][0]["configuration"]["denominatorCount"] =
            json!(1);
        invalid.push((valid.clone(), Some(nonzero)));
        let mut unknown = plan.clone();
        unknown["nativePlan"]["plan"]["providers"][0]["configuration"]
            .as_object_mut()
            .unwrap()
            .remove("denominatorCount");
        invalid.push((valid.clone(), Some(unknown)));
        invalid.push((valid.clone(), None));
        for (field, value) in [
            ("status", json!("failed")),
            ("status", json!("cancelled")),
            ("complete", json!(true)),
            ("coverage_gaps", json!(["missing"])),
        ] {
            let mut report = valid.clone();
            report["providerResults"][0]["result"][field] = value;
            invalid.push((report, Some(plan.clone())));
        }
        for (field, value) in [
            ("notApplicableReason", json!("host-declaration-absent")),
            ("notApplicable", Value::Null),
            ("candidates", json!([{"path":"unexpected"}])),
        ] {
            let mut report = valid.clone();
            report["providerResults"][0]["result"]["details"][field] = value;
            invalid.push((report, Some(plan.clone())));
        }
        for (report, plan) in invalid {
            let stage =
                deterministic_stage_metrics(&report, &AUDIT_BEHAVIOR_PROVIDERS, plan.as_ref());
            assert_eq!(stage["complete"], false, "{report} / {plan:?}");
            assert_ne!(
                selected_stage_raw_metrics(&report, &stage)["rawScannerCandidates"]
                    ["evidenceState"],
                "not-applicable"
            );
        }
    }

    fn close(actual: Option<f64>, expected: f64) -> bool {
        actual.is_some_and(|value| (value - expected).abs() < 1e-9)
    }

    #[test]
    fn repeat_bound_is_explicit_and_interval_needs_repeat_evidence() {
        assert!(!valid_repeats(0));
        assert!(valid_repeats(1));
        assert!(valid_repeats(MAX_REPEATS));
        assert!(!valid_repeats(MAX_REPEATS + 1));
        assert_eq!(
            repeat_interval(&[Some(8)], 1)["status"],
            "insufficient-repeat-evidence"
        );
        assert_eq!(repeat_interval(&[Some(8), None], 2)["status"], "unknown");
        let interval = repeat_interval(&[Some(8), Some(12)], 2);
        assert_eq!(interval["status"], "reported-empirical-range");
        assert_eq!(interval["min"], 8);
        assert_eq!(interval["max"], 12);
        assert_eq!(interval["halfRange"], 2.0);
    }

    #[test]
    fn token_budget_reconciles_exact_usage_and_exhausts_next_case() {
        let mut budget = TokenBudget::new(DEFAULT_CASE_TOKEN_BUDGET, DEFAULT_CASE_TOKEN_BUDGET);
        let allocation = budget.reserve_case().unwrap();
        assert_eq!(allocation, DEFAULT_CASE_TOKEN_BUDGET);
        assert_eq!(budget.settle_case(allocation, Some(allocation)), allocation);
        assert_eq!(budget.remaining, 0);
        assert!(budget.reserve_case().is_none());
        assert_eq!(budget.to_json()["actualTokens"], allocation);
    }

    #[test]
    fn case_reservation_is_configurable_but_capped_by_aggregate_remaining() {
        let mut budget = TokenBudget::new(7, 50_000);
        assert_eq!(budget.reserve_case(), Some(7));
        budget.settle_case(7, Some(2));
        assert_eq!(budget.remaining, 5);
        assert_eq!(budget.reserve_case(), Some(5));
        assert_eq!(budget.to_json()["perCaseLimitTokens"], 50_000);
    }

    #[test]
    fn unknown_usage_burns_full_shared_reservation() {
        let mut budget = TokenBudget::new(DEFAULT_CASE_TOKEN_BUDGET * 2, DEFAULT_CASE_TOKEN_BUDGET);
        let allocation = budget.reserve_case().unwrap();
        budget.settle_case(allocation, None);
        assert_eq!(budget.remaining, DEFAULT_CASE_TOKEN_BUDGET);
        assert!(budget.halted);
        assert_eq!(budget.unknown_cases, 1);
        assert_eq!(budget.to_json()["actualTokens"], Value::Null);
        assert!(budget.reserve_case().is_none());
    }

    #[test]
    fn measured_overrun_halts_later_cases() {
        let mut budget = TokenBudget::new(20, 10);
        let allocation = budget.reserve_case().unwrap();
        budget.settle_case(allocation, Some(11));
        assert_eq!(budget.overrun, 1);
        assert!(budget.halted);
        assert!(budget.reserve_case().is_none());
    }

    #[test]
    fn aa_arms_share_one_token_budget_ledger() {
        let mut budget = TokenBudget::new(DEFAULT_CASE_TOKEN_BUDGET, DEFAULT_CASE_TOKEN_BUDGET);
        let arm_a = budget.reserve_case().unwrap();
        budget.settle_case(arm_a, Some(arm_a / 2));
        let arm_b = budget.reserve_case().unwrap();
        budget.settle_case(arm_b, Some(arm_b));
        assert_eq!(budget.actual, DEFAULT_CASE_TOKEN_BUDGET);
        assert_eq!(budget.remaining, 0);
        assert!(budget.reserve_case().is_none());
    }

    #[test]
    fn runtime_token_usage_requires_complete_reported_actuals() {
        let reported = json!({"runtime":{"usage":{"status":"reported","inputTokens":9,"outputTokens":4,"retryTokens":1,"cachedInputTokens":2}}});
        assert_eq!(observed_runtime_tokens(&reported), Some(14));
        let unknown = json!({"runtime":{"usage":{"status":"unknown","inputTokens":9,"outputTokens":4,"retryTokens":1}}});
        assert_eq!(observed_runtime_tokens(&unknown), None);
    }

    #[test]
    fn case_filter_rejects_unknown_ids_before_execution() {
        let requested = std::collections::BTreeSet::from(["missing".to_owned()]);
        let known = std::collections::BTreeSet::from(["present".to_owned()]);
        assert_eq!(
            validate_case_filter(&requested, &known).unwrap_err(),
            "unknown --case id(s): missing"
        );
    }

    #[test]
    fn telemetry_intervals_keep_ablation_usage_distinct() {
        let mut first = BenchTelemetry::new(1, true);
        first.timed_cases = 1;
        first.wall_time_ms = 100;
        first.runtime_calls = 1;
        first.runtime_tokens = [20, 5, 3, 0];
        let mut second = first.clone();
        second.wall_time_ms = 120;
        second.runtime_tokens = [30, 8, 4, 0];
        let intervals = telemetry_intervals(&[first, second], 2);
        assert_eq!(intervals["wallTimeMs"]["min"], 100);
        assert_eq!(intervals["runtimeInputTokens"]["min"], 20);
        assert_eq!(intervals["runtimeInputTokens"]["max"], 30);

        let deterministic = telemetry_intervals(&[BenchTelemetry::new(1, false)], 2);
        assert_eq!(
            deterministic["runtimeInputTokens"]["status"],
            "not-requested"
        );
    }

    fn site(path: &str, a: u32, b: u32) -> Site {
        Site {
            path: path.into(),
            line_range: [a, b],
        }
    }

    fn planted(id: &str, category: Category, path: &str, range: [u32; 2]) -> Case {
        Case {
            id: id.into(),
            kind: Kind::Planted,
            scope: format!("range:base..{id}"),
            category: Some(category),
            ruled: true,
            ruling: None,
            summary: String::new(),
            expected: vec![Expected {
                path: path.into(),
                line_range: range,
                lens: String::new(),
                severity: String::new(),
                alt: Vec::new(),
            }],
            rulings: Vec::new(),
        }
    }

    fn clean(id: &str) -> Case {
        Case {
            id: id.into(),
            kind: Kind::Clean,
            scope: format!("range:base..{id}"),
            category: None,
            ruled: true,
            ruling: None,
            summary: String::new(),
            expected: Vec::new(),
            rulings: Vec::new(),
        }
    }

    fn finding(location: &str) -> Observed {
        Observed {
            locations: vec![parse_location(location)],
        }
    }

    fn obs(entries: &[(&str, Vec<Observed>)]) -> BTreeMap<String, Vec<Observed>> {
        entries
            .iter()
            .map(|(id, findings)| (id.to_string(), findings.clone()))
            .collect()
    }

    #[test]
    fn location_parsing_handles_lines_ranges_and_bare_paths() {
        assert_eq!(
            parse_location("src/a.rs:12"),
            Loc {
                path: "src/a.rs".into(),
                start: Some(12),
                end: Some(12)
            }
        );
        assert_eq!(
            parse_location("src\\a.rs:3-9"),
            Loc {
                path: "src/a.rs".into(),
                start: Some(3),
                end: Some(9)
            }
        );
        assert_eq!(
            parse_location("src/a.rs"),
            Loc {
                path: "src/a.rs".into(),
                start: None,
                end: None
            }
        );
    }

    #[test]
    fn report_findings_keep_all_locations() {
        let report = json!({"findings": [
            {"id": "a", "locations": ["x.rs:1", "y.rs:2-3"]},
            {"id": "b", "locations": []},
        ]});
        let findings = findings_from_report(&report);
        assert_eq!(findings.len(), 2);
        assert_eq!(findings[0].locations.len(), 2);
        assert!(findings[1].locations.is_empty());
        assert!(findings_from_report(&json!({})).is_empty());
    }

    #[test]
    fn report_metrics_separate_final_findings_from_raw_candidates_and_unknown_usage() {
        let metrics = report_metrics(&json!({
            "status": "findings",
            "findings": [{"locations": ["src/a.rs:4"]}],
            "providerResults": [{
                "provider": "security.scan",
                "result": {"details": {"scannerCandidates": [{"id": "c1"}]}}
            }]
        }));
        assert_eq!(metrics["rawScannerCandidates"]["status"], "available");
        assert_eq!(metrics["rawScannerCandidates"]["count"], 1);
        assert_eq!(metrics["finalReport"]["findingCount"], 1);
        assert_eq!(
            metrics["phaseTelemetry"]["phases"][0]["actualInputTokens"]["status"],
            "unknown"
        );
        assert_eq!(
            metrics["phaseTelemetry"]["phases"][0]["actualCachedInputTokens"]["value"],
            Value::Null
        );
    }

    #[test]
    fn canonical_candidate_generator_details_keep_provider_provenance() {
        let report = json!({"status":"incomplete","findings":[],"providerResults":[
            {"provider":"legacy.data.internal-suite","result":{"details":{"candidates":[{"path":"src/session.ts","line":4}]}}},
            {"provider":"legacy.security.binary-pins","result":{"details":{"candidates":[]}}}
        ]});
        let metrics = report_metrics(&report);
        assert_eq!(metrics["rawScannerCandidates"]["status"], "available");
        assert_eq!(metrics["rawScannerCandidates"]["count"], 1);
        assert_eq!(
            metrics["rawScannerCandidates"]["candidateProviders"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        let (candidates, count) = raw_candidate_observations(&report).unwrap();
        assert_eq!(count, 1);
        assert_eq!(candidates[0].locations[0].path, "src/session.ts");
        assert_eq!(metrics["finalReport"]["completeness"]["complete"], false);
    }

    #[test]
    fn report_metrics_distinguish_missing_from_malformed_candidate_evidence() {
        let absent = report_metrics(&json!({"findings": []}));
        assert_eq!(absent["rawScannerCandidates"]["status"], "unavailable");
        assert_eq!(absent["rawScannerCandidates"]["count"], Value::Null);

        let malformed = report_metrics(&json!({
            "findings": [],
            "providerResults": [{
                "result": {"details": {"scannerCandidates": "not-an-array"}}
            }]
        }));
        assert_eq!(malformed["rawScannerCandidates"]["status"], "malformed");
        assert_eq!(malformed["rawScannerCandidates"]["count"], Value::Null);
    }

    #[test]
    fn runtime_usage_keeps_missing_actuals_unknown() {
        let root =
            std::env::temp_dir().join(format!("audit-bench-runtime-usage-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("runtime-calls")).unwrap();
        let runtime = json!({"calls":1});
        assert_eq!(runtime_usage(&root, &runtime)["status"], "unknown");
        assert!(runtime_usage(&root, &runtime)["inputTokens"].is_null());
        let missing_calls = runtime_usage(&root, &json!({"status":"done"}));
        assert_eq!(missing_calls["status"], "unknown");
        assert_eq!(missing_calls["callCount"], Value::Null);
        fs::write(
            root.join("runtime-calls/call.json"),
            serde_json::to_vec(&json!({"observation":{"usage":{
                "inputTokens":10,
                "outputTokens":4,
                "cachedInputTokens":3,
                "retryTokens":0
            }}}))
            .unwrap(),
        )
        .unwrap();
        let usage = runtime_usage(&root, &runtime);
        assert_eq!(usage["status"], "reported");
        assert_eq!(usage["inputTokens"], 10);
        assert_eq!(usage["cachedInputTokens"], 3);
        assert_eq!(usage["actualCost"]["status"], "unknown");

        let followup = root.join("variant");
        fs::create_dir_all(followup.join("runtime-calls")).unwrap();
        fs::write(
            followup.join("runtime-calls/variant-call.json"),
            serde_json::to_vec(&json!({"observation":{"usage":{
                "inputTokens":5,
                "outputTokens":1,
                "cachedInputTokens":0,
                "retryTokens":0
            }}}))
            .unwrap(),
        )
        .unwrap();
        let runtime_with_followup = json!({
            "calls":1,
            "followup":{"run":followup.to_string_lossy(),"calls":1}
        });
        let usage = runtime_usage(&root, &runtime_with_followup);
        assert_eq!(usage["status"], "reported");
        assert_eq!(usage["callCount"], 2);
        assert_eq!(usage["inputTokens"], 15);
        assert_eq!(usage["outputTokens"], 5);
        let missing_followup_calls = runtime_usage(
            &root,
            &json!({"calls":1,"followup":{"run":followup.to_string_lossy()}}),
        );
        assert_eq!(missing_followup_calls["status"], "unknown");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn raw_candidate_observations_preserve_known_and_unknown_anchors() {
        let report = json!({"providerResults": [{
            "result": {"details": {"scannerCandidates": [
                {"path": "src\\a.rs", "line": 5, "endLine": 7, "locationStatus": "known"},
                {"path": "src/b.rs", "locationStatus": "unknown"},
                {"provider": "scan", "line": 2}
            ]}}
        }]});
        let (candidates, count) = raw_candidate_observations(&report).unwrap();
        assert_eq!(count, 3);
        assert_eq!(candidates[0].locations[0].path, "src/a.rs");
        assert_eq!(
            (
                candidates[0].locations[0].start,
                candidates[0].locations[0].end
            ),
            (Some(5), Some(7))
        );
        assert!(candidates[1].locations.is_empty());
        assert!(candidates[2].locations.is_empty());
        assert!(raw_candidate_observations(&json!({"providerResults":[]})).is_none());
    }

    #[test]
    fn recall_and_location_recall_differ_by_line() {
        let cases = [
            planted("p1", Category::Security, "a.rs", [10, 12]),
            planted("p2", Category::Correctness, "b.rs", [5, 5]),
            planted("p3", Category::Perf, "c.rs", [1, 1]),
        ];
        let observed = obs(&[
            ("p1", vec![finding("a.rs:11")]),    // exact location
            ("p2", vec![finding("b.rs:40")]),    // right file, wrong line
            ("p3", vec![finding("other.rs:1")]), // miss
        ]);
        let score = score_run(&cases, &observed);
        assert_eq!(score.items, 3);
        assert!(close(score.recall(), 2.0 / 3.0));
        assert!(close(score.location_recall(), 1.0 / 3.0));
    }

    #[test]
    fn range_findings_match_by_overlap() {
        let cases = [planted("p1", Category::Lean, "a.rs", [10, 12])];
        let hit = score_run(&cases, &obs(&[("p1", vec![finding("a.rs:12-20")])]));
        let miss = score_run(&cases, &obs(&[("p1", vec![finding("a.rs:13-20")])]));
        assert_eq!(hit.location_hits, 1);
        assert_eq!(miss.location_hits, 0);
        assert_eq!(miss.path_hits, 1);
    }

    #[test]
    fn caller_recall_needs_the_primary_site_not_the_alternate() {
        let mut caller = planted("c1", Category::CallerRegression, "caller.rs", [30, 31]);
        caller.expected[0].alt.push(site("changed.rs", 5, 9));
        let at_alt = score_run(
            &[caller.clone()],
            &obs(&[("c1", vec![finding("changed.rs:6")])]),
        );
        assert!(close(at_alt.recall(), 1.0));
        assert!(close(at_alt.location_recall(), 1.0));
        assert!(close(at_alt.caller_recall(), 0.0));
        let at_caller = score_run(&[caller], &obs(&[("c1", vec![finding("caller.rs:31")])]));
        assert!(close(at_caller.caller_recall(), 1.0));
    }

    #[test]
    fn caller_recall_is_absent_without_caller_cases() {
        let cases = [planted("p1", Category::Security, "a.rs", [1, 1])];
        let score = score_run(&cases, &obs(&[("p1", vec![finding("a.rs:1")])]));
        assert!(score.caller_recall().is_none());
    }

    #[test]
    fn precision_bounds_count_unresolved_wrong_then_right() {
        let cases = [
            planted("p1", Category::Security, "a.rs", [10, 12]),
            clean("k1"),
        ];
        let observed = obs(&[
            // one right, two unresolved
            (
                "p1",
                vec![finding("a.rs:10"), finding("a.rs:99"), finding("z.rs:1")],
            ),
            // one wrong: a finding on a ruled-clean change
            ("k1", vec![finding("q.rs:1")]),
        ]);
        let score = score_run(&cases, &observed);
        assert_eq!((score.right, score.wrong, score.unresolved), (1, 1, 2));
        assert!(close(score.precision_lower(), 1.0 / 4.0));
        assert!(close(score.precision_upper(), 3.0 / 4.0));
    }

    #[test]
    fn ruling_overrides_expectation_matching() {
        let mut case = planted("p1", Category::Perf, "a.rs", [1, 5]);
        case.rulings.push(Ruling {
            path: "b.rs".into(),
            line_range: [7, 7],
            verdict: Verdict::Right,
        });
        case.rulings.push(Ruling {
            path: "a.rs".into(),
            line_range: [3, 3],
            verdict: Verdict::Wrong,
        });
        let observed = obs(&[(
            "p1",
            vec![finding("b.rs:7"), finding("a.rs:3"), finding("a.rs:1")],
        )]);
        let score = score_run(&[case], &observed);
        // b.rs:7 ruled right, a.rs:3 ruled wrong despite overlapping the
        // expected range, a.rs:1 matches only the expectation.
        assert_eq!((score.right, score.wrong, score.unresolved), (2, 1, 0));
    }

    #[test]
    fn no_findings_gives_undefined_precision() {
        let cases = [planted("p1", Category::Security, "a.rs", [1, 1])];
        let score = score_run(&cases, &obs(&[("p1", vec![])]));
        assert!(score.precision_lower().is_none());
        assert!(score.precision_upper().is_none());
        assert!(close(score.recall(), 0.0));
    }

    #[test]
    fn clean_rate_counts_cases_without_findings() {
        let cases = [clean("k1"), clean("k2"), clean("k3"), clean("k4")];
        let observed = obs(&[
            ("k1", vec![]),
            ("k2", vec![]),
            ("k3", vec![finding("x.rs:1")]),
            ("k4", vec![finding("x.rs:1"), finding("y.rs:2")]),
        ]);
        let score = score_run(&cases, &observed);
        assert!(close(score.clean_rate(), 0.5));
        assert_eq!(score.wrong, 3);
    }

    #[test]
    fn unruled_rows_are_never_scored() {
        let mut unruled_planted = planted("p2", Category::Security, "b.rs", [1, 1]);
        unruled_planted.ruled = false;
        let mut unruled_clean = clean("k2");
        unruled_clean.ruled = false;
        let cases = [
            planted("p1", Category::Security, "a.rs", [1, 1]),
            unruled_planted,
            clean("k1"),
            unruled_clean,
        ];
        // The unruled rows carry findings; they must not change any count.
        let observed = obs(&[
            ("p1", vec![finding("a.rs:1")]),
            ("p2", vec![finding("zz.rs:1")]),
            ("k1", vec![]),
            ("k2", vec![finding("zz.rs:2")]),
        ]);
        let score = score_run(&cases, &observed);
        assert_eq!(score.unruled_skipped, 2);
        assert_eq!(score.items, 1);
        assert_eq!(score.clean_cases, 1);
        assert_eq!((score.right, score.wrong, score.unresolved), (1, 0, 0));
        assert!(score.failed_cases.is_empty());
    }

    #[test]
    fn cases_that_did_not_run_remain_in_first_attempt_denominators() {
        let cases = [
            planted("p1", Category::Security, "a.rs", [1, 1]),
            planted("p2", Category::Security, "b.rs", [1, 1]),
            clean("k1"),
        ];
        let score = score_run(&cases, &obs(&[("p1", vec![finding("a.rs:1")])]));
        assert_eq!(score.failed_cases, vec!["p2".to_string(), "k1".to_string()]);
        assert_eq!(score.items, 2);
        assert_eq!(score.clean_cases, 1);
        assert_eq!((score.planned_cases, score.completed_cases), (3, 1));
        assert!(close(score.recall(), 0.5));
        assert!(close(score.clean_rate(), 0.0));
    }

    #[test]
    fn incomplete_runtime_keeps_partial_output_but_is_not_completed() {
        let cases = [
            planted("p1", Category::Security, "a.rs", [1, 1]),
            planted("p2", Category::Security, "b.rs", [1, 1]),
        ];
        let failed = std::collections::BTreeSet::from(["p1".to_owned()]);
        let score =
            score_run_with_failures(&cases, &obs(&[("p1", vec![finding("a.rs:1")])]), &failed);
        assert_eq!(score.failed_cases, vec!["p1".to_string(), "p2".to_string()]);
        assert_eq!((score.planned_cases, score.completed_cases), (2, 0));
        assert_eq!(score.items, 2);
        assert!(close(score.recall(), 0.5));
    }

    #[test]
    fn failed_clean_partial_report_is_not_a_pass() {
        let cases = [clean("k1")];
        let failed = std::collections::BTreeSet::from(["k1".to_owned()]);
        let score = score_run_with_failures(&cases, &obs(&[("k1", vec![])]), &failed);

        assert_eq!(score.clean_cases, 1);
        assert_eq!(score.clean_passed, 0);
        assert_eq!((score.planned_cases, score.completed_cases), (1, 0));
        assert_eq!(score.failed_cases, vec!["k1".to_owned()]);
        assert!(close(score.clean_rate(), 0.0));
    }

    #[test]
    fn merge_adds_counts_before_taking_ratios() {
        let first = score_run(
            &[planted("p1", Category::Security, "a.rs", [1, 1])],
            &obs(&[("p1", vec![finding("a.rs:1")])]),
        );
        let second = score_run(
            &[
                planted("p2", Category::Security, "b.rs", [1, 1]),
                planted("p3", Category::Security, "c.rs", [1, 1]),
                planted("p4", Category::Security, "d.rs", [1, 1]),
            ],
            &obs(&[("p2", vec![]), ("p3", vec![]), ("p4", vec![])]),
        );
        let mut total = first.clone();
        total.merge(&second);
        // 1 of 4 items, not the mean of 100% and 0%.
        assert!(close(total.recall(), 0.25));
    }

    #[test]
    fn aa_band_is_half_the_pooled_range() {
        let band = aa_band(&[0.50, 0.60], &[0.55, 0.40]).unwrap();
        assert!((band.half_width - 0.10).abs() < 1e-9);
        assert!((band.mean_a - 0.55).abs() < 1e-9);
        assert!((band.mean_b - 0.475).abs() < 1e-9);
        assert!((band.mean_delta - 0.075).abs() < 1e-9);
    }

    #[test]
    fn identical_twin_runs_have_zero_band() {
        let band = aa_band(&[0.8, 0.8, 0.8], &[0.8, 0.8, 0.8]).unwrap();
        assert!(band.half_width.abs() < 1e-12);
        assert!(band.mean_delta.abs() < 1e-12);
    }

    #[test]
    fn aa_band_needs_both_arms() {
        assert!(aa_band(&[], &[0.5]).is_none());
        assert!(aa_band(&[0.5], &[]).is_none());
    }

    #[test]
    fn scope_parsing_and_base_resolution_specs() {
        let range = parse_scope("range:base..case-1").unwrap();
        assert_eq!(range.head_ref(), "case-1");
        assert_eq!(range.base_spec(), "base");
        let commit = parse_scope("commit:abc123").unwrap();
        assert_eq!(commit.head_ref(), "abc123");
        assert_eq!(commit.base_spec(), "abc123^");
        assert!(parse_scope("range:base").is_err());
        assert!(parse_scope("range:-x..y").is_err());
        assert!(parse_scope("range:a..b..c").is_err());
        assert!(parse_scope("commit:").is_err());
        assert!(parse_scope("whole").is_err());
    }

    #[test]
    fn case_file_validation_rejects_malformed_rows() {
        let mut file = CaseFile {
            schema: CASES_SCHEMA.into(),
            fixture: "f".into(),
            split: None,
            language: String::new(),
            base: String::new(),
            cases: vec![
                planted("p1", Category::Security, "a.rs", [1, 2]),
                clean("k1"),
            ],
        };
        assert!(validate_case_file(&file).is_ok());

        let mut duplicate = file.clone();
        duplicate.cases.push(clean("k1"));
        assert!(validate_case_file(&duplicate).is_err());

        let mut no_category = file.clone();
        no_category.cases[0].category = None;
        assert!(validate_case_file(&no_category).is_err());

        let mut bad_range = file.clone();
        bad_range.cases[0].expected[0].line_range = [5, 2];
        assert!(validate_case_file(&bad_range).is_err());

        let mut dirty_clean = file.clone();
        dirty_clean.cases[1].expected = file.cases[0].expected.clone();
        assert!(validate_case_file(&dirty_clean).is_err());

        file.schema = "other".into();
        assert!(validate_case_file(&file).is_err());
    }

    #[test]
    fn case_json_defaults_to_ruled_and_rejects_unknown_fields() {
        let ok: Case = serde_json::from_value(json!({
            "id": "c", "kind": "clean", "scope": "range:base..c"
        }))
        .unwrap();
        assert!(ok.ruled);
        let unruled: Case = serde_json::from_value(json!({
            "id": "c", "kind": "planted", "scope": "range:base..c",
            "category": "caller-regression", "ruled": false,
            "expected": [{"path": "a.rs", "lineRange": [1, 2], "lens": "x", "severity": "high"}]
        }))
        .unwrap();
        assert!(!unruled.ruled);
        assert_eq!(unruled.category, Some(Category::CallerRegression));
        let typo = serde_json::from_value::<Case>(json!({
            "id": "c", "kind": "clean", "scope": "range:base..c", "rulled": true
        }));
        assert!(typo.is_err());
    }

    #[test]
    fn fixture_split_defaults_to_unknown_and_keeps_heldout_explicit() {
        let parse = |split: Option<&str>| {
            let mut value = json!({
                "schema": CASES_SCHEMA,
                "fixture": "f",
                "cases": [{"id":"clean","kind":"clean","scope":"range:base..clean"}]
            });
            if let Some(split) = split {
                value["split"] = json!(split);
            }
            serde_json::from_value::<CaseFile>(value).unwrap()
        };
        assert_eq!(parse(None).split_label(), "unknown");
        assert_eq!(parse(Some("heldout")).split_label(), "heldout");
        assert_eq!(parse(Some("tuning")).split_label(), "tuning");
    }
}
