//! `legion-dev audit-bench`: score an installed `legion audit` against the
//! planted-case fixtures in `evals/audit-bench/` (design ADR-6).
//!
//! The runner never invokes a model. It clones each fixture bundle, runs the
//! deterministic `legion audit` phase once per case scope, and compares the
//! reported finding locations with the human-ruled expectations in
//! `<fixture>.cases.json`. Rows with `ruled: false` are never scored.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const CASES_SCHEMA: &str = "legion-audit-bench-cases/1";

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
    pub language: String,
    #[serde(default)]
    pub base: String,
    pub cases: Vec<Case>,
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
    /// Expected items in scored planted cases.
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
    /// Cases that produced no usable observation; excluded from every ratio.
    pub failed_cases: Vec<String>,
}

fn ratio(numerator: u32, denominator: u32) -> Option<f64> {
    (denominator > 0).then(|| f64::from(numerator) / f64::from(denominator))
}

impl RunScore {
    pub fn recall(&self) -> Option<f64> {
        ratio(self.path_hits, self.items)
    }

    pub fn location_recall(&self) -> Option<f64> {
        ratio(self.location_hits, self.items)
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
        self.right += other.right;
        self.wrong += other.wrong;
        self.unresolved += other.unresolved;
        self.unruled_skipped += other.unruled_skipped;
        self.failed_cases.extend(other.failed_cases.iter().cloned());
    }

    pub fn to_json(&self) -> Value {
        json!({
            "recall": self.recall(),
            "locationRecall": self.location_recall(),
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
                "findingsRight": self.right,
                "findingsWrong": self.wrong,
                "findingsUnresolved": self.unresolved,
                "unruledSkipped": self.unruled_skipped,
            },
            "failedCases": self.failed_cases,
        })
    }
}

/// Score one run. `observed` maps case id to that case's findings; a case with
/// no entry did not run and is reported in `failed_cases`, never scored.
pub fn score_run(cases: &[Case], observed: &BTreeMap<String, Vec<Observed>>) -> RunScore {
    let mut score = RunScore::default();
    for case in cases {
        if !case.ruled {
            score.unruled_skipped += 1;
            continue;
        }
        let Some(findings) = observed.get(&case.id) else {
            score.failed_cases.push(case.id.clone());
            continue;
        };
        match case.kind {
            Kind::Clean => {
                score.clean_cases += 1;
                if findings.is_empty() {
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
    pub repeat: u32,
    pub aa: bool,
    pub with_lenses: bool,
    pub work_dir: Option<PathBuf>,
    pub keep: bool,
    pub json: bool,
}

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|e| format!("git {}: {e}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
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

/// Run `legion audit` for one case inside `clone`; returns the findings.
fn audit_case(
    legion: &Path,
    clone: &Path,
    case: &Case,
    out: &Path,
) -> Result<Vec<Observed>, String> {
    let scope = parse_scope(&case.scope)?;
    git(clone, &["clean", "-fdxq"])?;
    git(clone, &["checkout", "-fq", "--detach", scope.head_ref()])?;
    let spec = format!("{}^{{commit}}", scope.base_spec());
    let base = git(clone, &["rev-parse", "--verify", &spec])?;
    let _ = fs::remove_dir_all(out);
    fs::create_dir_all(out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    let output = Command::new(legion)
        .arg("audit")
        .arg(clone)
        .args(["--base", &base, "--quiet", "--out"])
        .arg(out)
        .output()
        .map_err(|e| format!("cannot run {}: {e}", legion.display()))?;
    // Findings make `legion audit` exit non-zero; only a missing report is a failure.
    let report_path = out.join("report.json");
    let text = fs::read_to_string(&report_path).map_err(|_| {
        format!(
            "no report.json (exit {:?}): {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
                .lines()
                .last()
                .unwrap_or("")
        )
    })?;
    let report: Value =
        serde_json::from_str(&text).map_err(|e| format!("{}: {e}", report_path.display()))?;
    Ok(findings_from_report(&report))
}

struct FixtureRun {
    score: RunScore,
    errors: Vec<String>,
}

fn run_fixture(
    opts: &Options,
    bench: &Path,
    work: &Path,
    label: &str,
    fixture: &str,
) -> Result<FixtureRun, String> {
    let fixtures = bench.join("fixtures");
    let file = load_cases(&fixtures, fixture)?;
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
    git(work, &["clone", "-q", &bundle_arg, &clone_arg])?;
    let mut observed = BTreeMap::new();
    let mut errors = Vec::new();
    for case in file.cases.iter().filter(|case| case.ruled) {
        let out = work.join(label).join(format!("{fixture}.{}.out", case.id));
        match audit_case(&opts.legion, &clone, case, &out) {
            Ok(findings) => {
                observed.insert(case.id.clone(), findings);
            }
            Err(error) => errors.push(format!("{fixture}/{}: {error}", case.id)),
        }
    }
    Ok(FixtureRun {
        score: score_run(&file.cases, &observed),
        errors,
    })
}

fn fmt_ratio(value: Option<f64>) -> String {
    value.map_or_else(|| "n/a".to_string(), |v| format!("{:.1}%", v * 100.0))
}

fn arm_json(runs: &[RunScore]) -> Value {
    let recalls: Vec<f64> = runs.iter().filter_map(RunScore::recall).collect();
    json!({
        "runs": runs.iter().map(RunScore::to_json).collect::<Vec<_>>(),
        "meanRecall": mean(&recalls),
    })
}

pub fn run(root: &Path, opts: Options) -> bool {
    if opts.with_lenses {
        eprintln!("legion-dev audit-bench: --with-lenses is reserved and not implemented");
        return false;
    }
    if opts.repeat == 0 {
        eprintln!("legion-dev audit-bench: --repeat must be at least 1");
        return false;
    }
    if !opts.legion.is_file() {
        eprintln!(
            "legion-dev audit-bench: --legion {} is not a file",
            opts.legion.display()
        );
        return false;
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
    let mut errors = Vec::new();
    for arm in arms {
        let mut runs = Vec::new();
        for index in 1..=opts.repeat {
            let label = format!("{arm}{index}");
            let mut total = RunScore::default();
            for fixture in &fixtures {
                let result = run_fixture(opts, &bench, &work, &label, fixture)?;
                total.merge(&result.score);
                errors.extend(result.errors);
            }
            runs.push(total);
        }
        arm_scores.push(runs);
    }

    fn recalls(runs: &[RunScore]) -> Vec<f64> {
        runs.iter().filter_map(RunScore::recall).collect()
    }
    let band = if opts.aa {
        aa_band(&recalls(&arm_scores[0]), &recalls(&arm_scores[1]))
    } else {
        None
    };
    let summary = json!({
        "legion": opts.legion,
        "fixtures": fixtures,
        "repeat": opts.repeat,
        "armA": arm_json(&arm_scores[0]),
        "armB": arm_scores.get(1).map(|runs| arm_json(runs)),
        "aaBand": band.as_ref().map(|b| json!({
            "meanA": b.mean_a,
            "meanB": b.mean_b,
            "meanDelta": b.mean_delta,
            "halfWidth": b.half_width,
        })),
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
                    "{arm}{}: recall {} | location {} | caller {} | clean {} | precision {}..{} ({} unresolved)",
                    index + 1,
                    fmt_ratio(run.recall()),
                    fmt_ratio(run.location_recall()),
                    fmt_ratio(run.caller_recall()),
                    fmt_ratio(run.clean_rate()),
                    fmt_ratio(run.precision_lower()),
                    fmt_ratio(run.precision_upper()),
                    run.unresolved
                );
            }
        }
        if let Some(band) = &band {
            println!(
                "A/A band: +/-{:.1} pp (arm means {:.1}% vs {:.1}%)",
                band.half_width * 100.0,
                band.mean_a * 100.0,
                band.mean_b * 100.0
            );
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

    fn close(actual: Option<f64>, expected: f64) -> bool {
        actual.is_some_and(|value| (value - expected).abs() < 1e-9)
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
    fn cases_that_did_not_run_are_excluded_and_listed() {
        let cases = [
            planted("p1", Category::Security, "a.rs", [1, 1]),
            planted("p2", Category::Security, "b.rs", [1, 1]),
            clean("k1"),
        ];
        let score = score_run(&cases, &obs(&[("p1", vec![finding("a.rs:1")])]));
        assert_eq!(score.failed_cases, vec!["p2".to_string(), "k1".to_string()]);
        assert_eq!(score.items, 1);
        assert_eq!(score.clean_cases, 0);
        assert!(close(score.recall(), 1.0));
        assert!(score.clean_rate().is_none());
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
}
