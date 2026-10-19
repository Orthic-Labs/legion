//! Per-tool output parsing for the frozen legacy-check surface.
//!
//! Ports the `run:` closures of `tools/audit/collect-facts.mjs` (and its
//! oldest ancestor, `52a90cf0^:tools/skills/audit/collect-facts.mjs`) into
//! typed Rust. Each function here mirrors ONE JS check's parse logic —
//! finding/summary counts, its severity mapping, and (where the JS source
//! explicitly treats unparseable output as a failed scan rather than a clean
//! one) the same "malformed output => not proven" rule. Deliberately NOT
//! ported: JS's own inconsistencies (e.g. `count || null` turning a real
//! zero into a null finding count for `cargo_unused_deps`) are
//! preserved rather than "fixed", because parity with the frozen legacy
//! behaviour is the point of this module.
//! cargo-deny additionally requires its complete four-check summary so an
//! operational failure or truncated JSONL stream cannot become clean evidence.
//!
//! `dispatch_json` handles tools whose entire stdout is one JSON value
//! (object or array). `dispatch_text` handles tools whose stdout is plain
//! text, one-JSON-object-per-line (JSONL), or a JSON blob nested inside a
//! non-JSON wrapper the generic whole-buffer `serde_json::from_slice` in
//! `execution_from_receipt` fails to parse as a single `Value`.
//!
//! `duplication` (jscpd) and `cargo_deny` do not agree with the rest of the
//! registry on where their machine-readable output lands: jscpd writes its
//! JSON report to `<outDir>/_jscpd/jscpd-report.json` on disk rather than
//! printing it, and cargo-deny's JSON diagnostics stream on **stderr**, not
//! stdout. `mod.rs`'s `ReportSource`/`execution_from_receipt` routes each
//! check to the right stream or file-backed artifact before handing bytes to
//! `dispatch_json`/`dispatch_text` below, so this module still only owns
//! parsing, not artifact plumbing.

use serde_json::Value;

/// One tool's parsed result, ready for `mod.rs` to fold into
/// `LegacyCheckOutput` via `push_finding` + `details` merge.
pub(crate) struct ParseOutcome {
    /// `findings_count` as the JS check would have reported it (including
    /// JS's own `count || null` quirks where the source has them).
    pub findings_count: Option<u64>,
    /// True exactly when the JS source's own comments/logic call this an
    /// "unparseable output — scan not proven" case (`status: 'error'`), not
    /// merely "we happened to fail to parse it here".
    pub malformed: bool,
    /// Extra fields merged verbatim into `output.details` (JS `meta`).
    pub meta: Vec<(&'static str, Value)>,
    /// Finding-id rule namespace for the summary finding.
    pub rule: &'static str,
    /// Severity of the summary finding when `findings_count > 0`.
    pub severity: &'static str,
}

impl ParseOutcome {
    fn ok(rule: &'static str, severity: &'static str, findings_count: Option<u64>) -> Self {
        Self {
            findings_count,
            malformed: false,
            meta: Vec::new(),
            rule,
            severity,
        }
    }

    fn with_meta(mut self, meta: Vec<(&'static str, Value)>) -> Self {
        self.meta = meta;
        self
    }

    fn malformed(rule: &'static str, severity: &'static str) -> Self {
        Self {
            findings_count: None,
            malformed: true,
            meta: Vec::new(),
            rule,
            severity,
        }
    }
}

/// JS `count || null`: a real, parseable zero collapses to a null finding
/// count. The `cargo_unused_deps` check does this;
/// preserved here rather than corrected, per the module doc comment.
fn zero_as_null(count: u64) -> Option<u64> {
    if count == 0 {
        None
    } else {
        Some(count)
    }
}

/// Dispatch for checks whose stdout is a single JSON value (object or
/// array). Returns `None` for checks not covered here (native checks, or
/// checks this pass did not reach — see `mod.rs` doc comment on the caller).
pub(crate) fn dispatch_json(check: &str, value: &Value) -> Option<ParseOutcome> {
    match check {
        "dead_code" => Some(knip(value)),
        "duplication" => Some(jscpd(value)),
        "lint" => lint_json(value),
        "types" => types_json(value),
        "sast" => Some(semgrep(value)),
        "ci_lint" => Some(actionlint(value)),
        "docker" => Some(hadolint(value)),
        "swift_lint" => Some(swiftlint(value)),
        "js_licenses" => Some(js_licenses(value)),
        "deps_cve" => Some(deps_cve(value)),
        "py_deps_cve" => Some(py_deps_cve(value)),
        "cargo_audit" => Some(cargo_audit(value)),
        "cargo_unsafe" => Some(cargo_unsafe(value)),
        "outdated" => Some(outdated(value)),
        "cargo_outdated" => Some(cargo_outdated(value)),
        _ => None,
    }
}

/// Dispatch for checks whose stdout is plain text or JSONL (i.e. the
/// whole-buffer `serde_json::from_slice::<Value>` in `execution_from_receipt`
/// failed, so `mod.rs` falls through to the text path).
pub(crate) fn dispatch_text(check: &str, text: &str) -> Option<ParseOutcome> {
    match check {
        "types" => Some(tsc(text)),
        "cargo_deny" => Some(cargo_deny(text)),
        "cargo_unused_deps" => Some(cargo_machete(text)),
        "lint" => Some(clippy(text)),
        "debt_markers" => Some(debt_markers(text)),
        "build" => Some(build(text)),
        _ => None,
    }
}

// ---------- dead_code (knip --reporter json) ----------
// JS: count = (j.files?.length || 0) + (Array.isArray(j.issues) ? j.issues.length
//                                        : Object.keys(j.issues || {}).length)
// Parse failure -> count stays null, status still 'ran' (no malformed rule in JS).
fn knip(value: &Value) -> ParseOutcome {
    let object = value.as_object();
    let files_len = object
        .and_then(|o| o.get("files"))
        .and_then(Value::as_array)
        .map(|a| a.len() as u64);
    let issues_len = object.and_then(|o| o.get("issues")).and_then(|issues| {
        issues
            .as_array()
            .map(|rows| rows.iter().filter(|row| knip_row_has_findings(row)).count() as u64)
            .or_else(|| issues.as_object().map(|o| o.len() as u64))
    });
    match (files_len, issues_len) {
        // Neither expected key present: not a knip report, so not a clean scan.
        (None, None) => ParseOutcome::malformed("legacy.dead_code.knip", "low"),
        (a, b) => ParseOutcome::ok(
            "legacy.dead_code.knip",
            "low",
            Some(a.unwrap_or(0) + b.unwrap_or(0)),
        ),
    }
}

/// Array-form `issues` rows are per-file objects whose category fields
/// (`exports`, `dependencies`, ...) are arrays. A row whose categories are all
/// empty is a file knip looked at, not a finding. A row with no array fields
/// at all is an unknown shape and still counts, as the legacy collector did.
fn knip_row_has_findings(row: &Value) -> bool {
    let Some(object) = row.as_object() else {
        return true;
    };
    let mut saw_array = false;
    for value in object.values() {
        if let Some(items) = value.as_array() {
            saw_array = true;
            if !items.is_empty() {
                return true;
            }
        }
    }
    !saw_array
}

// ---------- duplication (jscpd --reporters json) ----------
// JS: count = j.statistics?.total?.clones ?? (Array.isArray(j.duplicates) ? j.duplicates.length : null)
// Explicit rule: count === null -> status 'error' ("scan not proven"), same class as secrets/deps_cve.
fn jscpd(value: &Value) -> ParseOutcome {
    let count = value
        .get("statistics")
        .and_then(|s| s.get("total"))
        .and_then(|t| t.get("clones"))
        .and_then(Value::as_u64)
        .or_else(|| {
            value
                .get("duplicates")
                .and_then(Value::as_array)
                .map(|a| a.len() as u64)
        });
    match count {
        Some(count) => ParseOutcome::ok("legacy.duplication.jscpd", "low", Some(count)),
        None => ParseOutcome::malformed("legacy.duplication.jscpd", "low"),
    }
}

// ---------- lint (JSON-emitting tools: biome, eslint, ruff) ----------
// biome: diagnostics array length. eslint: array of files, sum errorCount+warningCount.
// ruff: JSON array of violations, its own length. All three: no malformed rule in JS.
fn lint_json(value: &Value) -> Option<ParseOutcome> {
    if let Some(diagnostics) = value.get("diagnostics").and_then(Value::as_array) {
        return Some(ParseOutcome::ok(
            "legacy.lint.biome",
            "medium",
            Some(diagnostics.len() as u64),
        ));
    }
    if let Some(files) = value.as_array() {
        // eslint shape: [{errorCount, warningCount, ...}, ...]
        if files
            .iter()
            .all(|f| f.get("errorCount").is_some() || f.get("warningCount").is_some())
            && !files.is_empty()
        {
            let count: u64 = files
                .iter()
                .map(|f| {
                    f.get("errorCount").and_then(Value::as_u64).unwrap_or(0)
                        + f.get("warningCount").and_then(Value::as_u64).unwrap_or(0)
                })
                .sum();
            return Some(ParseOutcome::ok(
                "legacy.lint.eslint",
                "medium",
                Some(count),
            ));
        }
        // ruff shape: [{code, filename, ...}, ...] (or an empty array — clean run).
        if !files.iter().all(Value::is_object) {
            return Some(ParseOutcome::malformed("legacy.lint.ruff", "medium"));
        }
        return Some(ParseOutcome::ok(
            "legacy.lint.ruff",
            "medium",
            Some(files.len() as u64),
        ));
    }
    // Neither a biome report nor an array of violations: unexpected shape.
    Some(ParseOutcome::malformed("legacy.lint.tool", "medium"))
}

// ---------- clippy (cargo clippy --message-format=json, JSONL on stdout) ----------
// A 101 exit is a completed diagnostic scan only when Cargo's entire stdout
// is JSONL, its final event is an unsuccessful build-finished, & every error
// is a located denied lint. Compiler errors, crashes & empty/truncated reports
// remain incomplete even if Cargo itself returned normally.
pub(crate) fn clippy_diagnostic_exit(stdout: &[u8], stderr: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(stdout) else {
        return false;
    };
    let Ok(errors) = std::str::from_utf8(stderr) else {
        return false;
    };
    if [
        "panicked at",
        "internal compiler error",
        "process didn't exit successfully",
        "could not execute process",
        "signal:",
    ]
    .iter()
    .any(|marker| errors.contains(marker))
    {
        return false;
    }
    let mut diagnostic = false;
    let mut finished = false;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        if finished {
            return false;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            return false;
        };
        match value["reason"].as_str() {
            Some("compiler-message") => {
                let message = &value["message"];
                if !matches!(
                    message["level"].as_str(),
                    Some("error" | "warning" | "note" | "help" | "failure-note")
                ) {
                    return false;
                }
                if message["level"] == "error" {
                    let Some(code) = message.pointer("/code/code").and_then(Value::as_str) else {
                        return false;
                    };
                    let code = code.strip_prefix("clippy::").unwrap_or(code);
                    let mut identifier = code.bytes();
                    if !identifier
                        .next()
                        .is_some_and(|b| b.is_ascii_lowercase() || b == b'_')
                        || !identifier
                            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
                    {
                        return false;
                    }
                    if !message["spans"].as_array().is_some_and(|spans| {
                        spans.iter().any(|span| {
                            span["is_primary"] == true
                                && span["file_name"]
                                    .as_str()
                                    .is_some_and(|path| !path.is_empty())
                                && span["line_start"].as_u64().is_some_and(|line| line > 0)
                        })
                    }) {
                        return false;
                    }
                    diagnostic = true;
                }
            }
            Some("build-finished") if value["success"] == false => finished = true,
            Some("compiler-artifact" | "build-script-executed") => {}
            _ => return false,
        }
    }
    diagnostic && finished
}

// JS counts only `compiler-message` reasons with a non-empty `message.spans` and a
// warning/error level; malformed/non-JSON lines are silently skipped (count defaults 0,
// never null — no malformed rule).
fn clippy(text: &str) -> ParseOutcome {
    let mut count = 0_u64;
    let mut saw_reason = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if value.get("reason").and_then(Value::as_str).is_some() {
            saw_reason = true;
        }
        if value.get("reason").and_then(Value::as_str) != Some("compiler-message") {
            continue;
        }
        let Some(message) = value.get("message") else {
            continue;
        };
        let has_spans = message
            .get("spans")
            .and_then(Value::as_array)
            .is_some_and(|spans| !spans.is_empty());
        let level_ok = message
            .get("level")
            .and_then(Value::as_str)
            .is_some_and(|level| level.starts_with("warning") || level.starts_with("error"));
        if has_spans && level_ok {
            count += 1;
        }
    }
    if !saw_reason {
        // cargo always emits cargo-message lines (at least build-finished);
        // none means the output was not a cargo JSON stream (or was empty).
        return ParseOutcome::malformed("legacy.lint.clippy", "medium");
    }
    ParseOutcome::ok("legacy.lint.clippy", "medium", Some(count))
}

// ---------- types (tsc --noEmit, plain text; basedpyright --outputjson) ----------
// tsc: count lines matching /error TS\d+/ across combined stdout+stderr.
fn tsc(text: &str) -> ParseOutcome {
    let count = text
        .lines()
        .filter(|line| {
            if let Some(rest) = line.split_once("error TS") {
                rest.1.chars().next().is_some_and(|c| c.is_ascii_digit())
            } else {
                false
            }
        })
        .count() as u64;
    ParseOutcome::ok("legacy.types.tsc", "high", Some(count))
}

// basedpyright --outputjson: summary.errorCount, or null on parse failure (no malformed rule).
fn types_json(value: &Value) -> Option<ParseOutcome> {
    let count = value
        .get("summary")
        .and_then(|summary| summary.get("errorCount"))
        .and_then(Value::as_u64);
    Some(match count {
        Some(count) => ParseOutcome::ok("legacy.types.basedpyright", "high", Some(count)),
        None => ParseOutcome::malformed("legacy.types.basedpyright", "high"),
    })
}

// ---------- sast (semgrep --json) ----------
// Envelope acceptance is intentionally stricter than historical JS parity.
fn semgrep(value: &Value) -> ParseOutcome {
    if super::semgrep::valid_envelope(value) {
        ParseOutcome::ok(
            "legacy.sast.semgrep",
            "high",
            Some(value["results"].as_array().unwrap().len() as u64),
        )
    } else {
        ParseOutcome::malformed("legacy.sast.semgrep", "high")
    }
}

// ---------- ci_lint (actionlint -format "{{json .}}", a JSON array) ----------
fn actionlint(value: &Value) -> ParseOutcome {
    // actionlint's `{{json .}}` template prints `null` for a clean run.
    if value.is_null() {
        return ParseOutcome::ok("legacy.ci_lint.actionlint", "medium", Some(0));
    }
    match value.as_array() {
        Some(rows) => ParseOutcome::ok(
            "legacy.ci_lint.actionlint",
            "medium",
            Some(rows.len() as u64),
        ),
        None => ParseOutcome::malformed("legacy.ci_lint.actionlint", "medium"),
    }
}

// ---------- docker (hadolint --format json Dockerfile, a JSON array) ----------
fn hadolint(value: &Value) -> ParseOutcome {
    match value.as_array() {
        Some(rows) => ParseOutcome::ok("legacy.docker.hadolint", "medium", Some(rows.len() as u64)),
        None => ParseOutcome::malformed("legacy.docker.hadolint", "medium"),
    }
}

// ---------- swift_lint (swiftlint lint --reporter json, a JSON array) ----------
fn swiftlint(value: &Value) -> ParseOutcome {
    match value.as_array() {
        Some(rows) => ParseOutcome::ok(
            "legacy.swift_lint.swiftlint",
            "medium",
            Some(rows.len() as u64),
        ),
        None => ParseOutcome::malformed("legacy.swift_lint.swiftlint", "medium"),
    }
}

// ---------- js_licenses (license-checker --json --production) ----------
// JS: flagged = packages whose `.licenses` matches the copyleft regex; total = all
// license-bearing packages. findings_count is the flagged (copyleft) count, not total.
fn js_licenses(value: &Value) -> ParseOutcome {
    const COPYLEFT: &[&str] = &[
        "GPL", "AGPL", "LGPL", "SSPL", "CC-BY-SA", "EUPL", "OSL", "CPAL",
    ];
    let Some(object) = value.as_object() else {
        return ParseOutcome::malformed("legacy.js_licenses.license-checker", "high");
    };
    // A healthy dependency-free project still contributes its root package.
    // The CLI's zero-package read failure prints {}; never interpret it as clean.
    if object.is_empty() {
        return ParseOutcome::malformed("legacy.js_licenses.license-checker", "high");
    }
    let mut total = 0_u64;
    let mut flagged = 0_u64;
    for entry in object.values() {
        let Some(licenses) = entry.get("licenses") else {
            continue;
        };
        total += 1;
        let text = match licenses {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        if COPYLEFT
            .iter()
            .any(|marker| text.to_ascii_uppercase().contains(marker))
        {
            flagged += 1;
        }
    }
    ParseOutcome::ok("legacy.js_licenses.license-checker", "high", Some(flagged)).with_meta(vec![
        ("totalDeps", Value::from(total)),
        ("copyleft", Value::from(flagged)),
    ])
}

// ---------- deps_cve (npm/pnpm audit --json) ----------
// JS: count = metadata.vulnerabilities.total ?? sum(Object.values(vulnerabilities)).
// Explicit rule: count === null -> status 'error' ("scan not proven"), same class as secrets.
fn deps_cve(value: &Value) -> ParseOutcome {
    let vulnerabilities = value.get("metadata").and_then(|m| m.get("vulnerabilities"));
    let count = vulnerabilities
        .and_then(|v| v.get("total"))
        .and_then(Value::as_u64)
        .or_else(|| {
            vulnerabilities
                .and_then(Value::as_object)
                .map(|object| object.values().filter_map(Value::as_u64).sum::<u64>())
        });
    match count {
        Some(count) => ParseOutcome::ok("legacy.deps_cve.audit", "critical", Some(count)),
        None => ParseOutcome::malformed("legacy.deps_cve.audit", "critical"),
    }
}

// ---------- py_deps_cve (explicit frozen requirements; no host environment) ----------
fn py_deps_cve(value: &Value) -> ParseOutcome {
    let invalid = || ParseOutcome::malformed("legacy.py_deps_cve.pip-audit", "critical");
    let Some(deps) = value.get("dependencies").and_then(Value::as_array) else {
        return invalid();
    };
    if deps.is_empty()
        || value
            .get("fixes")
            .and_then(Value::as_array)
            .is_none_or(|f| !f.is_empty())
    {
        return invalid();
    }
    let mut count = 0_u64;
    for dep in deps {
        if dep.get("skip_reason").is_some()
            || dep
                .get("name")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || dep
                .get("version")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        {
            return invalid();
        }
        let Some(vulns) = dep.get("vulns").and_then(Value::as_array) else {
            return invalid();
        };
        for vuln in vulns {
            if vuln
                .get("id")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
                || vuln
                    .get("fix_versions")
                    .and_then(Value::as_array)
                    .is_none_or(|v| !v.iter().all(Value::is_string))
            {
                return invalid();
            }
        }
        let Some(next) = count.checked_add(vulns.len() as u64) else {
            return invalid();
        };
        count = next;
    }
    ParseOutcome::ok("legacy.py_deps_cve.pip-audit", "critical", Some(count))
}

// ---------- cargo_audit (cargo audit --json) ----------
// JS: count = JSON.parse(r.stdout)?.vulnerabilities?.count ?? null. No malformed rule.
fn cargo_audit(value: &Value) -> ParseOutcome {
    let count = value
        .get("vulnerabilities")
        .and_then(|v| v.get("count"))
        .and_then(Value::as_u64);
    match count {
        Some(count) => ParseOutcome::ok("legacy.cargo_audit.cargo-audit", "critical", Some(count)),
        None => ParseOutcome::malformed("legacy.cargo_audit.cargo-audit", "critical"),
    }
}

// ---------- cargo_deny (all four checks, offline JSONL on stderr) ----------
// cargo-deny 0.20.2 emits a terminal summary even for a clean run. Its error
// exit is a bitset; code 1 alone cannot distinguish findings from an operational
// failure. Reconcile emitted error/warning diagnostics with all four stats.
pub(super) fn cargo_deny_completion(text: &str) -> Option<(u64, i32)> {
    let mut errors = 0_u64;
    let mut warnings = 0_u64;
    let mut summary = None;
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if summary.is_some() {
            return None; // The sole summary must be terminal.
        }
        let value: Value = serde_json::from_str(line).ok()?;
        match value.get("type")?.as_str()? {
            "diagnostic" => {
                let fields = value.get("fields")?.as_object()?;
                fields.get("message")?.as_str()?;
                match fields.get("severity")?.as_str()? {
                    "error" => errors = errors.checked_add(1)?,
                    "warning" => warnings = warnings.checked_add(1)?,
                    "note" | "help" => {}
                    _ => return None,
                }
            }
            "summary" => {
                let fields = value.get("fields")?.as_object()?;
                if fields.len() != 4 {
                    return None;
                }
                let mut totals = [0_u64; 2];
                let mut exit = 0;
                for (bit, check) in ["advisories", "bans", "licenses", "sources"]
                    .iter()
                    .enumerate()
                {
                    let stats = fields.get(*check)?.as_object()?;
                    if stats.len() != 4 {
                        return None;
                    }
                    for (index, name) in ["errors", "warnings", "notes", "helps"].iter().enumerate()
                    {
                        let count = stats.get(*name)?.as_u64()?;
                        u32::try_from(count).ok()?;
                        if index < 2 {
                            totals[index] = totals[index].checked_add(count)?;
                        }
                        if index == 0 && count > 0 {
                            exit |= 1 << bit;
                        }
                    }
                }
                if totals != [errors, warnings] {
                    return None;
                }
                summary = Some((errors.checked_add(warnings)?, exit));
            }
            // Structured non-diagnostic logs may precede successful summaries;
            // an error log is an operational failure even if a summary follows.
            "log" => {
                let fields = value.get("fields")?.as_object()?;
                let level = fields.get("level")?.as_str()?;
                if !matches!(
                    level,
                    "WARN" | "INFO" | "DEBUG" | "TRACE" | "warn" | "info" | "debug" | "trace"
                ) {
                    return None;
                }
            }
            _ => return None,
        }
    }
    summary
}

fn cargo_deny(text: &str) -> ParseOutcome {
    match cargo_deny_completion(text) {
        Some((count, _)) => ParseOutcome::ok("legacy.cargo_deny.cargo-deny", "high", Some(count)),
        None => ParseOutcome::malformed("legacy.cargo_deny.cargo-deny", "high"),
    }
}

// ---------- cargo_unused_deps (cargo machete --with-metadata, plain text) ----------
// JS: no JSON; one unused crate per indented, non-header line.
// `count = (...).length || null` (zero -> null, preserved).
// Completion contract grounded in cargo-machete v0.9.1 main.rs. Its per-manifest
// errors are printed on stderr & swallowed by upstream, including exit-zero
// clean summaries. Unknown report formats remain incomplete rather than clean.
pub(super) fn cargo_machete_report_complete(
    stdout: &[u8],
    stderr: &[u8],
    exit: Option<i32>,
) -> bool {
    let (Ok(stdout), Ok(stderr)) = (std::str::from_utf8(stdout), std::str::from_utf8(stderr))
    else {
        return false;
    };
    if stderr.lines().collect::<Vec<_>>()
        != [
            "Analyzing dependencies of crates in this directory...",
            "Done!",
        ]
    {
        return false;
    }
    let clean = "cargo-machete didn't find any unused dependencies in this directory. Good job!";
    if exit == Some(0) {
        return stdout.trim_end_matches(['\r', '\n']) == clean;
    }
    if exit != Some(1) {
        return false;
    }
    let Some(body) = stdout
        .strip_prefix("cargo-machete found the following unused dependencies in this directory:\n")
    else {
        return false;
    };
    let advisory = "\nIf you believe cargo-machete has detected an unused dependency incorrectly,\nyou can add the dependency to the list of dependencies to ignore in the\n`[package.metadata.cargo-machete]` section of the appropriate Cargo.toml.\nFor example:\n\n[package.metadata.cargo-machete]\nignored = [\"prost\"]\n\n";
    let Some(body) = body.strip_suffix(advisory) else {
        return false;
    };
    let mut package = false;
    let mut dependencies = 0_u64;
    for line in body.lines() {
        if let Some(dependency) = line.strip_prefix('\t') {
            if !package
                || dependency.is_empty()
                || !dependency
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return false;
            }
            dependencies += 1;
        } else if let Some((name, path)) = line.split_once(" -- ") {
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                || !path.ends_with("Cargo.toml:")
            {
                return false;
            }
            package = true;
        } else {
            return false;
        }
    }
    dependencies > 0 && cargo_machete(stdout).findings_count == Some(dependencies)
}

fn cargo_machete(text: &str) -> ParseOutcome {
    let count = text
        .lines()
        .filter(|line| {
            let indented = line.starts_with(' ') || line.starts_with('\t');
            let has_content = !line.trim().is_empty();
            let is_header = [
                "Analyzing",
                "If you",
                "cargo-machete",
                "found the following",
            ]
            .iter()
            .any(|needle| line.contains(needle));
            indented && has_content && !is_header
        })
        .count() as u64;
    ParseOutcome::ok(
        "legacy.cargo_unused_deps.cargo-machete",
        "low",
        zero_as_null(count),
    )
}

// ---------- cargo_unsafe (cargo-geiger 0.13.0 full SafetyReport) ----------
// Pinned upstream cargo-geiger-serde/report.rs: QuickSafetyReport is not a scan.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GeigerReport {
    packages: Vec<GeigerEntry>,
    packages_without_metrics: Vec<GeigerPackage>,
    used_but_not_scanned_files: Vec<String>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GeigerEntry {
    package: GeigerPackageInfo,
    unsafety: GeigerUnsafeInfo,
}
#[derive(serde::Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
struct GeigerPackage {
    name: String,
    version: String,
    source: GeigerSource,
}
#[derive(serde::Deserialize, PartialEq, Eq, Hash)]
enum GeigerSource {
    Git { url: String, rev: String },
    Registry { name: String, url: String },
    Path(String),
}
impl GeigerPackage {
    fn valid(&self) -> bool {
        !self.name.is_empty()
            && !self.version.is_empty()
            && match &self.source {
                GeigerSource::Git { url, rev } => !url.is_empty() && !rev.is_empty(),
                GeigerSource::Registry { name, url } => !name.is_empty() && !url.is_empty(),
                GeigerSource::Path(url) => !url.is_empty(),
            }
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GeigerPackageInfo {
    id: GeigerPackage,
    dependencies: Vec<GeigerPackage>,
    dev_dependencies: Vec<GeigerPackage>,
    build_dependencies: Vec<GeigerPackage>,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GeigerUnsafeInfo {
    used: GeigerCounters,
    unused: GeigerCounters,
    #[serde(rename = "forbids_unsafe")]
    _forbids_unsafe: bool,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GeigerCounters {
    functions: GeigerCount,
    exprs: GeigerCount,
    item_impls: GeigerCount,
    item_traits: GeigerCount,
    methods: GeigerCount,
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GeigerCount {
    safe: u64,
    unsafe_: u64,
}
impl GeigerCounters {
    fn totals(&self) -> Option<(u64, u64)> {
        let (mut safe, mut unsafe_) = (0_u64, 0_u64);
        for count in [
            &self.functions,
            &self.exprs,
            &self.item_impls,
            &self.item_traits,
            &self.methods,
        ] {
            safe = safe.checked_add(count.safe)?;
            unsafe_ = unsafe_.checked_add(count.unsafe_)?;
        }
        Some((safe, unsafe_))
    }
}
fn cargo_unsafe(value: &Value) -> ParseOutcome {
    const RULE: &str = "legacy.cargo_unsafe.cargo-geiger";
    let invalid = || ParseOutcome::malformed(RULE, "medium");
    let Ok(report) = serde_json::from_value::<GeigerReport>(value.clone()) else {
        return invalid();
    };
    if report.packages.is_empty()
        || !report.packages_without_metrics.is_empty()
        || !report.used_but_not_scanned_files.is_empty()
    {
        return invalid();
    }
    let mut ids = std::collections::HashSet::new();
    let (mut safe_total, mut unsafe_total, mut unused_safe, mut unused_unsafe) =
        (0_u64, 0_u64, 0_u64, 0_u64);
    for entry in report.packages {
        let package = entry.package;
        if !package.id.valid()
            || !package
                .dependencies
                .iter()
                .chain(&package.dev_dependencies)
                .chain(&package.build_dependencies)
                .all(GeigerPackage::valid)
            || !ids.insert(package.id)
        {
            return invalid();
        }
        let Some((safe, unsafe_)) = entry.unsafety.used.totals() else {
            return invalid();
        };
        let Some((other_safe, other_unsafe)) = entry.unsafety.unused.totals() else {
            return invalid();
        };
        let (Some(a), Some(b), Some(c), Some(d)) = (
            safe_total.checked_add(safe),
            unsafe_total.checked_add(unsafe_),
            unused_safe.checked_add(other_safe),
            unused_unsafe.checked_add(other_unsafe),
        ) else {
            return invalid();
        };
        (safe_total, unsafe_total, unused_safe, unused_unsafe) = (a, b, c, d);
    }
    ParseOutcome::ok(RULE, "medium", Some(unsafe_total))
}

// ---------- outdated (npm/pnpm outdated --json) ----------
// JS: total = entry count; majors_behind = entries whose latest major > current major.
fn outdated(_value: &Value) -> ParseOutcome {
    // Production uses node_outdated::execute. A standalone report, including
    // {}, cannot prove npm's silently skipped registry lookups were examined.
    ParseOutcome::malformed("legacy.outdated.npm", "low")
}

// ---------- cargo_outdated (cargo outdated --format json --root-deps-only) ----------
fn cargo_outdated(value: &Value) -> ParseOutcome {
    let invalid = || ParseOutcome::malformed("legacy.cargo_outdated.cargo-outdated", "low");
    let Some(object) = value.as_object() else {
        return invalid();
    };
    if object.len() != 2
        || !object
            .get("crate_name")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty())
    {
        return invalid();
    }
    let Some(deps) = object.get("dependencies").and_then(Value::as_array) else {
        return invalid();
    };
    let semver = regex::Regex::new(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$").expect("static semver pattern");
    let version = |text: &str| semver.is_match(text);
    let status = |text: &str| text == "---" || text == "Removed" || version(text);
    let mut total = 0;
    let mut majors = 0;
    let mut names = std::collections::BTreeSet::new();
    for dep in deps {
        let Some(row) = dep.as_object() else {
            return invalid();
        };
        if row.len() != 6
            || !["name", "project", "compat", "latest", "kind", "platform"]
                .iter()
                .all(|key| row.contains_key(*key))
        {
            return invalid();
        }
        let Some(name) = row
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        else {
            return invalid();
        };
        let Some(project) = row
            .get("project")
            .and_then(Value::as_str)
            .filter(|value| version(value))
        else {
            return invalid();
        };
        let Some(compat) = row
            .get("compat")
            .and_then(Value::as_str)
            .filter(|value| status(value))
        else {
            return invalid();
        };
        let Some(latest) = row
            .get("latest")
            .and_then(Value::as_str)
            .filter(|value| status(value))
        else {
            return invalid();
        };
        if !names.insert(name)
            || !row.get("kind").is_some_and(|value| {
                value.is_null()
                    || matches!(value.as_str(), Some("Normal" | "Development" | "Build"))
            })
            || !row.get("platform").is_some_and(|value| {
                value.is_null() || value.as_str().is_some_and(|text| !text.is_empty())
            })
        {
            return invalid();
        }
        // Each status column independently uses `---` for unchanged.
        // Removed is a change, while only a numeric latest version can be major-behind.
        if (compat != "---" && compat != project) || (latest != "---" && latest != project) {
            total += 1;
        }
        if version(latest) && major_behind(dep, "project", "latest") {
            majors += 1;
        }
    }
    ParseOutcome::ok("legacy.cargo_outdated.cargo-outdated", "low", Some(total))
        .with_meta(vec![("majorsBehind", Value::from(majors))])
}

fn major_behind(entry: &Value, current_key: &str, latest_key: &str) -> bool {
    let major = |value: &Value, key: &str| -> Option<u64> {
        value
            .get(key)
            .and_then(Value::as_str)?
            .split('.')
            .next()?
            .parse()
            .ok()
    };
    match (major(entry, current_key), major(entry, latest_key)) {
        (Some(c), Some(l)) if c != 0 && l != 0 => l > c,
        _ => false,
    }
}

// ---------- debt_markers (git grep -nIE "(ponytail:|\b(TODO|FIXME|HACK|XXX)\b)") ----------
// JS: findings_count = every matched line; meta breaks out ponytail / ponytail_no_trigger
// (ponytail lines that lack "upgrade"/"ceiling"/"if") / todo_fixme counts. No malformed rule
// (a clean repo — zero matches — is a real, valid `ran` result, not an error).
fn debt_markers(text: &str) -> ParseOutcome {
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    let ponytail: Vec<&&str> = lines.iter().filter(|l| l.contains("ponytail:")).collect();
    let ponytail_no_trigger = ponytail
        .iter()
        .filter(|l| {
            let lower = l.to_ascii_lowercase();
            !(lower.contains("upgrade")
                || lower.contains("ceiling")
                || contains_word_ci(&lower, "if"))
        })
        .count() as u64;
    let todos = lines
        .iter()
        .filter(|l| {
            ["TODO", "FIXME", "HACK", "XXX"]
                .iter()
                .any(|marker| contains_word(l, marker))
        })
        .count() as u64;
    ParseOutcome::ok(
        "legacy.debt_markers.git-grep",
        "low",
        Some(lines.len() as u64),
    )
    .with_meta(vec![
        ("ponytail", Value::from(ponytail.len() as u64)),
        ("ponytailNoTrigger", Value::from(ponytail_no_trigger)),
        ("todoFixme", Value::from(todos)),
    ])
}

/// Case-sensitive `\bword\b` match, for JS regexes with no `i` flag (the
/// debt-marker `TODO|FIXME|HACK|XXX` check — `git grep`/JS both match those
/// only in their literal uppercase form).
fn contains_word(haystack: &str, word: &str) -> bool {
    haystack
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|token| token == word)
}

/// Case-insensitive `\bword\b` match, for JS regexes carrying the `i` flag
/// (the ponytail trigger-word check, and the `build` warning-line scan).
fn contains_word_ci(haystack: &str, word: &str) -> bool {
    haystack
        .split(|c: char| !c.is_alphanumeric() && c != '_')
        .any(|token| token.eq_ignore_ascii_case(word))
}

// ---------- build (project build script / cargo build; combined stdout+stderr) ----------
// JS: warns = lines matching /\bwarn(ing)?\b/i across combined output. `status` is driven
// by exit code elsewhere (r.code === 0 ? 'ran' : 'error'), not by this count.
fn build(text: &str) -> ParseOutcome {
    let count = text
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            contains_word(&lower, "warn") || contains_word(&lower, "warning")
        })
        .count() as u64;
    ParseOutcome::ok("legacy.build.warnings", "medium", Some(count))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Synthetic parser controls only; these are never execution qualification.
    fn denied_clippy_report(code: &str) -> Vec<u8> {
        format!(
            "{}\n{}\n",
            serde_json::json!({
                "reason":"compiler-message", "message": {
                    "level":"error", "code":{"code":code},
                    "spans":[{"is_primary":true,"file_name":"src/lib.rs","line_start":2}]
                }
            }),
            serde_json::json!({"reason":"build-finished","success":false})
        )
        .into_bytes()
    }

    #[test]
    fn clippy_exit_101_requires_located_lint_and_terminal_event() {
        assert!(clippy_diagnostic_exit(
            &denied_clippy_report("clippy::eq_op"),
            b""
        ));
        assert!(clippy_diagnostic_exit(
            &denied_clippy_report("unused_imports"),
            b""
        ));
        assert!(clippy_diagnostic_exit(
            &denied_clippy_report("clippy::char_lit_as_u8"),
            b""
        ));
        assert!(!clippy_diagnostic_exit(
            &denied_clippy_report("clippy::8bit_lint"),
            b""
        ));
        assert!(!clippy_diagnostic_exit(&denied_clippy_report("E0425"), b""));
        assert!(!clippy_diagnostic_exit(b"", b""));
        assert!(!clippy_diagnostic_exit(
            b"{\"reason\":\"build-finished\",\"success\":false}\n",
            b""
        ));
        let report = denied_clippy_report("clippy::eq_op");
        let first = report.split(|b| *b == b'\n').next().unwrap();
        assert!(!clippy_diagnostic_exit(first, b""));
    }

    #[test]
    fn clippy_exit_101_rejects_crash_and_corrupt_reports() {
        let report = denied_clippy_report("clippy::eq_op");
        for stderr in [
            "thread panicked at fixture",
            "internal compiler error",
            "signal: 11",
            "process didn't exit successfully",
            "could not execute process",
        ] {
            assert!(!clippy_diagnostic_exit(&report, stderr.as_bytes()));
        }
        let mut trailing = report.clone();
        trailing.extend_from_slice(b"not json\n");
        assert!(!clippy_diagnostic_exit(&trailing, b""));
        let unlocated = String::from_utf8(report)
            .unwrap()
            .replace("\"is_primary\":true", "\"is_primary\":false");
        assert!(!clippy_diagnostic_exit(unlocated.as_bytes(), b""));
    }

    // Realistic captured-output fixtures live under
    // engine/crates/legion-audit/tests/fixtures/legacy_parse/, written by hand
    // from each tool's documented JSON/text output shape.
    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!("../../../tests/fixtures/legacy_parse/", $name))
        };
    }

    fn json(text: &str) -> Value {
        serde_json::from_str(text).expect("fixture is valid JSON")
    }

    #[test]
    fn knip_sums_files_and_issue_object() {
        let outcome = knip(&json(fixture!("knip.json")));
        // 2 files + 3 per-file issue entries (object form of `issues`).
        assert_eq!(outcome.findings_count, Some(5));
        assert!(!outcome.malformed);
    }

    #[test]
    fn knip_array_rows_with_only_empty_categories_are_not_findings() {
        let outcome = knip(&json(
            r#"{"files":[],"issues":[{"file":"app.js","dependencies":[],"exports":[],"types":[]},{"file":"b.js","dependencies":[],"exports":[{"name":"unused"}]}]}"#,
        ));
        assert_eq!(outcome.findings_count, Some(1));
        let clean = knip(&json(r#"{"files":[],"issues":[]}"#));
        assert_eq!(clean.findings_count, Some(0));
    }

    #[test]
    fn jscpd_missing_clones_and_non_array_duplicates_is_malformed() {
        let outcome = jscpd(&json(fixture!("jscpd_malformed.json")));
        assert!(outcome.malformed);
        assert_eq!(outcome.findings_count, None);
    }

    #[test]
    fn eslint_sums_error_and_warning_counts_across_files() {
        let outcome = lint_json(&json(fixture!("eslint.json"))).expect("eslint shape recognized");
        assert_eq!(outcome.rule, "legacy.lint.eslint");
        assert_eq!(outcome.findings_count, Some(3));
    }

    #[test]
    fn biome_counts_diagnostics_array() {
        let outcome =
            lint_json(&json(fixture!("biome-lint-output.json"))).expect("biome shape recognized");
        assert_eq!(outcome.rule, "legacy.lint.biome");
        assert_eq!(outcome.findings_count, Some(2));
    }

    #[test]
    fn clippy_counts_only_compiler_messages_with_spans_and_level() {
        let text = concat!(
            r#"{"reason":"compiler-message","message":{"level":"warning","spans":[{"file_name":"src/a.rs"}]}}"#,
            "\n",
            r#"{"reason":"compiler-message","message":{"level":"error","spans":[{"file_name":"src/b.rs"}]}}"#,
            "\n",
            r#"{"reason":"compiler-message","message":{"level":"warning","spans":[]}}"#,
            "\n",
            r#"{"reason":"build-finished"}"#,
            "\n",
            "not json at all",
        );
        let outcome = clippy(text);
        assert_eq!(outcome.findings_count, Some(2));
    }

    #[test]
    fn tsc_counts_error_ts_lines_only() {
        let outcome = tsc(fixture!("tsc.txt"));
        assert_eq!(outcome.findings_count, Some(2));
    }

    #[test]
    fn semgrep_counts_results_array() {
        let outcome = semgrep(&json(fixture!("semgrep.json")));
        assert_eq!(outcome.findings_count, Some(1));
    }

    #[test]
    fn actionlint_counts_top_level_array() {
        let value =
            json(r#"[{"message":"shellcheck reported issue"},{"message":"unpinned action"}]"#);
        let outcome = actionlint(&value);
        assert_eq!(outcome.findings_count, Some(2));
    }

    #[test]
    fn hadolint_counts_top_level_array() {
        let value = json(r#"[{"code":"DL3008","level":"warning"}]"#);
        let outcome = hadolint(&value);
        assert_eq!(outcome.findings_count, Some(1));
    }

    #[test]
    fn swiftlint_counts_top_level_array() {
        let value = json(r#"[{"rule_id":"line_length"},{"rule_id":"force_cast"}]"#);
        let outcome = swiftlint(&value);
        assert_eq!(outcome.findings_count, Some(2));
    }

    #[test]
    fn js_licenses_flags_only_copyleft_packages() {
        let value = json(
            r#"{"left-pad@1.3.0":{"licenses":"MIT"},"gpl-thing@2.0.0":{"licenses":"GPL-3.0"},"no-licenses@1.0.0":{}}"#,
        );
        let outcome = js_licenses(&value);
        assert_eq!(outcome.findings_count, Some(1));
        assert!(outcome
            .meta
            .iter()
            .any(|(key, value)| *key == "totalDeps" && *value == Value::from(2_u64)));
    }

    #[test]
    fn js_licenses_empty_object_is_unproven_not_clean() {
        let outcome = js_licenses(&json("{}"));
        assert!(outcome.malformed);
        assert_eq!(outcome.findings_count, None);
    }

    #[test]
    fn deps_cve_reads_metadata_total() {
        let outcome = deps_cve(&json(fixture!("deps_cve_npm_audit.json")));
        assert_eq!(outcome.findings_count, Some(4));
        assert!(!outcome.malformed);
    }

    #[test]
    fn deps_cve_null_count_is_malformed() {
        let outcome = deps_cve(&json(r#"{"metadata":{}}"#));
        assert!(outcome.malformed);
        assert_eq!(outcome.findings_count, None);
    }

    #[test]
    fn py_deps_cve_sums_per_dependency_vuln_arrays() {
        let value = json(
            r#"{"dependencies":[{"name":"requests","version":"2.0","vulns":[{"id":"PYSEC-1","fix_versions":[]}]},{"name":"flask","version":"1.0","vulns":[]}],"fixes":[]}"#,
        );
        let outcome = py_deps_cve(&value);
        assert_eq!(outcome.findings_count, Some(1));
    }

    #[test]
    fn cargo_audit_reads_vulnerabilities_count() {
        let outcome = cargo_audit(&json(fixture!("cargo_audit.json")));
        assert_eq!(outcome.findings_count, Some(3));
    }

    #[test]
    fn cargo_deny_counts_error_and_warning_diagnostics() {
        let outcome = cargo_deny(fixture!("cargo_deny.jsonl"));
        assert_eq!(outcome.findings_count, Some(2));
    }

    #[test]
    fn cargo_deny_requires_terminal_complete_reconciled_summary() {
        assert!(cargo_deny("").malformed);
        let mut summary = serde_json::json!({"type":"summary", "fields":{}});
        for check in ["advisories", "bans", "licenses", "sources"] {
            summary["fields"][check] =
                serde_json::json!({"errors":0,"warnings":0,"notes":0,"helps":0});
        }
        let clean = summary.to_string();
        assert_eq!(cargo_deny(&clean).findings_count, Some(0));
        assert_eq!(cargo_deny_completion(&clean), Some((0, 0)));
        assert!(cargo_deny(&format!("{clean}\n{clean}")).malformed);
        summary["fields"]["sources"]["errors"] = serde_json::json!(1);
        assert!(cargo_deny(&summary.to_string()).malformed);
        let diagnostic =
            r#"{"type":"diagnostic","fields":{"severity":"error","message":"source denied"}}"#;
        assert_eq!(
            cargo_deny_completion(&format!("{diagnostic}\n{summary}")),
            Some((1, 8))
        );
        summary["fields"]
            .as_object_mut()
            .unwrap()
            .remove("licenses");
        assert!(cargo_deny(&format!("{diagnostic}\n{summary}")).malformed);
        assert!(
            cargo_deny(r#"{"type":"log","fields":{"level":"ERROR","message":"database missing"}}"#)
                .malformed
        );
        for bits in 0..16 {
            let mut rows = Vec::new();
            let mut fields = serde_json::Map::new();
            for (bit, name) in ["advisories", "bans", "licenses", "sources"]
                .into_iter()
                .enumerate()
            {
                let failed = bits & (1 << bit) != 0;
                fields.insert(name.into(), serde_json::json!({"errors":u32::from(failed),"warnings":0,"notes":0,"helps":0}));
                if failed {
                    rows.push(serde_json::json!({"type":"diagnostic","fields":{"severity":"error","message":name}}).to_string());
                }
            }
            rows.push(serde_json::json!({"type":"summary","fields":fields}).to_string());
            assert_eq!(
                cargo_deny_completion(&rows.join("\n")),
                Some(((bits as u32).count_ones() as u64, bits))
            );
        }
    }

    #[test]
    fn cargo_machete_completion_rejects_swallowed_manifest_errors_and_unknown_output() {
        let clean =
            b"cargo-machete didn't find any unused dependencies in this directory. Good job!\n";
        let progress = b"Analyzing dependencies of crates in this directory...\nDone!\n";
        assert!(cargo_machete_report_complete(clean, progress, Some(0)));
        assert!(!cargo_machete_report_complete(clean, b"Analyzing dependencies of crates in this directory...\nerror when handling ./Cargo.toml: invalid manifest\nDone!\n", Some(0)));
        assert!(!cargo_machete_report_complete(clean, progress, Some(2)));
        assert!(!cargo_machete_report_complete(b"", progress, Some(0)));
        assert!(!cargo_machete_report_complete(
            b"arbitrary text\n",
            progress,
            Some(0)
        ));
        let positive = "cargo-machete found the following unused dependencies in this directory:\nmachete-probe -- ./Cargo.toml:\n\tmachete-helper\n\nIf you believe cargo-machete has detected an unused dependency incorrectly,\nyou can add the dependency to the list of dependencies to ignore in the\n`[package.metadata.cargo-machete]` section of the appropriate Cargo.toml.\nFor example:\n\n[package.metadata.cargo-machete]\nignored = [\"prost\"]\n\n";
        assert!(cargo_machete_report_complete(
            positive.as_bytes(),
            progress,
            Some(1)
        ));
        assert!(!cargo_machete_report_complete(
            positive.as_bytes(),
            progress,
            Some(0)
        ));
        assert!(!cargo_machete_report_complete(
            positive
                .replace("\tmachete-helper", "\tunrelated diagnostic text")
                .as_bytes(),
            progress,
            Some(1)
        ));
    }

    #[test]
    fn cargo_machete_counts_indented_crate_lines_not_headers() {
        let outcome = cargo_machete(fixture!("cargo_machete.txt"));
        assert_eq!(outcome.findings_count, Some(3));
    }

    #[test]
    fn cargo_machete_zero_unused_collapses_to_null() {
        let outcome = cargo_machete("Analyzing dependencies of 1 crate...\n");
        assert_eq!(outcome.findings_count, None);
    }

    fn geiger_report() -> Value {
        let counters = serde_json::json!({"functions":{"safe":1,"unsafe_":0},"exprs":{"safe":0,"unsafe_":0},
            "item_impls":{"safe":0,"unsafe_":0},"item_traits":{"safe":0,"unsafe_":0},"methods":{"safe":0,"unsafe_":0}});
        serde_json::json!({"packages":[{"package":{"id":{"name":"fixture","version":"0.0.0","source":{"Path":"file:///fixture"}},
            "dependencies":[],"dev_dependencies":[],"build_dependencies":[]},
            "unsafety":{"used":counters,"unused":counters,"forbids_unsafe":false}}],
            "packages_without_metrics":[],"used_but_not_scanned_files":[]})
    }
    #[test]
    fn cargo_unsafe_requires_full_typed_report_and_checked_counters() {
        let clean = geiger_report();
        assert_eq!(cargo_unsafe(&clean).findings_count, Some(0));
        let mut positive = clean.clone();
        positive["packages"][0]["unsafety"]["used"]["functions"]["unsafe_"] = Value::from(2);
        positive["packages"][0]["unsafety"]["used"]["methods"]["unsafe_"] = Value::from(1);
        assert_eq!(cargo_unsafe(&positive).findings_count, Some(3));
        let mut cases = vec![
            serde_json::json!({"packages":[]}),
            serde_json::json!({"packages":[{"forbids_unsafe":true}],"packages_without_metrics":[]}),
        ];
        for key in ["packages_without_metrics", "used_but_not_scanned_files"] {
            let mut value = clean.clone();
            value.as_object_mut().unwrap().remove(key);
            cases.push(value);
        }
        let mut value = clean.clone();
        value["packages"] = serde_json::json!([]);
        cases.push(value);
        let mut value = clean.clone();
        value["packages_without_metrics"] =
            serde_json::json!([clean["packages"][0]["package"]["id"].clone()]);
        cases.push(value);
        let mut value = clean.clone();
        value["used_but_not_scanned_files"] = serde_json::json!(["missing.rs"]);
        cases.push(value);
        let mut value = clean.clone();
        value["packages"]
            .as_array_mut()
            .unwrap()
            .push(clean["packages"][0].clone());
        cases.push(value);
        for block in ["used", "unused"] {
            for category in ["functions", "exprs", "item_impls", "item_traits", "methods"] {
                let mut value = clean.clone();
                value["packages"][0]["unsafety"][block]
                    .as_object_mut()
                    .unwrap()
                    .remove(category);
                cases.push(value);
                for field in ["safe", "unsafe_"] {
                    for bad in [
                        serde_json::json!(-1),
                        serde_json::json!(1.5),
                        serde_json::json!("0"),
                        Value::Null,
                        Value::Bool(false),
                    ] {
                        let mut value = clean.clone();
                        value["packages"][0]["unsafety"][block][category][field] = bad;
                        cases.push(value);
                    }
                    let mut value = clean.clone();
                    value["packages"][0]["unsafety"][block]["functions"][field] =
                        Value::from(u64::MAX);
                    value["packages"][0]["unsafety"][block]["methods"][field] = Value::from(1);
                    cases.push(value);
                }
            }
        }
        for value in cases {
            let result = cargo_unsafe(&value);
            assert!(result.malformed, "{value}");
            assert_eq!(result.findings_count, None);
        }
    }

    #[test]
    fn outdated_alone_never_claims_completion() {
        assert!(outdated(&json(fixture!("outdated_npm.json"))).malformed);
        assert!(outdated(&json("{}")).malformed);
        assert!(outdated(&json(r#"{"error":{"code":"E404"}}"#)).malformed);
    }

    #[test]
    fn cargo_outdated_counts_both_status_columns_and_removed() {
        let outcome = cargo_outdated(&json(
            r#"{"crate_name":"probe","dependencies":[{"name":"compat","project":"1.0.0","compat":"1.0.1","latest":"---","kind":"Normal","platform":null},{"name":"latest","project":"1.0.0","compat":"---","latest":"2.0.0","kind":"Normal","platform":null},{"name":"removed","project":"1.0.0","compat":"Removed","latest":"Removed","kind":"Normal","platform":null},{"name":"unchanged","project":"1.0.0","compat":"---","latest":"---","kind":"Normal","platform":null}]}"#,
        ));
        assert!(!outcome.malformed);
        assert_eq!(outcome.findings_count, Some(3));
        assert!(outcome
            .meta
            .iter()
            .any(|(key, value)| *key == "majorsBehind" && *value == Value::from(1_u64)));
    }

    #[test]
    fn cargo_outdated_rejects_missing_and_malformed_rows() {
        for value in [
            r#"{"dependencies":[]}"#,
            r#"{"crate_name":"probe","dependencies":[{}]}"#,
            r#"{"crate_name":"probe","dependencies":[{"name":"bad","project":"1.0.0","compat":"---","latest":null,"kind":"Normal","platform":null}]}"#,
        ] {
            assert!(cargo_outdated(&json(value)).malformed);
        }
        assert_eq!(
            cargo_outdated(&json(r#"{"crate_name":"probe","dependencies":[]}"#)).findings_count,
            Some(0)
        );
    }

    #[test]
    fn cargo_outdated_rejects_invalid_versions_and_untyped_optional_fields() {
        let valid = json(
            r#"{"crate_name":"probe","dependencies":[{"name":"dep","project":"1.0.0","compat":"---","latest":"2.0.0","kind":"Normal","platform":null}]}"#,
        );
        for (field, value) in [
            ("project", Value::from("01.0.0")),
            ("compat", Value::from("not-a-version")),
            ("latest", Value::from("2")),
            ("kind", Value::from(42)),
            ("platform", Value::from(false)),
        ] {
            let mut report = valid.clone();
            report["dependencies"][0][field] = value;
            assert!(cargo_outdated(&report).malformed, "{field}");
        }
        let mut duplicate = valid.clone();
        duplicate["dependencies"]
            .as_array_mut()
            .unwrap()
            .push(valid["dependencies"][0].clone());
        assert!(cargo_outdated(&duplicate).malformed);
    }

    #[test]
    fn debt_markers_counts_lines_and_splits_ponytail_from_todo() {
        let outcome = debt_markers(fixture!("debt_markers.txt"));
        assert_eq!(outcome.findings_count, Some(4));
        assert!(outcome
            .meta
            .iter()
            .any(|(key, value)| *key == "ponytail" && *value == Value::from(2_u64)));
        // one ponytail line contains "upgrade" (has a trigger word), the other doesn't.
        assert!(outcome
            .meta
            .iter()
            .any(|(key, value)| *key == "ponytailNoTrigger" && *value == Value::from(1_u64)));
        assert!(outcome
            .meta
            .iter()
            .any(|(key, value)| *key == "todoFixme" && *value == Value::from(2_u64)));
    }

    #[test]
    fn build_counts_warning_lines_case_insensitively() {
        let text = "Compiling foo v0.1.0\nwarning: unused variable `x`\nerror[E0308]: mismatched types\nWARNING: deprecated API\nCompiling done";
        let outcome = build(text);
        assert_eq!(outcome.findings_count, Some(2));
    }

    #[test]
    fn unexpected_shapes_are_malformed_not_clean() {
        let wrong = json(r#"{"unrelated":true}"#);
        let scalar = json("42");
        assert!(knip(&wrong).malformed);
        assert!(jscpd(&wrong).malformed);
        assert!(lint_json(&scalar).expect("lint outcome").malformed);
        assert!(
            lint_json(&json(r#"["a","b"]"#))
                .expect("lint outcome")
                .malformed
        );
        assert!(types_json(&wrong).expect("types outcome").malformed);
        assert!(semgrep(&wrong).malformed);
        assert!(actionlint(&wrong).malformed);
        assert!(hadolint(&wrong).malformed);
        assert!(swiftlint(&wrong).malformed);
        assert!(js_licenses(&json("[]")).malformed);
        assert!(deps_cve(&wrong).malformed);
        assert!(py_deps_cve(&wrong).malformed);
        assert!(cargo_audit(&wrong).malformed);
        assert!(cargo_unsafe(&wrong).malformed);
        assert!(outdated(&json("[]")).malformed);
        assert!(cargo_outdated(&wrong).malformed);
        assert!(clippy("").malformed);
        assert!(clippy("plain text, not cargo json").malformed);
    }

    #[test]
    fn legitimately_empty_expected_shapes_stay_clean() {
        assert_eq!(semgrep(&json(r#"{"version":"1.141.0","results":[],"errors":[],"paths":{"scanned":[],"skipped":[]},"skipped_rules":[]}"#)).findings_count, Some(0));
        assert_eq!(actionlint(&Value::Null).findings_count, Some(0));
        assert!(!actionlint(&Value::Null).malformed);
        assert_eq!(hadolint(&json("[]")).findings_count, Some(0));
        assert_eq!(swiftlint(&json("[]")).findings_count, Some(0));
        assert!(outdated(&json("{}")).malformed);
        assert!(!clippy(r#"{"reason":"build-finished","success":true}"#).malformed);
    }

    #[test]
    fn dispatch_json_routes_known_checks_and_none_for_unknown() {
        assert!(dispatch_json("dead_code", &json(fixture!("knip.json"))).is_some());
        assert!(dispatch_json("apple_platform", &Value::Null).is_none());
    }

    #[test]
    fn dispatch_text_routes_known_checks_and_none_for_unknown() {
        assert!(dispatch_text("types", "src/a.ts(1,1): error TS1005").is_some());
        assert!(dispatch_text("apple_platform", "").is_none());
    }
}
