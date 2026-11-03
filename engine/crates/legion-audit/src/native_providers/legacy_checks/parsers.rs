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
