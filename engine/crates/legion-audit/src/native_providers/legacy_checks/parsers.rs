//! Per-tool output parsing for the frozen legacy-check surface.
//!
//! Ports the `run:` closures of `tools/audit/collect-facts.mjs` (and its
//! oldest ancestor, `52a90cf0^:tools/skills/audit/collect-facts.mjs`) into
//! typed Rust. Each function here mirrors ONE JS check's parse logic —
//! finding/summary counts, its severity mapping, and (where the JS source
//! explicitly treats unparseable output as a failed scan rather than a clean
//! one) the same "malformed output => not proven" rule. Deliberately NOT
//! ported: JS's own inconsistencies (e.g. `count || null` turning a real
//! zero into a null finding count for `cargo_deny`/`cargo_unused_deps`) are
//! preserved rather than "fixed", because parity with the frozen legacy
//! behaviour is the point of this module.
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
pub(super) struct ParseOutcome {
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
/// count. Two JS checks (`cargo_deny`, `cargo_unused_deps`) do this;
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
pub(super) fn dispatch_json(check: &str, value: &Value) -> Option<ParseOutcome> {
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
pub(super) fn dispatch_text(check: &str, text: &str) -> Option<ParseOutcome> {
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
            .map(|a| a.len() as u64)
            .or_else(|| issues.as_object().map(|o| o.len() as u64))
    });
    let count = match (files_len, issues_len) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0) + b.unwrap_or(0)),
    };
    ParseOutcome::ok("legacy.dead_code.knip", "low", count)
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
        return Some(ParseOutcome::ok(
            "legacy.lint.ruff",
            "medium",
            Some(files.len() as u64),
        ));
    }
    None
}

// ---------- clippy (cargo clippy --message-format=json, JSONL on stdout) ----------
// JS counts only `compiler-message` reasons with a non-empty `message.spans` and a
// warning/error level; malformed/non-JSON lines are silently skipped (count defaults 0,
// never null — no malformed rule).
fn clippy(text: &str) -> ParseOutcome {
    let mut count = 0_u64;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
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
    value.get("summary").map(|summary| {
        let count = summary.get("errorCount").and_then(Value::as_u64);
        ParseOutcome::ok("legacy.types.basedpyright", "high", count)
    })
}

// ---------- sast (semgrep --json) ----------
// JS: count = (JSON.parse(r.stdout).results || []).length. No malformed rule.
fn semgrep(value: &Value) -> ParseOutcome {
    let count = value
        .get("results")
        .and_then(Value::as_array)
        .map(|a| a.len() as u64);
    ParseOutcome::ok("legacy.sast.semgrep", "high", count)
}

// ---------- ci_lint (actionlint -format "{{json .}}", a JSON array) ----------
fn actionlint(value: &Value) -> ParseOutcome {
    let count = value.as_array().map(|a| a.len() as u64);
    ParseOutcome::ok("legacy.ci_lint.actionlint", "medium", count)
}

// ---------- docker (hadolint --format json Dockerfile, a JSON array) ----------
fn hadolint(value: &Value) -> ParseOutcome {
    let count = value.as_array().map(|a| a.len() as u64);
    ParseOutcome::ok("legacy.docker.hadolint", "medium", count)
}

// ---------- swift_lint (swiftlint lint --reporter json, a JSON array) ----------
fn swiftlint(value: &Value) -> ParseOutcome {
    let count = value.as_array().map(|a| a.len() as u64);
    ParseOutcome::ok("legacy.swift_lint.swiftlint", "medium", count)
}

// ---------- js_licenses (license-checker --json --production) ----------
// JS: flagged = packages whose `.licenses` matches the copyleft regex; total = all
// license-bearing packages. findings_count is the flagged (copyleft) count, not total.
fn js_licenses(value: &Value) -> ParseOutcome {
    const COPYLEFT: &[&str] = &[
        "GPL", "AGPL", "LGPL", "SSPL", "CC-BY-SA", "EUPL", "OSL", "CPAL",
    ];
    let Some(object) = value.as_object() else {
        return ParseOutcome::ok("legacy.js_licenses.license-checker", "high", None);
    };
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
    ParseOutcome::ok(
        "legacy.js_licenses.license-checker",
        "high",
        Some(flagged),
    )
    .with_meta(vec![
        ("totalDeps", Value::from(total)),
        ("copyleft", Value::from(flagged)),
    ])
}

// ---------- deps_cve (npm/pnpm audit --json) ----------
// JS: count = metadata.vulnerabilities.total ?? sum(Object.values(vulnerabilities)).
// Explicit rule: count === null -> status 'error' ("scan not proven"), same class as secrets.
fn deps_cve(value: &Value) -> ParseOutcome {
    let vulnerabilities = value.get("metadata").and_then(|m| m.get("vulnerabilities"));
    let count = vulnerabilities.and_then(|v| v.get("total")).and_then(Value::as_u64).or_else(|| {
        vulnerabilities.and_then(Value::as_object).map(|object| {
            object
                .values()
                .filter_map(Value::as_u64)
                .sum::<u64>()
        })
    });
    match count {
        Some(count) => ParseOutcome::ok("legacy.deps_cve.audit", "critical", Some(count)),
        None => ParseOutcome::malformed("legacy.deps_cve.audit", "critical"),
    }
}

// ---------- py_deps_cve (pip-audit -f json) ----------
// JS: deps = Array.isArray(j) ? j : (j.dependencies || []); count = sum of each dep's
// vulns/vulnerabilities array length. No malformed rule (parse failure leaves count null).
fn py_deps_cve(value: &Value) -> ParseOutcome {
    let deps = value
        .as_array()
        .cloned()
        .or_else(|| {
            value
                .get("dependencies")
                .and_then(Value::as_array)
                .cloned()
        });
    let count = deps.map(|deps| {
        deps.iter()
            .map(|dep| {
                dep.get("vulns")
                    .or_else(|| dep.get("vulnerabilities"))
                    .and_then(Value::as_array)
                    .map(|a| a.len() as u64)
                    .unwrap_or(0)
            })
            .sum::<u64>()
    });
    ParseOutcome::ok("legacy.py_deps_cve.pip-audit", "critical", count)
}

// ---------- cargo_audit (cargo audit --json) ----------
// JS: count = JSON.parse(r.stdout)?.vulnerabilities?.count ?? null. No malformed rule.
fn cargo_audit(value: &Value) -> ParseOutcome {
    let count = value
        .get("vulnerabilities")
        .and_then(|v| v.get("count"))
        .and_then(Value::as_u64);
    ParseOutcome::ok("legacy.cargo_audit.cargo-audit", "critical", count)
}

// ---------- cargo_deny (cargo deny --format json check; JSONL on stderr in JS) ----------
// JS loops every line of stderr+stdout, JSON-parses each, counts `type === 'diagnostic'`
// entries whose severity/level matches /error|warning/i. `findings_count: count || null`
// (a real zero collapses to null — preserved, see module doc comment).
fn cargo_deny(text: &str) -> ParseOutcome {
    let mut count = 0_u64;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if value.get("type").and_then(Value::as_str) != Some("diagnostic") {
            continue;
        }
        let level = value
            .get("fields")
            .and_then(|f| f.get("severity").or_else(|| f.get("level")))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase();
        if level.contains("error") || level.contains("warning") {
            count += 1;
        }
    }
    ParseOutcome::ok("legacy.cargo_deny.cargo-deny", "high", zero_as_null(count))
}

// ---------- cargo_unused_deps (cargo machete --with-metadata, plain text) ----------
// JS: no JSON; one unused crate per indented, non-header line.
// `count = (...).length || null` (zero -> null, preserved).
fn cargo_machete(text: &str) -> ParseOutcome {
    let count = text
        .lines()
        .filter(|line| {
            let indented = line.starts_with(' ') || line.starts_with('\t');
            let has_content = !line.trim().is_empty();
            let is_header = ["Analyzing", "If you", "cargo-machete", "found the following"]
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

// ---------- cargo_unsafe (cargo geiger --output-format Json) ----------
// JS: sum of every package's used unsafety categories' `unsafe_` counters. No malformed rule.
fn cargo_unsafe(value: &Value) -> ParseOutcome {
    let packages = value.get("packages").and_then(Value::as_array);
    let count = packages.map(|packages| {
        packages
            .iter()
            .filter_map(|p| p.get("unsafety")?.get("used"))
            .filter_map(Value::as_object)
            .flat_map(|used| used.values())
            .filter_map(|category| category.get("unsafe_"))
            .filter_map(Value::as_u64)
            .sum::<u64>()
    });
    ParseOutcome::ok("legacy.cargo_unsafe.cargo-geiger", "medium", count)
}

// ---------- outdated (npm/pnpm outdated --json) ----------
// JS: total = entry count; majors_behind = entries whose latest major > current major.
fn outdated(value: &Value) -> ParseOutcome {
    let Some(object) = value.as_object() else {
        return ParseOutcome::ok("legacy.outdated.pkg-mgr", "low", None);
    };
    let total = object.len() as u64;
    let majors = object
        .values()
        .filter(|entry| major_behind(entry, "current", "latest"))
        .count() as u64;
    ParseOutcome::ok("legacy.outdated.pkg-mgr", "low", Some(total)).with_meta(vec![(
        "majorsBehind",
        Value::from(majors),
    )])
}

// ---------- cargo_outdated (cargo outdated --format json --root-deps-only) ----------
fn cargo_outdated(value: &Value) -> ParseOutcome {
    let Some(deps) = value.get("dependencies").and_then(Value::as_array) else {
        return ParseOutcome::ok("legacy.cargo_outdated.cargo-outdated", "low", None);
    };
    let relevant: Vec<&Value> = deps
        .iter()
        .filter(|dep| {
            let latest = dep.get("latest").and_then(Value::as_str);
            match latest {
                Some(latest) if latest != "---" => {
                    Some(latest) != dep.get("project").and_then(Value::as_str)
                }
                _ => false,
            }
        })
        .collect();
    let majors = relevant
        .iter()
        .filter(|dep| major_behind(dep, "project", "latest"))
        .count() as u64;
    ParseOutcome::ok(
        "legacy.cargo_outdated.cargo-outdated",
        "low",
        Some(relevant.len() as u64),
    )
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
            !(lower.contains("upgrade") || lower.contains("ceiling") || contains_word_ci(&lower, "if"))
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

    // Realistic captured-output fixtures live under
    // engine/crates/legion-audit/tests/fixtures/legacy_parse/, written by hand
    // from each tool's documented JSON/text output shape.
    macro_rules! fixture {
        ($name:literal) => {
            include_str!(concat!(
                "../../../tests/fixtures/legacy_parse/",
                $name
            ))
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
        let outcome = lint_json(&json(fixture!("biome-lint-output.json"))).expect("biome shape recognized");
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
        let value = json(r#"[{"message":"shellcheck reported issue"},{"message":"unpinned action"}]"#);
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
            r#"{"dependencies":[{"name":"requests","vulns":[{"id":"PYSEC-1"}]},{"name":"flask","vulnerabilities":[]}]}"#,
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
    fn cargo_deny_zero_diagnostics_collapses_to_null() {
        let outcome = cargo_deny("");
        assert_eq!(outcome.findings_count, None);
        assert!(!outcome.malformed);
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

    #[test]
    fn cargo_unsafe_sums_used_unsafe_counters() {
        let value = json(
            r#"{"packages":[{"unsafety":{"used":{"functions":{"unsafe_":2,"safe":1},"exprs":{"unsafe_":1}}}}]}"#,
        );
        let outcome = cargo_unsafe(&value);
        assert_eq!(outcome.findings_count, Some(3));
    }

    #[test]
    fn outdated_counts_total_and_major_behind() {
        let outcome = outdated(&json(fixture!("outdated_npm.json")));
        assert_eq!(outcome.findings_count, Some(2));
        assert!(outcome
            .meta
            .iter()
            .any(|(key, value)| *key == "majorsBehind" && *value == Value::from(1_u64)));
    }

    #[test]
    fn cargo_outdated_filters_unchanged_and_placeholder_entries() {
        let value = json(
            r#"{"dependencies":[{"name":"serde","project":"1.0.150","latest":"1.0.200"},{"name":"tokio","project":"1.30.0","latest":"1.30.0"},{"name":"local-crate","project":"0.1.0","latest":"---"}]}"#,
        );
        let outcome = cargo_outdated(&value);
        assert_eq!(outcome.findings_count, Some(1));
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
