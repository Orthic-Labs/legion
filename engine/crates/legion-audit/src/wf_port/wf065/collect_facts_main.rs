//! Port of `tools/audit/collect-facts.mjs`'s `doctor()` and `main()`'s
//! `facts.json` assembly.
//!
//! The full check list is `super::collect_facts_checks_a::checks_a()` (first
//! half) concatenated with `super::collect_facts_checks_b`'s second half,
//! executed through `super::collect_facts_exec::{pool, exec_one}` (bounded
//! concurrency + per-check redacted-log persistence — that module's own
//! doc comment owns the exact `pool`/`exec_one` contract). This module
//! owns what is downstream of execution and is pure/testable independent of
//! that wiring:
//!
//! - [`doctor_rows`] / [`DoctorRow`] — `doctor()`'s per-check
//!   `ready`/`not-configured`/`missing-tool`/`missing-dep` classification.
//!   Takes a `which`/`has_dep` closure so it needs no real subprocess or
//!   filesystem to test.
//! - [`assemble_facts`] — `main()`'s post-execution assembly: `verdict`/
//!   `execution_status` per result, `incomplete` (D2: required+applicable
//!   but not `ran`), `secrets_unscanned`, `manifest_drift` (declared vs.
//!   runtime check-name set), and the final `facts.json` JSON shape
//!   (`kind`, `stack`, `concurrency`, `scope`, `decomposition`, `checks`,
//!   `detectionDisagreement`). Takes already-executed per-check envelope
//!   records (the `execOne` output shape) rather than running anything
//!   itself, so it is exercised here with hand-built fixtures instead of a
//!   real check run.
//!
//! `pruneOldRuns` and `detect()` are already ported in [`super::collect_facts`].

use serde_json::{json, Value};

use super::collect_facts::DetectedStack;

// ---------------------------------------------------------------------
// doctor()
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct DoctorRow {
    pub check: String,
    pub tool: Option<String>,
    pub required: bool,
    pub ready: &'static str,
}

/// One check's doctor-readiness inputs: its name plus whether it was
/// force-skipped (`--skip`), mirroring the `_forceSkip` branch that
/// short-circuits every other rule.
pub struct DoctorInput<'a> {
    pub check: &'a str,
    pub tool: Option<&'a str>,
    pub required: bool,
    pub force_skip: bool,
}

/// `doctor(d, checks)`'s per-row `ready` classification. `which`/`has_dep`
/// are injected so this needs no real PATH lookup or `package.json` parse
/// to test — same "behind a trait" boundary as [`super::collect_facts_checks_b::CommandRunner`].
pub fn doctor_rows(
    d: &DetectedStack,
    checks: &[DoctorInput],
    which: impl Fn(&str) -> bool,
    has_dep: impl Fn(&str) -> bool,
    any_tracked_swift: bool,
) -> Vec<DoctorRow> {
    checks
        .iter()
        .map(|c| {
            let ready: &'static str = if c.force_skip {
                "skipped"
            } else {
                match c.check {
                    "secrets" => if which("gitleaks") { "ready" } else { "missing-tool" },
                    "sast" => if which("semgrep") { "ready" } else { "missing-tool" },
                    "ci_lint" => if which("actionlint") { "ready" } else { "missing-tool" },
                    "docker" => if which("hadolint") { "ready" } else { "missing-tool" },
                    "cargo_audit" => if !d.rust { "not-configured" } else if which("cargo-audit") { "ready" } else { "missing-tool" },
                    "cargo_deny" => if !d.rust { "not-configured" } else if which("cargo-deny") { "ready" } else { "missing-tool" },
                    "cargo_unused_deps" => if !d.rust { "not-configured" } else if which("cargo-machete") { "ready" } else { "missing-tool" },
                    "cargo_unsafe" => if !d.rust { "not-configured" } else if which("cargo-geiger") { "ready" } else { "missing-tool" },
                    "py_deps_cve" => if !d.py { "not-configured" } else if which("pip-audit") { "ready" } else { "missing-tool" },
                    "tauri_capabilities" => if d.tauri { "ready" } else { "not-configured" },
                    "apple_platform" => if any_tracked_swift { "ready" } else { "not-configured" },
                    "react_hooks" => if d.node && has_dep("react") { "ready" } else { "not-configured" },
                    "swift_lint" => if !(d.swift || any_tracked_swift) { "not-configured" } else if which("swiftlint") { "ready" } else { "missing-tool" },
                    "js_licenses" => if d.node { if has_dep("license-checker") { "ready" } else { "missing-dep" } } else { "not-configured" },
                    "cargo_outdated" => if !d.rust { "not-configured" } else if which("cargo-outdated") { "ready" } else { "missing-tool" },
                    "dead_code" => if has_dep("knip") { "ready" } else { "missing-dep" },
                    "duplication" => if has_dep("jscpd") { "ready" } else { "missing-dep" },
                    "types" => if d.ts && has_dep("typescript") { "ready" } else if d.py { if which("basedpyright") || which("mypy") { "ready" } else { "missing-tool" } } else { "not-configured" },
                    "lint" => if d.biome || d.eslint || d.py || d.rust { "ready" } else { "not-configured" },
                    "build" => if d.build_script || d.rust { "ready" } else { "not-configured" },
                    _ => "configured",
                }
            };
            DoctorRow { check: c.check.to_string(), tool: c.tool.map(str::to_string), required: c.required, ready }
        })
        .collect()
}

// ---------------------------------------------------------------------
// main()'s post-execution facts.json assembly
// ---------------------------------------------------------------------

/// One check's `execOne`-shaped result record, as consumed by
/// `assemble_facts`. Mirrors the JS object literal `execOne` returns
/// (minus `_rawLog`, which is written to disk and deleted before this
/// point in the JS too).
#[derive(Debug, Clone)]
pub struct ExecutedCheck {
    pub check: String,
    pub tool: Option<String>,
    pub required: bool,
    pub tier: String,
    pub status: String, // "ran" | "error" | "skipped" | "unproven"
    pub skip_reason: Option<String>,
    pub exit_code: Option<i64>,
    pub findings_count: Option<i64>,
    pub meta: Option<Value>,
}

impl ExecutedCheck {
    /// `results[i].execution_status`/`verdict` per the JS post-loop:
    /// `verdict` is `'fail'` when `status === 'ran'` and either
    /// `exit_code > 0` or `findings_count > 0`, `'pass'` when `ran` and
    /// neither, else `'unproven'`.
    fn verdict(&self) -> &'static str {
        if self.status == "ran" {
            let exit_fail = self.exit_code.is_some_and(|c| c > 0);
            let findings_fail = self.findings_count.is_some_and(|c| c > 0);
            if exit_fail || findings_fail { "fail" } else { "pass" }
        } else {
            "unproven"
        }
    }
}

pub struct AssembledFacts {
    pub facts: Value,
    pub incomplete: bool,
    pub secrets_unscanned: bool,
    pub manifest_drift: Option<Value>,
}

/// `main()`'s facts-object assembly, from `results` onward (the D2
/// `incomplete` rule, `secrets_unscanned`, manifest-drift selfcheck, and
/// the final `facts.json` payload shape). `declared_manifest_checks` is
/// `manifest.json`'s `checks[].check` set (`None` when the manifest could
/// not be read/parsed, matching the JS `catch {}` around that read — drift
/// stays `null`, never fabricated).
#[allow(clippy::too_many_arguments)]
pub fn assemble_facts(
    workspace: &str,
    out_dir: &str,
    d: &DetectedStack,
    concurrency: u32,
    scope: Value,
    results: &[ExecutedCheck],
    declared_manifest_checks: Option<&[String]>,
    generated_at: &str,
) -> AssembledFacts {
    let incomplete = results.iter().any(|r| r.required && r.status != "ran");
    let secrets_unscanned = results.iter().any(|r| r.check == "secrets" && r.status != "ran");

    let manifest_drift = declared_manifest_checks.map(|declared| {
        let declared_set: std::collections::BTreeSet<&String> = declared.iter().collect();
        let runtime_set: std::collections::BTreeSet<&String> = results.iter().map(|r| &r.check).collect();
        let missing_from_manifest: Vec<&String> = runtime_set.iter().filter(|c| !declared_set.contains(**c)).copied().collect();
        let stale_in_manifest: Vec<&String> = declared_set
            .iter()
            .filter(|c| !runtime_set.contains(**c) && c.as_str() != "runtime")
            .copied()
            .collect();
        (missing_from_manifest, stale_in_manifest)
    });
    let manifest_drift_value = manifest_drift.as_ref().and_then(|(missing, stale)| {
        if missing.is_empty() && stale.is_empty() {
            None
        } else {
            Some(json!({"missing_from_manifest": missing, "stale_in_manifest": stale}))
        }
    });

    let decomposition = results
        .iter()
        .find(|r| r.check == "decomposition")
        .and_then(|r| r.meta.clone())
        .unwrap_or(Value::Null);

    let checks_json: Vec<Value> = results
        .iter()
        .map(|r| {
            json!({
                "check": r.check, "tool": r.tool, "required": r.required, "tier": r.tier,
                "command": Value::Null, "exit_code": r.exit_code, "status": r.status,
                "skip_reason": r.skip_reason, "findings_count": r.findings_count,
                "meta": r.meta, "execution_status": r.status, "verdict": r.verdict(),
            })
        })
        .collect();

    let detection_disagreement: Vec<Value> = results
        .iter()
        .filter(|r| r.status == "skipped" && r.skip_reason.is_some())
        .map(|r| {
            json!({
                "check": r.check, "reason": r.skip_reason,
                "note": "toolchain absent per local detect(); Blueprint projection decides provider applicability",
            })
        })
        .collect();

    let facts = json!({
        "kind": "audit-facts", "generated_at": generated_at,
        "workspace": workspace, "out_dir": out_dir,
        "stack": {"node": d.node, "ts": d.ts, "py": d.py, "rust": d.rust, "pkgMgr": d.pkg_mgr, "git": d.git},
        "concurrency": concurrency, "incomplete": incomplete, "secrets_unscanned": secrets_unscanned,
        "manifest_drift": manifest_drift_value,
        "scope": scope,
        "decomposition": if decomposition.is_null() { Value::Null } else { decomposition },
        "checks": checks_json,
        "detectionOwner": "blueprint",
        "detectionDisagreement": detection_disagreement,
    });

    AssembledFacts { facts, incomplete, secrets_unscanned, manifest_drift: manifest_drift_value }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stack() -> DetectedStack {
        DetectedStack {
            git: true, node: true, pkg: None, pkg_mgr: "pnpm", ts: true, py: false,
            rust: true, rust_dir: Some(".".to_string()), swift: false, tauri: false,
            build_script: true, eslint: true, biome: false, workflows: true, dockerfile: false,
        }
    }

    #[test]
    fn doctor_rows_classify_cargo_audit_by_rust_and_tool_presence() {
        let d = stack();
        let checks = [DoctorInput { check: "cargo_audit", tool: Some("cargo-audit"), required: false, force_skip: false }];
        let rows = doctor_rows(&d, &checks, |bin| bin == "cargo-audit", |_| false, false);
        assert_eq!(rows[0].ready, "ready");

        let mut d2 = stack();
        d2.rust = false;
        let rows2 = doctor_rows(&d2, &checks, |_| true, |_| false, false);
        assert_eq!(rows2[0].ready, "not-configured");
    }

    #[test]
    fn doctor_rows_force_skip_wins_over_every_other_rule() {
        let d = stack();
        let checks = [DoctorInput { check: "secrets", tool: Some("gitleaks"), required: true, force_skip: true }];
        let rows = doctor_rows(&d, &checks, |_| true, |_| true, true);
        assert_eq!(rows[0].ready, "skipped");
    }

    #[test]
    fn doctor_rows_swift_lint_gates_on_root_flag_or_any_tracked_swift() {
        let mut d = stack();
        d.swift = false;
        let checks = [DoctorInput { check: "swift_lint", tool: Some("swiftlint"), required: false, force_skip: false }];
        let rows = doctor_rows(&d, &checks, |_| false, |_| false, true); // tracked .swift in a subdir
        assert_eq!(rows[0].ready, "missing-tool"); // configured (tracked swift found) but tool absent
    }

    fn exec(check: &str, required: bool, status: &str, exit_code: Option<i64>, findings: Option<i64>) -> ExecutedCheck {
        ExecutedCheck {
            check: check.to_string(), tool: None, required, tier: "core".to_string(),
            status: status.to_string(), skip_reason: None, exit_code, findings_count: findings, meta: None,
        }
    }

    #[test]
    fn assemble_facts_flags_incomplete_when_a_required_check_did_not_run() {
        let d = stack();
        let results = vec![exec("lint", true, "error", Some(1), None), exec("types", false, "ran", Some(0), Some(0))];
        let out = assemble_facts("/repo", "/repo/.audit/out", &d, 6, json!({}), &results, None, "2026-01-01T00:00:00.000Z");
        assert!(out.incomplete);
        assert!(!out.secrets_unscanned);
    }

    #[test]
    fn assemble_facts_flags_secrets_unscanned_when_secrets_check_did_not_run() {
        let d = stack();
        let results = vec![exec("secrets", false, "unproven", None, None)];
        let out = assemble_facts("/repo", "/repo/.audit/out", &d, 6, json!({}), &results, None, "2026-01-01T00:00:00.000Z");
        assert!(out.secrets_unscanned);
    }

    #[test]
    fn assemble_facts_verdict_is_pass_only_when_ran_with_no_exit_or_findings_failure() {
        let d = stack();
        let results = vec![
            exec("a", false, "ran", Some(0), Some(0)),
            exec("b", false, "ran", Some(1), Some(0)),
            exec("c", false, "ran", Some(0), Some(2)),
            exec("d", false, "unproven", None, None),
        ];
        let out = assemble_facts("/repo", "/o", &d, 6, json!({}), &results, None, "t");
        let checks = out.facts["checks"].as_array().unwrap();
        assert_eq!(checks[0]["verdict"], "pass");
        assert_eq!(checks[1]["verdict"], "fail");
        assert_eq!(checks[2]["verdict"], "fail");
        assert_eq!(checks[3]["verdict"], "unproven");
    }

    #[test]
    fn assemble_facts_manifest_drift_reports_missing_and_stale_names() {
        let d = stack();
        let results = vec![exec("lint", false, "ran", Some(0), Some(0)), exec("new_check", false, "ran", Some(0), Some(0))];
        let declared = vec!["lint".to_string(), "retired_check".to_string(), "runtime".to_string()];
        let out = assemble_facts("/repo", "/o", &d, 6, json!({}), &results, Some(&declared), "t");
        let drift = out.manifest_drift.unwrap();
        assert_eq!(drift["missing_from_manifest"], json!(["new_check"]));
        assert_eq!(drift["stale_in_manifest"], json!(["retired_check"]));
    }

    #[test]
    fn assemble_facts_manifest_drift_is_null_when_sets_match() {
        let d = stack();
        let results = vec![exec("lint", false, "ran", Some(0), Some(0))];
        let declared = vec!["lint".to_string(), "runtime".to_string()];
        let out = assemble_facts("/repo", "/o", &d, 6, json!({}), &results, Some(&declared), "t");
        assert!(out.manifest_drift.is_none());
    }

    #[test]
    fn assemble_facts_detection_disagreement_lists_skipped_checks_with_reasons() {
        let d = stack();
        let mut r = exec("secrets", false, "skipped", None, None);
        r.skip_reason = Some("gitleaks not installed".to_string());
        let out = assemble_facts("/repo", "/o", &d, 6, json!({}), &[r], None, "t");
        let dis = out.facts["detectionDisagreement"].as_array().unwrap();
        assert_eq!(dis.len(), 1);
        assert_eq!(dis[0]["check"], "secrets");
    }
}
