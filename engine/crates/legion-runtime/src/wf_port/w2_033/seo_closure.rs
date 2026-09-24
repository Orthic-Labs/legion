//! Rust port of `skills/seo/scripts/seo_closure.py`: the static closure gate for Legion
//! SEO implementation coverage.
//!
//! `seo_closure.py` is a repository-structure closure gate: it walks the live `skills/seo`
//! tree, reads several JSON config files and markdown references, and cross-checks them
//! against required-file sets. This module ports both the pure validation logic (the
//! `##`-heading slug extractor and the phase catalog's structural checks) and the
//! filesystem walk/read that drives it ([`check`]), plus a [`run`] CLI entry point
//! equivalent to the Python `main()`.

use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// Port of `headings(path)`: for each `## Heading Text` line, produce the same slug as
/// Python's `re.sub(r'[^a-z0-9]+', '-', match.group(1).lower()).strip('-')`.
pub fn headings(markdown: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in markdown.lines() {
        let Some(rest) = line.strip_prefix("## ") else {
            continue;
        };
        let heading = rest.trim_end();
        if heading.is_empty() {
            continue;
        }
        out.insert(slugify(heading));
    }
    out
}

fn slugify(heading: &str) -> String {
    let mut slug = String::with_capacity(heading.len());
    let mut last_was_sep = false;
    for ch in heading.to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            last_was_sep = false;
        } else if !last_was_sep {
            slug.push('-');
            last_was_sep = true;
        }
    }
    slug.trim_matches('-').to_string()
}

/// A phase entry's minimal shape needed for the structural checks, mirroring the fields of
/// `control-catalog.json`'s `phases[]` that `check()` validates.
#[derive(Debug, Clone)]
pub struct PhaseRange {
    pub id: i64,
    pub source_lines: Option<(i64, i64)>,
    pub has_owners: bool,
}

/// Port of the phase-id, status-vocabulary, critical-gate, and `source_lines` contiguity
/// checks inside `check()`. Returns the same error strings the Python tool prints (prefixed
/// `FAIL:` there; unprefixed here — the caller formats).
pub fn validate_phases(
    phases: &[PhaseRange],
    statuses: &BTreeSet<String>,
    critical_gates: &BTreeSet<String>,
    required_critical_gates: &BTreeSet<String>,
    source_line_count: i64,
) -> Vec<String> {
    let mut errors = Vec::new();

    let ids: Vec<i64> = phases.iter().map(|p| p.id).collect();
    let expected: Vec<i64> = (1..=30).collect();
    if ids != expected {
        errors.push(format!("checklist phases must be exactly 1..30; got {ids:?}"));
    }

    let expected_statuses: BTreeSet<String> = ["pass", "partial", "fail", "na", "not_testable"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if statuses != &expected_statuses {
        errors.push("status vocabulary does not match canonical five-state contract".to_string());
    }

    if critical_gates != required_critical_gates {
        errors.push("critical gate set differs from governed SEO closure contract".to_string());
    }

    let mut previous_end: i64 = 73;
    for phase in phases {
        match phase.source_lines {
            None => errors.push(format!("phase {} missing exact source_lines", phase.id)),
            Some((start, end)) => {
                if start != previous_end + 1 {
                    errors.push(format!(
                        "phase {} source range is not contiguous after line {previous_end}: [{start}, {end}]",
                        phase.id
                    ));
                }
                if end < start {
                    errors.push(format!(
                        "phase {} has invalid source range: [{start}, {end}]",
                        phase.id
                    ));
                }
                previous_end = end;
            }
        }
        if !phase.has_owners {
            errors.push(format!("phase {} has no owner", phase.id));
        }
    }
    if previous_end != source_line_count {
        errors.push(format!(
            "phase source ranges stop at {previous_end}, source line count is {source_line_count}"
        ));
    }

    errors
}

/// Port of the "required set has entries not present in the discovered set" checks used
/// repeatedly by `check()` (required scripts / refs / test fixtures / workflow packs), given
/// the set of names already discovered on disk.
pub fn missing_required<'a>(required: &BTreeSet<&'a str>, present: &BTreeSet<String>) -> Vec<&'a str> {
    required
        .iter()
        .copied()
        .filter(|name| !present.contains(*name))
        .collect()
}

const REQUIRED_SCRIPTS: &[&str] = &[
    "site_audit.py", "gsc_query.py", "gsc_query_v2.py", "gsc_inspect.py", "ga4_report.py",
    "pagespeed_check.py", "crux_history.py", "ai_visibility_import.py",
    "templated_metadata.py", "search_ops.py", "seo_project.py", "provider_registry.py",
    "query_ownership.py", "question_inventory.py", "rank_tracker.py", "coverage.py",
    "contracts.py", "checklist_compiler.py", "seo_closure.py",
];
const REQUIRED_REFS: &[&str] = &[
    "manual.md", "operations.md", "ai-search-2026.md", "geo.md", "technical.md",
    "page.md", "schema.md", "sitemap.md", "images.md", "local.md", "hreflang.md",
    "programmatic.md", "backlinks.md", "off-page.md", "search-experience.md",
    "topic-clusters.md", "ecommerce-2026.md", "workflow-packs.md",
    "openseo-absorption.md", "free-data-sources.md", "quality-gates.md",
];
const REQUIRED_TEST_FILES: &[&str] = &[
    "test_seo_kernel.py", "test_seo_governance.py", "test_provider_replay.py",
    "fixtures/gsc_rows.json", "fixtures/gsc_replay.json", "fixtures/ai_google.csv",
    "fixtures/ai_bing.csv", "fixtures/badseo/noindex.html", "fixtures/badseo/clean.html",
];
const REQUIRED_PACKS: &[&str] = &[
    "policy", "bot-policy", "logs", "crawl-efficiency", "agent-readiness",
    "search-appearance", "discover", "media", "documents", "ecommerce", "publisher",
    "access-states", "migration", "analytics", "forecast", "experiment", "monitor",
    "release-gate", "incident", "feeds",
];
const REQUIRED_CRITICAL_GATES: &[&str] = &[
    "indexability", "canonical-integrity", "redirect-integrity", "security-policy",
    "measurement-integrity", "deployment-verification", "authority-boundary",
];
const ROUTER_REQUIRED: &[&str] = &[
    "workflow-packs.md", "seo_project.py", "provider_registry.py", "gsc_query_v2.py",
    "ai_visibility_import.py", "search_ops.py", "coverage.py", "seo_closure.py",
];

fn set_of(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

/// The closure check's result, matching Python `check()`'s return dict shape.
#[derive(Debug, Clone, Serialize)]
pub struct ClosureResult {
    pub status: &'static str,
    pub scope: &'static str,
    pub phase_count: usize,
    pub workflow_pack_count: usize,
    pub critical_gate_count: usize,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Port of `check()`. `seo_root` is `skills/seo` (the Python `SEO_ROOT = Path(__file__)
/// .resolve().parent.parent`, i.e. two levels up from `scripts/seo_closure.py`);
/// `repo_root` is `seo_root.parent().parent()` (the Python `REPO_ROOT`).
pub fn check(seo_root: &Path) -> ClosureResult {
    let repo_root: PathBuf = seo_root
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| seo_root.to_path_buf());

    let mut errors: Vec<String> = Vec::new();
    let warnings: Vec<String> = Vec::new();

    let catalog_path = seo_root.join("config").join("control-catalog.json");
    if !catalog_path.exists() {
        return ClosureResult {
            status: "fail",
            scope: "repository implementation closure; authenticated runtime availability/outcomes are separately evidenced",
            phase_count: 0,
            workflow_pack_count: 0,
            critical_gate_count: 0,
            errors: vec![format!("missing {}", catalog_path.display())],
            warnings,
        };
    }
    let catalog = match read_json(&catalog_path) {
        Ok(v) => v,
        Err(e) => {
            return ClosureResult {
                status: "fail",
                scope: "repository implementation closure; authenticated runtime availability/outcomes are separately evidenced",
                phase_count: 0,
                workflow_pack_count: 0,
                critical_gate_count: 0,
                errors: vec![e],
                warnings,
            };
        }
    };

    let phases_json = catalog.get("phases").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    let phases: Vec<PhaseRange> = phases_json
        .iter()
        .map(|p| PhaseRange {
            id: p.get("id").and_then(|v| v.as_i64()).unwrap_or(-1),
            source_lines: p.get("source_lines").and_then(|v| v.as_array()).and_then(|a| {
                if a.len() == 2 {
                    Some((a[0].as_i64()?, a[1].as_i64()?))
                } else {
                    None
                }
            }),
            has_owners: p
                .get("owners")
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false),
        })
        .collect();

    let statuses: BTreeSet<String> = catalog
        .get("statuses")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let critical_gates: BTreeSet<String> = catalog
        .get("critical_gates")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let required_gates = set_of(REQUIRED_CRITICAL_GATES);
    let source_line_count = catalog.get("source_line_count").and_then(|v| v.as_i64()).unwrap_or(-1);

    errors.extend(validate_phases(&phases, &statuses, &critical_gates, &required_gates, source_line_count));

    // Owner / script existence checks per-phase (validate_phases only checks structure).
    for p in &phases_json {
        let pid = p.get("id").and_then(|v| v.as_i64()).unwrap_or(-1);
        for owner in p.get("owners").and_then(|v| v.as_array()).into_iter().flatten() {
            if let Some(rel) = owner.as_str() {
                if !seo_root.join(rel).exists() {
                    errors.push(format!("phase {pid} owner missing: {rel}"));
                }
            }
        }
        for script in p.get("scripts").and_then(|v| v.as_array()).into_iter().flatten() {
            if let Some(name) = script.as_str() {
                if !seo_root.join("scripts").join(name).exists() {
                    errors.push(format!("phase {pid} script missing: {name}"));
                }
            }
        }
    }

    let scripts_dir = seo_root.join("scripts");
    for name in REQUIRED_SCRIPTS {
        if !scripts_dir.join(name).exists() {
            errors.push(format!("required SEO implementation script missing: {name}"));
        }
    }
    let refs_dir = seo_root.join("references");
    for name in REQUIRED_REFS {
        if !refs_dir.join(name).exists() {
            errors.push(format!("required SEO reference missing: {name}"));
        }
    }

    let provider_registry_path = seo_root.join("config").join("provider-registry.json");
    let contracts_path = seo_root.join("config").join("contracts.json");
    let qualification_path = seo_root.join("config").join("qualification.json");
    for (path, label) in [
        (&provider_registry_path, "provider-registry.json"),
        (&contracts_path, "contracts.json"),
        (&qualification_path, "qualification.json"),
    ] {
        if !path.exists() {
            errors.push(format!("{label} missing"));
        }
    }

    if provider_registry_path.exists() {
        match read_json(&provider_registry_path) {
            Ok(v) => {
                let providers = v.get("providers").and_then(|x| x.as_object()).cloned().unwrap_or_default();
                for required in [
                    "local", "google_gsc", "google_ga4", "google_pagespeed_crux",
                    "google_generative_export", "bing_ai_export",
                ] {
                    if !providers.contains_key(required) {
                        errors.push(format!("provider registry missing core provider: {required}"));
                    }
                }
            }
            Err(e) => errors.push(e),
        }
    }
    if contracts_path.exists() {
        match read_json(&contracts_path) {
            Ok(v) => {
                for key in [
                    "evidence_required", "finding_required", "recommendation_required",
                    "action_required", "outcome_required",
                ] {
                    let truthy = v.get(key).map(is_truthy).unwrap_or(false);
                    if !truthy {
                        errors.push(format!("contracts missing {key}"));
                    }
                }
            }
            Err(e) => errors.push(e),
        }
    }
    if qualification_path.exists() {
        match read_json(&qualification_path) {
            Ok(v) => {
                let ok = v.get("provider_replay_required").map(is_truthy).unwrap_or(false)
                    && v.get("runtime_gates").map(is_truthy).unwrap_or(false)
                    && v.get("installed_path_gates").map(is_truthy).unwrap_or(false);
                if !ok {
                    errors.push("qualification.json missing provider/runtime/installed-path gate declarations".to_string());
                }
            }
            Err(e) => errors.push(e),
        }
    }

    let declared_packs: BTreeSet<String> = catalog
        .get("workflow_packs")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    let required_packs = set_of(REQUIRED_PACKS);
    let missing_packs: Vec<&str> = REQUIRED_PACKS
        .iter()
        .copied()
        .filter(|p| !declared_packs.contains(*p))
        .collect();
    if !missing_packs.is_empty() {
        errors.push(format!("workflow packs missing from catalog: {missing_packs:?}"));
    }
    let _ = &required_packs;

    let workflow_packs_path = seo_root.join("references").join("workflow-packs.md");
    if workflow_packs_path.exists() {
        if let Ok(md) = std::fs::read_to_string(&workflow_packs_path) {
            let hs = headings(&md);
            for pack in REQUIRED_PACKS {
                if !hs.iter().any(|h| h.contains(pack)) {
                    errors.push(format!("workflow pack has no documented owner section: {pack}"));
                }
            }
        }
    }

    let router_path = seo_root.join("SKILL.md");
    let router = std::fs::read_to_string(&router_path).unwrap_or_default();
    for required in ROUTER_REQUIRED {
        if !router.contains(required) {
            errors.push(format!("router does not expose/invoke closure component: {required}"));
        }
    }

    let tests_dir = seo_root.join("tests");
    for rel in REQUIRED_TEST_FILES {
        if !tests_dir.join(rel).exists() {
            errors.push(format!("required SEO regression fixture/test missing: {rel}"));
        }
    }

    let manifest_path = seo_root.join("config").join("source-manifest.json");
    if !manifest_path.exists() {
        errors.push("missing source-manifest.json".to_string());
    } else {
        match read_json(&manifest_path) {
            Ok(manifest) => {
                let sources = manifest.get("sources").and_then(|v| v.as_array()).cloned().unwrap_or_default();
                let checklist = sources.iter().find(|s| s.get("role").and_then(|r| r.as_str()) == Some("control-source"));
                let implementation = sources
                    .iter()
                    .find(|s| s.get("role").and_then(|r| r.as_str()) == Some("implementation-contract"));
                if checklist.is_none() || implementation.is_none() {
                    errors.push("source manifest missing control-source or implementation-contract".to_string());
                } else if let Some(checklist) = checklist {
                    if checklist.get("sha256") != catalog.get("source_sha256") {
                        errors.push("control catalog source digest does not match source manifest".to_string());
                    }
                    if checklist.get("line_count") != catalog.get("source_line_count") {
                        errors.push("control catalog line count does not match source manifest".to_string());
                    }
                }
                for source in &sources {
                    let has_sha = source.get("sha256").map(is_truthy).unwrap_or(false);
                    let has_lines = source.get("line_count").map(is_truthy).unwrap_or(false);
                    if !has_sha || !has_lines {
                        let name = source.get("name").and_then(|v| v.as_str()).unwrap_or_default();
                        errors.push(format!("source manifest incomplete for {name}"));
                    }
                }
            }
            Err(e) => errors.push(e),
        }
    }

    let legacy = scripts_dir.join("gsc_query.py");
    if legacy.exists() {
        if let Ok(text) = std::fs::read_to_string(&legacy) {
            if !text.to_lowercase().contains("dimensionless") || !text.contains("gsc_query_v2") {
                errors.push("legacy gsc_query.py does not delegate to provenance-safe v2 aggregate semantics".to_string());
            }
        }
    }

    let test_runner = repo_root.join("scripts").join("test-python.mjs");
    let runner_ok = test_runner.exists()
        && std::fs::read_to_string(&test_runner)
            .map(|t| t.contains("skills/seo/tests"))
            .unwrap_or(false);
    if !runner_ok {
        errors.push("SEO Python regression suite is not wired into repository Python CI".to_string());
    }
    let notices = repo_root.join("docs").join("THIRD_PARTY_NOTICES.md");
    let notices_ok = notices.exists()
        && std::fs::read_to_string(&notices)
            .map(|t| t.contains("AgriciDaniel/claude-seo") && t.contains("every-app/open-seo"))
            .unwrap_or(false);
    if !notices_ok {
        errors.push("third-party notices do not record SEO donor methodology provenance".to_string());
    }

    let status = if errors.is_empty() { "pass" } else { "fail" };
    ClosureResult {
        status,
        scope: "repository implementation closure; authenticated runtime availability/outcomes are separately evidenced",
        phase_count: phases.len(),
        workflow_pack_count: declared_packs.len(),
        critical_gate_count: critical_gates.len(),
        errors,
        warnings,
    }
}

fn is_truthy(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Null => false,
        serde_json::Value::Bool(b) => *b,
        serde_json::Value::Number(n) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        serde_json::Value::String(s) => !s.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        serde_json::Value::Object(o) => !o.is_empty(),
    }
}

/// Port of `main()`. `args` excludes the program name; `--json` mirrors the Python flag.
/// `seo_root` is the `skills/seo` directory the gate runs against (the Python script
/// derives this from `__file__`; here the caller supplies it, defaulting to
/// `<cwd>/skills/seo` in [`run`]).
pub fn run_against(seo_root: &Path, args: &[String]) -> i32 {
    let json_flag = args.iter().any(|a| a == "--json");
    let result = check(seo_root);
    if json_flag {
        println!("{}", serde_json::to_string_pretty(&result).unwrap_or_default());
    } else {
        println!(
            "SEO closure: {} — {} phases, {} workflow packs, {} critical gates",
            result.status.to_uppercase(),
            result.phase_count,
            result.workflow_pack_count,
            result.critical_gate_count
        );
        for error in &result.errors {
            println!("FAIL: {error}");
        }
        for warning in &result.warnings {
            println!("WARN: {warning}");
        }
    }
    if result.status == "pass" {
        0
    } else {
        1
    }
}

/// CLI entry point equivalent to `python seo_closure.py`, resolving `SEO_ROOT` as
/// `<current_dir>/skills/seo` (the layout every caller in this repository runs from).
pub fn run(args: &[String]) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_default();
    run_against(&cwd.join("skills").join("seo"), args)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headings_slugifies_like_python() {
        let md = "# Title\n\n## Bot Policy & Logs\n\nbody\n\n## Search-Appearance\n";
        let hs = headings(md);
        assert!(hs.contains("bot-policy-logs"));
        assert!(hs.contains("search-appearance"));
        assert_eq!(hs.len(), 2);
    }

    #[test]
    fn validate_phases_flags_gaps_and_bad_ids() {
        let phases = vec![
            PhaseRange {
                id: 1,
                source_lines: Some((74, 100)),
                has_owners: true,
            },
            PhaseRange {
                id: 2,
                source_lines: Some((105, 120)),
                has_owners: false,
            },
        ];
        let statuses: BTreeSet<String> = ["pass", "partial", "fail", "na", "not_testable"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let gates: BTreeSet<String> = ["indexability"].iter().map(|s| s.to_string()).collect();
        let required_gates = gates.clone();
        let errors = validate_phases(&phases, &statuses, &gates, &required_gates, 120);
        assert!(errors.iter().any(|e| e.contains("must be exactly 1..30")));
        assert!(errors.iter().any(|e| e.contains("not contiguous")));
        assert!(errors.iter().any(|e| e.contains("phase 2 has no owner")));
    }

    #[test]
    fn validate_phases_clean_input_has_no_errors() {
        let mut phases = Vec::new();
        let mut start = 74i64;
        for id in 1..=30 {
            let end = start + 4;
            phases.push(PhaseRange {
                id,
                source_lines: Some((start, end)),
                has_owners: true,
            });
            start = end + 1;
        }
        let statuses: BTreeSet<String> = ["pass", "partial", "fail", "na", "not_testable"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let gates: BTreeSet<String> = BTreeSet::new();
        let errors = validate_phases(&phases, &statuses, &gates, &gates, start - 1);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn missing_required_reports_gaps() {
        let required: BTreeSet<&str> = ["a.py", "b.py", "c.py"].into_iter().collect();
        let present: BTreeSet<String> = ["a.py".to_string()].into_iter().collect();
        let mut missing = missing_required(&required, &present);
        missing.sort();
        assert_eq!(missing, vec!["b.py", "c.py"]);
    }

    #[test]
    fn check_reports_missing_catalog_on_empty_root() {
        let root = std::env::temp_dir().join(format!(
            "legion-seo-closure-empty-{}-{}",
            std::process::id(),
            {
                static C: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                C.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            }
        ));
        std::fs::create_dir_all(&root).unwrap();
        let result = check(&root);
        assert_eq!(result.status, "fail");
        assert!(result.errors.iter().any(|e| e.contains("missing")));
    }

    /// Runs `check()` against this repository's real `skills/seo` tree, matching what
    /// `python skills/seo/scripts/seo_closure.py` reports when invoked from the repo root.
    #[test]
    fn check_against_repo_seo_root_is_pass_or_reports_real_gaps() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        // engine/crates/legion-runtime -> repo root is three levels up.
        let repo_root = manifest_dir
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .expect("repo root");
        let seo_root = repo_root.join("skills").join("seo");
        if !seo_root.exists() {
            // Not running inside the full monorepo checkout; skip rather than fail.
            return;
        }
        let result = check(&seo_root);
        // Whatever the outcome, the walk must actually have found the catalog and
        // produced structured counts rather than the "missing catalog" short-circuit.
        assert!(result.phase_count > 0, "errors: {:?}", result.errors);
    }
}
