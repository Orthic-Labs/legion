//! A07 known answers for `code.javascript.native`: pinned Oxlint/Biome
//! planning, package and framework discovery, native-only owned configs,
//! outcome classification, and Qwik lexer leads. Pure planner/parser tests
//! over authored fixtures. No process is launched, no installed-behavior or
//! production qualification claim is made. checks not run - root integration
//! owns verification.

use legion_audit::{
    native_providers::code::javascript_native::{
        classify_run, coverage_manifest, frozen_reader, no_node_coverage, owned_biome_config,
        owned_oxlint_config, owned_config_text, parse_version_output, plan_native_lint,
        qwik_leads, qwik_version_facts, validate_pin, version_gaps, Linter, NativeLintOptions,
        NativeLintPlan, NativeLintStatus, NativeLintUnit, NativeLinterPin, NATIVE_RULES,
        PROVIDER_ID,
    },
    InventoryEntry,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

const STAGE: &str = "stage";
const MAX_FINDINGS: usize = 200;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/javascript-native")
}

fn repo_root() -> PathBuf {
    fixture_root().join("monorepo")
}

fn output(rel: &str) -> Vec<u8> {
    let path = fixture_root().join(rel);
    fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn collect(dir: &Path, base: &Path, out: &mut Vec<InventoryEntry>) {
    let mut children: Vec<PathBuf> = fs::read_dir(dir)
        .expect("fixture directory")
        .map(|entry| entry.expect("fixture entry").path())
        .collect();
    children.sort();
    for child in children {
        if child.is_dir() {
            collect(&child, base, out);
            continue;
        }
        let rel = child
            .strip_prefix(base)
            .expect("fixture under base")
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&child).expect("fixture file");
        out.push(InventoryEntry {
            path: rel,
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: Some(digest(&bytes)),
        });
    }
}

fn entries() -> Vec<InventoryEntry> {
    let root = repo_root();
    let mut out = Vec::new();
    collect(&root, &root, &mut out);
    out
}

/// Fixture identity only. It is not a catalog pin and proves no installed
/// binary; it exists so planning can proceed over authored fixtures.
fn fixture_pin(linter: Linter) -> NativeLinterPin {
    NativeLinterPin {
        linter,
        version: "0.0.0-fixture".to_string(),
        distribution_digest: digest(b"fixture-distribution"),
    }
}

fn unit<'a>(plan: &'a NativeLintPlan, dir: &str) -> &'a NativeLintUnit {
    plan.units
        .iter()
        .find(|unit| unit.package_dir == dir)
        .unwrap_or_else(|| panic!("unit for {dir:?}"))
}

fn has_gap(gaps: &[String], kind: &str) -> bool {
    gaps.iter().any(|gap| gap.ends_with(kind))
}

#[test]
fn owned_configs_enable_only_native_plugins_and_the_exact_rule_subset() {
    let oxlint = owned_oxlint_config();
    let plugins: Vec<&str> = oxlint["plugins"]
        .as_array()
        .expect("plugins array")
        .iter()
        .map(|plugin| plugin.as_str().expect("plugin name"))
        .collect();
    assert_eq!(plugins, vec!["eslint", "jsx-a11y", "react", "typescript"]);
    let rules = oxlint["rules"].as_object().expect("rules object");
    assert_eq!(rules.len(), NATIVE_RULES.len());
    assert!(rules.values().all(|level| level == "error"));

    let biome = owned_biome_config();
    assert_eq!(biome["linter"]["rules"]["recommended"], json!(false));
    assert_eq!(biome["linter"]["rules"]["suspicious"]["noDebugger"], json!("error"));

    for linter in [Linter::Oxlint, Linter::Biome] {
        let text = owned_config_text(linter);
        assert!(!text.contains("extends"), "owned config must not extend");
        assert!(!text.contains("jsPlugins"), "owned config must not load JS plugins");
    }
}

#[test]
fn plan_is_node_free_and_owns_argv_without_repository_configs() {
    let entries = entries();
    let root = repo_root();
    let read = frozen_reader(&root, &entries);
    let plan = plan_native_lint(
        &entries,
        &read,
        &fixture_pin(Linter::Oxlint),
        &NativeLintOptions::new(Linter::Oxlint, STAGE),
    );
    assert_eq!(plan.provider_id, PROVIDER_ID);
    for unit in &plan.units {
        assert_eq!(unit.program, "oxlint");
        assert!(!unit.argv.iter().any(|arg| matches!(arg.as_str(), "npx" | "pnpm" | "node" | "npm")));
        assert!(unit.argv.contains(&"--disable-nested-config".to_string()));
        assert!(unit.argv.starts_with(&[
            "--config".to_string(),
            "stage/legion-owned-oxlint.json".to_string(),
        ]));
        assert_eq!(unit.config_file, "legion-owned-oxlint.json");
        assert_eq!(unit.config_text, owned_config_text(Linter::Oxlint));
    }

    let web = unit(&plan, "apps/web");
    assert_eq!(web.ignored_repo_configs, vec!["apps/web/eslint.config.mjs".to_string()]);
    assert!(web.argv.contains(&"apps/web/src/root.tsx".to_string()));
    assert!(web.runnable());
    assert_eq!(web.files.len(), 3);
    assert!(!plan.units.iter().any(|unit| unit.program == "npx"));
}

#[test]
fn monorepo_packages_keep_their_roots_and_exclude_generated_trees() {
    let entries = entries();
    let root = repo_root();
    let read = frozen_reader(&root, &entries);
    let plan = plan_native_lint(
        &entries,
        &read,
        &fixture_pin(Linter::Oxlint),
        &NativeLintOptions::new(Linter::Oxlint, STAGE),
    );
    let dirs: Vec<&str> = plan.packages.iter().map(|package| package.dir.as_str()).collect();
    assert_eq!(dirs, vec!["", "apps/web", "packages/empty", "packages/ui"]);
    assert!(plan
        .excluded
        .iter()
        .any(|excluded| excluded.path == "node_modules/lib/index.js"
            && excluded.reason == "excluded-segment:node_modules"));
    assert!(plan.unowned.is_empty());

    let empty = unit(&plan, "packages/empty");
    assert!(empty.files.is_empty());
    assert!(!empty.runnable());
    assert_eq!(
        classify_run(empty, None, b"", b"", &read, MAX_FINDINGS).status,
        NativeLintStatus::ZeroFiles
    );
    assert_eq!(unit(&plan, "packages/ui").files.len(), 1);
}

#[test]
fn framework_versions_come_from_lockfiles_not_manifest_ranges() {
    let entries = entries();
    let root = repo_root();
    let read = frozen_reader(&root, &entries);
    let plan = plan_native_lint(
        &entries,
        &read,
        &fixture_pin(Linter::Oxlint),
        &NativeLintOptions::new(Linter::Oxlint, STAGE),
    );
    let web = plan
        .packages
        .iter()
        .find(|package| package.dir == "apps/web")
        .expect("web package");
    assert_eq!(web.lockfile.as_deref(), Some("pnpm-lock.yaml"));
    let qwik = web
        .frameworks
        .iter()
        .find(|fact| fact.framework == "qwik")
        .expect("qwik fact");
    assert_eq!(qwik.manifest_range.as_deref(), Some("^1.12.0"));
    assert_eq!(qwik.locked_version.as_deref(), Some("1.12.1"));
    assert!(qwik.version_proven);

    let ui = plan
        .packages
        .iter()
        .find(|package| package.dir == "packages/ui")
        .expect("ui package");
    let react = ui.frameworks.first().expect("react fact");
    assert_eq!(react.locked_version.as_deref(), Some("18.3.1"));

    let facts = qwik_version_facts(&plan.packages);
    assert_eq!(facts.len(), 2);
    assert!(facts.iter().all(|fact| fact["versionProven"] == json!(true)));
}

#[test]
fn unreadable_lockfile_leaves_framework_versions_unproven() {
    let mut entries = entries();
    // Replace the monorepo lockfile digest with a missing digest so the
    // lockfile is unreadable through the frozen reader.
    for entry in entries.iter_mut() {
        if entry.path == "pnpm-lock.yaml" {
            entry.digest = None;
        }
    }
    let root = repo_root();
    let read = frozen_reader(&root, &entries);
    let plan = plan_native_lint(
        &entries,
        &read,
        &fixture_pin(Linter::Oxlint),
        &NativeLintOptions::new(Linter::Oxlint, STAGE),
    );
    let web = plan
        .packages
        .iter()
        .find(|package| package.dir == "apps/web")
        .expect("web package");
    let qwik = web
        .frameworks
        .iter()
        .find(|fact| fact.framework == "qwik")
        .expect("qwik fact");
    assert!(!qwik.version_proven);
    assert!(qwik.locked_version.is_none());
    assert!(has_gap(&qwik.gaps, "framework-lockfile-unreadable"));
}

#[test]
fn unpinned_tool_identity_blocks_every_run_and_is_never_clean() {
    let entries = entries();
    let root = repo_root();
    let read = frozen_reader(&root, &entries);
    let plan = plan_native_lint(
        &entries,
        &read,
        &NativeLinterPin::unpinned(Linter::Oxlint),
        &NativeLintOptions::new(Linter::Oxlint, STAGE),
    );
    let web = unit(&plan, "apps/web");
    assert!(!web.runnable());
    assert!(has_gap(&web.gaps, "oxlint-version-unpinned"));
    assert!(has_gap(&web.gaps, "oxlint-distribution-digest-missing"));
    let outcome = classify_run(
        web,
        Some(0),
        &output("outputs/oxlint-clean.json"),
        b"",
        &read,
        MAX_FINDINGS,
    );
    assert_eq!(outcome.status, NativeLintStatus::Incomplete);
    assert!(!validate_pin(&NativeLinterPin::unpinned(Linter::Oxlint)).is_empty());
}

#[test]
fn unsealed_source_marks_its_package_incomplete() {
    let mut entries = entries();
    for entry in entries.iter_mut() {
        if entry.path == "apps/web/src/clean.ts" {
            entry.digest = None;
        }
    }
    let root = repo_root();
    let read = frozen_reader(&root, &entries);
    let plan = plan_native_lint(
        &entries,
        &read,
        &fixture_pin(Linter::Oxlint),
        &NativeLintOptions::new(Linter::Oxlint, STAGE),
    );
    let web = unit(&plan, "apps/web");
    assert!(has_gap(&web.gaps, "javascript-source-unsealed:apps/web/src/clean.ts"));
    assert!(!web.runnable());
}

#[test]
fn frozen_reader_refuses_content_that_does_not_match_its_digest() {
    let mut entries = entries();
    for entry in entries.iter_mut() {
        if entry.path == "apps/web/src/clean.ts" {
            entry.digest = Some(digest(b"tampered"));
        }
    }
    let root = repo_root();
    let read = frozen_reader(&root, &entries);
    assert!(read("apps/web/src/clean.ts").is_none());
    assert!(read("apps/web/src/root.tsx").is_some());
}

#[test]
fn oxlint_outcomes_are_distinct_clean_finding_config_rule_and_operational() {
    let entries = entries();
    let root = repo_root();
    let read = frozen_reader(&root, &entries);
    let plan = plan_native_lint(
        &entries,
        &read,
        &fixture_pin(Linter::Oxlint),
        &NativeLintOptions::new(Linter::Oxlint, STAGE),
    );
    let web = unit(&plan, "apps/web");
    let clean = classify_run(web, Some(0), &output("outputs/oxlint-clean.json"), b"", &read, MAX_FINDINGS);
    assert_eq!(clean.status, NativeLintStatus::Clean);
    assert!(clean.gaps.is_empty());
    assert_eq!(clean.files_scanned, Some(3));
    assert_eq!(clean.files_expected, 3);

    let finding = classify_run(web, Some(1), &output("outputs/oxlint-findings.json"), b"", &read, MAX_FINDINGS);
    assert_eq!(finding.status, NativeLintStatus::Findings);
    assert_eq!(finding.findings.len(), 1);
    let found = &finding.findings[0];
    assert_eq!(found.rule, "eslint/no-debugger");
    assert_eq!(found.path, "apps/web/src/root.tsx");
    assert_eq!(found.line, 6);
    assert_eq!(found.severity, "error");

    let invalid = classify_run(
        web,
        Some(1),
        b"",
        &output("stderr/oxlint-invalid-config.txt"),
        &read,
        MAX_FINDINGS,
    );
    assert_eq!(invalid.status, NativeLintStatus::InvalidConfig);

    let unsupported = classify_run(
        web,
        Some(1),
        b"",
        &output("stderr/oxlint-unsupported-rule.txt"),
        &read,
        MAX_FINDINGS,
    );
    assert_eq!(unsupported.status, NativeLintStatus::UnsupportedRule);

    let operational = classify_run(web, Some(3), b"", b"", &read, MAX_FINDINGS);
    assert_eq!(operational.status, NativeLintStatus::OperationalFailure);
    assert!(has_gap(&operational.gaps, "native-lint-exit:3"));

    let killed = classify_run(web, None, b"", b"", &read, MAX_FINDINGS);
    assert_eq!(killed.status, NativeLintStatus::OperationalFailure);

    let malformed = classify_run(web, Some(0), b"not json", b"", &read, MAX_FINDINGS);
    assert_eq!(malformed.status, NativeLintStatus::MalformedReport);

    let exit_without_findings = classify_run(
        web,
        Some(1),
        &output("outputs/oxlint-no-diagnostics-exit-one.json"),
        b"",
        &read,
        MAX_FINDINGS,
    );
    assert_eq!(exit_without_findings.status, NativeLintStatus::OperationalFailure);
}

#[test]
fn scanned_set_mismatch_is_incomplete_never_clean() {
    let entries = entries();
    let root = repo_root();
    let read = frozen_reader(&root, &entries);
    let plan = plan_native_lint(
        &entries,
        &read,
        &fixture_pin(Linter::Oxlint),
        &NativeLintOptions::new(Linter::Oxlint, STAGE),
    );
    // packages/ui has one source; the clean report claims three files.
    let ui = unit(&plan, "packages/ui");
    let outcome = classify_run(ui, Some(0), &output("outputs/oxlint-clean.json"), b"", &read, MAX_FINDINGS);
    assert_eq!(outcome.status, NativeLintStatus::Incomplete);
    assert!(has_gap(&outcome.gaps, "native-lint-scanned-set-mismatch:3/1"));
}

#[test]
fn biome_never_claims_clean_without_a_proven_scanned_set() {
    let entries = entries();
    let root = repo_root();
    let read = frozen_reader(&root, &entries);
    let plan = plan_native_lint(
        &entries,
        &read,
        &fixture_pin(Linter::Biome),
        &NativeLintOptions::new(Linter::Biome, STAGE),
    );
    let ui = unit(&plan, "packages/ui");
    assert!(ui.argv.starts_with(&[
        "lint".to_string(),
        "--config-path".to_string(),
        STAGE.to_string(),
        "--reporter".to_string(),
        "json".to_string(),
    ]));
    let clean = classify_run(ui, Some(0), br#"{"summary":{},"diagnostics":[]}"#, b"", &read, MAX_FINDINGS);
    assert_eq!(clean.status, NativeLintStatus::Incomplete);
    assert!(has_gap(&clean.gaps, "biome-scanned-set-unproven"));

    let source = fs::read(root.join("packages/ui/src/Button.tsx")).expect("button fixture");
    let offset = source
        .windows(7)
        .position(|window| window == b"console")
        .expect("console token");
    let report = json!({
        "summary": {"diagnosticsNotPrinted": 0},
        "diagnostics": [{
            "category": "lint/suspicious/noDebugger",
            "severity": "error",
            "description": "Disallow console statements.",
            "location": {"path": {"file": "packages/ui/src/Button.tsx"}, "span": [offset, offset + 7]}
        }]
    });
    let found = classify_run(
        ui,
        Some(1),
        report.to_string().as_bytes(),
        b"",
        &read,
        MAX_FINDINGS,
    );
    assert_eq!(found.status, NativeLintStatus::Findings);
    assert_eq!(found.findings[0].rule, "lint/suspicious/noDebugger");
    assert_eq!(found.findings[0].line, 2);
    assert_eq!(found.findings[0].path, "packages/ui/src/Button.tsx");

    let config_error = json!({
        "summary": {},
        "diagnostics": [{"category": "configuration", "severity": "error", "description": "bad", "location": {}}]
    });
    let invalid = classify_run(ui, Some(1), config_error.to_string().as_bytes(), b"", &read, MAX_FINDINGS);
    assert_eq!(invalid.status, NativeLintStatus::InvalidConfig);
}

#[test]
fn qwik_lexer_matches_are_leads_only() {
    let entries = entries();
    let root = repo_root();
    let read = frozen_reader(&root, &entries);
    let leads = qwik_leads(&entries, &read);
    assert_eq!(leads.len(), 1, "one boundary line with a non-serializable constructor");
    let lead: &Value = &leads[0];
    assert_eq!(lead["kind"], json!("qwik-serialization-boundary-lead"));
    assert_eq!(lead["path"], json!("apps/web/src/root.tsx"));
    assert_eq!(lead["line"], json!(5));
    assert!(lead["token"].as_str().expect("token").starts_with("new Map"));
    assert_eq!(lead["leadOnly"], json!(true));
    assert_eq!(lead["satisfiesObligations"], json!(false));
}

#[test]
fn coverage_claims_no_equivalence_and_keeps_qwik_runtime_uncovered() {
    let manifest = coverage_manifest();
    assert_eq!(manifest["claimsEslintPluginEquivalence"], json!(false));
    assert_eq!(manifest["claimsQwikCompilerEquivalence"], json!(false));
    assert_eq!(
        manifest["nativeScanSatisfiesQwikOptimizerResumabilityRuntime"],
        json!(false)
    );
    let covered = manifest["coveredConcerns"].as_array().expect("covered");
    assert!(covered.contains(&json!("react-hooks")));
    assert!(covered.contains(&json!("a11y")));
    let uncovered = manifest["uncoveredConcerns"].as_array().expect("uncovered");
    assert!(uncovered
        .iter()
        .any(|item| item["concern"] == json!("qwik-resumability") && item["owner"] == json!("A16")));
    assert!(uncovered
        .iter()
        .any(|item| item["concern"] == json!("typescript-semantics") && item["owner"] == json!("A03")));
}

#[test]
fn no_node_profile_excludes_legacy_node_tools_and_keeps_uncovered_visible() {
    let profile = no_node_coverage();
    let excluded = profile["excludedLegacyNodeTools"].as_array().expect("excluded");
    assert!(excluded.contains(&json!("code.javascript:build")));
    assert!(excluded.contains(&json!("code.javascript:test")));
    let uncovered = profile["uncoveredConcerns"].as_array().expect("uncovered");
    assert!(!uncovered.is_empty());
}

#[test]
fn version_probe_requires_a_recognized_version_string() {
    assert_eq!(parse_version_output(b"Version 1.2.3\n"), Some("1.2.3".to_string()));
    assert_eq!(parse_version_output(b"unrecognized"), None);
    let pin = fixture_pin(Linter::Oxlint);
    assert!(version_gaps(None, &pin)
        .iter()
        .any(|gap| gap.ends_with("oxlint-version-unproven")));
    assert!(version_gaps(Some("9.9.9"), &pin)
        .iter()
        .any(|gap| gap.ends_with("oxlint-version-mismatch:9.9.9")));
    assert!(version_gaps(Some(pin.version.as_str()), &pin).is_empty());
}

#[test]
fn runner_record_is_never_marked_executed() {
    let entries = entries();
    let root = repo_root();
    let read = frozen_reader(&root, &entries);
    let plan = plan_native_lint(
        &entries,
        &read,
        &fixture_pin(Linter::Oxlint),
        &NativeLintOptions::new(Linter::Oxlint, STAGE),
    );
    let record = unit(&plan, "apps/web").runner_record();
    assert_eq!(record["executed"], json!(false));
    assert_eq!(record["runnable"], json!(true));
    assert_eq!(record["programCandidates"], json!(["oxlint"]));
    assert_eq!(record["parser"], json!("oxlint-json-1"));
}
