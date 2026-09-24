//! Port of test assertions for chunk wf065 (`tools/audit/{audit-verify.mjs,
//! audit_store.py, collect-facts.mjs, provider-benchmarks.mjs}`), driving the
//! Rust ports in `legion_audit::wf_port::wf065`.
//!
//! `audit_provider.py` is dropped (Membrane `ContextProvider` adapter — see
//! `wf065::mod` docs) and has no tests here.

use std::collections::BTreeMap;
use std::fs;

use legion_audit::wf_port::wf065::audit_store::{
    derive_finding_id, make_finding, AuditStore, EvidenceLocusInput, FindingDraft,
};
use legion_audit::wf_port::wf065::audit_verify::{
    allowed_child_keys, checks_match, child_env, classify_replay, frozen_contracts_match,
    normalize_checks, offline_env_overrides, project_execution_checks, result_digest, CheckResult,
};
use legion_audit::wf_port::wf065::collect_facts::{
    classify_file, clean_path, decomposition_review_loc, detect, gitleaks_candidates,
    in_git_worktree, is_generated_or_vendored_path, is_run_dir_name, git_ref, in_scope,
    looks_missing, mechanical_splits, oversized_files, prune_old_runs, redact,
    resolve_root_positional, FileClass, FileLoc,
};
use legion_audit::wf_port::wf065::provider_benchmarks::{
    benchmark_record_for, compute_fixtures_digest, digest_file, file_bindings, is_result_fresh,
    measure_fixture_set, qualification_from_results, result_qualification_digest, Binding,
    ExpectedFinding, FixtureCase, FixturesDoc, ProviderBinding, ProviderIdentity, RawCandidate,
    UNMEASURED_GAP_KIND,
};

// =================================================================================================
// collect_facts
// =================================================================================================

#[test]
fn clean_path_strips_backslashes_leading_dot_run_and_trailing_slash() {
    assert_eq!(clean_path(Some("a\\b\\c/")), Some("a/b/c".to_string()));
    assert_eq!(clean_path(Some("./foo/bar")), Some("foo/bar".to_string()));
    // Non-global JS regex: only the FIRST "./" run is stripped.
    assert_eq!(clean_path(Some("././foo")), Some("./foo".to_string()));
    assert_eq!(clean_path(Some("")), None);
    assert_eq!(clean_path(None), None);
}

#[test]
fn git_ref_rejects_unsafe_refs_and_passes_safe_ones() {
    assert_eq!(git_ref(None).unwrap(), None);
    assert_eq!(git_ref(Some("")).unwrap(), None);
    assert_eq!(git_ref(Some("main")).unwrap(), Some("main".to_string()));
    assert_eq!(
        git_ref(Some("release/1.2.3-rc1@x")).unwrap(),
        Some("release/1.2.3-rc1@x".to_string())
    );
    assert!(git_ref(Some("main; rm -rf /")).is_err());
    assert!(git_ref(Some("-x")).is_err(), "must not start with a non-alnum");
}

#[test]
fn in_scope_matches_dir_and_descendants_only() {
    assert!(in_scope("src/lib.rs", None));
    assert!(in_scope("tauri-app-next", Some("tauri-app-next")));
    assert!(in_scope("tauri-app-next/src/main.rs", Some("tauri-app-next")));
    assert!(!in_scope("other/src/main.rs", Some("tauri-app-next")));
    assert!(!in_scope("tauri-app-nextbogus/x", Some("tauri-app-next")));
}

#[test]
fn redact_covers_every_secret_family() {
    let sk = format!("sk-{}", "a".repeat(20));
    assert_eq!(redact(Some(&sk)).unwrap(), "<REDACTED:openai>");
    let akia = format!("AKIA{}", "A".repeat(16));
    assert_eq!(redact(Some(&akia)).unwrap(), "<REDACTED:aws>");
    let ghp = format!("ghp_{}", "a".repeat(20));
    assert_eq!(redact(Some(&ghp)).unwrap(), "<REDACTED:github>");
    let slack = format!("xoxb-{}", "a".repeat(12));
    assert_eq!(redact(Some(&slack)).unwrap(), "<REDACTED:slack>");
    let key = "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----";
    assert_eq!(redact(Some(key)).unwrap(), "<REDACTED:privkey>");
    let b64 = "A".repeat(60);
    assert_eq!(redact(Some(&b64)).unwrap(), "<REDACTED:b64>");
    assert_eq!(redact(Some("hello world")).unwrap(), "hello world");
    assert_eq!(redact(None), None);
}

#[test]
fn looks_missing_detects_absent_tool_signals() {
    assert!(looks_missing("", "spawn eslint ENOENT"));
    assert!(looks_missing("'tsc' is not recognized as an internal command", ""));
    assert!(!looks_missing("2 problems (2 errors, 0 warnings)", ""));
}

#[test]
fn is_generated_or_vendored_path_matches_known_prefixes() {
    assert!(is_generated_or_vendored_path("vendor/foo.rs"));
    assert!(is_generated_or_vendored_path("src-tauri/gen/schemas/x.json"));
    assert!(is_generated_or_vendored_path("apps/web/src/generated/api.ts"));
    assert!(!is_generated_or_vendored_path("src/lib.rs"));
}

#[test]
fn classify_file_prefers_test_then_tooling_then_runtime() {
    assert_eq!(classify_file("src/foo.test.ts"), FileClass::Test);
    assert_eq!(classify_file("tests/unit/bar.rs"), FileClass::Test);
    assert_eq!(classify_file("conftest.py"), FileClass::Test);
    assert_eq!(classify_file(".github/workflows/ci.yml"), FileClass::Tooling);
    assert_eq!(classify_file("Dockerfile"), FileClass::Tooling);
    assert_eq!(classify_file("src/main.rs"), FileClass::Runtime);
}

#[test]
fn decomposition_review_loc_prefers_env_then_config_then_default() {
    let env = decomposition_review_loc(Some("500"), None);
    assert_eq!(env.value, 500);
    assert_eq!(env.source, "blueprint-config");
    assert!(env.ignored.is_empty());

    let ignored_env = decomposition_review_loc(Some("50"), None);
    assert_eq!(ignored_env.value, 400);
    assert_eq!(ignored_env.source, "workspace-default");
    assert_eq!(ignored_env.ignored.len(), 1);
    assert_eq!(ignored_env.ignored[0].source, "CORTEX_DECOMPOSITION_REVIEW_LOC");

    let config = decomposition_review_loc(None, Some(&serde_json::json!(600)));
    assert_eq!(config.value, 600);
    assert_eq!(config.source, ".agent/config.json");

    let default = decomposition_review_loc(None, None);
    assert_eq!(default.value, 400);
    assert_eq!(default.source, "workspace-default");
}

#[test]
fn resolve_root_positional_skips_value_flag_arguments() {
    let args: Vec<String> = ["--only", "apple_platform", "/repo"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(resolve_root_positional(&args), Some("/repo".to_string()));

    let no_root: Vec<String> = ["--only", "apple_platform"].into_iter().map(String::from).collect();
    assert_eq!(resolve_root_positional(&no_root), None);

    let bare: Vec<String> = vec!["/repo".to_string()];
    assert_eq!(resolve_root_positional(&bare), Some("/repo".to_string()));
}

#[test]
fn gitleaks_candidates_strip_secrets_and_use_fingerprint_or_digest() {
    let json = serde_json::json!([
        { "Fingerprint": "abc123", "RuleID": "generic-api-key", "File": "src/db.ts", "StartLine": 4, "Secret": "sk-should-never-appear" },
        { "RuleID": "aws-key", "File": "infra/main.tf", "StartLine": 9, "Secret": "AKIAsecret" },
    ])
    .to_string();
    let candidates = gitleaks_candidates(&json).unwrap();
    assert_eq!(candidates.len(), 2);
    assert_eq!(candidates[0].digest, "abc123");
    assert_eq!(candidates[0].rule.as_deref(), Some("generic-api-key"));
    assert!(candidates[1].digest.starts_with("sha256:"));
    for c in &candidates {
        let serialized = serde_json::to_string(c).unwrap();
        assert!(!serialized.contains("Secret"));
        assert!(!serialized.contains("sk-"));
        assert!(!serialized.contains("AKIA"));
    }
    assert!(gitleaks_candidates("not json").is_err());
    assert!(gitleaks_candidates("{}").is_err());
}

#[test]
fn oversized_files_filters_and_sorts_descending() {
    let files = vec![
        FileLoc { path: "src/small.rs".into(), loc: 50, bytes: 500 },
        FileLoc { path: "src/big.rs".into(), loc: 900, bytes: 9000 },
        FileLoc { path: "src/bigger.rs".into(), loc: 1200, bytes: 12000 },
    ];
    let out = oversized_files(&files, 400);
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].file, "src/bigger.rs");
    assert_eq!(out[1].file, "src/big.rs");
    assert_eq!(out[0].class, "runtime");
}

#[test]
fn mechanical_splits_reconstructs_logical_units_above_threshold() {
    let files = vec![
        FileLoc { path: "src/widget_parts/part1.rs".into(), loc: 300, bytes: 3000 },
        FileLoc { path: "src/widget_parts/part2.rs".into(), loc: 300, bytes: 3000 },
        FileLoc { path: "src/widget_parts/part3.rs".into(), loc: 300, bytes: 3000 },
        FileLoc { path: "src/lonely_part.rs".into(), loc: 50, bytes: 500 },
    ];
    let splits = mechanical_splits(&files, 400);
    assert_eq!(splits.len(), 1);
    assert_eq!(splits[0].dir, "src/widget_parts");
    assert_eq!(splits[0].parts, 3);
    assert_eq!(splits[0].logical_loc, 900);
    assert_eq!(splits[0].class, "runtime");

    // Below threshold: no split reported.
    let small = vec![
        FileLoc { path: "src/tiny_parts/part1.rs".into(), loc: 10, bytes: 100 },
        FileLoc { path: "src/tiny_parts/part2.rs".into(), loc: 10, bytes: 100 },
    ];
    assert!(mechanical_splits(&small, 400).is_empty());
}

// =================================================================================================
// audit_store
// =================================================================================================

fn locus(path: &str, start: i64, end: i64) -> EvidenceLocusInput {
    EvidenceLocusInput {
        path: path.to_string(),
        start_line: start,
        end_line: end,
    }
}

#[test]
fn derive_finding_id_is_stable_across_repeated_calls_and_rejects_empty_inputs() {
    let loci = vec![locus("src/lib.rs", 10, 12)];
    let id1 = derive_finding_id("legion", "security.credentials", &loci).unwrap();
    let id2 = derive_finding_id("legion", "security.credentials", &loci).unwrap();
    assert_eq!(id1, id2);
    assert!(id1.starts_with("audit:rule:"));
    assert!(id1.contains("security.credentials:src/lib.rs:"));

    assert!(derive_finding_id("", "rule", &loci).is_err());
    assert!(derive_finding_id("repo", "", &loci).is_err());
    assert!(derive_finding_id("repo", "rule", &[]).is_err());
}

#[test]
fn make_finding_populates_seen_timestamps_and_default_provenance() {
    let draft = FindingDraft {
        repository_id: "legion".to_string(),
        scope_id: "legion".to_string(),
        rule_id: "security.credentials.hardcoded-key".to_string(),
        category: "security".to_string(),
        title: "Hardcoded API key".to_string(),
        evidence_loci: vec![locus("src/db.ts", 1, 1)],
        audit_generation: "gen-1".to_string(),
        ..Default::default()
    };
    let finding = make_finding(&draft, None, None, "open", "2026-09-23T00:00:00Z").unwrap();
    assert_eq!(finding.status, "open");
    assert_eq!(finding.first_seen_at, "2026-09-23T00:00:00Z");
    assert_eq!(finding.last_seen_at, "2026-09-23T00:00:00Z");
    assert_eq!(finding.first_seen_generation, "gen-1");
    assert_eq!(finding.provenance.kind, "deterministic_scanner");
    assert_eq!(finding.provenance.rule_id, "security.credentials.hardcoded-key");
    assert!(finding.supersedes.is_empty());
    assert_eq!(finding.superseded_by, None);
}

#[test]
fn store_upsert_preserves_first_seen_and_refreshes_last_seen() {
    let tmp = std::env::temp_dir().join(format!("legion-wf065-store-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    let mut store = AuditStore::new(&tmp);

    let draft = FindingDraft {
        repository_id: "legion".to_string(),
        scope_id: "legion".to_string(),
        rule_id: "security.credentials.hardcoded-key".to_string(),
        category: "security".to_string(),
        title: "Hardcoded API key".to_string(),
        evidence_loci: vec![locus("src/db.ts", 1, 1)],
        audit_generation: "gen-1".to_string(),
        ..Default::default()
    };
    let f1 = make_finding(&draft, None, None, "open", "2026-09-01T00:00:00Z").unwrap();
    let inserted = store.upsert(f1.clone(), "2026-09-01T00:00:00Z").unwrap();
    assert_eq!(inserted.first_seen_at, "2026-09-01T00:00:00Z");

    let mut f2 = f1.clone();
    f2.audit_generation = "gen-2".to_string();
    f2.last_seen_at = String::new(); // caller did not stamp one; store fills it.
    let refreshed = store.upsert(f2, "2026-09-05T00:00:00Z").unwrap();
    assert_eq!(refreshed.first_seen_at, "2026-09-01T00:00:00Z", "firstSeenAt is preserved");
    assert_eq!(refreshed.last_seen_at, "2026-09-05T00:00:00Z");
    assert_eq!(refreshed.last_seen_generation, "gen-2");
    assert_eq!(refreshed.id, f1.id);

    assert_eq!(store.len().unwrap(), 1);
    let active = store.active(Some("legion")).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(store.active(Some("other-repo")).unwrap().len(), 0);

    // Reload from disk: the JSONL file round-trips.
    let mut reloaded = AuditStore::new(&tmp);
    let loaded = reloaded.get(&f1.id).unwrap().unwrap();
    assert_eq!(loaded.last_seen_generation, "gen-2");

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn store_supersede_retires_old_and_links_successor() {
    let tmp = std::env::temp_dir().join(format!("legion-wf065-store-supersede-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    let mut store = AuditStore::new(&tmp);

    let draft = FindingDraft {
        repository_id: "legion".to_string(),
        scope_id: "legion".to_string(),
        rule_id: "security.credentials.hardcoded-key".to_string(),
        category: "security".to_string(),
        title: "Hardcoded API key".to_string(),
        evidence_loci: vec![locus("src/db.ts", 1, 1)],
        audit_generation: "gen-1".to_string(),
        ..Default::default()
    };
    let old = make_finding(&draft, None, None, "open", "2026-09-01T00:00:00Z").unwrap();
    store.upsert(old.clone(), "2026-09-01T00:00:00Z").unwrap();

    let mut new_draft = draft.clone();
    new_draft.evidence_loci = vec![locus("src/db.ts", 5, 5)];
    new_draft.audit_generation = "gen-2".to_string();
    let new_finding = make_finding(&new_draft, None, None, "open", "2026-09-05T00:00:00Z").unwrap();

    let successor = store.supersede(&old.id, new_finding, "2026-09-05T00:00:00Z").unwrap();
    assert!(successor.supersedes.contains(&old.id));

    let retired = store.get(&old.id).unwrap().unwrap();
    assert_eq!(retired.status, "superseded");
    assert_eq!(retired.superseded_by, Some(successor.id.clone()));

    let active = store.active(None).unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].id, successor.id);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn store_set_status_resolved_and_back_to_open() {
    let tmp = std::env::temp_dir().join(format!("legion-wf065-store-status-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    let mut store = AuditStore::new(&tmp);

    let draft = FindingDraft {
        repository_id: "legion".to_string(),
        scope_id: "legion".to_string(),
        rule_id: "security.credentials.hardcoded-key".to_string(),
        category: "security".to_string(),
        title: "Hardcoded API key".to_string(),
        evidence_loci: vec![locus("src/db.ts", 1, 1)],
        audit_generation: "gen-1".to_string(),
        ..Default::default()
    };
    let f = make_finding(&draft, None, None, "open", "2026-09-01T00:00:00Z").unwrap();
    store.upsert(f.clone(), "2026-09-01T00:00:00Z").unwrap();

    let resolved = store.set_status(&f.id, "resolved", None, "2026-09-02T00:00:00Z").unwrap();
    assert_eq!(resolved.status, "resolved");
    assert!(resolved.resolved_at.is_some());
    assert_eq!(store.active(None).unwrap().len(), 0);

    let reopened = store.set_status(&f.id, "open", None, "2026-09-03T00:00:00Z").unwrap();
    assert_eq!(reopened.status, "open");
    assert_eq!(reopened.resolved_at, None);
    assert_eq!(store.active(None).unwrap().len(), 1);

    // superseded is not a valid set_status target.
    assert!(store.set_status(&f.id, "superseded", None, "2026-09-04T00:00:00Z").is_err());
    assert!(store.set_status("unknown-id", "resolved", None, "2026-09-04T00:00:00Z").is_err());

    let _ = fs::remove_dir_all(&tmp);
}

// =================================================================================================
// audit_verify
// =================================================================================================

#[test]
fn classify_replay_always_excludes_build_and_blocks_project_checks_without_sandbox() {
    let planned: Vec<String> = ["repo", "secrets", "types", "lint", "build"]
        .into_iter()
        .map(String::from)
        .collect();

    let inactive = classify_replay(&planned, false);
    assert_eq!(inactive.replayable, vec!["repo".to_string(), "secrets".to_string()]);
    assert!(inactive.unproven.contains(&"build".to_string()));
    assert!(inactive.unproven.contains(&"types".to_string()));
    assert!(inactive.unproven.contains(&"lint".to_string()));
    assert!(inactive.sandbox_blocked_any);

    let active = classify_replay(&planned, true);
    assert_eq!(
        active.replayable,
        vec!["repo".to_string(), "secrets".to_string(), "types".to_string(), "lint".to_string()]
    );
    assert_eq!(active.unproven, vec!["build".to_string()]);
    assert!(!active.sandbox_blocked_any);
}

#[test]
fn project_execution_checks_names_the_fixed_set() {
    let set = project_execution_checks();
    assert!(set.contains("cargo_unsafe"));
    assert!(!set.contains("secrets"));
    assert!(!set.contains("repo"));
}

#[test]
fn child_env_filters_to_allowlist_then_applies_overrides() {
    let mut parent = BTreeMap::new();
    parent.insert("PATH".to_string(), "/usr/bin".to_string());
    parent.insert("SECRET_TOKEN".to_string(), "sk-leak".to_string());
    parent.insert("HOME".to_string(), "/home/x".to_string());

    let mut overrides = BTreeMap::new();
    overrides.insert("AUDIT_OFFLINE".to_string(), "1".to_string());

    let env = child_env(&parent, &overrides);
    assert_eq!(env.get("PATH"), Some(&"/usr/bin".to_string()));
    assert_eq!(env.get("HOME"), Some(&"/home/x".to_string()));
    assert!(!env.contains_key("SECRET_TOKEN"), "non-allowlisted keys are dropped");
    assert_eq!(env.get("AUDIT_OFFLINE"), Some(&"1".to_string()));
}

#[test]
fn offline_env_overrides_appends_to_existing_maven_gradle_flags() {
    let mut parent = BTreeMap::new();
    parent.insert("MAVEN_ARGS".to_string(), "-q".to_string());
    let overrides = offline_env_overrides(&parent);
    assert_eq!(overrides.get("MAVEN_ARGS"), Some(&"-q -o".to_string()));
    assert_eq!(overrides.get("AUDIT_OFFLINE"), Some(&"1".to_string()));
    assert_eq!(overrides.get("GOPROXY"), Some(&"off".to_string()));

    let empty_parent = BTreeMap::new();
    let overrides2 = offline_env_overrides(&empty_parent);
    assert_eq!(overrides2.get("GRADLE_OPTS"), Some(&"-Dorg.gradle.offline=true".to_string()));
}

#[test]
fn allowed_child_keys_does_not_include_arbitrary_secrets() {
    let allowed = allowed_child_keys();
    assert!(allowed.contains("PATH"));
    assert!(!allowed.contains("OPENAI_API_KEY"));
    assert!(!allowed.contains("SECRET_TOKEN"));
}

#[test]
fn checks_match_compares_status_and_findings_count() {
    let a = CheckResult { check: "secrets".into(), status: "ran".into(), findings_count: Some(0) };
    let b = CheckResult { check: "secrets".into(), status: "ran".into(), findings_count: Some(0) };
    let c = CheckResult { check: "secrets".into(), status: "ran".into(), findings_count: Some(1) };
    assert!(checks_match(Some(&a), Some(&b)));
    assert!(!checks_match(Some(&a), Some(&c)));
    assert!(!checks_match(Some(&a), None));
}

#[test]
fn normalize_checks_sorts_and_projects_and_result_digest_is_stable() {
    let checks = vec![
        CheckResult { check: "types".into(), status: "ran".into(), findings_count: Some(0) },
        CheckResult { check: "repo".into(), status: "ran".into(), findings_count: None },
    ];
    let normalized = normalize_checks(&checks);
    assert_eq!(normalized[0].check, "repo");
    assert_eq!(normalized[1].check, "types");

    let digest1 = result_digest(&checks).unwrap();
    let mut reordered = checks.clone();
    reordered.reverse();
    let digest2 = result_digest(&reordered).unwrap();
    assert_eq!(digest1, digest2, "digest is order-insensitive over the check list");

    let mut mutated = checks.clone();
    mutated[0].findings_count = Some(5);
    let digest3 = result_digest(&mutated).unwrap();
    assert_ne!(digest1, digest3);
}

#[test]
fn frozen_contracts_match_ignores_unrelated_fields_but_detects_provider_drift() {
    let prior = serde_json::json!({
        "generatedAt": "2026-01-01T00:00:00Z",
        "binding": { "registryDigest": "sha256:aaa" },
        "denominator": { "providerIds": ["p1"] },
        "providers": [{ "id": "p1", "runner": {"kind": "x"}, "denominator": {}, "benchmark": {} }],
        "coverageFamilies": ["security"],
    });
    let mut recomputed = prior.clone();
    recomputed["generatedAt"] = serde_json::json!("2026-02-02T00:00:00Z");
    assert!(frozen_contracts_match(&prior, &recomputed), "unrelated field must not create drift");

    let mut drifted = prior.clone();
    drifted["providers"][0]["denominator"] = serde_json::json!({ "expectedChecks": ["lint"] });
    assert!(!frozen_contracts_match(&prior, &drifted), "provider contract drift must be detected");
}

// =================================================================================================
// provider_benchmarks
// =================================================================================================

fn fixtures_doc() -> FixturesDoc {
    FixturesDoc {
        schema_version: 1,
        kind: "audit-benchmark-fixtures".to_string(),
        cases: vec![
            FixtureCase {
                id: "case-hit".into(),
                file: "src/db.ts".into(),
                text: "const API_KEY = \"sk-1234\";\n".into(),
                expected: vec![ExpectedFinding { rule_id: "security.credentials.hardcoded-key".into(), line: 1, file: None }],
            },
            FixtureCase {
                id: "case-miss".into(),
                file: "src/auth.ts".into(),
                text: "const PASSWORD = \"hunter2\";\n".into(),
                expected: vec![ExpectedFinding { rule_id: "security.credentials.hardcoded-key".into(), line: 1, file: None }],
            },
            FixtureCase {
                id: "case-clean".into(),
                file: "src/util.ts".into(),
                text: "export const sum = (a, b) => a + b;\n".into(),
                expected: vec![],
            },
        ],
    }
}

fn binding_for() -> ProviderBinding {
    ProviderBinding {
        implementation_digests: vec![Binding {
            path: "src/providers/pack.mjs".into(),
            digest: format!("sha256:{}", "a".repeat(64)),
        }],
        rule_pack_digests: vec![Binding {
            path: "src/providers/security/packs/credentials.mjs".into(),
            digest: format!("sha256:{}", "b".repeat(64)),
        }],
    }
}

fn runner_detects_first_file_only(case: &FixtureCase) -> legion_audit::wf_port::wf065::provider_benchmarks::Result<Vec<RawCandidate>> {
    if !case.text.contains("API_KEY") {
        return Ok(vec![]);
    }
    Ok(vec![RawCandidate {
        rule_id: Some("security.credentials.hardcoded-key".to_string()),
        file: Some(case.file.clone()),
        line: Some(1),
    }])
}

#[test]
fn fixtures_validation_counts_clean_vs_planted_cases() {
    let doc = fixtures_doc();
    let stats = legion_audit::wf_port::wf065::provider_benchmarks::validate_fixtures(&doc).unwrap();
    assert_eq!(stats.case_count, 3);
    assert_eq!(stats.planted_finding_count, 2);
    assert_eq!(stats.clean_case_count, 1);
}

#[test]
fn fixture_digest_is_order_insensitive_and_content_bound() {
    let doc = fixtures_doc();
    let mut reordered = doc.clone();
    reordered.cases.reverse();
    assert_eq!(
        compute_fixtures_digest(&doc).unwrap(),
        compute_fixtures_digest(&reordered).unwrap()
    );
    let mut mutated = doc.clone();
    mutated.cases[0].text = "changed".to_string();
    assert_ne!(
        compute_fixtures_digest(&doc).unwrap(),
        compute_fixtures_digest(&mutated).unwrap()
    );
}

#[test]
fn measure_fixture_set_reports_missed_recall_without_synthesizing() {
    let provider = ProviderIdentity { id: "security.credentials".into(), version: "1".into(), rule_pack: None };
    let result = measure_fixture_set(
        &provider,
        &binding_for(),
        |c| runner_detects_first_file_only(c),
        &fixtures_doc(),
        "2026-07-21T00:00:00.000Z",
    )
    .unwrap();
    assert_eq!(result.metrics.true_positives, 1);
    assert_eq!(result.metrics.false_positives, 0);
    assert_eq!(result.metrics.false_negatives, 1);
    assert_eq!(result.metrics.precision, 1.0);
    assert_eq!(result.metrics.recall, 0.5);
}

#[test]
fn measure_fixture_set_perfect_detection_yields_precision_and_recall_of_one() {
    let provider = ProviderIdentity { id: "p.perfect".into(), version: "1".into(), rule_pack: None };
    let result = measure_fixture_set(
        &provider,
        &binding_for(),
        |c| {
            if c.text.contains("API_KEY") || c.text.contains("PASSWORD") {
                Ok(vec![RawCandidate {
                    rule_id: Some("security.credentials.hardcoded-key".to_string()),
                    file: Some(c.file.clone()),
                    line: Some(1),
                }])
            } else {
                Ok(vec![])
            }
        },
        &fixtures_doc(),
        "2026-07-21T00:00:00.000Z",
    )
    .unwrap();
    assert_eq!(result.metrics.true_positives, 2);
    assert_eq!(result.metrics.false_positives, 0);
    assert_eq!(result.metrics.false_negatives, 0);
    assert_eq!(result.metrics.precision, 1.0);
    assert_eq!(result.metrics.recall, 1.0);
}

#[test]
fn measure_fixture_set_zero_denominators_error_instead_of_synthesizing() {
    let empty_truth = FixturesDoc {
        schema_version: 1,
        kind: "audit-benchmark-fixtures".to_string(),
        cases: vec![FixtureCase {
            id: "clean-only".into(),
            file: "a.ts".into(),
            text: "x\n".into(),
            expected: vec![],
        }],
    };
    let provider = ProviderIdentity { id: "p".into(), version: "1".into(), rule_pack: None };
    let no_candidates = measure_fixture_set(&provider, &binding_for(), |_| Ok(vec![]), &empty_truth, "t");
    assert!(no_candidates.unwrap_err().to_string().contains("precision is undefined"));

    let with_fp = measure_fixture_set(
        &provider,
        &binding_for(),
        |c| Ok(vec![RawCandidate { rule_id: Some("r.x".into()), file: Some(c.file.clone()), line: Some(1) }]),
        &empty_truth,
        "t",
    );
    assert!(with_fp.unwrap_err().to_string().contains("recall is undefined"));
}

#[test]
fn measure_fixture_set_propagates_runner_failure_and_malformed_candidates() {
    let provider = ProviderIdentity { id: "p".into(), version: "1".into(), rule_pack: None };
    let failed = measure_fixture_set(
        &provider,
        &binding_for(),
        |_| Err(legion_audit::wf_port::wf065::provider_benchmarks::BenchmarkError::Invalid("boom".into())),
        &fixtures_doc(),
        "t",
    );
    assert!(failed.unwrap_err().to_string().contains("failed on fixture case"));

    let malformed = measure_fixture_set(
        &provider,
        &binding_for(),
        |_| Ok(vec![RawCandidate { rule_id: Some("r.x".into()), file: None, line: None }]),
        &fixtures_doc(),
        "t",
    );
    assert!(malformed.unwrap_err().to_string().contains("unlocatable candidate"));
}

#[test]
fn qualification_digest_is_stable_and_changes_with_evidence() {
    let provider = ProviderIdentity { id: "security.credentials".into(), version: "1".into(), rule_pack: None };
    let first = measure_fixture_set(&provider, &binding_for(), runner_detects_first_file_only, &fixtures_doc(), "2026-07-21T00:00:00.000Z").unwrap();
    let again = measure_fixture_set(&provider, &binding_for(), runner_detects_first_file_only, &fixtures_doc(), "2026-07-21T00:00:00.000Z").unwrap();
    assert_eq!(first.qualification_digest, again.qualification_digest);
    assert_eq!(first.qualification_digest, result_qualification_digest(&first).unwrap());

    let mut drifted = first.clone();
    drifted.metrics.recall = 0.75;
    assert_ne!(
        result_qualification_digest(&first).unwrap(),
        result_qualification_digest(&drifted).unwrap()
    );
}

#[test]
fn freshness_binds_results_to_implementation_and_rule_pack_digests() {
    let provider = ProviderIdentity { id: "security.credentials".into(), version: "1".into(), rule_pack: None };
    let result = measure_fixture_set(&provider, &binding_for(), runner_detects_first_file_only, &fixtures_doc(), "2026-07-21T00:00:00.000Z").unwrap();
    assert!(is_result_fresh(&result, &binding_for()));

    let mut other_pack = binding_for();
    other_pack.rule_pack_digests[0].path = "src/providers/security/packs/injection.mjs".to_string();
    assert!(!is_result_fresh(&result, &other_pack));

    let mut tampered = result.clone();
    tampered.binding.rule_pack_digests[0].digest = format!("sha256:{}", "c".repeat(64));
    assert!(!is_result_fresh(&tampered, &binding_for()));

    let mut unbound = result.clone();
    unbound.binding.implementation_digests.clear();
    unbound.binding.rule_pack_digests.clear();
    assert!(!is_result_fresh(&unbound, &ProviderBinding::default()));
}

#[test]
fn measured_providers_are_distinguished_from_unmeasured_with_plan_shaped_gaps() {
    let provider = ProviderIdentity { id: "security.credentials".into(), version: "1".into(), rule_pack: None };
    let fresh = measure_fixture_set(&provider, &binding_for(), runner_detects_first_file_only, &fixtures_doc(), "2026-07-21T00:00:00.000Z").unwrap();

    let mut stale = fresh.clone();
    stale.provider.id = "security.injection".to_string();
    stale.measured_at = "2026-07-20T00:00:00.000Z".to_string();
    stale.binding.implementation_digests[0].digest = format!("sha256:{}", "d".repeat(64));

    let mut current_by_provider = BTreeMap::new();
    current_by_provider.insert("security.credentials".to_string(), binding_for());
    current_by_provider.insert("security.injection".to_string(), binding_for());

    let qualification = qualification_from_results(
        &[fresh, stale],
        &current_by_provider,
        &["legacy.security.binary-pins".to_string()],
    );
    assert_eq!(qualification.records["security.credentials"].status, "measured");
    assert!(qualification.records["security.credentials"]
        .qualification_digest
        .as_deref()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(
        qualification.records["legacy.security.binary-pins"].status,
        "unproven"
    );
    let mut unmeasured = qualification.unmeasured_providers.clone();
    unmeasured.sort();
    assert_eq!(
        unmeasured,
        vec!["legacy.security.binary-pins".to_string(), "security.injection".to_string()]
    );
    for gap in &qualification.benchmark_gaps {
        assert_eq!(gap.kind, UNMEASURED_GAP_KIND);
    }
    assert!(!qualification.precision_measured);
}

#[test]
fn compute_provider_binding_digests_real_files_and_fails_cleanly() {
    let tmp = std::env::temp_dir().join(format!("legion-wf065-bench-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    fs::write(tmp.join("engine.mjs"), "export const engine = true;\n").unwrap();
    fs::write(tmp.join("pack.mjs"), "export const rules = [];\n").unwrap();

    let provider = legion_audit::wf_port::wf065::provider_benchmarks::Provider {
        id: "security.credentials".into(),
        runner: legion_audit::wf_port::wf065::provider_benchmarks::ProviderRunner {
            script: Some("engine.mjs".into()),
            module: Some("pack.mjs".into()),
        },
    };
    let binding = legion_audit::wf_port::wf065::provider_benchmarks::compute_provider_binding(&provider, &tmp).unwrap();
    assert_eq!(binding.implementation_digests[0].path, "engine.mjs");
    assert_eq!(binding.implementation_digests[0].digest, digest_file(&tmp.join("engine.mjs")).unwrap());
    assert_eq!(binding.rule_pack_digests[0].path, "pack.mjs");

    let no_impl = legion_audit::wf_port::wf065::provider_benchmarks::Provider {
        id: "x".into(),
        runner: legion_audit::wf_port::wf065::provider_benchmarks::ProviderRunner { script: None, module: None },
    };
    assert!(legion_audit::wf_port::wf065::provider_benchmarks::compute_provider_binding(&no_impl, &tmp)
        .unwrap_err()
        .to_string()
        .contains("no measurable implementation"));

    assert!(file_bindings(&["missing.mjs".to_string()], &tmp)
        .unwrap_err()
        .to_string()
        .contains("missing on disk"));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn benchmark_record_for_falls_back_to_unmeasured_when_stale() {
    let provider = ProviderIdentity { id: "security.credentials".into(), version: "1".into(), rule_pack: None };
    let result = measure_fixture_set(&provider, &binding_for(), runner_detects_first_file_only, &fixtures_doc(), "2026-07-21T00:00:00.000Z").unwrap();
    let record = benchmark_record_for(&result, &binding_for());
    assert_eq!(record.status, "measured");
    // `isResultFresh` (`tools/audit/provider-benchmarks.mjs`) only compares
    // against `current` when `current`'s own lists are non-empty — an
    // empty/default `current` is "uncomparable" and is ignored, not
    // treated as stale (see that file's doc comment and
    // `tests/audit-provider-benchmarks.test.mjs`'s own staleness case,
    // which mutates a digest rather than passing an empty binding). So a
    // genuinely stale binding needs a differing recorded digest.
    let mut mismatched = binding_for();
    mismatched.implementation_digests[0].digest = format!("sha256:{}", "d".repeat(64));
    let stale_record = benchmark_record_for(&result, &mismatched);
    assert_eq!(stale_record.status, "unproven");
    assert_eq!(stale_record.qualification_digest, None);
}

// =================================================================================================
// provider_benchmarks CLI (verify/status — the fs+JSON-only subset of the
// legacy `measure|verify|status` CLI; `measure` needs a dynamic JS import
// and has no Rust equivalent, see provider_benchmarks.rs's CLI section doc).
// =================================================================================================

use legion_audit::wf_port::wf065::provider_benchmarks::{
    cmd_status, cmd_verify, parse_current_binding_file, run_cli, BenchmarkResult,
};

fn write_results_doc(path: &std::path::Path, result: &BenchmarkResult) {
    let doc = serde_json::json!({
        "schemaVersion": 1,
        "kind": "audit-provider-benchmark-results",
        "generatedAt": "2026-07-21T00:00:00.000Z",
        "results": [result],
    });
    fs::write(path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
}

#[test]
fn cmd_verify_counts_results_and_freshness_against_root() {
    let tmp = std::env::temp_dir().join(format!("legion-wf065-cli-verify-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    fs::write(tmp.join("engine.mjs"), "export const engine = true;\n").unwrap();
    fs::write(tmp.join("pack.mjs"), "export const rules = [];\n").unwrap();

    let provider = ProviderIdentity { id: "security.credentials".into(), version: "1".into(), rule_pack: None };
    let binding = ProviderBinding {
        implementation_digests: file_bindings(&["engine.mjs".to_string()], &tmp).unwrap(),
        rule_pack_digests: file_bindings(&["pack.mjs".to_string()], &tmp).unwrap(),
    };
    let result = measure_fixture_set(&provider, &binding, runner_detects_first_file_only, &fixtures_doc(), "2026-07-21T00:00:00.000Z").unwrap();
    let results_path = tmp.join("results.json");
    write_results_doc(&results_path, &result);

    // No root: just counts results, no freshness field.
    let report = cmd_verify(&results_path, None).unwrap();
    assert!(report.valid);
    assert_eq!(report.results, 1);
    assert_eq!(report.fresh, None);

    // With root: the on-disk files match the recorded digests exactly => fresh.
    let report = cmd_verify(&results_path, Some(&tmp)).unwrap();
    assert_eq!(report.fresh, Some(1));

    // Mutate a bound file so its digest no longer matches => not fresh.
    fs::write(tmp.join("engine.mjs"), "export const engine = false; // changed\n").unwrap();
    let report = cmd_verify(&results_path, Some(&tmp)).unwrap();
    assert_eq!(report.fresh, Some(0));

    // run_cli wires the same path end-to-end and prints valid JSON to stdout.
    let argv = vec![
        "verify".to_string(),
        "--results".to_string(),
        results_path.to_string_lossy().to_string(),
    ];
    assert_eq!(run_cli(&argv), 0);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn cmd_status_reports_unmeasured_providers_and_matching_exit_code() {
    let tmp = std::env::temp_dir().join(format!("legion-wf065-cli-status-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let provider = ProviderIdentity { id: "security.credentials".into(), version: "1".into(), rule_pack: None };
    let result = measure_fixture_set(&provider, &binding_for(), runner_detects_first_file_only, &fixtures_doc(), "2026-07-21T00:00:00.000Z").unwrap();
    let doc = serde_json::json!({
        "schemaVersion": 1,
        "kind": "audit-provider-benchmark-results",
        "results": [result],
    });
    let results_json = serde_json::to_string(&doc).unwrap();

    // Required id is measured and its current binding matches => exit 0.
    let mut current = BTreeMap::new();
    current.insert("security.credentials".to_string(), binding_for());
    let report = cmd_status(&results_json, &["security.credentials".to_string()], &current).unwrap();
    assert_eq!(report.exit_code, 0);
    assert!(report.qualification.unmeasured_providers.is_empty());

    // A required id with no result at all is unmeasured => exit 1.
    let report = cmd_status(
        &results_json,
        &["security.credentials".to_string(), "security.injection".to_string()],
        &current,
    )
    .unwrap();
    assert_eq!(report.exit_code, 1);
    assert_eq!(report.qualification.unmeasured_providers, vec!["security.injection".to_string()]);

    // run_cli end-to-end via files, including --current-binding parsing.
    let results_path = tmp.join("results.json");
    fs::write(&results_path, &results_json).unwrap();
    let binding_path = tmp.join("bindings.json");
    fs::write(
        &binding_path,
        serde_json::to_string(&serde_json::json!({ "byProvider": { "security.credentials": binding_for() } })).unwrap(),
    )
    .unwrap();
    let argv = vec![
        "status".to_string(),
        "--results".to_string(),
        results_path.to_string_lossy().to_string(),
        "--require".to_string(),
        "security.credentials".to_string(),
        "--current-binding".to_string(),
        binding_path.to_string_lossy().to_string(),
    ];
    assert_eq!(run_cli(&argv), 0);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn parse_current_binding_file_accepts_by_provider_and_bare_shapes() {
    let by_provider = serde_json::json!({ "byProvider": { "p1": binding_for() } });
    let parsed = parse_current_binding_file(&serde_json::to_string(&by_provider).unwrap()).unwrap();
    assert!(parsed.contains_key("p1"));

    let bare = serde_json::json!({ "p2": binding_for() });
    let parsed = parse_current_binding_file(&serde_json::to_string(&bare).unwrap()).unwrap();
    assert!(parsed.contains_key("p2"));

    assert!(parse_current_binding_file("[]").is_err());
}

#[test]
fn run_cli_measure_reports_unsupported_and_unknown_command_is_usage_error() {
    assert_eq!(run_cli(&["measure".to_string()]), 2);
    assert_eq!(run_cli(&["bogus".to_string()]), 2);
    assert_eq!(run_cli(&[]), 2);
}

// =================================================================================================
// collect_facts: detect() + prune_old_runs (fs-only, no spawned process).
// =================================================================================================

#[test]
fn detect_reads_stack_markers_from_a_real_temp_workspace() {
    let tmp = std::env::temp_dir().join(format!("legion-wf065-detect-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(tmp.join("src-tauri")).unwrap();
    fs::write(tmp.join("package.json"), r#"{"scripts":{"build":"tsc"},"dependencies":{"react":"18.0.0"}}"#).unwrap();
    fs::write(tmp.join("pnpm-lock.yaml"), "lockfileVersion: '9.0'\n").unwrap();
    fs::write(tmp.join("tsconfig.json"), "{}").unwrap();
    fs::write(tmp.join("eslint.config.mjs"), "export default [];\n").unwrap();
    fs::write(tmp.join("src-tauri/Cargo.toml"), "[package]\nname=\"x\"\n").unwrap();
    fs::write(tmp.join("src-tauri/tauri.conf.json"), "{}").unwrap();
    fs::create_dir_all(tmp.join(".git")).unwrap();

    let d = detect(&tmp);
    assert!(d.git);
    assert!(d.node);
    assert_eq!(d.pkg_mgr, "pnpm");
    assert!(d.ts);
    assert!(!d.py);
    assert!(d.rust);
    assert_eq!(d.rust_dir.as_deref(), Some("src-tauri"));
    assert!(d.tauri);
    assert!(d.build_script);
    assert!(d.eslint);
    assert!(!d.biome);
    assert_eq!(
        d.pkg.as_ref().and_then(|p| p.get("dependencies")).and_then(|d| d.get("react")).and_then(|v| v.as_str()),
        Some("18.0.0")
    );

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn detect_defaults_to_npm_and_no_node_without_package_json() {
    let tmp = std::env::temp_dir().join(format!("legion-wf065-detect-bare-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let d = detect(&tmp);
    assert!(!d.node);
    assert!(d.pkg.is_none());
    assert_eq!(d.pkg_mgr, "npm");
    assert!(!d.rust);
    assert_eq!(d.rust_dir, None);
    assert!(!d.tauri);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn in_git_worktree_walks_up_to_a_parent_git_dir() {
    let tmp = std::env::temp_dir().join(format!("legion-wf065-gitwalk-{}", std::process::id()));
    let sub = tmp.join("a/b/c");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&sub).unwrap();
    fs::create_dir_all(tmp.join(".git")).unwrap();

    assert!(in_git_worktree(&sub));

    // Immediately under `.git`'s own directory: also found (depth 0).
    assert!(in_git_worktree(&tmp));

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn is_run_dir_name_matches_only_the_iso_timestamp_shape() {
    assert!(is_run_dir_name("2026-07-21T00-00-00-000Z"));
    assert!(!is_run_dir_name("2026-07-21"));
    assert!(!is_run_dir_name("audit"));
    assert!(!is_run_dir_name("2026-07-21T00-00-00-000Z-extra"));
}

#[test]
fn prune_old_runs_keeps_newest_n_and_never_deletes_the_current_run() {
    let tmp = std::env::temp_dir().join(format!("legion-wf065-prune-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    let runs = [
        "2026-01-01T00-00-00-000Z",
        "2026-01-02T00-00-00-000Z",
        "2026-01-03T00-00-00-000Z",
    ];
    for r in runs {
        fs::create_dir_all(tmp.join(r)).unwrap();
    }
    // A non-matching entry (e.g. a persistent store dir) must never be touched.
    fs::create_dir_all(tmp.join("audit")).unwrap();

    // keep=1, current is the OLDEST run: it survives even though it would
    // otherwise be pruned, and only the newest-besides-current is kept too
    // per the JS `slice(Math.max(keep,1))` + `name === currentTs` skip.
    prune_old_runs(&tmp, "2026-01-01T00-00-00-000Z", 1);

    assert!(tmp.join("2026-01-03T00-00-00-000Z").exists(), "newest kept");
    assert!(tmp.join("2026-01-01T00-00-00-000Z").exists(), "current run never deleted");
    assert!(!tmp.join("2026-01-02T00-00-00-000Z").exists(), "middle run pruned");
    assert!(tmp.join("audit").exists(), "non-run-shaped dir untouched");

    let _ = fs::remove_dir_all(&tmp);
}
