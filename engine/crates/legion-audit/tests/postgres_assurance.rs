//! A10 acceptance coverage for PostgreSQL migration safety and workload
//! evidence. Authored, never run by the packet worker — root executes.
//! Requires root to add `pub mod postgres;` to
//! `native_providers/architecture/mod.rs`.

use legion_audit::artifact_evidence::{
    ImportKind, ImportVerdict, ImportedEvidenceRecord,
};
use legion_audit::native_providers::architecture::postgres::{
    analyze_postgres, assess_evidence, discovered_database_fingerprints, host_fingerprint,
    MigrationPhase, PostgresContext, PostgresExpectation, PostgresSourceFile,
    CONCERN_BACKUP_RESTORE, CONCERN_CONTENTION, CONCERN_EXPLAIN_PLAN, CONCERN_ISOLATED_MIGRATION,
    CONCERN_WORKLOAD_MEASURED,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/postgres-assurance")
}

fn collect(dir: &Path, prefix: &str, out: &mut Vec<PostgresSourceFile>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .expect("fixture dir")
        .map(|e| e.expect("entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let rel = format!("{prefix}/{name}");
        if path.is_dir() {
            collect(&path, &rel, out);
        } else {
            out.push(PostgresSourceFile {
                path: rel,
                text: fs::read_to_string(&path).expect("fixture text"),
            });
        }
    }
}

fn load(sub: &str) -> Vec<PostgresSourceFile> {
    let mut out = Vec::new();
    collect(&root().join(sub), sub, &mut out);
    out
}

fn sql(path: &str, text: &str) -> PostgresSourceFile {
    PostgresSourceFile { path: path.into(), text: text.into() }
}

fn rules(a: &legion_audit::native_providers::architecture::postgres::PostgresAnalysis) -> BTreeSet<String> {
    a.findings.iter().map(|f| f.rule.clone()).collect()
}

#[test]
fn broken_migrations_report_version_aware_defects_and_never_complete() {
    let a = analyze_postgres(&load("broken"), &PostgresContext::default());
    let found = rules(&a);
    for rule in [
        "index-build-blocks-writes",
        "add-column-table-rewrite",
        "migration-later-object-order",
        "set-not-null-full-scan",
        "constraint-validates-under-lock",
        "non-transactional-statement-in-transaction",
        "definer-searchpath-unpinned",
        "permissive-rls-policy",
        "destructive-change-unclassified",
    ] {
        assert!(found.contains(rule), "missing {rule}; got {found:?}");
    }
    assert_eq!(a.facts["serverMajor"], json!(15));
    // Production cardinality is never inferable from source.
    assert!(a.gaps.iter().any(|g| g.starts_with("table-cardinality-unknown:")));
    assert!(a.gaps.iter().any(|g| g.starts_with("lock-timeout-unset:")));
    assert!(!a.into_analysis().complete);
}

#[test]
fn legitimate_expand_contract_sequence_has_no_findings_or_gaps() {
    let mut ctx = PostgresContext {
        server_major: Some(15),
        search_path: Some(vec!["public".into()]),
        lock_timeout_declared: true,
        ..Default::default()
    };
    ctx.baseline_tables.insert("customers".into());
    let contract = "valid/supabase/migrations/20240301000000_contract.sql";
    ctx.phases.insert(contract.into(), MigrationPhase::Contract);
    ctx.contract_compat_verified.insert(contract.into());
    ctx.transaction_wrapped
        .insert("valid/supabase/migrations/20240201000000_expand.sql".into(), false);
    let a = analyze_postgres(&load("valid"), &ctx);
    assert!(a.findings.is_empty(), "{:?}", a.findings);
    assert!(a.gaps.is_empty(), "{:?}", a.gaps);
    assert!(a.into_analysis().complete);
}

#[test]
fn contract_without_compat_evidence_and_unspecified_destruction_are_findings() {
    let mut ctx = PostgresContext { server_major: Some(15), search_path: Some(vec![]), lock_timeout_declared: true, ..Default::default() };
    ctx.baseline_tables.insert("customers".into());
    let path = "valid/supabase/migrations/20240301000000_contract.sql";
    ctx.phases.insert(path.into(), MigrationPhase::Contract);
    let a = analyze_postgres(&load("valid"), &ctx);
    assert!(rules(&a).contains("contract-step-without-compat-evidence"));
    ctx.phases.insert(path.into(), MigrationPhase::Expand);
    let a = analyze_postgres(&load("valid"), &ctx);
    assert!(rules(&a).contains("destructive-in-expand-phase"));
}

#[test]
fn version_gated_syntax_is_a_defect_only_on_old_targets() {
    let files = [sql(
        "db/migrations/20240101_idx.sql",
        "create table public.t (a int, b int);\ncreate index idx on public.t (a) include (b);\n",
    )];
    let old = PostgresContext { server_major: Some(10), search_path: Some(vec![]), lock_timeout_declared: true, ..Default::default() };
    assert!(rules(&analyze_postgres(&files, &old)).contains("syntax-unsupported-by-target-version"));
    let new = PostgresContext { server_major: Some(15), ..old.clone() };
    assert!(!rules(&analyze_postgres(&files, &new)).contains("syntax-unsupported-by-target-version"));
    // Unknown version is a gap, not a clean pass.
    let unknown = PostgresContext { server_major: None, ..old };
    let a = analyze_postgres(&files, &unknown);
    assert!(a.gaps.iter().any(|g| g.starts_with("postgres-version-unknown")));
}

#[test]
fn add_column_default_is_rewrite_before_11_but_not_after() {
    let files = [
        sql("db/migrations/1_init.sql", "create table public.t (id int);\n"),
        sql("db/migrations/2_add.sql", "alter table public.t add column flag boolean default false;\n"),
    ];
    let ctx = |v| PostgresContext { server_major: Some(v), search_path: Some(vec![]), lock_timeout_declared: true, ..Default::default() };
    assert!(rules(&analyze_postgres(&files, &ctx(10))).contains("add-column-table-rewrite"));
    assert!(!rules(&analyze_postgres(&files, &ctx(15))).contains("add-column-table-rewrite"));
}

#[test]
fn missing_concurrently_and_missing_down_migration_are_not_automatic_defects() {
    let files = [
        sql("db/migrations/1_init.sql", "create table public.t (id int);\ncreate index t_id on public.t (id);\n"),
    ];
    let ctx = PostgresContext { server_major: Some(15), search_path: Some(vec![]), lock_timeout_declared: true, ..Default::default() };
    let a = analyze_postgres(&files, &ctx);
    assert!(a.findings.is_empty(), "{:?}", a.findings);
}

#[test]
fn concurrently_without_known_transaction_scope_is_a_gap_and_wrapped_runner_is_a_defect() {
    let files = [sql(
        "db/migrations/1_idx.sql",
        "create index concurrently i on public.t (id);\nselect 1;\n",
    )];
    let mut ctx = PostgresContext { server_major: Some(15), search_path: Some(vec![]), lock_timeout_declared: true, ..Default::default() };
    ctx.baseline_tables.insert("t".into());
    let a = analyze_postgres(&files, &ctx);
    assert!(a.gaps.iter().any(|g| g.starts_with("transaction-wrapper-unknown")));
    assert!(!rules(&a).contains("non-transactional-statement-in-transaction"));
    ctx.transaction_wrapped.insert("db/migrations/1_idx.sql".into(), true);
    assert!(rules(&analyze_postgres(&files, &ctx)).contains("non-transactional-statement-in-transaction"));
}

#[test]
fn dynamic_sql_and_nonsql_frameworks_are_gaps_and_down_sections_are_ignored() {
    let a = analyze_postgres(&load("dynamic"), &PostgresContext::default());
    assert!(a.gaps.iter().any(|g| g.starts_with("dynamic-sql:")));
    assert!(!a.clone().into_analysis().complete);

    let goose = sql(
        "db/migrations/20240101_x.sql",
        "-- +goose Up\ncreate table public.t (id int);\n-- +goose Down\ndrop table public.t;\n",
    );
    let ctx = PostgresContext { server_major: Some(15), search_path: Some(vec![]), lock_timeout_declared: true, ..Default::default() };
    assert!(analyze_postgres(&[goose], &ctx).findings.is_empty());

    let rails = sql("db/migrate/20240101_add.rb", "class Add < ActiveRecord::Migration[7.0]; end");
    let a = analyze_postgres(&[rails], &ctx);
    assert!(a.gaps.iter().any(|g| g.starts_with("migration-framework-nonsql:")));
}

#[test]
fn duplicate_versions_and_unknown_schema_are_explicit() {
    let ctx = PostgresContext { server_major: Some(15), search_path: Some(vec![]), lock_timeout_declared: true, ..Default::default() };
    let files = [
        sql("db/migrations/20240101_a.sql", "create table public.a (id int);\n"),
        sql("db/migrations/20240101_b.sql", "create table public.b (id int);\n"),
        sql("db/migrations/20240102_c.sql", "alter table public.unknown_t add column x int;\n"),
    ];
    let a = analyze_postgres(&files, &ctx);
    assert!(rules(&a).contains("duplicate-migration-version"));
    assert!(a.gaps.iter().any(|g| g.starts_with("object-origin-unknown")));
}

#[test]
fn database_urls_are_fingerprinted_never_retained() {
    let set = discovered_database_fingerprints(
        "DATABASE_URL=postgres://user:secret@prod-db.example.com:5432/app?sslmode=require",
    );
    assert_eq!(set.len(), 1);
    let fp = set.iter().next().unwrap();
    assert!(!fp.contains("secret") && !fp.contains("prod-db"));
    assert_eq!(*fp, host_fingerprint("prod-db.example.com:5432", "app"));
}

// ------------------------------------------------------------ evidence

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn good_facts(concern: &str) -> Value {
    json!({
        "schemaVersion": 1,
        "concern": concern,
        "target": {
            "kind": "scratch", "isolationAttested": true,
            "hostFingerprint": host_fingerprint("scratch.internal:5432", "audit"),
            "roleSuperuser": false, "roleRestricted": true,
            "statementTimeoutMs": 10000, "lockTimeoutMs": 2000
        },
        "postgresVersionMajor": 15, "postgresVersionFull": "15.4",
        "schemaDigest": "sha256:aa", "indexSetDigest": "sha256:bb", "migrationHead": "20240301000000",
        "migration": {"applied": ["20240101000000"], "failedStatements": 0},
        "plan": {"explain": true, "analyze": true, "queryIds": ["q1"]},
        "workload": {
            "readOps": 1000, "writeOps": 200, "durationMs": 60000,
            "dataDistributionDigest": "sha256:cc", "rowCounts": {"customers": 100000},
            "queries": [{"id": "q1", "paramsDigest": "sha256:dd", "executions": 900}],
            "denominatorAttested": true
        },
        "contention": {"measured": true, "concurrentSessions": 8, "lockWaitMsMax": 40, "deadlocks": 0},
        "restore": {
            "restored": true, "backupDigest": "sha256:ee", "verifiedInvariants": ["fk-customers-orders"],
            "rowCountsMatch": true, "representativeSampleDigest": "sha256:ff", "rowCounts": {"customers": 100000}
        }
    })
}

fn verdict(kind: ImportKind, bytes: &[u8], newly_executed: bool) -> ImportVerdict {
    let record: ImportedEvidenceRecord = serde_json::from_value(json!({
        "schemaVersion": 1, "evidenceId": "ev-1", "claimsDigest": "sha256:00",
        "kind": serde_json::to_value(kind).unwrap(), "authenticated": true,
        "attestor": "ci", "trustRootId": "root", "verifierId": "v",
        "outcome": "passed", "repositories": [], "target": "db", "toolchain": "pg15",
        "artifacts": [], "artifactDigest": digest(bytes), "denominatorDigest": "sha256:11",
        "examinedScope": [], "missingScope": [], "newlyExecuted": newly_executed,
        "issuedAt": "2024-01-01T00:00:00Z", "freshUntil": "2099-01-01T00:00:00Z"
    }))
    .expect("record");
    ImportVerdict { authenticated: true, satisfies_obligation: true, reasons: vec![], record: Some(record) }
}

fn expectation() -> PostgresExpectation {
    PostgresExpectation {
        postgres_major: Some(15),
        schema_digest: Some("sha256:aa".into()),
        index_set_digest: Some("sha256:bb".into()),
        migration_head: Some("20240301000000".into()),
        required_query_ids: ["q1".to_owned()].into(),
        required_invariants: ["fk-customers-orders".to_owned()].into(),
        min_concurrent_sessions: 4,
        ..Default::default()
    }
}

fn assess(concern: &str, kind: ImportKind, facts: &Value, expect: &PostgresExpectation) -> legion_audit::native_providers::architecture::postgres::ObligationAssessment {
    let bytes = serde_json::to_vec(facts).unwrap();
    assess_evidence(concern, &verdict(kind, &bytes, true), &bytes, expect)
}

#[test]
fn matching_isolated_evidence_satisfies_each_concern() {
    let cases = [
        (CONCERN_ISOLATED_MIGRATION, ImportKind::Runtime),
        (CONCERN_WORKLOAD_MEASURED, ImportKind::Performance),
        (CONCERN_CONTENTION, ImportKind::Performance),
        (CONCERN_BACKUP_RESTORE, ImportKind::Runtime),
    ];
    for (concern, kind) in cases {
        let r = assess(concern, kind, &good_facts(concern), &expectation());
        assert_eq!(r.status, "satisfied", "{concern}: {:?}", r.reasons);
        assert!(r.measured_execution);
    }
}

#[test]
fn plan_only_evidence_is_not_measured_execution() {
    let mut facts = good_facts(CONCERN_EXPLAIN_PLAN);
    facts["plan"]["analyze"] = json!(false);
    let r = assess(CONCERN_EXPLAIN_PLAN, ImportKind::Performance, &facts, &expectation());
    assert_eq!(r.status, "satisfied");
    assert!(!r.measured_execution);

    let mut facts = good_facts(CONCERN_WORKLOAD_MEASURED);
    facts["workload"]["readOps"] = json!(0);
    facts["workload"]["writeOps"] = json!(0);
    facts["plan"]["analyze"] = json!(false);
    let r = assess(CONCERN_WORKLOAD_MEASURED, ImportKind::Performance, &facts, &expectation());
    assert_eq!(r.status, "unmet");
    assert!(r.reasons.iter().any(|x| x == "plan-only-is-not-measured-execution"));
}

#[test]
fn source_detected_queries_are_not_a_complete_workload() {
    let mut facts = good_facts(CONCERN_WORKLOAD_MEASURED);
    facts["workload"]["denominatorAttested"] = json!(false);
    let r = assess(CONCERN_WORKLOAD_MEASURED, ImportKind::Performance, &facts, &expectation());
    assert_eq!(r.status, "unmet");
    assert!(r.reasons.iter().any(|x| x == "workload-denominator-unattested"));

    let mut expect = expectation();
    expect.required_query_ids.insert("q2".into());
    let r = assess(CONCERN_WORKLOAD_MEASURED, ImportKind::Performance, &good_facts(CONCERN_WORKLOAD_MEASURED), &expect);
    assert!(r.reasons.iter().any(|x| x == "detected-queries-not-in-workload"));
}

#[test]
fn wrong_version_schema_or_head_leaves_obligation_unmet() {
    let c = CONCERN_ISOLATED_MIGRATION;
    let mut facts = good_facts(c);
    facts["postgresVersionMajor"] = json!(14);
    assert!(assess(c, ImportKind::Runtime, &facts, &expectation()).reasons.contains(&"postgres-version-mismatch".to_owned()));
    let mut facts = good_facts(c);
    facts["schemaDigest"] = json!("sha256:zz");
    assert!(assess(c, ImportKind::Runtime, &facts, &expectation()).reasons.contains(&"schema-digest-mismatch".to_owned()));
    let mut facts = good_facts(c);
    facts["migrationHead"] = json!("older");
    assert!(assess(c, ImportKind::Runtime, &facts, &expectation()).reasons.contains(&"migration-head-mismatch".to_owned()));
}

#[test]
fn backup_existence_without_verified_restore_is_unmet() {
    let c = CONCERN_BACKUP_RESTORE;
    let mut facts = good_facts(c);
    facts["restore"]["restored"] = json!(false);
    facts["restore"]["verifiedInvariants"] = json!([]);
    let r = assess(c, ImportKind::Runtime, &facts, &expectation());
    assert_eq!(r.status, "unmet");
    assert!(r.reasons.contains(&"restore-not-performed".to_owned()));
    assert!(r.reasons.contains(&"restore-invariants-unverified".to_owned()));
    assert!(!r.measured_execution);
}

#[test]
fn production_or_repository_referenced_targets_are_refused() {
    let c = CONCERN_ISOLATED_MIGRATION;
    let prod = host_fingerprint("prod-db.example.com:5432", "app");
    let mut expect = expectation();
    expect.forbidden_host_fingerprints.insert(prod.clone());
    let mut facts = good_facts(c);
    facts["target"]["hostFingerprint"] = json!(prod);
    let r = assess(c, ImportKind::Runtime, &facts, &expect);
    assert!(r.reasons.contains(&"target-is-repository-referenced-database".to_owned()));

    let mut facts = good_facts(c);
    facts["target"]["kind"] = json!("production");
    facts["target"]["roleSuperuser"] = json!(true);
    facts["target"]["statementTimeoutMs"] = json!(null);
    let r = assess(c, ImportKind::Runtime, &facts, &expectation());
    for reason in ["target-not-declared-isolated", "target-role-not-restricted", "statement-timeout-unbounded"] {
        assert!(r.reasons.contains(&reason.to_owned()), "{reason}: {:?}", r.reasons);
    }
}

#[test]
fn replayed_or_unauthenticated_evidence_never_satisfies() {
    let c = CONCERN_CONTENTION;
    let bytes = serde_json::to_vec(&good_facts(c)).unwrap();
    let replay = assess_evidence(c, &verdict(ImportKind::Performance, &bytes, false), &bytes, &expectation());
    assert_eq!(replay.status, "unmet");
    let mut v = verdict(ImportKind::Performance, &bytes, true);
    v.authenticated = false;
    assert_eq!(assess_evidence(c, &v, &bytes, &expectation()).status, "unmet");
    let none = ImportVerdict { authenticated: false, satisfies_obligation: false, reasons: vec!["untrusted-issuer".into()], record: None };
    assert_eq!(assess_evidence(c, &none, &bytes, &expectation()).status, "unmet");
}
