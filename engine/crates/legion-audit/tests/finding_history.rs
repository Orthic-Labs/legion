//! A15 finding history, debt and index acceptance (N11, N12, N13, N18-adjacent, N22).

use legion_audit::debt::{self, DebtPolicy, FirstSeen};
use legion_audit::finding_history::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const REPORT: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const EVID: &str = "sha256:2222222222222222222222222222222222222222222222222222222222222222";

fn prior(id: &str) -> PriorFinding {
    PriorFinding {
        id: id.into(),
        rule_id: "rule.a".into(),
        rule_revision: "1".into(),
        path: "src/a.rs".into(),
        legacy_status: "open".into(),
        disposition: Some(Disposition::Open),
        reuse_key: None,
        dismissal: None,
        superseded_by: None,
    }
}

fn run() -> RunView {
    RunView {
        report_digest: REPORT.into(),
        complete: true,
        executed_rules: BTreeMap::from([("rule.a".into(), "1".into())]),
        covered_paths: BTreeSet::from(["src/a.rs".into()]),
        ..RunView::default()
    }
}

fn evidence(id: &str) -> ResolutionEvidence {
    ResolutionEvidence {
        finding_id: id.into(),
        kind: ResolutionKind::RuleRerunClean,
        report_digest: REPORT.into(),
        rule_id: "rule.a".into(),
        rule_revision: "1".into(),
        regression_condition: "rule.a stays clean on src/a.rs".into(),
        accepted_by: None,
        evidence_digest: EVID.into(),
    }
}

fn one(priors: &[PriorFinding], run: &RunView) -> Assessment {
    reconcile(priors, run, None).unwrap().remove(0)
}

#[test]
fn absence_with_valid_evidence_is_verified_fixed() {
    let mut r = run();
    r.evidence.insert("f1".into(), evidence("f1"));
    let a = one(&[prior("f1")], &r);
    assert_eq!(a.disposition, Disposition::VerifiedFixed);
    assert_eq!(suggested_legacy_status(&a), Some("resolved"));
}

#[test]
fn absence_without_evidence_is_never_verified_fixed() {
    let a = one(&[prior("f1")], &run());
    assert_eq!(a.disposition, Disposition::NeedsRevalidation);
    assert!(!a.verified_fixed());
}

#[test]
fn evidence_without_regression_condition_or_wrong_report_is_rejected() {
    let mut e = evidence("f1");
    e.regression_condition = "  ".into();
    let mut r = run();
    r.evidence.insert("f1".into(), e);
    assert!(!one(&[prior("f1")], &r).verified_fixed());

    let mut e = evidence("f1");
    e.report_digest = EVID.into();
    let mut r = run();
    r.evidence.insert("f1".into(), e);
    assert!(!one(&[prior("f1")], &r).verified_fixed());
}

#[test]
fn rename_and_deleted_symbol_never_close() {
    let mut r = run();
    r.evidence.insert("f1".into(), evidence("f1"));
    r.relocated.insert("f1".into(), "sha256:cand".into());
    let a = one(&[prior("f1")], &r);
    assert_eq!(a.disposition, Disposition::UnresolvedLocation);

    let mut r = run();
    r.evidence.insert("f2".into(), evidence("f2"));
    r.missing_symbols.insert("f2".into());
    assert_eq!(
        one(&[prior("f2")], &r).disposition,
        Disposition::UnresolvedLocation
    );
}

#[test]
fn removed_scanner_incomplete_run_and_narrow_scope_preserve_open() {
    let mut no_rule = run();
    no_rule.executed_rules.clear();
    let a = one(&[prior("f1")], &no_rule);
    assert_eq!(
        (a.disposition, a.basis),
        (Disposition::Open, Basis::NotExamined)
    );

    let mut incomplete = run();
    incomplete.complete = false;
    assert_eq!(
        one(&[prior("f1")], &incomplete).disposition,
        Disposition::Open
    );

    let mut narrow = run();
    narrow.covered_paths = BTreeSet::from(["src/other.rs".into()]);
    let a = one(&[prior("f1")], &narrow);
    assert_eq!(
        (a.disposition, a.basis),
        (Disposition::Open, Basis::NotExamined)
    );
}

#[test]
fn changed_rule_revision_needs_revalidation() {
    let mut r = run();
    r.executed_rules.insert("rule.a".into(), "2".into());
    assert_eq!(
        one(&[prior("f1")], &r).disposition,
        Disposition::NeedsRevalidation
    );
}

#[test]
fn legacy_resolved_and_dismissed_are_not_verified_fixed() {
    let mut resolved = prior("f1");
    resolved.legacy_status = "resolved".into();
    resolved.disposition = None;
    let a = one(&[resolved.clone()], &run());
    assert_eq!(a.standing, Standing::LegacyResolvedUnverified);
    assert_eq!(a.disposition, Disposition::NeedsRevalidation);
    // Still reported: legacy resolved is contradicted, finding is Open.
    let mut r = run();
    r.present.insert("f1".into());
    assert_eq!(one(&[resolved], &r).disposition, Disposition::Open);

    let mut dismissed = prior("f2");
    dismissed.legacy_status = "dismissed".into();
    dismissed.dismissal = Some(Dismissal {
        authority: "owner".into(),
        reason: "accepted risk".into(),
        at: None,
    });
    let a = one(&[dismissed.clone()], &run());
    assert_eq!(a.standing, Standing::Dismissed);
    assert!(!a.verified_fixed());
    let mut narrow = run();
    narrow.covered_paths.clear();
    assert!(!one(&[dismissed], &narrow).verified_fixed());
}

fn key() -> ReuseKey {
    ReuseKey {
        rule_id: "rule.a".into(),
        rule_revision: "1".into(),
        source_digests: BTreeMap::from([("src/a.rs".into(), "d1".into())]),
        caller_digests: BTreeMap::from([("src/b.rs".into(), "c1".into())]),
        config_digest: Some("cfg1".into()),
        ..ReuseKey::default()
    }
}

fn reused_run(new_key: ReuseKey) -> RunView {
    let mut r = run();
    r.present.insert("f1".into());
    r.reused.insert("f1".into());
    r.reuse_keys.insert("f1".into(), new_key);
    r
}

#[test]
fn reuse_requires_unchanged_context_and_stays_distinct_from_executed() {
    let mut p = prior("f1");
    p.reuse_key = Some(key());
    let a = one(&[p.clone()], &reused_run(key()));
    assert_eq!((a.disposition, a.basis), (Disposition::Open, Basis::Reused));

    let mut changed_caller = key();
    changed_caller
        .caller_digests
        .insert("src/b.rs".into(), "c2".into());
    let a = one(&[p.clone()], &reused_run(changed_caller));
    assert_eq!(a.disposition, Disposition::NeedsRevalidation);
    assert!(a.reasons.iter().any(|r| r.contains("caller changed")));

    let mut changed_config = key();
    changed_config.config_digest = Some("cfg2".into());
    assert_eq!(
        one(&[p.clone()], &reused_run(changed_config)).disposition,
        Disposition::NeedsRevalidation
    );

    // Executed (not reused) present finding is Open/Executed regardless of key.
    let mut r = run();
    r.present.insert("f1".into());
    let a = one(&[p], &r);
    assert_eq!(
        (a.disposition, a.basis),
        (Disposition::Open, Basis::Executed)
    );
}

#[test]
fn unknown_dependency_closure_and_stale_advisory_force_revalidation() {
    let mut old = key();
    old.dependency_closure = ClosureState::Known;
    old.dependency_graph_digest = Some("g1".into());
    old.advisory_freshness = Some("current".into());
    old.registry_freshness = Some("current".into());
    let mut p = prior("f1");
    p.reuse_key = Some(old.clone());
    assert_eq!(
        one(&[p.clone()], &reused_run(old.clone())).disposition,
        Disposition::Open
    );

    let mut unknown = old.clone();
    unknown.dependency_closure = ClosureState::Unknown;
    assert_eq!(
        one(&[p.clone()], &reused_run(unknown)).disposition,
        Disposition::NeedsRevalidation
    );

    let mut stale = old;
    stale.advisory_freshness = Some("stale".into());
    assert_eq!(
        one(&[p], &reused_run(stale)).disposition,
        Disposition::NeedsRevalidation
    );
}

#[test]
fn distinct_ids_never_merge_and_duplicates_are_rejected() {
    let mut a = prior("f1");
    let mut b = prior("f2");
    a.path = "src/x.rs".into();
    b.path = "src/y.rs".into();
    let out = reconcile(&[a.clone(), b], &run(), None).unwrap();
    assert_eq!(out.len(), 2);
    assert!(reconcile(&[a.clone(), a], &run(), None).is_err());
}

#[test]
fn unmatched_present_ids_are_new() {
    let mut r = run();
    r.present.insert("fresh".into());
    let out = reconcile(&[], &r, None).unwrap();
    assert_eq!(out[0].disposition, Disposition::New);
}

#[test]
fn record_round_trips_additive_assurance() {
    let record = serde_json::json!({
        "id": "f1", "status": "resolved",
        "provenance": {"ruleId": "rule.a", "version": "1"},
        "evidenceLoci": [{"path": "src/a.rs", "startLine": 1, "endLine": 1}],
        "supersededBy": null,
    });
    let p = PriorFinding::from_record(&record).unwrap();
    assert_eq!(p.legacy_status, "resolved");
    let a = one(&[p], &run());
    let patch = assurance_patch(&a, None);
    assert!(patch.get("status").is_none());
    assert_eq!(patch["assurance"]["disposition"], "needs-revalidation");
}

// ------------------------------------------------------------------ index

fn scratch(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "legion-finding-history-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(root.join(".audit/state/reports")).unwrap();
    root
}

fn put_report(root: &PathBuf, body: &str) -> String {
    use sha2::{Digest, Sha256};
    let name = format!("{}.json", hex::encode(Sha256::digest(body.as_bytes())));
    std::fs::write(root.join(".audit/state/reports").join(&name), body).unwrap();
    name
}

#[test]
fn index_rebuilds_from_reports_rejects_bad_ones_and_never_rewrites_reports() {
    let root = scratch("index");
    let good = put_report(
        &root,
        r#"{"status":"findings","gaps":[],"findings":[{"id":"f1"},{"id":"f2"}]}"#,
    );
    let partial = put_report(
        &root,
        r#"{"status":"incomplete","gaps":["x"],"findings":[]}"#,
    );
    let reports = root.join(".audit/state/reports");
    std::fs::write(reports.join("deadbeef.json"), "{}").unwrap();
    let before = std::fs::read(reports.join(&good)).unwrap();

    let (index, rebuilt) = load_or_rebuild(&root).unwrap();
    assert!(rebuilt);
    assert_eq!(index.baselines().count(), 1);
    assert_eq!(
        index
            .reports
            .iter()
            .find(|r| r.file == good)
            .unwrap()
            .finding_ids,
        ["f1", "f2"]
    );
    assert!(
        !index
            .reports
            .iter()
            .find(|r| r.file == partial)
            .unwrap()
            .baseline_eligible
    );
    assert_eq!(index.rejected.len(), 1);

    // Intact cache is reused.
    assert!(!load_or_rebuild(&root).unwrap().1);

    // Corrupt cache rebuilds.
    std::fs::write(
        root.join(".audit/audit/finding-history-index.json"),
        "{corrupt",
    )
    .unwrap();
    assert!(load_or_rebuild(&root).unwrap().1);

    // Stale cache (new report) rebuilds.
    put_report(&root, r#"{"status":"clean","gaps":[],"findings":[]}"#);
    let (index, rebuilt) = load_or_rebuild(&root).unwrap();
    assert!(rebuilt);
    assert_eq!(index.baselines().count(), 2);

    assert_eq!(std::fs::read(reports.join(&good)).unwrap(), before);
    let _ = std::fs::remove_dir_all(&root);
}

// ------------------------------------------------------------------- debt

#[test]
fn debt_harvest_owner_reason_and_acceptance() {
    let src = "// TODO(adrian): remove shim\n\
               let x = 1; // FIXME\n\
               #[allow(dead_code)] // audit-accept: owner=sec reason=\"legacy ffi\" expires=2027-01-01\n\
               // eslint-disable-next-line audit-accept: owner=a\n\
               let todo_list = 1;\n";
    let records = debt::harvest("src/a.rs", src);
    assert_eq!(records.len(), 4);
    assert_eq!(records[0].owner.as_deref(), Some("adrian"));
    assert_eq!(records[0].reason.as_deref(), Some("remove shim"));
    assert!(records[1].owner.is_none());
    assert!(records[2].accepted);
    assert!(!records[3].accepted);
    let a = debt::assess(&records[3], "2026-10-23", DebtPolicy::default());
    assert!(a.invalid_acceptance.is_some());
}

#[test]
fn debt_age_is_not_invented_and_not_blocking_without_policy() {
    let records = debt::harvest("a.rs", "// TODO: later\n");
    let unknown = debt::assess(&records[0], "2026-10-23", DebtPolicy::default());
    assert_eq!(unknown.age_days, None);
    assert!(unknown.advisories.contains(&"age-unknown".to_owned()));

    let merged = debt::merge_first_seen(
        &[],
        records.clone(),
        &BTreeMap::new(),
        "2026-10-01T00:00:00Z",
        REPORT,
    );
    assert!(matches!(merged[0].first_seen, FirstSeen::Observed { .. }));
    let observed = debt::assess(&merged[0], "2026-10-23", DebtPolicy::default());
    assert_eq!(observed.age_days, Some(22));
    assert!(!observed.deadline_exceeded);
    let strict = debt::assess(
        &merged[0],
        "2026-10-23",
        DebtPolicy {
            marker_deadline_days: Some(10),
        },
    );
    assert!(strict.deadline_exceeded);

    let history = BTreeMap::from([(records[0].id.clone(), "2026-01-01T00:00:00Z".to_owned())]);
    let merged = debt::merge_first_seen(&merged, records, &history, "2026-10-23T00:00:00Z", REPORT);
    assert!(matches!(merged[0].first_seen, FirstSeen::History { .. }));
}

#[test]
fn removed_marker_is_not_a_repair_claim_and_ids_survive_line_moves() {
    let before = debt::harvest("a.rs", "// TODO: x\n");
    let moved = debt::harvest("a.rs", "\n\n// TODO: x\n");
    assert_eq!(before[0].id, moved[0].id);
    let d = debt::diff(&before, &[]);
    assert_eq!(d.removed, vec![before[0].id.clone()]);
}

#[test]
fn expired_acceptance_is_explicit() {
    let r = debt::harvest(
        "a.rs",
        "#[allow(x)] // audit-accept: owner=a reason=r expires=2026-01-01\n",
    );
    assert!(debt::assess(&r[0], "2026-10-23", DebtPolicy::default()).expired);
}
