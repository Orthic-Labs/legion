//! Journal, resume and metrics behaviour (CP sections 11, 12, 20).
//! Expects `pub mod journal; pub mod resume; pub mod metrics;` in lib.rs.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use legion_audit::journal::{
    clear_stale_lock, compare_histories, verify_dir, AuditEvent, DefectCode, EventKind,
    Expectation, Journal, EVENTS_FILE, HEAD_FILE, LOCK_FILE,
};
use legion_audit::metrics::{derive, to_json, BudgetEntry, MetricsInput, ReceiptMetric};
use legion_audit::resume::{plan_resume, resume, ReceiptRecord, ResumeDecision, ResumeInput};

const PLAN: &str = "sha256:plan-one";

fn tmp() -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "legion-audit-journal-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn has(v: &legion_audit::journal::JournalVerification, code: DefectCode) -> bool {
    v.defects.iter().any(|d| d.code == code)
}

/// plan_frozen, a finished (receipt r-a), b started only.
fn interrupted_run(dir: &PathBuf) {
    let mut j = Journal::create(dir, PLAN, 1000).unwrap();
    j.append(EventKind::ProviderStarted, "a", "sha256:x", 1010)
        .unwrap();
    j.append(EventKind::ProviderFinished, "a", "sha256:r-a", 1050)
        .unwrap();
    j.append(EventKind::ProviderStarted, "b", "sha256:x", 1060)
        .unwrap();
}

fn lines(dir: &PathBuf) -> Vec<String> {
    std::fs::read_to_string(dir.join(EVENTS_FILE))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(dir: &PathBuf, lines: &[String]) {
    std::fs::write(dir.join(EVENTS_FILE), lines.join("\n") + "\n").unwrap();
}

#[test]
fn clean_journal_verifies_and_reopens() {
    let dir = tmp();
    interrupted_run(&dir);
    let v = verify_dir(&dir, PLAN, &Expectation::default());
    assert!(v.is_valid(), "{:?}", v.defects);
    assert_eq!(v.events.len(), 4);
    assert_eq!(v.unsealed_tail, 0);
    let j = Journal::open(&dir, PLAN).unwrap();
    assert_eq!(j.events().len(), 4);
}

#[test]
fn edit_is_detected() {
    let dir = tmp();
    interrupted_run(&dir);
    let mut l = lines(&dir);
    l[2] = l[2].replace("sha256:r-a", "sha256:r-evil");
    write_lines(&dir, &l);
    let v = verify_dir(&dir, PLAN, &Expectation::default());
    assert!(has(&v, DefectCode::DigestMismatch));
    assert!(Journal::open(&dir, PLAN).is_err());
}

#[test]
fn reorder_gap_and_deletion_are_detected() {
    let dir = tmp();
    interrupted_run(&dir);
    let original = lines(&dir);

    let mut swapped = original.clone();
    swapped.swap(1, 2);
    write_lines(&dir, &swapped);
    let v = verify_dir(&dir, PLAN, &Expectation::default());
    assert!(!v.is_valid());
    assert!(has(&v, DefectCode::ForkOrReorder) || has(&v, DefectCode::SequenceGap));

    let mut gap = original.clone();
    gap.remove(1);
    write_lines(&dir, &gap);
    let v = verify_dir(&dir, PLAN, &Expectation::default());
    assert!(has(&v, DefectCode::SequenceGap));
    assert!(has(&v, DefectCode::PreviousDigestMismatch));
}

#[test]
fn duplicated_event_is_a_fork() {
    let dir = tmp();
    interrupted_run(&dir);
    let mut l = lines(&dir);
    l.insert(3, l[2].clone());
    write_lines(&dir, &l);
    let v = verify_dir(&dir, PLAN, &Expectation::default());
    assert!(has(&v, DefectCode::ForkOrReorder));
}

#[test]
fn truncated_tail_is_detected_by_seal_and_by_finalization_expectation() {
    let dir = tmp();
    let mut j = Journal::create(&dir, PLAN, 1).unwrap();
    j.append(EventKind::ProviderStarted, "a", "sha256:x", 2)
        .unwrap();
    j.append(EventKind::ProviderFinished, "a", "sha256:r-a", 3)
        .unwrap();
    j.append(EventKind::ReportFinalized, "run", "sha256:report", 4)
        .unwrap();
    let final_head = j.head();
    assert!(final_head.finalized);
    drop(j);

    let full = lines(&dir);
    write_lines(&dir, &full[..3]);
    let v = verify_dir(&dir, PLAN, &Expectation::default());
    assert!(has(&v, DefectCode::Truncated));

    // A forged seal that matches the shortened log still fails when a
    // finalized journal is required or an external head is known.
    let shortened = verify_dir(&dir, PLAN, &Expectation::default());
    let mut seal = shortened.head.clone().unwrap();
    seal.sequence = 3;
    seal.digest = Some(shortened.events[2].digest.clone());
    seal.finalized = false;
    std::fs::write(dir.join(HEAD_FILE), serde_json::to_vec(&seal).unwrap()).unwrap();
    let v = verify_dir(
        &dir,
        PLAN,
        &Expectation {
            require_finalized: true,
            expected_head: Some(final_head),
            final_plan_digest: None,
        },
    );
    assert!(has(&v, DefectCode::NotFinalized));
    assert!(has(&v, DefectCode::ExpectedHeadMismatch));
}

#[test]
fn missing_seal_and_wrong_plan_are_refused() {
    let dir = tmp();
    interrupted_run(&dir);
    let wrong = verify_dir(&dir, "sha256:other-plan", &Expectation::default());
    assert!(has(&wrong, DefectCode::FirstEventNotPlanFrozen));
    assert!(Journal::open(&dir, "sha256:other-plan").is_err());
    std::fs::remove_file(dir.join(HEAD_FILE)).unwrap();
    let v = verify_dir(&dir, PLAN, &Expectation::default());
    assert!(has(&v, DefectCode::SealMissing));
}

#[test]
fn appends_cannot_violate_ordering_or_follow_finalization() {
    let dir = tmp();
    let mut j = Journal::create(&dir, PLAN, 1).unwrap();
    assert!(j
        .append(EventKind::ProviderFinished, "a", "sha256:r", 2)
        .is_err());
    assert!(j.append(EventKind::PlanFrozen, "x", "sha256:r", 2).is_err());
    j.append(EventKind::ProviderStarted, "a", "sha256:x", 2)
        .unwrap();
    assert!(j
        .append(EventKind::ProviderStarted, "a", "sha256:x", 3)
        .is_err());
    assert!(j
        .append(EventKind::ReportFinalized, "run", "sha256:r", 3)
        .is_err());
    j.append(EventKind::ProviderFinished, "a", "sha256:r", 4)
        .unwrap();
    j.append(EventKind::ReportFinalized, "run", "sha256:r", 5)
        .unwrap();
    assert!(j
        .append(EventKind::RetryScheduled, "a", "sha256:r", 6)
        .is_err());
}

#[test]
fn run_lock_is_exclusive_and_stale_lock_needs_explicit_clear() {
    let dir = tmp();
    let j = Journal::create(&dir, PLAN, 1).unwrap();
    assert!(Journal::open(&dir, PLAN).is_err());
    drop(j);
    assert!(Journal::open(&dir, PLAN).is_ok());
    std::fs::write(dir.join(LOCK_FILE), "999999").unwrap();
    assert!(Journal::open(&dir, PLAN).is_err());
    clear_stale_lock(&dir).unwrap();
    assert!(Journal::open(&dir, PLAN).is_ok());
}

#[test]
fn torn_uncommitted_tail_is_recovered_but_committed_loss_is_not() {
    let dir = tmp();
    interrupted_run(&dir);
    let mut raw = std::fs::read(dir.join(EVENTS_FILE)).unwrap();
    raw.extend_from_slice(b"{\"sequence\":5,\"prev");
    std::fs::write(dir.join(EVENTS_FILE), raw).unwrap();
    let j = Journal::open(&dir, PLAN).unwrap();
    assert!(j.recovered_torn_bytes > 0);
    assert_eq!(j.events().len(), 4);
    drop(j);

    // Cutting a sealed line in half is lost committed history, not a torn write.
    let raw = std::fs::read(dir.join(EVENTS_FILE)).unwrap();
    std::fs::write(dir.join(EVENTS_FILE), &raw[..raw.len() - 20]).unwrap();
    assert!(Journal::open(&dir, PLAN).is_err());
}

#[test]
fn amendment_moves_effective_plan_and_wrong_plan_events_are_rejected() {
    let dir = tmp();
    let mut j = Journal::create(&dir, PLAN, 1).unwrap();
    j.append_amendment("sha256:plan-two", "sha256:amend", 2)
        .unwrap();
    assert_eq!(j.effective_plan_digest(), "sha256:plan-two");
    j.append(EventKind::ProviderStarted, "a", "sha256:x", 3)
        .unwrap();
    drop(j);
    let v = verify_dir(
        &dir,
        PLAN,
        &Expectation {
            final_plan_digest: Some("sha256:plan-two".into()),
            ..Default::default()
        },
    );
    assert!(v.is_valid(), "{:?}", v.defects);
    let mut l = lines(&dir);
    // Fabricate a later event bound to the superseded plan.
    let mut ev: AuditEvent = serde_json::from_str(&l[2]).unwrap();
    ev.plan_digest = PLAN.into();
    l[2] = serde_json::to_string(&ev).unwrap();
    write_lines(&dir, &l);
    let v = verify_dir(&dir, PLAN, &Expectation::default());
    assert!(has(&v, DefectCode::PlanMismatch));
}

#[test]
fn divergent_histories_are_reported_as_fork() {
    let a = tmp();
    let b = tmp();
    interrupted_run(&a);
    interrupted_run(&b);
    let ea = verify_dir(&a, PLAN, &Expectation::default()).events;
    let mut jb = Journal::open(&b, PLAN).unwrap();
    jb.append(EventKind::RetryScheduled, "b", "sha256:x", 2000)
        .unwrap();
    let eb = jb.events().to_vec();
    drop(jb);
    // Same prefix, one extends the other: not a fork.
    assert_eq!(compare_histories(&ea, &eb), (ea.len().min(eb.len()), false));
    let mut ja = Journal::open(&a, PLAN).unwrap();
    ja.append(EventKind::BreakerTripped, "b", "sha256:y", 2001)
        .unwrap();
    let ea = ja.events().to_vec();
    let (_, fork) = compare_histories(&ea, &eb);
    assert!(fork);
}

fn input(receipts: Vec<ReceiptRecord>) -> ResumeInput {
    ResumeInput {
        plan_digest: PLAN.into(),
        planned_providers: vec!["a".into(), "b".into(), "c".into()],
        receipts,
        ..Default::default()
    }
}

fn receipt_a() -> ReceiptRecord {
    ReceiptRecord {
        provider: "a".into(),
        plan_digest: PLAN.into(),
        receipt_digest: "sha256:r-a".into(),
        verified: true,
    }
}

#[test]
fn resume_reuses_reruns_gaps_and_appends_resume_event() {
    let dir = tmp();
    interrupted_run(&dir);
    let mut i = input(vec![receipt_a()]);
    i.idempotent = BTreeSet::from(["b".to_string()]);
    let plan = plan_resume(&dir, &i).unwrap();
    assert!(matches!(plan.decisions["a"], ResumeDecision::Reuse { .. }));
    assert!(matches!(plan.decisions["b"], ResumeDecision::Rerun { .. }));
    assert_eq!(plan.decisions["c"], ResumeDecision::Run);

    // Non-idempotent b becomes an explicit gap closed by a failure event.
    let i2 = input(vec![receipt_a()]);
    let (journal, plan) = resume(&dir, &i2, 5000).unwrap();
    assert_eq!(plan.gaps(), vec!["b".to_string()]);
    let kinds: Vec<_> = journal.events().iter().map(|e| e.kind).collect();
    assert_eq!(
        &kinds[4..],
        &[EventKind::RunResumed, EventKind::ProviderFailed]
    );
    drop(journal);
    assert!(verify_dir(&dir, PLAN, &Expectation::default()).is_valid());
}

#[test]
fn resume_refuses_on_any_mismatch() {
    let dir = tmp();
    interrupted_run(&dir);

    let missing = plan_resume(&dir, &input(vec![])).unwrap_err();
    assert!(missing
        .reasons
        .iter()
        .any(|r| r.contains("receipt is missing")));

    let mut tampered = receipt_a();
    tampered.receipt_digest = "sha256:forged".into();
    assert!(plan_resume(&dir, &input(vec![tampered])).is_err());

    let mut unverified = receipt_a();
    unverified.verified = false;
    assert!(plan_resume(&dir, &input(vec![unverified])).is_err());

    let mut other_plan = receipt_a();
    other_plan.plan_digest = "sha256:elsewhere".into();
    assert!(plan_resume(&dir, &input(vec![other_plan])).is_err());

    let mut wrong_plan = input(vec![receipt_a()]);
    wrong_plan.plan_digest = "sha256:not-the-plan".into();
    assert!(plan_resume(&dir, &wrong_plan).is_err());

    let mut shrunk = input(vec![receipt_a()]);
    shrunk.planned_providers = vec!["a".into()];
    let refusal = plan_resume(&dir, &shrunk).unwrap_err();
    assert!(refusal
        .reasons
        .iter()
        .any(|r| r.contains("outside the frozen plan")));

    // Refusal never appends.
    assert_eq!(lines(&dir).len(), 4);

    // Tampered journal, then finalized journal.
    let mut l = lines(&dir);
    l[1] = l[1].replace("\"a\"", "\"z\"");
    write_lines(&dir, &l);
    assert!(plan_resume(&dir, &input(vec![receipt_a()])).is_err());
}

#[test]
fn resume_refuses_finalized_run_and_orphan_receipt_is_not_proof() {
    let dir = tmp();
    interrupted_run(&dir);
    // Orphan: receipt for c exists but the journal never saw c.
    let orphan = ReceiptRecord {
        provider: "c".into(),
        plan_digest: PLAN.into(),
        receipt_digest: "sha256:r-c".into(),
        verified: true,
    };
    let plan = plan_resume(&dir, &input(vec![receipt_a(), orphan])).unwrap();
    assert_eq!(plan.orphan_receipts, vec!["c".to_string()]);
    assert_eq!(plan.decisions["c"], ResumeDecision::Run);

    let mut j = Journal::open(&dir, PLAN).unwrap();
    j.append(EventKind::ProviderFailed, "b", "sha256:f", 2000)
        .unwrap();
    j.append(EventKind::ProviderSkipped, "c", "sha256:s", 2001)
        .unwrap();
    j.append(EventKind::ReportFinalized, "run", "sha256:report", 2002)
        .unwrap();
    drop(j);
    let refusal = plan_resume(&dir, &input(vec![receipt_a()])).unwrap_err();
    assert!(refusal.reasons.iter().any(|r| r.contains("finalized")));
}

#[test]
fn metrics_are_derived_deterministically_and_non_authoritative() {
    let dir = tmp();
    let mut j = Journal::create(&dir, PLAN, 1000).unwrap();
    j.append(EventKind::ProviderStarted, "a", "sha256:x", 1100)
        .unwrap();
    j.append(EventKind::ProviderFailed, "a", "sha256:f", 1150)
        .unwrap();
    j.append(EventKind::RetryScheduled, "a", "sha256:x", 1160)
        .unwrap();
    j.append(EventKind::BreakerTripped, "a", "sha256:x", 1161)
        .unwrap();
    j.append(EventKind::FallbackUsed, "a", "sha256:x", 1162)
        .unwrap();
    j.append(EventKind::ProviderStarted, "a", "sha256:x", 1200)
        .unwrap();
    j.append(EventKind::ProviderFinished, "a", "sha256:r-a", 1300)
        .unwrap();
    j.append(EventKind::ProviderSkipped, "b", "sha256:s", 1310)
        .unwrap();
    j.append(EventKind::ProviderStarted, "c", "sha256:x", 1320)
        .unwrap();
    let events = j.events().to_vec();
    drop(j);

    let input = MetricsInput {
        plan_digest: PLAN.into(),
        receipts: vec![
            ReceiptMetric {
                provider: "a".into(),
                output_bytes: 10,
                cache_hit: true,
            },
            ReceiptMetric {
                provider: "b".into(),
                output_bytes: 5,
                cache_hit: false,
            },
        ],
        budget: vec![
            BudgetEntry {
                provider: "a".into(),
                resource: "tokens".into(),
                amount: 7,
            },
            BudgetEntry {
                provider: "c".into(),
                resource: "tokens".into(),
                amount: 3,
            },
        ],
        reused_providers: BTreeSet::new(),
    };
    let m1 = derive(&events, &input).unwrap();
    let m2 = derive(&events, &input).unwrap();
    assert_eq!(to_json(&m1).unwrap(), to_json(&m2).unwrap());
    assert!(!m1.authoritative);
    assert_eq!(m1.retries, 1);
    assert_eq!(m1.breaker_trips, 1);
    assert_eq!(m1.fallbacks, 1);
    assert_eq!(m1.provider_duration_ms["a"], 50 + 100);
    assert_eq!(m1.counts.completed, 1);
    assert_eq!(m1.counts.failed, 1);
    assert_eq!(m1.counts.skipped, 1);
    assert_eq!(m1.counts.interrupted, 1);
    assert_eq!(m1.total_duration_ms, 320);
    assert_eq!(m1.output_bytes_total, 15);
    assert_eq!(m1.receipts_cache_hits, 1);
    assert_eq!(m1.budget_totals["tokens"], 10);

    // A tampered history is refused, not summarised.
    let mut forged = events.clone();
    forged[1].subject = "z".into();
    assert!(derive(&forged, &input).is_err());
}
