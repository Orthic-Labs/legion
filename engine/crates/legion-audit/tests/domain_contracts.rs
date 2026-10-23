//! A12 acceptance coverage for domain contracts. Authored, never run by the
//! packet worker — root executes. Requires root to add `pub mod domain_contract;`
//! to `src/lib.rs`.

use legion_audit::assurance::SnapshotRef;
use legion_audit::domain_contract::{
    BindingStatus, ContractFileInput, DomainContractSet, DomainEvaluation, UnresolvedKind,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn case_dir(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/domain-contracts")
        .join(case)
}

/// Repository id = file stem. Each repository is bound to a distinct digest.
fn load(case: &str) -> (Vec<ContractFileInput>, Vec<SnapshotRef>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(case_dir(case))
        .expect("fixture dir")
        .map(|e| e.expect("entry").path())
        .collect();
    entries.sort();
    let mut files = Vec::new();
    let mut snapshots = Vec::new();
    for (index, path) in entries.iter().enumerate() {
        let repo = path.file_stem().unwrap().to_string_lossy().into_owned();
        files.push(ContractFileInput {
            repository_id: repo.clone(),
            path: format!("contracts/{repo}.json"),
            bytes: fs::read(path).expect("fixture bytes"),
            expected_digest: None,
        });
        snapshots.push(SnapshotRef {
            repository_id: repo,
            snapshot_digest: format!("sha256:{:064x}", index + 1),
        });
    }
    (files, snapshots)
}

fn set(case: &str, required: bool) -> DomainContractSet {
    let (files, snapshots) = load(case);
    DomainContractSet::build(&files, &snapshots, required)
}

fn eval(case: &str) -> (DomainContractSet, DomainEvaluation) {
    let set = set(case, true);
    let evaluation = set.evaluate();
    (set, evaluation)
}

fn rules(evaluation: &DomainEvaluation) -> Vec<&str> {
    evaluation
        .candidates
        .iter()
        .map(|c| c.rule.as_str())
        .collect()
}

#[test]
fn valid_counterparts_raise_no_candidate_and_stay_resolved() {
    for case in ["money-valid", "time-valid", "state-valid"] {
        let (set, evaluation) = eval(case);
        assert!(set.is_fully_resolved(), "{case}: {:?}", set.unresolved);
        assert!(
            evaluation.candidates.is_empty(),
            "{case}: {:?}",
            evaluation.candidates
        );
        for d in &evaluation.dispositions {
            assert_eq!(d.status, "implemented-unverified", "{case}: {d:?}");
            assert_eq!(d.spec.status, "pass");
            assert_eq!(d.standards.status, "not-applicable");
        }
        assert!(!set.execution_authority);
    }
    let (set, evaluation) = eval("tenant-valid");
    assert!(
        evaluation.candidates.is_empty(),
        "{:?}",
        evaluation.candidates
    );
    assert!(set.unresolved.is_empty(), "{:?}", set.unresolved);
}

#[test]
fn cents_versus_major_units_is_detected() {
    let (_, evaluation) = eval("money-cents-vs-major");
    assert!(rules(&evaluation).contains(&"money-unit-mismatch"));
    let hit = evaluation
        .candidates
        .iter()
        .find(|c| c.rule == "money-unit-mismatch")
        .unwrap();
    assert_eq!(hit.repository_id, "storefront");
    assert_eq!(hit.axis, "spec");
    assert!(hit.id.starts_with("domain:") && !hit.evidence.is_empty());
    assert_eq!(evaluation.dispositions[0].status, "contradicted");
    assert_eq!(evaluation.dispositions[0].spec.status, "findings");
}

#[test]
fn utc_versus_local_time_is_detected() {
    let (_, evaluation) = eval("time-local");
    assert!(rules(&evaluation).contains(&"timezone-mismatch"));
}

#[test]
fn tenant_id_mismatch_is_detected_as_data_safety() {
    let (_, evaluation) = eval("tenant-mismatch");
    let hit = evaluation
        .candidates
        .iter()
        .find(|c| c.rule == "tenant-id-mismatch")
        .unwrap();
    assert_eq!(hit.severity, "error");
    assert_eq!(hit.repository_id, "mobile");
}

#[test]
fn incompatible_order_states_are_detected() {
    let (_, evaluation) = eval("state-incompatible");
    let hits = rules(&evaluation)
        .into_iter()
        .filter(|r| *r == "order-state-incompatible")
        .count();
    assert!(
        hits >= 2,
        "state and transition findings expected, got {:?}",
        evaluation.candidates
    );
}

#[test]
fn missing_authority_is_unresolved_not_guessed() {
    let (set, evaluation) = eval("missing-authority");
    assert!(!set.has_terms());
    let kinds: Vec<UnresolvedKind> = set.unresolved.iter().map(|u| u.kind).collect();
    assert!(kinds.contains(&UnresolvedKind::MissingAuthority));
    assert!(kinds.contains(&UnresolvedKind::MissingContracts));
    assert!(!set.is_fully_resolved());
    assert!(evaluation.candidates.is_empty());
    assert!(evaluation
        .dispositions
        .iter()
        .all(|d| d.status == "unproven"));
}

#[test]
fn conflicting_versions_are_ambiguous_and_excluded() {
    let (set, evaluation) = eval("conflicting-versions");
    assert!(set
        .unresolved
        .iter()
        .any(|u| u.kind == UnresolvedKind::ConflictingVersions));
    assert!(!set.terms.contains_key("orders/total"));
    let d = evaluation
        .dispositions
        .iter()
        .find(|d| d.term_id == "orders/total")
        .unwrap();
    assert_eq!(d.status, "ambiguous");
}

#[test]
fn unknown_consumers_stay_unproven() {
    let (set, evaluation) = eval("unknown-consumer");
    let kinds: Vec<UnresolvedKind> = set.unresolved.iter().map(|u| u.kind).collect();
    assert!(kinds.contains(&UnresolvedKind::UnknownConsumer));
    assert!(kinds.contains(&UnresolvedKind::UnknownExternalConsumers));
    assert_eq!(evaluation.dispositions[0].status, "unproven");
}

#[test]
fn identical_names_are_never_equated_and_collisions_are_reported() {
    let (_, evaluation) = eval("name-collision");
    // Each mapping matches its own term; the shared symbol is not a defect.
    assert!(
        evaluation.candidates.is_empty(),
        "{:?}",
        evaluation.candidates
    );
    assert_eq!(evaluation.name_collisions.len(), 1);
    assert_eq!(evaluation.name_collisions[0].term_ids.len(), 2);
}

#[test]
fn absent_contracts_invent_nothing_unless_required() {
    let (_, snapshots) = load("money-valid");
    let optional = DomainContractSet::build(&[], &snapshots, false);
    assert!(optional.unresolved.is_empty() && optional.evaluate().candidates.is_empty());
    let required = DomainContractSet::build(&[], &snapshots, true);
    assert!(required
        .unresolved
        .iter()
        .any(|u| u.kind == UnresolvedKind::MissingContracts));
    assert!(!required.is_fully_resolved());
}

#[test]
fn contract_change_invalidates_prior_binding_even_with_identical_implementation() {
    let (files, snapshots) = load("money-valid");
    let before = DomainContractSet::build(&files, &snapshots, true);
    let binding = before.binding();
    assert_eq!(binding.verify_against(&before), BindingStatus::Valid);
    let scoped = before.scoped_digest(&["orders/total".to_owned()]);

    let mut changed = files.clone();
    let text = String::from_utf8(changed[0].bytes.clone()).unwrap();
    changed[0].bytes = text.replace("\"scale\": 2", "\"scale\": 3").into_bytes();
    let after = DomainContractSet::build(&changed, &snapshots, true);
    assert_ne!(before.set_digest, after.set_digest);
    assert_ne!(scoped, after.scoped_digest(&["orders/total".to_owned()]));
    assert!(matches!(
        binding.verify_against(&after),
        BindingStatus::Invalidated { .. }
    ));
}

#[test]
fn digest_mismatch_and_unbound_repository_are_untrusted() {
    let (mut files, snapshots) = load("money-valid");
    files[0].expected_digest = Some(format!("sha256:{:064x}", 7));
    files.push(ContractFileInput {
        repository_id: "rogue".into(),
        path: "contracts/rogue.json".into(),
        bytes: files[1].bytes.clone(),
        expected_digest: None,
    });
    let set = DomainContractSet::build(&files, &snapshots, true);
    let kinds: Vec<UnresolvedKind> = set.unresolved.iter().map(|u| u.kind).collect();
    assert!(kinds.contains(&UnresolvedKind::DigestMismatch));
    assert!(kinds.contains(&UnresolvedKind::UnboundRepository));
    assert!(set
        .files
        .iter()
        .all(|f| f.repository_id != files[0].repository_id || !f.accepted));
}
