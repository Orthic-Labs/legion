//! Integration tests for wf020 —
//! `src/lib/report/families/{data-privacy,docs-contract,governance,
//! requirements,shared}.mjs`.
//!
//! All five files reduce to one function, `buildFamilySummary` in
//! `shared.mjs`; the other four are verbatim
//! `export {buildFamilySummary} from './shared.mjs';` re-exports with no
//! body of their own. That function was already ported and unit-tested by
//! wf019 as `wf_port::wf019::family_summary::build_family_summary`
//! (assigned a *different* set of four re-export files —
//! `architecture.mjs`/`code.mjs`/`compatibility.mjs`/`data-integrity.mjs`
//! — that re-export the same `shared.mjs` function). `wf_port::wf020`
//! re-exports that same port rather than duplicating it; see
//! `engine/crates/legion-audit/src/wf_port/wf020/mod.rs` for the full
//! disposition note.
//!
//! No JS test file exists for any of this chunk's five source files, so
//! there is no JS assertion set to port test-for-test. These cases are
//! derived directly from the `buildFamilySummary` source in `shared.mjs`,
//! run against this chunk's own family names (`data-privacy`,
//! `docs-contract`, `governance`, `requirements`) as an independent
//! regression check.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod
//! wf019;` and `pub mod wf020;` inside it) into `legion_audit`'s crate
//! root.

use legion_audit::wf_port::wf020::{build_family_summary, Denominator, FamilyResult};

fn result(id: &str, family: &str, status: &str, complete: bool, expected: f64, examined: f64) -> FamilyResult {
    FamilyResult {
        id: Some(id.to_string()),
        provider: None,
        family: Some(family.to_string()),
        complete: Some(complete),
        status: Some(status.to_string()),
        denominator: Some(Denominator { expected, examined }),
        tool: None,
        raw_artifacts: Vec::new(),
        component_ids: Vec::new(),
        limitations: Vec::new(),
    }
}

#[test]
fn data_privacy_family_clean_when_all_providers_present_and_complete() {
    let results = vec![
        result("p1", "data-privacy", "pass", true, 3.0, 3.0),
        result("p2", "data-privacy", "pass", true, 2.0, 2.0),
        // A result from an unrelated family must not be pulled in.
        result("p3", "governance", "pass", true, 1.0, 1.0),
    ];
    let summary = build_family_summary(
        &results,
        Some("data-privacy"),
        &["p1".to_string(), "p2".to_string()],
        &[],
    );
    assert_eq!(summary.status, "complete");
    assert!(summary.clean);
    assert!(summary.gaps.is_empty());
    assert_eq!(summary.providers.len(), 2);
    assert!(summary.providers.iter().all(|p| p.id.as_deref() != Some("p3")));
}

#[test]
fn docs_contract_family_empty_selection_reports_denominator_zero() {
    let results: Vec<FamilyResult> = vec![];
    let summary = build_family_summary(&results, Some("docs-contract"), &["only".to_string()], &[]);
    assert!(!summary.clean);
    assert_eq!(summary.status, "incomplete");
    assert!(summary
        .gaps
        .iter()
        .any(|g| g.kind == "family-denominator-zero" && g.family.as_deref() == Some("docs-contract")));
    assert!(summary
        .gaps
        .iter()
        .any(|g| g.kind == "required-provider-missing" && g.provider_id.as_deref() == Some("only")));
}

#[test]
fn governance_family_incomplete_denominator_is_flagged_incomplete() {
    // examined (2) does not reach expected (5): incomplete per JS
    // `denominator.examined !== denominator.expected`.
    let results = vec![result("gov-a", "governance", "pass", true, 5.0, 2.0)];
    let summary = build_family_summary(&results, Some("governance"), &["gov-a".to_string()], &[]);
    assert!(!summary.clean);
    assert_eq!(summary.status, "incomplete");
    assert!(summary
        .gaps
        .iter()
        .any(|g| g.kind == "provider-result-incomplete" && g.provider_id.as_deref() == Some("gov-a")));
    assert_eq!(summary.incomplete_providers, vec!["gov-a".to_string()]);
}

#[test]
fn requirements_family_non_pass_status_counts_as_incomplete() {
    // status != 'pass' also trips JS's incomplete check even when the
    // denominator and `complete` flag both look clean.
    let results = vec![result("req-a", "requirements", "fail", true, 1.0, 1.0)];
    let summary = build_family_summary(&results, Some("requirements"), &["req-a".to_string()], &[]);
    assert!(!summary.clean);
    assert!(summary
        .gaps
        .iter()
        .any(|g| g.kind == "provider-result-incomplete" && g.provider_id.as_deref() == Some("req-a")));
}

#[test]
fn selected_provider_ids_narrow_the_denominator_over_required() {
    // JS: `expected = selectedProviderIds.length ? selectedProviderIds :
    // requiredProviderIds`. With a non-empty selection, a required id not
    // in the selection is not pulled into `expected` and so produces no
    // gap for being "missing" from selection — but it IS still unioned
    // into the `missing` check via `[...required, ...selected]`, so it is
    // reported once selection excludes it from `selected`.
    let results = vec![result("chosen", "data-privacy", "pass", true, 1.0, 1.0)];
    let summary = build_family_summary(
        &results,
        Some("data-privacy"),
        &["chosen".to_string(), "unchosen".to_string()],
        &["chosen".to_string()],
    );
    assert_eq!(summary.providers.len(), 1);
    assert_eq!(summary.providers[0].id.as_deref(), Some("chosen"));
    let gap = summary
        .gaps
        .iter()
        .find(|g| g.provider_id.as_deref() == Some("unchosen"))
        .expect("unchosen must still surface as a gap");
    assert_eq!(gap.kind, "required-provider-missing");
}

#[test]
fn provider_id_falls_back_to_provider_field_for_all_four_owned_families() {
    for family in ["data-privacy", "docs-contract", "governance", "requirements"] {
        let mut r = result("unused", family, "pass", true, 1.0, 1.0);
        r.id = None;
        r.provider = Some("prov-fallback".to_string());
        let summary = build_family_summary(&[r], Some(family), &["prov-fallback".to_string()], &[]);
        assert!(summary.clean, "family {family} should be clean");
        assert_eq!(summary.providers[0].id.as_deref(), Some("prov-fallback"));
    }
}
