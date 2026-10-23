//! A09 acceptance coverage for native structural facts. Authored, never run
//! by the packet worker — root executes. Imports require root to add
//! `pub mod structure;` to `native_providers/architecture/mod.rs`.

use legion_audit::native_providers::architecture::structure::{
    analyze_structure, DuplicateKind, ExclusionReason, InvestigationPriority, ParseStatus,
    SeamKind, StructureConfig, StructureFileInput, StructureLanguage, UncertaintyKind,
};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
};

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/structure-quality")
}

fn collect(dir: &Path, prefix: &str, out: &mut Vec<StructureFileInput>) {
    let mut entries = fs::read_dir(dir)
        .expect("fixture dir")
        .map(|entry| entry.expect("fixture entry").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let relative = if prefix.is_empty() { name.clone() } else { format!("{prefix}/{name}") };
        if path.is_dir() {
            collect(&path, &relative, out);
        } else {
            out.push(StructureFileInput {
                path: relative,
                text: fs::read_to_string(&path).expect("fixture text"),
            });
        }
    }
}

fn fixture_inputs(subdir: &str) -> Vec<StructureFileInput> {
    let mut inputs = Vec::new();
    collect(&fixture_root().join(subdir), subdir, &mut inputs);
    inputs
}

fn test_config() -> StructureConfig {
    StructureConfig {
        review_loc_threshold: 20,
        duplicate_min_tokens: 25,
        qualified_token_languages: BTreeSet::new(),
        shared_invariants: Vec::new(),
    }
}

#[test]
fn clean_large_component_has_no_automatic_defect() {
    let facts = analyze_structure(&fixture_inputs("clean-large"), None, &test_config());
    let file = facts
        .files
        .iter()
        .find(|file| file.path.ends_with("Profile.tsx"))
        .expect("profile component measured");
    let metrics = file.metrics.as_ref().expect("parsed metrics");
    assert!(metrics.code_lines > 20, "fixture must exceed the review trigger");
    assert_eq!(file.parse_status, ParseStatus::Parsed);
    assert_eq!(file.grammar, "lexical-typescript/1");
    assert_eq!(
        file.component.investigation_priority,
        InvestigationPriority::None,
        "one coherent component over the LOC trigger is not a defect"
    );
    assert!(file.component.state.iter().any(|state| state.contains("useState")));
    assert!(!facts.proves_dead_code);
}

#[test]
fn one_impl_di_seam_and_legitimate_barrel_are_preserved() {
    let seam = analyze_structure(&fixture_inputs("di-seam"), None, &test_config());
    let store = &seam.files[0].component;
    assert_eq!(store.single_impl_abstractions, vec!["Store"]);
    assert!(store.seams.contains(&SeamKind::DependencyInjection));
    assert!(store.seams.contains(&SeamKind::Test));
    // Priority (if any) is investigation only; the preserved seam is recorded
    // as the reason this one-impl abstraction is not an automatic defect.
    // The genuinely orphaned private helper is only ever a candidate.
    let orphan = seam
        .unused_candidates
        .iter()
        .find(|candidate| candidate.symbol == "orphaned_helper")
        .expect("orphan is a candidate");
    assert!(!orphan.certifies_dead);

    let barrel = analyze_structure(&fixture_inputs("barrel"), None, &test_config());
    let index = barrel
        .files
        .iter()
        .find(|file| file.path.ends_with("index.ts"))
        .expect("barrel measured");
    assert!(index.component.seams.contains(&SeamKind::Barrel));
    assert!(barrel.logical_modules.iter().all(|module| !module.mechanical_split));
}

#[test]
fn mechanical_split_aggregates_logical_module() {
    let facts = analyze_structure(&fixture_inputs("mechanical-split"), None, &test_config());
    let module = facts
        .logical_modules
        .iter()
        .find(|module| module.mechanical_split)
        .expect("partNN group reconstructed");
    assert_eq!(module.member_paths.len(), 2);
    let summed: u64 = facts
        .files
        .iter()
        .filter(|file| module.member_paths.contains(&file.path))
        .filter_map(|file| file.metrics.as_ref().map(|metrics| metrics.code_lines))
        .sum();
    assert_eq!(module.aggregated_code_lines, summed);
    assert!(module.aggregated_code_lines > 0);
    assert!(module.evidence.iter().any(|line| line.contains("include!")));
}

#[test]
fn exact_and_near_duplicates_stay_distinct_and_qualification_gated() {
    let facts = analyze_structure(&fixture_inputs("duplicates"), None, &test_config());
    assert!(facts.duplicates.iter().any(|span| span.kind == DuplicateKind::Exact
        && span.language == StructureLanguage::Rust));
    assert!(facts.duplicates.iter().any(|span| span.kind == DuplicateKind::Near
        && span.language == StructureLanguage::TypeScript));
    assert!(facts.duplicates.iter().all(|span| !span.qualified));
    assert!(facts.replaces_jscpd_for.is_empty());
    assert!(facts.gaps.iter().any(|gap| gap.contains("duplication-unqualified")));
    assert!(facts
        .duplicates
        .iter()
        .all(|span| span.shared_abstraction.is_none()),
        "no shared abstraction without invariant/ownership evidence");
    for suggestion in &facts.suggestions {
        assert!(suggestion.severity.is_none());
        assert_eq!(suggestion.release_outcome_effect, "none");
        assert!(!suggestion.extraction_boundary.is_empty());
        assert!(!suggestion.callers.is_empty());
    }

    let mut qualified = test_config();
    qualified
        .qualified_token_languages
        .insert(StructureLanguage::Rust);
    let facts = analyze_structure(&fixture_inputs("duplicates"), None, &qualified);
    assert_eq!(facts.replaces_jscpd_for, vec![StructureLanguage::Rust]);
    assert!(facts
        .duplicates
        .iter()
        .filter(|span| span.language == StructureLanguage::Rust)
        .all(|span| span.qualified));
    assert!(facts
        .duplicates
        .iter()
        .filter(|span| span.language == StructureLanguage::TypeScript)
        .all(|span| !span.qualified));
}

#[test]
fn generated_and_vendor_exclusions_are_recorded() {
    let facts = analyze_structure(&fixture_inputs("excluded"), None, &test_config());
    assert!(facts.files.is_empty());
    assert!(facts.exclusions.iter().any(|exclusion| {
        exclusion.path.ends_with("api.g.ts")
            && matches!(
                exclusion.reason,
                ExclusionReason::GeneratedPath | ExclusionReason::GeneratedMarker
            )
    }));
    assert!(facts.exclusions.iter().any(|exclusion| {
        exclusion.path.contains("vendor/") && exclusion.reason == ExclusionReason::VendorPath
    }));
}

#[test]
fn reflected_and_route_discovered_symbols_cannot_be_certified_dead() {
    let facts = analyze_structure(&fixture_inputs("dynamic"), None, &test_config());
    assert!(facts.unused_candidates.iter().all(|candidate| !candidate.certifies_dead));
    assert!(!facts
        .unused_candidates
        .iter()
        .any(|candidate| candidate.symbol == "reflectedHandler"),
        "exported reflected handler is public API, never a dead candidate");
    let routes = facts
        .files
        .iter()
        .find(|file| file.path.ends_with("routes.ts"))
        .expect("routes measured");
    assert!(routes.uncertainties.contains(&UncertaintyKind::DynamicImport));
    assert!(routes.uncertainties.contains(&UncertaintyKind::Reflection));
    assert!(routes.uncertainties.contains(&UncertaintyKind::RouteDiscovery));

    let swift = facts
        .files
        .iter()
        .find(|file| file.path.ends_with("Reflected.swift"))
        .expect("swift measured");
    assert_eq!(swift.grammar, "lexical-swift/1");
    assert!(swift.uncertainties.contains(&UncertaintyKind::SwiftSelector));
    assert!(swift.metrics.is_some());

    let kotlin = facts
        .files
        .iter()
        .find(|file| file.path.ends_with("Screen.kt"))
        .expect("kotlin measured");
    assert_eq!(kotlin.grammar, "lexical-kotlin/1");
    assert!(kotlin.uncertainties.contains(&UncertaintyKind::AndroidResource));
    assert!(kotlin.metrics.is_some());
}

#[test]
fn unsupported_parse_is_partial_never_zero_complexity() {
    let facts = analyze_structure(&fixture_inputs("unsupported"), None, &test_config());
    let broken = &facts.files[0];
    assert!(matches!(broken.parse_status, ParseStatus::Partial { .. }));
    assert!(broken.metrics.is_none(), "unsupported syntax must not report zero complexity");
    assert!(facts.partial);
    assert!(facts.gaps.iter().any(|gap| gap.contains("partial-parse")));
    assert!(facts.duplicates.is_empty());
}

#[test]
fn graph_callers_flow_into_component_facts() {
    use legion_audit::graph_context::{ContextEdge, GraphContext, SourceSpan};
    let graph = GraphContext {
        contract_version: "legion-graph/1".into(),
        edges: vec![ContextEdge {
            from: "barrel/index.ts".into(),
            to: "barrel/config.ts".into(),
            kind: "imports".into(),
            confidence: "certain".into(),
            source: "blueprint".into(),
            evidence: SourceSpan {
                path: "barrel/index.ts".into(),
                start_line: 1,
                end_line: 1,
                source_digest: "sha256:fixture".into(),
            },
        }],
        ..GraphContext::default()
    };
    let facts = analyze_structure(&fixture_inputs("barrel"), Some(&graph), &test_config());
    let config = facts
        .files
        .iter()
        .find(|file| file.path.ends_with("config.ts"))
        .expect("config measured");
    assert!(config
        .component
        .callers
        .iter()
        .any(|caller| caller.contains("certain/blueprint")));
    assert!(!facts.proves_dead_code);
}
