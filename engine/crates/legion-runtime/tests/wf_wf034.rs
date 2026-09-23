//! Tests ported from `tests/routing.test.mjs` (the routing-only cases; the
//! commercial-lens case in that file belongs to a different module and is
//! not part of this chunk), for wf034
//! (`src/lib/routing/{index,loader,resolver,validator}.mjs`).
//!
//! This file depends on `legion_runtime::wf_port::wf034`, which is not yet
//! wired into `legion-runtime`'s public module tree (the integrator adds
//! `pub mod wf_port;` in `src/lib.rs` and `pub mod wf034;` in
//! `src/wf_port/mod.rs` per the wf034 chunk assignment). Until that wiring
//! lands, this file will not compile as part of the crate's test target.
//!
//! Fixtures under `tests/fixtures/wf_wf034/` are a trimmed copy of
//! `src/registry/routing/domains.json` (verbatim) and a filtered copy of
//! `src/registry/skills/index.json` (only the bundles the domains registry
//! references, plus the `commit` entrypoint used by the
//! entrypoints-are-not-group-children case).

use std::path::{Path, PathBuf};

use legion_runtime::wf_port::wf034::{
    load_routing_groups, resolve_domain, resolve_group_child, validate_routing_groups,
    DomainResolution,
};
use serde_json::Value;

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_wf034")
}

fn domains_registry() -> Value {
    let text = std::fs::read_to_string(
        fixture_root().join("src/registry/routing/domains.json"),
    )
    .expect("read domains.json");
    serde_json::from_str(&text).expect("parse domains.json")
}

// ---------------------------------------------------------------------------
// "grouping domains resolve capabilities from the canonical catalog"
// ---------------------------------------------------------------------------

#[test]
fn grouping_domains_resolve_capabilities_from_the_canonical_catalog() {
    let root = fixture_root();
    let registry = domains_registry();
    let domain_ids: Vec<String> = registry["domains"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["id"].as_str().unwrap().to_string())
        .collect();

    for domain_id in &domain_ids {
        let resolution = resolve_domain(&root, domain_id).expect("resolve_domain");
        match resolution {
            DomainResolution::Resolved {
                domain_id: resolved_id,
                capabilities,
            } => {
                assert_eq!(&resolved_id, domain_id);
                assert!(!capabilities.is_empty(), "{domain_id} has capabilities");
                for capability in &capabilities {
                    // Roles are not grouping children.
                    assert!(
                        !capability.id.starts_with("sage")
                            && !capability.id.starts_with("alchemist")
                            && !capability.id.starts_with("oracle"),
                        "roles are not grouping children ({})",
                        capability.id
                    );
                    assert_eq!(
                        capability.manifest,
                        format!("skills/manifests/{}.json", capability.id)
                    );
                }
            }
            other => panic!("expected {domain_id} to resolve, got {other:?}"),
        }
    }

    let not_found = resolve_domain(&root, "not-a-declared-group").expect("resolve_domain");
    assert!(matches!(not_found, DomainResolution::NotFound { .. }));
}

// ---------------------------------------------------------------------------
// "registry is the single source of grouping children (RTE-001)"
// ---------------------------------------------------------------------------

#[test]
fn registry_is_the_single_source_of_grouping_children() {
    let root = fixture_root();
    let registry = domains_registry();
    let graph = load_routing_groups(&root).expect("load_routing_groups");

    for domain in registry["domains"].as_array().unwrap() {
        let domain_id = domain["id"].as_str().unwrap();
        let actual = graph
            .domains
            .iter()
            .find(|d| d.id == domain_id)
            .unwrap_or_else(|| panic!("{domain_id} present in loaded graph"));
        let expected_children: Vec<String> = domain["children"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|c| c["id"].as_str().unwrap().to_string())
            .collect();
        let actual_children: Vec<String> =
            actual.children.iter().map(|c| c.id.clone()).collect();
        assert_eq!(
            actual_children, expected_children,
            "{domain_id} children come from the registry"
        );
    }
}

// ---------------------------------------------------------------------------
// "grouping projection is capabilities-only; every child resolves to a
// catalog capability"
// ---------------------------------------------------------------------------

#[test]
fn grouping_projection_is_capabilities_only() {
    let root = fixture_root();
    let report = validate_routing_groups(&load_routing_groups(&root).unwrap());
    assert!(report.ok, "{:?}", report.findings);

    let graph = load_routing_groups(&root).unwrap();
    for domain in &graph.domains {
        for child in &domain.children {
            let record = resolve_group_child(&graph.skill_index, &child.id);
            assert!(record.is_some(), "{} is a catalog capability", child.id);
            assert_eq!(record.unwrap().id, child.id);
        }
    }

    assert!(
        resolve_group_child(&graph.skill_index, "commit").is_none(),
        "entrypoints are not group children"
    );
}

// ---------------------------------------------------------------------------
// "validator rejects duplicate groups, non-catalog children, and dangling
// members"
// ---------------------------------------------------------------------------

#[test]
fn validator_rejects_duplicate_groups_non_catalog_children_and_dangling_members() {
    let root = fixture_root();
    let graph = load_routing_groups(&root).unwrap();

    let mut invalid = graph.clone();
    let first = invalid.domains[0].clone();
    invalid.domains.push(first);
    invalid.domains[0].children.push(child("not-a-capability"));
    invalid.domains[0].children.push(child("sage"));
    invalid.domains[0].children.push(child("commit"));

    let report = validate_routing_groups(&invalid);
    assert!(!report.ok);
    assert!(report.findings.iter().any(|f| f.code == "duplicate-root"));
    assert_eq!(
        report
            .findings
            .iter()
            .filter(|f| f.code == "dangling-target")
            .count(),
        3
    );
}

fn child(id: &str) -> legion_runtime::wf_port::wf034::RoutingChild {
    legion_runtime::wf_port::wf034::RoutingChild {
        id: id.to_string(),
        extra: serde_json::Map::new(),
    }
}
