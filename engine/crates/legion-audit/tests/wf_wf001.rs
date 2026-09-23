//! Integration tests porting the JS test coverage for
//! `src/lib/analysis/components.mjs` and `src/lib/analysis/reachability.mjs`
//! (see `../../../../tests/reachability.test.mjs` in the JS tree).
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod wf001;`
//! inside it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf001::{
    build_components, join_reachability, reachability_gap, CallEvidence, Manifest, Package,
    ReachabilityState, ReachedFlag,
};

fn manifest(name: &str) -> Manifest {
    Manifest {
        name: name.to_string(),
        extra: serde_json::Map::new(),
    }
}

#[test]
fn build_components_sorts_edges_and_output() {
    let out = build_components(vec![
        Package {
            root: "packages/svc-b".to_string(),
            manifest: Some(manifest("svc-b")),
            dependencies: vec!["z-lib".to_string(), "a-lib".to_string()],
            dependents: vec![],
        },
        Package {
            root: "packages/svc-a".to_string(),
            manifest: Some(manifest("svc-a")),
            dependencies: vec![],
            dependents: vec!["z-app".to_string(), "a-app".to_string()],
        },
    ])
    .expect("valid manifests");

    assert_eq!(out.len(), 2);
    for c in &out {
        assert!(c.id.starts_with("component:"));
        assert_eq!(c.id.len(), "component:".len() + 20);
    }
    // Output sorted by id (lexicographic), matching localeCompare on ASCII hex.
    assert!(out[0].id <= out[1].id);

    let svc_b = out.iter().find(|c| c.root == "packages/svc-b").unwrap();
    assert_eq!(svc_b.dependencies, vec!["a-lib".to_string(), "z-lib".to_string()]);
    let svc_a = out.iter().find(|c| c.root == "packages/svc-a").unwrap();
    assert_eq!(svc_a.dependents, vec!["a-app".to_string(), "z-app".to_string()]);
}

#[test]
fn build_components_id_is_deterministic_hash_of_name_and_root() {
    let first = build_components(vec![Package {
        root: "packages/x".to_string(),
        manifest: Some(manifest("x-pkg")),
        dependencies: vec![],
        dependents: vec![],
    }])
    .unwrap();
    let second = build_components(vec![Package {
        root: "packages/x".to_string(),
        manifest: Some(manifest("x-pkg")),
        dependencies: vec![],
        dependents: vec![],
    }])
    .unwrap();
    assert_eq!(first[0].id, second[0].id);

    // A different root for the same manifest name changes the id (root is
    // part of the hash input, joined with a NUL byte in the JS source).
    let different_root = build_components(vec![Package {
        root: "packages/y".to_string(),
        manifest: Some(manifest("x-pkg")),
        dependencies: vec![],
        dependents: vec![],
    }])
    .unwrap();
    assert_ne!(first[0].id, different_root[0].id);
}

#[test]
fn build_components_missing_manifest_errors_with_root_in_message() {
    let err = build_components(vec![Package {
        root: "packages/missing".to_string(),
        manifest: None,
        dependencies: vec![],
        dependents: vec![],
    }])
    .unwrap_err();
    assert_eq!(err.to_string(), "component manifest required: packages/missing");
}

// --- reachability.mjs: tests/reachability.test.mjs ported 1:1 ---

#[test]
fn no_call_evidence_is_unknown() {
    let out = join_reachability(serde_json::Map::new(), Some(vec![]), None);
    assert_eq!(out.reachability, ReachabilityState::Unknown);
}

#[test]
fn verified_reach_is_reachable() {
    let out = join_reachability(
        serde_json::Map::new(),
        Some(vec![CallEvidence {
            id: None,
            from: None,
            to: None,
            provider: None,
            confidence: None,
            reached: ReachedFlag::Bool(true),
        }]),
        None,
    );
    assert_eq!(out.reachability, ReachabilityState::Reachable);
}

#[test]
fn unknown_is_never_inferred_from_missing_graph() {
    let gap = reachability_gap("x".to_string(), None, None);
    assert_eq!(gap.kind, "reachability-unproven");
    // A clean claim can never rely on the absence of reachability evidence.
    assert_ne!(gap.kind, "reachable");
}
