//! Integration coverage for chunk w2_056: the faithful port of
//! `src/lib/skills/{dependency-closure,loader,resolver,route-resources,
//! verify}.mjs` in `legion_runtime::wf_port::w2_056`.
//!
//! Exercises the five ported modules together against a small fixture
//! package under `tests/fixtures/wf_w2_056/`, mirroring the shape of
//! `tests/dependency-closure.test.mjs` and `tests/skills/wave1.test.mjs`
//! without depending on the live repository's own `skills/` tree (which
//! evolves independently of this port).

use std::collections::BTreeMap;
use std::path::PathBuf;

use legion_runtime::wf_port::w2_056::{
    load_skill, resolve_skill_invocation, verify_dependency_closure, verify_skill_bytes,
    verify_skill_catalog, LoadedSkill, SelectionSource,
};

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/wf_w2_056")
}

fn registry() -> serde_json::Value {
    let path = fixture_root().join("src/registry/capabilities.json");
    let text = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn demo_manifest() -> serde_json::Value {
    let path = fixture_root().join("skills/demo/manifest.json");
    let text = std::fs::read_to_string(path).unwrap();
    serde_json::from_str(&text).unwrap()
}

#[test]
fn dependency_closure_is_clean_over_the_fixture_package() {
    let root = fixture_root();
    let mut manifests = BTreeMap::new();
    manifests.insert("demo".to_string(), demo_manifest());

    let result = verify_dependency_closure(&root, &manifests, &registry()).unwrap();
    assert!(result.ok, "unexpected findings: {:?}", result.findings);
    assert_eq!(result.summary.semantic_bundles, 1);
    assert_eq!(result.summary.dependency_declarations, 1);
    assert_eq!(result.summary.typed_resources, 2);
}

#[test]
fn dependency_closure_flags_a_host_capability_with_no_registry_entry() {
    let root = fixture_root();
    let mut manifest = demo_manifest();
    // Corrupt the in-memory manifest's declared consumer to also exercise
    // verifyManifestConsumers' stale-consumer path in the same pass.
    manifest["parity"] = serde_json::json!({"consumers": ["skills/demo/does-not-exist.mjs"]});
    let mut manifests = BTreeMap::new();
    manifests.insert("demo".to_string(), manifest);

    let mut broken_registry = registry();
    broken_registry["capabilities"]
        .as_object_mut()
        .unwrap()
        .remove("browser-automation");

    let result = verify_dependency_closure(&root, &manifests, &broken_registry).unwrap();
    assert!(!result.ok);
    let codes: Vec<&str> = result.findings.iter().map(|f| f.code).collect();
    assert!(codes.contains(&"undeclared-capability"));
    assert!(codes.contains(&"host-requirement-mismatch"));
    assert!(codes.contains(&"stale-consumer"));
}

#[test]
fn resolver_resolves_explicit_command_and_alias() {
    let root = fixture_root();
    let direct = resolve_skill_invocation("/demo hello", &root).unwrap();
    match direct {
        legion_runtime::wf_port::w2_056::InvocationResolution::Resolved { canonical, argument_text, .. } => {
            assert_eq!(canonical, "demo");
            assert_eq!(argument_text, "hello");
        }
        other => panic!("unexpected {other:?}"),
    }

    let via_alias = resolve_skill_invocation("/d hello", &root).unwrap();
    match via_alias {
        legion_runtime::wf_port::w2_056::InvocationResolution::Resolved { canonical, .. } => {
            assert_eq!(canonical, "demo");
        }
        other => panic!("unexpected {other:?}"),
    }

    let not_command = resolve_skill_invocation("plain text", &root).unwrap();
    assert_eq!(
        not_command,
        legion_runtime::wf_port::w2_056::InvocationResolution::NotExplicitCommand
    );
}

#[test]
fn resolver_validates_semantic_selection_against_the_catalog() {
    let root = fixture_root();
    let ids = vec!["demo".to_string(), "missing".to_string()];
    let result =
        legion_runtime::wf_port::w2_056::validate_capability_selection(&ids, SelectionSource::Semantic, &root)
            .unwrap();
    assert_eq!(result.status, "invalid");
    assert_eq!(result.resolved.len(), 1);
    assert_eq!(result.resolved[0].id, "demo");
    assert_eq!(result.invalid.len(), 1);
    assert_eq!(result.invalid[0].reason, "not-found");
}

#[test]
fn loader_loads_and_projects_the_ready_file() {
    let root = fixture_root();
    let bytes = std::fs::read(root.join("skills/demo/SKILL.md")).unwrap();
    let (_, digest) = verify_skill_bytes(&bytes, "");

    let mut manifest = demo_manifest();
    manifest["files"] = serde_json::json!([{"path": "SKILL.md", "digest": digest}]);
    let mut manifests = BTreeMap::new();
    manifests.insert("demo".to_string(), manifest);

    let loaded = load_skill("legion-skill://demo/SKILL.md", &root, &manifests, "audit").unwrap();
    match loaded {
        LoadedSkill::Ready { text, capabilities, .. } => {
            assert!(text.contains("Body text with no host commands."));
            assert!(!capabilities.mutation);
            assert!(!capabilities.publish);
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn loader_reports_corrupt_on_digest_mismatch() {
    let root = fixture_root();
    let mut manifest = demo_manifest();
    manifest["files"] = serde_json::json!([{"path": "SKILL.md", "digest": "sha256:deadbeef"}]);
    let mut manifests = BTreeMap::new();
    manifests.insert("demo".to_string(), manifest);

    let loaded = load_skill("legion-skill://demo/SKILL.md", &root, &manifests, "audit").unwrap();
    assert!(matches!(loaded, LoadedSkill::Corrupt { .. }));
}

#[test]
fn verify_skill_catalog_matches_the_fixture_digest() {
    let root = fixture_root();
    let bytes = std::fs::read(root.join("skills/demo/SKILL.md")).unwrap();
    let (_, digest) = verify_skill_bytes(&bytes, "");

    let mut manifest = demo_manifest();
    manifest["files"] = serde_json::json!([
        {"path": "SKILL.md", "digest": digest, "uri": "legion-skill://demo/SKILL.md"},
    ]);

    let result = verify_skill_catalog(&root, &[manifest], false);
    // `dependencies.json`, `notes.md`, and `manifest.json` are on disk but
    // not declared in this trimmed manifest, so they surface as `unexpected`
    // — exactly what `verifySkillCatalog` is for.
    assert!(!result.ok);
    assert!(result.findings.iter().all(|f| f.code == "unexpected"));
}
