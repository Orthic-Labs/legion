//! Integration coverage for `legion_runtime::l4_platform::distribution`,
//! ported from `tests/public-l5-distribution.deepseek.test.mjs` (B8-017,
//! B8-018, B8-024) in the JS legacy spec.

use legion_runtime::l4_platform::distribution::{
    build_notice_inventory, build_release_manifest, generate_claims, generate_claims_from_qualification,
    generate_sboms, inventory_distribution, inventory_runtime_dependencies, reconcile_distribution_contents,
    render_notices, render_support_markdown, ReleaseManifestInput,
};
use serde_json::json;
use std::fs;

#[test]
fn b8_017_sboms_notices_and_provenance_blockers() {
    let components = vec![json!({
        "name": "legion", "version": "1.0.0", "license": "SEE LICENSE", "source": "local",
        "shipped": true, "distributionStatus": "integrated",
    })];
    let sboms = generate_sboms("legion", &components, None);
    assert_eq!(sboms["cyclonedx"]["components"].as_array().unwrap().len(), 1);
    assert_eq!(sboms["spdx"]["packages"].as_array().unwrap().len(), 1);

    let inventory = build_notice_inventory(&components);
    assert_eq!(inventory["blockers"].as_array().unwrap().len(), 0);
    assert!(render_notices(inventory["components"].as_array().unwrap()).contains("legion"));

    let creator_blockers = build_notice_inventory(&[json!({"name": "creator", "shipped": true, "source": "external", "license": Option::<String>::None})]);
    assert_eq!(creator_blockers["blockers"][0]["kind"], "redistribution-rights-unresolved");

    let manifest = json!({"dependencies": {"alpha": "1.2.3"}});
    let provenance = json!({"alpha": {"source": "registry", "digest": "sha256:a", "license": "MIT"}});
    let runtime_inventory = inventory_runtime_dependencies(&manifest, &provenance);
    assert_eq!(
        runtime_inventory[0],
        json!({"type": "library", "name": "alpha", "version": "1.2.3", "source": "registry", "digest": "sha256:a", "license": "MIT", "shipped": true, "distributionStatus": "integrated"})
    );

    let creator_material = vec![json!({"name": "designer", "shipped": false})];
    let distribution = inventory_distribution(&[&runtime_inventory, &creator_material]);
    assert_eq!(distribution[0]["name"], "alpha");
    assert_eq!(reconcile_distribution_contents(&distribution, &[json!("alpha")])["decision"], "QUALIFIED");
    assert_eq!(reconcile_distribution_contents(&distribution, &[])["decision"], "BLOCKED");
}

#[test]
fn b8_018_release_manifest_binds_final_bytes() {
    let root = std::env::temp_dir().join(format!("legion-l4-release-it-{}", std::process::id()));
    let _ = fs::create_dir_all(root.join("dist"));
    fs::write(root.join("dist/pkg.tgz"), b"final-bytes").unwrap();
    fs::write(root.join("sbom.json"), br#"{"components":[{"name":"legion"}]}"#).unwrap();
    fs::write(root.join("NOTICE.md"), b"notice").unwrap();
    fs::write(root.join("SHA256SUMS"), b"sum").unwrap();

    let manifest = build_release_manifest(ReleaseManifestInput {
        root: &root,
        version: "1.0.0",
        source_revision: "1234567",
        artifacts: vec![json!({"path": "dist/pkg.tgz", "type": "package"})],
        channels: vec![json!({"id": "internal"})],
        checksums: vec![json!({"path": "SHA256SUMS"})],
        sboms: vec![json!({"path": "sbom.json"})],
        notices: vec![json!({"path": "NOTICE.md"})],
        signatures: vec![json!({"path": "signature.json", "status": "placeholder"})],
        notarization: vec![],
        qualification_artifacts: vec![],
    });
    assert!(manifest["sboms"][0]["digest"].as_str().unwrap().starts_with("sha256:"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn b8_024_claims_derive_from_exact_measured_identity() {
    let claims = generate_claims(&[json!({
        "id": "js", "subject": "JavaScript", "state": "deterministic-measured",
        "artifactDigest": "sha256:a", "corpusDigest": "sha256:c", "providerDigest": "sha256:p",
        "expectedIdentity": {"artifactDigest": "sha256:a", "corpusDigest": "sha256:c", "providerDigest": "sha256:p"},
        "hostCapabilities": ["process"], "authorityLimits": ["source-only"], "resourceConstraints": {"maxConcurrency": 1},
    })]);
    assert_eq!(claims[0]["state"], "deterministic-measured");
    assert_eq!(claims[0]["authorityLimits"], json!(["source-only"]));
    assert!(render_support_markdown(&claims).contains("deterministic-measured"));

    let downgraded = generate_claims(&[json!({
        "id": "bad", "subject": "Bad", "state": "deterministic-measured",
        "artifactDigest": "sha256:x", "corpusDigest": "sha256:c", "providerDigest": "sha256:p",
        "expectedIdentity": {"artifactDigest": "sha256:a", "corpusDigest": "sha256:c", "providerDigest": "sha256:p"},
    })]);
    assert_eq!(downgraded[0]["state"], "unproven");

    let self_only = generate_claims(&[json!({
        "id": "self", "state": "deterministic-measured",
        "artifactDigest": "sha256:x", "corpusDigest": "sha256:y", "providerDigest": "sha256:z",
    })]);
    assert_eq!(self_only[0]["state"], "unproven");

    let from_qualification =
        generate_claims_from_qualification(Some(&json!({"claims": [{"id": "self", "state": "deterministic-measured"}]})), None);
    assert_eq!(from_qualification["claims"][0]["state"], "unproven");
}
