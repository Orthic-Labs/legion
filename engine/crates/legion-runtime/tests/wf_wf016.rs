//! Integration coverage for chunk wf016
//! (`src/lib/remediation/{design-proposal,effect-graph,fix-contract,mechanical}.mjs`
//! and `src/lib/remediation/producers/config.mjs`).
//!
//! These exercise the ported functions the way a caller outside the crate
//! would: through `legion_runtime::wf_port::wf016::*` (once the integrator
//! wires `pub mod wf_port;` into `legion_runtime`'s `lib.rs`). Unit tests
//! covering internal edge cases live alongside each ported file under
//! `src/wf_port/wf016/`.

use legion_runtime::wf_port::wf016::{
    blocks_auto_apply, build_effect_graph, build_effect_graph_schema, design_proposal, evaluate_fix_loop, fix_proposal, mechanical_registry,
    plan_mechanical_remediation, producer_for, BuildEffectGraphInput, DesignProposalInput, EvaluateFixLoopInput, FixProposalInput, FIX_STOPS,
};
use serde_json::json;

#[test]
fn fix_contract_round_trip() {
    let proposal = fix_proposal(FixProposalInput {
        finding_id: json!("finding-1"),
        root_cause_digest: json!("sha256:root"),
        producer: json!({ "engine": "ast-grep" }),
        target_paths: vec!["b.js".to_string(), "a.js".to_string()],
        preconditions: vec!["parse-clean".to_string()],
        patch: json!({ "path": "patches/fix.patch", "digest": null }),
        expected_behavior: vec!["fixed".to_string()],
        risks: vec!["regression".to_string()],
        validation_commands: vec!["affected-provider-rerun".to_string()],
        tier: json!("MECHANICAL"),
    });
    assert_eq!(proposal["targetPaths"], json!(["a.js", "b.js"]));
    assert!(proposal["id"].as_str().unwrap().starts_with("sha256:"));

    assert_eq!(FIX_STOPS.len(), 8);
    let decision = evaluate_fix_loop(EvaluateFixLoopInput { batch_index: 0, regression: true, ..Default::default() });
    assert!(decision.stop);
    assert_eq!(decision.reason, Some("regression"));
}

#[test]
fn effect_graph_flags_unplanned_public_surface_and_computes_closure() {
    let plan_graph = json!({
        "providers": [
            { "id": "security.cookie", "paths": ["src/config/**"], "family": "security", "dependsOn": [], "requiredForCleanClaim": true },
            { "id": "ux.checkout", "paths": [], "family": "ux", "dependsOn": ["security.cookie"], "requiredForCleanClaim": false },
        ],
        "baselineGates": [{ "id": "g-security", "requiredForApply": true }],
    });
    let proposal = json!({
        "id": "prop-1",
        "findingIds": ["f1"],
        "patch": { "digest": "sha256:patch" },
        "targetPaths": ["src/config/cookies.json"],
        "publicSurfaceChanges": [],
        "changes": [],
    });
    let effect_graph = build_effect_graph(BuildEffectGraphInput {
        proposal,
        plan_graph,
        binding: json!({ "runId": "r1" }),
        observed_public_surface_changes: vec!["api:/v1/checkout".to_string()],
        ..Default::default()
    })
    .expect("effect graph builds");

    assert_eq!(effect_graph["affectedProviders"], json!(["security.cookie", "ux.checkout"]));
    assert_eq!(effect_graph["requiredProviders"], json!(["security.cookie"]));
    assert_eq!(effect_graph["requiredGates"], json!(["g-security"]));
    assert!(blocks_auto_apply(&effect_graph));

    let schema = build_effect_graph_schema();
    assert_eq!(schema["title"], json!("RemediationEffectGraphV1"));
}

#[test]
fn mechanical_registry_and_plan_remediation_for_config_rules() {
    let registry = mechanical_registry();
    assert!(registry.iter().any(|e| e.id == "config.cookie-samesite"));
    assert!(registry.iter().any(|e| e.id == "config.content-type-nosniff"));

    assert!(producer_for("browser-http.content-type-nosniff").is_some());
    assert!(producer_for("unknown-rule").is_none());

    let finding = json!({
        "id": "finding-cookie",
        "ruleId": "browser-http.cookie-samesite",
        "location": { "path": "config/session.json" },
    });
    let sandbox = json!({ "kind": "legion-remediation-sandbox", "primaryRepositoryMutated": false });
    let proposal =
        plan_mechanical_remediation(&finding, &sandbox, |_path| "{\n  \"cookie\": { \"secure\": true }\n}".to_string(), &json!({ "runId": "r1" }))
            .expect("plans a mechanical proposal");
    assert_eq!(proposal["tier"], json!("MECHANICAL"));
    assert_eq!(proposal["owner"], json!("code"));
    assert_eq!(proposal["producer"]["id"], json!("config.cookie-samesite"));
    assert_eq!(proposal["patch"]["edits"][0]["keyPath"], json!(["cookie", "sameSite"]));
}

#[test]
fn design_proposal_preserves_approved_text_and_rejects_out_of_scope_paths() {
    let packet = json!({
        "owner": "designer",
        "findingIds": ["f-design"],
        "producer": { "id": "designer-agent" },
        "digest": "sha256:packet",
        "scope": ["src/ui/**"],
        "protectedSurfaces": ["src/ui/legal/**"],
        "approvedTextDigests": { "hero": "sha256:approved-hero" },
    });

    let ok = design_proposal(DesignProposalInput {
        packet: packet.clone(),
        changes: vec![json!({ "kind": "layout", "path": "src/ui/Hero.tsx" })],
        preserved_text_digests: json!({ "hero": "sha256:approved-hero" }),
        binding: json!({ "runId": "r1" }),
    })
    .expect("preserved text passes");
    assert_eq!(ok["owner"], json!("designer"));
    assert_eq!(ok["tier"], json!("DESIGN"));
    assert_eq!(ok["preservedTextDigests"], json!({ "hero": "sha256:approved-hero" }));

    let rejected_text = design_proposal(DesignProposalInput {
        packet: packet.clone(),
        changes: vec![json!({ "kind": "layout", "path": "src/ui/Hero.tsx" })],
        preserved_text_digests: json!({ "hero": "sha256:tampered" }),
        binding: json!({}),
    })
    .unwrap_err();
    assert!(rejected_text.0.contains("may not alter approved text"));

    let rejected_protected = design_proposal(DesignProposalInput {
        packet,
        changes: vec![json!({ "kind": "layout", "path": "src/ui/legal/Terms.tsx" })],
        preserved_text_digests: json!({ "hero": "sha256:approved-hero" }),
        binding: json!({}),
    })
    .unwrap_err();
    assert!(rejected_protected.0.contains("protected surface"));
}
