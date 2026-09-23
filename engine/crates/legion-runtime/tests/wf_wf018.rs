//! Tests ported from `tests/security-l4/b7-033-effect-graph-verification.test.mjs`,
//! `tests/security-l4/b7-032-reasoning-packets.test.mjs` (the `writingProposal`
//! and shared `assertOwnerAuthority`/`assertProducerIsNotVerifier` cases), and
//! `tests/remediation/worktree.test.mjs`, for wf018
//! (`src/lib/remediation/{verify-proposal,worktree,writing-proposal}.mjs`).
//!
//! This test file depends on `legion_runtime::wf_port::wf018`, which is not
//! yet wired into `legion-runtime`'s public module tree (the integrator adds
//! `pub mod wf_port;` in `src/lib.rs` and `pub mod wf018;` in
//! `src/wf_port/mod.rs` per the wf018 chunk assignment). Until that wiring
//! lands, this file will not compile as part of the crate's test target.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use legion_runtime::wf_port::wf018::{
    assert_owner_authority, assert_producer_is_not_verifier, assert_path_allowed,
    build_verification_schema, create_remediation_worktree, remove_remediation_worktree,
    verify_proposal, worktree_receipt, writing_proposal, ProcessOutcome, ProcessRunner,
    ProcessSpec,
};
use serde_json::json;

// ---------------------------------------------------------------------------
// Shared test fixtures.
// ---------------------------------------------------------------------------

fn binding() -> serde_json::Value {
    json!({
        "planDigest": "sha256:plan",
        "repositoryRevision": "abc123",
        "dirtyPatchDigest": null,
        "blueprintGenerationId": "gen",
        "blueprintManifestDigest": "sha256:manifest",
        "registryDigest": "sha256:registry",
    })
}

fn writing_packet() -> serde_json::Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-remediation-packet",
        "owner": "writing",
        "tier": "WRITING",
        "findingIds": ["sha256:finding"],
        "scope": ["content/home.md"],
        "protectedSurfaces": ["src/**", "schemas/**"],
        "producer": { "id": "writing.copy-agent", "kind": "reasoning", "version": "1.0.0", "contextId": "ctx-producer" },
        "binding": binding(),
        "digest": "sha256:packet",
    })
}

// ---------------------------------------------------------------------------
// b7-032-reasoning-packets.test.mjs — assertOwnerAuthority
// ---------------------------------------------------------------------------

#[test]
fn each_owner_has_exactly_its_own_authority_and_nothing_more() {
    // JS: assert.equal(assertOwnerAuthority('writing', { kind: 'text' }), true);
    assert!(assert_owner_authority("writing", &json!({ "kind": "text" })).is_ok());
    // JS: assert.throws(() => assertOwnerAuthority('writing', { kind: 'source-patch' }), /writing proposals may change words only/);
    let err = assert_owner_authority("writing", &json!({ "kind": "source-patch" })).unwrap_err();
    assert!(err.contains("writing proposals may change words only"));
    let err = assert_owner_authority("writing", &json!({ "kind": "style" })).unwrap_err();
    assert!(err.contains("writing proposals may change words only"));
    // JS: assert.equal(assertOwnerAuthority('designer', { kind: 'style' }), true);
    assert!(assert_owner_authority("designer", &json!({ "kind": "style" })).is_ok());
    assert!(assert_owner_authority("designer", &json!({ "kind": "layout" })).is_ok());
    let err = assert_owner_authority("designer", &json!({ "kind": "text" })).unwrap_err();
    assert!(err.contains("designer proposals may not change approved text"));
    assert!(assert_owner_authority("code", &json!({ "kind": "source-patch" })).is_ok());
    let err = assert_owner_authority("code", &json!({ "kind": "text" })).unwrap_err();
    assert!(err.contains("code proposals may change bounded source only"));
}

// ---------------------------------------------------------------------------
// b7-032-reasoning-packets.test.mjs — a writing proposal changes words only
// and stays inside its scope
// ---------------------------------------------------------------------------

#[test]
fn a_writing_proposal_changes_words_only_and_stays_inside_its_scope() {
    let packet = writing_packet();
    let proposal = writing_proposal(
        &packet,
        &[json!({
            "kind": "text",
            "path": "content/home.md",
            "contentItemId": "sha256:item",
            "before": "the #1 fastest platform",
            "after": "a fast platform",
        })],
        &binding(),
    )
    .unwrap();

    assert_eq!(proposal["kind"], "legion-remediation-proposal");
    assert_eq!(proposal["owner"], "writing");
    assert_eq!(proposal["tier"], "WRITING");
    assert_eq!(proposal["targetPaths"], json!(["content/home.md"]));
    assert!(proposal.get("verified").is_none());
    assert!(proposal.get("applied").is_none());
    assert_eq!(proposal["contentItemIds"], json!(["sha256:item"]));

    // JS: assert.throws(..., /writing proposals may change words only/);
    let err = writing_proposal(
        &packet,
        &[json!({ "kind": "source-patch", "path": "src/app.mjs" })],
        &binding(),
    )
    .unwrap_err();
    assert!(err.contains("writing proposals may change words only"));

    // A protected surface is the stronger rejection and wins over mere scope.
    let err = writing_proposal(
        &packet,
        &[json!({ "kind": "text", "path": "src/app.mjs", "contentItemId": "x" })],
        &binding(),
    )
    .unwrap_err();
    assert!(err.contains("protected surface"));

    let err = writing_proposal(
        &packet,
        &[json!({ "kind": "text", "path": "content/about.md", "contentItemId": "x" })],
        &binding(),
    )
    .unwrap_err();
    assert!(err.contains("outside the packet scope"));
}

#[test]
fn a_writing_proposal_rejects_a_change_missing_its_content_item_id() {
    let packet = writing_packet();
    let err = writing_proposal(
        &packet,
        &[json!({ "kind": "text", "path": "content/home.md" })],
        &binding(),
    )
    .unwrap_err();
    assert!(err.contains("must name the content item it rewrites"));
}

#[test]
fn assert_path_allowed_matches_the_reasoning_packets_semantics() {
    let packet = writing_packet();
    assert!(assert_path_allowed(&packet, "content/home.md").is_ok());
    assert!(assert_path_allowed(&packet, "src/app.mjs").unwrap_err().contains("protected surface"));
    assert!(assert_path_allowed(&packet, "content/about.md").unwrap_err().contains("outside the packet scope"));
}

// ---------------------------------------------------------------------------
// b7-033-effect-graph-verification.test.mjs
// ---------------------------------------------------------------------------

fn proposal_fixture() -> serde_json::Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-remediation-proposal",
        "id": "sha256:proposal",
        "findingIds": ["sha256:finding"],
        "owner": "code",
        "producer": { "id": "code.agent", "kind": "reasoning", "version": "1.0.0", "contextId": "ctx-producer" },
        "targetPaths": ["src/render.mjs"],
        "patch": { "path": "patches/code.patch", "digest": "sha256:patch" },
        "changes": [{ "kind": "source-patch", "path": "src/render.mjs", "symbols": ["renderBody"] }],
        "tier": "AGENT_GUIDED",
        "binding": binding(),
        "verified": true,
        "providersPass": true,
    })
}

fn effect_graph_fixture() -> serde_json::Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-patch-effect-graph",
        "proposalId": "sha256:proposal",
        "changedFiles": ["src/render.mjs"],
        "changedSymbols": ["renderBody"],
        "changedConfig": [],
        "contentItems": [],
        "publicSurfaceChanges": [],
        "unplannedPublicSurfaceChanges": [],
        "affectedProviders": ["report.render", "security.evidence-synthesis", "security.output-handling"],
        "affectedFamilies": ["report", "security"],
        "requiredProviders": ["security.evidence-synthesis", "security.output-handling"],
        "requiredGates": ["gate.no-new-high", "gate.tests-pass"],
        "digest": "sha256:effect",
        "binding": binding(),
    })
}

fn verifier() -> serde_json::Value {
    json!({ "id": "verify.neutral", "contextId": "ctx-verifier" })
}

fn full_provider_results() -> Vec<serde_json::Value> {
    vec![
        json!({ "provider": "security.output-handling", "complete": true, "status": "pass" }),
        json!({ "provider": "security.evidence-synthesis", "complete": true, "status": "pass" }),
    ]
}

fn full_gate_results() -> Vec<serde_json::Value> {
    vec![
        json!({ "id": "gate.no-new-high", "passed": true }),
        json!({ "id": "gate.tests-pass", "passed": true }),
    ]
}

#[test]
fn producer_and_verifier_identities_must_be_distinct() {
    let effect = effect_graph_fixture();
    let proposal = proposal_fixture();
    let providers = full_provider_results();
    let gates = full_gate_results();

    let verdict = verify_proposal(&proposal, &effect, &verifier(), &providers, &gates, &binding()).unwrap();
    assert_eq!(verdict["valid"], true);

    // JS: same id as producer -> throws.
    let err = verify_proposal(
        &proposal,
        &effect,
        &json!({ "id": "code.agent", "contextId": "ctx-x" }),
        &providers,
        &gates,
        &binding(),
    )
    .unwrap_err();
    assert!(err.contains("producer may not verify its own proposal"));

    // JS: same contextId as producer -> throws.
    let err = verify_proposal(
        &proposal,
        &effect,
        &json!({ "id": "verify.neutral", "contextId": "ctx-producer" }),
        &providers,
        &gates,
        &binding(),
    )
    .unwrap_err();
    assert!(err.contains("producer may not verify its own proposal"));
}

#[test]
fn verification_never_trusts_producer_supplied_pass_booleans() {
    let effect = effect_graph_fixture();
    let proposal = proposal_fixture();
    let providers = vec![
        json!({ "provider": "security.output-handling", "complete": true, "status": "fail" }),
        json!({ "provider": "security.evidence-synthesis", "complete": true, "status": "pass" }),
    ];
    let gates = full_gate_results();

    let verdict = verify_proposal(&proposal, &effect, &verifier(), &providers, &gates, &binding()).unwrap();
    assert_eq!(verdict["valid"], false);
    assert!(verdict["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["kind"] == "affected-provider-failed"));
    assert_eq!(verdict["verifiedBy"], "neutral-verification");
    assert_eq!(verdict["trustedProducerAssertions"], false);
}

#[test]
fn all_affected_mandatory_evidence_and_baseline_gates_must_be_present_and_pass() {
    let effect = effect_graph_fixture();
    let proposal = proposal_fixture();
    let full = full_provider_results();
    let gates = full_gate_results();

    let missing_provider = verify_proposal(&proposal, &effect, &verifier(), &full[..1], &gates, &binding()).unwrap();
    assert_eq!(missing_provider["valid"], false);
    assert!(missing_provider["coverageGaps"].as_array().unwrap().iter().any(|gap| {
        gap["kind"] == "missing-affected-provider" && gap["provider"] == "security.evidence-synthesis"
    }));

    let missing_gate = verify_proposal(&proposal, &effect, &verifier(), &full, &gates[..1], &binding()).unwrap();
    assert_eq!(missing_gate["valid"], false);
    assert!(missing_gate["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["kind"] == "missing-baseline-gate" && gap["gate"] == "gate.tests-pass"));

    let incomplete_providers = vec![
        full[0].clone(),
        json!({ "provider": "security.evidence-synthesis", "complete": false, "status": "pass" }),
    ];
    let incomplete = verify_proposal(&proposal, &effect, &verifier(), &incomplete_providers, &gates, &binding()).unwrap();
    assert_eq!(incomplete["valid"], false);
}

#[test]
fn vacuous_verification_is_rejected_when_effects_exist() {
    let effect = effect_graph_fixture();
    let proposal = proposal_fixture();

    let vacuous = verify_proposal(&proposal, &effect, &verifier(), &[], &[], &binding()).unwrap();
    assert_eq!(vacuous["valid"], false);
    assert!(vacuous["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["kind"] == "vacuous-verification"));

    let mut blocked_effect = effect.clone();
    blocked_effect["unplannedPublicSurfaceChanges"] = json!(["public-api:renderBody"]);
    let providers = full_provider_results();
    let gates = full_gate_results();
    let blocked = verify_proposal(&proposal, &blocked_effect, &verifier(), &providers, &gates, &binding()).unwrap();
    assert_eq!(blocked["valid"], false);
    assert!(blocked["coverageGaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap["kind"] == "unplanned-public-surface-change"));
}

#[test]
fn the_committed_verification_schema_matches_its_generator() {
    let schema = build_verification_schema();
    assert!(schema["required"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "verifier"));
    assert_eq!(schema["properties"]["trustedProducerAssertions"]["const"], false);
}

// ---------------------------------------------------------------------------
// worktree.test.mjs
// ---------------------------------------------------------------------------

struct FakeRunner {
    fail: bool,
}

impl ProcessRunner for FakeRunner {
    fn run<'a>(&'a self, _spec: ProcessSpec) -> Pin<Box<dyn Future<Output = ProcessOutcome> + Send + 'a>> {
        let fail = self.fail;
        Box::pin(async move {
            if fail {
                ProcessOutcome { exit_code: Some(1), stdout: None, stderr: Some("boom".to_string()), error: None }
            } else {
                ProcessOutcome { exit_code: Some(0), stdout: None, stderr: None, error: None }
            }
        })
    }
}

#[tokio::test]
async fn create_remediation_worktree_uses_an_isolated_detached_path() {
    let runner = FakeRunner { fail: false };
    let result = create_remediation_worktree(
        Path::new("/repo"),
        Path::new("/repo/.git"),
        "abc123",
        "run-1",
        &runner,
    )
    .await
    .unwrap();
    assert_eq!(result.path, PathBuf::from("/repo/.git").join("legion-worktrees").join("run-1"));
    assert_eq!(result.base_commit, "abc123");
    assert_eq!(
        result.cleanup,
        vec!["git", "worktree", "remove", "--force", result.path.to_str().unwrap()],
    );
}

#[tokio::test]
async fn worktree_add_failure_throws() {
    let runner = FakeRunner { fail: true };
    let err = create_remediation_worktree(Path::new("/r"), Path::new("/r/.git"), "a", "r", &runner)
        .await
        .unwrap_err();
    assert!(err.contains("git worktree add failed"));
}

#[tokio::test]
async fn remove_remediation_worktree_reports_failure_with_recovery() {
    let runner = FakeRunner { fail: true };
    let result = remove_remediation_worktree(Path::new("/w"), &runner).await;
    assert_eq!(result.removed, false);
    assert_eq!(result.error.as_deref(), Some("boom"));
}

#[test]
fn worktree_receipt_declares_primary_worktree_untouched() {
    let cleanup = vec!["git".to_string(), "worktree".to_string(), "remove".to_string(), "--force".to_string(), "/w".to_string()];
    let receipt = worktree_receipt(Path::new("/w"), "a", "r", &cleanup);
    assert_eq!(receipt["primaryWorktreeUntouched"], true);
    assert_eq!(receipt["kind"], "legion-remediation-worktree");
}

#[tokio::test]
async fn real_git_worktree_lifecycle_works_end_to_end() {
    struct RealRunner;
    impl ProcessRunner for RealRunner {
        fn run<'a>(&'a self, spec: ProcessSpec) -> Pin<Box<dyn Future<Output = ProcessOutcome> + Send + 'a>> {
            Box::pin(async move {
                let output = std::process::Command::new(&spec.executable)
                    .args(&spec.args)
                    .current_dir(&spec.cwd)
                    .output();
                match output {
                    Ok(output) => ProcessOutcome {
                        exit_code: output.status.code(),
                        stdout: Some(String::from_utf8_lossy(&output.stdout).into_owned()),
                        stderr: Some(String::from_utf8_lossy(&output.stderr).into_owned()),
                        error: None,
                    },
                    Err(e) => ProcessOutcome { exit_code: None, stdout: None, stderr: None, error: Some(e.to_string()) },
                }
            })
        }
    }

    let dir = std::env::temp_dir().join(format!("legion-wt-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let runner = RealRunner;

    let run = |args: &[&str]| {
        std::process::Command::new("git").args(args).current_dir(&dir).output().unwrap()
    };
    run(&["init", "-q", "."]);
    run(&["config", "user.email", "t@t"]);
    run(&["config", "user.name", "t"]);
    run(&["commit", "-q", "--allow-empty", "-m", "base"]);
    let base = String::from_utf8(run(&["rev-parse", "HEAD"]).stdout).unwrap().trim().to_string();
    let git_dir = String::from_utf8(run(&["rev-parse", "--git-dir"]).stdout).unwrap().trim().to_string();
    let git_common_dir = dir.join(git_dir);

    let wt = create_remediation_worktree(&dir, &git_common_dir, &base, "run-x", &runner).await.unwrap();
    let removed = remove_remediation_worktree(&wt.path, &runner).await;
    assert_eq!(removed.removed, true);

    let _ = std::fs::remove_dir_all(&dir);
}
