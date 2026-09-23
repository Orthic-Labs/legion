//! Integration tests for chunk w2_046 (`src/lib/host/arcane/
//! {codex-escalation,continuity,decision-envelope,denial-circuit,
//! discipline-controls}.mjs`), exercising the ported code through the
//! crate's public `wf_port::w2_046::*` modules.
//!
//! NOTE: this file compiles only once the integrator wires
//! `pub mod wf_port;` + `pub mod w2_046;` into
//! `engine/crates/legion-runtime/src/{lib.rs,wf_port/mod.rs}` (this chunk
//! owns `src/wf_port/w2_046/**` only, not those files). See the chunk
//! report for the exact patch.

use std::fs;
use std::path::Path;

use legion_runtime::wf_port::w2_046::canonical::digest_value;
use legion_runtime::wf_port::w2_046::codex_escalation::evaluate_codex_escalation;
use legion_runtime::wf_port::w2_046::continuity::{
    rehydrate_untrusted_data, ContinuityController,
};
use legion_runtime::wf_port::w2_046::decision_envelope::{
    create_decision_envelope, DecisionEnvelopeDetail, DecisionEnvelopeInput,
};
use legion_runtime::wf_port::w2_046::denial_circuit::{
    apply_denial_circuit, DenialContext, DenialResult, MemoryDenialCircuit,
};
use legion_runtime::wf_port::w2_046::discipline_controls::{
    generated_lock_targets, no_verify_blocked, DisciplinePayload,
};
use serde_json::json;

fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wf_w2_046")
        .join(name);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

/// Port of `codex-escalation.mjs`'s `evaluateCodexEscalation` behaviour on a
/// realistic captured Bash-tool command, driven from a fixture file the way
/// the JS gate reads a piped prompt off the file the command names.
#[test]
fn codex_escalation_reads_stdin_fixture_and_counts_evidence() {
    let raw = fixture("stdin_command.txt");
    let command = raw.trim();
    let prompt_source = fixture("stdin_prompt.txt");
    let outcome = evaluate_codex_escalation(command, |path| {
        assert_eq!(path, "prompt.txt");
        Some(prompt_source.clone())
    });
    // Spec (`evidenceCount` in `codex-escalation.mjs`): the fixture prompt's
    // "I also attempted a clean reinstall via pip install -e ." contains
    // both an `attempted` verb match and a separate `pip install` verb
    // match more than 20 chars apart, and each has a RESULT
    // ("failed"/`\w+Error\b` via "ModuleNotFoundError") within 120 chars,
    // so ATTEMPT/RESULT counts 3 attempts here, not 2.
    assert!(outcome.allowed, "expected evidenced escalation to be allowed: {outcome:?}");
    assert_eq!(outcome.evidence, Some(3));
}

/// Port of `evaluateCodexEscalation`'s inline-quote path with insufficient
/// evidence, mirroring `test_gate_codex_escalation.py`'s "prose intent is
/// not evidence" case.
#[test]
fn codex_escalation_denies_prose_without_evidence() {
    let outcome = evaluate_codex_escalation(
        "codex exec \"I believe this should work, please just handle it for me today\"",
        |_| None,
    );
    // Spec (`codex-escalation.mjs`): the denial reason string is
    // "BLOCKED [codex-escalation-gate]: ...". "ARC_ESCALATION_RECURSION" is
    // a distinct error `code` used only by `selectStrongerWorkingModel`'s
    // recursion guard, unrelated to this evidence-insufficient denial.
    assert!(!outcome.allowed);
    assert_eq!(outcome.evidence, Some(0));
    assert!(outcome.reason.unwrap().contains("BLOCKED [codex-escalation-gate]"));
}

/// Port of `decision-envelope.mjs`'s `createDecisionEnvelope`, exercising a
/// realistic denial envelope shape as `applyDenialCircuit` and host callers
/// would build it, using `canonical.mjs`'s digest from the same chunk.
#[test]
fn decision_envelope_denied_envelope_matches_shape() {
    let env = create_decision_envelope(DecisionEnvelopeInput {
        allowed: false,
        code: Some("ARC_EVIDENCE_INSUFFICIENT".to_string()),
        detail: DecisionEnvelopeDetail {
            missing_classes: vec!["deterministic".to_string()],
            termination_terminate: false,
            certification: None,
            retry_signature: None,
        },
        enforcement_health: Some("strong".to_string()),
    })
    .unwrap();
    assert!(!env.allowed);
    assert_eq!(env.certification, "rejected");
    assert_eq!(env.responsible_producer, Some("legion run close".to_string()));
    assert_eq!(
        env.public_reason,
        "ARC_EVIDENCE_INSUFFICIENT: Required evidence is missing."
    );
}

/// Cross-module integration: `applyDenialCircuit` wraps a denied
/// `createDecisionEnvelope`-shaped result and the retry signature it stamps
/// is a `canonical.mjs`-style digest, matching `denial-circuit.mjs`'s
/// `circuitFingerprint` contract.
#[test]
fn denial_circuit_stamps_retry_signature_on_denied_envelope() {
    let env = create_decision_envelope(DecisionEnvelopeInput {
        allowed: false,
        code: Some("ARC_EVIDENCE_STALE".to_string()),
        detail: DecisionEnvelopeDetail::default(),
        enforcement_health: Some("strong".to_string()),
    })
    .unwrap();

    let result = DenialResult {
        allowed: env.allowed,
        code: env.code.clone(),
        message: Some(env.public_reason.clone()),
        enforcement_health: Some(env.enforcement_health.clone()),
        missing_classes: env.missing_classes.clone(),
        target: None,
        termination_terminate: false,
        retry_signature: None,
    };

    let mut circuit = MemoryDenialCircuit::default();
    let out = apply_denial_circuit(
        result,
        Some(&mut circuit),
        DenialContext {
            event_type: Some("PreToolUse"),
            control_class: None,
            session_id: "sess-1".to_string(),
            run_id: "run-1".to_string(),
            task_id: "task-1".to_string(),
        },
    )
    .unwrap();

    let sig = out.retry_signature.expect("retry signature stamped");
    assert!(sig.starts_with("sha256:"));
    // PreToolUse -> "effect" control class, which never opens the circuit.
    assert!(!out.termination_terminate);
}

/// Port of `discipline-controls.mjs`'s `preEffectDiscipline` no-verify and
/// generated-lock checks against a realistic PreToolUse-shaped payload
/// fixture (captured Bash tool_input JSON).
#[test]
fn discipline_controls_blocks_no_verify_from_fixture_payload() {
    let raw = fixture("commit_no_verify_payload.json");
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let command = value["tool_input"]["command"].as_str().unwrap().to_string();
    assert!(no_verify_blocked(&command));

    let payload = DisciplinePayload { command: Some(command), ..Default::default() };
    assert!(generated_lock_targets(&payload).is_empty());
}

/// Port of `rehydrateUntrustedData`'s typed-envelope contract, using
/// `canonical.mjs`'s `digest_value` the same way the JS module imports it
/// from `contracts/arcane/canonical.mjs`.
#[test]
fn continuity_rehydrates_untrusted_payload_with_matching_digest() {
    let payload = json!({"note": "external tool output", "n": 3});
    let digest = digest_value(&payload);
    let envelope = json!({
        "schema": "rehydration-envelope.v1",
        "trust": "UNTRUSTED_DATA",
        "content_digest": digest,
        "payload": payload,
    });
    let out = rehydrate_untrusted_data(&envelope).unwrap();
    assert!(!out.authority_granted);
    assert_eq!(out.instruction_status, "DATA_ONLY");
}

/// Port of `ContinuityController`'s epoch lifecycle: bind, claim an effect,
/// deny a duplicate claim, cancel, and reject the stale token afterward —
/// mirroring the JS class's own inline usage pattern in continuity.mjs.
#[test]
fn continuity_controller_lifecycle() {
    let mut controller = ContinuityController::new(1, 1, vec!["seed-effect".to_string()]);
    let token = controller.bind("workitem-1").unwrap();
    assert!(controller.claim_effect(&token, "seed-effect").is_err()); // already completed
    let (_id, accepted) = controller.claim_effect(&token, "new-effect").unwrap();
    assert!(accepted);
    controller.cancel(2).unwrap();
    assert!(controller.assert_current(&token).is_err());
    let mut ids = controller.completed_effect_ids();
    ids.sort();
    assert_eq!(ids, vec!["new-effect", "seed-effect"]);
}
