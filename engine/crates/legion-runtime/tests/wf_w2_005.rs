//! Tests ported from `skills/covenant/scripts/test_validate_external_review_packet.py`
//! for wf_port chunk w2_005 (`skills/covenant/scripts/validate-external-review-packet.py`
//! and its engine dependency `skills/covenant/engine/packet-validator.py`).
//!
//! This test file depends on `legion_runtime::wf_port::w2_005`, which is not yet wired
//! into `legion-runtime`'s public module tree (the integrator adds `pub mod wf_port;` in
//! `src/lib.rs` and `pub mod w2_005;` in `src/wf_port/mod.rs` per the w2_005 chunk
//! assignment). Until that wiring lands, this file will not compile as part of the
//! crate's test target.

use std::path::Path;

use legion_runtime::wf_port::w2_005::{
    validate_external_review_packet, validate_packet, CANONICAL_EXTERNAL_MODE,
};

const TEMPLATE: &str = include_str!("fixtures/wf_w2_005/external-review-packet-template.md");

// ---------------------------------------------------------------------------
// test_validate_external_review_packet.py
// ---------------------------------------------------------------------------

#[test]
fn canonical_marker_and_no_run_rejection() {
    // JS/Py: assert validator.validate(canonical, TEMPLATE, False, True) == []
    let template_path = Path::new("external-review-packet-template.md");
    let errors = validate_external_review_packet(TEMPLATE, template_path, false, true, false);
    assert_eq!(errors, Vec::<String>::new());

    // Py: errors = validator.validate(canonical.replace(CANONICAL, "RUN_COVENANT", 1), ...)
    //     assert any("Mode must be" in error for error in errors)
    let mutated = TEMPLATE.replacen(CANONICAL_EXTERNAL_MODE, "RUN_COVENANT", 1);
    let errors = validate_external_review_packet(&mutated, template_path, false, true, false);
    assert!(errors.iter().any(|e| e.contains("Mode must be")));
}

// ---------------------------------------------------------------------------
// Additional coverage on the engine validator (`packet-validator.py`'s `validate()`),
// which `validate-external-review-packet.py` delegates to once its own Mode gate
// passes. The template itself is only ever checked in `template=True` (self-check)
// mode by the Python test; these exercise the deeper structural/content checks the
// engine validator applies to a filled, non-template packet.
// ---------------------------------------------------------------------------

fn filled_packet(packet_path_label: &str) -> String {
    format!(
        r#"# EXTERNAL REVIEW PACKET — Sample

## 0. Packet Control

- **Created:** 2026-09-23T00:00:00Z
- **Mode:** PACKET_ONLY — DO_NOT_RUN_COVENANT
- **Audience:** External reviewer
- **Packet path:** {packet_path_label}
- **Requested response:** Diagnosis

## 1. Problem in Plain Language

The thing broke in a specific and reproducible way that we describe here.

## 2. User Intent

### Exact request

> Please diagnose why the packet validator rejects a filled-in packet.

### Desired outcome

The validator accepts a fully filled packet with no placeholders remaining.

### Definition of success

validate() returns an empty list of defects for this packet.

## 3. What Went Wrong

| Failure | Exact symptom/evidence | Consequence |
|---|---|---|
| Validator rejects packet | raised errors unexpectedly | blocked review |

## 4. Current System & State

The Covenant packet validator is a Python CLI ported to Rust for legion-runtime.

## 5. Constraints & Invariants

- Must preserve packet-only mode
- Must not run Covenant directly
- Must stay within Guard boundary

## 6. Existing Attempts & Inputs

| Attempt/input | Result | Keep, reject, or reconsider |
|---|---|---|
| Ran validator locally | Passed on template | Keep |

## 7. Evidence Bundle

Embed essential text, code, errors, schemas, or excerpts here. Do not rely on local-only path access.

```text
This is a substantive evidence excerpt that is long enough to pass the sixty
character minimum length check enforced by the engine validator's fenced block.
```

## 8. Known Unknowns

- None currently identified

## 9. Questions for Reviewer

1. What is root cause?
2. What exact design or wording changes close it?
3. Which bypasses or failure paths remain?
4. What should be enforced mechanically rather than requested in prose?
5. Which recommendations are must-fix vs optional value additions?

## 10. Response Contract

Return a verdict: `READY_TO_IMPLEMENT` or `REVISE_PACKET`.

Do not assume access to old chat, local filesystem, or unstated context.
"#
    )
}

#[test]
fn inline_filled_packet_passes_with_inline_declared() {
    let text = filled_packet("`INLINE`");
    let errors = validate_packet(&text, Path::new("packet.md"), true, false, false);
    assert_eq!(errors, Vec::<String>::new(), "unexpected errors: {errors:?}");
}

#[test]
fn inline_packet_rejects_non_inline_declared_path() {
    let text = filled_packet("/some/absolute/path.md");
    let errors = validate_packet(&text, Path::new("packet.md"), true, false, false);
    assert!(errors
        .iter()
        .any(|e| e == "inline packet must declare Packet path INLINE"));
}

#[test]
fn durable_packet_requires_matching_absolute_path_and_md_suffix() {
    let dir = std::env::temp_dir().join(format!("wf_w2_005_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("packet.md");
    let declared = format!("`{}`", path.to_string_lossy());
    let text = filled_packet(&declared);
    let errors = validate_packet(&text, &path, false, false, false);
    assert_eq!(errors, Vec::<String>::new(), "unexpected errors: {errors:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn durable_packet_in_forbidden_storage_is_rejected() {
    // Build a path with a component that is *exactly* "tmp" (the forbidden-storage
    // check matches whole path components, not substrings), regardless of where the
    // platform's actual temp directory lives.
    let dir = std::env::temp_dir()
        .join(format!("wf_w2_005_{}", std::process::id()))
        .join("tmp");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("packet.md");
    let declared = format!("`{}`", path.to_string_lossy());
    let text = filled_packet(&declared);
    let errors = validate_packet(&text, &path, false, false, false);
    assert!(
        errors
            .iter()
            .any(|e| e == "durable packet cannot use temporary/cache/review-run storage"),
        "expected forbidden-storage rejection: {errors:?}"
    );
    let _ = std::fs::remove_dir_all(dir.parent().unwrap());
}

#[test]
fn unfilled_placeholder_is_rejected() {
    let text = filled_packet("`INLINE`").replace("Diagnosis", "{{DIAGNOSIS_DESIGN_REWRITE_OR_REVIEW}}");
    let errors = validate_packet(&text, Path::new("packet.md"), true, false, false);
    assert!(errors.iter().any(|e| e == "unfilled placeholder remains"));
}

#[test]
fn missing_response_contract_verdicts_is_rejected() {
    let text = filled_packet("`INLINE`").replace(
        "Return a verdict: `READY_TO_IMPLEMENT` or `REVISE_PACKET`.",
        "Return a verdict.",
    );
    let errors = validate_packet(&text, Path::new("packet.md"), true, false, false);
    assert!(errors
        .iter()
        .any(|e| e == "response contract lacks required verdict values"));
}

#[test]
fn banned_old_context_phrase_is_rejected() {
    let text = filled_packet("`INLINE`").replace(
        "The thing broke in a specific and reproducible way that we describe here.",
        "As discussed, the thing broke in a specific and reproducible way.",
    );
    let errors = validate_packet(&text, Path::new("packet.md"), true, false, false);
    assert!(errors
        .iter()
        .any(|e| e == "old-context dependency: as discussed"));
}

#[test]
fn secret_pattern_is_detected() {
    let text = filled_packet("`INLINE`").replace(
        "The thing broke in a specific and reproducible way that we describe here.",
        "api_key: sk-ABCDEFGHIJKLMNOPQRSTUVWX123456",
    );
    let errors = validate_packet(&text, Path::new("packet.md"), true, false, false);
    assert!(errors.iter().any(|e| e.starts_with("possible secret detected")));
}

#[test]
fn wrong_mode_label_is_rejected() {
    let text = filled_packet("`INLINE`").replace(
        "PACKET_ONLY — DO_NOT_RUN_COVENANT",
        "RUN_COVENANT_NOW",
    );
    let errors = validate_packet(&text, Path::new("packet.md"), true, false, false);
    assert!(errors
        .iter()
        .any(|e| e == "Mode must be PACKET_ONLY — DO_NOT_RUN_COVENANT"));
}

#[test]
fn thin_wrapper_short_circuits_before_engine_checks_run() {
    // The wrapper (`validate-external-review-packet.py`) only checks for the canonical
    // marker substring anywhere in text; it does not require the label itself to carry
    // it verbatim before delegating. Confirm the short-circuit path returns exactly one
    // error and does not also surface deeper structural defects.
    let errors =
        validate_external_review_packet("garbage text with no marker", Path::new("packet.md"), true, false, false);
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0], format!("Mode must be {}", CANONICAL_EXTERNAL_MODE));
}
