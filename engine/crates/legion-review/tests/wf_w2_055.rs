//! Integration tests for chunk w2_055
//! (`legion_review::wf_port::w2_055::{value_gate_report, value_gate_runner,
//! vision_input}`), plus a coverage check for the already-ported
//! `untrusted-evidence-envelope.mjs`.
//!
//! These call through the crate's public surface the same way the
//! `wf_w2_05{0,1,2,3,4}.rs` precedents do, once the integrator wires
//! `pub mod wf_port;` + `pub mod w2_055;` into `lib.rs`/`wf_port/mod.rs`.

use legion_review::wf_port::w2_055::{value_gate_report, value_gate_runner, vision_input};

#[test]
fn value_gate_report_renders_a_full_page_for_one_sample() {
    let findings = vec![value_gate_report::FindingRecord {
        finding_id: "f1".into(),
        claim: "the retry loop can spin forever".into(),
        author_seat: "correctness".into(),
    }];
    let mut blind = std::collections::HashMap::new();
    blind.insert(
        "f1".to_string(),
        value_gate_report::Disposition { action: "raised".into(), rationale: "no bound".into() },
    );
    let mut peer = std::collections::HashMap::new();
    peer.insert(
        "f1".to_string(),
        value_gate_report::Disposition {
            action: "dropped".into(),
            rationale: "bounded elsewhere".into(),
        },
    );
    let rows = value_gate_report::compare_findings(&findings, &blind, &peer);
    assert!(rows[0].flipped);

    let sample = value_gate_report::Sample {
        label: "Retry bound review".into(),
        blind: value_gate_report::BranchOutcome {
            jury_verdict_tier: "block".into(),
            blockers: vec!["f1".into()],
        },
        peer: value_gate_report::BranchOutcome {
            jury_verdict_tier: "pass".into(),
            blockers: vec![],
        },
        changes: vec!["revised retry bound".into()],
        inflation: 1.0,
        room: value_gate_report::RoomAccounting { escalation_rate: 0.0 },
        findings: rows,
    };
    let html = value_gate_report::render(&[sample]);
    assert!(html.contains("Retry bound review"));
    assert!(html.contains("Frozen gate: PASS."));
    assert!(html.contains("ACTION FLIP"));
}

#[test]
fn value_gate_runner_validates_and_applies_folded_addendum() {
    let raw = vec![value_gate_runner::RawDisposition {
        finding_id: "f1".into(),
        action: "FOLDED".into(),
        rationale: "confirmed".into(),
        revision_text: "add a max-attempts guard".into(),
    }];
    let normalized =
        value_gate_runner::validate_implementer_output(Some(&raw), &["f1".to_string()]).unwrap();
    assert_eq!(normalized[0].action, "folded");

    let packet = "PLAN:\nretry until success\n\nSUCCESS_CRITERIA:\n- converges\n";
    let revised = value_gate_runner::apply_folded_addendum(packet, &normalized).unwrap();
    assert!(revised.contains("EXPERIMENTAL IMPLEMENTER REVISIONS:"));
    assert!(revised.contains("- [f1] add a max-attempts guard"));
    assert!(revised.find("EXPERIMENTAL").unwrap() < revised.find("SUCCESS_CRITERIA:").unwrap());
}

#[test]
fn value_gate_runner_rejects_finding_set_mismatch() {
    let raw = vec![value_gate_runner::RawDisposition {
        finding_id: "f1".into(),
        action: "refuted".into(),
        rationale: "not applicable".into(),
        revision_text: "".into(),
    }];
    let err = value_gate_runner::validate_implementer_output(
        Some(&raw),
        &["f1".to_string(), "f2".to_string()],
    )
    .unwrap_err();
    assert_eq!(err, value_gate_runner::ValidationError::FindingSetMismatch);
}

#[test]
fn vision_input_prepares_payload_from_markdown_paths() {
    let dir = std::env::temp_dir().join(format!("wf-w2-055-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let image_path = dir.join("frame.png");
    std::fs::write(&image_path, b"not-a-real-png-but-bytes").unwrap();
    let image_path_str = image_path.to_string_lossy().into_owned();

    struct RealFsSource;
    impl vision_input::ImageSource for RealFsSource {
        fn size(&self, path: &str) -> Option<u64> {
            std::fs::metadata(path).ok().map(|m| m.len())
        }
        fn base64(&self, path: &str) -> Option<String> {
            std::fs::read(path).ok().map(|bytes| {
                bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
            })
        }
        fn video_keyframes(&self, _video_path: &str) -> Vec<String> {
            Vec::new()
        }
    }

    let text = format!("See attached: {image_path_str}");
    let source = RealFsSource;
    let payload = vision_input::prepare_vision_payload(&text, vision_input::MAX_IMAGES, &source, |p| {
        std::path::Path::new(p).exists()
    });
    assert_eq!(payload.len(), 1);
    assert_eq!(payload[0].mime, "image/png");
    assert_eq!(payload[0].source, image_path_str);

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn evidence_envelope_already_covers_untrusted_evidence_envelope_mjs() {
    // Coverage check for src/lib/review/untrusted-evidence-envelope.mjs
    // (B7-029): ALREADY-NATIVE-VERIFIED via legion_review::review_port.
    // A fresh envelope must exist and the defence-in-depth constants must
    // still match the JS source's contract.
    assert_eq!(legion_review::review_port::evidence_envelope::UNTRUSTED_EVIDENCE_SCHEMA_VERSION, 1);
    assert!(legion_review::review_port::evidence_envelope::REVIEW_FAMILIES
        .contains(&"security"));
}
