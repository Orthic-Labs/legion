//! Integration coverage for the C3 gaps closed on the production reasoning
//! entry points: excerpt slicing, conditional-lens trigger detection, and
//! report-schema validation.
//!
//! These exercise the crate's public `native_providers::reasoning` surface
//! (`excerpts`, `triggers`, `lens_schemas`, `lens_plan`), the same modules
//! `build_invocation`/`verify_response` call, per the project rule to
//! "assert new decode behaviour on the PRODUCTION entry point, not on the
//! helper you edited."

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use legion_audit::native_providers::reasoning::{excerpts, lens_plan, lens_schemas, triggers};
use serde_json::json;

struct ScratchDir(PathBuf);
impl ScratchDir {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "legion-audit-reasoning-excerpts-it-{}-{}-{id}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write(root: &Path, rel: &str, content: &str) {
    let full = root.join(rel);
    if let Some(parent) = full.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(full, content).unwrap();
}

#[test]
fn excerpt_mode_matches_lens_plan_for_every_owned_provider() {
    // Raw excerpts for security/schema/correctness/performance/minimize/
    // doc-drift; skeleton for architecture/ai-slop/naming/dead-file, per
    // `lens_plan.rs` and `lens-routing.md`'s "Excerpt compression" section.
    for (provider, expect_raw) in [
        ("reasoning.security", true),
        ("reasoning.schema", true),
        ("reasoning.correctness", true),
        ("reasoning.performance", true),
        ("reasoning.minimize", true),
        ("reasoning.doc-drift", true),
        ("reasoning.architecture", false),
        ("reasoning.ai-slop", false),
        ("reasoning.naming", false),
        ("reasoning.dead-file", false),
    ] {
        let mode = lens_plan::lens_plan_excerpt_mode(provider).expect(provider);
        let is_raw = mode == lens_plan::ExcerptMode::Raw;
        assert_eq!(is_raw, expect_raw, "{provider}: unexpected excerpt mode {mode:?}");
    }
}

#[test]
fn raw_excerpt_slicing_is_file_line_anchored_and_redacted_across_languages() {
    let dir = ScratchDir::new();
    write(dir.path(), "src/lib.rs", "pub fn a() {}\nconst TOKEN: &str = \"ghp_abcdefghijklmnopqrstuvwxyz012345\";\n");
    write(dir.path(), "web/app.ts", "export function b() { return 1; }\n");
    write(dir.path(), "ios/App.swift", "func c() {}\n");
    write(dir.path(), "scripts/tool.py", "def d():\n    return 1\n");

    let paths = vec![
        "src/lib.rs".to_string(),
        "web/app.ts".to_string(),
        "ios/App.swift".to_string(),
        "scripts/tool.py".to_string(),
    ];
    let excerpts = excerpts::build_excerpts(dir.path(), &paths, lens_plan::ExcerptMode::Raw);
    assert_eq!(excerpts.len(), 4);
    let rust = excerpts.iter().find(|e| e.path == "src/lib.rs").unwrap();
    assert_eq!(rust.language, "rust");
    assert!(rust.anchors.iter().any(|a| a.starts_with("src/lib.rs:")));
    assert!(rust.redacted, "the ghp_ token must be redacted");
    assert!(!rust.content.contains("ghp_abcdefghijklmnopqrstuvwxyz012345"));

    for (path, language) in [("web/app.ts", "typescript"), ("ios/App.swift", "swift"), ("scripts/tool.py", "python")] {
        let excerpt = excerpts.iter().find(|e| e.path == path).unwrap();
        assert_eq!(excerpt.language, language);
    }
}

#[test]
fn skeleton_excerpt_slicing_keeps_signatures_and_drops_bodies_across_languages() {
    let dir = ScratchDir::new();
    write(
        dir.path(),
        "src/lib.rs",
        "use std::fmt;\n\npub struct Thing {\n    x: i32,\n}\n\npub fn compute() -> i32 {\n    let secret_body = 41 + 1;\n    secret_body\n}\n",
    );
    let paths = vec!["src/lib.rs".to_string()];
    let excerpts = excerpts::build_excerpts(dir.path(), &paths, lens_plan::ExcerptMode::Skeleton);
    let excerpt = &excerpts[0];
    assert!(excerpt.content.contains("use std::fmt;"));
    assert!(excerpt.content.contains("pub struct Thing {"));
    assert!(excerpt.content.contains("pub fn compute() -> i32 {"));
    assert!(!excerpt.content.contains("secret_body = 41 + 1"));
    assert!(excerpt.content.contains("{ ... }"));
    assert!(!excerpt.redacted, "skeleton mode does not redact (no bodies survive to carry secrets)");
}

#[test]
fn conditional_trigger_detection_covers_all_five_lenses_with_evidence() {
    let dir = ScratchDir::new();
    write(dir.path(), "web/Button.tsx", "export const Button = () => <button />;\n");
    write(dir.path(), "db/migrations/0001_init.sql", "CREATE TABLE t (id INT);\n");
    write(dir.path(), "src/sidecar/run.rs", "fn main() { std::process::Command::new(\"x\"); }\n");
    write(dir.path(), "src/platform.rs", "#[cfg(target_os = \"windows\")]\nfn win() {}\n");
    write(dir.path(), "release/tauri.conf.json", "{}\n");

    let paths = vec![
        "web/Button.tsx".to_string(),
        "db/migrations/0001_init.sql".to_string(),
        "src/sidecar/run.rs".to_string(),
        "src/platform.rs".to_string(),
        "release/tauri.conf.json".to_string(),
    ];
    let evaluations = triggers::evaluate_all_conditional_triggers(dir.path(), &paths);
    assert_eq!(evaluations.len(), 5);
    for evaluation in &evaluations {
        assert!(evaluation.fired, "{} should have fired with matching evidence present", evaluation.lens);
        assert!(!evaluation.evidence_paths.is_empty());
        assert!(!evaluation.reason.is_empty());
    }

    // Absence must be provably checked, not silently skipped.
    let empty_dir = ScratchDir::new();
    let none_fired = triggers::evaluate_all_conditional_triggers(empty_dir.path(), &[]);
    assert!(none_fired.iter().all(|evaluation| !evaluation.fired));
    assert!(none_fired.iter().all(|evaluation| evaluation.reason.contains("zero hits")));
}

#[test]
fn lens_plan_conditional_trigger_text_matches_a_real_evaluator() {
    // Every conditional lens in lens_plan.rs must also be evaluable by
    // triggers.rs (the description and the detector must not drift apart).
    for provider in [
        "reasoning.a11y",
        "reasoning.data-safety",
        "reasoning.resilience",
        "reasoning.platform-parity",
        "reasoning.release-readiness",
    ] {
        let lens = lens_plan::lens_id_for_provider(provider).expect(provider);
        assert!(triggers::evaluate_trigger(Path::new("."), lens, &[]).is_some(), "{lens} has no trigger evaluator");
    }
}

#[test]
fn report_schema_body_is_present_for_every_owned_lens_and_matches_the_packet_id() {
    for provider in [
        "reasoning.doc-drift",
        "reasoning.architecture",
        "reasoning.correctness",
        "reasoning.ai-slop",
        "reasoning.naming",
        "reasoning.dead-file",
        "reasoning.schema",
        "reasoning.security",
        "reasoning.minimize",
        "reasoning.performance",
        "reasoning.a11y",
        "reasoning.data-safety",
        "reasoning.resilience",
        "reasoning.platform-parity",
        "reasoning.release-readiness",
        "legacy.security.variant-analysis",
    ] {
        let packet = lens_plan::lens_plan_packet_value(provider).expect(provider);
        let schema_id = packet["reportSchema"].as_str().unwrap();
        let lens = lens_plan::lens_id_for_provider(provider).unwrap();
        let schema_body = lens_schemas::lens_report_schema(lens).expect(provider);
        assert_eq!(schema_body["$id"], json!(format!("https://legion.audit/schemas/{schema_id}")));
        assert!(schema_body["required"].as_array().unwrap().contains(&json!("evidence")));
    }
}

#[test]
fn correctness_lens_output_fails_closed_without_verify_pass() {
    let unverified = json!([{
        "id": "f-1",
        "lens": "correctness",
        "severity": "high",
        "confidence": "likely",
        "evidence": ["src/x.rs:10-20"],
        "failureScenario": "unhandled Err on the hot path",
        "action": "propagate the error instead of unwrap()",
        "verifyStatus": "unverified"
    }]);
    let findings: Vec<_> = unverified.as_array().unwrap().clone();
    assert!(lens_schemas::validate_lens_output("correctness", &findings).is_err());

    let verified = json!([{
        "id": "f-1",
        "lens": "correctness",
        "severity": "high",
        "confidence": "likely",
        "evidence": ["src/x.rs:10-20"],
        "failureScenario": "unhandled Err on the hot path",
        "action": "propagate the error instead of unwrap()",
        "verifyStatus": "verified",
        "verificationMethod": "deterministic-reproduction"
    }]);
    let findings: Vec<_> = verified.as_array().unwrap().clone();
    assert!(lens_schemas::validate_lens_output("correctness", &findings).is_ok());
}

#[test]
fn minimize_lens_output_requires_a_ponytail_tag() {
    let missing_tag = json!([{
        "id": "f-1",
        "lens": "minimize",
        "severity": "medium",
        "confidence": "speculative",
        "evidence": ["src/y.rs:1-5"],
        "failureScenario": "one-impl trait with no second implementation or seam",
        "action": "inline the trait",
        "verifyStatus": "unverified"
    }]);
    let findings: Vec<_> = missing_tag.as_array().unwrap().clone();
    assert!(lens_schemas::validate_lens_output("minimize", &findings).is_err());
}
