//! Integration test for chunk r18 (`live-commit-manual-edits.mjs`),
//! exercising the source-verification pipeline through the crate's public
//! `wf_port::r18` module. Detailed unit tests live alongside the source in
//! `src/wf_port/r18/verify.rs`; this file checks the public API surface is
//! reachable and wired together correctly end to end.

use legion_runtime::wf_port::r18::{
    normalize_project_source_path, verify_applied_entry, verify_entries_after_repair,
    InMemorySourceStore,
};
use serde_json::json;

#[test]
fn verify_applied_entry_end_to_end() {
    let store = InMemorySourceStore::new()
        .with_file("src/hero.tsx", "export const title = 'New Headline';\n");
    let batch = json!({
        "candidates": [],
        "entries": [],
    });
    let entry = json!({
        "id": "entry-1",
        "ops": [{
            "ref": "op-1",
            "originalText": "Old Headline",
            "newText": "New Headline",
            "sourceHint": {"file": "src/hero.tsx", "line": 1},
        }],
    });

    let failures = verify_applied_entry(&store, &batch, &entry, &["src/hero.tsx".to_string()]);
    assert!(
        failures.is_empty(),
        "expected no failures, got {failures:?}"
    );

    let (verified, failed) = verify_entries_after_repair(
        &store,
        &json!({"candidates": [], "entries": [entry]}),
        &["entry-1".to_string()],
        &["src/hero.tsx".to_string()],
    );
    assert_eq!(verified, vec!["entry-1".to_string()]);
    assert!(failed.is_empty());
}

#[test]
fn normalize_project_source_path_public_api() {
    assert_eq!(
        normalize_project_source_path("/repo", Some("/repo/src/app.tsx")),
        Some("src/app.tsx".to_string())
    );
    assert_eq!(
        normalize_project_source_path("/repo", Some("../outside.tsx")),
        None
    );
}
