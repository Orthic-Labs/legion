//! Integration smoke test for chunk w2_018
//! (`skills/designer/engine/scripts/live-*.mjs` ports) against the crate's
//! public API, the way an external caller would use it.
//!
//! NOTE: this test file assumes the integrator has wired
//! `pub mod wf_port;` (already present) and, inside
//! `engine/crates/legion-runtime/src/wf_port/mod.rs`, added
//! `pub mod w2_018;` — see this chunk's port report
//! (`w2_018.md`) for the exact patch.

use legion_runtime::wf_port::w2_018::{buffer, discard, evidence, inject, insert};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

struct TempDir(PathBuf);
impl TempDir {
    fn new(label: &str) -> Self {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "legion-w2_018-it-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn discard_manual_edits_round_trips_through_the_buffer() {
    let tmp = TempDir::new("discard");
    let live_dir = tmp.path().join(".impeccable").join("live");
    fs::create_dir_all(&live_dir).unwrap();
    fs::write(
        buffer::get_buffer_path(&live_dir),
        serde_json::to_string(&json!({
            "version": 1,
            "entries": [
                { "id": "a", "pageUrl": "/", "ops": [{"ref": "1"}] },
                { "id": "b", "pageUrl": "/x", "ops": [{"ref": "2"}] },
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let result = discard::discard_manual_edits(&live_dir, Some("/")).unwrap();
    assert_eq!(result.discarded, 1);
    assert_eq!(result.total_count, 1);

    let remaining = buffer::read_buffer(&live_dir);
    assert_eq!(remaining.entries.len(), 1);
    assert_eq!(remaining.entries[0].page_url.as_deref(), Some("/x"));
}

#[test]
fn manual_edit_evidence_locates_the_source_file_for_a_staged_edit() {
    let tmp = TempDir::new("evidence");
    let cwd = tmp.path();
    let live_dir = cwd.join(".impeccable").join("live");
    fs::create_dir_all(&live_dir).unwrap();
    fs::write(
        buffer::get_buffer_path(&live_dir),
        serde_json::to_string(&json!({
            "version": 1,
            "entries": [{
                "id": "e1",
                "pageUrl": "/",
                "ops": [{
                    "ref": "r1",
                    "tag": "h1",
                    "originalText": "Ship it today",
                    "newText": "Ship it now",
                }],
            }],
        }))
        .unwrap(),
    )
    .unwrap();

    let src = cwd.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("Banner.jsx"),
        "export default () => <h1>Ship it today</h1>;\n",
    )
    .unwrap();

    let result = evidence::build_manual_edit_evidence(cwd, &live_dir, None);
    assert_eq!(result["count"], json!(1));
    let matches = result["candidates"][0]["textMatches"].as_array().unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0]["file"], json!("src/Banner.jsx"));
}

#[test]
fn inject_tag_insert_remove_and_csp_patch_round_trip() {
    let cfg = inject::InjectConfig {
        files: vec!["index.html".to_string()],
        exclude: vec![],
        insert_before: None,
        insert_after: Some("<body>".to_string()),
        comment_syntax: "html".to_string(),
    };
    assert!(inject::validate_config(&cfg).is_ok());

    let original = r#"<html><head><meta http-equiv="Content-Security-Policy" content="default-src 'self'"></head><body>hi</body></html>"#;
    let inserted = inject::insert_tag(original, &cfg, 4321, "index.html");
    assert_ne!(inserted, original);
    assert!(inserted.contains("http://localhost:4321/live.js"));

    let patched = inject::patch_csp_meta(&inserted, 4321);
    assert!(patched.contains("http://localhost:4321"));

    let reverted_csp = inject::revert_csp_meta(&patched);
    let removed_tag = inject::remove_tag(&reverted_csp);
    assert_eq!(removed_tag, original);
}

#[test]
fn insert_wrapper_lines_respect_position_and_syntax() {
    assert!(insert::is_insert_position("after"));
    assert!(!insert::is_insert_position("inside"));
    assert_eq!(insert::compute_insert_line(5, 9, "before"), 5);
    assert_eq!(insert::compute_insert_line(5, 9, "after"), 10);

    let cs = insert::CommentSyntax {
        open: "<!--".to_string(),
        close: "-->".to_string(),
    };
    let lines = insert::build_insert_wrapper_lines("s1", 2, "", &cs, false);
    assert_eq!(lines.len(), 5);
    assert!(lines.iter().any(|l| l.contains("data-impeccable-mode=\"insert\"")));
}
