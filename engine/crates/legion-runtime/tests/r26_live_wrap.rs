//! Integration tests for packet r26's additions to the w2_020 port of
//! `skills/designer/engine/scripts/live-wrap.mjs`: the filesystem walk
//! (`find_file_with_query`/`search_dir`) and the manual-edit-buffer-consuming
//! selection-impact functions (`pending_entries_that_may_affect_wrap`,
//! `manual_edit_may_affect_wrap`, `apply_buffered_manual_edit_to_lines`,
//! `build_css_authoring`).

use legion_runtime::wf_port::w2_020::wrap::{
    apply_buffered_manual_edit_to_lines, build_css_authoring, detect_style_mode,
    find_file_with_query, manual_edit_may_affect_wrap, pending_entries_that_may_affect_wrap,
};
use legion_runtime::wf_port::w2_021::manual_edits_buffer::{ManualEditEntry, ManualEditOp};
use serde_json::json;

fn tmp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "legion-wf-r26-{name}-{}-{}",
        std::process::id(),
        ((std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos())
        .wrapping_shl(20)
            | ({
                static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                u128::from(SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
            }))
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn op(original_text: &str, new_text: &str) -> ManualEditOp {
    ManualEditOp {
        ref_: Some("r1".to_string()),
        original_text: Some(original_text.to_string()),
        new_text: Some(new_text.to_string()),
        deleted: false,
        extra: serde_json::Map::new(),
    }
}

// --- find_file_with_query / search_dir ---------------------------------

#[test]
fn find_file_with_query_locates_content_under_src() {
    let cwd = tmp_dir("find");
    std::fs::create_dir_all(cwd.join("src/components")).unwrap();
    std::fs::write(
        cwd.join("src/components/Hero.tsx"),
        "export const Hero = () => <div className=\"hero-combined-left\">hi</div>;",
    )
    .unwrap();

    let found = find_file_with_query("hero-combined-left", &cwd, false).unwrap();
    assert_eq!(found, cwd.join("src/components/Hero.tsx"));
}

#[test]
fn find_file_with_query_skips_node_modules_and_missing_query() {
    let cwd = tmp_dir("skip");
    std::fs::create_dir_all(cwd.join("node_modules/pkg")).unwrap();
    std::fs::write(cwd.join("node_modules/pkg/index.html"), "needle-value").unwrap();

    assert!(find_file_with_query("needle-value", &cwd, false).is_none());
    assert!(find_file_with_query("does-not-exist-anywhere", &cwd, false).is_none());
}

#[test]
fn find_file_with_query_skips_generated_files_unless_included() {
    let cwd = tmp_dir("generated");
    std::fs::create_dir_all(cwd.join("src")).unwrap();
    std::fs::write(
        cwd.join("src/Generated.html"),
        "<!-- @generated -->\n<div class=\"needle-marker\"></div>",
    )
    .unwrap();

    assert!(find_file_with_query("needle-marker", &cwd, false).is_none());
    assert!(find_file_with_query("needle-marker", &cwd, true).is_some());
}

// --- build_css_authoring -------------------------------------------------

#[test]
fn build_css_authoring_scoped_vs_astro_global_prefixed() {
    let scoped = detect_style_mode("Hero.tsx");
    let authoring = build_css_authoring(&scoped, 2);
    assert_eq!(authoring.strategy, "scope-rule");
    assert_eq!(authoring.selector_examples.len(), 2);
    assert!(authoring.selector_examples[0].contains("@scope"));

    let astro = detect_style_mode("Hero.astro");
    let authoring = build_css_authoring(&astro, 2);
    assert_eq!(authoring.strategy, "global-prefixed");
    assert_eq!(
        authoring.selector_examples[0],
        "[data-impeccable-variant=\"1\"] > .variant-class"
    );
}

// --- buffer-consuming selection-impact functions -------------------------

#[test]
fn manual_edit_may_affect_wrap_true_when_original_text_is_in_selection() {
    let cwd = tmp_dir("affect");
    let target = std::path::Path::new("src/Hero.tsx");
    let lines = vec!["<div class=\"hero\">Old Text</div>".to_string()];
    let target_abs = cwd.join(target);

    let hit = op("Old Text", "New Text");
    assert!(manual_edit_may_affect_wrap(&hit, &target_abs, &lines, 0, &cwd));

    let miss = op("Nonexistent Text", "New Text");
    assert!(!manual_edit_may_affect_wrap(&miss, &target_abs, &lines, 0, &cwd));
}

#[test]
fn pending_entries_that_may_affect_wrap_filters_by_op_match() {
    let cwd = tmp_dir("pending");
    let target = std::path::Path::new("src/Hero.tsx");
    let lines = vec!["<div>Hello World</div>".to_string()];
    let target_abs = cwd.join(target);

    let matching_entry = ManualEditEntry {
        id: Some("e1".to_string()),
        page_url: Some("/".to_string()),
        element: None,
        ops: vec![op("Hello World", "Bye World")],
        staged_at: None,
    };
    let non_matching_entry = ManualEditEntry {
        id: Some("e2".to_string()),
        page_url: Some("/".to_string()),
        element: None,
        ops: vec![op("Totally Different", "X")],
        staged_at: None,
    };
    let entries = vec![matching_entry, non_matching_entry];

    let affecting = pending_entries_that_may_affect_wrap(&entries, &target_abs, &lines, 0, &cwd);
    assert_eq!(affecting.len(), 1);
    assert_eq!(affecting[0].id.as_deref(), Some("e1"));
}

#[test]
fn apply_buffered_manual_edit_to_lines_uses_source_hint_first() {
    let lines = vec![
        "line zero".to_string(),
        "target Old Text here".to_string(),
        "line two".to_string(),
    ];
    let mut hinted = op("Old Text", "New Text");
    hinted.extra.insert(
        "sourceHint".to_string(),
        json!({ "file": "Hero.tsx", "line": 2 }),
    );

    let (result, changed) = apply_buffered_manual_edit_to_lines(&lines, 0, &hinted);
    assert!(changed);
    assert_eq!(result[1], "target New Text here");
    assert_eq!(result[0], lines[0]);
}

#[test]
fn apply_buffered_manual_edit_to_lines_falls_back_to_single_occurrence() {
    let lines = vec!["a Old Text b".to_string(), "c".to_string()];
    let plain = op("Old Text", "New Text");

    let (result, changed) = apply_buffered_manual_edit_to_lines(&lines, 0, &plain);
    assert!(changed);
    assert_eq!(result[0], "a New Text b");
}

#[test]
fn apply_buffered_manual_edit_to_lines_no_match_returns_unchanged() {
    let lines = vec!["nothing here".to_string()];
    let plain = op("Old Text", "New Text");

    let (result, changed) = apply_buffered_manual_edit_to_lines(&lines, 0, &plain);
    assert!(!changed);
    assert_eq!(result, lines);
}
