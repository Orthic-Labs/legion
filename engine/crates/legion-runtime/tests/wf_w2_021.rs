//! Integration tests for the w2_021 port of
//! `skills/designer/engine/scripts/live/{insert-ui,manual-apply,
//! manual-edit-routes,manual-edits-buffer,session-store}.mjs`.
//!
//! NOTE: requires the integrator to wire `pub mod wf_port;` and
//! `pub mod w2_021;` into `legion-runtime` (see
//! `engine/crates/legion-runtime/src/wf_port/mod.rs`) before this file will
//! compile/run.

use std::path::Path;

use legion_runtime::wf_port::w2_021::insert_ui::{
    apply_insert_toggle, apply_pick_toggle, can_create_insert, clamp_placeholder_size,
    compute_insert_position, cursor_for_insert_axis, cursor_for_placeholder_edge,
    detect_insert_axis_from_style, hit_sibling_insert_gap, insert_create_disabled_reason,
    insert_line_coords, is_variant_shown, placeholder_sizing, resize_placeholder_from_edge,
    CanCreateInsertInput, ClampOpts, ContainerStyle, GapOpts, InsertAxis, InsertPosition,
    PlaceholderBox, PlaceholderSizing, PlaceholderSizingInput, Rect, Sibling,
    PLACEHOLDER_MIN_WIDTH,
};
use legion_runtime::wf_port::w2_021::manual_apply::{
    compact_manual_log_text, count_manual_apply_ops, manual_edit_apply_chunk_size,
    summarize_manual_log_file, truncate_manual_apply_text,
};
use legion_runtime::wf_port::w2_021::manual_edit_routes::summarize_pending_manual_edit_batch;
use legion_runtime::wf_port::w2_021::manual_edits_buffer::{
    count_by_page, read_buffer, remove_entries, stage_entry, truncate_buffer, ManualEditOp,
};
use legion_runtime::wf_port::w2_021::session_store::LiveSessionStore;
use serde_json::json;

fn tmp_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "legion-wf-w2-021-{name}-{}-{}",
        std::process::id(),
        ((std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()).wrapping_shl(20) | ({ static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0); u128::from(SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) }))
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------------------------------------------------------------------
// insert_ui
// ---------------------------------------------------------------------

#[test]
fn detect_axis_flex_row_and_column() {
    let row = ContainerStyle {
        display: Some("flex".into()),
        flex_direction: Some("row".into()),
        ..Default::default()
    };
    assert_eq!(detect_insert_axis_from_style(&row), InsertAxis::Row);

    let col = ContainerStyle {
        display: Some("flex".into()),
        flex_direction: Some("column".into()),
        ..Default::default()
    };
    assert_eq!(detect_insert_axis_from_style(&col), InsertAxis::Column);

    let block = ContainerStyle::default();
    assert_eq!(detect_insert_axis_from_style(&block), InsertAxis::Column);
}

#[test]
fn detect_axis_grid_multi_column_is_row() {
    let grid = ContainerStyle {
        display: Some("grid".into()),
        grid_template_columns: Some("1fr 1fr 1fr".into()),
        ..Default::default()
    };
    assert_eq!(detect_insert_axis_from_style(&grid), InsertAxis::Row);

    let grid_single = ContainerStyle {
        display: Some("grid".into()),
        grid_template_columns: Some("1fr".into()),
        ..Default::default()
    };
    assert_eq!(detect_insert_axis_from_style(&grid_single), InsertAxis::Row);
}

#[test]
fn compute_insert_position_column_and_row() {
    let rect = Rect {
        top: 100.0,
        left: 0.0,
        width: 200.0,
        height: 100.0,
        ..Default::default()
    };
    assert_eq!(
        compute_insert_position(0.0, 120.0, Some(&rect), InsertAxis::Column),
        InsertPosition::Before
    );
    assert_eq!(
        compute_insert_position(0.0, 180.0, Some(&rect), InsertAxis::Column),
        InsertPosition::After
    );
    assert_eq!(
        compute_insert_position(10.0, 0.0, Some(&rect), InsertAxis::Row),
        InsertPosition::Before
    );
    assert_eq!(
        compute_insert_position(190.0, 0.0, Some(&rect), InsertAxis::Row),
        InsertPosition::After
    );
    assert_eq!(
        compute_insert_position(0.0, 0.0, None, InsertAxis::Column),
        InsertPosition::After
    );
}

#[test]
fn can_create_insert_requires_prompt_or_annotation() {
    let empty = CanCreateInsertInput {
        prompt: None,
        comments: &[],
        strokes: &[],
    };
    assert!(!can_create_insert(&empty));
    assert_eq!(
        insert_create_disabled_reason(&empty),
        Some("Add a prompt or annotate the placeholder to create")
    );

    let with_prompt = CanCreateInsertInput {
        prompt: Some("  make a hero  "),
        comments: &[],
        strokes: &[],
    };
    assert!(can_create_insert(&with_prompt));
    assert_eq!(insert_create_disabled_reason(&with_prompt), None);

    let with_stroke = CanCreateInsertInput {
        prompt: None,
        comments: &[],
        strokes: &[vec![(0.0, 0.0), (1.0, 1.0)]],
    };
    assert!(can_create_insert(&with_stroke));

    let short_stroke = CanCreateInsertInput {
        prompt: None,
        comments: &[],
        strokes: &[vec![(0.0, 0.0)]],
    };
    assert!(!can_create_insert(&short_stroke));

    let with_comment = CanCreateInsertInput {
        prompt: None,
        comments: &[json!({"text": "hi"})],
        strokes: &[],
    };
    assert!(can_create_insert(&with_comment));
}

#[test]
fn insert_line_coords_row_and_column() {
    let rect = Rect {
        top: 10.0,
        left: 20.0,
        width: 30.0,
        height: 40.0,
        ..Default::default()
    };
    let row_before = insert_line_coords(&rect, InsertPosition::Before, InsertAxis::Row);
    assert_eq!(row_before.left, 18.0);
    assert_eq!(row_before.top, 10.0);
    assert_eq!(row_before.height, 40.0);

    let row_after = insert_line_coords(&rect, InsertPosition::After, InsertAxis::Row);
    assert_eq!(row_after.left, 52.0);

    let col_before = insert_line_coords(&rect, InsertPosition::Before, InsertAxis::Column);
    assert_eq!(col_before.top, 8.0);
    assert_eq!(col_before.width, 30.0);

    let col_after = insert_line_coords(&rect, InsertPosition::After, InsertAxis::Column);
    assert_eq!(col_after.top, 52.0);
}

#[test]
fn cursor_helpers() {
    assert_eq!(cursor_for_insert_axis(InsertAxis::Row), "ew-resize");
    assert_eq!(cursor_for_insert_axis(InsertAxis::Column), "ns-resize");
    assert_eq!(cursor_for_placeholder_edge('n'), "ns-resize");
    assert_eq!(cursor_for_placeholder_edge('s'), "ns-resize");
    assert_eq!(cursor_for_placeholder_edge('e'), "ew-resize");
    assert_eq!(cursor_for_placeholder_edge('w'), "ew-resize");
    assert_eq!(cursor_for_placeholder_edge('x'), "default");
}

#[test]
fn hit_sibling_insert_gap_row() {
    let siblings = vec![
        Sibling {
            el: "a",
            rect: Rect {
                top: 0.0,
                left: 0.0,
                width: 100.0,
                height: 50.0,
                ..Default::default()
            },
        },
        Sibling {
            el: "b",
            rect: Rect {
                top: 0.0,
                left: 110.0,
                width: 100.0,
                height: 50.0,
                ..Default::default()
            },
        },
    ];
    let hit = hit_sibling_insert_gap(105.0, 25.0, &siblings, GapOpts::default()).unwrap();
    assert_eq!(hit.anchor, "b");
    assert_eq!(hit.axis, InsertAxis::Row);
    assert_eq!(hit.position, InsertPosition::Before);

    // Fewer than two siblings never hits.
    assert!(hit_sibling_insert_gap(0.0, 0.0, &siblings[..1], GapOpts::default()).is_none());
}

#[test]
fn hit_sibling_insert_gap_column_fallback() {
    let siblings = vec![
        Sibling {
            el: "top",
            rect: Rect {
                top: 0.0,
                left: 0.0,
                width: 100.0,
                height: 50.0,
                ..Default::default()
            },
        },
        Sibling {
            el: "bottom",
            rect: Rect {
                top: 60.0,
                left: 0.0,
                width: 100.0,
                height: 50.0,
                ..Default::default()
            },
        },
    ];
    let hit = hit_sibling_insert_gap(50.0, 55.0, &siblings, GapOpts::default()).unwrap();
    assert_eq!(hit.anchor, "bottom");
    assert_eq!(hit.axis, InsertAxis::Column);
}

#[test]
fn placeholder_sizing_variants() {
    let flex = placeholder_sizing(&PlaceholderSizingInput {
        axis: InsertAxis::Row,
        parent_display: Some("flex"),
        parent_width: Some(500.0),
        anchor_flex: None,
    });
    assert_eq!(
        flex,
        PlaceholderSizing::Flex {
            flex: "1 1 0".into(),
            min_width: 0.0
        }
    );

    let grid = placeholder_sizing(&PlaceholderSizingInput {
        axis: InsertAxis::Row,
        parent_display: Some("grid"),
        parent_width: Some(500.0),
        anchor_flex: None,
    });
    assert_eq!(grid, PlaceholderSizing::Auto);

    let percent = placeholder_sizing(&PlaceholderSizingInput {
        axis: InsertAxis::Column,
        parent_display: Some("block"),
        parent_width: Some(500.0),
        anchor_flex: None,
    });
    assert_eq!(percent, PlaceholderSizing::Percent);

    let explicit = placeholder_sizing(&PlaceholderSizingInput {
        axis: InsertAxis::Column,
        parent_display: Some("block"),
        parent_width: Some(50.0),
        anchor_flex: None,
    });
    assert_eq!(
        explicit,
        PlaceholderSizing::Explicit {
            width: PLACEHOLDER_MIN_WIDTH
        }
    );
}

#[test]
fn clamp_and_resize_placeholder() {
    let (w, h) = clamp_placeholder_size(1000.0, 10.0, 300.0, ClampOpts::default());
    assert_eq!(w, 300.0);
    assert_eq!(h, 48.0);

    let start = PlaceholderBox {
        width: 200.0,
        height: 100.0,
        margin_left: 0.0,
        margin_top: 0.0,
    };
    let resized = resize_placeholder_from_edge(start, 'e', 50.0, 0.0, 1000.0, ClampOpts::default());
    assert_eq!(resized.width, 250.0);

    let resized_w = resize_placeholder_from_edge(start, 'w', 50.0, 0.0, 1000.0, ClampOpts::default());
    assert_eq!(resized_w.width, 150.0);
    assert_eq!(resized_w.margin_left, 50.0);
}

#[test]
fn toggles_are_mutually_exclusive() {
    assert_eq!(apply_pick_toggle(false, true), (true, false));
    assert_eq!(apply_pick_toggle(true, false), (false, false));
    assert_eq!(apply_insert_toggle(true, false), (false, true));
    // Spec (`applyInsertToggle` in `insert-ui.mjs`): turning insert OFF
    // (insertActive true -> nextInsert false) leaves pickActive untouched
    // (it only forces pickActive false when nextInsert is true), so with
    // pickActive already false the result is (false, false), not (true,
    // false).
    assert_eq!(apply_insert_toggle(false, true), (false, false));
}

#[test]
fn variant_shown() {
    assert!(is_variant_shown(false, false));
    assert!(!is_variant_shown(true, false));
    assert!(!is_variant_shown(false, true));
}

// ---------------------------------------------------------------------
// manual_apply (pure helpers)
// ---------------------------------------------------------------------

#[test]
fn chunk_size_clamps_and_defaults() {
    assert_eq!(manual_edit_apply_chunk_size(None), 3);
    assert_eq!(manual_edit_apply_chunk_size(Some(f64::NAN)), 3);
    assert_eq!(manual_edit_apply_chunk_size(Some(0.0)), 1);
    assert_eq!(manual_edit_apply_chunk_size(Some(500.0)), 20);
    assert_eq!(manual_edit_apply_chunk_size(Some(7.9)), 7);
}

#[test]
fn count_ops_handles_array_or_batch_shape() {
    let batch = json!({
        "entries": [
            { "ops": [1, 2, 3] },
            { "ops": [1] },
            {},
        ]
    });
    assert_eq!(count_manual_apply_ops(&batch), 4);

    let bare_array = json!([{ "ops": [1, 2] }]);
    assert_eq!(count_manual_apply_ops(&bare_array), 2);

    assert_eq!(count_manual_apply_ops(&json!({})), 0);
}

#[test]
fn truncate_text_respects_limit() {
    assert_eq!(
        truncate_manual_apply_text(Some("short"), 10),
        Some("short".to_string())
    );
    assert_eq!(
        truncate_manual_apply_text(Some("abcdefghij"), 5),
        Some("abcde".to_string())
    );
    assert_eq!(truncate_manual_apply_text(None, 5), None);
}

#[test]
fn summarize_log_file_relativizes_within_cwd() {
    let cwd = Path::new("/proj/root");
    assert_eq!(
        summarize_manual_log_file(Some("/proj/root/src/a.rs"), cwd),
        Some("src/a.rs".to_string())
    );
    assert_eq!(
        summarize_manual_log_file(Some("relative/path.rs"), cwd),
        Some("relative/path.rs".to_string())
    );
    assert_eq!(
        summarize_manual_log_file(Some("/outside/other.rs"), cwd),
        Some("/outside/other.rs".to_string())
    );
    assert_eq!(summarize_manual_log_file(None, cwd), None);
}

#[test]
fn compact_log_text_collapses_whitespace_and_truncates() {
    assert_eq!(
        compact_manual_log_text(Some("  a   b\tc\n"), 200),
        Some("a b c".to_string())
    );
    let long = "x".repeat(250);
    let out = compact_manual_log_text(Some(&long), 200).unwrap();
    assert!(out.starts_with(&"x".repeat(200)));
    assert!(out.ends_with("... [truncated 50 chars]"));
}

// ---------------------------------------------------------------------
// manual_edits_buffer
// ---------------------------------------------------------------------

fn op(ref_: &str, new_text: &str) -> ManualEditOp {
    ManualEditOp {
        ref_: Some(ref_.to_string()),
        original_text: None,
        new_text: Some(new_text.to_string()),
        deleted: false,
        extra: Default::default(),
    }
}

#[test]
fn stage_entry_merges_by_page_and_ref_keeping_original_text() {
    let dir = tmp_dir("buffer-merge");

    let buf = stage_entry(
        &dir,
        "entry-1",
        "https://example.com/",
        None,
        vec![ManualEditOp {
            ref_: Some("r1".into()),
            original_text: Some("Hello".into()),
            new_text: Some("Hi".into()),
            deleted: false,
            extra: Default::default(),
        }],
    )
    .unwrap();
    assert_eq!(buf.entries.len(), 1);
    assert_eq!(buf.entries[0].ops[0].original_text.as_deref(), Some("Hello"));
    assert_eq!(buf.entries[0].ops[0].new_text.as_deref(), Some("Hi"));

    // Re-editing the same (pageUrl, ref) keeps the true originalText and
    // updates newText.
    let buf2 = stage_entry(
        &dir,
        "entry-1",
        "https://example.com/",
        None,
        vec![op("r1", "Hi there")],
    )
    .unwrap();
    assert_eq!(buf2.entries.len(), 1);
    assert_eq!(buf2.entries[0].ops.len(), 1);
    assert_eq!(
        buf2.entries[0].ops[0].original_text.as_deref(),
        Some("Hello")
    );
    assert_eq!(buf2.entries[0].ops[0].new_text.as_deref(), Some("Hi there"));

    let (total, per_page) = {
        let counts = count_by_page(&dir);
        (counts.total_count, counts.per_page)
    };
    assert_eq!(total, 1);
    assert_eq!(per_page.get("https://example.com/"), Some(&1));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stage_entry_adds_new_op_for_new_ref() {
    let dir = tmp_dir("buffer-new-ref");
    stage_entry(&dir, "e1", "u1", None, vec![op("r1", "a")]).unwrap();
    let buf = stage_entry(&dir, "e1", "u1", None, vec![op("r2", "b")]).unwrap();
    assert_eq!(buf.entries.len(), 1);
    assert_eq!(buf.entries[0].ops.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn remove_entries_counts_ops_and_prunes_empties() {
    let dir = tmp_dir("buffer-remove");
    stage_entry(&dir, "e1", "page-a", None, vec![op("r1", "a"), op("r2", "b")]).unwrap();
    stage_entry(&dir, "e2", "page-b", None, vec![op("r3", "c")]).unwrap();

    let removed = remove_entries(&dir, |entry| entry.page_url.as_deref() == Some("page-a"));
    assert_eq!(removed, 2);

    let buf = read_buffer(&dir);
    assert_eq!(buf.entries.len(), 1);
    assert_eq!(buf.entries[0].page_url.as_deref(), Some("page-b"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn truncate_buffer_empties_and_returns_removed_count() {
    let dir = tmp_dir("buffer-truncate");
    stage_entry(&dir, "e1", "page-a", None, vec![op("r1", "a"), op("r2", "b")]).unwrap();
    let removed = truncate_buffer(&dir);
    assert_eq!(removed, 2);
    let buf = read_buffer(&dir);
    assert!(buf.entries.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn read_buffer_missing_file_returns_empty() {
    let dir = tmp_dir("buffer-missing");
    let buf = read_buffer(&dir);
    assert!(buf.entries.is_empty());
    assert_eq!(buf.version, 1);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// manual_edit_routes
// ---------------------------------------------------------------------

#[test]
fn summarize_pending_batch_filters_by_page() {
    let dir = tmp_dir("routes-summary");
    stage_entry(&dir, "e1", "page-a", None, vec![op("r1", "a"), op("r2", "b")]).unwrap();
    stage_entry(&dir, "e2", "page-b", None, vec![op("r3", "c")]).unwrap();

    let all = summarize_pending_manual_edit_batch(&dir, None);
    assert_eq!(all.pending_entry_count, 2);
    assert_eq!(all.pending_op_count, 3);

    let page_a = summarize_pending_manual_edit_batch(&dir, Some("page-a"));
    assert_eq!(page_a.pending_entry_count, 1);
    assert_eq!(page_a.pending_op_count, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// session_store
// ---------------------------------------------------------------------

#[test]
fn append_event_and_get_snapshot_round_trip() {
    let dir = tmp_dir("session-basic");
    let mut store = LiveSessionStore::new(&dir, None).unwrap();

    let snap = store
        .append_event(
            json!({ "id": "s1", "type": "generate", "pageUrl": "https://x/", "count": 3 }),
            None,
        )
        .unwrap();
    assert_eq!(snap["phase"], json!("generate_requested"));
    assert_eq!(snap["pageUrl"], json!("https://x/"));
    assert_eq!(snap["expectedVariants"], json!(3));

    let snap2 = store
        .append_event(
            json!({ "id": "s1", "type": "variants_ready", "sourceFile": "a.tsx", "arrivedVariants": 3 }),
            None,
        )
        .unwrap();
    assert_eq!(snap2["phase"], json!("variants_ready"));
    assert_eq!(snap2["sourceFile"], json!("a.tsx"));
    assert!(snap2["pendingEvent"].is_null());

    let fetched = store.get_snapshot(Some("s1"), false).unwrap().unwrap();
    assert_eq!(fetched["phase"], json!("variants_ready"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn get_snapshot_hides_completed_unless_requested() {
    let dir = tmp_dir("session-completed");
    let mut store = LiveSessionStore::new(&dir, None).unwrap();
    store
        .append_event(json!({ "id": "s1", "type": "generate" }), None)
        .unwrap();
    store
        .append_event(json!({ "id": "s1", "type": "complete" }), None)
        .unwrap();

    assert!(store.get_snapshot(Some("s1"), false).unwrap().is_none());
    let visible = store.get_snapshot(Some("s1"), true).unwrap().unwrap();
    assert_eq!(visible["phase"], json!("completed"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn append_event_requires_id_and_type() {
    let dir = tmp_dir("session-validation");
    let mut store = LiveSessionStore::new(&dir, None).unwrap();
    let err = store
        .append_event(json!({ "type": "generate" }), None)
        .unwrap_err();
    assert_eq!(err, "event id required");

    let err2 = store
        .append_event(json!({ "id": "s1" }), None)
        .unwrap_err();
    assert_eq!(err2, "event type required");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn stale_checkpoint_is_ignored_and_flagged() {
    let dir = tmp_dir("session-checkpoint");
    let mut store = LiveSessionStore::new(&dir, None).unwrap();
    store
        .append_event(json!({ "id": "s1", "type": "generate" }), None)
        .unwrap();
    store
        .append_event(
            json!({ "id": "s1", "type": "checkpoint", "revision": 5, "phase": "editing" }),
            None,
        )
        .unwrap();
    let snap = store
        .append_event(
            json!({ "id": "s1", "type": "checkpoint", "revision": 2, "phase": "should_not_apply" }),
            None,
        )
        .unwrap();
    assert_eq!(snap["phase"], json!("editing"));
    let diagnostics = snap["diagnostics"].as_array().unwrap();
    assert!(diagnostics
        .iter()
        .any(|d| d["error"] == json!("stale_checkpoint_ignored")));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn list_active_sessions_returns_sorted_snapshots() {
    let dir = tmp_dir("session-list");
    let mut store = LiveSessionStore::new(&dir, None).unwrap();
    store
        .append_event(json!({ "id": "b", "type": "generate" }), None)
        .unwrap();
    store
        .append_event(json!({ "id": "a", "type": "generate" }), None)
        .unwrap();
    let sessions = store.list_active_sessions();
    let ids: Vec<&str> = sessions.iter().map(|s| s["id"].as_str().unwrap()).collect();
    assert_eq!(ids, vec!["a", "b"]);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unknown_event_type_is_diagnosed() {
    let dir = tmp_dir("session-unknown");
    let mut store = LiveSessionStore::new(&dir, None).unwrap();
    let snap = store
        .append_event(json!({ "id": "s1", "type": "mystery" }), None)
        .unwrap();
    let diagnostics = snap["diagnostics"].as_array().unwrap();
    assert!(diagnostics
        .iter()
        .any(|d| d["error"] == json!("unknown_event_type") && d["type"] == json!("mystery")));
    let _ = std::fs::remove_dir_all(&dir);
}
