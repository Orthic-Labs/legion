//! Packet r28: tests for the insert-ui helpers added to close the
//! w2_021/insert_ui.rs gap so
//! `skills/designer/engine/scripts/live/insert-ui.mjs` can be deleted:
//! `setVariantShown`, `buildInsertGeneratePayload`,
//! `resolveInsertSessionAnchor`, `buildInsertPlaceholderSnapshot`, and
//! `findInsertAnchorInDom`.

use legion_runtime::wf_port::w2_021::insert_ui::{
    build_insert_generate_payload, build_insert_placeholder_snapshot, find_insert_anchor_in_dom,
    resolve_insert_session_anchor, set_variant_shown, AnchorInfo, DomQuery,
    InsertGeneratePayloadInput, InsertAxis, InsertPosition, PlaceholderGeometry, VariantElement,
};
use serde_json::json;

#[derive(Debug, Default, Clone)]
struct FakeEl {
    hidden: bool,
    display: String,
}

impl VariantElement for FakeEl {
    fn remove_hidden_attr(&mut self) {
        self.hidden = false;
    }
    fn set_hidden_attr(&mut self) {
        self.hidden = true;
    }
    fn set_style_display(&mut self, value: &str) {
        self.display = value.to_string();
    }
}

#[test]
fn set_variant_shown_toggles_hidden_and_display() {
    let mut el = FakeEl {
        hidden: true,
        display: "none".to_string(),
    };
    set_variant_shown(Some(&mut el), true);
    assert!(!el.hidden);
    assert_eq!(el.display, "");

    set_variant_shown(Some(&mut el), false);
    assert!(el.hidden);
    assert_eq!(el.display, "none");
}

#[test]
fn set_variant_shown_none_is_noop() {
    // Must not panic when there is no element (mirrors the JS `if (!el) return;`).
    set_variant_shown::<FakeEl>(None, true);
}

#[test]
fn build_insert_generate_payload_omits_empty_optional_fields() {
    let payload = build_insert_generate_payload(&InsertGeneratePayloadInput {
        id: "abc",
        count: 2,
        page_url: "https://example.com",
        anchor_context: json!({"sel": "div.foo"}),
        position: InsertPosition::Before,
        placeholder: json!({"w": 100}),
        freeform_prompt: Some("   "),
        comments: &[],
        strokes: &[],
        screenshot_path: None,
    });
    assert_eq!(payload["type"], "generate");
    assert_eq!(payload["mode"], "insert");
    assert_eq!(payload["insert"]["position"], "before");
    assert!(payload.get("freeformPrompt").is_none());
    assert!(payload.get("comments").is_none());
    assert!(payload.get("strokes").is_none());
    assert!(payload.get("screenshotPath").is_none());
}

#[test]
fn build_insert_generate_payload_includes_present_optional_fields() {
    let comments = vec![json!({"text": "hi"})];
    let strokes = vec![json!({"points": [[0, 0], [1, 1]]})];
    let payload = build_insert_generate_payload(&InsertGeneratePayloadInput {
        id: "abc",
        count: 1,
        page_url: "https://example.com",
        anchor_context: json!({"sel": "div.foo"}),
        position: InsertPosition::After,
        placeholder: json!({"w": 100}),
        freeform_prompt: Some("  make it blue  "),
        comments: &comments,
        strokes: &strokes,
        screenshot_path: Some("/tmp/shot.png"),
    });
    assert_eq!(payload["insert"]["position"], "after");
    assert_eq!(payload["freeformPrompt"], "make it blue");
    assert_eq!(payload["comments"], json!(comments));
    assert_eq!(payload["strokes"], json!(strokes));
    assert_eq!(payload["screenshotPath"], "/tmp/shot.png");
}

#[test]
fn resolve_insert_session_anchor_prefers_visible_variant() {
    let wrapper = "wrapper".to_string();
    let pick = |w: &String, idx: i64| -> Option<String> { Some(format!("{w}-variant-{idx}")) };
    let anchor = resolve_insert_session_anchor(
        Some(&wrapper),
        2,
        1,
        Some("placeholder".to_string()),
        None,
        Some(&pick),
    );
    assert_eq!(anchor, Some("wrapper-variant-1".to_string()));
}

#[test]
fn resolve_insert_session_anchor_falls_back_to_placeholder_then_insert_anchor() {
    // No wrapper/pick -> placeholder.
    let anchor = resolve_insert_session_anchor::<String>(
        None,
        0,
        0,
        Some("placeholder".to_string()),
        Some("insert-anchor".to_string()),
        None,
    );
    assert_eq!(anchor, Some("placeholder".to_string()));

    // No placeholder -> insert anchor.
    let anchor = resolve_insert_session_anchor::<String>(
        None,
        0,
        0,
        None,
        Some("insert-anchor".to_string()),
        None,
    );
    assert_eq!(anchor, Some("insert-anchor".to_string()));

    // Neither -> None.
    let anchor = resolve_insert_session_anchor::<String>(None, 0, 0, None, None, None);
    assert_eq!(anchor, None);
}

#[test]
fn resolve_insert_session_anchor_pick_miss_falls_through() {
    let wrapper = "wrapper".to_string();
    let pick = |_w: &String, _idx: i64| -> Option<String> { None };
    let anchor = resolve_insert_session_anchor(
        Some(&wrapper),
        2,
        1,
        Some("placeholder".to_string()),
        None,
        Some(&pick),
    );
    assert_eq!(anchor, Some("placeholder".to_string()));
}

#[test]
fn build_insert_placeholder_snapshot_parses_px_margins_and_defaults() {
    let anchor = AnchorInfo {
        tag_name: Some("SECTION"),
        class_name: Some("card active"),
        text_content: Some("  Hello world  "),
    };
    let placeholder = PlaceholderGeometry {
        offset_width: Some(123.6),
        offset_height: None,
        margin_left: Some("12.5px"),
        margin_top: Some("not-a-number"),
    };
    let snap = build_insert_placeholder_snapshot(
        &anchor,
        &placeholder,
        InsertPosition::Before,
        Some(InsertAxis::Row),
    );
    assert_eq!(snap.width, 124);
    assert_eq!(snap.height, 80); // PLACEHOLDER_DEFAULT_HEIGHT
    assert_eq!(snap.margin_left, 12.5);
    assert_eq!(snap.margin_top, 0.0); // unparsable -> 0, matches JS `parseFloat(...) || 0`
    assert_eq!(snap.anchor_tag, "SECTION");
    assert_eq!(snap.anchor_classes, "card active");
    assert_eq!(snap.anchor_text, "Hello world");
}

#[test]
fn build_insert_placeholder_snapshot_defaults_missing_tag_to_div() {
    let anchor = AnchorInfo {
        tag_name: None,
        class_name: None,
        text_content: None,
    };
    let placeholder = PlaceholderGeometry::default();
    let snap =
        build_insert_placeholder_snapshot(&anchor, &placeholder, InsertPosition::After, None);
    assert_eq!(snap.anchor_tag, "DIV");
    assert_eq!(snap.layout_axis, InsertAxis::Column);
}

#[derive(Clone, Debug, PartialEq)]
struct FakeNode {
    id: &'static str,
    text: &'static str,
}

struct FakeDoc {
    body_nodes: Vec<FakeNode>,
    queryable: Vec<FakeNode>,
}

impl DomQuery<FakeNode> for FakeDoc {
    fn body_contains(&self, el: &FakeNode) -> bool {
        self.body_nodes.iter().any(|n| n.id == el.id)
    }
    fn query_selector_all(&self, _selector: &str) -> Vec<FakeNode> {
        self.queryable.clone()
    }
    fn text_content(&self, el: &FakeNode) -> String {
        el.text.to_string()
    }
}

#[test]
fn find_insert_anchor_in_dom_prefers_live_anchor_if_still_attached() {
    let live = FakeNode {
        id: "live",
        text: "still here",
    };
    let doc = FakeDoc {
        body_nodes: vec![live.clone()],
        queryable: vec![],
    };
    let found = find_insert_anchor_in_dom(&doc, None, Some(&live));
    assert_eq!(found, Some(live));
}

#[test]
fn find_insert_anchor_in_dom_falls_back_to_snapshot_match() {
    let anchor = AnchorInfo {
        tag_name: Some("DIV"),
        class_name: Some("card"),
        text_content: Some("Hello world, this describes the card in detail"),
    };
    let placeholder = PlaceholderGeometry::default();
    let snap =
        build_insert_placeholder_snapshot(&anchor, &placeholder, InsertPosition::Before, None);

    let wrong = FakeNode {
        id: "wrong",
        text: "unrelated content",
    };
    let right = FakeNode {
        id: "right",
        text: "Hello world, this describes the card in detail and more",
    };
    let doc = FakeDoc {
        body_nodes: vec![],
        queryable: vec![wrong, right.clone()],
    };
    // Stale live anchor (detached) is ignored, snapshot text match wins.
    let stale = FakeNode {
        id: "stale",
        text: "gone",
    };
    let found = find_insert_anchor_in_dom(&doc, Some(&snap), Some(&stale));
    assert_eq!(found, Some(right));
}

#[test]
fn find_insert_anchor_in_dom_no_snapshot_and_no_live_anchor_returns_none() {
    let doc = FakeDoc {
        body_nodes: vec![],
        queryable: vec![],
    };
    let found = find_insert_anchor_in_dom(&doc, None, None);
    assert_eq!(found, None);
}
