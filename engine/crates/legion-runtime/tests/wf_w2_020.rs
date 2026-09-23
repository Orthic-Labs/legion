//! Integration coverage for wf_port chunk w2_020
//! (`skills/designer/engine/scripts/live-wrap.mjs`, `live.mjs`,
//! `live/browser-script-parts.mjs`, `live/completion.mjs`,
//! `live/event-validation.mjs`).
//!
//! Per-function unit tests live alongside their modules under
//! `src/wf_port/w2_020/`; this file exercises the chunk's public surface
//! end-to-end the way a caller would, mirroring assertions from the
//! JS test suites those files came from (`tests/live-wrap.test.mjs` and
//! equivalents were not found in the legion repo tree at port time — no
//! `.test.mjs` file references `event-validation.mjs`, `completion.mjs`,
//! `browser-script-parts.mjs`, `live-wrap.mjs` or `live.mjs` directly by
//! name; see `w2_020.md` for the search that was run).

use legion_runtime::wf_port::w2_020::{
    browser_script_parts::{
        assemble_live_browser_script, resolve_live_browser_script_parts, ScriptPartSource, LIVE_BROWSER_SCRIPT_PARTS,
    },
    completion::{completion_ack_for_accept_result, completion_type_for_accept_result},
    event_validation::{can_create_insert, validate_event, VISUAL_ACTIONS},
    live_cli::{glob_to_regex, missing_live_context, scan_for_drift, DirEntry},
    wrap::{build_search_queries, detect_comment_syntax, find_element, find_closing_line},
};
use serde_json::json;

#[test]
fn event_validation_end_to_end_generate_replace_flow() {
    assert!(VISUAL_ACTIONS.contains(&"bolder"));
    let msg = json!({
        "type": "generate",
        "id": "0123abcd",
        "count": 2,
        "action": "bolder",
        "element": {"outerHTML": "<div></div>"},
    });
    assert_eq!(validate_event(Some(&msg)), None);

    let bad = json!({"type": "generate", "id": "0123abcd", "count": 2, "action": "not-a-real-action", "element": {"outerHTML": "<div></div>"}});
    assert_eq!(validate_event(Some(&bad)), Some("generate: invalid action".to_string()));

    assert!(can_create_insert(Some("prompt text"), None, None));
}

#[test]
fn completion_pipeline_drives_ack_shape() {
    let accept_result = json!({"handled": true, "carbonize": true});
    let completion_type = completion_type_for_accept_result("accept", Some(&accept_result));
    assert_eq!(completion_type, "agent_done");
    let ack = completion_ack_for_accept_result("deadbeef", completion_type, Some(&accept_result));
    assert_eq!(ack["requiresComplete"], json!(true));
    assert_eq!(ack["nextCommand"], json!("live-complete.mjs --id deadbeef"));
}

#[test]
fn browser_script_parts_resolve_and_assemble() {
    let resolved = resolve_live_browser_script_parts("/proj/scripts/live", LIVE_BROWSER_SCRIPT_PARTS).unwrap();
    assert_eq!(resolved.len(), 3);

    let sources: Vec<ScriptPartSource> = resolved
        .into_iter()
        .map(|p| ScriptPartSource {
            name: p.name,
            file: p.file,
            index: p.index,
            path: p.path,
            source: format!("/* {} */", p.name),
        })
        .collect();

    let vocab = serde_json::to_string(&json!([{"value": "bolder", "label": "Bolder"}])).unwrap();
    let script = assemble_live_browser_script("tok", 9999, &vocab, &sources);
    assert!(script.starts_with("window.__IMPECCABLE_TOKEN__ = 'tok';"));
    assert!(script.contains("__IMPECCABLE_PORT__ = 9999"));
    assert!(script.contains("session-state"));
    assert!(script.contains("browser-ui"));
}

#[test]
fn live_cli_context_and_drift_scan() {
    assert_eq!(missing_live_context(false, true), vec!["PRODUCT.md"]);
    assert!(glob_to_regex("src/**/*.html").is_match("src/a/b.html"));

    let files: Vec<(&str, ())> = vec![("src/index.html", ()), ("src/orphan.html", ())];
    let list_dir = move |dir: &str| -> Vec<DirEntry> {
        files
            .iter()
            .filter_map(|(path, _)| {
                path.strip_prefix(&format!("{dir}/")).map(|rest| DirEntry {
                    name: rest.to_string(),
                    is_dir: false,
                })
            })
            .collect()
    };
    let resolved = vec!["src/index.html".to_string()];
    let report = scan_for_drift(&resolved, &[], list_dir).unwrap();
    assert_eq!(report.orphans, vec!["src/orphan.html".to_string()]);
}

#[test]
fn wrap_search_and_element_location_flow() {
    let queries = build_search_queries(Some("hero"), Some("card featured"), Some("section"), None);
    assert_eq!(queries[0], "id=\"hero\"");
    assert!(queries.contains(&"card".to_string()));

    assert_eq!(detect_comment_syntax("Page.tsx").open, "{/*");

    let lines: Vec<String> = "<section class=\"card\">\n  <p>hi</p>\n</section>"
        .lines()
        .map(str::to_string)
        .collect();
    let found = find_element(&lines, "card", Some("section")).unwrap();
    assert_eq!(found.start_line, 0);
    assert_eq!(find_closing_line(&lines, 0), 2);
    assert_eq!(found.end_line, 2);
}
