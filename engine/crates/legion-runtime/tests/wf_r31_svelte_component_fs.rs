//! Integration tests for packet r31: the filesystem/session orchestration
//! layer of `skills/designer/engine/scripts/live/svelte-component.mjs`
//! (`ensureRuntimeHelper`, `scaffoldSvelteComponentSession`,
//! `scaffoldSvelteComponentInsertSession`, `findSvelteComponentManifest`,
//! `resolveSourceFile`, `inlineSvelteComponentAccept`,
//! `inlineSvelteComponentInsertAccept`, `removeSvelteComponentSession`,
//! `removeAllSvelteComponentSessions`, `deferredAcceptsPath`,
//! `readDeferredAccepts`/`writeDeferredAccept`/
//! `applyDeferredSvelteComponentAccepts`), exercised through the crate's
//! public `wf_port::w2_022::svelte_component` module.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use legion_runtime::wf_port::w2_022::svelte_component::{
    apply_deferred_svelte_component_accepts, component_session_dir, deferred_accepts_path,
    ensure_runtime_helper, find_svelte_component_manifest, inline_svelte_component_accept,
    manifest_path_for_session, read_deferred_accepts, remove_all_svelte_component_sessions,
    remove_svelte_component_session, resolve_source_file, scaffold_svelte_component_insert_session,
    scaffold_svelte_component_session, write_deferred_accept, ScaffoldInsertSessionInput,
    ScaffoldSessionInput, SVELTE_COMPONENT_ROOT,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_project_root() -> PathBuf {
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!("legion-r31-{pid}-{n}"));
    std::fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn ensure_runtime_helper_writes_file_once() {
    let cwd = temp_project_root();
    let path = ensure_runtime_helper(&cwd).unwrap();
    assert!(path.ends_with("node_modules/.impeccable-live/__runtime.js"));
    let content = std::fs::read_to_string(&path).unwrap();
    assert_eq!(content, "export { mount, unmount } from 'svelte';\n");
    // Second call is a no-op (file already exists, content unchanged).
    std::fs::write(&path, "custom").unwrap();
    let path2 = ensure_runtime_helper(&cwd).unwrap();
    assert_eq!(path, path2);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "custom");
}

#[test]
fn scaffold_session_writes_manifest_and_variant_stubs() {
    let cwd = temp_project_root();
    let route = cwd.join("src/routes/+page.svelte");
    std::fs::create_dir_all(route.parent().unwrap()).unwrap();
    std::fs::write(&route, "<div>{user.name}</div>\n").unwrap();

    let original_lines = vec!["<div>{user.name}</div>".to_string()];
    let result = scaffold_svelte_component_session(
        ScaffoldSessionInput {
            id: "sess1",
            count: 2,
            source_file: "src/routes/+page.svelte",
            source_start_line: 1,
            source_end_line: 1,
            original_lines: &original_lines,
        },
        &cwd,
    )
    .unwrap();

    assert_eq!(result.prop_contract.len(), 1);
    assert_eq!(result.prop_contract[0].prop, "name");
    assert_eq!(result.component_dir, format!("{SVELTE_COMPONENT_ROOT}/sess1"));

    let manifest_path = manifest_path_for_session("sess1", &cwd);
    assert!(manifest_path.exists());
    let manifest = find_svelte_component_manifest("sess1", &cwd).unwrap();
    assert_eq!(manifest["id"], "sess1");
    assert_eq!(manifest["count"], 2);

    let dir = component_session_dir("sess1", &cwd);
    assert!(dir.join("v1.svelte").exists());
    assert!(dir.join("v2.svelte").exists());
    let v1 = std::fs::read_to_string(dir.join("v1.svelte")).unwrap();
    assert!(v1.contains("let { name } = $props();"));
}

#[test]
fn scaffold_insert_session_uses_insert_stub() {
    let cwd = temp_project_root();
    let route = cwd.join("src/routes/+page.svelte");
    std::fs::create_dir_all(route.parent().unwrap()).unwrap();
    std::fs::write(&route, "<div>anchor</div>\n").unwrap();

    let anchor_lines = vec!["<div>anchor</div>".to_string()];
    let result = scaffold_svelte_component_insert_session(
        ScaffoldInsertSessionInput {
            id: "ins1",
            count: 1,
            source_file: "src/routes/+page.svelte",
            insert_line: 2,
            position: "after",
            anchor_start_line: Some(1),
            anchor_end_line: Some(1),
            anchor_lines: &anchor_lines,
        },
        &cwd,
    )
    .unwrap();

    assert!(result.prop_contract.is_empty());
    let dir = component_session_dir("ins1", &cwd);
    let v1 = std::fs::read_to_string(dir.join("v1.svelte")).unwrap();
    assert!(v1.contains("Insert variant 1"));
    let manifest = find_svelte_component_manifest("ins1", &cwd).unwrap();
    assert_eq!(manifest["mode"], "insert");
}

#[test]
fn resolve_source_file_rejects_absolute_and_escaping_paths() {
    let cwd = temp_project_root();
    assert!(resolve_source_file("/etc/passwd", &cwd).is_err());
    assert!(resolve_source_file("../outside.svelte", &cwd).is_err());
    assert!(resolve_source_file("missing.svelte", &cwd).is_err());

    std::fs::write(cwd.join("present.svelte"), "x").unwrap();
    let resolved = resolve_source_file("present.svelte", &cwd).unwrap();
    assert!(resolved.ends_with("present.svelte"));
}

#[test]
fn inline_accept_rewrites_source_and_removes_session() {
    let cwd = temp_project_root();
    let route = cwd.join("src/routes/+page.svelte");
    std::fs::create_dir_all(route.parent().unwrap()).unwrap();
    std::fs::write(
        &route,
        "<script>\n</script>\n<div>{user.name}</div>\n<style>\n</style>\n",
    )
    .unwrap();

    let original_lines = vec!["<div>{user.name}</div>".to_string()];
    scaffold_svelte_component_session(
        ScaffoldSessionInput {
            id: "acc1",
            count: 1,
            source_file: "src/routes/+page.svelte",
            source_start_line: 3,
            source_end_line: 3,
            original_lines: &original_lines,
        },
        &cwd,
    )
    .unwrap();

    // Overwrite variant 1 with a variant that has different markup and CSS.
    let dir = component_session_dir("acc1", &cwd);
    std::fs::write(
        dir.join("v1.svelte"),
        "<script>\n  let { name } = $props();\n</script>\n<div class=\"row\">{name}</div>\n\n<style>\n  .row { padding: 4px; }\n</style>\n",
    )
    .unwrap();

    let manifest = find_svelte_component_manifest("acc1", &cwd).unwrap();
    let result = inline_svelte_component_accept(&manifest, 1, None, &cwd);
    assert!(result.handled, "accept failed: {:?}", result.error);

    let new_source = std::fs::read_to_string(&route).unwrap();
    assert!(new_source.contains("{user.name}"), "expr restored: {new_source}");
    assert!(new_source.contains("class=\"row\""));
    assert!(new_source.contains("padding: 4px;"));

    // Session directory should be gone after a successful accept.
    assert!(!dir.exists());
    assert!(find_svelte_component_manifest("acc1", &cwd).is_none());
}

#[test]
fn inline_accept_reports_missing_variant() {
    let cwd = temp_project_root();
    let route = cwd.join("src/routes/+page.svelte");
    std::fs::create_dir_all(route.parent().unwrap()).unwrap();
    std::fs::write(&route, "<div>{x}</div>\n").unwrap();

    let original_lines = vec!["<div>{x}</div>".to_string()];
    scaffold_svelte_component_session(
        ScaffoldSessionInput {
            id: "missvar",
            count: 1,
            source_file: "src/routes/+page.svelte",
            source_start_line: 1,
            source_end_line: 1,
            original_lines: &original_lines,
        },
        &cwd,
    )
    .unwrap();

    let manifest = find_svelte_component_manifest("missvar", &cwd).unwrap();
    let result = inline_svelte_component_accept(&manifest, 9, None, &cwd);
    assert!(!result.handled);
    assert_eq!(result.error.as_deref(), Some("Variant 9 not found"));
}

#[test]
fn remove_session_and_remove_all_sessions() {
    let cwd = temp_project_root();
    let original_lines = vec!["<div>x</div>".to_string()];
    let route = cwd.join("page.svelte");
    std::fs::write(&route, "<div>x</div>\n").unwrap();
    for id in ["s1", "s2"] {
        scaffold_svelte_component_session(
            ScaffoldSessionInput {
                id,
                count: 1,
                source_file: "page.svelte",
                source_start_line: 1,
                source_end_line: 1,
                original_lines: &original_lines,
            },
            &cwd,
        )
        .unwrap();
    }
    ensure_runtime_helper(&cwd).unwrap();

    remove_svelte_component_session("s1", &cwd);
    assert!(!component_session_dir("s1", &cwd).exists());
    assert!(component_session_dir("s2", &cwd).exists());

    remove_all_svelte_component_sessions(&cwd);
    assert!(!component_session_dir("s2", &cwd).exists());
    // __runtime.js (the `__`-prefixed entry) survives a "remove all" pass.
    assert!(cwd.join(SVELTE_COMPONENT_ROOT).join("__runtime.js").exists());
}

#[test]
fn deferred_accepts_round_trip_and_apply() {
    let cwd = temp_project_root();
    let route = cwd.join("page.svelte");
    std::fs::write(&route, "<div>{v}</div>\n").unwrap();
    let original_lines = vec!["<div>{v}</div>".to_string()];
    scaffold_svelte_component_session(
        ScaffoldSessionInput {
            id: "def1",
            count: 1,
            source_file: "page.svelte",
            source_start_line: 1,
            source_end_line: 1,
            original_lines: &original_lines,
        },
        &cwd,
    )
    .unwrap();

    let entry = serde_json::json!({ "id": "def1", "variantNum": 1, "paramValues": null });
    write_deferred_accept(entry, &cwd).unwrap();

    let data = read_deferred_accepts(&cwd);
    assert_eq!(data.accepts.len(), 1);
    assert_eq!(data.accepts[0]["id"], "def1");

    let result = apply_deferred_svelte_component_accepts(&cwd).unwrap();
    assert_eq!(result.applied, 1);
    assert_eq!(result.failed, 0);

    // File is cleaned up once every entry has been applied.
    assert!(!deferred_accepts_path(&cwd).exists());
    let after = read_deferred_accepts(&cwd);
    assert!(after.accepts.is_empty());
}

#[test]
fn deferred_accepts_path_is_stable_and_keyed_by_project_root() {
    let cwd_a = temp_project_root();
    let cwd_b = temp_project_root();
    let path_a1 = deferred_accepts_path(&cwd_a);
    let path_a2 = deferred_accepts_path(&cwd_a);
    let path_b = deferred_accepts_path(&cwd_b);
    assert_eq!(path_a1, path_a2);
    assert_ne!(path_a1, path_b);
    assert!(path_a1.ends_with("deferred-svelte-component-accepts.json"));
}
