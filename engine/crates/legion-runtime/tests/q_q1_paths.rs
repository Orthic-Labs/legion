//! Integration tests for chunk q_q1
//! (`skills/designer/engine/scripts/lib/impeccable-paths.mjs`), exercising
//! the port through the crate's public `wf_port::q_q1` module.

use legion_runtime::wf_port::q_q1::{
    get_critique_dir, get_design_sidecar_candidates, get_design_sidecar_path,
    get_impeccable_dir, get_legacy_live_annotations_dir, get_legacy_live_config_path,
    get_legacy_live_server_path, get_legacy_live_sessions_dir, get_live_annotations_dir,
    get_live_config_path, get_live_dir, get_live_server_path, get_live_sessions_dir,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_project_root() -> PathBuf {
    let pid = std::process::id();
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("legion-q-q1-{pid}-{n}"))
}

#[test]
fn impeccable_dir_and_design_sidecar_under_fresh_root() {
    let root = temp_project_root();
    assert_eq!(get_impeccable_dir(&root), root.join(".impeccable"));
    assert_eq!(
        get_design_sidecar_path(&root),
        root.join(".impeccable").join("design.json")
    );
}

#[test]
fn design_sidecar_candidates_dedup_matches_source_when_context_equals_root() {
    let root = temp_project_root();
    let candidates = get_design_sidecar_candidates(&root, &root);
    assert_eq!(
        candidates,
        vec![
            root.join(".impeccable").join("design.json"),
            root.join("DESIGN.json"),
        ]
    );
}

#[test]
fn live_tree_paths_nest_under_impeccable_live() {
    let root = temp_project_root();
    let live = root.join(".impeccable").join("live");
    assert_eq!(get_live_dir(&root), live);
    assert_eq!(get_live_config_path(&root), live.join("config.json"));
    assert_eq!(get_live_server_path(&root), live.join("server.json"));
    assert_eq!(get_live_sessions_dir(&root), live.join("sessions"));
    assert_eq!(get_live_annotations_dir(&root), live.join("annotations"));
    assert_eq!(get_critique_dir(&root), root.join(".impeccable").join("critique"));
}

#[test]
fn legacy_live_paths_use_dotfile_and_dotdir_forms() {
    let root = temp_project_root();
    assert_eq!(
        get_legacy_live_server_path(&root),
        root.join(".impeccable-live.json")
    );
    assert_eq!(
        get_legacy_live_sessions_dir(&root),
        root.join(".impeccable-live").join("sessions")
    );
    assert_eq!(
        get_legacy_live_annotations_dir(&root),
        root.join(".impeccable-live").join("annotations")
    );
    let scripts_dir = Path::new("/workspace/legion/skills/designer/engine/scripts");
    assert_eq!(
        get_legacy_live_config_path(scripts_dir),
        scripts_dir.join("config.json")
    );
}
