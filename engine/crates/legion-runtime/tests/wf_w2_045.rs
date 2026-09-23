//! Integration tests for chunk w2_045
//! (`src/lib/dispatch-validator/{validate-dispatch.py,validate-tasklist.py}`),
//! exercising the ported path/scope primitives through the crate's public
//! `wf_port::w2_045::path_utils` module.
//!
//! NOTE: this file compiles only once the integrator wires
//! `pub mod w2_045;` into `engine/crates/legion-runtime/src/wf_port/mod.rs`
//! (this chunk owns `src/wf_port/w2_045/**` only, not `mod.rs`). See the
//! chunk report for the exact patch.

use legion_runtime::wf_port::w2_045::path_utils::{
    canonical_locator, clean_path_value, direct_file_allowlist_path, direct_scope_path,
    in_platform_temp_dir, is_absolute_path, resolve_declared_path, scope_static_prefix,
    scopes_overlap,
};
use std::path::Path;

/// Port of `validate-tasklist.py` / `validate-dispatch.py` test fixture:
/// a same-shape direct-packet `plannedFiles` allowlist as exercised by
/// `test_validate_dispatch.py`'s direct-packet fixtures.
fn fixture(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/wf_w2_045")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"))
}

#[test]
fn planned_files_fixture_round_trips_through_direct_file_allowlist_path() {
    let raw = fixture("planned_files.txt");
    let planned: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();

    // Every fixture entry is a valid, unique allowlist path (mirrors
    // validate-dispatch.py's `direct plannedFiles` structural checks).
    let mut seen = std::collections::BTreeSet::new();
    for entry in &planned {
        let normalized = direct_file_allowlist_path(entry)
            .unwrap_or_else(|| panic!("fixture entry should be a valid allowlist path: {entry}"));
        assert!(seen.insert(normalized), "duplicate/aliased planned file: {entry}");
    }
}

#[test]
fn scope_collision_matrix_matches_python_owned_paths_semantics() {
    // Mirrors validate-dispatch.py's `direct OWN collision` matrix: two
    // workers cannot own overlapping scopes, but sibling directories are
    // fine.
    assert!(scopes_overlap(
        "engine/crates/legion-runtime/src/wf_port/w2_045",
        "engine/crates/legion-runtime/src/wf_port/w2_045/path_utils.rs"
    ));
    assert!(!scopes_overlap(
        "engine/crates/legion-runtime/src/wf_port/w2_045",
        "engine/crates/legion-runtime/src/wf_port/w2_046"
    ));
    assert_eq!(
        scope_static_prefix("engine/crates/legion-runtime/tests/fixtures/wf_w2_045/*"),
        "engine/crates/legion-runtime/tests/fixtures/wf_w2_045"
    );
}

#[test]
fn direct_scope_path_forbids_absolute_and_parent_escaping_declarations() {
    assert_eq!(
        direct_scope_path("engine/crates/legion-runtime"),
        Some("engine/crates/legion-runtime".to_string())
    );
    assert_eq!(direct_scope_path("/etc/passwd"), None);
    assert_eq!(direct_scope_path("../outside-repo"), None);
    assert_eq!(direct_scope_path(""), None);
}

#[test]
fn clean_path_value_and_is_absolute_path_agree_on_declared_label_values() {
    // Mirrors how storage_errors() reads "**Validated artifact path:**"
    // label values straight out of dispatch Markdown.
    let declared = "  `/workspace/legion/docs/dispatch.md`  ";
    let cleaned = clean_path_value(declared);
    assert_eq!(cleaned, "/workspace/legion/docs/dispatch.md");
    assert!(is_absolute_path(&cleaned));
}

#[test]
fn resolve_declared_path_and_canonical_locator_round_trip_repo_relative_paths() {
    // `repository_root` (ported from `validate-dispatch.py`) walks up from
    // the artifact looking for `.git`, which in this monorepo layout is the
    // top-level `legion/` directory, not the `legion-runtime` crate root —
    // so a "repo-relative" declared path must be relative to `legion/`,
    // i.e. include the `engine/crates/legion-runtime/` prefix.
    let artifact = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let resolved =
        resolve_declared_path("engine/crates/legion-runtime/src/wf_port/w2_045/mod.rs", &artifact);
    assert!(resolved.ends_with("src/wf_port/w2_045/mod.rs"));
    assert_eq!(
        canonical_locator(&resolved),
        "engine/crates/legion-runtime/src/wf_port/w2_045/mod.rs"
    );
}

#[test]
fn in_platform_temp_dir_rejects_repository_paths() {
    let artifact = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    assert!(!in_platform_temp_dir(&artifact));
}
