//! Pure path-derivation port of `skills/designer/engine/scripts/lib/impeccable-paths.mjs`.
//!
//! Every function here takes an explicit `project_root: &Path` in place of
//! the JS source's `resolveProjectRoot(cwd, options)` call (that resolver
//! lives in `../context.mjs`, which is not yet ported — see the module
//! docs). Callers that already have a resolved project root get identical
//! path values to the JS source; callers that need root *discovery* still
//! need the future `context.mjs` port.

use std::path::{Path, PathBuf};

pub const IMPECCABLE_DIR: &str = ".impeccable";
pub const LIVE_DIR: &str = "live";
pub const CRITIQUE_DIR: &str = "critique";

/// `getImpeccableDir(cwd, options)` — `path.join(projectRoot, '.impeccable')`.
pub fn get_impeccable_dir(project_root: &Path) -> PathBuf {
    project_root.join(IMPECCABLE_DIR)
}

/// `getDesignSidecarPath(cwd, options)`.
pub fn get_design_sidecar_path(project_root: &Path) -> PathBuf {
    get_impeccable_dir(project_root).join("design.json")
}

/// `getDesignSidecarCandidates(cwd, contextDir, options)`.
///
/// `contextDir` defaults to `cwd` in the JS source; here it defaults to
/// `project_root` when the caller passes the same value for both, matching
/// that default. Order and dedup (`!candidates.includes(contextLegacy)`)
/// match the source exactly.
pub fn get_design_sidecar_candidates(project_root: &Path, context_dir: &Path) -> Vec<PathBuf> {
    let mut candidates = vec![
        get_design_sidecar_path(project_root),
        project_root.join("DESIGN.json"),
    ];
    let context_legacy = context_dir.join("DESIGN.json");
    if !candidates.contains(&context_legacy) {
        candidates.push(context_legacy);
    }
    candidates
}

/// `getLiveDir(cwd, options)`.
pub fn get_live_dir(project_root: &Path) -> PathBuf {
    get_impeccable_dir(project_root).join(LIVE_DIR)
}

/// `getLiveConfigPath(cwd, options)`.
pub fn get_live_config_path(project_root: &Path) -> PathBuf {
    get_live_dir(project_root).join("config.json")
}

/// `getLegacyLiveConfigPath(scriptsDir)`.
pub fn get_legacy_live_config_path(scripts_dir: &Path) -> PathBuf {
    scripts_dir.join("config.json")
}

/// `getLiveServerPath(cwd, options)`.
pub fn get_live_server_path(project_root: &Path) -> PathBuf {
    get_live_dir(project_root).join("server.json")
}

/// `getLegacyLiveServerPath(cwd, options)`.
pub fn get_legacy_live_server_path(project_root: &Path) -> PathBuf {
    project_root.join(".impeccable-live.json")
}

/// `getLiveSessionsDir(cwd, options)`.
pub fn get_live_sessions_dir(project_root: &Path) -> PathBuf {
    get_live_dir(project_root).join("sessions")
}

/// `getLegacyLiveSessionsDir(cwd, options)`.
pub fn get_legacy_live_sessions_dir(project_root: &Path) -> PathBuf {
    project_root.join(".impeccable-live").join("sessions")
}

/// `getLiveAnnotationsDir(cwd, options)`.
pub fn get_live_annotations_dir(project_root: &Path) -> PathBuf {
    get_live_dir(project_root).join("annotations")
}

/// `getLegacyLiveAnnotationsDir(cwd, options)`.
pub fn get_legacy_live_annotations_dir(project_root: &Path) -> PathBuf {
    project_root.join(".impeccable-live").join("annotations")
}

/// `getCritiqueDir(cwd, options)`.
pub fn get_critique_dir(project_root: &Path) -> PathBuf {
    get_impeccable_dir(project_root).join(CRITIQUE_DIR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn impeccable_dir_joins_dotfile_under_root() {
        let root = Path::new("/workspace/project");
        assert_eq!(
            get_impeccable_dir(root),
            Path::new("/workspace/project/.impeccable")
        );
    }

    #[test]
    fn design_sidecar_path_is_impeccable_dir_slash_design_json() {
        let root = Path::new("/workspace/project");
        assert_eq!(
            get_design_sidecar_path(root),
            Path::new("/workspace/project/.impeccable/design.json")
        );
    }

    #[test]
    fn design_sidecar_candidates_match_js_order_and_dedup() {
        let root = Path::new("/workspace/project");
        // contextDir == cwd == project_root, mirroring the JS default
        // `getDesignSidecarCandidates(cwd, contextDir = cwd, options)`.
        let candidates = get_design_sidecar_candidates(root, root);
        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/workspace/project/.impeccable/design.json"),
                PathBuf::from("/workspace/project/DESIGN.json"),
            ],
            "contextLegacy == projectRoot/DESIGN.json is already in candidates, so it is not duplicated"
        );
    }

    #[test]
    fn design_sidecar_candidates_appends_distinct_context_legacy() {
        let root = Path::new("/workspace/project");
        let context_dir = Path::new("/workspace/project/subdir");
        let candidates = get_design_sidecar_candidates(root, context_dir);
        assert_eq!(
            candidates,
            vec![
                PathBuf::from("/workspace/project/.impeccable/design.json"),
                PathBuf::from("/workspace/project/DESIGN.json"),
                PathBuf::from("/workspace/project/subdir/DESIGN.json"),
            ]
        );
    }

    #[test]
    fn live_dir_and_config_path() {
        let root = Path::new("/workspace/project");
        assert_eq!(
            get_live_dir(root),
            Path::new("/workspace/project/.impeccable/live")
        );
        assert_eq!(
            get_live_config_path(root),
            Path::new("/workspace/project/.impeccable/live/config.json")
        );
    }

    #[test]
    fn legacy_live_config_path_joins_scripts_dir() {
        let scripts_dir = Path::new("/workspace/project/skills/designer/engine/scripts");
        assert_eq!(
            get_legacy_live_config_path(scripts_dir),
            Path::new("/workspace/project/skills/designer/engine/scripts/config.json")
        );
    }

    #[test]
    fn live_server_paths_current_and_legacy() {
        let root = Path::new("/workspace/project");
        assert_eq!(
            get_live_server_path(root),
            Path::new("/workspace/project/.impeccable/live/server.json")
        );
        assert_eq!(
            get_legacy_live_server_path(root),
            Path::new("/workspace/project/.impeccable-live.json")
        );
    }

    #[test]
    fn live_sessions_and_annotations_dirs_current_and_legacy() {
        let root = Path::new("/workspace/project");
        assert_eq!(
            get_live_sessions_dir(root),
            Path::new("/workspace/project/.impeccable/live/sessions")
        );
        assert_eq!(
            get_legacy_live_sessions_dir(root),
            Path::new("/workspace/project/.impeccable-live/sessions")
        );
        assert_eq!(
            get_live_annotations_dir(root),
            Path::new("/workspace/project/.impeccable/live/annotations")
        );
        assert_eq!(
            get_legacy_live_annotations_dir(root),
            Path::new("/workspace/project/.impeccable-live/annotations")
        );
    }

    #[test]
    fn critique_dir_joins_impeccable_dir() {
        let root = Path::new("/workspace/project");
        assert_eq!(
            get_critique_dir(root),
            Path::new("/workspace/project/.impeccable/critique")
        );
    }
}
