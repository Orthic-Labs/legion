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
