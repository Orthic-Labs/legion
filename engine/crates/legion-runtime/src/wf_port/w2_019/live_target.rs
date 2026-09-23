//! Port of the pure logic in
//! `skills/designer/engine/scripts/live-target.mjs`.
//!
//! `resolveLiveTarget` in JS also performs the argv parse
//! (`parseTargetPath`, from `lib/target-args.mjs`) and project-root
//! discovery (`resolveProjectRoot`, from `context.mjs`) — both owned by
//! other, unported chunks. This ports the remaining pure computation:
//! given an already-parsed target path (or none) and an already-resolved
//! project root, derive the absolute target path and the `targetOptions`
//! object passed on to the rest of the pipeline.
//!
//! See [`crate::wf_port::w2_019`] for what is and isn't ported from this
//! file.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};

/// Port of `resolveLiveTarget`'s return shape (the parts this module
/// computes; `originalCwd`/`projectRoot` are inputs here, not outputs,
/// since their JS computation lives outside this chunk).
#[derive(Debug, Clone, PartialEq)]
pub struct LiveTargetResolution {
    pub original_cwd: PathBuf,
    pub project_root: PathBuf,
    pub target_path: Option<String>,
    pub absolute_target_path: Option<PathBuf>,
    /// Mirrors `targetOptions`: `{ targetPath: absoluteTargetPath }` when a
    /// target path was given, else `{}`.
    pub target_options: Value,
}

/// Port of the tail of `resolveLiveTarget(cwd, args)` starting from
/// `const absoluteTargetPath = targetPath ? ... : null;`, given the caller
/// has already run `parseTargetPath`/`resolveProjectRoot` (or the
/// no-target-path defaults) upstream.
///
/// - `original_cwd` mirrors `path.resolve(cwd)`.
/// - `target_path` mirrors the string `parseTargetPath` returned (or
///   `None` when no target was given).
/// - `project_root` mirrors the value `resolveProjectRoot` returned when a
///   target path was given, or `original_cwd` unchanged otherwise (JS:
///   `targetPath ? resolveProjectRoot(...) : originalCwd`) — callers with
///   a target path pass in whatever `resolveProjectRoot` produced.
pub fn resolve_live_target(
    original_cwd: &Path,
    target_path: Option<&str>,
    project_root: &Path,
) -> LiveTargetResolution {
    let absolute_target_path = target_path.map(|t| {
        let p = Path::new(t);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            original_cwd.join(p)
        }
    });

    let target_options = match &absolute_target_path {
        Some(p) => json!({ "targetPath": p.to_string_lossy() }),
        None => json!({}),
    };

    LiveTargetResolution {
        original_cwd: original_cwd.to_path_buf(),
        project_root: project_root.to_path_buf(),
        target_path: target_path.map(str::to_string),
        absolute_target_path,
        target_options,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_target_path_yields_empty_options_and_cwd_as_root() {
        let cwd = Path::new("/proj");
        let res = resolve_live_target(cwd, None, cwd);
        assert_eq!(res.target_path, None);
        assert_eq!(res.absolute_target_path, None);
        assert_eq!(res.target_options, json!({}));
        assert_eq!(res.project_root, cwd);
    }

    #[test]
    fn relative_target_path_is_joined_to_original_cwd() {
        let cwd = Path::new("/proj");
        let root = Path::new("/proj");
        let res = resolve_live_target(cwd, Some("apps/web"), root);
        assert_eq!(
            res.absolute_target_path,
            Some(PathBuf::from("/proj/apps/web"))
        );
        assert_eq!(
            res.target_options,
            json!({ "targetPath": "/proj/apps/web" })
        );
    }

    #[test]
    fn absolute_target_path_is_kept_as_is() {
        let cwd = Path::new("/proj");
        let root = Path::new("/proj");
        let res = resolve_live_target(cwd, Some("/other/app"), root);
        assert_eq!(res.absolute_target_path, Some(PathBuf::from("/other/app")));
    }
}
