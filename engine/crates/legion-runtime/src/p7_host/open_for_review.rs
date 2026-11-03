//! Port of src/lib/open-for-review.mjs. The actual OS-viewer spawn (`open` /
//! `xdg-open` / `start`) is a real side effect and is injected via `launch`
//! so this module stays testable; `open_for_review` reproduces the pure
//! decision logic (path filtering, common-parent-dir resolution) faithfully.

use std::path::{Path, PathBuf};

/// Port of `commonParentDir`. Paths are assumed already-resolved (absolute).
pub fn common_parent_dir(paths: &[PathBuf]) -> Option<PathBuf> {
    if paths.is_empty() {
        return None;
    }
    if paths.len() == 1 {
        return paths[0].parent().map(Path::to_path_buf);
    }
    // Compare and rebuild via `Path::components()`/`PathBuf::push` rather
    // than joining strings with `MAIN_SEPARATOR_STR`: the root component
    // (e.g. `/` on a Unix-style path) already carries its own separator
    // semantics, and re-joining it as a plain string segment doubles up
    // the separator on Windows (`RootDir` stringifies to `\`, so joining
    // `["\\", "repo", "docs"]` with `\` produces the UNC-looking
    // `\\repo\docs` instead of `\repo\docs`).
    let parts: Vec<Vec<std::path::Component>> =
        paths.iter().map(|p| p.components().collect()).collect();
    let min_len = parts.iter().map(Vec::len).min().unwrap_or(0);
    let mut common: Vec<std::path::Component> = Vec::new();
    for i in 0..min_len {
        let seg = parts[0][i];
        if parts.iter().all(|p| p[i] == seg) {
            common.push(seg);
        } else {
            break;
        }
    }
    if common.is_empty() {
        paths[0].parent().map(Path::to_path_buf)
    } else {
        let mut buf = PathBuf::new();
        for c in common {
            buf.push(c.as_os_str());
        }
        Some(buf)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenForReviewOutcome {
    pub ok: bool,
    pub opened: Option<PathBuf>,
}

/// Port of `openForReview`'s decision logic, given already-resolved input
/// paths and an `exists` probe. `launch` performs the actual OS-open call and
/// returns whether it succeeded (mirroring `openOne`'s resolved boolean).
pub fn open_for_review(
    paths: &[PathBuf],
    exists: &dyn Fn(&Path) -> bool,
    launch: &mut dyn FnMut(&Path) -> bool,
) -> OpenForReviewOutcome {
    let existing: Vec<PathBuf> = paths.iter().filter(|p| exists(p)).cloned().collect();
    if existing.is_empty() {
        return OpenForReviewOutcome {
            ok: false,
            opened: None,
        };
    }
    let target = if existing.len() == 1 {
        existing[0].clone()
    } else {
        common_parent_dir(&existing).unwrap_or_else(|| existing[0].clone())
    };
    let ok = launch(&target);
    OpenForReviewOutcome {
        ok,
        opened: Some(target),
    }
}
