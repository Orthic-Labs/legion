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
    let parts: Vec<Vec<String>> = paths
        .iter()
        .map(|p| {
            p.components()
                .map(|c| c.as_os_str().to_string_lossy().to_string())
                .collect()
        })
        .collect();
    let min_len = parts.iter().map(Vec::len).min().unwrap_or(0);
    let mut common = Vec::new();
    for i in 0..min_len {
        let seg = &parts[0][i];
        if parts.iter().all(|p| &p[i] == seg) {
            common.push(seg.clone());
        } else {
            break;
        }
    }
    if common.is_empty() {
        paths[0].parent().map(Path::to_path_buf)
    } else {
        Some(PathBuf::from(common.join(std::path::MAIN_SEPARATOR_STR)))
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
        return OpenForReviewOutcome { ok: false, opened: None };
    }
    let target = if existing.len() == 1 {
        existing[0].clone()
    } else {
        common_parent_dir(&existing).unwrap_or_else(|| existing[0].clone())
    };
    let ok = launch(&target);
    OpenForReviewOutcome { ok, opened: Some(target) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_parent_dir_of_single_path_is_its_directory() {
        let paths = vec![PathBuf::from("/repo/docs/report.md")];
        assert_eq!(common_parent_dir(&paths), Some(PathBuf::from("/repo/docs")));
    }

    #[test]
    fn common_parent_dir_finds_shared_ancestor() {
        let paths = vec![
            PathBuf::from("/repo/docs/a.md"),
            PathBuf::from("/repo/docs/sub/b.md"),
        ];
        assert_eq!(common_parent_dir(&paths), Some(PathBuf::from("/repo/docs")));
    }

    #[test]
    fn open_for_review_reports_failure_when_no_path_exists() {
        let outcome = open_for_review(&[PathBuf::from("/missing")], &|_| false, &mut |_| true);
        assert!(!outcome.ok);
        assert!(outcome.opened.is_none());
    }

    #[test]
    fn open_for_review_opens_the_only_existing_path() {
        let outcome = open_for_review(
            &[PathBuf::from("/repo/a.md"), PathBuf::from("/missing.md")],
            &|p| p == Path::new("/repo/a.md"),
            &mut |_| true,
        );
        assert!(outcome.ok);
        assert_eq!(outcome.opened, Some(PathBuf::from("/repo/a.md")));
    }

    #[test]
    fn open_for_review_opens_common_parent_for_multiple_paths() {
        let outcome = open_for_review(
            &[PathBuf::from("/repo/docs/a.md"), PathBuf::from("/repo/docs/b.md")],
            &|_| true,
            &mut |_| true,
        );
        assert_eq!(outcome.opened, Some(PathBuf::from("/repo/docs")));
    }
}
