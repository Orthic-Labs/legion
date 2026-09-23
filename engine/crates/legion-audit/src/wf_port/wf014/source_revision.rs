//! Port of `src/lib/qualification/source-revision.mjs`.
//!
//! Content-based source revision. Hashes the tracked SOURCE tree
//! (qualification evidence, architecture notes, and the lockfile excluded)
//! plus any dirty non-excluded working files. Two checkouts with identical
//! source bytes produce the identical revision regardless of git history —
//! so a commit that only touches `qualification/` (e.g. sealing a book
//! receipt) does not change the revision, and receipts survive their own
//! commit.

use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

/// JS `EXCLUDED`.
fn excluded(path: &str) -> bool {
    path.starts_with("qualification/") || path == "architecture.md" || path == "pnpm-lock.yaml"
}

fn run_git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("failed to spawn git {args:?}: {error}"));
    if !output.status.success() {
        panic!(
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn source_revision(root: &Path, include_dirty: bool) -> String {
    let mut hash = Sha256::new();

    // Tracked source content, stable order: path NUL blob-sha NUL. Uses
    // git's own blob identity (content hash) so we avoid re-reading every
    // tracked file.
    let tracked_output = run_git(
        root,
        &["ls-tree", "-r", "HEAD", "--format=%(objectname) %(path)"],
    );
    let mut tracked: Vec<(String, String)> = tracked_output
        .split(['\n', '\r'])
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            let space = line.find(' ')?;
            let objectname = line[..space].to_string();
            let path = line[space + 1..].replace('\\', "/");
            Some((path, objectname))
        })
        .filter(|(path, _)| !excluded(path))
        .collect();
    tracked.sort_by(|(a, _), (b, _)| a.cmp(b));
    for (path, blob) in &tracked {
        hash.update(path.as_bytes());
        hash.update(b"\0");
        hash.update(blob.as_bytes());
        hash.update(b"\0");
    }

    // Dirty overlay: modified + untracked non-excluded files, hashed by
    // content.
    let mut dirty: Vec<String> = if include_dirty {
        let dirty_output = run_git(root, &["ls-files", "-m", "-o", "--exclude-standard"]);
        let mut names: Vec<String> = dirty_output
            .split(['\n', '\r'])
            .filter(|line| !line.is_empty())
            .map(|path| path.replace('\\', "/"))
            .filter(|path| !excluded(path))
            .collect();
        names.sort();
        names
    } else {
        Vec::new()
    };
    for name in &dirty {
        hash.update(b"dirty:");
        hash.update(name.as_bytes());
        hash.update(b"\0");
        match std::fs::read(root.join(name)) {
            Ok(bytes) => hash.update(&bytes),
            Err(_) => hash.update(b"unreadable"),
        }
        hash.update(b"\0");
    }

    let digest = format!("content.sha256:{}", hex::encode(hash.finalize()));
    if dirty.is_empty() {
        digest
    } else {
        format!("{digest}+dirty")
    }
}

/// JS `currentSourceRevision`.
pub fn current_source_revision(root: &Path) -> String {
    source_revision(root, true)
}

/// JS `committedSourceRevision`.
///
/// Qualification receipts are committed artifacts. Seal them to tracked
/// HEAD, never to unrelated working-copy bytes that cannot exist in a clean
/// checkout.
pub fn committed_source_revision(root: &Path) -> String {
    source_revision(root, false)
}
