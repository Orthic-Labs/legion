//! Directory-walk rollback/snapshot machinery ported from
//! `live-commit-manual-edits.mjs` (packet R18R26, closing the gap
//! documented in `super::mod` before this module existed).
//!
//! Ports `normalizeProjectSourcePath`'s real-fs composition (path
//! arithmetic + `isGeneratedFile`), `normalizeRelativeFile`,
//! `normalizeRollbackPath`, `snapshotRollbackFiles`, `collectRollbackFiles`,
//! `scanRollbackDir`, `changedFilesSinceSnapshot`, `rollbackChangedFiles`,
//! `collectApplyOwnedFiles` and `unreportedChangedFiles`. These all walk the
//! real project directory tree (`fs.readdirSync`/`fs.realpathSync`), so
//! unlike `super::verify` (which reads only named files behind
//! `SourceStore`) they operate directly on `std::fs` — tests use a real
//! temp directory, per the port brief's guidance for directory-walk code.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::p8_designer::is_generated::{is_generated_file, IsGeneratedOptions};
use crate::wf_port::r18::verify::normalize_project_source_path;
use crate::wf_port::w2_017::commit_edits::unique_strings;

/// Mirrors `ROLLBACK_EXTENSIONS`.
pub const ROLLBACK_EXTENSIONS: &[&str] = &[
    ".astro", ".cjs", ".css", ".htm", ".html", ".js", ".json", ".jsx", ".md", ".mdx", ".mjs",
    ".scss", ".svelte", ".svg", ".ts", ".tsx", ".txt", ".vue", ".yaml", ".yml",
];

/// Mirrors `ROLLBACK_SKIP_DIRS`.
pub const ROLLBACK_SKIP_DIRS: &[&str] = &[
    ".astro",
    ".git",
    ".impeccable",
    ".next",
    ".nuxt",
    ".svelte-kit",
    "build",
    "coverage",
    "dist",
    "node_modules",
];

/// Port of `normalizeProjectSourcePath(cwd, file, opts)` with real
/// filesystem checks composed in (path arithmetic reused from
/// [`crate::wf_port::r18::verify::normalize_project_source_path`]).
pub fn normalize_project_source_path_fs(
    cwd: &Path,
    file: Option<&str>,
    require_exists: bool,
) -> Option<String> {
    let cwd_str = cwd.to_string_lossy();
    let relative = normalize_project_source_path(&cwd_str, file)?;
    let absolute = cwd.join(&relative);
    if require_exists && !absolute.exists() {
        return None;
    }
    let opts = IsGeneratedOptions {
        cwd: Some(cwd.to_path_buf()),
    };
    if is_generated_file(&absolute.to_string_lossy(), &opts) {
        return None;
    }
    Some(relative)
}

/// Port of `normalizeRelativeFile(cwd, file)`.
pub fn normalize_relative_file(cwd: &Path, file: Option<&str>) -> Option<String> {
    normalize_project_source_path_fs(cwd, file, true)
}

/// Port of `normalizeRollbackPath(cwd, file)`.
pub fn normalize_rollback_path(cwd: &Path, file: Option<&str>) -> Option<String> {
    normalize_project_source_path_fs(cwd, file, false)
}

/// Port of `scanRollbackDir(dir, cwd, out, seenDirs, seenFiles, depth)`.
fn scan_rollback_dir(
    dir: &Path,
    cwd: &Path,
    out: &mut Vec<String>,
    seen_dirs: &mut HashSet<PathBuf>,
    seen_files: &mut HashSet<PathBuf>,
    depth: u32,
) {
    if depth > 10 {
        return;
    }
    let real_dir = match std::fs::canonicalize(dir) {
        Ok(p) => strip_verbatim_prefix(p),
        Err(_) => return,
    };
    if !seen_dirs.insert(real_dir) {
        return;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let name = entry.file_name();
        let name_str = name.to_string_lossy().to_string();
        if file_type.is_dir() {
            if ROLLBACK_SKIP_DIRS.contains(&name_str.as_str()) {
                continue;
            }
            scan_rollback_dir(&entry.path(), cwd, out, seen_dirs, seen_files, depth + 1);
            continue;
        }
        if !file_type.is_file() {
            continue;
        }
        let ext = entry
            .path()
            .extension()
            .map(|e| format!(".{}", e.to_string_lossy().to_lowercase()))
            .unwrap_or_default();
        if !ROLLBACK_EXTENSIONS.contains(&ext.as_str()) {
            continue;
        }
        let absolute = entry.path();
        let opts = IsGeneratedOptions {
            cwd: Some(cwd.to_path_buf()),
        };
        if is_generated_file(&absolute.to_string_lossy(), &opts) {
            continue;
        }
        let real_file = match std::fs::canonicalize(&absolute) {
            Ok(p) => strip_verbatim_prefix(p),
            Err(_) => continue,
        };
        if !seen_files.insert(real_file) {
            continue;
        }
        let relative = match pathdiff_relative(&absolute, cwd) {
            Some(r) if !r.is_empty() && !r.starts_with("..") => r,
            _ => continue,
        };
        out.push(relative);
    }
}

/// Strips the Windows `\\?\` verbatim prefix that `canonicalize` adds, per
/// the port brief's cross-platform pitfall note.
fn strip_verbatim_prefix(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        p
    }
}

fn pathdiff_relative(to: &Path, from: &Path) -> Option<String> {
    use std::path::Component;
    let to_comps: Vec<Component> = to.components().collect();
    let from_comps: Vec<Component> = from.components().collect();
    let mut i = 0;
    while i < to_comps.len() && i < from_comps.len() && to_comps[i] == from_comps[i] {
        i += 1;
    }
    let mut out = PathBuf::new();
    for _ in i..from_comps.len() {
        out.push("..");
    }
    for comp in &to_comps[i..] {
        out.push(comp.as_os_str());
    }
    Some(out.to_string_lossy().replace('\\', "/"))
}

/// Port of `collectRollbackFiles(cwd)`.
pub fn collect_rollback_files(cwd: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen_dirs = HashSet::new();
    let mut seen_files = HashSet::new();
    scan_rollback_dir(cwd, cwd, &mut out, &mut seen_dirs, &mut seen_files, 0);
    out
}

/// One snapshotted file's prior state, mirroring the JS
/// `{ existed, content }` shape.
#[derive(Debug, Clone)]
pub enum SnapshotEntry {
    Existed { content: String },
    Missing,
}

/// Port of the `Map` returned by `snapshotRollbackFiles`.
pub type RollbackSnapshot = HashMap<String, SnapshotEntry>;

/// Port of `snapshotRollbackFiles(cwd, files)`.
pub fn snapshot_rollback_files(cwd: &Path, files: Option<&[String]>) -> RollbackSnapshot {
    let mut snapshot = RollbackSnapshot::new();
    let rollback_files: Vec<String> = match files {
        Some(files) if !files.is_empty() => {
            let values: Vec<Value> = files.iter().map(|f| Value::String(f.clone())).collect();
            unique_strings(&values)
                .into_iter()
                .filter_map(|f| normalize_rollback_path(cwd, Some(&f)))
                .collect()
        }
        _ => collect_rollback_files(cwd),
    };
    for relative_file in rollback_files {
        let absolute = cwd.join(&relative_file);
        match std::fs::read_to_string(&absolute) {
            Ok(content) => {
                snapshot.insert(relative_file, SnapshotEntry::Existed { content });
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                snapshot.insert(relative_file, SnapshotEntry::Missing);
            }
            Err(_) => {
                // Other read failures are not safe to roll back; matches the
                // JS `catch` block that only handles `ENOENT`.
            }
        }
    }
    snapshot
}

/// One changed-file record, mirroring `{ file, kind }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedFile {
    pub file: String,
    pub kind: &'static str,
}

/// Port of `changedFilesSinceSnapshot(cwd, snapshot, scopeFiles)`.
pub fn changed_files_since_snapshot(
    cwd: &Path,
    snapshot: &RollbackSnapshot,
    scope_files: Option<&[String]>,
) -> Vec<ChangedFile> {
    let mut changed: Vec<(String, ChangedFile)> = Vec::new();
    let mut changed_index: HashMap<String, usize> = HashMap::new();
    let mut push = |file: String, kind: &'static str, changed: &mut Vec<(String, ChangedFile)>, idx: &mut HashMap<String, usize>| {
        let record = ChangedFile { file: file.clone(), kind };
        if let Some(&i) = idx.get(&file) {
            changed[i] = (file, record);
        } else {
            idx.insert(file.clone(), changed.len());
            changed.push((file, record));
        }
    };

    let scoped_files: Option<Vec<String>> = scope_files.filter(|s| !s.is_empty()).map(|files| {
        files
            .iter()
            .filter_map(|f| normalize_rollback_path(cwd, Some(f)))
            .collect()
    });
    let current_files: HashSet<String> = match &scoped_files {
        Some(files) => files.iter().cloned().collect(),
        None => collect_rollback_files(cwd).into_iter().collect(),
    };

    for (relative_file, before) in snapshot.iter() {
        if scoped_files.is_some() && !current_files.contains(relative_file) {
            continue;
        }
        let absolute = cwd.join(relative_file);
        match before {
            SnapshotEntry::Missing => {
                if absolute.exists() {
                    push(relative_file.clone(), "added", &mut changed, &mut changed_index);
                }
                continue;
            }
            SnapshotEntry::Existed { content } => {
                if !absolute.exists() {
                    push(relative_file.clone(), "deleted", &mut changed, &mut changed_index);
                    continue;
                }
                match std::fs::read_to_string(&absolute) {
                    Ok(current) => {
                        if &current != content {
                            push(relative_file.clone(), "modified", &mut changed, &mut changed_index);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
    }
    for relative_file in current_files.iter() {
        if !snapshot.contains_key(relative_file) {
            push(relative_file.clone(), "unknown", &mut changed, &mut changed_index);
        }
    }
    changed.into_iter().map(|(_, v)| v).collect()
}

/// Result of [`rollback_changed_files`], mirroring
/// `{ rolledBackFiles, rollbackFailures }`.
#[derive(Debug, Clone, Default)]
pub struct RollbackResult {
    pub rolled_back_files: Vec<String>,
    pub rollback_failures: Vec<Value>,
}

/// Port of `rollbackChangedFiles(cwd, snapshot, extraFiles, scopeFiles)`.
pub fn rollback_changed_files(
    cwd: &Path,
    snapshot: &RollbackSnapshot,
    extra_files: &[String],
    scope_files: &[String],
) -> RollbackResult {
    let scope: HashSet<String> = scope_files
        .iter()
        .chain(extra_files.iter())
        .filter_map(|f| normalize_rollback_path(cwd, Some(f)))
        .collect();
    let scope_vec: Vec<String> = scope.iter().cloned().collect();
    let changed = changed_files_since_snapshot(cwd, snapshot, Some(&scope_vec));
    let mut by_file: HashMap<String, ChangedFile> = changed
        .into_iter()
        .map(|item| (item.file.clone(), item))
        .collect();
    for file in extra_files {
        if let Some(relative) = normalize_rollback_path(cwd, Some(file)) {
            by_file.entry(relative.clone()).or_insert(ChangedFile {
                file: relative.clone(),
                kind: if snapshot.contains_key(&relative) {
                    "reported"
                } else {
                    "unknown"
                },
            });
        }
    }

    let mut rolled_back_files = Vec::new();
    let mut rollback_failures = Vec::new();
    for item in by_file.values() {
        if !scope.contains(&item.file) {
            continue;
        }
        let absolute = cwd.join(&item.file);
        let before = snapshot.get(&item.file);
        let restore = match before {
            Some(SnapshotEntry::Existed { content }) => {
                let parent_ok = absolute
                    .parent()
                    .map(|p| std::fs::create_dir_all(p).is_ok())
                    .unwrap_or(true);
                if !parent_ok {
                    Err("mkdir_failed".to_string())
                } else {
                    std::fs::write(&absolute, content).map_err(|e| e.to_string())
                }
            }
            Some(SnapshotEntry::Missing) if item.kind == "added" && absolute.exists() => {
                std::fs::remove_file(&absolute).map_err(|e| e.to_string())
            }
            None => {
                rollback_failures.push(serde_json::json!({
                    "file": item.file,
                    "reason": "no_snapshot",
                }));
                continue;
            }
            _ => {
                rollback_failures.push(serde_json::json!({
                    "file": item.file,
                    "reason": "no_snapshot",
                }));
                continue;
            }
        };
        match restore {
            Ok(()) => rolled_back_files.push(item.file.clone()),
            Err(message) => rollback_failures.push(serde_json::json!({
                "file": item.file,
                "reason": "restore_failed",
                "message": message,
            })),
        }
    }
    RollbackResult {
        rolled_back_files,
        rollback_failures,
    }
}

/// Port of `collectApplyOwnedFiles(batch, cwd, extraFiles)`.
pub fn collect_apply_owned_files(batch: &Value, cwd: &Path, extra_files: &[String]) -> Vec<String> {
    let mut files: Vec<Value> = Vec::new();
    if let Some(entries) = batch.get("entries").and_then(Value::as_array) {
        for entry in entries {
            if let Some(ops) = entry.get("ops").and_then(Value::as_array) {
                for op in ops {
                    if let Some(f) = op.pointer("/sourceHint/file") {
                        files.push(f.clone());
                    }
                }
            }
        }
    }
    if let Some(candidates) = batch.get("candidates").and_then(Value::as_array) {
        for candidate in candidates {
            if let Some(f) = candidate.pointer("/sourceHint/relativeFile") {
                files.push(f.clone());
            }
            if let Some(f) = candidate.pointer("/sourceHint/file") {
                files.push(f.clone());
            }
            for key in [
                "textMatches",
                "objectKeyMatches",
                "locatorMatches",
                "contextTextMatches",
            ] {
                if let Some(items) = candidate.get(key).and_then(Value::as_array) {
                    for item in items {
                        if let Some(f) = item.get("file") {
                            files.push(f.clone());
                        }
                    }
                }
            }
        }
    }
    for f in extra_files {
        files.push(Value::String(f.clone()));
    }
    unique_strings(&files)
        .into_iter()
        .filter_map(|f| normalize_rollback_path(cwd, Some(&f)))
        .collect()
}

/// Port of `unreportedChangedFiles(cwd, snapshot, reportedFiles, scopeFiles)`.
pub fn unreported_changed_files(
    cwd: &Path,
    snapshot: &RollbackSnapshot,
    reported_files: &[String],
    scope_files: &[String],
) -> Vec<String> {
    let reported: HashSet<String> = reported_files
        .iter()
        .filter_map(|f| normalize_rollback_path(cwd, Some(f)))
        .collect();
    let scope: Vec<String> = scope_files
        .iter()
        .filter_map(|f| normalize_rollback_path(cwd, Some(f)))
        .collect();
    let scope_set: HashSet<String> = scope.iter().cloned().collect();
    changed_files_since_snapshot(cwd, snapshot, Some(&scope))
        .into_iter()
        .map(|item| item.file)
        .filter(|file| scope_set.contains(file))
        .filter(|file| !reported.contains(file))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "legion-r18-rollback-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn collect_rollback_files_skips_node_modules_and_extension_filters() {
        let dir = temp_dir();
        std::fs::write(dir.join("a.ts"), "export const a = 1;").unwrap();
        std::fs::write(dir.join("readme.bin"), "skip").unwrap();
        std::fs::create_dir_all(dir.join("node_modules")).unwrap();
        std::fs::write(dir.join("node_modules").join("x.js"), "skip").unwrap();
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src").join("b.tsx"), "export const b = 1;").unwrap();

        let mut files = collect_rollback_files(&dir);
        files.sort();
        assert_eq!(files, vec!["a.ts".to_string(), "src/b.tsx".to_string()]);
    }

    #[test]
    fn snapshot_and_rollback_restores_modified_file() {
        let dir = temp_dir();
        std::fs::write(dir.join("a.ts"), "original").unwrap();
        let snapshot = snapshot_rollback_files(&dir, None);
        std::fs::write(dir.join("a.ts"), "changed").unwrap();
        let scope = vec!["a.ts".to_string()];
        let result = rollback_changed_files(&dir, &snapshot, &[], &scope);
        assert_eq!(result.rolled_back_files, vec!["a.ts".to_string()]);
        assert!(result.rollback_failures.is_empty());
        assert_eq!(std::fs::read_to_string(dir.join("a.ts")).unwrap(), "original");
    }

    #[test]
    fn rollback_removes_newly_added_file() {
        let dir = temp_dir();
        let snapshot = snapshot_rollback_files(&dir, Some(&["a.ts".to_string()]));
        std::fs::write(dir.join("a.ts"), "added").unwrap();
        let scope = vec!["a.ts".to_string()];
        let result = rollback_changed_files(&dir, &snapshot, &[], &scope);
        assert_eq!(result.rolled_back_files, vec!["a.ts".to_string()]);
        assert!(!dir.join("a.ts").exists());
    }

    #[test]
    fn changed_files_since_snapshot_reports_unknown_for_unsnapshotted_current_file() {
        let dir = temp_dir();
        std::fs::write(dir.join("a.ts"), "x").unwrap();
        let snapshot: RollbackSnapshot = RollbackSnapshot::new();
        let scope = vec!["a.ts".to_string()];
        let changed = changed_files_since_snapshot(&dir, &snapshot, Some(&scope));
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].kind, "unknown");
    }

    #[test]
    fn unreported_changed_files_filters_reported() {
        let dir = temp_dir();
        std::fs::write(dir.join("a.ts"), "before").unwrap();
        std::fs::write(dir.join("b.ts"), "before").unwrap();
        let snapshot = snapshot_rollback_files(&dir, Some(&["a.ts".to_string(), "b.ts".to_string()]));
        std::fs::write(dir.join("a.ts"), "after").unwrap();
        std::fs::write(dir.join("b.ts"), "after").unwrap();
        let scope = vec!["a.ts".to_string(), "b.ts".to_string()];
        let unreported = unreported_changed_files(&dir, &snapshot, &["a.ts".to_string()], &scope);
        assert_eq!(unreported, vec!["b.ts".to_string()]);
    }
}
