//! Source-verification pipeline ported from `live-commit-manual-edits.mjs`.
//!
//! Real disk access (`fs.readFileSync`) is pushed behind [`SourceStore`] so
//! this logic can be unit tested with an in-memory fake, per the port rules.
//! Line-level matching (`lineShowsAppliedOp`, `windowShowsAppliedOp`,
//! `verificationTargetPassesLines`, ...) is not re-implemented here — it is
//! reused from `wf_port::w2_017::commit_edits`, which already ports it.

use std::collections::{HashMap, HashSet};

use serde_json::Value;

use crate::wf_port::w2_017::commit_edits::{
    escape_regexp, line_has_object_key, line_matches_manual_edit_locator, line_shows_applied_op,
    op_has_locator, verification_target_passes_lines, Op, VerificationTarget,
};

/// Abstracts `fs.readFileSync(absolute, 'utf-8')` for a project-relative
/// path. Returns `None` on any read failure (missing file, not UTF-8, ...),
/// mirroring the JS `try { ... } catch { return ... }` guards throughout the
/// source file.
pub trait SourceStore {
    /// Returns the file's contents split on `\n`, matching
    /// `content.split('\n')` (no trailing-newline trimming, same as JS).
    fn read_lines(&self, relative_file: &str) -> Option<Vec<String>>;
}

/// Test/fake implementation: an in-memory map of relative path -> content.
#[derive(Debug, Default, Clone)]
pub struct InMemorySourceStore(pub HashMap<String, String>);

impl InMemorySourceStore {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn with_file(
        mut self,
        relative_file: impl Into<String>,
        content: impl Into<String>,
    ) -> Self {
        self.0.insert(relative_file.into(), content.into());
        self
    }
}

impl SourceStore for InMemorySourceStore {
    fn read_lines(&self, relative_file: &str) -> Option<Vec<String>> {
        self.0
            .get(relative_file)
            .map(|c| c.split('\n').map(str::to_string).collect())
    }
}

/// Real-filesystem [`SourceStore`], for production callers (the CLI entry
/// point). Mirrors `fs.readFileSync(path.resolve(cwd, relativeFile),
/// 'utf-8').split('\n')`, returning `None` on any read failure exactly like
/// the JS `try { ... } catch { return ... }` guards this trait abstracts.
#[derive(Debug, Clone)]
pub struct FsSourceStore {
    pub cwd: std::path::PathBuf,
}

impl FsSourceStore {
    pub fn new(cwd: impl Into<std::path::PathBuf>) -> Self {
        Self { cwd: cwd.into() }
    }
}

impl SourceStore for FsSourceStore {
    fn read_lines(&self, relative_file: &str) -> Option<Vec<String>> {
        let absolute = self.cwd.join(relative_file);
        std::fs::read_to_string(absolute)
            .ok()
            .map(|c| c.split('\n').map(str::to_string).collect())
    }
}

/// Port of:
/// ```js
/// function normalizeProjectSourcePath(cwd, file, opts = {}) {
///   if (!file || typeof file !== 'string') return null;
///   const absolute = path.isAbsolute(file) ? file : path.resolve(cwd, file);
///   const relative = path.relative(cwd, absolute);
///   if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) return null;
///   if (opts.requireExists && !fs.existsSync(absolute)) return null;
///   if (isGeneratedFile(absolute, { cwd })) return null;
///   return relative;
/// }
/// ```
///
/// This ports only the path-arithmetic guard (component-wise, not string
/// prefix, so `..foo` is not mistaken for an escape). The `requireExists`
/// and `isGeneratedFile` guards are real-I/O checks a caller composes
/// separately: `std::fs::try_exists` and the already-ported
/// `p8_designer::is_generated::is_generated_file`.
pub fn normalize_project_source_path(cwd: &str, file: Option<&str>) -> Option<String> {
    let file = file.filter(|f| !f.is_empty())?;
    let cwd_path = std::path::Path::new(cwd);
    let file_path = std::path::Path::new(file);
    let absolute = if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        cwd_path.join(file_path)
    };
    let relative = pathdiff(&absolute, cwd_path)?;
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return None;
    }
    if relative
        .components()
        .next()
        .map(|c| c.as_os_str() == "..")
        .unwrap_or(false)
    {
        return None;
    }
    Some(relative.to_string_lossy().replace('\\', "/"))
}

/// Minimal component-wise `path.relative(from, to)`, since the standard
/// library has no direct equivalent. Both paths are treated as already
/// lexically resolved (no symlink following, matching how the JS callers
/// only ever pass `path.resolve`d inputs).
fn pathdiff(to: &std::path::Path, from: &std::path::Path) -> Option<std::path::PathBuf> {
    use std::path::Component;
    let to_comps: Vec<Component> = to.components().collect();
    let from_comps: Vec<Component> = from.components().collect();
    let mut i = 0;
    while i < to_comps.len() && i < from_comps.len() && to_comps[i] == from_comps[i] {
        i += 1;
    }
    let mut out = std::path::PathBuf::new();
    for _ in i..from_comps.len() {
        out.push("..");
    }
    for comp in &to_comps[i..] {
        out.push(comp.as_os_str());
    }
    Some(out)
}

fn candidates_for<'a>(batch: &'a Value, entry_id: &str) -> Vec<&'a Value> {
    batch
        .get("candidates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|c| c.get("entryId").and_then(Value::as_str) == Some(entry_id))
        .collect()
}

fn str_field<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

/// Port of `siblingCandidatesForEntry(batch, op)`.
pub fn sibling_candidates_for_entry<'a>(
    batch: &'a Value,
    entry_id: &str,
    op_ref: &str,
) -> Vec<&'a Value> {
    if entry_id.is_empty() {
        return Vec::new();
    }
    candidates_for(batch, entry_id)
        .into_iter()
        .filter(|c| str_field(c, "ref") != Some(op_ref))
        .collect()
}

/// Port of `objectKeyCandidatesForOp(batch, op)`.
pub fn object_key_candidates_for_op<'a>(
    batch: &'a Value,
    entry_id: &str,
    op_ref: &str,
) -> Vec<&'a Value> {
    candidates_for(batch, entry_id)
        .into_iter()
        .filter(|c| str_field(c, "ref") == Some(op_ref))
        .flat_map(|c| {
            c.get("objectKeyMatches")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .collect()
}

/// Port of `objectKeyMatchStillUsesOriginal(cwd, match, op)`.
pub fn object_key_match_still_uses_original(
    store: &dyn SourceStore,
    m: &Value,
    original_text: &str,
    new_text: &str,
) -> bool {
    let relative = match normalize_project_source_path("", str_field(m, "file")) {
        Some(r) => r,
        None => return false,
    };
    let line_number = m.get("line").and_then(Value::as_i64).unwrap_or(0);
    if line_number < 1 {
        return false;
    }
    let lines = match store.read_lines(&relative) {
        Some(l) => l,
        None => return false,
    };
    // Port of `const start = Math.max(0, lineNumber - 4); const end =
    // Math.min(lines.length, lineNumber + 3);` (both 1-based `lineNumber`
    // indexing directly into the 0-based `lines` array, matching JS).
    let start = (line_number - 4).max(0) as usize;
    let end = (line_number + 3).min(lines.len() as i64).max(0) as usize;
    if start >= end || start >= lines.len() {
        return false;
    }
    let window = &lines[start..end];
    if window.iter().any(|l| line_has_object_key(l, new_text)) {
        return false;
    }
    window.iter().any(|l| line_has_object_key(l, original_text))
}

/// Port of `coupledObjectKeyFailuresForOp(batch, op, cwd)`. Returns one
/// failure `Value` per still-original object-key match.
///
/// Named `..._ref` because [`Op`] (from `w2_017::commit_edits`) does not
/// carry `ref`/`entryId` fields the way the JS `op` object does after the
/// `{ ...rawOp, entryId: entry.id }` spread, so callers pass them in.
pub fn coupled_object_key_failures_for_op_ref(
    store: &dyn SourceStore,
    batch: &Value,
    entry_id: &str,
    op_ref: &str,
    op: &Op,
) -> Vec<Value> {
    let original = op.original_text.as_deref().unwrap_or("");
    let new_text = op.new_text.as_deref().unwrap_or("");
    if original.is_empty() || new_text.is_empty() || original == new_text {
        return Vec::new();
    }
    object_key_candidates_for_op(batch, entry_id, op_ref)
        .into_iter()
        .filter(|m| object_key_match_still_uses_original(store, m, original, new_text))
        .map(|m| {
            let relative = normalize_project_source_path("", str_field(m, "file"))
                .unwrap_or_else(|| str_field(m, "file").unwrap_or("").to_string());
            serde_json::json!({
                "ref": op_ref,
                "reason": "source_verification_failed",
                "detail": "edited_text_source_key_dependency_not_updated",
                "candidates": [{
                    "file": relative,
                    "line": m.get("line").cloned().unwrap_or(Value::Null),
                    "kind": "object_key_match",
                    "reason": "edited text is also a source key; update the coupled key to newText or fail the entry",
                }],
            })
        })
        .collect()
}

/// Port of `sourceHintWindowFailure(cwd, op)`.
pub fn source_hint_window_failure(
    store: &dyn SourceStore,
    op: &Op,
    source_hint_file: Option<&str>,
    source_hint_line: Option<i64>,
) -> Option<Value> {
    let line = source_hint_line.filter(|l| *l != 0)?;
    let file = source_hint_file.filter(|f| !f.is_empty())?;
    let relative = normalize_project_source_path("", Some(file))?;
    let lines = store.read_lines(&relative)?;
    let line = line.max(1) as usize;
    let line_text = lines.get(line - 1).map(String::as_str).unwrap_or("");
    let original_text = op.original_text.as_deref().unwrap_or("");
    if !original_text.is_empty()
        && line_text.contains(original_text)
        && !line_shows_applied_op(line_text, op)
    {
        return Some(serde_json::json!({
            "file": relative,
            "line": line,
            "reason": "source_hint_still_contains_original_text",
        }));
    }
    None
}

/// Port of `locatorTargetsInFile(cwd, relativeFile, op)`.
pub fn locator_targets_in_file(
    store: &dyn SourceStore,
    relative_file: &str,
    op: &Op,
) -> Vec<Value> {
    if !op_has_locator(op) {
        return Vec::new();
    }
    let lines = match store.read_lines(relative_file) {
        Some(l) => l,
        None => return Vec::new(),
    };
    let mut out = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if !line_matches_manual_edit_locator(line, op) {
            continue;
        }
        out.push(serde_json::json!({
            "file": relative_file,
            "line": index + 1,
            "kind": "reported_locator_match",
        }));
        if out.len() >= 20 {
            break;
        }
    }
    out
}

/// A single verification target, as JSON, matching the JS `{ file, line,
/// kind, reported }` shape produced by `verificationTargetsForOp`.
fn push_target(
    out: &mut Vec<Value>,
    seen: &mut HashSet<String>,
    file: Option<&str>,
    line: Option<Value>,
    kind: &str,
    reported: &HashSet<String>,
) {
    let relative = match normalize_project_source_path("", file) {
        Some(r) => r,
        None => return,
    };
    let line_number = match line.as_ref().and_then(Value::as_i64) {
        Some(n) if n >= 1 => n,
        _ => return,
    };
    let key = format!("{relative}:{line_number}:{kind}");
    if !seen.insert(key) {
        return;
    }
    out.push(serde_json::json!({
        "file": relative,
        "line": line_number,
        "kind": kind,
        "reported": reported.contains(&relative),
    }));
}

/// Port of `verificationTargetsForOp(batch, op, reportedFiles, cwd)`.
///
/// `op_json` is the raw op `Value` (needs `sourceHint`), `entry_id`/`op_ref`
/// identify the op for candidate lookup (mirrors the JS `{ ...rawOp,
/// entryId: entry.id }` spread), and `reported_files` mirrors the JS
/// `reportedFiles` argument.
pub fn verification_targets_for_op(
    store: &dyn SourceStore,
    batch: &Value,
    op_json: &Value,
    entry_id: &str,
    op_ref: &str,
    reported_files: &[String],
    op: &Op,
) -> Vec<Value> {
    let reported: HashSet<String> = reported_files.iter().cloned().collect();
    let mut out = Vec::new();
    let mut seen = HashSet::new();

    let candidate = candidates_for(batch, entry_id)
        .into_iter()
        .find(|c| str_field(c, "ref") == Some(op_ref));

    if let Some(hint) = op_json.get("sourceHint") {
        push_target(
            &mut out,
            &mut seen,
            str_field(hint, "file"),
            hint.get("line").cloned(),
            "source_hint",
            &reported,
        );
    }
    if let Some(candidate) = candidate {
        if let Some(hint) = candidate.get("sourceHint") {
            let file = str_field(hint, "relativeFile").or_else(|| str_field(hint, "file"));
            push_target(
                &mut out,
                &mut seen,
                file,
                hint.get("line").cloned(),
                "candidate_source_hint",
                &reported,
            );
        }
        for (arr_key, kind) in [
            ("textMatches", "text_match"),
            ("objectKeyMatches", "object_key_match"),
            ("locatorMatches", "locator_match"),
            ("contextTextMatches", "context_text_match"),
        ] {
            if let Some(items) = candidate.get(arr_key).and_then(Value::as_array) {
                for item in items {
                    push_target(
                        &mut out,
                        &mut seen,
                        str_field(item, "file"),
                        item.get("line").cloned(),
                        kind,
                        &reported,
                    );
                }
            }
        }
    }

    for sibling in sibling_candidates_for_entry(batch, entry_id, op_ref) {
        if let Some(hint) = sibling.get("sourceHint") {
            let file = str_field(hint, "relativeFile").or_else(|| str_field(hint, "file"));
            push_target(
                &mut out,
                &mut seen,
                file,
                hint.get("line").cloned(),
                "entry_source_hint",
                &reported,
            );
        }
        for (arr_key, kind) in [
            ("textMatches", "entry_text_match"),
            ("objectKeyMatches", "entry_object_key_match"),
            ("contextTextMatches", "entry_context_text_match"),
        ] {
            if let Some(items) = sibling.get(arr_key).and_then(Value::as_array) {
                for item in items {
                    push_target(
                        &mut out,
                        &mut seen,
                        str_field(item, "file"),
                        item.get("line").cloned(),
                        kind,
                        &reported,
                    );
                }
            }
        }
    }

    for relative_file in reported_files {
        for target in locator_targets_in_file(store, relative_file, op) {
            let key = format!(
                "{}:{}:{}",
                target["file"].as_str().unwrap_or(""),
                target["line"],
                target["kind"].as_str().unwrap_or("")
            );
            if seen.insert(key) {
                out.push(target);
            }
        }
    }

    out
}

/// Port of `verificationTargetPasses(cwd, target, op)`.
pub fn verification_target_passes(store: &dyn SourceStore, target: &Value, op: &Op) -> bool {
    let file = match target.get("file").and_then(Value::as_str) {
        Some(f) => f,
        None => return false,
    };
    let lines = match store.read_lines(file) {
        Some(l) => l,
        None => return false,
    };
    let line_refs: Vec<&str> = lines.iter().map(String::as_str).collect();
    let vt = VerificationTarget {
        line: target.get("line").and_then(Value::as_u64).unwrap_or(0) as usize,
        kind: target
            .get("kind")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        reported: target
            .get("reported")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    };
    verification_target_passes_lines(&line_refs, &vt, op)
}

/// Port of `verifyAppliedEntry({ batch, entry, reportedFiles, cwd })` for a
/// single op (callers loop `entry.ops`). `op_json` supplies `sourceHint`;
/// `op` is the already-typed [`Op`] for the same operation.
pub fn verify_applied_entry_op(
    store: &dyn SourceStore,
    batch: &Value,
    entry_id: &str,
    op_ref: &str,
    op_json: &Value,
    op: &Op,
    reported_files: &[String],
) -> Vec<Value> {
    if op.new_text.is_none() {
        return vec![serde_json::json!({
            "ref": op_ref,
            "reason": "source_verification_failed",
            "detail": "missing_newText",
        })];
    }
    let targets =
        verification_targets_for_op(store, batch, op_json, entry_id, op_ref, reported_files, op);
    let coupled = coupled_object_key_failures_for_op_ref(store, batch, entry_id, op_ref, op);
    if coupled.is_empty()
        && targets
            .iter()
            .any(|t| verification_target_passes(store, t, op))
    {
        return Vec::new();
    }
    if !coupled.is_empty() {
        return coupled;
    }
    if let Some(hint) = op_json.get("sourceHint") {
        if let Some(failure) = source_hint_window_failure(
            store,
            op,
            str_field(hint, "file"),
            hint.get("line").and_then(Value::as_i64),
        ) {
            return vec![serde_json::json!({
                "ref": op_ref,
                "reason": "source_verification_failed",
                "detail": failure["reason"],
            })];
        }
    }
    let new_text = op.new_text.as_deref().unwrap_or("");
    let detail = if new_text.is_empty() {
        "originalText_still_present_in_plausible_source_location"
    } else {
        "newText_not_found_in_plausible_source_location"
    };
    vec![serde_json::json!({
        "ref": op_ref,
        "reason": "source_verification_failed",
        "detail": detail,
        "candidates": targets,
    })]
}

/// Port of `verifyAppliedEntry` looped over an entry's `ops`.
pub fn verify_applied_entry(
    store: &dyn SourceStore,
    batch: &Value,
    entry: &Value,
    reported_files: &[String],
) -> Vec<Value> {
    let entry_id = entry.get("id").and_then(Value::as_str).unwrap_or("");
    let mut failures = Vec::new();
    for raw_op in entry
        .get("ops")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let op_ref = str_field(raw_op, "ref").unwrap_or("");
        let op = op_from_json(raw_op);
        failures.extend(verify_applied_entry_op(
            store,
            batch,
            entry_id,
            op_ref,
            raw_op,
            &op,
            reported_files,
        ));
    }
    failures
}

fn op_from_json(v: &Value) -> Op {
    Op {
        original_text: v
            .get("originalText")
            .and_then(Value::as_str)
            .map(String::from),
        new_text: v
            .get("newText")
            .and_then(Value::as_str)
            .map(String::from)
            .or_else(|| {
                if v.get("deleted").and_then(Value::as_bool) == Some(true) {
                    Some(String::new())
                } else {
                    None
                }
            }),
        deleted: v.get("deleted").and_then(Value::as_bool).unwrap_or(false),
        tag: v.get("tag").and_then(Value::as_str).map(String::from),
        element_id: v.get("elementId").and_then(Value::as_str).map(String::from),
        classes: v
            .get("classes")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Port of `verificationFailuresForEntries(batch, entries, reason, extra)`.
pub fn verification_failures_for_entries(entries: &[Value], reason: &str) -> Vec<Value> {
    entries
        .iter()
        .map(|entry| {
            serde_json::json!({
                "id": entry.get("id").cloned().unwrap_or(Value::Null),
                "reason": reason,
            })
        })
        .collect()
}

/// Port of `verifyEntriesAfterRepair({ batch, appliedEntryIds, files, cwd })`.
/// Returns `(verified_ids, failed)`.
pub fn verify_entries_after_repair(
    store: &dyn SourceStore,
    batch: &Value,
    applied_entry_ids: &[String],
    reported_files: &[String],
) -> (Vec<String>, Vec<Value>) {
    let mut verified_ids = Vec::new();
    let mut failed = Vec::new();
    let applied: HashSet<&str> = applied_entry_ids.iter().map(String::as_str).collect();
    for entry in batch
        .get("entries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = entry.get("id").and_then(Value::as_str).unwrap_or("");
        if !applied.contains(id) {
            continue;
        }
        let failures = verify_applied_entry(store, batch, entry, reported_files);
        if failures.is_empty() {
            verified_ids.push(id.to_string());
        } else {
            failed.push(serde_json::json!({
                "id": id,
                "reason": "source_verification_failed",
                "failures": failures,
            }));
        }
    }
    (verified_ids, failed)
}

/// Port of `escapeRegExp` re-export for callers that only need this module.
pub fn escape(value: &str) -> String {
    escape_regexp(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_project_source_path_rejects_escape() {
        assert_eq!(
            normalize_project_source_path("/proj", Some("../etc/passwd")),
            None
        );
        assert_eq!(normalize_project_source_path("/proj", Some("")), None);
    }

    #[test]
    fn normalize_project_source_path_accepts_relative() {
        assert_eq!(
            normalize_project_source_path("/proj", Some("/proj/src/app.js")),
            Some("src/app.js".to_string())
        );
        assert_eq!(
            normalize_project_source_path("/proj", Some("src/app.js")),
            Some("src/app.js".to_string())
        );
    }

    #[test]
    fn object_key_match_still_uses_original_detects_stale_key() {
        let store =
            InMemorySourceStore::new().with_file("src/data.js", "before\n  label: 'x',\nafter");
        let m = serde_json::json!({"file": "src/data.js", "line": 2});
        assert!(object_key_match_still_uses_original(
            &store, &m, "label", "title"
        ));
    }

    #[test]
    fn object_key_match_still_uses_original_false_once_updated() {
        let store =
            InMemorySourceStore::new().with_file("src/data.js", "before\n  title: 'x',\nafter");
        let m = serde_json::json!({"file": "src/data.js", "line": 2});
        assert!(!object_key_match_still_uses_original(
            &store, &m, "label", "title"
        ));
    }

    #[test]
    fn locator_targets_in_file_matches_tag_and_id() {
        let store = InMemorySourceStore::new().with_file(
            "index.html",
            "<div id=\"hero\">Old</div>\n<span>nope</span>",
        );
        let op = Op {
            element_id: Some("hero".into()),
            tag: Some("div".into()),
            ..Default::default()
        };
        let targets = locator_targets_in_file(&store, "index.html", &op);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0]["line"], 1);
    }

    #[test]
    fn verify_applied_entry_passes_when_new_text_present() {
        let store =
            InMemorySourceStore::new().with_file("src/hero.js", "const t = 'New Headline';");
        let batch = serde_json::json!({"entries": [], "candidates": []});
        let entry = serde_json::json!({
            "id": "e1",
            "ops": [{
                "ref": "r1",
                "originalText": "Old Headline",
                "newText": "New Headline",
                "sourceHint": {"file": "src/hero.js", "line": 1},
            }],
        });
        let failures = verify_applied_entry(&store, &batch, &entry, &["src/hero.js".to_string()]);
        assert!(failures.is_empty(), "{failures:?}");
    }

    #[test]
    fn verify_applied_entry_fails_when_original_still_present() {
        let store =
            InMemorySourceStore::new().with_file("src/hero.js", "const t = 'Old Headline';");
        let batch = serde_json::json!({"entries": [], "candidates": []});
        let entry = serde_json::json!({
            "id": "e1",
            "ops": [{
                "ref": "r1",
                "originalText": "Old Headline",
                "newText": "New Headline",
                "sourceHint": {"file": "src/hero.js", "line": 1},
            }],
        });
        let failures = verify_applied_entry(&store, &batch, &entry, &["src/hero.js".to_string()]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0]["reason"], "source_verification_failed");
    }

    #[test]
    fn verify_applied_entry_fails_on_missing_new_text() {
        let store = InMemorySourceStore::new();
        let batch = serde_json::json!({"entries": [], "candidates": []});
        let entry = serde_json::json!({
            "id": "e1",
            "ops": [{"ref": "r1"}],
        });
        let failures = verify_applied_entry(&store, &batch, &entry, &[]);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0]["detail"], "missing_newText");
    }

    #[test]
    fn verify_entries_after_repair_splits_verified_and_failed() {
        let store = InMemorySourceStore::new()
            .with_file("src/a.js", "const t = 'New A';")
            .with_file("src/b.js", "const t = 'Old B';");
        let batch = serde_json::json!({
            "candidates": [],
            "entries": [
                {"id": "e1", "ops": [{"ref": "r1", "originalText": "Old A", "newText": "New A", "sourceHint": {"file": "src/a.js", "line": 1}}]},
                {"id": "e2", "ops": [{"ref": "r2", "originalText": "Old B", "newText": "New B", "sourceHint": {"file": "src/b.js", "line": 1}}]},
            ],
        });
        let (verified, failed) = verify_entries_after_repair(
            &store,
            &batch,
            &["e1".to_string(), "e2".to_string()],
            &["src/a.js".to_string(), "src/b.js".to_string()],
        );
        assert_eq!(verified, vec!["e1".to_string()]);
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0]["id"], "e2");
    }

    #[test]
    fn coupled_object_key_failures_flags_unupdated_key() {
        let store = InMemorySourceStore::new().with_file("src/data.js", "  label: 'value',\n");
        let batch = serde_json::json!({
            "candidates": [{
                "entryId": "e1",
                "ref": "r1",
                "objectKeyMatches": [{"file": "src/data.js", "line": 1}],
            }],
        });
        let op = Op {
            original_text: Some("label".into()),
            new_text: Some("title".into()),
            ..Default::default()
        };
        let failures = coupled_object_key_failures_for_op_ref(&store, &batch, "e1", "r1", &op);
        assert_eq!(failures.len(), 1);
        assert_eq!(
            failures[0]["detail"],
            "edited_text_source_key_dependency_not_updated"
        );
    }

    #[test]
    fn verification_failures_for_entries_wraps_reason() {
        let entries = vec![
            serde_json::json!({"id": "e1"}),
            serde_json::json!({"id": "e2"}),
        ];
        let failures = verification_failures_for_entries(&entries, "rollback_failed");
        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0]["reason"], "rollback_failed");
    }
}
