//! Pure logic ported from `live-commit-manual-edits.mjs`.
//!
//! Only the functions that do not touch the filesystem, `process.env`, or
//! sibling modules outside this chunk are ported here (`argVal`, `countOps`,
//! `summarizeAppliedEntries`, `normalizeFailedEntries`, `mergeFailedEntries`,
//! `candidatesForEntry`, `uniqueStrings`, `allEntryIds`, `mergeUniqueStrings`,
//! `repairAttemptLimit`, `escapeRegExp`, `normalizeVerificationText`,
//! `lineShowsAppliedOp`, `opHasLocator`, `lineMatchesManualEditLocator`,
//! `lineHasObjectKey`, `windowShowsAppliedOp`, `verificationTargetPassesLines`,
//! `summarizeRepairFailures`, `buildRepairBatch`).
//!
//! The CLI entry point `commitManualEdits` and everything it calls that
//! touches disk (`normalizeProjectSourcePath`/`normalizeRelativeFile`,
//! `sourceHintWindowFailure`, `objectKeyMatchStillUsesOriginal`,
//! `locatorTargetsInFile`, `verificationTargetPasses`,
//! `snapshotRollbackFiles`/`collectRollbackFiles`/`scanRollbackDir`,
//! `changedFilesSinceSnapshot`, `rollbackChangedFiles`,
//! `repairPostApplyValidation`) is not ported: it depends on
//! `live-manual-edit-evidence.mjs`, `live/manual-edits-buffer.mjs`,
//! `lib/is-generated.mjs` and `live-copy-edit-agent.mjs`, none of which are
//! files this chunk owns.

use regex::{escape as regex_escape, Regex};
use serde_json::{Map, Value};

/// Port of:
/// ```js
/// function argVal(args, name) {
///   const prefix = name + '=';
///   for (const arg of args) {
///     if (arg === name) return true;
///     if (arg.startsWith(prefix)) return arg.slice(prefix.length);
///   }
///   return null;
/// }
/// ```
#[derive(Debug, Clone, PartialEq)]
pub enum ArgVal {
    Bool(bool),
    Str(String),
    None,
}

pub fn arg_val(args: &[String], name: &str) -> ArgVal {
    let prefix = format!("{name}=");
    for arg in args {
        if arg == name {
            return ArgVal::Bool(true);
        }
        if let Some(rest) = arg.strip_prefix(&prefix) {
            return ArgVal::Str(rest.to_string());
        }
    }
    ArgVal::None
}

/// Port of:
/// ```js
/// function countOps(entries) {
///   let count = 0;
///   for (const entry of entries || []) count += Array.isArray(entry.ops) ? entry.ops.length : 0;
///   return count;
/// }
/// ```
pub fn count_ops(entries: &[Value]) -> usize {
    entries
        .iter()
        .map(|entry| {
            entry
                .get("ops")
                .and_then(Value::as_array)
                .map(|ops| ops.len())
                .unwrap_or(0)
        })
        .sum()
}

/// Port of `summarizeAppliedEntries(entries, appliedEntryIds)`.
pub fn summarize_applied_entries(entries: &[Value], applied_entry_ids: &[String]) -> Vec<Value> {
    let ids: std::collections::HashSet<&str> =
        applied_entry_ids.iter().map(String::as_str).collect();
    let mut out = Vec::new();
    for entry in entries {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        if !ids.contains(id) {
            continue;
        }
        let ops = entry
            .get("ops")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for op in ops {
            out.push(serde_json::json!({
                "id": id,
                "ref": op.get("ref").cloned().unwrap_or(Value::Null),
                "originalText": op.get("originalText").cloned().unwrap_or(Value::Null),
                "newText": op.get("newText").cloned().unwrap_or(Value::Null),
            }));
        }
    }
    out
}

/// Port of `uniqueStrings(values)`: keeps first-seen order, drops
/// non-strings and blank/whitespace-only strings.
pub fn unique_strings(values: &[Value]) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for v in values {
        if let Some(s) = v.as_str() {
            if s.trim().is_empty() {
                continue;
            }
            if seen.insert(s.to_string()) {
                out.push(s.to_string());
            }
        }
    }
    out
}

/// Port of `mergeUniqueStrings(...groups)`.
pub fn merge_unique_strings(groups: &[&[Value]]) -> Vec<String> {
    let flat: Vec<Value> = groups.iter().flat_map(|g| g.iter().cloned()).collect();
    unique_strings(&flat)
}

/// Port of `allEntryIds(batch)`.
pub fn all_entry_ids(batch: &Value) -> Vec<String> {
    batch
        .get("entries")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|e| e.get("id").and_then(Value::as_str))
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Port of `candidatesForEntry(batch, entryId)`: flattens
/// `sourceHint`/`textMatches`/`objectKeyMatches`/`locatorMatches`/
/// `contextTextMatches` across candidates for the entry, capped at 12.
pub fn candidates_for_entry(batch: &Value, entry_id: &str) -> Vec<Value> {
    let mut out = Vec::new();
    let Some(candidates) = batch.get("candidates").and_then(Value::as_array) else {
        return out;
    };
    for candidate in candidates {
        if candidate.get("entryId").and_then(Value::as_str) != Some(entry_id) {
            continue;
        }
        if let Some(hint) = candidate.get("sourceHint") {
            if !hint.is_null() {
                out.push(hint.clone());
            }
        }
        for key in ["textMatches", "objectKeyMatches", "locatorMatches", "contextTextMatches"] {
            if let Some(arr) = candidate.get(key).and_then(Value::as_array) {
                out.extend(arr.iter().cloned());
            }
        }
    }
    out.truncate(12);
    out
}

/// Port of `normalizeFailedEntries(batch, result, fallbackReason)`.
pub fn normalize_failed_entries(batch: &Value, result: &Value, fallback_reason: &str) -> Vec<Value> {
    let mut failed_by_entry_id: std::collections::HashMap<String, Value> =
        std::collections::HashMap::new();
    if let Some(failed) = result.get("failed").and_then(Value::as_array) {
        for item in failed {
            let entry_id = item
                .get("entryId")
                .and_then(Value::as_str)
                .or_else(|| item.get("id").and_then(Value::as_str));
            if let Some(entry_id) = entry_id {
                failed_by_entry_id.insert(entry_id.to_string(), item.clone());
            }
        }
    }

    let mut out = Vec::new();
    let entries = batch
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for entry in entries {
        let Some(id) = entry.get("id").and_then(Value::as_str) else {
            continue;
        };
        let Some(item) = failed_by_entry_id.get(id) else {
            continue;
        };
        let reason = item
            .get("reason")
            .and_then(Value::as_str)
            .or_else(|| item.get("message").and_then(Value::as_str))
            .map(str::to_string)
            .unwrap_or_else(|| {
                if fallback_reason.is_empty() {
                    "failed".to_string()
                } else {
                    fallback_reason.to_string()
                }
            });
        let candidates = match item.get("candidates").and_then(Value::as_array) {
            Some(arr) if !arr.is_empty() => Value::Array(arr.clone()),
            _ => Value::Array(candidates_for_entry(batch, id)),
        };
        out.push(serde_json::json!({
            "id": id,
            "reason": reason,
            "candidates": candidates,
        }));
    }
    out
}

/// Port of `mergeFailedEntries(...groups)`: later groups win on conflict,
/// merging `candidates`/`checks` from the earlier entry when the later one
/// omits them (`item.candidates || out[existingIndex].candidates`), keeping
/// first-seen order for new ids.
pub fn merge_failed_entries(groups: &[&[Value]]) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let mut index_by_id: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();

    for item in groups.iter().flat_map(|g| g.iter()) {
        if !item.is_object() {
            continue;
        }
        let id = item.get("id").and_then(Value::as_str).map(str::to_string);
        let Some(id) = id.filter(|s| !s.is_empty()) else {
            out.push(item.clone());
            continue;
        };
        match index_by_id.get(&id) {
            None => {
                index_by_id.insert(id, out.len());
                out.push(item.clone());
            }
            Some(&idx) => {
                let mut merged = out[idx].as_object().cloned().unwrap_or_default();
                if let Some(new_obj) = item.as_object() {
                    for (k, v) in new_obj {
                        merged.insert(k.clone(), v.clone());
                    }
                }
                let candidates = item
                    .get("candidates")
                    .filter(|v| !v.is_null())
                    .cloned()
                    .or_else(|| out[idx].get("candidates").cloned());
                if let Some(c) = candidates {
                    merged.insert("candidates".to_string(), c);
                } else {
                    merged.remove("candidates");
                }
                let checks = item
                    .get("checks")
                    .filter(|v| !v.is_null())
                    .cloned()
                    .or_else(|| out[idx].get("checks").cloned());
                if let Some(c) = checks {
                    merged.insert("checks".to_string(), c);
                } else {
                    merged.remove("checks");
                }
                out[idx] = Value::Object(merged);
            }
        }
    }
    out
}

const DEFAULT_REPAIR_ATTEMPTS: i64 = 3;

/// Port of `repairAttemptLimit(env)`. `raw_env_value` is
/// `env.IMPECCABLE_LIVE_MANUAL_EDIT_REPAIR_ATTEMPTS` (or `None` if unset,
/// mirroring `Number(undefined || DEFAULT_REPAIR_ATTEMPTS)`).
pub fn repair_attempt_limit(raw_env_value: Option<&str>) -> i64 {
    let value: f64 = match raw_env_value {
        Some(s) if !s.is_empty() => match s.trim().parse::<f64>() {
            Ok(n) => n,
            Err(_) => return DEFAULT_REPAIR_ATTEMPTS,
        },
        _ => DEFAULT_REPAIR_ATTEMPTS as f64,
    };
    if !value.is_finite() {
        return DEFAULT_REPAIR_ATTEMPTS;
    }
    let truncated = value.trunc() as i64;
    truncated.clamp(1, 10)
}

/// Truthy-check matching JS `if (value)` for a `serde_json::Value` field.
fn is_truthy(value: Option<&Value>) -> bool {
    match value {
        None => false,
        Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().map(|f| f != 0.0).unwrap_or(true),
        Some(Value::Array(_)) | Some(Value::Object(_)) => true,
    }
}

fn candidate_summary(candidate: &Value) -> Value {
    serde_json::json!({
        "file": candidate.get("file").cloned().unwrap_or(Value::Null),
        "line": candidate.get("line").cloned().unwrap_or(Value::Null),
        "kind": candidate.get("kind").cloned().unwrap_or(Value::Null),
        "reason": candidate.get("reason").cloned().unwrap_or(Value::Null),
    })
}

/// Port of `summarizeRepairFailures(failures = [])`.
pub fn summarize_repair_failures(failures: &[Value]) -> Vec<Value> {
    failures
        .iter()
        .take(20)
        .map(|failure| {
            let reason = failure
                .get("reason")
                .filter(|v| is_truthy(Some(v)))
                .cloned()
                .or_else(|| failure.get("detail").filter(|v| is_truthy(Some(v))).cloned())
                .unwrap_or_else(|| Value::String("validation_failed".to_string()));
            let mut out = Map::new();
            out.insert("reason".to_string(), reason);

            let entry_id = failure
                .get("id")
                .filter(|v| is_truthy(Some(v)))
                .cloned()
                .or_else(|| failure.get("entryId").filter(|v| is_truthy(Some(v))).cloned());
            if let Some(v) = entry_id {
                out.insert("entryId".to_string(), v);
            }
            for key in ["ref", "detail", "file", "message", "marker"] {
                if let Some(v) = failure.get(key).filter(|v| is_truthy(Some(v))) {
                    out.insert(key.to_string(), v.clone());
                }
            }
            if let Some(files) = failure.get("files").and_then(Value::as_array) {
                out.insert(
                    "files".to_string(),
                    Value::Array(files.iter().take(8).cloned().collect()),
                );
            }
            if let Some(candidates) = failure.get("candidates").and_then(Value::as_array) {
                out.insert(
                    "candidates".to_string(),
                    Value::Array(candidates.iter().take(8).map(candidate_summary).collect()),
                );
            }
            if let Some(sub_failures) = failure.get("failures").and_then(Value::as_array) {
                let mapped: Vec<Value> = sub_failures
                    .iter()
                    .take(8)
                    .map(|item| {
                        let reason = item
                            .get("reason")
                            .filter(|v| is_truthy(Some(v)))
                            .cloned()
                            .or_else(|| item.get("detail").cloned());
                        let mut sub = serde_json::json!({
                            "ref": item.get("ref").cloned().unwrap_or(Value::Null),
                            "reason": reason.unwrap_or(Value::Null),
                            "detail": item.get("detail").cloned().unwrap_or(Value::Null),
                        });
                        if let Some(cands) = item.get("candidates").and_then(Value::as_array) {
                            sub["candidates"] = Value::Array(
                                cands.iter().take(6).map(candidate_summary).collect(),
                            );
                        }
                        sub
                    })
                    .collect();
                out.insert("failures".to_string(), Value::Array(mapped));
            }
            if let Some(checks) = failure.get("checks").filter(|v| is_truthy(Some(v))) {
                out.insert("checks".to_string(), checks.clone());
            }
            Value::Object(out)
        })
        .collect()
}

/// Port of `buildRepairBatch(batch, repair)`.
pub fn build_repair_batch(batch: &Value, repair: Value) -> Value {
    let mut out = batch.as_object().cloned().unwrap_or_default();
    out.insert("repair".to_string(), repair);
    Value::Object(out)
}

/// Port of `escapeRegExp(value)`.
pub fn escape_regexp(value: &str) -> String {
    regex_escape(value)
}

/// Port of `normalizeVerificationText(text)`.
pub fn normalize_verification_text(text: &str) -> String {
    let re = Regex::new(r"\s+").expect("static regex");
    re.replace_all(text, " ").trim().to_string()
}

/// Mirrors the op fields `lineShowsAppliedOp` and friends read:
/// `originalText`, `newText`, `deleted`.
#[derive(Debug, Clone, Default)]
pub struct Op {
    pub original_text: Option<String>,
    pub new_text: Option<String>,
    pub deleted: bool,
    pub tag: Option<String>,
    pub element_id: Option<String>,
    pub classes: Vec<String>,
}

/// Port of:
/// ```js
/// function lineShowsAppliedOp(line, op) {
///   const originalText = typeof op?.originalText === 'string' ? op.originalText : '';
///   const newText = typeof op?.newText === 'string' ? op.newText : '';
///   const deletion = op?.deleted === true || newText.length === 0;
///   if (deletion) return !!originalText && !line.includes(originalText);
///   if (!line.includes(newText)) return false;
///   if (originalText && !newText.includes(originalText) && line.includes(originalText)) return false;
///   return true;
/// }
/// ```
pub fn line_shows_applied_op(line: &str, op: &Op) -> bool {
    let original_text = op.original_text.as_deref().unwrap_or("");
    let new_text = op.new_text.as_deref().unwrap_or("");
    let deletion = op.deleted || new_text.is_empty();
    if deletion {
        return !original_text.is_empty() && !line.contains(original_text);
    }
    if !line.contains(new_text) {
        return false;
    }
    if !original_text.is_empty() && !new_text.contains(original_text) && line.contains(original_text) {
        return false;
    }
    true
}

/// Port of `opHasLocator(op)`.
pub fn op_has_locator(op: &Op) -> bool {
    op.tag.as_ref().is_some_and(|t| !t.is_empty())
        || op.element_id.as_ref().is_some_and(|e| !e.is_empty())
        || op.classes.iter().any(|c| !c.is_empty())
}

/// Port of `lineMatchesManualEditLocator(line, op)`.
pub fn line_matches_manual_edit_locator(line: &str, op: &Op) -> bool {
    if let Some(tag) = op.tag.as_deref().filter(|t| !t.is_empty()) {
        let pattern = format!(r"(?i)<\s*{}(?=[\s>/]|$)", regex_escape(tag));
        let re = Regex::new(&pattern).expect("built from escaped input");
        if !re.is_match(line) {
            return false;
        }
    }

    if let Some(element_id) = op.element_id.as_deref().filter(|e| !e.is_empty()) {
        let pattern = format!(r#"\bid\s*=\s*["']{}["']"#, regex_escape(element_id));
        let re = Regex::new(&pattern).expect("built from escaped input");
        if !re.is_match(line) {
            return false;
        }
    }

    for class_name in op.classes.iter().filter(|c| !c.is_empty()) {
        if !line.contains(class_name.as_str()) {
            return false;
        }
    }

    true
}

/// Port of `lineHasObjectKey(line, text)`.
///
/// The JS regex uses a backreference (`(['"\`])text\2\s*:`) to require the
/// same quote character on both sides; the `regex` crate has no
/// backreference support, so this expands that into an explicit alternation
/// over the three quote characters, which is equivalent.
pub fn line_has_object_key(line: &str, text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    let escaped = regex_escape(text);
    for quote in ['\'', '"', '`'] {
        let quoted_pattern = format!(r"(^|[\s,{{]){quote}{escaped}{quote}\s*:");
        let quoted_re = Regex::new(&quoted_pattern).expect("built from escaped input");
        if quoted_re.is_match(line) {
            return true;
        }
    }
    let identifier_safe = Regex::new(r"^[A-Za-z_$][\w$]*$")
        .expect("static regex")
        .is_match(text);
    if !identifier_safe {
        return false;
    }
    let bare_pattern = format!(r"(^|[\s,{{]){}\s*:", regex_escape(text));
    let bare_re = Regex::new(&bare_pattern).expect("built from escaped input");
    bare_re.is_match(line)
}

/// Port of `windowShowsAppliedOp(lines, op)`.
pub fn window_shows_applied_op(lines: &[&str], op: &Op) -> bool {
    let new_text = op.new_text.as_deref().unwrap_or("");
    if new_text.is_empty() {
        return false;
    }
    let original_text = op.original_text.as_deref().unwrap_or("");
    let normalized_new = normalize_verification_text(new_text);
    let normalized_original = normalize_verification_text(original_text);
    let joined = lines.join("\n");
    let normalized_window = normalize_verification_text(&joined);
    if normalized_new.is_empty() || !normalized_window.contains(&normalized_new) {
        return false;
    }
    if !normalized_original.is_empty()
        && !normalized_new.contains(&normalized_original)
        && normalized_window.contains(&normalized_original)
    {
        return false;
    }
    true
}

/// Mirrors the fields `verificationTargetPassesLines` reads off a
/// verification target (`file` is not consulted by the pure line-matching
/// portion, so it is omitted here; callers that need it keep it alongside).
#[derive(Debug, Clone)]
pub struct VerificationTarget {
    /// 1-based line number, matching the JS `target.line`.
    pub line: usize,
    pub kind: String,
    pub reported: bool,
}

/// Port of `verificationTargetPassesLines(lines, target, op)`. `lines` is
/// 0-indexed, matching the JS `String.split('\n')` array; `target.line`
/// stays 1-based as in JS.
pub fn verification_target_passes_lines(lines: &[&str], target: &VerificationTarget, op: &Op) -> bool {
    let idx = target.line.checked_sub(1);
    let line = idx.and_then(|i| lines.get(i)).copied().unwrap_or("");
    if line_shows_applied_op(line, op) {
        return true;
    }
    let original_text = op.original_text.as_deref().unwrap_or("");
    if !original_text.is_empty() && line.contains(original_text) {
        return false;
    }
    let kind = target.kind.as_str();
    let can_search_window = target.reported
        || kind.contains("context_text_match")
        || kind.contains("object_key_match")
        || kind.contains("text_match");
    if !can_search_window {
        return false;
    }
    let radius: i64 = if kind.contains("context_text_match") { 20 } else { 4 };
    let target_line = target.line as i64;
    let start = (target_line - radius - 1).max(0) as usize;
    let end = ((target_line + radius) as usize).min(lines.len());
    if start >= end {
        return false;
    }
    let window_lines = &lines[start..end];
    if window_lines.iter().any(|l| line_shows_applied_op(l, op)) {
        return true;
    }
    window_shows_applied_op(window_lines, op)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn arg_val_variants() {
        let args = vec!["--foo".to_string(), "--bar=baz".to_string()];
        assert_eq!(arg_val(&args, "--foo"), ArgVal::Bool(true));
        assert_eq!(arg_val(&args, "--bar"), ArgVal::Str("baz".to_string()));
        assert_eq!(arg_val(&args, "--missing"), ArgVal::None);
    }

    #[test]
    fn count_ops_sums_arrays() {
        let entries = vec![
            json!({"ops": [1, 2, 3]}),
            json!({"ops": []}),
            json!({"noops": true}),
        ];
        assert_eq!(count_ops(&entries), 3);
    }

    #[test]
    fn summarize_applied_entries_filters_and_flattens() {
        let entries = vec![
            json!({"id": "a", "ops": [{"ref": "r1", "originalText": "o", "newText": "n"}]}),
            json!({"id": "b", "ops": [{"ref": "r2"}]}),
        ];
        let out = summarize_applied_entries(&entries, &["a".to_string()]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["id"], "a");
        assert_eq!(out[0]["ref"], "r1");
    }

    #[test]
    fn unique_strings_dedupes_and_drops_blank() {
        let values = vec![json!("a"), json!("a"), json!(""), json!("  "), json!(1), json!("b")];
        assert_eq!(unique_strings(&values), vec!["a", "b"]);
    }

    #[test]
    fn all_entry_ids_filters_falsy() {
        let batch = json!({"entries": [{"id": "a"}, {"id": ""}, {}, {"id": "b"}]});
        assert_eq!(all_entry_ids(&batch), vec!["a", "b"]);
    }

    #[test]
    fn candidates_for_entry_flattens_and_caps() {
        let batch = json!({
            "candidates": [
                {
                    "entryId": "a",
                    "sourceHint": "h1",
                    "textMatches": ["t1", "t2"],
                    "objectKeyMatches": [],
                    "locatorMatches": [],
                    "contextTextMatches": []
                },
                {"entryId": "other", "sourceHint": "ignored"}
            ]
        });
        let out = candidates_for_entry(&batch, "a");
        assert_eq!(out, vec![json!("h1"), json!("t1"), json!("t2")]);
    }

    #[test]
    fn normalize_failed_entries_uses_fallback_reason_and_computed_candidates() {
        let batch = json!({
            "entries": [{"id": "a"}, {"id": "b"}],
            "candidates": [{"entryId": "a", "sourceHint": "hint-a"}]
        });
        let result = json!({"failed": [{"entryId": "a"}]});
        let out = normalize_failed_entries(&batch, &result, "default_reason");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["id"], "a");
        assert_eq!(out[0]["reason"], "default_reason");
        assert_eq!(out[0]["candidates"], json!(["hint-a"]));
    }

    #[test]
    fn merge_failed_entries_merges_by_id_later_wins() {
        let a = vec![json!({"id": "x", "reason": "r1", "candidates": ["c1"]})];
        let b = vec![json!({"id": "x", "reason": "r2"})];
        let out = merge_failed_entries(&[&a, &b]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["reason"], "r2");
        assert_eq!(out[0]["candidates"], json!(["c1"]));
    }

    #[test]
    fn summarize_repair_failures_shapes_output_and_caps_lists() {
        let failures = vec![json!({
            "entryId": "e1",
            "ref": "r1",
            "detail": "still stale",
            "file": "src/a.tsx",
            "candidates": [
                {"file": "src/a.tsx", "line": 3, "kind": "text_match", "reason": "x"},
                {"file": "src/b.tsx", "line": 9, "kind": "text_match", "reason": "y"}
            ],
            "checks": {"ok": false}
        })];
        let out = summarize_repair_failures(&failures);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0]["reason"], "still stale");
        assert_eq!(out[0]["entryId"], "e1");
        assert_eq!(out[0]["candidates"][0]["file"], "src/a.tsx");
        assert_eq!(out[0]["checks"]["ok"], false);
    }

    #[test]
    fn summarize_repair_failures_defaults_reason_and_caps_at_twenty() {
        let failures: Vec<Value> = (0..25).map(|i| json!({"id": format!("e{i}")})).collect();
        let out = summarize_repair_failures(&failures);
        assert_eq!(out.len(), 20);
        assert_eq!(out[0]["reason"], "validation_failed");
        assert_eq!(out[0]["entryId"], "e0");
    }

    #[test]
    fn repair_attempt_limit_defaults_and_clamps() {
        assert_eq!(repair_attempt_limit(None), 3);
        assert_eq!(repair_attempt_limit(Some("")), 3);
        assert_eq!(repair_attempt_limit(Some("0")), 1);
        assert_eq!(repair_attempt_limit(Some("99")), 10);
        assert_eq!(repair_attempt_limit(Some("5")), 5);
        assert_eq!(repair_attempt_limit(Some("notanumber")), 3);
    }

    #[test]
    fn escape_regexp_matches_js_char_class() {
        assert_eq!(escape_regexp("a.b*c"), "a\\.b\\*c");
    }

    #[test]
    fn normalize_verification_text_collapses_whitespace() {
        assert_eq!(normalize_verification_text("  a\n\tb   c  "), "a b c");
    }

    #[test]
    fn line_shows_applied_op_deletion_and_insertion() {
        let deletion = Op { original_text: Some("old".into()), new_text: None, deleted: true, ..Default::default() };
        assert!(line_shows_applied_op("no trace here", &deletion));
        assert!(!line_shows_applied_op("still has old text", &deletion));

        let insertion = Op { original_text: Some("hi".into()), new_text: Some("hi there".into()), deleted: false, ..Default::default() };
        assert!(line_shows_applied_op("say hi there now", &insertion));
        assert!(!line_shows_applied_op("say hi now", &insertion));
    }

    #[test]
    fn op_has_locator_variants() {
        assert!(!op_has_locator(&Op::default()));
        assert!(op_has_locator(&Op { tag: Some("div".into()), ..Default::default() }));
        assert!(op_has_locator(&Op { element_id: Some("x".into()), ..Default::default() }));
        assert!(op_has_locator(&Op { classes: vec!["a".into()], ..Default::default() }));
    }

    #[test]
    fn line_matches_manual_edit_locator_all_conditions() {
        let op = Op {
            tag: Some("div".into()),
            element_id: Some("hero".into()),
            classes: vec!["card".into()],
            ..Default::default()
        };
        assert!(line_matches_manual_edit_locator(r#"<div id="hero" class="card">"#, &op));
        assert!(!line_matches_manual_edit_locator(r#"<span id="hero" class="card">"#, &op));
        assert!(!line_matches_manual_edit_locator(r#"<div id="other" class="card">"#, &op));
        assert!(!line_matches_manual_edit_locator(r#"<div id="hero" class="thing">"#, &op));
    }

    #[test]
    fn line_has_object_key_quoted_and_bare() {
        assert!(line_has_object_key(r#"  "title": "Hello","#, "title"));
        assert!(line_has_object_key("  title: 'Hello',", "title"));
        assert!(!line_has_object_key("  nottitle: 1,", "title"));
        assert!(!line_has_object_key("  x: 1,", "not an identifier"));
    }

    #[test]
    fn window_shows_applied_op_checks_normalized_text() {
        let op = Op { original_text: Some("Hello".into()), new_text: Some("Hello World".into()), ..Default::default() };
        assert!(window_shows_applied_op(&["prefix", "Hello   World", "suffix"], &op));
        assert!(!window_shows_applied_op(&["nothing", "here"], &op));
    }

    #[test]
    fn verification_target_passes_lines_direct_and_window() {
        let op = Op { original_text: Some("old".into()), new_text: Some("new".into()), ..Default::default() };
        let lines = vec!["a", "has new here", "c"];
        let target = VerificationTarget { line: 2, kind: "text_match".into(), reported: false };
        assert!(verification_target_passes_lines(&lines, &target, &op));

        let lines2 = vec!["a", "still has old", "c"];
        let target2 = VerificationTarget { line: 2, kind: "text_match".into(), reported: false };
        assert!(!verification_target_passes_lines(&lines2, &target2, &op));

        // window search: reported target with match on a nearby line
        let lines3 = vec!["a", "unrelated", "b", "has new right here", "c"];
        let target3 = VerificationTarget { line: 2, kind: "reported_locator_match".into(), reported: true };
        assert!(verification_target_passes_lines(&lines3, &target3, &op));
    }
}
