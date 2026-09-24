//! CLI entry point and top-level orchestration ported from
//! `live-commit-manual-edits.mjs`'s `commitManualEdits`,
//! `repairPostApplyValidation`, `clearAppliedEntries` and `main` /
//! argv-dispatch tail (packet R18R26).
//!
//! Wires together the pieces already ported elsewhere in this repo:
//! - [`super::verify`] for the source-verification pipeline
//!   (`verifyAppliedEntry`/`verifyEntriesAfterRepair`), against
//!   [`super::verify::FsSourceStore`] for real disk reads.
//! - [`super::rollback`] for the directory-walk snapshot/rollback
//!   machinery.
//! - [`crate::wf_port::w2_018::copy_edit_agent`] for the AI-runner
//!   subprocess orchestration (`runCopyEditBatchAgent`,
//!   `runCopyEditPostApplyChecks`), which already lives behind the
//!   [`crate::wf_port::w2_018::copy_edit_agent::ProcessRunner`] trait.
//! - [`crate::wf_port::w2_018::evidence::build_manual_edit_evidence`] for
//!   `buildManualEditEvidence`.
//! - [`crate::wf_port::w2_021::manual_edits_buffer`] for
//!   `readBufferStrict`/`countByPage`/`clearAppliedEntries` (via
//!   `remove_entries`).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::wf_port::r18::rollback::{
    changed_files_since_snapshot, collect_apply_owned_files, rollback_changed_files,
    snapshot_rollback_files, unreported_changed_files, RollbackSnapshot,
};
use crate::wf_port::r18::verify::{
    verification_failures_for_entries, verify_applied_entry, verify_entries_after_repair,
    FsSourceStore, SourceStore,
};
use crate::wf_port::w2_017::commit_edits::{
    all_entry_ids, arg_val, build_repair_batch, candidates_for_entry, count_ops,
    merge_failed_entries, merge_unique_strings, normalize_failed_entries, repair_attempt_limit,
    summarize_applied_entries, summarize_repair_failures, unique_strings, ArgVal,
};
use crate::wf_port::w2_018::copy_edit_agent::{
    choose_copy_edit_agent, command_exists, describe_no_provider_error,
    run_copy_edit_batch_agent, run_copy_edit_post_apply_checks, Provider, ProcessRunner,
    SystemProcessRunner,
};
use crate::wf_port::w2_018::evidence::build_manual_edit_evidence;
use crate::wf_port::w2_021::manual_edits_buffer::{self, count_by_page};

/// Port of `commitManualEdits`'s options bag. `batch` mirrors the
/// `providedBatch` testing seam.
pub struct CommitOptions<'a> {
    pub cwd: PathBuf,
    pub page_url: Option<String>,
    pub provider: Option<String>,
    pub env: &'a HashMap<String, String>,
    pub timeout_ms: Option<u64>,
    pub repair_only: bool,
    pub transaction_id: Option<String>,
    pub batch: Option<Value>,
}

fn live_dir(cwd: &Path) -> PathBuf {
    cwd.join(".impeccable").join("live")
}

/// Port of `chooseCopyEditAgent` resolution as `runCopyEditBatchAgent`
/// performs it: `opts.provider || chooseCopyEditAgent({ env, chatAvailable
/// })`. An explicit provider string is used as-is (matching the JS, which
/// does not re-validate an explicitly supplied provider).
fn resolve_provider(provider: Option<&str>, env: &HashMap<String, String>) -> Option<Provider> {
    if let Some(p) = provider {
        return match p {
            "mock" => Some(Provider::Mock),
            "chat" => Some(Provider::Chat),
            "codex" => Some(Provider::Codex),
            "claude" => Some(Provider::Claude),
            _ => None,
        };
    }
    let env_mode = env.get("IMPECCABLE_LIVE_COPY_AGENT").map(String::as_str);
    choose_copy_edit_agent(env_mode, command_exists, || false)
}

/// Port of `clearAppliedEntries(cwd, appliedEntryIds)`.
fn clear_applied_entries(cwd: &Path, applied_entry_ids: &[String]) -> usize {
    let ids: HashSet<&str> = applied_entry_ids.iter().map(String::as_str).collect();
    if ids.is_empty() {
        return 0;
    }
    manual_edits_buffer::remove_entries(cwd, |entry| {
        entry
            .id
            .as_deref()
            .map(|id| ids.contains(id))
            .unwrap_or(false)
    })
}

fn count_by_page_json(cwd: &Path) -> Value {
    let counts = count_by_page(cwd);
    json!({
        "totalCount": counts.total_count,
        "perPage": counts.per_page,
    })
}

fn run_agent(
    batch: &Value,
    cwd: &Path,
    env: &HashMap<String, String>,
    provider: Option<Provider>,
    runner: &dyn ProcessRunner,
    timeout_ms: Option<u64>,
) -> Result<Value, String> {
    let provider = provider.ok_or_else(|| {
        describe_no_provider_error(command_exists, || false, env.contains_key("CLAUDE_CODE_OAUTH_TOKEN"))
    })?;
    let result_dir = std::env::temp_dir().join(format!(
        "impeccable-copy-batch-{}-{}",
        std::process::id(),
        NEXT_TMP.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::create_dir_all(&result_dir);
    let result_path = result_dir.join("result.json");
    run_copy_edit_batch_agent(batch, cwd, env, provider, runner, &result_path, timeout_ms)
}

static NEXT_TMP: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Port of `verifyEntriesAfterRepair` + `findUnappliedEntrySourceChanges`
/// snapshot-comparison helper `snapshotTargetPasses`, reused inline by
/// `repairPostApplyValidation`.
fn verify_entries_after_repair_fs(
    cwd: &Path,
    batch: &Value,
    applied_entry_ids: &[String],
    files: &[String],
) -> (Vec<String>, Vec<Value>) {
    let store = FsSourceStore::new(cwd.to_path_buf());
    let reported_files: Vec<String> = unique_strings(
        &files
            .iter()
            .map(|f| Value::String(f.clone()))
            .collect::<Vec<_>>(),
    )
    .into_iter()
    .filter_map(|f| crate::wf_port::r18::rollback::normalize_relative_file(cwd, Some(&f)))
    .collect();
    verify_entries_after_repair(&store, batch, applied_entry_ids, &reported_files)
}

/// Port of `repairPostApplyValidation`.
#[allow(clippy::too_many_arguments)]
fn repair_post_apply_validation(
    batch: &Value,
    cwd: &Path,
    page_url: Option<&str>,
    count: usize,
    provider: Option<&str>,
    env: &HashMap<String, String>,
    timeout_ms: Option<u64>,
    runner: &dyn ProcessRunner,
    transaction_id: Option<&str>,
    applied_entry_ids: &[String],
    files: &[String],
    failed: &[Value],
    notes: &[Value],
    warnings: &[Value],
    repair_reason: &str,
    repair_failures: &[Value],
) -> Value {
    let max_attempts = repair_attempt_limit(
        env.get("IMPECCABLE_LIVE_MANUAL_EDIT_REPAIR_ATTEMPTS")
            .map(String::as_str),
    );
    let mut current_files = merge_unique_strings(&[&files
        .iter()
        .map(|f| Value::String(f.clone()))
        .collect::<Vec<_>>()]);
    let mut current_applied_ids = merge_unique_strings(&[&applied_entry_ids
        .iter()
        .map(|f| Value::String(f.clone()))
        .collect::<Vec<_>>()]);
    let mut current_failed: Vec<Value> = failed.to_vec();
    let mut current_notes: Vec<Value> = notes.to_vec();
    let mut current_warnings: Vec<Value> = warnings.to_vec();
    let mut current_failures: Vec<Value> = repair_failures.to_vec();

    let resolved_provider = resolve_provider(provider, env);

    let mut attempt = 1i64;
    while attempt <= max_attempts {
        let repair = json!({
            "attempt": attempt,
            "maxAttempts": max_attempts,
            "transactionId": transaction_id,
            "reason": repair_reason,
            "failures": summarize_repair_failures(&current_failures),
            "files": current_files,
            "pageUrl": page_url,
        });
        let repair_batch = build_repair_batch(batch, repair);

        let repair_result = match run_agent(
            &repair_batch,
            cwd,
            env,
            resolved_provider,
            runner,
            timeout_ms,
        ) {
            Ok(r) => r,
            Err(err) => {
                current_failures = vec![json!({
                    "reason": "repair_agent_failed",
                    "message": err,
                })];
                attempt += 1;
                continue;
            }
        };

        let repair_files: Vec<Value> = repair_result
            .get("files")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        current_files = merge_unique_strings(&[
            &current_files
                .iter()
                .map(|f| Value::String(f.clone()))
                .collect::<Vec<_>>(),
            &repair_files,
        ]);
        if let Some(n) = repair_result.get("notes").and_then(Value::as_array) {
            current_notes.extend(n.iter().cloned());
        }
        if let Some(w) = repair_result.get("warnings").and_then(Value::as_array) {
            current_warnings.extend(w.iter().cloned());
        }
        let repair_applied: Vec<Value> = repair_result
            .get("appliedEntryIds")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        current_applied_ids = merge_unique_strings(&[
            &current_applied_ids
                .iter()
                .map(|f| Value::String(f.clone()))
                .collect::<Vec<_>>(),
            &repair_applied,
        ]);
        let repair_normalized_failed =
            normalize_failed_entries(batch, &repair_result, "repair_failed");
        current_failed = merge_failed_entries(&[&current_failed, &repair_normalized_failed]);

        let (verified_ids, verify_failed) =
            verify_entries_after_repair_fs(cwd, batch, &current_applied_ids, &current_files);
        if !verify_failed.is_empty() {
            current_failures = verify_failed;
            attempt += 1;
            continue;
        }

        let repaired_checks =
            run_copy_edit_post_apply_checks(cwd, &current_files, runner);
        current_warnings.extend(repaired_checks.warnings.iter().cloned());
        if !repaired_checks.ok {
            current_failures = repaired_checks.failures;
            attempt += 1;
            continue;
        }

        let cleared = clear_applied_entries(cwd, &verified_ids);
        let counts = count_by_page_json(cwd);
        let verified_id_set: HashSet<&str> = verified_ids.iter().map(String::as_str).collect();
        let entries = batch
            .get("entries")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let remaining_failed: Vec<Value> = merge_failed_entries(&[&current_failed])
            .into_iter()
            .filter(|item| {
                item.get("id")
                    .and_then(Value::as_str)
                    .map(|id| !verified_id_set.contains(id))
                    .unwrap_or(true)
            })
            .collect();
        let mut out = json!({
            "applied": summarize_applied_entries(&entries, &verified_ids),
            "failed": remaining_failed,
            "files": current_files,
            "cleared": cleared,
            "count": count,
            "pageUrl": page_url,
            "warnings": current_warnings,
            "notes": current_notes,
            "repair": {
                "status": "repaired",
                "attempts": attempt,
                "maxAttempts": max_attempts,
                "transactionId": transaction_id,
            },
        });
        merge_counts(&mut out, &counts);
        return out;
    }

    let entries = batch
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let decision_failed_entries: Vec<Value> = if !current_applied_ids.is_empty() {
        let applied_set: HashSet<&str> = current_applied_ids.iter().map(String::as_str).collect();
        entries
            .iter()
            .filter(|entry| {
                entry
                    .get("id")
                    .and_then(Value::as_str)
                    .map(|id| applied_set.contains(id))
                    .unwrap_or(false)
            })
            .map(|entry| {
                let id = entry.get("id").and_then(Value::as_str).unwrap_or("");
                json!({
                    "id": id,
                    "reason": repair_reason,
                    "checks": current_failures,
                    "candidates": candidates_for_entry(batch, id),
                })
            })
            .collect()
    } else {
        let mut base = verification_failures_for_entries(&entries, repair_reason);
        for item in base.iter_mut() {
            item["checks"] = Value::Array(current_failures.clone());
        }
        base
    };

    let counts = count_by_page_json(cwd);
    let mut out = json!({
        "applied": Vec::<Value>::new(),
        "failed": merge_failed_entries(&[&decision_failed_entries, &current_failed]),
        "files": current_files,
        "cleared": 0,
        "count": count,
        "pageUrl": page_url,
        "warnings": current_warnings,
        "notes": current_notes,
        "reason": "manual_edit_repair_needs_decision",
        "needsManualDecision": true,
        "repair": {
            "status": "needs_decision",
            "attempts": max_attempts,
            "maxAttempts": max_attempts,
            "transactionId": transaction_id,
            "failures": summarize_repair_failures(&current_failures),
            "files": current_files,
        },
    });
    merge_counts(&mut out, &counts);
    out
}

fn merge_counts(out: &mut Value, counts: &Value) {
    if let (Some(out_obj), Some(counts_obj)) = (out.as_object_mut(), counts.as_object()) {
        for (k, v) in counts_obj {
            out_obj.insert(k.clone(), v.clone());
        }
    }
}

/// Port of `commitManualEdits({ cwd, pageUrl, provider, env, timeoutMs,
/// repairOnly, transactionId, batch })`.
pub fn commit_manual_edits(opts: CommitOptions, runner: &dyn ProcessRunner) -> Value {
    let cwd = &opts.cwd;
    let page_url = opts.page_url.as_deref();

    if let Err(err) = manual_edits_buffer::read_buffer_strict(cwd) {
        let counts = count_by_page_json(cwd);
        let mut out = json!({
            "applied": Vec::<Value>::new(),
            "failed": Vec::<Value>::new(),
            "files": Vec::<Value>::new(),
            "cleared": 0,
            "count": 0,
            "pageUrl": page_url,
            "reason": "manual_edit_buffer_invalid",
            "message": err,
        });
        merge_counts(&mut out, &counts);
        return out;
    }

    let batch = opts
        .batch
        .clone()
        .unwrap_or_else(|| build_manual_edit_evidence(cwd, &live_dir(cwd), page_url));
    let entries = batch
        .get("entries")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let count = count_ops(&entries);
    if count == 0 {
        let counts = count_by_page_json(cwd);
        let mut out = json!({
            "applied": Vec::<Value>::new(),
            "failed": Vec::<Value>::new(),
            "files": Vec::<Value>::new(),
            "cleared": 0,
            "count": 0,
            "pageUrl": page_url,
            "reason": "no_pending_edits",
        });
        merge_counts(&mut out, &counts);
        return out;
    }

    let base_rollback_scope = collect_apply_owned_files(&batch, cwd, &[]);
    let rollback_snapshot: RollbackSnapshot =
        snapshot_rollback_files(cwd, Some(&base_rollback_scope));

    let result = if opts.repair_only {
        Ok(json!({
            "status": "done",
            "appliedEntryIds": all_entry_ids(&batch),
            "failed": Vec::<Value>::new(),
            "files": collect_apply_owned_files(&batch, cwd, &[]),
            "notes": ["repair-only validation pass"],
        }))
    } else {
        run_agent(
            &batch,
            cwd,
            opts.env,
            resolve_provider(opts.provider.as_deref(), opts.env),
            runner,
            opts.timeout_ms,
        )
    };

    let result = match result {
        Ok(r) => r,
        Err(err) => {
            let rollback =
                rollback_changed_files(cwd, &rollback_snapshot, &[], &base_rollback_scope);
            let failed: Vec<Value> = entries
                .iter()
                .map(|entry| {
                    let id = entry.get("id").cloned().unwrap_or(Value::Null);
                    json!({
                        "id": id,
                        "reason": err,
                        "candidates": candidates_for_entry(&batch, id.as_str().unwrap_or("")),
                    })
                })
                .collect();
            let counts = count_by_page_json(cwd);
            let mut out = json!({
                "applied": Vec::<Value>::new(),
                "failed": failed,
                "files": Vec::<Value>::new(),
                "cleared": 0,
                "count": count,
                "pageUrl": page_url,
                "rolledBackFiles": rollback.rolled_back_files,
                "rollbackFailures": rollback.rollback_failures,
            });
            merge_counts(&mut out, &counts);
            return out;
        }
    };

    let result_files: Vec<String> = unique_strings(
        &result
            .get("files")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    );

    if result.get("status").and_then(Value::as_str) == Some("error") {
        let rollback_scope = collect_apply_owned_files(&batch, cwd, &result_files);
        let rollback =
            rollback_changed_files(cwd, &rollback_snapshot, &result_files, &rollback_scope);
        let fallback = result
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("AI copy edit failed");
        let failed = normalize_failed_entries(&batch, &result, fallback);
        let failed = if !failed.is_empty() {
            failed
        } else {
            verification_failures_for_entries(&entries, fallback)
        };
        let counts = count_by_page_json(cwd);
        let mut out = json!({
            "applied": Vec::<Value>::new(),
            "failed": failed,
            "files": result_files,
            "cleared": 0,
            "count": count,
            "pageUrl": page_url,
            "notes": result.get("notes").cloned().unwrap_or_else(|| json!([])),
            "rolledBackFiles": rollback.rolled_back_files,
            "rollbackFailures": rollback.rollback_failures,
        });
        merge_counts(&mut out, &counts);
        return out;
    }

    let reported_applied_ids: Vec<String> = unique_strings(
        &result
            .get("appliedEntryIds")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    );
    let reported_files: Vec<String> = result_files
        .iter()
        .filter_map(|f| crate::wf_port::r18::rollback::normalize_relative_file(cwd, Some(f)))
        .collect();
    let ai_failed = normalize_failed_entries(&batch, &result, "AI copy edit failed");
    let rollback_scope = collect_apply_owned_files(&batch, cwd, &result_files);
    let failed_ids: HashSet<&str> = ai_failed
        .iter()
        .filter_map(|item| item.get("id").and_then(Value::as_str))
        .collect();
    let conflicting_applied_ids: Vec<String> = reported_applied_ids
        .iter()
        .filter(|id| failed_ids.contains(id.as_str()))
        .cloned()
        .collect();

    if !conflicting_applied_ids.is_empty() {
        let rollback =
            rollback_changed_files(cwd, &rollback_snapshot, &result_files, &rollback_scope);
        let conflicting_set: HashSet<&str> =
            conflicting_applied_ids.iter().map(String::as_str).collect();
        let conflicting_entries: Vec<Value> = entries
            .iter()
            .filter(|e| {
                e.get("id")
                    .and_then(Value::as_str)
                    .map(|id| conflicting_set.contains(id))
                    .unwrap_or(false)
            })
            .cloned()
            .collect();
        let mut failed = verification_failures_for_entries(&conflicting_entries, "conflicting_apply_result");
        failed.extend(ai_failed.iter().filter(|item| {
            item.get("id")
                .and_then(Value::as_str)
                .map(|id| !conflicting_set.contains(id))
                .unwrap_or(true)
        }).cloned());
        let counts = count_by_page_json(cwd);
        let mut out = json!({
            "applied": Vec::<Value>::new(),
            "failed": failed,
            "files": result_files,
            "cleared": 0,
            "count": count,
            "pageUrl": page_url,
            "notes": result.get("notes").cloned().unwrap_or_else(|| json!([])),
            "rolledBackFiles": rollback.rolled_back_files,
            "rollbackFailures": rollback.rollback_failures,
        });
        merge_counts(&mut out, &counts);
        return out;
    }

    let unreported_files =
        unreported_changed_files(cwd, &rollback_snapshot, &result_files, &rollback_scope);
    if !unreported_files.is_empty() {
        let mut extended_scope = rollback_scope.clone();
        extended_scope.extend(unreported_files.iter().cloned());
        let rollback =
            rollback_changed_files(cwd, &rollback_snapshot, &result_files, &extended_scope);
        let mut failed = verification_failures_for_entries(&entries, "unreported_source_changes");
        for item in failed.iter_mut() {
            item["files"] = json!(unreported_files);
        }
        let counts = count_by_page_json(cwd);
        let mut out = json!({
            "applied": Vec::<Value>::new(),
            "failed": failed,
            "files": result_files,
            "unreportedFiles": unreported_files,
            "cleared": 0,
            "count": count,
            "pageUrl": page_url,
            "notes": result.get("notes").cloned().unwrap_or_else(|| json!([])),
            "rolledBackFiles": rollback.rolled_back_files,
            "rollbackFailures": rollback.rollback_failures,
        });
        merge_counts(&mut out, &counts);
        return out;
    }

    if result.get("status").and_then(Value::as_str) == Some("done") && reported_applied_ids.is_empty() {
        let rollback =
            rollback_changed_files(cwd, &rollback_snapshot, &result_files, &rollback_scope);
        let failed = verification_failures_for_entries(&entries, "missing_applied_entry_ids");
        let counts = count_by_page_json(cwd);
        let mut out = json!({
            "applied": Vec::<Value>::new(),
            "failed": failed,
            "files": result_files,
            "cleared": 0,
            "count": count,
            "pageUrl": page_url,
            "notes": result.get("notes").cloned().unwrap_or_else(|| json!([])),
            "rolledBackFiles": rollback.rolled_back_files,
            "rollbackFailures": rollback.rollback_failures,
        });
        merge_counts(&mut out, &counts);
        return out;
    }

    let reported_applied_id_set: HashSet<&str> =
        reported_applied_ids.iter().map(String::as_str).collect();
    let reported_applied_entries: Vec<Value> = entries
        .iter()
        .filter(|e| {
            e.get("id")
                .and_then(Value::as_str)
                .map(|id| reported_applied_id_set.contains(id))
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    if !reported_applied_ids.is_empty() && reported_files.is_empty() {
        let repair_failures = verification_failures_for_entries(&reported_applied_entries, "missing_touched_files");
        return repair_post_apply_validation(
            &batch,
            cwd,
            page_url,
            count,
            opts.provider.as_deref(),
            opts.env,
            opts.timeout_ms,
            runner,
            opts.transaction_id.as_deref(),
            &reported_applied_ids,
            &result_files,
            &ai_failed,
            result
                .get("notes")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .as_slice(),
            result
                .get("warnings")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .as_slice(),
            "missing_touched_files",
            &repair_failures,
        );
    }

    let store = FsSourceStore::new(cwd.to_path_buf());
    let mut verified_applied_ids = Vec::new();
    let mut verification_failed = Vec::new();
    for entry in &reported_applied_entries {
        let failures = verify_applied_entry(&store, &batch, entry, &reported_files);
        let id = entry.get("id").and_then(Value::as_str).unwrap_or("");
        if failures.is_empty() {
            verified_applied_ids.push(id.to_string());
        } else {
            verification_failed.push(json!({
                "id": id,
                "reason": "source_verification_failed",
                "failures": failures,
                "candidates": candidates_for_entry(&batch, id),
            }));
        }
    }

    let status = result.get("status").and_then(Value::as_str);
    let ai_failed_ids: HashSet<&str> = ai_failed
        .iter()
        .filter_map(|i| i.get("id").and_then(Value::as_str))
        .collect();
    let unreported_entries: Vec<Value> = if status == Some("done") || status == Some("partial") {
        entries
            .iter()
            .filter(|e| {
                let id = e.get("id").and_then(Value::as_str).unwrap_or("");
                !reported_applied_id_set.contains(id) && !ai_failed_ids.contains(id)
            })
            .cloned()
            .collect()
    } else {
        Vec::new()
    };
    let mut non_repair_failed = verification_failures_for_entries(&unreported_entries, "not_reported_applied");
    non_repair_failed.extend(ai_failed.iter().cloned());

    let mut failed: Vec<Value> = verification_failed.clone();
    failed.extend(non_repair_failed.iter().cloned());

    let unapplied_entries: Vec<Value> = entries
        .iter()
        .filter(|e| {
            e.get("id")
                .and_then(Value::as_str)
                .map(|id| !reported_applied_id_set.contains(id))
                .unwrap_or(true)
        })
        .cloned()
        .collect();
    let leaked_unapplied =
        find_unapplied_entry_source_changes(&batch, &unapplied_entries, &reported_files, cwd, &rollback_snapshot);
    if !leaked_unapplied.is_empty() {
        let leaked_ids: HashSet<String> = leaked_unapplied
            .iter()
            .filter_map(|i| i.get("id").and_then(Value::as_str).map(str::to_string))
            .collect();
        let verified_set: HashSet<&str> = verified_applied_ids.iter().map(String::as_str).collect();
        let rolled_back_verified: Vec<Value> = reported_applied_entries
            .iter()
            .filter(|e| {
                e.get("id")
                    .and_then(Value::as_str)
                    .map(|id| verified_set.contains(id))
                    .unwrap_or(false)
            })
            .map(|e| {
                let id = e.get("id").and_then(Value::as_str).unwrap_or("");
                json!({
                    "id": id,
                    "reason": "rolled_back_due_to_failed_entry_source_changed",
                    "candidates": candidates_for_entry(&batch, id),
                })
            })
            .collect();
        let rollback =
            rollback_changed_files(cwd, &rollback_snapshot, &result_files, &rollback_scope);
        let mut combined = leaked_unapplied.clone();
        combined.extend(failed.iter().filter(|item| {
            item.get("id")
                .and_then(Value::as_str)
                .map(|id| !leaked_ids.contains(id))
                .unwrap_or(true)
        }).cloned());
        combined.extend(rolled_back_verified);
        let counts = count_by_page_json(cwd);
        let mut out = json!({
            "applied": Vec::<Value>::new(),
            "failed": combined,
            "files": result_files,
            "cleared": 0,
            "count": count,
            "pageUrl": page_url,
            "rolledBackFiles": rollback.rolled_back_files,
            "rollbackFailures": rollback.rollback_failures,
            "notes": result.get("notes").cloned().unwrap_or_else(|| json!([])),
        });
        merge_counts(&mut out, &counts);
        return out;
    }

    if !verification_failed.is_empty() {
        return repair_post_apply_validation(
            &batch,
            cwd,
            page_url,
            count,
            opts.provider.as_deref(),
            opts.env,
            opts.timeout_ms,
            runner,
            opts.transaction_id.as_deref(),
            &reported_applied_ids,
            &result_files,
            &non_repair_failed,
            result
                .get("notes")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .as_slice(),
            result
                .get("warnings")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .as_slice(),
            "source_verification_failed",
            &verification_failed,
        );
    }

    let post_checks = run_copy_edit_post_apply_checks(cwd, &result_files, runner);
    if !post_checks.ok {
        let post_check_entries = if !verified_applied_ids.is_empty() {
            let verified_set: HashSet<&str> = verified_applied_ids.iter().map(String::as_str).collect();
            reported_applied_entries
                .iter()
                .filter(|e| {
                    e.get("id")
                        .and_then(Value::as_str)
                        .map(|id| verified_set.contains(id))
                        .unwrap_or(false)
                })
                .cloned()
                .collect::<Vec<_>>()
        } else {
            entries.clone()
        };
        let applied_ids_for_repair: Vec<String> = if !verified_applied_ids.is_empty() {
            verified_applied_ids.clone()
        } else {
            post_check_entries
                .iter()
                .filter_map(|e| e.get("id").and_then(Value::as_str).map(str::to_string))
                .collect()
        };
        let mut warnings = result
            .get("warnings")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        warnings.extend(post_checks.warnings.iter().cloned());
        return repair_post_apply_validation(
            &batch,
            cwd,
            page_url,
            count,
            opts.provider.as_deref(),
            opts.env,
            opts.timeout_ms,
            runner,
            opts.transaction_id.as_deref(),
            &applied_ids_for_repair,
            &result_files,
            &failed,
            result
                .get("notes")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .as_slice(),
            &warnings,
            "post_apply_validation_failed",
            &post_checks.failures,
        );
    }

    let cleared = clear_applied_entries(cwd, &verified_applied_ids);
    let counts = count_by_page_json(cwd);
    let mut warnings = result
        .get("warnings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    warnings.extend(post_checks.warnings.iter().cloned());
    let mut out = json!({
        "applied": summarize_applied_entries(&entries, &verified_applied_ids),
        "failed": failed,
        "files": result_files,
        "cleared": cleared,
        "count": count,
        "pageUrl": page_url,
        "warnings": warnings,
        "notes": result.get("notes").cloned().unwrap_or_else(|| json!([])),
    });
    merge_counts(&mut out, &counts);
    out
}

/// Port of `findUnappliedEntrySourceChanges` and its `snapshotTargetPasses`
/// helper, composed from [`super::verify`]'s pure target/verification
/// helpers against the on-disk snapshot instead of the live file.
fn find_unapplied_entry_source_changes(
    batch: &Value,
    entries: &[Value],
    reported_files: &[String],
    cwd: &Path,
    rollback_snapshot: &RollbackSnapshot,
) -> Vec<Value> {
    let store = FsSourceStore::new(cwd.to_path_buf());
    let mut failures = Vec::new();
    for entry in entries {
        let entry_id = entry.get("id").and_then(Value::as_str).unwrap_or("");
        let Some(ops) = entry.get("ops").and_then(Value::as_array) else {
            continue;
        };
        for raw_op in ops {
            let new_text = raw_op.get("newText").and_then(Value::as_str).unwrap_or("");
            if new_text.is_empty() {
                continue;
            }
            let op = crate::wf_port::w2_017::commit_edits::Op {
                original_text: raw_op
                    .get("originalText")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                new_text: Some(new_text.to_string()),
                deleted: raw_op
                    .get("deleted")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                tag: raw_op.get("tag").and_then(Value::as_str).map(str::to_string),
                element_id: raw_op
                    .get("elementId")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                classes: raw_op
                    .get("classes")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|c| c.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
            };
            let op_ref = raw_op.get("ref").and_then(Value::as_str).unwrap_or("");
            let targets = crate::wf_port::r18::verify::verification_targets_for_op(
                &store,
                batch,
                raw_op,
                entry_id,
                op_ref,
                reported_files,
                &op,
            );
            let leaked: Vec<Value> = targets
                .into_iter()
                .filter(|target| {
                    crate::wf_port::r18::verify::verification_target_passes(&store, target, &op)
                        && !snapshot_target_passes(rollback_snapshot, target, &op)
                })
                .collect();
            if leaked.is_empty() {
                continue;
            }
            let mut candidates: Vec<Value> = leaked
                .iter()
                .map(|t| {
                    json!({
                        "file": t.get("file").cloned().unwrap_or(Value::Null),
                        "line": t.get("line").cloned().unwrap_or(Value::Null),
                        "kind": t.get("kind").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect();
            candidates.extend(candidates_for_entry(batch, entry_id));
            candidates.truncate(12);
            failures.push(json!({
                "id": entry_id,
                "reason": "failed_entry_source_changed",
                "ref": op_ref,
                "newText": new_text,
                "candidates": candidates,
            }));
            break;
        }
    }
    failures
}

fn snapshot_target_passes(
    snapshot: &RollbackSnapshot,
    target: &Value,
    op: &crate::wf_port::w2_017::commit_edits::Op,
) -> bool {
    let Some(file) = target.get("file").and_then(Value::as_str) else {
        return false;
    };
    let before = match snapshot.get(file) {
        Some(crate::wf_port::r18::rollback::SnapshotEntry::Existed { content }) => content,
        _ => return false,
    };
    let lines: Vec<&str> = before.split('\n').collect();
    crate::wf_port::w2_017::commit_edits::verification_target_passes_lines(
        &lines,
        &crate::wf_port::w2_017::commit_edits::VerificationTarget {
            line: target.get("line").and_then(Value::as_u64).unwrap_or(0) as usize,
            kind: target
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            reported: target.get("reported").and_then(Value::as_bool).unwrap_or(false),
        },
        op,
    )
}

/// CLI argv dispatch, mirroring `main()` / the `--help` branch /
/// `console.log(JSON.stringify(result))`. Returns `(stdout, exit_code)`
/// instead of printing and calling `process.exit` directly, so callers
/// (a thin `fn main`, or tests) control I/O.
pub fn run_cli(args: &[String], cwd: PathBuf, env: &HashMap<String, String>) -> (i32, String) {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return (
            0,
            "Usage: legion-commit-manual-edits [--page-url=<url>] [--provider=auto|codex|claude|mock]"
                .to_string(),
        );
    }

    let page_url = match arg_val(args, "--page-url") {
        ArgVal::Str(s) => Some(s),
        ArgVal::Bool(true) => None,
        _ => None,
    };
    let provider = match arg_val(args, "--provider") {
        ArgVal::Str(s) => Some(s),
        _ => None,
    };
    let timeout_ms = env
        .get("IMPECCABLE_LIVE_COPY_AGENT_TIMEOUT_MS")
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(120_000);

    let opts = CommitOptions {
        cwd,
        page_url,
        provider,
        env,
        timeout_ms: Some(timeout_ms),
        repair_only: false,
        transaction_id: None,
        batch: None,
    };
    let runner = SystemProcessRunner;
    let result = commit_manual_edits(opts, &runner);
    (0, result.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::w2_018::copy_edit_agent::{ProcessRunResult, ProcessSpec};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "legion-r18-commit-cli-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct NullRunner;
    impl ProcessRunner for NullRunner {
        fn run(&self, _spec: &ProcessSpec) -> ProcessRunResult {
            ProcessRunResult {
                success: false,
                spawn_failed: true,
                timed_out: false,
                stdout: String::new(),
                stderr: "not used".to_string(),
            }
        }
    }

    #[test]
    fn no_pending_edits_short_circuits() {
        let dir = temp_dir();
        let env = HashMap::new();
        let opts = CommitOptions {
            cwd: dir,
            page_url: None,
            provider: Some("mock".to_string()),
            env: &env,
            timeout_ms: None,
            repair_only: false,
            transaction_id: None,
            batch: Some(json!({ "entries": [], "candidates": [] })),
        };
        let runner = NullRunner;
        let result = commit_manual_edits(opts, &runner);
        assert_eq!(result["reason"], "no_pending_edits");
        assert_eq!(result["count"], 0);
    }

    #[test]
    fn invalid_buffer_reports_buffer_invalid() {
        let dir = temp_dir();
        let live = dir.join(".impeccable").join("live");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(live.join("pending-manual-edits.json"), "not json").unwrap();
        let env = HashMap::new();
        let opts = CommitOptions {
            cwd: dir,
            page_url: None,
            provider: Some("mock".to_string()),
            env: &env,
            timeout_ms: None,
            repair_only: false,
            transaction_id: None,
            batch: None,
        };
        let runner = NullRunner;
        let result = commit_manual_edits(opts, &runner);
        assert_eq!(result["reason"], "manual_edit_buffer_invalid");
    }

    #[test]
    fn run_cli_help_short_circuits() {
        let env = HashMap::new();
        let (code, out) = run_cli(&["--help".to_string()], PathBuf::from("."), &env);
        assert_eq!(code, 0);
        assert!(out.contains("Usage:"));
    }
}
