//! Rust port of `scripts/release/admission.mjs` (Gate 0A — static source
//! closure for the Legion release chain). Admission runs before any platform
//! fanout, without release credentials, and refuses a dispatch whose source
//! identity, CI state, or version identity is not already closed. Every
//! check here is deterministic: it reads committed state and completed CI
//! conclusions, never model judgement.
//!
//! Ported faithfully, including `writeStageSummary` and `verifyEvidence`
//! (also defined in this JS file and re-exported by
//! `installer-release-chain.mjs`'s `admission`/`stage-summary`/
//! `evidence-verification` subcommands).

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use serde_json::{json, Value};

use super::paths::{is_stable_semver, read_json, sha256_file, write_json_pretty, ReleaseResult};

const REPOSITORY: &str = "Orthic-Labs/legion";
const CI_WORKFLOW: &str = "ci.yml";

#[derive(Debug, Clone)]
pub struct RequiredStage {
    pub stage: &'static str,
    pub platform: Option<&'static str>,
    pub architecture: Option<&'static str>,
}

/// Stages that must each carry a SUCCEEDED finalize stage-summary, bound to
/// this exact version + source revision + run, before publication may proceed.
pub const REQUIRED_RELEASE_STAGES: &[RequiredStage] = &[
    RequiredStage { stage: "candidate", platform: Some("windows"), architecture: Some("x86_64") },
    RequiredStage { stage: "candidate", platform: Some("macos"), architecture: Some("arm64") },
    RequiredStage { stage: "windows-sign", platform: Some("windows"), architecture: Some("x86_64") },
    RequiredStage { stage: "macos-sign", platform: Some("macos"), architecture: Some("arm64") },
    RequiredStage { stage: "installed-qualification", platform: None, architecture: None },
];

fn repo_root() -> PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        dir = PathBuf::from(manifest_dir);
    }
    dir.pop(); // engine/xtask -> engine
    dir.pop(); // engine -> repo root
    dir
}

struct GitResult {
    status: Option<i32>,
    stdout: String,
    stderr: String,
}

fn git(root: &Path, args: &[&str]) -> GitResult {
    match Command::new("git").args(args).current_dir(root).output() {
        Ok(output) => GitResult {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(err) => GitResult { status: None, stdout: String::new(), stderr: err.to_string() },
    }
}

fn gh(root: &Path, args: &[&str]) -> GitResult {
    match Command::new("gh").args(args).current_dir(root).output() {
        Ok(output) => GitResult {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        Err(err) => GitResult { status: None, stdout: String::new(), stderr: err.to_string() },
    }
}

fn declared_version(root: &Path) -> ReleaseResult<String> {
    let path = root.join("release").join("version.json");
    if !path.exists() {
        return Err("release chain admission requires release/version.json".to_string());
    }
    let parsed = read_json(&path, "release/version.json")?;
    match parsed.get("version").and_then(Value::as_str) {
        Some(v) => Ok(v.to_string()),
        None => Err("release/version.json does not declare a version".to_string()),
    }
}

/// The admission job checks out the dispatched revision, so comparing against
/// HEAD would be tautological. Ancestry is proven against the real remote
/// ref, fetching it explicitly when the remote-tracking ref is not present.
pub fn assert_source_revision_is_ancestor_of_main(root: &Path, revision: &str, remote: &str, branch: &str) -> ReleaseResult<()> {
    let refname = format!("{remote}/{branch}");
    if git(root, &["rev-parse", "--verify", "-q", &refname]).status != Some(0) {
        if git(root, &["fetch", remote, branch]).status != Some(0) {
            return Err(format!("release chain admission could not fetch {remote} {branch} to verify ancestry"));
        }
        if git(root, &["rev-parse", "--verify", "-q", &refname]).status != Some(0) {
            return Err(format!("release chain admission could not resolve {refname} after fetch"));
        }
    }
    if git(root, &["merge-base", "--is-ancestor", revision, &refname]).status != Some(0) {
        return Err(format!("release chain admission source revision is not an ancestor of {refname}"));
    }
    Ok(())
}

pub fn tag_or_release_exists(root: &Path, version: &str) -> bool {
    let tag = format!("v{version}");
    if git(root, &["ls-remote", "--exit-code", "--tags", "origin", &format!("refs/tags/{tag}")]).status == Some(0) {
        return true;
    }
    gh(root, &["release", "view", &tag, "--repo", REPOSITORY, "--json", "tagName"]).status == Some(0)
}

/// Gate 0A: same-SHA CI must be terminal and green. A release admitted while
/// its own CI is still running can be authorized by a run that later turns
/// red, which is exactly how one Membrane release began against a red tree.
pub fn assert_same_sha_ci_is_green(root: &Path, revision: &str) -> ReleaseResult<()> {
    let listed = gh(
        root,
        &["run", "list", "--repo", REPOSITORY, "--commit", revision, "--workflow", CI_WORKFLOW, "--json", "status,conclusion,databaseId", "--limit", "25"],
    );
    if listed.status != Some(0) {
        return Err(format!("release chain admission could not read same-SHA CI runs: {}", listed.stderr.trim()));
    }
    let runs: Value = serde_json::from_str(&listed.stdout).map_err(|_| "release chain admission could not parse same-SHA CI runs".to_string())?;
    let runs = runs.as_array().cloned().unwrap_or_default();
    if runs.is_empty() {
        return Err(format!("release chain admission found no {CI_WORKFLOW} run for {revision}"));
    }
    let unfinished: Vec<&Value> = runs.iter().filter(|r| r.get("status").and_then(Value::as_str) != Some("completed")).collect();
    if !unfinished.is_empty() {
        return Err(format!("release chain admission requires terminal same-SHA CI; {} run(s) still in progress", unfinished.len()));
    }
    if !runs.iter().any(|r| r.get("conclusion").and_then(Value::as_str) == Some("success")) {
        return Err(format!("release chain admission requires a successful {CI_WORKFLOW} run for {revision}"));
    }
    let failed: Vec<String> = runs
        .iter()
        .filter(|r| {
            let conclusion = r.get("conclusion").and_then(Value::as_str);
            conclusion != Some("success") && conclusion != Some("cancelled") && conclusion != Some("skipped")
        })
        .map(|r| format!("{}:{}", r.get("databaseId").map(|v| v.to_string()).unwrap_or_default(), r.get("conclusion").and_then(Value::as_str).unwrap_or("null")))
        .collect();
    if !failed.is_empty() {
        return Err(format!("release chain admission found a non-green same-SHA CI run: {}", failed.join(", ")));
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct AdmissionResult {
    pub status: &'static str,
    pub version: String,
    #[serde(rename = "sourceRevision")]
    pub source_revision: String,
    #[serde(rename = "signedQualification")]
    pub signed_qualification: bool,
    pub publish: bool,
}

fn env_get(env: &HashMap<String, String>, key: &str) -> String {
    env.get(key).cloned().unwrap_or_default()
}

pub fn admit_release(env: &HashMap<String, String>, root: &Path) -> ReleaseResult<AdmissionResult> {
    let output_path = env_get(env, "GITHUB_OUTPUT");
    if output_path.is_empty() {
        return Err("release chain admission requires GITHUB_OUTPUT".to_string());
    }
    // dry_run: a rehearsal dispatch from a branch that exercises packaging,
    // signing & installed qualification with publication skipped, so the
    // first real dispatch is never the first execution. It accepts any
    // refs/heads/* ref, skips the first-attempt and tag/release-existence
    // checks, and refuses to be combined with publish=true.
    let dry_run = env_get(env, "RIGHT_GIT_DRY_RUN") == "true";
    let workflow_ref = env_get(env, "RIGHT_GIT_WORKFLOW_REF");
    if dry_run {
        if !workflow_ref.starts_with("refs/heads/") || workflow_ref == "refs/heads/" {
            return Err(format!("release chain admission dry run requires dispatch from a branch (refs/heads/*), got: {workflow_ref}"));
        }
    } else if workflow_ref != "refs/heads/main" {
        return Err(format!("release chain admission requires dispatch from refs/heads/main, got: {workflow_ref}"));
    }
    let run_attempt = env_get(env, "RIGHT_GIT_RUN_ATTEMPT");
    if !dry_run {
        let is_digits = !run_attempt.is_empty() && run_attempt.chars().all(|c| c.is_ascii_digit());
        if !is_digits || run_attempt.parse::<i64>() != Ok(1) {
            return Err(format!("release chain admission requires the first run attempt, got: {run_attempt}"));
        }
    }
    let release_version = env_get(env, "RIGHT_GIT_RELEASE_VERSION");
    if !is_stable_semver(&release_version) {
        return Err(format!("release chain admission requires an exact semver release version, got: {release_version}"));
    }
    if dry_run && env_get(env, "RIGHT_GIT_PUBLISH") == "true" {
        return Err("release chain admission refuses publish=true together with dry_run=true".to_string());
    }

    // Version/tag/release contradiction: the dispatched version must be the
    // one the frozen source actually declares, or the built artifacts carry
    // a different version than the tag they are published under.
    let declared = declared_version(root)?;
    if declared != release_version {
        return Err(format!("release chain admission version {release_version} contradicts release/version.json {declared}"));
    }

    let revision = env_get(env, "RIGHT_GIT_SOURCE_REVISION");
    let is_sha40 = revision.len() == 40 && revision.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if !is_sha40 {
        return Err("release chain admission requires an exact 40-character lowercase source revision SHA".to_string());
    }
    if git(root, &["cat-file", "-e", &format!("{revision}^{{commit}}")]).status != Some(0) {
        return Err("release chain admission source revision does not resolve to a known commit".to_string());
    }
    // A dry run accepts any branch ref, so the source revision need not yet
    // be an ancestor of main; the tag/release-existence check is skipped too
    // because a rehearsal never publishes. Same-SHA CI must still be green.
    if !dry_run {
        assert_source_revision_is_ancestor_of_main(root, &revision, "origin", "main")?;
    }
    assert_same_sha_ci_is_green(root, &revision)?;

    let signed_qualification = env_get(env, "RIGHT_GIT_SIGNED_QUALIFICATION") == "true";
    let publish = env_get(env, "RIGHT_GIT_PUBLISH") == "true";
    if publish && !signed_qualification {
        return Err("release chain admission requires signed_qualification=true whenever publish=true".to_string());
    }
    if !dry_run && tag_or_release_exists(root, &release_version) {
        return Err(format!("release chain admission version v{release_version} already has a tag or release (drafts included)"));
    }

    let mut file = fs::OpenOptions::new().append(true).create(true).open(&output_path).map_err(|e| format!("could not open GITHUB_OUTPUT: {e}"))?;
    for (key, value) in [
        ("version", release_version.clone()),
        ("source_revision", revision.clone()),
        ("signed_qualification", signed_qualification.to_string()),
        ("publish", publish.to_string()),
        ("dry_run", dry_run.to_string()),
        ("artifact_suffix", if dry_run { "-dry-run".to_string() } else { String::new() }),
    ] {
        writeln!(file, "{key}={value}").map_err(|e| format!("could not write GITHUB_OUTPUT: {e}"))?;
    }

    Ok(AdmissionResult { status: "admitted", version: release_version, source_revision: revision, signed_qualification, publish })
}

fn collect_evidence_files(root: Option<&Path>) -> ReleaseResult<Vec<Value>> {
    let Some(root) = root else { return Ok(vec![]) };
    if !root.exists() {
        return Ok(vec![]);
    }
    let mut out = vec![];
    collect_evidence_files_walk(root, root, &mut out)?;
    Ok(out)
}

fn collect_evidence_files_walk(base: &Path, dir: &Path, out: &mut Vec<Value>) -> ReleaseResult<()> {
    let entries = fs::read_dir(dir).map_err(|e| format!("failed to list {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if meta.is_dir() {
            collect_evidence_files_walk(base, &path, out)?;
        } else if meta.is_file() {
            let rel = path.strip_prefix(base).unwrap_or(&path).to_string_lossy().replace('\\', "/");
            out.push(json!({ "name": rel, "sha256": sha256_file(&path)?, "size": meta.len() }));
        }
    }
    Ok(())
}

pub fn write_stage_summary(env: &HashMap<String, String>) -> ReleaseResult<Value> {
    let action = env_get(env, "RIGHT_GIT_STAGE_ACTION");
    if action != "init" && action != "finalize" {
        return Err(format!("release chain stage-summary requires RIGHT_GIT_STAGE_ACTION of init or finalize, got: {action}"));
    }
    let stage_root = env_get(env, "RIGHT_GIT_STAGE_ROOT");
    if stage_root.is_empty() {
        return Err("release chain stage-summary requires RIGHT_GIT_STAGE_ROOT".to_string());
    }
    let stage = env_get(env, "RIGHT_GIT_STAGE");
    if stage.is_empty() {
        return Err("release chain stage-summary requires RIGHT_GIT_STAGE".to_string());
    }
    let release_version = env_get(env, "RIGHT_GIT_RELEASE_VERSION");
    let revision = env_get(env, "RIGHT_GIT_SOURCE_REVISION");
    if release_version.is_empty() || revision.is_empty() {
        return Err("release chain stage-summary requires RIGHT_GIT_RELEASE_VERSION & RIGHT_GIT_SOURCE_REVISION".to_string());
    }
    let mut status = "STARTED".to_string();
    let mut exit_code: Option<i64> = None;
    if action == "finalize" {
        status = env_get(env, "RIGHT_GIT_STAGE_STATUS").to_uppercase();
        if status != "SUCCEEDED" && status != "FAILED" {
            return Err(format!("release chain stage-summary requires RIGHT_GIT_STAGE_STATUS of succeeded or failed, got: {}", env_get(env, "RIGHT_GIT_STAGE_STATUS")));
        }
        let raw = env_get(env, "RIGHT_GIT_STAGE_EXIT_CODE");
        let parsed: Option<i64> = raw.parse().ok();
        let Some(code) = parsed else {
            return Err("release chain stage-summary finalize requires a numeric RIGHT_GIT_STAGE_EXIT_CODE".to_string());
        };
        exit_code = Some(code);
        if status == "SUCCEEDED" && code != 0 {
            return Err("release chain stage-summary cannot mark a nonzero exit code SUCCEEDED".to_string());
        }
    }
    let stage_root_path = Path::new(&stage_root);
    fs::create_dir_all(stage_root_path).map_err(|e| format!("could not create {stage_root}: {e}"))?;
    let optional = |key: &str| -> Value {
        let v = env_get(env, key);
        if v.is_empty() { Value::Null } else { Value::String(v) }
    };
    let evidence_root = env.get("RIGHT_GIT_STAGE_EVIDENCE_ROOT").map(|s| PathBuf::from(s));
    let summary = json!({
        "schemaVersion": 1,
        "stage": stage,
        "action": action,
        "producer": optional("RIGHT_GIT_STAGE_PRODUCER"),
        "status": status,
        "exitCode": exit_code,
        "version": release_version,
        "sourceRevision": revision,
        "platform": optional("RIGHT_GIT_RELEASE_PLATFORM"),
        "architecture": optional("RIGHT_GIT_RELEASE_ARCHITECTURE"),
        "runId": optional("RIGHT_GIT_RUN_ID"),
        "runAttempt": optional("RIGHT_GIT_RUN_ATTEMPT"),
        "evidence": collect_evidence_files(evidence_root.as_deref())?,
        "recordedAt": now_iso8601(),
    });
    write_json_pretty(&stage_root_path.join("stage-summary.json"), &summary)?;
    Ok(summary)
}

fn now_iso8601() -> String {
    // No chrono dependency in this crate's workspace deps; a lightweight
    // manual UTC formatter (matches `new Date().toISOString()`'s shape:
    // this field is evidence metadata only and is never compared by
    // `verifyEvidence`, so sub-second precision parity is not required).
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let (h, m, s) = (time_of_day / 3600, (time_of_day % 3600) / 60, time_of_day % 60);
    let mut year = 1970i64;
    let mut remaining_days = days as i64;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let year_days = if leap { 366 } else { 365 };
        if remaining_days < year_days {
            break;
        }
        remaining_days -= year_days;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_lengths = if leap { [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] } else { [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] };
    let mut month = 1;
    for len in month_lengths {
        if remaining_days < len {
            break;
        }
        remaining_days -= len;
        month += 1;
    }
    let day = remaining_days + 1;
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

fn find_stage_summaries(root: &Path) -> ReleaseResult<Vec<Value>> {
    if !root.exists() {
        return Err(format!("release chain evidence-verification root is missing: {}", root.display()));
    }
    let mut out = vec![];
    find_stage_summaries_walk(root, &mut out)?;
    Ok(out)
}

fn find_stage_summaries_walk(dir: &Path, out: &mut Vec<Value>) -> ReleaseResult<()> {
    let entries = fs::read_dir(dir).map_err(|e| format!("failed to list {}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let path = entry.path();
        let meta = fs::symlink_metadata(&path).map_err(|e| e.to_string())?;
        if meta.is_dir() {
            find_stage_summaries_walk(&path, out)?;
        } else if meta.is_file() && path.file_name().map(|n| n == "stage-summary.json").unwrap_or(false) {
            let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
            out.push(serde_json::from_str(&text).map_err(|e| format!("invalid stage-summary.json at {}: {e}", path.display()))?);
        }
    }
    Ok(())
}

pub fn verify_evidence(env: &HashMap<String, String>) -> ReleaseResult<Value> {
    let release_version = env_get(env, "RIGHT_GIT_RELEASE_VERSION");
    let revision = env_get(env, "RIGHT_GIT_SOURCE_REVISION");
    let run_id = env_get(env, "RIGHT_GIT_RUN_ID");
    let run_attempt = env_get(env, "RIGHT_GIT_RUN_ATTEMPT");
    let stage_summary_root = env_get(env, "RIGHT_GIT_STAGE_SUMMARY_ROOT");
    if release_version.is_empty() || revision.is_empty() || run_id.is_empty() || run_attempt.is_empty() || stage_summary_root.is_empty() {
        return Err("release chain evidence-verification requires RIGHT_GIT_RELEASE_VERSION, RIGHT_GIT_SOURCE_REVISION, RIGHT_GIT_RUN_ID, RIGHT_GIT_RUN_ATTEMPT & RIGHT_GIT_STAGE_SUMMARY_ROOT".to_string());
    }
    let all_summaries = find_stage_summaries(Path::new(&stage_summary_root))?;
    let summaries: Vec<Value> = all_summaries
        .into_iter()
        .filter(|s| {
            s.get("action").and_then(Value::as_str) == Some("finalize")
                && s.get("version").and_then(Value::as_str) == Some(release_version.as_str())
                && s.get("sourceRevision").and_then(Value::as_str) == Some(revision.as_str())
                && s.get("runId").map(|v| v.to_string().trim_matches('"').to_string()) == Some(run_id.clone())
                && s.get("runAttempt").map(|v| v.to_string().trim_matches('"').to_string()) == Some(run_attempt.clone())
        })
        .collect();
    for required in REQUIRED_RELEASE_STAGES {
        let label = match required.platform {
            Some(p) => format!("{} ({}/{})", required.stage, p, required.architecture.unwrap_or("")),
            None => required.stage.to_string(),
        };
        let found = summaries.iter().find(|s| {
            s.get("stage").and_then(Value::as_str) == Some(required.stage)
                && required.platform.map(|p| s.get("platform").and_then(Value::as_str) == Some(p)).unwrap_or(true)
                && required.architecture.map(|a| s.get("architecture").and_then(Value::as_str) == Some(a)).unwrap_or(true)
        });
        let Some(found) = found else {
            return Err(format!("release chain evidence-verification is missing a required stage summary: {label}"));
        };
        if found.get("status").and_then(Value::as_str) != Some("SUCCEEDED") {
            return Err(format!("release chain evidence-verification stage did not succeed: {label}"));
        }
    }
    Ok(json!({
        "schemaVersion": 1,
        "verified": true,
        "version": release_version,
        "sourceRevision": revision,
        "runId": run_id,
        "runAttempt": run_attempt,
        "stages": summaries.iter().map(|s| json!({
            "stage": s.get("stage"),
            "platform": s.get("platform"),
            "architecture": s.get("architecture"),
            "status": s.get("status"),
        })).collect::<Vec<_>>(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("legion-admission-{name}-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn base_env(output: &Path) -> HashMap<String, String> {
        HashMap::from([
            ("GITHUB_OUTPUT".to_string(), output.to_string_lossy().to_string()),
            ("RIGHT_GIT_WORKFLOW_REF".to_string(), "refs/heads/main".to_string()),
            ("RIGHT_GIT_RUN_ATTEMPT".to_string(), "1".to_string()),
            ("RIGHT_GIT_RELEASE_VERSION".to_string(), "0.0.0".to_string()),
            ("RIGHT_GIT_SOURCE_REVISION".to_string(), "0".repeat(40)),
        ])
    }

    #[test]
    fn admission_requires_github_output() {
        let env = HashMap::new();
        let err = admit_release(&env, Path::new(".")).unwrap_err();
        assert!(err.contains("GITHUB_OUTPUT"));
    }

    #[test]
    fn admission_refuses_non_main_ref() {
        let dir = scratch("attempt");
        let output = dir.join("out.txt");
        fs::write(&output, "").unwrap();
        let mut env = base_env(&output);
        env.insert("RIGHT_GIT_WORKFLOW_REF".to_string(), "refs/heads/topic".to_string());
        let err = admit_release(&env, Path::new(".")).unwrap_err();
        assert!(err.contains("refs/heads/main"), "{err}");
    }

    #[test]
    fn admission_refuses_non_first_attempt() {
        let dir = scratch("attempt2");
        let output = dir.join("out.txt");
        fs::write(&output, "").unwrap();
        let mut env = base_env(&output);
        env.insert("RIGHT_GIT_RUN_ATTEMPT".to_string(), "2".to_string());
        let err = admit_release(&env, Path::new(".")).unwrap_err();
        assert!(err.contains("first run attempt"), "{err}");
    }

    #[test]
    fn admission_requires_exact_semver() {
        let dir = scratch("version");
        let output = dir.join("out.txt");
        fs::write(&output, "").unwrap();
        let mut env = base_env(&output);
        env.insert("RIGHT_GIT_RELEASE_VERSION".to_string(), "0.3".to_string());
        let err = admit_release(&env, Path::new(".")).unwrap_err();
        assert!(err.contains("exact semver"), "{err}");
    }

    #[test]
    fn dry_run_requires_branch_ref() {
        let dir = scratch("dryrun");
        let output = dir.join("out.txt");
        fs::write(&output, "").unwrap();
        let mut env = base_env(&output);
        env.insert("RIGHT_GIT_DRY_RUN".to_string(), "true".to_string());
        env.insert("RIGHT_GIT_WORKFLOW_REF".to_string(), "refs/tags/v9.9.9".to_string());
        let err = admit_release(&env, Path::new(".")).unwrap_err();
        assert!(err.contains("requires dispatch from a branch"), "{err}");
    }

    #[test]
    fn dry_run_refuses_publish_true() {
        let dir = scratch("dryrun2");
        let output = dir.join("out.txt");
        fs::write(&output, "").unwrap();
        let mut env = base_env(&output);
        env.insert("RIGHT_GIT_DRY_RUN".to_string(), "true".to_string());
        env.insert("RIGHT_GIT_WORKFLOW_REF".to_string(), "refs/heads/topic".to_string());
        env.insert("RIGHT_GIT_PUBLISH".to_string(), "true".to_string());
        let err = admit_release(&env, Path::new(".")).unwrap_err();
        assert!(err.contains("refuses publish=true together with dry_run=true"), "{err}");
    }

    #[test]
    fn stage_summary_cannot_mark_nonzero_exit_succeeded() {
        let root = scratch("stage");
        let mut env = HashMap::new();
        env.insert("RIGHT_GIT_STAGE_ACTION".to_string(), "finalize".to_string());
        env.insert("RIGHT_GIT_STAGE_ROOT".to_string(), root.to_string_lossy().to_string());
        env.insert("RIGHT_GIT_STAGE".to_string(), "candidate".to_string());
        env.insert("RIGHT_GIT_RELEASE_VERSION".to_string(), "0.3.12".to_string());
        env.insert("RIGHT_GIT_SOURCE_REVISION".to_string(), "a".repeat(40));
        env.insert("RIGHT_GIT_STAGE_STATUS".to_string(), "succeeded".to_string());
        env.insert("RIGHT_GIT_STAGE_EXIT_CODE".to_string(), "2".to_string());
        let err = write_stage_summary(&env).unwrap_err();
        assert!(err.contains("nonzero exit code"), "{err}");

        env.insert("RIGHT_GIT_STAGE_EXIT_CODE".to_string(), "0".to_string());
        let ok = write_stage_summary(&env).unwrap();
        assert_eq!(ok.get("status").and_then(Value::as_str), Some("SUCCEEDED"));
        let written: Value = serde_json::from_str(&fs::read_to_string(root.join("stage-summary.json")).unwrap()).unwrap();
        assert_eq!(written.get("stage").and_then(Value::as_str), Some("candidate"));
    }

    #[test]
    fn evidence_verification_refuses_incomplete_stages() {
        let root = scratch("evidence");
        let stage = root.join("candidate-windows");
        fs::create_dir_all(&stage).unwrap();
        fs::write(
            stage.join("stage-summary.json"),
            serde_json::to_string(&json!({
                "schemaVersion": 1, "stage": "candidate", "action": "finalize", "status": "SUCCEEDED",
                "version": "0.3.12", "sourceRevision": "a".repeat(40), "platform": "windows", "architecture": "x86_64",
                "runId": "1", "runAttempt": "1",
            })).unwrap(),
        ).unwrap();
        let mut env = HashMap::new();
        env.insert("RIGHT_GIT_RELEASE_VERSION".to_string(), "0.3.12".to_string());
        env.insert("RIGHT_GIT_SOURCE_REVISION".to_string(), "a".repeat(40));
        env.insert("RIGHT_GIT_RUN_ID".to_string(), "1".to_string());
        env.insert("RIGHT_GIT_RUN_ATTEMPT".to_string(), "1".to_string());
        env.insert("RIGHT_GIT_STAGE_SUMMARY_ROOT".to_string(), root.to_string_lossy().to_string());
        let err = verify_evidence(&env).unwrap_err();
        assert!(err.contains("missing a required stage summary"), "{err}");
    }
}
