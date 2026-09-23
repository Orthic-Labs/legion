//! Port of the pure, non-spawning logic in `tools/audit/audit-verify.mjs`.
//!
//! `audit-verify.mjs` is an out-of-band CLI: it reads two prior JSON
//! artifacts (`facts.json`, `plan.json`), recomputes a Blueprint-backed audit
//! plan (`buildAuditPlan`, from `tools/audit/audit-plan.mjs` — a Blueprint
//! adapter this chunk's DROP rule keeps out of scope), and spawns
//! `collect-facts.mjs` again under an offline environment to replay
//! deterministic checks. None of that — plan recomputation, Blueprint
//! binding, or child-process replay — is a pure function of its inputs, so
//! it is not ported.
//!
//! What is pure and ported here is the drift/classification arithmetic the
//! CLI's `console.log` narration is built from:
//!
//! - `PROJECT_EXECUTION_CHECKS` / `classify_unproven_checks` — which planned
//!   checks the verifier can legitimately replay, given whether the network
//!   sandbox is active (`build` is always excluded by design; a
//!   project-executing check is blocked without an active sandbox).
//! - `child_env` — the fixed allowlist that filters the *parent* process
//!   environment down to the safe subset passed to the replayed
//!   `collect-facts.mjs` child (`ALLOWED_CHILD_KEYS`), plus the offline
//!   overrides (`AUDIT_OFFLINE=1`, `npm_config_offline=true`, ...).
//! - `normalize_checks` / `result_digest` — the check-list canonicalization
//!   and digest used to compare a prior report's checks against a replay's.
//! - `frozen_contract_digest` — the subset of a plan (`registryDigest`,
//!   `denominator`, `providers[]` sans volatile fields, `coverageFamilies`)
//!   whose equality gates "MATCH registry digest, provider contracts, and
//!   denominators" vs. "DRIFT".

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

/// `PROJECT_EXECUTION_CHECKS`: checks that execute project code (install,
/// compile, run a linter over the whole tree, ...) rather than only reading
/// tracked files — these require the network sandbox to be active before a
/// verifier replay may run them.
pub fn project_execution_checks() -> BTreeSet<&'static str> {
    [
        "types",
        "lint",
        "build",
        "dead_code",
        "duplication",
        "ci_lint",
        "docker",
        "sast",
        "swift_lint",
        "js_licenses",
        "cargo_unsafe",
        "cargo_unused_deps",
    ]
    .into_iter()
    .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct CheckReplayPlan {
    /// Checks the verifier will attempt to replay.
    pub replayable: Vec<String>,
    /// Checks classified UNPROVEN, in the order they were first excluded:
    /// `build` (always, by design) then any project-executing check blocked
    /// by an inactive network sandbox — de-duplicated exactly as the JS
    /// `[...new Set([...buildExcluded, ...blockedChecks])]` does.
    pub unproven: Vec<String>,
    /// Whether any blocked (non-`build`) check was excluded because the
    /// sandbox was inactive — feeds the UNPROVEN log line's explanatory
    /// clause.
    pub sandbox_blocked_any: bool,
}

/// `unprovenChecks` classification: given the plan's `denominator.expectedChecks`
/// and whether the network sandbox is active, split into replayable vs.
/// unproven, exactly matching the JS `blockedChecks`/`buildExcluded`/
/// `unprovenChecks`/`checks` derivation.
pub fn classify_replay(planned_checks: &[String], network_sandbox_active: bool) -> CheckReplayPlan {
    let project_checks = project_execution_checks();
    let blocked_checks: Vec<String> = if network_sandbox_active {
        Vec::new()
    } else {
        planned_checks
            .iter()
            .filter(|c| project_checks.contains(c.as_str()))
            .cloned()
            .collect()
    };
    let build_excluded: Vec<String> = planned_checks
        .iter()
        .filter(|c| c.as_str() == "build")
        .cloned()
        .collect();

    let mut seen = BTreeSet::new();
    let mut unproven = Vec::new();
    for c in build_excluded.iter().chain(blocked_checks.iter()) {
        if seen.insert(c.clone()) {
            unproven.push(c.clone());
        }
    }

    let replayable: Vec<String> = planned_checks
        .iter()
        .filter(|c| !unproven.contains(c))
        .cloned()
        .collect();

    CheckReplayPlan {
        replayable,
        sandbox_blocked_any: !blocked_checks.is_empty(),
        unproven,
    }
}

/// `ALLOWED_CHILD_KEYS`: the fixed environment-variable allowlist passed
/// through to a replayed `collect-facts.mjs` child process.
pub fn allowed_child_keys() -> BTreeSet<&'static str> {
    [
        "PATH", "Path", "HOME", "USER", "SHELL", "TERM", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP",
        "SYSTEMROOT", "PATHEXT", "COMSPEC", "WINDIR",
        "NODE", "NODE_PATH", "NODE_OPTIONS",
        "AUDIT_OFFLINE", "AUDIT_NETWORK_GUARD",
        "npm_config_offline", "CARGO_NET_OFFLINE", "PIP_NO_INDEX",
        "GOPROXY", "GOSUMDB", "BUNDLE_FROZEN", "MAVEN_ARGS", "GRADLE_OPTS",
        "CORTEX_BIN", "RESEARCH_RUN_ROOT",
        "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED",
    ]
    .into_iter()
    .collect()
}

/// `childEnv(overrides)`: filter `parent_env` down to `allowed_child_keys`,
/// then apply `overrides` (which may introduce keys outside the allowlist —
/// the JS spreads `overrides` last and unconditionally, same here).
pub fn child_env(
    parent_env: &BTreeMap<String, String>,
    overrides: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let allowed = allowed_child_keys();
    let mut env: BTreeMap<String, String> = parent_env
        .iter()
        .filter(|(k, _)| allowed.contains(k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for (k, v) in overrides {
        env.insert(k.clone(), v.clone());
    }
    env
}

/// `offlineEnv`: the fixed overrides applied on top of `child_env` for a
/// replay run. `maven_args`/`gradle_opts` are the parent's existing value
/// (if any) with the offline flag appended — mirrors the JS
/// `[process.env.MAVEN_ARGS, '-o'].filter(Boolean).join(' ')` join.
pub fn offline_env_overrides(parent_env: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let join_flag = |existing: Option<&String>, flag: &str| -> String {
        match existing {
            Some(v) if !v.is_empty() => format!("{v} {flag}"),
            _ => flag.to_string(),
        }
    };
    let mut out = BTreeMap::new();
    out.insert("AUDIT_OFFLINE".to_string(), "1".to_string());
    out.insert("npm_config_offline".to_string(), "true".to_string());
    out.insert("CARGO_NET_OFFLINE".to_string(), "true".to_string());
    out.insert("PIP_NO_INDEX".to_string(), "1".to_string());
    out.insert("GOPROXY".to_string(), "off".to_string());
    out.insert("GOSUMDB".to_string(), "off".to_string());
    out.insert("BUNDLE_FROZEN".to_string(), "true".to_string());
    out.insert(
        "MAVEN_ARGS".to_string(),
        join_flag(parent_env.get("MAVEN_ARGS"), "-o"),
    );
    out.insert(
        "GRADLE_OPTS".to_string(),
        join_flag(parent_env.get("GRADLE_OPTS"), "-Dorg.gradle.offline=true"),
    );
    out
}

/// A single replayed/reported check result's comparison-relevant fields
/// (`{status, findings_count}` — matches the JS `index()`/comparison in the
/// "check replay" loop).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CheckResult {
    pub check: String,
    pub status: String,
    #[serde(default)]
    pub findings_count: Option<i64>,
}

/// Does `left` (prior) match `right` (replay) on status + findings_count?
pub fn checks_match(left: Option<&CheckResult>, right: Option<&CheckResult>) -> bool {
    let (l_status, l_count) = match left {
        Some(c) => (Some(c.status.as_str()), c.findings_count),
        None => (None, None),
    };
    let (r_status, r_count) = match right {
        Some(c) => (Some(c.status.as_str()), c.findings_count),
        None => (None, None),
    };
    l_status == r_status && l_count == r_count
}

/// `normalizeChecks`: project to `{check, status, findings_count}` and sort
/// by `check` (locale compare ≈ byte compare for the ASCII check names used
/// here).
pub fn normalize_checks(checks: &[CheckResult]) -> Vec<CheckResult> {
    let mut out: Vec<CheckResult> = checks
        .iter()
        .map(|c| CheckResult {
            check: c.check.clone(),
            status: c.status.clone(),
            findings_count: c.findings_count,
        })
        .collect();
    out.sort_by(|a, b| a.check.cmp(&b.check));
    out
}

/// `sha256(canonicalJson(...))` over an arbitrary canonical-JSON-able value.
/// `serde_json::Value::Object` is a `BTreeMap` in this workspace (no
/// `preserve_order` feature on `serde_json`), so `serde_json::to_string`
/// already emits sorted-key canonical JSON.
pub fn canonical_digest<T: serde::Serialize>(value: &T) -> Result<String, String> {
    let canonical: serde_json::Value =
        serde_json::to_value(value).map_err(|e| format!("not serializable: {e}"))?;
    let bytes = serde_json::to_vec(&canonical).map_err(|e| format!("not serializable: {e}"))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// `priorResultDigest`/`freshResultDigest`: digest of the normalized check
/// list, for the "result digest" MATCH/DRIFT line.
pub fn result_digest(checks: &[CheckResult]) -> Result<String, String> {
    canonical_digest(&normalize_checks(checks))
}

/// The frozen subset of a plan compared by `frozenContract` — provider
/// records are stripped down to `{id, runner, denominator, benchmark,
/// conditionalActivation}` (`conditionalActivation` defaults to `null` when
/// absent, matching `?? null`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct FrozenProvider {
    pub id: serde_json::Value,
    pub runner: serde_json::Value,
    pub denominator: serde_json::Value,
    pub benchmark: serde_json::Value,
    #[serde(rename = "conditionalActivation")]
    pub conditional_activation: serde_json::Value,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct FrozenContract {
    #[serde(rename = "registryDigest")]
    pub registry_digest: serde_json::Value,
    pub denominator: serde_json::Value,
    pub providers: Vec<FrozenProvider>,
    #[serde(rename = "coverageFamilies")]
    pub coverage_families: serde_json::Value,
}

/// Build a `FrozenContract` from a generic plan `Value` (the plan schema
/// itself lives in `tools/audit/audit-plan.mjs`, out of this chunk's scope —
/// this projects the fields `frozenContract` reads, whatever the plan's full
/// shape is).
pub fn frozen_contract(plan: &serde_json::Value) -> FrozenContract {
    let providers = plan
        .get("providers")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    FrozenContract {
        registry_digest: plan
            .pointer("/binding/registryDigest")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        denominator: plan.get("denominator").cloned().unwrap_or(serde_json::Value::Null),
        providers: providers
            .iter()
            .map(|p| FrozenProvider {
                id: p.get("id").cloned().unwrap_or(serde_json::Value::Null),
                runner: p.get("runner").cloned().unwrap_or(serde_json::Value::Null),
                denominator: p.get("denominator").cloned().unwrap_or(serde_json::Value::Null),
                benchmark: p.get("benchmark").cloned().unwrap_or(serde_json::Value::Null),
                conditional_activation: p
                    .get("conditionalActivation")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
            })
            .collect(),
        coverage_families: plan
            .get("coverageFamilies")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
    }
}

/// `canonicalJson(frozenContract(priorPlan)) !== canonicalJson(frozenContract(recomputed))`
/// — true when the two plans' frozen contracts MATCH.
pub fn frozen_contracts_match(prior_plan: &serde_json::Value, recomputed_plan: &serde_json::Value) -> bool {
    let prior = canonical_digest(&frozen_contract(prior_plan));
    let recomputed = canonical_digest(&frozen_contract(recomputed_plan));
    match (prior, recomputed) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
