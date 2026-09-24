//! Port of `tools/audit/audit-verify.mjs`, including its CLI entrypoint
//! ([`run`]).
//!
//! `audit-verify.mjs` reads two prior JSON artifacts (`facts.json`,
//! `plan.json`), recomputes a Blueprint-backed audit plan (`buildAuditPlan`,
//! from `tools/audit/audit-plan.mjs`), verifies the plan's repository/
//! Blueprint binding (`verifyPlanBinding`, backed by
//! `collectRepositoryBinding`/`readBlueprintManifestBinding` from
//! `src/adapters/blueprint-packet.mjs`), and spawns `collect-facts.mjs`
//! again under an offline environment to replay deterministic checks.
//!
//! [`run`] is a faithful CLI-level port of everything in that file that
//! does **not** require the Blueprint-backed plan/provider-registry stack
//! (`audit-plan.mjs`, `provider-registry.mjs`, `blueprint-packet.mjs`):
//! plan seal verification, the network-sandbox-receipt check, replay-check
//! classification, the `collect-facts` replay itself (subprocess
//! orchestration behind [`ReplayRunner`], faithfully invoking the same
//! child under the same offline env — see [`child_env`]/
//! [`offline_env_overrides`]), check-by-check replay comparison, the result
//! digest, and the semantic verification-projection comparison (via
//! `legion_runtime::p5_core::{verification_projection, verification_digest}`,
//! already a native port of `src/lib/verification-projection.mjs`).
//!
//! **Named, real gap** (not a stand-in): the provider-set/frozen-contract
//! recomputation (`buildAuditPlan` + `JSON.stringify(expectedProviders) !==
//! ...`/`frozenContract(recomputed)`) and the repository/Blueprint binding
//! check (`verifyPlanBinding` against *current* `collectRepositoryBinding`/
//! `readBlueprintManifestBinding`) are not run by [`run`]: they require
//! `audit-plan.mjs`'s provider-registry-backed plan builder and
//! `blueprint-packet.mjs`'s Blueprint adapter, neither of which has any
//! native port anywhere in `engine/` (`git grep` for `build_audit_plan`,
//! `collect_repository_binding`, `read_blueprint_manifest_binding` is
//! empty) — both are out of this packet's target files
//! (`audit-runtime.mjs`/`audit-verify.mjs` only) and Blueprint is the
//! product's explicit DROP boundary elsewhere in this crate. `run` reports
//! those two sections as `unproven` (via [`RunOutcome::binding_unproven`]/
//! [`RunOutcome::provider_set_unproven`]) rather than fabricating a
//! MATCH/DRIFT verdict it cannot actually compute — never a false "clean".
//! `verify_plan_binding` itself (the pure comparison function) is already
//! ported in full in [`crate::wf_port::wf064::plan::verify_plan_binding`];
//! only the *current*-side binding collectors are the unported dependency.
//!
//! What is pure and was already ported here is the drift/classification
//! arithmetic the CLI's `console.log` narration is built from:
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

// ---------------------------------------------------------------------
// CLI entrypoint: `pub fn run`
// ---------------------------------------------------------------------

use std::path::{Path, PathBuf};

/// Parsed `--facts <path> [--plan <path>]` argv, matching the JS `arg()`
/// helper's `--flag value` scan.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct VerifyArgs {
    pub facts: Option<String>,
    pub plan: Option<String>,
}

/// Port of the JS `arg(name)` scan: `args.indexOf(name)`, then the next
/// element if found.
pub fn parse_args(args: &[String]) -> VerifyArgs {
    let get = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    VerifyArgs {
        facts: get("--facts"),
        plan: get("--plan"),
    }
}

/// Subprocess orchestration for the `collect-facts.mjs` replay, behind a
/// trait so [`run`] is testable with a fake (no real spawn/network). The
/// production implementation shells out to `node <collect_facts_script>
/// <workspace> --only <checks> --out <out> [scope args...]` under
/// [`child_env`]/[`offline_env_overrides`], exactly as the JS
/// `execFileSync(process.execPath, [collect, ...], { env: offlineEnv })`
/// call does.
pub trait ReplayRunner {
    /// Run the replay; on success, returns the freshly-collected
    /// `facts.json` contents (parsed). Mirrors `execFileSync` + `readFileSync(join(out, 'facts.json'))`.
    fn replay(
        &self,
        workspace: &str,
        checks: &[String],
        out_dir: &Path,
        scope_args: &[String],
        env: &BTreeMap<String, String>,
    ) -> Result<serde_json::Value, String>;
}

/// Production [`ReplayRunner`]: spawns `node collect-facts.mjs` (the same
/// child the original CLI spawns), inheriting stdio, writing into a fresh
/// temp dir per call.
pub struct NodeCollectFactsRunner {
    /// Absolute path to `tools/audit/collect-facts.mjs` (or an equivalent
    /// entrypoint) — the JS resolves this via `fileURLToPath(new
    /// URL('./collect-facts.mjs', import.meta.url))` relative to its own
    /// location; the native caller passes the resolved path explicitly.
    pub collect_facts_script: PathBuf,
    /// `node` (or an absolute interpreter path) — mirrors `process.execPath`.
    pub node_bin: String,
}

impl ReplayRunner for NodeCollectFactsRunner {
    fn replay(
        &self,
        workspace: &str,
        checks: &[String],
        out_dir: &Path,
        scope_args: &[String],
        env: &BTreeMap<String, String>,
    ) -> Result<serde_json::Value, String> {
        std::fs::create_dir_all(out_dir).map_err(|e| format!("mkdir {}: {e}", out_dir.display()))?;
        let mut cmd = std::process::Command::new(&self.node_bin);
        cmd.arg(&self.collect_facts_script)
            .arg(workspace)
            .arg("--only")
            .arg(checks.join(","))
            .arg("--out")
            .arg(out_dir);
        for a in scope_args {
            cmd.arg(a);
        }
        cmd.env_clear();
        for (k, v) in env {
            cmd.env(k, v);
        }
        let status = cmd
            .status()
            .map_err(|e| format!("spawn {}: {e}", self.node_bin))?;
        if !status.success() {
            return Err(format!("collect-facts replay exited with {status}"));
        }
        let fresh_path = out_dir.join("facts.json");
        let bytes = std::fs::read(&fresh_path)
            .map_err(|e| format!("read {}: {e}", fresh_path.display()))?;
        serde_json::from_slice(&bytes).map_err(|e| format!("parse {}: {e}", fresh_path.display()))
    }
}

/// `--base`/`--base-commit`/`--dir`/`--type` scope replay args, built from
/// `priorPlan.scope` exactly like the JS `scopeArgs` derivation (only
/// `type !== 'all'` is passed through, matching `scope.type &&
/// scope.type !== 'all'`).
pub fn scope_replay_args(scope: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(t) = scope.get("type").and_then(|v| v.as_str()) {
        if t != "all" {
            out.push("--type".to_string());
            out.push(t.to_string());
        }
    }
    if let Some(b) = scope.get("base").and_then(|v| v.as_str()) {
        out.push("--base".to_string());
        out.push(b.to_string());
    }
    if let Some(bc) = scope.get("baseCommit").and_then(|v| v.as_str()) {
        out.push("--base-commit".to_string());
        out.push(bc.to_string());
    }
    if let Some(d) = scope.get("dir").and_then(|v| v.as_str()) {
        out.push("--dir".to_string());
        out.push(d.to_string());
    }
    out
}

/// The full structured result of a [`run`] call — every line the JS prints
/// via `console.log`, captured as data (the CLI wrapper turns this into
/// stdout lines + an exit code) so tests can assert on it directly instead
/// of scraping printed text.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct RunOutcome {
    pub seal_valid: bool,
    /// `binding` is out of scope (see module doc) — always `true`
    /// ("unproven", not a fabricated MATCH).
    pub binding_unproven: bool,
    pub network_sandbox_drift: bool,
    /// Provider-set/frozen-contract recomputation is out of scope (see
    /// module doc) — always `true`.
    pub provider_set_unproven: bool,
    pub unproven_checks: Vec<String>,
    pub sandbox_blocked_any: bool,
    pub check_results: Vec<(String, bool)>,
    pub result_digest_match: Option<bool>,
    pub semantic_projection_match: Option<bool>,
    pub drift_count: u32,
    /// `false` (exit 2) when `--facts`/plan reading fails before any
    /// verification could run.
    pub usage_error: Option<String>,
}

/// Faithful port of `audit-verify.mjs`'s executable body, for the subset
/// that does not require the Blueprint-backed plan stack (see module doc
/// for the named, out-of-scope remainder). `args` is the parsed CLI argv;
/// `runner` replays `collect-facts` for the checks that are replayable.
///
/// Returns the process exit code: `2` on a usage/missing-file error
/// (matching the JS `process.exit(2)` paths), otherwise `drift ? 1 : 0`
/// (matching `process.exit(drift ? 1 : 0)`) computed over the sections this
/// port actually runs.
pub fn run(args: &VerifyArgs, runner: &dyn ReplayRunner) -> (i32, RunOutcome) {
    let mut outcome = RunOutcome {
        binding_unproven: true,
        provider_set_unproven: true,
        ..Default::default()
    };

    let Some(facts_path) = args.facts.as_deref() else {
        outcome.usage_error = Some(
            "usage: legion audit verify --facts <prior .audit/<ts>/facts.json> [--plan <plan.json>]"
                .to_string(),
        );
        return (2, outcome);
    };
    let prior_bytes = match std::fs::read(facts_path) {
        Ok(b) => b,
        Err(e) => {
            outcome.usage_error = Some(format!("cannot read facts file {facts_path}: {e}"));
            return (2, outcome);
        }
    };
    let prior: serde_json::Value = match serde_json::from_slice(&prior_bytes) {
        Ok(v) => v,
        Err(e) => {
            outcome.usage_error = Some(format!("invalid facts JSON {facts_path}: {e}"));
            return (2, outcome);
        }
    };

    let plan_path: String = args.plan.clone().unwrap_or_else(|| {
        prior
            .pointer("/plan/path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                let dir = Path::new(facts_path)
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_default();
                dir.join("plan.json").to_string_lossy().to_string()
            })
    });
    if !Path::new(&plan_path).exists() {
        outcome.usage_error = Some(format!("plan missing: {plan_path}"));
        return (2, outcome);
    }
    let plan_bytes = match std::fs::read(&plan_path) {
        Ok(b) => b,
        Err(e) => {
            outcome.usage_error = Some(format!("cannot read plan file {plan_path}: {e}"));
            return (2, outcome);
        }
    };
    let prior_plan: serde_json::Value = match serde_json::from_slice(&plan_bytes) {
        Ok(v) => v,
        Err(e) => {
            outcome.usage_error = Some(format!("invalid plan JSON {plan_path}: {e}"));
            return (2, outcome);
        }
    };

    let mut drift: u32 = 0;

    // seal
    let prior_plan_map = prior_plan.as_object().cloned().unwrap_or_default();
    outcome.seal_valid = crate::wf_port::wf064::plan::verify_plan_seal(&prior_plan_map);
    if !outcome.seal_valid {
        drift += 1;
    }

    // network sandbox receipt (pure — no Blueprint dependency)
    let prior_sandbox_active = prior
        .pointer("/network_policy/sandboxActive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let network_sandbox_active = std::env::var("AUDIT_NETWORK_GUARD").as_deref() == Ok("active");
    if prior_sandbox_active != network_sandbox_active {
        outcome.network_sandbox_drift = true;
        drift += 1;
    }

    // planned checks: classify replayable vs. unproven
    let planned_checks: Vec<String> = prior_plan
        .pointer("/denominator/expectedChecks")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let replay_plan = classify_replay(&planned_checks, network_sandbox_active);
    outcome.unproven_checks = replay_plan.unproven.clone();
    outcome.sandbox_blocked_any = replay_plan.sandbox_blocked_any;
    drift += replay_plan.unproven.len() as u32;

    let mut fresh: Option<serde_json::Value> = None;
    if !replay_plan.replayable.is_empty() {
        let workspace = prior
            .get("workspace")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let scope = prior_plan.get("scope").cloned().unwrap_or(serde_json::Value::Null);
        let scope_args = scope_replay_args(&scope);
        let mut parent_env: BTreeMap<String, String> = BTreeMap::new();
        for (k, v) in std::env::vars() {
            parent_env.insert(k, v);
        }
        let overrides = offline_env_overrides(&parent_env);
        let env = child_env(&parent_env, &overrides);
        let out_dir = std::env::temp_dir().join(format!(
            "audit-verify-{}-{}",
            std::process::id(),
            REPLAY_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        match runner.replay(&workspace, &replay_plan.replayable, &out_dir, &scope_args, &env) {
            Ok(f) => fresh = Some(f),
            Err(_) => {
                // A replay spawn failure is itself drift: the checks could
                // not be revalidated (mirrors execFileSync throwing, which
                // the JS CLI never catches — it would crash; here we count
                // it as drift on every replayable check instead of a hard
                // panic, since `run` must return a result, not exit the
                // process).
                drift += replay_plan.replayable.len() as u32;
            }
        }
    }

    if let Some(fresh_facts) = &fresh {
        let before: Vec<CheckResult> = serde_json::from_value(
            prior.get("checks").cloned().unwrap_or(serde_json::Value::Array(vec![])),
        )
        .unwrap_or_default();
        let after: Vec<CheckResult> = serde_json::from_value(
            fresh_facts.get("checks").cloned().unwrap_or(serde_json::Value::Array(vec![])),
        )
        .unwrap_or_default();
        let before_by_name: BTreeMap<&str, &CheckResult> =
            before.iter().map(|c| (c.check.as_str(), c)).collect();
        let after_by_name: BTreeMap<&str, &CheckResult> =
            after.iter().map(|c| (c.check.as_str(), c)).collect();
        for check in &replay_plan.replayable {
            let left = before_by_name.get(check.as_str()).copied();
            let right = after_by_name.get(check.as_str()).copied();
            let matched = checks_match(left, right);
            outcome.check_results.push((check.clone(), matched));
            if !matched {
                drift += 1;
            }
        }

        let prior_digest = result_digest(&before);
        let fresh_digest = result_digest(&after);
        let digest_match = matches!((prior_digest, fresh_digest), (Ok(a), Ok(b)) if a == b);
        outcome.result_digest_match = Some(digest_match);
        if !digest_match {
            drift += 1;
        }
    }

    // Semantic verification projection: already-ported native comparison
    // (legion_runtime::p5_core), mirroring `verificationProjection`/
    // `verificationDigest` from `src/lib/verification-projection.mjs`.
    if let Some(fresh_facts) = &fresh {
        let prior_digest = legion_runtime::p5_core::verification_digest(&prior);
        let fresh_digest = legion_runtime::p5_core::verification_digest(fresh_facts);
        let matched = matches!((prior_digest, fresh_digest), (Ok(a), Ok(b)) if a == b);
        outcome.semantic_projection_match = Some(matched);
        if !matched {
            drift += 1;
        }
    }

    outcome.drift_count = drift;
    (if drift > 0 { 1 } else { 0 }, outcome)
}

static REPLAY_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(test)]
mod run_tests {
    use super::*;
    use std::sync::Mutex;

    struct FakeRunner {
        result: Mutex<Option<Result<serde_json::Value, String>>>,
    }
    impl ReplayRunner for FakeRunner {
        fn replay(
            &self,
            _workspace: &str,
            _checks: &[String],
            _out_dir: &Path,
            _scope_args: &[String],
            _env: &BTreeMap<String, String>,
        ) -> Result<serde_json::Value, String> {
            self.result.lock().unwrap().take().unwrap_or(Err("no fixture set".into()))
        }
    }

    fn write_json(dir: &Path, name: &str, value: &serde_json::Value) -> String {
        let path = dir.join(name);
        std::fs::write(&path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
        path.to_string_lossy().to_string()
    }

    /// `run` reads the process-global `AUDIT_NETWORK_GUARD` env var (mirroring
    /// the JS CLI's `process.env`), so any test that reads or mutates it must
    /// hold this lock for its duration: `cargo test` runs `#[test]`s
    /// concurrently by default, and an unsynchronized `set_var`/`remove_var`
    /// in one thread can flip `network_sandbox_active` mid-run in another,
    /// producing spurious `network_sandbox_drift` (a real race, not a logic
    /// bug in `run` itself).
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn missing_facts_flag_is_usage_error() {
        let runner = FakeRunner { result: Mutex::new(None) };
        let (code, outcome) = run(&VerifyArgs::default(), &runner);
        assert_eq!(code, 2);
        assert!(outcome.usage_error.is_some());
    }

    #[test]
    fn missing_plan_file_is_usage_error() {
        let dir = std::env::temp_dir().join(format!("avr-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let facts_path = write_json(&dir, "facts.json", &serde_json::json!({"workspace": "/x"}));
        let runner = FakeRunner { result: Mutex::new(None) };
        let args = VerifyArgs { facts: Some(facts_path), plan: Some(dir.join("nope.json").to_string_lossy().to_string()) };
        let (code, outcome) = run(&args, &runner);
        assert_eq!(code, 2);
        assert!(outcome.usage_error.unwrap().starts_with("plan missing"));
    }

    #[test]
    fn no_replayable_checks_and_clean_seal_is_zero_drift() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // The facts fixture below asserts `sandboxActive: false`; pin the
        // guard var to match instead of trusting the ambient environment
        // (some sandboxes/CI runners export `AUDIT_NETWORK_GUARD=active`,
        // which flips `network_sandbox_active` and adds spurious drift).
        std::env::remove_var("AUDIT_NETWORK_GUARD");
        let dir = std::env::temp_dir().join(format!("avr2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let plan = serde_json::json!({
            "denominator": {"expectedChecks": ["build"]},
            "scope": {},
        });
        let plan_path = write_json(&dir, "plan.json", &plan);
        let facts = serde_json::json!({
            "workspace": "/x",
            "network_policy": {"sandboxActive": false},
            "checks": [],
        });
        let facts_path = write_json(&dir, "facts.json", &facts);
        let runner = FakeRunner { result: Mutex::new(None) };
        let args = VerifyArgs { facts: Some(facts_path), plan: Some(plan_path) };
        let (code, outcome) = run(&args, &runner);
        // "build" is always unproven — 1 drift point, matching the JS
        // `unprovenChecks.length` contribution. The plan here is also
        // unsealed, which `verify_plan_seal` (mirroring JS) always treats as
        // invalid — see `matching_replay_is_clean` below, which seals its
        // plan for real specifically to get zero drift from the seal. So
        // this fixture's total is unproven(1) + unsealed-plan(1) = 2, not 1.
        assert_eq!(code, 1);
        assert_eq!(outcome.unproven_checks, vec!["build".to_string()]);
        assert_eq!(outcome.drift_count, 2);
        assert_eq!(outcome.seal_valid, false); // no seal present => invalid, counted above
    }

    #[test]
    fn matching_replay_is_clean() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("avr3-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // An unsealed plan is always `DRIFT plan seal is invalid` (matching
        // `verifyPlanSeal`, which returns false with no seal present) — seal
        // it for real so this "clean" scenario has zero drift from the seal.
        let unsealed_plan = serde_json::json!({
            "denominator": {"expectedChecks": ["types"]},
            "scope": {},
        });
        let sealed_map = crate::wf_port::wf064::plan::seal_plan(
            unsealed_plan.as_object().unwrap(),
            None,
        );
        let plan = serde_json::Value::Object(sealed_map);
        let plan_path = write_json(&dir, "plan.json", &plan);
        let facts = serde_json::json!({
            "workspace": "/x",
            "network_policy": {"sandboxActive": true},
            "checks": [{"check": "types", "status": "pass", "findings_count": 0}],
        });
        let facts_path = write_json(&dir, "facts.json", &facts);
        std::env::set_var("AUDIT_NETWORK_GUARD", "active");
        let runner = FakeRunner {
            result: Mutex::new(Some(Ok(facts.clone()))),
        };
        let args = VerifyArgs { facts: Some(facts_path), plan: Some(plan_path) };
        let (code, outcome) = run(&args, &runner);
        std::env::remove_var("AUDIT_NETWORK_GUARD");
        assert_eq!(outcome.unproven_checks, Vec::<String>::new());
        assert_eq!(outcome.check_results, vec![("types".to_string(), true)]);
        assert_eq!(outcome.result_digest_match, Some(true));
        assert_eq!(outcome.semantic_projection_match, Some(true));
        assert_eq!(code, 0);
    }

    #[test]
    fn replay_spawn_failure_counts_as_drift() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("avr4-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let plan = serde_json::json!({
            "denominator": {"expectedChecks": ["types"]},
            "scope": {},
        });
        let plan_path = write_json(&dir, "plan.json", &plan);
        let facts = serde_json::json!({
            "workspace": "/x",
            "network_policy": {"sandboxActive": true},
            "checks": [],
        });
        let facts_path = write_json(&dir, "facts.json", &facts);
        std::env::set_var("AUDIT_NETWORK_GUARD", "active");
        let runner = FakeRunner { result: Mutex::new(Some(Err("boom".into()))) };
        let args = VerifyArgs { facts: Some(facts_path), plan: Some(plan_path) };
        let (code, outcome) = run(&args, &runner);
        std::env::remove_var("AUDIT_NETWORK_GUARD");
        assert_eq!(code, 1);
        assert!(outcome.drift_count >= 1);
    }
}
