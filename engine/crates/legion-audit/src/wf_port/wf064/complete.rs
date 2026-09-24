//! Port of `tools/audit/audit-complete.mjs`.
//!
//! Scope note: `runCompleteAudit`'s deep provider-suite calls
//! (`runNativeFamilies`, `runFrameworkSuite`, `runDataSuite`,
//! `runInfrastructureSuite`, `generateSecurityCandidates`,
//! `auditVisualArtifacts`, Blueprint projection via
//! `readBlueprintPacket`/`enrichProjectionWithEcosystems`, and provider
//! registry loading) are each a separate, un-ported legacy `.mjs` module
//! outside this packet's two target files — genuinely impossible to port
//! faithfully here since no Rust equivalents of those provider-suite
//! modules exist in this crate tree. Every piece of `audit-complete.mjs`
//! that is *this file's own logic* — CLI argv parsing, the direct-entrypoint
//! check, the offline policy, the small pure helpers
//! (`providerPlan`/`selected`/`frozenFiles`/`securityProviderPlans`), the
//! `collect-facts.mjs` subprocess invocation shape, and the reconciliation
//! logic (`reconcileCompleteRun` and its `familyCoverage`/
//! `denominatorDrift` helpers) — is ported faithfully below, with
//! process/filesystem I/O pushed behind traits so the logic is testable
//! with fakes (per the port brief's subprocess-orchestration rule).

use crate::wf_port::wf064::plan::reconcile_plan_with_facts;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;

/// Mirrors `providerPlan(plan, id)`.
pub fn provider_plan_by_id<'a>(plan: &'a Value, id: &str) -> Option<&'a Value> {
    provider_plan(plan, id)
}

/// Mirrors `selected(plan, id)`.
pub fn selected(plan: &Value, id: &str) -> bool {
    provider_plan(plan, id).is_some()
}

/// Mirrors `frozenFiles(plan, id, fallback)`.
pub fn frozen_files(plan: &Value, id: &str, fallback: &[String]) -> Vec<String> {
    match provider_plan(plan, id) {
        None => Vec::new(),
        Some(provider) => provider
            .pointer("/denominator/paths")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_else(|| fallback.to_vec()),
    }
}

/// Mirrors `securityProviderPlans(plan)`: every planned provider whose
/// runner is the `security-suite.mjs` runtime script.
pub fn security_provider_plans(plan: &Value) -> Vec<&Value> {
    plan.get("providers")
        .and_then(|v| v.as_array())
        .map(|providers| {
            providers
                .iter()
                .filter(|p| {
                    p.pointer("/runner/kind").and_then(|v| v.as_str()) == Some("runtime-script")
                        && p.pointer("/runner/script").and_then(|v| v.as_str())
                            == Some("src/providers/security-suite.mjs")
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Mirrors the `arg(args, name)` CLI helper: the value following the first
/// occurrence of `name`, or `None` if `name` is absent or is the last
/// argument.
pub fn cli_arg<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Mirrors the `values(args, name)` CLI helper: a comma-separated `arg`
/// value split into trimmed, non-empty parts.
pub fn cli_values(args: &[String], name: &str) -> Vec<String> {
    match cli_arg(args, name) {
        None => Vec::new(),
        Some(raw) => raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect(),
    }
}

/// Mirrors the `first(args)` CLI helper: the first bare (non-`--flag`)
/// argument, skipping the value that follows any recognized valued flag.
/// Falls back to `cwd_fallback` (JS falls back to `process.cwd()`) when no
/// bare argument is present.
pub fn cli_first<'a>(args: &'a [String], cwd_fallback: &'a str) -> &'a str {
    const VALUED: &[&str] = &[
        "--out",
        "--only",
        "--skip",
        "--type",
        "--base",
        "--base-commit",
        "--dir",
        "--blueprint-out",
        "--url",
        "--surfaces",
        "--visual-spec",
        "--visual-baselines",
        "--width",
        "--height",
    ];
    let mut index = 0usize;
    while index < args.len() {
        let a = args[index].as_str();
        if a.starts_with("--") {
            if VALUED.contains(&a) {
                index += 1;
            }
            index += 1;
            continue;
        }
        return a;
    }
    cwd_fallback
}

/// Mirrors `isMainEntrypoint`'s normalization step
/// (`normalizedExecutableHref`): on Windows, compare case-insensitively;
/// elsewhere, compare as-is. The actual `realpathSync`/`pathToFileURL`
/// resolution is filesystem/URL I/O owned by the caller — this function
/// takes two already-resolved, canonical href/path strings and applies only
/// the deterministic platform-normalization + comparison JS performs last.
pub fn is_main_entrypoint_href(resolved_argv_href: &str, resolved_module_href: &str, platform_is_windows: bool) -> bool {
    if platform_is_windows {
        resolved_argv_href.to_lowercase() == resolved_module_href.to_lowercase()
    } else {
        resolved_argv_href == resolved_module_href
    }
}

/// Mirrors the argv passed to `spawnSync(process.execPath, args, ...)` when
/// invoking `collect-facts.mjs`: `[COLLECT_FACTS, root, '--out', outDir,
/// '--only', expectedChecks.join(',')]` plus the optional `--type`/`--base`/
/// `--base-commit`/`--dir` scope flags. Pure argv construction, kept
/// separate from the actual `Command` spawn so it is trivially testable.
#[derive(Debug, Clone, Default)]
pub struct CollectFactsScope {
    pub scope_type: Option<String>,
    pub base: Option<String>,
    pub base_commit: Option<String>,
    pub dir: Option<String>,
}

pub fn collect_facts_argv(
    collect_facts_script: &str,
    root: &str,
    out_dir: &str,
    expected_checks: &[String],
    scope: &CollectFactsScope,
) -> Vec<String> {
    let mut args = vec![
        collect_facts_script.to_string(),
        root.to_string(),
        "--out".to_string(),
        out_dir.to_string(),
        "--only".to_string(),
        expected_checks.join(","),
    ];
    if let Some(scope_type) = &scope.scope_type {
        if scope_type != "all" {
            args.push("--type".to_string());
            args.push(scope_type.clone());
        }
    }
    if let Some(base) = &scope.base {
        args.push("--base".to_string());
        args.push(base.clone());
    }
    if let Some(base_commit) = &scope.base_commit {
        args.push("--base-commit".to_string());
        args.push(base_commit.clone());
    }
    if let Some(dir) = &scope.dir {
        args.push("--dir".to_string());
        args.push(dir.clone());
    }
    args
}

/// Behind-a-trait stand-in for `spawnSync`, so orchestration logic that
/// shells out (the `collect-facts.mjs` invocation, and analogous
/// `audit-runtime.mjs` calls made elsewhere in this file) can be exercised
/// with a fake runner instead of a real process, per the port brief's
/// subprocess-orchestration rule.
pub trait CommandRunner {
    /// Runs `program` with `args` in `cwd`; returns the process exit code
    /// (mirrors the subset of `spawnSync`'s result this file inspects:
    /// `run.status`).
    fn run(&mut self, program: &str, args: &[String], cwd: &str) -> i32;
}

/// Mirrors `applyOfflinePolicy`'s environment-variable side effects
/// (`AUDIT_OFFLINE`, `npm_config_offline`, `CARGO_NET_OFFLINE`,
/// `PIP_NO_INDEX`, `GOPROXY`, `GOSUMDB`, `BUNDLE_FROZEN`, and the
/// `MAVEN_ARGS`/`GRADLE_OPTS` append-if-present pattern) behind a trait so
/// the pure policy computation in [`offline_policy_skip_set`] can be
/// exercised without mutating real process environment.
pub trait EnvSetter {
    fn get(&self, key: &str) -> Option<String>;
    fn set(&mut self, key: &str, value: &str);
}

/// Mirrors the environment-mutation half of `applyOfflinePolicy`: sets the
/// fixed offline flags, and appends `-o` / `-Dorg.gradle.offline=true` to
/// any existing `MAVEN_ARGS`/`GRADLE_OPTS` (JS: `[existing, flag].filter(Boolean).join(' ')`).
pub fn apply_offline_env(env: &mut dyn EnvSetter) {
    env.set("AUDIT_OFFLINE", "1");
    env.set("npm_config_offline", "true");
    env.set("CARGO_NET_OFFLINE", "true");
    env.set("PIP_NO_INDEX", "1");
    env.set("GOPROXY", "off");
    env.set("GOSUMDB", "off");
    env.set("BUNDLE_FROZEN", "true");
    let maven = [env.get("MAVEN_ARGS"), Some("-o".to_string())]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    env.set("MAVEN_ARGS", &maven);
    let gradle = [env.get("GRADLE_OPTS"), Some("-Dorg.gradle.offline=true".to_string())]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(" ");
    env.set("GRADLE_OPTS", &gradle);
}

/// `NETWORK_DEPENDENT_CHECKS`.
pub fn network_dependent_checks() -> BTreeSet<&'static str> {
    [
        "deps_cve",
        "py_deps_cve",
        "cargo_audit",
        "cargo_deny",
        "outdated",
        "cargo_outdated",
        "binary_pins",
    ]
    .into_iter()
    .collect()
}

/// `PROJECT_EXECUTION_CHECKS`.
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

/// The deterministic core of `applyOfflinePolicy`: given the caller's
/// requested `skip` list and whether the trusted network sandbox is active,
/// returns the sorted, deduped final skip set. Always includes the
/// network-dependent checks; additionally includes every project-execution
/// check when the sandbox is not active (mirrors JS `guardedSkips`). Setting
/// the offline environment variables themselves (`AUDIT_OFFLINE`,
/// `CARGO_NET_OFFLINE`, etc.) is process-environment mutation and is not
/// ported here.
pub fn offline_policy_skip_set(requested_skip: &[String], network_sandbox_active: bool) -> Vec<String> {
    let mut skip: BTreeSet<String> = requested_skip.iter().cloned().collect();
    skip.extend(network_dependent_checks().into_iter().map(String::from));
    if !network_sandbox_active {
        skip.extend(project_execution_checks().into_iter().map(String::from));
    }
    skip.into_iter().collect()
}

fn provider_plan<'a>(plan: &'a Value, id: &str) -> Option<&'a Value> {
    plan.get("providers")
        .and_then(|v| v.as_array())
        .and_then(|providers| providers.iter().find(|p| p.get("id").and_then(|v| v.as_str()) == Some(id)))
}

/// `familyCoverage`.
fn family_coverage(plan: &Value, results: &[Value]) -> (Vec<Value>, Vec<Value>) {
    use std::collections::BTreeMap;
    let mut by_family: BTreeMap<String, Vec<&Value>> = BTreeMap::new();
    for result in results {
        if let Some(family) = result.get("family").and_then(|v| v.as_str()) {
            by_family.entry(family.to_string()).or_default().push(result);
        }
    }
    let families: Vec<Value> = plan
        .get("coverageFamilies")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|family| {
            let id = family.get("id").and_then(|v| v.as_str()).unwrap_or_default();
            let executions = by_family.get(id);
            match executions {
                Some(execs) if !execs.is_empty() => {
                    let mut with_exec = family.clone();
                    let exec_values: Vec<Value> = execs
                        .iter()
                        .map(|e| {
                            json!({
                                "provider": e.get("provider").cloned().unwrap_or(Value::Null),
                                "status": e.get("status").cloned().unwrap_or(Value::Null),
                                "complete": e.get("complete").cloned().unwrap_or(Value::Null),
                                "coverage": e.get("coverage").cloned().unwrap_or(Value::Null),
                            })
                        })
                        .collect();
                    with_exec["executions"] = json!(exec_values);
                    with_exec
                }
                _ => family,
            }
        })
        .collect();
    let unresolved: Vec<Value> = families
        .iter()
        .filter(|family| {
            let executions = family.get("executions").and_then(|v| v.as_array());
            match executions.map(|v| v.as_slice()) {
                None | Some([]) => {
                    let qualification = family.get("qualification").and_then(|v| v.as_str());
                    let missing_providers = family
                        .get("missingProviders")
                        .and_then(|v| v.as_array())
                        .map(|a| !a.is_empty())
                        .unwrap_or(false);
                    qualification != Some("complete") || missing_providers
                }
                Some(execs) => execs.iter().any(|item| {
                    let incomplete = item.get("complete").and_then(|v| v.as_bool()) != Some(true);
                    let bad_status = matches!(
                        item.get("status").and_then(|v| v.as_str()),
                        Some("unproven") | Some("error")
                    );
                    incomplete || bad_status
                }),
            }
        })
        .cloned()
        .collect();
    (families, unresolved)
}

/// `denominatorDrift`.
fn denominator_drift(plan: &Value, provider_results: &[Value]) -> Vec<Value> {
    let mut gaps = Vec::new();
    for result in provider_results {
        let provider_id = match result.get("provider").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => continue,
        };
        let contract = match provider_plan(plan, provider_id) {
            Some(c) => c,
            None => continue,
        };
        let coverage = match result.get("coverage") {
            Some(c) if !c.is_null() => c,
            _ => continue,
        };
        let denominator = match contract.get("denominator") {
            Some(d) if !d.is_null() => d,
            _ => continue,
        };
        let expected_digest = denominator.get("pathDigest");
        let observed_digest = coverage
            .get("pathDigest")
            .or_else(|| coverage.get("denominatorDigest"));
        if let (Some(expected), Some(observed)) = (expected_digest, observed_digest) {
            if !expected.is_null() && !observed.is_null() && expected != observed {
                gaps.push(json!({
                    "provider": provider_id,
                    "kind": "denominator-digest-mismatch",
                    "expectedDigest": expected,
                    "observedDigest": observed,
                }));
                continue;
            }
        }
        let expected = denominator.get("pathCount").cloned().unwrap_or(Value::Null);
        let observed = coverage
            .get("expectedFiles")
            .or_else(|| coverage.get("pathCount"))
            .or_else(|| coverage.get("fileCount"))
            .cloned()
            .or_else(|| {
                coverage
                    .get("paths")
                    .and_then(|v| v.as_array())
                    .map(|a| json!(a.len()))
            });
        if let Some(observed) = observed {
            if !observed.is_null() {
                let observed_num = observed.as_f64();
                let expected_num = expected.as_f64();
                if observed_num != expected_num {
                    gaps.push(json!({
                        "provider": provider_id,
                        "expectedPathCount": expected,
                        "observedPathCount": observed,
                    }));
                }
            }
        }
    }
    gaps
}

/// Faithful port of `reconcileCompleteRun`.
pub fn reconcile_complete_run(
    plan: &Map<String, Value>,
    facts: &Value,
    provider_results: &[Value],
    security_result: &Value,
    projection: &Value,
    binding_verification: &Value,
) -> Value {
    let plan_value = Value::Object(plan.clone());
    let legacy = reconcile_plan_with_facts(plan, facts);
    let (families, unresolved) = family_coverage(&plan_value, provider_results);
    let selected_runtime: BTreeSet<&str> = plan_value
        .get("providers")
        .and_then(|v| v.as_array())
        .map(|providers| {
            providers
                .iter()
                .filter(|p| p.get("phase").and_then(|v| v.as_str()) == Some("runtime"))
                .filter_map(|p| p.get("id").and_then(|v| v.as_str()))
                .collect()
        })
        .unwrap_or_default();
    let observed: BTreeSet<&str> = provider_results
        .iter()
        .filter_map(|p| p.get("provider").and_then(|v| v.as_str()))
        .collect();
    let missing_runtime_providers: Vec<&str> = selected_runtime
        .iter()
        .filter(|id| !observed.contains(*id))
        .copied()
        .collect();
    let legacy_provider_results = legacy["providerResults"].as_array().cloned().unwrap_or_default();
    let facts_complete = legacy_provider_results
        .iter()
        .filter(|p| p.get("phase").and_then(|v| v.as_str()) == Some("facts"))
        .all(|p| p.get("complete").and_then(|v| v.as_bool()) == Some(true));
    let provider_incomplete = provider_results.iter().any(|p| {
        p.get("complete").and_then(|v| v.as_bool()) == Some(false)
            || matches!(
                p.get("status").and_then(|v| v.as_str()),
                Some("unproven") | Some("error") | Some("missing") | Some("fail")
            )
    });
    let security_pending = security_result
        .pointer("/candidates")
        .and_then(|v| v.as_array())
        .map(|a| !a.is_empty())
        .unwrap_or(false);
    let plan_incomplete = !plan_value
        .get("coverageGaps")
        .and_then(|v| v.as_array())
        .map(|a| a.is_empty())
        .unwrap_or(true)
        || plan_value.pointer("/qualification/state").and_then(|v| v.as_str()) == Some("unproven");
    let denominator_mismatches = denominator_drift(&plan_value, provider_results);
    let binding_valid = binding_verification.get("valid").and_then(|v| v.as_bool()) == Some(true);
    let projection_ready = projection.get("state").and_then(|v| v.as_str()) == Some("ready");
    let legacy_valid = legacy.get("valid").and_then(|v| v.as_bool()) == Some(true);

    let incomplete = facts.get("incomplete").and_then(|v| v.as_bool()) == Some(true)
        || plan_incomplete
        || !projection_ready
        || !legacy_valid
        || !facts_complete
        || !binding_valid
        || provider_incomplete
        || !missing_runtime_providers.is_empty()
        || !unresolved.is_empty()
        || security_pending
        || !denominator_mismatches.is_empty();

    let mut out = facts.clone();
    if let Value::Object(map) = &mut out {
        map.insert("incomplete".to_string(), json!(incomplete));
        map.insert(
            "blueprint".to_string(),
            json!({
                "state": projection.get("state").cloned().unwrap_or(Value::Null),
                "reason": projection.get("reason").cloned().unwrap_or(Value::Null),
                "generationId": projection.get("generationId").cloned().unwrap_or(Value::Null),
                "manifestDigest": projection.get("manifestDigest").cloned().unwrap_or(Value::Null),
                "fileCount": projection.get("fileCount").cloned().unwrap_or(json!(0)),
                "sourceFileCount": projection.get("sourceFileCount").cloned().unwrap_or(json!(0)),
                "parsedExtensions": projection.get("parsedExtensions").cloned().unwrap_or_else(|| json!([])),
                "unsupportedExtensions": projection.get("unsupportedExtensions").cloned().unwrap_or_else(|| json!([])),
            }),
        );
        map.insert(
            "plan".to_string(),
            json!({
                "schemaVersion": plan_value.get("schemaVersion").cloned().unwrap_or(Value::Null),
                "seal": plan_value.get("seal").cloned().unwrap_or(Value::Null),
                "binding": plan_value.get("binding").cloned().unwrap_or(Value::Null),
                "expectedChecks": plan_value.pointer("/denominator/expectedChecks").cloned().unwrap_or_else(|| json!([])),
                "selectedProviderIds": plan_value.pointer("/denominator/providerIds").cloned().unwrap_or_else(|| json!([])),
                "reasoningProviders": plan_value.pointer("/denominator/reasoningProviders").cloned().unwrap_or_else(|| json!([])),
                "coverageGaps": plan_value.get("coverageGaps").cloned().unwrap_or_else(|| json!([])),
            }),
        );
        let mut combined_results: Vec<Value> = legacy_provider_results
            .into_iter()
            .filter(|p| p.get("status").and_then(|v| v.as_str()) != Some("pending"))
            .collect();
        combined_results.extend(provider_results.iter().cloned());
        map.insert(
            "provider_reconciliation".to_string(),
            json!({
                "valid": legacy.get("valid").cloned().unwrap_or(Value::Null),
                "expectedChecks": legacy.get("expectedChecks").cloned().unwrap_or(Value::Null),
                "observedChecks": legacy.get("observedChecks").cloned().unwrap_or(Value::Null),
                "missingChecks": legacy.get("missingChecks").cloned().unwrap_or(Value::Null),
                "unplannedChecks": legacy.get("unplannedChecks").cloned().unwrap_or(Value::Null),
                "providerResults": combined_results,
                "coverageFamilies": families,
                "unresolvedCoverage": unresolved,
                "missingRuntimeProviders": missing_runtime_providers,
                "denominatorMismatches": denominator_mismatches,
            }),
        );
        map.insert(
            "security".to_string(),
            json!({
                "candidatesPath": "security-candidates.json",
                "candidatesCount": security_result.pointer("/candidates").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0),
                "adjudicationRequired": security_pending,
            }),
        );
        map.insert("plan_binding_verification".to_string(), binding_verification.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_policy_always_includes_network_dependent_checks() {
        let skip = offline_policy_skip_set(&[], true);
        assert!(skip.contains(&"deps_cve".to_string()));
        assert!(skip.contains(&"cargo_audit".to_string()));
        // Sandbox active: project-execution checks are NOT force-skipped.
        assert!(!skip.contains(&"lint".to_string()));
    }

    #[test]
    fn offline_policy_without_sandbox_also_skips_project_execution() {
        let skip = offline_policy_skip_set(&["custom_check".to_string()], false);
        assert!(skip.contains(&"lint".to_string()));
        assert!(skip.contains(&"build".to_string()));
        assert!(skip.contains(&"custom_check".to_string()));
        assert!(skip.contains(&"deps_cve".to_string()));
    }

    #[test]
    fn reconcile_complete_run_marks_incomplete_on_provider_failure() {
        let plan = json!({
            "schemaVersion": 1, "coverageGaps": [], "qualification": {"state": "ready"},
            "denominator": {"expectedChecks": [], "providerIds": [], "reasoningProviders": []},
            "providers": [], "coverageFamilies": [],
        })
        .as_object()
        .unwrap()
        .clone();
        let facts = json!({"checks": [], "incomplete": false});
        let provider_results = vec![json!({"provider": "p1", "status": "fail", "complete": true})];
        let security_result = json!({"candidates": []});
        let projection = json!({"state": "ready"});
        let binding_verification = json!({"valid": true});
        let out = reconcile_complete_run(&plan, &facts, &provider_results, &security_result, &projection, &binding_verification);
        assert_eq!(out["incomplete"], json!(true));
    }

    #[test]
    fn cli_first_skips_valued_flag_arguments() {
        let args = ["--out".to_string(), "outdir".to_string(), "/repo".to_string()];
        assert_eq!(cli_first(&args, "/cwd"), "/repo");
    }

    #[test]
    fn cli_first_falls_back_to_cwd_when_no_bare_arg() {
        let args = ["--quiet".to_string()];
        assert_eq!(cli_first(&args, "/cwd"), "/cwd");
    }

    #[test]
    fn cli_arg_and_values_parse_comma_lists() {
        let args = ["--skip".to_string(), " a, b ,,c".to_string()];
        assert_eq!(cli_arg(&args, "--skip"), Some(" a, b ,,c"));
        assert_eq!(cli_values(&args, "--skip"), vec!["a", "b", "c"]);
        assert_eq!(cli_values(&args, "--missing"), Vec::<String>::new());
    }

    #[test]
    fn is_main_entrypoint_href_is_case_sensitive_off_windows() {
        assert!(!is_main_entrypoint_href("file:///Repo/x.mjs", "file:///repo/x.mjs", false));
        assert!(is_main_entrypoint_href("file:///repo/x.mjs", "file:///repo/x.mjs", false));
    }

    #[test]
    fn is_main_entrypoint_href_is_case_insensitive_on_windows() {
        assert!(is_main_entrypoint_href("file:///Repo/x.mjs", "file:///repo/x.mjs", true));
    }

    #[test]
    fn collect_facts_argv_includes_diff_scope_flags() {
        let scope = CollectFactsScope {
            scope_type: Some("changed".to_string()),
            base: Some("main".to_string()),
            base_commit: None,
            dir: None,
        };
        let argv = collect_facts_argv("collect-facts.mjs", "/repo", "/out", &["lint".to_string(), "build".to_string()], &scope);
        assert_eq!(
            argv,
            vec!["collect-facts.mjs", "/repo", "--out", "/out", "--only", "lint,build", "--type", "changed", "--base", "main"]
        );
    }

    #[test]
    fn collect_facts_argv_omits_type_flag_when_all() {
        let scope = CollectFactsScope { scope_type: Some("all".to_string()), ..Default::default() };
        let argv = collect_facts_argv("collect-facts.mjs", "/repo", "/out", &[], &scope);
        assert!(!argv.contains(&"--type".to_string()));
    }

    #[test]
    fn security_provider_plans_filters_by_runner() {
        let plan = json!({
            "providers": [
                {"id": "security.injection", "runner": {"kind": "runtime-script", "script": "src/providers/security-suite.mjs"}},
                {"id": "framework.major-suite", "runner": {"kind": "runtime-script", "script": "src/providers/framework-suite.mjs"}},
            ]
        });
        let plans = security_provider_plans(&plan);
        assert_eq!(plans.len(), 1);
        assert_eq!(plans[0]["id"], json!("security.injection"));
    }

    #[test]
    fn frozen_files_falls_back_when_no_denominator_paths() {
        let plan = json!({"providers": [{"id": "data.internal-suite", "denominator": {}}]});
        let fallback = vec!["a.rs".to_string()];
        assert_eq!(frozen_files(&plan, "data.internal-suite", &fallback), fallback);
        assert_eq!(frozen_files(&plan, "missing", &fallback), Vec::<String>::new());
    }

    struct FakeEnv {
        vars: std::collections::HashMap<String, String>,
    }
    impl EnvSetter for FakeEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.vars.get(key).cloned()
        }
        fn set(&mut self, key: &str, value: &str) {
            self.vars.insert(key.to_string(), value.to_string());
        }
    }

    #[test]
    fn apply_offline_env_appends_to_existing_maven_and_gradle_opts() {
        let mut env = FakeEnv {
            vars: [
                ("MAVEN_ARGS".to_string(), "-DskipTests".to_string()),
                ("GRADLE_OPTS".to_string(), "-Xmx2g".to_string()),
            ]
            .into_iter()
            .collect(),
        };
        apply_offline_env(&mut env);
        assert_eq!(env.get("MAVEN_ARGS").as_deref(), Some("-DskipTests -o"));
        assert_eq!(env.get("GRADLE_OPTS").as_deref(), Some("-Xmx2g -Dorg.gradle.offline=true"));
        assert_eq!(env.get("AUDIT_OFFLINE").as_deref(), Some("1"));
    }

    #[test]
    fn apply_offline_env_sets_flag_alone_when_unset() {
        let mut env = FakeEnv { vars: std::collections::HashMap::new() };
        apply_offline_env(&mut env);
        assert_eq!(env.get("MAVEN_ARGS").as_deref(), Some("-o"));
    }

    #[test]
    fn reconcile_complete_run_complete_when_everything_passes() {
        let plan = json!({
            "schemaVersion": 1, "coverageGaps": [], "qualification": {"state": "ready"},
            "denominator": {"expectedChecks": [], "providerIds": [], "reasoningProviders": []},
            "providers": [], "coverageFamilies": [],
        })
        .as_object()
        .unwrap()
        .clone();
        let facts = json!({"checks": [], "incomplete": false});
        let provider_results = vec![json!({"provider": "p1", "status": "pass", "complete": true})];
        let security_result = json!({"candidates": []});
        let projection = json!({"state": "ready"});
        let binding_verification = json!({"valid": true});
        let out = reconcile_complete_run(&plan, &facts, &provider_results, &security_result, &projection, &binding_verification);
        assert_eq!(out["incomplete"], json!(false));
    }
}
