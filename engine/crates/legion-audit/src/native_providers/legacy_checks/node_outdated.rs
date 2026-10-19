//! npm outdated completion is a reconciliation, never inference from `{}`.
//! Every operation uses the existing SDK & network-allowed, project-write-denied sandbox.
use super::*;

// Duplicate keys are ambiguous input, including conflicting declarations in
// one dependency section. serde_json::Value alone would keep only the last.
struct StrictJson(Value);
impl<'de> serde::Deserialize<'de> for StrictJson {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StrictJson;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<StrictJson, M::Error> {
                let mut value = serde_json::Map::new();
                while let Some((key, item)) = map.next_entry::<String, StrictJson>()? {
                    if value.insert(key, item.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(StrictJson(Value::Object(value)))
            }
            fn visit_seq<S: serde::de::SeqAccess<'de>>(
                self,
                mut seq: S,
            ) -> Result<StrictJson, S::Error> {
                let mut value = Vec::new();
                while let Some(item) = seq.next_element::<StrictJson>()? {
                    value.push(item.0);
                }
                Ok(StrictJson(Value::Array(value)))
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<StrictJson, E> {
                Ok(StrictJson(json!(v)))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<StrictJson, E> {
                Ok(StrictJson(json!(v)))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<StrictJson, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| StrictJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("nonfinite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::String(v.into())))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::String(v)))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::Null))
            }
        }
        de.deserialize_any(Visitor)
    }
}
fn strict_json(bytes: &[u8]) -> Option<Value> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let value = <StrictJson as serde::Deserialize>::deserialize(&mut de)
        .ok()?
        .0;
    de.end().ok()?;
    Some(value)
}

const SECTIONS: [&str; 4] = [
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

fn stable(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|b| b.is_ascii_digit())
                && (part.len() == 1 || !part.starts_with('0'))
                && part.parse::<u64>().is_ok()
        })
}
fn package_name(value: &str) -> bool {
    let part = |s: &str| {
        !s.is_empty()
            && s.bytes().all(|b| {
                b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_' | b'.')
            })
            && !s.starts_with('.')
            && !s.starts_with('_')
    };
    if let Some(scoped) = value.strip_prefix('@') {
        scoped
            .split_once('/')
            .is_some_and(|(scope, name)| part(scope) && part(name) && !name.contains('/'))
    } else {
        part(value)
    }
}

fn declarations(manifest: &Value, gaps: &mut Vec<String>) -> BTreeMap<String, String> {
    let mut expected: BTreeMap<String, String> = BTreeMap::new();
    let mut conflicts = BTreeSet::new();
    for section in SECTIONS {
        let Some(value) = manifest.get(section) else {
            continue;
        };
        let Some(deps) = value.as_object() else {
            gaps.push(format!("npm-outdated-declarations-invalid:{section}"));
            continue;
        };
        for (name, value) in deps {
            let Some(version) = value.as_str().filter(|v| stable(v) && package_name(name)) else {
                gaps.push(format!(
                    "npm-outdated-declaration-unsupported:{section}:{name}"
                ));
                conflicts.insert(name.clone());
                continue;
            };
            if expected
                .insert(name.clone(), version.into())
                .is_some_and(|prior| prior != version)
            {
                conflicts.insert(name.clone());
                gaps.push(format!("npm-outdated-declaration-conflict:{name}"));
            }
        }
    }
    for name in conflicts {
        expected.remove(&name);
    }
    if expected.is_empty() {
        gaps.push("npm-outdated-nonempty-dependencies-unproven".into());
    }
    expected
}

fn frozen_root(input: &LegacyCheckInput, gaps: &mut Vec<String>) -> Option<(Value, String)> {
    for entry in &input.denominator.entries {
        if entry.path != "package.json" {
            gaps.push(format!("npm-outdated-manifest-uncovered:{}", entry.path));
        }
    }
    let entry = input
        .denominator
        .entries
        .iter()
        .find(|e| e.path == "package.json")?;
    let path = input.root.join("package.json");
    let meta = std::fs::symlink_metadata(&path).ok()?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
    if entry.digest.as_deref() != Some(digest.as_str()) {
        return None;
    }
    let manifest = strict_json(&bytes)?;
    manifest.as_object()?;
    Some((manifest, digest))
}

/// Unsupported local manager/config inputs never silently weaken registry checks.
fn configuration(root: &Path, manifest: &Value, gaps: &mut Vec<String>) {
    if manifest
        .get("packageManager")
        .is_some_and(|v| !v.as_str().is_some_and(|s| s.starts_with("npm@")))
    {
        gaps.push("npm-outdated-manager-unsupported".into());
    }
    for lock in ["pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"] {
        if root.join(lock).exists() {
            gaps.push(format!("npm-outdated-manager-lock-unsupported:{lock}"));
        }
    }
    for key in ["workspaces", "overrides", "resolutions", "publishConfig"] {
        if manifest.get(key).is_some() {
            gaps.push(format!("npm-outdated-configuration-unsupported:{key}"));
        }
    }
    let npmrc = root.join(".npmrc");
    if npmrc.exists() {
        gaps.push("npm-outdated-project-config-unsupported:.npmrc".into());
    }
}

struct Probe {
    value: Option<Value>,
    raw: Value,
    state: LegacyCheckProcessState,
    exit: Option<i32>,
    gaps: Vec<String>,
}

async fn probe(
    executor: &NativeLegacyCheckExecutor,
    plan: &crate::FrozenPlan,
    provider: &AuditProvider,
    scratch: &AuditScratch,
    deadline: std::time::Instant,
    ordinal: usize,
    label: &str,
    mut args: Vec<String>,
    exits: &[i32],
    cancellation: CancellationToken,
) -> Result<Probe, AuditError> {
    let cache = scratch.cache_dir().join(format!("npm-outdated-{ordinal}"));
    std::fs::create_dir(&cache)
        .map_err(|e| AuditError::Provider(format!("npm-outdated-fresh-cache:{e}")))?;
    // Avoid ambient user/global configuration & cache. A project .npmrc is
    // rejected before dispatch; no configuration can alter registry coverage.
    let config = cache.join("empty.npmrc");
    let global = cache.join("global.npmrc");
    std::fs::write(&global, []).map_err(|e| AuditError::Provider(e.to_string()))?;
    std::fs::write(&config, []).map_err(|e| AuditError::Provider(e.to_string()))?;
    args.extend([
        "--registry=https://registry.npmjs.org/".into(),
        "--online".into(),
        "--offline=false".into(),
        "--prefer-offline=false".into(),
        "--prefer-online=true".into(),
        "--ignore-scripts=true".into(),
        "--audit=false".into(),
        "--fund=false".into(),
        format!("--cache={}", cache.to_string_lossy()),
        format!("--userconfig={}", config.to_string_lossy()),
        format!("--globalconfig={}", global.to_string_lossy()),
    ]);
    let (mut environment, allowlist) = audit_environment(scratch);
    environment.insert(
        "npm_config_cache".into(),
        cache.to_string_lossy().into_owned(),
    );
    let mut executable = "npm".to_owned();
    let mut sandbox = None;
    let mut version_args = vec!["--version".into()];
    if cfg!(target_os = "macos") {
        if let Ok(resolved) = resolve_request(&executor.root, "npm", &args) {
            if let Ok(auth) = legion_effects::authenticate_sandbox(
                &resolved.executable.to_string_lossy(),
                &resolved.args,
                &executor.root.to_string_lossy(),
                sandbox_mode_for_check("outdated"),
                &scratch.sandbox_dir(),
            ) {
                executable = auth.wrapped_executable;
                args = auth.wrapped_args;
                version_args = args
                    .iter()
                    .take(4)
                    .cloned()
                    .chain(["--version".into()])
                    .collect();
                sandbox = Some(legion_effects::SandboxReceipt {
                    id: auth.id,
                    network: auth.network,
                    filesystem_scope: auth.filesystem_scope,
                });
            }
        }
    }
    let request = ExternalToolRequest {
        request_id: format!(
            "audit:{}:{}:npm:{ordinal}:{label}",
            provider.id,
            plan.digest()
        ),
        provider_id: provider.id.clone(),
        plan_id: plan.digest().into(),
        policy_id: provider
            .configuration
            .get("policyId")
            .and_then(Value::as_str)
            .unwrap_or("audit")
            .into(),
        task_id: Some("outdated".into()),
        executable,
        args,
        cwd: executor.root.to_string_lossy().into_owned(),
        shell: false,
        accepted_exit_codes: exits.iter().copied().collect(),
        environment,
        environment_allowlist: allowlist,
        requires_network_sandbox: true,
        sandbox,
        timeout_ms: deadline
            .saturating_duration_since(std::time::Instant::now())
            .as_millis()
            .clamp(1, 120_000) as u64,
        stdout_limit: provider
            .bounds
            .get("stdoutLimit")
            .and_then(Value::as_u64)
            .unwrap_or(8 * 1024 * 1024) as usize,
        stderr_limit: provider
            .bounds
            .get("stderrLimit")
            .and_then(Value::as_u64)
            .unwrap_or(8 * 1024 * 1024) as usize,
        version_args,
        ..ExternalToolRequest::default()
    };
    let receipt = executor
        .external_project_tool
        .as_ref()
        .expect("checked before probes")
        .execute(request, cancellation)
        .await;
    let roots = [scratch.artifacts_dir(), executor.root.clone()];
    let stdout = receipt
        .stdout
        .as_ref()
        .and_then(|a| readable_artifact(&[roots[0].as_path(), roots[1].as_path()], a));
    let stderr = receipt
        .stderr
        .as_ref()
        .and_then(|a| readable_artifact(&[roots[0].as_path(), roots[1].as_path()], a));
    let state = match receipt.state {
        legion_provider_sdk::ExecutionState::Completed => LegacyCheckProcessState::Completed,
        legion_provider_sdk::ExecutionState::MissingExecutable => {
            LegacyCheckProcessState::MissingExecutable
        }
        legion_provider_sdk::ExecutionState::UnauthorizedEffect
        | legion_provider_sdk::ExecutionState::Blocked
        | legion_provider_sdk::ExecutionState::SandboxMissing
        | legion_provider_sdk::ExecutionState::UnsealedExecutable => {
            LegacyCheckProcessState::Unauthorized
        }
        legion_provider_sdk::ExecutionState::Timeout => LegacyCheckProcessState::Timeout,
        legion_provider_sdk::ExecutionState::Cancelled => LegacyCheckProcessState::Cancelled,
        legion_provider_sdk::ExecutionState::OutputLimited => {
            LegacyCheckProcessState::OutputLimited
        }
        _ => LegacyCheckProcessState::Failed,
    };
    let value = (receipt.complete
        && state == LegacyCheckProcessState::Completed
        && exits.contains(&receipt.exit_code.unwrap_or(-1))
        && stderr.is_some())
    .then(|| stdout.as_deref().and_then(|bytes| strict_json(bytes)))
    .flatten()
    .filter(|value| value.is_object() && value.get("error").is_none());
    let raw = json!({"label":label,"receipt":crate::execution_policy::receipt_json(&receipt),
        "stdout":stdout.as_ref().map(|b| String::from_utf8_lossy(b).into_owned()),
        "stderr":stderr.as_ref().map(|b| String::from_utf8_lossy(b).into_owned())});
    Ok(Probe {
        value,
        raw,
        state,
        exit: receipt.exit_code,
        gaps: receipt.gaps.clone(),
    })
}

fn installed(value: &Value, name: &str) -> Option<String> {
    if value.get("error").is_some()
        || value
            .get("problems")
            .is_some_and(|v| v.as_array().is_none_or(|a| !a.is_empty()))
    {
        return None;
    }
    let row = value.get("dependencies")?.get(name)?.as_object()?;
    if ["invalid", "missing", "extraneous", "error", "problems"]
        .iter()
        .any(|key| row.get(*key).is_some())
    {
        return None;
    }
    row.get("version")?
        .as_str()
        .filter(|v| stable(v))
        .map(str::to_owned)
}
fn registry_version(value: &Value, name: &str, expected: Option<&str>) -> Option<String> {
    if value.get("name").and_then(Value::as_str) != Some(name) || value.get("error").is_some() {
        return None;
    }
    let version = value.get("version")?.as_str()?;
    if !stable(version)
        || expected.is_some_and(|wanted| version != wanted)
        || expected.is_none() && value.get("engines").is_some()
    {
        return None;
    }
    Some(version.into())
}
fn rows(
    value: &Value,
    expected: &BTreeMap<String, String>,
    gaps: &mut Vec<String>,
) -> BTreeMap<String, Vec<(String, String, String)>> {
    let mut rows = BTreeMap::new();
    let Some(object) = value.as_object().filter(|v| !v.contains_key("error")) else {
        gaps.push("npm-outdated-report-invalid".into());
        return rows;
    };
    for (name, value) in object {
        if !expected.contains_key(name) {
            gaps.push(format!("npm-outdated-unexpected-row:{name}"));
            continue;
        }
        let items: Vec<&Value> = value
            .as_array()
            .map(|a| a.iter().collect())
            .unwrap_or_else(|| vec![value]);
        if items.is_empty() {
            gaps.push(format!("npm-outdated-empty-row:{name}"));
        }
        let mut valid = Vec::new();
        for row in items {
            let triple = ["current", "wanted", "latest"]
                .map(|key| row.get(key).and_then(Value::as_str).filter(|s| stable(s)));
            if let [Some(current), Some(wanted), Some(latest)] = triple {
                if row.is_object()
                    && row.get("error").is_none()
                    && (current != wanted || wanted != latest)
                {
                    valid.push((current.into(), wanted.into(), latest.into()));
                } else {
                    gaps.push(format!("npm-outdated-unchanged-row:{name}"));
                }
            } else {
                gaps.push(format!("npm-outdated-row-invalid:{name}"));
            }
        }
        if !valid.is_empty() {
            rows.insert(name.clone(), valid);
        }
    }
    rows
}

// The resolver prioritizes the project local-bin entry & canonicalizes its
// target. Refuse that origin before resolution can erase it, even when npm
// points outside this project. No projectExecution authority is granted here.
fn project_npm_unsupported(root: &std::path::Path) -> bool {
    let local = root.join("node_modules/.bin/npm");
    let has_entry = |path: &std::path::Path| match std::fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    };
    if has_entry(&local) {
        return true;
    }
    #[cfg(windows)]
    for extension in ["exe", "cmd", "bat", "com"] {
        if has_entry(&local.with_extension(extension)) {
            return true;
        }
    }
    // Also retain refusal for a host-selected executable located in project.
    resolve_request(root, "npm", &[]).is_ok_and(|r| r.executable.starts_with(root))
}

pub(super) async fn execute(
    executor: &NativeLegacyCheckExecutor,
    plan: &crate::FrozenPlan,
    provider: &AuditProvider,
    input: &LegacyCheckInput,
    cancellation: CancellationToken,
) -> Result<ProviderResult, AuditError> {
    let mut output = LegacyCheckOutput::default();
    let mut gaps = Vec::new();
    let root = frozen_root(input, &mut gaps);
    if root.is_none() {
        gaps.push("npm-outdated-frozen-root-manifest-unproven".into());
    }
    let expected = root
        .as_ref()
        .map(|(manifest, _)| {
            configuration(&input.root, manifest, &mut gaps);
            declarations(manifest, &mut gaps)
        })
        .unwrap_or_default();
    if expected.len() > 256 {
        gaps.push("npm-outdated-dependency-probe-bound-exceeded".into());
    }
    let project_npm = project_npm_unsupported(&executor.root);
    if project_npm {
        gaps.push("npm-outdated-project-npm-unsupported".into());
    }
    let configuration_invalid = project_npm
        || expected.len() > 256
        || gaps.iter().any(|g| {
            g.starts_with("npm-outdated-manager-")
                || g.starts_with("npm-outdated-configuration-")
                || g.starts_with("npm-outdated-project-config-")
        });
    let mut evidence = Vec::new();
    let mut process_state = LegacyCheckProcessState::Completed;
    let mut exit = None;
    let mut reconciled = Vec::new();
    if executor.external_project_tool.is_none() {
        gaps.push("npm-outdated-external-project-tool-unavailable".into());
        process_state = LegacyCheckProcessState::Unauthorized;
    } else if root.is_some() && !expected.is_empty() && !configuration_invalid {
        let scratch = executor.scratch()?;
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(
                provider
                    .bounds
                    .get("timeoutMs")
                    .and_then(Value::as_u64)
                    .unwrap_or(120_000),
            );
        let outdated = probe(
            executor,
            plan,
            provider,
            &scratch,
            deadline,
            0,
            "outdated",
            vec!["outdated".into(), "--json".into()],
            &[0, 1],
            cancellation.clone(),
        )
        .await?;
        gaps.extend(outdated.gaps.clone());
        process_state = outdated.state;
        exit = outdated.exit;
        let mut report = BTreeMap::new();
        if let Some(value) = &outdated.value {
            report = rows(value, &expected, &mut gaps);
        } else {
            gaps.push("npm-outdated-report-unproven".into());
        }
        evidence.push(outdated.raw);
        // Missing executable/admission is terminal; never attempt alternate tool.
        if process_state == LegacyCheckProcessState::Completed {
            let ls = probe(
                executor,
                plan,
                provider,
                &scratch,
                deadline,
                1,
                "installed",
                vec![
                    "ls".into(),
                    "--depth=0".into(),
                    "--json".into(),
                    "--include=dev".into(),
                    "--include=optional".into(),
                    "--include=peer".into(),
                ],
                &[0],
                cancellation.clone(),
            )
            .await?;
            gaps.extend(ls.gaps.clone());
            let installed_value = ls.value.clone();
            evidence.push(ls.raw);
            for (index, (name, declared)) in expected.iter().enumerate() {
                if cancellation.is_cancelled() || std::time::Instant::now() >= deadline {
                    gaps.push("npm-outdated-cancelled-or-deadline".into());
                    break;
                }
                let exact = probe(
                    executor,
                    plan,
                    provider,
                    &scratch,
                    deadline,
                    2 + index * 2,
                    &format!("exact:{name}"),
                    vec!["view".into(), format!("{name}@{declared}"), "--json".into()],
                    &[0],
                    cancellation.clone(),
                )
                .await?;
                let latest = probe(
                    executor,
                    plan,
                    provider,
                    &scratch,
                    deadline,
                    3 + index * 2,
                    &format!("latest:{name}"),
                    vec!["view".into(), format!("{name}@latest"), "--json".into()],
                    &[0],
                    cancellation.clone(),
                )
                .await?;
                let installed_version = installed_value.as_ref().and_then(|v| installed(v, name));
                let exact_ok = exact
                    .value
                    .as_ref()
                    .and_then(|v| registry_version(v, name, Some(declared)))
                    .is_some();
                let latest_version = latest
                    .value
                    .as_ref()
                    .and_then(|v| registry_version(v, name, None));
                gaps.extend(exact.gaps.clone());
                gaps.extend(latest.gaps.clone());
                evidence.extend([exact.raw, latest.raw]);
                if installed_version.is_none() || !exact_ok || latest_version.is_none() {
                    gaps.push(format!(
                        "npm-outdated-dependency-completion-unproven:{name}"
                    ));
                    continue;
                }
                let latest_version = latest_version.unwrap();
                let installed_version = installed_version.unwrap();
                let matching = report.get(name).is_some_and(|rows| {
                    rows.iter().all(|(current, wanted, latest)| {
                        current == &installed_version
                            && wanted == declared
                            && latest == &latest_version
                    })
                });
                let changed = installed_version != *declared || declared != &latest_version;
                if (changed && !matching) || (!changed && report.contains_key(name)) {
                    gaps.push(format!("npm-outdated-triple-unreconciled:{name}"));
                    continue;
                }
                reconciled.push(json!({"name":name,"installed":installed_version,"declared":declared,"latest":latest_version,"changed":changed}));
                if changed {
                    push_finding(&mut output,&format!("legacy.outdated.npm:{name}"),"low","package.json",1,
                        &format!("{name}: installed {installed_version}, wanted {declared}, latest {latest_version}"));
                }
            }
            if outdated.value.is_some()
                && ((report.is_empty() && outdated.exit != Some(0))
                    || (!report.is_empty() && outdated.exit != Some(1)))
            {
                gaps.push("npm-outdated-exit-report-inconsistent".into());
            }
        }
    }
    // Re-read frozen bytes after online operations so mutation cannot prove clean.
    let mut after_gaps = Vec::new();
    if frozen_root(input, &mut after_gaps) != root {
        gaps.push("npm-outdated-source-changed".into());
    }
    if reconciled.len() != expected.len() {
        gaps.push("npm-outdated-dependencies-uncovered".into());
    }
    gaps.sort();
    gaps.dedup();
    output.complete = gaps.is_empty();
    output.status = if output.complete {
        if output.findings.is_empty() {
            ProviderStatus::Ok
        } else {
            ProviderStatus::Complete
        }
    } else {
        ProviderStatus::Partial
    };
    output.coverage_gaps = gaps.clone();
    let examined = u64::from(output.complete && root.is_some());
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined,
        gaps,
    });
    output.details.insert(
        "findingsCount".into(),
        if output.complete || !output.findings.is_empty() {
            json!(output.findings.len())
        } else {
            Value::Null
        },
    );
    if let Some(first) = evidence.first() {
        output
            .details
            .insert("executionReceipt".into(), first["receipt"].clone());
    }
    output.details.insert("npmOutdatedCompletion".into(),json!({"schemaVersion":1,"scope":"npm exact stable direct dependencies; public registry responses for this run only", "rootManifest":root.as_ref().map(|(_,digest)|json!({"path":"package.json","digest":digest})),"expected":expected,"reconciled":reconciled,"probes":evidence}));
    let execution = LegacyCheckExecution {
        state: process_state,
        exit_code: exit,
        stdout: Vec::new(),
        stderr: Vec::new(),
        receipt_id: None,
        output: Some(output),
        error: None,
    };
    LegacyCheckDispatcher::new()
        .project_result(provider, input, execution)
        .map_err(|e| AuditError::Provider(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    #[test]
    fn outward_project_npm_symlink_cannot_gain_host_tool_authority() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let parent = std::env::temp_dir().join(format!(
            "legion-node-outdated-origin-{}-{nonce}",
            std::process::id()
        ));
        let root = parent.join("project");
        let host = parent.join("host-npm");
        std::fs::create_dir_all(root.join("node_modules/.bin")).unwrap();
        std::fs::write(&host, b"host fixture bytes; never executed").unwrap();
        let local = root.join("node_modules/.bin/npm");
        std::os::unix::fs::symlink(&host, &local).unwrap();
        let resolved = resolve_request(&root, "npm", &[]).unwrap();
        assert_eq!(resolved.executable, std::fs::canonicalize(&host).unwrap());
        assert!(!resolved.executable.starts_with(&root));
        assert!(project_npm_unsupported(&root));
        // A dangling local entry also cannot silently select a host fallback.
        std::fs::remove_file(&host).unwrap();
        assert!(project_npm_unsupported(&root));
        std::fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn duplicate_fields_and_trailing_documents_rejected() {
        assert!(strict_json(br#"{"dependencies":{"a":"1.0.0","a":"2.0.0"}}"#).is_none());
        assert!(strict_json(b"{} {}").is_none());
        assert_eq!(
            strict_json(br#"{"a":[true,null,2,2.5,"ok"]}"#),
            Some(json!({"a":[true,null,2,2.5,"ok"]}))
        );
    }
    #[test]
    fn all_sections_conflicts_and_exact_stable_boundary() {
        let mut gaps = Vec::new();
        let deps = declarations(
            &json!({"dependencies":{"a":"1.0.0"},"devDependencies":{"b":"2.0.0"},"optionalDependencies":{"c":"3.0.0"},"peerDependencies":{"d":"4.0.0"}}),
            &mut gaps,
        );
        assert_eq!(deps.len(), 4);
        assert!(gaps.is_empty());
        let deps = declarations(
            &json!({"dependencies":{"a":"1.0.0","b":"^1.0.0"},"peerDependencies":{"a":"2.0.0"}}),
            &mut gaps,
        );
        assert!(deps.is_empty());
        assert!(gaps.iter().any(|g| g.contains("conflict")));
        for version in ["1.2.3-beta.1", "^1.2.3", "01.2.3", "1.2", "latest"] {
            assert!(!stable(version));
        }
    }
    #[test]
    fn array_rows_and_errors_cannot_be_clean() {
        let expected = BTreeMap::from([("a".into(), "1.0.0".into())]);
        let mut gaps = Vec::new();
        let parsed = rows(
            &json!({"a":[{"current":"1.0.0","wanted":"1.0.0","latest":"2.0.0"}]}),
            &expected,
            &mut gaps,
        );
        assert_eq!(parsed["a"].len(), 1);
        assert!(gaps.is_empty());
        rows(&json!({"error":{"code":"E404"}}), &expected, &mut gaps);
        assert!(!gaps.is_empty());
        assert!(registry_version(
            &json!({"name":"a","version":"2.0.0","engines":{"node":">=18"}}),
            "a",
            None
        )
        .is_none());
        assert_eq!(
            installed(&json!({"dependencies":{"a":{"version":"0.9.0"}}}), "a"),
            Some("0.9.0".into())
        );
    }
}
