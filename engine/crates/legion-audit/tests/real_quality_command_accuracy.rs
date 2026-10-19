//! Constructed SDK controls for existing build & lint providers, using actual pinned Cargo.
//! No production CLI owner-admission claim; test provider still requires real attested enrollment.
#![cfg(target_os = "macos")]

use legion_audit::{
    execute_with_cancellation,
    native_providers::legacy_checks::{resolve_request, AuditExternalProjectTool, AuditScratch},
    AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use legion_effects::{ExternalToolRequest, PolicyAuthorizer, PolicyDecision, ToolOrigin};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

const SOURCE: &str = "engine/crates/legion-audit/tests/real_quality_command_accuracy.rs";
const POLICY: &str = "legion-real-quality-command-qualification-v1";
const BUILD: &str = "legacy.quality.build";
const LINT: &str = "legacy.quality.lint";

fn digest(bytes: &[u8]) -> String {
    let hex = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

fn canonical_bytes(value: &Value) -> Vec<u8> {
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Object(items) => {
                let sorted: BTreeMap<_, _> = items.iter().collect();
                let mut object = serde_json::Map::new();
                for (key, value) in sorted {
                    object.insert(key.clone(), ordered(value));
                }
                Value::Object(object)
            }
            Value::Array(items) => Value::Array(items.iter().map(ordered).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&ordered(value)).unwrap()
}

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let base = std::env::var_os("LEGION_QUALITY_COMMAND_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let path = base.join(format!(
            "legion-quality-command-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        let path = fs::canonicalize(path).unwrap();
        for dir in ["home", "tmp"] {
            fs::create_dir(path.join(dir)).unwrap();
        }
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn registry_spec(id: &str) -> Value {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == id)
        .unwrap()
        .clone()
}

fn binding(id: &str, fixtures: &BTreeMap<String, String>) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    fn walk(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink(), "source binding refuses symlinks");
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), files);
            }
        } else {
            files.insert(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
                digest(&fs::read(path).unwrap()),
            );
        }
    }
    let mut sources = BTreeMap::new();
    for path in [
        "engine/crates/legion-audit/src",
        "engine/crates/legion-effects/src",
        "engine/crates/legion-provider-sdk/src",
        "engine/crates/legion-contracts/src",
        "engine/crates/legion-rules/src",
        "src/registry/rules",
        "src/registry/controls",
        "engine/Cargo.toml",
        "engine/Cargo.lock",
        "engine/rust-toolchain.toml",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        SOURCE,
    ] {
        walk(&root, &root.join(path), &mut sources);
    }
    let mut spec = registry_spec(id);
    spec.as_object_mut().unwrap().remove("benchmark");
    json!({
        "providerSpec": spec,
        "providerSpecDigest": digest(&canonical_bytes(&spec)),
        "sources": sources,
        "sourcesDigest": digest(&canonical_bytes(&json!(sources))),
        "fixtureSources": fixtures,
        "fixtureSourcesDigest": digest(&canonical_bytes(&json!(fixtures))),
        "fixture": SOURCE
    })
}

fn expected_environment(run: &Path) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let base = [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "COMSPEC",
        "HOME",
        "USERPROFILE",
    ];
    let mut env: BTreeMap<String, String> = base
        .iter()
        .filter_map(|name| {
            std::env::var(name)
                .ok()
                .map(|value| ((*name).into(), value))
        })
        .collect();
    let mut allowed: BTreeSet<String> = base.into_iter().map(str::to_owned).collect();
    for (name, path) in [
        ("TMPDIR", "tmp"),
        ("TEMP", "tmp"),
        ("TMP", "tmp"),
        ("XDG_CACHE_HOME", "cache/xdg"),
        ("CARGO_TARGET_DIR", "cache/cargo-target"),
        ("npm_config_cache", "cache/npm"),
        ("RUFF_CACHE_DIR", "cache/ruff"),
        ("MYPY_CACHE_DIR", "cache/mypy"),
        ("PYTHONPYCACHEPREFIX", "cache/pycache"),
        ("GOCACHE", "cache/go-build"),
    ] {
        env.insert(name.into(), run.join(path).to_string_lossy().into_owned());
        allowed.insert(name.into());
    }
    env.insert("PYTHONNOUSERSITE".into(), "1".into());
    env.insert("GIT_CONFIG_NOSYSTEM".into(), "1".into());
    allowed.insert("PYTHONNOUSERSITE".into());
    allowed.insert("GIT_CONFIG_NOSYSTEM".into());
    env.insert("PYTHONDONTWRITEBYTECODE".into(), "1".into());
    allowed.insert("PYTHONDONTWRITEBYTECODE".into());
    (env, allowed)
}

struct ScopedPolicy {
    id: String,
    check: String,
    plan: String,
    root: PathBuf,
    tool: PathBuf,
    tool_digest: String,
    wrapper: PathBuf,
    wrapper_digest: String,
    profile: PathBuf,
    profile_text: String,
    args: Vec<String>,
    environment: BTreeMap<String, String>,
    allowlist: BTreeSet<String>,
    accepted_exits: BTreeSet<i32>,
    decisions: Mutex<Vec<Value>>,
}
impl ScopedPolicy {
    fn sandbox_id(&self) -> String {
        format!(
            "sandbox:macos:{}",
            digest(self.profile_text.as_bytes()).trim_start_matches("sha256:")
        )
    }

    fn wrapped_args(&self, suffix: &[String]) -> Vec<String> {
        let mut args = vec![
            "-f".into(),
            self.profile.to_string_lossy().into_owned(),
            "--".into(),
            self.tool.to_string_lossy().into_owned(),
        ];
        args.extend_from_slice(suffix);
        args
    }

    fn definition(&self) -> Value {
        json!({
            "id": POLICY,
            "version": 1,
            "provider": self.id,
            "task": self.check,
            "plan": self.plan,
            "cwd": self.root,
            "artifactRequestId": "legion-audit/<64 lowercase hex>; one admission only",
            "tool": {"path": self.tool, "digest": self.tool_digest},
            "wrapper": {"path": self.wrapper, "digest": self.wrapper_digest},
            "profile": {"path": self.profile, "text": self.profile_text,
                "digest": digest(self.profile_text.as_bytes()), "receiptId": self.sandbox_id()},
            "args": self.args,
            "wrappedArgs": self.wrapped_args(&self.args),
            "versionArgs": self.wrapped_args(&["--version".into()]),
            "environment": self.environment,
            "environmentAllowlist": self.allowlist,
            "timeoutMs": 120000,
            "stdoutLimit": 8388608,
            "stderrLimit": 8388608,
            "sandbox": "native-macos-deny-network-quality-command-contract",
            "acceptedExitCodes": self.accepted_exits
        })
    }

    fn permits(&self, req: &ExternalToolRequest) -> bool {
        let artifact_id = req.request_id.strip_prefix("legion-audit/");
        req.schema_version == 1
            && artifact_id.is_some_and(|id| {
                id.len() == 64
                    && id
                        .bytes()
                        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            })
            && req.provider_id == self.id
            && req.plan_id == self.plan
            && req.policy_id == "audit"
            && req.task_id.as_deref() == Some(self.check.as_str())
            && req.cwd == self.root.to_string_lossy().as_ref()
            && req.origin == ToolOrigin::TargetProject
            && !req.shell
            && req.requires_network_sandbox
            && req.sandbox.as_ref().is_some_and(|sandbox| {
                sandbox.id == self.sandbox_id()
                    && sandbox.network
                    && sandbox.filesystem_scope.as_deref() == self.root.to_str()
            })
            && !req.skip_version_probe
            && req.version_requirement.is_none()
            && req.executable == self.wrapper.to_string_lossy().as_ref()
            && req.expected_digest.as_deref() == Some(self.wrapper_digest.as_str())
            && fs::read(&self.wrapper).is_ok_and(|bytes| digest(&bytes) == self.wrapper_digest)
            && fs::read(&self.tool).is_ok_and(|bytes| digest(&bytes) == self.tool_digest)
            && !self.profile.is_symlink()
            && fs::read(&self.profile)
                .is_ok_and(|bytes| bytes.as_slice() == self.profile_text.as_bytes())
            && req.args == self.wrapped_args(&self.args)
            && req.version_args == self.wrapped_args(&["--version".into()])
            && req.environment == self.environment
            && req.environment_allowlist == self.allowlist
            && req.sensitive_argument_indexes.is_empty()
            && req.sensitive_environment_names.is_empty()
            && req.timeout_ms == 120000
            && req.stdout_limit == 8388608
            && req.stderr_limit == 8388608
            && req.accepted_exit_codes == self.accepted_exits
    }
}
impl PolicyAuthorizer for ScopedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        let mut decisions = self.decisions.lock().unwrap();
        let allowed = decisions.is_empty() && self.permits(request);
        decisions.push(json!({
            "allowed": allowed,
            "requestId": request.request_id,
            "providerId": request.provider_id,
            "planId": request.plan_id,
            "taskId": request.task_id,
            "executable": request.executable,
            "expectedDigest": request.expected_digest,
            "args": request.args,
            "versionArgs": request.version_args,
            "cwd": request.cwd,
            "environmentNames": request.environment.keys().collect::<Vec<_>>(),
            "environmentDigest": digest(&serde_json::to_vec(&request.environment).unwrap()),
            "timeoutMs": request.timeout_ms,
            "stdoutLimit": request.stdout_limit,
            "stderrLimit": request.stderr_limit,
            "acceptedExitCodes": request.accepted_exit_codes,
            "requiresNetworkSandbox": request.requires_network_sandbox,
            "sandbox": request.sandbox.as_ref().map(|sandbox| json!({"id": sandbox.id,
                "network": sandbox.network, "filesystemScope": sandbox.filesystem_scope}))
        }));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&canonical_bytes(&self.definition())),
            reason: Some(
                if allowed {
                    "exact constructed quality-command fixture admission"
                } else {
                    "outside exact constructed quality-command fixture policy"
                }
                .into(),
            ),
        }
    }
}

struct SharedPolicy(Arc<ScopedPolicy>);
impl PolicyAuthorizer for SharedPolicy {
    fn authorize(&self, request: &ExternalToolRequest) -> PolicyDecision {
        self.0.authorize(request)
    }
}

fn artifact(receipt: &Value, stream: &str, scratch: &AuditScratch) -> Vec<u8> {
    let item = &receipt[stream];
    assert_eq!(item["immutable"], true);
    let relative = Path::new(item["path"].as_str().unwrap());
    assert!(!relative.is_absolute());
    let root = fs::canonicalize(scratch.artifacts_dir()).unwrap();
    let path = fs::canonicalize(root.join(relative)).unwrap();
    assert!(path.starts_with(&root));
    let bytes = fs::read(path).unwrap();
    assert_eq!(item["digest"], digest(&bytes));
    assert_eq!(item["bytes"], bytes.len());
    bytes
}

fn fixture_files(id: &str, control: &str) -> BTreeMap<String, String> {
    let source = match (id, control) {
        (BUILD, "positive") => "use std::fmt;\npub fn answer() -> u8 { 42 }\n",
        (BUILD, "absence") => "pub fn answer() -> u8 { 42 }\n",
        (LINT, "positive") => "pub fn equal(value: i32) -> bool {\n    value == value\n}\n",
        (LINT, "absence") => {
            "pub fn equal(left: i32, right: i32) -> bool {\n    left == right\n}\n"
        }
        (BUILD | LINT, "compiler-failure") => "pub fn answer() -> u8 { missing_name }\n",
        _ => panic!("unsupported quality fixture {id}/{control}"),
    };
    [
        ("Cargo.toml", "[package]\nname = \"legion_quality_fixture\"\nversion = \"0.0.0\"\nedition = \"2021\"\n[workspace]\n"),
        ("Cargo.lock", "# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 4\n\n[[package]]\nname = \"legion_quality_fixture\"\nversion = \"0.0.0\"\n"),
        ("rust-toolchain.toml", "[toolchain]\nchannel = \"1.98.0\"\nprofile = \"minimal\"\ncomponents = [\"clippy\"]\n"),
        ("src/lib.rs", source),
    ].into_iter().map(|(path, text)| (path.into(), text.into())).collect()
}

fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink(), "fixture snapshots refuse symlinks");
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), files);
            }
        } else {
            files.insert(
                path.strip_prefix(root).unwrap().to_str().unwrap().into(),
                digest(&fs::read(path).unwrap()),
            );
        }
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files);
    files
}

fn case(base: &Path, id: &str, control: &str) -> Value {
    let case_id = format!("{}-{control}", id.replace('.', "-"));
    let root = base.join(&case_id).join("source");
    let run = base.join(&case_id).join("run");
    let fixtures = fixture_files(id, control);
    for (path, source) in &fixtures {
        let file = root.join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, source).unwrap();
    }
    let before = snapshot(&root);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&case_id)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec(id)).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"constructed-quality-command-fixture-key"))
        .unwrap();
    let provider = frozen
        .provider(id)
        .expect("actual shipped provider must be selected");
    let expected_coverage = provider.configuration["denominatorCount"].as_u64().unwrap();
    assert!(
        expected_coverage > 0,
        "preserve entire shipped selector denominator"
    );
    let (tool_name, check, args) = if id == BUILD {
        ("project-build", "build", vec!["build".to_owned()])
    } else {
        (
            "project-lint",
            "lint",
            [
                "clippy",
                "--all-targets",
                "--message-format=json",
                "--",
                "-D",
                "warnings",
            ]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        )
    };
    let requested_args = if id == LINT {
        vec!["--json".into()]
    } else {
        vec![]
    };
    let resolved =
        resolve_request(&root, tool_name, &requested_args).expect("real pinned Cargo required");
    assert_eq!(resolved.args, args);
    assert_eq!(resolved.cwd, root);
    let tool = fs::canonicalize(&resolved.executable).unwrap();
    let toolchain =
        fs::canonicalize(std::env::var_os("LEGION_QUALITY_TOOLCHAIN_BIN").unwrap()).unwrap();
    assert_eq!(
        tool,
        toolchain.join("cargo"),
        "use actual pinned toolchain binary, not rustup shim"
    );
    assert!(!tool.starts_with(base));
    let bytes = fs::read(&tool).unwrap();
    assert!(!bytes.starts_with(b"#!"), "no script substitute");
    assert_eq!(digest(&bytes), resolved.digest);
    let scratch = Arc::new(AuditScratch::with_scratch_dir(&root, &run).unwrap());
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").expect("native macOS sandbox required");
    let escaped = root
        .to_str()
        .unwrap()
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    let profile_text = format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* file-write* (subpath \"{escaped}\"))\n");
    let profile = scratch.sandbox_dir().join(format!(
        "audit-{}.sb",
        digest(profile_text.as_bytes()).trim_start_matches("sha256:")
    ));
    let (environment, allowlist) = expected_environment(&run);
    let policy = Arc::new(ScopedPolicy {
        id: id.into(),
        check: check.into(),
        plan: frozen.digest().into(),
        root: root.clone(),
        tool: tool.clone(),
        tool_digest: resolved.digest,
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
        profile,
        profile_text,
        args,
        environment,
        allowlist,
        accepted_exits: if id == BUILD {
            [0].into_iter().collect()
        } else {
            [0, 1, 2, 101].into_iter().collect()
        },
        decisions: Mutex::new(Vec::new()),
    });
    let effects = legion_effects::EffectExecutor::new(
        legion_effects::platform::unix::UnixProcess::new(),
        legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
        SharedPolicy(policy.clone()),
    );
    let mut native = NativeProviderRegistry::new(&root)
        .with_scratch(scratch.clone())
        .with_external_project_tool(Arc::new(AuditExternalProjectTool::new(effects)));
    native.legacy_checks = native
        .legacy_checks
        .with_fixture_policy_authorizer(policy.clone());
    let report = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(execute_with_cancellation(
            &frozen,
            &inventory,
            &native,
            tokio_util::sync::CancellationToken::new(),
        ))
        .unwrap();
    assert_eq!(report.planned_providers, vec![id]);
    assert_eq!(report.results.len(), 1);
    let result = &report.results[0].result;
    let receipt = &result.details["executionReceipt"];
    let stdout = artifact(receipt, "stdout", &scratch);
    let stderr = artifact(receipt, "stderr", &scratch);
    let stdout_text = std::str::from_utf8(&stdout).unwrap();
    let stderr_text = std::str::from_utf8(&stderr).unwrap();
    let version = receipt["executable"]["version"]["output"].as_str().unwrap();
    assert!(
        version.starts_with("cargo 1.98.0 "),
        "existing pinned CI toolchain required"
    );
    assert_eq!(receipt["executable"]["version"]["qualified"], true);
    assert_eq!(receipt["executable"]["version"]["exitCode"], 0);
    assert_eq!(
        receipt["executable"]["version"]["args"],
        json!(policy.wrapped_args(&["--version".into()]))
    );
    assert_eq!(receipt["planId"], frozen.digest());
    assert_eq!(receipt["providerId"], id);
    assert_eq!(receipt["taskId"], check);
    assert_eq!(receipt["cwd"], root.to_str().unwrap());
    assert_eq!(receipt["policy"]["allowed"], true);
    assert_eq!(receipt["policy"]["id"], POLICY);
    assert_eq!(
        receipt["policy"]["digest"],
        digest(&canonical_bytes(&policy.definition()))
    );
    assert_eq!(
        receipt["command"]["args"],
        json!(policy.wrapped_args(&policy.args))
    );
    assert_eq!(
        receipt["executable"]["canonicalPath"],
        policy.wrapper.to_str().unwrap()
    );
    assert_eq!(receipt["executable"]["digest"], policy.wrapper_digest);
    assert_eq!(receipt["sandbox"]["required"], true);
    assert_eq!(receipt["sandbox"]["networkEnabled"], true);
    assert_eq!(receipt["sandbox"]["receiptId"], policy.sandbox_id());
    assert_eq!(
        fs::read(&policy.profile).unwrap(),
        policy.profile_text.as_bytes()
    );
    assert_eq!(receipt["processTree"]["started"], true);
    assert_eq!(receipt["processTree"]["terminated"], true);
    assert_eq!(receipt["processTree"]["reaped"], true);
    assert!(receipt["signal"].is_null());
    assert_eq!(
        snapshot(&root),
        before,
        "all staged fixture siblings remain unchanged"
    );
    assert_eq!(digest(&fs::read(&tool).unwrap()), policy.tool_digest);
    let positive = control == "positive";
    let failed = control == "compiler-failure";
    let expected_rule = if id == BUILD {
        "legacy.build.warnings"
    } else {
        "legacy.lint.clippy"
    };
    let tool_report: Vec<Value> = if id == LINT {
        stdout_text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).expect("actual Cargo JSONL"))
            .collect()
    } else {
        Vec::new()
    };
    let diagnostics: Vec<&Value> = tool_report
        .iter()
        .filter(|row| {
            row["reason"] == "compiler-message"
                && matches!(row["message"]["level"].as_str(), Some("error" | "warning"))
        })
        .collect();
    if failed {
        assert!(
            !result.complete,
            "compiler failure must never qualify as clean or complete"
        );
        assert!(!result.coverage_gaps.is_empty());
        assert_eq!(receipt["exitCode"], 101);
        assert!(format!("{stdout_text}\n{stderr_text}").contains("E0425"));
        assert!(format!("{stdout_text}\n{stderr_text}").contains("missing_name"));
        if id == LINT {
            assert!(diagnostics
                .iter()
                .any(|row| row["message"]["code"]["code"] == "E0425"));
            assert!(result
                .coverage_gaps
                .iter()
                .any(|gap| gap == "cargo-clippy-diagnostic-exit-unproven"));
        } else {
            assert_eq!(receipt["state"], "failed");
            assert_eq!(receipt["complete"], false);
        }
        assert!(
            result.findings.is_empty(),
            "execution failure has no qualified finding"
        );
    } else {
        assert!(
            result.applicable && result.complete,
            "{:?}",
            result.coverage_gaps
        );
        assert!(result.coverage_gaps.is_empty() && result.degradation.is_empty());
        assert!(matches!(
            result.status,
            legion_contracts::ProviderStatus::Ok | legion_contracts::ProviderStatus::Complete
        ));
        let coverage = result.coverage.as_ref().unwrap();
        assert_eq!(
            (coverage.expected, coverage.examined),
            (expected_coverage, expected_coverage)
        );
        assert!(coverage.gaps.is_empty());
        assert_eq!(
            coverage.denominator_digest,
            provider.configuration["denominatorDigest"]
                .as_str()
                .unwrap()
        );
        assert_eq!(receipt["state"], "completed");
        assert_eq!(receipt["complete"], true);
        assert_eq!(receipt["gaps"], json!([]));
        assert_eq!(
            receipt["exitCode"],
            if id == LINT && positive { 101 } else { 0 }
        );
        assert_eq!(result.findings.len(), usize::from(positive));
        assert_eq!(result.details["candidates"], json!([]));
        let count = result.details["findingsCount"].as_u64().unwrap();
        if id == BUILD {
            if positive {
                assert!(
                    count > 0,
                    "real compiler stderr warning must reach build parser"
                );
                assert!(stderr_text.contains("warning: unused import: `std::fmt`"));
                assert!(stderr_text.contains("src/lib.rs:1:5"));
                assert!(stderr_text.contains("generated 1 warning"));
                assert_eq!(
                    stderr_text
                        .lines()
                        .filter(|line| line.starts_with("warning:"))
                        .count(),
                    2
                );
            } else {
                assert_eq!(count, 0);
                assert!(!stderr_text.contains("warning:"));
            }
        } else {
            assert_eq!(tool_report.last().unwrap()["reason"], "build-finished");
            assert_eq!(tool_report.last().unwrap()["success"], !positive);
            assert_eq!(count, diagnostics.len() as u64);
            assert_eq!(!diagnostics.is_empty(), positive);
            for row in &diagnostics {
                assert_eq!(row["message"]["code"]["code"], "clippy::eq_op");
                assert_eq!(row["message"]["level"], "error");
                assert!(row["message"]["spans"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|span| {
                        span["is_primary"] == true
                            && span["file_name"] == "src/lib.rs"
                            && span["line_start"] == 2
                    }));
            }
        }
        if positive {
            let evidence = &result.details["findingEvidence"];
            let finding = &result.findings[0];
            assert_eq!(evidence[finding.id.as_str()]["ruleId"], expected_rule);
        }
    }
    let decisions = policy.decisions.lock().unwrap();
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0]["allowed"], true);
    assert_eq!(decisions[0]["requestId"], receipt["requestId"]);
    assert_eq!(decisions[0]["planId"], receipt["planId"]);
    assert_eq!(decisions[0]["providerId"], receipt["providerId"]);
    assert_eq!(decisions[0]["taskId"], receipt["taskId"]);
    assert_eq!(decisions[0]["args"], receipt["command"]["args"]);
    json!({
        "provider":id, "caseId":case_id, "control":control,
        "fixtureFiles":fixtures, "fixtureSources":before, "inventory":inventory,
        "planDigest":frozen.digest(), "frozenProvider":provider,
        "expected":{"complete":!failed,"findingCount":usize::from(positive),
            "ruleId":expected_rule,"rawDiagnostic":if failed {json!("E0425")} else if !positive {Value::Null}
                else if id == BUILD {json!("unused_imports")} else {json!("clippy::eq_op")}},
        "matched":true,"actualStdout":stdout_text,"actualStderr":stderr_text,
        "actualToolReport":tool_report,"nativeResult":result,
        "policyDefinition":policy.definition(),"policyDecisions":*decisions,"executionReceipt":receipt,
        "locatorPrecision":"case classification from actual diagnostic; native finding is aggregate summary anchor"
    })
}

#[test]
#[ignore = "constructed SDK qualification; requires pinned Rust 1.98.0 actual toolchain binaries & native macOS sandbox"]
fn real_quality_command_accuracy() {
    if let Some(base) = std::env::var_os("LEGION_QUALITY_COMMAND_CHILD") {
        let base = fs::canonicalize(base).unwrap();
        assert_eq!(
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            base.join("home")
        );
        for id in [BUILD, LINT] {
            let cases: Vec<Value> = ["positive", "absence", "compiler-failure"]
                .into_iter()
                .map(|control| case(&base, id, control))
                .collect();
            let fixtures: BTreeMap<String, String> = cases
                .iter()
                .flat_map(|case| {
                    case["fixtureSources"]
                        .as_object()
                        .unwrap()
                        .iter()
                        .map(|(path, digest)| {
                            (
                                format!("{}/{path}", case["caseId"].as_str().unwrap()),
                                digest.as_str().unwrap().into(),
                            )
                        })
                        .collect::<Vec<_>>()
                })
                .collect();
            let mut record = json!({
                "schema":"legion-quality-command-sdk-accuracy/1", "kind":"quality-command-sdk-constructed",
                "productionQualification":false, "claimScope":"known-answer-fixture-cases",
                "provider":id,"providerVersion":registry_spec(id)["providerVersion"],
                "modelCalls":0,"executionPath":"native-sdk-frozen-plan-real-cargo",
                "admissionScope":"explicit constructed SDK authorizer; no production CLI owner-admission claim",
                "binding":binding(id,&fixtures), "cases":cases,
                "metrics":{"cases":3,"matched":3,"mismatched":0}, "status":"pass"
            });
            record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
            if let Some(dir) = std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR") {
                assert!(Path::new(&dir).is_absolute());
                fs::create_dir_all(&dir).unwrap();
                fs::write(
                    PathBuf::from(dir).join(format!("{}.json", id.replace('.', "_"))),
                    serde_json::to_vec_pretty(&record).unwrap(),
                )
                .unwrap();
            }
            println!(
                "QUALITY_COMMAND_SDK_ACCURACY {}",
                serde_json::to_string(&record).unwrap()
            );
        }
        return;
    }
    let fixture = Fixture::new();
    let toolchain = fs::canonicalize(
        std::env::var_os("LEGION_QUALITY_TOOLCHAIN_BIN")
            .expect("explicit installed toolchain bin required"),
    )
    .unwrap();
    let mut paths = vec![toolchain.clone()];
    paths.extend(std::env::split_paths(&std::env::var_os("PATH").unwrap()));
    let mut child = Command::new(std::env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "real_quality_command_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&fixture.0)
        .env_clear()
        .env("PATH", std::env::join_paths(paths).unwrap())
        .env("HOME", fixture.0.join("home"))
        .env("XDG_CONFIG_HOME", fixture.0.join("home"))
        .env("TMPDIR", fixture.0.join("tmp"))
        .env("LEGION_QUALITY_COMMAND_CHILD", &fixture.0)
        .env("LEGION_QUALITY_TOOLCHAIN_BIN", toolchain);
    let retained = PathBuf::from(
        std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR")
            .expect("retained quality-command artifact directory required"),
    );
    assert!(retained.is_absolute());
    fs::create_dir_all(&retained).unwrap();
    let retained = fs::canonicalize(retained).unwrap();
    assert!(
        !retained.starts_with(&fixture.0),
        "child logs must survive fixture cleanup"
    );
    child.env("LEGION_PROVIDER_BENCHMARK_DIR", &retained);
    let output = child.output().unwrap();
    // Preserve complete actual child streams, including libtest headers/summary, as artifacts.
    // CI receives only untouched record payload lines; its terminal proof is outer libtest.
    fs::write(retained.join("child.stdout.log"), &output.stdout).unwrap();
    fs::write(retained.join("child.stderr.log"), &output.stderr).unwrap();
    let execution = json!({
        "schema":"legion-quality-command-child-execution/1",
        "productionQualification":false,
        "status":{"success":output.status.success(),"exitCode":output.status.code(),
            "signal":output.status.signal(),"display":output.status.to_string()},
        "stdout":{"file":"child.stdout.log","bytes":output.stdout.len(),"sha256":digest(&output.stdout)},
        "stderr":{"file":"child.stderr.log","bytes":output.stderr.len(),"sha256":digest(&output.stderr)}
    });
    fs::write(
        retained.join("child-execution.json"),
        serde_json::to_vec_pretty(&execution).unwrap(),
    )
    .unwrap();
    assert!(
        output.status.success(),
        "real quality-command fixture child failed; full streams retained"
    );
    let marker = b"QUALITY_COMMAND_SDK_ACCURACY ";
    let records: Vec<&[u8]> = output
        .stdout
        .split_inclusive(|byte| *byte == b'\n')
        .filter_map(|line| {
            line.windows(marker.len())
                .position(|bytes| bytes == marker)
                .map(|position| &line[position..])
        })
        .collect();
    assert_eq!(
        records.len(),
        2,
        "child must emit exactly two original records"
    );
    for (line, id) in records.iter().zip([BUILD, LINT]) {
        assert_eq!(
            line.last(),
            Some(&b'\n'),
            "original record line must be complete"
        );
        let record: Value = serde_json::from_slice(&line[marker.len()..]).unwrap();
        assert_eq!(record["provider"], id);
        assert_eq!(record["status"], "pass");
        assert_eq!(record["productionQualification"], false);
    }
    let mut stdout = std::io::stdout().lock();
    for line in records {
        stdout.write_all(line).unwrap();
    }
}
