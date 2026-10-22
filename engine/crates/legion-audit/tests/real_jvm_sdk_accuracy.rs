//! Real JVM/v1 SDK known answers. Requires fixed enrolled tools; never bootstraps.
#![cfg(all(target_os = "macos", target_arch = "aarch64"))]
use legion_audit::{
    execute_with_cancellation,
    native_providers::{
        code,
        legacy_checks::{AuditExternalProjectTool, AuditScratch},
        security::producer::SandboxPolicy,
    },
    AuditPlan, FilesystemInventorySource, InventorySource, NativeProviderRegistry,
};
use legion_contracts::ProviderSpec;
use legion_effects::{
    ArtifactRecord, ExecutionReceipt, ExternalToolRequest, PolicyAuthorizer, PolicyDecision,
    ToolOrigin,
};
use legion_provider_sdk::ExternalProjectTool;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};
const HARNESS: &str = "engine/crates/legion-audit/tests/real_jvm_sdk_accuracy.rs";
const FIXTURES: &str = "scripts/ci/fixtures/audit-code-jvm-sdk";
const POLICY: &str = "legion-jvm-sdk-known-answer-v1";
const TASKS: [&str; 5] = ["wrapper", "compile", "lint", "test", "dependency"];
const CONTROLS: [&str; 15] = [
    "positive",
    "nonempty-clean",
    "compile-error",
    "test-failure",
    "no-op-test",
    "missing-dependency",
    "wrapper-drift",
    "source-drift",
    "dependency-drift",
    "enrollment-drift",
    "unsupported-variant",
    "missing-tool",
    "rejected-admission",
    "absent-sandbox",
    "request-mutation",
];
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}
fn canonical(value: &Value) -> Vec<u8> {
    fn ordered(value: &Value) -> Value {
        match value {
            Value::Object(items) => {
                let items = items.iter().collect::<BTreeMap<_, _>>();
                Value::Object(
                    items
                        .into_iter()
                        .map(|(k, v)| (k.clone(), ordered(v)))
                        .collect(),
                )
            }
            Value::Array(items) => Value::Array(items.iter().map(ordered).collect()),
            _ => value.clone(),
        }
    }
    serde_json::to_vec(&ordered(value)).unwrap()
}
fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn visit(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink());
        if path.is_dir() {
            for item in fs::read_dir(path).unwrap() {
                visit(root, &item.unwrap().path(), files)
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
    let mut files = BTreeMap::new();
    visit(root, root, &mut files);
    files
}
fn generated_session_provenance(relative: &Path) -> bool {
    let Ok(tail) = relative
        .strip_prefix("engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance")
    else {
        return false;
    };
    let mut components = tail.components();
    let Some(std::path::Component::Normal(name)) = components.next() else {
        return false;
    };
    if components.next().is_some() {
        return false;
    }
    name.to_str()
        .and_then(|name| name.strip_suffix(".json"))
        .is_some_and(|name| {
            name.len() == 64
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}
fn source_binding_walk(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
    assert!(!path.is_symlink());
    if path.is_dir() {
        for item in fs::read_dir(path).unwrap() {
            source_binding_walk(root, &item.unwrap().path(), files);
        }
    } else {
        let relative = path.strip_prefix(root).unwrap();
        if path.is_file() && generated_session_provenance(relative) {
            return;
        }
        let relative = relative.to_string_lossy().replace('\\', "/");
        let bytes = fs::read(path).unwrap();
        let sha = if relative == "src/registry/providers.json" {
            let mut registry: Value = serde_json::from_slice(&bytes).unwrap();
            for provider in registry["providers"].as_array_mut().unwrap() {
                provider.as_object_mut().unwrap().remove("benchmark");
            }
            digest(&canonical(&registry))
        } else {
            digest(&bytes)
        };
        files.insert(relative, sha);
    }
}
fn source_binding() -> BTreeMap<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let mut files = BTreeMap::new();
    for relative in [
        "engine/crates/legion-audit/src",
        "engine/crates/legion-effects/src",
        "engine/crates/legion-provider-sdk/src",
        "engine/crates/legion-contracts/src",
        "engine/crates/legion-rules/src",
        "src/registry/rules",
        "src/registry/controls",
        FIXTURES,
        HARNESS,
        "scripts/ci/audit-jvm-sdk-inputs.json",
        "scripts/ci/provision-jvm-sdk.py",
        "scripts/ci/audit-jvm-sdk-accuracy.py",
        "engine/Cargo.toml",
        "engine/Cargo.lock",
        "engine/rust-toolchain.toml",
        "engine/crates/legion-audit/Cargo.toml",
        "engine/crates/legion-effects/Cargo.toml",
        "engine/crates/legion-provider-sdk/Cargo.toml",
        "engine/crates/legion-contracts/Cargo.toml",
        "engine/crates/legion-rules/Cargo.toml",
        "src/registry/providers.json",
    ] {
        source_binding_walk(&root, &root.join(relative), &mut files);
    }
    files
}
#[test]
fn source_collector_excludes_only_regular_exact_session_receipts() {
    let base = std::env::var_os("RUNNER_TEMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/Volumes/D/scratch"));
    let root = base.join(format!(
        "legion-jvm-source-receipts-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let source = "engine/crates/legion-audit/src";
    let prefix = format!("{source}/.audit/arcane/receipts/session-provenance");
    let receipt = format!("{prefix}/{}.json", "a".repeat(64));
    let protected = [
        format!("{source}/actual.rs"),
        format!("{prefix}/{}.json", "C".repeat(64)),
        format!("{prefix}/{}.json", "g".repeat(64)),
        format!("{prefix}/{}.json", "a".repeat(63)),
        format!("{prefix}/{}.json", "a".repeat(65)),
        format!("{prefix}/{}.json.bak", "a".repeat(64)),
        format!("{prefix}/nested/{}.json", "a".repeat(64)),
        format!(
            "{source}/nested/.audit/arcane/receipts/session-provenance/{}.json",
            "a".repeat(64)
        ),
        format!("{prefix}/{}.json/child.rs", "b".repeat(64)),
    ];
    for relative in std::iter::once(&receipt).chain(protected.iter()) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, b"original source\n").unwrap();
    }
    let collect = || {
        let mut files = BTreeMap::new();
        source_binding_walk(&root, &root.join(source), &mut files);
        files
    };
    let before = collect();
    assert!(!before.contains_key(&receipt));
    for relative in &protected {
        assert!(!generated_session_provenance(Path::new(relative)));
        assert_eq!(before.get(relative), Some(&digest(b"original source\n")));
    }
    fs::write(root.join(&receipt), b"new generated receipt\n").unwrap();
    assert_eq!(collect(), before);
    for relative in &protected {
        fs::write(root.join(relative), b"changed source\n").unwrap();
        assert_eq!(collect().get(relative), Some(&digest(b"changed source\n")));
        assert_ne!(collect().get(relative), before.get(relative));
        fs::write(root.join(relative), b"original source\n").unwrap();
    }
    let alias = root.join(source).join(format!(
        r".audit\arcane\receipts\session-provenance\{}.json",
        "a".repeat(64)
    ));
    assert!(!generated_session_provenance(
        alias.strip_prefix(&root).unwrap()
    ));
    fs::write(&alias, b"literal-backslash source\n").unwrap();
    // Display keys retain existing normalization; exclusion uses actual components.
    assert_eq!(
        collect().get(&receipt),
        Some(&digest(b"literal-backslash source\n"))
    );
    fs::write(&alias, b"changed literal-backslash source\n").unwrap();
    assert_eq!(
        collect().get(&receipt),
        Some(&digest(b"changed literal-backslash source\n"))
    );
    assert_ne!(
        collect().get(&receipt),
        Some(&digest(b"literal-backslash source\n"))
    );
    fs::remove_file(&alias).unwrap();
    let path = root.join(&receipt);
    fs::remove_file(&path).unwrap();
    for target in [
        root.join(&protected[0]),
        root.join(format!("{prefix}/{}.json", "b".repeat(64))),
    ] {
        std::os::unix::fs::symlink(target, &path).unwrap();
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| collect())).is_err());
        fs::remove_file(&path).unwrap();
    }
    fs::write(&path, b"generated receipt restored\n").unwrap();
    assert!(!collect().contains_key(&receipt));
    fs::remove_dir_all(root).unwrap();
}
fn actual_receipt(receipt: &ExecutionReceipt) -> Value {
    let value = json!({
        "schemaVersion": receipt.schema_version,
        "receiptId": receipt.receipt_id, "requestId": receipt.request_id,
        "providerId": receipt.provider_id, "planId": receipt.plan_id,
        "policyId": receipt.policy_id,
        "policy": receipt.policy.as_ref().map(|p| json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
        "taskId": receipt.task_id, "state": receipt.state.as_str(), "complete": receipt.complete,
        "executable": receipt.executable.as_ref().map(|e| json!({"requestedPath":e.requested_path,"canonicalPath":e.canonical_path,"digest":e.digest,"digestState":format!("{:?}",e.digest_state).to_ascii_lowercase(),"signature":format!("{:?}",e.signature).to_ascii_lowercase(),"version":{"args":e.version.args,"output":e.version.output,"exitCode":e.version.exit_code,"qualified":e.version.qualified,"skippedByPolicy":e.version.skipped_by_policy}})),
        "command": receipt.command.as_ref().map(|c| json!({"executable":c.executable,"args":c.args,"environmentNames":c.environment_names,"redactedArgumentIndexes":c.redacted_argument_indexes,"redactedEnvironmentNames":c.redacted_environment_names})),
        "cwd": receipt.cwd, "environmentNames": receipt.environment_names,
        "sandbox": {"required":receipt.sandbox.required,"receiptId":receipt.sandbox.receipt_id,"networkEnabled":receipt.sandbox.network_enabled},
        "processTree": {"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,"hardKilled":receipt.process_tree.hard_killed,"reaped":receipt.process_tree.reaped,"detail":receipt.process_tree.detail},
        "timing": {"startedAtMs":receipt.timing.started_at_ms,"completedAtMs":receipt.timing.completed_at_ms,"durationMs":receipt.timing.duration_ms},
        "exitCode": receipt.exit_code, "signal": receipt.signal,
        "stdout": receipt.stdout.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "stderr": receipt.stderr.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "parser": {"attempted":receipt.parser.attempted,"succeeded":receipt.parser.succeeded,"error":receipt.parser.error},
        "gaps": receipt.gaps,
    });
    value
}
fn request_value(request: &ExternalToolRequest) -> Value {
    json!({"schemaVersion":request.schema_version,"requestId":request.request_id,
        "providerId":request.provider_id,"planId":request.plan_id,"policyId":request.policy_id,"taskId":request.task_id,
        "executable":request.executable,"args":request.args,"cwd":request.cwd,"origin":format!("{:?}",request.origin),
        "shell":request.shell,"expectedDigest":request.expected_digest,"acceptedExitCodes":request.accepted_exit_codes,
        "versionArgs":request.version_args,"skipVersionProbe":request.skip_version_probe,"versionRequirement":request.version_requirement,
        "environment":request.environment,"environmentAllowlist":request.environment_allowlist,
        "sensitiveArgumentIndexes":request.sensitive_argument_indexes,"sensitiveEnvironmentNames":request.sensitive_environment_names,
        "requiresNetworkSandbox":request.requires_network_sandbox,
        "sandbox":request.sandbox.as_ref().map(|s|json!({"id":s.id,"network":s.network,"filesystemScope":s.filesystem_scope})),
        "timeoutMs":request.timeout_ms,"stdoutLimit":request.stdout_limit,"stderrLimit":request.stderr_limit})
}
fn stream(record: Option<&ArtifactRecord>, scratch: &AuditScratch) -> Value {
    let Some(r) = record else {
        return Value::Null;
    };
    let relative = Path::new(&r.path);
    assert!(
        r.immutable
            && !relative.is_absolute()
            && relative
                .components()
                .all(|c| matches!(c, Component::Normal(_)))
    );
    let root = fs::canonicalize(scratch.artifacts_dir()).unwrap();
    let path = fs::canonicalize(root.join(relative)).unwrap();
    assert!(path.starts_with(&root));
    let bytes = fs::read(&path).unwrap();
    assert_eq!(r.digest, digest(&bytes));
    assert_eq!(r.bytes, bytes.len());
    json!({"path":r.path,"absolutePath":path,"digest":r.digest,"bytes":r.bytes,"immutable":r.immutable,"rawBytes":bytes})
}
struct ExactPolicy {
    root: PathBuf,
    scratch: Arc<AuditScratch>,
    enrollment: Value,
    files: BTreeMap<String, String>,
    plan: String,
    control: String,
    decisions: Mutex<Vec<Value>>,
}
impl ExactPolicy {
    fn args(&self, task: &str) -> Vec<String> {
        let home = self.scratch.root().join("cache").join("jvm-owned/home");
        let stage = self.scratch.root().join("tmp").join("jvm-source");
        let agent=home.join("wrapper/dists/gradle-9.2.1-bin/2t0n5ozlw9xmuyvbp7dnzaxug/gradle-9.2.1/lib/agents/gradle-instrumentation-agent-9.2.1.jar");
        let temp = self.scratch.root().join("cache/jvm-owned/tmp");
        let daemon_args=format!("-Xmx512m -Xms256m -XX:MaxMetaspaceSize=384m -XX:+HeapDumpOnOutOfMemoryError -Dfile.encoding=UTF-8 -Duser.language=en -Duser.country=US -Duser.variant= -Djava.io.tmpdir={}",temp.display());
        let mut args = vec![
            "-Xmx512m".into(),
            "-Xms256m".into(),
            "-XX:MaxMetaspaceSize=384m".into(),
            "-XX:+HeapDumpOnOutOfMemoryError".into(),
            "-Dfile.encoding=UTF-8".into(),
            "-Duser.language=en".into(),
            "-Duser.country=US".into(),
            "-Duser.variant=".into(),
            format!("-Djava.io.tmpdir={}", temp.display()),
            format!("-javaagent:{}", agent.display()),
            format!("-Dgradle.user.home={}", home.display()),
            "-cp".into(),
            stage
                .join("gradle/wrapper/gradle-wrapper.jar")
                .to_string_lossy()
                .into_owned(),
            "org.gradle.wrapper.GradleWrapperMain".into(),
            format!("-Dorg.gradle.jvmargs={daemon_args}"),
            "--offline".into(),
            "--no-daemon".into(),
            "--console=plain".into(),
            "--no-configuration-cache".into(),
            "--gradle-user-home".into(),
            home.to_string_lossy().into_owned(),
            "--project-cache-dir".into(),
            self.scratch
                .root()
                .join("cache")
                .join("jvm-owned/project")
                .to_string_lossy()
                .into_owned(),
        ];
        if task == "wrapper" {
            args.push("--version".into())
        } else {
            args.push("--rerun-tasks".into());
            args.push(
                match task {
                    "compile" => "legionCompile",
                    "lint" => "legionLint",
                    "dependency" => "legionDependency",
                    "test" => "legionTest",
                    _ => "INVALID",
                }
                .into(),
            )
        };
        args
    }
    fn expected(&self, task: &str, request_id: String) -> ExternalToolRequest {
        let stage = self.scratch.root().join("tmp").join("jvm-source");
        let java = Path::new(
            self.enrollment["toolchains"]["jdk"]["root"]
                .as_str()
                .unwrap(),
        )
        .join("bin/java");
        let profile=format!("(version 1)\n(allow default)\n(deny network*)\n(deny file-write* (subpath \"{0}\"))\n(allow file-write-data (require-all (subpath \"{0}\") (vnode-type DIRECTORY)))\n(allow network-bind (local udp \"*:*\"))\n",stage.to_string_lossy().replace('\\',"\\\\").replace('"',"\\\""));
        let sha = digest(profile.as_bytes());
        let profile_path = self
            .scratch
            .sandbox_dir()
            .join(format!("audit-gradle-{}.sb", &sha[7..]));
        assert_eq!(fs::read(&profile_path).unwrap(), profile.as_bytes());
        let mut wrapped_args = vec![
            "-f".into(),
            profile_path.to_string_lossy().into_owned(),
            "--".into(),
            java.to_string_lossy().into_owned(),
        ];
        wrapped_args.extend(self.args(task));
        let auth = legion_effects::SandboxAuthentication {
            id: format!("sandbox:macos:gradle-bind-only:{}", &sha[7..]),
            network: true,
            filesystem_scope: Some(stage.to_string_lossy().into_owned()),
            wrapped_executable: "/usr/bin/sandbox-exec".into(),
            wrapped_args,
        };
        let (mut environment, mut allowlist) = expected_environment(self.scratch.root());
        let jdk = self.enrollment["toolchains"]["jdk"]["root"]
            .as_str()
            .unwrap();
        for (name, value) in [
            ("PATH", format!("{jdk}/bin:/usr/bin:/bin")),
            ("JAVA_HOME", jdk.into()),
            (
                "GRADLE_USER_HOME",
                self.scratch
                    .root()
                    .join("cache")
                    .join("jvm-owned/home")
                    .to_string_lossy()
                    .into_owned(),
            ),
            (
                "LEGION_KOTLIN_HOME",
                self.enrollment["toolchains"]["kotlin"]["root"]
                    .as_str()
                    .unwrap()
                    .into(),
            ),
            (
                "LEGION_SCALA_HOME",
                self.enrollment["toolchains"]["scala"]["root"]
                    .as_str()
                    .unwrap()
                    .into(),
            ),
            (
                "LEGION_JVM_BUILD",
                self.scratch
                    .root()
                    .join("cache")
                    .join("jvm-owned/build")
                    .to_string_lossy()
                    .into_owned(),
            ),
            ("NO_COLOR", "1".into()),
            ("LC_ALL", "C".into()),
        ] {
            environment.insert(name.into(), value);
            allowlist.insert(name.into());
        }
        let version_args = {
            let mut v = auth
                .wrapped_args
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<_>>();
            v.push(java.to_string_lossy().into_owned());
            v.extend(self.args("wrapper"));
            v
        };
        ExternalToolRequest {
            request_id,
            provider_id: "code.jvm".into(),
            plan_id: self.plan.clone(),
            policy_id: "audit".into(),
            task_id: Some(task.into()),
            expected_digest: Some(digest(&fs::read(&auth.wrapped_executable).unwrap())),
            executable: auth.wrapped_executable,
            args: auth.wrapped_args,
            cwd: stage.to_string_lossy().into_owned(),
            origin: ToolOrigin::TargetProject,
            accepted_exit_codes: [0].into_iter().collect(),
            version_args,
            environment,
            environment_allowlist: allowlist,
            requires_network_sandbox: true,
            sandbox: if self.control == "absent-sandbox" {
                None
            } else {
                Some(legion_effects::SandboxReceipt {
                    id: auth.id,
                    network: auth.network,
                    filesystem_scope: auth.filesystem_scope,
                })
            },
            timeout_ms: 120000,
            stdout_limit: 33554432,
            stderr_limit: 33554432,
            ..ExternalToolRequest::default()
        }
    }
    fn definition(&self) -> Value {
        json!({"id":POLICY,"version":1,"provider":"code.jvm","planDigest":self.plan,"control":self.control,"projectFiles":self.files,"enrollment":self.enrollment,"tasks":TASKS,"timeoutMs":120000,"stdoutLimit":33554432,"stderrLimit":33554432,"sandboxAdmission":legion_effects::gradle_sandbox::QUALIFICATION_ADMISSION,"scope":"exact constructed JVM/v1 project; no production admission"})
    }
}
fn expected_environment(run: &Path) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let names = [
        "PATH",
        "PATHEXT",
        "SystemRoot",
        "COMSPEC",
        "HOME",
        "USERPROFILE",
    ];
    let mut environment = names
        .iter()
        .filter_map(|n| std::env::var(n).ok().map(|v| ((*n).to_owned(), v)))
        .collect::<BTreeMap<_, _>>();
    let mut allowlist = names
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    for (name, relative) in [
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
        environment.insert(
            name.into(),
            run.join(relative).to_string_lossy().into_owned(),
        );
        allowlist.insert(name.into());
    }
    for (name, value) in [
        ("PYTHONDONTWRITEBYTECODE", "1"),
        ("PYTHONNOUSERSITE", "1"),
        ("GIT_CONFIG_NOSYSTEM", "1"),
    ] {
        environment.insert(name.into(), value.into());
        allowlist.insert(name.into());
    }
    (environment, allowlist)
}
impl PolicyAuthorizer for ExactPolicy {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        let task = r.task_id.as_deref().unwrap_or("");
        let mut decisions = self.decisions.lock().unwrap();
        let id_ok = r
            .request_id
            .strip_prefix("legion-audit/")
            .is_some_and(|id| {
                id.len() == 64
                    && id
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            });
        let allowed = TASKS.contains(&task)
            && id_ok
            && *r == self.expected(task, r.request_id.clone())
            && snapshot(&self.root) == self.files
            && !decisions.iter().any(|v| v["requestId"] == r.request_id);
        decisions.push(json!({"requestId":r.request_id,"task":task,"allowed":allowed,"request":request_value(r)}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&canonical(&self.definition())),
            reason: Some(
                if allowed {
                    "exact frozen JVM fixture"
                } else {
                    "outside frozen JVM fixture"
                }
                .into(),
            ),
        }
    }
}
struct SharedPolicy(Arc<ExactPolicy>);
impl PolicyAuthorizer for SharedPolicy {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        self.0.authorize(r)
    }
}
struct Recorder {
    inner: Arc<dyn ExternalProjectTool>,
    scratch: Arc<AuditScratch>,
    policy: Arc<ExactPolicy>,
    rows: Arc<Mutex<Vec<Value>>>,
}
#[async_trait::async_trait]
impl ExternalProjectTool for Recorder {
    async fn execute(
        &self,
        mut request: ExternalToolRequest,
        cancel: tokio_util::sync::CancellationToken,
    ) -> ExecutionReceipt {
        let original = request_value(&request);
        if self.policy.control == "absent-sandbox" {
            request.sandbox = None;
        }
        if self.policy.control == "request-mutation" {
            request.args.push("--refresh-dependencies".into());
        }
        let req = request_value(&request);
        let receipt = self.inner.execute(request, cancel).await;
        let mut rows = self.rows.lock().unwrap();
        let row = json!({"providerRequest":original,"request":req,"executionReceipt":actual_receipt(&receipt),"stdout":stream(receipt.stdout.as_ref(),&self.scratch),"stderr":stream(receipt.stderr.as_ref(),&self.scratch)});
        fs::write(
            self.scratch
                .root()
                .join(format!("sdk-execution-{}.json", rows.len())),
            serde_json::to_vec_pretty(&row).unwrap(),
        )
        .unwrap();
        rows.push(row);
        if self.policy.control == "source-drift" && rows.len() == 1 {
            fs::write(
                self.policy.root.join("src/main/java/JavaAnswer.java"),
                "// drift after actual wrapper receipt\n",
            )
            .unwrap();
        }
        if self.policy.control == "dependency-drift"
            && rows.last().unwrap()["request"]["taskId"] == "dependency"
        {
            fs::write(
                self.policy
                    .root
                    .join("support/src/main/java/support/Support.java"),
                "// dependency source drift after actual graph receipt\n",
            )
            .unwrap();
        }
        receipt
    }
}
fn fixtures(root: &Path, enrollment: &Value, control: &str) {
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(FIXTURES);
    for relative in snapshot(&source).keys() {
        let to = root.join(relative);
        fs::create_dir_all(to.parent().unwrap()).unwrap();
        fs::copy(source.join(relative), to).unwrap();
    }
    fs::copy(
        enrollment["assets"]["wrapper"]["path"].as_str().unwrap(),
        root.join("gradle/wrapper/gradle-wrapper.jar"),
    )
    .unwrap();
    let change = |path: &str, from: &str, to: &str| {
        let path = root.join(path);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.contains(from));
        fs::write(path, text.replace(from, to)).unwrap();
    };
    match control {
        "positive" => {
            for path in [
                "src/main/java/JavaAnswer.java",
                "src/main/kotlin/KotlinAnswer.kt",
                "src/main/scala/ScalaAnswer.scala",
            ] {
                change(path, "Support.answer()", "Support.legacy()");
            }
            change("src/test/kotlin/known-answer.kts","check(KotlinAnswer.answer() == 42)","@Deprecated(\"known-answer\") fun legacyAnswer() = KotlinAnswer.answer()\ncheck(legacyAnswer() == 42)");
        }
        "compile-error" => change(
            "src/main/java/JavaAnswer.java",
            "return support.Support.answer() * 7;",
            "return DOES_NOT_EXIST;",
        ),
        "test-failure" => change(
            "src/test/java/KnownAnswerTest.java",
            "actual != 42",
            "actual != 43",
        ),
        "no-op-test" => {
            fs::write(root.join("src/test/java/KnownAnswerTest.java"),"public final class KnownAnswerTest { public static void main(String[] args) {} }\n").unwrap();
        }
        "missing-dependency" => {
            change("support/build.gradle","plugins { id 'java-library' }","plugins { id 'java-library' }\ntasks.named('jar') { archiveBaseName = 'changed-support' }");
        }
        "unsupported-variant" => {
            fs::write(
                root.join("unlisted.scala"),
                "object Unlisted { def answer = 42 }\n",
            )
            .unwrap();
        }
        _ => {}
    }
}
fn spec() -> Value {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    let mut spec = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "code.jvm")
        .unwrap()
        .clone();
    spec.as_object_mut().unwrap().remove("benchmark");
    spec
}
fn child(control: &str, base: &Path, retained: &Path) {
    let enrollment_bytes =
        fs::read(std::env::var_os("LEGION_JVM_SDK_ENROLLMENT_JSON").unwrap()).unwrap();
    let enrollment: Value = serde_json::from_slice(&enrollment_bytes).unwrap();
    let root = base.join("source");
    fs::create_dir_all(&root).unwrap();
    fixtures(&root, &enrollment, control);
    let root = root.canonicalize().unwrap();
    let before = snapshot(&root);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(control)
        .unwrap();
    // ProviderSpec's required benchmark field carries no execution semantics.
    // Normalize it to an empty object (the contract requires an object) so the
    // plan never depends on enrollment state; retained providerSpec omits it.
    let mut execution_spec = spec();
    execution_spec["benchmark"] = json!({});
    let frozen = AuditPlan::compile_with_root(
        Some(&root),
        &inventory,
        &[serde_json::from_value::<ProviderSpec>(execution_spec).unwrap()],
    )
    .unwrap()
    .freeze(Some(b"jvm-sdk-frozen-fixture-key"))
    .unwrap();
    let scratch =
        Arc::new(AuditScratch::with_scratch_dir(&root, retained.join("scratch")).unwrap());
    let policy = Arc::new(ExactPolicy {
        root: root.clone(),
        scratch: scratch.clone(),
        enrollment: enrollment.clone(),
        files: before.clone(),
        plan: frozen.digest().into(),
        control: control.into(),
        decisions: Mutex::new(Vec::new()),
    });
    let actual: Arc<dyn ExternalProjectTool> = if control == "rejected-admission" {
        Arc::new(legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
            legion_audit::execution_policy::OwnerAdmissionRequired,
        ))
    } else {
        Arc::new(legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
            SharedPolicy(policy.clone()),
        ))
    };
    let rows = Arc::new(Mutex::new(Vec::new()));
    let recorder = Recorder {
        inner: actual,
        scratch: scratch.clone(),
        policy: policy.clone(),
        rows: rows.clone(),
    };
    if control == "wrapper-drift" {
        fs::write(root.join("gradlew"), "#!/bin/sh\nexit 0\n").unwrap();
    }
    let native = NativeProviderRegistry::new(&root)
        .with_scratch(scratch.clone())
        .with_external_project_tool(Arc::new(AuditExternalProjectTool::new(recorder)))
        .with_code(
            code::ProviderExecutorAdapter::new()
                .with_root(&root)
                .with_sandbox(SandboxPolicy::Required)
                .with_tool_bounds(120000, 3600000),
        );
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let report = runtime
        .block_on(execute_with_cancellation(
            &frozen,
            &inventory,
            &native,
            tokio_util::sync::CancellationToken::new(),
        ))
        .unwrap();
    assert_eq!(report.results.len(), 1);
    let native_result = serde_json::to_value(&report.results[0].result).unwrap();
    let rows = rows.lock().unwrap().clone();
    let decisions = policy.decisions.lock().unwrap().clone();
    let mut result = json!({"control":control,"provider":"code.jvm","scope":if matches!(control,"absent-sandbox"|"request-mutation"){"sdk-boundary-control"}else{"native-provider-known-answer-fixture"},"fixtureSources":before,"fixtureAfter":snapshot(&root),"inventory":inventory,"planDigest":frozen.digest(),"frozenProvider":frozen.provider("code.jvm").unwrap(),"policyDefinition":policy.definition(),"policyDecisions":decisions,"sdkExecutions":rows,"nativeResult":native_result,"matched":false});
    let path = retained.join("case.json");
    fs::write(&path, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    let complete = matches!(control, "positive" | "nonempty-clean");
    assert_eq!(
        result["nativeResult"]["complete"], complete,
        "{control}: only full actual five-tool/all-language scopes complete"
    );
    if complete {
        assert_eq!(result["nativeResult"]["coverage"]["expected"], before.len());
        assert_eq!(result["nativeResult"]["coverage"]["examined"], before.len());
        assert_eq!(rows.len(), 5);
        assert!(result["nativeResult"]["coverage_gaps"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(result["fixtureAfter"], result["fixtureSources"]);
        for row in &rows {
            let r = &row["executionReceipt"];
            assert_eq!(r["state"], "completed");
            assert_eq!(r["complete"], true);
            assert_eq!(r["processTree"]["started"], true);
            assert_eq!(r["processTree"]["reaped"], true);
            assert_eq!(r["policy"]["allowed"], true);
            assert_eq!(r["sandbox"]["required"], true);
        }
        let findings = result["nativeResult"]["details"]["findingEvidence"]
            .as_object()
            .unwrap();
        if control == "positive" {
            for language in ["java", "kotlin", "kts", "scala"] {
                assert!(
                    findings
                        .values()
                        .any(|f| f["ruleId"] == format!("jvm-compiler-warning:{language}")),
                    "missing planted native {language} warning"
                );
            }
        } else {
            assert!(
                findings.is_empty(),
                "nonempty clean fixture produced false finding"
            );
        }
    } else {
        assert!(!result["nativeResult"]["coverage_gaps"]
            .as_array()
            .unwrap()
            .is_empty());
        let gaps = result["nativeResult"]["coverage_gaps"].to_string();
        let expected_gap = match control {
            "missing-tool" => "closure-root",
            "enrollment-drift" => "toolchain-drift",
            "wrapper-drift" => "changed-since-inventory",
            "unsupported-variant" => "source-set-denominator",
            "source-drift" | "dependency-drift" => "project-input-drift",
            "rejected-admission" => "native-owner-admission-unavailable",
            "request-mutation" => "unauthorized_effect",
            "absent-sandbox" => "sandbox-missing",
            "compile-error" => "tool-failed",
            "test-failure" => "tool-failed:test",
            "no-op-test" => "test-assertions-incomplete",
            "missing-dependency" => "dependency-artifact-identity",
            _ => panic!("unexpected control"),
        };
        assert!(
            gaps.contains(expected_gap),
            "{control}: intended gap {expected_gap} missing from {gaps}"
        );
        match control {
            "missing-tool" | "enrollment-drift" | "unsupported-variant" | "wrapper-drift" => {
                assert!(rows.is_empty())
            }
            "dependency-drift" => {
                assert_eq!(rows.len(), 5);
                assert_ne!(result["fixtureAfter"], result["fixtureSources"]);
            }
            "source-drift" => {
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0]["executionReceipt"]["state"], "completed");
                assert_ne!(result["fixtureAfter"], result["fixtureSources"]);
            }
            "rejected-admission" | "request-mutation" => {
                assert_eq!(rows.len(), 5);
                for row in &rows {
                    assert_eq!(row["executionReceipt"]["state"], "unauthorized_effect");
                    assert_eq!(row["executionReceipt"]["processTree"]["started"], false);
                }
            }
            "absent-sandbox" => {
                assert_eq!(rows.len(), 5);
                for row in &rows {
                    assert_eq!(row["executionReceipt"]["state"], "sandbox_missing");
                    assert_eq!(row["executionReceipt"]["processTree"]["started"], false);
                }
            }
            "compile-error" | "test-failure" | "no-op-test" | "missing-dependency" => {
                assert_eq!(rows.len(), 5);
                assert!(rows
                    .iter()
                    .any(|row| row["executionReceipt"]["processTree"]["started"] == true));
            }
            _ => panic!("unfrozen control"),
        }
    }
    result["matched"] = json!(true);
    fs::write(path, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
}
#[test]
#[ignore = "fixed CI-enrolled macOS arm64 JVM toolchains; external scratch/retention roots required"]
fn real_jvm_sdk_accuracy() {
    if let Ok(control) = std::env::var("LEGION_JVM_CONTROL") {
        let base = PathBuf::from(std::env::var_os("LEGION_JVM_CASE_ROOT").unwrap());
        let retained = PathBuf::from(std::env::var_os("LEGION_JVM_CASE_OUTPUT").unwrap());
        child(&control, &base, &retained);
        return;
    }
    assert_eq!(code::jvm::CONFIG.extensions, ["java", "kt", "kts", "scala"]);
    assert_eq!(code::jvm::CONFIG.tools, TASKS);
    assert_eq!(code::jvm::CONFIG.required_context, ["sourceSets"]);
    let base = PathBuf::from(
        std::env::var_os("LEGION_JVM_SDK_SCRATCH").expect("explicit external scratch required"),
    );
    assert!(base.is_absolute() && !base.exists());
    fs::create_dir_all(&base).unwrap();
    let base = base.canonicalize().unwrap();
    let retained = PathBuf::from(
        std::env::var_os("LEGION_JVM_SDK_OUTPUT").expect("explicit retained output required"),
    );
    assert!(retained.is_absolute() && !retained.exists());
    fs::create_dir_all(&retained).unwrap();
    let retained = retained.canonicalize().unwrap();
    let enrollment = PathBuf::from(
        std::env::var_os("LEGION_JVM_SDK_ENROLLMENT_JSON")
            .expect("fixed CI-provisioned JVM enrollment required"),
    )
    .canonicalize()
    .unwrap();
    let enrollment_bytes = fs::read(&enrollment).unwrap();
    fs::write(retained.join("enrollment.json"), &enrollment_bytes).unwrap();
    let confinement_path = PathBuf::from(
        std::env::var_os("LEGION_JVM_CONFINEMENT_RECORD")
            .expect("actual shared-owner confinement record required"),
    );
    let confinement_bytes = fs::read(&confinement_path).unwrap();
    let confinement: Value = serde_json::from_slice(&confinement_bytes).unwrap();
    assert_eq!(confinement["schema"], "legion-gradle-bind-confinement/1");
    assert_eq!(confinement["complete"], true);
    assert_eq!(
        confinement["sandboxAdmission"],
        legion_effects::gradle_sandbox::QUALIFICATION_ADMISSION
    );
    assert_eq!(
        confinement["sourceDigest"],
        digest(include_bytes!("../../legion-effects/src/gradle_sandbox.rs"))
    );
    assert_eq!(
        confinement["controls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["mode"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["confinement", "hang", "orphan"]
    );
    fs::write(retained.join("confinement.json"), &confinement_bytes).unwrap();
    let source_before = source_binding();
    let mut cases = Vec::new();
    let mut child_executions = Vec::new();
    for control in CONTROLS {
        let case_base = base.join(control);
        let output = retained.join(control);
        fs::create_dir_all(case_base.join("home")).unwrap();
        fs::create_dir_all(case_base.join("tmp")).unwrap();
        fs::create_dir_all(&output).unwrap();
        let child_enrollment = if matches!(control, "missing-tool" | "enrollment-drift") {
            let mut v: Value = serde_json::from_slice(&enrollment_bytes).unwrap();
            if control == "missing-tool" {
                v["toolchains"]["jdk"]["root"] = json!(case_base.join("missing-jdk"));
            } else {
                v["toolchains"]["kotlin"]["files"]["lib/kotlin-stdlib.jar"] =
                    json!("sha256:".to_owned() + &"0".repeat(64));
            }
            let path = case_base.join("missing-enrollment.json");
            fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
            path
        } else {
            enrollment.clone()
        };
        let child_output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "real_jvm_sdk_accuracy",
                "--ignored",
                "--nocapture",
            ])
            .current_dir(&case_base)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", case_base.join("home"))
            .env("XDG_CONFIG_HOME", case_base.join("home"))
            .env("TMPDIR", case_base.join("tmp"))
            .env("LEGION_JVM_SDK_ENROLLMENT_JSON", child_enrollment)
            .env("LEGION_JVM_CONTROL", control)
            .env("LEGION_JVM_CASE_ROOT", &case_base)
            .env("LEGION_JVM_CASE_OUTPUT", &output)
            .output()
            .unwrap();
        fs::write(output.join("child.stdout.log"), &child_output.stdout).unwrap();
        fs::write(output.join("child.stderr.log"), &child_output.stderr).unwrap();
        child_executions.push(json!({"control":control,"success":child_output.status.success(),"exitCode":child_output.status.code(),"stdout":{"path":format!("{control}/child.stdout.log"),"digest":digest(&child_output.stdout),"bytes":child_output.stdout.len()},"stderr":{"path":format!("{control}/child.stderr.log"),"digest":digest(&child_output.stderr),"bytes":child_output.stderr.len()}}));
        let case = fs::read(output.join("case.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .unwrap_or_else(|| json!({"control":control,"matched":false,"childFailure":true}));
        cases.push(case);
    }
    let unchanged =
        source_before == source_binding() && fs::read(&enrollment).unwrap() == enrollment_bytes;
    let eligible = unchanged
        && cases.len() == CONTROLS.len()
        && cases.iter().all(|c| c["matched"] == true)
        && child_executions.iter().all(|c| c["success"] == true);
    let mut record = json!({"schema":"legion-jvm-sdk-accuracy/1","provider":"code.jvm","operationContract":"jvm/v1","harness":HARNESS,"qualificationEligible":eligible,"productionQualification":false,"scope":"constructed frozen Gradle JVM/v1 controls on macOS arm64; compiler diagnostic lint only; no arbitrary-project or production owner-admission claim","providerSpec":spec(),"originalContract":{"extensions":code::jvm::CONFIG.extensions,"variants":code::jvm::CONFIG.variants,"tools":code::jvm::CONFIG.tools,"context":code::jvm::CONFIG.required_context},"sourceClosure":source_before,"sourceUnchanged":unchanged,"confinement":{"file":"confinement.json","digest":digest(&confinement_bytes),"bytes":confinement_bytes.len()},"enrollment":{"file":"enrollment.json","digest":digest(&enrollment_bytes),"bytes":enrollment_bytes.len()},"controls":CONTROLS,"cases":cases,"childExecutions":child_executions});
    record["sandboxAdmission"] = json!(legion_effects::gradle_sandbox::QUALIFICATION_ADMISSION);
    record["qualificationDigest"] = json!(digest(&canonical(&record)));
    let bytes = serde_json::to_vec_pretty(&record).unwrap();
    fs::write(retained.join("code_jvm.json"), &bytes).unwrap();
    assert!(eligible,"JVM known-answer qualification failed; original SDK receipts/streams & child failures retained");
    println!(
        "JVM_SDK_ACCURACY_ARTIFACT {}",
        json!({"schema":"legion-jvm-sdk-artifact/1","provider":"code.jvm","file":"code_jvm.json","digest":digest(&bytes),"bytes":bytes.len(),"qualificationDigest":record["qualificationDigest"],"qualificationEligible":eligible,"productionQualification":false})
    );
}
