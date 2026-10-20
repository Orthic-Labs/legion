//! Genuine CMake/Clang/clang-tidy/CTest SDK controls for frozen C-family operations/v1.
#![cfg(target_os = "macos")]
use legion_audit::{
    native_providers::{
        code,
        legacy_checks::{AuditExternalProjectTool, AuditScratch},
    },
    AuditPlan, FilesystemInventorySource, InventorySource,
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
    sync::{Arc, Mutex},
};
const SOURCE: &str = "engine/crates/legion-audit/tests/c_family_sdk_accuracy.rs";
const FIXTURES: &str = "scripts/ci/fixtures/audit-c-family-sdk-accuracy";
const BOOTSTRAP: &str = "scripts/ci/audit-c-family-sdk-bootstrap.py";
const VALIDATOR: &str = "scripts/ci/audit-c-family-sdk-accuracy.py";
const CLAIM_SCOPE: &str =
    "source-bound CMake/Clang C-family operations/v1 known-answer SDK fixtures";
const POLICY: &str = "legion-c-family-native-fixture-v1";
const PROVIDER: &str = "code.c-family";
const CONTROLS: &[&str] = &[
    "nonempty-clean",
    "compiler-warning",
    "lint-warning",
    "analyzer-defect",
    "sanitizer-defect",
    "test-failure",
    "malformed-cmake",
    "unenrolled-sysroot",
    "orphan-source",
    "orphan-header",
    "source-drift",
    "missing-tool",
    "rejected-admission",
    "absent-sandbox",
];
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

fn generated_session_provenance(relative: &Path) -> bool {
    relative.parent()
        == Some(Path::new(
            "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance",
        ))
        && relative
            .file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.strip_suffix(".json"))
            .is_some_and(|name| {
                name.len() == 64
                    && name
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
}

fn bind_source_tree(root: &Path, path: &Path, files: &mut BTreeMap<String, String>) {
    assert!(!path.is_symlink(), "source binding refuses symlinks");
    if path.is_file() && generated_session_provenance(path.strip_prefix(root).unwrap()) {
        return;
    }
    if path.is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            bind_source_tree(root, &entry.unwrap().path(), files);
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

#[test]
fn source_binding_excludes_only_regular_generated_session_receipts() {
    fn snapshot(root: &Path) -> BTreeMap<String, String> {
        let mut files = BTreeMap::new();
        bind_source_tree(root, root, &mut files);
        files
    }
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    let base = std::env::var_os("RUNNER_TEMP")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let scratch = Scratch(base.join(format!(
        "legion-sdk-source-binding-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )));
    let root = &scratch.0;
    let prefix = "engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance/";
    let source = root.join("engine/crates/legion-audit/src/mod.rs");
    fs::create_dir_all(source.parent().unwrap()).unwrap();
    fs::write(&source, b"pub fn source() {}\n").unwrap();
    let baseline = snapshot(root);
    let receipt = root.join(format!("{prefix}{}.json", "0123456789abcdef".repeat(4)));
    fs::create_dir_all(receipt.parent().unwrap()).unwrap();
    fs::write(&receipt, b"generated receipt").unwrap();
    assert_eq!(snapshot(root), baseline);
    fs::write(&receipt, b"different host receipt").unwrap();
    assert_eq!(snapshot(root), baseline);
    fs::remove_file(&receipt).unwrap();
    fs::create_dir(&receipt).unwrap();
    fs::write(receipt.join("nested.rs"), b"retained child").unwrap();
    assert_eq!(snapshot(root).len(), baseline.len() + 1);
    fs::remove_dir_all(&receipt).unwrap();
    for relative in [
        format!("{prefix}{}.rs", "a".repeat(64)),
        format!("{prefix}{}.JSON", "a".repeat(64)),
        format!("{prefix}{}.json", "A".repeat(64)),
        format!("{prefix}{}.json", "g".repeat(64)),
        format!("{prefix}{}.json", "a".repeat(63)),
        format!("{prefix}{}.json", "a".repeat(65)),
        format!("{prefix}nested/{}.json", "a".repeat(64)),
        format!("nested/{prefix}{}.json", "a".repeat(64)),
    ] {
        let path = root.join(&relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"must remain bound").unwrap();
        let before = snapshot(root);
        assert_eq!(before.len(), baseline.len() + 1, "{relative}");
        fs::write(&path, b"changed retained bytes").unwrap();
        assert_ne!(snapshot(root), before, "{relative}");
        fs::remove_file(path).unwrap();
    }
    // A Unix backslash is filename data, even when display normalization looks generated.
    #[cfg(unix)]
    for relative in [
        format!(
            r"engine/crates/legion-audit/src/.audit/arcane/receipts/session-provenance\{}.json",
            "a".repeat(64)
        ),
        format!(
            r"engine\crates/legion-audit/src/.audit/arcane/receipts/session-provenance/{}.json",
            "a".repeat(64)
        ),
        format!(
            r"engine\crates\legion-audit\src\.audit\arcane\receipts\session-provenance\{}.json",
            "a".repeat(64)
        ),
    ] {
        let path = root.join(&relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"literal backslash source").unwrap();
        let before = snapshot(root);
        assert_eq!(before.len(), baseline.len() + 1, "{relative}");
        fs::write(&path, b"changed literal backslash source").unwrap();
        assert_ne!(snapshot(root), before, "{relative}");
        fs::remove_file(path).unwrap();
    }
    assert_eq!(snapshot(root), baseline);
    fs::write(&source, b"pub fn changed_source() {}\n").unwrap();
    assert_ne!(snapshot(root), baseline);
    std::os::unix::fs::symlink(&source, &receipt).unwrap();
    assert!(std::panic::catch_unwind(|| snapshot(root)).is_err());
    fs::remove_file(receipt).unwrap();
}

fn binding(id: &str, fixtures: &BTreeMap<String, String>) -> Value {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
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
        FIXTURES,
        BOOTSTRAP,
        VALIDATOR,
        "scripts/ci/audit-c-family-sdk-registration.py",
        "scripts/ci/schemas/audit-c-family-sdk-accuracy.schema.json",
    ] {
        bind_source_tree(&root, &root.join(path), &mut sources);
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
    for (name, value) in [
        ("NO_COLOR", "1"),
        ("CARGO_NET_OFFLINE", "true"),
        ("CARGO_TERM_COLOR", "never"),
    ] {
        env.insert(name.into(), value.into());
        allowed.insert(name.into());
    }
    for name in [
        "CARGO_HOME",
        "RUSTUP_HOME",
        "GOPATH",
        "GOROOT",
        "GOMODCACHE",
    ] {
        if let Ok(value) = std::env::var(name) {
            env.insert(name.into(), value);
            allowed.insert(name.into());
        }
    }
    (env, allowed)
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

#[derive(Clone)]
struct Toolchain {
    tools: BTreeMap<String, (PathBuf, String, String)>,
    runtime: BTreeMap<String, String>,
    enrollment: Value,
    enrollment_digest: String,
    enrollment_path: PathBuf,
    enrollment_bytes: Vec<u8>,
}
impl Toolchain {
    fn load(path: &Path) -> Self {
        let bytes = fs::read(path).unwrap();
        let enrollment_digest = digest(&bytes);
        let enrollment: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(enrollment["schema"], "legion-c-family-toolchain/1");
        assert_eq!(enrollment["productionQualification"], false);
        let mut tools = BTreeMap::new();
        for name in ["cmake", "ctest", "clang", "clang++", "clang-tidy", "make"] {
            let v = &enrollment["tools"][name];
            let p = PathBuf::from(v["path"].as_str().unwrap());
            assert!(p.is_absolute() && p.is_file());
            let bytes = fs::read(&p).unwrap();
            assert!(!bytes.starts_with(b"#!"));
            let d = v["digest"].as_str().unwrap().to_owned();
            assert_eq!(digest(&bytes), d);
            let version = v["version"].as_str().unwrap().to_owned();
            assert!(!version.trim().is_empty());
            tools.insert(name.into(), (p, d, version));
        }
        let runtime: BTreeMap<String, String> =
            serde_json::from_value(enrollment["runtimeFiles"].clone()).unwrap();
        assert!(!runtime.is_empty());
        assert!(
            runtime.keys().any(|p| p.contains("libclang_rt.asan")),
            "actual ASan runtime closure required"
        );
        assert!(
            runtime
                .keys()
                .any(|p| p.contains("CMake") || p.contains("cmake")),
            "actual CMake module closure required"
        );
        let out = Self {
            tools,
            runtime,
            enrollment,
            enrollment_digest,
            enrollment_path: path.into(),
            enrollment_bytes: bytes,
        };
        out.verify();
        out
    }
    fn verify(&self) {
        for (p, d, _) in self.tools.values() {
            assert_eq!(digest(&fs::read(p).unwrap()), *d);
        }
        for (p, d) in &self.runtime {
            assert!(Path::new(p).is_absolute());
            assert_eq!(digest(&fs::read(p).unwrap()), *d);
        }
        for root in self.enrollment["runtimeRoots"].as_array().unwrap() {
            let aliases: BTreeMap<String, String> =
                serde_json::from_value(root["aliases"].clone()).unwrap();
            for (p, target) in &aliases {
                assert!(Path::new(p).is_symlink());
                assert_eq!(Path::new(p).canonicalize().unwrap(), PathBuf::from(target));
            }
        }
        assert_eq!(
            digest(&fs::read(&self.enrollment_path).unwrap()),
            self.enrollment_digest
        );
    }
    fn search(&self) -> Vec<PathBuf> {
        let mut dirs = Vec::new();
        for (p, _, _) in self.tools.values() {
            let dir = p.parent().unwrap().to_path_buf();
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
        dirs
    }
}
struct Scope {
    plan: String,
    root: PathBuf,
    scratch: Arc<AuditScratch>,
    stage: PathBuf,
    chain: Toolchain,
    wrapper: PathBuf,
    wrapper_digest: String,
    search: Vec<PathBuf>,
    seen: Mutex<BTreeSet<String>>,
    decisions: Mutex<Vec<Value>>,
    allow_absent: bool,
}
impl Scope {
    fn profile(&self, _cwd: &str) -> String {
        format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{0}\"))\n(deny file-write* (subpath \"{0}\"))\n",self.root.to_str().unwrap().replace('\\',"\\\\").replace('"',"\\\""))
    }
    fn environment(
        &self,
        r: &ExternalToolRequest,
    ) -> Option<(BTreeMap<String, String>, BTreeSet<String>)> {
        let (mut env, mut allow) = expected_environment(self.scratch.root());
        env.insert(
            "PATH".into(),
            std::env::join_paths(&self.search).ok()?.to_str()?.into(),
        );
        for (name, value) in [
            ("CPATH", String::new()),
            ("C_INCLUDE_PATH", String::new()),
            ("CPLUS_INCLUDE_PATH", String::new()),
            ("OBJC_INCLUDE_PATH", String::new()),
            ("HOME", self.stage.parent()?.join("home").to_str()?.into()),
            (
                "USERPROFILE",
                self.stage.parent()?.join("home").to_str()?.into(),
            ),
            (
                "XDG_CONFIG_HOME",
                self.stage.parent()?.join("home/.config").to_str()?.into(),
            ),
            ("LEGION_C_FAMILY_STAGE", self.stage.to_str()?.into()),
        ] {
            env.insert(name.into(), value);
            allow.insert(name.into());
        }
        for (n, v) in [
            (
                "LEGION_C_FAMILY_SDK_ENROLLMENT",
                self.chain.enrollment_path.to_str()?.to_owned(),
            ),
            (
                "LEGION_C_FAMILY_SDK_ENROLLMENT_DIGEST",
                self.chain.enrollment_digest.clone(),
            ),
        ] {
            env.insert(n.into(), v);
            allow.insert(n.into());
        }
        let cmake = self.chain.tools["cmake"].0.canonicalize().ok()?;
        let share = cmake.parent()?.parent()?.join("share");
        env.insert("LEGION_C_FAMILY_CMAKE_SHARE".into(), share.to_str()?.into());
        allow.insert("LEGION_C_FAMILY_CMAKE_SHARE".into());
        let generated = r.environment.get("LEGION_C_FAMILY_GENERATED")?;
        let map: BTreeMap<String, String> = serde_json::from_str(generated).ok()?;
        for (p, d) in &map {
            if !(Path::new(p).starts_with(self.stage.parent()?)
                || self.chain.runtime.get(p) == Some(d))
                || fs::read(p).ok().is_none_or(|b| digest(&b) != *d)
            {
                return None;
            }
        }
        env.insert("LEGION_C_FAMILY_GENERATED".into(), generated.clone());
        allow.insert("LEGION_C_FAMILY_GENERATED".into());
        if r.args
            .get(3)
            .and_then(|p| Path::new(p).file_name())
            .and_then(|p| p.to_str())
            == Some("ctest")
            && r.task_id.as_deref() == Some("sanitizer")
            && r.args.get(4).map(String::as_str) == Some("--output-on-failure")
        {
            for (n, v) in [
                (
                    "ASAN_OPTIONS",
                    "detect_leaks=0:halt_on_error=1:abort_on_error=0:exitcode=86",
                ),
                ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"),
            ] {
                env.insert(n.into(), v.into());
                allow.insert(n.into());
            }
        }
        Some((env, allow))
    }
    fn args(&self, r: &ExternalToolRequest, name: &str, args: &[String]) -> bool {
        let stage = self.stage.to_string_lossy().into_owned();
        let parent = self.stage.parent().unwrap();
        let build = parent.join("build");
        let instrumented = parent.join("instrumented");
        let task = r.task_id.as_deref().unwrap_or("");
        if name == "cmake" {
            if args.first().map(String::as_str) == Some("--build") {
                return [build, instrumented]
                    .iter()
                    .any(|b| args == ["--build", b.to_str().unwrap(), "--parallel", "1"]);
            }
            return [(&build,false),(&instrumented,true)].iter().any(|(dest,sanitized)|{
                let flags=if *sanitized{"-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all"}else{"-O0 -g"};
                let mut expected=vec!["--trace-expand".into(),"--trace-format=json-v1".into(),format!("--trace-redirect={}",dest.join("configure-trace.jsonl").display()),"-S".into(),stage.clone(),"-B".into(),dest.to_string_lossy().into_owned(),"-G".into(),"Unix Makefiles".into(),"-DCMAKE_BUILD_TYPE=Debug".into(),"-DCMAKE_EXPORT_COMPILE_COMMANDS=ON".into(),format!("-DCMAKE_MAKE_PROGRAM={}",self.chain.tools["make"].0.display()),format!("-DCMAKE_C_COMPILER={}",self.chain.tools["clang"].0.display()),format!("-DCMAKE_CXX_COMPILER={}",self.chain.tools["clang++"].0.display()),format!("-DCMAKE_C_FLAGS={flags}"),format!("-DCMAKE_CXX_FLAGS={flags}"),"-DBUILD_TESTING=ON".into(),"-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF".into(),"-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF".into()];
                expected.push(format!("-DCMAKE_OSX_SYSROOT={}",self.chain.enrollment["sdkRoot"].as_str().unwrap()));
                args==expected && task==if *sanitized{"sanitizer"}else{"compiler"}
            });
        }
        if name == "ctest" {
            return [build, instrumented].iter().any(|b| {
                (args
                    == [
                        "--show-only=json-v1",
                        "--output-log",
                        b.join("tests.json.log").to_str().unwrap(),
                    ]
                    && task
                        == if b.file_name().unwrap() == "build" {
                            "test"
                        } else {
                            "sanitizer"
                        })
                    || (args
                        == [
                            "--output-on-failure",
                            "--no-tests=error",
                            "--output-junit",
                            b.join("junit.xml").to_str().unwrap(),
                        ]
                        && task
                            == if b.file_name().unwrap() == "build" {
                                "test"
                            } else {
                                "sanitizer"
                            })
            });
        }
        let files = ["value.c", "branch.cc", "runtime.cxx", "main.cpp"];
        let mut flags = args;
        if name == "clang-tidy" {
            if task != "lint"
                || args.len() < 6
                || args[..3]
                    != [
                        "--config={}",
                        "--checks=-*,bugprone-branch-clone",
                        "--use-color=false",
                    ]
                || args[4] != "--"
                || !files
                    .iter()
                    .any(|f| args[3] == self.stage.join(f).to_string_lossy())
            {
                return false;
            }
            flags = &args[5..];
        } else if !["compiler", "analyzer"].contains(&task)
            || !files.iter().any(|f| {
                args.last()
                    .is_some_and(|p| *p == self.stage.join(f).to_string_lossy())
            })
        {
            return false;
        }
        let includes = format!("-I{stage}");
        flags.iter().all(|a| {
            a == "-isysroot"
                || a == self.chain.enrollment["sdkRoot"].as_str().unwrap()
                || a == &includes
                || [
                    "-O0",
                    "-g",
                    "-Wall",
                    "-Wextra",
                    "-std=gnu11",
                    "-std=gnu++17",
                    "-fno-color-diagnostics",
                    "-fno-caret-diagnostics",
                    "-fsyntax-only",
                    "--analyze",
                    "-Xanalyzer",
                    "-analyzer-output=text",
                ]
                .contains(&a.as_str())
                || files
                    .iter()
                    .any(|f| *a == self.stage.join(f).to_string_lossy())
        })
    }
    fn permits(&self, r: &ExternalToolRequest) -> bool {
        let Some(target) = r.args.get(3) else {
            return false;
        };
        let Some((name, (_, target_digest, _))) = self
            .chain
            .tools
            .iter()
            .find(|(_, v)| v.0.to_string_lossy() == *target)
        else {
            return false;
        };
        if name == "make" {
            return false;
        }
        let cwd = Path::new(&r.cwd);
        if ![
            self.stage.clone(),
            self.stage.parent().unwrap().join("build"),
            self.stage.parent().unwrap().join("instrumented"),
        ]
        .contains(&cwd.to_path_buf())
        {
            return false;
        }
        let profile = self.profile(&r.cwd);
        let profile_digest = digest(profile.as_bytes());
        let profile_path = self.scratch.sandbox_dir().join(format!(
            "audit-{}.sb",
            profile_digest.trim_start_matches("sha256:")
        ));
        let expected_prefix = [
            "-f".into(),
            profile_path.to_string_lossy().into_owned(),
            "--".into(),
            target.clone(),
        ];
        let environment = self.environment(r);
        r.schema_version == 1
            && r.provider_id == PROVIDER
            && r.plan_id == self.plan
            && r.policy_id == "audit"
            && r.origin == ToolOrigin::TargetProject
            && !r.shell
            && r.executable == self.wrapper.to_string_lossy()
            && r.expected_digest.as_deref() == Some(self.wrapper_digest.as_str())
            && fs::read(&self.wrapper).is_ok_and(|b| digest(&b) == self.wrapper_digest)
            && fs::read(target).is_ok_and(|b| digest(&b) == *target_digest)
            && r.args.len() > 4
            && r.args[..4] == expected_prefix
            && self.args(r, name, &r.args[4..])
            && r.version_args == [expected_prefix.to_vec(), vec!["--version".into()]].concat()
            && !r.skip_version_probe
            && r.version_requirement.is_none()
            && r.requires_network_sandbox
            && (r.sandbox.as_ref().is_some_and(|s| {
                s.id == format!(
                    "sandbox:macos:{}",
                    profile_digest.trim_start_matches("sha256:")
                ) && s.network
                    && s.filesystem_scope.as_deref() == self.root.to_str()
            }) || self.allow_absent && r.sandbox.is_none())
            && fs::read(profile_path).is_ok_and(|b| b == profile.as_bytes())
            && environment.is_some_and(|(env, allow)| {
                r.environment == env && r.environment_allowlist == allow
            })
            && r.accepted_exit_codes
                == if ["clang", "clang++", "clang-tidy"].contains(&name.as_str()) {
                    [0, 1].into_iter().collect()
                } else {
                    [0].into_iter().collect()
                }
            && r.timeout_ms > 0
            && r.timeout_ms <= 120000
            && r.stdout_limit == 33554432
            && r.stderr_limit == 33554432
            && r.sensitive_argument_indexes.is_empty()
            && r.sensitive_environment_names.is_empty()
    }
}
struct SharedScope(Arc<Scope>);
impl PolicyAuthorizer for SharedScope {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        self.0.chain.verify();
        let allowed = self.0.permits(r) && self.0.seen.lock().unwrap().insert(r.request_id.clone());
        self.0
            .decisions
            .lock()
            .unwrap()
            .push(json!({"request":request_value(r),"allowed":allowed}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&canonical_bytes(
                &json!({"plan":self.0.plan,"stage":self.0.stage,"toolchain":self.0.chain.enrollment,"source":SOURCE}),
            )),
            reason: Some("exact source-bound native C-family SDK fixture only".into()),
        }
    }
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
struct Recorder {
    inner: Arc<dyn ExternalProjectTool>,
    scratch: Arc<AuditScratch>,
    rows: Arc<Mutex<Vec<Value>>>,
    requests: Arc<Mutex<Vec<ExternalToolRequest>>>,
    drift: Option<PathBuf>,
    absent_sandbox: bool,
}
#[async_trait::async_trait]
impl ExternalProjectTool for Recorder {
    async fn execute(
        &self,
        mut request: ExternalToolRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> ExecutionReceipt {
        if self.absent_sandbox {
            request.sandbox = None;
        }
        let req = request_value(&request);
        self.requests.lock().unwrap().push(request.clone());
        let receipt = self.inner.execute(request, cancellation).await;
        if self.requests.lock().unwrap().len() == 1 {
            if let Some(path) = &self.drift {
                fs::write(
                    path,
                    "/* controlled source drift */\nint c_value(void){return 10;}\n",
                )
                .unwrap();
            }
        }
        let mut rows = self.rows.lock().unwrap();
        let path = self
            .scratch
            .root()
            .join(format!("sdk-execution-{}.json", rows.len()));
        // Retain original receipt before stream verification can fail; no receipt is minted here.
        let receipt_value = actual_receipt(&receipt);
        fs::write(
            &path,
            serde_json::to_vec_pretty(&json!({"request":req,"executionReceipt":receipt_value,
            "stdout":null,"stderr":null}))
            .unwrap(),
        )
        .unwrap();
        let row = json!({"request":req,"executionReceipt":receipt_value,
            "stdout":stream(receipt.stdout.as_ref(),&self.scratch),"stderr":stream(receipt.stderr.as_ref(),&self.scratch)});
        fs::write(&path, serde_json::to_vec_pretty(&row).unwrap()).unwrap();
        rows.push(row);
        receipt
    }
}

fn fixture_files(control: &str) -> BTreeMap<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .join(FIXTURES);
    let mut files: BTreeMap<String, String> = [
        "CMakeLists.txt",
        "common.h",
        "detail.hpp",
        "value.c",
        "branch.cc",
        "runtime.cxx",
        "main.cpp",
    ]
    .into_iter()
    .map(|p| (p.into(), fs::read_to_string(root.join(p)).unwrap()))
    .collect();
    match control {
        "compiler-warning" => {
            files.insert(
                "value.c".into(),
                "#include \"common.h\"\nint c_value(void) { int never_used; return 10; }\n".into(),
            );
        }
        "lint-warning" => {
            files.insert("branch.cc".into(),"#include \"detail.hpp\"\nint cc_value() { volatile int input = 1; if (input == 1) { return 11; } else { return 11; } }\n".into());
        }
        "analyzer-defect" => {
            files.insert("branch.cc".into(),"#include \"detail.hpp\"\nint cc_value() { return 11; }\nint analyzer_only() { int *pointer = 0; return *pointer; }\n".into());
        }
        "sanitizer-defect" => {
            files.insert("runtime.cxx".into(),"#include \"detail.hpp\"\nint cxx_value() {\n#if __has_feature(address_sanitizer)\n  volatile int zero = 0; return 12 / zero;\n#else\n  return 12;\n#endif\n}\n".into());
        }
        "test-failure" => {
            let main = files.get_mut("main.cpp").unwrap();
            *main = main.replace("return 0;", "return 5;");
        }
        "malformed-cmake" => {
            files.insert(
                "CMakeLists.txt".into(),
                "cmake_minimum_required(VERSION 3.20)\nproject(\n".into(),
            );
        }
        "unenrolled-sysroot" => {
            files
                .get_mut("CMakeLists.txt")
                .unwrap()
                .push_str("set(CMAKE_OSX_SYSROOT /tmp)\n");
        }
        "orphan-source" => {
            files.insert(
                "unbuilt.c".into(),
                "int unbuilt(void) { return 7; }\n".into(),
            );
        }
        "orphan-header" => {
            files.insert(
                "unread.hpp".into(),
                "inline int unread() { return 7; }\n".into(),
            );
        }
        _ => {}
    }
    files
}

fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<String, String>) {
        assert!(!path.is_symlink());
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                walk(root, &entry.unwrap().path(), out);
            }
        } else {
            out.insert(
                path.strip_prefix(root).unwrap().to_str().unwrap().into(),
                digest(&fs::read(path).unwrap()),
            );
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

fn case(base: &Path, retained: &Path, chain: &Toolchain, control: &str) -> Value {
    let id = format!("code-c-family-{control}");
    let root = base.join(&id).join("source");
    let files = fixture_files(control);
    for (path, text) in &files {
        let target = root.join(path);
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(target, text).unwrap();
    }
    let root = fs::canonicalize(root).unwrap();
    let before = snapshot(&root);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&id)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec(PROVIDER)).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"native-c-family-constructed-sdk-key"))
        .unwrap();
    let scratch =
        Arc::new(AuditScratch::with_scratch_dir(&root, retained.join("cases").join(&id)).unwrap());
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let search = chain.search();
    let scope = Arc::new(Scope {
        plan: frozen.digest().into(),
        root: root.clone(),
        scratch: scratch.clone(),
        stage: scratch.root().join("tmp/c-family/source"),
        chain: chain.clone(),
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
        search: search.clone(),
        seen: Mutex::new(BTreeSet::new()),
        decisions: Mutex::new(Vec::new()),
        allow_absent: control == "absent-sandbox",
    });
    let inner: Arc<dyn ExternalProjectTool> = if control == "rejected-admission" {
        Arc::new(legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
            legion_audit::execution_policy::OwnerAdmissionRequired,
        ))
    } else {
        Arc::new(legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
            SharedScope(scope.clone()),
        ))
    };
    let rows = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::new(Mutex::new(Vec::new()));
    let recorder = Recorder {
        inner,
        scratch: scratch.clone(),
        rows: rows.clone(),
        requests: requests.clone(),
        drift: (control == "source-drift").then(|| root.join("value.c")),
        absent_sandbox: control == "absent-sandbox",
    };
    let search = if control == "missing-tool" {
        let missing = base.join("empty-tools");
        fs::create_dir_all(&missing).unwrap();
        vec![missing]
    } else {
        search
    };
    let result = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(
            code::ProviderExecutorAdapter::new()
                .with_root(&root)
                .with_search_path(search)
                .execute_async(
                    &frozen,
                    frozen.provider(PROVIDER).unwrap(),
                    &inventory,
                    Arc::new(AuditExternalProjectTool::new(recorder)),
                    scratch.clone(),
                    tokio_util::sync::CancellationToken::new(),
                ),
        )
        .unwrap();
    let result = serde_json::to_value(result).unwrap();
    let sdk = rows.lock().unwrap().clone();
    let decisions = scope.decisions.lock().unwrap().clone();
    let after = snapshot(&root);
    let mut record = json!({"caseId":id,"fixtureRoot":root,"scratchRoot":scratch.root(),"control":control,"provider":PROVIDER,"productionQualification":false,"qualificationEligible":false,"scope":"source-bound CMake C/CPP known-answer native SDK fixture","fixtureFiles":files,"fixtureSources":before,"fixtureAfter":after,"inventory":inventory,"planDigest":frozen.digest(),"result":result,"sdkExecutions":sdk,"admissionDecisions":decisions,"assertionsPassed":false});
    let path = retained.join(format!("{id}.json"));
    fs::write(&path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    let findings = result["details"]["findingEvidence"].as_object().unwrap();
    let has = |rule: &str, path: &str| {
        findings
            .values()
            .any(|f| f["ruleId"].as_str().is_some_and(|r| r.contains(rule)) && f["path"] == path)
    };
    let gaps = result["coverage_gaps"].to_string();
    match control {
        "nonempty-clean" => {
            assert_eq!(result["complete"], true, "native nonempty-clean: {record}");
            assert!(findings.is_empty(), "{record}");
            for tool in ["compiler", "lint", "analyzer", "sanitizer", "test"] {
                assert_eq!(
                    result["details"]["nativeAnalysis"]["toolEvidence"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|v| v["id"] == tool)
                        .unwrap()["status"],
                    "pass",
                    "{record}"
                );
            }
            let runs = &result["details"]["nativeProducer"]["toolReceipts"];
            let text = runs.to_string();
            assert!(
                text.contains("dependencyCoverage")
                    || result.to_string().contains("dependencyCoverage")
            );
            assert!(result.to_string().contains("sanitizerResults"));
            let context = result["details"]["nativeProducer"]["toolReceipts"].to_string();
            assert!(context.contains("nativeInputSnapshots") && context.contains("treeDigest"));
            assert!(
                sdk.iter().any(|r| r["request"]["args"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|a| a == "-isysroot")),
                "SDK flag was not replayed"
            );
            let analysis = result.to_string();
            assert!(
                analysis.contains("sdkHeaders") && analysis.contains("stdint.h"),
                "actual SDK/header dependency evidence missing"
            );
            assert!(result.to_string().contains("testResults"));
        }
        "compiler-warning" => assert!(has("unused-variable", "value.c"), "{record}"),
        "lint-warning" => assert!(has("bugprone-branch-clone", "branch.cc"), "{record}"),
        "analyzer-defect" => assert!(has("core.NullDereference", "branch.cc"), "{record}"),
        "sanitizer-defect" => {
            assert!(has("ubsan:runtime-error", "runtime.cxx"), "{record}");
            assert_ne!(result["complete"], true);
            assert!(
                sdk.iter().any(|r| r["request"]["taskId"] == "sanitizer"
                    && r["executionReceipt"]["exitCode"] == 8),
                "{record}"
            );
        }
        "test-failure" => {
            assert_ne!(result["complete"], true);
            assert!(
                sdk.iter()
                    .any(|r| r["request"]["taskId"] == "test"
                        && r["executionReceipt"]["exitCode"] == 8),
                "{record}"
            );
        }
        "malformed-cmake" => {
            assert_ne!(result["complete"], true);
            assert!(
                sdk.iter()
                    .any(|r| r["executionReceipt"]["processTree"]["started"] == true
                        && r["executionReceipt"]["exitCode"] == 1),
                "{record}"
            );
        }
        "unenrolled-sysroot" => {
            assert_ne!(result["complete"], true);
            assert!(gaps.contains("unsupported-project-cmake-syntax"));
            assert!(sdk.is_empty());
        }
        "orphan-source" => {
            assert_ne!(result["complete"], true);
            assert!(gaps.contains("orphan-source-not-built"), "{record}");
        }
        "orphan-header" => {
            assert_ne!(result["complete"], true);
            assert!(gaps.contains("orphan-source-or-header"), "{record}");
        }
        "source-drift" => {
            assert_ne!(result["complete"], true);
            assert!(gaps.contains("source-closure-changed"), "{record}");
            assert_ne!(before, after);
            assert!(!sdk.is_empty());
        }
        "missing-tool" => {
            assert_ne!(result["complete"], true);
            assert!(gaps.contains("clang-missing"));
            assert!(sdk.is_empty());
        }
        "rejected-admission" => {
            assert_ne!(result["complete"], true);
            assert!(
                sdk.iter()
                    .any(|r| r["executionReceipt"]["state"] == "unauthorized_effect"
                        && r["executionReceipt"]["processTree"]["started"] == false),
                "{record}"
            );
        }
        "absent-sandbox" => {
            assert_ne!(result["complete"], true);
            assert!(
                sdk.iter()
                    .any(|r| r["executionReceipt"]["state"] == "sandbox_missing"
                        && r["executionReceipt"]["processTree"]["started"] == false),
                "{record}"
            );
        }
        _ => unreachable!(),
    }
    if control != "source-drift" {
        assert_eq!(before, after, "fixture input changed");
    }
    for row in &sdk {
        let receipt = &row["executionReceipt"];
        assert_eq!(receipt["providerId"], PROVIDER);
        assert_eq!(receipt["planId"], frozen.digest());
        if receipt["processTree"]["started"] == true {
            assert_eq!(receipt["policy"]["allowed"], true);
            assert_eq!(receipt["sandbox"]["required"], true);
            assert_eq!(receipt["processTree"]["reaped"], true);
            let target = row["request"]["args"][3].as_str().unwrap();
            let (_, _, version) = chain
                .tools
                .values()
                .find(|v| v.0.to_string_lossy() == target)
                .unwrap();
            assert!(
                receipt["executable"]["version"]["output"]
                    .as_str()
                    .unwrap()
                    .contains(version),
                "pinned native version mismatch: {row}"
            );
        }
    }
    record["assertionsPassed"] = json!(true);
    fs::write(path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    record
}

#[test]
#[ignore = "requires explicit pinned CMake/Clang/clang-tidy/CTest enrollment, macOS sandbox & external scratch"]
fn c_family_sdk_accuracy() {
    let base = fs::canonicalize(PathBuf::from(
        std::env::var_os("LEGION_C_FAMILY_SCRATCH").expect("explicit external scratch"),
    ))
    .unwrap();
    assert!(
        base.starts_with("/Volumes/D/scratch")
            || base.starts_with("/private/tmp")
            || base.starts_with("/tmp")
    );
    let run = base.join(format!(
        "c-family-sdk-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&run).unwrap();
    let retained = run.join("evidence");
    fs::create_dir_all(&retained).unwrap();
    let enrollment = PathBuf::from(
        std::env::var_os("LEGION_C_FAMILY_ENROLLMENT_JSON")
            .expect("pinned native toolchain/runtime enrollment required"),
    );
    let chain = Toolchain::load(&enrollment);
    assert!(chain.tools.values().all(|(p, _, _)| !p.starts_with(&run)));
    let cases: Vec<_> = CONTROLS
        .iter()
        .map(|c| case(&run, &retained, &chain, c))
        .collect();
    assert_eq!(cases.len(), CONTROLS.len());
    assert!(cases.iter().all(|c| c["assertionsPassed"] == true));
    let fixtures = fixture_files("nonempty-clean");
    let fixture_digests = fixtures
        .iter()
        .map(|(p, t)| (p.clone(), digest(t.as_bytes())))
        .collect();
    assert_eq!(
        chain.enrollment_digest,
        digest(&fs::read(&enrollment).unwrap()),
        "toolchain enrollment changed"
    );
    let mut record = json!({"schema":"legion-c-family-sdk-qualification/1","claimScope":CLAIM_SCOPE,"provider":PROVIDER,"productionQualification":false,"selfProducerQualification":false,"qualificationEligible":true,"operationsVersion":"c-family-operations/v1","sourceBinding":binding(PROVIDER,&fixture_digests),"toolchainEnrollment":chain.enrollment,"toolchainEnrollmentDigest":chain.enrollment_digest,"toolchainEnrollmentRawBytes":chain.enrollment_bytes,"controls":CONTROLS,"cases":cases,"assertionsPassed":true,"modelCalls":0});
    record["qualificationDigest"] = json!(digest(&canonical_bytes(&record)));
    chain.verify();
    let bytes = serde_json::to_vec_pretty(&record).unwrap();
    let path = retained.join("code-c-family-native-sdk.json");
    fs::write(&path, &bytes).unwrap();
    println!("C_FAMILY_SDK_ACCURACY_ARTIFACT {}",serde_json::to_string(&json!({"provider":PROVIDER,"path":path,"sha256":digest(&bytes),"qualificationDigest":record["qualificationDigest"]})).unwrap());
}
