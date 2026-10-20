//! Genuine PHP/Ruby SDK known-answer controls; no production admission is supplied.
#![cfg(target_os = "macos")]
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
    io::Write,
    os::unix::process::ExitStatusExt,
    path::{Component, Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};
const SOURCE: &str = "engine/crates/legion-audit/tests/real_php_ruby_code_command_accuracy.rs";
const FIXTURES: &str = "scripts/ci/fixtures/audit-code-php-ruby-sdk-accuracy";
const POLICY: &str = "legion-real-php-ruby-code-command-fixture-v1";
const PHP_RUBY: &str = "code.php-ruby";
const CONTROLS: [&str; 16] = [
    "nonempty-clean",
    "php-lint-positive",
    "ruby-lint-positive",
    "type-positive",
    "security-positive",
    "php-test-failure",
    "ruby-test-failure",
    "malformed-manifest",
    "malformed-lock",
    "source-drift",
    "missing-tool",
    "rejected-admission",
    "absent-sandbox",
    "disabled-sandbox",
    "timeout",
    "cancel",
];
const ENV: [&str; 4] = [
    "LEGION_PHP_RUBY_SDK_ENROLLMENT_JSON",
    "LEGION_PHP_RUBY_SDK_PHP",
    "LEGION_PHP_RUBY_SDK_RUBY",
    "LEGION_PHP_RUBY_SDK_BIN_DIR",
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

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let base = std::env::var_os("LEGION_PHP_RUBY_CODE_COMMAND_SCRATCH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/Volumes/D/scratch"));
        let path = base.join(format!(
            "legion-php-ruby-code-command-{}-{}",
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
        FIXTURES,
        "scripts/ci/php-ruby-sdk-assets",
        "scripts/ci/audit-php-ruby-sdk-bootstrap.py",
        "scripts/ci/provision-python-qualification-tools.py",
        "scripts/ci/audit-pip-audit-provider-accuracy.py",
        "scripts/ci/php-ruby-sdk-inputs.json",
        "scripts/ci/audit-php-ruby-code-sdk-accuracy.py",
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

fn repository() -> PathBuf {
    fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")).unwrap()
}
fn owned_literal(path: &str, name: &str) -> String {
    let text = fs::read_to_string(repository().join(path)).unwrap();
    let start = format!("const {name}: &str = r#\"");
    let body = text.split_once(&start).expect("source-owned literal").1;
    body.split_once("\"#;")
        .expect("source-owned literal end")
        .0
        .into()
}
fn expected_inputs(policy: &ScopedPolicy, enrollment: &Value) -> Value {
    let base = policy.scratch.root().join("tmp").join("php-ruby-sdk");
    let stage = base.join("source");
    let home = base.join("home");
    let output = base.join("output");
    let repo = base.join("repository");
    let sources: BTreeMap<_, _> = policy
        .fixtures
        .iter()
        .map(|(p, t)| (p, digest(t.as_bytes())))
        .collect();
    let covered = enrollment["advisory"]["packages"].clone();
    let feed = enrollment["advisory"]["path"].as_str().unwrap();
    let metadata=serde_json::to_vec(&json!({"packages":{},"metadata-url":"p2/%package%.json","available-packages":covered,"security-advisories":{"metadata":false,"api-url":format!("file://{feed}")}})).unwrap();
    let config=serde_json::to_vec(&json!({"repositories":{"packagist.org":{"type":"composer","url":format!("file://{}",repo.display())}}})).unwrap();
    let mut owned = BTreeMap::new();
    owned.insert(
        repo.join("packages.json").to_str().unwrap().to_owned(),
        digest(&metadata),
    );
    owned.insert(
        home.join("config.json").to_str().unwrap().to_owned(),
        digest(&config),
    );
    owned.insert(
        feed.to_owned(),
        enrollment["advisory"]["digest"]
            .as_str()
            .unwrap()
            .to_owned(),
    );
    let selected: Vec<_> = policy
        .fixtures
        .keys()
        .filter(|p| p.ends_with(".php"))
        .collect();
    let enrollment_path = std::env::var(ENV[0]).unwrap();
    let descriptor =
        json!({"path":enrollment_path,"digest":digest(&fs::read(enrollment_path).unwrap())});
    json!({"typeSuppressionUnsupported":false,"schema":"legion-php-ruby-inputs/1","root":policy.root,"stage":stage,"sources":sources,"selectedPhp":selected,"ownedFiles":owned,"enrollment":descriptor,"advisoryCovered":true,"lockedPackages":["symfony/process"],"output":output})
}
fn expected_commands(policy: &ScopedPolicy, enrollment: &Value, timeout: u64) -> Vec<Value> {
    let (base_env, base_allow) = expected_environment(policy.scratch.root());
    let mut commands = Vec::new();
    let mut add = |task: &str,
                   tool: &str,
                   cwd: &Path,
                   args: Vec<String>,
                   probe: Vec<String>,
                   accepted: Vec<i32>,
                   env: BTreeMap<String, String>,
                   allow: BTreeSet<String>,
                   kind: Option<&str>| {
        commands.push(json!({"task":task,"tool":tool,"cwd":cwd,"args":policy.prefix(tool,&args),"versionArgs":policy.prefix(tool,&probe),"acceptedExitCodes":accepted,"environment":env,"environmentAllowlist":allow,"timeoutMs":timeout,"kind":kind}));
    };
    let ruby_cwd = policy.scratch.root().join("tmp").join("ruby-lint");
    for (n, _) in policy
        .fixtures
        .keys()
        .filter(|p| p.ends_with(".rb"))
        .enumerate()
    {
        let mut env = base_env.clone();
        for (name, value) in [
            ("HOME", ruby_cwd.to_string_lossy().into_owned()),
            ("USERPROFILE", ruby_cwd.to_string_lossy().into_owned()),
            ("XDG_CONFIG_HOME", ruby_cwd.to_string_lossy().into_owned()),
            ("RUBOCOP_OPTS", String::new()),
            ("RUBYOPT", String::new()),
            ("RUBYLIB", String::new()),
            ("GEM_HOME", enrollment["gemRoot"].as_str().unwrap().into()),
            ("GEM_PATH", enrollment["gemRoot"].as_str().unwrap().into()),
        ] {
            env.insert(name.into(), value);
        }
        let allow = base_allow
            .iter()
            .cloned()
            .chain(env.keys().cloned())
            .collect();
        let mut args = vec![
            "--config".into(),
            ruby_cwd.join("audit.yml").to_str().unwrap().into(),
        ];
        args.extend(
            [
                "--format",
                "json",
                "--lint",
                "--no-server",
                "--no-parallel",
                "--no-color",
                "--ignore-parent-exclusion",
                "--ignore-disable-comments",
                "--raise-cop-error",
                "--fail-level",
                "info",
                "--",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        args.push(
            ruby_cwd
                .join(format!("source-{n}.rb"))
                .to_str()
                .unwrap()
                .into(),
        );
        add(
            "ruby-lint",
            "rubocop",
            &ruby_cwd,
            args,
            vec!["--no-server".into(), "--version".into()],
            vec![0, 1],
            env,
            allow,
            None,
        );
    }
    let base = policy.scratch.root().join("tmp").join("php-ruby-sdk");
    let stage = base.join("source");
    let home = base.join("home");
    let output = base.join("output");
    let inputs = expected_inputs(policy, enrollment);
    let input_digest = digest(&serde_json::to_vec(&inputs).unwrap());
    let mut env = base_env.clone();
    for (key, value) in [
        (
            "LEGION_PHP_RUBY_FROZEN_INPUTS",
            base.join("inputs.json").to_str().unwrap().into(),
        ),
        ("LEGION_PHP_RUBY_FROZEN_DIGEST", input_digest),
        ("HOME", home.to_str().unwrap().into()),
        ("COMPOSER_HOME", home.to_str().unwrap().into()),
        (
            "COMPOSER_CACHE_DIR",
            output.join("composer-cache").to_str().unwrap().into(),
        ),
        ("COMPOSER_DISABLE_NETWORK", "1".into()),
        ("COMPOSER_NO_INTERACTION", "1".into()),
        ("GEM_HOME", enrollment["gemRoot"].as_str().unwrap().into()),
        ("GEM_PATH", enrollment["gemRoot"].as_str().unwrap().into()),
        (
            "BUNDLE_GEMFILE",
            stage.join("Gemfile").to_str().unwrap().into(),
        ),
        ("BUNDLE_FROZEN", "true".into()),
        ("BUNDLE_DISABLE_VERSION_CHECK", "true".into()),
        (
            "BUNDLE_USER_HOME",
            output.join("bundle").to_str().unwrap().into(),
        ),
        ("RUBYOPT", String::new()),
        ("RUBYLIB", String::new()),
    ] {
        env.insert(key.into(), value);
    }
    let phar = |name: &str| {
        vec![
            "-n".into(),
            enrollment["assets"][name]["path"].as_str().unwrap().into(),
        ]
    };
    let mut specs: Vec<(&str, &str, &str, Vec<String>, Vec<String>, Vec<i32>)> = Vec::new();
    let mut args = phar("composer");
    args.extend(
        [
            "--no-plugins",
            "--no-scripts",
            "validate",
            "--strict",
            "--no-check-publish",
        ]
        .map(str::to_owned),
    );
    specs.push((
        "package",
        "php",
        "composer-validate",
        args,
        {
            let mut p = phar("composer");
            p.push("--version".into());
            p
        },
        vec![0],
    ));
    let mut args = phar("phpstan");
    args.extend(
        [
            "analyse",
            "--error-format=json",
            "--no-progress",
            "--no-interaction",
            "--debug",
            "--level=max",
        ]
        .map(str::to_owned),
    );
    args.push("--autoload-file".into());
    args.push(
        enrollment["assets"]["phpunit"]["path"]
            .as_str()
            .unwrap()
            .into(),
    );
    args.push("--".into());
    args.extend(
        policy
            .fixtures
            .keys()
            .filter(|p| p.ends_with(".php"))
            .map(|p| stage.join(p).to_str().unwrap().into()),
    );
    specs.push((
        "type",
        "php",
        "phpstan",
        args,
        {
            let mut p = phar("phpstan");
            p.push("--version".into());
            p
        },
        vec![0, 1],
    ));
    let report = output.join("phpunit.xml");
    let mut args = phar("phpunit");
    args.extend(
        [
            "--colors=never",
            "--no-output",
            "--do-not-record-test-run-history",
            "--do-not-cache-test-index",
            "--fail-on-empty-test-suite",
            "--fail-on-risky",
            "--fail-on-warning",
            "--fail-on-notice",
            "--fail-on-deprecation",
            "--log-junit",
        ]
        .map(str::to_owned),
    );
    args.push(report.to_str().unwrap().into());
    specs.push((
        "test",
        "php",
        "phpunit",
        args,
        {
            let mut p = phar("phpunit");
            p.push("--version".into());
            p
        },
        vec![0],
    ));
    specs.push((
        "test",
        "php",
        "phpunit-report",
        vec![
            "-n".into(),
            "-r".into(),
            owned_literal(
                "engine/crates/legion-audit/src/native_providers/code/php_ruby_commands.rs",
                "JUNIT_CHECK",
            ),
            report.to_str().unwrap().into(),
        ],
        vec!["--version".into()],
        vec![0],
    ));
    specs.push((
        "test",
        "ruby",
        "rake",
        vec![
            enrollment["tools"]["bundle"]["path"]
                .as_str()
                .unwrap()
                .into(),
            "exec".into(),
            "rake".into(),
            "test".into(),
        ],
        vec!["--version".into()],
        vec![0],
    ));
    let mut args = phar("composer");
    args.extend(
        [
            "--no-plugins",
            "--no-scripts",
            "audit",
            "--locked",
            "--format=json",
            "--no-interaction",
        ]
        .map(str::to_owned),
    );
    specs.push((
        "security",
        "php",
        "composer-audit",
        args,
        {
            let mut p = phar("composer");
            p.push("--version".into());
            p
        },
        vec![0, 1],
    ));
    for (task, tool, kind, args, probe, accepted) in specs {
        let mut env = env.clone();
        env.insert("LEGION_PHP_RUBY_COMMAND".into(), kind.into());
        let allow = base_allow
            .iter()
            .cloned()
            .chain(env.keys().cloned())
            .collect();
        add(
            task,
            tool,
            &stage,
            args,
            probe,
            accepted,
            env,
            allow,
            Some(kind),
        );
    }
    for (n, path) in policy
        .fixtures
        .keys()
        .filter(|p| {
            (p.ends_with(".php") || p.ends_with(".rb"))
                && !(policy.root.parent().unwrap().file_name().unwrap()
                    == "code-php-ruby-source-drift"
                    && p.as_str() == "app.php")
        })
        .enumerate()
    {
        let (task, tool, extension) = if path.ends_with(".php") {
            ("lint", "php", "php")
        } else {
            ("ruby-syntax", "ruby", "rb")
        };
        let staged = policy
            .scratch
            .root()
            .join("tmp")
            .join(format!("native-syntax-{n}.{extension}"));
        let args = if tool == "php" {
            vec!["-n".into(), "-l".into(), staged.to_str().unwrap().into()]
        } else {
            vec!["--disable-gems".into(),"-rripper".into(),"-e".into(),"unless Ripper.sexp(File.read(ARGV.fetch(0))); STDERR.puts 'Ruby syntax error'; exit 1; end; puts 'Syntax OK'".into(),staged.to_str().unwrap().into()]
        };
        add(
            task,
            tool,
            &policy.root,
            args,
            vec!["--version".into()],
            vec![0, 1, 2, 255],
            base_env.clone(),
            base_allow.clone(),
            None,
        );
    }
    commands
}
struct ScopedPolicy {
    plan: String,
    root: PathBuf,
    scratch: Arc<AuditScratch>,
    fixtures: BTreeMap<String, String>,
    tools: BTreeMap<String, (PathBuf, String)>,
    wrapper: PathBuf,
    wrapper_digest: String,
    commands: Vec<Value>,
    runtime_digests: Value,
    enrollment_digest: String,
    absent_sandbox: bool,
    decisions: Mutex<Vec<Value>>,
}
impl ScopedPolicy {
    fn profile_text(&self) -> String {
        let root = self
            .root
            .to_str()
            .unwrap()
            .replace('\\', "\\\\")
            .replace('"', "\\\"");
        format!("(version 1)\n(allow default)\n(deny network*)\n(allow file-read* (subpath \"{root}\"))\n(deny file-write* (subpath \"{root}\"))\n")
    }
    fn profile(&self) -> PathBuf {
        self.scratch.sandbox_dir().join(format!(
            "audit-{}.sb",
            digest(self.profile_text().as_bytes()).trim_start_matches("sha256:")
        ))
    }
    fn sandbox_id(&self) -> String {
        format!(
            "sandbox:macos:{}",
            digest(self.profile_text().as_bytes()).trim_start_matches("sha256:")
        )
    }
    fn prefix(&self, tool: &str, args: &[String]) -> Vec<String> {
        let mut out = vec![
            "-f".into(),
            self.profile().to_str().unwrap().into(),
            "--".into(),
            self.tools[tool].0.to_str().unwrap().into(),
        ];
        out.extend_from_slice(args);
        out
    }
    fn definition(&self) -> Value {
        let inputs: BTreeMap<_, _> = self
            .fixtures
            .iter()
            .map(|(p, t)| (p, digest(t.as_bytes())))
            .collect();
        json!({"id":POLICY,"version":1,"scope":"exact constructed PHP/Ruby SDK fixtures; no production owner admission","provider":PHP_RUBY,"planDigest":self.plan,"originalRoot":self.root,"frozenInputs":inputs,"toolIdentities":self.tools,"runtimeDigests":self.runtime_digests,"enrollmentDigest":self.enrollment_digest,"wrapper":{"path":self.wrapper,"digest":self.wrapper_digest},"profile":{"path":self.profile(),"text":self.profile_text(),"receiptId":self.sandbox_id()},"commands":self.commands,"absentSandboxControl":self.absent_sandbox,"stdoutLimit":33554432,"stderrLimit":33554432})
    }
    fn fresh(&self) -> Self {
        Self {
            plan: self.plan.clone(),
            root: self.root.clone(),
            scratch: self.scratch.clone(),
            fixtures: self.fixtures.clone(),
            tools: self.tools.clone(),
            wrapper: self.wrapper.clone(),
            wrapper_digest: self.wrapper_digest.clone(),
            commands: self.commands.clone(),
            runtime_digests: self.runtime_digests.clone(),
            enrollment_digest: self.enrollment_digest.clone(),
            absent_sandbox: self.absent_sandbox,
            decisions: Mutex::new(Vec::new()),
        }
    }
    fn permits(&self, r: &ExternalToolRequest) -> bool {
        let matches: Vec<_> = self
            .commands
            .iter()
            .filter(|c| {
                r.task_id.as_deref() == c["task"].as_str()
                    && json!(r.args) == c["args"]
                    && json!(r.version_args) == c["versionArgs"]
                    && json!(r.cwd) == c["cwd"]
                    && json!(r.environment) == c["environment"]
                    && json!(r.environment_allowlist) == c["environmentAllowlist"]
                    && json!(r.accepted_exit_codes) == c["acceptedExitCodes"]
                    && json!(r.timeout_ms) == c["timeoutMs"]
            })
            .collect();
        let sandbox = if self.absent_sandbox {
            r.sandbox.is_none()
        } else {
            r.sandbox.as_ref().is_some_and(|s| {
                s.id == self.sandbox_id()
                    && s.network
                    && s.filesystem_scope.as_deref() == self.root.to_str()
            }) && fs::read(self.profile()).is_ok_and(|b| b == self.profile_text().as_bytes())
        };
        matches.len() == 1
            && r.schema_version == 1
            && r.provider_id == PHP_RUBY
            && r.plan_id == self.plan
            && r.policy_id == "audit"
            && r.request_id.strip_prefix("legion-audit/").is_some_and(|p| {
                p.len() == 64
                    && p.bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            })
            && r.origin == ToolOrigin::TargetProject
            && !r.shell
            && r.executable == self.wrapper.to_string_lossy()
            && r.expected_digest.as_deref() == Some(self.wrapper_digest.as_str())
            && fs::read(&self.wrapper).is_ok_and(|b| digest(&b) == self.wrapper_digest)
            && self
                .tools
                .values()
                .all(|(p, d)| fs::read(p).is_ok_and(|b| digest(&b) == *d))
            && !r.skip_version_probe
            && r.version_requirement.is_none()
            && r.requires_network_sandbox
            && sandbox
            && r.sensitive_argument_indexes.is_empty()
            && r.sensitive_environment_names.is_empty()
            && r.stdout_limit == 33554432
            && r.stderr_limit == 33554432
    }
}
impl PolicyAuthorizer for ScopedPolicy {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        let mut decisions = self.decisions.lock().unwrap();
        let allowed = self.permits(r) && !decisions.iter().any(|d| d["requestId"] == r.request_id);
        decisions.push(json!({"requestId":r.request_id,"taskId":r.task_id,"allowed":allowed,"request":request_value(r)}));
        PolicyDecision {
            allowed,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: digest(&canonical_bytes(&self.definition())),
            reason: Some(
                if allowed {
                    "exact constructed PHP/Ruby SDK fixture request"
                } else {
                    "outside exact constructed PHP/Ruby SDK fixture contract"
                }
                .into(),
            ),
        }
    }
}
struct SharedPolicy(Arc<ScopedPolicy>);
impl PolicyAuthorizer for SharedPolicy {
    fn authorize(&self, r: &ExternalToolRequest) -> PolicyDecision {
        self.0.authorize(r)
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
    cancel_rake: bool,
}
#[async_trait::async_trait]
impl ExternalProjectTool for Recorder {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> ExecutionReceipt {
        let req = request_value(&request);
        self.requests.lock().unwrap().push(request.clone());
        let cancellation = if self.cancel_rake
            && request
                .args
                .ends_with(&["exec".into(), "rake".into(), "test".into()])
        {
            let token = tokio_util::sync::CancellationToken::new();
            let stop = token.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                stop.cancel();
            });
            token
        } else {
            cancellation
        };
        let receipt = self.inner.execute(request, cancellation).await;
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
fn request_mutations(
    captured: &ExternalToolRequest,
    original: &ScopedPolicy,
    runtime: &tokio::runtime::Runtime,
) -> Value {
    let mut controls = Vec::new();
    for field in ["args", "cwd", "executable", "planId"] {
        let scratch = Arc::new(
            AuditScratch::with_scratch_dir(
                &original.root,
                original.scratch.root().join("mutations").join(field),
            )
            .unwrap(),
        );
        // Same policy definition/digest; fresh replay state cannot hide a binding defect.
        let policy = Arc::new(original.fresh());
        let mut request = captured.clone();
        request.request_id = format!(
            "legion-audit/{}",
            digest(format!("{}:mutation:{field}", captured.request_id).as_bytes())
                .trim_start_matches("sha256:")
        );
        assert!(
            policy.permits(&request),
            "fresh request ID must not cause mutation refusal"
        );
        let baseline = request_value(&request);
        match field {
            "args" => request.args.push("--outside-fixture-command".into()),
            "cwd" => {
                request.cwd = original
                    .root
                    .parent()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            }
            "executable" => {
                request.executable = original.tools["php"].0.to_string_lossy().into_owned()
            }
            "planId" => request.plan_id = "different-frozen-plan".into(),
            _ => unreachable!(),
        }
        let actual = legion_effects::EffectExecutor::new(
            legion_effects::platform::unix::UnixProcess::new(),
            legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
            SharedPolicy(policy.clone()),
        );
        let rows = Arc::new(Mutex::new(Vec::new()));
        let recorder = Recorder {
            inner: Arc::new(actual),
            scratch: scratch.clone(),
            rows: rows.clone(),
            requests: Arc::new(Mutex::new(Vec::new())),
            cancel_rake: false,
        };
        runtime.block_on(recorder.execute(request, tokio_util::sync::CancellationToken::new()));
        let executions = rows.lock().unwrap().clone();
        let mut row = json!({"control":format!("request-mutation-{field}"),"scope":"sdk-exact-policy-boundary",
            "qualificationEligible":false,"sourceRequest":request_value(captured),"baselineRequest":baseline,
            "mutatedField":field,"policyDefinition":policy.definition(),"policyDecisions":policy.decisions.lock().unwrap().clone(),
            "sdkExecutions":executions,"matched":false});
        fs::write(
            scratch.root().join("mutation-observation.json"),
            serde_json::to_vec_pretty(&row).unwrap(),
        )
        .unwrap();
        assert_eq!(row["policyDefinition"], original.definition());
        assert_eq!(executions.len(), 1);
        let receipt = &executions[0]["executionReceipt"];
        assert_eq!(receipt["state"], "unauthorized_effect");
        assert_eq!(receipt["complete"], false);
        assert_eq!(receipt["processTree"]["started"], false);
        assert_eq!(receipt["policy"]["allowed"], false);
        assert_eq!(receipt["policy"]["id"], POLICY);
        assert_eq!(
            receipt["policy"]["digest"],
            digest(&canonical_bytes(&original.definition()))
        );
        assert!(receipt["executable"].is_null());
        assert_eq!(row["policyDecisions"].as_array().unwrap().len(), 1);
        row["matched"] = json!(true);
        fs::write(
            scratch.root().join("mutation-observation.json"),
            serde_json::to_vec_pretty(&row).unwrap(),
        )
        .unwrap();
        controls.push(row);
    }
    json!(controls)
}
fn fixture_files(control: &str) -> BTreeMap<String, String> {
    let control = if [
        "missing-tool",
        "rejected-admission",
        "absent-sandbox",
        "disabled-sandbox",
        "source-drift",
    ]
    .contains(&control)
    {
        "nonempty-clean"
    } else {
        control
    };
    let root = repository().join(FIXTURES).join(control);
    fn walk(root: &Path, p: &Path, out: &mut BTreeMap<String, String>) {
        assert!(!p.is_symlink());
        if p.is_dir() {
            for e in fs::read_dir(p).unwrap() {
                walk(root, &e.unwrap().path(), out)
            }
        } else {
            out.insert(
                p.strip_prefix(root).unwrap().to_str().unwrap().into(),
                fs::read_to_string(p).unwrap(),
            );
        }
    }
    let mut files = BTreeMap::new();
    walk(&root, &root, &mut files);
    assert!(!files.is_empty());
    files
}
fn snapshot(root: &Path) -> BTreeMap<String, String> {
    fn walk(root: &Path, p: &Path, out: &mut BTreeMap<String, String>) {
        assert!(!p.is_symlink());
        if p.is_dir() {
            for e in fs::read_dir(p).unwrap() {
                walk(root, &e.unwrap().path(), out)
            }
        } else {
            out.insert(
                p.strip_prefix(root).unwrap().to_str().unwrap().into(),
                digest(&fs::read(p).unwrap()),
            );
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}
fn raw(row: &Value, key: &str) -> Vec<u8> {
    row[key]["rawBytes"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|n| u8::try_from(n.as_u64().unwrap()).unwrap())
                .collect()
        })
        .unwrap_or_default()
}
fn runtime_one(expected: &Value) -> Value {
    use std::io::Read;
    assert_eq!(expected["root"], "/");
    let roots: Vec<PathBuf> = expected["roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| PathBuf::from(v.as_str().unwrap()))
        .collect();
    let excluded: Vec<PathBuf> = expected["exclusions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| PathBuf::from(v.as_str().unwrap()))
        .collect();
    let mut files = BTreeMap::new();
    let mut links = BTreeMap::new();
    let mut count = 0usize;
    fn walk(
        path: &Path,
        excluded: &[PathBuf],
        files: &mut BTreeMap<String, String>,
        links: &mut BTreeMap<String, String>,
        count: &mut usize,
        depth: usize,
    ) {
        if excluded.iter().any(|p| path == p) {
            return;
        }
        *count += 1;
        assert!(
            *count <= 200000 && depth <= 128,
            "bounded closed runtime traversal"
        );
        let m = fs::symlink_metadata(path).unwrap();
        let key = path.strip_prefix("/").unwrap().to_str().unwrap().to_owned();
        if m.file_type().is_symlink() {
            links.insert(key, fs::read_link(path).unwrap().to_str().unwrap().into());
        } else if m.is_dir() {
            for e in fs::read_dir(path).unwrap() {
                walk(&e.unwrap().path(), excluded, files, links, count, depth + 1)
            }
        } else {
            assert!(m.is_file() && m.len() <= 128 * 1024 * 1024);
            let mut f = fs::File::open(path).unwrap();
            let mut h = Sha256::new();
            let mut total = 0u64;
            let mut buf = [0u8; 65536];
            loop {
                let n = f.read(&mut buf).unwrap();
                if n == 0 {
                    break;
                }
                total += n as u64;
                assert!(total <= 128 * 1024 * 1024);
                h.update(&buf[..n]);
            }
            assert_eq!(total, m.len());
            let after = fs::symlink_metadata(path).unwrap();
            assert!(after.is_file());
            assert_eq!(after.len(), m.len());
            assert_eq!(after.modified().ok(), m.modified().ok());
            files.insert(
                key,
                format!(
                    "sha256:{}",
                    h.finalize()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ),
            );
        }
    }
    for root in &roots {
        assert!(root.is_absolute());
        assert_eq!(fs::canonicalize(root).unwrap(), *root);
        walk(root, &excluded, &mut files, &mut links, &mut count, 0)
    }
    for (rel, target) in expected["links"].as_object().unwrap() {
        let path = Path::new("/").join(rel);
        assert!(path.is_symlink());
        assert_eq!(
            fs::read_link(&path).unwrap().to_str().unwrap(),
            target.as_str().unwrap()
        );
        let resolved = fs::canonicalize(&path).unwrap();
        assert!(!excluded.iter().any(|p| resolved.starts_with(p)));
        let key = resolved.strip_prefix("/").unwrap().to_str().unwrap();
        assert!(
            files.contains_key(key) || files.keys().any(|p| p.starts_with(&format!("{key}/"))),
            "alias target bytes retained"
        );
        links.insert(rel.clone(), target.as_str().unwrap().to_owned());
    }
    for absent in expected["absent"].as_array().unwrap() {
        assert!(fs::symlink_metadata(absent.as_str().unwrap())
            .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound));
    }
    assert_eq!(json!(files), expected["files"]);
    assert_eq!(json!(links), expected["links"]);
    let value =
        json!({"absent":expected["absent"],"files":files,"links":links,"roots":expected["roots"]});
    assert_eq!(digest(&canonical_bytes(&value)), expected["digest"]);
    json!({"schema":"legion-php-ruby-sdk-runtime-observation/1","runtimeDigest":expected["digest"],"fileCount":files.len(),"linkCount":links.len(),"absentCount":expected["absent"].as_array().unwrap().len()})
}
fn runtime_closure(enrollment: &Value) -> Value {
    json!({"php":runtime_one(&enrollment["runtime"]["php"]),"ruby":runtime_one(&enrollment["runtime"]["ruby"])})
}
fn verify_enrollment(enrollment: &Value) {
    assert_eq!(enrollment["schema"], "legion-php-ruby-sdk-enrollment/1");
    assert_eq!(enrollment["qualificationEligible"], false);
    for (name, version) in [
        ("composer", "2.10.3"),
        ("phpstan", "2.3.1"),
        ("phpunit", "13.4.3"),
    ] {
        assert_eq!(enrollment["assets"][name]["version"], version);
    }
    assert_eq!(enrollment["tools"]["rubocop"]["version"], "1.80.2");
    for name in ENV {
        assert_eq!(
            enrollment["environment"][name],
            std::env::var(name).unwrap()
        );
    }
    for (relative, descriptor) in enrollment["inputs"].as_object().unwrap() {
        assert_eq!(
            descriptor["digest"],
            digest(&fs::read(repository().join(relative)).unwrap())
        );
    }
    assert_eq!(
        enrollment["advisory"]["digest"],
        "sha256:20e797fa56d83ba55647bf7616700fade0d35d4bec515d85c88098ed8cce8430"
    );
    assert_eq!(
        enrollment["advisory"]["packages"],
        json!(["symfony/process"])
    );
    runtime_closure(enrollment);
}

fn case(base: &Path, retained: &Path, enrollment: &Value, control: &str) -> Value {
    let case_id = format!("code-php-ruby-{control}");
    let root = base.join(&case_id).join("source");
    let fixtures = fixture_files(control);
    for (rel, text) in &fixtures {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }
    let before = snapshot(&root);
    let inventory = FilesystemInventorySource::new(&root)
        .unwrap()
        .inventory(&case_id)
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(registry_spec(PHP_RUBY)).unwrap();
    let frozen = AuditPlan::compile_with_root(Some(&root), &inventory, &[spec])
        .unwrap()
        .freeze(Some(b"constructed-php-ruby-sdk-fixture-key"))
        .unwrap();
    let scratch = Arc::new(
        AuditScratch::with_scratch_dir(&root, retained.join("cases").join(&case_id)).unwrap(),
    );
    let mut tools: BTreeMap<String, (PathBuf, String)> = BTreeMap::new();
    for (section, names) in [
        ("tools", vec!["php", "ruby", "bundle", "rubocop"]),
        ("assets", vec!["composer", "phpstan", "phpunit"]),
    ] {
        for name in names {
            let item = &enrollment[section][name];
            let path = PathBuf::from(item["path"].as_str().unwrap());
            assert!(path.is_absolute());
            let sha = digest(&fs::read(&path).unwrap());
            assert_eq!(sha, item["digest"]);
            tools.insert(name.into(), (path, sha));
        }
    }
    let bin = PathBuf::from(std::env::var(ENV[3]).unwrap());
    let search = vec![
        bin,
        tools["php"].0.parent().unwrap().to_path_buf(),
        tools["ruby"].0.parent().unwrap().to_path_buf(),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ];
    let timeout = if control == "timeout" { 5000 } else { 120000 };
    let wrapper = fs::canonicalize("/usr/bin/sandbox-exec").unwrap();
    let mut exact = ScopedPolicy {
        plan: frozen.digest().into(),
        root: root.clone(),
        scratch: scratch.clone(),
        fixtures: fixtures.clone(),
        tools,
        wrapper_digest: digest(&fs::read(&wrapper).unwrap()),
        wrapper,
        commands: Vec::new(),
        runtime_digests: json!({"php":enrollment["runtime"]["php"]["digest"],"ruby":enrollment["runtime"]["ruby"]["digest"]}),
        enrollment_digest: digest(&fs::read(std::env::var(ENV[0]).unwrap()).unwrap()),
        absent_sandbox: control == "absent-sandbox",
        decisions: Mutex::new(Vec::new()),
    };
    exact.commands = expected_commands(&exact, enrollment, timeout);
    let policy = Arc::new(exact);
    let rows = Arc::new(Mutex::new(Vec::new()));
    let requests = Arc::new(Mutex::new(Vec::new()));
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
    let recorder = Recorder {
        inner: actual,
        scratch: scratch.clone(),
        rows: rows.clone(),
        requests: requests.clone(),
        cancel_rake: control == "cancel",
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    if control == "source-drift" {
        fs::write(
            root.join("app.php"),
            "<?php\nfunction answer(): int { return 99; }\n",
        )
        .unwrap();
    }
    let runtime_before = runtime_closure(enrollment);
    let native_result = if control == "absent-sandbox" {
        let c = &policy.commands[0];
        let request = ExternalToolRequest {
            request_id: format!(
                "legion-audit/{}",
                digest(case_id.as_bytes()).trim_start_matches("sha256:")
            ),
            provider_id: PHP_RUBY.into(),
            plan_id: frozen.digest().into(),
            policy_id: "audit".into(),
            task_id: Some(c["task"].as_str().unwrap().into()),
            executable: policy.wrapper.to_str().unwrap().into(),
            args: serde_json::from_value(c["args"].clone()).unwrap(),
            cwd: c["cwd"].as_str().unwrap().into(),
            expected_digest: Some(policy.wrapper_digest.clone()),
            version_args: serde_json::from_value(c["versionArgs"].clone()).unwrap(),
            environment: serde_json::from_value(c["environment"].clone()).unwrap(),
            environment_allowlist: serde_json::from_value(c["environmentAllowlist"].clone())
                .unwrap(),
            accepted_exit_codes: serde_json::from_value(c["acceptedExitCodes"].clone()).unwrap(),
            requires_network_sandbox: true,
            sandbox: None,
            timeout_ms: timeout,
            stdout_limit: 33554432,
            stderr_limit: 33554432,
            ..ExternalToolRequest::default()
        };
        runtime.block_on(recorder.execute(request, tokio_util::sync::CancellationToken::new()));
        Value::Null
    } else {
        let search = if control == "missing-tool" {
            let empty = base.join(&case_id).join("empty-bin");
            fs::create_dir(&empty).unwrap();
            vec![empty]
        } else {
            search
        };
        let native = NativeProviderRegistry::new(&root)
            .with_scratch(scratch.clone())
            .with_external_project_tool(Arc::new(AuditExternalProjectTool::new(recorder)))
            .with_code(
                code::ProviderExecutorAdapter::new()
                    .with_root(&root)
                    .with_search_path(search)
                    .with_sandbox(if control == "disabled-sandbox" {
                        SandboxPolicy::Disabled
                    } else {
                        SandboxPolicy::Required
                    })
                    .with_tool_bounds(timeout, timeout * 20),
            );
        let report = runtime
            .block_on(execute_with_cancellation(
                &frozen,
                &inventory,
                &native,
                tokio_util::sync::CancellationToken::new(),
            ))
            .unwrap();
        assert_eq!(report.planned_providers, vec![PHP_RUBY]);
        assert_eq!(report.results.len(), 1);
        serde_json::to_value(&report.results[0].result).unwrap()
    };
    let mut result = json!({"caseId":case_id,"control":control,"provider":PHP_RUBY,"scope":if control=="absent-sandbox"{"sdk-boundary-control"}else{"native-provider-known-answer-fixture"},"fixtureFiles":fixtures,"fixtureSources":before,"inventory":inventory,"planDigest":frozen.digest(),"frozenProvider":frozen.provider(PHP_RUBY).unwrap(),"nativeResult":native_result,"policyDefinition":policy.definition(),"policyDecisions":policy.decisions.lock().unwrap().clone(),"sdkExecutions":rows.lock().unwrap().clone(),"runtimeBefore":runtime_before,"matched":false});
    let junit = scratch
        .root()
        .join("tmp")
        .join("php-ruby-sdk/output/phpunit.xml");
    result["junitReport"] = if junit.is_file() {
        let raw = fs::read(&junit).unwrap();
        json!({"path":junit,"digest":digest(&raw),"bytes":raw.len(),"rawBytes":raw})
    } else {
        Value::Null
    };
    let path = scratch.root().join("case-observation.json");
    fs::write(&path, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    // Persist actual original evidence before any assertion or runtime replay.
    result["runtimeAfter"] = runtime_closure(enrollment);
    assert_eq!(result["runtimeBefore"], result["runtimeAfter"]);
    if control != "source-drift" {
        assert_eq!(
            snapshot(&root),
            before,
            "audited original source must remain unchanged"
        );
    }
    let executions = result["sdkExecutions"].as_array().unwrap();
    let expected = match control {
        "absent-sandbox" => 1,
        "missing-tool" | "disabled-sandbox" => 0,
        "source-drift" => 5,
        "malformed-manifest" | "malformed-lock" => 6,
        _ => 12,
    };
    assert_eq!(
        executions.len(),
        expected,
        "every applicable request must be attempted"
    );
    if control == "absent-sandbox" {
        let r = &executions[0]["executionReceipt"];
        assert_eq!(r["state"], "sandbox_missing");
        assert_eq!(r["policy"]["allowed"], true);
        assert_eq!(r["processTree"]["started"], false);
    } else {
        assert_eq!(native_result["complete"], false);
        assert_eq!(native_result["coverage"]["expected"], before.len());
        let gaps = native_result["coverage_gaps"].as_array().unwrap();
        assert!(!gaps.is_empty());
        for row in executions {
            let r = &row["executionReceipt"];
            assert_eq!(r["providerId"], PHP_RUBY);
            assert_eq!(r["planId"], frozen.digest());
            if control == "rejected-admission" {
                assert_eq!(r["state"], "unauthorized_effect");
                assert_eq!(r["policy"]["allowed"], false);
                assert_eq!(r["processTree"]["started"], false);
                continue;
            }
            assert_eq!(r["policy"]["allowed"], true);
            assert_eq!(r["policy"]["id"], POLICY);
            assert_eq!(r["sandbox"]["receiptId"], policy.sandbox_id());
            assert_eq!(r["sandbox"]["required"], true);
            assert_eq!(
                r["executable"]["version"]["args"],
                row["request"]["versionArgs"]
            );
            assert_eq!(r["executable"]["version"]["qualified"], true);
            assert_eq!(r["processTree"]["started"], true);
            assert_eq!(r["processTree"]["terminated"], true);
            assert_eq!(r["processTree"]["reaped"], true);
        }
        let full = matches!(
            control,
            "nonempty-clean" | "ruby-lint-positive" | "type-positive" | "security-positive"
        );
        if full {
            assert_eq!(native_result["coverage"]["examined"], 4);
            assert_eq!(
                native_result["coverage_gaps"],
                json!(["code.php-ruby:selection-narrower-than-denominator:4of10"])
            );
            assert!(executions
                .iter()
                .all(|r| r["executionReceipt"]["state"] == "completed"
                    && r["executionReceipt"]["complete"] == true));
            let receipts = native_result["details"]["nativeProducer"]["toolReceipts"]
                .as_array()
                .unwrap();
            for receipt in receipts.iter().filter(|r| !r["sdkReceipt"].is_null()) {
                assert!(executions
                    .iter()
                    .any(|r| r["executionReceipt"] == receipt["sdkReceipt"]));
                if !receipt["nativeInputSnapshots"].is_null() {
                    let s = &receipt["nativeInputSnapshots"];
                    assert_eq!(s["unchanged"], true);
                    assert_eq!(s["before"], s["after"]);
                    assert_eq!(s["before"]["inputs"], expected_inputs(&policy, enrollment));
                }
            }
            let boundary = receipts
                .iter()
                .find(|r| r["kind"] == "php-ruby-native-enrollment-boundary")
                .unwrap();
            assert_eq!(boundary["before"], boundary["after"]);
            assert!(boundary["beforeError"].is_null() && boundary["afterError"].is_null());
            let report = executions
                .iter()
                .find(|r| {
                    r["request"]["environment"]["LEGION_PHP_RUBY_COMMAND"] == "phpunit-report"
                })
                .unwrap();
            let report: Value = serde_json::from_slice(&raw(report, "stdout")).unwrap();
            assert_eq!(report["schema"], "legion-phpunit-assertions/1");
            assert!(
                report["tests"].as_u64().unwrap() > 0 && report["assertions"].as_u64().unwrap() > 0
            );
            let rake = executions
                .iter()
                .find(|r| r["request"]["environment"]["LEGION_PHP_RUBY_COMMAND"] == "rake")
                .unwrap();
            assert!(String::from_utf8(raw(rake, "stdout"))
                .unwrap()
                .contains("1 runs, 1 assertions, 0 failures, 0 errors, 0 skips"));
            let findings = native_result["details"]["findingEvidence"]
                .as_object()
                .unwrap();
            match control {
                "nonempty-clean" => {
                    assert!(findings.is_empty());
                    assert!(executions
                        .iter()
                        .all(|r| r["executionReceipt"]["exitCode"] == 0));
                }
                "ruby-lint-positive" => assert!(findings
                    .values()
                    .any(|f| f["ruleId"] == "rubocop:Lint/UselessAssignment"
                        && f["path"] == "lib/answer.rb")),
                "type-positive" => assert!(findings
                    .values()
                    .any(|f| f["ruleId"] == "phpstan:return.type" && f["path"] == "app.php")),
                "security-positive" => {
                    for id in ["PKSA-rkkf-636k-qjb3", "PKSA-wws7-mr54-jsny"] {
                        assert!(findings
                            .values()
                            .any(|f| f["ruleId"] == format!("composer-audit:{id}")
                                && f["path"] == "composer.lock"));
                    }
                }
                _ => unreachable!(),
            }
        }
        match control {
            "php-lint-positive" => {
                assert!(native_result["details"]["findingEvidence"]
                    .as_object()
                    .unwrap()
                    .values()
                    .any(|f| f["path"] == "app.php"));
                assert!(executions
                    .iter()
                    .any(|r| r["request"]["taskId"] == "lint"
                        && r["executionReceipt"]["exitCode"] != 0));
            }
            "php-test-failure" | "ruby-test-failure" => {
                let kind = if control == "php-test-failure" {
                    "phpunit"
                } else {
                    "rake"
                };
                let row = executions
                    .iter()
                    .find(|r| r["request"]["environment"]["LEGION_PHP_RUBY_COMMAND"] == kind)
                    .unwrap();
                assert_eq!(row["executionReceipt"]["state"], "failed");
                assert_ne!(row["executionReceipt"]["exitCode"], 0);
                if control == "ruby-test-failure" {
                    assert!(String::from_utf8(raw(row, "stdout"))
                        .unwrap()
                        .contains("1 runs, 1 assertions, 1 failures, 0 errors, 0 skips"));
                }
                assert!(gaps.iter().any(|g| g.as_str().unwrap().contains("test")));
            }
            "timeout" | "cancel" => {
                let row = executions
                    .iter()
                    .find(|r| r["request"]["environment"]["LEGION_PHP_RUBY_COMMAND"] == "rake")
                    .unwrap();
                assert_eq!(
                    row["executionReceipt"]["state"],
                    if control == "timeout" {
                        "timeout"
                    } else {
                        "cancelled"
                    }
                );
                assert_eq!(row["executionReceipt"]["complete"], false);
                assert!(String::from_utf8(raw(row, "stderr"))
                    .unwrap()
                    .contains("LEGION_PHP_RUBY_LIFECYCLE_TEST_STARTED"));
                assert!(gaps.iter().any(|g| g.as_str().unwrap().contains("test")));
            }
            "malformed-manifest" | "malformed-lock" => assert!(gaps.iter().any(|g| g
                .as_str()
                .unwrap()
                .contains(if control == "malformed-manifest" {
                    "php-ruby-composer-manifest-json"
                } else {
                    "php-ruby-composer-lock-json"
                }))),
            "source-drift" => assert!(gaps
                .iter()
                .any(|g| g.as_str().unwrap().contains("php-ruby-source-changed"))),
            "disabled-sandbox" => assert!(gaps.iter().any(|g| g
                .as_str()
                .unwrap()
                .contains("php-ruby-project-code-requires-authenticated-sandbox"))),
            "missing-tool" => assert!(gaps
                .iter()
                .any(|g| g.as_str().unwrap().contains("tool-missing"))),
            _ => {}
        }
    }
    if control == "nonempty-clean" {
        let captured = requests
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.task_id.as_deref() == Some("package"))
            .unwrap()
            .clone();
        result["requestMutationControls"] = request_mutations(&captured, &policy, &runtime);
    }
    result["matched"] = json!(true);
    fs::write(&path, serde_json::to_vec_pretty(&result).unwrap()).unwrap();
    result
}
fn emit(retained: &Path, record: &mut Value) {
    record["qualificationDigest"] = json!(digest(&canonical_bytes(record)));
    let bytes = serde_json::to_vec_pretty(record).unwrap();
    fs::write(retained.join("code_php-ruby.json"), &bytes).unwrap();
    assert_eq!(
        fs::read(retained.join("code_php-ruby.json")).unwrap(),
        bytes
    );
    println!("PHP_RUBY_CODE_COMMAND_SDK_ACCURACY_ARTIFACT {}",serde_json::to_string(&json!({"schema":"legion-php-ruby-code-command-sdk-artifact/1","provider":PHP_RUBY,"file":"code_php-ruby.json","digest":digest(&bytes),"bytes":bytes.len(),"qualificationDigest":record["qualificationDigest"],"qualificationEligible":record["qualificationEligible"],"productionQualification":false})).unwrap());
}
#[test]
#[ignore = "genuine PHP/Ruby SDK controls require CI-provisioned full runtime/tool enrollment, native macOS sandbox & explicit scratch/output roots"]
fn real_php_ruby_code_command_accuracy() {
    if let Some(base) = std::env::var_os("LEGION_PHP_RUBY_CODE_COMMAND_CHILD") {
        let base = fs::canonicalize(base).unwrap();
        assert_eq!(
            PathBuf::from(std::env::var_os("HOME").unwrap()),
            base.join("home")
        );
        let retained =
            fs::canonicalize(std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR").unwrap()).unwrap();
        let enrollment_path = PathBuf::from(std::env::var_os(ENV[0]).unwrap());
        let enrollment_bytes = fs::read(&enrollment_path).unwrap();
        fs::write(
            retained.join("php-ruby-sdk-enrollment.json"),
            &enrollment_bytes,
        )
        .unwrap();
        let enrollment: Value = serde_json::from_slice(&enrollment_bytes).unwrap();
        verify_enrollment(&enrollment);
        let runtime_before = runtime_closure(&enrollment);
        let cases: Vec<Value> = CONTROLS
            .into_iter()
            .map(|c| case(&base, &retained, &enrollment, c))
            .collect();
        let runtime_after = runtime_closure(&enrollment);
        assert_eq!(runtime_before, runtime_after);
        verify_enrollment(&enrollment);
        assert_eq!(fs::read(enrollment_path).unwrap(), enrollment_bytes);
        let config = code::evidence::config_for(PHP_RUBY).unwrap();
        assert_eq!(
            config.tools,
            ["package", "lint", "ruby-lint", "type", "test", "security"]
        );
        assert!(config.required_context.is_empty());
        assert_eq!(config.extensions, ["php", "rb"]);
        assert_eq!(
            json!(config.variants),
            json!([["php", ["php"]], ["ruby", ["rb"]]])
        );
        let mutations = cases[0]["requestMutationControls"].as_array().unwrap();
        let eligible = cases.len() == CONTROLS.len()
            && cases.iter().all(|c| c["matched"] == true)
            && mutations.len() == 4
            && mutations.iter().all(|m| m["matched"] == true);
        assert!(eligible);
        let fixture_sources: BTreeMap<String, String> = cases
            .iter()
            .flat_map(|c| {
                c["fixtureSources"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(p, d)| {
                        (
                            format!("{}/{p}", c["caseId"].as_str().unwrap()),
                            d.as_str().unwrap().to_owned(),
                        )
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut record = json!({"schema":"legion-php-ruby-code-command-sdk-accuracy/1","kind":"php-ruby-code-command-sdk-constructed","provider":PHP_RUBY,"providerVersion":registry_spec(PHP_RUBY)["providerVersion"],"productionQualification":false,"qualificationEligible":eligible,"claimScope":"known-answer-fixture-cases","executionPath":"native-sdk-frozen-plan-self-sourced-code","modelCalls":0,"admissionScope":"explicit constructed SDK authorizer; genuine OwnerAdmissionRequired denial; no production owner-admission claim","advisoryScope":"untouched official captured symfony/process query; affected and unaffected genuine locked versions; no full/current database claim","binding":binding(PHP_RUBY,&fixture_sources),"requiredContract":{"tools":config.tools,"extensions":config.extensions,"variants":config.variants,"requiredContext":config.required_context},"executedScope":config.tools,"enrollment":{"file":"php-ruby-sdk-enrollment.json","digest":digest(&enrollment_bytes),"bytes":enrollment_bytes.len()},"runtimeBefore":runtime_before,"runtimeAfter":runtime_after,"cases":cases,"missingControls":[],"metrics":{"cases":CONTROLS.len(),"matched":CONTROLS.len(),"mismatched":0,"wholeProviderQualified":false,"boundedSdkAccuracyQualified":eligible},"status":"observed-known-answer-controls"});
        emit(&retained, &mut record);
        return;
    }
    let fixture = Fixture::new();
    let retained = PathBuf::from(
        std::env::var_os("LEGION_PROVIDER_BENCHMARK_DIR")
            .expect("explicit retained PHP/Ruby SDK output required"),
    );
    assert!(retained.is_absolute());
    fs::create_dir_all(&retained).unwrap();
    let retained = fs::canonicalize(retained).unwrap();
    assert!(!retained.starts_with(&fixture.0) && !fixture.0.starts_with(&retained));
    let environment: BTreeMap<String, String> = ENV
        .into_iter()
        .map(|name| {
            let path = PathBuf::from(
                std::env::var_os(name).expect("explicit PHP/Ruby enrollment required"),
            );
            assert!(path.is_absolute() && !path.starts_with(&fixture.0));
            (name.into(), path.to_str().unwrap().into())
        })
        .collect();
    let path = std::env::join_paths([
        PathBuf::from(&environment[ENV[3]]),
        PathBuf::from(&environment[ENV[1]])
            .parent()
            .unwrap()
            .to_path_buf(),
        PathBuf::from(&environment[ENV[2]])
            .parent()
            .unwrap()
            .to_path_buf(),
        PathBuf::from("/usr/bin"),
        PathBuf::from("/bin"),
    ])
    .unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "real_php_ruby_code_command_accuracy",
            "--ignored",
            "--nocapture",
        ])
        .current_dir(&fixture.0)
        .env_clear()
        .env("PATH", path)
        .env("HOME", fixture.0.join("home"))
        .env("XDG_CONFIG_HOME", fixture.0.join("home"))
        .env("TMPDIR", fixture.0.join("tmp"))
        .envs(environment)
        .env("LEGION_PHP_RUBY_CODE_COMMAND_CHILD", &fixture.0)
        .env("LEGION_PROVIDER_BENCHMARK_DIR", &retained)
        .output()
        .unwrap();
    fs::write(retained.join("child.stdout.log"), &output.stdout).unwrap();
    fs::write(retained.join("child.stderr.log"), &output.stderr).unwrap();
    fs::write(retained.join("child-execution.json"),serde_json::to_vec_pretty(&json!({"schema":"legion-php-ruby-code-command-child-execution/1","productionQualification":false,"status":{"success":output.status.success(),"exitCode":output.status.code(),"signal":output.status.signal()},"stdout":{"file":"child.stdout.log","bytes":output.stdout.len(),"sha256":digest(&output.stdout)},"stderr":{"file":"child.stderr.log","bytes":output.stderr.len(),"sha256":digest(&output.stderr)}})).unwrap()).unwrap();
    assert!(
        output.status.success(),
        "actual SDK child failed; original evidence retained"
    );
    let marker = b"PHP_RUBY_CODE_COMMAND_SDK_ACCURACY_ARTIFACT ";
    let lines: Vec<&[u8]> = output
        .stdout
        .split_inclusive(|b| *b == b'\n')
        .filter_map(|line| {
            line.windows(marker.len())
                .position(|w| w == marker)
                .map(|p| &line[p..])
        })
        .collect();
    assert_eq!(lines.len(), 1);
    let locator: Value = serde_json::from_slice(&lines[0][marker.len()..]).unwrap();
    let bytes = fs::read(retained.join("code_php-ruby.json")).unwrap();
    assert_eq!(
        locator["schema"],
        "legion-php-ruby-code-command-sdk-artifact/1"
    );
    assert_eq!(locator["provider"], PHP_RUBY);
    assert_eq!(locator["digest"], digest(&bytes));
    assert_eq!(locator["bytes"], bytes.len());
    assert_eq!(locator["qualificationEligible"], true);
    assert_eq!(locator["productionQualification"], false);
    let mut record: Value = serde_json::from_slice(&bytes).unwrap();
    let q = record
        .as_object_mut()
        .unwrap()
        .remove("qualificationDigest")
        .unwrap();
    assert_eq!(q, digest(&canonical_bytes(&record)));
    assert_eq!(locator["qualificationDigest"], q);
    std::io::stdout().lock().write_all(lines[0]).unwrap();
}
