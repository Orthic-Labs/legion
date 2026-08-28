use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_policy_model::{
    ApprovalState, CanonicalPath, CapabilityCeiling, CapabilityGrant, ContractVersion, EffectClass,
    EnforcementLevel, HostEnforcement, LeasePolicy, LeaseState, PathOperation, PathScope,
    PolicyContext, PolicyPack, PolicyRule, ReceiptRequirements, ReceiptState, RuleDecision,
    RulePredicate, SymlinkState, TrustLevel, TrustMinima, UnclassifiedEffect,
    POLICY_SCHEMA_VERSION,
};
use serde_json::{json, Value};

struct Fixture {
    root: PathBuf,
    config: PathBuf,
    policy_context: Value,
}

static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(0);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn values<T: Ord>(values: impl IntoIterator<Item = T>) -> BTreeSet<T> {
    values.into_iter().collect()
}

fn policy_pack() -> PolicyPack {
    PolicyPack {
        schema_version: POLICY_SCHEMA_VERSION,
        kind: "arcane-policy-pack".into(),
        policy_id: "m1-cli-test-policy".into(),
        version: 1,
        contract_versions: vec![ContractVersion {
            name: "m1".into(),
            major: 1,
            minor: 0,
        }],
        unclassified_effect: UnclassifiedEffect::Deny,
        effect_rules: vec![PolicyRule {
            schema_version: POLICY_SCHEMA_VERSION,
            id: "allow-m1-capability".into(),
            effect_class: EffectClass::FileWrite,
            rule: RuleDecision::Allow,
            predicate: RulePredicate::default(),
            approval_required: false,
            trust_minimum: TrustLevel::CapabilitySignature,
            required_enforcement: EnforcementLevel::Strong,
            receipt_required: false,
            exception_capable: false,
            note: Some("M1 CLI fixture".into()),
        }],
        capability: CapabilityCeiling {
            effects: values([EffectClass::FileWrite]),
            operations: values(["write".into()]),
            targets: BTreeSet::new(),
            max_ttl_seconds: 60,
            max_uses: 1,
            delegable: false,
            trust: TrustLevel::CapabilitySignature,
        },
        leases: LeasePolicy {
            max_ttl_seconds: 60,
            max_uses: 1,
            delegable: false,
        },
        trust_minima: TrustMinima {
            mutation: TrustLevel::CapabilitySignature,
            read_only: TrustLevel::Unauthenticated,
            claim_release: TrustLevel::CapabilitySignature,
            legacy_import: TrustLevel::CapabilitySignature,
        },
        host_enforcement: HostEnforcement {
            required_for_mutation: EnforcementLevel::Strong,
            required_for_read_only: EnforcementLevel::ReadOnly,
        },
        receipt_requirements: ReceiptRequirements {
            effect_receipt: false,
            bind_policy_digest: true,
            bind_capability_id: true,
        },
    }
}

fn policy_context() -> PolicyContext {
    let repository = "repo".to_string();
    let worktree = "main".to_string();
    PolicyContext {
        schema_version: POLICY_SCHEMA_VERSION,
        contract: ContractVersion {
            name: "m1".into(),
            major: 1,
            minor: 0,
        },
        effect_class: EffectClass::FileWrite,
        operation: PathOperation::Write,
        path: Some(
            CanonicalPath::from_relative(
                "m1-cli-test-root",
                PathScope {
                    repository: repository.clone(),
                    worktree: worktree.clone(),
                },
                "skills/demo/SKILL.md",
                SymlinkState::NotFollowed,
            )
            .expect("canonical path"),
        ),
        repository,
        worktree,
        trust: TrustLevel::CapabilitySignature,
        enforcement: EnforcementLevel::Strong,
        approval: ApprovalState::None,
        lease: LeaseState::Active,
        receipt: ReceiptState::NotRequired,
        grant: Some(CapabilityGrant {
            schema_version: POLICY_SCHEMA_VERSION,
            id: "m1-cli-grant".into(),
            effects: values([EffectClass::FileWrite]),
            operations: values(["write".into()]),
            targets: BTreeSet::new(),
            ttl_seconds: 60,
            max_uses: 1,
            delegable: false,
            trust: TrustLevel::CapabilitySignature,
            lease_id: Some("m1-cli-lease".into()),
        }),
        tags: BTreeSet::new(),
    }
}

fn fixture(with_body: bool) -> Fixture {
    let root = std::env::temp_dir().join(format!(
        "legion-m1-cli-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos(),
        NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(root.join("registry")).expect("registry directory");
    fs::write(
        root.join("registry/index.json"),
        r#"{"schemaVersion":2,"bundles":[{"id":"demo","source":"skills/demo/SKILL.md","description":"M1 fixture"}]}"#,
    )
    .expect("compact catalog");
    if with_body {
        write_body(&root, "deterministic body");
    }
    fs::write(root.join("mcp-schema.json"), "mcp schema").expect("schema");
    fs::write(root.join("assets.json"), "assets").expect("assets");
    let digest =
        |name: &str| legion_catalog::hex_digest(&fs::read(root.join(name)).expect("digest source"));
    let manifest = legion_runtime::ReleaseManifest {
        release_version: env!("CARGO_PKG_VERSION").into(),
        runtime: legion_runtime::RuntimeIdentity {
            platform: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            sha256: legion_catalog::hex_digest(
                &fs::read(env!("CARGO_BIN_EXE_legion")).expect("Legion executable"),
            ),
            provenance: "rightkit-release://m1-cli-fixture".into(),
        },
        capability_catalog_sha256: digest("registry/index.json"),
        mcp_tool_schema_sha256: digest("mcp-schema.json"),
        declarative_assets_sha256: digest("assets.json"),
        state_schema_version: 1,
        rightkit_ax: legion_runtime::RightkitAxIdentity {
            version: "0.2.0".into(),
            source_commit: "01f52555202da3dffc6b649ca44e803b55238081".into(),
        },
    };
    fs::write(
        root.join("release.json"),
        serde_json::to_vec(&manifest).expect("manifest JSON"),
    )
    .expect("manifest");
    let config = root.join("m1-composition.json");
    fs::write(
        &config,
        serde_json::to_vec(&json!({
            "schemaVersion": 1,
            "kind": "legion-m1-composition",
            "releaseManifestPath": "release.json",
            "catalogRoot": ".",
            "catalogIndexPath": "registry/index.json",
            "providers": [{"id":"m1-native-capability"}],
            "policyPack": policy_pack(),
            "releaseBinding": {
                "runtimeProvenance": "rightkit-release://m1-cli-fixture",
                "catalogPath": "registry/index.json",
                "mcpToolSchemaPath": "mcp-schema.json",
                "declarativeAssetsPath": "assets.json",
                "declarativeAssetsKind": "file",
            }
        }))
        .expect("composition JSON"),
    )
    .expect("composition");
    Fixture {
        root,
        config,
        policy_context: serde_json::to_value(policy_context()).expect("policy context JSON"),
    }
}

fn write_body(root: &std::path::Path, body: &str) {
    fs::create_dir_all(root.join("skills/demo")).expect("skill directory");
    fs::write(root.join("skills/demo/SKILL.md"), body).expect("skill body");
}

fn legion(arguments: &[&str], config: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(arguments)
        .env("LEGION_M1_CONFIG", config)
        .output()
        .expect("native Legion CLI must execute")
}

fn start_stdio(config: &std::path::Path) -> (Child, ChildStdin, BufReader<ChildStdout>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["serve", "--stdio"])
        .env("LEGION_M1_CONFIG", config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("native MCP server must start");
    let stdin = child.stdin.take().expect("stdin");
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    (child, stdin, stdout)
}

#[test]
fn installed_composition_is_resolved_from_the_executable() {
    let root = std::env::temp_dir().join(format!(
        "legion-m1-installed-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    let executable_name = if cfg!(windows) {
        "legion.exe"
    } else {
        "legion"
    };
    let executable = root.join("bin").join(executable_name);
    let share = root.join("share/legion");
    let assets = share.join("assets");
    fs::create_dir_all(assets.join("registry")).expect("installed registry directory");
    fs::create_dir_all(assets.join("skills/demo")).expect("installed skill directory");
    fs::copy(env!("CARGO_BIN_EXE_legion"), &executable).unwrap_or_else(|_| {
        fs::create_dir_all(executable.parent().expect("executable parent"))
            .expect("installed bin directory");
        fs::copy(env!("CARGO_BIN_EXE_legion"), &executable).expect("installed executable")
    });
    fs::write(
        assets.join("registry/index.json"),
        r#"{"schemaVersion":2,"bundles":[{"id":"demo","source":"skills/demo/SKILL.md","description":"installed fixture"}]}"#,
    )
    .expect("installed catalog");
    fs::write(assets.join("skills/demo/SKILL.md"), "installed body").expect("installed skill");
    fs::write(assets.join("mcp-schema.json"), "installed schema").expect("installed schema");
    fs::write(assets.join("assets.json"), "installed assets").expect("installed assets");
    let digest = |path: &std::path::Path| {
        legion_catalog::hex_digest(&fs::read(path).expect("installed digest source"))
    };
    let manifest = legion_runtime::ReleaseManifest {
        release_version: env!("CARGO_PKG_VERSION").into(),
        runtime: legion_runtime::RuntimeIdentity {
            platform: std::env::consts::OS.into(),
            architecture: std::env::consts::ARCH.into(),
            sha256: digest(&executable),
            provenance: "rightkit-release://installed-test".into(),
        },
        capability_catalog_sha256: digest(&assets.join("registry/index.json")),
        mcp_tool_schema_sha256: digest(&assets.join("mcp-schema.json")),
        declarative_assets_sha256: digest(&assets.join("assets.json")),
        state_schema_version: 1,
        rightkit_ax: legion_runtime::RightkitAxIdentity {
            version: "0.2.0".into(),
            source_commit: "01f52555202da3dffc6b649ca44e803b55238081".into(),
        },
    };
    fs::write(
        share.join("release.json"),
        serde_json::to_vec(&manifest).expect("installed manifest JSON"),
    )
    .expect("installed manifest");
    fs::write(
        share.join("composition.json"),
        serde_json::to_vec(&json!({
            "schemaVersion": 1,
            "kind": "legion-m1-composition",
            "releaseManifestPath": "release.json",
            "catalogRoot": "assets",
            "catalogIndexPath": "registry/index.json",
            "providers": [{"id":"m1-native-capability"}],
            "policyPack": policy_pack(),
            "releaseBinding": {
                "runtimeProvenance": "rightkit-release://installed-test",
                "catalogPath": "assets/registry/index.json",
                "mcpToolSchemaPath": "assets/mcp-schema.json",
                "declarativeAssetsPath": "assets/assets.json",
                "declarativeAssetsKind": "file",
            }
        }))
        .expect("installed composition JSON"),
    )
    .expect("installed composition");

    let output = Command::new(&executable)
        .args(["--json", "status"])
        .env_remove("LEGION_M1_CONFIG")
        .output()
        .expect("installed Legion status");
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("installed status JSON");
    assert_eq!(value["kind"], "legion-m1-status");
    assert_eq!(value["status"], "incomplete");
    assert_eq!(value["fidelity"], "degraded");
    assert_eq!(value["native"]["scope"], "m1-vertical-slice");
    assert!(value["gaps"]
        .as_array()
        .is_some_and(|gaps| !gaps.is_empty()));
    fs::remove_dir_all(root).expect("installed fixture cleanup");
}

fn request(stdin: &mut ChildStdin, stdout: &mut BufReader<ChildStdout>, request: Value) -> Value {
    writeln!(stdin, "{}", request).expect("write MCP request");
    stdin.flush().expect("flush MCP request");
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read MCP response");
    serde_json::from_str(&line).expect("MCP response JSON")
}

#[test]
fn actual_binary_serves_the_shared_m1_surface_and_lazy_capability_body() {
    let fixture = fixture(false);
    let status = legion(&["status"], &fixture.config);
    assert_eq!(status.status.code(), Some(2));
    let status: Value = serde_json::from_slice(&status.stdout).expect("status JSON");
    assert_eq!(status["status"], "incomplete");
    assert_eq!(
        status["native"]["releaseVersion"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(status["native"]["status"], "complete");

    let (mut child, mut stdin, mut stdout) = start_stdio(&fixture.config);
    write_body(&fixture.root, "late body");

    let initialized = request(
        &mut stdin,
        &mut stdout,
        json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{}}),
    );
    assert_eq!(
        initialized["result"]["releaseIdentity"]["releaseVersion"],
        env!("CARGO_PKG_VERSION")
    );
    assert_eq!(
        initialized["result"]["releaseIdentity"]["runtime"]["provenance"],
        "rightkit-release://m1-cli-fixture"
    );

    let listed = request(
        &mut stdin,
        &mut stdout,
        json!({"jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{}}),
    );
    let names = listed["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(names, ["legion_m1_status", "legion_m1_invoke"]);

    let invoked = request(
        &mut stdin,
        &mut stdout,
        json!({
            "jsonrpc":"2.0",
            "id":3,
            "method":"tools/call",
            "params": {
                "name":"legion_m1_invoke",
                "arguments":{"capabilityId":"demo", "policyContext":fixture.policy_context}
            }
        }),
    );
    let result = &invoked["result"]["structuredContent"]["data"];
    assert_eq!(
        result["capability"]["body_sha256"],
        legion_catalog::hex_digest(b"late body"),
        "{invoked}"
    );
    assert_eq!(result["policyEvaluation"]["decision"]["outcome"], "allow");
    assert_eq!(result["policyReceipt"]["decision"]["outcome"], "allow");
    assert_eq!(
        result["invocationReceipt"]["provider"],
        "m1-native-capability"
    );
    assert_eq!(result["invocationReceipt"]["complete"], true);

    drop(stdin);
    assert!(child.wait().expect("server exit").success());
}

#[test]
fn mismatch_remains_a_stdio_protocol_failure_without_tools() {
    let fixture = fixture(true);
    let mut config: Value =
        serde_json::from_slice(&fs::read(&fixture.config).expect("composition")).expect("JSON");
    config["releaseBinding"]["runtimeProvenance"] = json!("wrong-provenance");
    fs::write(&fixture.config, serde_json::to_vec(&config).expect("JSON")).expect("composition");

    let (mut child, mut stdin, mut stdout) = start_stdio(&fixture.config);
    let initialized = request(
        &mut stdin,
        &mut stdout,
        json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{}}),
    );
    assert_eq!(
        initialized["error"]["message"],
        "legion setup repair --confirm"
    );
    assert!(initialized.get("result").is_none());

    let listed = request(
        &mut stdin,
        &mut stdout,
        json!({"jsonrpc":"2.0", "id":2, "method":"tools/list", "params":{}}),
    );
    assert_eq!(listed["error"]["message"], "legion setup repair --confirm");
    assert!(listed.get("result").is_none());

    drop(stdin);
    assert!(child.wait().expect("server exit").success());
}
