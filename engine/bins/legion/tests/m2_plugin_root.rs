use std::{
    collections::BTreeSet,
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use legion_policy_model::{
    CapabilityCeiling, ContractVersion, EffectClass, EnforcementLevel, HostEnforcement,
    LeasePolicy, PolicyPack, PolicyRule, ReceiptRequirements, RuleDecision, RulePredicate,
    TrustLevel, TrustMinima, UnclassifiedEffect, POLICY_SCHEMA_VERSION,
};
use serde_json::{json, Value};

const PUBLIC_SKILLS: [&str; 24] = [
    "ads",
    "alchemist",
    "architect",
    "audit",
    "audit-fix",
    "audit-visual",
    "brand",
    "brand-identity",
    "coder",
    "commit",
    "covenant",
    "debugger",
    "designer",
    "dispatch",
    "gotchas",
    "handoff",
    "marketing",
    "qa",
    "research",
    "seo",
    "social",
    "tasklist",
    "wake",
    "writing",
];

struct Fixture {
    root: PathBuf,
    config: PathBuf,
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
        policy_id: "m2-plugin-root-test-policy".into(),
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
            note: Some("M2 plugin-root fixture".into()),
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
            legacy_import: TrustLevel::Unauthenticated,
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

fn fixture() -> Fixture {
    let requested_root = std::env::temp_dir().join(format!(
        "legion-m2-plugin-root-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos(),
        NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(requested_root.join("registry")).expect("registry directory");
    // macOS exposes its temporary root through `/var`, a symlink to
    // `/private/var`; use its physical path so portability checks assess this
    // fixture rather than rejecting the host alias.
    let root = fs::canonicalize(requested_root).expect("canonical fixture root");
    fs::write(
        root.join("registry/index.json"),
        r#"{"schemaVersion":2,"bundles":[{"id":"demo","source":"skills/demo/SKILL.md","description":"fixture"}]}"#,
    )
    .expect("catalog index");
    fs::create_dir_all(root.join("skills/demo")).expect("catalog body directory");
    fs::write(root.join("skills/demo/SKILL.md"), "fixture body").expect("catalog body");
    fs::write(
        root.join("mcp-schema.json"),
        br#"{"type":"object","properties":{}}"#,
    )
    .expect("schema");
    fs::write(root.join("assets.json"), "assets").expect("assets");
    let digest =
        |name: &str| legion_catalog::hex_digest(&fs::read(root.join(name)).expect("digest source"));
    let manifest = legion_runtime::ReleaseManifest {
        release_version: env!("CARGO_PKG_VERSION").into(),
        runtime: legion_runtime::RuntimeIdentity {
            platform: std::env::consts::OS.into(),
            architecture: legion_runtime::release_binding::current_runtime_architecture().into(),
            sha256: legion_catalog::hex_digest(
                &fs::read(env!("CARGO_BIN_EXE_legion")).expect("Legion executable"),
            ),
            provenance: "rightkit-release://m2-plugin-root-fixture".into(),
        },
        capability_catalog_sha256: digest("registry/index.json"),
        mcp_tool_schema_sha256: digest("mcp-schema.json"),
        declarative_assets_sha256: digest("assets.json"),
        state_schema_version: 1,
        rightkit_ax: legion_runtime::RightkitAxIdentity {
            version: "0.2.1".into(),
            source_commit: "4c1a414269d8ffdb95b4b1e685440bd34784b41b".into(),
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
                "runtimeProvenance": "rightkit-release://m2-plugin-root-fixture",
                "catalogPath": "registry/index.json",
                "mcpToolSchemaPath": "mcp-schema.json",
                "declarativeAssetsPath": "assets.json",
                "declarativeAssetsKind": "file",
            }
        }))
        .expect("composition JSON"),
    )
    .expect("composition");
    Fixture { root, config }
}

fn portable_package(fixture: &Fixture) -> PathBuf {
    let root = fixture.root.join("legion-plugin");
    fs::create_dir_all(&root).expect("plugin root");
    fs::write(
        root.join("plugin.json"),
        include_bytes!("../../../assets/legion-plugin/plugin.json"),
    )
    .expect("plugin manifest");
    fs::write(
        root.join("mcp.json"),
        br#"{"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json","mcpServers":{"legion":{"type":"stdio","command":"legion","args":["serve","--stdio","--plugin-root","${PLUGIN_ROOT}"]}}}"#,
    )
    .expect("MCP manifest");
    let mut public_files = vec!["plugin.json".to_string(), "mcp.json".to_string()];
    for skill in PUBLIC_SKILLS {
        let relative = format!("skills/{skill}/SKILL.md");
        let path = root.join(&relative);
        fs::create_dir_all(path.parent().expect("skill parent")).expect("skill directory");
        fs::write(&path, format!("---\nname: {skill}\n---\nUse {skill}.\n")).expect("skill");
        public_files.push(relative);
    }
    fs::write(
        root.join("rightax-portable-core.json"),
        serde_json::to_vec(&json!({
            "schemaVersion": 1,
            "kind": "rightax-portable-core",
            "plugin": "legion",
            "publicSkills": PUBLIC_SKILLS,
            "publicFiles": public_files,
            "privateWorkspaceContent": false,
            "clientProjections": {
                "claude": {
                    "portableCore": false,
                    "projection": "claude-native-plugin+standalone-skills",
                    "fidelity": "full+skills-only",
                    "executableRegistration": true
                },
                "codex": {
                    "portableCore": true,
                    "projection": "agent-plugins+codex-sidecar",
                    "fidelity": "full+sidecar",
                    "executableRegistration": true
                },
                "cursor": {
                    "portableCore": true,
                    "projection": "agent-plugins+optional-cursor-sidecar",
                    "fidelity": "full+optional-sidecar",
                    "executableRegistration": true
                },
                "pi": {
                    "portableCore": false,
                    "projection": "agents-skills",
                    "fidelity": "skills-only",
                    "executableRegistration": false
                },
                "antigravity": {
                    "portableCore": true,
                    "projection": "agent-plugins-portable-core",
                    "fidelity": "portable-core",
                    "executableRegistration": true
                }
            }
        }))
        .expect("RightAX contract"),
    )
    .expect("RightAX contract file");
    root
}

fn start_stdio(plugin_root: &Path, config: &Path) -> (Child, ChildStdin, BufReader<ChildStdout>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "serve",
            "--stdio",
            "--plugin-root",
            plugin_root.to_str().expect("plugin root UTF-8"),
        ])
        .env("LEGION_M1_CONFIG", config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("native MCP server must start");
    let stdin = child.stdin.take().expect("stdin");
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    (child, stdin, stdout)
}

fn request(stdin: &mut ChildStdin, stdout: &mut BufReader<ChildStdout>, request: Value) -> Value {
    writeln!(stdin, "{request}").expect("write MCP request");
    stdin.flush().expect("flush MCP request");
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read MCP response");
    serde_json::from_str(&line).expect("MCP response JSON")
}

fn serve_output(plugin_root: &Path, config: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "serve",
            "--stdio",
            "--plugin-root",
            plugin_root.to_str().expect("plugin root UTF-8"),
        ])
        .env("LEGION_M1_CONFIG", config)
        .output()
        .expect("native Legion CLI must execute")
}

#[test]
fn actual_binary_accepts_bound_plugin_root_before_starting_mcp() {
    let fixture = fixture();
    let plugin_root = portable_package(&fixture);
    let (mut child, mut stdin, mut stdout) = start_stdio(&plugin_root, &fixture.config);

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
        "rightkit-release://m2-plugin-root-fixture"
    );

    drop(stdin);
    assert!(child.wait().expect("server exit").success());
}

#[test]
fn invalid_plugin_roots_fail_before_mcp_startup() {
    let fixture = fixture();
    let plugin_root = portable_package(&fixture);
    fs::remove_file(plugin_root.join("mcp.json")).expect("remove required entry");

    let output = serve_output(&plugin_root, &fixture.config);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "MCP must not have started");
    assert!(String::from_utf8_lossy(&output.stderr).contains("portable plugin root rejected"));
}

#[test]
fn plugin_root_public_skill_drift_fails_closed_before_mcp_startup() {
    let fixture = fixture();
    let plugin_root = portable_package(&fixture);
    let contract_path = plugin_root.join("rightax-portable-core.json");
    let mut contract: Value =
        serde_json::from_slice(&fs::read(&contract_path).expect("RightAX contract"))
            .expect("RightAX contract JSON");
    contract["publicSkills"] = json!(["audit"]);
    fs::write(
        contract_path,
        serde_json::to_vec(&contract).expect("RightAX contract JSON"),
    )
    .expect("drifted RightAX contract");

    let output = serve_output(&plugin_root, &fixture.config);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "MCP must not have started");
    assert!(String::from_utf8_lossy(&output.stderr).contains("legion setup repair --confirm"));
}

#[test]
fn plugin_root_projection_and_extra_file_tampering_fail_closed_before_mcp_startup() {
    let fixture = fixture();
    let plugin_root = portable_package(&fixture);
    let contract_path = plugin_root.join("rightax-portable-core.json");
    let original = fs::read(&contract_path).expect("RightAX contract");
    let mut contract: Value = serde_json::from_slice(&original).expect("RightAX contract JSON");
    contract["clientProjections"]["pi"]["executableRegistration"] = json!(true);
    fs::write(
        &contract_path,
        serde_json::to_vec(&contract).expect("RightAX contract JSON"),
    )
    .expect("tampered projection");

    let projection_output = serve_output(&plugin_root, &fixture.config);
    assert_eq!(projection_output.status.code(), Some(2));
    assert!(
        projection_output.stdout.is_empty(),
        "MCP must not have started"
    );
    assert!(String::from_utf8_lossy(&projection_output.stderr)
        .contains("Pi projection may not register"));

    fs::write(&contract_path, original).expect("restore RightAX contract");
    fs::write(plugin_root.join("private.txt"), "unexpected").expect("extra file");

    let extra_output = serve_output(&plugin_root, &fixture.config);
    assert_eq!(extra_output.status.code(), Some(2));
    assert!(extra_output.stdout.is_empty(), "MCP must not have started");
    assert!(String::from_utf8_lossy(&extra_output.stderr).contains("extra file private.txt"));
}
