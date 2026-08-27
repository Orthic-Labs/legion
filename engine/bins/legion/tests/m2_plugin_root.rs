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

const PACKAGE_FILES: [&str; 6] = [
    "plugin.json",
    "mcp.json",
    "skills/legion/SKILL.md",
    "share/legion/release-binding.json",
    "share/legion/identity/release-identity.json",
    "share/legion/schemas/mcp-tools.schema.json",
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
            architecture: std::env::consts::ARCH.into(),
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
    for relative in PACKAGE_FILES {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("package parent")).expect("package directory");
        let content = match relative {
            "plugin.json" => br#"{"name":"legion"}"#.as_slice(),
            "mcp.json" => br#"{"$schema":"https://agent-plugins.org/schemas/1.0.0/mcp.schema.json","mcpServers":{"legion":{"type":"stdio","command":"legion","args":["serve","--stdio","--plugin-root","${PLUGIN_ROOT}"]}}}"#.as_slice(),
            "skills/legion/SKILL.md" => b"---\nname: legion\n---\nUse Legion.",
            "share/legion/release-binding.json" => {
                fs::copy(fixture.root.join("release.json"), &path).expect("release binding");
                continue;
            }
            "share/legion/identity/release-identity.json" => {
                fs::copy(fixture.root.join("release.json"), &path).expect("release identity");
                continue;
            }
            "share/legion/schemas/mcp-tools.schema.json" => {
                fs::copy(fixture.root.join("mcp-schema.json"), &path).expect("MCP tool schema");
                continue;
            }
            _ => unreachable!("known package file"),
        };
        fs::write(path, content).expect("package file");
    }
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
fn plugin_root_release_binding_mismatch_fails_closed_before_mcp_startup() {
    let fixture = fixture();
    let plugin_root = portable_package(&fixture);
    let mut binding: Value = serde_json::from_slice(
        &fs::read(plugin_root.join("share/legion/release-binding.json")).expect("binding"),
    )
    .expect("binding JSON");
    binding["releaseVersion"] = json!("9.9.9");
    fs::write(
        plugin_root.join("share/legion/release-binding.json"),
        serde_json::to_vec(&binding).expect("binding JSON"),
    )
    .expect("mismatched binding");

    let output = serve_output(&plugin_root, &fixture.config);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "MCP must not have started");
    assert!(String::from_utf8_lossy(&output.stderr).contains("legion setup --repair"));
}

#[test]
fn plugin_root_identity_and_schema_tampering_fail_closed_before_mcp_startup() {
    let fixture = fixture();
    let plugin_root = portable_package(&fixture);
    let identity_path = plugin_root.join("share/legion/identity/release-identity.json");
    let mut identity: Value = serde_json::from_slice(&fs::read(&identity_path).expect("identity"))
        .expect("identity JSON");
    identity["releaseVersion"] = json!("9.9.9");
    fs::write(
        &identity_path,
        serde_json::to_vec(&identity).expect("identity JSON"),
    )
    .expect("tampered identity");

    let identity_output = serve_output(&plugin_root, &fixture.config);
    assert_eq!(identity_output.status.code(), Some(2));
    assert!(
        identity_output.stdout.is_empty(),
        "MCP must not have started"
    );
    assert!(String::from_utf8_lossy(&identity_output.stderr)
        .contains("release-identity.json does not match"));

    fs::copy(fixture.root.join("release.json"), &identity_path).expect("restore identity");
    fs::write(
        plugin_root.join("share/legion/schemas/mcp-tools.schema.json"),
        br#"{"type":"object","properties":{"tampered":{"type":"string"}}}"#,
    )
    .expect("tampered schema");

    let schema_output = serve_output(&plugin_root, &fixture.config);
    assert_eq!(schema_output.status.code(), Some(2));
    assert!(schema_output.stdout.is_empty(), "MCP must not have started");
    assert!(String::from_utf8_lossy(&schema_output.stderr)
        .contains("mcp-tools.schema.json digest does not match"));
}
