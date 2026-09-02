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
        // Populated once the portable core exists (see `anchor_release`).
        portable_core_sha256: None,
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
    anchor_release(fixture, &root);
    root
}

/// Recompute the portable-core digest into the fixture's `release.json`,
/// mirroring what the real release assembler does after the core is assembled.
/// Tests that deliberately mutate the core call this again when they want to
/// reach a check downstream of the anchor.
fn anchor_release(fixture: &Fixture, plugin_root: &Path) {
    let core = fs::read(plugin_root.join("rightax-portable-core.json")).expect("core bytes");
    let manifest_path = fixture.root.join("release.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("release manifest"))
            .expect("release manifest JSON");
    manifest["portableCoreSha256"] = json!(legion_catalog::hex_digest(&core));
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("release manifest JSON"),
    )
    .expect("release manifest");
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
    // Re-anchor so the failure proves the skill-closure check, not the digest.
    anchor_release(&fixture, &plugin_root);

    let output = serve_output(&plugin_root, &fixture.config);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "MCP must not have started");
    assert!(String::from_utf8_lossy(&output.stderr).contains("legion setup repair --confirm"));
}

#[test]
fn plugin_root_accepts_a_core_that_ships_more_skills_than_the_binary_predates() {
    // The canonical skill set is whatever the release-authored contract
    // declares. A later release that adds a skill (here `oracle`) must not be
    // rejected by an older validator as long as the package still closes
    // exactly against its own contract.
    let fixture = fixture();
    let plugin_root = portable_package(&fixture);

    let extra = "oracle";
    let extra_relative = format!("skills/{extra}/SKILL.md");
    let extra_path = plugin_root.join(&extra_relative);
    fs::create_dir_all(extra_path.parent().expect("extra skill parent")).expect("extra skill dir");
    fs::write(&extra_path, format!("---\nname: {extra}\n---\nUse {extra}.\n")).expect("extra skill");

    let contract_path = plugin_root.join("rightax-portable-core.json");
    let mut contract: Value =
        serde_json::from_slice(&fs::read(&contract_path).expect("RightAX contract"))
            .expect("RightAX contract JSON");
    let skills = contract["publicSkills"].as_array_mut().expect("publicSkills");
    skills.push(json!(extra));
    let files = contract["publicFiles"].as_array_mut().expect("publicFiles");
    files.push(json!(extra_relative));
    fs::write(
        &contract_path,
        serde_json::to_vec(&contract).expect("RightAX contract JSON"),
    )
    .expect("extended RightAX contract");
    anchor_release(&fixture, &plugin_root);

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
    drop(stdin);
    assert!(child.wait().expect("server exit").success());
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
    anchor_release(&fixture, &plugin_root);

    let projection_output = serve_output(&plugin_root, &fixture.config);
    assert_eq!(projection_output.status.code(), Some(2));
    assert!(
        projection_output.stdout.is_empty(),
        "MCP must not have started"
    );
    assert!(String::from_utf8_lossy(&projection_output.stderr)
        .contains("Pi projection may not register"));

    fs::write(&contract_path, original).expect("restore RightAX contract");
    anchor_release(&fixture, &plugin_root);
    fs::write(plugin_root.join("private.txt"), "unexpected").expect("extra file");

    let extra_output = serve_output(&plugin_root, &fixture.config);
    assert_eq!(extra_output.status.code(), Some(2));
    assert!(extra_output.stdout.is_empty(), "MCP must not have started");
    assert!(String::from_utf8_lossy(&extra_output.stderr).contains("extra file private.txt"));
}

#[test]
fn plugin_root_with_a_matching_anchor_starts_mcp() {
    // The positive half of the F1 anchor: an untouched package whose core bytes
    // hash to the manifest digest is accepted.
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
    drop(stdin);
    assert!(child.wait().expect("server exit").success());
}

#[test]
fn plugin_root_rejects_core_bytes_that_drift_from_the_release_anchor() {
    let fixture = fixture();
    let plugin_root = portable_package(&fixture);
    let core_path = plugin_root.join("rightax-portable-core.json");
    let mut bytes = fs::read(&core_path).expect("core bytes");
    bytes.push(b' '); // one extra byte: JSON still parses, digest no longer matches
    fs::write(&core_path, bytes).expect("mutated core");

    let output = serve_output(&plugin_root, &fixture.config);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "MCP must not have started");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("portable core digest mismatch"), "{stderr}");
    assert!(stderr.contains("legion setup repair --confirm"), "{stderr}");
}

#[test]
fn plugin_root_rejects_a_release_without_the_portable_core_anchor() {
    let fixture = fixture();
    let plugin_root = portable_package(&fixture);
    let manifest_path = fixture.root.join("release.json");
    let mut manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest")).expect("manifest JSON");
    manifest
        .as_object_mut()
        .expect("manifest object")
        .remove("portableCoreSha256");
    fs::write(
        &manifest_path,
        serde_json::to_vec(&manifest).expect("manifest JSON"),
    )
    .expect("manifest");

    let output = serve_output(&plugin_root, &fixture.config);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("predates the portable-core anchor"));
}

#[test]
fn plugin_root_accepts_the_claude_projection_manifest_copy() {
    let fixture = fixture();
    let plugin_root = portable_package(&fixture);
    let projected = plugin_root.join(".claude-plugin");
    fs::create_dir_all(&projected).expect("claude-plugin dir");
    fs::copy(plugin_root.join("plugin.json"), projected.join("plugin.json")).expect("copy plugin.json");

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
    drop(stdin);
    assert!(child.wait().expect("server exit").success());
}

#[test]
fn plugin_root_rejects_a_mismatched_claude_projection_manifest_copy() {
    let fixture = fixture();
    let plugin_root = portable_package(&fixture);
    let projected = plugin_root.join(".claude-plugin");
    fs::create_dir_all(&projected).expect("claude-plugin dir");
    fs::write(
        projected.join("plugin.json"),
        r#"{"name":"legion","tampered":true}"#,
    )
    .expect("tampered projection copy");

    let output = serve_output(&plugin_root, &fixture.config);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty(), "MCP must not have started");
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not match plugin.json"));
}

#[cfg(windows)]
fn junction(link: &Path, target: &Path) {
    // `mklink` rejects the `\\?\` verbatim prefix that `canonicalize` produces.
    let plain = |path: &Path| {
        let text = path.to_string_lossy().into_owned();
        text.strip_prefix(r"\\?\").map(str::to_owned).unwrap_or(text)
    };
    let status = Command::new("cmd")
        .args(["/c", "mklink", "/J", &plain(link), &plain(target)])
        .status()
        .expect("mklink /J must run");
    assert!(status.success(), "mklink /J failed");
}

#[cfg(windows)]
fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("destination directory");
    for entry in fs::read_dir(source).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let from = entry.path();
        let to = destination.join(entry.file_name());
        if entry.file_type().expect("file type").is_dir() {
            copy_tree(&from, &to);
        } else {
            fs::copy(&from, &to).expect("copy file");
        }
    }
}

#[cfg(windows)]
#[test]
fn plugin_root_accepts_the_stable_current_junction() {
    let fixture = fixture();
    let package = portable_package(&fixture);
    let versioned = fixture.root.join("versions").join("0.1.0");
    copy_tree(&package, &versioned);
    let current = fixture.root.join("current");
    junction(&current, &versioned);

    let (mut child, mut stdin, mut stdout) = start_stdio(&current, &fixture.config);
    let initialized = request(
        &mut stdin,
        &mut stdout,
        json!({"jsonrpc":"2.0", "id":1, "method":"initialize", "params":{}}),
    );
    assert_eq!(
        initialized["result"]["releaseIdentity"]["releaseVersion"],
        env!("CARGO_PKG_VERSION")
    );
    drop(stdin);
    assert!(child.wait().expect("server exit").success());
}

#[cfg(windows)]
#[test]
fn plugin_root_rejects_a_junction_that_is_not_stable_current() {
    let fixture = fixture();
    let package = portable_package(&fixture);
    let sideways = fixture.root.join("sideways");
    junction(&sideways, &package);

    let output = serve_output(&sideways, &fixture.config);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("crosses symlink"));
}
