use legion_host::{
    assemble_clean_room, classify_external_qualification, verify_client_identity, ClientFidelity,
    ClientIdentity, CommandResolutionEvidence, ExternalQualificationInputs,
    ExternalQualificationStatus, FailureCode, PinnedAxEvidence, PortableTemplates,
    VerifiedPortableInputs, RIGHTKIT_AX_SOURCE_COMMIT, RIGHTKIT_AX_VERSION,
};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const PACKAGE_FILES: [&str; 6] = [
    "plugin.json",
    "mcp.json",
    "skills/legion/SKILL.md",
    "share/legion/release-binding.json",
    "share/legion/identity/release-identity.json",
    "share/legion/schemas/mcp-tools.schema.json",
];

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        Self(std::env::temp_dir().join(format!("legion-m2-{label}-{}-{nonce}", std::process::id())))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn templates() -> PortableTemplates {
    PortableTemplates {
        plugin_json: include_bytes!("../assets/legion-plugin/plugin.json").to_vec(),
        mcp_json: include_bytes!("../assets/legion-plugin/mcp.json").to_vec(),
        skill_markdown: include_bytes!("../assets/legion-plugin/skills/legion/SKILL.md").to_vec(),
    }
}

fn verified_inputs() -> VerifiedPortableInputs {
    VerifiedPortableInputs {
        release_binding: br#"{"releaseVersion":"0.1.0","runtime":"signed"}"#.to_vec(),
        release_identity: br#"{"releaseVersion":"0.1.0","catalog":"sha256:catalog"}"#.to_vec(),
        mcp_tool_schema: br#"{"type":"object","properties":{}}"#.to_vec(),
    }
}

fn identity(client_id: &str, selected_mechanism: &str) -> ClientIdentity {
    ClientIdentity {
        client_id: client_id.into(),
        selected_mechanism: selected_mechanism.into(),
        release_version: "0.1.0".into(),
        release_binding_digest: "sha256:binding".into(),
        capability_catalog_hash: "sha256:catalog".into(),
        mcp_tool_schema_hash: "sha256:mcp".into(),
        declarative_assets_hash: "sha256:assets".into(),
    }
}

fn resolution(client_id: &str) -> CommandResolutionEvidence {
    CommandResolutionEvidence {
        client_id: client_id.into(),
        resolution_mode: "agent-plugins-bare-command".into(),
        resolved_executable: "/opt/legion/bin/legion".into(),
        runtime_digest: "sha256:runtime".into(),
        provenance: "rightkit-release://fixture".into(),
        launch_environment_digest: "sha256:environment".into(),
        source_checkout: false,
        path_sanitized: true,
    }
}

fn package_files(root: &Path, current: &Path) -> Vec<String> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(current).expect("read assembled package directory") {
        let entry = entry.expect("package directory entry");
        let path = entry.path();
        if path.is_dir() {
            entries.extend(package_files(root, &path));
        } else {
            entries.push(
                path.strip_prefix(root)
                    .expect("package path under root")
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
    entries.sort();
    entries
}

#[test]
fn clean_room_assembly_has_exact_closed_layout_and_bare_mcp_contract() {
    let root = TempRoot::new("clean-room");
    let templates = templates();
    let package = assemble_clean_room(root.path(), &templates, &verified_inputs()).unwrap();

    assert_eq!(package.entries, PACKAGE_FILES.map(str::to_string));
    let mut expected_files = PACKAGE_FILES.map(str::to_string).to_vec();
    expected_files.sort();
    assert_eq!(package_files(&package.root, &package.root), expected_files);
    for relative in PACKAGE_FILES {
        let path = package.root.join(relative);
        assert!(path.starts_with(&package.root));
        let metadata = fs::symlink_metadata(&path).expect("package entry metadata");
        assert!(metadata.file_type().is_file());
        assert!(!metadata.file_type().is_symlink());
    }
    assert_eq!(
        fs::read(package.root.join("plugin.json")).unwrap(),
        templates.plugin_json
    );
    let mcp: Value = serde_json::from_slice(&fs::read(package.root.join("mcp.json")).unwrap())
        .expect("MCP template JSON");
    assert_eq!(
        mcp["$schema"],
        "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json"
    );
    assert_eq!(mcp["mcpServers"]["legion"]["command"], "legion");
    assert_eq!(
        mcp["mcpServers"]["legion"]["args"],
        serde_json::json!(["serve", "--stdio", "--plugin-root", "${PLUGIN_ROOT}"])
    );
}

#[test]
fn invalid_template_fails_before_creating_a_partial_clean_room() {
    let root = TempRoot::new("invalid-template");
    let mut templates = templates();
    templates.mcp_json = br#"{"mcpServers":{}}"#.to_vec();

    let error = assemble_clean_room(root.path(), &templates, &verified_inputs()).unwrap_err();
    assert_eq!(error.code(), FailureCode::InvalidDescriptor);
    assert!(!root.path().exists());
}

#[test]
fn portable_package_contains_no_embedded_runtime_or_interpreter() {
    let root = TempRoot::new("runtime-free");
    let package = assemble_clean_room(root.path(), &templates(), &verified_inputs()).unwrap();
    for relative in PACKAGE_FILES {
        assert!(
            !relative.ends_with(".mjs") && !relative.ends_with(".py") && !relative.ends_with(".sh")
        );
        let bytes = fs::read(package.root.join(relative)).unwrap();
        let content = String::from_utf8_lossy(&bytes);
        for forbidden in ["node", "python", "npx", "npm", "source-checkout"] {
            assert!(
                !content.to_ascii_lowercase().contains(forbidden),
                "{relative} contains forbidden runtime marker {forbidden}"
            );
        }
    }
}

#[test]
fn reference_clients_have_identical_bound_identity_and_fail_closed_on_skew() {
    let claude = identity("claude-code", "agent-plugins-bare-command");
    let codex = identity("codex", "supported-native-exact-path-registration");
    assert_eq!(
        (
            &claude.release_version,
            &claude.release_binding_digest,
            &claude.capability_catalog_hash,
            &claude.mcp_tool_schema_hash,
            &claude.declarative_assets_hash,
        ),
        (
            &codex.release_version,
            &codex.release_binding_digest,
            &codex.capability_catalog_hash,
            &codex.mcp_tool_schema_hash,
            &codex.declarative_assets_hash,
        )
    );
    verify_client_identity(&claude, &claude, &resolution("claude-code")).unwrap();

    let mut skewed = claude.clone();
    skewed.mcp_tool_schema_hash = "sha256:stale".into();
    let error = verify_client_identity(&claude, &skewed, &resolution("claude-code")).unwrap_err();
    assert_eq!(error.code(), FailureCode::ReleaseBindingMismatch);
    assert!(error.to_string().contains("legion setup --repair"));

    assert_eq!(
        ClientFidelity::from_evidence(true, false, false, false, false),
        ClientFidelity::Baseline
    );
    assert_eq!(
        ClientFidelity::from_evidence(true, true, true, true, true),
        ClientFidelity::Full
    );
}

#[test]
fn absent_external_evidence_is_a_typed_blocker_and_never_a_fabricated_pass() {
    let blocked = classify_external_qualification(&ExternalQualificationInputs::default());
    assert_eq!(
        blocked.status,
        ExternalQualificationStatus::ExternalQualificationBlocked
    );
    assert_eq!(
        blocked.missing_prerequisites,
        vec![
            "pinned-rightkit-ax-0.2.0@01f52555202da3dffc6b649ca44e803b55238081",
            "real-client-evidence",
            "signed-artifact-evidence",
        ]
    );

    let qualified = classify_external_qualification(&ExternalQualificationInputs {
        signed_artifact_evidence: Some("release-signature://fixture".into()),
        rightkit_ax: Some(PinnedAxEvidence {
            version: RIGHTKIT_AX_VERSION.into(),
            source_commit: RIGHTKIT_AX_SOURCE_COMMIT.into(),
            report_reference: "rightkit-ax://fixture".into(),
        }),
        real_client_evidence: Some("client://fixture".into()),
    });
    assert_eq!(qualified.status, ExternalQualificationStatus::Pass);
    assert!(qualified.missing_prerequisites.is_empty());
}

#[test]
fn m2_mechanical_adapters_delegate_to_installed_native_commands_without_source_paths() {
    let arcane_hook = include_str!("../../hooks/arcane-hook.mjs");
    assert!(arcane_hook.contains("spawnSync('legion-hook'"));
    assert!(arcane_hook.contains("shell: false"));
    for forbidden in ["/src/", "../src/", "server.mjs", "node "] {
        assert!(
            !arcane_hook.contains(forbidden),
            "arcane hook contains {forbidden}"
        );
    }

    let hooks = include_str!("../../src/integrations/hooks/index.mjs");
    for hook in ["PRE_COMMIT_HOOK", "PRE_PUSH_HOOK"] {
        assert!(hooks.contains(hook));
    }
    for forbidden in ["npx", "python", "@orthic-labs/legion"] {
        assert!(
            !hooks.contains(forbidden),
            "generated hooks contain {forbidden}"
        );
    }
}
