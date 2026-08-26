//! Source-side installed-product qualification gate.
//!
//! This harness consumes evidence produced by signed-release and real-client
//! runs. It never creates evidence, launches a product, or edits qualification
//! artifacts. Missing, malformed, or source-checkout inputs are typed blocks.

use legion_host::{
    classify_external_qualification, verify_client_identity, ClientFidelity, ClientIdentity,
    CommandResolutionEvidence, ExternalQualificationInputs, ExternalQualificationStatus,
    PinnedAxEvidence, RIGHTKIT_AX_SOURCE_COMMIT, RIGHTKIT_AX_VERSION,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

const SIGNED_ARTIFACT_ENV: &str = "LEGION_M6_SIGNED_ARTIFACT_EVIDENCE";
const RIGHTKIT_AX_ENV: &str = "LEGION_M6_RIGHTKIT_AX_EVIDENCE";
const REAL_CLIENT_ENV: &str = "LEGION_M6_REAL_CLIENT_EVIDENCE";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct EvidencePaths {
    signed_artifact: Option<PathBuf>,
    rightkit_ax: Option<PathBuf>,
    real_client: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum QualificationDecision {
    Qualified,
    Blocked(Vec<String>),
}

#[derive(Clone, Debug)]
struct SignedArtifactEvidence {
    platform: String,
    architecture: String,
    digest: String,
    signature: String,
    identity: SignedReleaseIdentity,
}

#[derive(Clone, Debug)]
struct SignedReleaseIdentity {
    release_version: String,
    capability_catalog_hash: String,
    mcp_tool_schema_hash: String,
    declarative_assets_hash: String,
}

#[derive(Clone, Debug)]
struct RealClientEvidence {
    client_id: String,
    client_version: String,
    selected_mechanism: String,
    resolved_executable: String,
    release_version: String,
    release_binding_digest: String,
    runtime_digest: String,
    provenance: String,
    capability_catalog_hash: String,
    mcp_tool_schema_hash: String,
    declarative_assets_hash: String,
    launch_environment_digest: String,
    fidelity: String,
    source_checkout: bool,
    path_sanitized: bool,
}

impl SignedArtifactEvidence {
    fn validate(&self) -> Result<(), &'static str> {
        for value in [
            &self.platform,
            &self.architecture,
            &self.signature,
            &self.identity.release_version,
            &self.identity.capability_catalog_hash,
            &self.identity.mcp_tool_schema_hash,
            &self.identity.declarative_assets_hash,
        ] {
            if value.trim().is_empty() {
                return Err("signed artifact evidence contains an empty identity field");
            }
        }
        if !is_sha256(&self.digest) {
            return Err("signed artifact digest must be SHA-256");
        }
        Ok(())
    }
}

impl RealClientEvidence {
    fn validate(&self) -> Result<(), &'static str> {
        for value in [
            &self.client_id,
            &self.client_version,
            &self.selected_mechanism,
            &self.resolved_executable,
            &self.release_version,
            &self.release_binding_digest,
            &self.runtime_digest,
            &self.provenance,
            &self.capability_catalog_hash,
            &self.mcp_tool_schema_hash,
            &self.declarative_assets_hash,
            &self.launch_environment_digest,
            &self.fidelity,
        ] {
            if value.trim().is_empty() {
                return Err("real-client evidence contains an empty field");
            }
        }
        if self.source_checkout || !self.path_sanitized {
            return Err("real-client evidence must be an installed, path-sanitized executable");
        }
        if self.fidelity != "Full" {
            return Err("real-client evidence must prove Full fidelity");
        }
        if !matches!(
            self.selected_mechanism.as_str(),
            "agent-plugins-bare-command" | "supported-native-exact-path-registration"
        ) {
            return Err("real-client evidence uses an unsupported mechanism");
        }
        for digest in [
            &self.release_binding_digest,
            &self.runtime_digest,
            &self.capability_catalog_hash,
            &self.mcp_tool_schema_hash,
            &self.declarative_assets_hash,
            &self.launch_environment_digest,
        ] {
            if !is_sha256(digest) {
                return Err("real-client evidence contains a non-SHA-256 digest");
            }
        }
        let normalized = self
            .resolved_executable
            .replace('\\', "/")
            .to_ascii_lowercase();
        if normalized.contains("/target/")
            || normalized.contains("/checkout/")
            || normalized.contains("/worktree/")
        {
            return Err("real-client executable resolves into a source checkout");
        }
        Ok(())
    }

    fn identity(&self) -> ClientIdentity {
        ClientIdentity {
            client_id: self.client_id.clone(),
            selected_mechanism: self.selected_mechanism.clone(),
            release_version: self.release_version.clone(),
            release_binding_digest: self.release_binding_digest.clone(),
            capability_catalog_hash: self.capability_catalog_hash.clone(),
            mcp_tool_schema_hash: self.mcp_tool_schema_hash.clone(),
            declarative_assets_hash: self.declarative_assets_hash.clone(),
        }
    }

    fn resolution(&self) -> CommandResolutionEvidence {
        CommandResolutionEvidence {
            client_id: self.client_id.clone(),
            resolution_mode: self.selected_mechanism.clone(),
            resolved_executable: self.resolved_executable.clone(),
            runtime_digest: self.runtime_digest.clone(),
            provenance: self.provenance.clone(),
            launch_environment_digest: self.launch_environment_digest.clone(),
            source_checkout: self.source_checkout,
            path_sanitized: self.path_sanitized,
        }
    }
}

fn verify_real_client_against_signed_artifact(
    signed: &SignedArtifactEvidence,
    client: &RealClientEvidence,
) -> Result<(), &'static str> {
    let expected = ClientIdentity {
        client_id: client.client_id.clone(),
        selected_mechanism: client.selected_mechanism.clone(),
        release_version: signed.identity.release_version.clone(),
        release_binding_digest: signed.digest.clone(),
        capability_catalog_hash: signed.identity.capability_catalog_hash.clone(),
        mcp_tool_schema_hash: signed.identity.mcp_tool_schema_hash.clone(),
        declarative_assets_hash: signed.identity.declarative_assets_hash.clone(),
    };
    verify_client_identity(&expected, &client.identity(), &client.resolution())
        .map_err(|_| "real-client identity does not match signed artifact identity")
}

fn is_sha256(value: &str) -> bool {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn evidence_paths_from_environment() -> EvidencePaths {
    let path = |name: &str| {
        std::env::var_os(name)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    EvidencePaths {
        signed_artifact: path(SIGNED_ARTIFACT_ENV),
        rightkit_ax: path(RIGHTKIT_AX_ENV),
        real_client: path(REAL_CLIENT_ENV),
    }
}

fn read_json_object(
    path: Option<&Path>,
    label: &str,
    missing: &mut Vec<String>,
) -> Option<serde_json::Value> {
    let Some(path) = path else {
        missing.push(label.into());
        return None;
    };
    let Ok(metadata) = fs::symlink_metadata(path) else {
        missing.push(label.into());
        return None;
    };
    if !metadata.file_type().is_file() {
        missing.push(format!("{label} (must be a regular file)"));
        return None;
    }
    match fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .filter(serde_json::Value::is_object)
    {
        Some(value) => Some(value),
        None => {
            missing.push(format!("{label} (must be a typed JSON object)"));
            None
        }
    }
}

fn exact_fields(value: &serde_json::Value, fields: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.len() == fields.len() && object.keys().all(|key| fields.contains(&key.as_str()))
}

fn string_field(value: &serde_json::Value, field: &str) -> Option<String> {
    value.get(field)?.as_str().map(str::to_owned)
}

fn parse_signed_artifact(value: serde_json::Value) -> Option<SignedArtifactEvidence> {
    if !exact_fields(
        &value,
        &[
            "platform",
            "architecture",
            "digest",
            "signature",
            "identity",
        ],
    ) {
        return None;
    }
    let identity = value.get("identity")?;
    if !exact_fields(
        identity,
        &[
            "releaseVersion",
            "capabilityCatalogHash",
            "mcpToolSchemaHash",
            "declarativeAssetsHash",
        ],
    ) {
        return None;
    }
    Some(SignedArtifactEvidence {
        platform: string_field(&value, "platform")?,
        architecture: string_field(&value, "architecture")?,
        digest: string_field(&value, "digest")?,
        signature: string_field(&value, "signature")?,
        identity: SignedReleaseIdentity {
            release_version: string_field(identity, "releaseVersion")?,
            capability_catalog_hash: string_field(identity, "capabilityCatalogHash")?,
            mcp_tool_schema_hash: string_field(identity, "mcpToolSchemaHash")?,
            declarative_assets_hash: string_field(identity, "declarativeAssetsHash")?,
        },
    })
}

fn parse_real_client(value: serde_json::Value) -> Option<RealClientEvidence> {
    let fields = [
        "clientId",
        "clientVersion",
        "selectedMechanism",
        "resolvedExecutable",
        "releaseVersion",
        "releaseBindingDigest",
        "runtimeDigest",
        "provenance",
        "capabilityCatalogHash",
        "mcpToolSchemaHash",
        "declarativeAssetsHash",
        "launchEnvironmentDigest",
        "fidelity",
        "sourceCheckout",
        "pathSanitized",
    ];
    if !exact_fields(&value, &fields) {
        return None;
    }
    Some(RealClientEvidence {
        client_id: string_field(&value, "clientId")?,
        client_version: string_field(&value, "clientVersion")?,
        selected_mechanism: string_field(&value, "selectedMechanism")?,
        resolved_executable: string_field(&value, "resolvedExecutable")?,
        release_version: string_field(&value, "releaseVersion")?,
        release_binding_digest: string_field(&value, "releaseBindingDigest")?,
        runtime_digest: string_field(&value, "runtimeDigest")?,
        provenance: string_field(&value, "provenance")?,
        capability_catalog_hash: string_field(&value, "capabilityCatalogHash")?,
        mcp_tool_schema_hash: string_field(&value, "mcpToolSchemaHash")?,
        declarative_assets_hash: string_field(&value, "declarativeAssetsHash")?,
        launch_environment_digest: string_field(&value, "launchEnvironmentDigest")?,
        fidelity: string_field(&value, "fidelity")?,
        source_checkout: value.get("sourceCheckout")?.as_bool()?,
        path_sanitized: value.get("pathSanitized")?.as_bool()?,
    })
}

fn pinned_ax_evidence(path: Option<&Path>, missing: &mut Vec<String>) -> Option<PinnedAxEvidence> {
    let value = read_json_object(path, "pinned-rightkit-ax-evidence", missing)?;
    if !exact_fields(&value, &["version", "sourceCommit", "reportReference"]) {
        missing.push("pinned-rightkit-ax-evidence (typed schema mismatch)".into());
        return None;
    }
    let evidence = PinnedAxEvidence {
        version: string_field(&value, "version")?,
        source_commit: string_field(&value, "sourceCommit")?,
        report_reference: string_field(&value, "reportReference")?,
    };
    if evidence.version != RIGHTKIT_AX_VERSION
        || evidence.source_commit != RIGHTKIT_AX_SOURCE_COMMIT
        || evidence.report_reference.trim().is_empty()
    {
        missing.push(format!(
            "pinned-rightkit-ax-{}@{}",
            RIGHTKIT_AX_VERSION, RIGHTKIT_AX_SOURCE_COMMIT
        ));
        return None;
    }
    Some(evidence)
}

fn classify_installed_product(paths: &EvidencePaths) -> QualificationDecision {
    let mut missing = Vec::new();
    let signed = read_json_object(
        paths.signed_artifact.as_deref(),
        "signed-artifact-evidence",
        &mut missing,
    )
    .and_then(parse_signed_artifact);
    if signed
        .as_ref()
        .is_some_and(|evidence| evidence.validate().is_err())
    {
        missing.push("signed-artifact-evidence (typed identity or digest invalid)".into());
    }
    let rightkit_ax = pinned_ax_evidence(paths.rightkit_ax.as_deref(), &mut missing);
    let client = read_json_object(
        paths.real_client.as_deref(),
        "real-client-evidence",
        &mut missing,
    )
    .and_then(parse_real_client);
    if client
        .as_ref()
        .is_some_and(|evidence| evidence.validate().is_err())
    {
        missing.push(
            "real-client-evidence (typed identity, resolution, or source path invalid)".into(),
        );
    }

    if let Some(evidence) = &client {
        if evidence.validate().is_ok() {
            let identity = evidence.identity();
            if verify_client_identity(&identity, &identity, &evidence.resolution()).is_err() {
                missing.push(
                    "real-client-evidence (identity or resolution verification failed)".into(),
                );
            }
        }
    }
    if let (Some(signed), Some(client)) = (&signed, &client) {
        if signed.validate().is_ok()
            && client.validate().is_ok()
            && verify_real_client_against_signed_artifact(signed, client).is_err()
        {
            missing.push("real-client-evidence (signed release identity mismatch)".into());
        }
    }
    let external = classify_external_qualification(&ExternalQualificationInputs {
        signed_artifact_evidence: signed
            .as_ref()
            .filter(|evidence| evidence.validate().is_ok())
            .map(|_| "signed-artifact-evidence".into()),
        rightkit_ax,
        real_client_evidence: client
            .as_ref()
            .filter(|evidence| evidence.validate().is_ok())
            .map(|_| "real-client-evidence".into()),
    });
    if external.status == ExternalQualificationStatus::ExternalQualificationBlocked {
        missing.extend(external.missing_prerequisites);
    }
    missing.sort();
    missing.dedup();
    if missing.is_empty() {
        QualificationDecision::Qualified
    } else {
        QualificationDecision::Blocked(missing)
    }
}

fn identity(client_id: &str, mechanism: &str) -> ClientIdentity {
    ClientIdentity {
        client_id: client_id.into(),
        selected_mechanism: mechanism.into(),
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

fn fixture_digest(hex: char) -> String {
    format!("sha256:{}", hex.to_string().repeat(64))
}

fn signed_artifact_fixture() -> SignedArtifactEvidence {
    SignedArtifactEvidence {
        platform: "windows".into(),
        architecture: "x86_64".into(),
        digest: fixture_digest('a'),
        signature: "signed-release-fixture".into(),
        identity: SignedReleaseIdentity {
            release_version: "0.1.0".into(),
            capability_catalog_hash: fixture_digest('b'),
            mcp_tool_schema_hash: fixture_digest('c'),
            declarative_assets_hash: fixture_digest('d'),
        },
    }
}

fn real_client_fixture(signed: &SignedArtifactEvidence) -> RealClientEvidence {
    RealClientEvidence {
        client_id: "claude-code".into(),
        client_version: "1.0.0".into(),
        selected_mechanism: "agent-plugins-bare-command".into(),
        resolved_executable: "/opt/legion/bin/legion".into(),
        release_version: signed.identity.release_version.clone(),
        release_binding_digest: signed.digest.clone(),
        runtime_digest: fixture_digest('e'),
        provenance: "rightkit-release://fixture".into(),
        capability_catalog_hash: signed.identity.capability_catalog_hash.clone(),
        mcp_tool_schema_hash: signed.identity.mcp_tool_schema_hash.clone(),
        declarative_assets_hash: signed.identity.declarative_assets_hash.clone(),
        launch_environment_digest: fixture_digest('f'),
        fidelity: "Full".into(),
        source_checkout: false,
        path_sanitized: true,
    }
}

#[test]
fn absent_installed_product_evidence_is_blocked() {
    let decision = classify_installed_product(&EvidencePaths::default());
    let QualificationDecision::Blocked(missing) = decision else {
        panic!("missing signed release evidence must never qualify")
    };
    assert!(missing
        .iter()
        .any(|item| item == "signed-artifact-evidence"));
    assert!(missing.iter().any(|item| item == "real-client-evidence"));
    assert!(missing
        .iter()
        .any(|item| item.starts_with("pinned-rightkit-ax-")));
}

#[test]
fn arbitrary_json_objects_are_blocked_by_typed_evidence_parsers() {
    let root = std::env::temp_dir().join(format!("legion-m6-{}", std::process::id()));
    fs::create_dir_all(&root).expect("evidence root");
    for (name, value) in [
        ("signed.json", "{}"),
        ("ax.json", "{}"),
        ("client.json", "{}"),
    ] {
        fs::write(root.join(name), value).expect("evidence fixture");
    }
    let decision = classify_installed_product(&EvidencePaths {
        signed_artifact: Some(root.join("signed.json")),
        rightkit_ax: Some(root.join("ax.json")),
        real_client: Some(root.join("client.json")),
    });
    assert!(matches!(decision, QualificationDecision::Blocked(_)));
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn environment_inputs_are_consumed_only_as_existing_typed_files() {
    let paths = evidence_paths_from_environment();
    let decision = classify_installed_product(&paths);
    if std::env::var_os(SIGNED_ARTIFACT_ENV).is_none()
        || std::env::var_os(RIGHTKIT_AX_ENV).is_none()
        || std::env::var_os(REAL_CLIENT_ENV).is_none()
    {
        assert!(matches!(decision, QualificationDecision::Blocked(_)));
    }
}

#[test]
fn client_identity_and_resolution_must_match_before_full_fidelity() {
    let expected = identity("claude-code", "agent-plugins-bare-command");
    verify_client_identity(&expected, &expected, &resolution("claude-code"))
        .expect("matching release identity should verify");

    let mut skewed = expected.clone();
    skewed.mcp_tool_schema_hash = "sha256:stale".into();
    assert!(verify_client_identity(&expected, &skewed, &resolution("claude-code")).is_err());

    assert_eq!(
        ClientFidelity::from_evidence(true, true, true, true, true),
        ClientFidelity::Full
    );
    assert_ne!(
        ClientFidelity::from_evidence(true, true, true, false, true),
        ClientFidelity::Full
    );
}

#[test]
fn signed_artifact_identity_mismatch_blocks_real_client() {
    let signed = signed_artifact_fixture();
    let mut client = real_client_fixture(&signed);
    assert!(signed.validate().is_ok());
    assert!(client.validate().is_ok());
    assert!(verify_real_client_against_signed_artifact(&signed, &client).is_ok());

    client.mcp_tool_schema_hash = fixture_digest('f');
    assert!(verify_real_client_against_signed_artifact(&signed, &client).is_err());
}

#[test]
fn source_checkout_resolution_can_never_qualify() {
    let expected = identity("codex", "supported-native-exact-path-registration");
    let mut source_checkout = resolution("codex");
    source_checkout.resolution_mode = "supported-native-exact-path-registration".into();
    source_checkout.resolved_executable = "D:/checkout/target/debug/legion".into();
    source_checkout.source_checkout = true;
    assert!(verify_client_identity(&expected, &expected, &source_checkout).is_err());
}
