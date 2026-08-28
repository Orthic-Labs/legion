use legion_host::{
    classify_external_qualification, verify_client_identity, ClientFidelity, ClientIdentity,
    CommandResolutionEvidence, ExternalQualificationInputs, ExternalQualificationStatus,
    FailureCode, PinnedAxEvidence, RIGHTKIT_AX_SOURCE_COMMIT, RIGHTKIT_AX_VERSION,
};

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
    assert!(error.to_string().contains("legion setup repair --confirm"));

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
            "pinned-rightkit-ax-0.2.1@4c1a414269d8ffdb95b4b1e685440bd34784b41b",
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
    let arcane_hook = include_str!("../../hooks/hooks.json");
    assert!(arcane_hook.contains("\"command\": \"legion-hook\""));
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
