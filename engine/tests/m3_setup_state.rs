use legion_host::{
    BoundRelease, ClientEvidence, ClientSelector, OnDiskSetupStore, PlanConfirmation, SetupAction,
    SetupErrorCode, SetupRegistry, SetupRequest, SetupState, SetupStore,
    SETUP_REGISTRY_SCHEMA_VERSION,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

struct TempRoot(PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let temp_dir = fs::canonicalize(std::env::temp_dir()).expect("physical temp directory");
        Self(temp_dir.join(format!("legion-m3-{label}-{}-{nonce}", std::process::id())))
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

fn release() -> BoundRelease {
    BoundRelease {
        release_version: "0.1.0-test".into(),
        runtime_digest: "sha256:runtime".into(),
        capability_catalog_hash: "sha256:catalog".into(),
        mcp_tool_schema_hash: "sha256:mcp".into(),
        declarative_asset_schema_hash: "sha256:assets".into(),
        state_compatibility: "1".into(),
    }
}

fn evidence() -> Vec<ClientEvidence> {
    vec![ClientEvidence {
        client_id: "claude-code".into(),
        detected: true,
        mechanisms: vec!["agent-plugins-bare-command".into()],
        command_proof_ref: Some("installed-command-proof".into()),
        qualification_evidence_ref: None,
    }]
}

#[test]
fn release_bound_real_client_evidence_promotes_full_fidelity() {
    let root = TempRoot::new("qualified-client");
    fs::create_dir_all(root.path().join("qualification")).expect("qualification directory");
    fs::write(
        root.path().join("qualification/signing-receipt.json"),
        serde_json::json!({
            "schemaVersion": 1,
            "kind": "legion-signing-receipt",
            "releaseVersion": release().release_version,
            "runtimeSha256": release().runtime_digest,
            "signer": "Damned Ventures LLC",
            "authenticodeStatus": "Valid",
            "timestamped": true,
            "rightkitAxVersion": "0.2.0",
            "rightkitAxSourceCommit": "01f52555202da3dffc6b649ca44e803b55238081"
        })
        .to_string(),
    )
    .expect("signing receipt");
    let mut registry = registry(root.path());
    let mut request = request(root.path(), SetupAction::Apply);
    request.client_evidence[0].qualification_evidence_ref =
        Some("installed-real-client-proof".into());
    let preview = registry.preview(request).expect("preview qualified setup");
    assert_eq!(preview.clients[0].fidelity, "Full");
    assert_eq!(
        serde_json::to_value(&preview.external_qualification.status).expect("serialize status"),
        serde_json::json!("qualified")
    );
}

fn request(root: &Path, action: SetupAction) -> SetupRequest {
    SetupRequest {
        action,
        selector: ClientSelector::ClientId("claude-code".into()),
        release: release(),
        platform_state_root: root.to_path_buf(),
        client_evidence: evidence(),
        dry_run: false,
    }
}

fn registry(root: &Path) -> SetupRegistry<OnDiskSetupStore> {
    SetupRegistry::open_on_disk(release(), root.to_path_buf()).expect("open setup registry")
}

fn execute(registry: &mut SetupRegistry<OnDiskSetupStore>, request: SetupRequest) {
    let preview = registry.preview(request).expect("preview setup action");
    let confirmation = PlanConfirmation {
        plan_id: preview.plan_id.clone(),
        plan_digest: preview.plan_digest.clone(),
    };
    registry
        .execute(
            registry
                .confirm(preview, confirmation)
                .expect("confirm preview"),
        )
        .expect("execute confirmed setup action");
}

#[test]
fn lifecycle_actions_are_plan_bound_and_status_is_durable() {
    let root = TempRoot::new("lifecycle");
    let mut registry = registry(root.path());

    let preview = registry
        .preview(request(root.path(), SetupAction::Apply))
        .expect("preview apply");
    assert_eq!(
        serde_json::to_value(&preview.external_qualification.status).expect("serialize status"),
        serde_json::json!("external_qualification_blocked")
    );
    assert!(
        !root.path().join("setup-state.json").exists(),
        "preview must not mutate durable setup state"
    );
    let tampered = PlanConfirmation {
        plan_id: preview.plan_id.clone(),
        plan_digest: "sha256:tampered".into(),
    };
    assert_eq!(
        registry
            .confirm(preview.clone(), tampered)
            .unwrap_err()
            .code,
        SetupErrorCode::PlanConfirmationRequired
    );

    execute(&mut registry, request(root.path(), SetupAction::Apply));
    assert!(
        registry
            .status(&ClientSelector::AllSupported)
            .expect("status after apply")[0]
            .installed
    );

    execute(&mut registry, request(root.path(), SetupAction::Disable));
    assert_eq!(
        registry
            .status(&ClientSelector::AllSupported)
            .expect("status after disable")[0]
            .fidelity,
        "Disabled"
    );
    execute(&mut registry, request(root.path(), SetupAction::Repair));
    assert!(
        registry
            .status(&ClientSelector::AllSupported)
            .expect("status after repair")[0]
            .installed
    );

    execute(&mut registry, request(root.path(), SetupAction::Remove));
    assert!(
        !registry
            .status(&ClientSelector::AllSupported)
            .expect("status after remove")[0]
            .installed
    );

    execute(&mut registry, request(root.path(), SetupAction::Purge));
    assert!(registry
        .status(&ClientSelector::AllSupported)
        .expect("status after purge")
        .is_empty());
    assert!(!root.path().join("setup-state.json").exists());
    assert!(root.path().join(".legion-owned").is_file());
}

#[test]
fn stale_plans_and_runtime_leases_block_mutation_until_released() {
    let root = TempRoot::new("stale-and-lease");
    let mut registry = registry(root.path());
    let stale = registry
        .preview(request(root.path(), SetupAction::Apply))
        .expect("create stale candidate");

    execute(&mut registry, request(root.path(), SetupAction::Apply));
    let stale_confirmation = PlanConfirmation {
        plan_id: stale.plan_id.clone(),
        plan_digest: stale.plan_digest.clone(),
    };
    let stale = registry
        .confirm(stale, stale_confirmation)
        .expect("stale plan still has internally matching confirmation");
    assert_eq!(
        registry.execute(stale).unwrap_err().code,
        SetupErrorCode::PlanStale
    );

    let lease = registry
        .acquire_runtime_lease("claude-code".into(), "1".into())
        .expect("lease current generation");
    let repair = registry
        .preview(request(root.path(), SetupAction::Repair))
        .expect("preview repair");
    let repair = registry
        .confirm(
            repair.clone(),
            PlanConfirmation {
                plan_id: repair.plan_id.clone(),
                plan_digest: repair.plan_digest.clone(),
            },
        )
        .expect("confirm repair");
    assert_eq!(
        registry.execute(repair).unwrap_err().code,
        SetupErrorCode::RuntimeLeaseActive
    );
    registry
        .release_runtime_lease(lease)
        .expect("release runtime lease");
    execute(&mut registry, request(root.path(), SetupAction::Repair));
}

#[test]
fn recovery_and_purge_failure_compensate_to_the_verified_generation() {
    let root = TempRoot::new("recovery");
    let mut registry = registry(root.path());
    execute(&mut registry, request(root.path(), SetupAction::Apply));

    let repair = registry
        .preview(request(root.path(), SetupAction::Repair))
        .expect("preview repair for recovery journal");
    let mut store = OnDiskSetupStore::open(root.path().to_path_buf()).expect("open raw store");
    store.snapshot("1").expect("snapshot generation one");
    store
        .write_state_atomic(&SetupState {
            schema_version: SETUP_REGISTRY_SCHEMA_VERSION,
            migration_generation: "interrupted".into(),
        })
        .expect("write interrupted state");
    fs::write(
        root.path().join("journal/pending.json"),
        serde_json::json!({"rollback": repair.rollback}).to_string(),
    )
    .expect("write pending journal");
    assert_eq!(
        registry
            .recover()
            .expect("recover interrupted generation")
            .recovered_generation
            .as_deref(),
        Some("1")
    );
    assert_eq!(
        store
            .load_state()
            .expect("restored state")
            .expect("state present")
            .migration_generation,
        "1"
    );

    fs::write(root.path().join("foreign.txt"), "must survive failed purge")
        .expect("foreign ownership marker");
    let purge = registry
        .preview(request(root.path(), SetupAction::Purge))
        .expect("preview purge");
    let purge = registry
        .confirm(
            purge.clone(),
            PlanConfirmation {
                plan_id: purge.plan_id.clone(),
                plan_digest: purge.plan_digest.clone(),
            },
        )
        .expect("confirm purge");
    assert_eq!(
        registry.execute(purge).unwrap_err().code,
        SetupErrorCode::PurgeOwnershipUnproven
    );
    assert!(root.path().join("foreign.txt").is_file());
    assert!(!root.path().join("journal/pending.json").exists());
    assert_eq!(
        store
            .load_state()
            .expect("compensated state")
            .expect("state retained")
            .migration_generation,
        "1"
    );
}

#[test]
fn roots_and_locks_fail_closed_before_state_changes() {
    let checkout = TempRoot::new("checkout");
    fs::create_dir_all(checkout.path()).expect("checkout root");
    fs::create_dir_all(checkout.path().join(".git")).expect("git marker");
    fs::write(checkout.path().join("Cargo.toml"), "[workspace]").expect("cargo marker");
    assert_eq!(
        OnDiskSetupStore::open(checkout.path().join("state"))
            .unwrap_err()
            .code,
        SetupErrorCode::SourceCheckoutReferenceRefused
    );

    let parent = TempRoot::new("parent-component");
    assert_eq!(
        OnDiskSetupStore::open(parent.path().join("nested/../state"))
            .unwrap_err()
            .code,
        SetupErrorCode::PlatformStateRootInvalid
    );

    let root = TempRoot::new("lock");
    let mut first = OnDiskSetupStore::open(root.path().to_path_buf()).expect("first store");
    let mut second = OnDiskSetupStore::open(root.path().to_path_buf()).expect("second store");
    let lock = first
        .acquire_exclusive_lock()
        .expect("first lifecycle lock");
    assert_eq!(
        second.acquire_exclusive_lock().unwrap_err().code,
        SetupErrorCode::StateLockUnavailable
    );
    first
        .release_exclusive_lock(lock)
        .expect("release lifecycle lock");
}

#[cfg(unix)]
#[test]
fn symlinked_platform_roots_are_refused() {
    use std::os::unix::fs::symlink;

    let parent = TempRoot::new("symlink-parent");
    let target = parent.path().join("target");
    fs::create_dir_all(&target).expect("symlink target");
    let link = parent.path().join("link");
    symlink(&target, &link).expect("state-root symlink");
    assert_eq!(
        OnDiskSetupStore::open(link).unwrap_err().code,
        SetupErrorCode::PathEscapeRefused
    );
}

#[test]
fn m2_plugin_root_and_setup_cli_routes_remain_explicit() {
    let mcp: serde_json::Value =
        serde_json::from_str(include_str!("../assets/legion-plugin/mcp.json"))
            .expect("portable MCP JSON");
    assert_eq!(mcp["mcpServers"]["legion"]["command"], "legion");
    assert_eq!(
        mcp["mcpServers"]["legion"]["args"],
        serde_json::json!(["serve", "--stdio", "--plugin-root", "${PLUGIN_ROOT}"])
    );

    let cli = include_str!("../bins/legion/src/cli.rs");
    for required in [
        "Command::Serve(args) => native_m1_serve(args).await",
        "Command::Setup(args) => commands::setup::run(args, cancellation.clone()).await",
    ] {
        assert!(cli.contains(required), "missing CLI route: {required}");
    }
    let setup = include_str!("../bins/legion/src/commands/setup.rs");
    assert!(
        !setup.contains("state-root"),
        "setup CLI must not accept a caller-selected state root"
    );
    for required in ["platform_state_root()", "open_platform("] {
        assert!(
            setup.contains(required),
            "setup CLI must use the host platform-root API: {required}"
        );
    }
    for command in [
        "Preview", "Apply", "Status", "Repair", "Disable", "Remove", "Purge",
    ] {
        assert!(setup.contains(command), "missing setup grammar: {command}");
    }
    for argv_surface in [
        "legion setup [--dry-run]",
        "--client",
        "legion setup purge",
        "--confirm",
        "load_installed_release",
        "share/legion/release.json",
    ] {
        assert!(
            setup.contains(argv_surface)
                || cli.contains(argv_surface)
                || include_str!("../crates/legion-runtime/src/release_binding.rs")
                    .contains(argv_surface),
            "missing installed-product argv surface: {argv_surface}"
        );
    }
}
