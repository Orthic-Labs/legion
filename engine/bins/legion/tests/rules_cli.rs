use std::process::Command;

fn fixture_git(root: &std::path::Path, args: &[&str]) {
    let mut child = Command::new("git")
        .current_dir(root)
        .args([
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env(
            "GIT_CONFIG_GLOBAL",
            if cfg!(windows) { "NUL" } else { "/dev/null" },
        )
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "fixture Git failed: {args:?}");
            break;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("fixture Git deadline: {args:?}");
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}
fn init_fixture_git(root: &std::path::Path) {
    // Audit state is disposable run output, excluded from clean source fixtures.
    std::fs::write(root.join(".gitignore"), ".audit/\n").unwrap();
    fixture_git(root, &["init", "-q", "--template="]);
    fixture_git(root, &["config", "user.name", "Audit Fixture"]);
    fixture_git(root, &["config", "user.email", "audit@example.invalid"]);
    fixture_git(root, &["add", "."]);
    fixture_git(root, &["commit", "-qm", "fixture source"]);
}
fn fixture_snapshot(root: &std::path::Path) -> legion_audit::snapshot::FrozenSnapshot {
    init_fixture_git(root);
    legion_audit::snapshot::FrozenSnapshot::capture(
        legion_audit::scope::ResolvedScope::resolve(
            root,
            legion_audit::scope::ScopeSpec::Repo,
            None,
        )
        .unwrap(),
    )
    .unwrap()
}
fn remove_fixture(root: &std::path::Path) {
    let Ok(meta) = std::fs::symlink_metadata(root) else {
        return;
    };
    if meta.is_dir() && !meta.file_type().is_symlink() {
        let mut permissions = meta.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            permissions.set_mode(permissions.mode() | 0o700);
        }
        #[cfg(not(unix))]
        permissions.set_readonly(false);
        std::fs::set_permissions(root, permissions).unwrap();
        for entry in std::fs::read_dir(root).unwrap() {
            remove_fixture(&entry.unwrap().path());
        }
        std::fs::remove_dir(root).unwrap();
    } else {
        #[cfg(not(unix))]
        {
            let mut permissions = meta.permissions();
            permissions.set_readonly(false);
            std::fs::set_permissions(root, permissions).unwrap();
        }
        std::fs::remove_file(root).unwrap();
    }
}

/// Rewritten from the retired `native_rules_evaluate_blueprint_bound_source`:
/// Legion (Rust) has no Blueprint/Membrane dependency, so `rules` evaluates
/// against its own local-filesystem inventory directly — there is no packet
/// to bind, so the `--blueprint-packet`/`--expected-generation` flags this
/// test used to pass are gone from the CLI entirely.
#[test]
fn native_rules_evaluate_local_inventory_bound_source() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-rules-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    remove_fixture(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(
        root.join("src/service.rs"),
        "fn update() { let url = \"http://updates.example\"; }\n",
    )
    .unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    assert!(
        !root.join(".git").exists(),
        "standalone rules fixture must remain nongit"
    );
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "rules",
            "--manifest",
            manifest.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--provider",
            "native.security.rules",
            "--pack",
            "security.native-workspace",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "complete");
    assert_eq!(result["providerResult"]["complete"], true);
    assert_eq!(
        result["providerResult"]["findings"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        result["providerResult"]["coverage"]["denominator_digest"],
        result["inventoryDigest"]
    );

    let snapshot = fixture_snapshot(&root);
    let frozen_rules = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "rules",
            "--manifest",
            manifest.to_str().unwrap(),
            "--root",
            snapshot.manifest.execution_root.to_str().unwrap(),
            "--provider",
            "native.security.rules",
            "--pack",
            "security.native-workspace",
        ])
        .output()
        .unwrap();
    assert_eq!(
        frozen_rules.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&frozen_rules.stderr)
    );
    // Artifacts live outside the scanned root so writing them cannot change
    // the inventory the rule result was bound to.
    let artifacts = root.with_extension("artifacts");
    std::fs::create_dir_all(&artifacts).unwrap();
    let result_path = artifacts.join("rule-result.json");
    std::fs::write(&result_path, &frozen_rules.stdout).unwrap();
    let plan = serde_json::json!({
        "reviewContext": {"snapshotManifest": snapshot.manifest_path, "snapshotKey": snapshot.manifest.key},
        "providers": [{
            "schemaVersion": 2,
            "id": "native.security.rules",
            "providerVersion": "1",
            "family": "security",
            "lensIds": [],
            "role": "deterministic",
            "phase": "source",
            "dependsOn": [],
            "consumes": ["repository-inventory"],
            "produces": ["provider-result"],
            "selector": {"op": "always"},
            "denominatorKind": "repository-inventory",
            "runner": {"kind": "built-in"},
            "hostCapabilities": [],
            "execution": {},
            "reasoning": {},
            "benchmark": {
                "status": "qualified",
                "requiredForCleanClaim": true,
                "qualificationDigest": "sha256:fixture"
            },
            "cleanClaim": "finding-producing",
            "controlIds": [],
            "scopes": [],
            "selectable": true
        }]
    });
    let plan_path = artifacts.join("provider-plan.json");
    std::fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
    let audit_out = root.join(".audit/run");
    let audit = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "audit",
            "--out",
            audit_out.to_str().unwrap(),
            "--provider-plan",
            plan_path.to_str().unwrap(),
            "--provider-result",
            result_path.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .env("AUDIT_PLAN_SIGNING_KEY", "fixture-signing-key")
        .output()
        .unwrap();
    assert_eq!(
        audit.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&audit.stderr)
    );
    let audit_summary: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap();
    // The plan is a bare provider list, so the run cannot read as bound.
    assert_eq!(audit_summary["auditStatus"], "incomplete");
    assert!(audit_summary["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap == "unsealed-plan"));
    assert_eq!(audit_summary["findingCount"], 1);
    assert!(audit_out.join("report.json").is_file());
    assert!(audit_out.join("report.sarif").is_file());
}

/// Rewritten from the retired `native_audit_continues_without_blueprint`:
/// Legion (Rust) has no Blueprint/Membrane fallback path to exercise — its
/// filesystem inventory is the only source, not a degraded fallback — so
/// this now asserts the plain local-inventory run completes without any
/// blueprint-flavored context notice.
#[test]
fn native_audit_runs_on_local_filesystem_inventory_only() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-audit-fallback-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    remove_fixture(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join(".audit/inputs")).unwrap();
    std::fs::write(root.join("src/service.rs"), "fn service() {}\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    assert!(
        !root.join(".git").exists(),
        "standalone rules fixture must remain nongit"
    );
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    let rules = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "rules",
            "--manifest",
            manifest.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--provider",
            "native.fixture",
        ])
        .output()
        .unwrap();
    assert_eq!(
        rules.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&rules.stderr)
    );
    let rules_summary: serde_json::Value = serde_json::from_slice(&rules.stdout).unwrap();
    assert_eq!(rules_summary["status"], "complete");
    // Legion has no external context engine to fall back from: the local
    // filesystem inventory is the only source, so there is nothing to notice.
    assert_eq!(rules_summary["contextNotices"], serde_json::json!([]));
    let snapshot = fixture_snapshot(&root);
    let frozen_rules = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "rules",
            "--manifest",
            manifest.to_str().unwrap(),
            "--root",
            snapshot.manifest.execution_root.to_str().unwrap(),
            "--provider",
            "native.fixture",
        ])
        .output()
        .unwrap();
    assert_eq!(
        frozen_rules.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&frozen_rules.stderr)
    );
    let plan = serde_json::json!({
        "reviewContext": {"snapshotManifest": snapshot.manifest_path, "snapshotKey": snapshot.manifest.key},
        "providers": [{
            "schemaVersion": 2,
            "id": "native.fixture",
            "providerVersion": "1",
            "family": "security",
            "lensIds": [],
            "role": "deterministic",
            "phase": "source",
            "dependsOn": [],
            "consumes": ["repository-inventory"],
            "produces": ["provider-result"],
            "selector": {"op": "always"},
            "denominatorKind": "repository-inventory",
            "runner": {"kind": "built-in"},
            "hostCapabilities": [],
            "execution": {},
            "reasoning": {},
            "benchmark": {
                "status": "qualified",
                "requiredForCleanClaim": true,
                "qualificationDigest": "sha256:fixture"
            },
            "cleanClaim": "finding-producing",
            "controlIds": [],
            "scopes": [],
            "selectable": true
        }]
    });
    let plan_path = root.join(".audit/inputs/provider-plan.json");
    let result_path = root.join(".audit/inputs/provider-result.json");
    std::fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
    std::fs::write(&result_path, &frozen_rules.stdout).unwrap();
    let audit_out = root.join(".audit/output");
    let audit = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "audit",
            "--out",
            audit_out.to_str().unwrap(),
            "--provider-plan",
            plan_path.to_str().unwrap(),
            "--provider-result",
            result_path.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .env("AUDIT_PLAN_SIGNING_KEY", "fixture-signing-key")
        .output()
        .unwrap();
    assert_eq!(
        audit.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&audit.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&audit.stdout).unwrap();
    // The plan is a bare provider list, so the run cannot read as bound.
    assert_eq!(summary["auditStatus"], "incomplete");
    assert!(summary["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap == "unsealed-plan"));
    assert_eq!(summary["contextNotices"], serde_json::json!([]));
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(audit_out.join("report.json")).unwrap()).unwrap();
    // No degraded-context notice is recorded on the report claims either —
    // there is no external context engine for Legion to have fallen back from.
    assert!(report["claims"].get("contextNotices").is_none());
    remove_fixture(&root);
}

#[test]
fn native_audit_composes_builtin_rule_executor_without_host_config() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-audit-composed-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    remove_fixture(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/service.rs"), "fn service() {}\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    init_fixture_git(&root);
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    let out = root.join("audit");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "audit",
            "--out",
            out.to_str().unwrap(),
            "--native-rule-manifest",
            manifest.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
        .env("AUDIT_PLAN_SIGNING_KEY", "fixture-signing-key")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(summary["auditStatus"], "incomplete");
    assert_eq!(summary["qualityGate"], "unproven");
    assert!(summary["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap == "native-provider-composition-partial"));
    assert_eq!(
        summary["plannedProviders"],
        serde_json::json!(["security.native-rules"])
    );
    assert_eq!(summary["resultCount"], 1);
    assert_eq!(summary["processExecution"], "complete");
    assert!(out.join("report.json").is_file());
    assert!(out.join("execution.json").is_file());
    remove_fixture(&root);
}

#[test]
fn native_rules_report_unproven_for_invalid_source_bytes() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-rules-invalid-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    remove_fixture(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/binary.rs"), [0xff, 0xfe]).unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "rules",
            "--manifest",
            manifest.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--provider",
            "native.fixture",
            "--pack",
            "security.native-workspace",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["status"], "incomplete");
    assert_eq!(result["providerResult"]["complete"], false);
    assert!(result["providerResult"]["coverage_gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap.as_str().unwrap().contains("source-invalid-utf8")));
    remove_fixture(&root);
}

#[test]
fn native_rules_emits_selector_bound_denominator() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-rules-selector-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    remove_fixture(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::create_dir_all(root.join("docs")).unwrap();
    std::fs::write(root.join("src/service.rs"), "fn service() {}\n").unwrap();
    std::fs::write(root.join("docs/readme.md"), "fixture\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "rules",
            "--manifest",
            manifest.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--provider",
            "native.fixture",
            "--selector",
            r#"{"op":"anyPath","patterns":["src/*.rs"]}"#,
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["providerResult"]["coverage"]["expected"], 1);
    assert_ne!(
        result["providerResult"]["coverage"]["denominator_digest"],
        result["inventoryDigest"]
    );
    assert_eq!(
        result["denominatorDigest"],
        result["providerResult"]["coverage"]["denominator_digest"]
    );
    remove_fixture(&root);
}

#[test]
fn native_audit_without_signing_material_runs_source_scan_as_unsigned_incomplete() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-audit-unsigned-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    remove_fixture(&root);
    std::fs::create_dir_all(root.join("src")).unwrap();
    std::fs::write(root.join("src/service.rs"), "fn service() {}\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    init_fixture_git(&root);
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../packs/native/manifest.v1.json");
    // The per-run plan key lives in host state; isolate it from the real user state.
    let state = std::env::temp_dir().join(format!(
        "legion-native-audit-unsigned-state-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    let out = root.join("audit");
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "audit",
            "--out",
            out.to_str().unwrap(),
            "--native-rule-manifest",
            manifest.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .env_remove("LEGION_NATIVE_APPLICATION_CONFIG")
        .env_remove("AUDIT_PLAN_SIGNING_KEY")
        .env("LEGION_STATE_ROOT", &state)
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "summary not JSON ({error}); stderr={}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
    assert_eq!(summary["auditStatus"], "incomplete");
    assert_eq!(summary["qualityGate"], "unproven");
    assert!(summary["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap == "native-provider-composition-partial"));
    assert_eq!(
        summary["plannedProviders"],
        serde_json::json!(["security.native-rules"])
    );
    assert_eq!(summary["resultCount"], 1);
    assert_eq!(summary["processExecution"], "complete");
    assert!(out.join("report.json").is_file());
    assert!(out.join("execution.json").is_file());
    // An `--out` run without host signing material is signed with a key
    // minted for that run, so lens packets can later be ingested; the plan is
    // therefore not reported as unsigned.
    assert!(!summary["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap == "unsigned-plan"));
    assert!(summary["planSignature"].is_string());
    let plan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("plan.json")).unwrap()).unwrap();
    assert_eq!(plan["seal"]["authenticity"], "hmac-sha256");
    // The key is held in host state, never in the run directory.
    assert!(!out.join("epoch.key").exists());
    assert_eq!(plan["planKey"]["custody"], "host-state");
    assert_eq!(
        std::fs::read_dir(state.join("audit-plan-keys"))
            .unwrap()
            .count(),
        1
    );
    let _ = std::fs::remove_dir_all(&state);
    remove_fixture(&root);
}
