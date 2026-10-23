use std::{collections::BTreeMap, process::Command, sync::Arc};

use legion_audit::{AuditError, FilesystemInventorySource, InventoryEnvelope, InventorySource};
use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderSpec, ProviderStatus};

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

/// Fixed-snapshot inventory fixture. Replaces the retired
/// `FileBlueprintInventorySource`: Legion (Rust) has no Blueprint/Membrane
/// packet to read, so a unit-level fixture that needs an exact, precomputed
/// inventory (independent of whatever else the test directory contains)
/// supplies it directly, the same way `StaticInventorySource` does inside
/// `legion_application`.
struct FixedInventorySource(InventoryEnvelope);

impl InventorySource for FixedInventorySource {
    fn inventory(&self, repository_id: &str) -> Result<InventoryEnvelope, AuditError> {
        if self.0.repository_id != repository_id {
            return Err(AuditError::SourceDrift(format!(
                "no configured inventory for repository {repository_id}"
            )));
        }
        Ok(self.0.clone())
    }
}

#[test]
fn configured_audit_writes_reconciled_json_and_sarif() {
    let root = std::env::temp_dir().join(format!(
        "legion-native-audit-{}-{}",
        std::process::id(),
        std::thread::current().name().unwrap_or("fixture")
    ));
    remove_fixture(&root);
    // Source files live in an isolated subdirectory so the frozen inventory
    // (and its digest) reflects exactly these two files, not whatever other
    // fixture artifacts (provider-plan.json, out/, ...) this test also
    // writes under `root`.
    let source_root = root.join("source");
    std::fs::create_dir_all(source_root.join("src")).unwrap();
    std::fs::write(source_root.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    std::fs::create_dir_all(source_root.join("docs")).unwrap();
    std::fs::write(source_root.join("docs/readme.md"), "fixture\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let source_root = std::fs::canonicalize(source_root).unwrap();
    let repository_id = source_root.to_string_lossy().into_owned();
    let snapshot = fixture_snapshot(&source_root);
    let execution_root = snapshot.manifest.execution_root.clone();
    let execution_id = execution_root.to_string_lossy().into_owned();
    let review_context = serde_json::json!({
        "snapshotManifest": snapshot.manifest_path,
        "snapshotKey": snapshot.manifest.key,
        "sourceRepository": source_root,
    });
    let provider_id = ProviderId::new("fixture-provider").unwrap();
    // Legion's own read-only filesystem walk is the sole inventory source;
    // use it here too so the fixture's digest matches exactly what the CLI
    // invocation below validates for this exact immutable execution root.
    let inventory = FilesystemInventorySource::new(&execution_root)
        .unwrap()
        .inventory(&execution_id)
        .unwrap();
    let result = ProviderResult {
        schema_version: 1,
        provider: provider_id.clone(),
        applicable: true,
        required: true,
        status: ProviderStatus::Complete,
        complete: true,
        coverage: Some(Coverage {
            denominator_digest: inventory.digest.clone(),
            expected: inventory.entries.len() as u64,
            examined: inventory.entries.len() as u64,
            gaps: Vec::new(),
        }),
        findings: Vec::new(),
        coverage_gaps: Vec::new(),
        degradation: Vec::new(),
        details: BTreeMap::new(),
    };
    let specification = ProviderSpec {
        schema_version: 2,
        id: provider_id.clone(),
        provider_version: "1".into(),
        family: "fixture".into(),
        lens_ids: Vec::new(),
        role: "deterministic".into(),
        phase: "source".into(),
        depends_on: Vec::new(),
        consumes: vec!["repository-inventory".into()],
        produces: vec!["provider-result".into()],
        selector: serde_json::json!({"op": "always"}),
        denominator_kind: "selected-scope".into(),
        runner: serde_json::json!({"kind": "built-in"}),
        host_capabilities: Vec::new(),
        execution: serde_json::json!({}),
        reasoning: serde_json::json!({}),
        benchmark: serde_json::json!({
            "status": "qualified",
            "requiredForCleanClaim": true,
            "qualificationDigest": "sha256:fixture"
        }),
        clean_claim: "finding-producing".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    };
    let invalid_result = {
        let mut invalid = result.clone();
        invalid.coverage.as_mut().unwrap().denominator_digest =
            format!("sha256:{}", "0".repeat(64));
        invalid
    };
    let source: Arc<dyn InventorySource> = Arc::new(FixedInventorySource(inventory.clone()));
    assert!(
        legion_application::NativeApplicationConfig::for_audit_artifacts(
            execution_id.clone(),
            source,
            vec![specification.clone()],
            vec![invalid_result],
            Some(execution_root.clone()),
        )
        .is_err()
    );
    let plan_path = root.join("provider-plan.json");
    std::fs::write(
        &plan_path,
        serde_json::to_vec_pretty(
            &serde_json::json!({"providers": [specification], "reviewContext": review_context}),
        )
        .unwrap(),
    )
    .unwrap();
    let result_path = root.join("provider-result.json");
    std::fs::write(
        &result_path,
        serde_json::to_vec_pretty(&serde_json::json!({"providerResult": result})).unwrap(),
    )
    .unwrap();
    let out = root.join("out");
    let mut command = Command::new(env!("CARGO_BIN_EXE_legion"));
    let output = command
        .args([
            "audit",
            "--out",
            out.to_str().unwrap(),
            "--json",
            "--provider-plan",
            plan_path.to_str().unwrap(),
            "--provider-result",
            result_path.to_str().unwrap(),
            &repository_id,
        ])
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
    // A bare provider list is accepted but never reads as bound or clean.
    assert_eq!(summary["auditStatus"], "incomplete");
    assert!(summary["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap == "unsealed-plan"));
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("report.json")).unwrap()).unwrap();
    assert_eq!(report["status"], "incomplete");
    assert_eq!(report["claims"]["executedProviderCount"], 1);
    let sarif: serde_json::Value =
        serde_json::from_slice(&std::fs::read(out.join("report.sarif")).unwrap()).unwrap();
    assert_eq!(sarif["version"], "2.1.0");
    assert!(out.join("execution.json").is_file());
}

const SEALED_KEY: &str = "fixture-signing-key";

fn fixture_specification() -> ProviderSpec {
    ProviderSpec {
        schema_version: 2,
        id: ProviderId::new("fixture-provider").unwrap(),
        provider_version: "1".into(),
        family: "fixture".into(),
        lens_ids: Vec::new(),
        role: "deterministic".into(),
        phase: "source".into(),
        depends_on: Vec::new(),
        consumes: vec!["repository-inventory".into()],
        produces: vec!["provider-result".into()],
        selector: serde_json::json!({"op": "always"}),
        denominator_kind: "selected-scope".into(),
        runner: serde_json::json!({"kind": "built-in"}),
        host_capabilities: Vec::new(),
        execution: serde_json::json!({}),
        reasoning: serde_json::json!({}),
        benchmark: serde_json::json!({
            "status": "qualified",
            "requiredForCleanClaim": true,
            "qualificationDigest": "sha256:fixture"
        }),
        clean_claim: "finding-producing".into(),
        control_ids: Vec::new(),
        scopes: Vec::new(),
        selectable: true,
    }
}

/// Writes a sealed plan (the `--plan-only` shape) and a matching result, runs
/// the direct route and returns the process output plus the run directory.
fn run_direct_with_sealed_plan(
    name: &str,
    tamper: impl Fn(&mut serde_json::Value),
    result_plan_digest: Option<&str>,
    scope: Option<&str>,
) -> (std::process::Output, std::path::PathBuf) {
    let root = std::env::temp_dir().join(format!(
        "legion-sealed-direct-{name}-{}",
        std::process::id()
    ));
    remove_fixture(&root);
    let source_root = root.join("source");
    std::fs::create_dir_all(source_root.join("src")).unwrap();
    std::fs::write(source_root.join("src/lib.rs"), "pub fn fixture() {}\n").unwrap();
    let root = std::fs::canonicalize(root).unwrap();
    let source_root = std::fs::canonicalize(source_root).unwrap();
    let repository_id = source_root.to_string_lossy().into_owned();
    let snapshot = fixture_snapshot(&source_root);
    let execution_root = snapshot.manifest.execution_root.clone();
    let execution_id = execution_root.to_string_lossy().into_owned();
    let review_context = serde_json::json!({
        "snapshotManifest": snapshot.manifest_path,
        "snapshotKey": snapshot.manifest.key,
        "sourceRepository": source_root,
    });
    let inventory = FilesystemInventorySource::new(&execution_root)
        .unwrap()
        .inventory(&execution_id)
        .unwrap();
    let mut specification = fixture_specification();
    specification.reasoning["reviewContext"] = review_context.clone();
    let frozen = legion_audit::AuditPlan::compile_with_root(
        Some(execution_root.as_path()),
        &inventory,
        std::slice::from_ref(&specification),
    )
    .unwrap()
    .freeze(Some(SEALED_KEY.as_bytes()))
    .unwrap();
    let mut plan = serde_json::json!({
        "schemaVersion": 1,
        "kind": "audit-provider-plan",
        "reviewContext": review_context,
        "planDigest": frozen.digest(),
        "planSignature": frozen.signature(),
        "seal": {
            "digest": frozen.digest(),
            "authenticity": "hmac-sha256",
            "signature": frozen.signature(),
        },
        "binding": {
            "repositoryRevision": inventory.generation,
            "inventoryDigest": inventory.digest,
        },
        "providers": ["fixture-provider"],
        "providerSpecs": [specification],
    });
    tamper(&mut plan);
    let result = ProviderResult {
        schema_version: 1,
        provider: specification.id.clone(),
        applicable: true,
        required: true,
        status: ProviderStatus::Complete,
        complete: true,
        coverage: Some(Coverage {
            denominator_digest: inventory.digest.clone(),
            expected: inventory.entries.len() as u64,
            examined: inventory.entries.len() as u64,
            gaps: Vec::new(),
        }),
        findings: Vec::new(),
        coverage_gaps: Vec::new(),
        degradation: Vec::new(),
        details: BTreeMap::new(),
    };
    let mut result_document = serde_json::json!({"providerResult": result});
    if let Some(digest) = result_plan_digest {
        result_document["planDigest"] = serde_json::json!(digest);
    }
    let plan_path = root.join("provider-plan.json");
    std::fs::write(&plan_path, serde_json::to_vec_pretty(&plan).unwrap()).unwrap();
    let result_path = root.join("provider-result.json");
    std::fs::write(
        &result_path,
        serde_json::to_vec_pretty(&result_document).unwrap(),
    )
    .unwrap();
    let out = root.join("out");
    let mut command = Command::new(env!("CARGO_BIN_EXE_legion"));
    command.arg("audit");
    if let Some(scope) = scope {
        command.args(["--type", scope]);
    }
    let output = command
        .args([
            "--out",
            out.to_str().unwrap(),
            "--json",
            "--provider-plan",
            plan_path.to_str().unwrap(),
            "--provider-result",
            result_path.to_str().unwrap(),
            &repository_id,
        ])
        .env("AUDIT_PLAN_SIGNING_KEY", SEALED_KEY)
        .output()
        .unwrap();
    (output, root)
}

#[test]
fn sealed_plan_is_accepted_without_an_unsealed_gap() {
    let (output, root) = run_direct_with_sealed_plan("accepted", |_| {}, None, None);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!summary["gaps"]
        .as_array()
        .unwrap()
        .iter()
        .any(|gap| gap == "unsealed-plan"));
    assert_eq!(summary["auditStatus"], "pass");
    let plan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("out/plan.json")).unwrap()).unwrap();
    assert!(plan.get("providerSelection").is_none());
    assert!(plan.get("fullScope").is_none());
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("out/report.json")).unwrap()).unwrap();
    assert!(report["claims"].get("providerCoverage").is_none());
    remove_fixture(&root);
}

#[test]
fn tampered_sealed_plan_is_refused() {
    let (output, root) = run_direct_with_sealed_plan(
        "tampered",
        |plan| plan["providerSpecs"][0]["providerVersion"] = serde_json::json!("2"),
        None,
        None,
    );
    assert_eq!(
        output.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("seal verification failed"));
    assert!(!root.join("out/report.json").exists());
    remove_fixture(&root);
}

#[test]
fn provider_result_naming_a_different_plan_digest_is_refused() {
    let other = format!("sha256:{}", "a".repeat(64));
    let (output, root) = run_direct_with_sealed_plan("digest", |_| {}, Some(&other), None);
    assert_eq!(
        output.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("names plan digest"));
    remove_fixture(&root);
}

#[test]
fn imported_snapshot_cannot_change_the_requested_scope() {
    let (output, root) =
        run_direct_with_sealed_plan("scope-mismatch", |_| {}, None, Some("committed"));
    assert_eq!(
        output.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("differs from current requested source scope"));
    assert!(!root.join("out/report.json").exists());
    remove_fixture(&root);
}

#[test]
fn imported_snapshot_cannot_hide_changed_source_bytes() {
    let (output, root) = run_direct_with_sealed_plan(
        "source-mismatch",
        |plan| {
            let source =
                std::path::Path::new(plan["reviewContext"]["sourceRepository"].as_str().unwrap());
            std::fs::write(source.join("src/lib.rs"), "pub fn changed() {}\n").unwrap();
        },
        None,
        None,
    );
    assert_eq!(
        output.status.code(),
        Some(5),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("differs from current requested source scope"));
    assert!(!root.join("out/report.json").exists());
    remove_fixture(&root);
}

/// Runs `legion audit findings <args> --repo <repo>` from the system temp
/// directory, which is never the repository, so the store must resolve from
/// the given root and not from the working directory.
fn findings_cli(repo: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_legion"))
        .current_dir(std::env::temp_dir())
        .arg("audit")
        .arg("findings")
        .args(args)
        .arg("--repo")
        .arg(repo)
        .output()
        .unwrap()
}

#[test]
fn findings_lifecycle_is_exposed_and_refuses_invalid_transitions() {
    let repo = std::env::temp_dir().join(format!("legion-findings-cli-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&repo);
    std::fs::create_dir_all(repo.join(".audit/audit")).unwrap();
    let repo = std::fs::canonicalize(repo).unwrap();
    let id = "audit:rule:abc1234-R1:src/a.rs:def5678";
    let record = serde_json::json!({
        "schemaVersion": 1, "id": id, "repositoryId": "repo-1", "scopeId": "scope-1",
        "auditGeneration": "g1", "linkedGraphGeneration": "", "severity": "medium",
        "category": "security", "title": "a finding",
        "evidenceLoci": [{"path": "src/a.rs", "startLine": 3, "endLine": 5}],
        "confidence": 1.0, "status": "open", "supersedes": [], "supersededBy": null,
        "firstSeenGeneration": "g1", "lastSeenGeneration": "g1",
        "firstSeenAt": "2026-01-01T00:00:00Z", "lastSeenAt": "2026-01-01T00:00:00Z",
        "resolvedGeneration": null, "resolvedAt": null,
        "provenance": {"kind": "manual", "name": "R1", "version": "1", "ruleId": "R1"}
    });
    std::fs::write(
        repo.join(".audit/audit/findings.jsonl"),
        format!("{}\n", serde_json::to_string(&record).unwrap()),
    )
    .unwrap();

    let listed = findings_cli(&repo, &["list", "--active"]);
    assert_eq!(listed.status.code(), Some(0));
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["count"], 1);
    assert_eq!(
        std::path::Path::new(listed["store"].as_str().unwrap()),
        repo.join(".audit/audit/findings.jsonl").as_path()
    );

    // A bare resolve is never a fix: it needs ResolutionEvidence plus a report.
    let bare = findings_cli(&repo, &["resolve", id, "--generation", "g2"]);
    assert_eq!(bare.status.code(), Some(4));
    // A dismissal without both an authority and a reason is refused too.
    let no_reason = findings_cli(&repo, &["dismiss", id, "--authority", "owner"]);
    assert_eq!(no_reason.status.code(), Some(4));
    let still_open = findings_cli(&repo, &["list", "--active"]);
    let still_open: serde_json::Value = serde_json::from_slice(&still_open.stdout).unwrap();
    assert_eq!(still_open["count"], 1);

    let dismissed = findings_cli(
        &repo,
        &[
            "dismiss",
            id,
            "--authority",
            "owner",
            "--reason",
            "accepted risk",
        ],
    );
    assert_eq!(
        dismissed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&dismissed.stderr)
    );
    let dismissed: serde_json::Value = serde_json::from_slice(&dismissed.stdout).unwrap();
    assert_eq!(dismissed["finding"]["status"], "dismissed");
    assert_eq!(dismissed["finding"]["dismissal"]["authority"], "owner");
    assert_eq!(dismissed["finding"]["dismissal"]["reason"], "accepted risk");

    let active = findings_cli(&repo, &["list", "--active"]);
    let active: serde_json::Value = serde_json::from_slice(&active.stdout).unwrap();
    assert_eq!(active["count"], 0);

    // Unknown ids and missing successors are refused with a usage error.
    assert_eq!(
        findings_cli(&repo, &["resolve", "audit:rule:none"])
            .status
            .code(),
        Some(4)
    );
    assert_eq!(
        findings_cli(&repo, &["supersede", id]).status.code(),
        Some(4)
    );
    assert_eq!(findings_cli(&repo, &["bogus", id]).status.code(), Some(4));
    std::fs::remove_dir_all(repo).unwrap();
}

#[test]
fn findings_positional_root_and_repo_flag_resolve_the_store_under_the_root() {
    let repo = std::env::temp_dir().join(format!("legion-findings-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&repo);
    std::fs::create_dir_all(repo.join(".audit/audit")).unwrap();
    let repo = std::fs::canonicalize(repo).unwrap();
    let id = "audit:rule:abc1234-R1:src/b.rs:fed9876";
    let record = serde_json::json!({
        "schemaVersion": 1, "id": id, "repositoryId": "repo-2", "scopeId": "scope-2",
        "auditGeneration": "g1", "linkedGraphGeneration": "", "severity": "low",
        "category": "security", "title": "b finding",
        "evidenceLoci": [{"path": "src/b.rs", "startLine": 1, "endLine": 2}],
        "confidence": 1.0, "status": "open", "supersedes": [], "supersededBy": null,
        "firstSeenGeneration": "g1", "lastSeenGeneration": "g1",
        "firstSeenAt": "2026-01-01T00:00:00Z", "lastSeenAt": "2026-01-01T00:00:00Z",
        "resolvedGeneration": null, "resolvedAt": null,
        "provenance": {"kind": "manual", "name": "R1", "version": "1", "ruleId": "R1"}
    });
    std::fs::write(
        repo.join(".audit/audit/findings.jsonl"),
        format!("{}\n", serde_json::to_string(&record).unwrap()),
    )
    .unwrap();
    let elsewhere = std::env::temp_dir();
    let store = repo.join(".audit/audit/findings.jsonl");

    // `list <root>` takes the root positionally, from a different working directory.
    let listed = Command::new(env!("CARGO_BIN_EXE_legion"))
        .current_dir(&elsewhere)
        .args(["audit", "findings", "list"])
        .arg(&repo)
        .output()
        .unwrap();
    assert_eq!(
        listed.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let listed: serde_json::Value = serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(listed["count"], 1);
    assert_eq!(
        std::path::Path::new(listed["store"].as_str().unwrap()),
        store.as_path()
    );

    // Id-taking actions take the root only through --repo.
    let bare = Command::new(env!("CARGO_BIN_EXE_legion"))
        .current_dir(&elsewhere)
        .args(["audit", "findings", "resolve", id, "--generation", "g2"])
        .arg("--repo")
        .arg(&repo)
        .output()
        .unwrap();
    assert_eq!(bare.status.code(), Some(4));
    let resolved = Command::new(env!("CARGO_BIN_EXE_legion"))
        .current_dir(&elsewhere)
        .args([
            "audit",
            "findings",
            "dismiss",
            id,
            "--generation",
            "g2",
            "--authority",
            "owner",
            "--reason",
            "accepted risk",
        ])
        .arg("--repo")
        .arg(&repo)
        .output()
        .unwrap();
    assert_eq!(
        resolved.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&resolved.stderr)
    );
    let resolved: serde_json::Value = serde_json::from_slice(&resolved.stdout).unwrap();
    assert_eq!(resolved["finding"]["status"], "dismissed");
    assert_eq!(
        std::path::Path::new(resolved["store"].as_str().unwrap()),
        store.as_path()
    );

    // Giving the root both positionally and with --repo is refused, not guessed.
    let both = Command::new(env!("CARGO_BIN_EXE_legion"))
        .current_dir(&elsewhere)
        .args(["audit", "findings", "list"])
        .arg(&repo)
        .arg("--repo")
        .arg(&repo)
        .output()
        .unwrap();
    assert_eq!(both.status.code(), Some(4));

    // An id-taking action given a second positional (a root) is refused.
    let extra = Command::new(env!("CARGO_BIN_EXE_legion"))
        .current_dir(&elsewhere)
        .args(["audit", "findings", "resolve", id, "extra-root"])
        .output()
        .unwrap();
    assert_eq!(extra.status.code(), Some(4));
    std::fs::remove_dir_all(repo).unwrap();
}

#[test]
fn findings_resolve_refuses_unverified_run_and_the_old_report_flag() {
    let repo = std::env::temp_dir().join(format!("legion-findings-run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&repo);
    std::fs::create_dir_all(repo.join(".audit/audit")).unwrap();
    let repo = std::fs::canonicalize(repo).unwrap();
    let id = "audit:rule:abc1234-R1:src/a.rs:def5678";
    let record = serde_json::json!({
        "schemaVersion": 1, "id": id, "repositoryId": "repo-1", "scopeId": "scope-1",
        "auditGeneration": "g1", "linkedGraphGeneration": "", "severity": "medium",
        "category": "security", "title": "a finding",
        "evidenceLoci": [{"path": "src/a.rs", "startLine": 3, "endLine": 5}],
        "confidence": 1.0, "status": "open", "supersedes": [], "supersededBy": null,
        "firstSeenGeneration": "g1", "lastSeenGeneration": "g1",
        "firstSeenAt": "2026-01-01T00:00:00Z", "lastSeenAt": "2026-01-01T00:00:00Z",
        "resolvedGeneration": null, "resolvedAt": null,
        "provenance": {"kind": "manual", "name": "R1", "version": "1", "ruleId": "R1"}
    });
    std::fs::write(
        repo.join(".audit/audit/findings.jsonl"),
        format!("{}\n", serde_json::to_string(&record).unwrap()),
    )
    .unwrap();
    // A forged "clean" run directory: report and evidence, no journal or signature.
    let fake = repo.join("fake-run");
    std::fs::create_dir_all(&fake).unwrap();
    let report = br#"{"schemaVersion":1,"status":"clean","findings":[],"gaps":[]}"#;
    std::fs::write(fake.join("report.json"), report).unwrap();
    let digest = format!("sha256:{}", {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(report))
    });
    let evidence = serde_json::json!({
        "findingId": id, "kind": "reviewed-repair", "reportDigest": digest,
        "ruleId": "R1", "ruleRevision": "1", "regressionCondition": "test x",
        "acceptedBy": "mallory", "evidenceDigest": digest
    });
    std::fs::write(repo.join("evidence.json"), evidence.to_string()).unwrap();
    for flag in ["--run", "--report"] {
        let out = findings_cli(
            &repo,
            &[
                "resolve",
                id,
                "--evidence",
                repo.join("evidence.json").to_str().unwrap(),
                flag,
                fake.to_str().unwrap(),
            ],
        );
        assert_ne!(out.status.code(), Some(0), "{flag}");
    }
    let active = findings_cli(&repo, &["list", "--active"]);
    let active: serde_json::Value = serde_json::from_slice(&active.stdout).unwrap();
    assert_eq!(active["count"], 1);
    let _ = std::fs::remove_dir_all(&repo);
}
