//! Constructed native controls only. No installed CLI or production claim.
//! Root integration explicitly admits this ignored harness with real pinned
//! Gitleaks; stubs cannot satisfy its executable digest/version assertions.
use super::*;
use crate::native_providers::security::{
    adapter::SecurityProviderExecutor,
    history::{manifest_value, FrozenHistory},
};
use crate::{FilesystemInventorySource, InventorySource, ProviderExecutor};
use std::collections::BTreeMap;
use std::io::Write;
use std::process::{Command, Stdio};
#[path = "history_qualification_record.rs"]
mod record;

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args([
            "-c",
            "user.name=Audit synthetic fixture",
            "-c",
            "user.email=audit-fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .args(args)
        .current_dir(root)
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Git fixture setup: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}
fn signed_fixture_tip(root: &Path) -> String {
    let head = git(root, &["rev-parse", "HEAD"]);
    let raw = git(root, &["cat-file", "commit", &head]);
    let (header, message) = raw.split_once("\n\n").unwrap();
    let bytes = format!("{header}\ngpgsig -----BEGIN PGP SIGNATURE-----\n invalid synthetic signature\n -----END PGP SIGNATURE-----\n\n{message}\n");
    let mut child = Command::new("git")
        .args(["hash-object", "-t", "commit", "-w", "--stdin"])
        .current_dir(root)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(bytes.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    let oid = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    git(root, &["update-ref", "refs/heads/main", &oid]);
    oid
}
fn token() -> String {
    format!("{}{}", "ghp_", "R7kQ2mZ9xL4vB8nC1dF6hJ3sT5wY0aE2gU9i")
}
fn put(root: &Path, path: &str, contents: &str) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, contents).unwrap();
}
fn commit(root: &Path, message: &str) -> String {
    git(root, &["add", "--all"]);
    git(root, &["commit", "--quiet", "-m", message]);
    git(root, &["rev-parse", "HEAD"])
}
fn fixture(parent: &Path, name: &str, planted: bool) -> (PathBuf, Option<String>, Option<String>) {
    let root = parent.join(name);
    fs::create_dir(&root).unwrap();
    git(&root, &["init", "--quiet", "--initial-branch=main"]);
    put(&root, "README.md", "synthetic qualification fixture\n");
    if planted {
        put(&root, "deleted.txt", &format!("token = \"{}\"\n", token()));
    }
    let deleted = commit(&root, "initial synthetic fixture");
    if planted {
        fs::remove_file(root.join("deleted.txt")).unwrap();
    } else {
        put(&root, "temporary.txt", "clean\n");
    }
    commit(&root, "intermediate synthetic fixture");
    if !planted {
        fs::remove_file(root.join("temporary.txt")).unwrap();
    }
    // Keep identical nonsecret final trees for clean/deleted-history controls.
    if !planted {
        commit(&root, "remove temporary file");
    }
    let branch = if planted {
        git(&root, &["checkout", "--quiet", "-b", "branch-only"]);
        put(
            &root,
            "branch-only.txt",
            &format!("token = \"{}\"\n", token()),
        );
        let oid = commit(&root, "branch-only synthetic fixture");
        git(&root, &["checkout", "--quiet", "main"]);
        Some(oid)
    } else {
        None
    };
    (
        fs::canonicalize(root).unwrap(),
        planted.then_some(deleted),
        branch,
    )
}
fn spec(inventory: &InventoryEnvelope) -> AuditProvider {
    let denominator = inventory
        .denominator_entries(&json!({"op":"always"}))
        .unwrap();
    serde_json::from_value(json!({"id":"secrets.current-history","version":"1.0.0","role":"security","phase":"source","lensIds":[],"dependencies":[],"kind":"typed-external-project-tool",
        "configuration":{"selector":{"op":"always"},"denominatorDigest":denominator.digest,"denominatorCount":denominator.entries.len()},"bounds":{},"cleanClaim":"evidence-only","benchmarkStatus":"not-required","benchmarkRequiredForCleanClaim":false,"qualificationDigest":null,"required":true})).unwrap()
}
fn inventory(root: &Path) -> InventoryEnvelope {
    FilesystemInventorySource::new(root)
        .unwrap()
        .inventory("synthetic-history-qualification")
        .unwrap()
}
fn producer(root: &Path, run_dir: &Path, bin: &Path) -> ArtifactProducer {
    ArtifactProducer::new(root)
        .with_run_dir(run_dir)
        .with_search_path(vec![bin.parent().unwrap().to_owned()])
        .with_sandbox(SandboxPolicy::Disabled)
        .with_policy_authorizer(Arc::new(legion_effects::StaticPolicy {
            decision: legion_effects::PolicyDecision {
                allowed: true,
                policy_id: "synthetic-secrets-history-qualification-only".into(),
                policy_version: 1,
                policy_digest: digest(b"synthetic-secrets-history-qualification-only"),
                reason: None,
            },
        }))
}
fn execute(root: &Path, producer: &ArtifactProducer) -> legion_contracts::ProviderResult {
    let inventory = inventory(root);
    SecurityProviderExecutor::default()
        .with_producer(producer.clone())
        .execute(&spec(&inventory), &inventory)
        .unwrap()
}

fn assert_final_finding(
    result: &legion_contracts::ProviderResult,
    path: &str,
    mode: &str,
    commit: Option<&str>,
) {
    assert!(
        !result.findings.is_empty(),
        "native positive control delivered no final findings"
    );
    let evidence = result.details["findingEvidence"].as_object().unwrap();
    let locations = result.details["findingLocations"].as_object().unwrap();
    assert!(
        result.findings.iter().any(|finding| {
            let id = finding.id.as_str();
            let Some(proof) = evidence.get(id) else {
                return false;
            };
            if proof["provider"] != "secrets.current-history"
                || proof["path"] != path
                || proof["line"] != 1
                || proof["redacted"] != true
            {
                return false;
            }
            if mode == "history"
                && (proof["mode"] != "history"
                    || proof["commit"].as_str() != commit
                    || proof["blobOid"].as_str().is_none()
                    || proof["blobDigest"].as_str().is_none()
                    || proof["historyManifestDigest"].as_str().is_none())
            {
                return false;
            }
            if mode == "current" && proof.get("commit").is_some() {
                return false;
            }
            locations.get(id) == Some(&json!([format!("{path}:1")]))
        }),
        "native positive control lost final finding/evidence/anchor binding: {path}"
    );
}

#[test]
#[ignore = "Root-owned real Gitleaks v8.30.0 qualification; requires explicit private scratch + pinned executable digest"]
fn native_current_history_qualification() {
    let parent = PathBuf::from(
        std::env::var_os("LEGION_SECRET_QUALIFICATION_DIR")
            .expect("explicit scratch directory required"),
    );
    let ci_root = std::env::var_os("RUNNER_TEMP").map(PathBuf::from);
    assert!(
        parent.starts_with("/Volumes/D/scratch")
            || parent.starts_with("D:\\scratch")
            || ci_root
                .as_ref()
                .is_some_and(|root| parent.starts_with(root)),
        "explicit external scratch or native CI RUNNER_TEMP required"
    );
    fs::create_dir_all(&parent).unwrap();
    let bin = fs::canonicalize(
        std::env::var_os("LEGION_GITLEAKS_BINARY").expect("real pinned Gitleaks required"),
    )
    .unwrap();
    let expected =
        std::env::var("LEGION_GITLEAKS_SHA256").expect("pinned actual executable SHA256 required");
    assert_eq!(digest(&fs::read(&bin).unwrap()), expected);
    let mut controls = BTreeMap::new();
    let mut cases = BTreeMap::new();
    let (planted, deleted, branch) = fixture(&parent, "planted-history", true);
    let (clean, _, _) = fixture(&parent, "clean-history", false);
    assert_eq!(
        fs::read(planted.join("README.md")).unwrap(),
        fs::read(clean.join("README.md")).unwrap()
    );
    assert_eq!(
        inventory(&planted)
            .entries
            .iter()
            .map(|entry| (&entry.path, &entry.digest))
            .collect::<Vec<_>>(),
        inventory(&clean)
            .entries
            .iter()
            .map(|entry| (&entry.path, &entry.digest))
            .collect::<Vec<_>>()
    );
    let planted_producer = producer(&planted, &parent, &bin);
    let result = execute(&planted, &planted_producer);
    assert!(result.complete, "{result:?}");
    let coverage = result.coverage.as_ref().unwrap();
    assert_eq!(coverage.expected, 1);
    assert_eq!(coverage.examined, 1);
    assert!(coverage.gaps.is_empty());
    let findings = result.details["analysis"]["findings"].as_array().unwrap();
    assert!(findings.iter().any(|finding| finding["mode"] == "history"
        && finding["file"] == "deleted.txt"
        && finding["commit"] == deleted.as_deref().unwrap()));
    assert!(findings.iter().any(|finding| finding["mode"] == "history"
        && finding["file"] == "branch-only.txt"
        && finding["commit"] == branch.as_deref().unwrap()));
    assert!(result.details["findingLocations"]
        .as_object()
        .unwrap()
        .values()
        .any(|locations| locations
            .as_array()
            .unwrap()
            .iter()
            .any(|location| location.as_str().unwrap().starts_with("deleted.txt:"))));
    assert!(!serde_json::to_string(&result.details)
        .unwrap()
        .contains(&token()));
    assert_final_finding(&result, "deleted.txt", "history", deleted.as_deref());
    assert_final_finding(&result, "branch-only.txt", "history", branch.as_deref());
    let clean_producer = producer(&clean, &parent, &bin);
    let clean_result = execute(&clean, &clean_producer);
    assert!(clean_result.complete, "{clean_result:?}");
    assert!(clean_result.findings.is_empty());
    let (current, _, _) = fixture(&parent, "current-secret", false);
    put(
        &current,
        "current.txt",
        &format!("token = \"{}\"\n", token()),
    );
    let current_producer = producer(&current, &parent, &bin);
    let current_result = execute(&current, &current_producer);
    assert!(current_result.complete, "{current_result:?}");
    assert!(current_result.details["analysis"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["mode"] == "current"
            && finding["file"] == "current.txt"
            && finding["commit"].is_null()));
    assert_final_finding(&current_result, "current.txt", "current", None);
    cases.insert(
        "planted".into(),
        record::case(&planted, &planted_producer, &result),
    );
    cases.insert(
        "clean".into(),
        record::case(&clean, &clean_producer, &clean_result),
    );
    cases.insert(
        "current".into(),
        record::case(&current, &current_producer, &current_result),
    );
    // Real Git binary attributes & a signed tip with hostile verifier settings.
    // --text must expose deleted text; --no-show-signature must prevent launch.
    let (attributes, attributes_deleted, _) = fixture(&parent, "attributes-signature", true);
    put(&attributes, ".gitattributes", "*.txt -diff\n");
    commit(&attributes, "synthetic binary attribute control");
    let signed_oid = signed_fixture_tip(&attributes);
    let verifier = parent.join("forbidden-gpg");
    let marker = parent.join("forbidden-gpg-ran");
    put(
        &parent,
        "forbidden-gpg",
        &format!(
            "#!/bin/sh\nprintf forbidden > '{}'\nexit 1\n",
            marker.display()
        ),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&verifier, fs::Permissions::from_mode(0o700)).unwrap();
    }
    git(&attributes, &["config", "log.showSignature", "true"]);
    git(
        &attributes,
        &["config", "gpg.program", verifier.to_str().unwrap()],
    );
    let attributes_producer = producer(&attributes, &parent, &bin);
    let attributes_result = execute(&attributes, &attributes_producer);
    assert!(attributes_result.complete, "{attributes_result:?}");
    assert!(attributes_result.details["analysis"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["mode"] == "history" && v["file"] == "deleted.txt"));
    assert_final_finding(
        &attributes_result,
        "deleted.txt",
        "history",
        attributes_deleted.as_deref(),
    );
    assert!(!marker.exists(), "project signature verifier executed");
    cases.insert(
        "attributes-signature".into(),
        record::case(&attributes, &attributes_producer, &attributes_result),
    );
    let signature_observation = json!({"signedTip":signed_oid,"logShowSignature":git(&attributes,&["config","--get","log.showSignature"]),"gpgProgram":git(&attributes,&["config","--get","gpg.program"]),"verifierDigest":digest(&fs::read(&verifier).unwrap()),"markerExists":marker.exists()});
    // Native retained streams outlive private run scratch & remain bound to
    // actual SDK artifacts, argv, policy receipt & executable identity.
    for (name, producer) in [
        ("planted", &planted_producer),
        ("clean", &clean_producer),
        ("current", &current_producer),
    ] {
        let runs = producer.retained_secret_runs.lock().unwrap();
        assert_eq!(runs.len(), 2);
        assert_ne!(
            runs[0].actual_receipt.request_id,
            runs[1].actual_receipt.request_id
        );
        let evidence_dir = parent.join(format!("{name}-native-evidence"));
        fs::create_dir(&evidence_dir).unwrap();
        for (index, run) in runs.iter().enumerate() {
            assert!(run.actual_receipt.policy.as_ref().unwrap().allowed);
            assert!(run.actual_receipt.process_tree.reaped);
            assert_eq!(
                run.actual_receipt.stdout.as_ref().unwrap().digest,
                digest(&run.stdout)
            );
            assert_eq!(
                run.actual_receipt.stderr.as_ref().unwrap().digest,
                digest(&run.stderr)
            );
            fs::write(evidence_dir.join(format!("{index}.stdout")), &run.stdout).unwrap();
            fs::write(evidence_dir.join(format!("{index}.stderr")), &run.stderr).unwrap();
            fs::write(
                evidence_dir.join(format!("{index}.sdk-receipt.txt")),
                format!("{:#?}", run.actual_receipt),
            )
            .unwrap();
            fs::write(
                evidence_dir.join(format!("{index}.projection.json")),
                serde_json::to_vec_pretty(&run.receipt).unwrap(),
            )
            .unwrap();
        }
        fs::write(evidence_dir.join("qualification-scope.json"),serde_json::to_vec_pretty(&json!({"productionQualification":false,"installedCliAdmission":false,"scannerDigest":expected,"fixture":name,"sdkSandboxPolicy":"disabled-by-explicit-synthetic-fixture-admission"})).unwrap()).unwrap();
    }
    fs::write(
        parent.join("planted-result.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    fs::write(
        parent.join("clean-result.json"),
        serde_json::to_vec_pretty(&clean_result).unwrap(),
    )
    .unwrap();
    fs::write(
        parent.join("current-result.json"),
        serde_json::to_vec_pretty(&current_result).unwrap(),
    )
    .unwrap();

    // Frozen snapshot uses its admitted original source/object store; its
    // execution root cannot discover a parent repository when manifest absent.
    let scope =
        crate::scope::ResolvedScope::resolve(&planted, crate::scope::ScopeSpec::Committed, None)
            .unwrap();
    let snapshot = crate::snapshot::FrozenSnapshot::capture(scope).unwrap();
    let snapshot_root = &snapshot.manifest.execution_root;
    let snapshot_inventory = inventory(snapshot_root);
    let snapshot_paths = snapshot_inventory
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    record::failure(
        &mut controls,
        "snapshot-without-manifest",
        FrozenHistory::capture(snapshot_root, None, &snapshot_inventory, &snapshot_paths),
    );
    record::incomplete(
        &mut controls,
        "snapshot-provider-without-manifest",
        execute(snapshot_root, &producer(snapshot_root, &parent, &bin)),
    );
    let snapshot_frozen = FrozenHistory::capture(
        snapshot_root,
        Some(&snapshot.manifest_path),
        &snapshot_inventory,
        &snapshot_paths,
    )
    .unwrap();
    assert_eq!(snapshot_frozen.manifest.source_root, planted);
    assert_eq!(snapshot_frozen.manifest.history_selection, "snapshot-scope");
    assert!(!snapshot_frozen
        .manifest
        .tips
        .contains(branch.as_deref().unwrap()));
    let snapshot_producer =
        producer(snapshot_root, &parent, &bin).with_snapshot_manifest(&snapshot.manifest_path);
    let snapshot_result = execute(snapshot_root, &snapshot_producer);
    assert!(snapshot_result.complete);
    assert_final_finding(
        &snapshot_result,
        "deleted.txt",
        "history",
        deleted.as_deref(),
    );
    let snapshot_case = record::case(snapshot_root, &snapshot_producer, &snapshot_result);
    let snapshot_record = json!({"case":snapshot_case,"manifestHex":fs::read(&snapshot.manifest_path).unwrap().iter().map(|v| format!("{v:02x}")).collect::<String>(),"manifestPath":snapshot.manifest_path,"manifestDigest":digest(&fs::read(&snapshot.manifest_path).unwrap()),"selectedOid":snapshot_frozen.manifest.selected_oid,"excludedBranch":branch});
    let mut manifest_bytes = fs::read(&snapshot.manifest_path).unwrap();
    manifest_bytes.push(b' ');
    let mut permissions = fs::metadata(&snapshot.manifest_path).unwrap().permissions();
    permissions.set_readonly(false);
    fs::set_permissions(&snapshot.manifest_path, permissions).unwrap();
    fs::write(&snapshot.manifest_path, manifest_bytes).unwrap();
    record::failure(
        &mut controls,
        "snapshot-manifest-tamper",
        snapshot_frozen.revalidate(),
    );
    record::failure(
        &mut controls,
        "snapshot-inventory-tamper",
        FilesystemInventorySource::new(snapshot_root)
            .unwrap()
            .inventory("synthetic-history-qualification")
            .map_err(|error| error.to_string()),
    );

    // Mutated proof, commit, blob & receipt/raw bytes cannot become clean.
    let frozen_inventory = inventory(&planted);
    let paths = frozen_inventory
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    let frozen = FrozenHistory::capture(&planted, None, &frozen_inventory, &paths).unwrap();
    let proof = manifest_value(&frozen.manifest);
    let mut changed = proof.clone();
    changed["manifest"]["head"] = json!("0".repeat(40));
    record::predicate(
        &mut controls,
        "history-manifest-tamper",
        super::super::history::validate_manifest(&changed).is_none(),
    );
    controls.get_mut("history-manifest-tamper").unwrap()["input"] = changed.clone();
    let finding = findings
        .iter()
        .find(|finding| finding["file"] == "deleted.txt")
        .unwrap();
    for field in ["commit", "blobOid", "blobDigest", "historyManifestDigest"] {
        let mut changed = finding.clone();
        changed[field] = json!("tampered");
        record::predicate(
            &mut controls,
            &format!("anchor-{field}-tamper"),
            !super::super::history::live_anchor(&changed, &proof),
        );
        controls.get_mut(&format!("anchor-{field}-tamper")).unwrap()["input"] = changed.clone();
    }
    let scratch = Scratch::create(Some(&parent)).unwrap();
    let provider = spec(&frozen_inventory);
    let run = Run {
        producer: &planted_producer,
        provider: &provider,
        inventory: &frozen_inventory,
        scratch,
        denied_receipts: RefCell::new(Vec::new()),
    };
    let retained = planted_producer.retained_secret_runs.lock().unwrap();
    let mut changed = retained[0].clone();
    changed.stdout.push(b' ');
    record::failure(
        &mut controls,
        "raw-digest-tamper",
        run.strict_gitleaks_report(&changed),
    );
    controls.get_mut("raw-digest-tamper").unwrap()["input"] = record::changed_run(&changed);
    let mut changed = retained[0].clone();
    changed.actual_receipt.complete = false;
    record::failure(
        &mut controls,
        "receipt-tamper",
        run.strict_gitleaks_report(&changed),
    );
    controls.get_mut("receipt-tamper").unwrap()["input"] = record::changed_run(&changed);
    let mut changed = retained[0].clone();
    changed.stdout = b"{".to_vec();
    changed.actual_receipt.stdout.as_mut().unwrap().digest = digest(&changed.stdout);
    changed.actual_receipt.stdout.as_mut().unwrap().bytes = changed.stdout.len();
    record::failure(
        &mut controls,
        "malformed-output",
        run.strict_gitleaks_report(&changed),
    );
    controls.get_mut("malformed-output").unwrap()["input"] = record::changed_run(&changed);
    drop(retained);
    let mut frozen_drift =
        FrozenHistory::capture(&clean, None, &inventory(&clean), &["README.md".into()]).unwrap();
    put(&clean, "README.md", "changed after freeze\n");
    record::failure(
        &mut controls,
        "current-bytes-drift",
        frozen_drift.revalidate(),
    );
    put(&clean, "README.md", "synthetic qualification fixture\n");
    frozen_drift.revalidate().unwrap();
    frozen_drift
        .manifest
        .current
        .insert("outside.txt".into(), digest(b"invented"));
    record::failure(
        &mut controls,
        "selected-pathset-drift",
        frozen_drift.revalidate(),
    );
    let child = planted.join("nongit-child");
    fs::create_dir(&child).unwrap();
    put(&child, "README.md", "child\n");
    record::failure(
        &mut controls,
        "nongit-child-parent-git",
        FrozenHistory::capture(&child, None, &inventory(&child), &["README.md".into()]),
    );
    record::incomplete(
        &mut controls,
        "nongit-provider",
        execute(&child, &producer(&child, &parent, &bin)),
    );
    let (shallow, _, _) = fixture(&parent, "shallow", false);
    let head = git(&shallow, &["rev-parse", "HEAD"]);
    fs::write(shallow.join(".git/shallow"), format!("{head}\n")).unwrap();
    record::failure(
        &mut controls,
        "shallow-repository",
        FrozenHistory::capture(&shallow, None, &inventory(&shallow), &["README.md".into()]),
    );
    record::incomplete(
        &mut controls,
        "shallow-provider",
        execute(&shallow, &producer(&shallow, &parent, &bin)),
    );
    let (missing, _, _) = fixture(&parent, "missing-object", false);
    let blob = git(&missing, &["rev-parse", "HEAD:README.md"]);
    fs::remove_file(
        missing
            .join(".git/objects")
            .join(&blob[..2])
            .join(&blob[2..]),
    )
    .unwrap();
    record::failure(
        &mut controls,
        "missing-object",
        FrozenHistory::capture(&missing, None, &inventory(&missing), &["README.md".into()]),
    );
    record::incomplete(
        &mut controls,
        "missing-object-provider",
        execute(&missing, &producer(&missing, &parent, &bin)),
    );
    let limited = producer(&planted, &parent, &bin).with_bounds(120_000, 16);
    record::incomplete(
        &mut controls,
        "truncated-output",
        execute(&planted, &limited),
    );
    record::emit(
        &parent,
        &bin,
        &expected,
        cases,
        controls,
        snapshot_record,
        signature_observation,
    );
}
