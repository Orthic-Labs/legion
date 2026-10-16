//! Exercise actual benchmark Git objects through frozen changed-file inventory,
//! shipped provider selection & canonical candidate projection.
use legion_audit::{
    native_providers::reasoning::security_adjudication::scanner_candidates, AuditProvider,
    FilesystemInventorySource, InventorySource, NativeProviderRegistry, ProviderExecutor,
    ProviderKind,
};
use legion_contracts::ProviderSpec;
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn data_provider() -> AuditProvider {
    let registry: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../src/registry/providers.json"
    )))
    .unwrap();
    let item = registry["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "legacy.data.internal-suite")
        .unwrap();
    let spec: ProviderSpec = serde_json::from_value(item.clone()).unwrap();
    AuditProvider {
        id: spec.id.to_string(),
        version: spec.provider_version,
        role: spec.role,
        phase: spec.phase,
        lens_ids: spec.lens_ids,
        dependencies: spec.depends_on.iter().map(ToString::to_string).collect(),
        kind: ProviderKind::RustAlgorithm,
        configuration: BTreeMap::from([("selector".into(), spec.selector)]),
        bounds: BTreeMap::new(),
        clean_claim: spec.clean_claim,
        benchmark_status: "unproven".into(),
        benchmark_required_for_clean_claim: false,
        qualification_digest: None,
        required: spec.selectable,
    }
}

#[test]
fn benchmark_redis_git_objects_keep_true_locations_and_clean_controls_through_registry() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root = std::env::temp_dir().join(format!(
        "legion-redis-bundle-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&root).unwrap();
    let bundle = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../evals/audit-bench/fixtures/audit-behavior.bundle")
        .canonicalize()
        .unwrap();
    fs::copy(&bundle, root.join("audit-behavior.bundle")).unwrap();
    let output = Command::new("git")
        .current_dir(&root)
        .args(["clone", "--quiet", "--no-checkout"])
        .arg("./audit-behavior.bundle")
        .arg("repo")
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    let repo = root.join("repo");
    let cases: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../evals/audit-bench/fixtures/audit-behavior.cases.json"
    )))
    .unwrap();
    let provider = data_provider();
    let mut inspected = 0;
    for case in cases["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        if !id.starts_with("audit-redis-") && id != "audit-map-set-clean" {
            continue;
        }
        inspected += 1;
        git(&repo, &["checkout", "--quiet", "--detach", id]);
        let changed = git(&repo, &["diff", "--name-only", &format!("base..{id}")])
            .lines()
            .map(ToOwned::to_owned)
            .collect::<BTreeSet<_>>();
        let inventory = FilesystemInventorySource::new(&repo)
            .unwrap()
            .with_only_paths(Some(changed))
            .inventory(id)
            .unwrap();
        let result = NativeProviderRegistry::new(&repo)
            .execute(&provider, &inventory)
            .unwrap();
        assert!(result.complete, "{id}: {:?}", result.coverage_gaps);
        assert!(result.findings.is_empty(), "{id}: candidate-only provider");
        let candidates = scanner_candidates(&repo, &provider.id, &result);
        let expected = case["expected"].as_array().unwrap();
        assert_eq!(candidates.len(), expected.len(), "{id}: {candidates:?}");
        for location in expected {
            assert!(
                candidates.iter().any(|candidate| {
                    candidate.rule == "data.redis-unbounded-value"
                        && candidate.path.as_deref() == location["path"].as_str()
                        && candidate.line == location["lineRange"][0].as_u64()
                        && candidate.location_status == "known"
                        && candidate.domain == "data"
                }),
                "{id}: missing {location}, actual {candidates:?}"
            );
        }
        let ids = candidates
            .iter()
            .map(|candidate| &candidate.finding_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), candidates.len(), "{id}: preserve both instances");
    }
    assert_eq!(inspected, 4);
    fs::remove_dir_all(root).unwrap();
}
