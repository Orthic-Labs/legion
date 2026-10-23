use legion_audit::dependency_inventory::{
    inventory, AdvisoryDatabase, DependencyPackage, DependencyRole, Ecosystem, FindingKind,
    Maintenance, ManifestInput, RegistryMetadata, SourceStatus,
};
use legion_audit::native_providers::security::dependency_osv::advisory_database_from_scan;
use serde_json::Value;

const CARGO_LOCK: &str = include_str!("fixtures/dependency-health/Cargo.lock");
const NPM_LOCK: &str = include_str!("fixtures/dependency-health/package-lock.json");
const SWIFT_RESOLVED: &str = include_str!("fixtures/dependency-health/Package.resolved");
const UV_LOCK: &str = include_str!("fixtures/dependency-health/uv.lock");
const OSV_SCAN: &str = include_str!("fixtures/dependency-health/osv-scan.json");

const DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn input(path: &str, raw: &str, target: &str) -> ManifestInput {
    ManifestInput {
        path: path.to_owned(),
        raw: raw.to_owned(),
        target: target.to_owned(),
    }
}

fn osv_database(status: SourceStatus) -> AdvisoryDatabase {
    let raw: Value = serde_json::from_str(OSV_SCAN).expect("osv fixture parses");
    let mut database = advisory_database_from_scan(&raw, "osv-fixture-db", DIGEST);
    database.status = status;
    database
}

fn named<'a>(packages: &'a [DependencyPackage], name: &str) -> &'a DependencyPackage {
    packages
        .iter()
        .find(|package| package.name == name)
        .unwrap_or_else(|| panic!("package {name} present"))
}

#[test]
fn cargo_vulnerability_is_direct_and_git_source_stays_a_gap() {
    let database = osv_database(SourceStatus::Current);
    let inventory = inventory(&[input("Cargo.lock", CARGO_LOCK, "")], Some(&database), &[]);

    let smallvec = named(&inventory.packages, "smallvec");
    assert_eq!(smallvec.registry, "crates.io");
    assert_eq!(smallvec.direct, Some(true));
    assert!(inventory.findings.iter().any(|finding| {
        finding.kind == FindingKind::Vulnerable
            && finding.advisory.as_deref() == Some("RUSTSEC-2019-0009")
            && finding.package == smallvec.identity
            && finding.fixed_versions == ["0.6.10"]
            && finding.reachability == "unknown"
    }));

    let serde = named(&inventory.packages, "serde");
    assert_eq!(serde.direct, Some(false));

    let gitdep = named(&inventory.packages, "gitdep");
    assert!(gitdep.registry.starts_with("git:"));
    assert_eq!(
        gitdep.revision.as_deref(),
        Some("0123456789abcdef0123456789abcdef01234567")
    );
    assert!(inventory.gaps.iter().any(|gap| {
        gap.kind == "advisory-coverage-unproven" && gap.subject.as_deref() == Some("git-source")
    }));
    assert_eq!(inventory.freshness.advisory, SourceStatus::Current);
    assert!(!inventory.complete);
}

#[test]
fn stale_advisory_database_never_yields_a_complete_inventory() {
    let database = osv_database(SourceStatus::Stale);
    let inventory = inventory(&[input("Cargo.lock", CARGO_LOCK, "")], Some(&database), &[]);

    assert!(inventory
        .gaps
        .iter()
        .any(|gap| gap.kind == "advisory-database-stale"));
    assert_eq!(inventory.freshness.advisory, SourceStatus::Stale);
    assert!(!inventory.complete);
}

#[test]
fn absent_advisory_database_is_an_explicit_gap_without_findings() {
    let inventory = inventory(&[input("Cargo.lock", CARGO_LOCK, "")], None, &[]);

    assert!(inventory
        .gaps
        .iter()
        .any(|gap| gap.kind == "advisory-database-absent"));
    assert!(inventory
        .findings
        .iter()
        .all(|finding| finding.kind != FindingKind::Vulnerable));
    assert_eq!(inventory.freshness.advisory, SourceStatus::Absent);
    assert!(!inventory.complete);
}

#[test]
fn unsupported_lock_format_is_reported_not_an_empty_success() {
    let inventory = inventory(&[input("uv.lock", UV_LOCK, "")], None, &[]);

    assert!(inventory.packages.is_empty());
    assert_eq!(inventory.unsupported.len(), 1);
    assert_eq!(inventory.unsupported[0].path, "uv.lock");
    assert_eq!(inventory.unsupported[0].reason, "lock-format-unsupported");
    assert!(!inventory.complete);
}

#[test]
fn npm_roles_and_swift_pins_are_scoped_and_explicitly_uncovered() {
    let inventory = inventory(
        &[
            input("package-lock.json", NPM_LOCK, "web"),
            input("Package.resolved", SWIFT_RESOLVED, "ios"),
        ],
        Some(&osv_database(SourceStatus::Current)),
        &[],
    );

    let left_pad = named(&inventory.packages, "left-pad");
    assert_eq!(left_pad.ecosystem, Ecosystem::Npm);
    assert_eq!(left_pad.registry, "registry.npmjs.org");
    assert_eq!(left_pad.scope, "web");
    assert_eq!(left_pad.direct, Some(true));
    assert_eq!(left_pad.role, DependencyRole::Runtime);

    let typescript = named(&inventory.packages, "typescript");
    assert_eq!(typescript.role, DependencyRole::Development);
    assert_eq!(typescript.direct, Some(true));

    let swift = named(&inventory.packages, "swift-argument-parser");
    assert_eq!(swift.ecosystem, Ecosystem::Swift);
    assert_eq!(swift.scope, "ios");
    assert!(swift.registry.starts_with("git:"));
    assert!(inventory.gaps.iter().any(|gap| {
        gap.kind == "advisory-coverage-unproven"
            && gap.subject.as_deref() == Some("ecosystem-unsupported")
    }));
    assert!(!inventory.complete);
}

#[test]
fn same_lock_under_two_targets_keeps_scopes_separate() {
    let database = osv_database(SourceStatus::Current);
    let inventory = inventory(
        &[
            input("Cargo.lock", CARGO_LOCK, "linux"),
            input("Cargo.lock", CARGO_LOCK, "macos"),
        ],
        Some(&database),
        &[],
    );

    let mut scopes: Vec<&str> = inventory
        .findings
        .iter()
        .filter(|finding| finding.kind == FindingKind::Vulnerable)
        .map(|finding| finding.scope.as_str())
        .collect();
    scopes.sort_unstable();
    assert_eq!(scopes, ["linux", "macos"]);
    assert_eq!(inventory.manifests.len(), 2);
}

#[test]
fn private_registry_with_a_public_name_is_not_matched_and_stays_a_gap() {
    let private_lock = "version = 3\n\n[[package]]\nname = \"smallvec\"\nversion = \"0.6.9\"\nsource = \"registry+https://registry.example.test/index\"\n";
    let inventory = inventory(
        &[input("Cargo.lock", private_lock, "")],
        Some(&osv_database(SourceStatus::Current)),
        &[],
    );

    assert!(inventory
        .findings
        .iter()
        .all(|finding| finding.kind != FindingKind::Vulnerable));
    assert!(inventory.gaps.iter().any(|gap| {
        gap.kind == "advisory-coverage-unproven"
            && gap.subject.as_deref() == Some("registry-not-advisory-covered")
    }));
    assert!(!inventory.complete);
}

#[test]
fn registry_metadata_counts_only_when_current() {
    let metadata = vec![
        RegistryMetadata {
            ecosystem: Ecosystem::Cargo,
            registry: "crates.io".to_owned(),
            name: "smallvec".to_owned(),
            latest_version: Some("1.13.2".to_owned()),
            deprecated: Some(false),
            maintenance: Maintenance::Active,
            status: SourceStatus::Current,
        },
        RegistryMetadata {
            ecosystem: Ecosystem::Cargo,
            registry: "crates.io".to_owned(),
            name: "serde".to_owned(),
            latest_version: Some("1.0.300".to_owned()),
            deprecated: None,
            maintenance: Maintenance::Unknown,
            status: SourceStatus::Stale,
        },
    ];
    let inventory = inventory(
        &[input("Cargo.lock", CARGO_LOCK, "")],
        Some(&osv_database(SourceStatus::Current)),
        &metadata,
    );

    assert!(inventory.findings.iter().any(|finding| {
        finding.kind == FindingKind::LatestDiffers && finding.detail.as_deref() == Some("1.13.2")
    }));
    assert!(inventory.gaps.iter().any(|gap| {
        gap.kind == "registry-metadata-stale" && gap.subject.as_deref() == Some("serde")
    }));
    assert!(inventory
        .findings
        .iter()
        .all(|finding| finding.detail.as_deref() != Some("1.0.300")));
    assert_eq!(inventory.freshness.registry, SourceStatus::Stale);
    assert!(!inventory.complete);
}

#[test]
fn empty_manifest_denominator_is_a_gap() {
    let inventory = inventory(&[], None, &[]);

    assert!(inventory
        .gaps
        .iter()
        .any(|gap| gap.kind == "dependency-manifest-denominator-zero"));
    assert!(!inventory.complete);
}
