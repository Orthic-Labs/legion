//! Port of `tests/naming-contract.test.mjs`'s `checkCanonicalNames`
//! coverage (chunk w2_049). The `canonicalAuthority` /
//! `canonicalizeAuthorityRecord` / `migrateNamingState` /
//! `migrateMcpServers` / `inspectMcpNaming` /
//! `isLegionOwnedAssuranceBinding` assertions in that JS file are already
//! covered by `p6_inventory_artifacts_naming.rs` against the
//! `p6_inventory::naming` port and are not repeated here.

use std::fs;
use std::path::{Path, PathBuf};

use legion_runtime::wf_port::w2_049::check_canonical_names;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repo root")
}

const FIXTURE_FILES: &[&str] = &[
    "src/config/naming-registry.json",
    "src/config/naming-legacy-allowlist.json",
    "README.md",
    "package.json",
    "MANIFEST.package.json",
    ".claude-plugin/plugin.json",
    ".codex-plugin/plugin.json",
    "src/lib/roster/index.mjs",
    "engine/bins/legion/src/commands/doctor.rs",
    "src/lib/contracts/arcane/authority-binding-store.mjs",
];

/// Port of `namingFixture()`: builds a temp copy of the fixed set of real
/// repository files the naming checker's semantic/allowlist checks touch.
fn naming_fixture() -> PathBuf {
    let root = repo_root();
    let dir = std::env::temp_dir().join(format!(
        "legion-naming-w2_049-{}-{}-{}",
        std::process::id(),
        {
            static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        },
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    for rel in FIXTURE_FILES {
        let src = root.join(rel);
        let dst = dir.join(rel);
        fs::create_dir_all(dst.parent().unwrap()).unwrap();
        fs::copy(&src, &dst).unwrap_or_else(|e| panic!("copy {rel}: {e}"));
    }
    dir
}

fn cleanup(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn naming_checker_rejects_unclassified_active_filenames_nul_and_legacy_manifest() {
    let fixture = naming_fixture();

    fs::create_dir_all(fixture.join("src/lib/naming")).unwrap();
    fs::write(
        fixture.join("src/lib/naming/seer-runtime.mjs"),
        b"export const active = true;\n",
    )
    .unwrap();
    fs::write(
        fixture.join("active.mjs"),
        b"export const value = \"\0seer\";\n",
    )
    .unwrap();
    fs::write(
        fixture.join("neutral-nul.mjs"),
        b"export const value = \"\0neutral\";\n",
    )
    .unwrap();

    let doctor_path = fixture.join("engine/bins/legion/src/commands/doctor.rs");
    let mut doctor_src = fs::read_to_string(&doctor_path).unwrap();
    doctor_src.push_str("\n// seer\n");
    fs::write(&doctor_path, doctor_src).unwrap();

    let manifest_path = fixture.join("MANIFEST.package.json");
    let mut manifest: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
    manifest["allowlistedTopLevel"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!("packages/seer/"));
    fs::write(
        &manifest_path,
        format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
    )
    .unwrap();

    let report = check_canonical_names(&fixture).expect("check succeeds");
    assert_eq!(report.status, "fail");

    let has = |path: &str, reason_contains: &str| {
        report
            .unclassified
            .iter()
            .any(|i| i.path == path && i.reason.contains(reason_contains))
    };
    assert!(has(
        "src/lib/naming/seer-runtime.mjs",
        "unclassified legacy filename"
    ));
    assert!(report.unclassified.iter().any(|i| i.path == "active.mjs"));
    assert!(has(
        "neutral-nul.mjs",
        "active source cannot be decoded for naming scan"
    ));
    assert!(has(
        "engine/bins/legion/src/commands/doctor.rs",
        "occurrence count differs"
    ));
    assert!(has(
        "MANIFEST.package.json",
        "retains legacy assurance package"
    ));

    cleanup(&fixture);
}

#[test]
fn naming_checker_rejects_security_pack_prefix_and_occurrence_bypasses() {
    let fixture = naming_fixture();

    // The real security-pack sources were deleted when Legion's legacy JS
    // was retired; synthesize an equivalent pair of fixture files (and a
    // matching exact-path allowlist rule) so this test still exercises the
    // same behaviour: an exact-path allowlist entry does not extend to
    // sibling files under the same directory prefix.
    let allowed_path = fixture.join("src/security/packs/output-handling.mjs");
    fs::create_dir_all(allowed_path.parent().unwrap()).unwrap();
    fs::write(&allowed_path, "export const currentAuthority = 'forge';\n").unwrap();

    let allowlist_path = fixture.join("src/config/naming-legacy-allowlist.json");
    let mut allowlist: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&allowlist_path).unwrap()).unwrap();
    allowlist["rules"].as_array_mut().unwrap().push(serde_json::json!({
        "path": "src/security/packs/output-handling.mjs",
        "tokens": ["forge"],
        "occurrences": {"forge": 1},
        "class": "R0",
        "reason": "fixture: ordinary security verb",
    }));
    fs::write(
        &allowlist_path,
        format!("{}\n", serde_json::to_string_pretty(&allowlist).unwrap()),
    )
    .unwrap();

    // Push the allowed file's occurrence count past what the allowlist rule
    // declares.
    let mut allowed_src = fs::read_to_string(&allowed_path).unwrap();
    allowed_src.push_str("\nexport const currentAuthority = 'forge';\n");
    fs::write(&allowed_path, allowed_src).unwrap();

    let injected_path = fixture.join("src/security/packs/injected.mjs");
    fs::write(&injected_path, "export const currentAuthority = 'forge';\n").unwrap();

    let report = check_canonical_names(&fixture).expect("check succeeds");
    assert_eq!(report.status, "fail");

    let has = |path: &str, reason_contains: &str| {
        report
            .unclassified
            .iter()
            .any(|i| i.path == path && i.reason.contains(reason_contains))
    };
    assert!(has(
        "src/security/packs/output-handling.mjs",
        "occurrence count differs"
    ));
    assert!(has(
        "src/security/packs/injected.mjs",
        "unclassified legacy token"
    ));

    cleanup(&fixture);
}

#[test]
fn naming_checker_rejects_dead_exact_path_and_unused_token_exemptions() {
    let fixture = naming_fixture();

    let allowlist_path = fixture.join("src/config/naming-legacy-allowlist.json");
    let mut allowlist: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&allowlist_path).unwrap()).unwrap();
    let rules = allowlist["rules"].as_array_mut().unwrap();
    rules.push(serde_json::json!({
        "path": "missing/legacy.md",
        "tokens": ["forge"],
        "class": "R5",
        "reason": "dead fixture",
    }));
    rules.push(serde_json::json!({
        "path": "README.md",
        "tokens": ["seer"],
        "class": "R5",
        "reason": "unused fixture",
    }));
    fs::write(
        &allowlist_path,
        format!("{}\n", serde_json::to_string_pretty(&allowlist).unwrap()),
    )
    .unwrap();

    let report = check_canonical_names(&fixture).expect("check succeeds");
    assert_eq!(report.status, "fail");

    assert!(report
        .unclassified
        .iter()
        .any(|i| i.path == "missing/legacy.md" && i.reason.contains("matches no files")));
    assert!(report.unclassified.iter().any(|i| i.path == "README.md"
        && i.token.as_deref() == Some("seer")
        && i.reason.contains("unused")));

    cleanup(&fixture);
}

#[test]
fn naming_checker_ignores_immutable_foundation_evidence_artifacts() {
    let fixture = naming_fixture();

    let report_path = fixture.join("docs/foundation/comparison.md");
    fs::create_dir_all(report_path.parent().unwrap()).unwrap();
    fs::write(
        &report_path,
        "Donor evidence may use historical tokens such as sentinel or seer.\n",
    )
    .unwrap();

    let report = check_canonical_names(&fixture).expect("check succeeds");
    assert_eq!(
        report
            .unclassified
            .iter()
            .filter(|i| i.path.starts_with("docs/foundation/"))
            .count(),
        0
    );

    cleanup(&fixture);
}

#[test]
fn repository_has_no_unclassified_legacy_naming() {
    let report = check_canonical_names(&repo_root()).expect("check succeeds");
    assert_eq!(report.unclassified, Vec::new());
}
