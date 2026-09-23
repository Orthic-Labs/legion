//! Tests for the P6 packet port: `legion_runtime::p6_inventory::{artifacts, naming}`.
//!
//! Mirrors the behaviour exercised (directly or transitively) by the
//! legacy JS in `src/lib/artifacts/{digests,paths}.mjs` and
//! `src/lib/naming/{registry,migrations}.mjs`.

use std::path::Path;

use legion_runtime::p6_inventory::artifacts::{digest_bytes, safe_artifact_path, ArtifactPathError};
use legion_runtime::p6_inventory::naming::{
    authority_aliases, canonical_authority, canonical_authority_ids, canonical_product,
    canonicalize_authority_record, equivalent_mcp_binding, inspect_mcp_naming,
    is_legion_owned_assurance_binding, migrate_mcp_servers, migrate_naming_state,
    naming_migration_status, NamingRegistry, NAMING_SCHEMA_VERSION,
};
use serde_json::json;

fn fixture_registry() -> NamingRegistry {
    NamingRegistry(json!({
        "schemaVersion": 1,
        "product": {
            "id": "legion",
            "displayName": "Legion",
            "legacyIds": [
                { "id": "nemesis", "status": "migration_only", "read": true, "write": false }
            ]
        },
        "authorities": {
            "sage": { "displayName": "Sage", "aliases": [] },
            "alchemist": {
                "displayName": "Alchemist",
                "aliases": [
                    { "id": "forge" },
                    { "id": "sorcerer" }
                ]
            },
            "oracle": {
                "displayName": "Oracle",
                "aliases": [
                    { "id": "seer" }
                ]
            },
            "arcane": {
                "displayName": "Arcane",
                "aliases": [
                    { "id": "sentinel" }
                ]
            }
        },
        "actors": {
            "legion": { "displayName": "Legion" },
            "kernel": { "displayName": "Kernel" }
        },
        "seats": {
            "covenant": { "displayName": "Covenant", "authority": false }
        }
    }))
}

// ---- artifacts::digest_bytes ----

#[test]
fn digest_bytes_matches_known_sha256() {
    // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(
        digest_bytes(b""),
        "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    // sha256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    assert_eq!(
        digest_bytes(b"abc"),
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

// ---- artifacts::safe_artifact_path ----

#[test]
fn safe_artifact_path_allows_nested_relative_child() {
    let root = Path::new("/runs/current");
    let resolved = safe_artifact_path(root, "logs/output.txt").unwrap();
    assert_eq!(resolved, Path::new("/runs/current/logs/output.txt"));
}

#[test]
fn safe_artifact_path_rejects_absolute_child() {
    let root = Path::new("/runs/current");
    assert_eq!(
        safe_artifact_path(root, "/etc/passwd").unwrap_err(),
        ArtifactPathError::AbsoluteChild
    );
}

#[test]
fn safe_artifact_path_rejects_windows_drive_absolute_child() {
    let root = Path::new("/runs/current");
    assert_eq!(
        safe_artifact_path(root, "C:\\secrets.txt").unwrap_err(),
        ArtifactPathError::AbsoluteChild
    );
}

#[test]
fn safe_artifact_path_rejects_traversal_segment() {
    let root = Path::new("/runs/current");
    assert_eq!(
        safe_artifact_path(root, "../outside.txt").unwrap_err(),
        ArtifactPathError::Traversal
    );
    assert_eq!(
        safe_artifact_path(root, "nested/../../outside.txt").unwrap_err(),
        ArtifactPathError::Traversal
    );
}

#[test]
fn safe_artifact_path_rejects_empty_child() {
    let root = Path::new("/runs/current");
    assert_eq!(
        safe_artifact_path(root, "").unwrap_err(),
        ArtifactPathError::AbsoluteChild
    );
}

// ---- naming::registry ----

#[test]
fn authority_aliases_maps_legacy_ids_to_canonical() {
    let registry = fixture_registry();
    let aliases = authority_aliases(&registry);
    assert_eq!(aliases.get("forge").map(String::as_str), Some("alchemist"));
    assert_eq!(aliases.get("sorcerer").map(String::as_str), Some("alchemist"));
    assert_eq!(aliases.get("seer").map(String::as_str), Some("oracle"));
    assert_eq!(aliases.get("sentinel").map(String::as_str), Some("arcane"));
}

#[test]
fn canonical_authority_normalizes_and_resolves_aliases() {
    let registry = fixture_registry();
    assert_eq!(canonical_authority("Seer", &registry), "oracle");
    assert_eq!(canonical_authority("  SORCERER ", &registry), "alchemist");
    assert_eq!(canonical_authority("legion_arcane", &registry), "legion-arcane");
    assert_eq!(canonical_authority("oracle", &registry), "oracle");
}

#[test]
fn canonical_product_resolves_legacy_id() {
    let registry = fixture_registry();
    assert_eq!(canonical_product("nemesis", &registry), "legion");
    assert_eq!(canonical_product("legion", &registry), "legion");
    assert_eq!(canonical_product("unknown", &registry), "unknown");
}

#[test]
fn canonical_authority_ids_are_sorted() {
    let registry = fixture_registry();
    assert_eq!(
        canonical_authority_ids(&registry),
        vec!["alchemist", "arcane", "oracle", "sage"]
    );
}

#[test]
fn canonicalize_authority_record_rewrites_known_fields_recursively() {
    let registry = fixture_registry();
    let record = json!({
        "authority": "seer",
        "authoritiesInvolved": ["forge", "sentinel"],
        "nested": { "role": "sorcerer" },
        "list": [{ "actor_role": "seer" }],
        "unrelatedField": "seer",
    });
    let out = canonicalize_authority_record(&record, &registry);
    assert_eq!(out["authority"], json!("oracle"));
    assert_eq!(out["authoritiesInvolved"], json!(["alchemist", "arcane"]));
    assert_eq!(out["nested"]["role"], json!("alchemist"));
    assert_eq!(out["list"][0]["actor_role"], json!("oracle"));
    // Non-authority fields pass through unchanged.
    assert_eq!(out["unrelatedField"], json!("seer"));
}

// ---- naming::migrations ----

#[test]
fn equivalent_mcp_binding_ignores_key_order() {
    let left = json!({"command": "python3", "args": ["-m", "x"]});
    let right = json!({"args": ["-m", "x"], "command": "python3"});
    assert!(equivalent_mcp_binding(&left, &right));
}

#[test]
fn is_legion_owned_assurance_binding_matches_module_flag() {
    let owned = json!({"command": "python3", "args": ["-m", "legion_kernel.adapters.mcp_server"]});
    assert!(is_legion_owned_assurance_binding(&owned));

    let wrong_module = json!({"command": "python3", "args": ["-m", "other.module"]});
    assert!(!is_legion_owned_assurance_binding(&wrong_module));

    let wrong_command = json!({"command": "node", "args": ["-m", "legion_kernel.adapters.mcp_server"]});
    assert!(!is_legion_owned_assurance_binding(&wrong_command));
}

#[test]
fn migrate_mcp_servers_renames_owned_legacy_seer_entry_to_oracle() {
    let registry = fixture_registry();
    let input = json!({
        "mcp_servers": {
            "seer": {"command": "python3", "args": ["-m", "legion_kernel.adapters.mcp_server"]}
        }
    });
    let migrated = migrate_mcp_servers(&input, &registry);
    let servers = migrated.get("mcp_servers").unwrap();
    assert!(servers.get("oracle").is_some());
    assert!(servers.get("seer").is_none());
}

#[test]
fn migrate_mcp_servers_drops_legacy_when_equivalent_oracle_already_present() {
    let registry = fixture_registry();
    let binding = json!({"command": "python3", "args": ["-m", "legion_kernel.adapters.mcp_server"]});
    let input = json!({
        "mcp_servers": {
            "seer": binding.clone(),
            "oracle": binding,
        }
    });
    let migrated = migrate_mcp_servers(&input, &registry);
    let servers = migrated.get("mcp_servers").unwrap();
    assert!(servers.get("oracle").is_some());
    assert!(servers.get("seer").is_none());
}

#[test]
fn migrate_mcp_servers_leaves_non_owned_legacy_entry_untouched() {
    let registry = fixture_registry();
    let input = json!({
        "mcp_servers": {
            "seer": {"command": "node", "args": ["server.js"]}
        }
    });
    let migrated = migrate_mcp_servers(&input, &registry);
    let servers = migrated.get("mcp_servers").unwrap();
    assert!(servers.get("seer").is_some());
    assert!(servers.get("oracle").is_none());
}

#[test]
fn inspect_mcp_naming_reports_absent_legacy_present_and_canonical() {
    let registry = fixture_registry();

    assert_eq!(inspect_mcp_naming(&json!({}), &registry).status, "absent");

    let legacy = json!({"mcp_servers": {"seer": {"command": "node"}}});
    let status = inspect_mcp_naming(&legacy, &registry);
    assert_eq!(status.status, "legacy-present");
    assert_eq!(status.legacy.len(), 1);
    assert_eq!(status.legacy[0].id, "seer");
    assert!(!status.legacy[0].owned);

    let canonical = json!({"mcp_servers": {"oracle": {"command": "node"}}});
    assert_eq!(inspect_mcp_naming(&canonical, &registry).status, "canonical");
}

#[test]
fn migrate_naming_state_is_idempotent_and_records_applied_migrations() {
    let registry = fixture_registry();
    let input = json!({"product": "nemesis"});
    let migrated = migrate_naming_state(&input, &registry);
    assert_eq!(migrated["product"], json!("legion"));
    assert_eq!(
        migrated["namingMigration"]["schemaVersion"],
        json!(NAMING_SCHEMA_VERSION)
    );
    let applied = migrated["namingMigration"]["applied"].as_array().unwrap();
    assert_eq!(applied.len(), 3);

    let twice = migrate_naming_state(&migrated, &registry);
    assert_eq!(migrated, twice);
}

#[test]
fn naming_migration_status_reports_canonical_and_current_flags() {
    let registry = fixture_registry();
    let input = json!({"product": "legion"});
    let status = naming_migration_status(&input, &registry);
    assert_eq!(status.schema_version, NAMING_SCHEMA_VERSION);
    assert!(!status.current); // input has no namingMigration marker yet
    assert!(status.canonical);
    assert_eq!(status.applied.len(), 3);
}
