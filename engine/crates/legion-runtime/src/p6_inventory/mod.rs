//! P6 inventory/platform port (packet P6-inventory-platform).
//!
//! This module ports the pure, self-contained pieces of
//! `src/lib/artifacts/**` and `src/lib/naming/{registry,migrations}.mjs`
//! from the legacy JS tree to Rust. It is intentionally narrow: the wider
//! `src/lib/inventory/**`, `src/lib/platform/**`, `src/lib/distribution/**`,
//! `src/lib/skills/**`, `src/lib/naming/check.mjs`,
//! `src/lib/tasklist-validator/**`, and `src/lib/dispatch-validator/**`
//! trees are NOT covered here (see the P6 packet report) and remain to be
//! ported in follow-up work.

pub mod artifacts;
pub mod naming;

pub use artifacts::{digest_bytes, safe_artifact_path, ArtifactPathError};
pub use naming::{
    authority_aliases, canonical_authority, canonical_authority_ids, canonical_product,
    canonical_serialized_authority, canonicalize_authority_record, equivalent_mcp_binding,
    inspect_mcp_naming, is_legion_owned_assurance_binding, load_naming_registry,
    migrate_mcp_servers, migrate_naming_state, naming_migration_status, McpNamingLegacyEntry,
    McpNamingStatus, NamedMigration, NamingMigrationStatus, NamingRegistry, NamingRegistryError,
    MIGRATIONS, NAMING_SCHEMA_VERSION,
};
