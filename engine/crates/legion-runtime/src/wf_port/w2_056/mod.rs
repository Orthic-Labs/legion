//! Faithful port of `src/lib/skills/{dependency-closure,loader,resolver,
//! route-resources,verify}.mjs` (chunk w2_056).
//!
//! These five modules were explicitly left out of the `l5_skills` pass (see
//! that module's doc comment) as "filesystem- and registry-dependent". This
//! chunk ports them in full, reusing the existing pure Rust ports for their
//! dependencies: `l5_skills::contracts::validate_skill_bundle`,
//! `l5_skills::skill_frontmatter::parse_skill_frontmatter`,
//! `l5_skills::profile::project_skill_text`, `l5_skills::uri::parse_skill_uri`,
//! `p6_inventory::artifacts::digest_bytes`, and
//! `p7_host::capabilities::command_capability_map`.
//!
//! Every function here performs the same filesystem I/O as its JS original
//! (synchronously — the JS `loader.mjs` uses `fs/promises` only because it
//! runs inside an async host; there is no concurrency to preserve).

pub mod dependency_closure;
pub mod loader;
pub mod resolver;
pub mod route_resources;
pub mod verify;

pub use dependency_closure::{
    classify_resource, parse_dependency_declaration, scan_host_command_references,
    scan_packaged_text, verify_capability_aliases, verify_dependency_closure,
    verify_manifest_consumers, verify_manifest_coverage, ClosureFinding, ClosureResult,
    ClosureSummary, DependencyClass, ResourceClassification, DEPENDENCY_CLASSES,
    DEPENDENCY_DECLARATION,
};
pub use loader::{load_skill, LoadedSkill, LoadedSkillCapabilities, LoaderError};
pub use resolver::{
    resolve_skill_invocation, validate_capability_selection, InvocationResolution,
    SelectionInvalid, SelectionResolution, SelectionResolved, SelectionSource,
};
pub use route_resources::{
    route_resource_table, scoped_host_capabilities, scoped_requirement_details,
    ScopedRequirementDetail, ROUTE_RESOURCES,
};
pub use verify::{verify_skill_bytes, verify_skill_catalog, VerifyFinding, VerifyResult};

/// Minimal self-contained temp-dir test helper (the crate has no `tempfile`
/// dependency): creates a unique directory under `std::env::temp_dir()` and
/// removes it (best effort) on drop. Shared by every test module in this
/// chunk.
#[cfg(test)]
pub(crate) mod test_support {
    use std::path::{Path, PathBuf};

    pub struct TempDir(PathBuf);

    impl TempDir {
        pub fn new() -> Self {
            let mut path = std::env::temp_dir();
            let unique = format!(
                "legion-wf-w2-056-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            path.push(unique);
            std::fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }

        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
