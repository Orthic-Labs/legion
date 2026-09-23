//! Port of `src/providers/security/model-extractors/{identity,mobile,native-workspace}.mjs`
//! and `src/providers/security/packs/{abuse-observability,abuse-resilience}.mjs`
//! (chunk wf055, area `src/providers/security`, target crate `legion-audit`).
//!
//! None of these five files reference Membrane or Blueprint services
//! directly: the mobile extractor reads `projection.auditFacts.packageManifests`
//! (a repository-blueprint *projection* field name, not a network call),
//! and none of the five source files import a Membrane/Blueprint client.
//! Nothing was dropped from this chunk on that basis.
//!
//! `common.rs` here ports `model-extractors/common.mjs`'s entity/relation/
//! fact/control-entity builders, and `abuse_observability.rs` ports the
//! minimal slice of `packs/pattern-pack.mjs` that `abuse-observability.mjs`
//! needs — both are shared JS infrastructure outside this chunk's owned
//! file list, reproduced locally (not as a reusable generic) since this
//! module owns only the five listed files' behaviour, not the shared
//! helper modules themselves.

pub mod abuse_observability;
pub mod abuse_resilience;
pub mod common;
pub mod identity;
pub mod mobile;
pub mod native_workspace;
