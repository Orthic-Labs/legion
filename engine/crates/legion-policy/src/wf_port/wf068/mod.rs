//! wf068 — port of `src/lib/contracts/arcane/{runtime-schema,state-paths,validate}.mjs`.
//!
//! Owned exclusively by this porting chunk. See the wf068 report
//! (`docs/pending/` loss ledger / scratchpad) for method notes, the
//! `Cargo.toml` patch this module needs from the integrator (`serde_json`
//! moved from `[dev-dependencies]` to `[dependencies]`), and the
//! already-native-coverage finding for `state-paths.mjs`.
//!
//! JS remains source of truth until CI parity is proven; nothing here is
//! wired into `legion-policy`'s public surface yet (the integrator adds
//! `pub mod wf068;` to `wf_port/mod.rs`).

pub mod errors;
pub mod runtime_schema;
pub mod schema;
pub mod state_paths;
pub mod validate;

pub use errors::ArcaneError;
pub use runtime_schema::RuntimeSchemaSet;
pub use schema::validate_schema;
pub use state_paths::{key_hex, state_file, state_paths, state_root, StatePaths};
pub use validate::{assert_valid, load_schema, validate_against, validate_against_def, ValidationOutcome};
