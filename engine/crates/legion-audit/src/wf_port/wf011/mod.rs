//! Port of `src/lib/providers/sdk/{artifacts,contracts,dag,index,result}.mjs`
//! (chunk wf011).
//!
//! These five files together form the provider-SDK v2 authority/validation
//! surface: artifact-ownership validation (`artifacts.mjs`), the v2 provider
//! record schema validator (`contracts.mjs`), the dependency DAG plus the
//! role/output authority table (`dag.mjs`), the SDK barrel re-export
//! (`index.mjs`), and the terminal-status result normalizer (`result.mjs`).
//!
//! Provider and result records are represented as `serde_json::Value`
//! objects rather than fixed Rust structs. The JS source treats provider
//! records as loosely-shaped plain objects (arbitrary/optional fields,
//! `??`/`!==` guards everywhere, no schema enforced before `contracts.mjs`
//! runs), and the existing Rust `legion-provider-sdk` crate models a
//! materially different, stricter `ProviderDefinition` shape (no
//! `produces`/`consumes` artifact tracking, no `role`/`phase`/`runner.kind`
//! v2 schema, no `ROLE_OUTPUT_AUTHORITY` table) — so there is no native
//! coverage of this exact behaviour to verify against. `serde_json::Value`
//! preserves object-key insertion order (workspace `serde_json` has the
//! `preserve_order` feature on), which `result::digest` depends on to match
//! JS `JSON.stringify` byte-for-byte.
//!
//! Every public error mirrors the JS `throw new TypeError(...)` /
//! `throw new Error(...)` message text exactly, so callers (and tests) can
//! match on the message the way the JS test suite matches on a regex.

pub mod artifacts;
pub mod contracts;
pub mod dag;
pub mod result;

use std::fmt;

/// Mirrors the untyped `Error`/`TypeError` the JS source throws. The JS
/// source never distinguishes `Error` from `TypeError` in a way callers
/// observe (both are caught the same way, matched only on `.message`), so
/// one error type with the exact message text is faithful.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct SdkError(pub String);

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl SdkError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

// index.mjs barrel re-export. The real `index.mjs` also re-exports
// `stableId`/`pathDenominator`/`validateProviderRecord`/`validateProviderResult`
// from `./testkit.mjs` and `PROVIDER_PHASES`/`PROVIDER_ROLES`/`PROVIDER_STATUS`/
// `assertEnum`/`canonicalJson`/`canonicalize`/`sha256` from
// `../../../registry/provider-contracts.mjs` and
// `../../../registry/provider-registry.mjs`. Those source files are outside
// this chunk (wf011 owns only artifacts.mjs, contracts.mjs, dag.mjs,
// index.mjs, result.mjs), so this barrel re-exports only the items this
// chunk actually ported.
pub use artifacts::validate_artifact_authority;
pub use contracts::{validate_provider_output_authority, validate_provider_v2};
pub use dag::{
    topological_providers, validate_provider_dag, validate_role_output, ROLE_OUTPUT_AUTHORITY,
};
pub use result::normalize_provider_result;
