//! Packet P7-runtime-host: JS→Rust port of src/lib/{host,capabilities,policy,
//! pr,goalroute,metrics,minimize,lenses,coverage,content,design}/**, and
//! src/lib/{host-projection,open-for-review,auto-jury,design-gate}.mjs.
//!
//! See /private/tmp/claude-501/-Volumes-D-claude-heardright/
//! 27c99660-46fe-472a-bd29-43596bb3bc77/scratchpad/loss/full-P7.md for the
//! per-file port status table. `goalroute/` and `minimize/` under src/lib
//! contain no .mjs files (nothing to port). This module currently covers:
//! capabilities/, content/, design/, policy/, pr/, metrics/, lenses/ (routing
//! lens-record validation only), coverage/ (evidence + registry validation),
//! host/{capabilities,fs,process,fixed-host,index,sandbox-policy,surfaces}.mjs,
//! host/adapters/*, host/arcane/stop-disposition.mjs, and host-projection.mjs
//! + open-for-review.mjs. Not yet ported (see report for why): the remaining
//! host/arcane/* files (decision-envelope, hook-adapter-core, host-event,
//! host-event-ledger, host-runtime-output, legacy-bridge, continuity,
//! session-binding, source-revision, codex-escalation, discipline-controls,
//! denial-circuit) and the standalone auto-jury.mjs / design-gate.mjs.

pub mod capabilities;
pub mod content;
pub mod coverage;
pub mod design;
pub mod host_adapters;
pub mod host_core;
pub mod host_projection;
pub mod lenses;
pub mod metrics;
pub mod open_for_review;
pub mod policy;
pub mod pr;

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(digest))
}

pub(crate) fn sha256_prefixed(namespace: &str, value: &serde_json::Value) -> String {
    let body = serde_json::to_string(value).unwrap_or_default();
    let mut bytes = Vec::with_capacity(namespace.len() + 1 + body.len());
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(body.as_bytes());
    sha256_hex(&bytes)
}
