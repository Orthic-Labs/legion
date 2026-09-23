//! Chunk wf060: Rust port of five `src/providers/security/packs/*.mjs`
//! lexical security detectors — `high-consequence.mjs`,
//! `http-protocol-cache.mjs`, `ics-ot.mjs`, `injection.mjs`,
//! `insecure-defaults.mjs`. See `common` for the shared `Context` /
//! `Observation` model and the chunk's scope note (only each pack's
//! `analyze()` is ported; `variantStrategies` coverage-report plumbing is
//! out of scope).
//!
//! Integration note (owned by the integrator, not this module): the parent
//! crate needs `pub mod wf_port;` and `wf_port` needs `pub mod wf060;`
//! wired in for these submodules to be reachable outside this directory.

pub mod common;
pub mod high_consequence;
pub mod http_protocol_cache;
pub mod ics_ot;
pub mod injection;
pub mod insecure_defaults;
