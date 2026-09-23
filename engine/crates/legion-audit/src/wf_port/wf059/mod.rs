//! wf059: port of the five `src/providers/security/packs/*.mjs` lexical
//! security detectors (crypto/identity-protocol, data-privacy,
//! developer-machine, embedded-iot, file-boundaries) — see
//! [`common`] for the shared `Context`/`Observation` types every submodule
//! uses, and each submodule's own doc comment for what it ports.
//!
//! This module is self-contained: no existing Rust coverage of these five
//! packs was found (`git grep` across `engine/` turned up nothing beyond an
//! unrelated `rules.rs` command-name match), so this is a from-scratch port,
//! not a verification pass.
//!
//! Not yet wired into a registry: the integrator adds `pub mod wf_port;` +
//! `pub mod wf059;` per the chunk assignment. Each submodule's `analyze`
//! function is the callable entry point once wired.

pub mod common;
pub mod crypto_identity_protocols;
pub mod data_privacy;
pub mod developer_machine;
pub mod embedded_iot;
pub mod file_boundaries;
