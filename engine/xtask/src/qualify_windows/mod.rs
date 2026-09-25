//! Rust port of `scripts/qualify-windows-release.mjs`: qualifies one Windows
//! portable release archive against the six installed-product lifecycle
//! gates (install, command resolution, client integration, update,
//! rollback, uninstall) without touching a developer machine, writing the
//! same `legion-windows-installed-product-qualification` receipt and
//! `legion-integration-journal` shape as the JS original.
//!
//! Split into: `tree` (archive/tar/atomic-replace file-system primitives),
//! `proofs` (Codex live-client proof + `setup status`/`repair` health
//! checks), `journal` (integration-journal/pointer/receipt writers),
//! `lifecycle` (the `qualifyWindowsRelease` orchestration), and `cli` (arg
//! parsing / xtask entry point).

pub mod cli;
pub mod journal;
pub mod lifecycle;
pub mod proofs;
pub mod tree;

pub use lifecycle::{qualify_windows_release, QualifyWindowsOptions};

#[cfg(test)]
mod tests;
