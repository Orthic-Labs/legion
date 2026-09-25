//! Rust port of `scripts/package-windows-release.mjs`.
//!
//! Package mode (`prepareWindowsArchive`, the default when `--finalize` is
//! not passed) is fully native: it reads `release/version.json`, validates
//! the assembled release tree, and shells out only to the system `tar` to
//! build the portable archive (exactly what the JS's own
//! `createPortableArchive` does — see `prepare::create_portable_archive`).
//!
//! Finalize mode (`--finalize`, `--publish-github`) is the CI-only signed
//! publication path. Its glue logic (signature/provenance/qualification
//! evidence verification, output layout, publication-policy checks) is
//! native. It still needs `@rightkit/release`'s Azure manifest signing and
//! GitHub Releases API client — an external npm package that stays, per
//! the "no JS side in legion" decision — so those specific calls, plus
//! legion's own not-yet-ported `checkUnsignedCandidate`
//! (`scripts/ci/prepare-unsigned-candidate.mjs`), run as `node -e
//! "import(...)"` one-liner subprocesses via `node_shim`. Every other byte
//! of orchestration (path safety, digest/receipt verification, evidence
//! wiring) is Rust.

pub mod cli;
pub mod evidence;
pub mod node_shim;
pub mod prepare;

#[cfg(test)]
mod tests;
