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
//! native (`evidence.rs`, `finalize.rs`). `checkUnsignedCandidate` calls the
//! already-ported `crate::prepare_unsigned_candidate` in-process. The
//! remaining calls that genuinely need `@rightkit/release`'s Azure manifest
//! signing and GitHub Releases API client — an external npm package that
//! stays, per the "no JS side in legion" decision — go through
//! `crate::rightkit_release_bridge` (the shared T4 subprocess bridge).

pub mod cli;
pub mod evidence;
pub mod finalize;
pub mod prepare;

#[cfg(test)]
mod tests;
