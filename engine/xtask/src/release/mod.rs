//! Rust home for Legion's release-chain scripts (ported from `scripts/release/*.mjs`).
//!
//! Each submodule is a faithful 1:1 port of one JS file; see that module's doc
//! comment for the exact source path and any porting notes.

pub mod admission;
pub mod installer_release_chain;
pub mod local_windows_development;
pub mod macos_build_installer;
pub mod macos_finalize;
pub mod paths;
pub mod windows_finalize;
pub mod windows_finalize_installer;
pub mod windows_qualify_installed;
