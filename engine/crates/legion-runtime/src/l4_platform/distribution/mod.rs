//! Port of `src/lib/distribution/**` (5 modules): claims, native-manifest,
//! notices, release-manifest, sbom.

pub mod claims;
pub mod native_manifest;
pub mod notices;
pub mod release_manifest;
pub mod sbom;

pub use claims::{generate_claims, generate_claims_from_qualification, render_support_markdown};
pub use native_manifest::{native_build_manifest, NativeBuildInput};
pub use notices::{build_notice_inventory, render_notices};
pub use release_manifest::{build_release_manifest, file_digest, safe_relative_path, sha256, ReleaseManifestInput};
pub use sbom::{
    cyclonedx_sbom, generate_sboms, inventory_distribution, inventory_runtime_dependencies,
    reconcile_distribution_contents, spdx_sbom,
};
