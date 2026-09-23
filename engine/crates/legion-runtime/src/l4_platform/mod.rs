//! L4 platform surface: Rust port of `src/lib/platform/**` (12 modules) and
//! `src/lib/distribution/**` (5 modules). The JS remains the legacy spec
//! that this module was ported from; Legion's Rust runtime is canonical.

pub mod artifact_sanitize;
mod base64util;
pub mod contracts;
pub mod distribution;
pub mod external;
pub mod faults;
pub mod journeys;
pub mod lifecycle;
pub mod promotion_equivalence;
pub mod release_candidate;

pub use artifact_sanitize::{
    is_canonical_base64, sanitize_artifact_content, sanitize_produced_artifact, sanitize_sensitive_value,
};
pub use contracts::{capability_receipt, require_capability, sha256, terminal_scenario_receipt};
pub use promotion_equivalence::promotion_equivalence;
pub use release_candidate::{create_release_candidate, verify_candidate_artifact};
