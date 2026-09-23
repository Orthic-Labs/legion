//! Port of `src/lib/platform/external/**` (exercises + evidence validation).

pub mod exercises;
pub mod validate;

pub use exercises::exercise_receipt;
pub use validate::{validate_external_evidence, ExpectedEvidence, SignatureVerifier};
