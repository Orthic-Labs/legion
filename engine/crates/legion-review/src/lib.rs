#![forbid(unsafe_code)]

pub mod adjudication;
pub mod candidate;
pub mod error;
pub mod normalize;
pub mod provider;
pub mod receipt;

pub use adjudication::{adjudicate, AdjudicatedResult, Adjudication, AdjudicationRequest};
pub use candidate::{CandidateClass, CandidateEnvelope, CandidateEvidence};
pub use error::ReviewError;
pub use normalize::{normalize, NormalizedReview};
pub use provider::{
    infer_judgment, infer_with_host, ProviderJudgment, ProviderOutcome, ReviewProviderMetadata,
};
pub use receipt::{emit_receipt, ReviewReceipt, ReviewStatus};

/// Complete the pure review path: adjudicate injected outcomes, normalize
/// deterministic ordering, and issue a receipt over IDs and provider metadata.
pub fn review(
    request: AdjudicationRequest,
    providers: Vec<ReviewProviderMetadata>,
) -> Result<(NormalizedReview, ReviewReceipt), ReviewError> {
    let normalized = normalize(adjudicate(request)?)?;
    let receipt = emit_receipt(&normalized, providers)?;
    Ok((normalized, receipt))
}
