#![forbid(unsafe_code)]

pub mod adjudication;
pub mod candidate;
pub mod error;
pub mod normalize;
pub mod provider;
pub mod receipt;

pub use adjudication::{adjudicate, AdjudicatedResult, Adjudication, AdjudicationRequest};
pub use candidate::{
    CandidateClass, CandidateEnvelope, CandidateEvidence, JudgmentPacket, PacketEvidence,
};
pub use error::ReviewError;
pub use normalize::{normalize, NormalizedReview};
pub use provider::{
    infer_judgment, infer_outcome, infer_with_host, normalize_verdict, ProviderJudgment,
    ProviderOutcome, ReviewProviderMetadata, ReviewVerdict,
};
pub use receipt::{emit_receipt, ReviewReceipt, ReviewStatus};

/// Complete the pure review path: adjudicate injected outcomes, normalize
/// deterministic ordering, and issue a receipt over IDs and provider metadata.
pub fn review(
    request: AdjudicationRequest,
    providers: Vec<ReviewProviderMetadata>,
) -> Result<(NormalizedReview, ReviewReceipt), ReviewError> {
    request.candidates.validate()?;
    for provider in &providers {
        provider.validate()?;
        if provider.evidence_pack != request.candidates.evidence_pack {
            return Err(ReviewError::Provenance(format!(
                "provider {} evidence pack does not match review packet",
                provider.provider
            )));
        }
    }
    let normalized = normalize(adjudicate(request)?)?;
    let receipt = emit_receipt(&normalized, providers)?;
    Ok((normalized, receipt))
}
