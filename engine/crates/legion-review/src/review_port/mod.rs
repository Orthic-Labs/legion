//! Port of `src/lib/review/*` JS/TS sources (packet P3-review).
//!
//! Owned module directory — new files only, does not touch sibling modules.

pub mod evidence_envelope;

pub use evidence_envelope::{
    assert_no_untrusted_interpolation, build_review_packet, build_untrusted_evidence_schema,
    detect_override_attempts, wrap_untrusted_evidence, ArtifactRef, BuildReviewPacketArgs,
    EnvelopeError, InjectionAttempt, Omission, ReviewPacket, Reviewer, UntrustedEvidenceRecord,
    WrapUntrustedEvidenceArgs, DEFAULT_EVIDENCE_MAX_BYTES, REVIEW_FAMILIES,
    UNTRUSTED_EVIDENCE_KINDS, UNTRUSTED_EVIDENCE_SCHEMA_VERSION,
};
