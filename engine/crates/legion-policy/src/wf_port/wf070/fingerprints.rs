//! Faithful port of `src/lib/verification/arcane/architecture-fingerprints.mjs`.
//!
//! Stage 3 fingerprints stay canonical, content-addressed, and free of
//! replay-envelope metadata. `architecture_state_fingerprint` delegates to
//! [`crate::wf_port::wf070::state::fingerprint_architecture_state`] so live
//! acceptance and replay compute the identical digest, exactly as the JS
//! source's doc comment requires.

use super::canon::{digest_value, CanonVal};
use super::state::fingerprint_architecture_state;

pub const ARCHITECTURE_ACCEPTED_EVENT_KIND: &str = "architecture-accepted-event.v1";

/// Digest of an architecture state. State owns its exact projection
/// definition; this delegates rather than re-deriving it.
pub fn architecture_state_fingerprint(state: &CanonVal) -> String {
    fingerprint_architecture_state(state)
}

/// Digest of an immutable accepted event, including its authentication.
pub fn architecture_event_fingerprint(event: &CanonVal) -> String {
    digest_value(event)
}

/// Stable CAS/tail identity for an empty or non-empty trajectory.
pub fn architecture_trajectory_fingerprint(events: &[CanonVal]) -> String {
    digest_value(&CanonVal::Arr(events.to_vec()))
}

pub fn architecture_decision_fingerprint(decision: &CanonVal) -> String {
    digest_value(decision)
}

pub fn architecture_evidence_fingerprint(evidence: &CanonVal) -> String {
    digest_value(evidence)
}

pub fn architecture_finding_fingerprint(finding: &CanonVal) -> String {
    digest_value(finding)
}

pub fn architecture_retry_fingerprint(retry: &CanonVal) -> String {
    digest_value(retry)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trajectory_fingerprint_of_empty_events_is_stable() {
        let a = architecture_trajectory_fingerprint(&[]);
        let b = architecture_trajectory_fingerprint(&[]);
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn event_fingerprint_changes_with_content() {
        let e1 = CanonVal::obj().set("event_id", CanonVal::Str("a".into()));
        let e2 = CanonVal::obj().set("event_id", CanonVal::Str("b".into()));
        assert_ne!(architecture_event_fingerprint(&e1), architecture_event_fingerprint(&e2));
    }

    #[test]
    fn decision_evidence_finding_retry_fingerprints_are_plain_digests() {
        let v = CanonVal::obj().set("id", CanonVal::Str("x".into()));
        assert_eq!(architecture_decision_fingerprint(&v), digest_value(&v));
        assert_eq!(architecture_evidence_fingerprint(&v), digest_value(&v));
        assert_eq!(architecture_finding_fingerprint(&v), digest_value(&v));
        assert_eq!(architecture_retry_fingerprint(&v), digest_value(&v));
    }
}
