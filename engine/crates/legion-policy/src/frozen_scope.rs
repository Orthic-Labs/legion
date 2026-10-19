//! Deterministic admission for explicitly frozen scope.
//!
//! This module authenticates nobody. A host adapter must implement
//! [`TrustedObservationSource`] from live, authenticated host state, including actual
//! model/session identity, authority assignment, launch context & revision ordering.
//! Never implement it by deserializing a worker's claimed identities or approval JSON.
//! Bindings are transport data, not grants. Closure discovery, canonical repository
//! identity, hashing actual bytes & enforcement at each effect boundary belong to hosts.
//! Admission is not an atomic effect lease: consumers must recheck at execution time.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FreezeBinding {
    pub repository: String,
    pub freeze_id: String,
    pub revision: u64,
    pub baseline_closure_sha256: String,
    pub closure_definition_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmendmentBinding {
    pub base_closure_sha256: String,
    pub patch_sha256: String,
    pub result_closure_sha256: String,
    pub missed_review_reason: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    Dispatch,
    Mutate,
    Build,
    Dequeue,
    Push,
    Publish,
    Adopt,
}

/// These digests describe actual host-computed bytes, never worker claims.
#[derive(Clone, Debug)]
pub struct EffectRequest {
    pub operation: Operation,
    pub repository: String,
    pub freeze: Option<FreezeBinding>,
    pub closure_definition_sha256: String,
    pub base_closure_sha256: String,
    pub result_closure_sha256: String,
    pub patch_sha256: Option<String>,
    pub amendment: Option<AmendmentBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredReviewers {
    /// Host authority principal assigned Sage, independent of its model identity.
    pub sage_authority: String,
    /// Canonical host model identities, never display names or aliases.
    pub fable_model: String,
    pub astra_model: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveFreeze {
    pub binding: FreezeBinding,
    pub status: FreezeStatus,
    pub reviewers: RequiredReviewers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreezeStatus {
    Active,
    Revoked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecisionKind {
    SageNecessity,
    Fable,
    Astra,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObservedDecision {
    Necessary,
    Unnecessary,
    Agree,
    Disagree,
}

/// Evidence exists only as output of an explicitly trusted source. Deliberately
/// lacks Deserialize: a name/role/session string supplied by a caller is no proof.
#[derive(Clone, Debug)]
pub struct HostObservation {
    pub session_id: String,
    pub model_identity: String,
    pub sage_authority: Option<String>,
    pub launch_id: String,
    /// Complete transcript provenance, including transitive session ancestors.
    pub input_sessions: Vec<String>,
    /// Host-wide monotonic event order, not a caller timestamp.
    pub sequence: u64,
    pub operation: Operation,
    pub freeze: FreezeBinding,
    pub amendment: AmendmentBinding,
    pub decision: ObservedDecision,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceError {
    Unavailable,
    Unauthenticated,
}

/// Security boundary: implement only in authenticated host adapters. `None` from
/// `current_freeze` certifies no explicit freeze exists; absence of a binding in a
/// request does not. Each lookup must consult authoritative current state, never
/// merely a TTL, an issued-at timestamp, or a cached highest-known revision.
/// Host storage must never roll revisions back or reuse a retired freeze identity;
/// revocation remains observable as `Some(Revoked)`, not absence of a freeze.
/// `observation` must resolve actual host-launched decisions & complete context
/// provenance; raw caller JSON must never be promoted into this type.
pub trait TrustedObservationSource {
    fn current_freeze(&self, repository: &str) -> Result<Option<LiveFreeze>, SourceError>;
    fn observation(
        &self,
        kind: DecisionKind,
        request: &EffectRequest,
    ) -> Result<Option<HostObservation>, SourceError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Allowance {
    Ambient,
    Unchanged,
    Amendment,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Denial {
    MissingLiveSource,
    Source(SourceError),
    InvalidIdentifier,
    InvalidDigest,
    InvalidRevision,
    AmbiguousReviewerMapping,
    MissingFreezeBinding,
    UnexpectedFreezeBinding,
    WrongRepository,
    WrongFreeze,
    StaleRevision,
    Revoked,
    WrongClosureDefinition,
    WrongBase,
    MissingAmendment,
    MissingPatch,
    SupersededPatch,
    WrongResult,
    MissingMissedReviewReason,
    MissingObservation(DecisionKind),
    WrongObservationIdentity(DecisionKind),
    WrongObservationOperation(DecisionKind),
    WrongObservationBinding(DecisionKind),
    WrongObservationAmendment(DecisionKind),
    DecisionRejected(DecisionKind),
    InvalidObservationProvenance(DecisionKind),
    AliasedReviewers,
    SharedReviewerTranscript,
    NecessityNotFirst,
    LiveStateChanged,
}

pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn identifier(s: &str) -> Result<(), Denial> {
    if s.trim().is_empty() || s.trim() != s || s.chars().any(char::is_control) {
        Err(Denial::InvalidIdentifier)
    } else {
        Ok(())
    }
}

fn digest(s: &str) -> Result<(), Denial> {
    if s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(Denial::InvalidDigest)
    }
}

fn validate_freeze(f: &FreezeBinding) -> Result<(), Denial> {
    identifier(&f.repository)?;
    identifier(&f.freeze_id)?;
    if f.revision == 0 {
        return Err(Denial::InvalidRevision);
    }
    digest(&f.baseline_closure_sha256)?;
    digest(&f.closure_definition_sha256)
}

fn validate_amendment(a: &AmendmentBinding) -> Result<(), Denial> {
    digest(&a.base_closure_sha256)?;
    digest(&a.patch_sha256)?;
    digest(&a.result_closure_sha256)?;
    if a.missed_review_reason.trim().is_empty() {
        return Err(Denial::MissingMissedReviewReason);
    }
    Ok(())
}

fn match_freeze(expected: &FreezeBinding, actual: &FreezeBinding) -> Result<(), Denial> {
    validate_freeze(actual)?;
    if actual.repository != expected.repository {
        return Err(Denial::WrongRepository);
    }
    if actual.freeze_id != expected.freeze_id {
        return Err(Denial::WrongFreeze);
    }
    if actual.revision != expected.revision {
        return Err(Denial::StaleRevision);
    }
    if actual.baseline_closure_sha256 != expected.baseline_closure_sha256 {
        return Err(Denial::WrongBase);
    }
    if actual.closure_definition_sha256 != expected.closure_definition_sha256 {
        return Err(Denial::WrongClosureDefinition);
    }
    Ok(())
}

fn observation(
    source: &dyn TrustedObservationSource,
    kind: DecisionKind,
    request: &EffectRequest,
    live: &LiveFreeze,
    amendment: &AmendmentBinding,
) -> Result<HostObservation, Denial> {
    let o = source
        .observation(kind, request)
        .map_err(Denial::Source)?
        .ok_or(Denial::MissingObservation(kind))?;
    for id in [&o.session_id, &o.model_identity, &o.launch_id] {
        identifier(id).map_err(|_| Denial::InvalidObservationProvenance(kind))?;
    }
    if o.sequence == 0
        || o.input_sessions
            .iter()
            .any(|s| identifier(s).is_err() || s == &o.session_id)
    {
        return Err(Denial::InvalidObservationProvenance(kind));
    }
    if o.operation != request.operation {
        return Err(Denial::WrongObservationOperation(kind));
    }
    match_freeze(&live.binding, &o.freeze).map_err(|_| Denial::WrongObservationBinding(kind))?;
    validate_amendment(&o.amendment)?;
    if o.amendment.patch_sha256 != amendment.patch_sha256 {
        return Err(Denial::SupersededPatch);
    }
    if &o.amendment != amendment {
        return Err(Denial::WrongObservationAmendment(kind));
    }
    let identity_matches = match kind {
        DecisionKind::SageNecessity => {
            o.sage_authority.as_deref() == Some(live.reviewers.sage_authority.as_str())
        }
        DecisionKind::Fable => o.model_identity == live.reviewers.fable_model,
        DecisionKind::Astra => o.model_identity == live.reviewers.astra_model,
    };
    if !identity_matches {
        return Err(Denial::WrongObservationIdentity(kind));
    }
    let agrees = match kind {
        DecisionKind::SageNecessity => o.decision == ObservedDecision::Necessary,
        _ => o.decision == ObservedDecision::Agree,
    };
    if !agrees {
        return Err(Denial::DecisionRejected(kind));
    }
    Ok(o)
}

/// Evaluate immediately before an effect. No model is invoked by this function.
pub fn evaluate(
    request: &EffectRequest,
    source: Option<&dyn TrustedObservationSource>,
) -> Result<Allowance, Denial> {
    identifier(&request.repository)?;
    let source = source.ok_or(Denial::MissingLiveSource)?;
    let live = source
        .current_freeze(&request.repository)
        .map_err(Denial::Source)?;
    let Some(live) = live else {
        return if request.freeze.is_some() {
            Err(Denial::UnexpectedFreezeBinding)
        } else {
            Ok(Allowance::Ambient)
        };
    };
    validate_freeze(&live.binding)?;
    if live.binding.repository != request.repository {
        return Err(Denial::WrongRepository);
    }
    if live.status == FreezeStatus::Revoked {
        return Err(Denial::Revoked);
    }
    match_freeze(
        &live.binding,
        request
            .freeze
            .as_ref()
            .ok_or(Denial::MissingFreezeBinding)?,
    )?;
    let r = &live.reviewers;
    for id in [&r.sage_authority, &r.fable_model, &r.astra_model] {
        identifier(id)?;
    }
    if r.fable_model == r.astra_model {
        return Err(Denial::AmbiguousReviewerMapping);
    }
    digest(&request.closure_definition_sha256)?;
    digest(&request.base_closure_sha256)?;
    digest(&request.result_closure_sha256)?;
    if request.closure_definition_sha256 != live.binding.closure_definition_sha256 {
        return Err(Denial::WrongClosureDefinition);
    }
    if request.base_closure_sha256 != live.binding.baseline_closure_sha256 {
        return Err(Denial::WrongBase);
    }
    let unchanged = request.result_closure_sha256 == live.binding.baseline_closure_sha256;
    let result = if unchanged && request.amendment.is_none() && request.patch_sha256.is_none() {
        Allowance::Unchanged
    } else {
        let a = request.amendment.as_ref().ok_or(Denial::MissingAmendment)?;
        validate_amendment(a)?;
        let patch = request.patch_sha256.as_ref().ok_or(Denial::MissingPatch)?;
        digest(patch)?;
        if a.base_closure_sha256 != request.base_closure_sha256 {
            return Err(Denial::WrongBase);
        }
        if &a.patch_sha256 != patch {
            return Err(Denial::SupersededPatch);
        }
        if a.result_closure_sha256 != request.result_closure_sha256 {
            return Err(Denial::WrongResult);
        }
        // Resolve necessity before even consulting either reviewer observation.
        let sage = observation(source, DecisionKind::SageNecessity, request, &live, a)?;
        let fable = observation(source, DecisionKind::Fable, request, &live, a)?;
        let astra = observation(source, DecisionKind::Astra, request, &live, a)?;
        if fable.session_id == astra.session_id || fable.launch_id == astra.launch_id {
            return Err(Denial::AliasedReviewers);
        }
        if fable.input_sessions.contains(&astra.session_id)
            || astra.input_sessions.contains(&fable.session_id)
        {
            return Err(Denial::SharedReviewerTranscript);
        }
        if sage.sequence >= fable.sequence || sage.sequence >= astra.sequence {
            return Err(Denial::NecessityNotFirst);
        }
        Allowance::Amendment
    };
    if source
        .current_freeze(&request.repository)
        .map_err(Denial::Source)?
        != Some(live)
    {
        return Err(Denial::LiveStateChanged);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct Host {
        live: Option<LiveFreeze>,
        observations: [Option<HostObservation>; 3],
        reads: Cell<usize>,
        calls: Cell<usize>,
        advance: bool,
        unavailable: bool,
    }
    impl TrustedObservationSource for Host {
        fn current_freeze(&self, _: &str) -> Result<Option<LiveFreeze>, SourceError> {
            if self.unavailable {
                return Err(SourceError::Unavailable);
            }
            let n = self.reads.get();
            self.reads.set(n + 1);
            let mut live = self.live.clone();
            if self.advance && n > 0 {
                live.as_mut().unwrap().binding.revision += 1;
            }
            Ok(live)
        }
        fn observation(
            &self,
            k: DecisionKind,
            _: &EffectRequest,
        ) -> Result<Option<HostObservation>, SourceError> {
            self.calls.set(self.calls.get() + 1);
            Ok(self.observations[k as usize].clone())
        }
    }
    fn fixture() -> (EffectRequest, Host) {
        let f = FreezeBinding {
            repository: "repo".into(),
            freeze_id: "freeze".into(),
            revision: 1,
            baseline_closure_sha256: sha256(b"base"),
            closure_definition_sha256: sha256(b"globs"),
        };
        let a = AmendmentBinding {
            base_closure_sha256: f.baseline_closure_sha256.clone(),
            patch_sha256: sha256(b"patch"),
            result_closure_sha256: sha256(b"result"),
            missed_review_reason: "prior review omitted generator input".into(),
        };
        let request = EffectRequest {
            operation: Operation::Push,
            repository: "repo".into(),
            freeze: Some(f.clone()),
            closure_definition_sha256: f.closure_definition_sha256.clone(),
            base_closure_sha256: a.base_closure_sha256.clone(),
            result_closure_sha256: a.result_closure_sha256.clone(),
            patch_sha256: Some(a.patch_sha256.clone()),
            amendment: Some(a.clone()),
        };
        let observations = std::array::from_fn(|i| {
            Some(HostObservation {
                session_id: format!("session-{i}"),
                model_identity: ["any-model", "fable-model", "astra-model"][i].into(),
                sage_authority: (i == 0).then(|| "assigned-sage".into()),
                launch_id: format!("launch-{i}"),
                input_sessions: vec![],
                sequence: i as u64 + 1,
                operation: Operation::Push,
                freeze: f.clone(),
                amendment: a.clone(),
                decision: if i == 0 {
                    ObservedDecision::Necessary
                } else {
                    ObservedDecision::Agree
                },
            })
        });
        (
            request,
            Host {
                live: Some(LiveFreeze {
                    binding: f,
                    status: FreezeStatus::Active,
                    reviewers: RequiredReviewers {
                        sage_authority: "assigned-sage".into(),
                        fable_model: "fable-model".into(),
                        astra_model: "astra-model".into(),
                    },
                }),
                observations,
                reads: Cell::new(0),
                calls: Cell::new(0),
                advance: false,
                unavailable: false,
            },
        )
    }
    #[test]
    fn ambient_and_unchanged_need_no_review() {
        let (mut q, mut h) = fixture();
        h.live = None;
        q.freeze = None;
        assert_eq!(evaluate(&q, Some(&h)), Ok(Allowance::Ambient));
        assert_eq!(h.calls.get(), 0);
        let (mut q, h) = fixture();
        q.result_closure_sha256 = q.base_closure_sha256.clone();
        q.amendment = None;
        q.patch_sha256 = None;
        assert_eq!(evaluate(&q, Some(&h)), Ok(Allowance::Unchanged));
        assert_eq!(h.calls.get(), 0);
    }
    #[test]
    fn exact_current_amendment_passes() {
        let (q, h) = fixture();
        assert_eq!(evaluate(&q, Some(&h)), Ok(Allowance::Amendment));
        assert_eq!(h.calls.get(), 3);
    }
    #[test]
    fn fail_closed_on_missing_live_state_and_missing_binding() {
        let (mut q, mut h) = fixture();
        assert_eq!(evaluate(&q, None), Err(Denial::MissingLiveSource));
        h.unavailable = true;
        assert_eq!(
            evaluate(&q, Some(&h)),
            Err(Denial::Source(SourceError::Unavailable))
        );
        h.unavailable = false;
        q.freeze = None;
        assert_eq!(evaluate(&q, Some(&h)), Err(Denial::MissingFreezeBinding));
    }
    type Change = fn(&mut EffectRequest, &mut Host);
    #[test]
    fn rejects_each_binding_and_evidence_failure() {
        let cases: Vec<(Change, Denial)> = vec![
            (|q, _| q.repository.clear(), Denial::InvalidIdentifier),
            (
                |q, _| q.result_closure_sha256 = "gg".repeat(32),
                Denial::InvalidDigest,
            ),
            (
                |q, _| q.freeze.as_mut().unwrap().revision = 0,
                Denial::InvalidRevision,
            ),
            (
                |q, _| q.freeze.as_mut().unwrap().repository = "other".into(),
                Denial::WrongRepository,
            ),
            (
                |q, _| q.freeze.as_mut().unwrap().freeze_id = "other".into(),
                Denial::WrongFreeze,
            ),
            (
                |q, _| q.freeze.as_mut().unwrap().revision += 1,
                Denial::StaleRevision,
            ),
            (
                |_, h| h.live.as_mut().unwrap().status = FreezeStatus::Revoked,
                Denial::Revoked,
            ),
            (
                |q, _| q.closure_definition_sha256 = sha256(b"other"),
                Denial::WrongClosureDefinition,
            ),
            (
                |q, _| q.base_closure_sha256 = sha256(b"other"),
                Denial::WrongBase,
            ),
            (|q, _| q.amendment = None, Denial::MissingAmendment),
            (|q, _| q.patch_sha256 = None, Denial::MissingPatch),
            (
                |q, _| q.patch_sha256 = Some(sha256(b"new patch")),
                Denial::SupersededPatch,
            ),
            (
                |q, _| q.result_closure_sha256 = sha256(b"other"),
                Denial::WrongResult,
            ),
            (
                |q, _| q.amendment.as_mut().unwrap().missed_review_reason = " ".into(),
                Denial::MissingMissedReviewReason,
            ),
            (
                |_, h| h.observations[0] = None,
                Denial::MissingObservation(DecisionKind::SageNecessity),
            ),
            (
                |_, h| h.observations[2] = None,
                Denial::MissingObservation(DecisionKind::Astra),
            ),
            (
                |_, h| h.observations[0].as_mut().unwrap().sage_authority = None,
                Denial::WrongObservationIdentity(DecisionKind::SageNecessity),
            ),
            (
                |_, h| h.observations[1].as_mut().unwrap().model_identity = "role:fable".into(),
                Denial::WrongObservationIdentity(DecisionKind::Fable),
            ),
            (
                |_, h| h.observations[1].as_mut().unwrap().decision = ObservedDecision::Disagree,
                Denial::DecisionRejected(DecisionKind::Fable),
            ),
            (
                |_, h| h.observations[0].as_mut().unwrap().decision = ObservedDecision::Agree,
                Denial::DecisionRejected(DecisionKind::SageNecessity),
            ),
            (
                |_, h| h.observations[1].as_mut().unwrap().operation = Operation::Build,
                Denial::WrongObservationOperation(DecisionKind::Fable),
            ),
            (
                |_, h| h.observations[1].as_mut().unwrap().freeze.revision += 1,
                Denial::WrongObservationBinding(DecisionKind::Fable),
            ),
            (
                |_, h| {
                    h.observations[1].as_mut().unwrap().amendment.patch_sha256 =
                        sha256(b"superseded")
                },
                Denial::SupersededPatch,
            ),
            (
                |_, h| {
                    h.observations[1]
                        .as_mut()
                        .unwrap()
                        .amendment
                        .result_closure_sha256 = sha256(b"other")
                },
                Denial::WrongObservationAmendment(DecisionKind::Fable),
            ),
            (
                |_, h| h.observations[2].as_mut().unwrap().session_id = "session-1".into(),
                Denial::AliasedReviewers,
            ),
            (
                |_, h| h.observations[2].as_mut().unwrap().launch_id = "launch-1".into(),
                Denial::AliasedReviewers,
            ),
            (
                |_, h| {
                    h.observations[2]
                        .as_mut()
                        .unwrap()
                        .input_sessions
                        .push("session-1".into())
                },
                Denial::SharedReviewerTranscript,
            ),
            (
                |_, h| h.observations[0].as_mut().unwrap().sequence = 3,
                Denial::NecessityNotFirst,
            ),
            (
                |_, h| h.observations[1].as_mut().unwrap().sequence = 0,
                Denial::InvalidObservationProvenance(DecisionKind::Fable),
            ),
            (
                |_, h| h.live.as_mut().unwrap().reviewers.astra_model = "fable-model".into(),
                Denial::AmbiguousReviewerMapping,
            ),
            (|_, h| h.advance = true, Denial::LiveStateChanged),
            (|_, h| h.live = None, Denial::UnexpectedFreezeBinding),
        ];
        for (index, (change, expected)) in cases.into_iter().enumerate() {
            let (mut q, mut h) = fixture();
            change(&mut q, &mut h);
            assert_eq!(evaluate(&q, Some(&h)), Err(expected), "case {index}");
        }
    }
    #[test]
    fn failed_necessity_does_not_consult_reviewers() {
        let (q, mut h) = fixture();
        h.observations[0].as_mut().unwrap().decision = ObservedDecision::Unnecessary;
        assert_eq!(
            evaluate(&q, Some(&h)),
            Err(Denial::DecisionRejected(DecisionKind::SageNecessity))
        );
        assert_eq!(h.calls.get(), 1);
    }
}
