//! Faithful port of `src/lib/verification/arcane/evidence-registry.mjs`.
//!
//! Acceptance evidence is compiled from caller-owned receipts/artifacts;
//! ReceiptStore remains its sole durable evidence plane.

use std::collections::BTreeMap;

use super::support::{allow_detail, deny, detail_of, ArcCode, Decision};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Current,
    RefreshRequired,
    Deprecated,
    Waived,
}

impl Lifecycle {
    fn as_str(&self) -> &'static str {
        match self {
            Lifecycle::Current => "CURRENT",
            Lifecycle::RefreshRequired => "REFRESH_REQUIRED",
            Lifecycle::Deprecated => "DEPRECATED",
            Lifecycle::Waived => "WAIVED",
        }
    }
}

/// Evidence freshness status. Mirrors JS `evidenceFreshness`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale(&'static str),
    StateMismatch,
    Expired,
}

#[derive(Debug, Clone)]
pub struct Artifact {
    pub authenticated: bool,
    pub integrated_state: Option<String>,
    pub observed_at_millis: Option<i64>,
    pub valid_until_millis: Option<i64>,
    pub acceptance_id: String,
    pub producer: String,
    pub verifier: String,
    pub completion_consumer: String,
}

pub struct FreshnessContext {
    pub integrated_state: Option<String>,
    pub latest_material_change_millis: Option<i64>,
    pub now_millis: i64,
}

/// Mirrors JS `evidenceFreshness`. `observedAt`/`validUntil` are modeled as
/// already-parsed millis (`Date.parse` equivalent) since wf072 owns no date
/// parser; `None` mirrors a `NaN`/unparsable timestamp.
pub fn evidence_freshness(artifact: &Artifact, ctx: &FreshnessContext) -> Freshness {
    if !artifact.authenticated {
        return Freshness::Stale("unauthenticated-artifact");
    }
    if artifact.integrated_state != ctx.integrated_state {
        return Freshness::StateMismatch;
    }
    let observed_at = artifact.observed_at_millis;
    let changed_at = ctx.latest_material_change_millis.unwrap_or(i64::MIN);
    match observed_at {
        None => return Freshness::Stale("material-change"),
        Some(o) if o < changed_at => return Freshness::Stale("material-change"),
        _ => {}
    }
    match artifact.valid_until_millis {
        None => return Freshness::Expired,
        Some(v) if v < ctx.now_millis => return Freshness::Expired,
        _ => {}
    }
    Freshness::Fresh
}

fn freshness_reason(f: &Freshness) -> Option<&'static str> {
    match f {
        Freshness::Fresh => None,
        Freshness::Stale(r) => Some(r),
        Freshness::StateMismatch => Some("integrated-state"),
        Freshness::Expired => Some("validity-horizon"),
    }
}

fn freshness_status(f: &Freshness) -> &'static str {
    match f {
        Freshness::Fresh => "FRESH",
        Freshness::Stale(_) => "STALE",
        Freshness::StateMismatch => "STATE_MISMATCH",
        Freshness::Expired => "EXPIRED",
    }
}

// ---------------------------------------------------------------------
// compareEvidenceCandidates
// ---------------------------------------------------------------------

#[derive(Clone)]
pub struct HardGate<C> {
    pub id: String,
    pub evaluate: Option<std::rc::Rc<dyn Fn(&C) -> Option<bool>>>,
}

#[derive(Debug, Clone)]
pub struct GateFailure {
    pub gate_id: Option<String>,
    pub reason: &'static str,
}

#[derive(Debug, Clone)]
pub struct Eliminated<C> {
    pub candidate: C,
    pub failures: Vec<GateFailure>,
}

#[derive(Debug, Clone)]
pub struct Ranked<C> {
    pub candidate: C,
    pub score: f64,
}

#[derive(Debug, Clone)]
pub struct ComparisonResult<C> {
    pub eligible: Vec<C>,
    pub eliminated: Vec<Eliminated<C>>,
    pub ranked: Vec<Ranked<C>>,
}

/// Eliminate mechanically-evaluable hard-gate failures before any scoring.
/// Mirrors JS `compareEvidenceCandidates`. Only the closure-form gate
/// (`evaluate`) is ported; the JS field/equals/oneOf/includes shorthand form
/// is a thin sugar over the same closure contract callers can express
/// directly in Rust, so it is left to call sites.
pub fn compare_evidence_candidates<C: Clone>(
    candidates: Vec<C>,
    hard_gates: &[HardGate<C>],
    score: impl Fn(&C) -> f64,
) -> ComparisonResult<C> {
    let mut eliminated = Vec::new();
    let mut eligible = Vec::new();

    for candidate in candidates {
        let mut failures = Vec::new();
        for gate in hard_gates {
            let result = gate.evaluate.as_ref().and_then(|f| f(&candidate));
            match result {
                Some(true) => {}
                Some(false) => failures.push(GateFailure { gate_id: Some(gate.id.clone()), reason: "hard-gate-failed" }),
                None => failures.push(GateFailure { gate_id: Some(gate.id.clone()), reason: "hard-gate-not-mechanically-evaluable" }),
            }
        }
        if failures.is_empty() {
            eligible.push(candidate);
        } else {
            eliminated.push(Eliminated { candidate, failures });
        }
    }

    let mut ranked: Vec<Ranked<C>> = eligible.iter().cloned().map(|c| {
        let s = score(&c);
        Ranked { candidate: c, score: s }
    }).collect();
    ranked.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));

    ComparisonResult { eligible, eliminated, ranked }
}

// ---------------------------------------------------------------------
// AcceptanceEvidenceRegistry
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub struct AcceptanceEntry {
    pub acceptance_id: String,
    pub claim_type: String,
    pub producer: String,
    pub durable_store: String,
    pub verifier: String,
    pub completion_consumer: String,
    pub integrated_state_binding: String,
    pub validity_policy: String,
    pub lifecycle: Lifecycle,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Waiver {
    pub waiver_id: String,
    pub acceptance_id: String,
    pub reason: String,
    pub carrier_state: Option<String>,
    pub issued_at: String,
    pub valid_until_millis: Option<i64>,
    pub lifecycle: Lifecycle,
    pub visible: bool,
}

pub struct WaiverContext {
    pub now_millis: i64,
    pub carrier_state: Option<Option<String>>,
}

#[derive(Default)]
pub struct AcceptanceEvidenceRegistry {
    entries: BTreeMap<String, AcceptanceEntry>,
    waivers: BTreeMap<String, Waiver>,
}

impl AcceptanceEvidenceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mirrors JS `register`.
    pub fn register(&mut self, mut entry: AcceptanceEntry) -> Decision {
        if entry.producer == entry.verifier || entry.producer == entry.completion_consumer {
            return deny(
                ArcCode::ArcSelfCertification,
                "producer cannot verify or consume its own closure evidence",
                detail_of(&[("acceptanceId", &entry.acceptance_id)]),
            );
        }
        // lifecycle is a typed enum in this port, so the JS "unknown
        // lifecycle" branch (a raw-string mismatch) cannot occur here; the
        // type system enforces it instead of a runtime check.
        entry.lifecycle = Lifecycle::Current;

        if let Some(prior) = self.entries.get(&entry.acceptance_id) {
            if *prior != entry {
                return deny(
                    ArcCode::ArcUnsoundSeal,
                    "acceptance evidence entry is immutable for this acceptance id",
                    detail_of(&[("acceptanceId", &entry.acceptance_id)]),
                );
            }
        }
        let id = entry.acceptance_id.clone();
        self.entries.insert(id.clone(), entry);
        allow_detail("acceptance evidence entry registered", detail_of(&[("acceptanceId", &id)]))
    }

    pub fn get(&self, acceptance_id: &str) -> Option<&AcceptanceEntry> {
        self.entries.get(acceptance_id)
    }

    pub fn entries(&self) -> Vec<&AcceptanceEntry> {
        self.entries.values().collect()
    }

    /// Mirrors JS `registerWaiver`.
    pub fn register_waiver(&mut self, mut waiver: Waiver) -> Decision {
        waiver.lifecycle = Lifecycle::Waived;
        waiver.visible = true;
        if let Some(prior) = self.waivers.get(&waiver.waiver_id) {
            if *prior != waiver {
                return deny(
                    ArcCode::ArcUnsoundSeal,
                    "evidence waiver is immutable for this waiver id",
                    detail_of(&[("waiverId", &waiver.waiver_id)]),
                );
            }
        }
        let id = waiver.waiver_id.clone();
        self.waivers.insert(id.clone(), waiver);
        allow_detail(
            "evidence waiver registered",
            detail_of(&[("waiverId", &id), ("lifecycle", "WAIVED"), ("visible", "true")]),
        )
    }

    /// Mirrors JS `getWaiver`.
    pub fn get_waiver(&self, waiver_id: &str, ctx: &WaiverContext) -> Option<Waiver> {
        let waiver = self.waivers.get(waiver_id)?;
        let expired = match waiver.valid_until_millis {
            None => true,
            Some(v) => v < ctx.now_millis,
        };
        let state_mismatch = match &ctx.carrier_state {
            Some(carrier) => *carrier != waiver.carrier_state,
            None => false,
        };
        let refresh = expired || state_mismatch;
        let mut out = waiver.clone();
        out.lifecycle = if refresh { Lifecycle::RefreshRequired } else { Lifecycle::Waived };
        out.visible = true;
        Some(out)
    }

    /// Mirrors JS `evaluateWaiver`.
    pub fn evaluate_waiver(&self, waiver_id: &str, ctx: &WaiverContext) -> Decision {
        let Some(waiver) = self.get_waiver(waiver_id, ctx) else {
            return deny(ArcCode::ArcEvidenceInsufficient, "evidence waiver is missing", detail_of(&[("waiverId", waiver_id)]));
        };
        if waiver.lifecycle == Lifecycle::RefreshRequired {
            return deny(
                ArcCode::ArcEvidenceStale,
                "evidence waiver requires refresh",
                detail_of(&[("waiverId", waiver_id), ("lifecycle", "REFRESH_REQUIRED"), ("visible", "true")]),
            );
        }
        allow_detail(
            "current visible evidence waiver verified",
            detail_of(&[("waiverId", waiver_id), ("lifecycle", "WAIVED"), ("visible", "true")]),
        )
    }

    /// Mirrors JS `verify`.
    pub fn verify(&self, acceptance_id: &str, artifact: &Artifact, ctx: &FreshnessContext) -> Decision {
        let Some(entry) = self.entries.get(acceptance_id) else {
            return deny(ArcCode::ArcUnsoundSeal, "acceptance evidence entry is missing", detail_of(&[("acceptanceId", acceptance_id)]));
        };
        if artifact.acceptance_id != acceptance_id
            || artifact.producer != entry.producer
            || artifact.verifier != entry.verifier
            || artifact.completion_consumer != entry.completion_consumer
        {
            return deny(
                ArcCode::ArcBindingMismatch,
                "evidence artifact does not match registered producer/verifier/consumer",
                detail_of(&[("acceptanceId", acceptance_id)]),
            );
        }
        let freshness = evidence_freshness(artifact, ctx);
        if freshness != Freshness::Fresh {
            let mut detail = detail_of(&[("acceptanceId", acceptance_id), ("completion", "CANDIDATE"), ("status", freshness_status(&freshness))]);
            if let Some(r) = freshness_reason(&freshness) {
                detail.insert("reason".into(), r.into());
            }
            return deny(ArcCode::ArcEvidenceStale, "acceptance evidence is not fresh for exact integrated state", detail);
        }
        allow_detail(
            "fresh exact-state acceptance evidence verified",
            detail_of(&[("acceptanceId", acceptance_id), ("freshness", "FRESH")]),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(id: &str, producer: &str, verifier: &str, consumer: &str) -> AcceptanceEntry {
        AcceptanceEntry {
            acceptance_id: id.into(),
            claim_type: "ct".into(),
            producer: producer.into(),
            durable_store: "store".into(),
            verifier: verifier.into(),
            completion_consumer: consumer.into(),
            integrated_state_binding: "binding".into(),
            validity_policy: "policy".into(),
            lifecycle: Lifecycle::Current,
        }
    }

    #[test]
    fn register_rejects_self_certification_by_producer_equals_verifier() {
        let mut reg = AcceptanceEvidenceRegistry::new();
        let d = reg.register(entry("a1", "same", "same", "consumer"));
        assert!(!d.allowed);
        assert_eq!(d.code, Some(ArcCode::ArcSelfCertification));
    }

    #[test]
    fn register_rejects_self_certification_by_producer_equals_consumer() {
        let mut reg = AcceptanceEvidenceRegistry::new();
        let d = reg.register(entry("a1", "same", "verifier", "same"));
        assert!(!d.allowed);
        assert_eq!(d.code, Some(ArcCode::ArcSelfCertification));
    }

    #[test]
    fn register_is_immutable_for_same_acceptance_id() {
        let mut reg = AcceptanceEvidenceRegistry::new();
        assert!(reg.register(entry("a1", "p", "v", "c")).allowed);
        assert!(reg.register(entry("a1", "p", "v", "c")).allowed); // identical re-register ok
        let d = reg.register(entry("a1", "p2", "v", "c"));
        assert!(!d.allowed);
        assert_eq!(d.code, Some(ArcCode::ArcUnsoundSeal));
    }

    #[test]
    fn verify_requires_exact_binding_match() {
        let mut reg = AcceptanceEvidenceRegistry::new();
        reg.register(entry("a1", "p", "v", "c"));
        let artifact = Artifact {
            authenticated: true,
            integrated_state: Some("s1".into()),
            observed_at_millis: Some(100),
            valid_until_millis: Some(1000),
            acceptance_id: "a1".into(),
            producer: "WRONG".into(),
            verifier: "v".into(),
            completion_consumer: "c".into(),
        };
        let ctx = FreshnessContext { integrated_state: Some("s1".into()), latest_material_change_millis: Some(0), now_millis: 500 };
        let d = reg.verify("a1", &artifact, &ctx);
        assert_eq!(d.code, Some(ArcCode::ArcBindingMismatch));
    }

    #[test]
    fn verify_returns_fresh_for_matching_artifact() {
        let mut reg = AcceptanceEvidenceRegistry::new();
        reg.register(entry("a1", "p", "v", "c"));
        let artifact = Artifact {
            authenticated: true,
            integrated_state: Some("s1".into()),
            observed_at_millis: Some(100),
            valid_until_millis: Some(1000),
            acceptance_id: "a1".into(),
            producer: "p".into(),
            verifier: "v".into(),
            completion_consumer: "c".into(),
        };
        let ctx = FreshnessContext { integrated_state: Some("s1".into()), latest_material_change_millis: Some(0), now_millis: 500 };
        let d = reg.verify("a1", &artifact, &ctx);
        assert!(d.allowed);
    }

    #[test]
    fn evidence_freshness_flags_unauthenticated() {
        let artifact = Artifact {
            authenticated: false,
            integrated_state: None,
            observed_at_millis: None,
            valid_until_millis: None,
            acceptance_id: "a".into(),
            producer: "p".into(),
            verifier: "v".into(),
            completion_consumer: "c".into(),
        };
        let ctx = FreshnessContext { integrated_state: None, latest_material_change_millis: None, now_millis: 0 };
        assert_eq!(evidence_freshness(&artifact, &ctx), Freshness::Stale("unauthenticated-artifact"));
    }

    #[test]
    fn evidence_freshness_flags_expired() {
        let artifact = Artifact {
            authenticated: true,
            integrated_state: Some("s".into()),
            observed_at_millis: Some(100),
            valid_until_millis: Some(100),
            acceptance_id: "a".into(),
            producer: "p".into(),
            verifier: "v".into(),
            completion_consumer: "c".into(),
        };
        let ctx = FreshnessContext { integrated_state: Some("s".into()), latest_material_change_millis: Some(0), now_millis: 500 };
        assert_eq!(evidence_freshness(&artifact, &ctx), Freshness::Expired);
    }

    #[test]
    fn compare_evidence_candidates_eliminates_hard_gate_failures_and_ranks_rest() {
        #[derive(Clone)]
        struct C {
            id: &'static str,
            pass: bool,
            score: f64,
        }
        let candidates = vec![
            C { id: "x", pass: true, score: 1.0 },
            C { id: "y", pass: false, score: 5.0 },
            C { id: "z", pass: true, score: 2.0 },
        ];
        let gates = vec![HardGate {
            id: "g1".into(),
            evaluate: Some(std::rc::Rc::new(|c: &C| Some(c.pass))),
        }];
        let result = compare_evidence_candidates(candidates, &gates, |c| c.score);
        assert_eq!(result.eligible.len(), 2);
        assert_eq!(result.eliminated.len(), 1);
        assert_eq!(result.eliminated[0].candidate.id, "y");
        assert_eq!(result.ranked[0].candidate.id, "z"); // higher score first
    }
}
