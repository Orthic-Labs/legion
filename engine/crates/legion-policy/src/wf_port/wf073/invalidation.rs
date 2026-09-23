//! Port of `src/lib/verification/arcane/invalidation.mjs` — `DependencyLedger`.
//!
//! S00 finding (legacy-semantic-inventory.json, `dependency_invalidation_mechanics`):
//! the predecessor's own invalidation is caller-driven string-equality plus a
//! locator-file re-hash, and explicitly has NO cascade. This module is new
//! work, not a port of predecessor behaviour: it builds a real dependency
//! graph and cascades transitively through `dimension: 'evidence'` edges,
//! exactly mirroring the already-new-work JS in `invalidation.mjs`.
//!
//! Historical-preservation rule: staleness is appended as a new fact. A
//! record's originally-bound dependency digests are never overwritten —
//! `register()`'s stored dependency list is immutable after registration;
//! `observe_change()` only ever flips a `stale` flag and appends to
//! `stale_events`.
//!
//! GAP vs the JS source: the JS constructor accepts an optional `root` and
//! persists a JSON snapshot to `<root>/ledger.json` on every mutation
//! (`_persist`/`_hydrate`), so a ledger can be rehydrated across process
//! restarts. That on-disk format is JS-process-specific (it round-trips
//! through this same module) and isn't exercised by the ported test suite
//! (`tests/arcane-package-s05-invalidation.test.mjs` never passes `root`),
//! so this port keeps the in-memory graph and `snapshot()` (equivalent to
//! the JS `snapshot()` getter used to build the persisted file) but does not
//! reimplement file-backed hydration. Flagging this as a known gap rather
//! than silently dropping it.
//!
//! GAP: JS event ids come from `ulid()` (`contracts/arcane/ids.mjs`), a
//! lexicographically-sortable, time-ordered id. No ulid crate is present in
//! this crate's `Cargo.lock`; this port derives a `sha256`-based id instead
//! (`invevt_<hex>`), which is unique and stable but not time-sortable. If
//! ordering-sensitive consumers appear, add a `ulid` dependency.

use std::collections::HashMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::errors::ArcaneError;

fn dep_key(dimension: &str, reference: &str) -> String {
    format!("{dimension}::{reference}")
}

/// Insertion-order-preserving string set — mirrors the iteration order of a
/// JS `Set`/`Map`, which several JS call sites (e.g. `staledEvidence`
/// ordering) implicitly rely on.
#[derive(Debug, Clone, Default)]
struct OrderedSet {
    order: Vec<String>,
    seen: std::collections::HashSet<String>,
}

impl OrderedSet {
    fn insert(&mut self, value: impl Into<String>) {
        let value = value.into();
        if self.seen.insert(value.clone()) {
            self.order.push(value);
        }
    }

    fn contains(&self, value: &str) -> bool {
        self.seen.contains(value)
    }

    fn iter(&self) -> impl Iterator<Item = &String> {
        self.order.iter()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub dimension: String,
    pub reference: String,
    pub digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleEvent {
    pub at: String,
    pub reason: String,
    pub dimension: String,
    pub reference: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Clone)]
struct EvidenceRecord {
    evidence_id: String,
    dependencies: Vec<Dependency>,
    stale: bool,
    stale_events: Vec<StaleEvent>,
    corrupt: bool,
    corrupt_reason: Option<String>,
    trusted: bool,
    registered_at: String,
}

/// Public, cloned read-back of an evidence record — mirrors the JS
/// `getEvidence`/`snapshot` shallow-clone-and-return contract (callers can
/// never mutate ledger-owned state through it).
#[derive(Debug, Clone)]
pub struct EvidenceView {
    pub evidence_id: String,
    pub dependencies: Vec<Dependency>,
    pub stale: bool,
    pub stale_events: Vec<StaleEvent>,
    pub corrupt: bool,
    pub corrupt_reason: Option<String>,
    pub trusted: bool,
    pub registered_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangedDigest {
    pub dimension: String,
    pub reference: String,
    pub from: Option<String>,
    pub to: String,
}

#[derive(Debug, Clone)]
pub struct InvalidationEvent {
    pub event_id: String,
    pub at: String,
    pub changed: ChangedDigest,
    pub staled_evidence: Vec<String>,
    pub cascaded_evidence: Vec<String>,
    pub affected_criteria: Vec<String>,
    pub affected_claims: Vec<String>,
    pub unaffected: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EligibilityStatus {
    Proven,
    Unproven,
    Insufficient,
}

#[derive(Debug, Clone)]
pub struct ProofEligibility {
    pub status: EligibilityStatus,
    pub reasons: Vec<String>,
    pub stale_evidence: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct QuarantineEntry {
    pub evidence_id: String,
    pub reason: String,
    pub at: String,
}

#[derive(Debug, Clone)]
pub struct LedgerSnapshot {
    pub evidence: Vec<EvidenceView>,
    pub criteria: Vec<(String, Vec<String>)>,
    pub claims: Vec<(String, Vec<String>)>,
    pub quarantined: Vec<QuarantineEntry>,
}

#[derive(Serialize)]
struct DependencyMeta<'a> {
    dimension: &'a str,
    reference: &'a str,
}

pub struct DependencyLedger {
    clock: Box<dyn Fn() -> String + Send + Sync>,
    evidence_order: Vec<String>,
    evidence: HashMap<String, EvidenceRecord>,
    /// "dimension::ref" -> evidence ids directly bound to that dependency key.
    dep_index: HashMap<String, OrderedSet>,
    /// evidenceId (a dependency target) -> evidence ids that depend on it via
    /// a `dimension: "evidence"` edge.
    evidence_dependents: HashMap<String, OrderedSet>,
    /// "dimension::ref" -> last-known digest observed for that key.
    current_digest: HashMap<String, String>,
    criterion_evidence: HashMap<String, OrderedSet>,
    criterion_order: Vec<String>,
    claim_criteria: HashMap<String, OrderedSet>,
    claim_order: Vec<String>,
    quarantine: Vec<QuarantineEntry>,
    event_seq: u64,
}

impl Default for DependencyLedger {
    fn default() -> Self {
        Self::new(|| default_clock())
    }
}

fn default_clock() -> String {
    // No wall-clock dependency is declared for this crate; callers that need
    // real timestamps pass their own `clock`. This default matches the JS
    // default only in *shape* (an ISO-8601-looking string), not in being a
    // real timestamp, and exists purely so `DependencyLedger::default()` is
    // usable in tests that don't care about `at`/`registeredAt` values.
    "1970-01-01T00:00:00.000Z".to_string()
}

impl DependencyLedger {
    pub fn new(clock: impl Fn() -> String + Send + Sync + 'static) -> Self {
        Self {
            clock: Box::new(clock),
            evidence_order: Vec::new(),
            evidence: HashMap::new(),
            dep_index: HashMap::new(),
            evidence_dependents: HashMap::new(),
            current_digest: HashMap::new(),
            criterion_evidence: HashMap::new(),
            criterion_order: Vec::new(),
            claim_criteria: HashMap::new(),
            claim_order: Vec::new(),
            quarantine: Vec::new(),
            event_seq: 0,
        }
    }

    /// Register an evidence record's dependency edges. `trusted: false`
    /// (legacy/unauthenticated evidence) means the record can be linked and
    /// cascaded against, but can never make a criterion `proven` — see
    /// `proof_eligibility`.
    pub fn register(&mut self, evidence_id: impl Into<String>, dependencies: Vec<Dependency>) {
        self.register_with_trust(evidence_id, dependencies, true);
    }

    pub fn register_with_trust(
        &mut self,
        evidence_id: impl Into<String>,
        dependencies: Vec<Dependency>,
        trusted: bool,
    ) {
        let evidence_id = evidence_id.into();
        let record = EvidenceRecord {
            evidence_id: evidence_id.clone(),
            dependencies: dependencies.clone(),
            stale: false,
            stale_events: Vec::new(),
            corrupt: false,
            corrupt_reason: None,
            trusted,
            registered_at: (self.clock)(),
        };
        if !self.evidence.contains_key(&evidence_id) {
            self.evidence_order.push(evidence_id.clone());
        }
        self.evidence.insert(evidence_id.clone(), record);

        for dep in &dependencies {
            let key = dep_key(&dep.dimension, &dep.reference);
            self.dep_index.entry(key.clone()).or_default().insert(evidence_id.clone());
            self.current_digest.entry(key).or_insert_with(|| dep.digest.clone());

            if dep.dimension == "evidence" {
                self.evidence_dependents
                    .entry(dep.reference.clone())
                    .or_default()
                    .insert(evidence_id.clone());
            }
        }
    }

    /// Bind an evidence record to a proof/claim eligibility edge.
    pub fn link(
        &mut self,
        evidence_id: &str,
        criterion_id: Option<&str>,
        claim_id: Option<&str>,
    ) -> Result<(), ArcaneError> {
        if !self.evidence.contains_key(evidence_id) {
            return Err(ArcaneError::with_details(
                "ARC_DEPENDENCY_UNKNOWN",
                format!("link: unknown evidenceId {evidence_id}"),
                serde_json::json!({ "evidenceId": evidence_id }),
            ));
        }
        let Some(criterion_id) = criterion_id else {
            if claim_id.is_some() {
                return Err(ArcaneError::with_details(
                    "ARC_DEPENDENCY_UNKNOWN",
                    "link: claimId requires criterionId",
                    serde_json::json!({ "evidenceId": evidence_id, "claimId": claim_id }),
                ));
            }
            return Ok(());
        };

        if !self.criterion_evidence.contains_key(criterion_id) {
            self.criterion_order.push(criterion_id.to_string());
        }
        self.criterion_evidence
            .entry(criterion_id.to_string())
            .or_default()
            .insert(evidence_id.to_string());

        if let Some(claim_id) = claim_id {
            if !self.claim_criteria.contains_key(claim_id) {
                self.claim_order.push(claim_id.to_string());
            }
            self.claim_criteria
                .entry(claim_id.to_string())
                .or_default()
                .insert(criterion_id.to_string());
        }
        Ok(())
    }

    /// A dependency changed. Stales exactly the evidence bound to it,
    /// cascades transitively through `dimension:"evidence"` edges,
    /// recomputes affected criteria/claims, and returns exactly ONE
    /// structured invalidation event.
    pub fn observe_change(&mut self, dimension: &str, reference: &str, digest: &str) -> InvalidationEvent {
        let key = dep_key(dimension, reference);
        let from = self.current_digest.get(&key).cloned();
        self.current_digest.insert(key.clone(), digest.to_string());

        // --- direct staling: exactly the evidence bound to (dimension, ref) ---
        let direct_ids: Vec<String> = self
            .dep_index
            .get(&key)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default();
        let mut staled_evidence = Vec::new();
        for id in &direct_ids {
            let Some(rec) = self.evidence.get(id) else { continue };
            if rec.stale {
                continue;
            }
            let dep = rec
                .dependencies
                .iter()
                .find(|d| d.dimension == dimension && d.reference == reference);
            if let Some(dep) = dep {
                if dep.digest != digest {
                    let from = dep.digest.clone();
                    let at = (self.clock)();
                    let rec = self.evidence.get_mut(id).unwrap();
                    rec.stale = true;
                    rec.stale_events.push(StaleEvent {
                        at,
                        reason: "dependency-changed".to_string(),
                        dimension: dimension.to_string(),
                        reference: reference.to_string(),
                        from: Some(from),
                        to: Some(digest.to_string()),
                    });
                    staled_evidence.push(id.clone());
                }
            }
        }

        // --- transitive cascade through evidence edges ---
        let mut cascaded_evidence = Vec::new();
        let mut touched: std::collections::HashSet<String> = staled_evidence.iter().cloned().collect();
        let mut queue: std::collections::VecDeque<String> = staled_evidence.iter().cloned().collect();
        while let Some(current) = queue.pop_front() {
            let dependents: Vec<String> = self
                .evidence_dependents
                .get(&current)
                .map(|set| set.iter().cloned().collect())
                .unwrap_or_default();
            for dep_id in dependents {
                if touched.contains(&dep_id) {
                    continue;
                }
                touched.insert(dep_id.clone());
                if !self.evidence.contains_key(&dep_id) {
                    // dangling reference; nothing to stale
                    continue;
                }
                let already_stale = self.evidence.get(&dep_id).unwrap().stale;
                if !already_stale {
                    let at = (self.clock)();
                    let rec = self.evidence.get_mut(&dep_id).unwrap();
                    rec.stale = true;
                    rec.stale_events.push(StaleEvent {
                        at,
                        reason: "cascaded-from-evidence".to_string(),
                        dimension: "evidence".to_string(),
                        reference: current.clone(),
                        from: None,
                        to: None,
                    });
                }
                cascaded_evidence.push(dep_id.clone());
                queue.push_back(dep_id);
            }
        }

        let touched_all: std::collections::HashSet<String> = staled_evidence
            .iter()
            .chain(cascaded_evidence.iter())
            .cloned()
            .collect();

        // --- affected criteria: any criterion with at least one touched evidence id ---
        let mut affected_criteria = Vec::new();
        for criterion_id in &self.criterion_order {
            let ev_set = self.criterion_evidence.get(criterion_id).unwrap();
            if ev_set.iter().any(|id| touched_all.contains(id)) {
                affected_criteria.push(criterion_id.clone());
            }
        }
        let affected_criteria_set: std::collections::HashSet<String> = affected_criteria.iter().cloned().collect();

        // --- affected claims: any claim resting on an affected criterion ---
        let mut affected_claims = Vec::new();
        for claim_id in &self.claim_order {
            let crit_set = self.claim_criteria.get(claim_id).unwrap();
            if crit_set.iter().any(|c| affected_criteria_set.contains(c)) {
                affected_claims.push(claim_id.clone());
            }
        }

        // --- unaffected: every registered evidence id this event did not touch ---
        let unaffected: Vec<String> = self
            .evidence_order
            .iter()
            .filter(|id| !touched_all.contains(*id))
            .cloned()
            .collect();

        self.event_seq += 1;
        let event_id = format!("invevt_{}", self.derive_event_id_hex(dimension, reference, digest));

        InvalidationEvent {
            event_id,
            at: (self.clock)(),
            changed: ChangedDigest {
                dimension: dimension.to_string(),
                reference: reference.to_string(),
                from,
                to: digest.to_string(),
            },
            staled_evidence,
            cascaded_evidence,
            affected_criteria,
            affected_claims,
            unaffected,
        }
    }

    fn derive_event_id_hex(&self, dimension: &str, reference: &str, digest: &str) -> String {
        let meta = DependencyMeta { dimension, reference };
        let mut hasher = Sha256::new();
        if let Ok(bytes) = serde_json::to_vec(&meta) {
            hasher.update(bytes);
        }
        hasher.update(digest.as_bytes());
        hasher.update(self.event_seq.to_le_bytes());
        hex::encode(hasher.finalize())
    }

    pub fn is_stale(&self, evidence_id: &str) -> Result<bool, ArcaneError> {
        self.evidence
            .get(evidence_id)
            .map(|rec| rec.stale)
            .ok_or_else(|| {
                ArcaneError::with_details(
                    "ARC_DEPENDENCY_UNKNOWN",
                    format!("isStale: unknown evidenceId {evidence_id}"),
                    serde_json::json!({ "evidenceId": evidence_id }),
                )
            })
    }

    /// Read back a registered evidence record (historical preservation
    /// check). Never fails for a corrupt record — corruption is reported,
    /// not hidden.
    pub fn get_evidence(&self, evidence_id: &str) -> Result<EvidenceView, ArcaneError> {
        self.evidence
            .get(evidence_id)
            .map(|rec| EvidenceView {
                evidence_id: rec.evidence_id.clone(),
                dependencies: rec.dependencies.clone(),
                stale: rec.stale,
                stale_events: rec.stale_events.clone(),
                corrupt: rec.corrupt,
                corrupt_reason: rec.corrupt_reason.clone(),
                trusted: rec.trusted,
                registered_at: rec.registered_at.clone(),
            })
            .ok_or_else(|| {
                ArcaneError::with_details(
                    "ARC_DEPENDENCY_UNKNOWN",
                    format!("getEvidence: unknown evidenceId {evidence_id}"),
                    serde_json::json!({ "evidenceId": evidence_id }),
                )
            })
    }

    /// Mark an evidence entry corrupt/unreadable without truncating history.
    /// The record is never dropped — it stays in the ledger, quarantined,
    /// and readable, but blocks any criterion it supports from becoming
    /// `proven`.
    pub fn mark_corrupt(&mut self, evidence_id: &str, reason: impl Into<String>) -> Result<(), ArcaneError> {
        let reason = reason.into();
        let at = (self.clock)();
        let rec = self.evidence.get_mut(evidence_id).ok_or_else(|| {
            ArcaneError::with_details(
                "ARC_DEPENDENCY_UNKNOWN",
                format!("markCorrupt: unknown evidenceId {evidence_id}"),
                serde_json::json!({ "evidenceId": evidence_id }),
            )
        })?;
        rec.corrupt = true;
        rec.corrupt_reason = Some(reason.clone());
        self.quarantine.push(QuarantineEntry {
            evidence_id: evidence_id.to_string(),
            reason,
            at,
        });
        Ok(())
    }

    pub fn quarantined(&self) -> Vec<QuarantineEntry> {
        self.quarantine.clone()
    }

    /// Recompute proof/claim eligibility for a criterion.
    pub fn proof_eligibility(&self, criterion_id: &str) -> ProofEligibility {
        let Some(ev_set) = self.criterion_evidence.get(criterion_id).filter(|s| !s.order.is_empty()) else {
            return ProofEligibility {
                status: EligibilityStatus::Insufficient,
                reasons: vec!["no evidence linked to criterion".to_string()],
                stale_evidence: Vec::new(),
            };
        };

        let mut reasons = Vec::new();
        let mut stale_evidence = Vec::new();
        let mut any_corrupt = false;
        let mut any_untrusted = false;

        for id in ev_set.iter() {
            let Some(rec) = self.evidence.get(id) else {
                any_corrupt = true;
                reasons.push(format!("evidence {id} missing from ledger"));
                continue;
            };
            if rec.corrupt {
                any_corrupt = true;
                reasons.push(format!(
                    "evidence {id} corrupt: {}",
                    rec.corrupt_reason.clone().unwrap_or_default()
                ));
            }
            if !rec.trusted {
                any_untrusted = true;
                reasons.push(format!(
                    "evidence {id} untrusted (legacy/unauthenticated import can never qualify)"
                ));
            }
            if rec.stale {
                stale_evidence.push(id.clone());
                reasons.push(format!("evidence {id} stale"));
            }
        }

        let status = if any_corrupt || any_untrusted {
            EligibilityStatus::Insufficient
        } else if !stale_evidence.is_empty() {
            EligibilityStatus::Unproven
        } else {
            EligibilityStatus::Proven
        };

        ProofEligibility { status, reasons, stale_evidence }
    }

    pub fn snapshot(&self) -> LedgerSnapshot {
        let evidence = self
            .evidence_order
            .iter()
            .filter_map(|id| self.evidence.get(id))
            .map(|rec| EvidenceView {
                evidence_id: rec.evidence_id.clone(),
                dependencies: rec.dependencies.clone(),
                stale: rec.stale,
                stale_events: rec.stale_events.clone(),
                corrupt: rec.corrupt,
                corrupt_reason: rec.corrupt_reason.clone(),
                trusted: rec.trusted,
                registered_at: rec.registered_at.clone(),
            })
            .collect();
        let criteria = self
            .criterion_order
            .iter()
            .map(|id| (id.clone(), self.criterion_evidence[id].iter().cloned().collect()))
            .collect();
        let claims = self
            .claim_order
            .iter()
            .map(|id| (id.clone(), self.claim_criteria[id].iter().cloned().collect()))
            .collect();
        LedgerSnapshot {
            evidence,
            criteria,
            claims,
            quarantined: self.quarantined(),
        }
    }
}
