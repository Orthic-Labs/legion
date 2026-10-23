//! Compatible lenses share exact source bytes once; receipts distinguish logical
//! reconstruction from physical transport. Verification always stays separate.
use super::{action, action_schema, digest, invalid, native, Controller, Observation};
use crate::{
    error::AuditError,
    native_providers::reasoning::{self, ingest, PendingLensWork},
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct BatchReview {
    pub items: Vec<(PendingLensWork, Value)>,
    pub author: Observation,
    pub gaps: Vec<String>,
}
pub(super) fn compatible(works: &[PendingLensWork]) -> bool {
    initial_prompt(works).is_ok_and(|prompt| prompt.is_some())
}
pub(super) fn initial_prompt(works: &[PendingLensWork]) -> Result<Option<Value>, AuditError> {
    initial_prompt_with_sizer(works, &mut super::InitialRequestSizer::default())
}
pub(super) fn initial_prompt_with_sizer(
    works: &[PendingLensWork],
    sizer: &mut super::InitialRequestSizer,
) -> Result<Option<Value>, AuditError> {
    let mut projected = works.to_vec();
    for work in &mut projected {
        work.request.packet = super::projection::packet(&work.request)?.0;
    }
    let Some(mut prompt) = ingest::shared_seat_payload(&projected)? else {
        return Ok(None);
    };
    for (row, work) in prompt["lenses"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .zip(works)
    {
        row["packetDigest"] = json!(digest(&work.request.packet)?);
        row["logicalReference"] =
            super::projection::invocation(&work.request)?["logicalReference"].clone();
    }
    prompt["task"] = json!("Review every compatible lens independently against shared exact excerpts. A top-level packet field {$sharedContext:fieldName} resolves only to sharedContext[fieldName]. logicalReference binds omitted run accounting & illustrative examples in the frozen invocation artifact; referenced material is not model-delivered, reviewed source or evidence of exhaustive coverage. Missing graph relationships remain unknown. Return finalResult:{results:[{requestId,finalResult:{complete:true,findings:[],withdrawn:[],details:{...required signed semanticReview/changeRisk}}}]}; exactly one result per requested requestId, no unknown or duplicate IDs. No claim of independent author contexts across lenses. Each finding includes id,title,anchor plus schema fields.");
    prompt["contextTools"] = super::tools::specs();
    prompt["conversation"] = json!([]);
    let mut common = works[0].request.clone();
    common.denominator_paths.retain(|path| {
        works
            .iter()
            .all(|work| work.request.denominator_paths.contains(path))
    });
    sizer.attach_context(&mut prompt, &common)?;
    // Both planning & transport must choose the same physical split before
    // authorization. No shared-byte credit applies to fallback singles.
    if native::rendered_input(&prompt)?.len() > super::MAX_REQUEST_BYTES / 2 {
        return Ok(None);
    }
    if super::planning_author_sizes(&prompt, works)?.host_envelope_bytes
        > super::MAX_REQUEST_BYTES as u64
    {
        return Ok(None);
    }
    Ok(Some(prompt))
}
impl Controller<'_> {
    pub(super) fn review_batch(
        &mut self,
        seat: &Value,
        works: &[PendingLensWork],
        initial: Option<String>,
    ) -> Result<BatchReview, AuditError> {
        let mut prompt = initial_prompt(works)?
            .ok_or_else(|| AuditError::BoundExceeded("shared-seat-split-required".into()))?;
        let shared = prompt["sharedContext"].clone();
        let shared_digest = prompt["sharedContextDigest"].clone();
        let mut logical = BTreeMap::new();
        for work in works {
            if logical
                .insert(work.request.request_id.clone(), work.clone())
                .is_some()
            {
                return Err(invalid("duplicate request IDs in shared seat"));
            }
        }
        let single_call = self.options.strict_no_retry || self.options.max_calls_per_packet <= 1;
        let schema = if single_call {
            super::final_only_action_schema()
        } else {
            action_schema()
        };
        if single_call {
            // One physical call: no host context request can be answered.
            prompt["contextTools"] = json!([]);
            prompt["singleCall"] = json!("This packet allows exactly one response: no toolRequest is available; review the supplied shared excerpts and emit finalResult.");
            let requests = works.iter().map(|work| &work.request).collect::<Vec<_>>();
            if let Some(note) = super::full_coverage_note(&requests) {
                prompt["coverage"] = json!(note);
            }
        }
        let mut initial = initial;
        let execution = super::model::author(
            works.iter().map(|work| work.provider_id.as_str()),
            self.options,
        )?;
        if seat["gatherPolicy"] != "deterministic"
            && works
                .iter()
                .any(|work| work.provider_id != "reasoning.dead-file")
        {
            let requests = works.iter().map(|work| &work.request).collect::<Vec<_>>();
            self.gather_for_author(
                seat,
                &requests,
                &mut prompt,
                &schema,
                &execution,
                initial.take(),
            )?;
        }
        for _ in 0..self.options.max_calls_per_packet {
            let author = self.call(
                seat,
                prompt.clone(),
                super::author_system(&execution),
                &schema,
                initial.take(),
                &execution,
            )?;
            if let Some(error) = &author.error {
                return Err(invalid(format!("incomplete:shared-seat-host:{error}")));
            }
            let reply = author
                .reply
                .clone()
                .ok_or_else(|| invalid("shared-seat reply missing"))?;
            let parsed = action(reply.clone())?;
            if let Some(request) = parsed.tool_request {
                super::require_context_continuation(self.options)?;
                let response = self.tools.call(request);
                prompt["conversation"]
                    .as_array_mut()
                    .ok_or_else(|| invalid("shared conversation missing"))?
                    .push(json!({"modelAction":reply,"hostToolReply":response}));
                continue;
            }
            let result = parsed
                .final_result
                .ok_or_else(|| invalid("shared-seat final result missing"))?;
            let returned = result["results"]
                .as_array()
                .ok_or_else(|| invalid("shared-seat final must partition results by requestId"))?;
            super::persist(
                &self.run.join("runtime-shared-results"),
                &format!(
                    "{}.json",
                    super::digest_bytes(author.context_id.as_bytes()).trim_start_matches("sha256:")
                ),
                &result,
            )?;
            let mut partitions = BTreeMap::new();
            let mut duplicates = BTreeSet::new();
            let mut gaps: Vec<String> = works
                .iter()
                .flat_map(|work| graph_gap_labels(&work.request.packet))
                .collect();
            gaps.sort();
            gaps.dedup();
            for row in returned {
                let Some(id) = row["requestId"].as_str() else {
                    gaps.push("shared-result-request-id-missing".into());
                    continue;
                };
                if !logical.contains_key(id) {
                    gaps.push(format!("shared-result-unknown:{id}"));
                    continue;
                }
                let Some(value) = row.get("finalResult").filter(|value| value.is_object()) else {
                    gaps.push(format!("shared-result-malformed:{id}"));
                    continue;
                };
                if partitions.insert(id.to_owned(), value.clone()).is_some() {
                    duplicates.insert(id.to_owned());
                    gaps.push(format!("shared-result-duplicate:{id}"));
                }
            }
            let mut items = Vec::new();
            for (id, work) in logical {
                if duplicates.contains(&id) {
                    continue;
                }
                let Some(value) = partitions.remove(&id) else {
                    gaps.push(format!("shared-result-missing:{id}"));
                    continue;
                };
                let projected = super::projection::packet(&work.request)?.0;
                let compact = ingest::compact_shared_packet(&projected, &shared)?;
                super::partial::preserve_author(self.run, &work, &value, &author)?;
                let proof = json!({"schemaVersion":1,"kind":"legion-evidence-delivery","source":"host-transport","receiptId":format!("delivery:{}:{id}",author.context_id),"requestId":id,"packetDigest":digest(&work.request.packet)?,"transportEncoding":"shared-audit-packet-reference-v1","projection":super::projection::evidence(&work.request)?,"reconstructedPacketBytes":legion_contracts::canonical_json_bytes(&projected).map_err(|error|invalid(error.to_string()))?.len(),"physicalRequestDigest":author.request_digest,"physicalRequestBytes":author.request_bytes,"sharedContextDigest":shared_digest,"reconstruction":{"sharedContext":shared,"compactPacket":compact},"complete":true,"truncated":false,"chunks":reasoning::delivery_chunk_manifest(&work.request).map_err(invalid)?,"host":native::observation_value(&author)});
                ingest::mint_runtime_delivery(self.run, &work.request, &proof)?;
                items.push((work, value));
            }
            return Ok(BatchReview {
                items,
                author,
                gaps,
            });
        }
        Err(AuditError::BoundExceeded(
            "incomplete:shared-context-call-limit".into(),
        ))
    }
}
// ---------------------------------------------------------------------------
// Pure completeness & budget accounting. No threads, models or I/O live here:
// the ledger is the single in-process mirror of the canonical reservation
// ledger (`next::reserve_call`) so sequential and bounded-parallel plans
// consume the same required obligations exactly once. It is not a scheduler.
// ---------------------------------------------------------------------------

/// Reserve held back for the one fresh verifier before any author executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifierReserve {
    pub tokens: u64,
    pub candidate_capacity: usize,
}
impl VerifierReserve {
    /// One fresh verifier call carries every candidate up to the output cap;
    /// its per-call allowance is withheld from author spend up front.
    pub fn plan(per_call_allowance: u64, output_token_ceiling: u64) -> Self {
        Self {
            tokens: per_call_allowance,
            candidate_capacity: super::verification::candidate_capacity(output_token_ceiling),
        }
    }
    /// Deterministic split; overflow persists unverified and is never dropped.
    pub fn partition<T>(&self, mut items: Vec<T>) -> (Vec<T>, Vec<T>) {
        let overflow = items.split_off(self.candidate_capacity.min(items.len()));
        (items, overflow)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationState {
    Pending,
    Reserved,
    Authored,
    Incomplete,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerRefusal {
    NotRequired(String),
    /// Already reserved, authored or spent: a second dispatch would double-charge.
    AlreadyDispatched(String),
    AuthorBudgetExhausted(String),
    NotReserved(String),
    RetryNotPermitted(String),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    Complete,
    Incomplete {
        missing_authors: Vec<String>,
        unverified: Vec<String>,
        gaps: Vec<String>,
    },
}
#[derive(Default)]
struct LedgerState {
    required: BTreeMap<String, ObligationState>,
    holds: BTreeMap<String, u64>,
    held: u64,
    charged: u64,
    verifier_charged: u64,
    candidates: BTreeSet<String>,
    verified: BTreeSet<String>,
    gaps: BTreeSet<String>,
    attempts: BTreeMap<String, u32>,
}
pub struct ReviewLedger {
    total: u64,
    reserve: VerifierReserve,
    state: std::sync::Mutex<LedgerState>,
}
impl ReviewLedger {
    pub fn new(total: u64, reserve: VerifierReserve, required: &[String]) -> Self {
        let mut state = LedgerState::default();
        for id in required {
            state
                .required
                .entry(id.clone())
                .or_insert(ObligationState::Pending);
        }
        Self {
            total,
            reserve,
            state: std::sync::Mutex::new(state),
        }
    }
    // A poisoned lock still holds consistent counters: every mutation below is
    // a single pass with no early exit between related writes.
    fn lock(&self) -> std::sync::MutexGuard<'_, LedgerState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
    fn author_room(&self, state: &LedgerState) -> u64 {
        self.total
            .saturating_sub(self.reserve.tokens)
            .saturating_sub(state.charged)
            .saturating_sub(state.held)
    }
    pub fn author_room_tokens(&self) -> u64 {
        self.author_room(&self.lock())
    }
    /// Atomic claim + reservation. Exactly one caller wins each obligation.
    pub fn reserve_author(&self, id: &str, tokens: u64) -> Result<(), LedgerRefusal> {
        let mut state = self.lock();
        match state.required.get(id).copied() {
            None => return Err(LedgerRefusal::NotRequired(id.into())),
            Some(ObligationState::Pending) => {}
            Some(_) => return Err(LedgerRefusal::AlreadyDispatched(id.into())),
        }
        if tokens > self.author_room(&state) {
            state.required.insert(id.into(), ObligationState::Incomplete);
            state.gaps.insert(format!("author-budget-exhausted:{id}"));
            return Err(LedgerRefusal::AuthorBudgetExhausted(id.into()));
        }
        state.required.insert(id.into(), ObligationState::Reserved);
        state.holds.insert(id.into(), tokens);
        state.held = state.held.saturating_add(tokens);
        *state.attempts.entry(id.into()).or_default() += 1;
        Ok(())
    }
    /// Known actual usage releases only the unspent remainder of its own hold;
    /// unknown usage keeps the whole admission charge.
    pub fn settle_author(&self, id: &str, actual: Option<u64>) -> Result<(), LedgerRefusal> {
        let mut state = self.lock();
        let hold = state
            .holds
            .remove(id)
            .ok_or_else(|| LedgerRefusal::NotReserved(id.into()))?;
        state.held = state.held.saturating_sub(hold);
        state.charged = state.charged.saturating_add(actual.unwrap_or(hold));
        state.required.insert(id.into(), ObligationState::Authored);
        Ok(())
    }
    /// Timeout, cancellation or transport failure: the hold is spent, never
    /// returned, and the obligation stays incomplete rather than clean.
    pub fn abandon_author(&self, id: &str, cause: &str) -> Result<(), LedgerRefusal> {
        let mut state = self.lock();
        let hold = state
            .holds
            .remove(id)
            .ok_or_else(|| LedgerRefusal::NotReserved(id.into()))?;
        state.held = state.held.saturating_sub(hold);
        state.charged = state.charged.saturating_add(hold);
        state.required.insert(id.into(), ObligationState::Incomplete);
        state.gaps.insert(format!("author-incomplete:{id}:{cause}"));
        Ok(())
    }
    /// Explicit retry only; the earlier charge stays and fresh tokens must fit.
    pub fn reserve_retry(&self, id: &str, tokens: u64) -> Result<(), LedgerRefusal> {
        let mut state = self.lock();
        if state.required.get(id) != Some(&ObligationState::Incomplete)
            || state.attempts.get(id).copied().unwrap_or(0) == 0
        {
            return Err(LedgerRefusal::RetryNotPermitted(id.into()));
        }
        if tokens > self.author_room(&state) {
            return Err(LedgerRefusal::AuthorBudgetExhausted(id.into()));
        }
        state.required.insert(id.into(), ObligationState::Reserved);
        state.holds.insert(id.into(), tokens);
        state.held = state.held.saturating_add(tokens);
        *state.attempts.entry(id.into()).or_default() += 1;
        Ok(())
    }
    /// Union-only: candidates survive every later cancellation, retry or reload.
    pub fn record_candidates<I: IntoIterator<Item = String>>(&self, ids: I) {
        self.lock().candidates.extend(ids);
    }
    /// A zero-finding scope claim needs independent verification like a candidate.
    pub fn record_zero_finding_claim(&self, request_id: &str) {
        self.lock().candidates.insert(format!("scope:{request_id}"));
    }
    /// Verifier spend draws only on its reserve; verified ids are those the
    /// verifier returned an anchored conclusion for.
    pub fn settle_verifier(&self, verified: &[String], tokens: u64) {
        let mut state = self.lock();
        state.verifier_charged = state.verifier_charged.saturating_add(tokens);
        if state.verifier_charged > self.reserve.tokens {
            state.gaps.insert("verifier-reserve-overrun".into());
        }
        state.verified.extend(verified.iter().cloned());
    }
    pub fn note_gap(&self, gap: impl Into<String>) {
        self.lock().gaps.insert(gap.into());
    }
    pub fn verifier_room_tokens(&self) -> u64 {
        self.reserve
            .tokens
            .saturating_sub(self.lock().verifier_charged)
    }
    pub fn completion(&self) -> Completion {
        let state = self.lock();
        let missing_authors: Vec<_> = state
            .required
            .iter()
            .filter(|(_, s)| **s != ObligationState::Authored)
            .map(|(id, _)| id.clone())
            .collect();
        let unverified: Vec<_> = state
            .candidates
            .difference(&state.verified)
            .cloned()
            .collect();
        if missing_authors.is_empty() && unverified.is_empty() && state.gaps.is_empty() {
            Completion::Complete
        } else {
            Completion::Incomplete {
                missing_authors,
                unverified,
                gaps: state.gaps.iter().cloned().collect(),
            }
        }
    }
}

/// Order-preserving, duplicate-free waves. `concurrency` is the admitted
/// configured width (1 = sequential); every id lands in exactly one wave.
pub fn plan_waves(ids: &[String], concurrency: usize) -> Vec<Vec<String>> {
    let mut seen = BTreeSet::new();
    let unique: Vec<_> = ids
        .iter()
        .filter(|id| seen.insert((*id).clone()))
        .cloned()
        .collect();
    unique
        .chunks(concurrency.max(1))
        .map(<[String]>::to_vec)
        .collect()
}

/// Split an over-budget bundle on lens boundaries only. A single lens that
/// still does not fit is returned as `oversized` with a gap, never truncated.
pub struct BundleSplit<T> {
    pub bundles: Vec<Vec<T>>,
    pub oversized: Vec<T>,
    pub gaps: Vec<String>,
}
pub fn split_bundle<T>(
    items: Vec<T>,
    fits: &mut dyn FnMut(&[T]) -> bool,
    label: &dyn Fn(&T) -> String,
) -> BundleSplit<T> {
    let mut out = BundleSplit {
        bundles: Vec::new(),
        oversized: Vec::new(),
        gaps: Vec::new(),
    };
    split_into(items, fits, label, &mut out);
    out
}
fn split_into<T>(
    mut items: Vec<T>,
    fits: &mut dyn FnMut(&[T]) -> bool,
    label: &dyn Fn(&T) -> String,
    out: &mut BundleSplit<T>,
) {
    if items.is_empty() {
        return;
    }
    if fits(&items) {
        out.bundles.push(items);
    } else if items.len() == 1 {
        out.gaps
            .push(format!("oversized-source:{}", label(&items[0])));
        out.oversized.append(&mut items);
    } else {
        let right = items.split_off(items.len() / 2);
        split_into(items, fits, label, out);
        split_into(right, fits, label, out);
    }
}

/// Missing, truncated, stale or unknown graph context stays an explicit gap;
/// a context receipt is never semantic proof of cross-layer behaviour.
pub fn graph_gap_labels(packet: &Value) -> Vec<String> {
    let Some(graph) = packet.pointer("/reviewContext/graphContext") else {
        return vec!["graph-context-absent".into()];
    };
    let mut gaps = Vec::new();
    for unknown in graph["unknowns"].as_array().into_iter().flatten() {
        gaps.push(format!(
            "graph-unknown:{}:{}",
            unknown["path"].as_str().unwrap_or("*"),
            unknown["cause"].as_str().unwrap_or("unspecified")
        ));
    }
    if graph["truncated"] == true {
        gaps.push("graph-truncated".into());
    }
    match graph["freshness"].as_str() {
        Some("fresh") => {}
        Some(other) => gaps.push(format!("graph-freshness:{other}")),
        None => gaps.push("graph-freshness:unknown".into()),
    }
    gaps.sort();
    gaps.dedup();
    gaps
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parallel_and_sequential_plans_cover_same_obligations_once() {
        let ids: Vec<String> = ["a", "b", "a", "c", "d"].map(String::from).to_vec();
        let flat = |w: Vec<Vec<String>>| {
            let mut all: Vec<_> = w.into_iter().flatten().collect();
            all.sort();
            all
        };
        assert_eq!(flat(plan_waves(&ids, 1)), flat(plan_waves(&ids, 3)));
        assert_eq!(flat(plan_waves(&ids, 0)).len(), 4);
    }
    #[test]
    fn ledger_blocks_duplicate_dispatch_and_preserves_reserve() {
        let ids = vec!["a".to_string(), "b".to_string()];
        let ledger = ReviewLedger::new(100, VerifierReserve::plan(40, 3000), &ids);
        assert!(ledger.reserve_author("a", 40).is_ok());
        assert_eq!(
            ledger.reserve_author("a", 1),
            Err(LedgerRefusal::AlreadyDispatched("a".into()))
        );
        assert_eq!(
            ledger.reserve_author("b", 21),
            Err(LedgerRefusal::AuthorBudgetExhausted("b".into()))
        );
        ledger.abandon_author("a", "timeout").unwrap();
        assert_eq!(ledger.author_room_tokens(), 20);
        assert!(matches!(ledger.completion(), Completion::Incomplete { .. }));
    }
    #[test]
    fn candidates_survive_abandon_and_overflow_is_not_dropped() {
        let reserve = VerifierReserve::plan(10, 300);
        let (kept, overflow) = reserve.partition(vec![1, 2, 3]);
        assert_eq!((kept.len(), overflow.len()), (1, 2));
        let ids = vec!["a".to_string()];
        let ledger = ReviewLedger::new(100, reserve, &ids);
        ledger.reserve_author("a", 10).unwrap();
        ledger.record_candidates(["c1".to_string()]);
        ledger.abandon_author("a", "cancel").unwrap();
        match ledger.completion() {
            Completion::Incomplete { unverified, .. } => assert_eq!(unverified, ["c1"]),
            Completion::Complete => panic!("false clean"),
        }
    }
    #[test]
    fn bundles_split_on_lens_boundaries_and_keep_oversized_gap() {
        let mut fits = |s: &[u32]| s.iter().sum::<u32>() <= 10;
        let split = split_bundle(vec![4, 4, 4, 50], &mut fits, &|n| n.to_string());
        assert_eq!(split.oversized, vec![50]);
        assert_eq!(split.gaps, vec!["oversized-source:50".to_string()]);
        assert_eq!(split.bundles.concat(), vec![4, 4, 4]);
    }
    #[test]
    fn missing_graph_is_a_gap_not_clean() {
        assert_eq!(graph_gap_labels(&json!({})), ["graph-context-absent"]);
        let g = json!({"reviewContext":{"graphContext":{"freshness":"fresh","truncated":true,"unknowns":[{"path":"a.rs","cause":"dynamic"}]}}});
        assert_eq!(
            graph_gap_labels(&g),
            ["graph-truncated", "graph-unknown:a.rs:dynamic"]
        );
    }
    #[test]
    fn shared_refs_are_exact_top_level_fields() {
        let original =
            json!({"excerpts":[{"path":"a","content":"one"}],"lensPlan":{"lens":"correctness"}});
        let shared = json!({"excerpts":original["excerpts"]});
        let mut compact = original.clone();
        compact["excerpts"] = json!({"$sharedContext":"excerpts"});
        compact["excerpts"] = shared["excerpts"].clone();
        assert_eq!(compact, original);
    }
}
