//! `legion audit next --run <dir>`: the resumable dispatch driver (audit v2,
//! ADR-3).
//!
//! `next` is a pure function of three inputs and one small piece of recorded
//! state:
//!
//! * the frozen plan, `lens-dispatch.json` (`seatId`, `wave`, `tier`, packets
//!   per seat, optional `reasoningBudget`);
//! * the ingested results: one `lens-receipts/<packet>.json` per finished
//!   packet, and for the security adjudicator the `adjudicationLedger` inside
//!   its receipt (what is still required, what was voided or contested);
//! * seat leases and counters in `<run>/next-state.json`, which is the only
//!   thing `next` writes besides the deterministic packet files it
//!   materialises for adjudication work.
//!
//! Repeated calls without new results return the same wave: active leases are
//! returned unchanged and nothing new is issued. A lease that expires without
//! a result is reissued and counts as an attempt.
//!
//! Termination is explicit. Limits: two attempts per seat; three adjudication
//! rounds plus one confirmation-only fourth round; a total issuance cap of `2 x plan seats + 3 x adjudication
//! candidates`; an optional frozen reasoning budget. Hitting a limit ends the
//! run as `incomplete:retry-exhausted` (listing the items) or
//! `budget-exhausted`, never a silent loop.
//!
//! Adjudication rounds follow dependency order, one issuance generation each:
//! round 1 the cluster batches; round 2 everything the batch verdicts
//! require (single-candidate confirmations, seeded spot-checks, high-risk and
//! uncertain individual reviews); round 3 what round 2 created (voided-batch
//! per-candidate reruns, confirmations of individual survivors). A round opens
//! only when the previous round has no live work left. A fourth round may hold
//! ONLY single-candidate confirmations of survivors from round 3; any other
//! work that would need a fourth round, and anything beyond round 4, is
//! `retry-exhausted`.
//!
//! The host-attested context receipt is still required: `next` never mints or
//! weakens receipts. A seat counts as finished only once `legion audit
//! ingest` has written its receipt (which verifies anchors, MAC and context
//! binding); `next` only reads receipt presence and the adjudication ledger.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    error::AuditError,
    native_providers::reasoning::{
        ingest::{LENS_PACKET_DIR, LENS_RECEIPT_DIR},
        security_adjudication::{
            adjudication_parent_packet_digest, stage_work_item, ScannerCandidate,
            ADJUDICATOR_PROVIDER_ID, STAGE_CONFIRMATION, STAGE_INDIVIDUAL, STAGE_SPOT_CHECK,
        },
    },
};

/// Default seat lease: 20 minutes.
pub const DEFAULT_LEASE_MS: u64 = 20 * 60 * 1000;
/// Attempts per seat (the first issue plus one reissue after lease expiry).
pub const MAX_SEAT_ATTEMPTS: u32 = 2;
/// Full adjudication rounds (issuance generations).
pub const MAX_ADJUDICATION_ROUNDS: u32 = 3;
/// Round number of the confirmation-only closing round that may follow
/// round 3 (confirmations of survivors from round-3 reruns, nothing else).
pub const CONFIRMATION_ROUND: u32 = MAX_ADJUDICATION_ROUNDS + 1;
/// Seats per wave when the plan records no `limits.waveWidth`.
pub const DEFAULT_WAVE_WIDTH: u64 = 16;
/// Token estimate charged to the judgment budget for a single-candidate
/// adjudication item (a labelled estimate, not a tokenizer count).
pub const STAGE_ITEM_TOKENS: u64 = 2_000;

pub const DISPATCH_FILE: &str = "lens-dispatch.json";
pub const STATE_FILE: &str = "next-state.json";
/// Conventional result path per lens packet: `<run>/lens-results/<packet>.json`.
pub const LENS_RESULT_DIR: &str = "lens-results";
/// Materialised adjudication seat packets and expected result paths.
pub const ADJUDICATION_DIR: &str = "adjudication";
const STATE_KIND: &str = "legion-audit-next-state";
const OUTPUT_KIND: &str = "legion-audit-next";
const BATCH_STAGE: &str = "batch";

/// Clock and lease length. `now_ms` is injected so tests (and replays) are
/// deterministic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NextOptions {
    pub now_ms: u64,
    pub lease_ms: u64,
}

impl NextOptions {
    pub fn now(lease_ms: u64) -> Self {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis() as u64);
        Self { now_ms, lease_ms }
    }
}

// ---------------------------------------------------------------------------
// Recorded state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Lease {
    attempts: u32,
    issued_at_ms: u64,
    expires_at_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct State {
    schema_version: u32,
    kind: String,
    /// Digest of the `lens-dispatch.json` bytes the state belongs to. A
    /// re-frozen plan starts a fresh state.
    dispatch_digest: String,
    /// Leases ever issued (the counter the issuance cap bounds).
    #[serde(default)]
    issuances: u64,
    /// Estimated tokens charged per tier.
    #[serde(default)]
    spent: BTreeMap<String, u64>,
    #[serde(default)]
    leases: BTreeMap<String, Lease>,
    /// Current adjudication round (0 = none opened yet).
    #[serde(default)]
    adjudication_round: u32,
    /// Item keys issued in the current round.
    #[serde(default)]
    round_keys: Vec<String>,
}

impl State {
    fn fresh(dispatch_digest: &str) -> Self {
        Self {
            schema_version: 1,
            kind: STATE_KIND.to_owned(),
            dispatch_digest: dispatch_digest.to_owned(),
            issuances: 0,
            spent: BTreeMap::new(),
            leases: BTreeMap::new(),
            adjudication_round: 0,
            round_keys: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Snapshot (everything `decide` reads)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct LensSeat {
    id: String,
    number: u64,
    wave: u64,
    tier: String,
    bundle: String,
    providers: Vec<String>,
    packets: Vec<String>,
    estimated_tokens: u64,
}

impl LensSeat {
    fn done(&self, done: &BTreeSet<String>) -> bool {
        !self.packets.is_empty() && self.packets.iter().all(|packet| done.contains(packet))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct AdjItem {
    /// `batch:<batchId>` or `<stage>:<candidateId>`.
    key: String,
    stage: String,
    candidate_id: Option<String>,
    batch_id: Option<String>,
    reason: Option<String>,
    tokens: u64,
}

#[derive(Clone, Debug)]
struct AdjSnapshot {
    /// Items still required and not yet satisfied, in key order.
    required: Vec<AdjItem>,
    /// Non-actionable reasons the adjudication cannot close (contested
    /// confirmations, unaccounted candidates).
    blockers: Vec<String>,
    complete: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Budget {
    judgment: Option<u64>,
    specialist: Option<u64>,
    mechanical: Option<u64>,
    max_seats: Option<u64>,
}

#[derive(Clone, Debug)]
struct Snapshot {
    seats: Vec<LensSeat>,
    /// Every seat in the frozen plan, adjudicator seat included (cap input).
    plan_seats: u64,
    /// Packet file names that have an ingested receipt.
    done: BTreeSet<String>,
    adjudication: Option<AdjSnapshot>,
    adjudication_candidates: u64,
    wave_width: u64,
    budget: Option<Budget>,
}

impl Snapshot {
    fn issuance_cap(&self) -> u64 {
        2 * self.plan_seats + 3 * self.adjudication_candidates
    }
}

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Lens,
    Adjudication,
}

#[derive(Clone, Debug)]
struct Work {
    key: String,
    kind: Kind,
    wave: u64,
    order: u64,
    tier: String,
    tokens: u64,
}

impl Work {
    fn rank(&self) -> (u8, u64, u64) {
        let kind = match self.kind {
            Kind::Lens => 0,
            Kind::Adjudication => 1,
        };
        (kind, self.wave, self.order)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ItemStatus {
    /// Never leased.
    Fresh,
    /// Lease still running.
    Active,
    /// Lease expired with attempts left.
    Reissue,
    /// Lease expired and the attempts are spent.
    Exhausted,
}

fn item_status(state: &State, key: &str, now_ms: u64) -> ItemStatus {
    match state.leases.get(key) {
        None => ItemStatus::Fresh,
        Some(lease) if now_ms < lease.expires_at_ms => ItemStatus::Active,
        Some(lease) if lease.attempts < MAX_SEAT_ATTEMPTS => ItemStatus::Reissue,
        Some(_) => ItemStatus::Exhausted,
    }
}

#[derive(Clone, Debug)]
struct Decision {
    /// `wave`, `done`, `incomplete:<reasons>` or `budget-exhausted`.
    status: String,
    wave: Option<u64>,
    /// Every returned item with its lease, lens seats first.
    issued: Vec<(Work, Lease)>,
    /// `(item, reason)`: `attempts`, `issuance-cap` or `round-limit`.
    exhausted: Vec<(String, String)>,
    budget_blocked: Vec<String>,
    blockers: Vec<String>,
}

fn budget_allows(snapshot: &Snapshot, state: &State, tier: &str, tokens: u64) -> bool {
    let Some(budget) = &snapshot.budget else {
        return true;
    };
    if budget.max_seats.is_some_and(|max| state.issuances >= max) {
        return false;
    }
    let limit = match tier {
        "specialist" => budget.specialist,
        "mechanical" => budget.mechanical,
        _ => budget.judgment,
    };
    match limit {
        Some(limit) => state.spent.get(tier).copied().unwrap_or(0) + tokens <= limit,
        None => true,
    }
}

fn blocker_reason(blocker: &str) -> &'static str {
    if blocker.starts_with("contested:") {
        "adjudication-contested"
    } else if blocker == "unaccounted" {
        "adjudication-unaccounted"
    } else {
        "adjudication-unresolved"
    }
}

/// One step of the driver. Mutates `state` (leases, counters, round) and
/// returns what to hand out. Pure given `(snapshot, state, now, lease)`.
fn decide(snapshot: &Snapshot, state: &mut State, now_ms: u64, lease_ms: u64) -> Decision {
    let mut exhausted: Vec<(String, String)> = Vec::new();
    let mut work: Vec<Work> = Vec::new();
    let mut lens_unmet = 0usize;
    for seat in &snapshot.seats {
        if seat.done(&snapshot.done) {
            continue;
        }
        lens_unmet += 1;
        if item_status(state, &seat.id, now_ms) == ItemStatus::Exhausted {
            exhausted.push((seat.id.clone(), "attempts".to_owned()));
            continue;
        }
        work.push(Work {
            key: seat.id.clone(),
            kind: Kind::Lens,
            wave: seat.wave,
            order: seat.number,
            tier: seat.tier.clone(),
            tokens: seat.estimated_tokens,
        });
    }

    let mut blockers: Vec<String> = Vec::new();
    let mut adjudication_unmet = false;
    if let Some(adjudication) = &snapshot.adjudication {
        blockers = adjudication.blockers.clone();
        adjudication_unmet = !adjudication.complete;
        let required: BTreeMap<&str, &AdjItem> = adjudication
            .required
            .iter()
            .map(|item| (item.key.as_str(), item))
            .collect();
        // A round stays open while any of its items is still live.
        let live = state.round_keys.iter().any(|key| {
            required.contains_key(key.as_str())
                && item_status(state, key, now_ms) != ItemStatus::Exhausted
        });
        if !live {
            let mut fresh: Vec<String> = adjudication
                .required
                .iter()
                .filter(|item| !state.leases.contains_key(&item.key))
                .map(|item| item.key.clone())
                .collect();
            fresh.sort();
            if !fresh.is_empty() {
                let confirmation_prefix = format!("{STAGE_CONFIRMATION}:");
                let (admitted, refused): (Vec<String>, Vec<String>) =
                    if state.adjudication_round < MAX_ADJUDICATION_ROUNDS {
                        (fresh, Vec::new())
                    } else if state.adjudication_round == MAX_ADJUDICATION_ROUNDS {
                        fresh
                            .into_iter()
                            .partition(|key| key.starts_with(&confirmation_prefix))
                    } else {
                        (Vec::new(), fresh)
                    };
                for key in refused {
                    exhausted.push((key, "round-limit".to_owned()));
                }
                if !admitted.is_empty() {
                    state.adjudication_round += 1;
                    state.round_keys = admitted;
                }
            }
        }
        let mut keys = state.round_keys.clone();
        keys.sort();
        for (order, key) in keys.into_iter().enumerate() {
            let Some(item) = required.get(key.as_str()) else {
                continue;
            };
            if item_status(state, &key, now_ms) == ItemStatus::Exhausted {
                exhausted.push((key, "attempts".to_owned()));
                continue;
            }
            work.push(Work {
                key,
                kind: Kind::Adjudication,
                wave: 0,
                order: order as u64,
                tier: "judgment".to_owned(),
                tokens: item.tokens,
            });
        }
    }

    let active: BTreeSet<String> = work
        .iter()
        .filter(|item| item_status(state, &item.key, now_ms) == ItemStatus::Active)
        .map(|item| item.key.clone())
        .collect();
    // Waves are sequential: the lowest wave that still has live lens work.
    let wave = work
        .iter()
        .filter(|item| item.kind == Kind::Lens)
        .map(|item| item.wave)
        .min();
    let mut pending: Vec<&Work> = work
        .iter()
        .filter(|item| {
            matches!(
                item_status(state, &item.key, now_ms),
                ItemStatus::Fresh | ItemStatus::Reissue
            ) && (item.kind == Kind::Adjudication || Some(item.wave) == wave)
        })
        .collect();
    pending.sort_by_key(|item| item.rank());

    let cap = snapshot.issuance_cap();
    let width = snapshot.wave_width.max(1) as usize;
    let mut capacity = width.saturating_sub(active.len());
    let mut newly: BTreeSet<String> = BTreeSet::new();
    let mut budget_blocked: Vec<String> = Vec::new();
    for item in pending {
        if capacity == 0 {
            break;
        }
        if state.issuances >= cap {
            exhausted.push((item.key.clone(), "issuance-cap".to_owned()));
            continue;
        }
        if !budget_allows(snapshot, state, &item.tier, item.tokens) {
            budget_blocked.push(item.key.clone());
            continue;
        }
        let attempts = state
            .leases
            .get(&item.key)
            .map_or(0, |lease| lease.attempts)
            + 1;
        state.leases.insert(
            item.key.clone(),
            Lease {
                attempts,
                issued_at_ms: now_ms,
                expires_at_ms: now_ms.saturating_add(lease_ms),
            },
        );
        state.issuances += 1;
        *state.spent.entry(item.tier.clone()).or_insert(0) += item.tokens;
        newly.insert(item.key.clone());
        capacity -= 1;
    }

    let mut returned: Vec<(Work, Lease)> = work
        .iter()
        .filter(|item| active.contains(&item.key) || newly.contains(&item.key))
        .filter_map(|item| {
            state
                .leases
                .get(&item.key)
                .map(|lease| (item.clone(), lease.clone()))
        })
        .collect();
    returned.sort_by_key(|(item, _)| item.rank());
    let returned_wave = returned
        .iter()
        .filter(|(item, _)| item.kind == Kind::Lens)
        .map(|(item, _)| item.wave)
        .min();

    let status = if !returned.is_empty() {
        "wave".to_owned()
    } else if lens_unmet == 0 && !adjudication_unmet {
        "done".to_owned()
    } else {
        let mut reasons: Vec<String> = Vec::new();
        if !exhausted.is_empty() {
            reasons.push("retry-exhausted".to_owned());
        }
        for blocker in &blockers {
            let reason = blocker_reason(blocker).to_owned();
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        if reasons.is_empty() && !budget_blocked.is_empty() {
            // Only the frozen reasoning budget stands in the way.
            "budget-exhausted".to_owned()
        } else {
            if !budget_blocked.is_empty() {
                reasons.push("budget-exhausted".to_owned());
            }
            if reasons.is_empty() {
                reasons.push("stalled".to_owned());
            }
            format!("incomplete:{}", reasons.join(","))
        }
    };
    Decision {
        status,
        wave: returned_wave,
        issued: returned,
        exhausted,
        budget_blocked,
        blockers,
    }
}

// ---------------------------------------------------------------------------
// Filesystem layer
// ---------------------------------------------------------------------------

fn invalid(message: impl Into<String>) -> AuditError {
    AuditError::Invalid(message.into())
}

fn read_json(path: &Path) -> Result<Value, AuditError> {
    let bytes = fs::read(path)
        .map_err(|error| invalid(format!("could not read {}: {error}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("{} is not valid JSON: {error}", path.display())))
}

fn write_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, AuditError> {
    fs::create_dir_all(dir)
        .map_err(|error| invalid(format!("could not create {}: {error}", dir.display())))?;
    let destination = dir.join(name);
    if fs::read(&destination).is_ok_and(|existing| existing == bytes) {
        return Ok(destination);
    }
    let temporary = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    fs::write(&temporary, bytes)
        .map_err(|error| invalid(format!("could not write {}: {error}", temporary.display())))?;
    fs::rename(&temporary, &destination).map_err(|error| {
        invalid(format!(
            "could not publish {}: {error}",
            destination.display()
        ))
    })?;
    Ok(destination)
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn parse_seat(seat: &Value, width: u64) -> Option<LensSeat> {
    let number = seat.get("seat").and_then(Value::as_u64)?;
    let id = seat
        .get("seatId")
        .and_then(Value::as_str)
        .map_or_else(|| format!("seat-{number:03}"), ToOwned::to_owned);
    let wave = seat
        .get("wave")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| number.saturating_sub(1) / width.max(1) + 1);
    Some(LensSeat {
        id,
        number,
        wave,
        tier: seat
            .get("tier")
            .and_then(Value::as_str)
            .unwrap_or("judgment")
            .to_owned(),
        bundle: seat
            .get("bundle")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        providers: strings(seat.get("providers")),
        packets: strings(seat.get("packets")),
        estimated_tokens: seat
            .get("estimatedTokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    })
}

fn parse_budget(dispatch: &Value) -> Option<Budget> {
    let budget = dispatch.get("reasoningBudget").filter(|v| v.is_object())?;
    let field = |name: &str| budget.get(name).and_then(Value::as_u64);
    Some(Budget {
        judgment: field("judgment"),
        specialist: field("specialist"),
        mechanical: field("mechanical"),
        max_seats: field("maxSeats"),
    })
}

struct AdjContext {
    parent_digest: String,
    candidates: Vec<ScannerCandidate>,
    batches: Vec<Value>,
}

fn parse_outstanding(entry: &str, batches: &[Value]) -> Result<AdjItem, String> {
    let batch_tokens = |id: &str| {
        batches
            .iter()
            .find(|batch| batch.get("batchId").and_then(Value::as_str) == Some(id))
            .and_then(|batch| batch.get("estimatedTokens").and_then(Value::as_u64))
            .unwrap_or(STAGE_ITEM_TOKENS)
    };
    if let Some(rest) = entry.strip_prefix("batch:") {
        let id = rest.split(':').next().unwrap_or(rest);
        return Ok(AdjItem {
            key: format!("batch:{id}"),
            stage: BATCH_STAGE.to_owned(),
            candidate_id: None,
            batch_id: Some(id.to_owned()),
            reason: None,
            tokens: batch_tokens(id),
        });
    }
    for stage in [STAGE_SPOT_CHECK, STAGE_CONFIRMATION] {
        if let Some(id) = entry.strip_prefix(&format!("{stage}:")) {
            return Ok(AdjItem {
                key: format!("{stage}:{id}"),
                stage: stage.to_owned(),
                candidate_id: Some(id.to_owned()),
                batch_id: None,
                reason: None,
                tokens: STAGE_ITEM_TOKENS,
            });
        }
    }
    if let Some(rest) = entry.strip_prefix(&format!("{STAGE_INDIVIDUAL}:")) {
        let (id, reason) = rest.rsplit_once(':').unwrap_or((rest, ""));
        return Ok(AdjItem {
            key: format!("{STAGE_INDIVIDUAL}:{id}"),
            stage: STAGE_INDIVIDUAL.to_owned(),
            candidate_id: Some(id.to_owned()),
            batch_id: None,
            reason: (!reason.is_empty()).then(|| reason.to_owned()),
            tokens: STAGE_ITEM_TOKENS,
        });
    }
    Err(entry.to_owned())
}

/// Derives the adjudication state from the adjudicator packet and, when one
/// was ingested, the ledger inside its receipt. `Ok(None)` when the run has no
/// batched adjudication (the adjudicator, if any, is then an ordinary seat).
fn load_adjudication(run_dir: &Path) -> Result<Option<(AdjSnapshot, AdjContext, u64)>, AuditError> {
    let packet_path = run_dir
        .join(LENS_PACKET_DIR)
        .join(format!("{ADJUDICATOR_PROVIDER_ID}.json"));
    if !packet_path.is_file() {
        return Ok(None);
    }
    let work = read_json(&packet_path)?;
    let Some(packet) = work.pointer("/request/packet") else {
        return Ok(None);
    };
    let batches = match packet
        .pointer("/candidateWorkItems/batches")
        .and_then(Value::as_array)
    {
        Some(batches) if !batches.is_empty() => batches.clone(),
        _ => return Ok(None),
    };
    let candidates: Vec<ScannerCandidate> = serde_json::from_value(
        packet
            .get("scannerCandidates")
            .cloned()
            .unwrap_or_else(|| json!([])),
    )
    .map_err(|error| invalid(format!("adjudication packet candidates: {error}")))?;
    let parent_digest = adjudication_parent_packet_digest(packet)
        .map_err(|error| invalid(format!("adjudication packet: {error}")))?;
    let clustered: u64 = packet
        .pointer("/candidateWorkItems/clusters")
        .and_then(Value::as_array)
        .map_or(0, |clusters| {
            clusters
                .iter()
                .map(|cluster| {
                    cluster
                        .get("memberIds")
                        .and_then(Value::as_array)
                        .map_or(0, |members| members.len() as u64)
                })
                .sum()
        });
    let candidate_count = if clustered > 0 {
        clustered
    } else {
        candidates.len() as u64
    };

    let receipt_path = run_dir
        .join(LENS_RECEIPT_DIR)
        .join(format!("{ADJUDICATOR_PROVIDER_ID}.json"));
    let mut required: BTreeMap<String, AdjItem> = BTreeMap::new();
    let mut blockers: Vec<String> = Vec::new();
    let mut complete = false;
    if receipt_path.is_file() {
        let receipt = read_json(&receipt_path)?;
        match receipt.pointer("/result/details/adjudicationLedger/ledger") {
            Some(ledger) => {
                complete = ledger
                    .get("complete")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let mut contested = false;
                for entry in strings(ledger.get("outstanding")) {
                    if entry.starts_with("contested:") {
                        contested = true;
                        blockers.push(entry);
                        continue;
                    }
                    match parse_outstanding(&entry, &batches) {
                        Ok(item) => {
                            required.insert(item.key.clone(), item);
                        }
                        Err(unknown) => blockers.push(format!("unrecognized:{unknown}")),
                    }
                }
                if !complete && required.is_empty() && !contested && blockers.is_empty() {
                    blockers.push("unaccounted".to_owned());
                }
            }
            None => blockers.push("ledger-missing".to_owned()),
        }
    } else {
        for batch in &batches {
            let Some(id) = batch.get("batchId").and_then(Value::as_str) else {
                continue;
            };
            let item = AdjItem {
                key: format!("batch:{id}"),
                stage: BATCH_STAGE.to_owned(),
                candidate_id: None,
                batch_id: Some(id.to_owned()),
                reason: None,
                tokens: batch
                    .get("estimatedTokens")
                    .and_then(Value::as_u64)
                    .unwrap_or(STAGE_ITEM_TOKENS),
            };
            required.insert(item.key.clone(), item);
        }
    }
    Ok(Some((
        AdjSnapshot {
            required: required.into_values().collect(),
            blockers,
            complete,
        },
        AdjContext {
            parent_digest,
            candidates,
            batches,
        },
        candidate_count,
    )))
}

struct Loaded {
    snapshot: Snapshot,
    dispatch_digest: String,
    adjudication: Option<AdjContext>,
}

fn load(run_dir: &Path) -> Result<Loaded, AuditError> {
    let dispatch_path = run_dir.join(DISPATCH_FILE);
    let bytes = fs::read(&dispatch_path).map_err(|error| {
        invalid(format!(
            "{} is missing ({error}); freeze a run with `legion audit --out <dir>` first",
            dispatch_path.display()
        ))
    })?;
    let dispatch: Value = serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("{DISPATCH_FILE} is not valid JSON: {error}")))?;
    let width = dispatch
        .pointer("/limits/waveWidth")
        .and_then(Value::as_u64)
        .filter(|width| *width > 0)
        .unwrap_or(DEFAULT_WAVE_WIDTH);
    let mut seats: Vec<LensSeat> = dispatch
        .get("seats")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|seat| parse_seat(seat, width))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let plan_seats = seats.len() as u64;
    let mut done = BTreeSet::new();
    if let Ok(entries) = fs::read_dir(run_dir.join(LENS_RECEIPT_DIR)) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".json") && !name.starts_with('.') {
                done.insert(name);
            }
        }
    }
    let mut adjudication = None;
    let mut context = None;
    let mut adjudication_candidates = 0;
    if let Some((snapshot, ctx, count)) = load_adjudication(run_dir)? {
        // The adjudicator seat is replaced by the round machine.
        seats.retain(|seat| seat.providers != [ADJUDICATOR_PROVIDER_ID.to_owned()]);
        adjudication = Some(snapshot);
        context = Some(ctx);
        adjudication_candidates = count;
    }
    Ok(Loaded {
        snapshot: Snapshot {
            seats,
            plan_seats,
            done,
            adjudication,
            adjudication_candidates,
            wave_width: width,
            budget: parse_budget(&dispatch),
        },
        dispatch_digest: digest_hex(&bytes),
        adjudication: context,
    })
}

fn load_state(run_dir: &Path, dispatch_digest: &str) -> Result<State, AuditError> {
    let path = run_dir.join(STATE_FILE);
    if !path.is_file() {
        return Ok(State::fresh(dispatch_digest));
    }
    let state: State = serde_json::from_value(read_json(&path)?)
        .map_err(|error| invalid(format!("{STATE_FILE} is invalid: {error}")))?;
    if state.kind != STATE_KIND || state.dispatch_digest != dispatch_digest {
        // A re-frozen plan owns a fresh state.
        return Ok(State::fresh(dispatch_digest));
    }
    Ok(state)
}

fn model_tier(tier: &str) -> &'static str {
    match tier {
        "mechanical" => "mechanical-cheap",
        "specialist" => "balanced-executor",
        _ => "judgment",
    }
}

fn adjudication_seat_id(key: &str) -> String {
    format!("adj-{}", &digest_hex(key.as_bytes())[..12])
}

/// Writes the deterministic seat packet for an adjudication item and returns
/// `(packet path, result path)`.
fn materialize(
    run_dir: &Path,
    context: &AdjContext,
    item: &AdjItem,
    seat_id: &str,
    round: u32,
) -> Result<(PathBuf, PathBuf), AuditError> {
    let body = if item.stage == BATCH_STAGE {
        let id = item.batch_id.as_deref().unwrap_or_default();
        let batch = context
            .batches
            .iter()
            .find(|batch| batch.get("batchId").and_then(Value::as_str) == Some(id))
            .ok_or_else(|| invalid(format!("adjudication batch {id} is not in the packet")))?;
        json!({
            "schemaVersion": 1,
            "kind": "legion-audit-adjudication-seat",
            "stage": BATCH_STAGE,
            "round": round,
            "batchId": id,
            "itemId": batch.get("itemId"),
            "contextId": batch.get("contextId"),
            "parentPacketDigest": context.parent_digest,
            "packet": batch.get("packet"),
        })
    } else {
        let id = item.candidate_id.as_deref().unwrap_or_default();
        let candidate = context
            .candidates
            .iter()
            .find(|candidate| candidate.finding_id == id)
            .ok_or_else(|| invalid(format!("adjudication candidate {id} is not in the packet")))?;
        let work = stage_work_item(candidate, &context.parent_digest, &item.stage)
            .map_err(|error| invalid(format!("adjudication item {}: {error}", item.key)))?;
        json!({
            "schemaVersion": 1,
            "kind": "legion-audit-adjudication-seat",
            "stage": item.stage,
            "round": round,
            "candidateId": id,
            "reason": item.reason,
            "itemId": work.item_id,
            "contextId": work.context_id,
            "parentPacketDigest": context.parent_digest,
            "packet": work.packet,
        })
    };
    let bytes = serde_json::to_vec_pretty(&body).map_err(|error| invalid(error.to_string()))?;
    let packet = write_file(
        &run_dir.join(ADJUDICATION_DIR).join("packets"),
        &format!("{seat_id}.json"),
        &bytes,
    )?;
    let result = run_dir
        .join(ADJUDICATION_DIR)
        .join("results")
        .join(format!("{seat_id}.json"));
    Ok((packet, result))
}

fn paths_json(paths: &[PathBuf]) -> Value {
    Value::Array(
        paths
            .iter()
            .map(|path| Value::String(path.to_string_lossy().into_owned()))
            .collect(),
    )
}

/// Computes the next ready wave for `run_dir`, records leases, and returns the
/// CLI document (`kind: legion-audit-next`).
pub fn next(run_dir: &Path, options: &NextOptions) -> Result<Value, AuditError> {
    let loaded = load(run_dir)?;
    let before = load_state(run_dir, &loaded.dispatch_digest)?;
    let mut state = before.clone();
    let decision = decide(
        &loaded.snapshot,
        &mut state,
        options.now_ms,
        options.lease_ms,
    );

    let mut seats_out: Vec<Value> = Vec::new();
    for (work, lease) in &decision.issued {
        match work.kind {
            Kind::Lens => {
                let Some(seat) = loaded.snapshot.seats.iter().find(|s| s.id == work.key) else {
                    continue;
                };
                let packets: Vec<PathBuf> = seat
                    .packets
                    .iter()
                    .map(|name| run_dir.join(LENS_PACKET_DIR).join(name))
                    .collect();
                let results: Vec<PathBuf> = seat
                    .packets
                    .iter()
                    .map(|name| {
                        let stem = name.strip_suffix(".json").unwrap_or(name);
                        run_dir.join(LENS_RESULT_DIR).join(format!("{stem}.json"))
                    })
                    .collect();
                seats_out.push(json!({
                    "seatId": seat.id,
                    "kind": "lens",
                    "wave": seat.wave,
                    "tier": seat.tier,
                    "modelTier": model_tier(&seat.tier),
                    "bundle": seat.bundle,
                    "providers": seat.providers,
                    "packetPaths": paths_json(&packets),
                    "resultPaths": paths_json(&results),
                    "estimatedTokens": seat.estimated_tokens,
                    "attempt": lease.attempts,
                    "issuedAtMs": lease.issued_at_ms,
                    "leaseExpiresAtMs": lease.expires_at_ms,
                }));
            }
            Kind::Adjudication => {
                let (Some(snapshot), Some(context)) =
                    (&loaded.snapshot.adjudication, &loaded.adjudication)
                else {
                    continue;
                };
                let Some(item) = snapshot.required.iter().find(|item| item.key == work.key) else {
                    continue;
                };
                let seat_id = adjudication_seat_id(&item.key);
                let (packet, result) =
                    materialize(run_dir, context, item, &seat_id, state.adjudication_round)?;
                seats_out.push(json!({
                    "seatId": seat_id,
                    "kind": "adjudication",
                    "key": item.key,
                    "stage": item.stage,
                    "round": state.adjudication_round,
                    "candidateId": item.candidate_id,
                    "batchId": item.batch_id,
                    "reason": item.reason,
                    "wave": Value::Null,
                    "tier": "judgment",
                    "modelTier": model_tier("judgment"),
                    "bundle": "adjudication",
                    "providers": [ADJUDICATOR_PROVIDER_ID],
                    "packetPaths": paths_json(&[packet]),
                    "resultPaths": paths_json(&[result]),
                    "estimatedTokens": item.tokens,
                    "attempt": lease.attempts,
                    "issuedAtMs": lease.issued_at_ms,
                    "leaseExpiresAtMs": lease.expires_at_ms,
                }));
            }
        }
    }

    if state != before {
        let bytes =
            serde_json::to_vec_pretty(&state).map_err(|error| invalid(error.to_string()))?;
        write_file(run_dir, STATE_FILE, &bytes)?;
    }

    let lens_total = loaded.snapshot.seats.len();
    let lens_done = loaded
        .snapshot
        .seats
        .iter()
        .filter(|seat| seat.done(&loaded.snapshot.done))
        .count();
    let adjudication = loaded.snapshot.adjudication.as_ref().map(|adj| {
        json!({
            "round": state.adjudication_round,
            "maxRounds": CONFIRMATION_ROUND,
            "required": adj.required.len(),
            "complete": adj.complete,
        })
    });
    let next_step = match decision.status.as_str() {
        "wave" => format!(
            "dispatch every seat (at most {} in parallel, each at its modelTier), write each result to its resultPaths, ingest the wave's results in one batch ingest, then run `legion audit next --run {}` again",
            loaded.snapshot.wave_width,
            run_dir.display()
        ),
        "done" => format!(
            "every seat is ingested; finish with `legion verify {}`",
            run_dir.display()
        ),
        _ => "the driver stopped; report the listed items as typed gaps and keep the audit incomplete".to_owned(),
    };
    Ok(json!({
        "schemaVersion": 1,
        "kind": OUTPUT_KIND,
        "run": run_dir,
        "status": decision.status,
        "wave": decision.wave,
        "leaseMs": options.lease_ms,
        "seats": seats_out,
        "progress": {
            "lensSeats": {"total": lens_total, "done": lens_done},
            "adjudication": adjudication,
            "issuances": state.issuances,
            "issuanceCap": loaded.snapshot.issuance_cap(),
            "attemptLimit": MAX_SEAT_ATTEMPTS,
            "waveWidth": loaded.snapshot.wave_width,
        },
        "exhausted": decision
            .exhausted
            .iter()
            .map(|(item, reason)| json!({"item": item, "reason": reason}))
            .collect::<Vec<_>>(),
        "budgetBlocked": decision.budget_blocked,
        "blockers": decision.blockers,
        "next": next_step,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const LEASE: u64 = 1_000;

    fn seat(number: u64, wave: u64, tier: &str) -> LensSeat {
        LensSeat {
            id: format!("seat-{number:03}"),
            number,
            wave,
            tier: tier.to_owned(),
            bundle: "J1".to_owned(),
            providers: vec![format!("reasoning.p{number}")],
            packets: vec![format!("reasoning.p{number}.json")],
            estimated_tokens: 100,
        }
    }

    fn snapshot(seats: Vec<LensSeat>) -> Snapshot {
        Snapshot {
            plan_seats: seats.len() as u64,
            seats,
            done: BTreeSet::new(),
            adjudication: None,
            adjudication_candidates: 0,
            wave_width: 16,
            budget: None,
        }
    }

    fn keys(decision: &Decision) -> Vec<String> {
        decision
            .issued
            .iter()
            .map(|(work, _)| work.key.clone())
            .collect()
    }

    fn adj_item(stage: &str, id: &str, reason: Option<&str>) -> AdjItem {
        let batch = stage == BATCH_STAGE;
        AdjItem {
            key: format!("{stage}:{id}"),
            stage: stage.to_owned(),
            candidate_id: (!batch).then(|| id.to_owned()),
            batch_id: batch.then(|| id.to_owned()),
            reason: reason.map(ToOwned::to_owned),
            tokens: 10,
        }
    }

    fn adjudication(required: Vec<AdjItem>, candidates: u64) -> (AdjSnapshot, u64) {
        (
            AdjSnapshot {
                required,
                blockers: Vec::new(),
                complete: false,
            },
            candidates,
        )
    }

    fn set_adjudication(snap: &mut Snapshot, required: Vec<AdjItem>, candidates: u64) {
        let (adj, count) = adjudication(required, candidates);
        snap.adjudication = Some(adj);
        snap.adjudication_candidates = count;
    }

    #[test]
    fn repeated_calls_return_the_same_wave_and_issue_nothing_new() {
        let mut snap = snapshot(vec![
            seat(1, 1, "judgment"),
            seat(2, 1, "specialist"),
            seat(3, 2, "mechanical"),
        ]);
        let mut state = State::fresh("d");
        let first = decide(&snap, &mut state, 10, LEASE);
        assert_eq!(first.status, "wave");
        assert_eq!(first.wave, Some(1));
        assert_eq!(keys(&first), ["seat-001", "seat-002"]);
        assert_eq!(state.issuances, 2);
        let frozen = state.clone();
        let second = decide(&snap, &mut state, 500, LEASE);
        assert_eq!(keys(&second), keys(&first));
        assert_eq!(
            state, frozen,
            "no results, no new issuance, no state change"
        );
        assert_eq!(
            second.issued[0].1, first.issued[0].1,
            "same lease, not a new one"
        );

        // Wave 2 opens only once wave 1 has results.
        snap.done.insert("reasoning.p1.json".to_owned());
        snap.done.insert("reasoning.p2.json".to_owned());
        let third = decide(&snap, &mut state, 600, LEASE);
        assert_eq!(keys(&third), ["seat-003"]);
        assert_eq!(third.wave, Some(2));
        snap.done.insert("reasoning.p3.json".to_owned());
        assert_eq!(decide(&snap, &mut state, 700, LEASE).status, "done");
    }

    #[test]
    fn expired_lease_reissues_the_seat_and_counts_an_attempt() {
        let snap = snapshot(vec![seat(1, 1, "judgment")]);
        let mut state = State::fresh("d");
        let first = decide(&snap, &mut state, 0, LEASE);
        assert_eq!(first.issued[0].1.attempts, 1);
        let again = decide(&snap, &mut state, LEASE, LEASE);
        assert_eq!(again.status, "wave");
        assert_eq!(again.issued[0].1.attempts, 2);
        assert_eq!(again.issued[0].1.expires_at_ms, 2 * LEASE);
        assert_eq!(state.issuances, 2);
    }

    #[test]
    fn a_seat_gets_two_attempts_then_the_run_is_retry_exhausted() {
        let mut snap = snapshot(vec![seat(1, 1, "judgment"), seat(2, 1, "judgment")]);
        let mut state = State::fresh("d");
        decide(&snap, &mut state, 0, LEASE);
        decide(&snap, &mut state, LEASE, LEASE);
        // Seat 2 finishes late on its second attempt; seat 1 never answers.
        snap.done.insert("reasoning.p2.json".to_owned());
        let last = decide(&snap, &mut state, 2 * LEASE, LEASE);
        assert_eq!(last.status, "incomplete:retry-exhausted");
        assert_eq!(
            last.exhausted,
            [("seat-001".to_owned(), "attempts".to_owned())]
        );
        assert!(last.issued.is_empty());
        assert_eq!(state.issuances, 4);
        // Stable: asking again changes nothing.
        let frozen = state.clone();
        assert_eq!(
            decide(&snap, &mut state, 9 * LEASE, LEASE).status,
            last.status
        );
        assert_eq!(state, frozen);
    }

    #[test]
    fn a_late_result_beats_an_exhausted_lease() {
        let mut snap = snapshot(vec![seat(1, 1, "judgment")]);
        let mut state = State::fresh("d");
        decide(&snap, &mut state, 0, LEASE);
        decide(&snap, &mut state, LEASE, LEASE);
        assert_eq!(
            decide(&snap, &mut state, 3 * LEASE, LEASE).status,
            "incomplete:retry-exhausted"
        );
        snap.done.insert("reasoning.p1.json".to_owned());
        assert_eq!(decide(&snap, &mut state, 3 * LEASE, LEASE).status, "done");
    }

    #[test]
    fn waves_never_exceed_the_width_and_the_rest_follow() {
        let seats: Vec<LensSeat> = (1..=20).map(|n| seat(n, 1, "mechanical")).collect();
        let mut snap = snapshot(seats);
        let mut state = State::fresh("d");
        let first = decide(&snap, &mut state, 0, LEASE);
        assert_eq!(first.issued.len(), 16);
        assert_eq!(decide(&snap, &mut state, 1, LEASE).issued.len(), 16);
        assert_eq!(state.issuances, 16);
        for n in 1..=16 {
            snap.done.insert(format!("reasoning.p{n}.json"));
        }
        let rest = decide(&snap, &mut state, 2, LEASE);
        assert_eq!(
            keys(&rest),
            ["seat-017", "seat-018", "seat-019", "seat-020"]
        );
    }

    #[test]
    fn adjudication_rounds_progress_through_voided_batch_fallback() {
        let mut snap = snapshot(Vec::new());
        let mut state = State::fresh("d");

        // Round 1: the two cluster batches.
        set_adjudication(
            &mut snap,
            vec![
                adj_item(BATCH_STAGE, "batch-0001", None),
                adj_item(BATCH_STAGE, "batch-0002", None),
            ],
            4,
        );
        let round1 = decide(&snap, &mut state, 0, LEASE);
        assert_eq!(keys(&round1), ["batch:batch-0001", "batch:batch-0002"]);
        assert_eq!(state.adjudication_round, 1);
        assert!(round1
            .issued
            .iter()
            .all(|(w, _)| w.kind == Kind::Adjudication));
        // Same call again: same round, nothing new.
        let frozen = state.clone();
        assert_eq!(keys(&decide(&snap, &mut state, 5, LEASE)), keys(&round1));
        assert_eq!(state, frozen);

        // Batches ingested: confirmations, spot-checks and a high-risk
        // dismissal are all required now (round 2).
        set_adjudication(
            &mut snap,
            vec![
                adj_item(STAGE_CONFIRMATION, "c3", None),
                adj_item(STAGE_SPOT_CHECK, "c1", None),
                adj_item(STAGE_INDIVIDUAL, "c2", Some("high-risk-dismissal")),
            ],
            4,
        );
        let round2 = decide(&snap, &mut state, 10, LEASE);
        assert_eq!(state.adjudication_round, 2);
        assert_eq!(round2.issued.len(), 3);

        // The spot-check disagreed: its batch is voided and its candidates
        // need per-candidate reruns, which wait for round 2 to drain first.
        set_adjudication(
            &mut snap,
            vec![
                adj_item(STAGE_SPOT_CHECK, "c1", None),
                adj_item(STAGE_INDIVIDUAL, "c9", Some("voided-batch")),
            ],
            4,
        );
        let waiting = decide(&snap, &mut state, 20, LEASE);
        assert_eq!(state.adjudication_round, 2, "round 2 still has a live item");
        assert_eq!(keys(&waiting), ["spotCheck:c1"]);

        // Round 2 finished: the voided-batch rerun opens round 3.
        set_adjudication(
            &mut snap,
            vec![adj_item(STAGE_INDIVIDUAL, "c9", Some("voided-batch"))],
            4,
        );
        let round3 = decide(&snap, &mut state, 30, LEASE);
        assert_eq!(state.adjudication_round, 3);
        assert_eq!(keys(&round3), ["individual:c9"]);

        // The rerun survived and now needs a confirmation: the
        // confirmation-only fourth round admits it.
        set_adjudication(&mut snap, vec![adj_item(STAGE_CONFIRMATION, "c9", None)], 4);
        let round4 = decide(&snap, &mut state, 40, LEASE);
        assert_eq!(round4.status, "wave");
        assert_eq!(state.adjudication_round, CONFIRMATION_ROUND);
        assert_eq!(keys(&round4), ["confirmation:c9"]);

        // Confirmed: nothing is required and the run reaches done.
        if let Some(adj) = snap.adjudication.as_mut() {
            adj.required.clear();
            adj.complete = true;
        }
        assert_eq!(decide(&snap, &mut state, 50, LEASE).status, "done");
    }

    #[test]
    fn round_four_admits_only_confirmations_and_nothing_beyond() {
        let mut snap = snapshot(Vec::new());
        let mut state = State::fresh("d");
        state.adjudication_round = MAX_ADJUDICATION_ROUNDS;
        // Round 3 finished; a confirmation and a non-confirmation appear.
        set_adjudication(
            &mut snap,
            vec![
                adj_item(STAGE_CONFIRMATION, "c1", None),
                adj_item(STAGE_INDIVIDUAL, "c2", Some("voided-batch")),
            ],
            4,
        );
        let round4 = decide(&snap, &mut state, 0, LEASE);
        assert_eq!(keys(&round4), ["confirmation:c1"]);
        assert_eq!(
            round4.exhausted,
            [("individual:c2".to_owned(), "round-limit".to_owned())]
        );
        // Round 4 drains; a further confirmation would be a fifth round.
        set_adjudication(&mut snap, vec![adj_item(STAGE_CONFIRMATION, "c3", None)], 4);
        let fifth = decide(&snap, &mut state, 10, LEASE);
        assert_eq!(fifth.status, "incomplete:retry-exhausted");
        assert_eq!(
            fifth.exhausted,
            [("confirmation:c3".to_owned(), "round-limit".to_owned())]
        );
        assert_eq!(state.adjudication_round, CONFIRMATION_ROUND);
    }

    #[test]
    fn a_completed_adjudication_and_lens_set_is_done() {
        let mut snap = snapshot(vec![seat(1, 1, "judgment")]);
        snap.done.insert("reasoning.p1.json".to_owned());
        set_adjudication(&mut snap, Vec::new(), 2);
        if let Some(adj) = snap.adjudication.as_mut() {
            adj.complete = true;
        }
        let mut state = State::fresh("d");
        let decision = decide(&snap, &mut state, 0, LEASE);
        assert_eq!(decision.status, "done");
        assert_eq!(state, State::fresh("d"));
    }

    #[test]
    fn contested_confirmations_end_the_run_incomplete() {
        let mut snap = snapshot(Vec::new());
        set_adjudication(&mut snap, Vec::new(), 1);
        if let Some(adj) = snap.adjudication.as_mut() {
            adj.blockers.push("contested:c1".to_owned());
        }
        let mut state = State::fresh("d");
        assert_eq!(
            decide(&snap, &mut state, 0, LEASE).status,
            "incomplete:adjudication-contested"
        );
    }

    #[test]
    fn the_total_issuance_cap_stops_new_leases() {
        // No plan seats and one candidate: cap = 3 issuances.
        let mut snap = snapshot(Vec::new());
        snap.plan_seats = 0;
        set_adjudication(
            &mut snap,
            (1..=4)
                .map(|n| adj_item(BATCH_STAGE, &format!("b{n}"), None))
                .collect(),
            1,
        );
        let mut state = State::fresh("d");
        let first = decide(&snap, &mut state, 0, LEASE);
        assert_eq!(first.status, "wave");
        assert_eq!(first.issued.len(), 3);
        assert_eq!(state.issuances, 3);
        assert_eq!(
            first.exhausted,
            [("batch:b4".to_owned(), "issuance-cap".to_owned())]
        );
        // Everything leased expires: reissues are refused too.
        let after = decide(&snap, &mut state, LEASE, LEASE);
        assert_eq!(after.status, "incomplete:retry-exhausted");
        assert_eq!(state.issuances, 3);
        assert_eq!(after.exhausted.len(), 4);
    }

    #[test]
    fn an_exhausted_reasoning_budget_is_reported_as_budget_exhausted() {
        let mut snap = snapshot(vec![seat(1, 1, "judgment")]);
        snap.budget = Some(Budget {
            judgment: Some(50),
            ..Budget::default()
        });
        let mut state = State::fresh("d");
        let decision = decide(&snap, &mut state, 0, LEASE);
        assert_eq!(decision.status, "budget-exhausted");
        assert_eq!(decision.budget_blocked, ["seat-001"]);
        assert_eq!(state.issuances, 0);

        // A budget that allows one seat of two spends it and blocks the rest.
        let mut two = snapshot(vec![seat(1, 1, "specialist"), seat(2, 1, "specialist")]);
        two.budget = Some(Budget {
            specialist: Some(150),
            ..Budget::default()
        });
        let mut state = State::fresh("d");
        let decision = decide(&two, &mut state, 0, LEASE);
        assert_eq!(decision.status, "wave");
        assert_eq!(keys(&decision), ["seat-001"]);
        assert_eq!(decision.budget_blocked, ["seat-002"]);
        two.done.insert("reasoning.p1.json".to_owned());
        assert_eq!(
            decide(&two, &mut state, 1, LEASE).status,
            "budget-exhausted"
        );
    }

    #[test]
    fn parser_accepts_exactly_what_the_ledger_producer_emits() {
        use crate::native_providers::reasoning::security_adjudication::{
            outstanding_batch, outstanding_individual, outstanding_stage,
        };
        let batches = vec![json!({"batchId": "batch-0001", "estimatedTokens": 77})];
        let batch = parse_outstanding(&outstanding_batch("batch-0001", 2), &batches).unwrap();
        assert_eq!(batch.key, "batch:batch-0001");
        assert_eq!(batch.tokens, 77);
        let spot =
            parse_outstanding(&outstanding_stage(STAGE_SPOT_CHECK, "a:b"), &batches).unwrap();
        assert_eq!(
            (spot.key.as_str(), spot.candidate_id.as_deref()),
            ("spotCheck:a:b", Some("a:b"))
        );
        let confirm =
            parse_outstanding(&outstanding_stage(STAGE_CONFIRMATION, "a:b"), &batches).unwrap();
        assert_eq!(confirm.key, "confirmation:a:b");
        let individual =
            parse_outstanding(&outstanding_individual("a:b", "voided-batch"), &batches).unwrap();
        assert_eq!(individual.key, "individual:a:b");
        assert_eq!(individual.candidate_id.as_deref(), Some("a:b"));
        assert_eq!(individual.reason.as_deref(), Some("voided-batch"));
    }

    // -- filesystem layer ---------------------------------------------------

    fn temp_run(name: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let dir = std::env::temp_dir().join(format!(
            "legion-next-{name}-{}-{nanos}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(dir.join(LENS_PACKET_DIR)).unwrap();
        dir
    }

    fn write_value(path: &Path, value: &Value) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
    }

    fn options(now_ms: u64) -> NextOptions {
        NextOptions {
            now_ms,
            lease_ms: LEASE,
        }
    }

    #[test]
    fn next_is_idempotent_on_disk_and_follows_receipts() {
        let run = temp_run("idempotent");
        write_value(
            &run.join(DISPATCH_FILE),
            &json!({
                "limits": {"waveWidth": 16},
                "seats": [
                    {"seat": 1, "seatId": "seat-001", "wave": 1, "tier": "judgment", "bundle": "J1",
                     "providers": ["reasoning.security"], "packets": ["reasoning.security.json"], "estimatedTokens": 10},
                    {"seat": 2, "seatId": "seat-002", "wave": 2, "tier": "mechanical", "bundle": "M1",
                     "providers": ["reasoning.naming"], "packets": ["reasoning.naming.part-0001.json", "reasoning.naming.part-0002.json"], "estimatedTokens": 5},
                ],
            }),
        );
        let first = next(&run, &options(100)).unwrap();
        assert_eq!(first["status"], "wave");
        assert_eq!(first["wave"], 1);
        assert_eq!(first["seats"][0]["seatId"], "seat-001");
        assert_eq!(first["seats"][0]["modelTier"], "judgment");
        let state_before = fs::read(run.join(STATE_FILE)).unwrap();
        let second = next(&run, &options(200)).unwrap();
        assert_eq!(second, first, "same wave until results arrive");
        assert_eq!(fs::read(run.join(STATE_FILE)).unwrap(), state_before);

        write_value(
            &run.join(LENS_RECEIPT_DIR).join("reasoning.security.json"),
            &json!({"provider": "reasoning.security"}),
        );
        let wave2 = next(&run, &options(300)).unwrap();
        assert_eq!(wave2["wave"], 2);
        assert_eq!(wave2["seats"][0]["seatId"], "seat-002");
        assert_eq!(wave2["seats"][0]["modelTier"], "mechanical-cheap");
        assert_eq!(
            wave2["seats"][0]["packetPaths"].as_array().unwrap().len(),
            2
        );
        assert!(wave2["seats"][0]["resultPaths"][1]
            .as_str()
            .unwrap()
            .replace('\\', "/")
            .ends_with("lens-results/reasoning.naming.part-0002.json"));

        // One of the two parts is not enough.
        write_value(
            &run.join(LENS_RECEIPT_DIR)
                .join("reasoning.naming.part-0001.json"),
            &json!({"provider": "reasoning.naming"}),
        );
        assert_eq!(next(&run, &options(400)).unwrap()["status"], "wave");
        write_value(
            &run.join(LENS_RECEIPT_DIR)
                .join("reasoning.naming.part-0002.json"),
            &json!({"provider": "reasoning.naming"}),
        );
        let done = next(&run, &options(500)).unwrap();
        assert_eq!(done["status"], "done");
        assert!(done["seats"].as_array().unwrap().is_empty());
        let _ = fs::remove_dir_all(&run);
    }

    #[test]
    fn a_refrozen_plan_starts_a_fresh_state() {
        let run = temp_run("refrozen");
        let plan = |packet: &str| json!({"seats": [{"seat": 1, "wave": 1, "tier": "judgment", "providers": ["reasoning.a"], "packets": [packet]}]});
        write_value(&run.join(DISPATCH_FILE), &plan("reasoning.a.json"));
        next(&run, &options(0)).unwrap();
        next(&run, &options(LEASE)).unwrap();
        assert_eq!(
            next(&run, &options(3 * LEASE)).unwrap()["status"],
            "incomplete:retry-exhausted"
        );
        write_value(&run.join(DISPATCH_FILE), &plan("reasoning.b.json"));
        let fresh = next(&run, &options(3 * LEASE)).unwrap();
        assert_eq!(fresh["status"], "wave");
        assert_eq!(fresh["seats"][0]["seatId"], "seat-001");
        assert_eq!(fresh["seats"][0]["attempt"], 1);
        let _ = fs::remove_dir_all(&run);
    }

    #[test]
    fn next_materialises_adjudication_seats_from_the_ledger() {
        let run = temp_run("adjudication");
        let adjudicator = format!("{ADJUDICATOR_PROVIDER_ID}.json");
        write_value(
            &run.join(DISPATCH_FILE),
            &json!({
                "seats": [{"seat": 1, "seatId": "seat-001", "wave": 1, "tier": "judgment", "bundle": "A",
                           "providers": [ADJUDICATOR_PROVIDER_ID], "packets": [adjudicator]}],
            }),
        );
        write_value(
            &run.join(LENS_PACKET_DIR).join(&adjudicator),
            &json!({
                "providerId": ADJUDICATOR_PROVIDER_ID,
                "request": {"packet": {
                    "scannerCandidates": [{
                        "findingId": "cand-1", "provider": "scan.secrets", "rule": "secret.token",
                        "severity": "high", "path": "src/a.rs", "line": 3,
                        "message": "hard coded token value", "evidenceExcerpt": "let token = value;"
                    }],
                    "candidateWorkItems": {
                        "batches": [{"batchId": "batch-0001", "itemId": "sha256:i", "contextId": "adjudicator:i",
                                     "estimatedTokens": 50, "packet": {"kind": "security-batch-adjudication-packet"}}],
                        "clusters": [{"clusterId": "k1", "memberIds": ["cand-1"]}],
                    },
                }},
            }),
        );
        let round1 = next(&run, &options(0)).unwrap();
        assert_eq!(round1["status"], "wave");
        assert_eq!(round1["seats"][0]["kind"], "adjudication");
        assert_eq!(round1["seats"][0]["stage"], "batch");
        assert_eq!(round1["progress"]["adjudication"]["round"], 1);
        let packet_path = PathBuf::from(round1["seats"][0]["packetPaths"][0].as_str().unwrap());
        let batch_packet = read_json(&packet_path).unwrap();
        assert_eq!(batch_packet["batchId"], "batch-0001");
        assert_eq!(batch_packet["contextId"], "adjudicator:i");
        assert_eq!(next(&run, &options(10)).unwrap(), round1);

        // The batch was ingested and the ledger asks for a spot-check.
        write_value(
            &run.join(LENS_RECEIPT_DIR).join(&adjudicator),
            &json!({"provider": ADJUDICATOR_PROVIDER_ID, "result": {"details": {"adjudicationLedger": {"ledger": {
                "complete": false,
                "outstanding": ["spotCheck:cand-1", "contested:cand-7"],
            }}}}}),
        );
        let round2 = next(&run, &options(20)).unwrap();
        assert_eq!(round2["status"], "wave");
        assert_eq!(round2["seats"][0]["stage"], "spotCheck");
        assert_eq!(round2["seats"][0]["candidateId"], "cand-1");
        assert_eq!(round2["progress"]["adjudication"]["round"], 2);
        assert_eq!(round2["blockers"][0], "contested:cand-7");
        let stage_packet = read_json(&PathBuf::from(
            round2["seats"][0]["packetPaths"][0].as_str().unwrap(),
        ))
        .unwrap();
        assert_eq!(stage_packet["stage"], "spotCheck");
        assert_eq!(
            stage_packet["packet"]["candidate"]["id"], "cand-1",
            "the single-candidate work item carries only that candidate"
        );

        // Spot-check done; only the contested confirmation remains.
        write_value(
            &run.join(LENS_RECEIPT_DIR).join(&adjudicator),
            &json!({"provider": ADJUDICATOR_PROVIDER_ID, "result": {"details": {"adjudicationLedger": {"ledger": {
                "complete": false,
                "outstanding": ["contested:cand-7"],
            }}}}}),
        );
        let stopped = next(&run, &options(30)).unwrap();
        assert_eq!(stopped["status"], "incomplete:adjudication-contested");

        write_value(
            &run.join(LENS_RECEIPT_DIR).join(&adjudicator),
            &json!({"provider": ADJUDICATOR_PROVIDER_ID, "result": {"details": {"adjudicationLedger": {"ledger": {
                "complete": true,
                "outstanding": [],
            }}}}}),
        );
        assert_eq!(next(&run, &options(40)).unwrap()["status"], "done");
        let _ = fs::remove_dir_all(&run);
    }
}
