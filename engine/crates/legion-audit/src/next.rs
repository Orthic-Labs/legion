//! `legion audit next --run <dir>`: the resumable dispatch driver (audit v2,
//! ADR-3).
//!
//! `next` is a pure function of three inputs and one small piece of recorded
//! state:
//!
//! * the frozen plan, `lens-dispatch.json` (`seatId`, `wave`, `tier`, packets
//!   per seat, required bounded `reasoningBudget`);
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
//! candidates`; a required frozen reasoning budget. Hitting a limit ends the
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
/// Default output reservation for legacy dispatch plans. Never an input estimate.
pub const DEFAULT_OUTPUT_TOKENS: u64 = 4_096;

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
    /// Monotonic reservations. Unknown usage never releases admission capacity.
    #[serde(default)]
    reservations: BTreeMap<String, Reservation>,
    #[serde(default)]
    terminal_status: Option<String>,
    #[serde(default)]
    budget_blocked: Vec<String>,
}

impl State {
    fn fresh(dispatch_digest: &str) -> Self {
        Self {
            schema_version: 2,
            kind: STATE_KIND.to_owned(),
            dispatch_digest: dispatch_digest.to_owned(),
            issuances: 0,
            spent: BTreeMap::new(),
            leases: BTreeMap::new(),
            adjudication_round: 0,
            round_keys: Vec::new(),
            reservations: BTreeMap::new(),
            terminal_status: None,
            budget_blocked: Vec::new(),
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
    total: u64,
    per_call: u64,
    output: u64,
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
        self.plan_seats
            .saturating_mul(2)
            .saturating_add(self.adjudication_candidates.saturating_mul(3))
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

/// Admission uses persisted reservations, not claimed physical usage. Actual
/// usage above reservation increases spend; unknown/below-reservation usage
/// retains its reservation, so a late receipt cannot replay freed capacity.
fn budget_allows(snapshot: &Snapshot, state: &State, tier: &str, tokens: u64) -> bool {
    let Some(budget) = &snapshot.budget else {
        return false;
    };
    budget_allows_tokens(budget, state, tier, tokens, true)
}

fn budget_allows_tokens(
    budget: &Budget,
    state: &State,
    tier: &str,
    tokens: u64,
    new_call: bool,
) -> bool {
    if new_call && budget.max_seats.is_none_or(|max| state.issuances >= max) {
        return false;
    }
    let limit = match tier {
        "specialist" => budget.specialist,
        "mechanical" => budget.mechanical,
        "judgment" => budget.judgment,
        _ => return false,
    }
    .unwrap_or(budget.total);
    let total = state
        .spent
        .values()
        .fold(0u64, |sum, value| sum.saturating_add(*value));
    state.terminal_status.is_none()
        && total
            .checked_add(tokens)
            .is_some_and(|sum| sum <= budget.total)
        && state
            .spent
            .get(tier)
            .copied()
            .unwrap_or(0)
            .checked_add(tokens)
            .is_some_and(|sum| sum <= limit)
        && (!new_call || tokens <= budget.per_call)
}

/// Byte-derived planning heuristic, not a provider token count. The host must
/// preflight the complete rendered request before send; physical authorization
/// reserves the full frozen per-call allowance because native overhead and
/// tokenization are not known in advance.
pub fn estimated_request_tokens(rendered_bytes: u64, output_tokens: u64) -> u64 {
    rendered_bytes.div_ceil(4).saturating_add(output_tokens)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Reservation {
    call_id: String,
    tier: String,
    planned_tokens: u64,
    reserved_tokens: u64,
    output_token_limit: u64,
    retry: bool,
    transport_authorized: bool,
    usage: Option<UsageReceipt>,
    #[serde(default)]
    native_cost_required: bool,
    #[serde(default)]
    reported_api_cost_usd: Option<String>,
}

/// Host input for every physical model attempt, including reflection, retry,
/// correction & requests containing tool replies. Never count unread tool data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetCall {
    /// `next` reservation for the first transport, or None for an extra call.
    pub reservation_id: Option<String>,
    pub call_id: String,
    pub tier: String,
    pub rendered_request_bytes: u64,
    pub output_token_limit: u64,
    pub retry: bool,
}

/// Trusted host usage. Cached input is a subset of input_tokens; retry_tokens
/// records additional provider retry usage NOT already in input/output. Each
/// host-controlled retry still needs its own reservation before transport.
/// None means unknown, including failures with no provider usage response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageReceipt {
    pub reservation_id: String,
    pub receipt_id: String,
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub retry_tokens: Option<u64>,
    pub failed: bool,
}

fn reservation_id(dispatch_digest: &str, key: &str, attempt: u32) -> String {
    digest_hex(format!("{dispatch_digest}\0{key}\0{attempt}").as_bytes())
}

fn record_reservation(
    state: &mut State,
    key: &str,
    attempt: u32,
    tier: &str,
    tokens: u64,
    output: u64,
) -> String {
    let id = reservation_id(&state.dispatch_digest, key, attempt);
    state.reservations.insert(
        id.clone(),
        Reservation {
            call_id: format!("{key}:attempt-{attempt}"),
            tier: tier.to_owned(),
            planned_tokens: tokens,
            reserved_tokens: tokens,
            output_token_limit: output,
            retry: attempt > 1,
            transport_authorized: false,
            usage: None,
            native_cost_required: false,
            reported_api_cost_usd: None,
        },
    );
    id
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
    if let Some(status) = &state.terminal_status {
        return Decision {
            status: status.clone(),
            wave: None,
            issued: Vec::new(),
            exhausted: Vec::new(),
            budget_blocked: state.budget_blocked.clone(),
            blockers: Vec::new(),
        };
    }
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
    let previously_blocked = !state.budget_blocked.is_empty();
    let mut budget_blocked: Vec<String> = state.budget_blocked.clone();
    for item in pending {
        if capacity == 0 {
            break;
        }
        if state.issuances >= cap {
            exhausted.push((item.key.clone(), "issuance-cap".to_owned()));
            continue;
        }
        if previously_blocked || !budget_allows(snapshot, state, &item.tier, item.tokens) {
            if !budget_blocked.contains(&item.key) {
                budget_blocked.push(item.key.clone());
            }
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
        let spent = state.spent.entry(item.tier.clone()).or_insert(0);
        *spent = spent.saturating_add(item.tokens);
        record_reservation(
            state,
            &item.key,
            attempts,
            &item.tier,
            item.tokens,
            snapshot.budget.as_ref().map_or(0, |budget| budget.output),
        );
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
    if !budget_blocked.is_empty() {
        state.budget_blocked = budget_blocked.clone();
        // Existing in-flight calls can finish, but no correction/retry/new call
        // can be authorized after exhaustion. Candidate receipts remain intact.
        if returned.is_empty() {
            state.terminal_status = Some(status.clone());
        }
    }
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
    fs::OpenOptions::new()
        .write(true)
        .open(&temporary)
        .and_then(|file| file.sync_all())
        .map_err(|error| invalid(format!("could not sync {}: {error}", temporary.display())))?;
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

fn parse_budget(dispatch: &Value) -> Result<Budget, AuditError> {
    let positive = |value: Option<&Value>, name: &str| -> Result<u64, AuditError> {
        value
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
            .ok_or_else(|| {
                invalid(format!(
                    "reasoning budget missing/malformed positive {name}"
                ))
            })
    };
    let (source, total, per_call, output, max_seats) =
        if let Some(source) = dispatch.get("reasoningBudget") {
            if !source.is_object() {
                return Err(invalid("reasoningBudget must be an object"));
            }
            if source.get("schemaVersion").is_some() {
                if source.get("schemaVersion").and_then(Value::as_u64) != Some(2) {
                    return Err(invalid("unsupported reasoningBudget schemaVersion"));
                }
                (
                    source,
                    positive(source.get("totalTokens"), "totalTokens")?,
                    positive(source.get("perCallTokens"), "perCallTokens")?,
                    positive(source.get("outputTokens"), "outputTokens")?,
                    positive(source.get("maxSeats"), "maxSeats")?,
                )
            } else {
                // Explicit legacy top-level migration. Every declared tier must be
                // valid, & their sum becomes the immutable total bound.
                let mut total = 0u64;
                for tier in ["judgment", "specialist", "mechanical"] {
                    if let Some(value) = source.get(tier) {
                        total = total
                            .checked_add(positive(Some(value), tier)?)
                            .ok_or_else(|| invalid("legacy reasoning budget overflow"))?;
                    }
                }
                if total == 0 {
                    return Err(invalid("legacy reasoningBudget has no bounded tiers"));
                }
                (
                    source,
                    total,
                    total,
                    DEFAULT_OUTPUT_TOKENS.min(total),
                    positive(source.get("maxSeats"), "maxSeats")?,
                )
            }
        } else {
            // Old producer wrote limits.*. Migrate explicitly; missing fields are
            // errors rather than an unlimited plan.
            let source = dispatch
                .get("limits")
                .ok_or_else(|| invalid("reasoning budget missing"))?;
            let total = positive(source.get("runTokenBudget"), "limits.runTokenBudget")?;
            let per_call = positive(source.get("seatTokenBudget"), "limits.seatTokenBudget")?;
            (
                source,
                total,
                per_call,
                DEFAULT_OUTPUT_TOKENS.min(per_call),
                positive(source.get("maxTotalSeats"), "limits.maxTotalSeats")?,
            )
        };
    if output > per_call || per_call > total {
        return Err(invalid(
            "reasoning budget requires outputTokens <= perCallTokens <= totalTokens",
        ));
    }
    let tier = |name: &str| -> Result<Option<u64>, AuditError> {
        source
            .get(name)
            .map(|value| positive(Some(value), name))
            .transpose()
    };
    Ok(Budget {
        total,
        per_call,
        output,
        max_seats: Some(max_seats),
        judgment: tier("judgment")?,
        specialist: tier("specialist")?,
        mechanical: tier("mechanical")?,
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
            .unwrap_or(0)
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
                tokens: 0,
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
            tokens: 0,
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
                if complete && !packet_receipt_complete(&receipt) {
                    complete = false;
                    blockers.push("evidence-incomplete".to_owned());
                }
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
                    .unwrap_or(0),
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

fn packet_receipt_complete(receipt: &Value) -> bool {
    if receipt.pointer("/result/complete").and_then(Value::as_bool) == Some(true) {
        return true;
    }
    // A numbered part carries the deliberate provider-scope gap until every
    // other part lands. It is finished only if that is its sole gap & trusted
    // host delivery/verification evidence exists for its own bytes.
    receipt.get("part").is_some()
        && receipt
            .pointer("/result/details/deliveryEvidence")
            .is_some()
        && receipt
            .pointer("/result/details/verificationEvidence")
            .is_some()
        && receipt
            .pointer("/result/coverage_gaps")
            .and_then(Value::as_array)
            .is_some_and(|gaps| {
                !gaps.is_empty()
                    && gaps.iter().all(|gap| {
                        gap.as_str()
                            .is_some_and(|gap| gap.starts_with("reasoning-part-scope:"))
                    })
            })
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
                let receipt = read_json(&entry.path())?;
                if packet_receipt_complete(&receipt) {
                    done.insert(name);
                }
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
    let budget = parse_budget(&dispatch)?;
    let runtime_encoding =
        dispatch.get("requestEncoding").and_then(Value::as_str) == Some("runtime-initial-v1");
    if runtime_encoding {
        let gather_calls = seats
            .iter()
            .filter(|seat| {
                seat.providers.iter().any(|provider| {
                    crate::native_providers::reasoning::lens_plan::lens_id_for_provider(provider)
                        != Some("dead-file")
                })
            })
            .count() as u64;
        let required_calls = plan_seats
            .saturating_add(gather_calls)
            .saturating_add(u64::from(plan_seats > 0));
        let required_tokens = required_calls.saturating_mul(budget.per_call);
        if required_calls > budget.max_seats.unwrap_or(0) || required_tokens > budget.total {
            return Err(AuditError::BoundExceeded(format!("audit budget infeasible before generation: {plan_seats} author seats + {gather_calls} cheap gathering calls + verification/context reserve require {required_calls} calls & {required_tokens} reserved tokens; limits permit {} calls & {} tokens. Narrow scope/lenses or increase budget; mandatory coverage was not reduced", budget.max_seats.unwrap_or(0), budget.total)));
        }
    }

    let mut sizer = crate::review_runtime::InitialRequestSizer::default();
    for seat in &mut seats {
        let mut bytes = 0u64;
        let mut work = Vec::new();
        for packet in &seat.packets {
            if Path::new(packet).file_name().and_then(|name| name.to_str()) != Some(packet.as_str())
            {
                return Err(invalid(
                    "lens packet must be a file name inside lens-packets",
                ));
            }
            let content =
                fs::read(run_dir.join(LENS_PACKET_DIR).join(packet)).map_err(|error| {
                    invalid(format!(
                        "budget cannot read delivered packet {packet}: {error}"
                    ))
                })?;
            bytes = bytes.saturating_add(content.len() as u64);
            if runtime_encoding {
                work.push(
                    serde_json::from_slice::<crate::native_providers::reasoning::PendingLensWork>(
                        &content,
                    )
                    .map_err(|error| {
                        invalid(format!("budget packet {packet} is malformed: {error}"))
                    })?,
                );
            }
        }
        if runtime_encoding {
            bytes = sizer.request_bytes(&work)?;
        }
        seat.estimated_tokens = estimated_request_tokens(bytes, budget.output);
    }
    if let (Some(snapshot), Some(context)) = (&mut adjudication, &context) {
        for item in &mut snapshot.required {
            let body = adjudication_body(context, item, CONFIRMATION_ROUND)?;
            let bytes =
                serde_json::to_vec_pretty(&body).map_err(|error| invalid(error.to_string()))?;
            item.tokens = estimated_request_tokens(bytes.len() as u64, budget.output);
        }
    }
    Ok(Loaded {
        snapshot: Snapshot {
            seats,
            plan_seats,
            done,
            adjudication,
            adjudication_candidates,
            wave_width: width,
            budget: Some(budget),
        },
        dispatch_digest: digest_hex(&bytes),
        adjudication: context,
    })
}

fn load_state(run_dir: &Path, dispatch_digest: &str) -> Result<State, AuditError> {
    let path = run_dir.join(STATE_FILE);
    if !path.is_file() {
        if fs::read_dir(run_dir.join(LENS_RECEIPT_DIR)).is_ok_and(|mut entries| {
            entries.any(|entry| {
                entry.is_ok_and(|entry| {
                    entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "json")
                })
            })
        }) {
            return Err(invalid(
                "existing lens receipts have no budget state; cannot reset spent usage",
            ));
        }
        return Ok(State::fresh(dispatch_digest));
    }
    let mut state: State = serde_json::from_value(read_json(&path)?)
        .map_err(|error| invalid(format!("{STATE_FILE} is invalid: {error}")))?;
    if state.kind != STATE_KIND || state.dispatch_digest != dispatch_digest {
        return Err(invalid("dispatch identity changed; preserve this run & freeze into a new run directory (budget cannot reset)"));
    }
    if state.schema_version > 2 {
        return Err(invalid("unsupported budget state schema"));
    }
    if state.issuances > 0 && state.spent.is_empty() {
        return Err(invalid(
            "persisted issuances have no budget spend; cannot safely migrate",
        ));
    }
    let mut minimum: BTreeMap<String, u64> = BTreeMap::new();
    for entry in state.reservations.values() {
        if entry.output_token_limit == 0
            || entry.reserved_tokens < entry.output_token_limit
            || !matches!(
                entry.tier.as_str(),
                "judgment" | "specialist" | "mechanical"
            )
        {
            return Err(invalid("malformed persisted budget reservation"));
        }
        let reported = entry.usage.as_ref().map_or(0, |usage| {
            usage
                .input_tokens
                .unwrap_or(0)
                .saturating_add(usage.output_tokens.unwrap_or(0))
                .saturating_add(usage.retry_tokens.unwrap_or(0))
        });
        let total = minimum.entry(entry.tier.clone()).or_insert(0);
        *total = total.saturating_add(entry.reserved_tokens.max(reported));
    }
    if state.issuances < state.reservations.len() as u64
        || minimum
            .iter()
            .any(|(tier, tokens)| state.spent.get(tier).copied().unwrap_or(0) < *tokens)
    {
        return Err(invalid(
            "persisted budget spend understates reservations/usage",
        ));
    }
    // Preserve legacy spent counters; no receipt can turn unknown legacy usage
    // into zero or create new capacity.
    state.schema_version = 2;
    Ok(state)
}

/// Cross-process exclusion for every budget read/modify/write. OS releases
/// this advisory lock on process exit, including crashes; a busy lock denies
/// admission. Never unlink the lock file (that would split concurrent locks).
struct StateLock {
    _file: fs::File,
}
impl StateLock {
    fn acquire(run_dir: &Path) -> Result<Self, AuditError> {
        fs::create_dir_all(run_dir).map_err(|error| invalid(error.to_string()))?;
        let path = run_dir.join(".next-state.lock");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| {
                invalid(format!(
                    "budget lock unavailable ({}): {error}",
                    path.display()
                ))
            })?;
        file.try_lock().map_err(|error| {
            invalid(format!(
                "budget state locked/unavailable ({}): {error}",
                path.display()
            ))
        })?;
        Ok(Self { _file: file })
    }
}

impl Drop for StateLock {
    fn drop(&mut self) {
        // Unix locks belong to the open file description, which another
        // thread's fork may inherit before exec. Closing only our descriptor
        // would let that child retain a completed transaction's lock. Unlock
        // explicitly while our descriptor is still open; never unlink it.
        let _ = self._file.unlock();
    }
}

fn save_state(run_dir: &Path, state: &State) -> Result<(), AuditError> {
    let bytes = serde_json::to_vec_pretty(state).map_err(|error| invalid(error.to_string()))?;
    write_file(run_dir, STATE_FILE, &bytes)?;
    Ok(())
}

fn budget_summary(state: &State) -> Value {
    let mut input = 0u64;
    let mut output = 0u64;
    let mut cached = 0u64;
    let mut retry = 0u64;
    let mut unknown = 0usize;
    let mut failures = 0usize;
    let mut overrun = 0u64;
    let mut output_cap_overrun = 0u64;
    let mut reported_cost = Some("0".to_owned());
    let mut unknown_cost = 0usize;
    for reservation in state.reservations.values() {
        if reservation.transport_authorized {
            match &reservation.reported_api_cost_usd {
                Some(cost) => {
                    reported_cost = reported_cost
                        .as_deref()
                        .and_then(|sum| crate::review_runtime::cost::add(sum, cost));
                    if reported_cost.is_none() {
                        unknown_cost += 1;
                    }
                }
                None => unknown_cost += 1,
            }
        }
        match &reservation.usage {
            Some(usage) => {
                input = input.saturating_add(usage.input_tokens.unwrap_or(0));
                output = output.saturating_add(usage.output_tokens.unwrap_or(0));
                cached = cached.saturating_add(usage.cached_input_tokens.unwrap_or(0));
                retry = retry.saturating_add(usage.retry_tokens.unwrap_or(0));
                failures += usize::from(usage.failed);
                output_cap_overrun = output_cap_overrun.saturating_add(
                    usage
                        .output_tokens
                        .unwrap_or(0)
                        .saturating_sub(reservation.output_token_limit),
                );
                if usage.input_tokens.is_none()
                    || usage.output_tokens.is_none()
                    || usage.cached_input_tokens.is_none()
                    || usage.retry_tokens.is_none()
                {
                    unknown += 1;
                }
                let reported = usage
                    .input_tokens
                    .unwrap_or(0)
                    .saturating_add(usage.output_tokens.unwrap_or(0))
                    .saturating_add(usage.retry_tokens.unwrap_or(0));
                overrun =
                    overrun.saturating_add(reported.saturating_sub(reservation.reserved_tokens));
            }
            None => unknown += 1,
        }
    }
    let known = unknown == 0 && state.issuances == state.reservations.len() as u64;
    let legacy_unknown = state
        .issuances
        .saturating_sub(state.reservations.len() as u64);
    let cost_known = unknown_cost == 0 && legacy_unknown == 0 && reported_cost.is_some();
    json!({
        "admissionBasis": "bytes/4 plus output is a planning heuristic; new physical calls reserve the full frozen per-call allowance; persisted earlier reservations retain their original amount; provider usage may exceed authorization",
        "plannedTokens": state.reservations.values().fold(0u64, |sum, reservation| sum.saturating_add(reservation.planned_tokens)),
        "reservedTokens": state.reservations.values().fold(0u64, |sum, reservation| sum.saturating_add(reservation.reserved_tokens)),
        "chargedByTier": state.spent,
        "actual": {
            "status": if known { "known" } else { "unknown" },
            "inputTokens": if known { Some(input) } else { None },
            "outputTokens": if known { Some(output) } else { None },
            "cachedInputTokens": if known { Some(cached) } else { None },
            "retryTokens": if known { Some(retry) } else { None },
            "knownInputTokens": input, "knownOutputTokens": output,
            "knownCachedInputTokens": cached, "knownRetryTokens": retry,
        },
        "unknownUsageCalls": unknown,
        "legacyUnknownUsageCalls": state.issuances.saturating_sub(state.reservations.len() as u64),
        "retryCalls": state.reservations.values().filter(|reservation| reservation.retry).count(),
        "failedCalls": failures, "actualOverrunTokens": overrun,
        "outputCapOverrunTokens": output_cap_overrun,
        "cost": {
            "currency": "USD",
            "basis": "provider-reported API-equivalent cost; not invoice charge",
            "status": if cost_known { "known" } else { "unknown" },
            "reportedApiEquivalentCostUsd": if cost_known { reported_cost.as_deref() } else { None },
            "knownReportedApiEquivalentSubtotalUsd": reported_cost,
            "unknownCostCalls": unknown_cost,
            "legacyUnknownCostCalls": legacy_unknown,
            "invoiceChargeStatus": "unknown",
            "invoiceChargeUsd": null,
        },
        "terminalStatus": state.terminal_status,
    })
}

/// Read the same locked ledger used for admission when rebuilding reports.
/// Planned but unused reservations are not physical calls; every authorized
/// call requires reconciled actuals, including explicit zeros for known usage.
pub fn persisted_budget_report(run_dir: &Path) -> Result<Option<Value>, AuditError> {
    if !run_dir.join(STATE_FILE).is_file() {
        return Ok(run_dir.join(DISPATCH_FILE).is_file().then(|| {
            json!({
                "budget":{"actual":{"status":"unknown"},"cost":{"status":"unknown","reportedApiEquivalentCostUsd":null,"invoiceChargeStatus":"unknown","invoiceChargeUsd":null}},
                "gaps":["reasoning-budget-state-missing"]
            })
        }));
    }
    let _lock = StateLock::acquire(run_dir)?;
    let loaded = load(run_dir)?;
    let state = load_state(run_dir, &loaded.dispatch_digest)?;
    let mut gaps = Vec::new();
    if let Some(status) = &state.terminal_status {
        gaps.push(format!("reasoning-budget-terminal:{status}"));
    }
    if state.issuances > state.reservations.len() as u64 {
        gaps.push("reasoning-budget-usage-unknown:legacy-issuances".into());
    }
    for reservation in state
        .reservations
        .values()
        .filter(|entry| entry.transport_authorized)
    {
        if reservation.native_cost_required && reservation.reported_api_cost_usd.is_none() {
            gaps.push(format!(
                "reasoning-budget-cost-unknown:{}",
                reservation.call_id
            ));
        }
        match &reservation.usage {
            Some(usage) => {
                if usage.input_tokens.is_none()
                    || usage.output_tokens.is_none()
                    || usage.cached_input_tokens.is_none()
                    || usage.retry_tokens.is_none()
                {
                    gaps.push(format!(
                        "reasoning-budget-usage-unknown:{}",
                        reservation.call_id
                    ));
                    if usage.failed {
                        gaps.push(format!(
                            "reasoning-budget-call-failed:{}",
                            reservation.call_id
                        ));
                    }
                }
            }
            None => gaps.push(format!(
                "reasoning-budget-usage-missing:{}",
                reservation.call_id
            )),
        }
    }
    Ok(Some(json!({"budget":budget_summary(&state),"gaps":gaps})))
}

/// Preflight every exact rendered request before transport. Returned
/// authorization is one-shot; replaying call_id or reservation_id is rejected.
/// Initial `next` reservations are upgraded in-place to the full frozen
/// per-call allowance. Extra calls get new entries. Rendered-byte estimates
/// remain planning data, since native input token counts are unavailable before
/// transport. Authorization is not a hard bound on provider-reported usage.
pub fn reserve_call(run_dir: &Path, call: &BudgetCall) -> Result<Value, AuditError> {
    let _lock = StateLock::acquire(run_dir)?;
    let loaded = load(run_dir)?;
    let mut state = load_state(run_dir, &loaded.dispatch_digest)?;
    if let Some(status) = &state.terminal_status {
        return Ok(
            json!({"authorized":false,"status":status,"complete":false,"callId":call.call_id,"budget":budget_summary(&state)}),
        );
    }
    let budget = loaded
        .snapshot
        .budget
        .as_ref()
        .ok_or_else(|| invalid("reasoning budget missing"))?;
    if call.call_id.trim().is_empty()
        || call.rendered_request_bytes == 0
        || call.output_token_limit == 0
        || call.output_token_limit > budget.output
    {
        return Err(invalid(
            "call requires nonempty ID, full rendered bytes & output cap within frozen budget",
        ));
    }
    if state
        .reservations
        .values()
        .any(|entry| entry.transport_authorized && entry.call_id == call.call_id)
    {
        return Err(invalid(
            "call already authorized; replay requires a new bounded attempt",
        ));
    }
    let tokens = estimated_request_tokens(call.rendered_request_bytes, call.output_token_limit);
    let (id, previous, new_call) = match &call.reservation_id {
        Some(id) => {
            let previous = state
                .reservations
                .get(id)
                .ok_or_else(|| invalid("reservation is not in this frozen run"))?;
            if previous.transport_authorized || previous.usage.is_some() {
                return Err(invalid("reservation already consumed"));
            }
            if previous.tier != call.tier {
                return Err(invalid("reservation tier changed"));
            }
            if !state.leases.iter().any(|(key, lease)| {
                reservation_id(&state.dispatch_digest, key, lease.attempts) == *id
            }) {
                return Err(invalid("reservation belongs to a superseded seat attempt"));
            }
            (id.clone(), previous.reserved_tokens, false)
        }
        None => {
            let id = reservation_id(
                &state.dispatch_digest,
                &format!("host-call:{}", call.call_id),
                1,
            );
            if state.reservations.contains_key(&id) {
                return Err(invalid("call ID already reserved"));
            }
            (id, 0, true)
        }
    };
    let reserved = previous.max(budget.per_call);
    let additional = reserved.saturating_sub(previous);
    if (new_call && !state.budget_blocked.is_empty())
        || tokens > budget.per_call
        || reserved > budget.per_call
        || !budget_allows_tokens(budget, &state, &call.tier, additional, new_call)
    {
        state
            .terminal_status
            .get_or_insert_with(|| "budget-exhausted".to_owned());
        state.budget_blocked.push(call.call_id.clone());
        save_state(run_dir, &state)?;
        return Ok(
            json!({"authorized": false, "status": "budget-exhausted", "complete": false, "callId": call.call_id, "budget": budget_summary(&state)}),
        );
    }
    if new_call && state.issuances >= loaded.snapshot.issuance_cap() {
        return Err(invalid(
            "issuance cap reached; extra attempt cannot be authorized",
        ));
    }
    if new_call {
        state.issuances += 1;
    }
    let spent = state.spent.entry(call.tier.clone()).or_insert(0);
    *spent = spent.saturating_add(additional);
    let planned = state
        .reservations
        .get(&id)
        .map_or(tokens, |entry| entry.planned_tokens);
    let retry = call.retry || state.reservations.get(&id).is_some_and(|entry| entry.retry);
    state.reservations.insert(
        id.clone(),
        Reservation {
            call_id: call.call_id.clone(),
            tier: call.tier.clone(),
            planned_tokens: planned,
            reserved_tokens: reserved,
            output_token_limit: call.output_token_limit,
            retry,
            transport_authorized: true,
            usage: None,
            native_cost_required: false,
            reported_api_cost_usd: None,
        },
    );
    save_state(run_dir, &state)?;
    Ok(
        json!({"authorized": true, "reservationId": id, "callId": call.call_id, "reservedTokens": reserved,
        "outputTokenLimit": call.output_token_limit, "budget": budget_summary(&state)}),
    )
}

/// Idempotently reconcile one trusted provider receipt. Conflicting receipts
/// are errors. Unknown actuals retain admission charge; unknowns & overruns
/// prohibit further transport without erasing any findings/receipts.
pub fn reconcile_usage(run_dir: &Path, receipt: &UsageReceipt) -> Result<Value, AuditError> {
    reconcile_usage_inner(run_dir, receipt, false, None)
}

/// Native invocations require exact provider-reported cost before another call.
pub(crate) fn reconcile_native_usage(
    run_dir: &Path,
    receipt: &UsageReceipt,
    reported_cost: Option<&str>,
) -> Result<Value, AuditError> {
    reconcile_usage_inner(run_dir, receipt, true, reported_cost)
}

/// A restarted native controller must not spend after an interrupted call or
/// an older receipt that cannot establish exact usage/cost. Generic hosts may
/// still reserve parallel calls; this check runs only at native startup.
pub(crate) fn enforce_native_accounting(run_dir: &Path) -> Result<(), AuditError> {
    let _lock = StateLock::acquire(run_dir)?;
    let loaded = load(run_dir)?;
    let mut state = load_state(run_dir, &loaded.dispatch_digest)?;
    if state.terminal_status.is_none() && state.issuances > state.reservations.len() as u64 {
        state.terminal_status = Some("incomplete:usage-unknown".into());
        save_state(run_dir, &state)?;
    }
    if state.terminal_status.is_none() {
        for entry in state
            .reservations
            .values()
            .filter(|entry| entry.transport_authorized)
        {
            let status = match &entry.usage {
                None => Some("incomplete:usage-unknown"),
                Some(usage)
                    if usage.input_tokens.is_none()
                        || usage.output_tokens.is_none()
                        || usage.cached_input_tokens.is_none()
                        || usage.retry_tokens.is_none() =>
                {
                    Some("incomplete:usage-unknown")
                }
                Some(_)
                    if entry
                        .reported_api_cost_usd
                        .as_deref()
                        .and_then(crate::review_runtime::cost::normalize)
                        .is_none() =>
                {
                    Some("incomplete:cost-unknown")
                }
                Some(_) => None,
            };
            if let Some(status) = status {
                state.terminal_status = Some(status.into());
                save_state(run_dir, &state)?;
                break;
            }
        }
    }
    Ok(())
}

fn reconcile_usage_inner(
    run_dir: &Path,
    receipt: &UsageReceipt,
    cost_required: bool,
    reported_cost: Option<&str>,
) -> Result<Value, AuditError> {
    let _lock = StateLock::acquire(run_dir)?;
    let loaded = load(run_dir)?;
    let mut state = load_state(run_dir, &loaded.dispatch_digest)?;
    let reported_cost = reported_cost.and_then(crate::review_runtime::cost::normalize);
    if receipt.receipt_id.trim().is_empty() {
        return Err(invalid("usage receipt ID missing"));
    }
    if let (Some(input), Some(cached)) = (receipt.input_tokens, receipt.cached_input_tokens) {
        if cached > input {
            return Err(invalid("cached input exceeds total input tokens"));
        }
    }
    for (id, entry) in &state.reservations {
        if id != &receipt.reservation_id
            && entry
                .usage
                .as_ref()
                .is_some_and(|usage| usage.receipt_id == receipt.receipt_id)
        {
            return Err(invalid(
                "usage receipt already bound to another reservation",
            ));
        }
    }
    let entry = state
        .reservations
        .get_mut(&receipt.reservation_id)
        .ok_or_else(|| invalid("usage reservation missing"))?;
    if !entry.transport_authorized {
        return Err(invalid("usage has no transport authorization"));
    }
    if let Some(existing) = &entry.usage {
        if existing != receipt
            || (cost_required
                && (!entry.native_cost_required || entry.reported_api_cost_usd != reported_cost))
        {
            return Err(invalid("conflicting usage receipt for reservation"));
        }
        return Ok(
            json!({"status": "reconciled", "idempotent": true, "budget": budget_summary(&state)}),
        );
    }
    let reported = receipt
        .input_tokens
        .unwrap_or(0)
        .saturating_add(receipt.output_tokens.unwrap_or(0))
        .saturating_add(receipt.retry_tokens.unwrap_or(0));
    let extra = reported.saturating_sub(entry.reserved_tokens);
    let output_excess = receipt
        .output_tokens
        .unwrap_or(0)
        .saturating_sub(entry.output_token_limit);
    let tier = entry.tier.clone();
    entry.usage = Some(receipt.clone());
    entry.native_cost_required = cost_required;
    entry.reported_api_cost_usd = reported_cost;
    let cost_unknown = cost_required && entry.reported_api_cost_usd.is_none();
    if extra > 0 || output_excess > 0 {
        let spent = state.spent.entry(tier).or_insert(0);
        *spent = spent.saturating_add(extra);
        state.terminal_status = Some("incomplete:budget-overrun".to_owned());
    } else if state.terminal_status.is_none() {
        if receipt.input_tokens.is_none()
            || receipt.output_tokens.is_none()
            || receipt.cached_input_tokens.is_none()
            || receipt.retry_tokens.is_none()
        {
            state.terminal_status = Some("incomplete:usage-unknown".to_owned());
        } else if cost_unknown {
            state.terminal_status = Some("incomplete:cost-unknown".to_owned());
        }
    }
    save_state(run_dir, &state)?;
    Ok(json!({"status": "reconciled", "idempotent": false, "budget": budget_summary(&state)}))
}

fn model_tier(tier: &str) -> &'static str {
    match tier {
        "mechanical" => "mechanical-cheap",
        "specialist" => "balanced-executor",
        _ => "balanced-executor",
    }
}

fn adjudication_seat_id(key: &str) -> String {
    format!("adj-{}", &digest_hex(key.as_bytes())[..12])
}

/// Writes the deterministic seat packet for an adjudication item and returns
/// `(packet path, result path)`.
fn adjudication_body(
    context: &AdjContext,
    item: &AdjItem,
    round: u32,
) -> Result<Value, AuditError> {
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
    Ok(body)
}

fn materialize(
    run_dir: &Path,
    context: &AdjContext,
    item: &AdjItem,
    seat_id: &str,
    round: u32,
) -> Result<(PathBuf, PathBuf), AuditError> {
    let body = adjudication_body(context, item, round)?;
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
    let _lock = StateLock::acquire(run_dir)?;
    let loaded = load(run_dir)?;
    let before = load_state(run_dir, &loaded.dispatch_digest)?;
    let mut state = before.clone();
    let decision = decide(
        &loaded.snapshot,
        &mut state,
        options.now_ms,
        options.lease_ms,
    );

    // Save admission BEFORE materializing or exposing work. A failed output
    // operation can strand a reservation, never issue uncharged work.
    save_state(run_dir, &state)?;
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
                    "reservationId": reservation_id(&state.dispatch_digest, &work.key, lease.attempts),
                    "requiresCallAuthorization": true,
                    "outputTokenLimit": loaded.snapshot.budget.as_ref().map(|budget| budget.output),
                    "perCallTokenAllowance": loaded.snapshot.budget.as_ref().map(|budget| budget.per_call),
                    "budgetReservationTokens": work.tokens,
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
                    "reservationId": reservation_id(&state.dispatch_digest, &work.key, lease.attempts),
                    "requiresCallAuthorization": true,
                    "outputTokenLimit": loaded.snapshot.budget.as_ref().map(|budget| budget.output),
                    "perCallTokenAllowance": loaded.snapshot.budget.as_ref().map(|budget| budget.per_call),
                    "budgetReservationTokens": work.tokens,
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
        "budget": budget_summary(&state),
        "complete": decision.status == "done",
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

    fn test_budget() -> Budget {
        Budget {
            total: 10_000_000,
            per_call: 1_000_000,
            output: 100,
            max_seats: Some(10_000),
            ..Budget::default()
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
            budget: Some(test_budget()),
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
            ..test_budget()
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
            ..test_budget()
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

    #[cfg(unix)]
    #[test]
    fn completed_budget_transaction_unlocks_descriptors_inherited_before_exec() {
        let run = budget_run("inherited-lock", 10_000);
        let transaction = StateLock::acquire(&run).unwrap();
        // try_clone shares the same open file description as an fd inherited
        // by a concurrently spawned child, without a timing-dependent fork.
        let inherited = transaction._file.try_clone().unwrap();
        assert!(reserve_call(&run, &call("held")).is_err());
        drop(transaction);

        let authorized = reserve_call(&run, &call("after-release")).unwrap();
        assert_eq!(authorized["authorized"], true);
        reconcile_usage(
            &run,
            &UsageReceipt {
                reservation_id: authorized["reservationId"].as_str().unwrap().into(),
                receipt_id: "after-release-usage".into(),
                input_tokens: Some(1),
                output_tokens: Some(1),
                cached_input_tokens: Some(0),
                retry_tokens: Some(0),
                failed: false,
            },
        )
        .unwrap();
        assert!(persisted_budget_report(&run).unwrap().unwrap()["gaps"]
            .as_array()
            .unwrap()
            .is_empty());

        let successor = StateLock::acquire(&run).unwrap();
        drop(inherited);
        // Closing a stale inherited descriptor must not unlock its successor.
        assert!(StateLock::acquire(&run).is_err());
        drop(successor);
        drop(StateLock::acquire(&run).unwrap());
        let _ = fs::remove_dir_all(run);
    }

    fn write_value(path: &Path, value: &Value) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let mut value = value.clone();
        if path.file_name().is_some_and(|name| name == DISPATCH_FILE) {
            if value.get("reasoningBudget").is_none() {
                value["reasoningBudget"] = json!({"schemaVersion":2,"totalTokens":10_000_000,"perCallTokens":1_000_000,"outputTokens":100,"maxSeats":10_000});
            }
            for seat in value["seats"].as_array().into_iter().flatten() {
                for packet in seat["packets"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                {
                    let packet = path.parent().unwrap().join(LENS_PACKET_DIR).join(packet);
                    if !packet.exists() {
                        fs::create_dir_all(packet.parent().unwrap()).unwrap();
                        fs::write(packet, b"{}").unwrap();
                    }
                }
            }
        }
        if path
            .parent()
            .and_then(Path::file_name)
            .is_some_and(|name| name == LENS_RECEIPT_DIR)
        {
            if !value.get("result").is_some_and(Value::is_object) {
                value["result"] = json!({});
            }
            if value["result"].get("complete").is_none() {
                value["result"]["complete"] = json!(true);
            }
        }
        fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
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
    fn a_refrozen_plan_cannot_reset_budget_state() {
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
        let before = fs::read(run.join(STATE_FILE)).unwrap();
        assert!(next(&run, &options(3 * LEASE))
            .unwrap_err()
            .to_string()
            .contains("budget cannot reset"));
        assert_eq!(fs::read(run.join(STATE_FILE)).unwrap(), before);
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
        assert_eq!(
            round1["seats"][0]["estimatedTokens"],
            estimated_request_tokens(fs::read(&packet_path).unwrap().len() as u64, 100)
        );
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
    #[test]
    fn missing_malformed_or_unbounded_budgets_fail_closed() {
        for value in [
            json!({}),
            json!({"reasoningBudget":null}),
            json!({"reasoningBudget":{}}),
            json!({"reasoningBudget":{"judgment":100}}),
            json!({"limits":{"runTokenBudget":100,"seatTokenBudget":"100","maxTotalSeats":2}}),
            json!({"reasoningBudget":{"schemaVersion":2,"totalTokens":100,"perCallTokens":50,"outputTokens":51,"maxSeats":2}}),
        ] {
            assert!(parse_budget(&value).is_err(), "must reject {value}");
        }
        let mut snap = snapshot(vec![seat(1, 1, "judgment")]);
        snap.budget = None;
        assert_eq!(
            decide(&snap, &mut State::fresh("d"), 0, LEASE).status,
            "budget-exhausted"
        );
    }

    #[test]
    fn legacy_budget_migration_has_total_and_call_bounds() {
        let budget = parse_budget(
            &json!({"limits":{"runTokenBudget":10000,"seatTokenBudget":5000,"maxTotalSeats":2}}),
        )
        .unwrap();
        assert_eq!(
            (budget.total, budget.per_call, budget.max_seats),
            (10000, 5000, Some(2))
        );
        let legacy = parse_budget(
            &json!({"reasoningBudget":{"judgment":5000,"specialist":6000,"maxSeats":3}}),
        )
        .unwrap();
        assert_eq!(legacy.total, 11000);
    }

    #[test]
    fn output_reserve_retry_total_tier_and_count_are_enforced() {
        assert_eq!(estimated_request_tokens(401, 77), 178);
        let mut snap = snapshot(vec![seat(1, 1, "judgment"), seat(2, 1, "specialist")]);
        snap.budget = Some(Budget {
            total: 150,
            ..test_budget()
        });
        let mut state = State::fresh("d");
        let decision = decide(&snap, &mut state, 0, LEASE);
        assert_eq!(keys(&decision), ["seat-001"]);
        assert_eq!(state.spent["judgment"], 100);
        snap.done.insert("reasoning.p1.json".into());
        assert_eq!(
            decide(&snap, &mut state, LEASE, LEASE).status,
            "budget-exhausted"
        );
        let mut retry = snapshot(vec![seat(1, 1, "judgment")]);
        retry.budget = Some(Budget {
            total: 150,
            ..test_budget()
        });
        let mut state = State::fresh("d");
        decide(&retry, &mut state, 0, LEASE);
        assert_eq!(
            decide(&retry, &mut state, LEASE, LEASE).status,
            "budget-exhausted"
        );
        assert_eq!(state.issuances, 1);
        let tier = Budget {
            specialist: Some(99),
            ..test_budget()
        };
        assert!(!budget_allows_tokens(
            &tier,
            &State::fresh("d"),
            "specialist",
            100,
            true
        ));
        let count = Budget {
            max_seats: Some(1),
            ..test_budget()
        };
        assert!(!budget_allows_tokens(&count, &state, "judgment", 1, true));
    }

    fn budget_run(name: &str, total: u64) -> PathBuf {
        budget_run_with_limits(name, total, 20, 10)
    }

    fn budget_run_with_limits(name: &str, total: u64, per_call: u64, output: u64) -> PathBuf {
        let run = temp_run(name);
        write_value(
            &run.join(DISPATCH_FILE),
            &json!({
                "reasoningBudget":{"schemaVersion":2,"totalTokens":total,"perCallTokens":per_call,"outputTokens":output,"maxSeats":4},
                "seats":[{"seat":1,"tier":"judgment","packets":["reasoning.a.json"]},{"seat":2,"tier":"judgment","packets":["reasoning.b.json"]}]
            }),
        );
        run
    }

    fn call(id: &str) -> BudgetCall {
        BudgetCall {
            reservation_id: None,
            call_id: id.into(),
            tier: "judgment".into(),
            rendered_request_bytes: 40,
            output_token_limit: 10,
            retry: false,
        }
    }

    #[test]
    fn reservations_resume_reject_replay_and_reconcile_idempotently() {
        let run = budget_run("usage", 100);
        let admitted = reserve_call(&run, &call("first")).unwrap();
        assert_eq!(admitted["authorized"], true);
        assert!(reserve_call(&run, &call("first")).is_err());
        let receipt = UsageReceipt {
            reservation_id: admitted["reservationId"].as_str().unwrap().into(),
            receipt_id: "receipt-1".into(),
            input_tokens: Some(5),
            output_tokens: Some(3),
            cached_input_tokens: Some(2),
            retry_tokens: Some(0),
            failed: false,
        };
        let first = reconcile_usage(&run, &receipt).unwrap();
        let bytes = fs::read(run.join(STATE_FILE)).unwrap();
        assert_eq!(first["budget"]["actual"]["inputTokens"], 5);
        assert_eq!(reconcile_usage(&run, &receipt).unwrap()["idempotent"], true);
        assert_eq!(fs::read(run.join(STATE_FILE)).unwrap(), bytes);
        let mut conflict = receipt.clone();
        conflict.output_tokens = Some(4);
        assert!(reconcile_usage(&run, &conflict).is_err());
        let mut retry = call("retry");
        retry.retry = true;
        reserve_call(&run, &retry).unwrap();
        let state = load_state(&run, &load(&run).unwrap().dispatch_digest).unwrap();
        assert_eq!(
            state.spent["judgment"], 40,
            "known cheaper actuals never replay capacity"
        );
        assert_eq!(budget_summary(&state)["retryCalls"], 1);
        let _ = fs::remove_dir_all(run);
    }

    #[test]
    fn unknown_failed_usage_is_not_zero_and_actual_overrun_stops_calls() {
        let run = budget_run("unknown", 100);
        let admitted = reserve_call(&run, &call("first")).unwrap();
        let mut receipt = UsageReceipt {
            reservation_id: admitted["reservationId"].as_str().unwrap().into(),
            receipt_id: "receipt-1".into(),
            input_tokens: None,
            output_tokens: None,
            cached_input_tokens: None,
            retry_tokens: None,
            failed: true,
        };
        let summary = reconcile_usage(&run, &receipt).unwrap();
        assert_eq!(summary["budget"]["actual"]["status"], "unknown");
        assert!(summary["budget"]["actual"]["inputTokens"].is_null());
        assert_eq!(
            summary["budget"]["terminalStatus"],
            "incomplete:usage-unknown"
        );
        assert_eq!(
            reserve_call(&run, &call("second")).unwrap()["authorized"],
            false
        );
        assert_eq!(
            next(
                &run,
                &NextOptions {
                    now_ms: 100,
                    lease_ms: 1
                }
            )
            .unwrap()["status"],
            "incomplete:usage-unknown"
        );
        let _ = fs::remove_dir_all(&run);
        let run = budget_run("overrun", 100);
        let second = reserve_call(&run, &call("second")).unwrap();
        receipt.reservation_id = second["reservationId"].as_str().unwrap().into();
        receipt.receipt_id = "receipt-2".into();
        receipt.input_tokens = Some(150);
        assert_eq!(
            reconcile_usage(&run, &receipt).unwrap()["budget"]["actualOverrunTokens"],
            130
        );
        assert_eq!(
            reserve_call(&run, &call("third")).unwrap()["authorized"],
            false
        );
        let _ = fs::remove_dir_all(run);
    }

    #[test]
    fn native_cost_is_exact_idempotent_and_unknown_cost_is_terminal() {
        let run = budget_run("native-cost", 100);
        let first = reserve_call(&run, &call("first")).unwrap();
        let mut receipt = UsageReceipt {
            reservation_id: first["reservationId"].as_str().unwrap().into(),
            receipt_id: "cost-1".into(),
            input_tokens: Some(5),
            output_tokens: Some(3),
            cached_input_tokens: Some(0),
            retry_tokens: Some(0),
            failed: false,
        };
        let result = reconcile_native_usage(&run, &receipt, Some("0.1")).unwrap();
        assert_eq!(
            result["budget"]["cost"]["reportedApiEquivalentCostUsd"],
            "0.1"
        );
        assert_eq!(
            reconcile_native_usage(&run, &receipt, Some("0.10")).unwrap()["idempotent"],
            true
        );
        assert!(reconcile_native_usage(&run, &receipt, Some("0.2")).is_err());
        let second = reserve_call(&run, &call("second")).unwrap();
        receipt.reservation_id = second["reservationId"].as_str().unwrap().into();
        receipt.receipt_id = "cost-2".into();
        let result = reconcile_native_usage(&run, &receipt, Some("0.2")).unwrap();
        assert_eq!(
            result["budget"]["cost"]["reportedApiEquivalentCostUsd"],
            "0.3"
        );
        assert!(result["budget"]["cost"]["invoiceChargeUsd"].is_null());
        let third = reserve_call(&run, &call("third")).unwrap();
        receipt.reservation_id = third["reservationId"].as_str().unwrap().into();
        receipt.receipt_id = "cost-3".into();
        let result = reconcile_native_usage(&run, &receipt, Some("-1")).unwrap();
        assert_eq!(result["budget"]["cost"]["status"], "unknown");
        assert!(result["budget"]["cost"]["reportedApiEquivalentCostUsd"].is_null());
        assert_eq!(
            result["budget"]["cost"]["knownReportedApiEquivalentSubtotalUsd"],
            "0.3"
        );
        assert_eq!(
            result["budget"]["terminalStatus"],
            "incomplete:cost-unknown"
        );
        assert_eq!(
            reserve_call(&run, &call("retry")).unwrap()["authorized"],
            false
        );
        enforce_native_accounting(&run).unwrap();
        assert_eq!(
            reserve_call(&run, &call("followup")).unwrap()["authorized"],
            false
        );
        let report = persisted_budget_report(&run).unwrap().unwrap();
        assert!(report["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap.as_str().unwrap().contains("cost-unknown")));
        let _ = fs::remove_dir_all(run);
    }

    #[test]
    fn native_resume_stops_after_authorized_call_without_receipt() {
        let run = budget_run("native-interrupted", 100);
        reserve_call(&run, &call("interrupted")).unwrap();
        enforce_native_accounting(&run).unwrap();
        let denied = reserve_call(&run, &call("resumed")).unwrap();
        assert_eq!(denied["authorized"], false);
        assert_eq!(
            denied["budget"]["terminalStatus"],
            "incomplete:usage-unknown"
        );
        assert!(denied["budget"]["cost"]["reportedApiEquivalentCostUsd"].is_null());
        let _ = fs::remove_dir_all(run);
    }

    #[test]
    fn next_reserves_full_packet_bytes_and_host_overhead_before_send() {
        let run = budget_run_with_limits("rendered", 10000, 1000, 10);
        fs::write(
            run.join(LENS_PACKET_DIR).join("reasoning.a.json"),
            vec![b'x'; 1000],
        )
        .unwrap();
        let wave = next(&run, &options(0)).unwrap();
        assert_eq!(wave["seats"][0]["budgetReservationTokens"], 260);
        let mut request = call("transport");
        request.reservation_id = Some(wave["seats"][0]["reservationId"].as_str().unwrap().into());
        request.rendered_request_bytes = 2000;
        let authorized = reserve_call(&run, &request).unwrap();
        assert_eq!(authorized["reservedTokens"], 1000);
        let state = load_state(&run, &load(&run).unwrap().dispatch_digest).unwrap();
        let reservation = &state.reservations[request.reservation_id.as_ref().unwrap()];
        assert_eq!(reservation.planned_tokens, 260);
        assert_eq!(reservation.reserved_tokens, 1000);
        assert!(reserve_call(&run, &request).is_err());
        let _ = fs::remove_dir_all(run);
    }

    #[test]
    fn physical_allowance_covers_unpredicted_input_and_still_stops_actual_overrun() {
        let run = budget_run_with_limits("native-allowance", 20000, 10000, 2500);
        let mut request = call("native-first");
        request.rendered_request_bytes = 17409;
        request.output_token_limit = 2500;
        let admitted = reserve_call(&run, &request).unwrap();
        assert_eq!(admitted["reservedTokens"], 10000);
        assert_eq!(admitted["budget"]["plannedTokens"], 6853);
        let receipt = UsageReceipt {
            reservation_id: admitted["reservationId"].as_str().unwrap().into(),
            receipt_id: "native-first-usage".into(),
            input_tokens: Some(7202),
            output_tokens: Some(122),
            cached_input_tokens: Some(7200),
            retry_tokens: Some(0),
            failed: false,
        };
        let reconciled = reconcile_usage(&run, &receipt).unwrap();
        assert_eq!(reconciled["budget"]["actual"]["inputTokens"], 7202);
        assert_eq!(reconciled["budget"]["actual"]["outputTokens"], 122);
        assert_eq!(reconciled["budget"]["actualOverrunTokens"], 0);
        assert_eq!(reconciled["budget"]["chargedByTier"]["judgment"], 10000);
        assert!(reconciled["budget"]["terminalStatus"].is_null());

        request.call_id = "native-second".into();
        let second = reserve_call(&run, &request).unwrap();
        assert_eq!(second["authorized"], true);
        assert_eq!(second["budget"]["chargedByTier"]["judgment"], 20000);
        let overrun = UsageReceipt {
            reservation_id: second["reservationId"].as_str().unwrap().into(),
            receipt_id: "native-second-usage".into(),
            input_tokens: Some(10001),
            output_tokens: Some(1),
            cached_input_tokens: Some(0),
            ..receipt
        };
        let reconciled = reconcile_usage(&run, &overrun).unwrap();
        assert_eq!(reconciled["budget"]["actualOverrunTokens"], 2);
        assert_eq!(reconciled["budget"]["chargedByTier"]["judgment"], 20002);
        assert_eq!(
            reconciled["budget"]["terminalStatus"],
            "incomplete:budget-overrun"
        );
        request.call_id = "native-third".into();
        assert_eq!(reserve_call(&run, &request).unwrap()["authorized"], false);
        let _ = fs::remove_dir_all(run);
    }

    #[test]
    fn physical_allowance_cannot_borrow_unused_actuals_or_exceed_tier_or_estimate_cap() {
        for tier_limit in [false, true] {
            let run = budget_run_with_limits("remaining-allowance", 15000, 10000, 10);
            if tier_limit {
                let mut dispatch = read_json(&run.join(DISPATCH_FILE)).unwrap();
                dispatch["reasoningBudget"]["totalTokens"] = json!(30000);
                dispatch["reasoningBudget"]["judgment"] = json!(15000);
                write_value(&run.join(DISPATCH_FILE), &dispatch);
            }
            let first = reserve_call(&run, &call("first")).unwrap();
            reconcile_usage(
                &run,
                &UsageReceipt {
                    reservation_id: first["reservationId"].as_str().unwrap().into(),
                    receipt_id: "cheap-actual".into(),
                    input_tokens: Some(1),
                    output_tokens: Some(1),
                    cached_input_tokens: Some(0),
                    retry_tokens: Some(0),
                    failed: false,
                },
            )
            .unwrap();
            let denied = reserve_call(&run, &call("second")).unwrap();
            assert_eq!(denied["authorized"], false);
            assert_eq!(denied["budget"]["chargedByTier"]["judgment"], 10000);
            let state = load_state(&run, &load(&run).unwrap().dispatch_digest).unwrap();
            assert_eq!(state.reservations.len(), 1);
            let _ = fs::remove_dir_all(run);
        }
        let run = budget_run_with_limits("estimate-over-cap", 20000, 10000, 2500);
        let mut request = call("oversized");
        request.rendered_request_bytes = 30001;
        request.output_token_limit = 2500;
        assert_eq!(estimated_request_tokens(30001, 2500), 10001);
        assert_eq!(reserve_call(&run, &request).unwrap()["authorized"], false);
        let state = load_state(&run, &load(&run).unwrap().dispatch_digest).unwrap();
        assert!(state.reservations.is_empty());
        assert!(state.spent.is_empty());
        let _ = fs::remove_dir_all(run);
    }

    #[test]
    fn earlier_estimated_reservation_overrun_remains_terminal_and_unchanged() {
        let run = budget_run_with_limits("earlier-overrun", 20000, 10000, 2500);
        let admitted = reserve_call(&run, &call("earlier-call")).unwrap();
        let mut state = load_state(&run, &load(&run).unwrap().dispatch_digest).unwrap();
        let id = admitted["reservationId"].as_str().unwrap();
        let reservation = state.reservations.get_mut(id).unwrap();
        reservation.planned_tokens = 6853;
        reservation.reserved_tokens = 6853;
        reservation.output_token_limit = 2500;
        reservation.usage = Some(UsageReceipt {
            reservation_id: id.into(),
            receipt_id: "earlier-actual".into(),
            input_tokens: Some(7202),
            output_tokens: Some(122),
            cached_input_tokens: Some(0),
            retry_tokens: Some(0),
            failed: false,
        });
        state.spent.insert("judgment".into(), 7324);
        state.terminal_status = Some("incomplete:budget-overrun".into());
        save_state(&run, &state).unwrap();
        let before = fs::read(run.join(STATE_FILE)).unwrap();
        assert_eq!(
            reserve_call(&run, &call("later-call")).unwrap()["authorized"],
            false
        );
        let report = persisted_budget_report(&run).unwrap().unwrap();
        assert_eq!(report["budget"]["actualOverrunTokens"], 471);
        assert_eq!(report["budget"]["reservedTokens"], 6853);
        assert_eq!(report["budget"]["chargedByTier"]["judgment"], 7324);
        assert_eq!(fs::read(run.join(STATE_FILE)).unwrap(), before);
        let _ = fs::remove_dir_all(run);
    }

    #[test]
    fn concurrent_calls_cannot_reserve_more_than_remaining() {
        use std::sync::{Arc, Barrier};
        let run = budget_run_with_limits("concurrent", 15000, 10000, 10);
        let barrier = Arc::new(Barrier::new(3));
        let workers: Vec<_> = ["one", "two"]
            .into_iter()
            .map(|name| {
                let run = run.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    reserve_call(&run, &call(name))
                })
            })
            .collect();
        barrier.wait();
        let admitted = workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap().ok())
            .filter(|value| value["authorized"] == true)
            .count();
        assert_eq!(admitted, 1);
        let state = load_state(&run, &load(&run).unwrap().dispatch_digest).unwrap();
        assert_eq!(state.spent["judgment"], 10000);
        let _ = fs::remove_dir_all(run);
    }
    #[test]
    fn partial_receipts_and_lost_state_cannot_claim_completion() {
        let run = budget_run("partial-receipt", 10000);
        next(&run, &options(0)).unwrap();
        write_value(
            &run.join(LENS_RECEIPT_DIR).join("reasoning.a.json"),
            &json!({"result":{"complete":false,"coverage_gaps":["delivery-unverified"]}}),
        );
        write_value(
            &run.join(LENS_RECEIPT_DIR).join("reasoning.b.json"),
            &json!({"result":{"complete":false,"coverage_gaps":["verification-unresolved"]}}),
        );
        assert_ne!(next(&run, &options(1)).unwrap()["status"], "done");
        fs::remove_file(run.join(STATE_FILE)).unwrap();
        assert!(next(&run, &options(2))
            .unwrap_err()
            .to_string()
            .contains("cannot reset spent"));
        let _ = fs::remove_dir_all(run);
    }

    #[test]
    fn finished_numbered_parts_accept_only_provider_scope_gap() {
        let part = json!({"part":{"number":1,"total":2},"result":{"complete":false,
            "coverage_gaps":["reasoning-part-scope:reasoning.test:part 1/2"],
            "details":{"deliveryEvidence":{},"verificationEvidence":{}}}});
        assert!(packet_receipt_complete(&part));
        let mut missing = part.clone();
        missing["result"]["coverage_gaps"]
            .as_array_mut()
            .unwrap()
            .push(json!("verification-unresolved"));
        assert!(!packet_receipt_complete(&missing));
    }
    #[test]
    fn reissued_retry_cannot_be_cleared_by_host_default_and_report_keeps_usage_gaps() {
        let run = budget_run("retry-summary", 10000);
        next(&run, &options(0)).unwrap();
        let retry = next(&run, &options(LEASE)).unwrap();
        let mut host_call = call("resumed-retry");
        host_call.reservation_id =
            Some(retry["seats"][0]["reservationId"].as_str().unwrap().into());
        let admitted = reserve_call(&run, &host_call).unwrap();
        assert!(admitted["budget"]["retryCalls"].as_u64().unwrap() >= 1);
        let report = persisted_budget_report(&run).unwrap().unwrap();
        assert!(report["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap.as_str().unwrap().contains("usage-missing")));
        reconcile_usage(
            &run,
            &UsageReceipt {
                reservation_id: admitted["reservationId"].as_str().unwrap().into(),
                receipt_id: "retry-failed".into(),
                input_tokens: None,
                output_tokens: None,
                cached_input_tokens: None,
                retry_tokens: None,
                failed: true,
            },
        )
        .unwrap();
        let report = persisted_budget_report(&run).unwrap().unwrap();
        assert!(report["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap.as_str().unwrap().contains("usage-unknown")));
        assert!(report["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap.as_str().unwrap().contains("call-failed")));
        let _ = fs::remove_dir_all(run);
    }

    #[test]
    fn reported_overrun_denies_other_already_issued_seat_after_resume() {
        let run = budget_run("issued-overrun", 10000);
        let wave = next(&run, &options(0)).unwrap();
        let mut first = call("first-seat");
        first.reservation_id = Some(wave["seats"][0]["reservationId"].as_str().unwrap().into());
        reserve_call(&run, &first).unwrap();
        reconcile_usage(
            &run,
            &UsageReceipt {
                reservation_id: first.reservation_id.unwrap(),
                receipt_id: "overrun".into(),
                input_tokens: Some(1),
                output_tokens: Some(11),
                cached_input_tokens: Some(0),
                retry_tokens: Some(0),
                failed: false,
            },
        )
        .unwrap();
        let before = fs::read(run.join(STATE_FILE)).unwrap();
        let mut second = call("second-seat");
        second.reservation_id = Some(wave["seats"][1]["reservationId"].as_str().unwrap().into());
        let denied = reserve_call(&run, &second).unwrap();
        assert_eq!(denied["authorized"], false);
        assert_eq!(denied["status"], "incomplete:budget-overrun");
        assert_eq!(fs::read(run.join(STATE_FILE)).unwrap(), before);
        assert!(persisted_budget_report(&run).unwrap().unwrap()["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|gap| gap.as_str().unwrap().contains("budget-overrun")));
        let _ = fs::remove_dir_all(run);
    }
}
