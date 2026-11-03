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
//! rounds plus one confirmation-only fourth round; a lease issuance cap of
//! `2 x plan seats + 3 x adjudication candidates`; a required frozen physical
//! call/token budget. Context & verification calls use that physical budget
//! without consuming lease retries. Hitting a limit ends the
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

use hmac::{Hmac, KeyInit, Mac};
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
    /// Physical calls reserved, including scheduler leases awaiting transport.
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
    /// Seat-local context exhaustion never closes sibling admission.
    #[serde(default)]
    context_limited: BTreeSet<String>,
    /// Digest of the explicit linked continuation; never present in legacy runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    continuation_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    historical_terminal_status: Option<String>,
}

impl State {
    fn lease_issuances(&self) -> u64 {
        self.leases.values().fold(0u64, |sum, lease| {
            sum.saturating_add(u64::from(lease.attempts))
        })
    }

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
            context_limited: BTreeSet::new(),
            continuation_digest: None,
            historical_terminal_status: None,
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
    gather_policy: Option<String>,
    providers: Vec<String>,
    packets: Vec<String>,
    estimated_tokens: u64,
    output_token_limit: Option<u64>,
    minimum_output_tokens: Option<u64>,
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
    output_token_limit: u64,
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

pub(crate) const MODEL_INPUT_BYTES_PER_TOKEN: u64 = 2;

/// Empirical model-input-byte planning estimate, not a provider token bound. Canonical
/// prompt, system & schema count once; host-envelope escaping is separate.
/// Host preflight still checks exact serialized bytes; physical authorization
/// reserves the full frozen per-call allowance because native overhead and
/// tokenization are not separable or known in advance. A native observation
/// used 10,938 input tokens for 23,460 visible bytes (0.466 tokens/byte).
pub fn estimated_request_tokens(model_input_bytes: u64, output_tokens: u64) -> u64 {
    model_input_bytes
        .div_ceil(MODEL_INPUT_BYTES_PER_TOKEN)
        .saturating_add(output_tokens)
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
    /// Exact serialized host envelope, retained independently of model input.
    pub rendered_request_bytes: u64,
    /// Canonical prompt UTF8 + system UTF8 + schema JSON UTF8, each once.
    pub model_input_bytes: u64,
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
    /// Thinking tokens the provider counted inside output_tokens (0 when
    /// unreported). They spend budget but do not count against the text cap.
    #[serde(default)]
    pub thinking_tokens: Option<u64>,
    pub failed: bool,
}

/// Output tokens that count against the frozen text cap: provider output
/// minus reported thinking (the native runtime grants thinking its own
/// allowance; see review_runtime::native::thinking_allowance).
pub fn text_output_tokens(usage: &UsageReceipt) -> u64 {
    usage
        .output_tokens
        .unwrap_or(0)
        .saturating_sub(usage.thinking_tokens.unwrap_or(0))
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
        if state.context_limited.contains(&seat.id) {
            continue;
        }
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
            output_token_limit: seat
                .output_token_limit
                .unwrap_or_else(|| snapshot.budget.as_ref().map_or(0, |budget| budget.output)),
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
                output_token_limit: snapshot.budget.as_ref().map_or(0, |budget| budget.output),
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
        if state.lease_issuances() >= cap {
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
            item.output_token_limit,
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
    } else if lens_unmet == 0 && !adjudication_unmet && state.context_limited.is_empty() {
        "done".to_owned()
    } else {
        let mut reasons: Vec<String> = Vec::new();
        for seat in &state.context_limited {
            reasons.push(format!("context-call-limit:{seat}"));
        }
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
        gather_policy: seat
            .get("gatherPolicy")
            .and_then(Value::as_str)
            .map(str::to_owned),
        providers: strings(seat.get("providers")),
        packets: strings(seat.get("packets")),
        estimated_tokens: seat
            .get("estimatedTokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        output_token_limit: seat.get("outputTokenLimit").and_then(Value::as_u64),
        minimum_output_tokens: None,
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

fn frozen_gather_calls(seats: &[LensSeat]) -> Result<u64, AuditError> {
    let mut calls = 0;
    for seat in seats {
        match seat.gather_policy.as_deref() {
            Some("deterministic") => {}
            Some("cheap-planner") | None => {
                if seat
                    .providers
                    .iter()
                    .any(|provider| provider != "reasoning.dead-file")
                {
                    calls += 1;
                }
            }
            Some(_) => return Err(invalid("unknown frozen gatherPolicy")),
        }
    }
    Ok(calls)
}

const SIZING_CACHE_FILE: &str = "next-sizing-cache.json";
const SIZING_CACHE_KIND: &str = "legion-audit-next-sizing-cache";
const SIZING_CACHE_DOMAIN: &str = "legion-audit-next-sizing-cache-v1";

struct SizingCacheContext {
    key: Vec<u8>,
    epoch: String,
    plan_digest: String,
}

/// Run custody needed to authenticate the cache: the sealed plan digest and
/// the epoch key that already MACs runtime-call evidence. Absent material
/// disables the cache entirely (sizes are recomputed, never trusted).
fn sizing_cache_context(run_dir: &Path) -> Option<SizingCacheContext> {
    let plan: Value = serde_json::from_slice(&fs::read(run_dir.join("plan.json")).ok()?).ok()?;
    let plan_digest = plan.pointer("/seal/digest")?.as_str()?.to_owned();
    let (key, epoch) = crate::native_providers::reasoning::ingest::load_epoch(run_dir).ok()?;
    Some(SizingCacheContext {
        key,
        epoch,
        plan_digest,
    })
}

fn sizing_input_digest(contents: &[(String, Vec<u8>)]) -> String {
    let mut hasher = Sha256::new();
    for (name, content) in contents {
        hasher.update((name.len() as u64).to_le_bytes());
        hasher.update(name.as_bytes());
        hasher.update((content.len() as u64).to_le_bytes());
        hasher.update(content);
    }
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn sizing_cache_mac(key: &[u8], body: &Value) -> Result<Hmac<Sha256>, AuditError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|error| invalid(format!("sizing cache key unusable: {error}")))?;
    mac.update(SIZING_CACHE_DOMAIN.as_bytes());
    mac.update(&[0]);
    mac.update(&crate::integrity::canonical_bytes(body)?);
    Ok(mac)
}

fn write_sizing_cache(
    run_dir: &Path,
    context: &SizingCacheContext,
    dispatch_digest: &str,
    sizes: &BTreeMap<String, (String, u64)>,
) -> Result<(), AuditError> {
    let seats: serde_json::Map<String, Value> = sizes
        .iter()
        .map(|(id, (digest, bytes))| {
            (
                id.clone(),
                json!({"inputDigest":digest,"modelVisibleInputBytes":bytes}),
            )
        })
        .collect();
    let mut envelope = json!({"schemaVersion":1,"kind":SIZING_CACHE_KIND,"dispatchDigest":dispatch_digest,"planDigest":context.plan_digest,"epochDigest":context.epoch,"seats":seats});
    let mac = sizing_cache_mac(&context.key, &envelope)?;
    envelope["authentication"] = json!({"alg":"HMAC-SHA256","macDomain":SIZING_CACHE_DOMAIN,"mac":hex::encode(mac.finalize().into_bytes())});
    let bytes = serde_json::to_vec_pretty(&envelope).map_err(|error| invalid(error.to_string()))?;
    write_file(run_dir, SIZING_CACHE_FILE, &bytes)?;
    Ok(())
}

/// Returns authenticated per-seat `(input digest, model-visible bytes)`.
/// A cache for another dispatch, plan or epoch is stale and ignored (the
/// caller recomputes & republishes). A cache for THIS key that is malformed or
/// fails its MAC was altered, so the run fails closed.
fn read_sizing_cache(
    run_dir: &Path,
    context: &SizingCacheContext,
    dispatch_digest: &str,
) -> Result<BTreeMap<String, (String, u64)>, AuditError> {
    let path = run_dir.join(SIZING_CACHE_FILE);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => {
            return Err(invalid(format!(
                "could not read {SIZING_CACHE_FILE}: {error}"
            )))
        }
    };
    let tampered = || {
        invalid(format!(
            "{SIZING_CACHE_FILE} failed authentication; remove it to recompute sizing"
        ))
    };
    let mut envelope: Value = serde_json::from_slice(&bytes).map_err(|_| tampered())?;
    let stale = envelope["schemaVersion"] != 1
        || envelope["kind"] != SIZING_CACHE_KIND
        || envelope["dispatchDigest"] != dispatch_digest
        || envelope["planDigest"] != context.plan_digest
        || envelope["epochDigest"] != context.epoch;
    if stale {
        return Ok(BTreeMap::new());
    }
    let authentication = envelope
        .as_object_mut()
        .and_then(|object| object.remove("authentication"))
        .ok_or_else(tampered)?;
    let claimed = authentication["mac"]
        .as_str()
        .and_then(|mac| hex::decode(mac).ok())
        .filter(|_| {
            authentication["alg"] == "HMAC-SHA256"
                && authentication["macDomain"] == SIZING_CACHE_DOMAIN
        })
        .ok_or_else(tampered)?;
    sizing_cache_mac(&context.key, &envelope)?
        .verify_slice(&claimed)
        .map_err(|_| tampered())?;
    let mut sizes = BTreeMap::new();
    for (id, entry) in envelope["seats"].as_object().ok_or_else(tampered)? {
        let digest = entry["inputDigest"].as_str().ok_or_else(tampered)?;
        let bytes = entry["modelVisibleInputBytes"]
            .as_u64()
            .ok_or_else(tampered)?;
        sizes.insert(id.clone(), (digest.to_owned(), bytes));
    }
    Ok(sizes)
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
    let runtime_encoding =
        dispatch.get("requestEncoding").and_then(Value::as_str) == Some("runtime-initial-v1");
    let adjudication_selected = seats.iter().any(|seat| {
        seat.providers
            .iter()
            .any(|provider| provider == ADJUDICATOR_PROVIDER_ID)
            || seat
                .packets
                .iter()
                .any(|packet| packet == &format!("{ADJUDICATOR_PROVIDER_ID}.json"))
    });
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
    if let Some((snapshot, ctx, count)) = if !runtime_encoding || adjudication_selected {
        load_adjudication(run_dir)?
    } else {
        // Native packets preserve the full pending universe. A deferred packet
        // carries no authority to open rounds outside the selected recipe.
        None
    } {
        // The adjudicator seat is replaced by the round machine.
        seats.retain(|seat| seat.providers != [ADJUDICATOR_PROVIDER_ID.to_owned()]);
        adjudication = Some(snapshot);
        context = Some(ctx);
        adjudication_candidates = count;
    }
    let budget = parse_budget(&dispatch)?;
    if runtime_encoding {
        let gather_calls = frozen_gather_calls(&seats)?;
        let required_calls = plan_seats
            .saturating_add(gather_calls)
            .saturating_add(u64::from(plan_seats > 0));
        let required_tokens = required_calls.saturating_mul(budget.per_call);
        if required_calls > budget.max_seats.unwrap_or(0) || required_tokens > budget.total {
            return Err(AuditError::BoundExceeded(format!("audit budget infeasible before generation: {plan_seats} author seats + {gather_calls} cheap gathering calls + verification/context reserve require {required_calls} calls & {required_tokens} reserved tokens; limits permit {} calls & {} tokens. Narrow scope/lenses or increase budget; mandatory coverage was not reduced", budget.max_seats.unwrap_or(0), budget.total)));
        }
    }

    let dispatch_digest = digest_hex(&bytes);
    // Sizing every packet re-opens the frozen snapshot, so its result is kept
    // in a MAC-bound cache keyed by dispatch + plan digest. Packet bytes are
    // still read & hashed on every load: a changed packet is never served a
    // cached size. Without custody key material nothing is cached or trusted.
    let cache_context = if runtime_encoding {
        sizing_cache_context(run_dir)
    } else {
        None
    };
    let cached_sizes = match &cache_context {
        Some(context) => read_sizing_cache(run_dir, context, &dispatch_digest)?,
        None => BTreeMap::new(),
    };
    let mut measured_sizes: BTreeMap<String, (String, u64)> = BTreeMap::new();
    let mut all_cached = true;
    let mut sizer = crate::review_runtime::InitialRequestSizer::default();
    for seat in &mut seats {
        let mut bytes = 0u64;
        let mut work = Vec::new();
        let mut contents = Vec::new();
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
            contents.push((packet.clone(), content));
        }
        let input_digest = sizing_input_digest(&contents);
        if runtime_encoding {
            let cached = cached_sizes
                .get(&seat.id)
                .filter(|(digest, _)| *digest == input_digest)
                .map(|(_, sized)| *sized);
            bytes = match cached {
                Some(sized) => sized,
                None => {
                    all_cached = false;
                    for (packet, content) in &contents {
                        work.push(
                            serde_json::from_slice::<
                                crate::native_providers::reasoning::PendingLensWork,
                            >(content)
                            .map_err(|error| {
                                invalid(format!("budget packet {packet} is malformed: {error}"))
                            })?,
                        );
                    }
                    sizer.model_visible_input_bytes(&work)?
                }
            };
            measured_sizes.insert(seat.id.clone(), (input_digest, bytes));
        }
        let output = seat.output_token_limit.unwrap_or(budget.output);
        if output == 0 || output > budget.output {
            return Err(invalid("seat output cap exceeds frozen output ceiling"));
        }
        if runtime_encoding {
            seat.minimum_output_tokens = Some(
                crate::native_providers::reasoning::ingest::minimum_output_tokens(
                    budget.output,
                    seat.packets.len(),
                ),
            );
        }
        seat.output_token_limit = Some(output);
        seat.estimated_tokens = estimated_request_tokens(bytes, output);
    }
    if let Some(context) = &cache_context {
        // Cache only; a failed write never blocks the budget transaction.
        if !all_cached || cached_sizes.len() != measured_sizes.len() {
            let _ = write_sizing_cache(run_dir, context, &dispatch_digest, &measured_sizes);
        }
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
        dispatch_digest,
        adjudication: context,
    })
}

fn load_state(run_dir: &Path, dispatch_digest: &str) -> Result<State, AuditError> {
    crate::continuation::validate_lineage(run_dir)?;
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
pub(crate) struct StateLock {
    _file: fs::File,
}
impl StateLock {
    // File::try_lock needs Rust 1.89; the toolchain in use provides it.
    #[allow(clippy::incompatible_msrv)]
    pub(crate) fn acquire(run_dir: &Path) -> Result<Self, AuditError> {
        let lock_root = crate::continuation::lock_root(run_dir)?;
        fs::create_dir_all(&lock_root).map_err(|error| invalid(error.to_string()))?;
        let path = lock_root.join(".next-state.lock");
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
    // File::unlock needs Rust 1.89; the toolchain in use provides it.
    #[allow(clippy::incompatible_msrv)]
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

/// Caller holds the canonical lineage lock. This validates the actual ledger,
/// rather than allowing a continuation to reinterpret partial JSON as zero.
pub(crate) fn continuation_parent_state(run_dir: &Path) -> Result<Value, AuditError> {
    let loaded = load(run_dir)?;
    let state = load_state(run_dir, &loaded.dispatch_digest)?;
    let summary = budget_summary(&state);
    if state.terminal_status.as_deref() != Some("incomplete:budget-overrun")
        || state.continuation_digest.is_some()
        || summary["actual"]["status"] != "known"
        || summary["cost"]["status"] != "known"
        || state.reservations.is_empty()
        || (summary["actualOverrunTokens"].as_u64().unwrap_or(0) == 0
            && summary["outputCapOverrunTokens"].as_u64().unwrap_or(0) == 0)
        || state
            .reservations
            .values()
            .any(|entry| !entry.transport_authorized || entry.usage.is_none())
    {
        return Err(invalid("continuation requires an original budget-overrun stop with fully known usage/cost and no unresolved reservations"));
    }
    serde_json::to_value(state).map_err(|error| invalid(error.to_string()))
}

pub(crate) fn continuation_summary(state: &Value) -> Result<Value, AuditError> {
    let state: State =
        serde_json::from_value(state.clone()).map_err(|error| invalid(error.to_string()))?;
    Ok(budget_summary(&state))
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
                    text_output_tokens(usage).saturating_sub(reservation.output_token_limit),
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
        "admissionBasis": "ceil(visible input bytes/2) plus output is an empirical planning estimate, not a provider token bound; admission retains 15% headroom capped at 1500 tokens; new physical calls reserve the full frozen per-call allowance; persisted earlier reservations retain their original amount; provider usage may exceed authorization",
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
        "contextLimitedSeats": state.context_limited,
        "historicalTerminalStatus": state.historical_terminal_status,
        "continuationDigest": state.continuation_digest,
        "leaseAttempts": state.lease_issuances(),
    })
}

/// Read the same locked ledger used for admission when rebuilding reports.
/// Planned but unused reservations are not physical calls; every authorized
/// call requires reconciled actuals, including explicit zeros for known usage.
pub fn persisted_budget_report(run_dir: &Path) -> Result<Option<Value>, AuditError> {
    if !run_dir.join(STATE_FILE).is_file() {
        crate::continuation::validate_lineage(run_dir)?;
        if run_dir
            .join(crate::continuation::CONTINUATION_FILE)
            .exists()
        {
            return Err(invalid("continuation ledger missing; budget cannot reset"));
        }
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
    if let Some(status) = &state.historical_terminal_status {
        gaps.push(format!("reasoning-budget-history:{status}"));
    }
    for seat in &state.context_limited {
        gaps.push(format!("incomplete:context-call-limit:{seat}"));
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
/// per-call allowance. Extra calls get new entries. Model-visible-byte estimates
/// remain planning data, since provider input token counts are unavailable before
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
        || call.model_input_bytes == 0
        || call.model_input_bytes > call.rendered_request_bytes
        || call.output_token_limit == 0
        || call.output_token_limit
            < crate::native_providers::reasoning::ingest::minimum_output_tokens(budget.output, 1)
        || call.output_token_limit > budget.output
    {
        return Err(invalid(
            "call requires nonempty ID, exact host envelope, bounded model input bytes & output cap within frozen budget",
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
    let tokens = estimated_request_tokens(call.model_input_bytes, call.output_token_limit);
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
            if previous.output_token_limit != call.output_token_limit {
                return Err(invalid("reservation output cap changed"));
            }
            if loaded
                .snapshot
                .seats
                .iter()
                .find(|seat| {
                    state.leases.get(&seat.id).is_some_and(|lease| {
                        reservation_id(&state.dispatch_digest, &seat.id, lease.attempts) == *id
                    })
                })
                .and_then(|seat| seat.minimum_output_tokens)
                .is_some_and(|minimum| call.output_token_limit < minimum)
            {
                return Err(invalid("shared seat output cap cannot cover every lens"));
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
    // The physical envelope is a property of this one call, never of the
    // cumulative ledger: report it as such and leave the ledger untouched so
    // the run is not terminalized as budget-exhausted.
    if tokens > crate::native_providers::reasoning::ingest::physical_planning_limit(budget.per_call)
    {
        return Ok(
            json!({"authorized":false,"status":"incomplete:context-call-limit","reason":"physical-envelope-exhausted","complete":false,"callId":call.call_id,"budget":budget_summary(&state)}),
        );
    }
    let reserved = previous.max(budget.per_call);
    let additional = reserved.saturating_sub(previous);
    if (new_call && !state.budget_blocked.is_empty())
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
    // Physical calls already obey maxSeats & full per-call token admission.
    // A context continuation is not another scheduler lease attempt.
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
        "outputTokenLimit": call.output_token_limit, "requestBytes":call.rendered_request_bytes,
        "requestByteBasis":"serialized-host-envelope", "modelVisibleInputBytes":call.model_input_bytes,
        "modelVisibleInputBasis":"canonical-prompt-utf8+system-utf8+schema-json-utf8-once", "budget": budget_summary(&state)}),
    )
}

/// Retire only this author seat. Unused lease admission can be released because
/// no transport was authorized; paid calls & their receipts remain immutable.
pub(crate) fn stop_context_seat(run_dir: &Path, seat_id: &str) -> Result<(), AuditError> {
    let _lock = StateLock::acquire(run_dir)?;
    let loaded = load(run_dir)?;
    if !loaded.snapshot.seats.iter().any(|seat| seat.id == seat_id) {
        return Err(invalid("context-limited seat missing from frozen dispatch"));
    }
    let mut state = load_state(run_dir, &loaded.dispatch_digest)?;
    state.context_limited.insert(seat_id.to_owned());
    if let Some(lease) = state.leases.get(seat_id) {
        let id = reservation_id(&state.dispatch_digest, seat_id, lease.attempts);
        if state
            .reservations
            .get(&id)
            .is_some_and(|entry| !entry.transport_authorized && entry.usage.is_none())
        {
            let unused = state.reservations.remove(&id).expect("checked reservation");
            let spent = state.spent.entry(unused.tier).or_insert(0);
            *spent = spent.saturating_sub(unused.reserved_tokens);
            state.issuances = state.issuances.saturating_sub(1);
        }
    }
    save_state(run_dir, &state)
}

/// Keep one full fresh verifier call available while collecting authors.
/// This read-only preflight never consumes a reservation or resets a stop.
pub(crate) fn native_author_has_verifier_reserve(
    run_dir: &Path,
    initial: Option<&str>,
) -> Result<bool, AuditError> {
    let _lock = StateLock::acquire(run_dir)?;
    let loaded = load(run_dir)?;
    let state = load_state(run_dir, &loaded.dispatch_digest)?;
    let budget = loaded
        .snapshot
        .budget
        .as_ref()
        .ok_or_else(|| invalid("reasoning budget missing"))?;
    let previous = initial.and_then(|id| state.reservations.get(id));
    let new_author = u64::from(previous.is_none());
    let additional = budget
        .per_call
        .saturating_sub(previous.map_or(0, |entry| entry.reserved_tokens));
    let total = state
        .spent
        .values()
        .fold(0u64, |sum, value| sum.saturating_add(*value));
    Ok(state.terminal_status.is_none()
        && state.issuances.saturating_add(new_author).saturating_add(1)
            <= budget.max_seats.unwrap_or(0)
        && total
            .saturating_add(additional)
            .saturating_add(budget.per_call)
            <= budget.total)
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
    let output_excess = text_output_tokens(receipt).saturating_sub(entry.output_token_limit);
    let tier = entry.tier.clone();
    entry.usage = Some(receipt.clone());
    entry.native_cost_required = cost_required;
    entry.reported_api_cost_usd = reported_cost;
    let cost_unknown = cost_required && entry.reported_api_cost_usd.is_none();
    // Reserved tokens bound physical spend; exceeding them is terminal. Text
    // beyond the frozen output cap is charged and reported (the native host
    // bounds total output, thinking included) but stops nothing by itself.
    if extra > 0 {
        let spent = state.spent.entry(tier).or_insert(0);
        *spent = spent.saturating_add(extra);
        state.terminal_status = Some("incomplete:budget-overrun".to_owned());
    } else if output_excess > 0 {
        state.spent.entry(tier).or_insert(0);
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
    next_inner(run_dir, options, &BTreeSet::new())
}

/// Current controller's observed author completions advance collection only.
/// They grant no ingestion, verification or public completion credit.
pub(crate) fn next_author_phase(
    run_dir: &Path,
    options: &NextOptions,
    authored_packets: &BTreeSet<String>,
) -> Result<Value, AuditError> {
    next_inner(run_dir, options, authored_packets)
}

fn next_inner(
    run_dir: &Path,
    options: &NextOptions,
    authored_packets: &BTreeSet<String>,
) -> Result<Value, AuditError> {
    let _lock = StateLock::acquire(run_dir)?;
    let mut loaded = load(run_dir)?;
    loaded
        .snapshot
        .done
        .extend(authored_packets.iter().cloned());
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
    if state != before {
        save_state(run_dir, &state)?;
    }
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
                    "gatherPolicy": seat.gather_policy,
                    "providers": seat.providers,
                    "packetPaths": paths_json(&packets),
                    "resultPaths": paths_json(&results),
                    "estimatedTokens": seat.estimated_tokens,
                    "reservationId": reservation_id(&state.dispatch_digest, &work.key, lease.attempts),
                    "requiresCallAuthorization": true,
                    "outputTokenLimit": work.output_token_limit,
                    "outputTokenCeiling": loaded.snapshot.budget.as_ref().map(|budget| budget.output),
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
                    // Adjudication packets carry their frozen excerpts; no planning call.
                    "gatherPolicy": "deterministic",
                    "packetPaths": paths_json(&[packet]),
                    "resultPaths": paths_json(&[result]),
                    "estimatedTokens": item.tokens,
                    "reservationId": reservation_id(&state.dispatch_digest, &work.key, lease.attempts),
                    "requiresCallAuthorization": true,
                    "outputTokenLimit": loaded.snapshot.budget.as_ref().map(|budget| budget.output),
                    "outputTokenCeiling": loaded.snapshot.budget.as_ref().map(|budget| budget.output),
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
            "issuanceCap": loaded.snapshot.budget.as_ref().and_then(|budget| budget.max_seats),
            "leaseIssuances": state.lease_issuances(),
            "leaseIssuanceCap": loaded.snapshot.issuance_cap(),
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
