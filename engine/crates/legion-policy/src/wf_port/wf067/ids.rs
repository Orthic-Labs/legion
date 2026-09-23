//! Faithful port of `src/lib/contracts/arcane/ids.mjs`.
//!
//! `packages/contracts/ids.md` is the source of truth for ID *shape*; this
//! module is the only place wf067 produces or checks one. Sequence IDs
//! (R-#, EC-#, T-#.#, ...) are authored upstream by Sage — this module
//! validates them, never mints them. Opaque runtime handles (run_/req_/...)
//! are Kernel-issued in production; minting here is for receipts/fixtures
//! only, matching the JS module's own scope note.

use std::sync::Mutex;

use super::errors::{ArcCode, ArcaneError};

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// ID family. Mirrors the keys of JS `HANDLE_PREFIX` plus the
/// sequence-id families in `ID_PATTERN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Run,
    Request,
    KernelTask,
    Artifact,
    EffectReceipt,
    EvidenceReceipt,
    Claim,
    WorkerCapsule,
    Requirement,
    Decision,
    Invariant,
    NonGoal,
    AcceptanceCriterion,
    ExecutionContract,
    ExecutionTask,
    Finding,
    Blocker,
    Amendment,
    Covenant,
}

/// Prefix for a mintable opaque-handle family, or `None` for a
/// sequence-id family (validated only, never minted). Mirrors JS
/// `HANDLE_PREFIX`.
pub fn handle_prefix(family: Family) -> Option<&'static str> {
    match family {
        Family::Run => Some("run_"),
        Family::Request => Some("req_"),
        Family::KernelTask => Some("ktask_"),
        Family::Artifact => Some("art_"),
        Family::EffectReceipt => Some("eff_"),
        Family::EvidenceReceipt => Some("ev_"),
        Family::Claim => Some("clm_"),
        Family::WorkerCapsule => Some("wc_"),
        _ => None,
    }
}

fn is_ulid(s: &str) -> bool {
    // Crockford base32, 26 chars, first char restricted to 0-7 is NOT
    // enforced by the JS regex (`[0-9A-HJKMNP-TV-Z]{26}`), so we mirror
    // that exactly: any 26 chars each in the Crockford alphabet (I, L, O,
    // U excluded), case-sensitive uppercase.
    if s.len() != 26 {
        return false;
    }
    s.bytes().all(|b| CROCKFORD.contains(&b))
}

/// True when `value` matches the grammar for `family`. Mirrors JS `isId`.
pub fn is_id(family: Family, value: &str) -> bool {
    match family {
        Family::Run => value.strip_prefix("run_").is_some_and(is_ulid),
        Family::Request => value.strip_prefix("req_").is_some_and(is_ulid),
        Family::KernelTask => value.strip_prefix("ktask_").is_some_and(is_ulid),
        Family::Artifact => value.strip_prefix("art_").is_some_and(is_ulid),
        Family::EffectReceipt => value.strip_prefix("eff_").is_some_and(is_ulid),
        Family::EvidenceReceipt => value.strip_prefix("ev_").is_some_and(is_ulid),
        Family::Claim => value.strip_prefix("clm_").is_some_and(is_ulid),
        Family::WorkerCapsule => value.strip_prefix("wc_").is_some_and(is_ulid),
        Family::Requirement => matches_seq(value, "R-"),
        Family::Decision => matches_seq(value, "D-"),
        Family::Invariant => matches_seq(value, "I-"),
        Family::NonGoal => matches_seq(value, "NG-"),
        Family::AcceptanceCriterion => matches_seq(value, "AC-"),
        Family::ExecutionContract => matches_seq(value, "EC-"),
        Family::ExecutionTask => matches_execution_task(value),
        Family::Finding => matches_seq(value, "F-"),
        Family::Blocker => matches_seq(value, "B-"),
        Family::Amendment => matches_seq(value, "A-"),
        Family::Covenant => matches_seq(value, "CV-"),
    }
}

fn matches_seq(value: &str, prefix: &str) -> bool {
    match value.strip_prefix(prefix) {
        Some(rest) => !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()),
        None => false,
    }
}

/// `^T-\d+(\.\d+)*$`
fn matches_execution_task(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("T-") else { return false };
    if rest.is_empty() {
        return false;
    }
    let mut segments = rest.split('.');
    let Some(first) = segments.next() else { return false };
    if first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    for seg in segments {
        if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
    }
    true
}

fn family_name(family: Family) -> &'static str {
    match family {
        Family::Run => "run",
        Family::Request => "request",
        Family::KernelTask => "kernelTask",
        Family::Artifact => "artifact",
        Family::EffectReceipt => "effectReceipt",
        Family::EvidenceReceipt => "evidenceReceipt",
        Family::Claim => "claim",
        Family::WorkerCapsule => "workerCapsule",
        Family::Requirement => "requirement",
        Family::Decision => "decision",
        Family::Invariant => "invariant",
        Family::NonGoal => "nonGoal",
        Family::AcceptanceCriterion => "acceptanceCriterion",
        Family::ExecutionContract => "executionContract",
        Family::ExecutionTask => "executionTask",
        Family::Finding => "finding",
        Family::Blocker => "blocker",
        Family::Amendment => "amendment",
        Family::Covenant => "covenant",
    }
}

/// Throws `ARC_ID_INVALID` unless `value` matches `family`'s grammar.
/// Mirrors JS `assertId`.
pub fn assert_id(family: Family, value: &str, label: Option<&str>) -> Result<(), ArcaneError> {
    if !is_id(family, value) {
        let label = label.unwrap_or_else(|| family_name(family));
        return Err(ArcaneError::new(
            ArcCode::ArcIdInvalid,
            format!("{label} does not match the ids.md grammar for {}", family_name(family)),
        )
        .with_detail("family", family_name(family))
        .with_detail("value", value.to_string()));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Monotonic ULID minting.
// ---------------------------------------------------------------------

struct MonotonicState {
    last_time: i64,
    last_random: Option<[u8; 10]>,
}

static STATE: Mutex<MonotonicState> = Mutex::new(MonotonicState { last_time: -1, last_random: None });

fn encode_time(ms: u64) -> String {
    let mut out = [0u8; 10];
    let mut t = ms;
    for i in (0..10).rev() {
        out[i] = CROCKFORD[(t % 32) as usize];
        t /= 32;
    }
    String::from_utf8(out.to_vec()).unwrap()
}

fn encode_random(bytes: &[u8; 10]) -> String {
    // 16 Crockford chars = 80 bits, fed from 10 random bytes.
    let mut bits: u128 = 0;
    for b in bytes {
        bits = (bits << 8) | (*b as u128);
    }
    let mut out = [0u8; 16];
    for i in (0..16).rev() {
        out[i] = CROCKFORD[(bits & 31) as usize];
        bits >>= 5;
    }
    String::from_utf8(out.to_vec()).unwrap()
}

fn random_bytes_10() -> [u8; 10] {
    // Dependency-free CSPRNG substitute: wf067 has no `rand` dependency
    // available. This draws from the OS entropy source when present and
    // falls back to a time/address-derived seed otherwise — sufficient for
    // ULID's collision-avoidance role (Kernel mints production ids; this
    // path is receipts/fixtures only per the module's own scope note).
    #[cfg(unix)]
    {
        use std::fs::File;
        use std::io::Read;
        if let Ok(mut f) = File::open("/dev/urandom") {
            let mut buf = [0u8; 10];
            if f.read_exact(&mut buf).is_ok() {
                return buf;
            }
        }
    }
    let mut buf = [0u8; 10];
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let addr = &buf as *const _ as u64;
    let mut x = (seed as u64) ^ addr;
    for slot in buf.iter_mut() {
        // xorshift64
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *slot = (x & 0xff) as u8;
    }
    buf
}

fn bump_random(prev: &[u8; 10]) -> [u8; 10] {
    let mut next = *prev;
    for i in (0..next.len()).rev() {
        if next[i] != 0xff {
            next[i] += 1;
            return next;
        }
        next[i] = 0;
    }
    random_bytes_10()
}

/// Monotonic ULID. Within the same millisecond the random component is
/// incremented rather than redrawn, so ids minted in a tight loop stay
/// lexicographically ordered. Mirrors JS `ulid`.
pub fn ulid(now_ms: u64) -> String {
    let mut state = STATE.lock().unwrap();
    let now = now_ms as i64;
    let rnd = if now == state.last_time && state.last_random.is_some() {
        bump_random(state.last_random.as_ref().unwrap())
    } else {
        random_bytes_10()
    };
    state.last_time = now;
    state.last_random = Some(rnd);
    encode_time(now_ms) + &encode_random(&rnd)
}

/// Mint an opaque handle of `family`. Mirrors JS `mintId`; panics'-worth
/// JS throw on a non-mintable family becomes `Err`.
pub fn mint_id(family: Family, now_ms: u64) -> Result<String, ArcaneError> {
    let prefix = handle_prefix(family)
        .ok_or_else(|| ArcaneError::new(ArcCode::ArcIdInvalid, format!("unknown handle family: {}", family_name(family))))?;
    Ok(format!("{prefix}{}", ulid(now_ms)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_id_round_trips_through_is_id() {
        let id = mint_id(Family::Run, 1_700_000_000_000).unwrap();
        assert!(id.starts_with("run_"));
        assert!(is_id(Family::Run, &id));
        assert!(!is_id(Family::Request, &id));
    }

    #[test]
    fn ulid_is_monotonic_within_same_millisecond() {
        let a = ulid(1_700_000_000_000);
        let b = ulid(1_700_000_000_000);
        assert!(b > a, "expected {b} > {a}");
    }

    #[test]
    fn sequence_ids_validate_but_are_never_minted() {
        assert!(is_id(Family::Requirement, "R-12"));
        assert!(!is_id(Family::Requirement, "R-"));
        assert!(!is_id(Family::Requirement, "R-1a"));
        assert!(handle_prefix(Family::Requirement).is_none());
    }

    #[test]
    fn execution_task_id_allows_dotted_segments() {
        assert!(is_id(Family::ExecutionTask, "T-1"));
        assert!(is_id(Family::ExecutionTask, "T-1.2.3"));
        assert!(!is_id(Family::ExecutionTask, "T-1."));
        assert!(!is_id(Family::ExecutionTask, "T-.1"));
        assert!(!is_id(Family::ExecutionTask, "T-"));
    }

    #[test]
    fn assert_id_errors_with_arc_id_invalid() {
        let err = assert_id(Family::Requirement, "not-an-id", None).unwrap_err();
        assert_eq!(err.code, ArcCode::ArcIdInvalid);
    }

    #[test]
    fn assert_id_passes_through_valid_value() {
        assert!(assert_id(Family::Decision, "D-7", Some("decision")).is_ok());
    }

    #[test]
    fn opaque_handle_families_reject_wrong_prefix() {
        let id = mint_id(Family::Artifact, 1_700_000_000_001).unwrap();
        assert!(!is_id(Family::EffectReceipt, &id));
    }
}
