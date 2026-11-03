//! Ported from src/packages/kernel/lib/ids.mjs (packet P5d).
//!
//! Faithful port of the Crockford-base32 ULID minting/validation used for
//! every kernel identity kind. JS defaults `entropy` to `crypto.randomBytes(10)`;
//! this port takes entropy explicitly (callers needing randomness should
//! supply it, e.g. via `random_entropy()`), since the crate has no `rand`
//! dependency to draw on.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::p5_core::kernel_errors::{KernelError, KernelErrorOptions};

const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// Port of the `PREFIXES` map / `ID_PREFIXES` export.
pub fn prefix_for(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "run" => "run_",
        "request" => "req_",
        "task" => "ktask_",
        "artifact" => "art_",
        "event" => "evt_",
        "effect" => "eff_",
        "evidence" => "ev_",
        "claim" => "clm_",
        "workerCapsule" => "wc_",
        _ => return None,
    })
}

fn usage_error(message: impl Into<String>) -> KernelError {
    KernelError::new(
        "INVALID_ARGUMENT",
        message,
        KernelErrorOptions {
            category: Some("usage".to_string()),
            ..Default::default()
        },
    )
}

/// Port of `encodeUlid(now, entropy)`.
#[allow(clippy::result_large_err)]
fn encode_ulid(now: u64, entropy: &[u8; 10]) -> Result<String, KernelError> {
    if now > 281_474_976_710_655 {
        return Err(usage_error("ULID timestamp is outside 48-bit range"));
    }
    let mut value: u128 = now as u128;
    for byte in entropy {
        value = (value << 8) | (*byte as u128);
    }
    let mut encoded = [0u8; 26];
    for slot in encoded.iter_mut().rev() {
        *slot = ALPHABET[(value & 31) as usize];
        value >>= 5;
    }
    Ok(String::from_utf8(encoded.to_vec()).expect("alphabet is ASCII"))
}

/// Non-cryptographic entropy source used where JS relied on `crypto.randomBytes`.
/// Callers that need cryptographic unguessability should supply their own
/// entropy; this exists only to give production call sites something to pass
/// by default.
pub fn random_entropy() -> [u8; 10] {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut state = (nanos as u64) ^ 0x9E37_79B9_7F4A_7C15;
    let mut out = [0u8; 10];
    for byte in out.iter_mut() {
        // splitmix64
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        *byte = (z & 0xFF) as u8;
    }
    out
}

pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Port of `mintId(kind, options)`.
#[allow(clippy::result_large_err)]
pub fn mint_id(kind: &str, now: u64, entropy: &[u8; 10]) -> Result<String, KernelError> {
    let prefix = prefix_for(kind).ok_or_else(|| usage_error(format!("unknown id kind: {kind}")))?;
    Ok(format!("{prefix}{}", encode_ulid(now, entropy)?))
}

fn is_valid_ulid_body(body: &str) -> bool {
    body.len() == 26 && body.bytes().all(|byte| ALPHABET.contains(&byte))
}

/// Port of `validateId(kind, value)`.
#[allow(clippy::result_large_err)]
pub fn validate_id(kind: &str, value: &str) -> Result<(), KernelError> {
    let prefix = prefix_for(kind).ok_or_else(|| usage_error(format!("unknown id kind: {kind}")))?;
    let valid = value
        .strip_prefix(prefix)
        .map(is_valid_ulid_body)
        .unwrap_or(false);
    if !valid {
        return Err(usage_error(format!("invalid {kind} id: {value}")));
    }
    Ok(())
}

/// Port of `validateExecutionTaskId(value)`: `^T-\d+(\.\d+)*$`.
#[allow(clippy::result_large_err)]
pub fn validate_execution_task_id(value: &str) -> Result<(), KernelError> {
    let invalid = || usage_error(format!("invalid ExecutionTask id: {value}"));
    let Some(rest) = value.strip_prefix("T-") else {
        return Err(invalid());
    };
    if rest.is_empty() {
        return Err(invalid());
    }
    for segment in rest.split('.') {
        if segment.is_empty() || !segment.bytes().all(|b| b.is_ascii_digit()) {
            return Err(invalid());
        }
    }
    Ok(())
}
