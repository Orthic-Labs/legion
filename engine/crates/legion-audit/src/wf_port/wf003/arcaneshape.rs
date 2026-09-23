// Phase 6.7 — receipt shape.
//
// Faithful Rust port of `src/lib/gauntlet/lib/arcaneshape.mjs`.
//
// Arcane's `normalizeCheck` reads `executor` and `status` from
// caller-supplied data only when authority !== 'model'. We always emit
// `executor: "host"` and `authority: "host"`, `receipt: ...` so the
// existing trust-class and issuer-derived-field enforcement applies
// unchanged.
//
// The gauntlet output never claims a check passed unless the underlying
// tool actually returned exit 0. Per the standing anti-gaming constraint,
// unrun checks are reported as 'unverified' (upstream, not modelled here).

use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct BuildReceiptInput {
    pub started_at: String,
    pub completed_at: String,
    pub command: String,
    /// The `summary` object as already assembled by the caller (arbitrary
    /// JSON — mirrors the JS caller passing its own `summary` object
    /// through untouched).
    pub summary: Value,
    /// The full `{ mutation, coverage, order }` layer objects as already
    /// assembled by the caller — including each layer's `results` array —
    /// mirroring the JS `layers` argument exactly (arcaneshape.mjs never
    /// narrows this to counts; it serializes the whole thing and only
    /// re-reads `passed`/`failed`/`total`/`percent` for the receipt's own
    /// `summary` block).
    pub layers: Value,
}

#[derive(Debug, Clone)]
pub struct Receipt {
    pub id: String,
    pub kind: String,
    pub specification: String,
    pub command: String,
    pub output: String,
    pub status: String,
    pub exit_code: i32,
    pub receipt: String,
}

/// Mirrors `buildReceipt({ startedAt, completedAt, command, summary, layers })`.
pub fn build_receipt(input: BuildReceiptInput) -> Receipt {
    let exit_status = if is_summary_ok(&input.summary) { 0 } else { 1 };
    let output = json!({
        "summary": input.summary,
        "layers": input.layers,
    });
    let counts = |name: &str, extra: &[&str]| -> Value {
        let layer = input.layers.get(name).cloned().unwrap_or(Value::Null);
        let mut obj = serde_json::Map::new();
        obj.insert("passed".to_string(), layer.get("passed").cloned().unwrap_or(json!(0)));
        obj.insert("failed".to_string(), layer.get("failed").cloned().unwrap_or(json!(0)));
        for key in extra {
            obj.insert((*key).to_string(), layer.get(*key).cloned().unwrap_or(json!(0)));
        }
        Value::Object(obj)
    };
    let receipt_body = json!({
        "schema": "orthic.tool-receipt.v1",
        "exit_status": exit_status,
        "started_at": input.started_at,
        "completed_at": input.completed_at,
        "summary": {
            "mutation": counts("mutation", &["total"]),
            "coverage": counts("coverage", &["percent"]),
            "order": counts("order", &["total"]),
        },
    });
    Receipt {
        id: generate_id(),
        kind: "gauntlet".to_string(),
        specification: "phase-6.7 evidence gauntlet: mutation + changed-lines coverage + test-order independence".to_string(),
        command: input.command,
        output: serde_json::to_string_pretty(&output).unwrap_or_default(),
        status: if exit_status == 0 { "passed".to_string() } else { "failed".to_string() },
        exit_code: exit_status,
        receipt: serde_json::to_string(&receipt_body).unwrap_or_default(),
    }
}

fn is_summary_ok(summary: &Value) -> bool {
    summary.get("ok").and_then(Value::as_bool).unwrap_or(false)
}

#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: String,
    pub kind: String,
    pub specification: String,
    pub command: String,
    pub output: String,
    pub output_ref: Option<String>,
    pub status: String,
    pub exit_code: i32,
    pub executor: String,
    pub authority: String,
    pub env_fingerprint: Option<String>,
    pub workspace_hash: Option<String>,
    pub receipt: String,
}

/// Mirrors `buildCheck(receipt)`: the full check object matching Arcane's
/// normalized shape.
pub fn build_check(receipt: &Receipt) -> Check {
    Check {
        id: receipt.id.clone(),
        kind: receipt.kind.clone(),
        specification: receipt.specification.clone(),
        command: receipt.command.clone(),
        output: receipt.output.clone(),
        output_ref: None,
        status: receipt.status.clone(),
        exit_code: receipt.exit_code,
        executor: "host".to_string(),
        authority: "host".to_string(),
        env_fingerprint: None,
        workspace_hash: None,
        receipt: receipt.receipt.clone(),
    }
}

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// `randomUUID()` in the JS source produces an RFC 4122 v4 UUID purely for
/// a unique receipt id — no code anywhere in this crate parses or
/// validates UUID structure. We generate a UUID-v4-shaped (8-4-4-4-12 hex,
/// version nibble `4`, RFC 4122 variant) identifier from a SHA-256 of
/// wall-clock time, process id, and a per-process counter, since the `uuid`
/// crate is not a dependency of `legion-audit` (see wf003 report for the
/// proposed Cargo.toml patch — this port intentionally avoids adding one).
fn generate_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let counter = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(counter.to_le_bytes());
    let digest = hasher.finalize();
    let hex = hex::encode(digest);
    let mut b = hex.as_bytes().to_vec();
    // Set version nibble (4) and variant bits (RFC 4122: 10xx) so the
    // output is shaped like a real v4 UUID even though it is not one.
    b[12] = b'4';
    let variant_nibble = match b[16] {
        b'0'..=b'9' => (b[16] - b'0') & 0x3 | 0x8,
        b'a'..=b'f' => (b[16] - b'a' + 10) & 0x3 | 0x8,
        _ => 0x8,
    };
    b[16] = char::from_digit(variant_nibble as u32, 16).unwrap() as u8;
    let hex = String::from_utf8(b).unwrap();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_are_unique_and_uuid_shaped() {
        let a = generate_id();
        let b = generate_id();
        assert_ne!(a, b);
        for id in [&a, &b] {
            let parts: Vec<&str> = id.split('-').collect();
            assert_eq!(parts.len(), 5);
            assert_eq!([parts[0].len(), parts[1].len(), parts[2].len(), parts[3].len(), parts[4].len()], [8, 4, 4, 4, 12]);
            assert!(parts[2].starts_with('4'));
        }
    }

    #[test]
    fn build_check_carries_host_executor_and_authority() {
        let receipt = build_receipt(BuildReceiptInput {
            started_at: "2026-01-01T00:00:00.000Z".to_string(),
            completed_at: "2026-01-01T00:00:01.000Z".to_string(),
            command: "gauntlet --base HEAD".to_string(),
            summary: json!({ "ok": true }),
            layers: json!({
                "mutation": { "passed": 3, "failed": 0, "total": 3 },
                "coverage": { "passed": 10, "failed": 0, "percent": 100.0 },
                "order": { "passed": 5, "failed": 0, "total": 5 },
            }),
        });
        assert_eq!(receipt.status, "passed");
        assert_eq!(receipt.exit_code, 0);
        let check = build_check(&receipt);
        assert_eq!(check.executor, "host");
        assert_eq!(check.authority, "host");
        assert_eq!(check.kind, "gauntlet");
        assert_eq!(check.status, "passed");
        let parsed: Value = serde_json::from_str(&check.receipt).unwrap();
        assert_eq!(parsed["schema"], "orthic.tool-receipt.v1");
        assert_eq!(parsed["summary"]["mutation"]["total"], 3);
        assert_eq!(parsed["summary"]["coverage"]["percent"], 100.0);
    }

    #[test]
    fn failing_summary_yields_exit_code_one() {
        let receipt = build_receipt(BuildReceiptInput {
            started_at: "t0".to_string(),
            completed_at: "t1".to_string(),
            command: "gauntlet".to_string(),
            summary: json!({ "ok": false, "error": "no_diff" }),
            layers: json!({
                "mutation": { "passed": 0, "failed": 0, "total": 0 },
                "coverage": { "passed": 0, "failed": 0 },
                "order": { "passed": 0, "failed": 0, "total": 0 },
            }),
        });
        assert_eq!(receipt.exit_code, 1);
        assert_eq!(receipt.status, "failed");
    }
}
