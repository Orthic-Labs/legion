//! Faithful Rust port of `src/lib/gauntlet/lib/arcaneshape.mjs`.
//!
//! Arcane's `normalizeCheck` reads `executor` and `status` from
//! caller-supplied data only when `authority !== 'model'`. We always emit
//! `executor: "host"` and `authority: "host"` so the existing trust-class
//! and issuer-derived-field enforcement applies unchanged.
//!
//! The gauntlet output never claims a check passed unless the underlying
//! tool actually returned exit 0: unrun checks are reported as
//! `"unverified"` upstream, never fabricated as `"passed"`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

static ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A non-cryptographic, collision-resistant-enough id in a UUID-like shape.
/// No `uuid` crate dependency is available to this chunk, so this derives
/// the id from wall-clock time, a process-local counter, and a SHA-256
/// digest of both.
pub fn random_id() -> String {
    let counter = ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(nanos.to_le_bytes());
    hasher.update(counter.to_le_bytes());
    let digest = hasher.finalize();
    let digest_bytes: &[u8] = digest.as_slice();
    let hex = hex::encode(&digest_bytes[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[derive(Debug, Clone)]
pub struct LayerSummary {
    pub passed: usize,
    pub failed: usize,
    pub total: usize,
}

#[derive(Debug, Clone)]
pub struct BuildReceiptInput {
    pub started_at: String,
    pub completed_at: String,
    pub command: String,
    /// `summary.ok` — whether the overall gauntlet run passed.
    pub summary_ok: bool,
    /// Mirrors JS `{ summary, layers }` — `layers` here carries each
    /// layer's *full* result set (`layers.mutation.results`, etc.), not
    /// just the picked metrics, matching `JSON.stringify({ summary, layers })`.
    pub output: Value,
    pub mutation: LayerSummary,
    pub coverage_percent: f64,
    pub coverage: LayerSummary,
    pub order: LayerSummary,
}

/// Mirrors `buildReceipt({ startedAt, completedAt, command, summary, layers })`.
pub fn build_receipt(input: BuildReceiptInput) -> Value {
    let exit_status: i64 = if input.summary_ok { 0 } else { 1 };
    let id = random_id();
    json!({
        "id": id,
        "kind": "gauntlet",
        "specification": "phase-6.7 evidence gauntlet: mutation + changed-lines coverage + test-order independence",
        "command": input.command,
        "output": serde_json::to_string_pretty(&input.output).unwrap_or_default(),
        "status": if exit_status == 0 { "passed" } else { "failed" },
        "exit_code": exit_status,
        "receipt": serde_json::to_string(&json!({
            "schema": "orthic.tool-receipt.v1",
            "exit_status": exit_status,
            "started_at": input.started_at,
            "completed_at": input.completed_at,
            "summary": {
                "mutation": { "passed": input.mutation.passed, "failed": input.mutation.failed, "total": input.mutation.total },
                "coverage": { "passed": input.coverage.passed, "failed": input.coverage.failed, "percent": input.coverage_percent },
                "order": { "passed": input.order.passed, "failed": input.order.failed, "total": input.order.total },
            }
        })).unwrap_or_default(),
    })
}

/// Mirrors `buildCheck(receipt)` — full check object matching Arcane's
/// normalized shape.
pub fn build_check(receipt: &Value) -> Value {
    json!({
        "id": receipt["id"],
        "kind": "gauntlet",
        "specification": receipt["specification"],
        "command": receipt["command"],
        "output": receipt["output"],
        "output_ref": receipt.get("output_ref").cloned().unwrap_or(Value::Null),
        "status": receipt["status"],
        "exit_code": receipt["exit_code"],
        "executor": "host",
        "authority": "host",
        "env_fingerprint": Value::Null,
        "workspace_hash": Value::Null,
        "receipt": receipt["receipt"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_check_always_carries_host_executor_and_authority() {
        let input = BuildReceiptInput {
            started_at: "t0".into(),
            completed_at: "t1".into(),
            command: "gauntlet".into(),
            summary_ok: false,
            output: json!({"summary": {"ok": false}, "layers": {}}),
            mutation: LayerSummary { passed: 0, failed: 1, total: 1 },
            coverage_percent: 0.0,
            coverage: LayerSummary { passed: 0, failed: 0, total: 0 },
            order: LayerSummary { passed: 0, failed: 0, total: 0 },
        };
        let receipt = build_receipt(input);
        assert_eq!(receipt["exit_code"], 1);
        assert_eq!(receipt["status"], "failed");
        let check = build_check(&receipt);
        assert_eq!(check["executor"], "host");
        assert_eq!(check["authority"], "host");
        assert_eq!(check["kind"], "gauntlet");
        let embedded: Value = serde_json::from_str(check["receipt"].as_str().unwrap()).unwrap();
        assert_eq!(embedded["schema"], "orthic.tool-receipt.v1");
        assert_eq!(embedded["exit_status"], 1);
        assert!(embedded["summary"]["mutation"].is_object());
    }
}
