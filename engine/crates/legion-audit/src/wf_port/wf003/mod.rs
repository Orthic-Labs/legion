//! wf003 — Phase 6.7 evidence gauntlet.
//!
//! Faithful Rust port of `src/lib/gauntlet/` (gauntlet.mjs + lib/{arcaneshape,
//! coverage,diff,mutation}.mjs). `src/lib/gauntlet/lib/order.mjs` is NOT part
//! of this chunk (wf003 owns only the five files listed in its assignment)
//! and is intentionally left unported here; `run_gauntlet` accepts an
//! already-computed order layer instead of shelling out to a port of it, so
//! wiring in a future wf-chunk's `order` port is a one-line change at the
//! call site rather than a rewrite of this module.
//!
//! This module is self-contained under `wf_port::wf003` per this chunk's
//! ownership boundary; `lib.rs`, `mod.rs` wiring elsewhere, and
//! `Cargo.toml` are NOT touched here (see the integrator note in the
//! chunk report).

pub mod arcaneshape;
pub mod coverage;
pub mod diff;
pub mod mutation;

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use arcaneshape::{build_check, build_receipt, BuildReceiptInput, Check};
use coverage::{run_coverage, CoverageLayer};
use diff::{load_diff, summarise, LoadDiffOptions};
use mutation::{run_mutation, MutationLayer};

#[derive(Debug, thiserror::Error)]
pub enum GauntletError {
    #[error("io error: {0}")]
    Io(String),
    #[error("git diff {range} failed: {stderr}")]
    GitDiffFailed { range: String, stderr: String },
}

/// A disabled layer, mirroring each `--no-*` branch in gauntlet.mjs, which
/// substitutes a trivially-passing empty layer rather than skipping the
/// key in the output.
pub fn disabled_mutation_layer() -> MutationLayer {
    MutationLayer { passed: 0, failed: 0, skipped: 0, total: 0, ok: true, results: Vec::new() }
}

pub fn disabled_coverage_layer() -> CoverageLayer {
    CoverageLayer { ok: true, passed: 0, failed: 0, total: 0, percent: None, error: None, stderr_tail: None, results: Vec::new() }
}

/// The `order` layer's shape from gauntlet.mjs's disabled branch
/// (`{ passed: 0, failed: 0, total: 0, ok: true, results: [] }`). Since
/// wf003 does not own `order.mjs`, callers that have not yet wired a real
/// order layer should pass this.
pub fn disabled_order_layer() -> Value {
    json!({ "passed": 0, "failed": 0, "total": 0, "ok": true, "results": [] })
}

pub struct RunGauntletOptions<'a> {
    pub cwd: Option<&'a Path>,
    pub base: Option<&'a str>,
    pub diff_file: Option<&'a Path>,
    pub test_command: &'a str,
    pub run_mutation: bool,
    pub run_coverage: bool,
    /// Pre-computed order layer (see module docs: order.mjs is out of
    /// scope for this port). Pass `disabled_order_layer()` to mirror
    /// `--no-order`.
    pub order_layer: Value,
}

pub struct GauntletRun {
    pub check: Check,
    /// Mirrors the JS process's `process.exit(receipt.exit_code)`.
    pub exit_code: i32,
}

/// Faithful port of gauntlet.mjs's orchestration (minus CLI arg parsing and
/// stdout/exit-process side effects, and minus the `order` layer's own
/// computation — see module docs).
pub fn run_gauntlet(opts: RunGauntletOptions<'_>) -> Result<GauntletRun, GauntletError> {
    let started_at = now_iso8601();
    let command = format!(
        "gauntlet --base {} --test \"{}\"",
        opts.base.unwrap_or("HEAD"),
        opts.test_command
    );

    let files = load_diff(LoadDiffOptions {
        cwd: opts.cwd,
        base: opts.base,
        head: None,
        diff_file: opts.diff_file,
    })?;

    if files.is_empty() {
        let completed_at = now_iso8601();
        let layers = json!({
            "mutation": disabled_mutation_layer(),
            "coverage": disabled_coverage_layer(),
            "order": disabled_order_layer(),
        });
        let summary = json!({ "ok": false, "error": "no_diff" });
        let receipt = build_receipt(BuildReceiptInput {
            started_at,
            completed_at,
            command,
            summary,
            layers,
        });
        let check = build_check(&receipt);
        return Ok(GauntletRun { exit_code: receipt.exit_code, check });
    }

    let mutation_layer = if opts.run_mutation {
        run_mutation(opts.cwd, &files, opts.test_command)?
    } else {
        disabled_mutation_layer()
    };
    let coverage_layer = if opts.run_coverage {
        run_coverage(opts.cwd, &files, opts.test_command)?
    } else {
        disabled_coverage_layer()
    };
    let order_layer = opts.order_layer.clone();
    let order_ok = order_layer.get("ok").and_then(Value::as_bool).unwrap_or(false);

    let diff_summary = summarise(&files);
    let ok = mutation_layer.ok && coverage_layer.ok && order_ok;
    let summary = json!({
        "ok": ok,
        "diff": { "files": diff_summary.files, "lines": diff_summary.lines },
        "layers": {
            "mutation": pick_metrics(&serde_json::to_value(&mutation_layer).unwrap_or(Value::Null)),
            "coverage": pick_metrics(&serde_json::to_value(&coverage_layer).unwrap_or(Value::Null)),
            "order": pick_metrics(&order_layer),
        },
    });

    let layers = json!({
        "mutation": mutation_layer,
        "coverage": coverage_layer,
        "order": order_layer,
    });

    let completed_at = now_iso8601();
    let receipt = build_receipt(BuildReceiptInput { started_at, completed_at, command, summary, layers });
    let check = build_check(&receipt);
    Ok(GauntletRun { exit_code: receipt.exit_code, check })
}

/// Mirrors `pickMetrics(layer)` from gauntlet.mjs.
fn pick_metrics(layer: &Value) -> Value {
    json!({
        "passed": layer.get("passed").and_then(Value::as_u64).unwrap_or(0),
        "failed": layer.get("failed").and_then(Value::as_u64).unwrap_or(0),
        "total": layer.get("total").and_then(Value::as_u64).unwrap_or(0),
        "percent": layer.get("percent").cloned().unwrap_or(Value::Null),
        "ok": layer.get("ok").and_then(Value::as_bool).unwrap_or(false),
        "error": layer.get("error").cloned().unwrap_or(Value::Null),
    })
}

/// Formats the current time as `new Date().toISOString()` would
/// (`YYYY-MM-DDTHH:MM:SS.mmmZ`), without depending on `chrono` (not a
/// workspace dependency).
fn now_iso8601() -> String {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let (y, mo, d) = civil_from_days((secs / 86_400) as i64);
    let rem = secs % 86_400;
    let h = rem / 3600;
    let mi = (rem % 3600) / 60;
    let s = rem % 60;
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

/// Howard Hinnant's `civil_from_days`: days-since-epoch -> (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_matches_known_epoch_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn now_iso8601_is_well_formed() {
        let s = now_iso8601();
        assert_eq!(s.len(), 24, "expected YYYY-MM-DDTHH:MM:SS.mmmZ, got {s}");
        assert!(s.ends_with('Z'));
        assert_eq!(s.as_bytes()[4], b'-');
        assert_eq!(s.as_bytes()[10], b'T');
    }

    #[test]
    fn disabled_layers_are_trivially_ok() {
        assert!(disabled_mutation_layer().ok);
        assert!(disabled_coverage_layer().ok);
        assert_eq!(disabled_order_layer()["ok"], true);
    }

    #[test]
    fn pick_metrics_defaults_missing_fields() {
        let v = pick_metrics(&json!({}));
        assert_eq!(v["passed"], 0);
        assert_eq!(v["ok"], false);
        assert!(v["percent"].is_null());
    }
}
