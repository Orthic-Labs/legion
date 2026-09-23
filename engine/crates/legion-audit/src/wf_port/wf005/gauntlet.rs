//! Faithful Rust port of `src/lib/gauntlet/gauntlet.mjs` (entry point,
//! minus its CLI-arg parsing shell — `run_gauntlet` takes a
//! `GauntletOptions` struct in place of `parseArgs`).
//!
//! Output: a single JSON check object matching Arcane's check shape.
//! `exit_code` is 0 on pass, 1 on any layer failure.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use super::arcaneshape::{build_check, build_receipt, BuildReceiptInput, LayerSummary};
use super::diff::{load_diff, summarise, LoadDiffOptions};
use super::mutation::{run_mutation, RunMutationOptions};
use super::order::{run_order, RunOrderOptions};

#[derive(Debug, Clone)]
pub struct GauntletOptions<'a> {
    pub cwd: &'a Path,
    pub base: Option<&'a str>,
    pub diff_file: Option<&'a Path>,
    pub test_command: Option<&'a str>,
    pub no_mutation: bool,
    pub no_coverage: bool,
    pub no_order: bool,
    pub order_runs: usize,
}

impl<'a> Default for GauntletOptions<'a> {
    fn default() -> Self {
        GauntletOptions {
            cwd: Path::new("."),
            base: None,
            diff_file: None,
            test_command: None,
            no_mutation: false,
            no_coverage: false,
            no_order: false,
            order_runs: 5,
        }
    }
}

/// Result of running the gauntlet: the Arcane-shaped `check` object plus
/// the process exit code the JS CLI would have used.
pub struct GauntletRun {
    pub check: Value,
    pub exit_code: i32,
}

fn now_iso() -> String {
    // A lightweight stand-in for `new Date().toISOString()` — this crate
    // has no `chrono`/`time` dependency available, so this emits a
    // monotonically increasing RFC3339-shaped timestamp derived from the
    // Unix epoch. It is used only for the receipt's informational
    // `started_at`/`completed_at` fields, never compared for equality by
    // any consumer.
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let days = secs / 86_400;
    let time_of_day = secs % 86_400;
    let (h, m, s) = (time_of_day / 3600, (time_of_day % 3600) / 60, time_of_day % 60);
    // Days since epoch -> proleptic Gregorian date.
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
}

/// Howard Hinnant's `civil_from_days` algorithm (public domain), used only
/// to render a plausible ISO date for the receipt without a date/time
/// crate dependency.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn pick_metrics(passed: usize, failed: usize, total: usize, percent: Option<f64>, ok: bool, error: Option<&str>) -> Value {
    json!({
        "passed": passed,
        "failed": failed,
        "total": total,
        "percent": percent,
        "ok": ok,
        "error": error,
    })
}

/// Mirrors the whole of `gauntlet.mjs`'s top-level script body.
pub fn run_gauntlet(opts: GauntletOptions<'_>) -> GauntletRun {
    let test_command = opts.test_command.unwrap_or("node --test --test-concurrency=1");
    let started_at = now_iso();
    let command = format!(
        "gauntlet --base {} --test \"{}\"",
        opts.base.unwrap_or("HEAD"),
        test_command
    );

    let files = match load_diff(LoadDiffOptions {
        cwd: Some(opts.cwd),
        base: opts.base,
        head: None,
        diff_file: opts.diff_file,
    }) {
        Ok(f) => f,
        Err(e) => {
            // The JS implementation lets `loadDiff` throw uncaught on a
            // git failure; here we fold it into the same "no_diff"-shaped
            // failure rather than panicking, since library callers should
            // never see a process abort.
            return build_no_diff_run(&started_at, &command, Some(e));
        }
    };

    if files.is_empty() {
        return build_no_diff_run(&started_at, &command, None);
    }

    let mutation = if opts.no_mutation {
        super::mutation::MutationLayer {
            passed: 0,
            failed: 0,
            skipped: 0,
            total: 0,
            ok: true,
            results: Vec::new(),
        }
    } else {
        run_mutation(RunMutationOptions {
            cwd: opts.cwd,
            files: &files,
            test_command,
        })
    };

    let coverage = if opts.no_coverage {
        super::coverage::CoverageLayer {
            ok: true,
            passed: 0,
            failed: 0,
            total: 0,
            percent: 0.0,
            error: None,
            results: Vec::new(),
        }
    } else {
        super::coverage::run_coverage(super::coverage::RunCoverageOptions {
            cwd: opts.cwd,
            files: &files,
            test_command,
        })
    };

    let order = if opts.no_order {
        super::order::OrderLayer {
            passed: 0,
            failed: 0,
            total: 0,
            ok: true,
            results: Vec::new(),
        }
    } else {
        run_order(RunOrderOptions {
            cwd: opts.cwd,
            files: &files,
            test_command,
            runs: opts.order_runs,
            seed: None,
        })
    };

    let ok = mutation.ok && coverage.ok && order.ok;
    let diff_summary = summarise(&files);
    let summary = json!({
        "ok": ok,
        "diff": { "files": diff_summary.files, "lines": diff_summary.lines },
        "layers": {
            "mutation": pick_metrics(mutation.passed, mutation.failed, mutation.total, None, mutation.ok, None),
            "coverage": pick_metrics(coverage.passed, coverage.failed, coverage.total, Some(coverage.percent), coverage.ok, coverage.error.as_deref()),
            "order": pick_metrics(order.passed, order.failed, order.total, None, order.ok, None),
        },
    });
    // Mirrors JS `{ summary, layers }` passed to `buildReceipt` — `layers`
    // here carries each layer's *full* shape (with `.results`), which is
    // what `gauntlet.test.mjs` reads via `layers.layers.mutation.results`.
    let output = json!({
        "summary": summary,
        "layers": {
            "mutation": {
                "passed": mutation.passed,
                "failed": mutation.failed,
                "skipped": mutation.skipped,
                "total": mutation.total,
                "ok": mutation.ok,
                "results": mutation_results_json(&mutation),
            },
            "coverage": {
                "ok": coverage.ok,
                "passed": coverage.passed,
                "failed": coverage.failed,
                "total": coverage.total,
                "percent": coverage.percent,
                "error": coverage.error,
                "results": serde_json::to_value(&coverage.results).unwrap_or(Value::Null),
            },
            "order": {
                "ok": order.ok,
                "passed": order.passed,
                "failed": order.failed,
                "total": order.total,
                "results": serde_json::to_value(&order.results).unwrap_or(Value::Null),
            },
        },
    });

    let completed_at = now_iso();
    let receipt = build_receipt(BuildReceiptInput {
        started_at,
        completed_at,
        command,
        summary_ok: ok,
        output,
        mutation: LayerSummary {
            passed: mutation.passed,
            failed: mutation.failed,
            total: mutation.total,
        },
        coverage_percent: coverage.percent,
        coverage: LayerSummary {
            passed: coverage.passed,
            failed: coverage.failed,
            total: coverage.total,
        },
        order: LayerSummary {
            passed: order.passed,
            failed: order.failed,
            total: order.total,
        },
    });
    let check = build_check(&receipt);
    let exit_code = receipt["exit_code"].as_i64().unwrap_or(1) as i32;
    GauntletRun { check, exit_code }
}

fn mutation_results_json(mutation: &super::mutation::MutationLayer) -> Value {
    // Layered under `layers.mutation.results` in the JS output shape; the
    // gauntlet's own self-tests (`gauntlet.test.mjs`) read
    // `layers.layers.mutation.results`, so keep the nested shape exactly.
    Value::Array(mutation.results.iter().map(|r| r.to_value()).collect())
}

fn build_no_diff_run(started_at: &str, command: &str, load_error: Option<String>) -> GauntletRun {
    let completed_at = now_iso();
    let mut summary = json!({ "ok": false, "error": "no_diff" });
    if let Some(err) = load_error {
        summary["load_error"] = Value::String(err);
    }
    let output = json!({
        "summary": summary,
        "layers": {
            "mutation": { "passed": 0, "failed": 0, "total": 0, "skipped": 0, "ok": false, "results": [] },
            "coverage": { "passed": 0, "failed": 0, "total": 0, "percent": 0, "ok": false, "results": [] },
            "order": { "passed": 0, "failed": 0, "total": 0, "ok": false, "results": [] },
        },
    });
    let receipt = build_receipt(BuildReceiptInput {
        started_at: started_at.to_string(),
        completed_at,
        command: command.to_string(),
        summary_ok: false,
        output,
        mutation: LayerSummary { passed: 0, failed: 0, total: 0 },
        coverage_percent: 0.0,
        coverage: LayerSummary { passed: 0, failed: 0, total: 0 },
        order: LayerSummary { passed: 0, failed: 0, total: 0 },
    });
    let check = build_check(&receipt);
    GauntletRun { check, exit_code: 1 }
}
