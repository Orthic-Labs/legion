//! Port of `skills/seo/extensions/banana/scripts/cost_tracker.py`.
//!
//! The Python CLI reads/writes a JSON ledger at `~/.banana/costs.json` and
//! prints human text or JSON to stdout. This port keeps the ledger as a
//! plain, serializable struct (`CostLedger`) and the pricing/estimation
//! logic as pure functions so the caller decides how to persist and how to
//! render output; no filesystem or process-exit side effects live here.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Cost per image in USD (approximate, based on ~1,290 output tokens).
/// Mirrors the Python `PRICING` table exactly (model -> resolution -> USD).
pub fn pricing_table() -> BTreeMap<&'static str, BTreeMap<&'static str, f64>> {
    let mut table = BTreeMap::new();

    let mut flash_3_1 = BTreeMap::new();
    flash_3_1.insert("512", 0.020);
    flash_3_1.insert("1K", 0.039);
    flash_3_1.insert("2K", 0.078);
    flash_3_1.insert("4K", 0.156);
    table.insert("gemini-3.1-flash-image-preview", flash_3_1);

    let mut flash_2_5 = BTreeMap::new();
    flash_2_5.insert("512", 0.020);
    flash_2_5.insert("1K", 0.039);
    table.insert("gemini-2.5-flash-image", flash_2_5);

    table
}

/// Batch API gets a 50% discount, matching Python's `BATCH_DISCOUNT`.
pub const BATCH_DISCOUNT: f64 = 0.5;

const DEFAULT_MODEL: &str = "gemini-3.1-flash-image-preview";
const VALID_RESOLUTIONS: [&str; 4] = ["512", "1K", "2K", "4K"];

/// A single warning surfaced by [`lookup_cost`], mirroring the Python
/// `print(..., file=sys.stderr)` warnings emitted on unknown model /
/// resolution input. The caller decides where to render these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CostWarning {
    UnknownModel(String),
    UnknownResolution(String),
}

/// Result of a cost lookup: the resolved per-image cost plus any warnings
/// that Python would have printed to stderr along the way.
#[derive(Debug, Clone, PartialEq)]
pub struct CostLookup {
    pub cost: f64,
    pub warnings: Vec<CostWarning>,
}

/// Look up cost for a model+resolution combination.
///
/// Faithful port of `_lookup_cost`: exact match first, then a substring
/// partial match (`key in model or model in key`) over the pricing table's
/// natural (insertion) order, then a fallback to 3.1 Flash pricing with a
/// warning. An unknown resolution likewise warns and falls back to "1K".
pub fn lookup_cost(model: &str, resolution: &str, batch: bool) -> CostLookup {
    let table = pricing_table();
    let mut warnings = Vec::new();

    let model_pricing = table.get(model).cloned().or_else(|| {
        // Partial match: iterate keys in the same order Python's dict
        // iteration would (insertion order == the literal's order above).
        for key in ["gemini-3.1-flash-image-preview", "gemini-2.5-flash-image"] {
            if key.contains(model) || model.contains(key) {
                return table.get(key).cloned();
            }
        }
        None
    });

    let model_pricing = model_pricing.unwrap_or_else(|| {
        warnings.push(CostWarning::UnknownModel(model.to_string()));
        table.get(DEFAULT_MODEL).cloned().unwrap()
    });

    if !VALID_RESOLUTIONS.contains(&resolution) {
        warnings.push(CostWarning::UnknownResolution(resolution.to_string()));
    }

    let mut cost = *model_pricing
        .get(resolution)
        .unwrap_or_else(|| model_pricing.get("1K").unwrap_or(&0.039));
    if batch {
        cost *= BATCH_DISCOUNT;
    }

    CostLookup { cost, warnings }
}

/// One logged generation entry. Mirrors the Python `entry` dict; `prompt`
/// is truncated to 100 chars exactly like Python's `args.prompt[:100]`
/// (by Unicode scalar, matching Python's by-codepoint slicing).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LedgerEntry {
    pub ts: String,
    pub model: String,
    pub res: String,
    pub cost: f64,
    pub prompt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DailyUsage {
    pub count: u64,
    pub cost: f64,
}

/// The full ledger, matching the Python JSON shape:
/// `{"total_cost": f64, "total_images": u64, "entries": [...], "daily": {...}}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CostLedger {
    pub total_cost: f64,
    pub total_images: u64,
    pub entries: Vec<LedgerEntry>,
    pub daily: BTreeMap<String, DailyUsage>,
}

impl Default for CostLedger {
    fn default() -> Self {
        Self {
            total_cost: 0.0,
            total_images: 0,
            entries: Vec::new(),
            daily: BTreeMap::new(),
        }
    }
}

/// Round to 4 decimal places the way Python's `round(x, 4)` does for the
/// typical positive-cost values this module deals with.
fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

/// Round to 3 decimal places, matching Python's `round(x, 3)`.
fn round3(value: f64) -> f64 {
    (value * 1_000.0).round() / 1_000.0
}

/// Truncate a prompt to at most 100 Unicode scalar values, matching
/// Python's `args.prompt[:100]` (Python strings slice by codepoint).
pub fn truncate_prompt(prompt: &str) -> String {
    prompt.chars().take(100).collect()
}

/// Result of [`log_entry`]: the entry appended plus the ledger's new totals,
/// matching the `{"logged": true, "cost", "total_cost", "total_images"}`
/// JSON Python prints.
#[derive(Debug, Clone, PartialEq)]
pub struct LogResult {
    pub cost: f64,
    pub total_cost: f64,
    pub total_images: u64,
}

/// Log a generation into the ledger (in place). `today` and `now` are
/// injected (Python uses `datetime.now(timezone.utc)`) so this stays pure
/// and testable; callers pass `"%Y-%m-%d"` / `"%Y-%m-%dT%H:%M:%S"`-formatted
/// UTC strings.
pub fn log_entry(
    ledger: &mut CostLedger,
    model: &str,
    resolution: &str,
    prompt: &str,
    batch: bool,
    today: &str,
    now: &str,
) -> (LogResult, Vec<CostWarning>) {
    let lookup = lookup_cost(model, resolution, batch);
    let cost = lookup.cost;

    let entry = LedgerEntry {
        ts: now.to_string(),
        model: model.to_string(),
        res: resolution.to_string(),
        cost,
        prompt: truncate_prompt(prompt),
    };
    ledger.entries.push(entry);
    ledger.total_cost = round4(ledger.total_cost + cost);
    ledger.total_images += 1;

    let daily = ledger.daily.entry(today.to_string()).or_default();
    daily.count += 1;
    daily.cost = round4(daily.cost + cost);

    (
        LogResult {
            cost,
            total_cost: ledger.total_cost,
            total_images: ledger.total_images,
        },
        lookup.warnings,
    )
}

/// Estimate cost for a batch of `count` images, matching `cmd_estimate`.
/// Returns `(cost_per_image, total, optional_batch_discounted_total)`; the
/// third element mirrors Python only printing the batch estimate line when
/// `--batch` was NOT already passed.
pub fn estimate(
    model: &str,
    resolution: &str,
    count: u64,
    batch: bool,
) -> (CostLookup, f64, Option<f64>) {
    let lookup = lookup_cost(model, resolution, batch);
    let total = round3(lookup.cost * count as f64);
    let batch_total = if !batch {
        Some(round3(lookup.cost * BATCH_DISCOUNT * count as f64))
    } else {
        None
    };
    (lookup, total, batch_total)
}

/// Reset the ledger to empty defaults, matching `cmd_reset` after the
/// `--confirm` gate (the gate itself is a caller/CLI concern).
pub fn reset_ledger() -> CostLedger {
    CostLedger::default()
}

/// `summary` command support: return up to the last 7 days, most recent
/// first, matching `sorted(daily.keys(), reverse=True)[:7]`.
pub fn last_n_days(ledger: &CostLedger, n: usize) -> Vec<(String, DailyUsage)> {
    let mut days: Vec<&String> = ledger.daily.keys().collect();
    days.sort_by(|a, b| b.cmp(a));
    days.into_iter()
        .take(n)
        .map(|day| {
            (
                day.clone(),
                ledger.daily.get(day).cloned().unwrap_or_default(),
            )
        })
        .collect()
}

/// `today` command support.
pub fn today_usage(ledger: &CostLedger, today: &str) -> DailyUsage {
    ledger.daily.get(today).cloned().unwrap_or_default()
}
