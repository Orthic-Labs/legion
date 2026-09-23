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
        .map(|day| (day.clone(), ledger.daily.get(day).cloned().unwrap_or_default()))
        .collect()
}

/// `today` command support.
pub fn today_usage<'a>(ledger: &'a CostLedger, today: &str) -> DailyUsage {
    ledger.daily.get(today).cloned().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_cost_exact_match() {
        let l = lookup_cost("gemini-3.1-flash-image-preview", "2K", false);
        assert_eq!(l.cost, 0.078);
        assert!(l.warnings.is_empty());
    }

    #[test]
    fn lookup_cost_batch_discount() {
        let l = lookup_cost("gemini-3.1-flash-image-preview", "1K", true);
        assert!((l.cost - 0.0195).abs() < 1e-9);
    }

    #[test]
    fn lookup_cost_partial_match() {
        // "gemini-3.1-flash-image-preview" contains "3.1-flash"
        let l = lookup_cost("3.1-flash", "512", false);
        assert_eq!(l.cost, 0.020);
        assert!(l.warnings.is_empty());
    }

    #[test]
    fn lookup_cost_unknown_model_warns_and_falls_back() {
        let l = lookup_cost("totally-unknown-model", "1K", false);
        assert_eq!(l.cost, 0.039);
        assert_eq!(
            l.warnings,
            vec![CostWarning::UnknownModel("totally-unknown-model".into())]
        );
    }

    #[test]
    fn lookup_cost_unknown_resolution_warns_and_uses_1k() {
        let l = lookup_cost("gemini-3.1-flash-image-preview", "8K", false);
        assert_eq!(l.cost, 0.039);
        assert_eq!(
            l.warnings,
            vec![CostWarning::UnknownResolution("8K".into())]
        );
    }

    #[test]
    fn truncate_prompt_caps_at_100_chars() {
        let long = "a".repeat(150);
        assert_eq!(truncate_prompt(&long).chars().count(), 100);
        assert_eq!(truncate_prompt("short"), "short");
    }

    #[test]
    fn log_entry_updates_totals_and_daily() {
        let mut ledger = CostLedger::default();
        let (r1, w1) = log_entry(
            &mut ledger,
            "gemini-3.1-flash-image-preview",
            "1K",
            "a cat",
            false,
            "2026-09-23",
            "2026-09-23T00:00:00",
        );
        assert!(w1.is_empty());
        assert_eq!(r1.cost, 0.039);
        assert_eq!(r1.total_images, 1);
        assert_eq!(ledger.total_images, 1);
        assert_eq!(ledger.total_cost, 0.039);
        assert_eq!(ledger.daily["2026-09-23"].count, 1);

        let (r2, _) = log_entry(
            &mut ledger,
            "gemini-3.1-flash-image-preview",
            "2K",
            "a dog",
            false,
            "2026-09-23",
            "2026-09-23T00:01:00",
        );
        assert_eq!(r2.total_images, 2);
        assert_eq!(ledger.total_cost, round4(0.039 + 0.078));
        assert_eq!(ledger.daily["2026-09-23"].count, 2);
        assert_eq!(ledger.entries.len(), 2);
    }

    #[test]
    fn estimate_reports_batch_discount_when_not_already_batch() {
        let (lookup, total, batch_total) = estimate("gemini-3.1-flash-image-preview", "1K", 10, false);
        assert_eq!(lookup.cost, 0.039);
        assert_eq!(total, round3(0.039 * 10.0));
        assert_eq!(batch_total, Some(round3(0.039 * 0.5 * 10.0)));
    }

    #[test]
    fn estimate_omits_batch_discount_line_when_already_batch() {
        let (_, _, batch_total) = estimate("gemini-3.1-flash-image-preview", "1K", 10, true);
        assert_eq!(batch_total, None);
    }

    #[test]
    fn reset_ledger_is_empty_defaults() {
        let ledger = reset_ledger();
        assert_eq!(ledger.total_cost, 0.0);
        assert_eq!(ledger.total_images, 0);
        assert!(ledger.entries.is_empty());
        assert!(ledger.daily.is_empty());
    }

    #[test]
    fn last_n_days_sorted_descending_and_capped() {
        let mut ledger = CostLedger::default();
        for day in ["2026-09-01", "2026-09-05", "2026-09-03"] {
            ledger.daily.insert(day.to_string(), DailyUsage { count: 1, cost: 0.01 });
        }
        let days = last_n_days(&ledger, 2);
        assert_eq!(
            days.iter().map(|(d, _)| d.clone()).collect::<Vec<_>>(),
            vec!["2026-09-05".to_string(), "2026-09-03".to_string()]
        );
    }

    #[test]
    fn today_usage_defaults_to_zero_when_missing() {
        let ledger = CostLedger::default();
        let u = today_usage(&ledger, "2026-09-23");
        assert_eq!(u, DailyUsage::default());
    }

    #[test]
    fn ledger_json_round_trips_python_shape() {
        let mut ledger = CostLedger::default();
        log_entry(
            &mut ledger,
            "gemini-2.5-flash-image",
            "512",
            "x",
            true,
            "2026-09-23",
            "2026-09-23T00:00:00",
        );
        let json = serde_json::to_string(&ledger).unwrap();
        assert!(json.contains("\"total_cost\""));
        assert!(json.contains("\"total_images\""));
        assert!(json.contains("\"entries\""));
        assert!(json.contains("\"daily\""));
        let back: CostLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(back, ledger);
    }
}
