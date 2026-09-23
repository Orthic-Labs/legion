//! Port of `skills/seo/scripts/keyword_planner.py`.
//!
//! Google Ads API — Keyword Planner for SEO keyword research (search
//! volume, CPC, and competition data). Requires a Google Ads Manager
//! account with a developer token.
//!
//! This module ports the pure, unit-testable core: customer-id
//! normalization, seed-keyword splitting, micros→currency conversion,
//! keyword-idea sorting, CLI bid-string formatting, and Google Ads
//! exception-message joining. The actual `GoogleAdsClient` call
//! (`google.ads.googleads`, config loaded via `google_auth.load_config` —
//! owned by a different chunk) needs a gRPC/OAuth stack this crate does
//! not depend on (see the w2_031 report). Callers drive a real Ads API
//! client behind [`AdsClient`] and shape results with the helpers below,
//! matching Python's field names, sort order, and formatting exactly.

use serde::Serialize;

pub const DEFAULT_LANGUAGE_ID: &str = "1000"; // English
pub const DEFAULT_LOCATION_ID: &str = "2840"; // United States
pub const DEFAULT_LIMIT: usize = 50;

/// `customer_id.replace("-", "")` in `_build_ads_client`.
pub fn normalize_customer_id(customer_id: &str) -> String {
    customer_id.replace('-', "")
}

/// `[k.strip() for k in args.keywords.split(",")]` — shared by both the
/// `ideas` and `volume` CLI commands.
pub fn split_keywords(raw: &str) -> Vec<String> {
    raw.split(',').map(str::trim).map(str::to_string).collect()
}

/// `metrics.low_top_of_page_bid_micros / 1_000_000 if ... else None`.
pub fn micros_to_currency(micros: Option<i64>) -> Option<f64> {
    match micros {
        Some(0) | None => None,
        Some(m) => Some(m as f64 / 1_000_000.0),
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct MonthlyVolume {
    pub year: i32,
    pub month: i32,
    pub volume: i64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct KeywordIdea {
    pub keyword: String,
    pub avg_monthly_searches: Option<i64>,
    pub competition: String,
    pub competition_index: Option<i64>,
    pub low_top_of_page_bid: Option<f64>,
    pub high_top_of_page_bid: Option<f64>,
    pub monthly_volumes: Vec<MonthlyVolume>,
}

/// `monthly_volumes[-12:] if monthly_volumes else []` — keep only the last
/// 12 entries (or fewer, or none).
pub fn last_12_months(mut volumes: Vec<MonthlyVolume>) -> Vec<MonthlyVolume> {
    if volumes.len() > 12 {
        volumes.drain(0..volumes.len() - 12);
    }
    volumes
}

/// `result["ideas"].sort(key=lambda k: k.get("avg_monthly_searches", 0) or 0, reverse=True)`.
///
/// Python's `or 0` also treats `avg_monthly_searches == 0` (falsy) as `0`
/// for the sort key, same as `None`; that is already the effective value
/// here since both `None` and `Some(0)` sort as `0`. Rust's stable sort
/// preserves relative order of equal keys, matching Python's stable
/// `list.sort`.
pub fn sort_ideas_desc(ideas: &mut [KeywordIdea]) {
    ideas.sort_by(|a, b| {
        let ka = a.avg_monthly_searches.unwrap_or(0);
        let kb = b.avg_monthly_searches.unwrap_or(0);
        kb.cmp(&ka)
    });
}

/// `GoogleAdsException` handling: `'; '.join(err.message for err in e.failure.errors)`.
pub fn join_ads_error_messages(messages: &[String]) -> String {
    format!("Google Ads API error: {}", messages.join("; "))
}

/// Non-`GoogleAdsException` catch-all: `f"Keyword Planner error: {e}"` /
/// `f"Keyword volume error: {e}"`.
pub fn generic_ideas_error(e: &str) -> String {
    format!("Keyword Planner error: {e}")
}

pub fn generic_volume_error(e: &str) -> String {
    format!("Keyword volume error: {e}")
}

/// Text-mode bid string, from `main()`'s pretty-printer:
/// `f"${bid_low:.2f}-${bid_high:.2f}" if bid_low and bid_high else "N/A"`.
/// Python's `if bid_low and bid_high` is falsy for `None` *and* `0.0`.
pub fn format_bid_str(low: Option<f64>, high: Option<f64>) -> String {
    let low_truthy = low.is_some_and(|v| v != 0.0);
    let high_truthy = high.is_some_and(|v| v != 0.0);
    if low_truthy && high_truthy {
        format!("${:.2}-${:.2}", low.unwrap(), high.unwrap())
    } else {
        "N/A".to_string()
    }
}

/// Client boundary a caller plugs a real Google Ads client behind for
/// `generate_keyword_ideas`/`get_keyword_volumes`.
pub trait AdsClient {
    fn generate_keyword_ideas(
        &self,
        customer_id: &str,
        seed_keywords: &[String],
        language_id: &str,
        location_id: &str,
    ) -> Result<Vec<KeywordIdea>, AdsError>;

    fn generate_keyword_volumes(
        &self,
        customer_id: &str,
        keywords: &[String],
        language_id: &str,
        location_id: &str,
    ) -> Result<Vec<KeywordIdea>, AdsError>;
}

#[derive(Debug, Clone)]
pub enum AdsError {
    /// `GoogleAdsException` with per-error messages.
    GoogleAds(Vec<String>),
    /// Any other exception, carrying its `str(e)`.
    Other(String),
}

impl AdsError {
    /// The exact error string Python assigns to `result["error"]`.
    pub fn ideas_message(&self) -> String {
        match self {
            AdsError::GoogleAds(msgs) => join_ads_error_messages(msgs),
            AdsError::Other(e) => generic_ideas_error(e),
        }
    }

    pub fn volume_message(&self) -> String {
        match self {
            AdsError::GoogleAds(msgs) => join_ads_error_messages(msgs),
            AdsError::Other(e) => generic_volume_error(e),
        }
    }
}

/// `generate_keyword_ideas(seed_keywords, ...)`, generalized over
/// [`AdsClient`]. Applies the `limit` truncation and descending sort exactly
/// as Python does (sort happens once, over the already-limited list, since
/// the Python loop breaks at `limit` before sorting).
pub fn generate_keyword_ideas_with<C: AdsClient>(
    client: &C,
    customer_id: &str,
    seed_keywords: &[String],
    language_id: &str,
    location_id: &str,
    limit: usize,
) -> (Vec<KeywordIdea>, Option<String>) {
    match client.generate_keyword_ideas(customer_id, seed_keywords, language_id, location_id) {
        Ok(mut ideas) => {
            ideas.truncate(limit);
            sort_ideas_desc(&mut ideas);
            (ideas, None)
        }
        Err(e) => (Vec::new(), Some(e.ideas_message())),
    }
}

pub fn get_keyword_volumes_with<C: AdsClient>(
    client: &C,
    customer_id: &str,
    keywords: &[String],
    language_id: &str,
    location_id: &str,
) -> (Vec<KeywordIdea>, Option<String>) {
    match client.generate_keyword_volumes(customer_id, keywords, language_id, location_id) {
        Ok(kws) => (kws, None),
        Err(e) => (Vec::new(), Some(e.volume_message())),
    }
}
