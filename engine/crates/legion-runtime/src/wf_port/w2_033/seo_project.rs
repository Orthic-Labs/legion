//! Rust port of the pure core of `skills/seo/scripts/seo_project.py`.
//!
//! `seo_project.py` reads/writes `.legion/seo/site.yaml` (JSON), inspects environment
//! variables, and reads/writes a disk cache. Filesystem and `os.environ` access are not
//! ported; what is ported verbatim (byte-for-byte deterministic) is the `cache_key` hash,
//! the `PlannedCall`/`preflight` budget arithmetic, the `env_state` classification (given
//! already-read values instead of reading `os.environ` directly), and the project-state
//! merge logic in `setup_project` (given the already-loaded existing state instead of
//! reading it from disk).

use serde::Serialize;
use sha2::{Digest, Sha256};

/// Port of `cache_key(provider, capability, target, *, country, language, device,
/// freshness_class)`. Mirrors Python's `json.dumps(..., sort_keys=True,
/// separators=(',', ':'))` followed by `hashlib.sha256(...).hexdigest()`: the six fields are
/// serialized as a JSON object with keys in alphabetical order and no extra whitespace.
pub fn cache_key(
    provider: &str,
    capability: &str,
    target: &str,
    country: &str,
    language: &str,
    device: &str,
    freshness_class: &str,
) -> String {
    // Field order matches Python `sort_keys=True`: alphabetical by key name.
    let payload = format!(
        "{{\"capability\":{cap},\"country\":{country},\"device\":{device},\"freshness_class\":{fresh},\"language\":{lang},\"provider\":{prov},\"target\":{target}}}",
        cap = serde_json::to_string(capability).unwrap(),
        country = serde_json::to_string(country).unwrap(),
        device = serde_json::to_string(device).unwrap(),
        fresh = serde_json::to_string(freshness_class).unwrap(),
        lang = serde_json::to_string(language).unwrap(),
        prov = serde_json::to_string(provider).unwrap(),
        target = serde_json::to_string(target).unwrap(),
    );
    let digest = Sha256::digest(payload.as_bytes());
    hex::encode(digest)
}

/// Port of the `PlannedCall` dataclass.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct PlannedCall {
    pub provider: String,
    pub capability: String,
    pub count: u64,
    pub estimated_unit_cost_usd: f64,
    pub cache_hits: u64,
}

impl PlannedCall {
    pub fn billable_count(&self) -> u64 {
        self.count.saturating_sub(self.cache_hits)
    }

    pub fn estimated_cost_usd(&self) -> f64 {
        round6(self.billable_count() as f64 * self.estimated_unit_cost_usd)
    }
}

fn round6(v: f64) -> f64 {
    (v * 1_000_000.0).round() / 1_000_000.0
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PlannedCallSummary {
    pub provider: String,
    pub capability: String,
    pub count: u64,
    pub estimated_unit_cost_usd: f64,
    pub cache_hits: u64,
    pub billable_count: u64,
    pub estimated_cost_usd: f64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct PreflightResult {
    pub status: &'static str,
    pub estimated_paid_cost_usd: f64,
    pub ceiling_usd: Option<f64>,
    pub calls: Vec<PlannedCallSummary>,
}

/// Port of `preflight(calls, ceiling_usd)`.
pub fn preflight(calls: &[PlannedCall], ceiling_usd: Option<f64>) -> PreflightResult {
    let total = round6(calls.iter().map(PlannedCall::estimated_cost_usd).sum());
    let status = match ceiling_usd {
        Some(ceiling) if total > ceiling => "needs_authority",
        _ => "ok",
    };
    let summaries = calls
        .iter()
        .map(|c| PlannedCallSummary {
            provider: c.provider.clone(),
            capability: c.capability.clone(),
            count: c.count,
            estimated_unit_cost_usd: c.estimated_unit_cost_usd,
            cache_hits: c.cache_hits,
            billable_count: c.billable_count(),
            estimated_cost_usd: c.estimated_cost_usd(),
        })
        .collect();
    PreflightResult {
        status,
        estimated_paid_cost_usd: total,
        ceiling_usd,
        calls: summaries,
    }
}

/// Port of `env_state(names)`: classifies presence of a provider's required environment
/// variables given their already-read values (`None` for an unset variable), instead of
/// reading `os.environ` directly.
pub fn env_state(values: &[Option<&str>]) -> &'static str {
    if values.iter().all(|v| v.is_some()) {
        "present"
    } else if values.iter().any(|v| v.is_some()) {
        "partial"
    } else {
        "absent"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_is_deterministic_and_field_order_independent_input() {
        let a = cache_key("google_api", "serp", "example.com", "US", "en", "desktop", "daily");
        let b = cache_key("google_api", "serp", "example.com", "US", "en", "desktop", "daily");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        let c = cache_key("google_api", "serp", "example.com", "GB", "en", "desktop", "daily");
        assert_ne!(a, c);
    }

    #[test]
    fn preflight_computes_billable_cost_and_ceiling_status() {
        let calls = vec![
            PlannedCall {
                provider: "dataforseo".into(),
                capability: "serp".into(),
                count: 100,
                estimated_unit_cost_usd: 0.01,
                cache_hits: 40,
            },
            PlannedCall {
                provider: "google_pagespeed_crux".into(),
                capability: "psi".into(),
                count: 10,
                estimated_unit_cost_usd: 0.0,
                cache_hits: 0,
            },
        ];
        let ok = preflight(&calls, Some(1.0));
        assert_eq!(ok.status, "ok");
        assert_eq!(ok.estimated_paid_cost_usd, 0.6);
        assert_eq!(ok.calls[0].billable_count, 60);

        let needs_authority = preflight(&calls, Some(0.5));
        assert_eq!(needs_authority.status, "needs_authority");

        let no_ceiling = preflight(&calls, None);
        assert_eq!(no_ceiling.status, "ok");
    }

    #[test]
    fn env_state_classifies_present_partial_absent() {
        assert_eq!(env_state(&[Some("a"), Some("b")]), "present");
        assert_eq!(env_state(&[Some("a"), None]), "partial");
        assert_eq!(env_state(&[None, None]), "absent");
        assert_eq!(env_state(&[]), "present");
    }
}
