//! Integration tests for packet `ap`: wiring the antipattern registry
//! (`skills/designer/engine/scripts/detector/registry/antipatterns.mjs`,
//! ported at `wf_port::w2_014::antipatterns`) into `wf_port::r07`'s
//! `AntipatternLookup` consumers (`detect_url`/`finding`/`filter_by_providers`)
//! via `wf_port::r07::RegistryLookup`, and into `wf_port::r05`'s
//! `RealDetectors` (`detect_text`/`detect_html`'s `filterByProviders` step).
//!
//! No network or real browser: `ChromeDriver`/`PageFetcher` are faked, per
//! the port's "I/O behind a trait, tested with fakes" rule.

use serde_json::{json, Value};

use legion_runtime::wf_port::r05::cli::{Detectors, UrlScanOptions};
use legion_runtime::wf_port::r05::real_detectors::RealDetectors;
use legion_runtime::wf_port::r07::browser::ChromeDriver;
use legion_runtime::wf_port::r07::findings::{finding, finding_at_line, filter_by_providers, Finding};
use legion_runtime::wf_port::r07::RegistryLookup;
use legion_runtime::wf_port::r08::sweep_live::PageFetcher;

// ---- RegistryLookup itself, against the real ANTIPATTERNS table ----

#[test]
fn registry_lookup_resolves_a_real_rule() {
    let reg = RegistryLookup;
    let f = finding(&reg, "gradient-text", "app.css", "background-clip: text").unwrap();
    assert_eq!(f.name, "Gradient text");
    assert_eq!(f.severity, "warning");
}

#[test]
fn registry_lookup_unknown_id_errors_like_js_throw() {
    let reg = RegistryLookup;
    assert!(finding(&reg, "not-a-real-rule", "x", "y").is_err());
}

#[test]
fn registry_lookup_filters_gated_rules_by_provider() {
    let reg = RegistryLookup;
    let findings = vec![
        finding_at_line(&reg, "side-tab", "a.css", "s", 1).unwrap(), // ungated
        finding_at_line(&reg, "gpt-thin-border-wide-shadow", "a.css", "s", 2).unwrap(), // gpt
        finding_at_line(&reg, "image-hover-transform", "a.css", "s", 3).unwrap(), // gemini
    ];
    let kept: Vec<Finding> = filter_by_providers(&reg, findings, &["gpt".to_string()]);
    let ids: Vec<&str> = kept.iter().map(|f| f.antipattern.as_str()).collect();
    assert_eq!(ids, vec!["side-tab", "gpt-thin-border-wide-shadow"]);
}

// ---- RealDetectors: detect_text/detect_html now gate on the registry ----

struct FakeDriver {
    responses: Vec<Value>,
}
impl ChromeDriver for FakeDriver {
    fn navigate(&mut self, _url: &str) -> Result<(), String> {
        Ok(())
    }
    fn evaluate(&mut self, _expression: &str) -> Result<Value, String> {
        Ok(self.responses.remove(0))
    }
}

struct FakeFetcher;
impl PageFetcher for FakeFetcher {
    fn fetch_text(&self, _url: &str) -> Result<String, String> {
        Ok(String::new())
    }
    fn check_status(&self, _url: &str) -> Option<u16> {
        Some(200)
    }
}

#[test]
fn real_detectors_detect_text_passes_through_when_no_providers_gated_off() {
    // The real registry does have gated rules, but none of the findings
    // `detect_text` produces from this content are gated ones, so nothing
    // should be dropped by the wiring itself.
    let mut driver = FakeDriver { responses: vec![] };
    let registry = RegistryLookup;
    let fetcher = FakeFetcher;
    let providers: Vec<String> = vec![];
    let mut detectors = RealDetectors {
        driver: &mut driver,
        registry: &registry,
        fetcher: &fetcher,
        browser_script: "",
        providers: &providers,
    };
    // side-tab is ungated: a matching source line must survive the
    // provider-filter step regardless of `providers`.
    let content = ".card { border-left: 4px solid #6366f1; }\n";
    let findings = detectors.detect_text(content, "card.css", None);
    assert!(
        findings.iter().any(|f| f.antipattern == "side-tab"),
        "ungated finding should survive filter_cli_findings_by_providers: {findings:?}"
    );
}

#[test]
fn real_detectors_url_scan_uses_the_same_registry() {
    let mut driver = FakeDriver {
        responses: vec![Value::Null, Value::Null, json!([])],
    };
    let registry = RegistryLookup;
    let fetcher = FakeFetcher;
    let providers: Vec<String> = vec![];
    let mut detectors = RealDetectors {
        driver: &mut driver,
        registry: &registry,
        fetcher: &fetcher,
        browser_script: "",
        providers: &providers,
    };
    let opts = UrlScanOptions {
        viewport: None,
        providers: vec![],
    };
    let findings = detectors.detect_url("https://example.com", &opts).unwrap();
    assert!(findings.is_empty());
}

