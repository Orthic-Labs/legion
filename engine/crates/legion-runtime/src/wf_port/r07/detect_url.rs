//! Port of `detectUrl`/`detectUrlCdp`/`createBrowserDetector` and
//! `serializeDesignSystemForBrowser` from `detect-url.mjs`/`detect-url-cdp.mjs`.
//!
//! See the [`super`] module doc for why the Puppeteer-vs-CDP lane split in
//! the JS collapses to a single [`ChromeDriver`]-backed path here, and for
//! the visual-contrast gap.

use serde_json::{json, Value};

use super::browser::ChromeDriver;
use super::findings::{filter_by_providers, AntipatternLookup, Finding};

/// Prefix on `Err` strings that mean "this check could not run", as opposed to
/// a real failure or a clean result. Callers must never treat such an error as
/// zero findings. Format: `unavailable:<reason>`.
pub const UNAVAILABLE_PREFIX: &str = "unavailable:";

/// The injected browser detector (`window.impeccableDetect`) is absent: the
/// script was empty or did not define the function.
pub const REASON_DETECTOR_SCRIPT_MISSING: &str = "detector-script-missing";

/// The documented visual-contrast fallback has no implementation.
pub const REASON_VISUAL_CONTRAST_NOT_IMPLEMENTED: &str = "visual-contrast-not-implemented";

/// Builds the typed unavailable error for `reason`.
pub fn unavailable_error(reason: &str) -> String {
    format!("{UNAVAILABLE_PREFIX}{reason}")
}

/// Returns the reason when `err` is a typed unavailable error.
pub fn unavailable_reason(err: &str) -> Option<&str> {
    err.strip_prefix(UNAVAILABLE_PREFIX)
}

/// Port of `options.viewport` default `{ width: 1280, height: 800 }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Viewport {
    pub width: u32,
    pub height: u32,
}

impl Default for Viewport {
    fn default() -> Self {
        Viewport {
            width: 1280,
            height: 800,
        }
    }
}

/// Mirrors the shape `designSystem` has when it's present, as read by
/// `serializeDesignSystemForBrowser`. JS treats `allowedFonts` as a `Set`,
/// `allowedColorKeys` as a `Map` of entries with a `.color` `{r,g,b}`, and
/// `allowedRadii` as `[{ px }, ...]`; the Rust shape mirrors that directly
/// rather than waiting on `design-system.mjs`'s own (unported) types.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DesignSystemInput {
    pub present: bool,
    pub has_fonts: bool,
    pub allowed_fonts: Vec<String>,
    pub has_colors: bool,
    pub allowed_color_keys: Vec<Rgb>,
    pub has_radii: bool,
    pub allowed_radii: Vec<f64>,
    pub has_pill_radius: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rgb {
    pub r: f64,
    pub g: f64,
    pub b: f64,
}

/// Port of `serializeDesignSystemForBrowser(designSystem)`. JS: `if
/// (!designSystem?.present) return null;` then builds a plain object,
/// filtering `allowedColorKeys` entries to ones with finite `r`/`g`/`b` and
/// `allowedRadii` entries to finite `px` values (both already guaranteed by
/// this port's typed [`Rgb`]/`f64` fields, so the filters here are
/// `is_finite()` checks mirroring `Number.isFinite`).
pub fn serialize_design_system_for_browser(ds: Option<&DesignSystemInput>) -> Option<Value> {
    let ds = ds?;
    if !ds.present {
        return None;
    }
    Some(json!({
        "present": true,
        "hasFonts": ds.has_fonts,
        "allowedFonts": ds.allowed_fonts,
        "hasColors": ds.has_colors,
        "allowedColors": ds.allowed_color_keys.iter()
            .filter(|c| c.r.is_finite() && c.g.is_finite() && c.b.is_finite())
            .map(|c| json!({"r": c.r, "g": c.g, "b": c.b}))
            .collect::<Vec<_>>(),
        "hasRadii": ds.has_radii,
        "allowedRadii": ds.allowed_radii.iter().filter(|px| px.is_finite()).collect::<Vec<_>>(),
        "hasPillRadius": ds.has_pill_radius,
    }))
}

/// Port of the options object threaded through `detectUrl`/`detectUrlCdp`.
/// `wait_until` and the Puppeteer-only `browser`/`waitUntil` semantics are
/// kept as fields for fidelity even though this port has one driver lane
/// (see the module doc); `quiet` mirrors the `!options?.quiet` stderr note
/// JS prints when falling back off Puppeteer (this port always takes that
/// lane, so `quiet` gates the same note here).
#[derive(Debug, Clone)]
pub struct DetectUrlOptions {
    pub viewport: Viewport,
    /// JS default: `250` in `detectUrlCdp`, `0` in `detectUrl` itself. The
    /// caller picks which default applies by calling [`detect_url_cdp`]
    /// directly (250) or going through [`detect_url`] (0), matching which
    /// JS function they'd have called.
    pub settle_ms: u64,
    pub providers: Vec<String>,
    pub design_system: Option<DesignSystemInput>,
    /// JS: `options?.visualContrast === false` skips the fallback lane
    /// entirely. Default `false` here since the fallback lane itself isn't
    /// ported (see module doc) — set `true` only once a real
    /// `visual_contrast_findings` hook is supplied.
    pub visual_contrast: bool,
    pub quiet: bool,
}

impl Default for DetectUrlOptions {
    fn default() -> Self {
        DetectUrlOptions {
            viewport: Viewport::default(),
            settle_ms: 0,
            providers: Vec::new(),
            design_system: None,
            visual_contrast: false,
            quiet: false,
        }
    }
}

/// One raw `{ type, detail, ignoreValue }` entry as `page.evaluate` returns
/// it from `window.impeccableDetect(...)`'s serialized groups, flattened the
/// way both JS callers do: `groups.flatMap(({ findings }) => findings.map(f
/// => ({ id: f.type, snippet: f.detail, ignoreValue: f.ignoreValue || '' })))`.
#[derive(Debug, Clone, PartialEq)]
pub struct RawFinding {
    pub id: String,
    pub snippet: String,
    pub ignore_value: String,
}

/// Parses the `Value` returned by evaluating
/// `window.impeccableDetect({ decorate: false, serialize: true })` into the
/// flattened raw-finding list both callers build. A non-array value (the
/// detector is absent, which evaluates to `null`) is not parsed here; callers
/// must report it as unavailable, see [`detect_url_cdp`]. Tolerant of
/// missing/malformed fields the same
/// way JS's optional chaining is: a missing `findings` array yields no
/// entries for that group rather than erroring.
pub fn flatten_serialized_groups(groups: &Value) -> Vec<RawFinding> {
    let mut out = Vec::new();
    let Some(groups) = groups.as_array() else {
        return out;
    };
    for group in groups {
        let Some(findings) = group.get("findings").and_then(Value::as_array) else {
            continue;
        };
        for f in findings {
            let id = f
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let snippet = f
                .get("detail")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let ignore_value = f
                .get("ignoreValue")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            out.push(RawFinding {
                id,
                snippet,
                ignore_value,
            });
        }
    }
    out
}

/// Builds `Finding`s from raw ones via the registry, mirroring
/// `results.map(f => { const item = finding(f.id, url, f.snippet); if
/// (f.ignoreValue) item.ignoreValue = f.ignoreValue; return item; })`
/// followed by `filterByProviders`. A raw finding whose `id` isn't in the
/// registry is dropped (the JS equivalent — `finding()` throwing on an
/// unknown id — would abort the whole scan; dropping is the documented,
/// safer divergence for a partial/evolving registry, noted in the r07 report).
pub fn to_findings(
    registry: &impl AntipatternLookup,
    url: &str,
    raw: Vec<RawFinding>,
    providers: &[String],
) -> Vec<Finding> {
    let built: Vec<Finding> = raw
        .into_iter()
        .filter_map(|f| {
            super::findings::finding(registry, &f.id, url, &f.snippet)
                .ok()
                .map(|mut item| {
                    if !f.ignore_value.is_empty() {
                        item.ignore_value = Some(f.ignore_value);
                    }
                    item
                })
        })
        .collect();
    filter_by_providers(registry, built, providers)
}

/// Port of `detectUrlCdp(url, options)`: navigate, configure
/// `window.__IMPECCABLE_CONFIG__`, inject `browser_script`, evaluate
/// `impeccableDetect`, and collect findings. `driver` stands in for the
/// launch+CDP-connect+navigate+evaluate sequence (`launchHeadless` +
/// `findPageTarget` + `cdpConnect` + `runtimeEval`); production callers pass
/// [`super::real::RealChromeDriver`], tests pass a fake.
///
/// Returns `Err("unavailable:detector-script-missing")` when `browser_script`
/// is empty or the injected `window.impeccableDetect` is not a function. A
/// check that could not run never resolves to an empty success.
pub fn detect_url_cdp(
    driver: &mut impl ChromeDriver,
    registry: &impl AntipatternLookup,
    url: &str,
    browser_script: &str,
    options: &DetectUrlOptions,
) -> Result<Vec<Finding>, String> {
    if browser_script.trim().is_empty() {
        return Err(unavailable_error(REASON_DETECTOR_SCRIPT_MISSING));
    }

    driver.navigate(url)?;

    let design_system = serialize_design_system_for_browser(options.design_system.as_ref());
    let config_patch = match &design_system {
        Some(ds) => json!({ "autoScan": false, "designSystem": ds }),
        None => json!({ "autoScan": false }),
    };
    driver.evaluate(&format!(
        "window.__IMPECCABLE_CONFIG__ = Object.assign({{}}, window.__IMPECCABLE_CONFIG__ || {{}}, {});",
        config_patch
    ))?;
    driver.evaluate(browser_script)?;
    // Absent function evaluates to `null`, which is not a result list.
    let serialized = driver.evaluate(
        "typeof window.impeccableDetect === 'function' ? window.impeccableDetect({ decorate: false, serialize: true }) : null",
    )?;
    if !serialized.is_array() {
        return Err(unavailable_error(REASON_DETECTOR_SCRIPT_MISSING));
    }

    let raw = flatten_serialized_groups(&serialized);
    Ok(to_findings(registry, url, raw, &options.providers))
}

/// Visual-contrast fallback for callers that have no implementation. Always
/// unavailable, never zero findings. The production wrapper in
/// `wf_port::r05::real_detectors` should pass this instead of `|_| Ok(Vec::new())`.
pub fn visual_contrast_unavailable(_url: &str) -> Result<Vec<Finding>, String> {
    Err(unavailable_error(REASON_VISUAL_CONTRAST_NOT_IMPLEMENTED))
}

/// Port of `detectUrl(url, options)`'s post-import-resolution body: the
/// Puppeteer-specific `page.setViewport`/`page.goto`/lifecycle calls JS makes
/// are the [`ChromeDriver`] trait's job here (see module doc), so this
/// function performs the same inject/evaluate/collect sequence as
/// [`detect_url_cdp`] plus the visual-contrast fallback hook.
///
/// `visual_contrast_findings`, when `options.visual_contrast` is true, is
/// called with the URL and should return the same shape
/// `runVisualContrastFallback` would append; passing `|_| Ok(Vec::new())`
/// matches upstream's `visualContrast: false` short circuit.
pub fn detect_url(
    driver: &mut impl ChromeDriver,
    registry: &impl AntipatternLookup,
    url: &str,
    browser_script: &str,
    options: &DetectUrlOptions,
    visual_contrast_findings: impl FnOnce(&str) -> Result<Vec<Finding>, String>,
) -> Result<Vec<Finding>, String> {
    let mut findings = detect_url_cdp(driver, registry, url, browser_script, options)?;
    if options.visual_contrast {
        findings.extend(visual_contrast_findings(url)?);
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::r07::findings::AntipatternRule;
    use std::collections::HashMap;

    struct FakeDriver {
        navigated_to: Vec<String>,
        evaluated: Vec<String>,
        /// Scripted responses returned in call order for `evaluate`.
        responses: Vec<Value>,
    }

    impl ChromeDriver for FakeDriver {
        fn navigate(&mut self, url: &str) -> Result<(), String> {
            self.navigated_to.push(url.to_string());
            Ok(())
        }
        fn evaluate(&mut self, expression: &str) -> Result<Value, String> {
            self.evaluated.push(expression.to_string());
            Ok(self.responses.remove(0))
        }
    }

    struct FakeRegistry(HashMap<String, AntipatternRule>);

    impl AntipatternLookup for FakeRegistry {
        fn get(&self, id: &str) -> Option<AntipatternRule> {
            self.0.get(id).cloned()
        }
        fn has_gated_providers(&self) -> bool {
            false
        }
    }

    fn registry() -> FakeRegistry {
        let mut m = HashMap::new();
        m.insert(
            "low-contrast".to_string(),
            AntipatternRule {
                name: "Low contrast".to_string(),
                description: "d".to_string(),
                severity: "warning".to_string(),
                gated: None,
            },
        );
        FakeRegistry(m)
    }

    #[test]
    fn serialize_design_system_none_when_absent_or_not_present() {
        assert_eq!(serialize_design_system_for_browser(None), None);
        let ds = DesignSystemInput {
            present: false,
            ..Default::default()
        };
        assert_eq!(serialize_design_system_for_browser(Some(&ds)), None);
    }

    #[test]
    fn serialize_design_system_filters_non_finite_colors_and_radii() {
        let ds = DesignSystemInput {
            present: true,
            has_colors: true,
            allowed_color_keys: vec![
                Rgb {
                    r: 1.0,
                    g: 2.0,
                    b: 3.0,
                },
                Rgb {
                    r: f64::NAN,
                    g: 0.0,
                    b: 0.0,
                },
            ],
            has_radii: true,
            allowed_radii: vec![4.0, f64::INFINITY],
            ..Default::default()
        };
        let out = serialize_design_system_for_browser(Some(&ds)).unwrap();
        assert_eq!(out["allowedColors"].as_array().unwrap().len(), 1);
        assert_eq!(out["allowedRadii"].as_array().unwrap().len(), 1);
        assert_eq!(out["present"], true);
    }

    #[test]
    fn flatten_serialized_groups_flattens_and_defaults_ignore_value() {
        let groups = json!([
            { "findings": [ { "type": "low-contrast", "detail": "snip" } ] },
            { "findings": [ { "type": "x", "detail": "y", "ignoreValue": "z" } ] },
            {}
        ]);
        let flat = flatten_serialized_groups(&groups);
        assert_eq!(flat.len(), 2);
        assert_eq!(flat[0].ignore_value, "");
        assert_eq!(flat[1].ignore_value, "z");
    }

    #[test]
    fn detect_url_cdp_navigates_injects_and_collects_findings() {
        let mut driver = FakeDriver {
            navigated_to: vec![],
            evaluated: vec![],
            responses: vec![
                Value::Null, // config patch eval
                Value::Null, // browser_script eval
                json!([{ "findings": [{ "type": "low-contrast", "detail": "s" }] }]),
            ],
        };
        let reg = registry();
        let opts = DetectUrlOptions::default();
        let out =
            detect_url_cdp(&mut driver, &reg, "https://x.test", "/* script */", &opts).unwrap();
        assert_eq!(driver.navigated_to, vec!["https://x.test".to_string()]);
        assert_eq!(driver.evaluated.len(), 3);
        assert!(driver.evaluated[1].contains("/* script */"));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].antipattern, "low-contrast");
        assert_eq!(out[0].file, "https://x.test");
    }

    #[test]
    fn detect_url_skips_visual_contrast_hook_when_disabled() {
        let mut driver = FakeDriver {
            navigated_to: vec![],
            evaluated: vec![],
            responses: vec![Value::Null, Value::Null, json!([])],
        };
        let reg = registry();
        let opts = DetectUrlOptions::default(); // visual_contrast: false
        let out = detect_url(
            &mut driver,
            &reg,
            "https://x.test",
            "/* s */",
            &opts,
            |_| panic!("must not be called when visual_contrast is false"),
        )
        .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn detect_url_appends_visual_contrast_hook_results_when_enabled() {
        let mut driver = FakeDriver {
            navigated_to: vec![],
            evaluated: vec![],
            responses: vec![Value::Null, Value::Null, json!([])],
        };
        let reg = registry();
        let mut opts = DetectUrlOptions::default();
        opts.visual_contrast = true;
        let extra = super::to_findings(
            &reg,
            "https://x.test",
            vec![RawFinding {
                id: "low-contrast".to_string(),
                snippet: "s".to_string(),
                ignore_value: String::new(),
            }],
            &[],
        );
        let out = detect_url(
            &mut driver,
            &reg,
            "https://x.test",
            "/* s */",
            &opts,
            |_| Ok(extra.clone()),
        )
        .unwrap();
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn empty_browser_script_is_unavailable_not_empty_success() {
        let mut driver = FakeDriver {
            navigated_to: vec![],
            evaluated: vec![],
            responses: vec![],
        };
        let reg = registry();
        let opts = DetectUrlOptions::default();
        for script in ["", "   \n\t"] {
            let err = detect_url_cdp(&mut driver, &reg, "https://x.test", script, &opts)
                .expect_err("empty script must not succeed");
            assert_eq!(unavailable_reason(&err), Some("detector-script-missing"));
        }
        // Rejected before any navigation or evaluation.
        assert!(driver.navigated_to.is_empty());
        assert!(driver.evaluated.is_empty());
    }

    #[test]
    fn script_without_impeccable_detect_is_unavailable_not_empty_success() {
        let mut driver = FakeDriver {
            navigated_to: vec![],
            evaluated: vec![],
            // config patch, browser script, then the absent-function probe -> null.
            responses: vec![Value::Null, Value::Null, Value::Null],
        };
        let reg = registry();
        let opts = DetectUrlOptions::default();
        let err = detect_url_cdp(
            &mut driver,
            &reg,
            "https://x.test",
            "/* no detector */",
            &opts,
        )
        .expect_err("missing impeccableDetect must not succeed");
        assert_eq!(err, "unavailable:detector-script-missing".to_string());
        assert_eq!(driver.navigated_to, vec!["https://x.test".to_string()]);
    }

    #[test]
    fn non_array_detector_result_is_unavailable() {
        let mut driver = FakeDriver {
            navigated_to: vec![],
            evaluated: vec![],
            responses: vec![Value::Null, Value::Null, json!({ "unexpected": true })],
        };
        let reg = registry();
        let opts = DetectUrlOptions::default();
        let err = detect_url_cdp(&mut driver, &reg, "https://x.test", "/* s */", &opts)
            .expect_err("malformed detector output must not succeed");
        assert_eq!(unavailable_reason(&err), Some("detector-script-missing"));
    }

    #[test]
    fn visual_contrast_hook_without_implementation_is_unavailable() {
        let mut driver = FakeDriver {
            navigated_to: vec![],
            evaluated: vec![],
            responses: vec![Value::Null, Value::Null, json!([])],
        };
        let reg = registry();
        let mut opts = DetectUrlOptions::default();
        opts.visual_contrast = true;
        let err = detect_url(
            &mut driver,
            &reg,
            "https://x.test",
            "/* s */",
            &opts,
            visual_contrast_unavailable,
        )
        .expect_err("unimplemented visual contrast must not look like zero findings");
        assert_eq!(
            unavailable_reason(&err),
            Some("visual-contrast-not-implemented")
        );
    }

    #[test]
    fn unavailable_reason_only_matches_typed_prefix() {
        assert_eq!(unavailable_reason("unavailable:x"), Some("x"));
        assert_eq!(unavailable_reason("network down"), None);
    }
}
