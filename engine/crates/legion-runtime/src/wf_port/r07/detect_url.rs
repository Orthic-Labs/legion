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
    /// entirely. Default `true`, matching the JS default; the lane is driven
    /// by [`super::visual_lane::visual_contrast_lane`] in production.
    pub visual_contrast: bool,
    /// JS `visualContrastBrowser === false` skips the browser-side analysis
    /// (`impeccableAnalyzeVisualContrast`) and goes straight to candidates.
    pub visual_contrast_browser: bool,
    /// JS `visualContrastPixel === false` stops after the browser-side lane,
    /// with no screenshot pixel comparison.
    pub visual_contrast_pixel: bool,
    /// JS `visualContrastMaxCandidates`, default 12.
    pub visual_contrast_max_candidates: u32,
    /// JS `visualContrastScrollOffscreen !== false`, default `true`.
    pub visual_contrast_scroll_offscreen: bool,
    pub quiet: bool,
}

impl Default for DetectUrlOptions {
    fn default() -> Self {
        DetectUrlOptions {
            viewport: Viewport::default(),
            settle_ms: 0,
            providers: Vec::new(),
            design_system: None,
            visual_contrast: true,
            visual_contrast_browser: true,
            visual_contrast_pixel: true,
            visual_contrast_max_candidates: 12,
            visual_contrast_scroll_offscreen: true,
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
    let serialized = run_browser_detector(driver, url, browser_script, options)?;
    let raw = flatten_serialized_groups(&serialized);
    Ok(to_findings(registry, url, raw, &options.providers))
}

/// The navigate + configure + inject + collect steps of `detectUrlCdp`,
/// returning the serialized detector groups (a JSON array) so later lanes
/// (the visual-contrast fallback) can read the same groups the JS passes to
/// `runVisualContrastFallback`.
pub fn run_browser_detector(
    driver: &mut impl ChromeDriver,
    url: &str,
    browser_script: &str,
    options: &DetectUrlOptions,
) -> Result<Value, String> {
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
    Ok(serialized)
}

/// Visual-contrast hook that reports itself unavailable: never zero findings.
/// Kept for callers and tests that must exercise the typed-unavailable path.
pub fn visual_contrast_unavailable<D: ChromeDriver>(
    _driver: &mut D,
    _url: &str,
    _groups: &Value,
    _options: &DetectUrlOptions,
) -> Result<Vec<RawFinding>, String> {
    Err(unavailable_error(REASON_VISUAL_CONTRAST_NOT_IMPLEMENTED))
}

/// Port of `detectUrl(url, options)`'s post-import-resolution body: the
/// Puppeteer-specific `page.setViewport`/`page.goto`/lifecycle calls JS makes
/// are the [`ChromeDriver`] trait's job here (see module doc), so this
/// function performs the same inject/evaluate/collect sequence as
/// [`detect_url_cdp`] plus the visual-contrast fallback hook.
///
/// `visual_contrast_findings`, when `options.visual_contrast` is true, is
/// called with the same driver, the URL, the serialized detector groups, and
/// the options, and returns raw findings in the same shape
/// `runVisualContrastFallback` appends to `results`. Production passes
/// [`super::visual_lane::visual_contrast_lane`]; `visual_contrast_unavailable`
/// is the typed-unavailable stand-in.
pub fn detect_url<D: ChromeDriver>(
    driver: &mut D,
    registry: &impl AntipatternLookup,
    url: &str,
    browser_script: &str,
    options: &DetectUrlOptions,
    visual_contrast_findings: impl FnOnce(
        &mut D,
        &str,
        &Value,
        &DetectUrlOptions,
    ) -> Result<Vec<RawFinding>, String>,
) -> Result<Vec<Finding>, String> {
    let groups = run_browser_detector(&mut *driver, url, browser_script, options)?;
    let mut raw = flatten_serialized_groups(&groups);
    if options.visual_contrast {
        raw.extend(visual_contrast_findings(
            &mut *driver,
            url,
            &groups,
            options,
        )?);
    }
    Ok(to_findings(registry, url, raw, &options.providers))
}
