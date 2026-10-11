//! Visual-contrast fallback lane: port of `runVisualContrastFallback` from
//! `skills/designer/engine/scripts/detector/engines/browser/detect-url.mjs`,
//! driving `captureVisualContrastCandidate` through [`ChromeDriver`].
//!
//! Inputs, all already available to the URL lane:
//! - the serialized detector groups from [`super::detect_url::run_browser_detector`]
//!   (their `low-contrast` selectors are excluded, as in JS);
//! - the browser-side globals `impeccableAnalyzeVisualContrast` and
//!   `impeccableCollectVisualContrastCandidates` defined by the shipped
//!   `detect-antipatterns-browser.js` that the caller already injects;
//! - screenshot PNGs and hide-attribute toggles through
//!   [`ChromeDriver::screenshot_png`], [`ChromeDriver::apply_hide`] and
//!   [`ChromeDriver::remove_hide`], decoded and compared by
//!   `wf_port::w2_013::screenshot_contrast`.
//!
//! A driver without screenshot support fails the lane with a typed
//! `unavailable:screenshot-not-supported` error, never a silent empty result.

use std::collections::HashSet;

use serde_json::{json, Value};

use super::browser::ChromeDriver;
use super::detect_url::{DetectUrlOptions, RawFinding};
use crate::wf_port::w2_013::screenshot_contrast::{
    capture_visual_contrast_candidate, Clip, ContrastCandidate, PageCapture, Rgb,
};

/// Adapts a [`ChromeDriver`] into the [`PageCapture`] that the w2_013
/// orchestration drives.
struct DriverCapture<'a, D: ChromeDriver> {
    driver: &'a mut D,
}

impl<'a, D: ChromeDriver> PageCapture for DriverCapture<'a, D> {
    fn screenshot_png(&mut self, clip: Clip) -> Result<Vec<u8>, String> {
        self.driver.screenshot_png(clip)
    }

    fn apply_hide(&mut self, selector: &str, background_clip_text: bool) -> Result<bool, String> {
        self.driver.apply_hide(selector, background_clip_text)
    }

    fn remove_hide(&mut self, selector: &str) {
        self.driver.remove_hide(selector)
    }
}

/// Port of `serializedGroups.filter(g => g.findings?.some(f => f.type ===
/// 'low-contrast')).map(g => g.selector).filter(Boolean)`.
fn existing_low_contrast_selectors(groups: &Value) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(groups) = groups.as_array() else {
        return out;
    };
    for group in groups {
        let has_low_contrast = group
            .get("findings")
            .and_then(Value::as_array)
            .map(|findings| {
                findings
                    .iter()
                    .any(|f| str_field(f, "type") == Some("low-contrast"))
            })
            .unwrap_or(false);
        if has_low_contrast {
            if let Some(selector) = str_field(group, "selector") {
                if !selector.is_empty() {
                    out.insert(selector.to_string());
                }
            }
        }
    }
    out
}

/// A non-array evaluation result (a missing global evaluates to `[]` in the
/// injected expressions, anything else is treated as "no results").
fn array_or_empty(value: Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items,
        _ => Vec::new(),
    }
}

fn str_field<'v>(value: &'v Value, key: &str) -> Option<&'v str> {
    value.get(key).and_then(Value::as_str)
}

fn f64_field(value: &Value, key: &str) -> Option<f64> {
    value.get(key).and_then(Value::as_f64)
}

fn parse_rgb(value: &Value) -> Option<Rgb> {
    Some(Rgb {
        r: f64_field(value, "r")?,
        g: f64_field(value, "g")?,
        b: f64_field(value, "b")?,
    })
}

fn parse_clip(value: &Value) -> Option<Clip> {
    let clip = value.get("clip")?;
    Some(Clip {
        x: f64_field(clip, "x")?.floor() as i64,
        y: f64_field(clip, "y")?.floor() as i64,
        width: f64_field(clip, "width")?.ceil() as i64,
        height: f64_field(clip, "height")?.ceil() as i64,
    })
}

/// Reads one browser candidate (`collectVisualContrastCandidates` shape) into
/// the w2_013 [`ContrastCandidate`]. A missing clip leaves `clip` as `None`,
/// which the orchestration treats as "no finding", matching the JS
/// `sanitizeScreenshotClip(!clip) -> null` path.
fn parse_candidate(value: &Value) -> ContrastCandidate {
    ContrastCandidate {
        selector: str_field(value, "selector").unwrap_or("").to_string(),
        clip: parse_clip(value),
        text_color: value.get("textColor").and_then(parse_rgb),
        prefer_rendered_foreground: value
            .get("preferRenderedForeground")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        background_clip_text: value
            .get("backgroundClipText")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        threshold: f64_field(value, "threshold").unwrap_or(4.5),
        text: str_field(value, "text")
            .filter(|t| !t.is_empty())
            .map(str::to_string),
        reasons: value
            .get("reasons")
            .and_then(Value::as_array)
            .map(|reasons| {
                reasons
                    .iter()
                    .filter_map(|r| r.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Port of `runVisualContrastFallback(page, serializedGroups, options, ...)`.
///
/// Returns raw findings for [`super::detect_url::detect_url`] to append before
/// registry mapping and provider filtering, exactly as the JS appends
/// `visualFindings` to `results`.
pub fn visual_contrast_lane<D: ChromeDriver>(
    driver: &mut D,
    _url: &str,
    groups: &Value,
    options: &DetectUrlOptions,
) -> Result<Vec<RawFinding>, String> {
    if !options.visual_contrast {
        return Ok(Vec::new());
    }
    let max_candidates = options.visual_contrast_max_candidates;
    let scroll_offscreen = options.visual_contrast_scroll_offscreen;
    let existing = existing_low_contrast_selectors(groups);

    let mut findings: Vec<RawFinding> = Vec::new();
    let mut browser_analyses: Vec<Value> = Vec::new();
    if options.visual_contrast_browser {
        let expression = format!(
            "(async () => {{ if (typeof window.impeccableAnalyzeVisualContrast !== 'function') return []; return window.impeccableAnalyzeVisualContrast({}); }})()",
            json!({ "maxCandidates": max_candidates, "scrollOffscreen": scroll_offscreen })
        );
        browser_analyses = array_or_empty(driver.evaluate(&expression)?);
        for result in &browser_analyses {
            let Some(finding) = result.get("finding").filter(|f| f.is_object()) else {
                continue;
            };
            let already_flagged =
                str_field(result, "selector").map_or(false, |s| existing.contains(s));
            if already_flagged {
                continue;
            }
            findings.push(RawFinding {
                id: str_field(finding, "id").unwrap_or("").to_string(),
                snippet: str_field(finding, "snippet").unwrap_or("").to_string(),
                ignore_value: String::new(),
            });
        }
    }

    // Selectors the browser analysis already resolved (pass or fail) are not
    // re-measured with pixels.
    let browser_resolved: HashSet<String> = browser_analyses
        .iter()
        .filter(|r| matches!(str_field(r, "status"), Some("fail") | Some("pass")))
        .filter_map(|r| str_field(r, "selector").map(str::to_string))
        .collect();

    let mut candidates: Vec<Value> = browser_analyses;
    if candidates.is_empty() {
        let expression = format!(
            "(() => {{ if (typeof window.impeccableCollectVisualContrastCandidates !== 'function') return []; return window.impeccableCollectVisualContrastCandidates({}); }})()",
            json!({ "maxCandidates": max_candidates })
        );
        candidates = array_or_empty(driver.evaluate(&expression)?);
    }

    if !options.visual_contrast_pixel {
        return Ok(findings);
    }

    let viewport_width = i64::from(options.viewport.width);
    let pending: Vec<ContrastCandidate> = candidates
        .iter()
        .filter(|c| {
            let skip = str_field(c, "selector").map_or(false, |s| {
                existing.contains(s) || browser_resolved.contains(s)
            });
            !skip
        })
        .map(parse_candidate)
        .collect();
    for candidate in &pending {
        let mut capture = DriverCapture {
            driver: &mut *driver,
        };
        if let Some(found) =
            capture_visual_contrast_candidate(&mut capture, candidate, Some(viewport_width))?
        {
            findings.push(RawFinding {
                id: found.id.to_string(),
                snippet: found.snippet,
                ignore_value: String::new(),
            });
        }
    }
    Ok(findings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wf_port::r07::detect_url::unavailable_reason;

    /// Scripted driver: `evals` answers `evaluate` in call order, `shots`
    /// answers `screenshot_png` in call order.
    struct ScriptedDriver {
        evals: Vec<Value>,
        shots: Vec<Vec<u8>>,
        expressions: Vec<String>,
    }

    impl ChromeDriver for ScriptedDriver {
        fn navigate(&mut self, _url: &str) -> Result<(), String> {
            Ok(())
        }
        fn evaluate(&mut self, expression: &str) -> Result<Value, String> {
            self.expressions.push(expression.to_string());
            Ok(self.evals.remove(0))
        }
        fn screenshot_png(&mut self, _clip: Clip) -> Result<Vec<u8>, String> {
            Ok(self.shots.remove(0))
        }
        fn apply_hide(
            &mut self,
            _selector: &str,
            _background_clip_text: bool,
        ) -> Result<bool, String> {
            Ok(true)
        }
    }

    /// A driver that only implements the required methods, so screenshot
    /// support is the trait's typed-unavailable default.
    struct NoScreenshotDriver {
        evals: Vec<Value>,
    }

    impl ChromeDriver for NoScreenshotDriver {
        fn navigate(&mut self, _url: &str) -> Result<(), String> {
            Ok(())
        }
        fn evaluate(&mut self, _expression: &str) -> Result<Value, String> {
            Ok(self.evals.remove(0))
        }
    }

    fn solid_png(pixel: [u8; 4], width: u32, height: u32) -> Vec<u8> {
        let buf = image::RgbaImage::from_pixel(width, height, image::Rgba(pixel));
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(buf)
            .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    }

    fn candidate_json(selector: &str, threshold: f64) -> Value {
        json!({
            "selector": selector,
            "clip": { "x": 0, "y": 0, "width": 4, "height": 4 },
            "textColor": { "r": 0, "g": 0, "b": 0, "a": 1 },
            "preferRenderedForeground": false,
            "backgroundClipText": false,
            "threshold": threshold,
            "text": "Read more",
            "reasons": ["low contrast background"]
        })
    }

    #[test]
    fn disabled_lane_makes_no_browser_calls() {
        let mut driver = ScriptedDriver {
            evals: vec![],
            shots: vec![],
            expressions: vec![],
        };
        let mut options = DetectUrlOptions::default();
        options.visual_contrast = false;
        let out =
            visual_contrast_lane(&mut driver, "https://x.test", &json!([]), &options).unwrap();
        assert!(out.is_empty());
        assert!(driver.expressions.is_empty());
    }

    #[test]
    fn browser_analysis_findings_are_returned_and_resolved_selectors_skip_pixels() {
        let mut driver = ScriptedDriver {
            evals: vec![json!([
                {
                    "selector": "p.a",
                    "status": "fail",
                    "finding": { "id": "low-contrast", "snippet": "browser contrast 2.0:1" }
                },
                { "selector": "p.b", "status": "pass", "finding": null }
            ])],
            shots: vec![],
            expressions: vec![],
        };
        let mut options = DetectUrlOptions::default();
        options.visual_contrast_pixel = false;
        let out =
            visual_contrast_lane(&mut driver, "https://x.test", &json!([]), &options).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "low-contrast");
        assert_eq!(out[0].snippet, "browser contrast 2.0:1");
        // Analyses were non-empty, so the collect step never ran.
        assert!(driver.evals.is_empty());
        assert!(driver.expressions[0].contains("impeccableAnalyzeVisualContrast"));
    }

    #[test]
    fn selectors_already_flagged_by_the_dom_detector_are_excluded() {
        let groups = json!([
            { "selector": "p.a", "findings": [{ "type": "low-contrast", "detail": "x" }] }
        ]);
        let mut driver = ScriptedDriver {
            evals: vec![json!([
                {
                    "selector": "p.a",
                    "status": "fail",
                    "finding": { "id": "low-contrast", "snippet": "dup" }
                }
            ])],
            shots: vec![],
            expressions: vec![],
        };
        let mut options = DetectUrlOptions::default();
        options.visual_contrast_pixel = false;
        let out = visual_contrast_lane(&mut driver, "https://x.test", &groups, &options).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn pixel_lane_flags_candidate_below_threshold_from_collect_step() {
        let mut driver = ScriptedDriver {
            // analyses empty -> collect runs and returns one candidate.
            evals: vec![json!([]), json!([candidate_json("p.c", 25.0)])],
            shots: vec![
                solid_png([0, 0, 0, 255], 4, 4),
                solid_png([255, 255, 255, 255], 4, 4),
            ],
            expressions: vec![],
        };
        let out = visual_contrast_lane(
            &mut driver,
            "https://x.test",
            &json!([]),
            &DetectUrlOptions::default(),
        )
        .unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, "low-contrast");
        // Black text on white is 21:1, under the 25:1 threshold used here.
        assert!(out[0].snippet.contains("21.0:1"), "{}", out[0].snippet);
        assert!(out[0].snippet.contains("need 25:1"), "{}", out[0].snippet);
        assert!(driver.expressions[1].contains("impeccableCollectVisualContrastCandidates"));
    }

    #[test]
    fn pixel_lane_does_not_flag_candidate_above_threshold() {
        let mut driver = ScriptedDriver {
            evals: vec![json!([]), json!([candidate_json("p.c", 4.5)])],
            shots: vec![
                solid_png([0, 0, 0, 255], 4, 4),
                solid_png([255, 255, 255, 255], 4, 4),
            ],
            expressions: vec![],
        };
        let out = visual_contrast_lane(
            &mut driver,
            "https://x.test",
            &json!([]),
            &DetectUrlOptions::default(),
        )
        .unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn missing_screenshot_support_is_a_typed_unavailable_error_not_a_clean_scan() {
        let mut driver = NoScreenshotDriver {
            evals: vec![json!([]), json!([candidate_json("p.c", 25.0)])],
        };
        let err = visual_contrast_lane(
            &mut driver,
            "https://x.test",
            &json!([]),
            &DetectUrlOptions::default(),
        )
        .expect_err("a driver that cannot screenshot must not report a clean result");
        assert_eq!(unavailable_reason(&err), Some("screenshot-not-supported"));
    }

    #[test]
    fn parse_candidate_reads_browser_shape_and_defaults() {
        let parsed = parse_candidate(&candidate_json("p.c", 3.0));
        assert_eq!(parsed.selector, "p.c");
        assert_eq!(
            parsed.clip,
            Some(Clip {
                x: 0,
                y: 0,
                width: 4,
                height: 4
            })
        );
        assert_eq!(parsed.threshold, 3.0);
        assert_eq!(parsed.text.as_deref(), Some("Read more"));
        assert_eq!(parsed.reasons, vec!["low contrast background".to_string()]);
        let bare = parse_candidate(&json!({ "selector": "p.d" }));
        assert_eq!(bare.clip, None);
        assert_eq!(bare.threshold, 4.5);
        assert_eq!(bare.text, None);
    }
}
