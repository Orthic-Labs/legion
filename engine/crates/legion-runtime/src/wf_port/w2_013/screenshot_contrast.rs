//! Port of `skills/designer/engine/scripts/detector/engines/visual/screenshot-contrast.mjs`
//! (packet `r10` closes out this file's remaining gap).
//!
//! `compareScreenshotContrast` decoded two `page.screenshot()` PNGs through
//! `<canvas>`/`getImageData` in a live browser tab. That decode-and-diff
//! step is now ported for real with the `image` crate in
//! [`compare_screenshot_contrast`], operating on the raw PNG bytes a
//! capture returns — no canvas needed. `captureVisualContrastCandidate`
//! drove `page.screenshot()` + `page.evaluate()` to toggle a hide-style on
//! the candidate element between two captures; that side effect now sits
//! behind the [`PageCapture`] trait (mirroring the `ChromeDeckStageBrowser`/
//! `ChromeThumbBrowser`/`RealChromeDriver` pattern already used in
//! `wf_port::r00`/`wf_port::r07`), with [`ChromeContrastCapture`] as the
//! `headless_chrome`-backed production implementation and
//! [`capture_visual_contrast_candidate`] as the faithful port of the JS
//! orchestration, driven purely through the trait so it is testable with a
//! fake (see `tests::capture_...` below) without a real browser.
//!
//! What was already pure, deterministic, DOM-free logic — and is kept below
//! with unit tests mirroring the JS behaviour exactly — is:
//! - [`sanitize_screenshot_clip`], the port of `sanitizeScreenshotClip`.
//! - [`relative_luminance`] and [`contrast_ratio`], the WCAG contrast math
//!   embedded in `compareScreenshotContrast`'s `page.evaluate` callback
//!   (the `luminance`/`ratio` closures).
//! - [`pick_percentile`], the `pick(pct)` helper from the same callback.

/// Port of the `clip` shape (`{ x, y, width, height }`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Clip {
    pub x: i64,
    pub y: i64,
    pub width: i64,
    pub height: i64,
}

/// Port of `sanitizeScreenshotClip(clip, viewport)`. `clip` is `None` when
/// the JS `clip` argument is falsy (`!clip`). `viewport_width` mirrors
/// `viewport?.width || 1600`; pass `None` (or any non-positive value) to
/// get the JS default of 1600.
pub fn sanitize_screenshot_clip(clip: Option<Clip>, viewport_width: Option<i64>) -> Option<Clip> {
    let clip = clip?;
    let x = (clip.x).max(0);
    let y = (clip.y).max(0);
    let vw = viewport_width.filter(|w| *w > 0).unwrap_or(1600);
    let width = clip.width.max(1).min(vw.max(1));
    let height = clip.height.max(1).min(320);
    if width < 1 || height < 1 {
        return None;
    }
    Some(Clip { x, y, width, height })
}

/// A single RGB sample, matching the `{ r, g, b }` objects passed to the
/// JS `luminance`/`ratio` closures.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Rgb {
    pub r: f64,
    pub g: f64,
    pub b: f64,
}

/// Port of the `luminance` closure inside `compareScreenshotContrast`'s
/// `page.evaluate` callback (WCAG 2.x relative luminance).
pub fn relative_luminance(c: Rgb) -> f64 {
    let convert = |v: f64| {
        let v = v / 255.0;
        if v <= 0.03928 {
            v / 12.92
        } else {
            ((v + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * convert(c.r) + 0.7152 * convert(c.g) + 0.0722 * convert(c.b)
}

/// Port of the `ratio` closure inside the same callback.
pub fn contrast_ratio(a: Rgb, b: Rgb) -> f64 {
    let l1 = relative_luminance(a);
    let l2 = relative_luminance(b);
    (l1.max(l2) + 0.05) / (l1.min(l2) + 0.05)
}

/// Port of the `pick(pct)` helper: `sorted_ratios` must already be sorted
/// ascending, matching the JS contract (`ratios.sort((a, b) => a - b)` is
/// done by the caller before repeated `pick` calls).
pub fn pick_percentile(sorted_ratios: &[f64], pct: f64) -> f64 {
    if sorted_ratios.is_empty() {
        return 0.0;
    }
    let len = sorted_ratios.len() as f64;
    let idx = ((pct / 100.0) * len).floor();
    let idx = idx.max(0.0).min(len - 1.0) as usize;
    sorted_ratios[idx]
}

/// Port of the `candidate` object's `textColor`/`preferRenderedForeground`
/// fields used by `compareScreenshotContrast`'s `cssTextColor` computation,
/// plus the metadata `captureVisualContrastCandidate` needs to build its
/// finding (`threshold`, `text`, `reasons`, `selector`,
/// `backgroundClipText`, `clip`).
#[derive(Clone, Debug, PartialEq, Default)]
pub struct ContrastCandidate {
    pub selector: String,
    pub clip: Option<Clip>,
    pub text_color: Option<Rgb>,
    pub prefer_rendered_foreground: bool,
    pub background_clip_text: bool,
    pub threshold: f64,
    pub text: Option<String>,
    pub reasons: Vec<String>,
}

/// Port of `compareScreenshotContrast`'s return shape.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct ContrastMetrics {
    pub glyph_pixels: u64,
    pub strongest_delta: i32,
    pub worst_ratio: Option<f64>,
    pub p10_ratio: Option<f64>,
    pub median_ratio: Option<f64>,
}

/// A single decoded-PNG finding, matching the `{ id: 'low-contrast',
/// snippet }` object `captureVisualContrastCandidate` returns.
#[derive(Clone, Debug, PartialEq)]
pub struct ContrastFinding {
    pub id: &'static str,
    pub snippet: String,
}

/// Port of `compareScreenshotContrast`'s `page.evaluate` callback body, now
/// running natively over decoded PNG bytes instead of a `<canvas>`. Mirrors
/// the JS pixel loop exactly: RGBA delta per pixel, `delta < 10` skip,
/// foreground from `candidate.textColor` (unless
/// `preferRenderedForeground`) or the "before" pixel, background from the
/// "after" pixel, contrast ratio collected, then `< 8` samples short-circuit
/// to all-`None` ratios (same as the JS early return).
pub fn compare_screenshot_contrast(
    before_png: &[u8],
    after_png: &[u8],
    candidate: &ContrastCandidate,
) -> Option<ContrastMetrics> {
    let before = image::load_from_memory(before_png).ok()?.to_rgba8();
    let after = image::load_from_memory(after_png).ok()?.to_rgba8();

    let width = before.width().min(after.width());
    let height = before.height().min(after.height());
    if width < 1 || height < 1 {
        return None;
    }

    let css_text_color = if candidate.text_color.is_some() && !candidate.prefer_rendered_foreground {
        candidate.text_color
    } else {
        None
    };

    let mut ratios: Vec<f64> = Vec::new();
    let mut glyph_pixels: u64 = 0;
    let mut strongest_delta: i32 = 0;

    for y in 0..height {
        for x in 0..width {
            let bp = before.get_pixel(x, y).0;
            let ap = after.get_pixel(x, y).0;
            let delta = (bp[0] as i32 - ap[0] as i32).abs()
                + (bp[1] as i32 - ap[1] as i32).abs()
                + (bp[2] as i32 - ap[2] as i32).abs()
                + (bp[3] as i32 - ap[3] as i32).abs();
            strongest_delta = strongest_delta.max(delta);
            if delta < 10 {
                continue;
            }
            glyph_pixels += 1;
            let fg = css_text_color.unwrap_or(Rgb {
                r: bp[0] as f64,
                g: bp[1] as f64,
                b: bp[2] as f64,
            });
            let bg = Rgb {
                r: ap[0] as f64,
                g: ap[1] as f64,
                b: ap[2] as f64,
            };
            ratios.push(contrast_ratio(fg, bg));
        }
    }

    if ratios.len() < 8 {
        return Some(ContrastMetrics {
            glyph_pixels,
            strongest_delta,
            worst_ratio: None,
            p10_ratio: None,
            median_ratio: None,
        });
    }

    ratios.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Some(ContrastMetrics {
        glyph_pixels,
        strongest_delta,
        worst_ratio: Some(ratios[0]),
        p10_ratio: Some(pick_percentile(&ratios, 10.0)),
        median_ratio: Some(pick_percentile(&ratios, 50.0)),
    })
}

/// Port of the browser side effects `captureVisualContrastCandidate` drives
/// (`page.screenshot()` and the hide-style `page.evaluate()` toggle),
/// abstracted so the orchestration in
/// [`capture_visual_contrast_candidate`] is testable without a real
/// browser. Mirrors `ChromeDeckStageBrowser`/`ChromeThumbBrowser` in
/// `wf_port::r00` and `RealChromeDriver` in `wf_port::r07`.
pub trait PageCapture {
    /// Port of `page.screenshot({ encoding: 'base64', clip, captureBeyondViewport: true })`,
    /// returning raw PNG bytes (the base64 encoding step is JS-transport
    /// only and adds nothing here).
    fn screenshot_png(&mut self, clip: Clip) -> Result<Vec<u8>, String>;

    /// Port of the `page.evaluate` block that queries `selector`, appends
    /// the shared `#impeccable-visual-contrast-hide-style` stylesheet if
    /// missing, and sets `data-impeccable-visual-contrast-target`
    /// (+ `data-impeccable-bgclip-text` when `background_clip_text`).
    /// Returns `false` when the selector is invalid or matches nothing,
    /// matching the JS `try { el = querySelector(selector) } catch { return
    /// false }` / `if (!el) return false`.
    fn apply_hide(&mut self, selector: &str, background_clip_text: bool) -> Result<bool, String>;

    /// Port of the `finally`/cleanup `page.evaluate` block that removes the
    /// two `data-impeccable-*` attributes, swallowing selector errors (the
    /// JS `.catch(() => {})`).
    fn remove_hide(&mut self, selector: &str);
}

/// Port of `captureVisualContrastCandidate(page, candidate, viewport)`.
/// `viewport_width` mirrors `viewport?.width`.
pub fn capture_visual_contrast_candidate(
    capture: &mut impl PageCapture,
    candidate: &ContrastCandidate,
    viewport_width: Option<i64>,
) -> Option<ContrastFinding> {
    let clip = sanitize_screenshot_clip(candidate.clip, viewport_width)?;

    let before_base64 = capture.screenshot_png(clip).ok()?;

    let applied = capture
        .apply_hide(&candidate.selector, candidate.background_clip_text)
        .unwrap_or(false);
    if !applied {
        return None;
    }

    let after_result = capture.screenshot_png(clip);
    // Mirror the JS `finally` block: cleanup always runs, even on error.
    capture.remove_hide(&candidate.selector);
    let after_base64 = after_result.ok()?;

    let metrics = compare_screenshot_contrast(&before_base64, &after_base64, candidate)?;
    let p10 = metrics.p10_ratio?;
    if !p10.is_finite() || metrics.glyph_pixels < 8 {
        return None;
    }
    let measured_ratio = p10;
    if measured_ratio >= candidate.threshold {
        return None;
    }
    let text_label = candidate
        .text
        .as_deref()
        .map(|t| format!(" \"{t}\""))
        .unwrap_or_default();
    let reason_label = if candidate.reasons.is_empty() {
        "visual background".to_string()
    } else {
        candidate.reasons.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
    };
    let median = metrics.median_ratio.unwrap_or(0.0);
    Some(ContrastFinding {
        id: "low-contrast",
        snippet: format!(
            "pixel contrast {measured_ratio:.1}:1 median {median:.1}:1 (need {}:1) on {reason_label}{text_label}",
            candidate.threshold
        ),
    })
}

/// Production `headless_chrome`-backed [`PageCapture`]. Same compile-review
/// caveat as `wf_port::r00::export_deck_stage_pdf::ChromeDeckStageBrowser`:
/// field/method names follow the documented 1.x API and should be
/// re-checked once `cargo` can run against the pinned version. No test
/// drives this type; tests exercise [`capture_visual_contrast_candidate`]
/// through a fake `PageCapture`.
pub struct ChromeContrastCapture {
    tab: std::sync::Arc<headless_chrome::Tab>,
    _browser: headless_chrome::Browser,
}

impl ChromeContrastCapture {
    /// Attaches to an already-navigated page. Screenshot-contrast capture
    /// runs against the live page under test (already opened elsewhere in
    /// the detector pipeline), so this takes an existing tab/browser pair
    /// rather than launching a fresh one.
    pub fn new(tab: std::sync::Arc<headless_chrome::Tab>, browser: headless_chrome::Browser) -> Self {
        Self {
            tab,
            _browser: browser,
        }
    }
}

impl PageCapture for ChromeContrastCapture {
    fn screenshot_png(&mut self, clip: Clip) -> Result<Vec<u8>, String> {
        let cdp_clip = headless_chrome::protocol::cdp::Page::Viewport {
            x: clip.x as f64,
            y: clip.y as f64,
            width: clip.width as f64,
            height: clip.height as f64,
            scale: 1.0,
        };
        self.tab
            .capture_screenshot(
                headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
                None,
                Some(cdp_clip),
                true,
            )
            .map_err(|e| e.to_string())
    }

    fn apply_hide(&mut self, selector: &str, background_clip_text: bool) -> Result<bool, String> {
        let token = format!(
            "impeccable-contrast-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            std::process::id()
        );
        let selector_json = serde_json::to_string(selector).unwrap_or_else(|_| "\"\"".to_string());
        let bgclip = if background_clip_text { "true" } else { "false" };
        let expression = format!(
            r#"(() => {{
  let el;
  try {{ el = document.querySelector({selector_json}); }} catch (e) {{ return false; }}
  if (!el) return false;
  let style = document.getElementById('impeccable-visual-contrast-hide-style');
  if (!style) {{
    style = document.createElement('style');
    style.id = 'impeccable-visual-contrast-hide-style';
    style.textContent = [
      '[data-impeccable-visual-contrast-target] {{',
      '  color: transparent !important;',
      '  -webkit-text-fill-color: transparent !important;',
      '  text-shadow: none !important;',
      '}}',
      '[data-impeccable-visual-contrast-target][data-impeccable-bgclip-text="true"] {{',
      '  background-image: none !important;',
      '}}',
    ].join('\n');
    document.head.appendChild(style);
  }}
  el.setAttribute('data-impeccable-visual-contrast-target', '{token}');
  if ({bgclip}) el.setAttribute('data-impeccable-bgclip-text', 'true');
  return true;
}})()"#
        );
        let remote_object = self.tab.evaluate(&expression, false).map_err(|e| e.to_string())?;
        Ok(matches!(remote_object.value, Some(serde_json::Value::Bool(true))))
    }

    fn remove_hide(&mut self, selector: &str) {
        let selector_json = serde_json::to_string(selector).unwrap_or_else(|_| "\"\"".to_string());
        let expression = format!(
            r#"(() => {{
  try {{
    const el = document.querySelector({selector_json});
    if (el) {{
      el.removeAttribute('data-impeccable-visual-contrast-target');
      el.removeAttribute('data-impeccable-bgclip-text');
    }}
  }} catch (e) {{ /* Ignore invalid or stale selectors during cleanup. */ }}
}})()"#
        );
        let _ = self.tab.evaluate(&expression, false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_clip_returns_none_for_missing_clip() {
        assert_eq!(sanitize_screenshot_clip(None, Some(1600)), None);
    }

    #[test]
    fn sanitize_clip_clamps_width_to_viewport_and_height_to_320() {
        let clip = Clip { x: -5, y: -3, width: 5000, height: 500 };
        let sanitized = sanitize_screenshot_clip(Some(clip), Some(1200)).unwrap();
        assert_eq!(sanitized, Clip { x: 0, y: 0, width: 1200, height: 320 });
    }

    #[test]
    fn sanitize_clip_defaults_viewport_width_to_1600() {
        let clip = Clip { x: 0, y: 0, width: 9999, height: 10 };
        let sanitized = sanitize_screenshot_clip(Some(clip), None).unwrap();
        assert_eq!(sanitized.width, 1600);
    }

    #[test]
    fn sanitize_clip_floors_dimensions_to_at_least_one() {
        let clip = Clip { x: 1, y: 1, width: 0, height: 0 };
        let sanitized = sanitize_screenshot_clip(Some(clip), Some(1600)).unwrap();
        assert_eq!(sanitized.width, 1);
        assert_eq!(sanitized.height, 1);
    }

    #[test]
    fn relative_luminance_of_black_is_zero_and_white_is_one() {
        assert_eq!(relative_luminance(Rgb { r: 0.0, g: 0.0, b: 0.0 }), 0.0);
        assert!((relative_luminance(Rgb { r: 255.0, g: 255.0, b: 255.0 }) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn contrast_ratio_of_black_on_white_is_21_to_1() {
        let black = Rgb { r: 0.0, g: 0.0, b: 0.0 };
        let white = Rgb { r: 255.0, g: 255.0, b: 255.0 };
        assert!((contrast_ratio(black, white) - 21.0).abs() < 1e-6);
    }

    #[test]
    fn contrast_ratio_is_symmetric() {
        let a = Rgb { r: 10.0, g: 200.0, b: 50.0 };
        let b = Rgb { r: 240.0, g: 30.0, b: 90.0 };
        assert!((contrast_ratio(a, b) - contrast_ratio(b, a)).abs() < 1e-9);
    }

    #[test]
    fn pick_percentile_matches_js_floor_formula() {
        let sorted = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        // JS: Math.floor((10/100)*5) = 0 -> sorted[0]
        assert_eq!(pick_percentile(&sorted, 10.0), 1.0);
        // JS: Math.floor((50/100)*5) = 2 -> sorted[2]
        assert_eq!(pick_percentile(&sorted, 50.0), 3.0);
    }

    #[test]
    fn pick_percentile_empty_is_zero() {
        assert_eq!(pick_percentile(&[], 10.0), 0.0);
    }

    fn encode_png(pixels: &[[u8; 4]], width: u32, height: u32) -> Vec<u8> {
        let mut buf = image::RgbaImage::new(width, height);
        for (i, px) in pixels.iter().enumerate() {
            let x = (i as u32) % width;
            let y = (i as u32) / width;
            buf.put_pixel(x, y, image::Rgba(*px));
        }
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(buf)
            .write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png)
            .unwrap();
        out
    }

    fn base_candidate() -> ContrastCandidate {
        ContrastCandidate {
            selector: ".target".to_string(),
            clip: Some(Clip { x: 0, y: 0, width: 4, height: 4 }),
            text_color: None,
            prefer_rendered_foreground: false,
            background_clip_text: false,
            threshold: 4.5,
            text: None,
            reasons: vec![],
        }
    }

    #[test]
    fn compare_screenshot_contrast_below_min_samples_returns_none_ratios() {
        // 2x2 image: identical pixels everywhere -> zero deltas -> < 8 samples.
        let before = encode_png(&[[0, 0, 0, 255]; 4], 2, 2);
        let after = encode_png(&[[0, 0, 0, 255]; 4], 2, 2);
        let metrics = compare_screenshot_contrast(&before, &after, &base_candidate()).unwrap();
        assert_eq!(metrics.glyph_pixels, 0);
        assert_eq!(metrics.worst_ratio, None);
        assert_eq!(metrics.p10_ratio, None);
        assert_eq!(metrics.median_ratio, None);
    }

    #[test]
    fn compare_screenshot_contrast_black_on_white_yields_21_to_1() {
        // 4x4 all-black "before" (text visible) vs all-white "after" (text
        // hidden) -> every pixel deltas by 255*3=765 >= 10, so all 16
        // samples count and the ratio is the WCAG max 21:1.
        let before = encode_png(&[[0, 0, 0, 255]; 16], 4, 4);
        let after = encode_png(&[[255, 255, 255, 255]; 16], 4, 4);
        let metrics = compare_screenshot_contrast(&before, &after, &base_candidate()).unwrap();
        assert_eq!(metrics.glyph_pixels, 16);
        assert!((metrics.worst_ratio.unwrap() - 21.0).abs() < 1e-6);
        assert!((metrics.median_ratio.unwrap() - 21.0).abs() < 1e-6);
    }

    #[test]
    fn compare_screenshot_contrast_uses_css_text_color_when_not_preferring_rendered() {
        let before = encode_png(&[[0, 0, 0, 255]; 16], 4, 4);
        let after = encode_png(&[[255, 255, 255, 255]; 16], 4, 4);
        let mut candidate = base_candidate();
        // Same "before" color, so the CSS-vs-rendered choice doesn't change
        // this particular ratio, but exercises the branch.
        candidate.text_color = Some(Rgb { r: 0.0, g: 0.0, b: 0.0 });
        candidate.prefer_rendered_foreground = false;
        let metrics = compare_screenshot_contrast(&before, &after, &candidate).unwrap();
        assert!((metrics.worst_ratio.unwrap() - 21.0).abs() < 1e-6);
    }

    struct FakeCapture {
        before: Vec<u8>,
        after: Vec<u8>,
        call: u32,
        hide_applied: bool,
        hide_removed: bool,
        apply_hide_result: bool,
    }

    impl PageCapture for FakeCapture {
        fn screenshot_png(&mut self, _clip: Clip) -> Result<Vec<u8>, String> {
            self.call += 1;
            if self.call == 1 {
                Ok(self.before.clone())
            } else {
                Ok(self.after.clone())
            }
        }

        fn apply_hide(&mut self, _selector: &str, _background_clip_text: bool) -> Result<bool, String> {
            self.hide_applied = true;
            Ok(self.apply_hide_result)
        }

        fn remove_hide(&mut self, _selector: &str) {
            self.hide_removed = true;
        }
    }

    #[test]
    fn capture_visual_contrast_candidate_returns_none_for_unsanitizable_clip() {
        let mut candidate = base_candidate();
        candidate.clip = None;
        let mut capture = FakeCapture {
            before: vec![],
            after: vec![],
            call: 0,
            hide_applied: false,
            hide_removed: false,
            apply_hide_result: true,
        };
        assert_eq!(capture_visual_contrast_candidate(&mut capture, &candidate, None), None);
        assert!(!capture.hide_applied);
    }

    #[test]
    fn capture_visual_contrast_candidate_returns_none_when_hide_not_applied() {
        let candidate = base_candidate();
        let before = encode_png(&[[0, 0, 0, 255]; 16], 4, 4);
        let mut capture = FakeCapture {
            before: before.clone(),
            after: before,
            call: 0,
            hide_applied: false,
            hide_removed: false,
            apply_hide_result: false,
        };
        assert_eq!(capture_visual_contrast_candidate(&mut capture, &candidate, None), None);
        assert!(capture.hide_applied);
        // Cleanup only runs after a successful apply_hide (mirrors the JS:
        // `if (!applied) return null;` happens before the try/finally).
        assert!(!capture.hide_removed);
    }

    #[test]
    fn capture_visual_contrast_candidate_flags_low_contrast_below_threshold() {
        let mut candidate = base_candidate();
        candidate.clip = Some(Clip { x: 0, y: 0, width: 4, height: 4 });
        candidate.threshold = 4.5;
        candidate.text = Some("Read more".to_string());
        candidate.reasons = vec!["low contrast background".to_string()];
        let before = encode_png(&[[0, 0, 0, 255]; 16], 4, 4);
        let after = encode_png(&[[255, 255, 255, 255]; 16], 4, 4);
        let mut capture = FakeCapture {
            before,
            after,
            call: 0,
            hide_applied: false,
            hide_removed: false,
            apply_hide_result: true,
        };
        // Black-on-white is 21:1, well above the 4.5:1 threshold, so this
        // should NOT be flagged -- exercises the "measured >= threshold"
        // short circuit.
        assert_eq!(capture_visual_contrast_candidate(&mut capture, &candidate, None), None);
        assert!(capture.hide_removed);
    }

    #[test]
    fn capture_visual_contrast_candidate_flags_when_ratio_is_below_threshold() {
        let mut candidate = base_candidate();
        candidate.threshold = 25.0; // above the achievable 21:1 max
        candidate.text = Some("Read more".to_string());
        candidate.reasons = vec!["low contrast background".to_string(), "extra".to_string(), "dropped".to_string(), "also-dropped".to_string()];
        let before = encode_png(&[[0, 0, 0, 255]; 16], 4, 4);
        let after = encode_png(&[[255, 255, 255, 255]; 16], 4, 4);
        let mut capture = FakeCapture {
            before,
            after,
            call: 0,
            hide_applied: false,
            hide_removed: false,
            apply_hide_result: true,
        };
        let finding = capture_visual_contrast_candidate(&mut capture, &candidate, None).unwrap();
        assert_eq!(finding.id, "low-contrast");
        assert!(finding.snippet.contains("21.0:1"));
        assert!(finding.snippet.contains("need 25:1"));
        assert!(finding.snippet.contains("low contrast background, extra, dropped"));
        assert!(!finding.snippet.contains("also-dropped"));
        assert!(finding.snippet.contains("\"Read more\""));
        assert!(capture.hide_removed);
    }
}
