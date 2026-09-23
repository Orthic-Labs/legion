//! Port of `skills/designer/engine/scripts/detector/engines/visual/screenshot-contrast.mjs`.
//!
//! `compareScreenshotContrast` and `captureVisualContrastCandidate` drive a
//! live Playwright/Puppeteer `page`: they call `page.screenshot()`,
//! `page.evaluate()` (which runs in a real browser tab, decodes PNGs via
//! `Image`/`<canvas>`, and reads back pixel data with
//! `getImageData`), and mutate live DOM style. None of that has a
//! meaningful Rust port — there is no browser or canvas in this crate, and
//! `legion-runtime` owns no browser-automation client in this chunk. That
//! orchestration stays JS-only, as with the DOM-injection scripts noted in
//! `wf_port::w2_011`.
//!
//! What *is* pure, deterministic, DOM-free logic — and is ported below with
//! unit tests mirroring the JS behaviour exactly — is:
//! - [`sanitize_screenshot_clip`], the port of `sanitizeScreenshotClip`.
//! - [`relative_luminance`] and [`contrast_ratio`], the WCAG contrast math
//!   embedded in `compareScreenshotContrast`'s `page.evaluate` callback
//!   (the `luminance`/`ratio` closures), pulled out so a future native
//!   screenshot pipeline (or a test) can reuse the same math without a
//!   browser.
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
}
