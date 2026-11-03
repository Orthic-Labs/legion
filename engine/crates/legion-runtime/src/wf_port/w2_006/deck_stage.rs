//! Port of `skills/designer/engine/huashu/assets/deck_stage.js` (chunk w2_006).
//!
//! `deck_stage.js` is a browser `<deck-stage>` web component: it drives
//! Shadow DOM, `customElements`, `localStorage`, `postMessage`,
//! `MutationObserver`, and keyboard/hash listeners. None of that runtime
//! surface is reachable from this headless engine, so it is not ported —
//! there is nothing behind those calls but browser globals.
//!
//! What *is* ported, faithfully, is every piece of deterministic logic the
//! component computes before touching the DOM: slide-label assignment
//! (`_collectSlides`), the storage key it derives from the page path
//! (`_storageKey`), the fit-to-viewport scale/offset transform
//! (`_updateScale`), the `#slide-N` hash parser (`_handleHash`), the
//! `current / total` counter text (`_updateDisplay`), and the
//! next/prev/goTo navigation state machine with its bounds checks. A host
//! embedding this engine in a real browser shell can drive a `DeckStage`
//! value with these pure functions and then apply the results (transform
//! string, active slide index, counter text) to its own DOM instead of
//! reimplementing the arithmetic.

use serde::{Deserialize, Serialize};

/// Default stage dimensions, matching `parseInt(this.getAttribute('width')) || 1920`
/// and the `height` equivalent in `connectedCallback`.
pub const DEFAULT_WIDTH: u32 = 1920;
pub const DEFAULT_HEIGHT: u32 = 1080;

/// Port of the `STORAGE_KEY_PREFIX` constant.
pub const STORAGE_KEY_PREFIX: &str = "deck-stage-slide-";

/// Port of `this._storageKey = STORAGE_KEY_PREFIX + (location.pathname || 'default')`.
pub fn storage_key(pathname: Option<&str>) -> String {
    let suffix = match pathname {
        Some(path) if !path.is_empty() => path,
        _ => "default",
    };
    format!("{STORAGE_KEY_PREFIX}{suffix}")
}

/// One `<section>` slide, mirroring the two attributes `_collectSlides`
/// assigns when they are not already present on the element:
/// `data-screen-label` and `data-om-validate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlideAttrs {
    /// `data-screen-label`, zero-padded to two digits, 1-indexed
    /// (`String(idx + 1).padStart(2, '0')`), unless the caller already set one.
    pub screen_label: String,
    /// `data-om-validate` is present (empty string) unless the caller already
    /// set one.
    pub om_validate: String,
}

/// Port of `_collectSlides`'s attribute-assignment loop. `existing` carries,
/// per slide in document order, whatever `data-screen-label` /
/// `data-om-validate` the section already had (`None` when the attribute was
/// absent, matching `!slide.hasAttribute(...)`).
pub fn collect_slide_attrs(existing: &[(Option<String>, Option<String>)]) -> Vec<SlideAttrs> {
    existing
        .iter()
        .enumerate()
        .map(|(idx, (label, om_validate))| SlideAttrs {
            screen_label: label.clone().unwrap_or_else(|| format!("{:02}", idx + 1)),
            om_validate: om_validate.clone().unwrap_or_default(),
        })
        .collect()
}

/// Port of the `#slide-(\d+)` regex and the 1-indexed → 0-indexed conversion
/// and bounds check in `_handleHash`. Returns `None` when the hash does not
/// match, or when the resulting index is out of `[0, slide_count)` — exactly
/// the cases where the original leaves `_currentSlide` untouched.
pub fn parse_slide_hash(hash: &str, slide_count: usize) -> Option<usize> {
    let digits = hash.strip_prefix("#slide-")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let one_indexed: i64 = digits.parse().ok()?;
    let idx = one_indexed - 1;
    if idx >= 0 && (idx as usize) < slide_count {
        Some(idx as usize)
    } else {
        None
    }
}

/// Port of `_restoreSlide`'s `parseInt` + bounds check against a stored
/// string value (the JS wraps `localStorage.getItem` in try/catch and simply
/// keeps `_currentSlide` at 0 on any failure — mirrored here by `None`).
pub fn restore_slide(stored: Option<&str>, slide_count: usize) -> Option<usize> {
    let stored = stored?;
    let idx: i64 = stored.trim().parse().ok()?;
    if idx >= 0 && (idx as usize) < slide_count {
        Some(idx as usize)
    } else {
        None
    }
}

/// The CSS transform `_updateScale` computes for the non-`noscale` path:
/// `translate(offsetX px, offsetY px) scale(scale)`, plus the `top`/`left`
/// values it always resets to `0`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct StageTransform {
    pub scale: f64,
    pub offset_x: f64,
    pub offset_y: f64,
}

impl StageTransform {
    /// Renders the exact `transform` CSS string the JS assigns:
    /// `` `translate(${offsetX}px, ${offsetY}px) scale(${scale})` ``.
    pub fn to_css(&self) -> String {
        format!(
            "translate({}px, {}px) scale({})",
            js_number(self.offset_x),
            js_number(self.offset_y),
            js_number(self.scale)
        )
    }
}

/// Formats an `f64` the way JS `Number#toString` would for the finite,
/// non-huge values this module produces: an integral value prints with no
/// decimal point, otherwise the shortest round-tripping decimal.
fn js_number(value: f64) -> String {
    if value == value.trunc() && value.is_finite() {
        format!("{}", value as i64)
    } else {
        let mut s = format!("{value}");
        if !s.contains('.') && !s.contains('e') {
            s.push_str(".0");
        }
        s
    }
}

/// Port of `_updateScale`'s scaled (non-`noscale`) branch:
/// `scale = min(viewportW / width, viewportH / height)`, then the stage is
/// centered in the viewport. Returns `None` when `width`/`height` are zero,
/// mirroring the `NaN`/`Infinity` the JS would silently produce (a host
/// should skip applying a transform in that case rather than reproduce it).
pub fn compute_scale(
    viewport_w: f64,
    viewport_h: f64,
    stage_w: u32,
    stage_h: u32,
) -> Option<StageTransform> {
    if stage_w == 0 || stage_h == 0 {
        return None;
    }
    let (w, h) = (stage_w as f64, stage_h as f64);
    let scale = (viewport_w / w).min(viewport_h / h);
    let scaled_w = w * scale;
    let scaled_h = h * scale;
    Some(StageTransform {
        scale,
        offset_x: (viewport_w - scaled_w) / 2.0,
        offset_y: (viewport_h - scaled_h) / 2.0,
    })
}

/// Port of `_updateDisplay`'s counter text: `` `${current + 1} / ${total}` ``.
pub fn counter_text(current_slide: usize, total_slides: usize) -> String {
    format!("{} / {}", current_slide + 1, total_slides)
}

/// Port of the `slideIndexChanged`/`totalSlides` postMessage payload shape
/// (`_updateDisplay`), for a host that wants to forward the same event to an
/// embedding page over its own channel instead of `window.postMessage`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlideChangeEvent {
    #[serde(rename = "slideIndexChanged")]
    pub slide_index_changed: usize,
    #[serde(rename = "totalSlides")]
    pub total_slides: usize,
}

/// Pure navigation state machine, mirroring `next`/`prev`/`goTo` and their
/// guard conditions (`_currentSlide < slides.length - 1`,
/// `_currentSlide > 0`, `idx >= 0 && idx < slides.length`). All three JS
/// methods save-then-redisplay only when the guard passes; callers here get
/// the same all-or-nothing behavior via the returned `bool`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeckStageState {
    pub current_slide: usize,
    pub total_slides: usize,
}

impl DeckStageState {
    pub fn new(total_slides: usize) -> Self {
        Self {
            current_slide: 0,
            total_slides,
        }
    }

    /// Returns `true` when the slide actually advanced (matches the JS
    /// guard `this._currentSlide < this._slides.length - 1`, which is false
    /// for `total_slides == 0` since the subtraction underflows toward a
    /// value `current_slide` can never be less than in JS's float domain —
    /// mirrored here by treating an empty deck as never advanceable).
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> bool {
        if self.total_slides > 0 && self.current_slide + 1 < self.total_slides {
            self.current_slide += 1;
            true
        } else {
            false
        }
    }

    /// Port of `prev`'s guard `this._currentSlide > 0`.
    pub fn prev(&mut self) -> bool {
        if self.current_slide > 0 {
            self.current_slide -= 1;
            true
        } else {
            false
        }
    }

    /// Port of `goTo`'s guard `idx >= 0 && idx < this._slides.length`.
    /// `idx` is `usize` here since the JS guard already rejects negatives;
    /// callers with a possibly-negative index should check before calling.
    pub fn go_to(&mut self, idx: usize) -> bool {
        if idx < self.total_slides {
            self.current_slide = idx;
            true
        } else {
            false
        }
    }

    pub fn counter_text(&self) -> String {
        counter_text(self.current_slide, self.total_slides)
    }

    pub fn change_event(&self) -> SlideChangeEvent {
        SlideChangeEvent {
            slide_index_changed: self.current_slide,
            total_slides: self.total_slides,
        }
    }
}
