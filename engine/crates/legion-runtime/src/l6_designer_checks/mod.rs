//! Packet L6-designer-checks: Rust port of the designer antipattern detector
//! engine (`skills/designer/engine/scripts/detector/rules/checks.mjs`,
//! ~2671 lines) and its rule modules.
//!
//! `checks.mjs` has two halves:
//! 1. **Pure logic** — string/number parsing (CSS color parsing, shadow
//!    parsing, radius parsing) and pure decision functions that take plain
//!    values (widths, colors, booleans) and return findings. Portable now.
//! 2. **DOM adapters** — functions that call `getComputedStyle`,
//!    `getBoundingClientRect`, walk `childNodes`, etc. against a live
//!    browser or jsdom `document`. These have no Rust equivalent yet: no
//!    HTML/CSS parser or DOM crate is pinned in this workspace (confirmed
//!    absent from `Cargo.lock` at port time), matching the P8-designer
//!    packet's own finding for `detect-html.mjs`/`css-cascade.mjs`.
//!
//! This module ports (1) only, rule-by-rule, starting with the local CSS
//! color parser (`checks.mjs` defines its own `parseAnyColor`/`oklchToRgb`
//! independent of `shared/color.mjs`) and the pure checks built on it.
//! `shared/color.mjs` itself (`colorToHex`, `contrastRatio`, `parseRgb`,
//! `relativeLuminance`, `hasChroma`, `isNeutralColor`, `getHue`,
//! `parseGradientColors`) is a separate, not-yet-ported foundation owned by
//! another packet (per `p8_designer`'s plan) — `checkColors`, `checkGlow`,
//! and the border/quality checks that consume it are deferred until that
//! lands.
//!
//! Ported so far: `css_color` (local color/shadow parsing) and `pure_checks`
//! (checkBorders is deferred — depends on `shared/color.mjs::isNeutralColor`;
//! see module docs there). See the packet report (`full-L6.md`) for the
//! per-rule table and the remaining ordered work list.

pub mod css_color;
pub mod pure_checks;

pub use css_color::{
    css_color_alpha, css_color_is_transparent, colors_nearly_match, is_accent_color_impl,
    oklch_to_rgb, parse_any_color, shadow_layer_alpha, shadow_max_blur_px, Rgba,
};
pub use pure_checks::{
    border_colors_from_style, border_widths_from_style, check_gpt_thin_border_wide_shadow,
    check_italic_serif, check_oversized_h1, cream_from_class_list, is_accent_color,
    is_card_like_from_props, is_cream_color, is_emoji_only_text, parse_radius_to_px,
    resolve_serif, Finding, ItalicSerifInput, OversizedH1Input, ResolvedSerif,
};
