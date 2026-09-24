//! Static-DOM adapter layer closing the packet-r10r11 gap named in
//! `wf_port::w2_013::detect_html`'s module doc: the `checkElement*`/
//! `checkPage*`/`check*FromDoc` glue in `checks.mjs` (~lines 616-2349) that
//! sits between `detect-html.mjs`'s `STATIC_ELEMENT_RULES` /
//! `isFullPage` page-check block and the pure functions already ported in
//! `l6_designer_checks::pure_checks` and `wf_port::r11` (this module's
//! sibling). Driven over `wf_port::r09`'s `StaticDocument`/`ComputedStyle`
//! (a real HTML5 DOM + CSS cascade via `scraper`), not a hand-rolled one.
//!
//! One load-bearing simplification, true to the actual call site: every
//! `STATIC_ELEMENT_RULES` entry in `detect-html.mjs` calls these with
//! `customPropMap = null` and (for colors) `hasAnchorInheritRule = false`
//! literally — `const customPropMap = null;` right above the loop. So the
//! `customPropMap`-gated branches in `checkElementColors`/
//! `checkElementHeroEyebrow` (var()-ref re-resolution, anchor-inherit
//! workaround) are dead code on *this* call path and are not ported here;
//! they'd only fire for callers that build a real map, which no `wf_port`
//! caller does. Separately, `wf_port::r09::build_static_style_map` already
//! resolves `var()` refs and expands the `border` shorthand into longhands
//! during cascade computation (see its own module doc), so the
//! `overrides`/`BorderOverride` jsdom-workaround parameter `checkElementBorders`
//! takes (also passed `null` at the real call site) has no work to do here
//! either — the same reason it's `null` in the JS source.
//!
//! Not ported (named precisely, all genuinely rect/layout-dependent, and
//! not exercised by `detectHtml`'s static path, which never passes a
//! `rect`): the `line-length`/`cramped-padding`-via-rect/
//! `body-text-viewport-edge` branches of `checkQuality` (gated on `rect &&`
//! in JS and skipped here the same way, by never constructing a rect), and
//! the live-browser-only globals-based `checkTypography()`/`checkLayout()`
//! (operate on the ambient `document`/`getComputedStyle`, not `detectHtml`'s
//! `doc`/`win` params — genuinely different functions from
//! `checkPageLayout(doc, win)`, which *is* ported below) plus every
//! `checkElement*DOM` sibling (calls real `getBoundingClientRect`), which
//! belong to the separate live/visual detector engine, not
//! `detect-html.mjs`.

use scraper::ElementRef;

use crate::l6_designer_checks::css_color::{css_color_is_transparent, colors_nearly_match, parse_any_color};
use crate::l6_designer_checks::pure_checks::{
    border_colors_from_style, border_widths_from_style, check_gpt_thin_border_wide_shadow,
    check_italic_serif, check_oversized_h1, is_card_like_from_props, is_emoji_only_text,
    parse_radius_to_px, Finding, ItalicSerifInput, OversizedH1Input,
};
use crate::wf_port::r09::{resolve_length_px, StaticDocument};
use crate::wf_port::w2_014::color::{parse_rgb, Rgba};

use super::{
    check_borders, check_colors, check_glow, check_hero_eyebrow, check_icon_tile, check_motion,
    check_repeated_section_kickers, BorderSides, ColorsInput, HeroEyebrowInput, IconTileInput,
    KickerCandidate, MotionInput,
};

// ─── Small DOM helpers (scraper has no jQuery-style closest/textContent) ──

fn tag_lower(el: ElementRef) -> String {
    el.value().name().to_ascii_lowercase()
}

fn attr<'a>(el: &ElementRef<'a>, name: &str) -> Option<&'a str> {
    el.value().attr(name)
}

fn class_list<'a>(el: &ElementRef<'a>) -> &'a str {
    attr(el, "class").unwrap_or("")
}

/// Concatenated text of direct `Text` children only (not descendants) —
/// port of `[...el.childNodes].filter(n => n.nodeType === 3)...join('')`.
fn direct_text(el: ElementRef) -> String {
    el.children()
        .filter_map(|n| n.value().as_text().map(|t| t.to_string()))
        .collect::<Vec<_>>()
        .join("")
}

/// Port of `el.textContent` (all descendant text, concatenated).
fn text_content(el: ElementRef) -> String {
    el.text().collect::<Vec<_>>().join("")
}

fn parent_element(el: ElementRef) -> Option<ElementRef> {
    el.parent().and_then(ElementRef::wrap)
}

fn previous_element_sibling(el: ElementRef) -> Option<ElementRef> {
    let mut sib = el.prev_sibling();
    while let Some(n) = sib {
        if let Some(e) = ElementRef::wrap(n) {
            return Some(e);
        }
        sib = n.prev_sibling();
    }
    None
}

fn children_elements(el: ElementRef) -> Vec<ElementRef> {
    el.children().filter_map(ElementRef::wrap).collect()
}

fn descendants(el: ElementRef) -> Vec<ElementRef> {
    el.descendants().filter_map(ElementRef::wrap).collect()
}

/// Port of `el.closest(selector)`, given a predicate instead of a CSS
/// selector string (callers already know exactly what they're matching).
fn closest_where<'a>(el: ElementRef<'a>, pred: impl Fn(&ElementRef<'a>) -> bool) -> Option<ElementRef<'a>> {
    let mut cur = Some(el);
    while let Some(e) = cur {
        if pred(&e) {
            return Some(e);
        }
        cur = parent_element(e);
    }
    None
}

fn contains(ancestor: ElementRef, other: ElementRef) -> bool {
    descendants(ancestor).iter().any(|d| d.id() == other.id())
}

// ─── resolveBackground / resolveGradientStops (checks.mjs ~637-729) ───────

/// Port of `readOwnBackgroundColor`, `DETECTOR_IS_BROWSER = false` path:
/// prefer the computed `background-color`, falling back to parsing the raw
/// inline `style=""` attribute the same way the JS jsdom fallback does.
/// (`wf_port::r09`'s cascade already resolves declared values from `style=`
/// into the computed map, but a background-image/gradient-bearing
/// shorthand can still leave `background-color` at its default — same gap
/// the JS fallback exists for.)
fn read_own_background_color(el: ElementRef, style_bg: &str) -> Option<Rgba> {
    let bg = parse_rgb(Some(style_bg));
    if bg.as_ref().map(|c| c.a >= 0.1).unwrap_or(false) {
        return bg;
    }
    let raw_style = attr(&el, "style").unwrap_or("");
    let inline_bg = raw_bg_declaration(raw_style);
    let Some(inline_bg) = inline_bg else { return bg };
    if inline_bg.to_ascii_lowercase().contains("gradient") || inline_bg.to_ascii_lowercase().contains("url(") {
        return bg;
    }
    parse_rgb(Some(&inline_bg)).or_else(|| parse_any_color(&inline_bg))
}

fn raw_bg_declaration(raw_style: &str) -> Option<String> {
    // Port of `/background(?:-color)?\s*:\s*([^;]+)/i`.
    let lower = raw_style.to_ascii_lowercase();
    let idx = lower.find("background-color").or_else(|| lower.find("background"))?;
    let after_colon = raw_style[idx..].find(':')?;
    let rest = &raw_style[idx + after_colon + 1..];
    let end = rest.find(';').unwrap_or(rest.len());
    let val = rest[..end].trim();
    if val.is_empty() {
        None
    } else {
        Some(val.to_string())
    }
}

fn bg_image_of(el: ElementRef, doc: &StaticDocument) -> String {
    doc.get_style(&el).get_property_value("background-image")
}

fn bg_color_of(el: ElementRef, doc: &StaticDocument) -> String {
    doc.get_style(&el).get_property_value("background-color")
}

fn has_gradient_or_url(bg_image: &str) -> bool {
    !bg_image.is_empty()
        && bg_image != "none"
        && (bg_image.to_ascii_lowercase().contains("gradient") || bg_image.to_ascii_lowercase().contains("url("))
}

/// Port of `resolveBackground(el, win, customPropMap)` (`customPropMap`
/// always `null` on this call path, see module doc).
pub fn resolve_background<'a>(el: ElementRef<'a>, doc: &StaticDocument) -> Option<Rgba> {
    let mut current = Some(el);
    while let Some(cur) = current {
        let bg_image = bg_image_of(cur, doc);
        let bg_color_str = bg_color_of(cur, doc);
        let gradient_or_url = has_gradient_or_url(&bg_image);

        let bg = read_own_background_color(cur, &bg_color_str);
        if let Some(b) = bg {
            if b.a > 0.1 && b.a >= 0.5 {
                return Some(b);
            }
        }
        if gradient_or_url {
            let tag = tag_lower(cur);
            if tag == "body" || tag == "html" {
                return Some(Rgba { r: 255.0, g: 255.0, b: 255.0, a: 1.0 });
            }
            return None;
        }
        current = parent_element(cur);
    }
    Some(Rgba { r: 255.0, g: 255.0, b: 255.0, a: 1.0 })
}

/// Port of `resolveGradientStops(el, win)`.
pub fn resolve_gradient_stops(el: ElementRef, doc: &StaticDocument) -> Vec<Rgba> {
    let mut current = Some(el);
    while let Some(cur) = current {
        let bg_image = bg_image_of(cur, doc);
        if !bg_image.is_empty() && bg_image != "none" && bg_image.to_ascii_lowercase().contains("gradient") {
            let stops = crate::wf_port::w2_014::color::parse_gradient_colors(Some(&bg_image));
            if !stops.is_empty() {
                return stops;
            }
        }
        let raw_style = attr(&cur, "style").unwrap_or("");
        if let Some(bg_match) = raw_bg_image_declaration(raw_style) {
            if bg_match.to_ascii_lowercase().contains("gradient") {
                let stops = crate::wf_port::w2_014::color::parse_gradient_colors(Some(&bg_match));
                if !stops.is_empty() {
                    return stops;
                }
            }
        }
        current = parent_element(cur);
    }
    Vec::new()
}

fn raw_bg_image_declaration(raw_style: &str) -> Option<String> {
    let lower = raw_style.to_ascii_lowercase();
    let idx = lower.find("background-image").or_else(|| lower.find("background"))?;
    let after_colon = raw_style[idx..].find(':')?;
    let rest = &raw_style[idx + after_colon + 1..];
    let end = rest.find(';').unwrap_or(rest.len());
    Some(rest[..end].trim().to_string())
}

// ─── resolveFontSizePx / resolveBorderRadiusPx (checks.mjs ~1226-1264, 745-755) ─

/// Port of `resolveFontSizePx(el, win)`.
pub fn resolve_font_size_px(el: ElementRef, doc: &StaticDocument) -> f64 {
    let mut chain: Vec<String> = Vec::new();
    let mut cur = Some(el);
    while let Some(e) = cur {
        chain.push(doc.get_style(&e).get_property_value("font-size"));
        cur = parent_element(e);
    }
    let mut px = 16.0f64;
    for v in chain.iter().rev() {
        if v.is_empty() || v == "inherit" {
            continue;
        }
        let num: f64 = match leading_number(v) {
            Some(n) => n,
            None => continue,
        };
        if v.ends_with("px") {
            px = num;
        } else if v.ends_with("rem") {
            px = num * 16.0;
        } else if v.ends_with("em") {
            px *= num;
        } else if v.ends_with('%') {
            px = (num / 100.0) * px;
        } else {
            px = num;
        }
    }
    px
}

fn leading_number(s: &str) -> Option<f64> {
    let t = s.trim();
    let end = t
        .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == '-' || c == '+'))
        .unwrap_or(t.len());
    t[..end].parse::<f64>().ok()
}

/// Port of `resolveBorderRadiusPx(el, style, widthPx, win)`.
pub fn resolve_border_radius_px(style: &crate::wf_port::r09::ComputedStyle, width_px: f64) -> f64 {
    let raw = style.get_property_value("border-radius");
    parse_radius_to_px(Some(&raw), Some(width_px)).unwrap_or(0.0)
}

// ─── checkElementBorders (checks.mjs ~1718-1743) ───────────────────────────

pub fn check_element_borders(
    tag: &str,
    style: &crate::wf_port::r09::ComputedStyle,
    resolved_radius: Option<f64>,
) -> Vec<Finding> {
    let widths = [
        style.get_property_value("border-top-width"),
        style.get_property_value("border-right-width"),
        style.get_property_value("border-bottom-width"),
        style.get_property_value("border-left-width"),
    ];
    let colors = [
        style.get_property_value("border-top-color"),
        style.get_property_value("border-right-color"),
        style.get_property_value("border-bottom-color"),
        style.get_property_value("border-left-color"),
    ];
    let w: Vec<f64> = widths.iter().map(|w| leading_number(w).unwrap_or(0.0)).collect();
    let radius = resolved_radius.unwrap_or_else(|| leading_number(&style.get_property_value("border-radius")).unwrap_or(0.0));
    check_borders(
        tag,
        &BorderSides {
            widths: [w[0], w[1], w[2], w[3]],
            colors: [
                Some(colors[0].as_str()),
                Some(colors[1].as_str()),
                Some(colors[2].as_str()),
                Some(colors[3].as_str()),
            ],
        },
        radius,
    )
}

// ─── checkElementColors (checks.mjs ~1748-1801) ────────────────────────────

pub fn check_element_colors(el: ElementRef, doc: &StaticDocument, style: &crate::wf_port::r09::ComputedStyle, tag: &str) -> Vec<Finding> {
    let direct = direct_text(el);
    let has_direct_text = !direct.trim().is_empty();
    let effective_bg = resolve_background(el, doc);
    let text_color = parse_rgb(Some(&style.get_property_value("color")));
    let effective_bg_stops = if effective_bg.is_none() {
        resolve_gradient_stops(el, doc)
    } else {
        Vec::new()
    };
    let bg_clip_raw = {
        let webkit = style.get_property_value("-webkit-background-clip");
        if webkit.is_empty() { style.get_property_value("background-clip") } else { webkit }
    };
    let bg_image_raw = style.get_property_value("background-image");
    let class_list_raw = class_list(&el);
    check_colors(&ColorsInput {
        tag,
        text_color,
        bg_color: read_own_background_color(el, &style.get_property_value("background-color")),
        effective_bg,
        effective_bg_stops: &effective_bg_stops,
        font_size: leading_number(&style.get_property_value("font-size")).unwrap_or(16.0),
        font_weight: leading_number(&style.get_property_value("font-weight")).unwrap_or(400.0),
        has_direct_text,
        is_emoji_only: is_emoji_only_text(&direct),
        bg_clip: non_empty(&bg_clip_raw),
        bg_image: non_empty(&bg_image_raw),
        class_list: non_empty(class_list_raw),
        is_browser: false,
    })
}

// ─── checkElementIconTile (checks.mjs ~1802-1836) ──────────────────────────

fn is_icon_child(el: &ElementRef) -> bool {
    let tag = tag_lower(*el);
    if tag == "svg" {
        return true;
    }
    if tag == "i" {
        let cls = class_list(el);
        return attr(el, "data-lucide").is_some() || cls.contains("fa-") || cls.contains("icon");
    }
    false
}

pub fn check_element_icon_tile(el: ElementRef, doc: &StaticDocument, tag: &str) -> Vec<Finding> {
    let Some(sibling) = previous_element_sibling(el) else { return vec![] };
    let sib_style = doc.get_style(&sibling);
    let sib_width = leading_number(&sib_style.get_property_value("width")).unwrap_or(0.0);
    let sib_height = leading_number(&sib_style.get_property_value("height")).unwrap_or(0.0);

    let icon_child = descendants(sibling).into_iter().find(is_icon_child);
    let mut icon_width = 0.0;
    if let Some(ic) = icon_child {
        let icon_style = doc.get_style(&ic);
        icon_width = leading_number(&icon_style.get_property_value("width"))
            .or_else(|| attr(&ic, "width").and_then(leading_number))
            .unwrap_or(0.0);
    }
    let sib_direct = direct_text(sibling);
    let has_inline_emoji_icon = children_elements(sibling).is_empty() && is_emoji_only_text(&sib_direct);

    let sib_tag = tag_lower(sibling);
    let heading_text = text_content(el);
    let sib_bg_image = sib_style.get_property_value("background-image");
    check_icon_tile(&IconTileInput {
        heading_tag: tag,
        heading_text: &heading_text,
        heading_top: 0.0,
        sibling_tag: Some(sib_tag.as_str()),
        sibling_width: sib_width,
        sibling_height: sib_height,
        sibling_bottom: 0.0,
        sibling_bg_color: parse_rgb(Some(&sib_style.get_property_value("background-color"))),
        sibling_bg_image: non_empty(&sib_bg_image),
        sibling_border_width: leading_number(&sib_style.get_property_value("border-top-width")).unwrap_or(0.0),
        sibling_border_radius: resolve_border_radius_px(&sib_style, sib_width),
        has_icon_child: icon_child.is_some() || has_inline_emoji_icon,
        icon_child_width: Some(icon_width),
    })
}

// ─── checkElementItalicSerif (checks.mjs ~1839-1848) ───────────────────────

pub fn check_element_italic_serif(el: ElementRef, style: &crate::wf_port::r09::ComputedStyle, tag: &str) -> Vec<Finding> {
    if tag != "h1" && tag != "h2" {
        return vec![];
    }
    let font_style = style.get_property_value("font-style");
    let font_family = style.get_property_value("font-family");
    let heading_text = text_content(el);
    check_italic_serif(ItalicSerifInput {
        tag,
        font_style: &font_style,
        font_family: non_empty(&font_family),
        font_size: leading_number(&style.get_property_value("font-size")).unwrap_or(0.0),
        heading_text: &heading_text,
    })
}

// ─── checkElementHeroEyebrow (checks.mjs ~1850-1878) ───────────────────────

pub fn check_element_hero_eyebrow(el: ElementRef, doc: &StaticDocument, style: &crate::wf_port::r09::ComputedStyle, tag: &str) -> Vec<Finding> {
    if tag != "h1" {
        return vec![];
    }
    let Some(sibling) = previous_element_sibling(el) else { return vec![] };
    let sib_style = doc.get_style(&sibling);
    let sib_font_size = leading_number(&sib_style.get_property_value("font-size")).unwrap_or(0.0);
    let letter_spacing_raw = sib_style.get_property_value("letter-spacing");
    let sib_tag = tag_lower(sibling);
    let heading_text = text_content(el);
    let sibling_text = text_content(sibling);
    let sib_text_transform = sib_style.get_property_value("text-transform");
    let sib_color = sib_style.get_property_value("color");
    check_hero_eyebrow(&HeroEyebrowInput {
        heading_tag: tag,
        heading_text: &heading_text,
        sibling_tag: Some(sib_tag.as_str()),
        sibling_text: &sibling_text,
        sibling_text_transform: non_empty(&sib_text_transform),
        sibling_font_size: sib_font_size,
        sibling_letter_spacing: resolve_length_px(&letter_spacing_raw, sib_font_size).unwrap_or(0.0),
        sibling_font_weight: leading_number(&sib_style.get_property_value("font-weight")).unwrap_or(0.0),
        sibling_color: non_empty(&sib_color),
    })
}

fn non_empty(s: &str) -> Option<&str> {
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

// ─── checkElementMotion / checkElementGlow (checks.mjs ~1890-1908) ─────────

pub fn check_element_motion(tag: &str, style: &crate::wf_port::r09::ComputedStyle) -> Vec<Finding> {
    let timing = [
        style.get_property_value("animation-timing-function"),
        style.get_property_value("transition-timing-function"),
    ]
    .into_iter()
    .filter(|s| !s.is_empty())
    .collect::<Vec<_>>()
    .join(" ");
    let transition_property = style.get_property_value("transition-property");
    let animation_name = style.get_property_value("animation-name");
    check_motion(&MotionInput {
        tag,
        transition_property: non_empty(&transition_property),
        animation_name: non_empty(&animation_name),
        timing_functions: non_empty(&timing),
        class_list: None,
    })
}

pub fn check_element_glow(tag: &str, style: &crate::wf_port::r09::ComputedStyle, effective_bg: Option<Rgba>) -> Vec<Finding> {
    let box_shadow = style.get_property_value("box-shadow");
    if box_shadow.is_empty() || box_shadow == "none" {
        return vec![];
    }
    check_glow(Some(&box_shadow), effective_bg)
}

// ─── checkElementOversizedH1 (checks.mjs ~2253-2258) ───────────────────────

pub fn check_element_oversized_h1(el: ElementRef, doc: &StaticDocument, tag: &str) -> Vec<Finding> {
    if tag != "h1" {
        return vec![];
    }
    let font_size = resolve_font_size_px(el, doc);
    let heading_text = collapse_ws(&text_content(el));
    check_oversized_h1(OversizedH1Input {
        tag,
        font_size,
        heading_text: &heading_text,
        rect: None,
        viewport_width: 0.0,
        viewport_height: 0.0,
    })
}

fn collapse_ws(s: &str) -> String {
    s.trim().split_whitespace().collect::<Vec<_>>().join(" ")
}

// ─── checkElementGptBorderShadow (checks.mjs ~2337-2340) ───────────────────

pub fn check_element_gpt_border_shadow(style: &crate::wf_port::r09::ComputedStyle) -> Vec<Finding> {
    let widths = border_widths_from_style(
        leading_number(&style.get_property_value("border-top-width")),
        leading_number(&style.get_property_value("border-right-width")),
        leading_number(&style.get_property_value("border-bottom-width")),
        leading_number(&style.get_property_value("border-left-width")),
    );
    let top = style.get_property_value("border-top-color");
    let right = style.get_property_value("border-right-color");
    let bottom = style.get_property_value("border-bottom-color");
    let left = style.get_property_value("border-left-color");
    let colors = border_colors_from_style(non_empty(&top), non_empty(&right), non_empty(&bottom), non_empty(&left));
    let box_shadow = style.get_property_value("box-shadow");
    check_gpt_thin_border_wide_shadow(&widths, &colors, &box_shadow)
}

// ─── checkElementClippedOverflow (checks.mjs ~2337-2491) ───────────────────

fn is_positioned_decorative(child: ElementRef) -> bool {
    if closest_where(child, |e| attr(e, "aria-hidden") == Some("true")).is_some() {
        return true;
    }
    let role = attr(&child, "role").unwrap_or("").to_ascii_lowercase();
    if role == "none" || role == "presentation" {
        return true;
    }
    let tag = tag_lower(child);
    if matches!(tag.as_str(), "img" | "svg" | "canvas" | "video") {
        return true;
    }
    let ident = format!("{} {}", class_list(&child), attr(&child, "id").unwrap_or(""));
    let decor_re = decorative_ident_re();
    if decor_re.is_match(&ident) && !positioned_child_has_substantive_content(child) {
        return true;
    }
    false
}

fn decorative_ident_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\b(art|bg|background|badge|blob|crop|decor|dot|glow|grain|image|mask|ornament|overlay|photo|scrim|shadow|shine|texture)\b").unwrap()
    })
}

fn positioned_child_has_substantive_content(child: ElementRef) -> bool {
    if !collapse_ws(&text_content(child)).is_empty() {
        return true;
    }
    // Interactive-selector match, hand-checked (tag/role/attr set) instead
    // of a CSS selector string, same fields `POSITIONED_CHILD_INTERACTIVE_SELECTOR`
    // lists.
    if is_interactive(child) {
        return true;
    }
    descendants(child).into_iter().any(is_interactive)
}

fn is_interactive(el: ElementRef) -> bool {
    let tag = tag_lower(el);
    if tag == "a" && attr(&el, "href").is_some() {
        return true;
    }
    if matches!(tag.as_str(), "button" | "input" | "select" | "summary" | "textarea") {
        return true;
    }
    if let Some(tabindex) = attr(&el, "tabindex") {
        if tabindex != "-1" {
            return true;
        }
    }
    matches!(
        attr(&el, "role").unwrap_or(""),
        "button" | "dialog" | "link" | "listbox" | "menu" | "menuitem" | "option" | "tooltip"
    )
}

fn clipping_container_is_intentional_viewport(el: ElementRef) -> bool {
    let role_desc = attr(&el, "aria-roledescription").unwrap_or("").to_ascii_lowercase();
    if role_desc.contains("carousel") || role_desc.contains("slider") {
        return true;
    }
    let ident = format!("{} {}", class_list(&el), attr(&el, "id").unwrap_or("")).to_ascii_lowercase();
    let re = viewport_ident_re();
    re.is_match(&ident)
}

fn viewport_ident_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\b(carousel|comparison|compare|fisheye|marquee|preview|scroller|slider|slideshow|split|viewport)\b|\b(demo-area|demo-stage|demo-viewport)\b").unwrap()
    })
}

fn positioned_style_implies_escape(style: &crate::wf_port::r09::ComputedStyle) -> bool {
    let props = [
        "top", "right", "bottom", "left", "inset", "inset-block", "inset-inline",
        "inset-block-start", "inset-block-end", "inset-inline-start", "inset-inline-end",
    ];
    let neg_re = negative_leading_re();
    let full_re = full_percent_re();
    for p in props {
        let v = style.get_property_value(p).trim().to_ascii_lowercase();
        if v.is_empty() {
            continue;
        }
        if neg_re.is_match(&v) || full_re.is_match(&v) {
            return true;
        }
    }
    false
}

fn negative_leading_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(^|[\s(])-+(?:\d|\.)").unwrap())
}

fn full_percent_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(^|[\s(])100(?:\.0+)?%").unwrap())
}

/// Port of `checkClippedOverflow(el, style, getStyle)`. Rects are never
/// available statically, so `positionedChildEscapesClip` always returns
/// `null` here (its `elementRect` guard fails the same way it does in the
/// static JS engine), and every candidate falls through to
/// `positionedStyleImpliesEscape` — exactly the JS fallback path.
pub fn check_element_clipped_overflow(el: ElementRef, doc: &StaticDocument, style: &crate::wf_port::r09::ComputedStyle) -> Vec<Finding> {
    let clips = |v: &str| v == "hidden" || v == "clip";
    let scrolls = |v: &str| v == "auto" || v == "scroll";
    let ox = style.get_property_value("overflow-x");
    let oy = style.get_property_value("overflow-y");
    let ov = style.get_property_value("overflow");
    let clip_x = clips(&ox) || clips(&ov);
    let clip_y = clips(&oy) || clips(&ov);
    if !(clip_x || clip_y) || scrolls(&ox) || scrolls(&oy) || scrolls(&ov) {
        return vec![];
    }
    if clipping_container_is_intentional_viewport(el) {
        return vec![];
    }
    for child in descendants(el) {
        let child_style = doc.get_style(&child);
        let pos = child_style.get_property_value("position");
        if pos == "absolute" || pos == "fixed" {
            if is_positioned_decorative(child) {
                continue;
            }
            if !positioned_style_implies_escape(&child_style) {
                continue;
            }
            let cls = class_list(&el).split_whitespace().next().unwrap_or("");
            let ident = if cls.is_empty() {
                format!("<{}>", tag_lower(el))
            } else {
                format!("<{}> \"{}\"", tag_lower(el), cls)
            };
            return vec![Finding {
                id: "clipped-overflow-container",
                snippet: format!("{ident} clips a positioned child"),
            }];
        }
    }
    vec![]
}

// ─── checkElementQuality / checkQuality (checks.mjs ~1349-1660, rect=None) ──

const FLUSH_SKIP_TAGS: &[&str] = &[
    "html", "body", "main", "header", "footer", "nav", "article", "aside", "button", "a",
    "label", "summary", "code", "pre", "input", "textarea", "select", "form", "figure", "table",
    "tbody", "thead", "tr", "td", "th",
];

fn has_visible_background_boundary(style: &crate::wf_port::r09::ComputedStyle, el: ElementRef, doc: &StaticDocument) -> bool {
    let bg = style.get_property_value("background-color");
    if css_color_is_transparent(&bg) {
        return false;
    }
    let mut parent = parent_element(el);
    while let Some(p) = parent {
        let ps = doc.get_style(&p);
        let parent_bg = ps.get_property_value("background-color");
        if !css_color_is_transparent(&parent_bg) {
            return !colors_nearly_match(&bg, &parent_bg);
        }
        parent = parent_element(p);
    }
    true
}

/// Port of `checkQuality(opts)` with `opts.rect = null` (the static-adapter
/// path — see module doc for exactly which rect-gated branches that skips).
pub fn check_element_quality(el: ElementRef, doc: &StaticDocument, style: &crate::wf_port::r09::ComputedStyle, tag: &str) -> Vec<Finding> {
    let el_id = attr(&el, "id").unwrap_or("");
    if el_id.starts_with("claude-") || el_id.starts_with("cic-") {
        return vec![];
    }

    let direct = direct_text(el);
    let has_direct_text = el.children().any(|n| {
        n.value()
            .as_text()
            .map(|t| !t.trim().is_empty())
            .unwrap_or(false)
    });
    let _ = direct;
    let text_content_full = text_content(el);
    let text_len = text_content_full.trim().chars().count();
    let font_size = resolve_font_size_px(el, doc);
    let line_height_raw = style.get_property_value("line-height");
    let letter_spacing_raw = style.get_property_value("letter-spacing");
    let line_height_px = resolve_length_px(&line_height_raw, font_size);
    let letter_spacing_px = resolve_length_px(&letter_spacing_raw, font_size);

    let mut findings = Vec::new();

    // --- Flush against a visible boundary --- (rect-free)
    let upper_tag = tag.to_ascii_uppercase();
    let el_position = style.get_property_value("position");
    let children = children_elements(el);
    if !FLUSH_SKIP_TAGS.contains(&tag)
        && !has_direct_text
        && el_position != "fixed"
        && el_position != "absolute"
        && !children.is_empty()
    {
        let border_w = [
            leading_number(&style.get_property_value("border-top-width")).unwrap_or(0.0),
            leading_number(&style.get_property_value("border-right-width")).unwrap_or(0.0),
            leading_number(&style.get_property_value("border-bottom-width")).unwrap_or(0.0),
            leading_number(&style.get_property_value("border-left-width")).unwrap_or(0.0),
        ];
        let border_colors = [
            style.get_property_value("border-top-color"),
            style.get_property_value("border-right-color"),
            style.get_property_value("border-bottom-color"),
            style.get_property_value("border-left-color"),
        ];
        let border_visible = [
            border_w[0] > 0.0 && !css_color_is_transparent(&border_colors[0]),
            border_w[1] > 0.0 && !css_color_is_transparent(&border_colors[1]),
            border_w[2] > 0.0 && !css_color_is_transparent(&border_colors[2]),
            border_w[3] > 0.0 && !css_color_is_transparent(&border_colors[3]),
        ];
        let mut outline_w = leading_number(&style.get_property_value("outline-width")).unwrap_or(0.0);
        let mut outline_style_val = style.get_property_value("outline-style");
        let mut outline_color_val = style.get_property_value("outline-color");
        let outline_shorthand = style.get_property_value("outline");
        if outline_w == 0.0 && !outline_shorthand.is_empty() {
            if let Some(w) = outline_width_re().captures(&outline_shorthand) {
                outline_w = w[1].parse().unwrap_or(0.0);
            }
            if outline_style_val.is_empty() && outline_style_word_re().is_match(&outline_shorthand) {
                outline_style_val = "solid".to_string();
            }
            if outline_color_val.is_empty() {
                if let Some(c) = outline_color_re().captures(&outline_shorthand) {
                    outline_color_val = c[1].to_string();
                }
            }
        }
        let outline_visible = outline_w > 0.0
            && !css_color_is_transparent(&outline_color_val)
            && !outline_style_val.is_empty()
            && outline_style_val != "none";
        let bg_visible = has_visible_background_boundary(style, el, doc);
        let any_visible = border_visible.iter().any(|v| *v) || outline_visible || bg_visible;

        if any_visible {
            let pad = [
                resolve_length_px(&style.get_property_value("padding-top"), font_size).unwrap_or(0.0),
                resolve_length_px(&style.get_property_value("padding-right"), font_size).unwrap_or(0.0),
                resolve_length_px(&style.get_property_value("padding-bottom"), font_size).unwrap_or(0.0),
                resolve_length_px(&style.get_property_value("padding-left"), font_size).unwrap_or(0.0),
            ];
            const CHILD_INSULATE_THRESHOLD: f64 = 4.0;
            let mut children_insulate = [false; 4]; // top,right,bottom,left
            for child in &children {
                let cs = doc.get_style(child);
                let cp = [
                    resolve_length_px(&cs.get_property_value("padding-top"), font_size).unwrap_or(0.0),
                    resolve_length_px(&cs.get_property_value("padding-right"), font_size).unwrap_or(0.0),
                    resolve_length_px(&cs.get_property_value("padding-bottom"), font_size).unwrap_or(0.0),
                    resolve_length_px(&cs.get_property_value("padding-left"), font_size).unwrap_or(0.0),
                ];
                let cm = [
                    resolve_length_px(&cs.get_property_value("margin-top"), font_size).unwrap_or(0.0),
                    resolve_length_px(&cs.get_property_value("margin-right"), font_size).unwrap_or(0.0),
                    resolve_length_px(&cs.get_property_value("margin-bottom"), font_size).unwrap_or(0.0),
                    resolve_length_px(&cs.get_property_value("margin-left"), font_size).unwrap_or(0.0),
                ];
                for i in 0..4 {
                    if cp[i] >= CHILD_INSULATE_THRESHOLD || cm[i] >= CHILD_INSULATE_THRESHOLD {
                        children_insulate[i] = true;
                    }
                }
            }

            // textFlush is null without a rect (matches `rect ?
            // textDescendantsFlushSides(...) : null`), so the `!textFlush
            // || textFlush[side]` gate always passes — same as the JS
            // static path.
            let sides = ["top", "right", "bottom", "left"];
            let mut flush_sides = Vec::new();
            for i in 0..4 {
                let side_bounded = border_visible[i] || outline_visible || bg_visible;
                if side_bounded && pad[i] <= 2.0 && !children_insulate[i] {
                    flush_sides.push(sides[i]);
                }
            }

            if !flush_sides.is_empty() {
                let has_text_child = children.iter().any(|c| collapse_ws(&text_content(*c)).chars().count() > 4);
                if has_text_child {
                    let cls = class_list(&el).split_whitespace().next().unwrap_or("");
                    let mut boundary_parts = Vec::new();
                    let border_sides_visible: Vec<&str> = sides
                        .iter()
                        .zip(border_visible.iter())
                        .filter(|(_, v)| **v)
                        .map(|(s, _)| *s)
                        .collect();
                    if border_sides_visible.len() == 4 {
                        boundary_parts.push("border".to_string());
                    } else if !border_sides_visible.is_empty() {
                        boundary_parts.push(format!("border-{}", border_sides_visible.join("/")));
                    }
                    if outline_visible {
                        boundary_parts.push("outline".to_string());
                    }
                    if bg_visible {
                        boundary_parts.push("bg".to_string());
                    }
                    let sides_label = if flush_sides.len() == 4 {
                        "all sides".to_string()
                    } else {
                        flush_sides.join("/")
                    };
                    let ident = if cls.is_empty() {
                        format!("<{}>", tag)
                    } else {
                        format!("<{}> \"{}\"", tag, cls)
                    };
                    findings.push(Finding {
                        id: "cramped-padding",
                        snippet: format!("{ident}: children flush against {} on {sides_label} (no inset)", boundary_parts.join("+")),
                    });
                }
            }
        }
    }

    // --- Tight line height ---
    if has_direct_text && text_len > 50 && !matches!(tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
        if let Some(lh) = line_height_px {
            if font_size > 0.0 {
                let ratio = lh / font_size;
                if ratio > 0.0 && ratio < 1.3 {
                    findings.push(Finding {
                        id: "tight-leading",
                        snippet: format!("line-height {ratio:.2}x (need >=1.3)"),
                    });
                }
            }
        }
    }

    // --- Justified text without hyphens ---
    if has_direct_text && style.get_property_value("text-align") == "justify" {
        let hyphens = {
            let h = style.get_property_value("hyphens");
            if h.is_empty() { style.get_property_value("-webkit-hyphens") } else { h }
        };
        if hyphens != "auto" {
            findings.push(Finding {
                id: "justified-text",
                snippet: "text-align: justify without hyphens: auto".to_string(),
            });
        }
    }

    // --- Tiny body text ---
    if has_direct_text && text_len > 20 && font_size < 12.0 {
        let skip_tags = ["sub", "sup", "code", "kbd", "samp", "var", "caption", "figcaption"];
        let in_ui_context = closest_where(el, |e| is_ui_context_tag(*e)).is_some();
        let is_uppercase = style.get_property_value("text-transform") == "uppercase";
        if !skip_tags.contains(&tag) && !in_ui_context && !is_uppercase {
            findings.push(Finding {
                id: "tiny-text",
                snippet: format!("{font_size}px body text"),
            });
        }
    }

    // --- All-caps body text ---
    if has_direct_text && text_len > 30 && style.get_property_value("text-transform") == "uppercase" {
        if !matches!(tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
            findings.push(Finding {
                id: "all-caps-body",
                snippet: format!("text-transform: uppercase on {text_len} chars of body text"),
            });
        }
    }

    // --- Wide letter spacing on body text ---
    if has_direct_text && text_len > 20 && style.get_property_value("text-transform") != "uppercase" {
        if let Some(ls) = letter_spacing_px {
            if ls > 0.0 && font_size > 0.0 {
                let tracking_em = ls / font_size;
                if tracking_em > 0.05 {
                    findings.push(Finding {
                        id: "wide-tracking",
                        snippet: format!("letter-spacing: {tracking_em:.2}em on body text"),
                    });
                }
            }
        }
    }

    // --- Crushed letter spacing ---
    if has_direct_text && text_len > 20 && font_size > 0.0 {
        if let Some(ls) = letter_spacing_px {
            if ls < 0.0 {
                let tracking_em = ls / font_size;
                if tracking_em <= -0.05 {
                    let excerpt: String = collapse_ws(&text_content_full).chars().take(40).collect();
                    findings.push(Finding {
                        id: "extreme-negative-tracking",
                        snippet: format!("letter-spacing: {tracking_em:.2}em — \"{excerpt}\""),
                    });
                }
            }
        }
    }

    findings
}

fn is_ui_context_tag(el: ElementRef) -> bool {
    let tag = tag_lower(el);
    if matches!(tag.as_str(), "button" | "a" | "label" | "summary" | "pre" | "nav" | "footer") {
        return true;
    }
    if attr(&el, "aria-hidden") == Some("true") {
        return true;
    }
    if matches!(attr(&el, "role").unwrap_or(""), "button" | "link" | "tab" | "menuitem" | "option") {
        return true;
    }
    let cls = class_list(&el).to_ascii_lowercase();
    [
        "badge", "caption", "chip", "code", "console", "diff", "label", "meta", "mock", "pill",
        "preview", "tag", "terminal", "writes",
    ]
    .iter()
    .any(|k| cls.contains(k))
}

fn outline_width_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(\d+(?:\.\d+)?)\s*px").unwrap())
}

fn outline_style_word_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)\b(solid|dashed|dotted|double|groove|ridge|inset|outset)\b").unwrap()
    })
}

fn outline_color_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(r"(?i)(rgba?\([^)]+\)|#[0-9a-fA-F]{3,8}|[a-zA-Z]+)\s*$").unwrap()
    })
}

// ─── checkPageQualityFromDoc (checks.mjs ~1678-1690) ───────────────────────

pub fn check_page_quality_from_doc(doc: &StaticDocument) -> Vec<Finding> {
    let sel = scraper::Selector::parse("h1, h2, h3, h4, h5, h6").expect("selector");
    let mut findings = Vec::new();
    let mut prev_level = 0u32;
    let mut prev_text = String::new();
    for h in doc.html.select(&sel) {
        let tag = tag_lower(h);
        let level: u32 = tag[1..2].parse().unwrap_or(0);
        let text: String = collapse_ws(&text_content(h)).chars().take(60).collect();
        if prev_level > 0 && level > prev_level + 1 {
            findings.push(Finding {
                id: "skipped-heading",
                snippet: format!(
                    "<h{prev_level}> \"{prev_text}\" followed by <h{level}> \"{text}\" (missing h{})",
                    prev_level + 1
                ),
            });
        }
        prev_level = level;
        prev_text = text;
    }
    findings
}

// ─── Repeated section kickers (checks.mjs ~1041-1121, 1881-1889) ──────────

fn is_repeated_kicker_card_context(heading: ElementRef, kicker: ElementRef) -> bool {
    let card_ctx = |e: &ElementRef| {
        let tag = tag_lower(*e);
        matches!(tag.as_str(), "article" | "button" | "a" | "li")
            || matches!(attr(e, "role").unwrap_or(""), "listitem" | "option")
    };
    match closest_where(heading, card_ctx) {
        Some(item) => contains(item, kicker) || item.id() == kicker.id(),
        None => false,
    }
}

fn kicker_skip(e: &ElementRef) -> bool {
    let tag = tag_lower(*e);
    if matches!(tag.as_str(), "nav" | "form" | "table" | "thead" | "tbody" | "tfoot" | "figure" | "figcaption" | "ol" | "ul" | "li") {
        return true;
    }
    if attr(e, "role") == Some("navigation") {
        return true;
    }
    if attr(e, "aria-hidden") == Some("true") {
        return true;
    }
    let cls = class_list(e).to_ascii_lowercase();
    let aria = attr(e, "aria-label").unwrap_or("").to_ascii_lowercase();
    cls.contains("breadcrumb") || aria.contains("breadcrumb") || attr(e, "data-impeccable-allow-kickers").is_some()
}

fn is_repeated_kicker_candidate(
    heading_tag: &str,
    heading_text: &str,
    heading_font_size: f64,
    kicker_tag: &str,
    kicker_text: &str,
    kicker_text_transform: &str,
    kicker_font_size: f64,
    kicker_letter_spacing: f64,
) -> bool {
    if !matches!(heading_tag, "h2" | "h3" | "h4") {
        return false;
    }
    if heading_text.chars().count() < 3 {
        return false;
    }
    let trimmed = heading_text.trim_matches('"').trim();
    if slash_word_re().is_match(trimmed) {
        return false;
    }
    if !(heading_font_size >= 20.0) {
        return false;
    }
    if matches!(kicker_tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
        return false;
    }
    if !matches!(kicker_tag, "p" | "span" | "div" | "small") {
        return false;
    }
    let len = kicker_text.chars().count();
    if kicker_text.is_empty() || len < 2 || len > 34 {
        return false;
    }
    if step_re().is_match(kicker_text) || digit1_2_re().is_match(kicker_text) {
        return false;
    }
    let is_uppercased = kicker_text_transform == "uppercase"
        || (kicker_text.chars().any(|c| c.is_ascii_uppercase()) && !kicker_text.chars().any(|c| c.is_ascii_lowercase()));
    if !is_uppercased {
        return false;
    }
    if !(kicker_font_size > 0.0 && kicker_font_size <= 14.0) {
        return false;
    }
    let min_tracked_spacing = (kicker_font_size * 0.08).max(1.0);
    kicker_letter_spacing >= min_tracked_spacing
}

fn slash_word_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?i)^/[\w-]+").unwrap())
}
fn step_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?i)^step\s*\d+").unwrap())
}
fn digit1_2_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"^\d{1,2}$").unwrap())
}

fn clean_inline_text(el: ElementRef) -> String {
    collapse_ws(&direct_text(el))
}

/// Port of `collectRepeatedSectionKickerCandidates` + `checkRepeatedSectionKickersFromDoc`.
pub fn check_repeated_section_kickers_from_doc(doc: &StaticDocument) -> Vec<Finding> {
    let sel = scraper::Selector::parse("h2, h3, h4").expect("selector");
    let mut candidates = Vec::new();
    for heading in doc.html.select(&sel) {
        if closest_where(heading, kicker_skip).is_some() {
            continue;
        }
        let Some(kicker) = previous_element_sibling(heading) else { continue };
        if closest_where(kicker, kicker_skip).is_some() {
            continue;
        }
        if is_repeated_kicker_card_context(heading, kicker) {
            continue;
        }

        let heading_style = doc.get_style(&heading);
        let kicker_style = doc.get_style(&kicker);
        let heading_text = collapse_ws(&text_content(heading));
        let kicker_text_raw = clean_inline_text(kicker);
        let kicker_text = if kicker_text_raw.is_empty() {
            collapse_ws(&text_content(kicker))
        } else {
            kicker_text_raw
        };
        let heading_font_size = resolve_length_px(&heading_style.get_property_value("font-size"), 16.0)
            .or_else(|| leading_number(&heading_style.get_property_value("font-size")))
            .unwrap_or(0.0);
        let kicker_font_size = resolve_length_px(&kicker_style.get_property_value("font-size"), 16.0)
            .or_else(|| leading_number(&kicker_style.get_property_value("font-size")))
            .unwrap_or(0.0);
        let kicker_letter_spacing =
            resolve_length_px(&kicker_style.get_property_value("letter-spacing"), kicker_font_size).unwrap_or(0.0);

        let heading_tag = tag_lower(heading);
        let kicker_tag = tag_lower(kicker);
        if !is_repeated_kicker_candidate(
            &heading_tag,
            &heading_text,
            heading_font_size,
            &kicker_tag,
            &kicker_text,
            &kicker_style.get_property_value("text-transform"),
            kicker_font_size,
            kicker_letter_spacing,
        ) {
            continue;
        }

        let heading_snip: String = heading_text.trim_matches('"').chars().take(60).collect();
        let kicker_snip: String = kicker_text.chars().take(40).collect();
        candidates.push(KickerCandidate {
            kicker_text: kicker_snip,
            heading_tag,
            heading_text: heading_snip,
        });
    }
    check_repeated_section_kickers(&candidates, 3)
}

// ─── checkPageLayout / checkCreamPalette (checks.mjs ~2092-2234) ──────────

fn is_card_like(el: ElementRef, doc: &StaticDocument) -> bool {
    let tag = tag_lower(el);
    if crate::p8_designer::constants::SAFE_TAGS.contains(tag.as_str())
        || matches!(tag.as_str(), "input" | "select" | "textarea" | "img" | "video" | "canvas" | "picture")
    {
        return false;
    }
    let style = doc.get_style(&el);
    let raw_style = attr(&el, "style").unwrap_or("");
    let cls = class_list(&el);

    let box_shadow = style.get_property_value("box-shadow");
    let has_shadow = (!box_shadow.is_empty() && box_shadow != "none")
        || shadow_class_re().is_match(cls)
        || raw_style.to_ascii_lowercase().contains("box-shadow");
    let has_border = border_class_re().is_match(cls);
    let width_px = leading_number(&style.get_property_value("width")).unwrap_or(0.0);
    let has_radius = resolve_border_radius_px(&style, width_px) > 0.0
        || rounded_class_re().is_match(cls)
        || raw_style.to_ascii_lowercase().contains("border-radius");
    let has_bg = bg_class_re().is_match(cls) || bg_decl_re().is_match(raw_style);

    is_card_like_from_props(has_shadow, has_border, has_radius, has_bg)
}

fn shadow_class_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\bshadow(?:-sm|-md|-lg|-xl|-2xl)?\b").unwrap())
}
fn border_class_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\bborder\b").unwrap())
}
fn rounded_class_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\brounded(?:-sm|-md|-lg|-xl|-2xl|-full)?\b").unwrap())
}
fn bg_class_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\bbg-(?:white|gray-\d+|slate-\d+)\b").unwrap())
}
fn bg_decl_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?i)background(?:-color)?\s*:\s*(?!transparent)").unwrap())
}
fn absolute_fixed_class_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"\b(?:absolute|fixed)\b").unwrap())
}
fn position_abs_fixed_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?i)position\s*:\s*(?:absolute|fixed)").unwrap())
}
fn dropdown_like_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?i)\b(?:dropdown|popover|tooltip|menu|modal|dialog)\b").unwrap())
}

/// Port of `checkPageLayout(doc, win)`.
pub fn check_page_layout(doc: &StaticDocument) -> Vec<Finding> {
    let all_sel = scraper::Selector::parse("*").expect("selector");
    let mut flagged: Vec<ElementRef> = Vec::new();
    for el in doc.html.select(&all_sel) {
        if !is_card_like(el, doc) {
            continue;
        }
        if flagged.iter().any(|f| f.id() == el.id()) {
            continue;
        }
        let tag = tag_lower(el);
        let cls = class_list(&el);
        let raw_style = attr(&el, "style").unwrap_or("");
        if matches!(tag.as_str(), "pre" | "code") {
            continue;
        }
        if absolute_fixed_class_re().is_match(cls) || position_abs_fixed_re().is_match(raw_style) {
            continue;
        }
        if collapse_ws(&text_content(el)).chars().count() < 10 {
            continue;
        }
        if dropdown_like_re().is_match(cls) {
            continue;
        }
        let mut parent = parent_element(el);
        while let Some(p) = parent {
            if is_card_like(p, doc) {
                flagged.push(el);
                break;
            }
            parent = parent_element(p);
        }
    }

    let mut findings = Vec::new();
    for el in &flagged {
        let is_ancestor = flagged.iter().any(|other| other.id() != el.id() && contains(*other, *el));
        if !is_ancestor {
            findings.push(Finding {
                id: "nested-cards",
                snippet: format!("Card inside card ({})", tag_lower(*el)),
            });
        }
    }
    findings
}

/// Port of `checkCreamPalette(doc, win)`.
pub fn check_cream_palette(doc: &StaticDocument) -> Vec<Finding> {
    let body_sel = scraper::Selector::parse("body").expect("selector");
    let Some(body) = doc.html.select(&body_sel).next() else { return vec![] };
    let html_el = doc.html.root_element();

    let body_style = doc.get_style(&body);
    let mut bg = read_own_background_color(body, &body_style.get_property_value("background-color"));
    if bg.as_ref().map(|c| c.a == 0.0).unwrap_or(true) {
        let html_style = doc.get_style(&html_el);
        bg = read_own_background_color(html_el, &html_style.get_property_value("background-color"));
    }
    if let Some(rgb) = &bg {
        if crate::l6_designer_checks::pure_checks::is_cream_color(rgb.r, rgb.g, rgb.b) {
            return vec![Finding {
                id: "cream-palette",
                snippet: format!("cream/beige page background rgb({}, {}, {})", rgb.r as i64, rgb.g as i64, rgb.b as i64),
            }];
        }
    }

    for el in [body, html_el] {
        if let Some(tok) = crate::l6_designer_checks::pure_checks::cream_from_class_list(attr(&el, "class")) {
            return vec![Finding {
                id: "cream-palette",
                snippet: format!("cream/beige page background (Tailwind {tok})"),
            }];
        }
    }
    vec![]
}

