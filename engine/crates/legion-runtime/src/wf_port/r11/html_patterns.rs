//! Port of `skills/designer/engine/scripts/detector/rules/checks.mjs`'s
//! `checkHtmlPatterns(html)` (source lines ~446-616) — pure regex/string
//! scanning over the raw HTML source, no DOM needed.
//!
//! One adaptation: the JS `pxVals` extraction inside the dark-glow branch
//! uses a negative lookbehind (`(?<![.\d])\b(0)\b(?![.\d])`), which the
//! `regex` crate (no lookaround) cannot express. Ported as a small
//! hand-written scanner (`extract_shadow_px_values`) that walks the same
//! `\d+px` / bare-`0` tokens by hand instead of translating the lookaround
//! literally — same effective behavior (a bare `0` token not preceded or
//! followed by a digit/dot).

use std::sync::OnceLock;

use regex::Regex;

use crate::l6_designer_checks::pure_checks::Finding;

fn purple_hex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)#(?:7c3aed|8b5cf6|a855f7|9333ea|7e22ce|6d28d9|6366f1|764ba2|667eea)\b").unwrap()
    })
}

fn purple_text_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?is)(?:(?:^|;)\s*color\s*:\s*(?:.*?)(?:#(?:7c3aed|8b5cf6|a855f7|9333ea|7e22ce|6d28d9))|gradient.*?#(?:7c3aed|8b5cf6|a855f7|764ba2|667eea))",
        )
        .unwrap()
    })
}

fn gradient_clip_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)(?:-webkit-)?background-clip\s*:\s*text").unwrap())
}

fn gradient_word_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)gradient").unwrap())
}

fn bg_clip_text_tw_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bbg-clip-text\b").unwrap())
}

fn bg_gradient_to_tw_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\bbg-gradient-to-").unwrap())
}

fn spacing_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:padding|margin)(?:-(?:top|right|bottom|left))?\s*:\s*(\d+)px").unwrap()
    })
}

fn gap_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)gap\s*:\s*(\d+)px").unwrap())
}

fn tw_space_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:p|px|py|pt|pb|pl|pr|m|mx|my|mt|mb|ml|mr|gap)-(\d+)\b").unwrap()
    })
}

fn rem_spacing_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:padding|margin)(?:-(?:top|right|bottom|left))?\s*:\s*([\d.]+)rem").unwrap()
    })
}

fn bounce_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)animation(?:-name)?\s*:\s*([^;{}]*(?:bounce|elastic|wobble|jiggle|spring)[^;{}]*)")
            .unwrap()
    })
}

fn bounce_token_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)bounce|elastic|wobble|jiggle|spring").unwrap())
}

fn bezier_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"cubic-bezier\(\s*([\d.-]+)\s*,\s*([\d.-]+)\s*,\s*([\d.-]+)\s*,\s*([\d.-]+)\s*\)").unwrap()
    })
}

fn trans_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)transition(?:-property)?\s*:\s*([^;{}]+)").unwrap())
}

fn trans_all_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\ball\b").unwrap())
}

fn trans_prop_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\b(?:(?:max|min)-)?(?:width|height)\b|\bpadding(?:-(?:top|right|bottom|left))?\b|\bmargin(?:-(?:top|right|bottom|left))?\b")
            .unwrap()
    })
}

fn dark_bg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)background(?:-color)?\s*:\s*(?:#(?:0[0-9a-f]|1[0-9a-f]|2[0-3])[0-9a-f]{4}\b|#(?:0|1)[0-9a-f]{2}\b|rgb\(\s*(\d{1,2})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\))")
            .unwrap()
    })
}

fn tw_dark_bg_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)\bbg-(?:gray|slate|zinc|neutral|stone)-(?:9\d{2}|800)\b").unwrap()
    })
}

fn shadow_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)box-shadow\s*:\s*([^;{}]+)").unwrap())
}

fn shadow_color_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"rgba?\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)").unwrap())
}

fn repeating_gradient_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)repeating-(?:linear|radial|conic)-gradient\s*\(").unwrap())
}

fn script_style_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?is)<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>").unwrap()
    })
}

fn any_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"<[^>]+>").unwrap())
}

fn theater_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\b(\w+)\s+theater\b").unwrap())
}

fn img_hover_css_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)\bimg\b[^,{}]*:hover\b[^{}]*\{[^}]*\btransform\s*:\s*(?:scale|rotate|translate|matrix|skew)"#)
            .unwrap()
    })
}

fn img_tag_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)<img\b[^>]*\bclass\s*=\s*"([^"]*)""#).unwrap())
}

fn img_hover_class_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\bhover:(?:scale|rotate|translate|skew)-").unwrap())
}

/// Port of the dark-glow branch's `pxVals` extraction:
/// `/(\d+)px|(?<![.\d])\b(0)\b(?![.\d])/g`. The regex crate has no
/// lookaround, so this hand-scans for `\d+px` tokens and bare `0` tokens
/// not adjacent to a digit or `.` on either side.
fn extract_shadow_px_values(val: &str) -> Vec<f64> {
    let bytes = val.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_digit() {
            let start = i;
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'p' && bytes.get(j + 1) == Some(&b'x') {
                if let Ok(n) = val[start..j].parse::<f64>() {
                    out.push(n);
                }
                i = j + 2;
                continue;
            }
            // Bare digit run: only a lone "0" counts, and only when not
            // adjacent to a digit/dot on either side (word-boundary + the
            // negative lookaround in the source).
            let is_zero_token = &val[start..j] == "0";
            let prev_ok = start == 0
                || {
                    let p = bytes[start - 1];
                    !(p.is_ascii_digit() || p == b'.')
                };
            let next_ok = j >= bytes.len() || {
                let n = bytes[j];
                !(n.is_ascii_digit() || n == b'.')
            };
            if is_zero_token && prev_ok && next_ok {
                out.push(0.0);
            }
            i = j;
            continue;
        }
        i += 1;
    }
    out
}

/// Port of `checkHtmlPatterns(html)`.
pub fn check_html_patterns(html: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    // --- Color ---
    if purple_hex_re().is_match(html) && purple_text_re().is_match(html) {
        findings.push(Finding {
            id: "ai-color-palette",
            snippet: "Purple/violet accent colors detected".to_string(),
        });
    }

    let mut found_gradient_text = false;
    for gm in gradient_clip_re().find_iter(html) {
        let start = gm.start().saturating_sub(200);
        let end = (gm.end() + 200).min(html.len());
        // Clamp to char boundaries.
        let end = html
            .char_indices()
            .map(|(i, c)| i + c.len_utf8())
            .find(|&i| i >= end)
            .unwrap_or(html.len());
        let start = html.char_indices().map(|(i, _)| i).filter(|&i| i <= start).last().unwrap_or(0);
        let context = &html[start..end];
        if gradient_word_re().is_match(context) {
            findings.push(Finding {
                id: "gradient-text",
                snippet: "background-clip: text + gradient".to_string(),
            });
            found_gradient_text = true;
            break;
        }
    }
    let _ = found_gradient_text;
    if bg_clip_text_tw_re().is_match(html) && bg_gradient_to_tw_re().is_match(html) {
        findings.push(Finding {
            id: "gradient-text",
            snippet: "bg-clip-text + bg-gradient (Tailwind)".to_string(),
        });
    }

    // --- Layout: monotonous spacing ---
    let mut spacing_values: Vec<i64> = Vec::new();
    for cap in spacing_re().captures_iter(html) {
        if let Ok(v) = cap[1].parse::<i64>() {
            if v > 0 && v < 200 {
                spacing_values.push(v);
            }
        }
    }
    for cap in gap_re().captures_iter(html) {
        if let Ok(v) = cap[1].parse::<i64>() {
            spacing_values.push(v);
        }
    }
    for cap in tw_space_re().captures_iter(html) {
        if let Ok(v) = cap[1].parse::<i64>() {
            spacing_values.push(v * 4);
        }
    }
    for cap in rem_spacing_re().captures_iter(html) {
        if let Ok(v) = cap[1].parse::<f64>() {
            let v = (v * 16.0).round() as i64;
            if v > 0 && v < 200 {
                spacing_values.push(v);
            }
        }
    }
    let rounded_spacing: Vec<i64> = spacing_values.iter().map(|v| ((*v as f64) / 4.0).round() as i64 * 4).collect();
    if rounded_spacing.len() >= 10 {
        use std::collections::HashMap;
        let mut counts: HashMap<i64, usize> = HashMap::new();
        for v in &rounded_spacing {
            *counts.entry(*v).or_insert(0) += 1;
        }
        let max_count = counts.values().copied().max().unwrap_or(0);
        let dominant_pct = max_count as f64 / rounded_spacing.len() as f64;
        let mut unique: Vec<i64> = rounded_spacing.iter().copied().filter(|v| *v > 0).collect();
        unique.sort_unstable();
        unique.dedup();
        if dominant_pct > 0.6 && unique.len() <= 3 {
            // Object.entries(counts).sort by count desc, take first key —
            // ties broken by first-insertion order in JS; HashMap iteration
            // order differs, so break ties by the smallest value (stable,
            // deterministic) to match "first seen" as closely as a hash
            // map allows.
            let mut entries: Vec<(i64, usize)> = counts.into_iter().collect();
            entries.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
            let dominant = entries[0].0;
            findings.push(Finding {
                id: "monotonous-spacing",
                snippet: format!(
                    "~{}px used {}/{} times ({}%)",
                    dominant,
                    max_count,
                    rounded_spacing.len(),
                    (dominant_pct * 100.0).round() as i64,
                ),
            });
        }
    }

    // --- Motion: bounce/elastic animation names ---
    if let Some(bm) = bounce_re().captures(html) {
        let group = &bm[1];
        let token = group
            .split(|c: char| c == ',' || c.is_whitespace())
            .find(|part| bounce_token_re().is_match(part));
        findings.push(Finding {
            id: "bounce-easing",
            snippet: format!("animation: {}", token.unwrap_or(group.trim())),
        });
    }

    // Overshoot cubic-bezier
    for bm in bezier_re().captures_iter(html) {
        let y1: f64 = bm[2].parse().unwrap_or(0.0);
        let y2: f64 = bm[4].parse().unwrap_or(0.0);
        if !(-0.1..=1.1).contains(&y1) || !(-0.1..=1.1).contains(&y2) {
            findings.push(Finding {
                id: "bounce-easing",
                snippet: format!("cubic-bezier({}, {}, {}, {})", &bm[1], &bm[2], &bm[3], &bm[4]),
            });
            break;
        }
    }

    // Layout property transitions
    for tm in trans_re().captures_iter(html) {
        let val = tm[1].to_lowercase();
        if trans_all_re().is_match(&val) {
            continue;
        }
        let found: Vec<&str> = trans_prop_re().find_iter(&val).map(|m| m.as_str()).collect();
        if !found.is_empty() {
            // find_iter over the lowercased `val` gives lowercase matches
            // directly, same as JS's case-insensitive `.match()` output.
            findings.push(Finding {
                id: "layout-transition",
                snippet: format!("transition: {}", found.join(", ")),
            });
            break;
        }
    }

    // --- Dark glow ---
    if dark_bg_re().is_match(html) || tw_dark_bg_re().is_match(html) {
        for shm in shadow_re().captures_iter(html) {
            let val = &shm[1];
            let Some(cm) = shadow_color_re().captures(val) else { continue };
            let r: f64 = cm[1].parse().unwrap_or(0.0);
            let g: f64 = cm[2].parse().unwrap_or(0.0);
            let b: f64 = cm[3].parse().unwrap_or(0.0);
            let max = r.max(g).max(b);
            let min = r.min(g).min(b);
            if (max - min) < 30.0 {
                continue;
            }
            let px_vals = extract_shadow_px_values(val);
            if px_vals.len() >= 3 && px_vals[2] > 4.0 {
                findings.push(Finding {
                    id: "dark-glow",
                    snippet: format!("Colored glow (rgb({},{},{})) on dark page", r as i64, g as i64, b as i64),
                });
                break;
            }
        }
    }

    // --- Provider tells (gated) ---
    if repeating_gradient_re().is_match(html) {
        findings.push(Finding {
            id: "repeating-stripes-gradient",
            snippet: "repeating-gradient decorative stripes".to_string(),
        });
    }

    {
        let no_script_style = script_style_tag_re().replace_all(html, " ");
        let body_text = any_tag_re().replace_all(&no_script_style, " ");
        if let Some(tm) = theater_re().find(&body_text) {
            findings.push(Finding {
                id: "theater-slop-phrase",
                snippet: format!("\"{}\"", tm.as_str().trim()),
            });
        }
    }

    if img_hover_css_re().is_match(html) {
        findings.push(Finding {
            id: "image-hover-transform",
            snippet: "img:hover { transform } rule".to_string(),
        });
    }
    for im in img_tag_re().captures_iter(html) {
        if img_hover_class_re().is_match(&im[1]) {
            findings.push(Finding {
                id: "image-hover-transform",
                snippet: "Tailwind hover transform on <img>".to_string(),
            });
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(fs: &[Finding]) -> Vec<&'static str> {
        fs.iter().map(|f| f.id).collect()
    }

    #[test]
    fn purple_palette_needs_both_hex_and_color_usage() {
        let html = r#"<div style="color:#7c3aed">hi</div>"#;
        assert!(ids(&check_html_patterns(html)).contains(&"ai-color-palette"));
        assert!(!ids(&check_html_patterns("<div>#7c3aed mentioned only</div>")).contains(&"ai-color-palette"));
    }

    #[test]
    fn gradient_text_css_and_tailwind() {
        let css = "<style>.a{background-clip:text;background:linear-gradient(red,blue)}</style>";
        assert!(ids(&check_html_patterns(css)).contains(&"gradient-text"));
        let tw = r#"<div class="bg-clip-text bg-gradient-to-r"></div>"#;
        assert!(ids(&check_html_patterns(tw)).contains(&"gradient-text"));
    }

    #[test]
    fn monotonous_spacing_dominant_value() {
        let mut html = String::new();
        for _ in 0..12 {
            html.push_str("<div style=\"padding: 16px\"></div>");
        }
        let fs = check_html_patterns(&html);
        assert!(ids(&fs).contains(&"monotonous-spacing"));
    }

    #[test]
    fn bounce_easing_from_animation_name_and_bezier() {
        assert!(ids(&check_html_patterns("<style>a{animation-name: bounce-in}</style>")).contains(&"bounce-easing"));
        assert!(ids(&check_html_patterns("<style>a{transition-timing-function: cubic-bezier(0.68, -0.55, 0.27, 1.55)}</style>")).contains(&"bounce-easing"));
    }

    #[test]
    fn layout_transition_flags_width_not_all() {
        assert!(ids(&check_html_patterns("<style>a{transition-property: width, color}</style>")).contains(&"layout-transition"));
        assert!(!ids(&check_html_patterns("<style>a{transition: all 0.2s}</style>")).contains(&"layout-transition"));
    }

    #[test]
    fn dark_glow_needs_saturated_shadow_with_blur() {
        let html = "<style>a{background:#111111;box-shadow: 0 0 24px rgba(124,58,237,0.6)}</style>";
        assert!(ids(&check_html_patterns(html)).contains(&"dark-glow"));
    }

    #[test]
    fn repeating_stripes_gradient_flagged() {
        let html = "<style>a{background: repeating-linear-gradient(45deg, red, blue)}</style>";
        assert!(ids(&check_html_patterns(html)).contains(&"repeating-stripes-gradient"));
    }

    #[test]
    fn theater_slop_phrase_from_text_content() {
        let html = "<body><p>Welcome to the innovation theater</p></body>";
        assert!(ids(&check_html_patterns(html)).contains(&"theater-slop-phrase"));
    }

    #[test]
    fn image_hover_transform_css_and_tailwind() {
        assert!(ids(&check_html_patterns("<style>img:hover{transform: scale(1.1)}</style>")).contains(&"image-hover-transform"));
        assert!(ids(&check_html_patterns(r#"<img class="hover:scale-105">"#)).contains(&"image-hover-transform"));
    }

    #[test]
    fn extract_shadow_px_values_matches_lookaround_semantics() {
        // The three zeros inside `rgba(0,0,0,.5)` also match the bare-`0`
        // arm (each is flanked by `(`/`,`, neither digit nor dot) — same
        // behavior as the JS lookaround regex, which has no notion of
        // "inside a color function" either.
        assert_eq!(
            extract_shadow_px_values("0 0 24px rgba(0,0,0,.5)"),
            vec![0.0, 0.0, 24.0, 0.0, 0.0, 0.0]
        );
        // Matches JS's `/(\d+)px/` behavior on "1.5px": \d+ only grabs the
        // "5" between the "." and "px" (JS regex has no decimal-aware
        // px matcher either), so this yields 5.0 then 24.0, not 1.5.
        assert_eq!(extract_shadow_px_values("1.5px 0 24px"), vec![5.0, 0.0, 24.0]);
    }
}
