//! Port of `skills/designer/engine/scripts/detector/engines/static-html/detect-html.mjs`.
//!
//! `detectHtml` and almost everything it calls (`checkStaticPageTypography`,
//! `STATIC_ELEMENT_RULES`, and the whole `../../rules/checks.mjs` /
//! `./css-cascade.mjs` machinery it drives) require a parsed HTML DOM with
//! computed CSS styles (`htmlparser2` + `css-select` + `css-tree` +
//! `domutils`, wired through this chunk's own hand-rolled `StaticDocument`
//! / `buildStaticStyleMap` / `buildStaticWindow` "static browser"). None of
//! that HTML/CSS parsing and cascade-resolution engine is owned by this
//! chunk (`w2_013` owns only the five files listed in its assignment, and
//! `css-cascade.mjs`, `rules/checks.mjs`, `design-system.mjs`, etc. belong
//! to other chunks with no Rust port in this tree yet), so `detectHtml`
//! itself is not portable here — reimplementing it would mean silently
//! also reimplementing an HTML parser and CSS cascade engine, which is out
//! of scope for a faithful line-level port of this file.
//!
//! One piece of `detect-html.mjs` *is* pure, DOM-free, deterministic logic
//! taking only a string as input: `checkElementBrokenImage(el)`'s
//! `src`-attribute classification (the parts of the function that don't
//! depend on `el.getAttribute`/`el.attribs` resolution, i.e. everything
//! once the raw `src` value is in hand). That is ported below as
//! [`classify_img_src`], callable once a caller (elsewhere, DOM-aware) has
//! extracted an `<img>`'s `src` attribute value.

/// The single finding id this file's ported logic can produce, matching
/// `STATIC_ELEMENT_RULES`'s `{ id: 'broken-image', ... }` entry.
pub const BROKEN_IMAGE_ANTIPATTERN_ID: &str = "broken-image";

/// Port of `checkElementBrokenImage(el)`'s classification logic, given the
/// already-resolved `src` attribute value (`None` when the attribute is
/// absent, matching JS's `src === undefined || src === null`).
///
/// Returns `Some(snippet)` when the element should be flagged as
/// `broken-image`, `None` otherwise — mirroring the JS function's return
/// of `[{ id: 'broken-image', snippet }]` vs `[]`.
pub fn classify_img_src(src: Option<&str>) -> Option<String> {
    match src {
        None => Some("<img> with no src attribute".to_string()),
        Some(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() || trimmed == "#" {
                Some(format!(r#"<img src="{raw}">"#))
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_src_attribute_is_flagged() {
        assert_eq!(
            classify_img_src(None),
            Some("<img> with no src attribute".to_string())
        );
    }

    #[test]
    fn empty_src_is_flagged() {
        assert_eq!(classify_img_src(Some("")), Some(r#"<img src="">"#.to_string()));
    }

    #[test]
    fn whitespace_only_src_is_flagged() {
        assert_eq!(classify_img_src(Some("   ")), Some(r#"<img src="   ">"#.to_string()));
    }

    #[test]
    fn hash_placeholder_src_is_flagged() {
        assert_eq!(classify_img_src(Some("#")), Some(r##"<img src="#">"##.to_string()));
    }

    #[test]
    fn real_src_is_not_flagged() {
        assert_eq!(classify_img_src(Some("/logo.png")), None);
    }
}
