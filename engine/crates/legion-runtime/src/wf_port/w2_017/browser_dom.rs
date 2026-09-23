//! Pure helpers ported from `live-browser-dom.js`.
//!
//! Only the DOM-independent pieces are ported: `desc`, `rectIsUsableAnchor`
//! and `cssId`. Everything else in that file (`own`, `pickable`,
//! `makeFrozenAnchor`, `liveUiRoot`, `uiAppend*`, `activeElementDeep`,
//! `defangOutsideHandlers`) reads or mutates a live DOM and has no Rust
//! equivalent; it stays as in-page JS.

/// Mirrors the shape `desc(el)` reads off a DOM element: tag name, id, and
/// class list, in the order JS would read `el.tagName` / `el.id` /
/// `el.classList`.
#[derive(Debug, Clone, Default)]
pub struct ElementShape {
    pub tag_name: String,
    pub id: String,
    pub class_list: Vec<String>,
}

/// Port of:
/// ```js
/// function desc(el) {
///   if (!el) return '';
///   let s = el.tagName.toLowerCase();
///   if (el.id) s += '#' + el.id;
///   else if (el.classList.length) s += '.' + [...el.classList].slice(0, 2).join('.');
///   return s;
/// }
/// ```
/// `el` being null/undefined is modeled as `Option<&ElementShape>`.
pub fn desc(el: Option<&ElementShape>) -> String {
    let Some(el) = el else { return String::new() };
    let mut s = el.tag_name.to_lowercase();
    if !el.id.is_empty() {
        s.push('#');
        s.push_str(&el.id);
    } else if !el.class_list.is_empty() {
        s.push('.');
        let joined = el
            .class_list
            .iter()
            .take(2)
            .cloned()
            .collect::<Vec<_>>()
            .join(".");
        s.push_str(&joined);
    }
    s
}

/// Mirrors the fields `rectIsUsableAnchor` and `makeFrozenAnchor` read off
/// `DOMRect` (`getBoundingClientRect()`).
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Rect {
    pub width: f64,
    pub height: f64,
}

/// Port of:
/// ```js
/// function rectIsUsableAnchor(rect) {
///   return !!rect && rect.width > 0.5 && rect.height > 0.5;
/// }
/// ```
pub fn rect_is_usable_anchor(rect: Option<&Rect>) -> bool {
    match rect {
        Some(r) => r.width > 0.5 && r.height > 0.5,
        None => false,
    }
}

/// Port of the `css?.escape` fallback branch of:
/// ```js
/// function cssId(id) {
///   if (css?.escape) return css.escape(id);
///   return String(id).replace(/([ !"#$%&'()*+,./:;<=>?@[\\\]^`{|}~])/g, '\\$1');
/// }
/// ```
/// `CSS.escape` itself is a browser API; when a live `CSS.escape` is not
/// available (the common case outside a real page), this reproduces the
/// script's own fallback regex exactly, byte for byte, one escaped
/// character at a time.
pub fn css_id_fallback(id: &str) -> String {
    const SPECIAL: &[char] = &[
        ' ', '!', '"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '.', '/', ':', ';',
        '<', '=', '>', '?', '@', '[', '\\', ']', '^', '`', '{', '|', '}', '~',
    ];
    let mut out = String::with_capacity(id.len() * 2);
    for ch in id.chars() {
        if SPECIAL.contains(&ch) {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desc_none_is_empty() {
        assert_eq!(desc(None), "");
    }

    #[test]
    fn desc_prefers_id_over_class() {
        let el = ElementShape {
            tag_name: "DIV".into(),
            id: "hero".into(),
            class_list: vec!["a".into(), "b".into()],
        };
        assert_eq!(desc(Some(&el)), "div#hero");
    }

    #[test]
    fn desc_falls_back_to_first_two_classes() {
        let el = ElementShape {
            tag_name: "Span".into(),
            id: String::new(),
            class_list: vec!["a".into(), "b".into(), "c".into()],
        };
        assert_eq!(desc(Some(&el)), "span.a.b");
    }

    #[test]
    fn desc_no_id_no_class() {
        let el = ElementShape {
            tag_name: "P".into(),
            id: String::new(),
            class_list: vec![],
        };
        assert_eq!(desc(Some(&el)), "p");
    }

    #[test]
    fn rect_usable_anchor_boundaries() {
        assert!(!rect_is_usable_anchor(None));
        assert!(!rect_is_usable_anchor(Some(&Rect {
            width: 0.5,
            height: 10.0
        })));
        assert!(!rect_is_usable_anchor(Some(&Rect {
            width: 10.0,
            height: 0.5
        })));
        assert!(rect_is_usable_anchor(Some(&Rect {
            width: 0.51,
            height: 0.51
        })));
    }

    #[test]
    fn css_id_fallback_escapes_special_chars() {
        assert_eq!(css_id_fallback("a b"), "a\\ b");
        assert_eq!(css_id_fallback("foo#bar"), "foo\\#bar");
        assert_eq!(css_id_fallback("plain"), "plain");
        assert_eq!(css_id_fallback("a.b:c"), "a\\.b\\:c");
    }
}
