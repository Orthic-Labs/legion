//! Port of `skills/designer/engine/huashu/scripts/fetch_images.py` (packet
//! Q0, chunk `q_q0`).
//!
//! The legacy script queries the Wikimedia Commons API and downloads
//! matching images. This port covers the pure, I/O-free pieces faithfully:
//!
//! - [`safe_slug`] — the `_safe(name)` sanitizer
//!   (`re.sub(r"[^\w\-.]", "_", name)[:60]`): non-word/non-`-`/non-`.`
//!   characters become `_`, result capped at 60 chars. Python's `\w` under
//!   the default (Unicode) `re` mode matches any Unicode "word" character
//!   (alphanumeric plus `_`), which this port mirrors via `char::is_alphanumeric`.
//! - [`strip_html_tags`] — the `re.sub("<[^>]+>", "", ...)` used to clean
//!   the `Artist` extmetadata field.
//! - [`output_filename`] — the derived download filename
//!   (`_safe(query) + "_" + _safe(title.replace("File:", ""))`, then
//!   `os.path.splitext(fn)[0][:55] + ext`), mirroring `fetch()`'s filename
//!   construction exactly, including the second 55-char cap applied after
//!   the extension is set aside.
//! - [`api_query_string`] — the `urllib.parse.urlencode(params)` query
//!   string for the Commons `generator=search` request, with the same
//!   fixed param set and ordering as `fetch()`'s `params` dict (Python
//!   dicts preserve insertion order, and `urlencode` walks them in that
//!   order).
//!
//! NOT-PORTED: the actual Commons API HTTP GET, the image download HTTP
//! GET, and directory creation (`_api_get`, the download loop in `fetch()`,
//! `os.makedirs`). `legion-runtime`'s `Cargo.toml` has no HTTP client
//! crate — see the Q0 report for the exact `reqwest` patch this would need.
//! Response-envelope parsing (`extmetadata` → license/artist/thumburl) is
//! likewise left for that later HTTP-capable port, since faithfully
//! porting it in isolation from a real response shape risks silently
//! diverging from the Wikimedia API's actual JSON.

/// Mirrors Python's `_safe(name)`:
/// `re.sub(r"[^\w\-.]", "_", name)[:60]`.
///
/// Python's default `re` mode is Unicode-aware, so `\w` matches any
/// Unicode letter/digit/underscore — mirrored here with
/// `char::is_alphanumeric() || c == '_'`. `-` and `.` are also kept as-is;
/// everything else becomes `_`. The result is capped at 60 **characters**
/// (Python slices by code point for `str`, matched here via `chars()`,
/// not bytes).
pub fn safe_slug(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    cleaned.chars().take(60).collect()
}

/// Mirrors Python's `re.sub("<[^>]+>", "", text)`: strips any substring
/// starting with `<`, containing no `>`, ending with `>` (i.e. simple HTML
/// tags with no embedded `>` — the same limitation the Python regex has,
/// e.g. a tag attribute value containing `>` would end the match early,
/// same as upstream).
pub fn strip_html_tags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_tag = false;
    for c in text.chars() {
        match (in_tag, c) {
            (false, '<') => in_tag = true,
            (true, '>') => in_tag = false,
            (false, _) => out.push(c),
            (true, _) => {}
        }
    }
    out
}

/// Splits `fn` into `(stem, ext)` the way `os.path.splitext` does: the
/// extension is the last `.`-prefixed suffix, unless the whole basename
/// starts with `.` and has no other `.` (a dotfile has no extension) or
/// there is no `.` at all (extension is empty). Mirrors the two
/// `os.path.splitext` calls in `fetch()` (once for the thumb URL's
/// extension, once for the assembled filename's 55-char cap).
fn splitext(name: &str) -> (&str, &str) {
    match name.rfind('.') {
        Some(0) => (name, ""),
        Some(idx) => (&name[..idx], &name[idx..]),
        None => (name, ""),
    }
}

/// Mirrors `os.path.splitext(thumb)[1].split("?")[0] or ".jpg"`: the
/// extension of a (possibly query-stringed) URL/path, defaulting to
/// `.jpg` when there is none.
pub fn thumb_extension(thumb_url: &str) -> String {
    let (_, ext) = splitext(thumb_url);
    let ext = ext.split('?').next().unwrap_or("");
    if ext.is_empty() {
        ".jpg".to_string()
    } else {
        ext.to_string()
    }
}

/// Mirrors `fetch()`'s output-filename construction:
/// ```python
/// fn = _safe(query) + "_" + _safe(title.replace("File:", ""))
/// fn = os.path.splitext(fn)[0][:55] + ext
/// ```
/// `title` is the raw Commons page title (e.g. `"File:Petronas Towers.jpg"`);
/// `ext` is the extension produced by [`thumb_extension`].
pub fn output_filename(query: &str, title: &str, ext: &str) -> String {
    let title_no_prefix = title.replace("File:", "");
    let fn_ = format!("{}_{}", safe_slug(query), safe_slug(&title_no_prefix));
    let (stem, _) = splitext(&fn_);
    let capped: String = stem.chars().take(55).collect();
    format!("{}{}", capped, ext)
}

/// Mirrors the fixed Commons API `params` dict `fetch()` builds, encoded
/// the way `urllib.parse.urlencode` would (insertion order preserved,
/// space encoded as `+`, values passed through `urlencode`'s default
/// `quote_plus`). `count` is `gsrlimit`/`iiprop` count context; `width` is
/// `iiurlwidth`.
pub fn api_query_string(query: &str, count: u32, width: u32) -> String {
    let pairs: [(&str, String); 8] = [
        ("action", "query".to_string()),
        ("format", "json".to_string()),
        ("generator", "search".to_string()),
        ("gsrsearch", query.to_string()),
        ("gsrnamespace", "6".to_string()),
        ("gsrlimit", count.to_string()),
        ("prop", "imageinfo".to_string()),
        ("iiprop", "url|extmetadata".to_string()),
    ];
    let mut out = String::new();
    for (i, (k, v)) in pairs.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(k);
        out.push('=');
        out.push_str(&url_encode_plus(v));
    }
    out.push_str(&format!("&iiurlwidth={}", width));
    out
}

/// Minimal `quote_plus`-equivalent for the ASCII/Unicode query values this
/// module actually needs to encode (search terms and the fixed literal
/// param values above): spaces become `+`, unreserved characters
/// (`A-Za-z0-9-_.~`) pass through, everything else is percent-encoded as
/// UTF-8 bytes — matching `urllib.parse.quote_plus`'s default behavior.
fn url_encode_plus(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_slug_replaces_disallowed_chars() {
        assert_eq!(safe_slug("Petronas Towers!"), "Petronas_Towers_");
        assert_eq!(safe_slug("a-b.c_d"), "a-b.c_d");
    }

    #[test]
    fn safe_slug_caps_at_60_chars() {
        let long = "a".repeat(100);
        assert_eq!(safe_slug(&long).len(), 60);
    }

    #[test]
    fn safe_slug_keeps_unicode_word_chars() {
        assert_eq!(safe_slug("乔治市街道"), "乔治市街道");
    }

    #[test]
    fn strip_html_tags_basic() {
        assert_eq!(strip_html_tags("<a href=\"x\">Jane Doe</a>"), "Jane Doe");
        assert_eq!(strip_html_tags("plain text"), "plain text");
        assert_eq!(strip_html_tags("<b>bold</b> and <i>italic</i>"), "bold and italic");
    }

    #[test]
    fn thumb_extension_from_url_with_query() {
        assert_eq!(
            thumb_extension("https://upload.wikimedia.org/x/Petronas.jpg?w=1600"),
            ".jpg"
        );
    }

    #[test]
    fn thumb_extension_defaults_to_jpg() {
        // Python's os.path.splitext matches the dot in the host here, so only a
        // dot-free URL falls back to ".jpg".
        assert_eq!(thumb_extension("https://upload.wikimedia.org/x/noext"), ".org/x/noext");
        assert_eq!(thumb_extension("noext"), ".jpg");
    }

    #[test]
    fn output_filename_strips_file_prefix_and_caps() {
        let name = output_filename("Petronas Towers", "File:Petronas Towers.jpg", ".jpg");
        assert_eq!(name, "Petronas_Towers_Petronas_Towers.jpg");
    }

    #[test]
    fn output_filename_55_char_cap_applies_to_stem_only() {
        let long_query = "q".repeat(40);
        let long_title = format!("File:{}.jpg", "t".repeat(40));
        let name = output_filename(&long_query, &long_title, ".jpg");
        let (stem, ext) = splitext(&name);
        assert!(stem.chars().count() <= 55);
        assert_eq!(ext, ".jpg");
    }

    #[test]
    fn api_query_string_matches_fixed_param_order() {
        let qs = api_query_string("Langkawi beach", 2, 1600);
        assert_eq!(
            qs,
            "action=query&format=json&generator=search&gsrsearch=Langkawi+beach&gsrnamespace=6&gsrlimit=2&prop=imageinfo&iiprop=url%7Cextmetadata&iiurlwidth=1600"
        );
    }
}
