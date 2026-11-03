//! Port of `skills/designer/engine/scripts/detector/shared/page.mjs`.

/// Mirrors `isFullPage(content)`: strips HTML comments, then checks for a
/// doctype/html/head tag to decide whether `content` is a full page (as
/// opposed to a component/partial).
pub fn is_full_page(content: &str) -> bool {
    let stripped = strip_html_comments(content);
    let lower = stripped.to_ascii_lowercase();
    contains_doctype(&lower)
        || contains_open_tag(&lower, "html")
        || contains_open_tag(&lower, "head")
}

fn strip_html_comments(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let bytes = content.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if content[i..].starts_with("<!--") {
            if let Some(end) = content[i..].find("-->") {
                i += end + 3;
                continue;
            } else {
                // Unterminated comment: JS regex `<!--[\s\S]*?-->` requires a
                // closing marker, so an unterminated comment is left as-is.
                out.push_str(&content[i..]);
                break;
            }
        }
        // advance by one char (not byte) to stay UTF-8 safe
        let ch = content[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn contains_doctype(lower: &str) -> bool {
    // /<!doctype\s/i
    lower.match_indices("<!doctype").any(
        |(idx, _)| matches!(lower.as_bytes().get(idx + 9), Some(b) if (*b as char).is_whitespace()),
    )
}

fn contains_open_tag(lower: &str, tag: &str) -> bool {
    // /<tag[\s>]/i
    let needle = format!("<{tag}");
    lower.match_indices(&needle).any(|(idx, _)| {
        matches!(
            lower.as_bytes().get(idx + needle.len()),
            Some(b) if (*b as char).is_whitespace() || *b == b'>'
        )
    })
}
