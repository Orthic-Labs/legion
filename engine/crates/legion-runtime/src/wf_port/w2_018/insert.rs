//! Port of `skills/designer/engine/scripts/live-insert.mjs` (chunk w2_018) —
//! self-contained pure logic only.
//!
//! `live-insert.mjs`'s CLI driver (`insertCli`) additionally depends on
//! `live-wrap.mjs` (`buildSearchQueries`, `findElement`, `findAllElements`,
//! `filterByText`, `findFileWithQuery`, `detectCommentSyntax`,
//! `detectStyleMode`, `buildCssAuthoring`, `buildCssSelectorPrefixExamples`)
//! and `live/svelte-component.mjs`, neither of which has an existing Rust
//! port and neither of which is in this chunk's owned scope (`live-wrap.mjs`
//! alone is a large, separately-chunked file). Only the driver-independent
//! exported helpers — `isInsertPosition`, `computeInsertLine`,
//! `buildInsertWrapperLines` — are ported here; the full CLI (file/element
//! resolution, source splicing, Svelte-component scaffolding) is left
//! NOT-STARTED pending a `live-wrap.mjs` port.

/// A `CommentSyntax` pair, mirroring the shape `detectCommentSyntax` in
/// `live-wrap.mjs` returns (`{ open, close }`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommentSyntax {
    pub open: String,
    pub close: String,
}

/// Mirrors `isInsertPosition(value)`: only `"before"` and `"after"` are
/// valid insert positions.
pub fn is_insert_position(value: &str) -> bool {
    matches!(value, "before" | "after")
}

/// Mirrors `computeInsertLine(startLine, endLine, position)`.
pub fn compute_insert_line(start_line: usize, end_line: usize, position: &str) -> usize {
    if position == "before" {
        start_line
    } else {
        end_line + 1
    }
}

/// Mirrors `buildInsertWrapperLines({ id, count, indent, commentSyntax, isJsx })`.
pub fn build_insert_wrapper_lines(
    id: &str,
    count: u32,
    indent: &str,
    comment_syntax: &CommentSyntax,
    is_jsx: bool,
) -> Vec<String> {
    let style_contents = if is_jsx {
        "style={{ display: \"contents\" }}"
    } else {
        "style=\"display: contents\""
    };
    let attrs = format!(
        "data-impeccable-variants=\"{id}\" data-impeccable-mode=\"insert\" data-impeccable-variant-count=\"{count}\" {style_contents}",
    );

    if is_jsx {
        vec![
            format!("{indent}<div {attrs}>"),
            format!(
                "{indent}  {} impeccable-variants-start {id} {}",
                comment_syntax.open, comment_syntax.close
            ),
            format!(
                "{indent}  {} Variants: insert below this line {}",
                comment_syntax.open, comment_syntax.close
            ),
            format!(
                "{indent}  {} impeccable-variants-end {id} {}",
                comment_syntax.open, comment_syntax.close
            ),
            format!("{indent}</div>"),
        ]
    } else {
        vec![
            format!(
                "{indent}{} impeccable-variants-start {id} {}",
                comment_syntax.open, comment_syntax.close
            ),
            format!("{indent}<div {attrs}>"),
            format!(
                "{indent}  {} Variants: insert below this line {}",
                comment_syntax.open, comment_syntax.close
            ),
            format!("{indent}</div>"),
            format!(
                "{indent}{} impeccable-variants-end {id} {}",
                comment_syntax.open, comment_syntax.close
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_position_validation() {
        assert!(is_insert_position("before"));
        assert!(is_insert_position("after"));
        assert!(!is_insert_position("inside"));
        assert!(!is_insert_position(""));
    }

    #[test]
    fn insert_line_before_uses_start_line() {
        assert_eq!(compute_insert_line(10, 20, "before"), 10);
    }

    #[test]
    fn insert_line_after_uses_end_line_plus_one() {
        assert_eq!(compute_insert_line(10, 20, "after"), 21);
    }

    #[test]
    fn wrapper_lines_html_mode_five_lines_wraps_markers() {
        let cs = CommentSyntax {
            open: "<!--".to_string(),
            close: "-->".to_string(),
        };
        let lines = build_insert_wrapper_lines("sess-1", 3, "  ", &cs, false);
        assert_eq!(lines.len(), 5);
        assert_eq!(lines[0], "  <!-- impeccable-variants-start sess-1 -->");
        assert!(lines[1].contains("data-impeccable-variants=\"sess-1\""));
        assert!(lines[1].contains("data-impeccable-mode=\"insert\""));
        assert!(lines[1].contains("data-impeccable-variant-count=\"3\""));
        assert!(lines[1].contains("style=\"display: contents\""));
        assert_eq!(lines[4], "  <!-- impeccable-variants-end sess-1 -->");
    }

    #[test]
    fn wrapper_lines_jsx_mode_uses_jsx_style_object_and_wraps_the_div_itself() {
        let cs = CommentSyntax {
            open: "{/*".to_string(),
            close: "*/}".to_string(),
        };
        let lines = build_insert_wrapper_lines("sess-2", 1, "", &cs, true);
        assert_eq!(lines.len(), 5);
        assert!(lines[0].starts_with("<div data-impeccable-variants=\"sess-2\""));
        assert!(lines[0].contains("style={{ display: \"contents\" }}"));
        assert_eq!(lines[1], "  {/* impeccable-variants-start sess-2 */}");
        assert_eq!(lines[3], "  {/* impeccable-variants-end sess-2 */}");
        assert_eq!(lines[4], "</div>");
    }
}
