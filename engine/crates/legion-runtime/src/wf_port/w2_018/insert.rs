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
