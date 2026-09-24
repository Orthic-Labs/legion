//! Port of the pure functions from
//! `skills/designer/engine/scripts/live-insert.mjs`:
//! `isInsertPosition`, `computeInsertLine`, `buildInsertWrapperLines`, and
//! the `argVal` argv helper.
//!
//! NOT ported (needs unported dependencies outside this packet's files, see
//! `mod.rs`): `resolveElementMatch`, `insertCli`, and everything that reads
//! `process.argv`/the filesystem or calls into `./live-wrap.mjs` /
//! `./live/svelte-component.mjs`.

/// Mirrors the source's `INSERT_POSITIONS` `Set` + `isInsertPosition`.
pub fn is_insert_position(value: &str) -> bool {
    matches!(value, "before" | "after")
}

/// Mirrors `computeInsertLine(startLine, endLine, position)`.
///
/// `position === 'before' ? startLine : endLine + 1`. The source does not
/// validate `position` here (validation happens earlier via
/// `isInsertPosition`), so any value other than `"before"` is treated as
/// `"after"`, exactly like the JS ternary.
pub fn compute_insert_line(start_line: usize, end_line: usize, position: &str) -> usize {
    if position == "before" {
        start_line
    } else {
        end_line + 1
    }
}

/// Mirrors the source's `detectCommentSyntax` return shape: `{ open, close }`.
#[derive(Debug, Clone)]
pub struct CommentSyntax {
    pub open: String,
    pub close: String,
}

/// Inputs to [`build_insert_wrapper_lines`], mirroring the destructured
/// object parameter in the source.
pub struct InsertWrapperArgs<'a> {
    pub id: &'a str,
    pub count: i64,
    pub indent: &'a str,
    pub comment_syntax: &'a CommentSyntax,
    pub is_jsx: bool,
}

/// Mirrors `buildInsertWrapperLines({ id, count, indent, commentSyntax, isJsx })`.
///
/// Faithful line-for-line port, including the two different wrapper shapes
/// for JSX vs. non-JSX targets and the exact attribute string construction
/// (`data-impeccable-variants`, `data-impeccable-mode`,
/// `data-impeccable-variant-count`, `style`).
pub fn build_insert_wrapper_lines(args: InsertWrapperArgs<'_>) -> Vec<String> {
    let InsertWrapperArgs {
        id,
        count,
        indent,
        comment_syntax,
        is_jsx,
    } = args;

    let style_contents = if is_jsx {
        "style={{ display: \"contents\" }}"
    } else {
        "style=\"display: contents\""
    };

    let attrs = format!(
        "data-impeccable-variants=\"{id}\" data-impeccable-mode=\"insert\" data-impeccable-variant-count=\"{count}\" {style_contents}"
    );

    if is_jsx {
        vec![
            format!("{indent}<div {attrs}>"),
            format!(
                "{indent}  {open} impeccable-variants-start {id} {close}",
                open = comment_syntax.open,
                close = comment_syntax.close
            ),
            format!(
                "{indent}  {open} Variants: insert below this line {close}",
                open = comment_syntax.open,
                close = comment_syntax.close
            ),
            format!(
                "{indent}  {open} impeccable-variants-end {id} {close}",
                open = comment_syntax.open,
                close = comment_syntax.close
            ),
            format!("{indent}</div>"),
        ]
    } else {
        vec![
            format!(
                "{indent}{open} impeccable-variants-start {id} {close}",
                open = comment_syntax.open,
                close = comment_syntax.close
            ),
            format!("{indent}<div {attrs}>"),
            format!(
                "{indent}  {open} Variants: insert below this line {close}",
                open = comment_syntax.open,
                close = comment_syntax.close
            ),
            format!("{indent}</div>"),
            format!(
                "{indent}{open} impeccable-variants-end {id} {close}",
                open = comment_syntax.open,
                close = comment_syntax.close
            ),
        ]
    }
}

/// Mirrors `argVal(args, flag)`: returns the argument immediately following
/// `flag` in `args`, or `None` if `flag` is absent or is the last element
/// (matching the source's `idx !== -1 && idx + 1 < args.length` guard).
pub fn arg_val<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let idx = args.iter().position(|a| a == flag)?;
    args.get(idx + 1).map(|s| s.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_position_matches_source_set() {
        assert!(is_insert_position("before"));
        assert!(is_insert_position("after"));
        assert!(!is_insert_position("inside"));
        assert!(!is_insert_position(""));
    }

    #[test]
    fn compute_insert_line_before_uses_start() {
        assert_eq!(compute_insert_line(10, 20, "before"), 10);
    }

    #[test]
    fn compute_insert_line_after_uses_end_plus_one() {
        assert_eq!(compute_insert_line(10, 20, "after"), 21);
    }

    #[test]
    fn compute_insert_line_unrecognized_falls_through_to_after() {
        // The JS ternary has no else-validation at this call site.
        assert_eq!(compute_insert_line(10, 20, "bogus"), 21);
    }

    #[test]
    fn wrapper_lines_non_jsx_html_comment_syntax() {
        let cs = CommentSyntax {
            open: "<!--".to_string(),
            close: "-->".to_string(),
        };
        let lines = build_insert_wrapper_lines(InsertWrapperArgs {
            id: "sess1",
            count: 3,
            indent: "  ",
            comment_syntax: &cs,
            is_jsx: false,
        });
        assert_eq!(
            lines,
            vec![
                "  <!-- impeccable-variants-start sess1 -->".to_string(),
                "  <div data-impeccable-variants=\"sess1\" data-impeccable-mode=\"insert\" data-impeccable-variant-count=\"3\" style=\"display: contents\">".to_string(),
                "    <!-- Variants: insert below this line -->".to_string(),
                "  </div>".to_string(),
                "  <!-- impeccable-variants-end sess1 -->".to_string(),
            ]
        );
    }

    #[test]
    fn wrapper_lines_jsx_comment_syntax() {
        let cs = CommentSyntax {
            open: "{/*".to_string(),
            close: "*/}".to_string(),
        };
        let lines = build_insert_wrapper_lines(InsertWrapperArgs {
            id: "abc",
            count: 1,
            indent: "",
            comment_syntax: &cs,
            is_jsx: true,
        });
        assert_eq!(
            lines,
            vec![
                "<div data-impeccable-variants=\"abc\" data-impeccable-mode=\"insert\" data-impeccable-variant-count=\"1\" style={{ display: \"contents\" }}>".to_string(),
                "  {/* impeccable-variants-start abc */}".to_string(),
                "  {/* Variants: insert below this line */}".to_string(),
                "  {/* impeccable-variants-end abc */}".to_string(),
                "</div>".to_string(),
            ]
        );
    }

    #[test]
    fn arg_val_returns_following_value() {
        let args = vec!["--id".to_string(), "sess1".to_string(), "--count".to_string(), "3".to_string()];
        assert_eq!(arg_val(&args, "--id"), Some("sess1"));
        assert_eq!(arg_val(&args, "--count"), Some("3"));
    }

    #[test]
    fn arg_val_missing_flag_is_none() {
        let args = vec!["--id".to_string(), "sess1".to_string()];
        assert_eq!(arg_val(&args, "--missing"), None);
    }

    #[test]
    fn arg_val_flag_is_last_element_is_none() {
        let args = vec!["--id".to_string()];
        assert_eq!(arg_val(&args, "--id"), None);
    }
}
