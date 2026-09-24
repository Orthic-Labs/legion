//! Port of `skills/designer/engine/scripts/live-insert.mjs`, including
//! `resolveElementMatch` and the `insertCli()` entry point (packet r22r24
//! follow-up): `./live-wrap.mjs` is now ported at `wf_port::w2_020::wrap`
//! and `./live/svelte-component.mjs` at `wf_port::w2_022::svelte_component`,
//! so the two blockers noted in `finish-r22.md` are closed.

use std::collections::HashMap;
use std::path::Path;

use serde_json::{json, Value};

use crate::p8_designer::is_generated::{is_generated_file, IsGeneratedOptions};
use crate::wf_port::w2_020::wrap as live_wrap;
use crate::wf_port::w2_022::svelte_component as svelte;

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

/// Result of [`resolve_element_match`]: either a single resolved match, or
/// an error mirroring the source's `{ error }` / `{ error, candidates }`
/// shapes (`element_not_found` / `element_ambiguous`).
pub enum ElementMatchResult {
    Match(live_wrap::LineRange),
    NotFound,
    Ambiguous(Vec<live_wrap::LineRange>),
}

/// Mirrors `resolveElementMatch({ lines, queries, tag, text })`.
pub fn resolve_element_match(
    lines: &[String],
    queries: &[String],
    tag: Option<&str>,
    text: Option<&str>,
) -> ElementMatchResult {
    if let Some(text) = text {
        let mut candidates: Vec<live_wrap::LineRange> = Vec::new();
        for q in queries {
            let all = live_wrap::find_all_elements(lines, q, tag);
            for c in all {
                if !candidates.iter().any(|x| x.start_line == c.start_line) {
                    candidates.push(c);
                }
            }
            if candidates.len() == 1 {
                break;
            }
        }
        if candidates.is_empty() {
            return ElementMatchResult::NotFound;
        }
        if candidates.len() == 1 {
            return ElementMatchResult::Match(candidates[0]);
        }
        let filtered = live_wrap::filter_by_text(&candidates, lines, text);
        if filtered.len() == 1 {
            return ElementMatchResult::Match(filtered[0]);
        }
        if filtered.is_empty() {
            return ElementMatchResult::Match(candidates[0]);
        }
        return ElementMatchResult::Ambiguous(filtered);
    }

    for q in queries {
        if let Some(m) = live_wrap::find_element(lines, q, tag) {
            return ElementMatchResult::Match(m);
        }
    }
    ElementMatchResult::NotFound
}

fn rel_forward_slash(path: &Path, cwd: &Path) -> String {
    path.strip_prefix(cwd)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

const HELP_TEXT: &str = "Usage: node live-insert.mjs [options]\n\n\
Find an anchor element in source and splice an insert-variant wrapper.\n\n\
Required:\n  \
--id ID            Session ID for the variant wrapper\n  \
--count N          Number of expected variants (1-8)\n  \
--position POS     before | after (relative to the anchor element)\n\n\
Element identification (at least one required):\n  \
--element-id ID    HTML id attribute of the anchor element\n  \
--classes A,B,C    Comma-separated CSS class names\n  \
--tag TAG          Tag name (div, section, etc.)\n  \
--query TEXT       Fallback: raw text to search for\n\n\
Optional:\n  \
--file PATH        Source file to search in (skips auto-detection)\n  \
--text TEXT        Anchor textContent for disambiguation (~80 chars)\n\n\
Output (JSON):\n  \
{ mode: \"insert\", file, position, insertLine, commentSyntax, styleMode, styleTag, cssAuthoring }";

/// Port of `insertCli()`. Mirrors argv parsing, filesystem I/O, and JSON
/// output/exit-code shape, minus the actual `process.exit`: callers get
/// `(exit_code, output_text)`, exactly like sibling CLI ports
/// (`w2_016::live_accept::run`).
pub fn run(args: &[String], cwd: &Path) -> (i32, String) {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return (0, HELP_TEXT.to_string());
    }

    let id = match arg_val(args, "--id") {
        Some(v) => v,
        None => return (1, "Missing --id".to_string()),
    };
    let count: i64 = arg_val(args, "--count").and_then(|v| v.parse().ok()).unwrap_or(3);
    let position = match arg_val(args, "--position") {
        Some(v) => v,
        None => return (1, "Missing --position (before | after)".to_string()),
    };
    if !is_insert_position(position) {
        return (1, format!("Invalid --position: {position}"));
    }
    let element_id = arg_val(args, "--element-id");
    let classes = arg_val(args, "--classes");
    let tag = arg_val(args, "--tag");
    let query = arg_val(args, "--query");
    let file_path = arg_val(args, "--file");
    let text = arg_val(args, "--text");

    if element_id.is_none() && classes.is_none() && query.is_none() {
        return (1, "Need at least one of: --element-id, --classes, --query".to_string());
    }

    let queries = live_wrap::build_search_queries(element_id, classes, tag, query);

    let mut target_file = file_path.map(|p| cwd.join(p));
    if let Some(tf) = &target_file {
        let opts = IsGeneratedOptions { cwd: Some(cwd.to_path_buf()) };
        if is_generated_file(&tf.to_string_lossy(), &opts) {
            return (
                1,
                json!({
                    "error": "file_is_generated",
                    "fallback": "agent-driven",
                    "file": rel_forward_slash(tf, cwd),
                })
                .to_string(),
            );
        }
    } else {
        for q in &queries {
            if let Some(f) = live_wrap::find_file_with_query(q, cwd, false) {
                target_file = Some(f);
                break;
            }
        }
        if target_file.is_none() {
            let mut generated_hit: Option<std::path::PathBuf> = None;
            for q in &queries {
                generated_hit = live_wrap::find_file_with_query(q, cwd, true);
                if generated_hit.is_some() {
                    break;
                }
            }
            return (
                1,
                json!({
                    "error": if generated_hit.is_some() { "element_not_in_source" } else { "element_not_found" },
                    "fallback": "agent-driven",
                    "hint": "See \"Handle fallback\" in live.md.",
                })
                .to_string(),
            );
        }
    }
    let target_file = target_file.expect("resolved above");

    let content = match std::fs::read_to_string(&target_file) {
        Ok(c) => c,
        Err(e) => return (1, json!({"error": "read_failed", "message": e.to_string()}).to_string()),
    };
    let lines: Vec<String> = content.split('\n').map(str::to_string).collect();
    let resolved = resolve_element_match(&lines, &queries, tag, text);

    let (start_line, end_line) = match resolved {
        ElementMatchResult::Ambiguous(candidates) => {
            let cands: Vec<Value> = candidates
                .iter()
                .map(|c| json!({"startLine": c.start_line + 1, "endLine": c.end_line + 1}))
                .collect();
            return (
                1,
                json!({
                    "error": "element_ambiguous",
                    "fallback": "agent-driven",
                    "file": rel_forward_slash(&target_file, cwd),
                    "candidates": cands,
                })
                .to_string(),
            );
        }
        ElementMatchResult::NotFound => {
            return (1, json!({"error": "element_not_found", "fallback": "agent-driven"}).to_string());
        }
        ElementMatchResult::Match(m) => (m.start_line, m.end_line),
    };

    let target_file_str = target_file.to_string_lossy().to_string();
    let comment_syntax = live_wrap::detect_comment_syntax(&target_file_str);
    let style_mode = live_wrap::detect_style_mode(&target_file_str);
    let is_jsx = comment_syntax.open == "{/*";
    let splice_index = compute_insert_line(start_line, end_line, position);
    let rel_target_file = rel_forward_slash(&target_file, cwd);

    let env: HashMap<String, String> = std::env::vars().collect();
    if svelte::should_use_svelte_component_injection(&target_file_str, &env) {
        let session = match svelte::scaffold_svelte_component_insert_session(
            svelte::ScaffoldInsertSessionInput {
                id,
                count,
                source_file: &rel_target_file,
                insert_line: splice_index as i64 + 1,
                position,
                anchor_start_line: Some(start_line as i64 + 1),
                anchor_end_line: Some(end_line as i64 + 1),
                anchor_lines: &lines[start_line..=end_line],
            },
            cwd,
        ) {
            Ok(s) => s,
            Err(e) => return (1, json!({"error": "write_failed", "message": e.to_string()}).to_string()),
        };
        let css = svelte::build_svelte_component_css_authoring(count as usize);
        return (
            0,
            json!({
                "mode": "insert",
                "position": position,
                "file": session.manifest_file,
                "sourceFile": rel_target_file,
                "previewMode": "svelte-component",
                "componentDir": session.component_dir,
                "propContract": Value::Array(vec![]),
                "insertLine": 1,
                "sourceInsertLine": splice_index as i64 + 1,
                "anchorStartLine": start_line as i64 + 1,
                "anchorEndLine": end_line as i64 + 1,
                "commentSyntax": {"open": comment_syntax.open, "close": comment_syntax.close},
                "styleMode": "svelte-component",
                "styleTag": Value::Null,
                "cssSelectorPrefixExamples": Value::Array(vec![]),
                "cssAuthoring": {
                    "mode": css.mode,
                    "strategy": css.strategy,
                    "rulePattern": css.rule_pattern,
                    "selectorExamples": css.selector_examples,
                    "requirements": css.requirements,
                    "forbidden": css.forbidden,
                    "paramsFile": css.params_file,
                },
            })
            .to_string(),
        );
    }

    // Mirrors `lines[spliceIndex]?.match(/^(\s*)/)?.[1] ?? lines[startLine]?.match(...)?.[1] ?? ''`:
    // the optional-chain only falls through to `startLine` when `spliceIndex`
    // is out of bounds (a `\s*` match always succeeds, even as `""`), not
    // when the matched indent happens to be empty.
    let leading_ws = |s: &str| -> String { s.chars().take_while(|c| c.is_whitespace()).collect() };
    let indent: String = lines
        .get(splice_index)
        .map(|l| leading_ws(l))
        .or_else(|| lines.get(start_line).map(|l| leading_ws(l)))
        .unwrap_or_default();

    let cs = CommentSyntax { open: comment_syntax.open.to_string(), close: comment_syntax.close.to_string() };
    let wrapper_lines = build_insert_wrapper_lines(InsertWrapperArgs {
        id,
        count,
        indent: &indent,
        comment_syntax: &cs,
        is_jsx,
    });

    let mut new_lines: Vec<String> = Vec::with_capacity(lines.len() + wrapper_lines.len());
    new_lines.extend_from_slice(&lines[..splice_index]);
    new_lines.extend(wrapper_lines);
    new_lines.extend_from_slice(&lines[splice_index..]);

    if let Err(e) = std::fs::write(&target_file, new_lines.join("\n")) {
        return (1, json!({"error": "write_failed", "message": e.to_string()}).to_string());
    }

    let insert_line = splice_index + 3;
    let css_authoring = live_wrap::build_css_authoring(&style_mode, count as u32);

    (
        0,
        json!({
            "mode": "insert",
            "position": position,
            "file": rel_target_file,
            "insertLine": insert_line as i64 + 1,
            "commentSyntax": {"open": comment_syntax.open, "close": comment_syntax.close},
            "styleMode": style_mode.mode,
            "styleTag": style_mode.style_tag,
            "cssSelectorPrefixExamples": live_wrap::build_css_selector_prefix_examples(style_mode.mode, count as u32),
            "cssAuthoring": {
                "mode": css_authoring.mode,
                "styleTag": css_authoring.style_tag,
                "strategy": css_authoring.strategy,
                "rulePattern": css_authoring.rule_pattern,
                "selectorExamples": css_authoring.selector_examples,
                "requirements": css_authoring.requirements,
                "forbidden": css_authoring.forbidden,
            },
        })
        .to_string(),
    )
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
