//! `wrapCli()` argv/console/exit orchestration and the Svelte-injection
//! branch, ported from `live-wrap.mjs` (packet R18R26, closing the gap
//! `super::wrap`'s module doc previously called out as not ported).
//!
//! Wires together the pure helpers already ported in [`super::wrap`]
//! (`build_search_queries`, `find_file_with_query`, `find_element`/
//! `find_all_elements`/`filter_by_text`, `detect_comment_syntax`,
//! `detect_style_mode`, `build_css_authoring`,
//! `build_css_selector_prefix_examples`, `min_leading_spaces`,
//! `pending_entries_that_may_affect_wrap`, `manual_edit_may_affect_wrap`,
//! `apply_buffered_manual_edit_to_lines`) with:
//! - `crate::wf_port::w2_021::manual_edits_buffer::read_buffer` for
//!   `readManualEditsBuffer`.
//! - `crate::wf_port::w2_022::svelte_component` for the Svelte-injection
//!   branch (`shouldUseSvelteComponentInjection`,
//!   `scaffoldSvelteComponentSession`, `buildSvelteComponentCssAuthoring`).
//! - real `std::fs` reads/writes for the target source file (mirroring
//!   `fs.readFileSync`/`fs.writeFileSync`).
//!
//! Returns `(exit_code, output)` instead of calling
//! `console.log`/`console.error`/`process.exit` directly, so a thin `main`
//! (or a test) controls I/O — same convention as
//! `wf_port::w2_020::live_cli::live_cli`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use crate::p8_designer::is_generated::{is_generated_file, IsGeneratedOptions};
use crate::wf_port::w2_020::wrap::{
    apply_buffered_manual_edit_to_lines, arg_val, build_css_authoring,
    build_css_selector_prefix_examples, build_search_queries, detect_comment_syntax,
    detect_style_mode, filter_by_text, find_all_elements, find_element, find_file_with_query,
    manual_edit_may_affect_wrap, min_leading_spaces, pending_entries_that_may_affect_wrap,
    LineRange,
};
use crate::wf_port::w2_021::manual_edits_buffer::read_buffer;
use crate::wf_port::w2_022::svelte_component::{
    build_svelte_component_css_authoring, scaffold_svelte_component_session,
    should_use_svelte_component_injection, ScaffoldSessionInput,
};

const HELP_TEXT: &str = "Usage: impeccable wrap [options]

Find an element in source and wrap it in a variant container.

Required:
  --id ID            Session ID for the variant wrapper
  --count N          Number of expected variants (1-8)

Element identification (at least one required):
  --element-id ID    HTML id attribute of the element
  --classes A,B,C    Comma- or space-separated CSS class names
  --tag TAG          Tag name (div, section, etc.)
  --query TEXT       Fallback: raw text to search for

Optional:
  --file PATH        Source file to search in (skips auto-detection)
  --text TEXT        Picked element's textContent. Used to disambiguate when
                     classes/tag match multiple sibling elements (e.g. a list
                     of <Card>s with the same className). Pass the first ~80
                     chars of event.element.textContent.
  --page-url URL     Current page URL. Required when pending manual edits may
                     affect the picked source block. Pending edits are filtered
                     to this page so an edit on /a doesn't bleed into /b.
  --help             Show this help message

Output (JSON):
  { file, startLine, endLine, insertLine, commentSyntax }

The agent should insert variant HTML at insertLine.";

fn err_json(value: Value) -> (i32, String) {
    (1, value.to_string())
}

fn strip_verbatim_prefix(path: PathBuf) -> PathBuf {
    match path.to_str() {
        Some(s) if s.starts_with(r"\\?\") => PathBuf::from(&s[4..]),
        _ => path,
    }
}

fn relative_slash(cwd: &Path, path: &Path) -> String {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    pathdiff(&abs, cwd)
        .unwrap_or_else(|| abs.to_string_lossy().to_string())
        .replace('\\', "/")
}

fn pathdiff(to: &Path, from: &Path) -> Option<String> {
    use std::path::Component;
    let to_comps: Vec<Component> = to.components().collect();
    let from_comps: Vec<Component> = from.components().collect();
    let mut i = 0;
    while i < to_comps.len() && i < from_comps.len() && to_comps[i] == from_comps[i] {
        i += 1;
    }
    let mut out = PathBuf::new();
    for _ in i..from_comps.len() {
        out.push("..");
    }
    for comp in &to_comps[i..] {
        out.push(comp.as_os_str());
    }
    Some(out.to_string_lossy().to_string())
}

/// Port of `wrapCli()`.
pub fn wrap_cli(args: &[String], cwd: &Path, env: &HashMap<String, String>) -> (i32, String) {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        return (0, HELP_TEXT.to_string());
    }

    let id = match arg_val(args, "--id") {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => return (1, "Missing --id".to_string()),
    };
    let count: u32 = arg_val(args, "--count")
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(3)
        .max(0) as u32;
    let element_id = arg_val(args, "--element-id");
    let classes = arg_val(args, "--classes");
    let tag = arg_val(args, "--tag");
    let query = arg_val(args, "--query");
    let file_path = arg_val(args, "--file");
    let text = arg_val(args, "--text");
    let page_url = arg_val(args, "--page-url");

    if element_id.is_none() && classes.is_none() && query.is_none() {
        return (1, "Need at least one of: --element-id, --classes, --query".to_string());
    }

    let queries = build_search_queries(element_id, classes, tag, query);
    let gen_opts = IsGeneratedOptions { cwd: Some(cwd.to_path_buf()) };

    let mut target_file: Option<PathBuf> = file_path.map(|f| cwd.join(f));
    if target_file.is_none() {
        for q in &queries {
            if let Some(found) = find_file_with_query(q, cwd, false) {
                target_file = Some(found);
                break;
            }
        }
        if target_file.is_none() {
            let mut generated_hit = None;
            for q in &queries {
                generated_hit = find_file_with_query(q, cwd, true);
                if generated_hit.is_some() {
                    break;
                }
            }
            return if let Some(hit) = generated_hit {
                err_json(json!({
                    "error": "element_not_in_source",
                    "fallback": "agent-driven",
                    "generatedMatch": relative_slash(cwd, &hit),
                    "hint": "Element found only in a generated file. See \"Handle fallback\" in live.md.",
                }))
            } else {
                err_json(json!({
                    "error": "element_not_found",
                    "fallback": "agent-driven",
                    "hint": "Element not found in any project file. It may be runtime-injected (JS component, etc.). See \"Handle fallback\" in live.md.",
                }))
            };
        }
    } else if let Some(tf) = &target_file {
        if is_generated_file(&tf.to_string_lossy(), &gen_opts) {
            return err_json(json!({
                "error": "file_is_generated",
                "fallback": "agent-driven",
                "file": relative_slash(cwd, tf),
                "hint": "Explicit --file points at a generated file. Writing here gets wiped by the next build. See \"Handle fallback\" in live.md.",
            }));
        }
    }
    let target_file = target_file.unwrap();

    let content = match std::fs::read_to_string(&target_file) {
        Ok(c) => c,
        Err(err) => return err_json(json!({ "error": format!("failed to read {}: {err}", target_file.display()) })),
    };
    let lines: Vec<String> = content.split('\n').map(str::to_string).collect();

    let candidate_match: Option<LineRange> = if let Some(text) = text {
        let mut candidates: Vec<LineRange> = Vec::new();
        for q in &queries {
            for c in find_all_elements(&lines, q, tag) {
                if !candidates.iter().any(|x| x.start_line == c.start_line) {
                    candidates.push(c);
                }
            }
            if candidates.len() == 1 {
                break;
            }
        }
        if candidates.is_empty() {
            return err_json(json!({
                "error": format!(
                    "Found file but could not locate element in {}. Searched for: {}",
                    target_file.display(),
                    queries.join(", ")
                ),
            }));
        }
        if candidates.len() == 1 {
            Some(candidates[0])
        } else {
            let filtered = filter_by_text(&candidates, &lines, text);
            if filtered.len() == 1 {
                Some(filtered[0])
            } else if filtered.is_empty() {
                Some(candidates[0])
            } else {
                return err_json(json!({
                    "error": "element_ambiguous",
                    "fallback": "agent-driven",
                    "file": relative_slash(cwd, &target_file),
                    "candidates": filtered.iter().map(|c| json!({
                        "startLine": c.start_line + 1,
                        "endLine": c.end_line + 1,
                    })).collect::<Vec<_>>(),
                    "hint": "Multiple source elements match both classes/tag and textContent. Pass --element-id, a more specific --text, or write the wrapper manually. See \"Handle fallback\" in live.md.",
                }));
            }
        }
    } else {
        let mut found = None;
        for q in &queries {
            found = find_element(&lines, q, tag);
            if found.is_some() {
                break;
            }
        }
        found
    };

    let Some(m) = candidate_match else {
        return err_json(json!({
            "error": format!(
                "Found file but could not locate element in {}. Searched for: {}",
                target_file.display(),
                queries.join(", ")
            ),
        }));
    };

    let (start_line, end_line) = (m.start_line, m.end_line);
    let target_file_str = target_file.to_string_lossy().to_string();
    let comment_syntax = detect_comment_syntax(&target_file_str);
    let style_mode = detect_style_mode(&target_file_str);
    let is_jsx = comment_syntax.open == "{/*";
    let indent: String = lines[start_line].chars().take_while(|c| c.is_whitespace()).collect();

    let mut original_lines: Vec<String> = lines[start_line..=end_line].to_vec();

    let pending_buffer = read_buffer(cwd);
    let pending_entries_for_target = if page_url.is_some() {
        Vec::new()
    } else {
        pending_entries_that_may_affect_wrap(
            &pending_buffer.entries,
            &target_file,
            &original_lines,
            start_line as i64,
            cwd,
        )
    };
    if !pending_entries_for_target.is_empty() {
        return err_json(json!({
            "error": "missing_page_url_with_pending_edits",
            "pendingEntries": pending_entries_for_target.len(),
            "hint": "Pending manual edits may affect the selected source block. Pass --page-url=$event.pageUrl so the wrap block reflects the user's staged DOM.",
        }));
    }
    if let Some(page_url) = page_url {
        let mut failed_buffered_ops = Vec::new();
        for entry in &pending_buffer.entries {
            if entry.page_url.as_deref() != Some(page_url) {
                continue;
            }
            for op in &entry.ops {
                let may_affect = manual_edit_may_affect_wrap(op, &target_file, &original_lines, start_line as i64, cwd);
                let (new_lines, changed) = apply_buffered_manual_edit_to_lines(&original_lines, start_line as i64, op);
                if changed {
                    original_lines = new_lines;
                    continue;
                }
                if !may_affect {
                    continue;
                }
                failed_buffered_ops.push(json!({
                    "entryId": entry.id,
                    "ref": op.ref_.clone(),
                    "originalText": op.original_text.clone(),
                    "reason": "ambiguous_or_unmatched_pending_edit",
                }));
            }
        }
        if !failed_buffered_ops.is_empty() {
            return err_json(json!({
                "error": "manual_edit_buffer_apply_failed",
                "pendingOps": failed_buffered_ops,
                "hint": "A staged copy edit appears to affect the selected source block, but could not be applied unambiguously to the wrap original. Apply or discard copy edits first, or write the wrapper manually.",
            }));
        }
    }

    let original_base_indent = min_leading_spaces(&original_lines);
    let reindent_original = |extra: &str| -> String {
        original_lines
            .iter()
            .map(|l| {
                if l.trim().is_empty() {
                    String::new()
                } else {
                    let rest: String = l.chars().skip(original_base_indent).collect();
                    format!("{indent}{extra}{rest}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    let original_indented = reindent_original("    ");
    let rel_target_file = relative_slash(cwd, &target_file);
    let use_svelte_component = should_use_svelte_component_injection(&target_file_str, env);

    let style_contents = if is_jsx {
        "style={{ display: \"contents\" }}"
    } else {
        "style=\"display: contents\""
    };

    let wrapper_lines: Vec<String> = if is_jsx {
        vec![
            format!("{indent}<div data-impeccable-variants=\"{id}\" data-impeccable-variant-count=\"{count}\" {style_contents}>"),
            format!("{indent}  {} impeccable-variants-start {id} {}", comment_syntax.open, comment_syntax.close),
            format!("{indent}  {} Original {}", comment_syntax.open, comment_syntax.close),
            format!("{indent}  <div data-impeccable-variant=\"original\">"),
            reindent_original("    "),
            format!("{indent}  </div>"),
            format!("{indent}  {} Variants: insert below this line {}", comment_syntax.open, comment_syntax.close),
            format!("{indent}  {} impeccable-variants-end {id} {}", comment_syntax.open, comment_syntax.close),
            format!("{indent}</div>"),
        ]
    } else {
        vec![
            format!("{indent}{} impeccable-variants-start {id} {}", comment_syntax.open, comment_syntax.close),
            format!("{indent}<div data-impeccable-variants=\"{id}\" data-impeccable-variant-count=\"{count}\" {style_contents}>"),
            format!("{indent}  {} Original {}", comment_syntax.open, comment_syntax.close),
            format!("{indent}  <div data-impeccable-variant=\"original\">"),
            original_indented,
            format!("{indent}  </div>"),
            format!("{indent}  {} Variants: insert below this line {}", comment_syntax.open, comment_syntax.close),
            format!("{indent}</div>"),
            format!("{indent}{} impeccable-variants-end {id} {}", comment_syntax.open, comment_syntax.close),
        ]
    };

    let mut output_file = target_file.clone();
    let mut output_start_line = start_line + 1;
    let mut output_end_line = start_line + wrapper_lines.len() + (original_lines.len() - 1);
    let insert_line;
    let mut svelte_component_dir: Option<String> = None;
    let mut svelte_prop_contract: Option<Value> = None;

    if use_svelte_component {
        let input = ScaffoldSessionInput {
            id: &id,
            count: count as i64,
            source_file: &rel_target_file,
            source_start_line: start_line as i64 + 1,
            source_end_line: end_line as i64 + 1,
            original_lines: &original_lines,
        };
        let session = match scaffold_svelte_component_session(input, cwd) {
            Ok(s) => s,
            Err(err) => {
                return err_json(json!({ "error": format!("failed to scaffold svelte component session: {err}") }));
            }
        };
        output_file = cwd.join(&session.manifest_file);
        output_start_line = 1;
        output_end_line = 1;
        insert_line = 1;
        svelte_component_dir = Some(session.component_dir.clone());
        svelte_prop_contract = Some(Value::Array(
            session
                .prop_contract
                .iter()
                .map(|c| json!({ "prop": c.prop, "expr": c.expr, "placeholder": c.placeholder }))
                .collect(),
        ));
    } else {
        let mut new_lines: Vec<String> = Vec::with_capacity(lines.len());
        new_lines.extend(lines[..start_line].iter().cloned());
        new_lines.extend(wrapper_lines.iter().cloned());
        new_lines.extend(lines[end_line + 1..].iter().cloned());
        if let Err(err) = std::fs::write(&target_file, new_lines.join("\n")) {
            return err_json(json!({ "error": format!("failed to write {}: {err}", target_file.display()) }));
        }
        insert_line = start_line + 6 + (original_lines.len() - 1) + 1;
    }

    let output_rel_file = relative_slash(cwd, &output_file);
    let svelte_component_authoring = if use_svelte_component {
        let a = build_svelte_component_css_authoring(count as usize);
        Some(json!({
            "mode": a.mode,
            "strategy": a.strategy,
            "rulePattern": a.rule_pattern,
            "selectorExamples": a.selector_examples,
            "requirements": a.requirements,
            "forbidden": a.forbidden,
            "paramsFile": a.params_file,
        }))
    } else {
        None
    };

    let css_authoring = if use_svelte_component {
        svelte_component_authoring.clone().unwrap_or(Value::Null)
    } else {
        let a = build_css_authoring(&style_mode, count);
        json!({
            "mode": a.mode,
            "styleTag": a.style_tag,
            "strategy": a.strategy,
            "rulePattern": a.rule_pattern,
            "selectorExamples": a.selector_examples,
            "requirements": a.requirements,
            "forbidden": a.forbidden,
        })
    };

    let out = json!({
        "file": output_rel_file,
        "sourceFile": if use_svelte_component { Value::String(rel_target_file.clone()) } else { Value::Null },
        "previewMode": if use_svelte_component { Value::String("svelte-component".to_string()) } else { Value::Null },
        "componentDir": svelte_component_dir,
        "propContract": svelte_prop_contract,
        "sourceStartLine": if use_svelte_component { Value::from(start_line + 1) } else { Value::Null },
        "sourceEndLine": if use_svelte_component { Value::from(end_line + 1) } else { Value::Null },
        "startLine": output_start_line,
        "endLine": output_end_line,
        "insertLine": insert_line,
        "commentSyntax": { "open": comment_syntax.open, "close": comment_syntax.close },
        "styleMode": if use_svelte_component { "svelte-component".to_string() } else { style_mode.mode.to_string() },
        "styleTag": if use_svelte_component { Value::Null } else { Value::String(style_mode.style_tag.clone()) },
        "cssSelectorPrefixExamples": if use_svelte_component { Vec::<String>::new() } else { build_css_selector_prefix_examples(style_mode.mode, count) },
        "cssAuthoring": css_authoring,
        "originalLineCount": original_lines.len(),
    });

    (0, out.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("legion-wrap-cli-{}-{}", std::process::id(), n));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn help_flag_short_circuits() {
        let env = HashMap::new();
        let (code, out) = wrap_cli(&["--help".to_string()], Path::new("."), &env);
        assert_eq!(code, 0);
        assert!(out.contains("Usage: impeccable wrap"));
    }

    #[test]
    fn missing_id_errors() {
        let env = HashMap::new();
        let (code, out) = wrap_cli(&["--query".to_string(), "hero".to_string()], Path::new("."), &env);
        assert_eq!(code, 1);
        assert_eq!(out, "Missing --id");
    }

    #[test]
    fn missing_locator_errors() {
        let env = HashMap::new();
        let (code, out) = wrap_cli(&["--id".to_string(), "s1".to_string()], Path::new("."), &env);
        assert_eq!(code, 1);
        assert!(out.contains("Need at least one of"));
    }

    #[test]
    fn wraps_matched_element_in_place() {
        let dir = temp_dir();
        std::fs::write(
            dir.join("index.html"),
            "<div>\n  <section class=\"hero\">\n    <p>hi</p>\n  </section>\n</div>",
        )
        .unwrap();
        let env = HashMap::new();
        let args = vec![
            "--id".to_string(),
            "s1".to_string(),
            "--count".to_string(),
            "2".to_string(),
            "--file".to_string(),
            "index.html".to_string(),
            "--classes".to_string(),
            "hero".to_string(),
        ];
        let (code, out) = wrap_cli(&args, &dir, &env);
        assert_eq!(code, 0, "unexpected error output: {out}");
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["file"], "index.html");
        assert_eq!(parsed["originalLineCount"], 3);
        let content = std::fs::read_to_string(dir.join("index.html")).unwrap();
        assert!(content.contains("impeccable-variants-start s1"));
        assert!(content.contains("data-impeccable-variant=\"original\""));
    }

    #[test]
    fn element_not_found_reports_fallback() {
        let dir = temp_dir();
        std::fs::write(dir.join("index.html"), "<div>no match here</div>").unwrap();
        let env = HashMap::new();
        let args = vec![
            "--id".to_string(),
            "s1".to_string(),
            "--count".to_string(),
            "1".to_string(),
            "--file".to_string(),
            "index.html".to_string(),
            "--query".to_string(),
            "does-not-exist".to_string(),
        ];
        let (code, out) = wrap_cli(&args, &dir, &env);
        assert_eq!(code, 1);
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert!(parsed["error"].as_str().unwrap().contains("could not locate element"));
    }
}
