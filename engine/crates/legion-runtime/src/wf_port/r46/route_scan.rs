//! Port of `managed_rust_route_errors()`, `label_value()` (the label-lookup
//! helper it depends on), and the `MANAGED_RUST_TOOL_RE` scanner from
//! `src/lib/dispatch-validator/validate-dispatch.py` (lines ~837-930,
//! ~947-949).
//!
//! **Pitfall note**: the Python source's `MANAGED_RUST_TOOL_RE` uses
//! lookaround (`(?<!...)`/`(?!...)`) to assert that a matched tool name is
//! not itself part of a larger dotted/hyphenated/word-joined token. The
//! `regex` crate has no lookaround support, so [`find_tool_tokens`]
//! reimplements the same "not preceded/followed by a word/`.`/`-`
//! character" boundary check manually by inspecting the characters
//! immediately surrounding each plain `cargo|rustc|rustdoc` match.

use crate::wf_port::w2_045::path_utils::resolve_declared_path;
use regex::Regex;
use std::path::Path;
use std::sync::OnceLock;

fn fenced_block_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?s)```[^\n]*\n(.*?)\n```").unwrap())
}

fn inline_code_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"`([^`\n]+)`").unwrap())
}

fn label_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^-\s+\*\*[^*]+:\*\*\s*(.*)$").unwrap())
}

fn rust_tool_plain_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)cargo|rustc|rustdoc").unwrap())
}

fn rightkit_prefix_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    // Port of `(?:^|[\s;&|])rightkit\s+(?:build\s+)?$` (case-insensitive),
    // tested against the text preceding a matched tool token.
    RE.get_or_init(|| Regex::new(r"(?i)(?:^|[\s;&|])rightkit\s+(?:build\s+)?$").unwrap())
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Port of `label_value()`: the value on the first `- **{label}** ...` line
/// (Markdown list item whose text starts with the bold label), trimmed.
pub fn label_value(text: &str, label: &str) -> Option<String> {
    let pattern = format!(r"(?m)^-\s+{}\s*(.*)$", regex::escape(label));
    let re = Regex::new(&pattern).ok()?;
    re.captures(text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().trim().to_string())
}

/// Find every `cargo`/`rustc`/`rustdoc` token in `value` that is not itself
/// part of a larger word/`.`/`-`-joined token (the lookaround-free
/// reimplementation of `MANAGED_RUST_TOOL_RE`). Returns `(start, tool_lowercase)`.
fn find_tool_tokens(value: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for m in rust_tool_plain_re().find_iter(value) {
        let start = m.start();
        let end = m.end();
        let preceded_ok = match value[..start].chars().next_back() {
            Some(c) => !(is_word_char(c) || c == '.' || c == '-'),
            None => true,
        };
        let followed_ok = match value[end..].chars().next() {
            Some(c) => !(is_word_char(c) || c == '.' || c == '-'),
            None => true,
        };
        if preceded_ok && followed_ok {
            out.push((start, m.as_str().to_lowercase()));
        }
    }
    out
}

/// Port of `managed_rust_route_errors()`: reject executable Rust-tool
/// routes in `text` that bypass `rightkit`. `artifact_path` mirrors the
/// Python function's optional artifact path, used to resolve a
/// `**Goal route artifact:**` label into a GoalRoute JSON document when
/// `route_document` is not already supplied. `route_document`, when
/// supplied, mirrors the Python function's optional pre-parsed JSON
/// argument (tests should pass this instead of writing a route file to
/// disk).
pub fn managed_rust_route_errors(
    text: &str,
    artifact_path: Option<&Path>,
    route_document: Option<&serde_json::Value>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen: std::collections::BTreeSet<(String, String)> = std::collections::BTreeSet::new();

    let mut check = |value: &str, source: &str| {
        for (start, tool) in find_tool_tokens(value) {
            let prefix = &value[..start];
            if rightkit_prefix_re().is_match(prefix) {
                continue;
            }
            let key = (source.to_string(), tool.clone());
            if seen.insert(key) {
                errors.push(format!(
                    "managed Rust route violation in {source}: direct {tool} invocation must use rightkit {tool}"
                ));
            }
        }
    };

    for (index, m) in fenced_block_re().captures_iter(text).enumerate() {
        let body = m.get(1).map(|g| g.as_str()).unwrap_or("");
        check(body, &format!("fenced block {}", index + 1));
    }

    for (index, m) in inline_code_re().captures_iter(text).enumerate() {
        let body = m.get(1).map(|g| g.as_str()).unwrap_or("");
        check(body, &format!("inline code {}", index + 1));
    }

    for (line_number, line) in text.lines().enumerate() {
        let line_number = line_number + 1;
        if line.starts_with('|') {
            let trimmed = line.trim().trim_matches('|');
            for (cell_number, cell) in trimmed.split('|').enumerate() {
                check(cell.trim(), &format!("table cell {line_number}:{}", cell_number + 1));
            }
        }
        if let Some(caps) = label_line_re().captures(line) {
            let value = caps.get(1).map(|g| g.as_str()).unwrap_or("");
            check(value, &format!("label value {line_number}"));
        }
    }

    let owned_route_document: Option<serde_json::Value> = if route_document.is_none() {
        artifact_path.and_then(|artifact_path| {
            let route_value = label_value(text, "**Goal route artifact:**").unwrap_or_default();
            if route_value.is_empty() {
                return None;
            }
            let candidate = resolve_declared_path(&route_value, artifact_path);
            std::fs::read_to_string(&candidate)
                .ok()
                .and_then(|contents| serde_json::from_str::<serde_json::Value>(&contents).ok())
        })
    } else {
        None
    };
    let route_document: Option<&serde_json::Value> = route_document.or(owned_route_document.as_ref());

    if let Some(route_document) = route_document.and_then(|v| v.as_object()) {
        if let Some(proofs) = route_document
            .get("state_b")
            .and_then(|v| v.as_object())
            .and_then(|o| o.get("proof"))
            .and_then(|v| v.as_array())
        {
            for (index, proof) in proofs.iter().enumerate() {
                if let Some(command) = proof.get("command").and_then(|v| v.as_str()) {
                    check(command, &format!("GoalRoute state_b.proof[{}].command", index + 1));
                }
            }
        }
    }

    errors
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_direct_cargo_in_fenced_block() {
        let text = "```bash\ncargo test\n```\n";
        let errors = managed_rust_route_errors(text, None, None);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("fenced block 1"), "{errors:?}");
        assert!(errors[0].contains("direct cargo invocation must use rightkit cargo"), "{errors:?}");
    }

    #[test]
    fn allows_rightkit_prefixed_cargo() {
        let text = "```bash\nrightkit build cargo test\n```\n";
        let errors = managed_rust_route_errors(text, None, None);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn allows_rightkit_without_build_prefix() {
        let text = "```bash\nrightkit cargo test\n```\n";
        let errors = managed_rust_route_errors(text, None, None);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn ignores_tool_name_embedded_in_larger_token() {
        // "cargo-audit" and "my.rustc.wrapper" are not bare tool
        // invocations; the lookaround-free boundary check must reject them
        // just like the Python lookaround does.
        let text = "`cargo-audit run` and `my.rustc.wrapper x` are fine";
        let errors = managed_rust_route_errors(text, None, None);
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn detects_tool_in_inline_code_and_table_cell_and_label_value() {
        let text = "\
Use `cargo build` here.

| Command |
| --- |
| rustc --version |

- **Exact action / command:** rustdoc --version
";
        let errors = managed_rust_route_errors(text, None, None);
        assert_eq!(errors.len(), 3, "{errors:?}");
        assert!(errors.iter().any(|e| e.contains("inline code 1") && e.contains("cargo")));
        assert!(errors.iter().any(|e| e.contains("table cell") && e.contains("rustc")));
        assert!(errors.iter().any(|e| e.contains("label value") && e.contains("rustdoc")));
    }

    #[test]
    fn scans_goal_route_proof_commands_when_supplied() {
        let text = "no inline mentions here";
        let route = serde_json::json!({
            "state_b": {
                "proof": [
                    {"command": "cargo test --workspace"},
                ]
            }
        });
        let errors = managed_rust_route_errors(text, None, Some(&route));
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("GoalRoute state_b.proof[1].command"), "{errors:?}");
    }

    #[test]
    fn resolves_goal_route_artifact_label_from_disk() {
        let dir = std::env::temp_dir().join(format!(
            "legion-r46-route-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        let route_path = dir.join("route.json");
        std::fs::write(
            &route_path,
            serde_json::to_vec(&serde_json::json!({
                "state_b": {"proof": [{"command": "rustc main.rs"}]}
            }))
            .unwrap(),
        )
        .unwrap();
        let artifact_path = dir.join("dispatch.md");
        std::fs::write(&artifact_path, "x").unwrap();

        let text = "- **Goal route artifact:** route.json\n";
        let errors = managed_rust_route_errors(text, Some(&artifact_path), None);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("rustc"), "{errors:?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn label_value_reads_first_matching_list_item() {
        let text = "intro\n- **Goal route artifact:** path/to/route.json\nmore text\n";
        assert_eq!(
            label_value(text, "**Goal route artifact:**"),
            Some("path/to/route.json".to_string())
        );
        assert_eq!(label_value(text, "**Missing label:**"), None);
    }
}
