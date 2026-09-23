//! Faithful Rust port of `src/lib/gauntlet/lib/mutation.mjs`.
//!
//! For each added line in the diff, derive a candidate mutant by applying a
//! small syntactic transformation. Rerun the user-supplied test command
//! against the mutated source. A mutant that survives (test still passes)
//! proves the test cannot fail on that change.
//!
//! Mutators are applied in the same priority order as the JS `MUTATORS`
//! array: the first mutator whose `apply` changes the line wins. The JS
//! transformations are implemented here with hand-rolled string scanning
//! (no `regex` crate dependency is available to this chunk), matched to
//! behave identically on the shapes exercised by the gauntlet's own
//! fixtures (`if (x === 0) ...`, `return expr;`).

use std::fs;
use std::path::Path;
use std::process::Command;

use serde_json::{json, Value};

use super::diff::DiffFile;

#[derive(Debug, Clone)]
pub enum MutationResult {
    Skipped {
        file: String,
        line: Option<usize>,
        reason: &'static str,
    },
    NoMutator {
        file: String,
        line: usize,
        reason: &'static str,
    },
    Survived {
        file: String,
        line: usize,
        mutator: &'static str,
        exit_code: i32,
    },
    Killed {
        file: String,
        line: usize,
        mutator: &'static str,
        exit_code: Option<i32>,
        stderr_tail: String,
    },
}

impl MutationResult {
    pub fn status(&self) -> &'static str {
        match self {
            MutationResult::Skipped { .. } => "skipped",
            MutationResult::NoMutator { .. } => "no-mutator",
            MutationResult::Survived { .. } => "survived",
            MutationResult::Killed { .. } => "killed",
        }
    }

    pub fn mutator(&self) -> Option<&'static str> {
        match self {
            MutationResult::Survived { mutator, .. } | MutationResult::Killed { mutator, .. } => {
                Some(mutator)
            }
            _ => None,
        }
    }

    /// Serializes to the same flat-object shape JS's `results.push({...})`
    /// entries use — a `status` string field alongside `file`/`line`/etc,
    /// not an internally-tagged `kind` discriminant.
    pub fn to_value(&self) -> Value {
        match self {
            MutationResult::Skipped { file, line, reason } => json!({
                "file": file,
                "line": line,
                "status": "skipped",
                "reason": reason,
            }),
            MutationResult::NoMutator { file, line, reason } => json!({
                "file": file,
                "line": line,
                "status": "no-mutator",
                "reason": reason,
            }),
            MutationResult::Survived { file, line, mutator, exit_code } => json!({
                "file": file,
                "line": line,
                "mutator": mutator,
                "status": "survived",
                "exit_code": exit_code,
            }),
            MutationResult::Killed { file, line, mutator, exit_code, stderr_tail } => json!({
                "file": file,
                "line": line,
                "mutator": mutator,
                "status": "killed",
                "exit_code": exit_code,
                "stderr_tail": stderr_tail,
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MutationLayer {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub total: usize,
    pub ok: bool,
    pub results: Vec<MutationResult>,
}

const MUTATOR_ORDER: [&str; 5] = ["neq-flip", "or-swap", "neg-flip", "literal-zero", "string-empty"];

fn apply_mutator(id: &str, line: &str) -> Option<String> {
    match id {
        "neq-flip" => neq_flip(line),
        "or-swap" => or_swap(line),
        "neg-flip" => neg_flip(line),
        "literal-zero" => literal_zero(line),
        "string-empty" => string_empty(line),
        _ => None,
    }
}

fn find_mutator(line: &str) -> Option<&'static str> {
    for id in MUTATOR_ORDER {
        if let Some(mutated) = apply_mutator(id, line) {
            if mutated != line {
                return Some(id);
            }
        }
    }
    None
}

/// `line.replace(/(\b\w[\w.]*)\s*===\s*([^\n]+)/g, "$1!==$2")`.
///
/// Because the JS capture group `[^\n]+` is greedy to end-of-line, only the
/// first `===` occurrence on a line ever matters — everything after it is
/// consumed by the replacement's second group.
fn neq_flip(line: &str) -> Option<String> {
    let pos = line.find("===")?;
    let before = &line[..pos];
    let trimmed_before = before.trim_end();
    let ident_end = trimmed_before.len();
    let bytes = trimmed_before.as_bytes();
    let mut ident_start = ident_end;
    while ident_start > 0 {
        let c = bytes[ident_start - 1] as char;
        if c.is_alphanumeric() || c == '_' || c == '.' {
            ident_start -= 1;
        } else {
            break;
        }
    }
    if ident_start == ident_end {
        return None; // requires at least one identifier char (\b\w[\w.]*)
    }
    let prefix = &line[..ident_start];
    let ident = &trimmed_before[ident_start..];
    let mut after = pos + 3;
    let line_bytes = line.as_bytes();
    while after < line.len() && (line_bytes[after] as char).is_whitespace() {
        after += 1;
    }
    Some(format!("{prefix}{ident}!=={}", &line[after..]))
}

/// `line.replace(/&&/, "||")` — replaces only the first occurrence.
fn or_swap(line: &str) -> Option<String> {
    let pos = line.find("&&")?;
    let mut s = String::with_capacity(line.len());
    s.push_str(&line[..pos]);
    s.push_str("||");
    s.push_str(&line[pos + 2..]);
    Some(s)
}

fn find_return_keyword(line: &str) -> Option<usize> {
    let mut search_from = 0usize;
    while let Some(rel) = line[search_from..].find("return") {
        let idx = search_from + rel;
        let boundary_before = idx == 0
            || !line.as_bytes()[idx - 1].is_ascii_alphanumeric() && line.as_bytes()[idx - 1] != b'_';
        let after = idx + 6;
        let boundary_after =
            after >= line.len() || !(line.as_bytes()[after] as char).is_alphanumeric() && line.as_bytes()[after] != b'_';
        if boundary_before && boundary_after {
            return Some(idx);
        }
        search_from = idx + 6;
    }
    None
}

/// `line.replace(/(\breturn\s+)(.+)/, "$1!($2)")`.
fn neg_flip(line: &str) -> Option<String> {
    let idx = find_return_keyword(line)?;
    let after_kw = idx + 6;
    let bytes = line.as_bytes();
    let mut ws_end = after_kw;
    while ws_end < line.len() && (bytes[ws_end] as char).is_whitespace() {
        ws_end += 1;
    }
    if ws_end == after_kw || ws_end >= line.len() {
        return None; // requires \s+ then at least one char (.+)
    }
    Some(format!(
        "{}{}!({})",
        &line[..after_kw],
        &line[after_kw..ws_end],
        &line[ws_end..]
    ))
}

/// `line.replace(/(\breturn\s+)([0-9]+)/, "$10")`.
fn literal_zero(line: &str) -> Option<String> {
    let idx = find_return_keyword(line)?;
    let after_kw = idx + 6;
    let bytes = line.as_bytes();
    let mut ws_end = after_kw;
    while ws_end < line.len() && (bytes[ws_end] as char).is_whitespace() {
        ws_end += 1;
    }
    if ws_end == after_kw {
        return None;
    }
    let mut digit_end = ws_end;
    while digit_end < line.len() && (bytes[digit_end] as char).is_ascii_digit() {
        digit_end += 1;
    }
    if digit_end == ws_end {
        return None;
    }
    Some(format!("{}0{}", &line[..ws_end], &line[digit_end..]))
}

/// `line.replace(/(\breturn\s+)(['"` + "`" + r#"])([^\n'"]*)\2/, "$1$2$2")`.
fn string_empty(line: &str) -> Option<String> {
    let idx = find_return_keyword(line)?;
    let after_kw = idx + 6;
    let bytes = line.as_bytes();
    let mut ws_end = after_kw;
    while ws_end < line.len() && (bytes[ws_end] as char).is_whitespace() {
        ws_end += 1;
    }
    if ws_end == after_kw || ws_end >= line.len() {
        return None;
    }
    let quote = bytes[ws_end] as char;
    if quote != '\'' && quote != '"' && quote != '`' {
        return None;
    }
    let content_start = ws_end + 1;
    let mut close = content_start;
    while close < line.len() {
        let c = line.as_bytes()[close] as char;
        if c == quote {
            break;
        }
        if c == '\'' || c == '"' {
            close += 1;
            continue;
        }
        close += 1;
    }
    if close >= line.len() || line.as_bytes()[close] as char != quote {
        return None; // unterminated
    }
    Some(format!(
        "{}{quote}{quote}{}",
        &line[..ws_end],
        &line[close + 1..]
    ))
}

pub struct RunMutationOptions<'a> {
    pub cwd: &'a Path,
    pub files: &'a [DiffFile],
    pub test_command: &'a str,
}

/// Mirrors `runMutation({ cwd, files, testCommand })`.
pub fn run_mutation(opts: RunMutationOptions<'_>) -> MutationLayer {
    let mut results: Vec<MutationResult> = Vec::new();
    for file in opts.files {
        let path = opts.cwd.join(&file.path);
        if !path.exists() {
            results.push(MutationResult::Skipped {
                file: file.path.clone(),
                line: None,
                reason: "missing_locator",
            });
            continue;
        }
        let original = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(_) => {
                results.push(MutationResult::Skipped {
                    file: file.path.clone(),
                    line: None,
                    reason: "missing_locator",
                });
                continue;
            }
        };
        let source_lines: Vec<&str> = original.split('\n').collect();
        for &line_no in &file.lines {
            if line_no == 0 || line_no > source_lines.len() {
                results.push(MutationResult::Skipped {
                    file: file.path.clone(),
                    line: Some(line_no),
                    reason: "out_of_range",
                });
                continue;
            }
            let idx = line_no - 1;
            let line = source_lines[idx];
            let Some(mutator) = find_mutator(line) else {
                results.push(MutationResult::NoMutator {
                    file: file.path.clone(),
                    line: line_no,
                    reason: "syntactic_shape_unhandled",
                });
                continue;
            };
            let mutated_line = apply_mutator(mutator, line).unwrap();
            let mut mutated_lines: Vec<String> = source_lines.iter().map(|s| s.to_string()).collect();
            mutated_lines[idx] = mutated_line;
            let mutated_source = mutated_lines.join("\n");

            fs::write(&path, &mutated_source).expect("write mutated source");
            let result = Command::new("sh")
                .arg("-c")
                .arg(opts.test_command)
                .current_dir(opts.cwd)
                .output();
            // Restore — never leave a mutated source behind.
            fs::write(&path, &original).expect("restore original source");

            match result {
                Ok(output) => {
                    let survived = output.status.success();
                    if survived {
                        results.push(MutationResult::Survived {
                            file: file.path.clone(),
                            line: line_no,
                            mutator,
                            exit_code: 0,
                        });
                    } else {
                        let stderr_tail = tail(&String::from_utf8_lossy(&output.stderr), 200);
                        results.push(MutationResult::Killed {
                            file: file.path.clone(),
                            line: line_no,
                            mutator,
                            exit_code: output.status.code(),
                            stderr_tail,
                        });
                    }
                }
                Err(e) => {
                    results.push(MutationResult::Killed {
                        file: file.path.clone(),
                        line: line_no,
                        mutator,
                        exit_code: None,
                        stderr_tail: format!("spawn failed: {e}"),
                    });
                }
            }
        }
    }

    let survived = results.iter().filter(|r| r.status() == "survived").count();
    let killed = results.iter().filter(|r| r.status() == "killed").count();
    let skipped = results
        .iter()
        .filter(|r| r.status() == "skipped" || r.status() == "no-mutator")
        .count();
    MutationLayer {
        passed: killed,
        failed: survived,
        skipped,
        total: results.len(),
        ok: survived == 0,
        results,
    }
}

fn tail(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        s[s.len() - max..].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neq_flip_matches_js_regex_shape() {
        assert_eq!(
            neq_flip("  if (v === 0) continue;"),
            Some("  if (v!==0) continue;".to_string())
        );
        assert_eq!(
            neq_flip("  if (values.length === 0) return 0;"),
            Some("  if (values.length!==0) return 0;".to_string())
        );
        assert_eq!(neq_flip("no operator here"), None);
    }

    #[test]
    fn neg_flip_wraps_rest_of_return() {
        assert_eq!(
            neg_flip("  return sum(values) / values.length;"),
            Some("  return !(sum(values) / values.length;)".to_string())
        );
    }

    #[test]
    fn find_mutator_prefers_neq_flip_over_neg_flip() {
        assert_eq!(
            find_mutator("  if (values.length === 0) return 0;"),
            Some("neq-flip")
        );
        assert_eq!(
            find_mutator("  return sum(values) / values.length;"),
            Some("neg-flip")
        );
        assert_eq!(find_mutator("}"), None);
    }
}
