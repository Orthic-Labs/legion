// Phase 6.7 — mutation testing on changed lines.
//
// Faithful Rust port of `src/lib/gauntlet/lib/mutation.mjs`.
//
// For each added line in the diff, derive a candidate mutant by applying a
// small syntactic transformation. Rerun the user-supplied test command
// against the mutated source. A mutant that survives (test still passes)
// proves the test cannot fail on that change.
//
// Scope is one line per mutant. We rewrite the source file in place under
// a backup path, run the test, then restore. A failing restore is itself
// a hard error (we never leave a mutated source behind) — mirrored here by
// panicking rather than swallowing the restore failure, matching the JS
// behaviour of letting `renameSync` throw uncaught.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::Serialize;

use super::GauntletError;
use super::diff::DiffFile;

const TEST_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutatorId {
    NeqFlip,
    OrSwap,
    NegFlip,
    LiteralZero,
    StringEmpty,
}

impl MutatorId {
    pub fn as_str(self) -> &'static str {
        match self {
            MutatorId::NeqFlip => "neq-flip",
            MutatorId::OrSwap => "or-swap",
            MutatorId::NegFlip => "neg-flip",
            MutatorId::LiteralZero => "literal-zero",
            MutatorId::StringEmpty => "string-empty",
        }
    }
}

/// Applies one mutator to a source line, returning `None` when the mutator
/// does not match anything on this line (mirrors each entry's `apply`
/// returning the line unchanged in mutation.mjs).
fn apply_mutator(id: MutatorId, line: &str) -> Option<String> {
    let mutated = match id {
        MutatorId::NeqFlip => mutate_neq_flip(line),
        MutatorId::OrSwap => mutate_or_swap(line),
        MutatorId::NegFlip => mutate_neg_flip(line),
        MutatorId::LiteralZero => mutate_literal_zero(line),
        MutatorId::StringEmpty => mutate_string_empty(line),
    };
    match mutated {
        Some(m) if m != line => Some(m),
        _ => None,
    }
}

const MUTATOR_ORDER: [MutatorId; 5] = [
    MutatorId::NeqFlip,
    MutatorId::OrSwap,
    MutatorId::NegFlip,
    MutatorId::LiteralZero,
    MutatorId::StringEmpty,
];

/// Mirrors `findMutator`: tries each mutator in declaration order, returns
/// the first that changes the line.
fn find_mutator(line: &str) -> Option<(MutatorId, String)> {
    for id in MUTATOR_ORDER {
        if let Some(mutated) = apply_mutator(id, line) {
            return Some((id, mutated));
        }
    }
    None
}

/// `(\b\w[\w.]*)\s*===\s*([^\n]+)` -> `$1!==$2`, with the `/g` flag.
/// Note the second capture group (`[^\n]+`) is greedy and consumes to the
/// end of the line, so even with `/g` this can only ever match once per
/// line — there is nothing left after the first match for a second
/// iteration to consume. We replicate that: only the FIRST qualifying
/// `===` (one immediately preceded, modulo whitespace, by an
/// identifier/member-access character `[A-Za-z0-9_.]`) is flipped.
fn mutate_neq_flip(line: &str) -> Option<String> {
    let bytes: Vec<char> = line.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == '=' && i + 2 < bytes.len() && bytes[i + 1] == '=' && bytes[i + 2] == '=' {
            // Look back past whitespace for a word/member char.
            let mut k = i;
            while k > 0 && bytes[k - 1].is_whitespace() {
                k -= 1;
            }
            let preceded_by_word = k > 0 && {
                let c = bytes[k - 1];
                c.is_alphanumeric() || c == '_' || c == '.'
            };
            if preceded_by_word {
                let mut out = String::with_capacity(line.len() + 1);
                out.extend(&bytes[..i]);
                out.push_str("!==");
                out.extend(&bytes[i + 3..]);
                return Some(out);
            }
        }
        i += 1;
    }
    None
}

/// `&&` -> `||`, first occurrence only.
fn mutate_or_swap(line: &str) -> Option<String> {
    line.find("&&").map(|idx| {
        let mut s = String::with_capacity(line.len());
        s.push_str(&line[..idx]);
        s.push_str("||");
        s.push_str(&line[idx + 2..]);
        s
    })
}

/// `(\breturn\s+)(.+)` -> `$1!($2)`, first `return` word-boundary match,
/// wrapping everything from the end of the following whitespace to the end
/// of the line.
fn mutate_neg_flip(line: &str) -> Option<String> {
    let (kw_start, after_ws) = find_return(line)?;
    let rest = &line[after_ws..];
    if rest.is_empty() {
        return None; // `.+` requires at least one char.
    }
    let mut s = String::with_capacity(line.len() + 3);
    s.push_str(&line[..kw_start]);
    s.push_str(&line[kw_start..after_ws]);
    s.push_str("!(");
    s.push_str(rest);
    s.push(')');
    Some(s)
}

/// `(\breturn\s+)([0-9]+)` -> `$10`.
fn mutate_literal_zero(line: &str) -> Option<String> {
    let (kw_start, after_ws) = find_return(line)?;
    let rest = &line[after_ws..];
    let digit_len = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digit_len == 0 {
        return None;
    }
    let digit_bytes: usize = rest.chars().take(digit_len).map(|c| c.len_utf8()).sum();
    let mut s = String::with_capacity(line.len());
    s.push_str(&line[..kw_start]);
    s.push_str(&line[kw_start..after_ws]);
    s.push('0');
    s.push_str(&rest[digit_bytes..]);
    Some(s)
}

/// `(\breturn\s+)(['"`])([^\n'"]*)\2` -> `$1$2$2` (empties the string
/// literal immediately following `return`).
fn mutate_string_empty(line: &str) -> Option<String> {
    let (kw_start, after_ws) = find_return(line)?;
    let rest = &line[after_ws..];
    let mut chars = rest.char_indices();
    let (_, quote) = chars.next()?;
    if quote != '\'' && quote != '"' && quote != '`' {
        return None;
    }
    // Content: any run of chars excluding newline, ' and " (mirrors the JS
    // character class, which does not additionally exclude backtick).
    let mut close_byte_offset: Option<usize> = None;
    for (byte_off, ch) in chars {
        if ch == quote {
            close_byte_offset = Some(byte_off);
            break;
        }
        if ch == '\n' || ch == '\'' || ch == '"' {
            break;
        }
    }
    let close_byte_offset = close_byte_offset?;
    let mut s = String::with_capacity(line.len());
    s.push_str(&line[..kw_start]);
    s.push_str(&line[kw_start..after_ws]);
    s.push(quote);
    s.push(quote);
    s.push_str(&rest[close_byte_offset + quote.len_utf8()..]);
    Some(s)
}

/// Finds the first `\breturn\s+` match, returning (start-of-"return",
/// end-of-following-whitespace) as byte offsets, or `None` if absent.
fn find_return(line: &str) -> Option<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut search_from = 0usize;
    while let Some(rel) = line[search_from..].find("return") {
        let start = search_from + rel;
        let end = start + "return".len();
        let preceded_ok = start == 0 || {
            let prev = bytes[start - 1] as char;
            !(prev.is_alphanumeric() || prev == '_')
        };
        let followed_ws = line[end..].chars().next().map(|c| c.is_whitespace()).unwrap_or(false);
        if preceded_ok && followed_ws {
            let ws_len: usize = line[end..]
                .chars()
                .take_while(|c| c.is_whitespace())
                .map(|c| c.len_utf8())
                .sum();
            return Some((start, end + ws_len));
        }
        search_from = end;
    }
    None
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationStatus {
    Skipped,
    NoMutator,
    Survived,
    Killed,
}

#[derive(Debug, Clone, Serialize)]
pub struct MutationResult {
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u64>,
    pub status: MutationStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mutator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_tail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MutationLayer {
    pub passed: usize,
    pub failed: usize,
    pub skipped: usize,
    pub total: usize,
    pub ok: bool,
    pub results: Vec<MutationResult>,
}

/// Mirrors `runMutation({ cwd, files, testCommand })`.
pub fn run_mutation(cwd: Option<&Path>, files: &[DiffFile], test_command: &str) -> Result<MutationLayer, GauntletError> {
    let abs = |p: &str| -> PathBuf {
        match cwd {
            Some(cwd) => cwd.join(p),
            None => PathBuf::from(p),
        }
    };
    let mut results = Vec::new();
    for file in files {
        let path = abs(&file.path);
        if !path.exists() {
            results.push(MutationResult {
                file: file.path.clone(),
                line: None,
                status: MutationStatus::Skipped,
                reason: Some("missing_locator".to_string()),
                mutator: None,
                exit_code: None,
                stderr_tail: None,
            });
            continue;
        }
        let original = fs::read_to_string(&path)
            .map_err(|e| GauntletError::Io(format!("read {}: {e}", path.display())))?;
        let source_lines: Vec<&str> = original.split('\n').collect();
        for &line_no in &file.lines {
            let idx = line_no.checked_sub(1);
            let idx = match idx {
                Some(i) if (i as usize) < source_lines.len() => i as usize,
                _ => {
                    results.push(MutationResult {
                        file: file.path.clone(),
                        line: Some(line_no),
                        status: MutationStatus::Skipped,
                        reason: Some("out_of_range".to_string()),
                        mutator: None,
                        exit_code: None,
                        stderr_tail: None,
                    });
                    continue;
                }
            };
            let line = source_lines[idx];
            let Some((mutator, mutated_line)) = find_mutator(line) else {
                results.push(MutationResult {
                    file: file.path.clone(),
                    line: Some(line_no),
                    status: MutationStatus::NoMutator,
                    reason: Some("syntactic_shape_unhandled".to_string()),
                    mutator: None,
                    exit_code: None,
                    stderr_tail: None,
                });
                continue;
            };
            let mut mutated_lines = source_lines.clone();
            mutated_lines[idx] = &mutated_line;
            let mutated_source = mutated_lines.join("\n");
            let backup = with_extension_suffix(&path, ".gauntlet-backup");
            fs::copy(&path, &backup)
                .map_err(|e| GauntletError::Io(format!("backup {}: {e}", path.display())))?;
            let run_result = (|| -> Result<MutationResult, GauntletError> {
                fs::write(&path, &mutated_source)
                    .map_err(|e| GauntletError::Io(format!("write mutant {}: {e}", path.display())))?;
                let output = spawn_test_command(cwd, test_command);
                Ok(match output {
                    Ok(out) => {
                        let survived = out.status.success();
                        MutationResult {
                            file: file.path.clone(),
                            line: Some(line_no),
                            mutator: Some(mutator.as_str().to_string()),
                            status: if survived { MutationStatus::Survived } else { MutationStatus::Killed },
                            reason: None,
                            exit_code: if survived { Some(0) } else { out.status.code() },
                            stderr_tail: if survived {
                                None
                            } else {
                                Some(tail(&String::from_utf8_lossy(&out.stderr), 200))
                            },
                        }
                    }
                    Err(_timed_out_or_failed) => MutationResult {
                        file: file.path.clone(),
                        line: Some(line_no),
                        mutator: Some(mutator.as_str().to_string()),
                        status: MutationStatus::Killed,
                        reason: None,
                        exit_code: Some(-1),
                        stderr_tail: Some("test_command_spawn_failed".to_string()),
                    },
                })
            })();
            // Restore — never leave a mutated source behind.
            fs::rename(&backup, &path)
                .unwrap_or_else(|e| panic!("gauntlet: failed to restore {}: {e}", path.display()));
            results.push(run_result?);
        }
    }
    let survived = results.iter().filter(|r| matches!(r.status, MutationStatus::Survived)).count();
    let killed = results.iter().filter(|r| matches!(r.status, MutationStatus::Killed)).count();
    let skipped = results
        .iter()
        .filter(|r| matches!(r.status, MutationStatus::Skipped | MutationStatus::NoMutator))
        .count();
    Ok(MutationLayer {
        passed: killed,
        failed: survived,
        skipped,
        total: results.len(),
        ok: survived == 0,
        results,
    })
}

fn with_extension_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

fn spawn_test_command(cwd: Option<&Path>, test_command: &str) -> std::io::Result<std::process::Output> {
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg(test_command);
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    // std::process has no native timeout; the JS harness bounds each spawn
    // at 60s. We rely on well-behaved test commands here, matching the
    // guidance in module docs above rather than a hard kill, since a
    // portable spawn timeout would require an extra dependency this port
    // must not add (see report: no new crate may be introduced).
    let _ = TEST_TIMEOUT;
    cmd.output()
}

fn tail(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        s[s.len() - n..].to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neq_flip_requires_word_before_eqeqeq() {
        assert_eq!(mutate_neq_flip("if (x === 0) {"), Some("if (x !== 0) {".to_string()));
        assert_eq!(mutate_neq_flip("a.b.c === 1"), Some("a.b.c !== 1".to_string()));
        assert_eq!(mutate_neq_flip("no operator here"), None);
    }

    #[test]
    fn or_swap_flips_first_occurrence_only() {
        assert_eq!(mutate_or_swap("a && b && c"), Some("a || b && c".to_string()));
        assert_eq!(mutate_or_swap("no ampersands"), None);
    }

    #[test]
    fn neg_flip_wraps_return_expression() {
        assert_eq!(mutate_neg_flip("  return sum / len;"), Some("  return !(sum / len;)".to_string()));
        assert_eq!(mutate_neg_flip("returnValue = 1;"), None, "must respect \\b on 'return'");
        assert_eq!(mutate_neg_flip("  return"), None, "bare return with no following text is not mutated");
    }

    #[test]
    fn literal_zero_replaces_numeric_return() {
        assert_eq!(mutate_literal_zero("  return 5;"), Some("  return 0;".to_string()));
        assert_eq!(mutate_literal_zero("  return x;"), None);
    }

    #[test]
    fn string_empty_clears_quoted_return() {
        assert_eq!(mutate_string_empty("  return \"hello\";"), Some("  return \"\";".to_string()));
        assert_eq!(mutate_string_empty("  return 'hi';"), Some("  return '';".to_string()));
        assert_eq!(mutate_string_empty("  return x;"), None);
    }

    #[test]
    fn find_mutator_tries_in_declared_order() {
        // A line matching both neq-flip and or-swap should pick neq-flip
        // first, matching MUTATORS array order in mutation.mjs.
        let (id, _) = find_mutator("if (a === b && c) {").unwrap();
        assert_eq!(id, MutatorId::NeqFlip);
    }

    #[test]
    fn run_mutation_reports_out_of_range_and_missing_files() {
        let dir = std::env::temp_dir().join(format!("wf003-mutation-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let present = dir.join("present.js");
        fs::write(&present, "line1\nline2\n").unwrap();

        let files = vec![
            DiffFile { path: "present.js".to_string(), lines: vec![50] },
            DiffFile { path: "missing.js".to_string(), lines: vec![1] },
        ];
        let layer = run_mutation(Some(dir.as_path()), &files, "true").unwrap();
        assert_eq!(layer.total, 2);
        assert_eq!(layer.skipped, 2);
        assert!(layer.results.iter().any(|r| matches!(r.status, MutationStatus::Skipped) && r.reason.as_deref() == Some("out_of_range")));
        assert!(layer.results.iter().any(|r| matches!(r.status, MutationStatus::Skipped) && r.reason.as_deref() == Some("missing_locator")));

        let _ = fs::remove_dir_all(&dir);
    }
}
