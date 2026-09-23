//! Port of `research-core/effects.py`: classify Research effects for
//! internal callers (worker vs. external-network tool calls).
//!
//! The Python uses a compiled regex for `NETWORK_COMMAND`. This crate does
//! not currently depend on the `regex` crate (see the packet report for the
//! Cargo.toml patch to add it), so the network-command detector below is a
//! hand-rolled equivalent: split on `;`/`&`/`|` into segments, trim leading
//! whitespace, and match each segment against the same command prefixes
//! with the same word-boundary semantics (`\b` after the matched prefix).

const WORKER_NAMES: [&str; 3] = ["agent", "task", "workflow"];
const EXTERNAL_NAMES: [&str; 6] = [
    "websearch",
    "webfetch",
    "web.search",
    "web.open",
    "web.find",
    "web.run",
];

/// `effects.normalized`.
pub fn normalized(tool: &str) -> String {
    tool.trim().to_lowercase()
}

/// `effects.is_worker`.
pub fn is_worker(tool: &str) -> bool {
    let name = normalized(tool);
    if WORKER_NAMES.contains(&name.as_str()) {
        return true;
    }
    name.starts_with("mcp__") && name.split("__").any(|part| WORKER_NAMES.contains(&part))
}

/// `effects.is_external`. `tool_input` mirrors the Python's
/// `tool_input.get("command", tool_input.get("cmd", ""))`, accepting either
/// a plain string or a list of strings joined with spaces.
pub fn is_external(tool: &str, command: Option<&str>) -> bool {
    let name = normalized(tool);
    if EXTERNAL_NAMES.contains(&name.as_str()) {
        return true;
    }
    if name.starts_with("mcp__") {
        return !is_worker(tool);
    }
    if matches!(
        name.as_str(),
        "bash" | "shell" | "terminal" | "exec" | "container.exec"
    ) {
        return command.map(is_network_command).unwrap_or(false);
    }
    false
}

/// The prefixes `NETWORK_COMMAND` matches, each followed by a `\b` word
/// boundary in the Python regex. Each entry's tokens must appear
/// contiguously separated by the given inter-token pattern (`\s+`).
const NETWORK_PREFIXES: &[&[&str]] = &[
    &["curl"],
    &["wget"],
    &["aria2c"],
    &["git", "clone"],
    &["git", "fetch"],
    &["git", "pull"],
    &["git", "ls-remote"],
    &["gh", "api"],
    &["npm", "install"],
    &["npm", "view"],
    &["npm", "search"],
    &["pnpm", "install"],
    &["pnpm", "view"],
    &["pip", "install"],
    &["python", "-m", "pip", "install"],
];

fn is_network_command(command: &str) -> bool {
    // The Python regex is anchored at `^` or after `[;&|]\s*`, so split the
    // full command into segments on those separators and test each segment
    // from its start (after leading whitespace), case-insensitively.
    for segment in split_command_segments(command) {
        let lower = segment.to_lowercase();
        let trimmed = lower.trim_start();
        for prefix in NETWORK_PREFIXES {
            if segment_starts_with_tokens(trimmed, prefix) {
                return true;
            }
        }
    }
    false
}

fn split_command_segments(command: &str) -> Vec<&str> {
    let mut segments = Vec::new();
    let mut start = 0;
    let bytes = command.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if *b == b';' || *b == b'&' || *b == b'|' {
            segments.push(&command[start..i]);
            start = i + 1;
        }
    }
    segments.push(&command[start..]);
    segments
}

/// True if `text` starts with `tokens` joined by whitespace, followed by a
/// word boundary (end of string, or a non-word character).
fn segment_starts_with_tokens(text: &str, tokens: &[&str]) -> bool {
    let mut rest = text;
    for (i, tok) in tokens.iter().enumerate() {
        if !rest.starts_with(tok) {
            return false;
        }
        rest = &rest[tok.len()..];
        if i + 1 < tokens.len() {
            let consumed = rest.len() - rest.trim_start().len();
            if consumed == 0 {
                return false;
            }
            rest = rest.trim_start();
        }
    }
    // \b boundary: next char (if any) must not be a "word" char (alnum or `_`).
    match rest.chars().next() {
        None => true,
        Some(c) => !(c.is_alphanumeric() || c == '_'),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_names_and_mcp_wrapped() {
        assert!(is_worker("Task"));
        assert!(is_worker("agent"));
        assert!(is_worker("mcp__legion__task"));
        assert!(!is_worker("bash"));
    }

    #[test]
    fn external_names() {
        assert!(is_external("WebSearch", None));
        assert!(is_external("web.open", None));
    }

    #[test]
    fn mcp_non_worker_is_external() {
        assert!(is_external("mcp__legion__search", None));
        assert!(!is_external("mcp__legion__task", None));
    }

    #[test]
    fn bash_with_network_command_is_external() {
        assert!(is_external("bash", Some("curl https://example.test")));
        assert!(is_external("bash", Some("cd /tmp && wget https://example.test")));
        assert!(is_external("bash", Some("git clone https://example.test/repo.git")));
        assert!(is_external("bash", Some("pip install requests")));
        assert!(is_external("bash", Some("python -m pip install requests")));
    }

    #[test]
    fn bash_without_network_command_is_not_external() {
        assert!(!is_external("bash", Some("ls -la")));
        assert!(!is_external("bash", Some("echo curling along")));
        assert!(!is_external("bash", None));
    }

    #[test]
    fn unrelated_tool_is_not_external() {
        assert!(!is_external("Read", Some("curl https://example.test")));
    }
}
