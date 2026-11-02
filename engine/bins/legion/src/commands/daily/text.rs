//! Text matching helpers for `legion daily`: the correction markers ported from
//! the failure-review `markers.py`, redaction, and small string utilities. No
//! regex dependency: each marker is a phrase with an explicit boundary rule.

pub fn is_word(character: char) -> bool {
    character.is_alphanumeric() || character == '_'
}

/// Collapse whitespace and cut to `max` characters (with an ellipsis).
pub fn clip(text: &str, max: usize) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() <= max {
        return flat;
    }
    let mut out: String = flat.chars().take(max).collect();
    out.push('\u{2026}');
    out
}

/// Lowercase ASCII slug of at most `max` characters.
pub fn slugify(text: &str, max: usize) -> String {
    let mut out = String::new();
    let mut pending_dash = false;
    for character in text.chars() {
        if character.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(character.to_ascii_lowercase());
        } else {
            pending_dash = true;
        }
    }
    out.truncate(max);
    out.trim_end_matches('-').to_owned()
}

/// How a phrase must end to match.
#[derive(Clone, Copy)]
pub enum End {
    /// Nothing after the phrase is checked.
    Open,
    /// The next character must not be a word character.
    Word,
    /// At least one word character must follow (`ignor\w+`).
    Tail,
    /// The next character must be one of these.
    Set(&'static str),
}

/// A phrase matches at a word start (the previous character is not a word
/// character) and satisfies its end rule. `lower` must already be lowercase.
pub fn phrase_at_boundaries(lower: &str, phrase: &str, end: End) -> bool {
    for (start, _) in lower.match_indices(phrase) {
        let before_ok = lower[..start]
            .chars()
            .next_back()
            .is_none_or(|character| !is_word(character));
        if !before_ok {
            continue;
        }
        let rest = &lower[start + phrase.len()..];
        let next = rest.chars().next();
        let end_ok = match end {
            End::Open => true,
            End::Word => next.is_none_or(|character| !is_word(character)),
            End::Tail => next.is_some_and(is_word),
            End::Set(set) => next.is_some_and(|character| set.contains(character)),
        };
        if end_ok {
            return true;
        }
    }
    false
}

/// A keyword from the bucket map: a trailing `*` allows a word tail
/// (`authoriz*` matches `authorized`), otherwise the word must end.
pub fn phrase_match(lower: &str, key: &str) -> bool {
    match key.strip_suffix('*') {
        Some(stem) => phrase_at_boundaries(lower, stem, End::Open),
        None => phrase_at_boundaries(lower, key, End::Word),
    }
}

const PROFANITY: &[(&str, End)] = &[
    ("fuck", End::Open),
    ("shit", End::Open),
    ("wtf", End::Word),
    ("ffs", End::Word),
    ("bullshit", End::Word),
    ("crap", End::Word),
    ("idiot", End::Open),
    ("stupid", End::Word),
    ("useless", End::Word),
    ("dumb", End::Word),
    ("moron", End::Word),
    ("garbage", End::Word),
    ("pathetic", End::Word),
    ("ridiculous", End::Word),
    ("lazy", End::Word),
];

const CORRECTIONS: &[(&str, End)] = &[
    ("i told you", End::Open),
    ("i said", End::Open),
    ("i asked", End::Open),
    ("i already", End::Open),
    ("again", End::Word),
    ("still", End::Word),
    ("why did", End::Open),
    ("why are", End::Open),
    ("why is", End::Open),
    ("why would", End::Open),
    ("why the", End::Open),
    ("why do", End::Open),
    ("why didn", End::Open),
    ("why haven", End::Open),
    ("why aren", End::Open),
    ("stop", End::Word),
    ("don't", End::Word),
    ("dont", End::Word),
    ("don\u{2019}t", End::Word),
    ("didn't", End::Word),
    ("didnt", End::Word),
    ("didn\u{2019}t", End::Word),
    ("not what", End::Open),
    ("wrong", End::Open),
    ("lie", End::Word),
    ("lies", End::Word),
    ("lied", End::Word),
    ("lying", End::Open),
    ("claimed", End::Open),
    ("false", End::Word),
    ("never", End::Word),
    ("how many times", End::Open),
    ("what the", End::Open),
    ("seriously", End::Open),
    ("you were supposed", End::Open),
    ("supposed to", End::Open),
    ("instead of", End::Open),
    ("who told you", End::Open),
    ("without my", End::Open),
    ("without asking", End::Open),
    ("i never", End::Open),
    ("no", End::Set(",.! ")),
    ("nope", End::Open),
    ("ignor", End::Tail),
    ("forgot", End::Open),
    ("keep doing", End::Open),
    ("keep making", End::Open),
    ("waste", End::Open),
];

/// Which marker family a user turn matched, if any (`markers.py`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Marker {
    Profanity,
    Correction,
}

pub fn correction_marker(text: &str) -> Option<Marker> {
    let lower = text.to_lowercase();
    if PROFANITY
        .iter()
        .any(|(phrase, end)| phrase_at_boundaries(&lower, phrase, *end))
    {
        return Some(Marker::Profanity);
    }
    if CORRECTIONS
        .iter()
        .any(|(phrase, end)| phrase_at_boundaries(&lower, phrase, *end))
    {
        return Some(Marker::Correction);
    }
    None
}

/// Text the host injects as a "user" turn; not Adrian's words.
pub fn is_injected(text: &str) -> bool {
    let trimmed = text.trim_start();
    [
        "<command-",
        "<local-command",
        "<task-notification",
        "<system-reminder",
        "<side-sessions-event",
        "<ci-monitor-event",
        "<user-prompt-submit-hook",
        "<environment_context",
        "<user_instructions",
        "<turn_aborted",
        "<subagent_notification",
        "Caveat:",
        "[SYSTEM NOTIFICATION",
        "[Request interrupted",
        "This session is being continued",
        "# AGENTS.md",
    ]
    .iter()
    .any(|prefix| trimmed.starts_with(prefix))
}

fn looks_secret(word: &str) -> bool {
    let core = word.trim_matches(|character: char| {
        !character.is_ascii_alphanumeric() && character != '_' && character != '-'
    });
    if core.len() < 20 {
        return false;
    }
    let lower = core.to_ascii_lowercase();
    if [
        "sk-",
        "ghp_",
        "gho_",
        "ghs_",
        "github_pat_",
        "xoxb-",
        "xoxp-",
        "akia",
    ]
    .iter()
    .any(|prefix| lower.starts_with(prefix))
    {
        return true;
    }
    let all_hex = core
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() || byte == b'-');
    let has_digit = core.bytes().any(|byte| byte.is_ascii_digit());
    let has_upper = core.bytes().any(|byte| byte.is_ascii_uppercase());
    let has_lower = core.bytes().any(|byte| byte.is_ascii_lowercase());
    core.len() >= 32 && !all_hex && has_digit && has_upper && has_lower && !core.contains('/')
}

/// Mask token-like words so a quote filed in an issue cannot leak a secret.
pub fn redact(text: &str) -> String {
    text.split_whitespace()
        .map(|word| {
            if looks_secret(word) {
                "[redacted]"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Every `ARC_*` code in `text`, in order of first appearance.
pub fn arc_codes(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (index, _) in text.match_indices("ARC_") {
        let glued = text[..index]
            .chars()
            .next_back()
            .is_some_and(|character| character.is_ascii_alphanumeric() || character == '_');
        if glued {
            continue;
        }
        let code: String = text[index..]
            .chars()
            .take_while(|character| {
                character.is_ascii_uppercase() || character.is_ascii_digit() || *character == '_'
            })
            .collect();
        let code = code.trim_end_matches('_').to_owned();
        if code.len() > 4 && !out.contains(&code) {
            out.push(code);
        }
    }
    out
}

/// The `name` of a `[HOOK:name:block]` denial, if `text` carries one.
pub fn hook_block_name(text: &str) -> Option<String> {
    let start = text.find("[HOOK:")? + "[HOOK:".len();
    let rest = &text[start..];
    let end = rest.find(":block]")?;
    let name = &rest[..end];
    let valid = !name.is_empty()
        && name.len() <= 40
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '_'
        });
    if valid {
        Some(name.to_owned())
    } else {
        None
    }
}

/// Lines that open with `UNRESOLVED:` (after list or emphasis markers).
pub fn unresolved_lines(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start_matches(|character: char| {
                character.is_whitespace() || matches!(character, '*' | '-' | '>' | '`' | '#' | '_')
            });
            let rest = trimmed.strip_prefix("UNRESOLVED:")?;
            let rest = rest.trim().trim_matches('*').trim();
            if rest.is_empty() {
                None
            } else {
                Some(rest.to_owned())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markers_follow_markers_py() {
        assert_eq!(
            correction_marker("what the fuck are you doing"),
            Some(Marker::Profanity)
        );
        assert_eq!(
            correction_marker("I told you to stop"),
            Some(Marker::Correction)
        );
        assert_eq!(
            correction_marker("why didn't you check"),
            Some(Marker::Correction)
        );
        assert_eq!(
            correction_marker("no, that is wrong"),
            Some(Marker::Correction)
        );
        assert_eq!(correction_marker("go ahead and merge it"), None);
        // `no` needs a following separator; `note` and `know` are not markers.
        assert_eq!(correction_marker("please note the change"), None);
        // `still` is a whole word: `stillness` is not a marker.
        assert_eq!(correction_marker("stillness"), None);
        assert_eq!(
            correction_marker("you ignored it"),
            Some(Marker::Correction)
        );
        assert_eq!(correction_marker("ignore"), Some(Marker::Correction));
    }

    #[test]
    fn keyword_phrases_respect_boundaries() {
        assert!(phrase_match("who authorized this", "authoriz*"));
        assert!(!phrase_match("unauthorized", "authoriz*"));
        assert!(phrase_match("run the ci now", "ci"));
        assert!(!phrase_match("special", "ci"));
        assert!(phrase_match("a worktree was made", "worktree*"));
        assert!(phrase_match("two worktrees", "worktree*"));
        assert!(phrase_match("use --no-broker here", "--no-broker"));
    }

    #[test]
    fn injected_turns_are_not_user_words() {
        assert!(is_injected("<task-notification>done</task-notification>"));
        assert!(is_injected("  [Request interrupted by user]"));
        assert!(!is_injected("stop doing that"));
    }

    #[test]
    fn redaction_masks_tokens_only() {
        let secret = "Abc123Def456Ghi789Jkl012Mno345Pqr678";
        assert_eq!(redact(&format!("use {secret} now")), "use [redacted] now");
        assert_eq!(
            redact("key sk-live-abcdefghijklmnopqrstu"),
            "key [redacted]"
        );
        let sha = "1a0d77a19dd64e78a0b7e2cd0fa1e2f3c4d5e6f7";
        assert_eq!(redact(&format!("commit {sha}")), format!("commit {sha}"));
        assert_eq!(redact("plain words only"), "plain words only");
    }

    #[test]
    fn clips_and_slugifies() {
        assert_eq!(clip("  a   b\nc  ", 10), "a b c");
        assert_eq!(clip("abcdef", 3), "abc\u{2026}");
        assert_eq!(
            slugify("RK_INTERNAL_DRIVE_REFUSED", 40),
            "rk-internal-drive-refused"
        );
        assert_eq!(slugify("--a  b--", 40), "a-b");
        assert_eq!(slugify("abcdef", 3), "abc");
    }

    #[test]
    fn finds_codes_hook_names_and_unresolved_lines() {
        let text = "PreToolUse:Bash hook error: ARC_SELF_SCHEDULE: no cron";
        assert_eq!(arc_codes(text), vec!["ARC_SELF_SCHEDULE".to_owned()]);
        assert!(arc_codes("fooARC_X_Y and nothing").is_empty());
        assert_eq!(
            hook_block_name("hook error: [HOOK:one-door:block]\nWhy: x").as_deref(),
            Some("one-door")
        );
        assert_eq!(hook_block_name("no hook here"), None);
        let lines = unresolved_lines(
            "done\n**UNRESOLVED:** the build was not run\n- UNRESOLVED: x\nUNRESOLVED:",
        );
        assert_eq!(
            lines,
            vec!["the build was not run".to_owned(), "x".to_owned()]
        );
    }
}
