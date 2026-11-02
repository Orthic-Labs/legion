//! Search before filing: `gh issue create` needs a `Checked:` line naming what was found.

use std::{fs, path::PathBuf};

use crate::protocol::{HookRequest, HookResponse};
use crate::state::{off, str_field, tool_input};

const MESSAGE: &str = "Search first: gh issue list -R <repo> --search '<terms>' --state all; then add a line to the body: 'Checked: #12, #34' or 'Checked: none found'.";

/// Does any line say `Checked: #n` (also `repo#n`) or `Checked: none found`?
fn has_checked(text: &str) -> bool {
    text.lines().any(|line| {
        let lower = line.to_lowercase();
        let rest = lower
            .split_once("checked:")
            .map_or("", |(_, rest)| rest.trim_start());
        let digits = |tail: &str| tail.starts_with(|c: char| c.is_ascii_digit());
        let issue = rest
            .split_whitespace()
            .next()
            .and_then(|token| token.split_once('#'));
        rest.starts_with("none found") || issue.is_some_and(|(_, number)| digits(number))
    })
}

/// The denial for a command that files an issue (`gh issue create`, or a `gh api` POST to
/// `.../issues`) with no `Checked:` line in its text or `--body-file`; unreadable files allow.
fn check(command: &str, cwd: &str) -> Option<String> {
    let (mut text, mut files_issue) = (command.to_owned(), false);
    for segment in crate::command_segments(command) {
        let words = crate::shell_words(crate::strip_command_prefixes(&segment));
        let Some((sub, rest)) = crate::program_subcommand(&words, "gh", &["-R", "--repo"]) else {
            continue;
        };
        let post = rest
            .iter()
            .any(|word| matches!(word.as_str(), "POST" | "-f" | "-F" | "--field"));
        let api = sub == "api" && post && rest.iter().any(|word| word.ends_with("/issues"));
        if !api && !(sub == "issue" && rest.first().map(String::as_str) == Some("create")) {
            continue;
        }
        files_issue = true;
        for (index, word) in rest.iter().enumerate() {
            let next = rest.get(index + 1).map(String::as_str);
            let flag = matches!(word.as_str(), "--body-file") || (sub == "issue" && word == "-F");
            let file = word.strip_prefix("--body-file=").or(next.filter(|_| flag));
            if let Some(file) = file {
                text.push_str(&fs::read_to_string(PathBuf::from(cwd).join(file)).ok()?);
            }
        }
    }
    (files_issue && !has_checked(&text)).then(|| MESSAGE.to_owned())
}

/// PreToolUse of a shell tool: deny `gh issue create` without a `Checked:` line.
pub fn pre_tool(request: &HookRequest) -> Option<HookResponse> {
    if off("issue-search") || !request.is_pre_effect() {
        return None;
    }
    let payload = request.payload.as_object()?;
    let command = crate::command_text(tool_input(payload)?)?;
    let message = check(
        &command,
        &str_field(payload, &["cwd", "workdir"]).unwrap_or_default(),
    )?;
    Some(HookResponse::denied(
        request.event_type.clone(),
        "ARC_ISSUE_SEARCH_FIRST",
        message,
        "strong",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::tests::temp_dir;

    #[test]
    fn filing_an_issue_needs_a_checked_line() {
        assert!(check("gh issue create --title x --body 'hi'", "").is_some());
        assert!(check(
            "gh issue create -R o/r --title x --body 'Checked: #12, #34'",
            ""
        )
        .is_none());
        assert!(check("gh issue create --body 'checked: none found'", "").is_none());
        assert!(check(
            "gh issue create --body \"$(cat <<'EOF'\nChecked: legion#5\nEOF\n)\"",
            ""
        )
        .is_none());
        assert!(check("gh issue list --search x && echo gh issue create", "").is_none());
    }

    #[test]
    fn the_body_file_is_read_and_an_unreadable_one_allows() {
        let dir = temp_dir("issue");
        fs::write(dir.join("ok.md"), "Checked: none found").unwrap();
        fs::write(dir.join("no.md"), "no line here").unwrap();
        let cwd = dir.to_string_lossy();
        assert!(check("gh issue create --title x --body-file ok.md", &cwd).is_none());
        assert!(check("gh issue create --title x -F no.md", &cwd).is_some());
        assert!(check("gh issue create --title x --body-file missing.md", &cwd).is_none());
    }

    #[test]
    fn the_api_post_variant_is_checked_too() {
        assert!(check("gh api repos/o/r/issues -f title=x -f body=y", "").is_some());
        assert!(check("gh api repos/o/r/issues", "").is_none());
    }
}
