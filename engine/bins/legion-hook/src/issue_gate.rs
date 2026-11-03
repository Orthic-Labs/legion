//! Search before filing: `gh issue create` needs a `Checked:` line naming what was found and
//! searched, exactly one type label, and for a `decision` a `Contract:` line and three boxes.

use std::{collections::BTreeSet, fs, path::PathBuf};

use crate::protocol::{HookRequest, HookResponse};
use crate::state::{off, str_field, tool_input};

const MESSAGE: &str = "Search first: gh issue list -R <repo> --search '<terms>' --state all; then add a line to the body: 'Checked: #12, #34 (search \"<terms>\")' or 'Checked: none found (search \"<terms>\")'.";
const LABEL_MESSAGE: &str = "Give the issue exactly one label: --label pipeline, decision, incident, bug or request.";
const DECISION_MESSAGE: &str = "A decision issue needs a line 'Contract: <doc> <clause>' and the boxes '- [ ] written-in-contract', '- [ ] enforced-in-code (path:line)' and '- [ ] verified-by-run (receipt)'.";
const TYPE_LABELS: [&str; 5] = ["pipeline", "decision", "incident", "bug", "request"];

/// Does any line say `Checked: #n` (also `repo#n`) or `Checked: none found`, with search terms
/// in `(search "<terms>")` on that same line?
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
        let named =
            rest.starts_with("none found") || issue.is_some_and(|(_, number)| digits(number));
        named && has_search_terms(line)
    })
}

/// Does the line carry `(search "<terms>")`, single quotes allowed, with non-empty terms?
fn has_search_terms(line: &str) -> bool {
    let line = line.to_lowercase().replace("\\\"", "\"");
    line.split_once("(search ").is_some_and(|(_, tail)| {
        let mut chars = tail.chars();
        match chars.next() {
            Some(quote @ ('"' | '\'')) => chars
                .as_str()
                .split_once(quote)
                .is_some_and(|(terms, _)| !terms.trim().is_empty()),
            _ => false,
        }
    })
}

/// The type labels a create names with `--label`/`-l`, `--label=`, or an API `labels[]=` field.
fn type_labels(words: &[String]) -> BTreeSet<&'static str> {
    let mut found = BTreeSet::new();
    for (index, word) in words.iter().enumerate() {
        let next = words.get(index + 1).map(String::as_str);
        let value = match word.as_str() {
            "--label" | "-l" => next,
            _ => word
                .strip_prefix("--label=")
                .or(word.strip_prefix("labels[]="))
                .or(word.strip_prefix("labels=")),
        };
        for name in value.unwrap_or_default().split(',') {
            if let Some(label) = TYPE_LABELS
                .iter()
                .find(|label| label.eq_ignore_ascii_case(name.trim()))
            {
                found.insert(*label);
            }
        }
    }
    found
}

/// Does the text carry a `Contract: <doc> <clause>` line and the three decision boxes?
fn decision_ready(text: &str) -> bool {
    let lower = text.to_lowercase();
    let contract = lower.lines().any(|line| {
        line.split_once("contract:")
            .is_some_and(|(_, rest)| rest.split_whitespace().count() >= 2)
    });
    let boxed = |name: &str| {
        lower.contains(&format!("[ ] {name}")) || lower.contains(&format!("[x] {name}"))
    };
    contract
        && ["written-in-contract", "enforced-in-code", "verified-by-run"]
            .iter()
            .all(|name| boxed(*name))
}

/// The denial for a command that files an issue (`gh issue create`, or a `gh api` POST to
/// `.../issues`) when its text or `--body-file` lacks a `Checked:` line with search terms, when
/// a filed issue does not carry exactly one type label, or when a `decision` lacks its contract
/// line and boxes; unreadable files allow.
fn check(command: &str, cwd: &str) -> Option<String> {
    let (mut text, mut filed) = (command.to_owned(), Vec::new());
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
        filed.push(type_labels(rest));
        for (index, word) in rest.iter().enumerate() {
            let next = rest.get(index + 1).map(String::as_str);
            let flag = matches!(word.as_str(), "--body-file") || (sub == "issue" && word == "-F");
            let file = word.strip_prefix("--body-file=").or(next.filter(|_| flag));
            if let Some(file) = file {
                text.push_str(&fs::read_to_string(PathBuf::from(cwd).join(file)).ok()?);
            }
        }
    }
    if filed.is_empty() {
        return None;
    }
    if !has_checked(&text) {
        return Some(MESSAGE.to_owned());
    }
    if filed.iter().any(|labels| labels.len() != 1) {
        return Some(LABEL_MESSAGE.to_owned());
    }
    let decision = filed.iter().any(|labels| labels.contains("decision"));
    (decision && !decision_ready(&text)).then(|| DECISION_MESSAGE.to_owned())
}

/// PreToolUse of a shell tool: deny an issue create that breaks the search, label or decision rule.
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
            "gh issue create -R o/r --label bug --title x --body 'Checked: #12, #34 (search \"hook\")'",
            ""
        )
        .is_none());
        assert!(check(
            "gh issue create --label bug --body 'checked: none found (search \"hook\")'",
            ""
        )
        .is_none());
        assert!(check(
            "gh issue create --label bug --body \"$(cat <<'EOF'\nChecked: legion#5 (search \"hook\")\nEOF\n)\"",
            ""
        )
        .is_none());
        assert!(check("gh issue list --search x && echo gh issue create", "").is_none());
    }

    #[test]
    fn checked_line_needs_search_terms() {
        let refused = |body: &str| check(&format!("gh issue create --label bug --body '{body}'"), "");
        assert_eq!(refused("Checked: #12"), Some(MESSAGE.to_owned()));
        assert_eq!(refused("Checked: none found"), Some(MESSAGE.to_owned()));
        assert_eq!(refused("Checked: #12 (search \"\")"), Some(MESSAGE.to_owned()));
        assert_eq!(refused("Checked: #12 (search hook)"), Some(MESSAGE.to_owned()));
        assert!(refused("Checked: #12 (search \"hook\")").is_none());
    }

    #[test]
    fn filing_needs_exactly_one_type_label() {
        let body = "--body 'Checked: none found (search \"hook\")'";
        let unlabelled = format!("gh issue create --title x {body}");
        assert_eq!(check(&unlabelled, ""), Some(LABEL_MESSAGE.to_owned()));
        let two = format!("gh issue create --label bug --label request {body}");
        assert_eq!(check(&two, ""), Some(LABEL_MESSAGE.to_owned()));
        let comma = format!("gh issue create --label bug,request {body}");
        assert_eq!(check(&comma, ""), Some(LABEL_MESSAGE.to_owned()));
        let outside = format!("gh issue create --label enhancement {body}");
        assert_eq!(check(&outside, ""), Some(LABEL_MESSAGE.to_owned()));
        assert!(check(&format!("gh issue create --label=request {body}"), "").is_none());
        assert!(check(&format!("gh issue create -l bug {body}"), "").is_none());
    }

    #[test]
    fn a_decision_needs_a_contract_line_and_three_boxes() {
        let checked = "Checked: none found (search \"contract\")";
        let contract = "Contract: docs/contracts/BROKER.md broker-03";
        let boxes = "- [ ] written-in-contract\n- [ ] enforced-in-code (path:line)\n- [ ] verified-by-run (receipt)";
        let issue = |body: &str| format!("gh issue create --label decision --title x --body '{body}'");
        assert_eq!(
            check(&issue(&format!("{checked}\n{boxes}")), ""),
            Some(DECISION_MESSAGE.to_owned())
        );
        assert_eq!(
            check(&issue(&format!("{checked}\nContract: BROKER\n{boxes}")), ""),
            Some(DECISION_MESSAGE.to_owned())
        );
        let missing_box = "- [ ] written-in-contract\n- [ ] verified-by-run (receipt)";
        assert_eq!(
            check(&issue(&format!("{checked}\n{contract}\n{missing_box}")), ""),
            Some(DECISION_MESSAGE.to_owned())
        );
        assert!(check(&issue(&format!("{checked}\n{contract}\n{boxes}")), "").is_none());
    }

    #[test]
    fn the_body_file_is_read_and_an_unreadable_one_allows() {
        let dir = temp_dir("issue");
        fs::write(dir.join("ok.md"), "Checked: none found (search \"x\")").unwrap();
        fs::write(dir.join("no.md"), "no line here").unwrap();
        let cwd = dir.to_string_lossy();
        assert!(check("gh issue create --label bug --title x --body-file ok.md", &cwd).is_none());
        assert!(check("gh issue create --label bug --title x -F no.md", &cwd).is_some());
        assert!(check("gh issue create --label bug --title x --body-file missing.md", &cwd).is_none());
    }

    #[test]
    fn the_api_post_variant_is_checked_too() {
        assert!(check("gh api repos/o/r/issues -f title=x -f body=y", "").is_some());
        assert!(check("gh api repos/o/r/issues", "").is_none());
        let body = "-f 'body=Checked: none found (search \"x\")'";
        assert_eq!(
            check(&format!("gh api repos/o/r/issues -f title=x {body}"), ""),
            Some(LABEL_MESSAGE.to_owned())
        );
        assert!(check(&format!("gh api repos/o/r/issues -f title=x {body} -f labels[]=bug"), "").is_none());
    }
}
