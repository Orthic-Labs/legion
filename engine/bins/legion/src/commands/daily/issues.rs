//! Issue upsert for `legion daily`. Matching is by the `Fingerprint:
//! <bucket>/<cause>` line in an issue body, never by title or by search, so a
//! recurring failure finds its issue and never opens a second one. The plan is
//! pure (it takes the issues already listed and the ledger) and the executor is
//! thin; nothing is written without `--apply`.
use super::{
    buckets, clock,
    ledger::{IssueNote, Ledger},
    proc,
    receipts::Flag,
    text::clip,
    transcripts::Failure,
};
use serde_json::Value;
use std::collections::BTreeMap;

pub const LEGION_REPO: &str = "Orthic-Labs/legion";
/// A broad cause (keyword fallback, red builds) needs this many occurrences in
/// the scan before it may open an issue, on top of repeating on two days.
pub const CATCH_ALL_MIN_TODAY: usize = 3;
/// Two dates only count as a recurrence when the first and last occurrence are
/// at least this far apart, so one sitting across UTC midnight is not "two days".
pub const MIN_SPAN_SECONDS: i64 = 12 * 3600;
const LIST_LIMIT: &str = "1000";
const OCCURRENCE_LINES: usize = 3;

/// An issue read from GitHub that carries a fingerprint line.
#[derive(Clone, Debug)]
pub struct Known {
    pub repo: String,
    pub number: u64,
    pub body: String,
    pub open: bool,
    pub closed_at: Option<i64>,
}

/// The `Fingerprint: <bucket>/<cause>` value in an issue body, if any.
pub fn fingerprint_of(body: &str) -> Option<String> {
    for line in body.lines() {
        let trimmed = line
            .trim()
            .trim_start_matches(|character: char| matches!(character, '-' | '*' | '>' | ' '));
        let Some(rest) = trimmed.strip_prefix("Fingerprint:") else {
            continue;
        };
        let value = rest.trim().trim_matches(|character: char| {
            character == '`' || character == '*' || character.is_whitespace()
        });
        if !value.is_empty() && value.contains('/') && !value.contains(char::is_whitespace) {
            return Some(value.to_owned());
        }
    }
    None
}

/// A fingerprint that was seen in the scan, ready to be matched to an issue.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub fingerprint: String,
    pub repo: &'static str,
    pub title: String,
    pub summary: String,
    pub origin: String,
    /// Dates (ascending) the ledger holds this fingerprint, today included.
    pub dates: Vec<String>,
    /// Seconds from the earliest to the latest occurrence the ledger holds.
    pub span_seconds: i64,
    /// Whether a new issue may be opened for it. A fingerprint that names no
    /// diagnosable cause (nothing matched, or a plain red build) is counted in
    /// the digest and only ever commented on if an issue already exists.
    pub files_issues: bool,
    /// Occurrences in this scan.
    pub today_count: usize,
    /// Time of the earliest occurrence in this scan.
    pub first_epoch: i64,
    /// Time of the latest occurrence in this scan.
    pub last_epoch: i64,
    pub catch_all: bool,
    pub hosts: Vec<String>,
    pub lines: Vec<String>,
}

fn host_list(hosts: &[String]) -> String {
    hosts.join(", ")
}

impl Candidate {
    /// Held by the ledger on a date before this scan's first occurrence.
    pub fn is_recurring(&self) -> bool {
        self.dates
            .first()
            .is_some_and(|first| first.as_str() < clock::date_of(self.first_epoch).as_str())
    }
}

/// Causes that carry no diagnosis: the keyword map found nothing, or it is a
/// plain red build, which is a normal part of development.
fn files_issues(cause: &str) -> bool {
    cause != "unclassified" && !cause.ends_with("-red")
}

/// One candidate per failure fingerprint in this scan.
pub fn candidates_from_failures(failures: &[Failure], ledger: &Ledger) -> Vec<Candidate> {
    let mut groups: BTreeMap<String, Vec<&Failure>> = BTreeMap::new();
    for failure in failures {
        groups
            .entry(failure.fingerprint())
            .or_default()
            .push(failure);
    }
    let mut out = Vec::new();
    for (fingerprint, mut group) in groups {
        group.sort_by(|left, right| right.epoch.cmp(&left.epoch));
        let Some(first) = group.first() else {
            continue;
        };
        let label = buckets::cause_label(&first.cause);
        let mut hosts: Vec<String> = group.iter().map(|failure| failure.host.clone()).collect();
        hosts.sort();
        hosts.dedup();
        let lines = group
            .iter()
            .take(OCCURRENCE_LINES)
            .map(|failure| {
                format!(
                    "- {} {} {} session {}: \"{}\"",
                    clock::date_of(failure.epoch),
                    clock::clock_of(failure.epoch),
                    failure.host,
                    clip(&failure.session, 8),
                    failure.quote
                )
            })
            .collect();
        out.push(Candidate {
            dates: ledger.dates_for(&fingerprint),
            span_seconds: ledger.span_seconds(&fingerprint),
            files_issues: files_issues(&first.cause),
            fingerprint,
            repo: LEGION_REPO,
            title: clip(
                &format!("Daily: {} {} (recurring)", first.bucket, label),
                120,
            ),
            summary: format!("The daily scan keeps finding this failure: {label}."),
            origin: format!("{} {}", first.bucket, buckets::bucket_name(first.bucket)),
            today_count: group.len(),
            first_epoch: group.last().map_or(first.epoch, |failure| failure.epoch),
            last_epoch: first.epoch,
            catch_all: group.iter().all(|failure| failure.catch_all),
            hosts,
            lines,
        });
    }
    out
}

/// One candidate per warmth flag.
pub fn candidates_from_flags(
    flags: &[Flag],
    ledger: &Ledger,
    today: &str,
    now: i64,
) -> Vec<Candidate> {
    flags
        .iter()
        .map(|flag| {
            let fingerprint = flag.fingerprint();
            Candidate {
                dates: ledger.dates_for(&fingerprint),
                span_seconds: ledger.span_seconds(&fingerprint),
                files_issues: true,
                repo: flag.owner,
                title: clip(
                    &format!(
                        "Broker warmth ({}, {}): {}",
                        flag.host, flag.repo, flag.label
                    ),
                    120,
                ),
                summary: format!(
                    "{} on {} for {}: {}.",
                    flag.label, flag.host, flag.repo, flag.detail
                ),
                origin: "Broker warmth, read from the broker receipts (Orthic-Labs/legion#138)"
                    .to_owned(),
                today_count: 1,
                first_epoch: now,
                last_epoch: now,
                catch_all: false,
                hosts: vec![flag.host.clone()],
                lines: vec![format!(
                    "- {today} {} {}: {}",
                    flag.host, flag.repo, flag.detail
                )],
                fingerprint,
            }
        })
        .collect()
}

/// What the run will do for one fingerprint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Create {
        repo: String,
        fingerprint: String,
        title: String,
        body: String,
    },
    Comment {
        repo: String,
        number: u64,
        fingerprint: String,
        body: String,
    },
    Reopen {
        repo: String,
        number: u64,
        fingerprint: String,
        body: String,
    },
    Skip {
        fingerprint: String,
        reason: String,
    },
}

impl Action {
    pub fn fingerprint(&self) -> &str {
        match self {
            Action::Create { fingerprint, .. }
            | Action::Comment { fingerprint, .. }
            | Action::Reopen { fingerprint, .. }
            | Action::Skip { fingerprint, .. } => fingerprint,
        }
    }

    pub fn verb(&self) -> &'static str {
        match self {
            Action::Create { .. } => "create",
            Action::Comment { .. } => "comment",
            Action::Reopen { .. } => "reopen",
            Action::Skip { .. } => "skip",
        }
    }

    /// One line for the digest and the console.
    pub fn describe(&self) -> String {
        match self {
            Action::Create {
                repo,
                title,
                fingerprint,
                ..
            } => {
                format!("create in {repo}: {title} [{fingerprint}]")
            }
            Action::Comment {
                repo,
                number,
                fingerprint,
                ..
            } => {
                format!("comment on {repo}#{number} [{fingerprint}]")
            }
            Action::Reopen {
                repo,
                number,
                fingerprint,
                ..
            } => {
                format!("reopen {repo}#{number}, fix did not work [{fingerprint}]")
            }
            Action::Skip {
                fingerprint,
                reason,
            } => format!("skip [{fingerprint}]: {reason}"),
        }
    }
}

pub struct PlanOptions {
    pub min_days: usize,
    pub max_new: usize,
    pub today: String,
    /// Repositories whose issues could not be listed: nothing is filed there.
    pub unavailable: Vec<String>,
}

enum Existing<'a> {
    Open(&'a Known),
    Closed(&'a Known),
    /// The ledger names an issue that is not in the listing.
    Unresolved(u64),
    Missing,
}

fn same(known: &Known, candidate: &Candidate) -> bool {
    known.repo == candidate.repo
        && fingerprint_of(&known.body).as_deref() == Some(candidate.fingerprint.as_str())
}

fn find_existing<'a>(candidate: &Candidate, known: &'a [Known], ledger: &Ledger) -> Existing<'a> {
    let open = known
        .iter()
        .filter(|issue| issue.open && same(issue, candidate))
        .min_by_key(|issue| issue.number);
    if let Some(issue) = open {
        return Existing::Open(issue);
    }
    let closed = known
        .iter()
        .filter(|issue| !issue.open && same(issue, candidate))
        .max_by_key(|issue| issue.closed_at.unwrap_or(0));
    if let Some(issue) = closed {
        return Existing::Closed(issue);
    }
    if let Some(note) = ledger.issues.get(&candidate.fingerprint) {
        let listed = known
            .iter()
            .find(|issue| issue.repo == note.repo && issue.number == note.number);
        return match listed {
            Some(issue) if issue.open => Existing::Open(issue),
            Some(issue) => Existing::Closed(issue),
            None => Existing::Unresolved(note.number),
        };
    }
    Existing::Missing
}

/// Ledger-named issues that the listing did not return; the caller fetches
/// each so a recurrence still finds its issue.
pub fn unlisted_ledger_issues(
    candidates: &[Candidate],
    known: &[Known],
    ledger: &Ledger,
) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = Vec::new();
    for candidate in candidates {
        if let Existing::Unresolved(number) = find_existing(candidate, known, ledger) {
            if number > 0 {
                if let Some(note) = ledger.issues.get(&candidate.fingerprint) {
                    out.push((note.repo.clone(), number));
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn skip(fingerprint: &str, reason: impl Into<String>) -> Action {
    Action::Skip {
        fingerprint: fingerprint.to_owned(),
        reason: reason.into(),
    }
}

fn occurrence_text(candidate: &Candidate) -> String {
    format!(
        "{} occurrence(s) in the latest scan (hosts: {}).\n{}",
        candidate.today_count,
        host_list(&candidate.hosts),
        candidate.lines.join("\n")
    )
}

pub fn create_body(candidate: &Candidate) -> String {
    format!(
        "{summary}\n\n\
         Fingerprint: {fp}\n\
         Checked: none found (search \"Fingerprint: {fp}\")\n\
         Source: {origin}\n\
         Seen on: {dates}\n\n\
         Latest occurrences:\n{occurrences}\n\n\
         Filed by `legion daily` (the M9 daily closed loop, Orthic-Labs/legion#138). \
         The job matches on the Fingerprint line: it comments here while the issue is open, \
         reopens it as \"fix did not work\" if the fingerprint recurs after it closes, and \
         files nothing new for it.",
        summary = candidate.summary,
        fp = candidate.fingerprint,
        origin = candidate.origin,
        dates = candidate.dates.join(", "),
        occurrences = occurrence_text(candidate),
    )
}

pub fn comment_body(candidate: &Candidate, today: &str) -> String {
    format!(
        "Daily scan {today}: `{}` again. Seen on {} day(s).\n{}",
        candidate.fingerprint,
        candidate.dates.len(),
        occurrence_text(candidate)
    )
}

pub fn reopen_body(candidate: &Candidate, closed_at: i64, today: &str) -> String {
    format!(
        "Fix did not work: `{}` recurred after this issue closed on {}. Daily scan {today}.\n{}",
        candidate.fingerprint,
        clock::date_of(closed_at),
        occurrence_text(candidate)
    )
}

/// Decide what to do for each candidate. Never creates when the fingerprint
/// already has an issue, open or closed, or when the ledger names one.
pub fn plan(
    candidates: &[Candidate],
    known: &[Known],
    ledger: &Ledger,
    options: &PlanOptions,
) -> Vec<Action> {
    let mut actions: Vec<Action> = Vec::new();
    let mut creates = 0usize;
    for candidate in candidates {
        let fingerprint = candidate.fingerprint.as_str();
        if options
            .unavailable
            .iter()
            .any(|repo| repo.as_str() == candidate.repo)
        {
            actions.push(skip(
                fingerprint,
                format!(
                    "issues in {} could not be listed; nothing filed",
                    candidate.repo
                ),
            ));
            continue;
        }
        let note = ledger.issues.get(fingerprint);
        match find_existing(candidate, known, ledger) {
            Existing::Open(issue) => {
                let commented = note
                    .is_some_and(|entry| entry.commented.iter().any(|date| date == &options.today));
                if commented {
                    actions.push(skip(
                        fingerprint,
                        format!("already commented on #{} today", issue.number),
                    ));
                } else {
                    actions.push(Action::Comment {
                        repo: issue.repo.clone(),
                        number: issue.number,
                        fingerprint: candidate.fingerprint.clone(),
                        body: comment_body(candidate, &options.today),
                    });
                }
            }
            Existing::Closed(issue) => {
                let closed_at = issue.closed_at.unwrap_or(0);
                let reopened = note
                    .is_some_and(|entry| entry.reopened.iter().any(|date| date == &options.today));
                if candidate.last_epoch <= closed_at {
                    actions.push(skip(
                        fingerprint,
                        format!(
                            "occurrences predate the close of #{} on {}; the fix was not in effect yet",
                            issue.number,
                            clock::date_of(closed_at)
                        ),
                    ));
                } else if reopened {
                    actions.push(skip(
                        fingerprint,
                        format!("#{} already reopened today", issue.number),
                    ));
                } else {
                    actions.push(Action::Reopen {
                        repo: issue.repo.clone(),
                        number: issue.number,
                        fingerprint: candidate.fingerprint.clone(),
                        body: reopen_body(candidate, closed_at, &options.today),
                    });
                }
            }
            Existing::Unresolved(number) => {
                actions.push(skip(
                    fingerprint,
                    format!("the ledger names #{number} but it could not be read; not filing a duplicate"),
                ));
            }
            Existing::Missing => {
                if !candidate.files_issues {
                    actions.push(skip(
                        fingerprint,
                        "no diagnosable cause; counted in the digest, not filed",
                    ));
                } else if candidate.dates.len() < options.min_days {
                    actions.push(skip(
                        fingerprint,
                        format!(
                            "seen on {} day(s); an issue needs {}",
                            candidate.dates.len(),
                            options.min_days
                        ),
                    ));
                } else if candidate.span_seconds < MIN_SPAN_SECONDS {
                    actions.push(skip(
                        fingerprint,
                        format!(
                            "the occurrences are {:.1} h apart; an issue needs {} h",
                            candidate.span_seconds as f64 / 3600.0,
                            MIN_SPAN_SECONDS / 3600
                        ),
                    ));
                } else if candidate.catch_all && candidate.today_count < CATCH_ALL_MIN_TODAY {
                    actions.push(skip(
                        fingerprint,
                        format!(
                            "broad cause with {} occurrence(s) in the scan; an issue needs {}",
                            candidate.today_count, CATCH_ALL_MIN_TODAY
                        ),
                    ));
                } else if creates >= options.max_new {
                    actions.push(skip(
                        fingerprint,
                        format!(
                            "new-issue cap of {} reached; it files on a later run",
                            options.max_new
                        ),
                    ));
                } else {
                    creates += 1;
                    actions.push(Action::Create {
                        repo: candidate.repo.to_owned(),
                        fingerprint: candidate.fingerprint.clone(),
                        title: candidate.title.clone(),
                        body: create_body(candidate),
                    });
                }
            }
        }
    }
    actions
}

// ---------------------------------------------------------------------------
// GitHub (`gh`)
// ---------------------------------------------------------------------------

fn gh(args: &[&str]) -> Result<String, String> {
    let mut command = proc::command("gh");
    command.args(args);
    command.env("GH_PROMPT_DISABLED", "1");
    let ran = proc::run(command)?;
    if ran.ok {
        Ok(ran.stdout)
    } else {
        Err(proc::failure_text(&ran))
    }
}

fn known_from_json(repo: &str, item: &Value) -> Option<Known> {
    let number = item.get("number").and_then(Value::as_u64)?;
    let state = item.get("state").and_then(Value::as_str).unwrap_or("OPEN");
    Some(Known {
        repo: repo.to_owned(),
        number,
        body: item
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned(),
        open: state.eq_ignore_ascii_case("OPEN"),
        closed_at: item
            .get("closedAt")
            .and_then(Value::as_str)
            .and_then(clock::parse_rfc3339),
    })
}

/// Every issue in `repo` (open and closed) whose body has a fingerprint line.
pub fn list_known(repo: &str) -> Result<Vec<Known>, String> {
    let output = gh(&[
        "issue",
        "list",
        "-R",
        repo,
        "--state",
        "all",
        "--limit",
        LIST_LIMIT,
        "--json",
        "number,title,body,state,closedAt",
    ])?;
    let value: Value = serde_json::from_str(&output)
        .map_err(|error| format!("gh issue list returned invalid JSON: {error}"))?;
    let items = value
        .as_array()
        .ok_or_else(|| "gh issue list did not return an array".to_owned())?;
    Ok(items
        .iter()
        .filter_map(|item| known_from_json(repo, item))
        .filter(|known| fingerprint_of(&known.body).is_some())
        .collect())
}

/// One issue by number (a ledger-named issue the listing missed).
pub fn view_known(repo: &str, number: u64) -> Result<Known, String> {
    let number_text = number.to_string();
    let output = gh(&[
        "issue",
        "view",
        number_text.as_str(),
        "-R",
        repo,
        "--json",
        "number,title,body,state,closedAt",
    ])?;
    let value: Value = serde_json::from_str(&output)
        .map_err(|error| format!("gh issue view returned invalid JSON: {error}"))?;
    known_from_json(repo, &value).ok_or_else(|| "gh issue view returned no number".to_owned())
}

fn number_from_url(output: &str) -> Option<u64> {
    let line = output.lines().rev().find(|line| !line.trim().is_empty())?;
    line.trim().rsplit('/').next()?.parse::<u64>().ok()
}

/// Run one action and record it in the ledger. Returns what happened.
pub fn apply(action: &Action, ledger: &mut Ledger, today: &str) -> Result<String, String> {
    match action {
        Action::Skip { reason, .. } => Ok(format!("skipped: {reason}")),
        Action::Create {
            repo,
            fingerprint,
            title,
            body,
        } => {
            let output = gh(&[
                "issue",
                "create",
                "-R",
                repo.as_str(),
                "--title",
                title.as_str(),
                "--body",
                body.as_str(),
            ])?;
            let number = number_from_url(&output);
            // Record the issue even when its number cannot be read, so the next
            // run finds a note and never files a duplicate.
            ledger.issues.insert(
                fingerprint.clone(),
                IssueNote {
                    repo: repo.clone(),
                    number: number.unwrap_or(0),
                    created: Some(today.to_owned()),
                    commented: Vec::new(),
                    reopened: Vec::new(),
                },
            );
            match number {
                Some(number) => Ok(format!("created {repo}#{number}")),
                None => Err(format!(
                    "created an issue but could not read its number from: {}",
                    clip(&output, 120)
                )),
            }
        }
        Action::Comment {
            repo,
            number,
            fingerprint,
            body,
        } => {
            let number_text = number.to_string();
            gh(&[
                "issue",
                "comment",
                number_text.as_str(),
                "-R",
                repo.as_str(),
                "--body",
                body.as_str(),
            ])?;
            let note = ledger
                .issues
                .entry(fingerprint.clone())
                .or_insert_with(|| IssueNote {
                    repo: repo.clone(),
                    number: *number,
                    ..IssueNote::default()
                });
            note.commented.push(today.to_owned());
            Ok(format!("commented on {repo}#{number}"))
        }
        Action::Reopen {
            repo,
            number,
            fingerprint,
            body,
        } => {
            let number_text = number.to_string();
            gh(&[
                "issue",
                "reopen",
                number_text.as_str(),
                "-R",
                repo.as_str(),
                "--comment",
                body.as_str(),
            ])?;
            let note = ledger
                .issues
                .entry(fingerprint.clone())
                .or_insert_with(|| IssueNote {
                    repo: repo.clone(),
                    number: *number,
                    ..IssueNote::default()
                });
            note.reopened.push(today.to_owned());
            Ok(format!("reopened {repo}#{number}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TODAY: &str = "2026-11-02";
    const NOW: i64 = 1_793_628_394;

    fn candidate(
        fingerprint: &str,
        dates: &[&str],
        today_count: usize,
        catch_all: bool,
    ) -> Candidate {
        Candidate {
            fingerprint: fingerprint.to_owned(),
            repo: LEGION_REPO,
            title: "Daily: test".to_owned(),
            summary: "summary".to_owned(),
            origin: "B3 Builds and CI".to_owned(),
            dates: dates.iter().map(|date| (*date).to_owned()).collect(),
            span_seconds: 86_400,
            files_issues: true,
            today_count,
            first_epoch: NOW,
            last_epoch: NOW,
            catch_all,
            hosts: vec!["mac".to_owned()],
            lines: vec!["- line".to_owned()],
        }
    }

    fn known(number: u64, fingerprint: &str, open: bool, closed_at: Option<i64>) -> Known {
        Known {
            repo: LEGION_REPO.to_owned(),
            number,
            body: format!("text\n\nFingerprint: {fingerprint}\nChecked: none found (search \"x\")"),
            open,
            closed_at,
        }
    }

    fn options(max_new: usize) -> PlanOptions {
        PlanOptions {
            min_days: 2,
            max_new,
            today: TODAY.to_owned(),
            unavailable: Vec::new(),
        }
    }

    #[test]
    fn reads_the_fingerprint_line() {
        assert_eq!(
            fingerprint_of("a\nFingerprint: B3/ci-as-compiler\nb").as_deref(),
            Some("B3/ci-as-compiler")
        );
        assert_eq!(
            fingerprint_of("- **Fingerprint:** `x/y`").as_deref(),
            Some("x/y")
        );
        assert_eq!(
            fingerprint_of("Fingerprint: `warmth/disk-low-mac-host`").as_deref(),
            Some("warmth/disk-low-mac-host")
        );
        assert_eq!(fingerprint_of("Fingerprint: two words/here"), None);
        assert_eq!(fingerprint_of("no fingerprint"), None);
    }

    #[test]
    fn a_first_day_failure_creates_nothing() {
        let actions = plan(
            &[candidate("B5/ignored-request", &["2026-11-02"], 4, false)],
            &[],
            &Ledger::default(),
            &options(5),
        );
        assert_eq!(actions.len(), 1);
        assert!(matches!(&actions[0], Action::Skip { reason, .. } if reason.contains("1 day")));
    }

    #[test]
    fn a_failure_on_two_days_creates_one_issue_with_a_checked_line() {
        let actions = plan(
            &[candidate(
                "B1/ignored-stop",
                &["2026-11-01", "2026-11-02"],
                2,
                false,
            )],
            &[],
            &Ledger::default(),
            &options(5),
        );
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            Action::Create {
                repo,
                body,
                title,
                fingerprint,
            } => {
                assert_eq!(repo, LEGION_REPO);
                assert_eq!(fingerprint, "B1/ignored-stop");
                assert!(title.starts_with("Daily"));
                assert!(body.contains("Fingerprint: B1/ignored-stop\n"));
                assert!(
                    body.contains("Checked: none found (search \"Fingerprint: B1/ignored-stop\")")
                );
            }
            other => panic!("expected create, got {other:?}"),
        }
    }

    #[test]
    fn an_existing_open_issue_gets_one_comment_a_day_and_no_duplicate() {
        let candidates = [candidate(
            "B1/ignored-stop",
            &["2026-11-01", "2026-11-02"],
            2,
            false,
        )];
        let listed = [known(41, "B1/ignored-stop", true, None)];
        let actions = plan(&candidates, &listed, &Ledger::default(), &options(5));
        assert!(matches!(&actions[0], Action::Comment { number: 41, .. }));

        let mut ledger = Ledger::default();
        ledger.issues.insert(
            "B1/ignored-stop".to_owned(),
            IssueNote {
                repo: LEGION_REPO.to_owned(),
                number: 41,
                commented: vec![TODAY.to_owned()],
                ..IssueNote::default()
            },
        );
        let again = plan(&candidates, &listed, &ledger, &options(5));
        assert!(
            matches!(&again[0], Action::Skip { reason, .. } if reason.contains("already commented"))
        );
    }

    #[test]
    fn a_closed_issue_reopens_only_for_an_occurrence_after_the_close() {
        let candidates = [candidate(
            "B3/ci-as-compiler",
            &["2026-10-30", "2026-11-02"],
            2,
            false,
        )];
        let closed_before = [known(9, "B3/ci-as-compiler", false, Some(NOW - 3600))];
        let actions = plan(&candidates, &closed_before, &Ledger::default(), &options(5));
        match &actions[0] {
            Action::Reopen { number, body, .. } => {
                assert_eq!(*number, 9);
                assert!(body.starts_with("Fix did not work"));
            }
            other => panic!("expected reopen, got {other:?}"),
        }
        let closed_after = [known(9, "B3/ci-as-compiler", false, Some(NOW + 3600))];
        let actions = plan(&candidates, &closed_after, &Ledger::default(), &options(5));
        assert!(matches!(&actions[0], Action::Skip { reason, .. } if reason.contains("predate")));
    }

    #[test]
    fn broad_causes_need_volume_and_new_issues_are_capped() {
        let broad = candidate("B5/ignored-request", &["2026-11-01", "2026-11-02"], 2, true);
        let actions = plan(&[broad], &[], &Ledger::default(), &options(5));
        assert!(
            matches!(&actions[0], Action::Skip { reason, .. } if reason.contains("broad cause"))
        );

        let many: Vec<Candidate> = (0..4)
            .map(|index| {
                candidate(
                    &format!("B2/cause-{index}"),
                    &["2026-11-01", "2026-11-02"],
                    2,
                    false,
                )
            })
            .collect();
        let actions = plan(&many, &[], &Ledger::default(), &options(2));
        let creates = actions
            .iter()
            .filter(|action| action.verb() == "create")
            .count();
        let capped = actions
            .iter()
            .filter(
                |action| matches!(action, Action::Skip { reason, .. } if reason.contains("cap")),
            )
            .count();
        assert_eq!(creates, 2);
        assert_eq!(capped, 2);
    }

    #[test]
    fn a_ledger_issue_missing_from_the_listing_blocks_a_duplicate() {
        let candidates = [candidate(
            "B4/ungrounded-cause",
            &["2026-11-01", "2026-11-02"],
            2,
            false,
        )];
        let mut ledger = Ledger::default();
        ledger.issues.insert(
            "B4/ungrounded-cause".to_owned(),
            IssueNote {
                repo: LEGION_REPO.to_owned(),
                number: 77,
                ..IssueNote::default()
            },
        );
        let actions = plan(&candidates, &[], &ledger, &options(5));
        assert!(matches!(&actions[0], Action::Skip { reason, .. } if reason.contains("#77")));
        assert_eq!(
            unlisted_ledger_issues(&candidates, &[], &ledger),
            vec![(LEGION_REPO.to_owned(), 77)]
        );
        // Once the issue is fetched, the plan comments on it instead.
        let fetched = [Known {
            repo: LEGION_REPO.to_owned(),
            number: 77,
            body: "no fingerprint line".to_owned(),
            open: true,
            closed_at: None,
        }];
        let actions = plan(&candidates, &fetched, &ledger, &options(5));
        assert!(matches!(&actions[0], Action::Comment { number: 77, .. }));
    }

    #[test]
    fn an_unlistable_repository_files_nothing() {
        let mut opts = options(5);
        opts.unavailable.push(LEGION_REPO.to_owned());
        let actions = plan(
            &[candidate(
                "B1/ignored-stop",
                &["2026-11-01", "2026-11-02"],
                2,
                false,
            )],
            &[],
            &Ledger::default(),
            &opts,
        );
        assert!(
            matches!(&actions[0], Action::Skip { reason, .. } if reason.contains("could not be listed"))
        );
    }

    #[test]
    fn undiagnosable_causes_are_counted_but_never_filed() {
        assert!(!files_issues("unclassified"));
        assert!(!files_issues("cargo-red"));
        assert!(files_issues("ignored-stop"));
        assert!(files_issues("hook-arc-self-schedule"));
        let mut unfiled = candidate("B3/cargo-red", &["2026-11-01", "2026-11-02"], 9, true);
        unfiled.files_issues = false;
        let actions = plan(&[unfiled], &[], &Ledger::default(), &options(5));
        assert!(matches!(&actions[0], Action::Skip { reason, .. } if reason.contains("not filed")));
        // An issue that already exists is still commented on.
        let mut unfiled = candidate("B3/cargo-red", &["2026-11-01", "2026-11-02"], 9, true);
        unfiled.files_issues = false;
        let listed = [known(5, "B3/cargo-red", true, None)];
        let actions = plan(&[unfiled], &listed, &Ledger::default(), &options(5));
        assert!(matches!(&actions[0], Action::Comment { number: 5, .. }));
    }

    #[test]
    fn two_dates_less_than_half_a_day_apart_do_not_open_an_issue() {
        let mut close = candidate("B1/ignored-stop", &["2026-11-01", "2026-11-02"], 2, false);
        close.span_seconds = 3600;
        let actions = plan(&[close], &[], &Ledger::default(), &options(5));
        assert!(matches!(&actions[0], Action::Skip { reason, .. } if reason.contains("apart")));
    }

    #[test]
    fn a_candidate_recurs_when_the_ledger_holds_an_earlier_date() {
        assert!(candidate("B1/x", &["2026-11-01", TODAY], 1, false).is_recurring());
        assert!(!candidate("B1/x", &[TODAY], 1, false).is_recurring());
        assert!(!candidate("B1/x", &[], 1, false).is_recurring());
    }

    #[test]
    fn parses_issue_numbers_from_gh_output() {
        assert_eq!(
            number_from_url("https://github.com/Orthic-Labs/legion/issues/139\n"),
            Some(139)
        );
        assert_eq!(
            number_from_url("warning\nhttps://github.com/o/r/issues/7"),
            Some(7)
        );
        assert_eq!(number_from_url("no url here"), None);
        assert_eq!(number_from_url(""), None);
    }

    #[test]
    fn builds_candidates_from_failures_with_ledger_dates() {
        use crate::commands::daily::transcripts::Kind;
        let failure = |id: &str, epoch: i64| Failure {
            id: id.to_owned(),
            host: "mac".to_owned(),
            kind: Kind::Correction,
            epoch,
            session: "26440622-40ce".to_owned(),
            project: "p".to_owned(),
            quote: "stop doing that".to_owned(),
            context: String::new(),
            bucket: "B1",
            cause: "ignored-stop".to_owned(),
            catch_all: false,
        };
        let failures = vec![failure("a", NOW), failure("b", NOW - 60)];
        let mut ledger = Ledger::default();
        for item in &failures {
            ledger.add_failure(item);
        }
        let found = candidates_from_failures(&failures, &ledger);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].fingerprint, "B1/ignored-stop");
        assert_eq!(found[0].today_count, 2);
        assert_eq!(found[0].last_epoch, NOW);
        assert_eq!(found[0].dates, vec![TODAY.to_owned()]);
        assert!(found[0].title.contains("kept working after a stop"));
        assert!(found[0].lines[0].contains("stop doing that"));
    }
}
