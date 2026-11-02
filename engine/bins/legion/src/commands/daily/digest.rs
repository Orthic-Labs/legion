//! The daily digest for Adrian: a short Markdown page. New failures, recurring
//! ones (with counts before and after any fix), fixes that worked, warmth flags
//! only when something is off, and the impact of each recent change.
use super::{
    buckets, clock,
    impact::{Change, Impact},
    issues::{fingerprint_of, Action, Candidate, Known},
    ledger::Ledger,
    receipts::{Flag, HostWarmth},
    transcripts::{Failure, Window},
};
use std::collections::BTreeMap;

const LIST_LIMIT: usize = 10;
/// A fingerprint with no events for this many covered days has stopped.
pub const QUIET_DAYS: usize = 7;

pub struct HostLine {
    pub host: String,
    pub transcripts: usize,
    pub failures: usize,
    pub receipts: usize,
}

pub struct Outcome {
    pub action: Action,
    pub result: String,
}

pub struct WarmthView<'a> {
    pub warmth: &'a HostWarmth,
    pub flags: &'a [Flag],
}

pub struct DigestInput<'a> {
    pub date: &'a str,
    pub window: Window,
    pub apply: bool,
    pub hosts: &'a [HostLine],
    pub failures: &'a [Failure],
    pub ledger: &'a Ledger,
    pub candidates: &'a [Candidate],
    pub outcomes: &'a [Outcome],
    pub known: &'a [Known],
    pub warmth: &'a [WarmthView<'a>],
    pub changes: &'a [(Change, Option<Impact>)],
    pub warnings: &'a [String],
}

fn line(out: &mut String, text: impl AsRef<str>) {
    out.push_str(text.as_ref());
    out.push('\n');
}

fn rate(value: Option<f64>) -> String {
    value.map_or("n/a".to_owned(), |number| format!("{number:.1}/day"))
}

/// Events for a fingerprint on the covered days in `[from_offset, to_offset]`
/// days from `date`, as (total, covered days).
fn span_total(
    ledger: &Ledger,
    fingerprint: &str,
    date: &str,
    from_offset: i64,
    to_offset: i64,
) -> (usize, usize) {
    let mut total = 0usize;
    let mut days = 0usize;
    for offset in from_offset..=to_offset {
        if let Some(day) = clock::shift_date(date, offset) {
            if ledger.covers_day(&day) {
                days += 1;
                total += ledger.count_on(&day, fingerprint);
            }
        }
    }
    (total, days)
}

/// Covered days after the last time `fingerprint` was seen, up to yesterday.
fn quiet_covered_days(ledger: &Ledger, fingerprint: &str, today: &str) -> usize {
    let Some(last) = ledger.dates_for(fingerprint).last().cloned() else {
        return 0;
    };
    let mut days = 0usize;
    let mut offset = 1i64;
    while let Some(day) = clock::shift_date(&last, offset) {
        if day.as_str() >= today {
            break;
        }
        if ledger.covers_day(&day) {
            days += 1;
        }
        offset += 1;
    }
    days
}

fn bucket_rows(input: &DigestInput) -> Vec<String> {
    let yesterday = clock::shift_date(input.date, -1).unwrap_or_default();
    let mut rows = Vec::new();
    for bucket in buckets::BUCKETS.iter() {
        let in_window = input
            .failures
            .iter()
            .filter(|failure| failure.bucket == bucket.id)
            .count();
        let previous = if input.ledger.covers_day(&yesterday) {
            Some(input.ledger.bucket_total(&yesterday, bucket.id))
        } else {
            None
        };
        let mut total = 0usize;
        let mut days = 0usize;
        for offset in 1..=7 {
            if let Some(day) = clock::shift_date(input.date, -offset) {
                if input.ledger.covers_day(&day) {
                    days += 1;
                    total += input.ledger.bucket_total(&day, bucket.id);
                }
            }
        }
        if in_window == 0 && previous.unwrap_or(0) == 0 && total == 0 {
            continue;
        }
        rows.push(format!(
            "| {} {} | {} | {} | {} |",
            bucket.id,
            bucket.name,
            in_window,
            previous.map_or("-".to_owned(), |count| count.to_string()),
            if days == 0 {
                "-".to_owned()
            } else {
                format!("{:.1} ({days} d)", total as f64 / days as f64)
            }
        ));
    }
    rows
}

fn action_for<'a>(input: &'a DigestInput, fingerprint: &str) -> Option<&'a Outcome> {
    input
        .outcomes
        .iter()
        .find(|outcome| outcome.action.fingerprint() == fingerprint)
}

fn status_text(input: &DigestInput, fingerprint: &str) -> String {
    match action_for(input, fingerprint) {
        Some(outcome) => {
            let plan = outcome.action.describe();
            if outcome.result.is_empty() {
                plan
            } else {
                format!("{plan} -> {}", outcome.result)
            }
        }
        None => "no action".to_owned(),
    }
}

fn candidate_line(input: &DigestInput, candidate: &Candidate) -> String {
    let first_date = candidate.dates.first().cloned().unwrap_or_default();
    let mut text = format!(
        "- `{}`: {} in this window; seen on {} day(s), first {}",
        candidate.fingerprint,
        candidate.today_count,
        candidate.dates.len(),
        first_date
    );
    let closed = input.known.iter().find(|issue| {
        !issue.open
            && fingerprint_of(&issue.body).as_deref() == Some(candidate.fingerprint.as_str())
    });
    if let Some(issue) = closed {
        if let Some(closed_at) = issue.closed_at {
            let close_date = clock::date_of(closed_at);
            let before = span_total(input.ledger, &candidate.fingerprint, &close_date, -7, -1);
            let after = span_total(input.ledger, &candidate.fingerprint, &close_date, 1, 14);
            text.push_str(&format!(
                "; fix closed {close_date}: {} before ({} d), {} after ({} d)",
                before.0, before.1, after.0, after.1
            ));
        }
    }
    text.push_str(&format!("; {}", status_text(input, &candidate.fingerprint)));
    text
}

fn quote_of(candidate: &Candidate) -> String {
    candidate.lines.first().cloned().unwrap_or_default()
}

fn failures_section(out: &mut String, input: &DigestInput) {
    line(
        out,
        format!("## Failures ({} in this window)", input.failures.len()),
    );
    let rows = bucket_rows(input);
    if rows.is_empty() {
        line(out, "None found.");
        return;
    }
    line(out, "");
    line(
        out,
        "| Bucket | In window | Yesterday | Average, last 7 scanned days |",
    );
    line(out, "|---|---|---|---|");
    for row in rows {
        line(out, row);
    }
}

fn new_and_recurring(out: &mut String, input: &DigestInput) {
    let failure_candidates: Vec<&Candidate> = input
        .candidates
        .iter()
        .filter(|candidate| !candidate.fingerprint.starts_with("warmth/"))
        .collect();
    let fresh: Vec<&&Candidate> = failure_candidates
        .iter()
        .filter(|candidate| !candidate.is_recurring())
        .collect();
    let recurring: Vec<&&Candidate> = failure_candidates
        .iter()
        .filter(|candidate| candidate.is_recurring())
        .collect();

    line(out, "");
    line(out, format!("## New failures ({})", fresh.len()));
    if fresh.is_empty() {
        line(out, "None.");
    }
    for candidate in fresh.iter().take(LIST_LIMIT) {
        line(
            out,
            format!(
                "- `{}`: {} in this window. {}",
                candidate.fingerprint,
                candidate.today_count,
                quote_of(candidate)
            ),
        );
    }
    if fresh.len() > LIST_LIMIT {
        line(out, format!("- ... and {} more", fresh.len() - LIST_LIMIT));
    }

    line(out, "");
    line(out, format!("## Recurring ({})", recurring.len()));
    if recurring.is_empty() {
        line(out, "None.");
    }
    for candidate in recurring.iter().take(LIST_LIMIT) {
        line(out, candidate_line(input, candidate));
    }
    if recurring.len() > LIST_LIMIT {
        line(
            out,
            format!("- ... and {} more", recurring.len() - LIST_LIMIT),
        );
    }
}

fn fixes_section(out: &mut String, input: &DigestInput) {
    let mut worked: Vec<String> = Vec::new();
    let mut quiet: Vec<String> = Vec::new();
    for issue in input.known {
        let Some(fingerprint) = fingerprint_of(&issue.body) else {
            continue;
        };
        if input.ledger.dates_for(&fingerprint).is_empty() {
            continue;
        }
        if quiet_covered_days(input.ledger, &fingerprint, input.date) < QUIET_DAYS {
            continue;
        }
        let text = format!(
            "- {}#{} `{}`: no events for {}+ scanned days",
            issue.repo, issue.number, fingerprint, QUIET_DAYS
        );
        if issue.open {
            quiet.push(format!("{text}; open, a candidate to close"));
        } else {
            worked.push(format!("{text}; closed, the fix worked"));
        }
    }
    line(out, "");
    line(out, format!("## Fixes that worked ({})", worked.len()));
    if worked.is_empty() {
        line(out, "None yet.");
    }
    for text in worked.iter().take(LIST_LIMIT) {
        line(out, text);
    }
    if !quiet.is_empty() {
        line(out, "");
        line(out, format!("Quiet but still open ({}):", quiet.len()));
        for text in quiet.iter().take(LIST_LIMIT) {
            line(out, text);
        }
    }
}

fn changes_section(out: &mut String, input: &DigestInput) {
    line(out, "");
    line(
        out,
        format!("## Impact of recent changes ({})", input.changes.len()),
    );
    if input.changes.is_empty() {
        line(out, "No changes in the period.");
        return;
    }
    line(out, "");
    line(out, "| Change | Bucket | This window, before / after the change | Daily average before -> after |");
    line(out, "|---|---|---|---|");
    for (change, impact) in input.changes.iter().take(LIST_LIMIT * 3) {
        let bucket = change
            .bucket
            .map_or("none".to_owned(), |id| format!("{id} ({})", change.basis));
        let (window_text, daily) = match impact {
            Some(impact) => (
                impact.in_window.map_or("-".to_owned(), |(before, after)| {
                    format!("{before} / {after}")
                }),
                format!(
                    "{} ({} d) -> {} ({} d)",
                    rate(impact.before_daily()),
                    impact.before_days,
                    rate(impact.after_daily()),
                    impact.after_days
                ),
            ),
            None => ("-".to_owned(), "-".to_owned()),
        };
        line(
            out,
            format!(
                "| `{}` {} ({}) | {} | {} | {} |",
                change.short,
                change.subject.replace('|', "/"),
                clock::date_of(change.epoch),
                bucket,
                window_text,
                daily
            ),
        );
    }
    if input.changes.len() > LIST_LIMIT * 3 {
        line(
            out,
            format!("... and {} more", input.changes.len() - LIST_LIMIT * 3),
        );
    }
}

fn warmth_section(out: &mut String, input: &DigestInput) {
    line(out, "");
    line(out, "## Broker warmth");
    for view in input.warmth {
        let warmth = view.warmth;
        let jobs: u64 = warmth.repos.values().map(|stats| stats.jobs).sum();
        if view.flags.is_empty() {
            line(
                out,
                format!(
                    "- {}: nothing off ({} job(s), {} receipt(s) read).",
                    warmth.host, jobs, warmth.receipts
                ),
            );
            continue;
        }
        line(
            out,
            format!(
                "- {}: {} flag(s) over {} job(s).",
                warmth.host,
                view.flags.len(),
                jobs
            ),
        );
        for flag in view.flags {
            line(
                out,
                format!(
                    "  - {} / {}: {}. {}",
                    flag.repo, flag.slug, flag.label, flag.detail
                ),
            );
            if let Some(stats) = warmth.repos.get(&flag.repo) {
                for worst in &stats.worst {
                    line(
                        out,
                        format!(
                            "    - worst job {} ({:.0}s): {}; {}",
                            worst.id,
                            worst.total_ms as f64 / 1000.0,
                            worst.why,
                            worst.command
                        ),
                    );
                }
            }
        }
    }
    if input.warmth.is_empty() {
        line(out, "- No receipts were read.");
    }
}

fn actions_section(out: &mut String, input: &DigestInput) {
    let active: Vec<&Outcome> = input
        .outcomes
        .iter()
        .filter(|outcome| outcome.action.verb() != "skip")
        .collect();
    let skipped = input.outcomes.len() - active.len();
    line(out, "");
    line(
        out,
        format!(
            "## Issue actions ({} to do, {} skipped; {})",
            active.len(),
            skipped,
            if input.apply {
                "applied"
            } else {
                "dry run, nothing written"
            }
        ),
    );
    if active.is_empty() {
        line(out, "None.");
    }
    for outcome in active {
        let result = if outcome.result.is_empty() {
            String::new()
        } else {
            format!(" -> {}", outcome.result)
        };
        line(out, format!("- {}{}", outcome.action.describe(), result));
    }
}

/// The whole digest.
pub fn render(input: &DigestInput) -> String {
    let mut out = String::new();
    line(&mut out, format!("# Legion daily, {}", input.date));
    let hosts = input
        .hosts
        .iter()
        .map(|host| {
            format!(
                "{} ({} transcript file(s), {} failure(s), {} receipt(s))",
                host.host, host.transcripts, host.failures, host.receipts
            )
        })
        .collect::<Vec<_>>()
        .join("; ");
    line(
        &mut out,
        format!(
            "Window {} to {}. {}. Mode: {}.",
            clock::rfc3339(input.window.since),
            clock::rfc3339(input.window.until),
            hosts,
            if input.apply { "apply" } else { "dry run" }
        ),
    );
    line(&mut out, "");
    failures_section_with_counts(&mut out, input);
    new_and_recurring(&mut out, input);
    fixes_section(&mut out, input);
    changes_section(&mut out, input);
    warmth_section(&mut out, input);
    actions_section(&mut out, input);
    if !input.warnings.is_empty() {
        line(&mut out, "");
        line(&mut out, "## Notes");
        for warning in input.warnings {
            line(&mut out, format!("- {warning}"));
        }
    }
    out
}

fn failures_section_with_counts(out: &mut String, input: &DigestInput) {
    let mut by_kind: BTreeMap<&'static str, usize> = BTreeMap::new();
    for failure in input.failures {
        *by_kind.entry(failure.kind.label()).or_insert(0) += 1;
    }
    let kinds = by_kind
        .iter()
        .map(|(kind, count)| format!("{count} {kind}"))
        .collect::<Vec<_>>()
        .join(", ");
    failures_section(out, input);
    if !kinds.is_empty() {
        line(out, "");
        line(out, format!("By kind: {kinds}."));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::daily::{
        issues::{Action, LEGION_REPO},
        transcripts::Kind,
    };

    const NOW: i64 = 1_793_628_394;

    fn failure(id: &str, epoch: i64, bucket: &'static str, cause: &str) -> Failure {
        Failure {
            id: id.to_owned(),
            host: "mac".to_owned(),
            kind: Kind::Correction,
            epoch,
            session: "26440622-aa".to_owned(),
            project: "p".to_owned(),
            quote: "stop that".to_owned(),
            context: String::new(),
            bucket,
            cause: cause.to_owned(),
            catch_all: false,
        }
    }

    #[test]
    fn renders_failures_recurrence_fixes_and_actions() {
        let window = Window {
            since: NOW - 86_400,
            until: NOW,
        };
        let failures = vec![
            failure("a", NOW - 100, "B1", "ignored-stop"),
            failure("b", NOW - 50, "B6", "loop-or-poll"),
        ];
        let mut ledger = Ledger::default();
        for item in &failures {
            ledger.add_failure(item);
        }
        // B1/ignored-stop also happened yesterday, so it recurs.
        ledger.add_failure(&failure("old", NOW - 86_400 - 100, "B1", "ignored-stop"));
        ledger.record_scan(NOW - 9 * 86_400, NOW);
        let candidates =
            crate::commands::daily::issues::candidates_from_failures(&failures, &ledger);
        assert_eq!(candidates.len(), 2);
        let outcomes = vec![Outcome {
            action: Action::Comment {
                repo: LEGION_REPO.to_owned(),
                number: 41,
                fingerprint: "B1/ignored-stop".to_owned(),
                body: "b".to_owned(),
            },
            result: String::new(),
        }];
        let known = vec![Known {
            repo: LEGION_REPO.to_owned(),
            number: 41,
            body: "Fingerprint: B1/ignored-stop".to_owned(),
            open: true,
            closed_at: None,
        }];
        let hosts = vec![HostLine {
            host: "mac".to_owned(),
            transcripts: 3,
            failures: 2,
            receipts: 10,
        }];
        let warmth = HostWarmth {
            host: "mac".to_owned(),
            receipts: 10,
            ..HostWarmth::default()
        };
        let views = vec![WarmthView {
            warmth: &warmth,
            flags: &[],
        }];
        let input = DigestInput {
            date: "2026-11-02",
            window,
            apply: false,
            hosts: &hosts,
            failures: &failures,
            ledger: &ledger,
            candidates: &candidates,
            outcomes: &outcomes,
            known: &known,
            warmth: &views,
            changes: &[],
            warnings: &["dell: ssh unavailable".to_owned()],
        };
        let text = render(&input);
        assert!(text.starts_with("# Legion daily, 2026-11-02"));
        assert!(text.contains("## Failures (2 in this window)"));
        assert!(text.contains("| B1 "));
        assert!(text.contains("## New failures (1)"));
        assert!(text.contains("`B6/loop-or-poll`"));
        assert!(text.contains("## Recurring (1)"));
        assert!(text.contains("`B1/ignored-stop`: 1 in this window; seen on 2 day(s)"));
        assert!(text.contains("comment on Orthic-Labs/legion#41"));
        assert!(text.contains("- mac: nothing off (0 job(s), 10 receipt(s) read)."));
        assert!(text.contains("1 to do"));
        assert!(text.contains("dry run, nothing written"));
        assert!(text.contains("## Notes"));
        assert!(text.contains("dell: ssh unavailable"));
    }

    #[test]
    fn a_closed_issue_with_no_events_for_a_week_is_a_fix_that_worked() {
        let window = Window {
            since: NOW - 86_400,
            until: NOW,
        };
        let mut ledger = Ledger::default();
        // Last seen 10 days ago; every day since is scanned and quiet.
        ledger.add_failure(&failure("old", NOW - 10 * 86_400, "B3", "ci-as-compiler"));
        ledger.record_scan(NOW - 12 * 86_400, NOW);
        let known = vec![Known {
            repo: LEGION_REPO.to_owned(),
            number: 9,
            body: "Fingerprint: B3/ci-as-compiler".to_owned(),
            open: false,
            closed_at: Some(NOW - 9 * 86_400),
        }];
        let input = DigestInput {
            date: "2026-11-02",
            window,
            apply: true,
            hosts: &[],
            failures: &[],
            ledger: &ledger,
            candidates: &[],
            outcomes: &[],
            known: &known,
            warmth: &[],
            changes: &[],
            warnings: &[],
        };
        let text = render(&input);
        assert!(text.contains("## Fixes that worked (1)"));
        assert!(text.contains("Orthic-Labs/legion#9"));
        assert!(text.contains("applied"));
        assert!(text.contains("No receipts were read."));
        assert!(text.contains("None found."));
    }
}
