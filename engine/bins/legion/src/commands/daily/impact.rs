//! Impact of every change (Adrian 2026-11-02): each change merged in the last
//! few days appears in the digest with its bucket's failure count before and
//! after, so each change is checked for whether it worked. The bucket comes
//! from, in order: a `Fingerprint:` line in the commit message, an issue the
//! ledger knows (`#N`), or the keyword map over the commit text. Counts are
//! this scan's events split at the commit time, and the daily average over the
//! fully scanned days before and after the commit's date.
use super::{
    buckets, clock,
    issues::{fingerprint_of, LEGION_REPO},
    ledger::Ledger,
    proc,
    transcripts::{Failure, Window},
};
use std::path::Path;

const HISTORY_DAYS: i64 = 7;
const AFTER_DAYS: i64 = 14;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Commit {
    pub sha: String,
    pub epoch: i64,
    pub subject: String,
    pub body: String,
}

/// Parse `git log --pretty=format:%H%x1f%ct%x1f%s%x1f%b%x1e` output.
pub fn parse_log(output: &str) -> Vec<Commit> {
    output
        .split('\u{1e}')
        .filter_map(|record| {
            let mut parts = record.trim_start().splitn(4, '\u{1f}');
            let sha = parts.next()?.trim();
            let epoch = parts.next()?.trim().parse::<i64>().ok()?;
            let subject = parts.next()?.trim();
            let body = parts.next().unwrap_or("").trim();
            if sha.is_empty() {
                return None;
            }
            Some(Commit {
                sha: sha.to_owned(),
                epoch,
                subject: subject.to_owned(),
                body: body.to_owned(),
            })
        })
        .collect()
}

/// Commits on the checked-out branch since `since_epoch`.
pub fn recent_commits(repo_root: &Path, since_epoch: i64) -> Result<Vec<Commit>, String> {
    let mut command = proc::command("git");
    command.arg("-C").arg(repo_root);
    command.args(["log", "--no-color"]);
    command.arg(format!("--since={}", clock::rfc3339(since_epoch)));
    command.arg("--pretty=format:%H%x1f%ct%x1f%s%x1f%b%x1e");
    let ran = proc::run(command)?;
    if !ran.ok {
        return Err(proc::failure_text(&ran));
    }
    Ok(parse_log(&ran.stdout))
}

/// A commit with the bucket it targets, if one can be told.
#[derive(Clone, Debug)]
pub struct Change {
    pub short: String,
    pub epoch: i64,
    pub subject: String,
    pub bucket: Option<&'static str>,
    pub basis: String,
}

/// Issue numbers written as `#123` in `text`.
fn issue_refs(text: &str) -> Vec<u64> {
    let bytes = text.as_bytes();
    let mut out: Vec<u64> = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] != b'#' {
            index += 1;
            continue;
        }
        let mut end = index + 1;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end > index + 1 {
            if let Ok(number) = text[index + 1..end].parse::<u64>() {
                out.push(number);
            }
        }
        index = end;
    }
    out
}

fn bucket_id(fingerprint: &str) -> Option<&'static str> {
    let id = fingerprint.split('/').next()?;
    buckets::BUCKETS
        .iter()
        .find(|bucket| bucket.id == id)
        .map(|bucket| bucket.id)
}

pub fn attribute(commit: &Commit, ledger: &Ledger) -> Change {
    let text = format!("{}\n{}", commit.subject, commit.body);
    let (bucket, basis) =
        if let Some(id) = fingerprint_of(&commit.body).as_deref().and_then(bucket_id) {
            (Some(id), "fingerprint line".to_owned())
        } else if let Some((id, number)) = issue_refs(&text).into_iter().find_map(|number| {
            ledger
                .issues
                .iter()
                .find(|(_, note)| note.repo == LEGION_REPO && note.number == number)
                .and_then(|(fingerprint, _)| bucket_id(fingerprint))
                .map(|id| (id, number))
        }) {
            (Some(id), format!("issue #{number}"))
        } else if let Some(id) = buckets::bucket_of_text(&text) {
            (Some(id), "keywords".to_owned())
        } else {
            (None, "no bucket".to_owned())
        };
    Change {
        short: commit.sha.chars().take(8).collect(),
        epoch: commit.epoch,
        subject: super::text::clip(&commit.subject, 90),
        bucket,
        basis,
    }
}

/// A bucket's failures around a change.
#[derive(Clone, Debug, Default)]
pub struct Impact {
    /// This scan's events in the bucket before and after the commit time, when
    /// the commit is inside the scan window.
    pub in_window: Option<(usize, usize)>,
    pub before_total: usize,
    pub before_days: usize,
    pub after_total: usize,
    pub after_days: usize,
}

impl Impact {
    pub fn before_daily(&self) -> Option<f64> {
        average(self.before_total, self.before_days)
    }

    pub fn after_daily(&self) -> Option<f64> {
        average(self.after_total, self.after_days)
    }
}

fn average(total: usize, days: usize) -> Option<f64> {
    if days == 0 {
        None
    } else {
        Some(total as f64 / days as f64)
    }
}

/// Count the bucket's events before and after `change`. Only fully scanned
/// days count toward the daily averages.
pub fn measure(
    change: &Change,
    failures: &[Failure],
    ledger: &Ledger,
    window: &Window,
) -> Option<Impact> {
    let bucket = change.bucket?;
    let mut impact = Impact::default();
    if change.epoch >= window.since && change.epoch <= window.until {
        let in_bucket = failures.iter().filter(|failure| failure.bucket == bucket);
        let mut before = 0usize;
        let mut after = 0usize;
        for failure in in_bucket {
            if failure.epoch < change.epoch {
                before += 1;
            } else {
                after += 1;
            }
        }
        impact.in_window = Some((before, after));
    }
    let change_date = clock::date_of(change.epoch);
    for offset in 1..=HISTORY_DAYS {
        if let Some(date) = clock::shift_date(&change_date, -offset) {
            if ledger.covers_day(&date) {
                impact.before_days += 1;
                impact.before_total += ledger.bucket_total(&date, bucket);
            }
        }
    }
    for offset in 1..=AFTER_DAYS {
        if let Some(date) = clock::shift_date(&change_date, offset) {
            if ledger.covers_day(&date) {
                impact.after_days += 1;
                impact.after_total += ledger.bucket_total(&date, bucket);
            }
        }
    }
    Some(impact)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::daily::{ledger::IssueNote, transcripts::Kind};

    const NOW: i64 = 1_793_628_394;

    fn commit(subject: &str, body: &str) -> Commit {
        Commit {
            sha: "0123456789abcdef".to_owned(),
            epoch: NOW,
            subject: subject.to_owned(),
            body: body.to_owned(),
        }
    }

    #[test]
    fn parses_git_log_records() {
        let output = "aaa111\u{1f}1793628394\u{1f}fix(hook): stop sleeps\u{1f}Fixes #12\nbody line\u{1e}\nbbb222\u{1f}1793620000\u{1f}docs: note\u{1f}\u{1e}";
        let commits = parse_log(output);
        assert_eq!(commits.len(), 2);
        assert_eq!(commits[0].sha, "aaa111");
        assert_eq!(commits[0].epoch, 1_793_628_394);
        assert_eq!(commits[0].subject, "fix(hook): stop sleeps");
        assert_eq!(commits[0].body, "Fixes #12\nbody line");
        assert_eq!(commits[1].body, "");
        assert!(parse_log("").is_empty());
    }

    #[test]
    fn finds_issue_references() {
        assert_eq!(issue_refs("Fixes #12 and #7, not # 3 or #x"), vec![12, 7]);
        assert!(issue_refs("no refs").is_empty());
    }

    #[test]
    fn attributes_by_fingerprint_then_issue_then_keywords() {
        let ledger = {
            let mut ledger = Ledger::default();
            ledger.issues.insert(
                "B6/loop-or-poll".to_owned(),
                IssueNote {
                    repo: LEGION_REPO.to_owned(),
                    number: 55,
                    ..IssueNote::default()
                },
            );
            ledger
        };
        let by_fingerprint = attribute(&commit("fix: x", "Fingerprint: B2/gate-bypass"), &ledger);
        assert_eq!(by_fingerprint.bucket, Some("B2"));
        assert_eq!(by_fingerprint.basis, "fingerprint line");

        let by_issue = attribute(&commit("fix: something", "Closes #55"), &ledger);
        assert_eq!(by_issue.bucket, Some("B6"));
        assert_eq!(by_issue.basis, "issue #55");

        let by_keywords = attribute(&commit("deny worktree creation", ""), &ledger);
        assert_eq!(by_keywords.bucket, Some("B10"));
        assert_eq!(by_keywords.basis, "keywords");

        let none = attribute(&commit("zzz", ""), &ledger);
        assert_eq!(none.bucket, None);
        assert_eq!(by_issue.short, "01234567");
    }

    #[test]
    fn measures_before_and_after_in_the_window_and_over_covered_days() {
        let failure = |id: &str, epoch: i64| Failure {
            id: id.to_owned(),
            host: "mac".to_owned(),
            kind: Kind::Correction,
            epoch,
            session: "s".to_owned(),
            project: "p".to_owned(),
            quote: String::new(),
            context: String::new(),
            bucket: "B6",
            cause: "loop-or-poll".to_owned(),
            catch_all: false,
        };
        let failures = vec![
            failure("a", NOW - 600),
            failure("b", NOW - 300),
            failure("c", NOW + 300),
        ];
        let mut ledger = Ledger::default();
        let day = |text: &str| clock::parse_rfc3339(text).unwrap();
        // Two fully scanned days before the change date, one after it.
        ledger.record_scan(day("2026-10-31T00:00:00Z"), day("2026-11-02T00:00:00Z"));
        ledger.record_scan(day("2026-11-03T00:00:00Z"), day("2026-11-04T00:00:00Z"));
        ledger.add_failure(&failure("h1", day("2026-10-31T10:00:00Z")));
        ledger.add_failure(&failure("h2", day("2026-10-31T11:00:00Z")));
        ledger.add_failure(&failure("h3", day("2026-11-01T10:00:00Z")));
        ledger.add_failure(&failure("p1", day("2026-11-03T10:00:00Z")));

        let change = attribute(
            &commit("stop the polling loops", "Fingerprint: B6/loop-or-poll"),
            &ledger,
        );
        let window = Window {
            since: NOW - 3600,
            until: NOW + 3600,
        };
        let impact = measure(&change, &failures, &ledger, &window).unwrap();
        assert_eq!(impact.in_window, Some((2, 1)));
        assert_eq!((impact.before_total, impact.before_days), (3, 2));
        assert_eq!((impact.after_total, impact.after_days), (1, 1));
        assert_eq!(impact.before_daily(), Some(1.5));
        assert_eq!(impact.after_daily(), Some(1.0));

        let unattributed = attribute(&commit("zzz", ""), &ledger);
        assert!(measure(&unattributed, &failures, &ledger, &window).is_none());

        let old_window = Window {
            since: NOW + 7200,
            until: NOW + 9000,
        };
        assert_eq!(
            measure(&change, &failures, &ledger, &old_window)
                .unwrap()
                .in_window,
            None
        );
    }
}
