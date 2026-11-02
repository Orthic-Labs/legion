//! The ledger (`~/.legion/daily/ledger.json`) and the GitHub side: match an open issue by its
//! `Fingerprint:` line, comment with new occurrences, reopen a closed one that recurred, and
//! create only for a fingerprint seen on 2 or more distinct days at least 12 hours apart.
use super::{exec, time};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, ops::RangeBounds, process::Command};

pub const LEGION: &str = "Orthic-Labs/legion";
pub const MAX_CREATES: usize = 5;

/// One run's counts per fingerprint: (events, first event, last event).
type Run = BTreeMap<String, (u64, i64, i64)>;

/// What each daily run saw (the day counts), the issue each fingerprint owns, and the end of
/// the last saved run (events after it are new).
#[derive(Default, Serialize, Deserialize)]
pub struct Ledger {
    pub runs: BTreeMap<String, Run>,
    pub issues: BTreeMap<String, u64>,
    pub last: i64,
}

impl Ledger {
    fn hits<'a>(&'a self, fp: &'a str) -> impl Iterator<Item = &'a (u64, i64, i64)> {
        self.runs.values().filter_map(move |run| run.get(fp))
    }

    /// Events of `fp` over all runs except the run dated `except`.
    pub fn total(&self, fp: &str, except: &str) -> u64 {
        let runs = self.runs.iter().filter(|(date, _)| date.as_str() != except);
        runs.map(|(_, run)| run.get(fp).map_or(0, |hit| hit.0))
            .sum()
    }

    pub fn days(&self, fp: &str) -> usize {
        self.hits(fp).count()
    }

    /// Seen on 2 or more distinct days at least 12 hours apart.
    pub fn qualifies(&self, fp: &str) -> bool {
        let (last, first) = (
            self.hits(fp).map(|hit| hit.2).max(),
            self.hits(fp).map(|hit| hit.1).min(),
        );
        self.days(fp) >= 2
            && last
                .zip(first)
                .is_some_and(|(last, first)| last - first >= 12 * 3600)
    }

    /// Save this run under its date (a same-day run replaces it) and prune old runs. A run
    /// that missed a host is not saved as a day, so it can never show a false "no recurrence".
    pub fn record(&mut self, date: &str, groups: &[Group], until: i64, complete: bool) {
        self.last = until;
        if complete {
            let mut run = Run::new();
            for g in groups.iter().filter(|g| !g.lines.is_empty()) {
                let (first, last) = (g.lines[0].epoch, g.lines[g.lines.len() - 1].epoch);
                run.insert(g.fp.clone(), (g.lines.len() as u64, first, last));
            }
            self.runs.insert(date.to_owned(), run);
            let cutoff = time::date(until - 120 * time::DAY);
            self.runs.retain(|run_date, _| *run_date >= cutoff);
        }
    }

    /// The bucket's mean events per run over the runs dated in `dates`, and how many runs.
    pub fn rate(&self, bucket: &str, dates: impl RangeBounds<String>) -> Option<(f64, usize)> {
        let prefix = format!("{bucket}/");
        let runs: Vec<&Run> = self.runs.range(dates).map(|(_, run)| run).collect();
        let mut total = 0;
        for run in &runs {
            let hits = run.iter().filter(|(fp, _)| fp.starts_with(&prefix));
            total += hits.map(|(_, hit)| hit.0).sum::<u64>();
        }
        (!runs.is_empty()).then(|| (total as f64 / runs.len() as f64, runs.len()))
    }
}

pub struct Known {
    pub number: u64,
    pub open: bool,
    pub closed_at: Option<i64>,
}

/// Runs `gh` with the arguments, or in a dry run does nothing.
pub type Gh<'a> = &'a mut dyn FnMut(&[&str]) -> Result<String, String>;

pub fn gh(args: &[&str]) -> Result<String, String> {
    exec(Command::new("gh").args(args).env("GH_PROMPT_DISABLED", "1"))
}

/// Every issue of `repo` (open and closed) with a `Fingerprint:` line; an open one wins, else
/// the newest.
pub fn list(repo: &str) -> Result<BTreeMap<String, Known>, String> {
    let fields = "number,state,closedAt,body";
    let out = gh(&[
        "issue", "list", "-R", repo, "--state", "all", "--limit", "1000", "--json", fields,
    ])?;
    let items: Vec<Value> =
        serde_json::from_str(&out).map_err(|e| format!("gh list {repo}: {e}"))?;
    let mut found: BTreeMap<String, Known> = BTreeMap::new();
    for item in &items {
        let body = item["body"].as_str().unwrap_or("");
        let line = body
            .lines()
            .find_map(|l| l.trim().strip_prefix("Fingerprint:"));
        let Some(line) = line else { continue };
        let fp = line.trim().trim_matches('`').to_owned();
        let number = item["number"].as_u64().unwrap_or(0);
        let open = item["state"] == "OPEN";
        let old = found.get(&fp).map_or((false, 0), |k| (k.open, k.number));
        if (open, number) > old {
            let closed_at = item["closedAt"].as_str().and_then(time::parse);
            found.insert(
                fp,
                Known {
                    number,
                    open,
                    closed_at,
                },
            );
        }
    }
    Ok(found)
}

/// Closed issues of `repo` with 7 or more saved runs since the day they closed and no
/// recurrence in any, as `repo#number fingerprint`.
pub fn fixed(repo: &str, known: &BTreeMap<String, Known>, ledger: &Ledger) -> Vec<String> {
    let mut fixed = Vec::new();
    for (fp, issue) in known.iter().filter(|(_, issue)| !issue.open) {
        let Some(closed) = issue.closed_at else {
            continue;
        };
        let after = ledger.runs.range(time::date(closed + time::DAY)..);
        let runs: Vec<&Run> = after.map(|(_, run)| run).collect();
        if runs.len() >= 7 && runs.iter().all(|run| !run.contains_key(fp)) {
            fixed.push(format!("{repo}#{} {fp}", issue.number));
        }
    }
    fixed
}

pub struct Line {
    pub epoch: i64,
    pub new: bool,
    pub text: String,
}

/// One fingerprint seen in this scan, and the repository that owns it.
pub struct Group {
    pub fp: String,
    pub repo: &'static str,
    pub title: String,
    pub lines: Vec<Line>,
    /// Occurrences in earlier runs; 0 means a new failure.
    pub before: u64,
}

impl Group {
    pub fn new(
        fp: &str,
        repo: &'static str,
        title: String,
        lines: impl IntoIterator<Item = (i64, bool, String)>,
        ledger: &Ledger,
        today: &str,
    ) -> Group {
        let lines = lines
            .into_iter()
            .map(|(epoch, new, text)| Line { epoch, new, text });
        Group {
            fp: fp.to_owned(),
            repo,
            title,
            lines: lines.collect(),
            before: ledger.total(fp, today),
        }
    }

    /// The count of lines after `after` (or the new ones when `None`), and the newest 8 of
    /// them as bullets. Lines are in time order.
    fn quoted(&self, after: Option<i64>) -> (usize, String) {
        let keep = |line: &&Line| after.map_or(line.new, |at| line.epoch > at);
        let kept: Vec<&Line> = self.lines.iter().rev().filter(keep).collect();
        let mut bullets = String::new();
        for line in kept.iter().take(8) {
            bullets += &format!("- {}\n", line.text);
        }
        (kept.len(), bullets)
    }
}

/// `summary`, or `FAILED <summary>: <error>`.
fn outcome(summary: String, result: &Result<String, String>) -> String {
    match result {
        Ok(_) => summary,
        Err(e) => format!("FAILED {summary}: {e}"),
    }
}

/// Comment on an open issue with its new occurrences, or reopen a closed one that recurred.
fn follow_up(g: &Group, issue: &Known, gh: Gh) -> Option<String> {
    let (count, quoted) = g.quoted(if issue.open {
        None
    } else {
        Some(issue.closed_at.unwrap_or(0))
    });
    let (verb, flag, what) = match issue.open {
        true => ("comment", "--body", "new occurrence(s) of"),
        false => ("reopen", "--comment", "fix did not work: recurrence(s) of"),
    };
    let (number, body) = (
        issue.number.to_string(),
        format!("Daily scan: {count} {what} {}\n\n{quoted}", g.fp),
    );
    let args: [&str; 7] = ["issue", verb, &number, "-R", g.repo, flag, &body];
    (count > 0).then(|| outcome(format!("{verb} {}#{number} ({})", g.repo, g.fp), &gh(&args)))
}

/// File a new issue and note it in the ledger.
fn create(g: &Group, ledger: &mut Ledger, gh: Gh) -> String {
    let body = format!(
        "{}\n\nFingerprint: {}\n\
         Checked: scanned Mac and Dell transcripts and broker receipts; {} events on {} days, \
         no open or closed issue carries this fingerprint.\n\n\
         Occurrences in the last run (newest first):\n{}\n\nFiled by `legion daily`.",
        g.title,
        g.fp,
        ledger.total(&g.fp, ""),
        ledger.days(&g.fp),
        g.quoted(Some(i64::MIN)).1,
    );
    let args: [&str; 8] = [
        "issue", "create", "-R", g.repo, "--title", &g.title, "--body", &body,
    ];
    let made = gh(&args);
    let url = made.as_ref().map_or("", |url| url.trim());
    if let Some(number) = url.rsplit('/').next().and_then(|n| n.parse().ok()) {
        ledger.issues.insert(g.fp.clone(), number);
    }
    outcome(format!("create {}: {}", g.repo, g.title), &made)
}

/// Do what GitHub needs, one line per action. `known` holds a repo only when its listing
/// worked; a repo without one is never written to. `ledger` already holds this run. An
/// unclassified fingerprint is too broad to file, and one the ledger already filed is not
/// filed twice (a fresh issue may not be in the listing yet).
pub fn sync(
    groups: &[Group],
    known: &BTreeMap<&str, BTreeMap<String, Known>>,
    ledger: &mut Ledger,
    gh: Gh,
) -> Vec<String> {
    let (mut done, mut creates) = (Vec::new(), 0);
    let mut order: Vec<&Group> = groups.iter().collect();
    order.sort_by_key(|group| std::cmp::Reverse(group.lines.len()));
    for g in order {
        let fp = &g.fp;
        match known.get(g.repo).map(|issues| issues.get(fp)) {
            Some(Some(issue)) => done.extend(follow_up(g, issue, gh)),
            Some(None) if !ledger.issues.contains_key(fp) && ledger.qualifies(fp) => {
                if creates < MAX_CREATES && !fp.ends_with("/unclassified") {
                    creates += 1;
                    done.push(create(g, ledger, gh));
                }
            }
            _ => {}
        }
    }
    done
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: i64 = time::DAY;
    const FP: &str = "B3/ci-as-compiler";
    type Listing = BTreeMap<&'static str, BTreeMap<String, Known>>;

    fn group(fp: &str, lines: &[(i64, bool)]) -> Group {
        let lines = lines
            .iter()
            .map(|&(epoch, new)| (epoch, new, format!("t{epoch}")));
        Group::new(fp, LEGION, "t".into(), lines, &Ledger::default(), "")
    }

    /// Save a run for `day` holding `groups`, as a daily run would.
    fn run_day(ledger: &mut Ledger, day: i64, groups: &[Group]) {
        ledger.record(&time::date(day * D), groups, (day + 1) * D, true);
    }

    /// A ledger where `FP` was seen at each of `at`, one run a day from day 1.
    fn saved(at: &[i64]) -> Ledger {
        let mut ledger = Ledger::default();
        for (day, at) in at.iter().enumerate() {
            run_day(&mut ledger, day as i64 + 1, &[group(FP, &[(*at, true)])]);
        }
        ledger
    }

    /// Issue 9 for `FP`: open, or closed at the time given.
    fn known(closed_at: Option<i64>) -> Known {
        Known {
            number: 9,
            open: closed_at.is_none(),
            closed_at,
        }
    }

    fn listing(issues: Vec<Known>) -> Listing {
        BTreeMap::from([(
            LEGION,
            issues.into_iter().map(|k| (FP.to_owned(), k)).collect(),
        )])
    }

    /// Run `sync` with a `gh` that records its calls and answers with an issue URL.
    fn run(groups: &[Group], known: &Listing, ledger: &mut Ledger) -> Vec<Vec<String>> {
        let mut calls = Vec::new();
        let mut gh = |args: &[&str]| {
            calls.push(args.iter().map(|arg| arg.to_string()).collect::<Vec<_>>());
            Ok::<String, String>("https://github.com/Orthic-Labs/legion/issues/41\n".to_owned())
        };
        sync(groups, known, ledger, &mut gh);
        calls
    }

    #[test]
    fn creation_needs_two_days_twelve_hours_apart_and_stops_at_five_a_run() {
        let mut ledger = saved(&[D + 100, 2 * D + 100]);
        assert!(ledger.qualifies(FP) && !saved(&[D + 86_000, 2 * D + 100]).qualifies(FP));
        let today = [group(FP, &[(2 * D, true)])];
        let calls = run(&today, &listing(vec![]), &mut ledger);
        assert_eq!(&calls[0][..2], ["issue", "create"]);
        let body = calls[0].last().unwrap();
        assert!(body.contains("\nFingerprint: B3/ci-as-compiler\nChecked: "));
        assert_eq!(ledger.issues[FP], 41);
        let fps: Vec<String> = (0..8).map(|n| format!("B3/c{n}")).collect();
        let groups =
            |at: i64| -> Vec<Group> { fps.iter().map(|fp| group(fp, &[(at, true)])).collect() };
        let mut many = Ledger::default();
        run_day(&mut many, 1, &groups(D + 100));
        run_day(&mut many, 2, &groups(2 * D + 100));
        let created = run(&groups(2 * D + 100), &listing(vec![]), &mut many);
        assert_eq!(created.len(), MAX_CREATES);
    }

    #[test]
    fn an_open_issue_gets_a_comment_for_new_occurrences_and_a_recurred_closed_one_reopens() {
        let mut ledger = Ledger::default();
        let (open, closed) = (listing(vec![known(None)]), |at| {
            listing(vec![known(Some(at))])
        });
        let both = [group(FP, &[(100, false), (200, true)])];
        let calls = run(&both, &open, &mut ledger);
        let comment = calls[0].last().unwrap();
        assert!(
            calls[0][1..3] == ["comment", "9"]
                && comment.contains("t200")
                && !comment.contains("t100")
        );
        assert!(run(&[group(FP, &[(100, false)])], &open, &mut ledger).is_empty());
        let calls = run(&both, &closed(150), &mut ledger);
        assert!(calls[0][1] == "reopen" && calls[0].last().unwrap().contains("fix did not work"));
        assert!(run(&both, &closed(300), &mut ledger).is_empty());
    }

    #[test]
    fn nothing_is_filed_without_a_listing_or_when_the_ledger_already_knows_an_issue() {
        let mut ledger = saved(&[D + 100, 2 * D + 100]);
        let groups = [group(FP, &[(2 * D, true)])];
        assert!(run(&groups, &BTreeMap::new(), &mut ledger).is_empty());
        ledger.issues.insert(FP.into(), 3);
        assert!(run(&groups, &listing(vec![]), &mut ledger).is_empty());
    }

    #[test]
    fn rates_and_fixes_come_from_saved_runs() {
        let mut ledger = saved(&[D + 5, 2 * D + 9, 3 * D + 1]);
        let from = time::date(2 * D);
        assert_eq!(
            (ledger.rate("B3", from.clone()..), ledger.rate("B4", from..)),
            (Some((1.0, 2)), Some((0.0, 2)))
        );
        let closed = Known {
            number: 2,
            open: false,
            closed_at: Some(3 * D + 50),
        };
        let closed = BTreeMap::from([(FP.to_owned(), closed)]);
        assert!(fixed(LEGION, &closed, &ledger).is_empty());
        (4..11).for_each(|day| run_day(&mut ledger, day, &[]));
        assert_eq!(
            fixed(LEGION, &closed, &ledger),
            [format!("{LEGION}#2 {FP}")]
        );
        run_day(&mut ledger, 11, &[group(FP, &[(11 * D, true)])]);
        assert!(fixed(LEGION, &closed, &ledger).is_empty());
    }
}
