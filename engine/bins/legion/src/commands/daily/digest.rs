//! The daily digest, kept short, and the impact table: each recent Legion commit against its
//! bucket's failures per run before and after its date.
use super::{
    buckets, exec, issues,
    issues::{Group, Ledger},
    scan::clip,
    time,
};
use std::{collections::BTreeMap, path::Path, process::Command};

const ROWS: usize = 12;

type Listing = BTreeMap<String, issues::Known>;

/// The issue a group belongs to, or why it has none.
fn issue(known: &BTreeMap<&str, Listing>, ledger: &Ledger, g: &Group) -> String {
    let listed = known.get(g.repo).and_then(|issues| issues.get(&g.fp));
    match (listed, ledger.issues.get(&g.fp)) {
        _ if g.fp.ends_with("/unclassified") => "too broad to file".to_owned(),
        (Some(k), _) => format!("#{} {}", k.number, if k.open { "open" } else { "closed" }),
        (None, Some(number)) => format!("#{number} filed"),
        (None, None) => format!("no issue yet, seen on {} day(s)", ledger.days(&g.fp)),
    }
}

/// A titled list; at most `limit` rows. Nothing when there are no rows.
fn section(out: &mut String, title: &str, rows: &[String], limit: usize) {
    if !rows.is_empty() {
        let shown = rows[..rows.len().min(limit)].join("\n");
        out.push_str(&format!("\n## {title}\n{shown}\n"));
        if rows.len() > limit {
            out.push_str(&format!("- ... {} more\n", rows.len() - limit));
        }
    }
}

pub fn bullets(rows: &[String]) -> Vec<String> {
    rows.iter().map(|row| format!("- {row}")).collect()
}

/// The digest: `header`, the new and recurring failures and the warmth flags (each with its
/// issue), then the caller's `sections` (title, rows).
pub fn render(
    header: &str,
    groups: &[Group],
    (ledger, known): (&Ledger, &BTreeMap<&str, Listing>),
    sections: &[(&str, Vec<String>)],
) -> String {
    let row = |g: &Group| {
        let texts: Vec<&str> = g.lines.iter().map(|line| line.text.as_str()).collect();
        let detail = if g.fp.starts_with("warmth/") {
            texts.join(" | ")
        } else if g.before == 0 {
            format!(
                "x{}: {}",
                g.lines.len(),
                g.lines.first().map_or("", |line| line.text.as_str())
            )
        } else {
            format!(
                "{} today, {} total over {} day(s)",
                g.lines.len(),
                ledger.total(&g.fp, ""),
                ledger.days(&g.fp)
            )
        };
        format!(
            "- `{}` {} [{}]",
            g.fp,
            clip(&detail, 200),
            issue(known, ledger, g)
        )
    };
    let rows = |keep: &dyn Fn(&Group) -> bool| -> Vec<String> {
        groups.iter().filter(|g| keep(*g)).map(&row).collect()
    };
    let mut out = header.to_owned();
    let warm = |g: &Group| g.fp.starts_with("warmth/");
    section(
        &mut out,
        "New failures",
        &rows(&|g| !warm(g) && g.before == 0),
        ROWS,
    );
    section(
        &mut out,
        "Recurring failures",
        &rows(&|g| !warm(g) && g.before > 0),
        ROWS,
    );
    section(&mut out, "Warmth flags", &rows(&warm), ROWS);
    for (title, rows) in sections {
        section(&mut out, title, rows, usize::MAX);
    }
    if groups.is_empty() {
        out.push_str("\nNo failures or warmth flags.\n");
    }
    out
}

/// `(epoch, short sha, message)` for commits at or after `since`.
fn parse_log(log: &str, since: i64) -> Vec<(i64, String, String)> {
    let mut found = Vec::new();
    for record in log.split('\u{1e}') {
        let parts: Vec<&str> = record.trim_start().splitn(4, '\u{1f}').collect();
        let &[at, sha, subject, body] = parts.as_slice() else {
            continue;
        };
        let Ok(at) = at.parse::<i64>() else { continue };
        if at >= since {
            found.push((at, sha.to_owned(), format!("{subject}\n{body}")));
        }
    }
    found
}

/// One table row per commit of the last 7 days in `repo`.
pub fn impact(repo: &Path, now: i64, ledger: &Ledger) -> Result<Vec<String>, String> {
    let format = "--pretty=format:%ct%x1f%h%x1f%s%x1f%b%x1e";
    let mut git = Command::new("git");
    git.arg("-C").arg(repo).args(["log", "-n", "300", format]);
    let commits = parse_log(&exec(&mut git)?, now - 7 * time::DAY);
    let rows: Vec<String> = commits
        .iter()
        .map(|commit| table_row(commit, ledger))
        .collect();
    let head = [
        "| commit | date | subject | bucket | before | after |",
        "|---|---|---|---|---|---|",
    ];
    Ok(if rows.is_empty() {
        rows
    } else {
        head.iter()
            .map(|line| line.to_string())
            .chain(rows)
            .collect()
    })
}

/// A commit's bucket and its mean failures per saved run in the 7 days up to its date and in
/// the runs after it.
fn table_row((at, sha, message): &(i64, String, String), ledger: &Ledger) -> String {
    let rate = |found: Option<(f64, usize)>| {
        found.map_or("n/a".to_owned(), |(mean, runs)| {
            format!("{mean:.1} over {runs} runs")
        })
    };
    let subject = clip(message.lines().next().unwrap_or(""), 60).replace('|', "/");
    let (date, bucket) = (time::date(*at), buckets::of_commit(message));
    let (before, after) = match &bucket {
        Some(b) => (
            ledger.rate(b, time::date(at - 7 * time::DAY)..=date.clone()),
            ledger.rate(b, time::date(at + time::DAY)..),
        ),
        None => (None, None),
    };
    format!(
        "| {sha} | {date} | {subject} | {} | {} | {} |",
        bucket.unwrap_or("none".into()),
        rate(before),
        rate(after)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const D: i64 = time::DAY;

    fn group(fp: &str, before: u64, repo: &'static str) -> Group {
        let lines = vec![(3 * D, true, "mac s1 \"quote\"".to_owned())];
        Group {
            before,
            ..Group::new(fp, repo, "t".into(), lines, &Ledger::default(), "")
        }
    }

    #[test]
    fn render_separates_new_recurring_and_warmth_and_labels_issues() {
        let (legion, rustright) = ("Orthic-Labs/legion", "Orthic-Labs/rustright");
        let mut groups = vec![
            group("B3/new-one", 0, legion),
            group("B4/old-one", 1, legion),
        ];
        groups.push(group("B11/unclassified", 0, legion));
        groups.push(group("warmth/h/x", 0, rustright));
        let mut ledger = Ledger::default();
        ledger.issues.insert("B3/new-one".into(), 7);
        ledger.record("2026-01-02", &groups, 3 * D, true);
        let open = issues::Known {
            number: 3,
            open: true,
            closed_at: None,
        };
        let known = BTreeMap::from([(legion, BTreeMap::from([("B4/old-one".to_owned(), open)]))]);
        let sections = [("Issue actions", bullets(&["would comment".to_owned()]))];
        let text = render("# Daily\n", &groups, (&ledger, &known), &sections);
        assert!(text.contains("`B3/new-one` x1") && text.contains("[#7 filed]"));
        assert!(
            text.contains("1 total over 1 day(s) [#3 open]")
                && text.contains("[too broad to file]")
        );
        assert!(
            text.contains("## Warmth flags") && text.contains("## Issue actions\n- would comment")
        );
    }

    #[test]
    fn the_git_log_filters_by_time_and_a_commit_row_compares_its_bucket() {
        let log = "500\u{1f}abc1234\u{1f}fix B3\u{1f}body\u{1e}\n100\u{1f}old\u{1f}old\u{1f}\u{1e}";
        assert_eq!(parse_log(log, 200).len(), 1);
        let mut ledger = Ledger::default();
        for day in [8, 9, 12] {
            ledger.record(&time::date(day * D), &[group("B3/ci", 0, "r")], 0, true);
        }
        let row = |message: &str| table_row(&(10 * D + 100, "abc".into(), message.into()), &ledger);
        assert!(row("fix B3 rerun").contains("| B3 | 1.0 over 2 runs | 1.0 over 1 runs |"));
        assert!(row("docs").contains("| none | n/a | n/a |"));
    }
}
