//! Gate coverage per host and repository, from the `rightkit.gate-coverage/1` reports the gate
//! writes after each pass (read-only). Each report is one run: `startedAt`/`endedAt` bound the
//! scan phase only, and `scans[]` holds `id`, `class`, `coverage` (`hit`, `ran`, `skipped`),
//! `status`, `key`, `reason` and an optional `code`. A keyed row that ran is a reusable row whose
//! cache missed. A rerun of an identical commit should hit every keyed row it passed before,
//! so misses there are the flag. A gate that adds `timing` to a row (`invocationId`,
//! `elapsedMs`, `cacheLookupMs`, `executionMs`) gives per-scan time; rows sharing one
//! `invocationId` are one execution and count once. A null field is unknown, not zero: each
//! sum says how many invocations it covers. `batchAttempts` counts batch tries and a numeric
//! `retries` is summed. Without `timing` the time stays unknown. No environment hash or broker
//! request id is derived; a missing or unreadable report is unknown, never a pass.
use super::{time, warmth};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub const SCHEMA: &str = "rightkit.gate-coverage/1";
/// Keyed lookups on identical-commit reruns needed before a hit rate is a flag.
const MIN_KEYED: u64 = 20;

/// One gate run's counts.
#[derive(Default, Clone, Copy)]
struct Counts {
    /// Rows with a cache key that ran: the reusable rows that missed.
    keyed_ran: u64,
    keyed_hit: u64,
    a_ran: u64,
    a_hit: u64,
    timeouts: u64,
}

/// Per-scan time from rows that carry `timing`, summed once per invocation.
#[derive(Default)]
struct Timing {
    rows: u64,
    invocations: BTreeMap<String, [Option<f64>; 3]>,
    batch_attempts: u64,
    retries: u64,
    /// The slowest invocations as (elapsed ms, scan id).
    slowest: Vec<(f64, String)>,
}

#[derive(Default)]
pub struct Repo {
    runs: u64,
    commits: BTreeSet<String>,
    /// Scan-phase milliseconds of each run, in the order the runs ended.
    phase_ms: Vec<u64>,
    total: Counts,
    /// Keyed rows on reruns of a commit already seen in the window.
    rerun_ran: u64,
    rerun_hit: u64,
    reruns: u64,
    /// Failed rows by `code` (or `status` when no code).
    failed: BTreeMap<String, u64>,
    timing: Timing,
}

#[derive(Default)]
pub struct Host {
    pub name: String,
    pub reports: usize,
    /// Reports that were not JSON or not this schema.
    pub unreadable: usize,
    pub repos: BTreeMap<String, Repo>,
    pub flags: Vec<warmth::Flag>,
}

/// The repository is the file name's prefix before `-YYYY-`: `heardright-2026-11-04T…json`.
fn repo_of(file: &str) -> Option<&str> {
    let bytes = file.as_bytes();
    (1..bytes.len().saturating_sub(5)).find_map(|at| {
        let year = file.get(at + 1..at + 5)?;
        (bytes[at] == b'-' && bytes[at + 5] == b'-' && year.bytes().all(|b| b.is_ascii_digit()))
            .then(|| &file[..at])
    })
}

/// Epoch milliseconds for `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn parse_ms(text: &str) -> Option<i64> {
    let ms = text
        .get(19..)
        .and_then(|rest| rest.strip_prefix('.'))
        .map_or(Some(0), |frac| frac.get(..3)?.parse::<i64>().ok())?;
    Some(time::parse(text)? * 1000 + ms)
}

fn is_timeout(row: &Value) -> bool {
    ["code", "reason", "status"].iter().any(|key| {
        let text = row[*key].as_str().unwrap_or("").to_lowercase();
        text.contains("timeout") || text.contains("timed out") || text.contains("timed_out")
    })
}

fn count(report: &Value, repo: &mut Repo) -> Counts {
    let mut counts = Counts::default();
    for row in report["scans"].as_array().into_iter().flatten() {
        let keyed = row["key"].as_str().is_some_and(|key| !key.is_empty());
        let class_a = row["class"] == "A";
        match row["coverage"].as_str() {
            Some("hit") => {
                counts.keyed_hit += u64::from(keyed);
                counts.a_hit += u64::from(class_a);
            }
            Some("ran") => {
                counts.keyed_ran += u64::from(keyed);
                counts.a_ran += u64::from(class_a);
            }
            _ => {}
        }
        if is_timeout(row) {
            counts.timeouts += 1;
        }
        let ms = |key: &str| row["timing"][key].as_f64();
        if let Some(invocation) = row["timing"]["invocationId"].as_str() {
            let t = &mut repo.timing;
            t.rows += 1;
            let elapsed = ms("elapsedMs").unwrap_or(0.0);
            let id = row["id"].as_str().unwrap_or("?").to_owned();
            if !t.invocations.contains_key(invocation) {
                t.slowest.push((elapsed, id));
                t.slowest.sort_by(|a, b| b.0.total_cmp(&a.0));
                t.slowest.truncate(3);
            }
            t.invocations.insert(
                invocation.to_owned(),
                [ms("elapsedMs"), ms("cacheLookupMs"), ms("executionMs")],
            );
        }
        repo.timing.retries += row["retries"].as_u64().unwrap_or(0);
        repo.timing.batch_attempts += row["batchAttempts"]
            .as_array()
            .map_or(0, |a| a.len() as u64);
        let status = row["status"].as_str().unwrap_or("?");
        if !matches!(status, "pass" | "not-in-pass" | "skipped") {
            let code = row["code"].as_str().unwrap_or(status);
            *repo.failed.entry(code.to_owned()).or_default() += 1;
        }
    }
    counts
}

fn add(total: &mut Counts, one: Counts) {
    total.keyed_ran += one.keyed_ran;
    total.keyed_hit += one.keyed_hit;
    total.a_ran += one.a_ran;
    total.a_hit += one.a_hit;
    total.timeouts += one.timeouts;
}

/// Read every coverage report in `dir` whose run ended inside `window`.
pub fn measure(name: &str, dir: &Path, window: (i64, i64)) -> Result<Host, String> {
    let entries =
        fs::read_dir(dir).map_err(|e| format!("gate coverage at {}: {e}", dir.display()))?;
    let mut runs: Vec<(i64, String, Value)> = Vec::new();
    let (mut reports, mut unreadable) = (0, 0);
    for entry in entries.flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = entry.metadata() else { continue };
        if !file.ends_with(".json") || time::modified(&meta) < window.0 - 300 {
            continue;
        }
        let Some(repo) = repo_of(&file) else { continue };
        let body = fs::read_to_string(entry.path()).ok();
        let report = body.and_then(|text| serde_json::from_str::<Value>(&text).ok());
        let Some(report) = report.filter(|r| r["schema"] == SCHEMA) else {
            unreadable += 1;
            continue;
        };
        let Some(ended) = report["endedAt"].as_str().and_then(parse_ms) else {
            unreadable += 1;
            continue;
        };
        reports += 1;
        if (window.0 * 1000..=window.1 * 1000).contains(&ended) {
            runs.push((ended, repo.to_owned(), report));
        }
    }
    runs.sort_by_key(|run| run.0);
    let mut repos: BTreeMap<String, Repo> = BTreeMap::new();
    for (ended, name, report) in &runs {
        let repo = repos.entry(name.clone()).or_default();
        let counts = count(report, repo);
        add(&mut repo.total, counts);
        repo.runs += 1;
        let started = report["startedAt"].as_str().and_then(parse_ms);
        if let Some(ms) = started.map(|s| ended - s).filter(|ms| *ms >= 0) {
            repo.phase_ms.push(ms as u64);
        }
        let commit = report["commit"].as_str().unwrap_or("").to_owned();
        if !commit.is_empty() && !repo.commits.insert(commit) {
            repo.reruns += 1;
            repo.rerun_ran += counts.keyed_ran;
            repo.rerun_hit += counts.keyed_hit;
        }
    }
    let flags = flags(name, &repos);
    Ok(Host {
        name: name.to_owned(),
        reports,
        unreadable,
        repos,
        flags,
    })
}

fn flags(host: &str, repos: &BTreeMap<String, Repo>) -> Vec<warmth::Flag> {
    let mut flags = Vec::new();
    let mut flag = |repo: &str, slug: &str, detail: String| {
        flags.push(warmth::Flag {
            kind: "gate",
            host: host.to_owned(),
            repo: repo.to_owned(),
            slug: slug.to_owned(),
            detail,
            owner: warmth::RIGHTKIT,
        });
    };
    for (name, repo) in repos {
        let keyed = repo.rerun_ran + repo.rerun_hit;
        if keyed >= MIN_KEYED && repo.rerun_hit * 2 < keyed {
            flag(
                name,
                "rerun-cache-miss",
                format!(
                    "{} rerun(s) of an identical commit hit {} of {keyed} keyed rows ({} missed)",
                    repo.reruns, repo.rerun_hit, repo.rerun_ran
                ),
            );
        }
        if repo.total.timeouts > 0 {
            flag(
                name,
                "scan-timeouts",
                format!("{} scan row(s) timed out", repo.total.timeouts),
            );
        }
    }
    flags
}

fn millis(ms: u64) -> String {
    if ms < 10_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{}s", ms / 1000)
    }
}

/// One row per repository with gate runs on `host`, flagged or not: the raw counts and timings.
pub fn report(host: &Host) -> Vec<String> {
    let mut rows = Vec::new();
    for (name, repo) in &host.repos {
        let mut sorted = repo.phase_ms.clone();
        sorted.sort_unstable();
        let phase = match (sorted.get(sorted.len() / 2), sorted.last()) {
            (Some(mid), Some(max)) => {
                format!("scan phase median {}, max {}", millis(*mid), millis(*max))
            }
            _ => "scan phase unknown".to_owned(),
        };
        let t = repo.total;
        let failed: Vec<String> = repo
            .failed
            .iter()
            .map(|(code, n)| format!("{code} {n}"))
            .collect();
        let failed = if failed.is_empty() {
            "none".to_owned()
        } else {
            failed.join(", ")
        };
        let tm = &repo.timing;
        let timing = if tm.rows == 0 {
            "per-scan timing not in the reports".to_owned()
        } else {
            let total = tm.invocations.len();
            let sum = |field: usize| {
                let known: Vec<f64> = tm.invocations.values().filter_map(|t| t[field]).collect();
                let ms = millis(known.iter().sum::<f64>() as u64);
                if known.len() == total {
                    ms
                } else {
                    format!("{ms} ({} of {total} known)", known.len())
                }
            };
            let slowest: Vec<String> = tm
                .slowest
                .iter()
                .map(|(ms, id)| format!("{id} {}", millis(*ms as u64)))
                .collect();
            format!(
                "{} timed rows in {total} invocations: aggregate scan service time {} (rows run \
                 concurrently and overlap: not wall time), cache lookup {}, execution {}, \
                 {} batch attempts, {} retries; slowest {}",
                tm.rows,
                sum(0),
                sum(1),
                sum(2),
                tm.batch_attempts,
                tm.retries,
                slowest.join(", ")
            )
        };
        rows.push(format!(
            "{} {name}: {} runs over {} commits ({} reruns), {phase}; Class A {} ran, {} hit; \
             keyed rows {} hit of {} (reruns {} of {}); {} timeouts; failed rows: {failed}; \
             {timing}",
            host.name,
            repo.runs,
            repo.commits.len(),
            repo.reruns,
            t.a_ran,
            t.a_hit,
            t.keyed_hit,
            t.keyed_hit + t.keyed_ran,
            repo.rerun_hit,
            repo.rerun_hit + repo.rerun_ran,
            t.timeouts,
        ));
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn repo_from_file_name() {
        assert_eq!(
            repo_of("heardright-2026-11-04T11-46-33-239Z-68995.json"),
            Some("heardright")
        );
        assert_eq!(
            repo_of("rk-agent-2026-11-04T10-04-02-870Z-1.json"),
            Some("rk-agent")
        );
        assert_eq!(repo_of("notes.json"), None);
    }

    #[test]
    fn millisecond_timestamps() {
        let a = parse_ms("2026-11-04T11:46:26.922Z").unwrap();
        let b = parse_ms("2026-11-04T11:46:33.239Z").unwrap();
        assert_eq!(b - a, 6317);
        assert_eq!(parse_ms("2026-11-04T11:46:26Z").unwrap() % 1000, 0);
    }

    #[test]
    fn identical_commit_rerun_that_misses_is_flagged() {
        let dir = std::env::temp_dir().join(format!("legion-gate-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let rows: Vec<Value> = (0..30)
            .map(|i| {
                json!({"id": format!("s{i}"), "class": "A", "coverage": "ran",
                    "status": "pass", "key": "k"})
            })
            .collect();
        for (i, end) in ["10:00:05.000", "10:10:05.000"].iter().enumerate() {
            let report = json!({"schema": SCHEMA, "commit": "abc",
                "startedAt": "2026-11-04T10:00:00.000Z", "endedAt": format!("2026-11-04T{end}Z"),
                "scans": rows});
            let path = dir.join(format!("heardright-2026-11-04T10-0{i}-00-000Z-{i}.json"));
            fs::write(path, report.to_string()).unwrap();
        }
        let start = time::parse("2026-11-04T00:00:00Z").unwrap();
        // The files' mtimes are now, so the window must cover now as well as the run times.
        let host = measure("mac", &dir, (start, time::now() + 60)).unwrap();
        let _ = fs::remove_dir_all(&dir);
        let repo = &host.repos["heardright"];
        assert_eq!(
            (repo.runs, repo.reruns, repo.rerun_ran, repo.rerun_hit),
            (2, 1, 30, 0)
        );
        assert!(host.flags.iter().any(|f| f.slug == "rerun-cache-miss"));
    }
}
