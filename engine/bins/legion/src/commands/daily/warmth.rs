//! Broker warmth per host and repository, from the build-control receipts (read-only). Only
//! what is off becomes a flag: unexplained cold starts and rebuilt units, rebuilds with no
//! source, lockfile, toolchain or feature change, a warm target that went cold or shrank, a low
//! or falling cache hit rate against the previous run, low disk, and refusals by code. Each
//! repository also counts its jobs and keeps its slowest ones, and the broker's lifecycle log
//! gives the admission pauses (`ADMISSION_PAUSED` / `ADMISSION_RESUMED`).
use super::time;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
};

pub const RUSTRIGHT: &str = "Orthic-Labs/rustright";
pub const RIGHTKIT: &str = "Orthic-Labs/rightkit";
const DISK_FLOOR: u64 = 50 << 30;
const MIN_LOOKUPS: u64 = 20;
/// A refusal code the broker writes without the `RK_`/`RR_` prefix.
const ADMISSION: &str = "ADMISSION_REJECTED";

/// One repository's baseline at the previous run, the comparison for today's flags.
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Mark {
    #[serde(default)]
    hits: u64,
    #[serde(default)]
    misses: u64,
    /// The largest `freshness.unitsAtStart` of the run, when a receipt reported one.
    #[serde(default)]
    units: Option<u64>,
    /// The run's cohorts (toolchain, profile, triple, features), `;`-joined in sorted order.
    #[serde(default)]
    cohort: String,
}

/// `~/.legion/daily/warmth-<host>.json`: each repository's baseline at the previous run.
pub type State = BTreeMap<String, Mark>;

/// One job kept for the report: the slowest by `totalMs`.
struct Worst {
    ms: u64,
    id: String,
    what: String,
}

/// Jobs kept per repository as its worst.
const WORST: usize = 3;

#[derive(Default)]
pub struct Repo {
    jobs: u64,
    /// Cold starts of any cause (`odd` holds only the unexplained ones).
    cold: u64,
    worst: Vec<Worst>,
    /// `(now, previous)` when the warm target's unit count fell since the previous run.
    lost: Option<(u64, u64)>,
    hits: u64,
    misses: u64,
    units: Option<u64>,
    cohorts: BTreeSet<String>,
    /// Units `notFresh` in receipts whose inputs and cause verdict show no change.
    clean_not_fresh: u64,
    refused: BTreeMap<String, u64>,
    /// Flag slug -> how many (jobs or units).
    odd: BTreeMap<&'static str, u64>,
}

impl Repo {
    fn cohort_key(&self) -> String {
        self.cohorts
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(";")
    }
}

pub struct Flag {
    pub host: String,
    pub repo: String,
    pub slug: String,
    pub detail: String,
    pub owner: &'static str,
}

impl Flag {
    pub fn fingerprint(&self) -> String {
        format!("warmth/{}/{}", self.repo, self.slug)
    }
}

/// Admission pauses in the window, from the broker's lifecycle log.
#[derive(Default)]
pub struct Pauses {
    /// `ADMISSION_PAUSED` events inside the window.
    count: usize,
    /// Seconds paused inside the window (an unresumed pause runs to the window's end).
    secs: i64,
    /// Pauses with no `ADMISSION_RESUMED` logged after them.
    unresumed: usize,
    reasons: BTreeSet<String>,
}

#[derive(Default)]
pub struct Host {
    pub name: String,
    pub receipts: usize,
    /// `None` when the lifecycle log was not readable, so pauses are unknown, not absent.
    pub pauses: Option<Pauses>,
    pub repos: BTreeMap<String, Repo>,
    pub flags: Vec<Flag>,
}

/// The folder under `/claude/` (Mac `/Volumes/D/claude/<repo>`, Dell `D:\Claude\<repo>`).
fn repo_of(workspace: &str) -> String {
    let path = workspace.replace('\\', "/").to_lowercase();
    let from = path.find("/claude/").map_or(0, |at| at + 8);
    let first = path[from..].split('/').find(|part| !part.is_empty());
    first.unwrap_or("(none)").to_owned()
}

/// The `RK_`/`RR_` code (or `ADMISSION_REJECTED`) of a refused job; a plain `FAILED` is the
/// build's own result.
fn refusal(receipt: &Value) -> Option<String> {
    let text = |key: &str| receipt[key].as_str().unwrap_or("").trim_start();
    let first = |key: &str| {
        text(key)
            .split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'))
            .next()
            .filter(|w| {
                w.len() > 3 && (w.starts_with("RK_") || w.starts_with("RR_") || *w == ADMISSION)
            })
    };
    let coded = first("error")
        .or_else(|| first("reason"))
        .map(str::to_owned);
    match text("status") {
        "REJECTED" | "TIMED_OUT" => Some(coded.unwrap_or_else(|| text("status").to_owned())),
        "FAILED" => coded,
        _ => None,
    }
}

/// True when every rebuilt unit's cause is unexplained: the cause evidence is complete,
/// `causeCounts` is a non-empty object, and every key is `fingerprint-missing` or `unexplained`.
/// A toolchain, feature, profile, rustflags, source or dependency change is an explanation, and
/// so are first builds, generation changes and evictions. The input closure only compares a job's
/// inputs before and after that one job, so it is not evidence about the previous build.
fn inputs_unchanged(receipt: &Value) -> bool {
    let fresh = &receipt["freshness"];
    let causes = fresh["causeCounts"].as_object();
    fresh["causeEvidence"]["state"] == "complete"
        && causes.is_some_and(|map| {
            !map.is_empty()
                && map
                    .keys()
                    .all(|key| matches!(key.as_str(), "fingerprint-missing" | "unexplained"))
        })
        && receipt["inputClosure"]["status"] == "verified"
}

/// Count one job receipt into its repository.
fn tally(repos: &mut BTreeMap<String, Repo>, receipt: &Value) {
    let workspace = receipt["workspace"].as_str().unwrap_or("");
    let repo = repos.entry(repo_of(workspace)).or_default();
    let (fresh, reuse) = (&receipt["freshness"], &receipt["cache"]["reuse"]);
    repo.jobs += 1;
    let what = format!(
        "{} {}, {} not fresh",
        receipt["stage"]["name"].as_str().unwrap_or("job"),
        receipt["status"].as_str().unwrap_or("?").to_lowercase(),
        fresh["notFresh"].as_u64().unwrap_or(0)
    );
    let id = receipt["id"].as_str().unwrap_or("?");
    repo.worst.push(Worst {
        ms: receipt["totalMs"].as_u64().unwrap_or(0),
        id: id.chars().take(8).collect(),
        what,
    });
    repo.worst.sort_by(|a, b| b.ms.cmp(&a.ms));
    repo.worst.truncate(WORST);
    if matches!(reuse["status"].as_str(), Some("PROVEN" | "MIXED" | "MISS")) {
        repo.hits += reuse["hits"].as_u64().unwrap_or(0);
        repo.misses += reuse["misses"].as_u64().unwrap_or(0);
    }
    if let Some(units) = fresh["unitsAtStart"].as_u64() {
        repo.units = Some(repo.units.map_or(units, |most| most.max(units)));
    }
    let cohort = &receipt["cacheCohort"];
    if cohort.is_object() {
        repo.cohorts.insert(format!(
            "{}|{}|{}|{}|{}",
            cohort["toolchain"],
            cohort["profile"],
            cohort["targetTriple"],
            cohort["features"],
            cohort["defaultFeatures"]
        ));
    }
    if receipt["coldStart"] == true {
        repo.cold += 1;
        let reason = fresh["coldCause"]
            .as_str()
            .or(receipt["coldStartReason"].as_str());
        let explained = ["empty", "missing", "first", "new", "absent"];
        if !reason
            .unwrap_or("")
            .split(['-', '_', ' '])
            .any(|word| explained.contains(&word))
        {
            *repo.odd.entry("unexplained-cold-starts").or_default() += 1;
        }
    }
    *repo.odd.entry("unexplained-rebuilt-units").or_default() +=
        fresh["unexplainedCount"].as_u64().unwrap_or(0);
    if inputs_unchanged(receipt) {
        repo.clean_not_fresh += fresh["notFresh"].as_u64().unwrap_or(0);
    }
    if let Some(code) = refusal(receipt) {
        *repo.refused.entry(code).or_default() += 1;
    }
}

fn rate((hits, misses): (u64, u64)) -> Option<f64> {
    (hits + misses >= MIN_LOOKUPS).then(|| hits as f64 / (hits + misses) as f64)
}

/// A flag for everything that is off, owned by RightKit for `RK_*` codes, else RustRight.
fn flags(
    host: &str,
    repos: &BTreeMap<String, Repo>,
    disk: Option<u64>,
    prior: &State,
    pauses: Option<&Pauses>,
) -> Vec<Flag> {
    let mut flags = Vec::new();
    let mut flag = |repo: &str, slug: String, detail: String| {
        let owner = if slug.starts_with("refusal-rk-") {
            RIGHTKIT
        } else {
            RUSTRIGHT
        };
        flags.push(Flag {
            host: host.to_owned(),
            repo: repo.to_owned(),
            slug,
            detail,
            owner,
        });
    };
    for (name, repo) in repos {
        for (slug, count) in repo.odd.iter().filter(|(_, count)| **count > 0) {
            flag(name, slug.to_string(), format!("{count} {slug}"));
        }
        let saved = prior.get(name);
        let before = saved.and_then(|mark| rate((mark.hits, mark.misses)));
        if let Some(now) = rate((repo.hits, repo.misses)) {
            if now < 0.5 || before.is_some_and(|before| before - now >= 0.2) {
                let was = before.map_or(String::new(), |b| {
                    format!(" (previous run {:.0}%)", b * 100.0)
                });
                flag(
                    name,
                    "low-cache-hit-rate".into(),
                    format!("hit rate {:.0}%{was}", now * 100.0),
                );
            }
        }
        if let Some((now, was)) = repo.lost {
            let verdict = if now == 0 {
                ", went cold"
            } else if now * 2 < was {
                ", shrank by half or more"
            } else {
                ""
            };
            flag(
                name,
                "warm-target-units-lost".into(),
                format!(
                    "{} units lost, {was} -> {now} since the previous run{verdict}",
                    was - now
                ),
            );
        }
        let cohort = repo.cohort_key();
        let same_cohort = saved.is_some_and(|mark| mark.cohort == cohort && !cohort.is_empty());
        if repo.clean_not_fresh > 0 && same_cohort {
            flag(
                name,
                "not-fresh-without-change".into(),
                format!(
                    "{} units rebuilt with no source, lockfile, toolchain or feature change",
                    repo.clean_not_fresh
                ),
            );
        }
        for (code, count) in &repo.refused {
            let slug = format!("refusal-{}", code.to_lowercase().replace('_', "-"));
            flag(name, slug, format!("{code}: {count} job(s)"));
        }
    }
    if let Some(paused) = pauses.filter(|p| p.count > 0 || p.unresumed > 0) {
        let reasons: Vec<&str> = paused.reasons.iter().map(String::as_str).collect();
        let reason = if reasons.is_empty() {
            String::new()
        } else {
            format!(": {}", reasons.join("; "))
        };
        let open = match paused.unresumed {
            0 => String::new(),
            n => format!(", {n} with no resume logged"),
        };
        flag(
            host,
            "admission-paused".into(),
            format!(
                "{} admission pause(s), {} paused{open}{reason}",
                paused.count,
                duration(paused.secs)
            ),
        );
    }
    if let Some(free) = disk.filter(|free| *free < DISK_FLOOR) {
        flag(
            host,
            "disk-low".into(),
            format!("{} GiB free on the build volume", free >> 30),
        );
    }
    flags
}

/// Seconds as `42s`, `7m05s` or `2h03m`.
fn duration(secs: i64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m{:02}s", s / 60, s % 60),
        s => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
    }
}

/// Milliseconds as `640ms`, `41s` or `7m05s`.
fn millis(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        duration((ms / 1000) as i64)
    }
}

/// The admission pauses in `window` from the broker's `lifecycle.ndjson`. The broker writes
/// `{"at", "type": "ADMISSION_PAUSED" | "ADMISSION_RESUMED", "reason", "holderPid"}` for every
/// pause and resume; the log is also full of heartbeats, so only lines naming `ADMISSION_` are
/// parsed. A pause that began before the window counts for the time it overlaps. A dead holder
/// may lift a pause without a resume event, so "no resume logged" is all that is claimed.
fn read_pauses(log: &Path, window: (i64, i64)) -> Option<Pauses> {
    let text = fs::read_to_string(log).ok()?;
    let mut found = Pauses::default();
    let mut open: Option<i64> = None;
    let close = |found: &mut Pauses, from: i64, to: i64| {
        found.secs += (to.min(window.1) - from.max(window.0)).max(0);
    };
    for line in text.lines().filter(|line| line.contains("\"ADMISSION_")) {
        let Ok(event) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(at) = event["at"].as_str().and_then(time::parse) else {
            continue;
        };
        match event["type"].as_str() {
            Some("ADMISSION_PAUSED") if at <= window.1 => {
                if let Some(from) = open.replace(at) {
                    close(&mut found, from, at);
                }
                if at >= window.0 {
                    found.count += 1;
                    let pid = event["holderPid"].as_u64();
                    let by = pid.map_or(String::new(), |pid| format!(" (holder pid {pid})"));
                    let why = event["reason"].as_str().unwrap_or("no reason given");
                    found.reasons.insert(format!("{}{by}", why.trim()));
                }
            }
            Some("ADMISSION_RESUMED") if at <= window.1 => {
                if let Some(from) = open.take() {
                    close(&mut found, from, at);
                }
            }
            _ => {}
        }
    }
    if let Some(from) = open {
        close(&mut found, from, window.1);
        found.unresumed = 1;
    }
    Some(found)
}

/// One row per repository that has a flag on `host`: its jobs, cold starts, unexplained
/// rebuilt units, units lost since the previous run, and its slowest jobs.
pub fn report(host: &Host) -> Vec<String> {
    let mut rows = Vec::new();
    for (name, repo) in &host.repos {
        if !host.flags.iter().any(|flag| flag.repo == *name) {
            continue;
        }
        let odd = |slug: &str| repo.odd.get(slug).copied().unwrap_or(0);
        let lost = repo
            .lost
            .map_or("0".to_owned(), |(now, was)| (was - now).to_string());
        let worst: Vec<String> = repo
            .worst
            .iter()
            .map(|job| format!("{} {} ({})", job.id, millis(job.ms), job.what))
            .collect();
        rows.push(format!(
            "{} {name}: {} jobs, {} cold starts ({} unexplained), {} unexplained rebuilt units, \
             {lost} units lost since the previous run; worst: {}",
            host.name,
            repo.jobs,
            repo.cold,
            odd("unexplained-cold-starts"),
            odd("unexplained-rebuilt-units"),
            worst.join("; ")
        ));
    }
    rows
}

/// Measure one host from the receipts in `dir` submitted inside `window`.
pub fn measure(
    name: &str,
    dir: &Path,
    window: (i64, i64),
    disk: Option<u64>,
    prior: &State,
    lifecycle: Option<&Path>,
) -> Result<Host, String> {
    let entries = fs::read_dir(dir).map_err(|e| format!("receipts at {}: {e}", dir.display()))?;
    let (mut repos, mut receipts) = (BTreeMap::new(), 0);
    for entry in entries.flatten() {
        let file = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = entry.metadata() else { continue };
        if !file.ends_with(".json")
            || file.contains("evidence")
            || time::modified(&meta) < window.0 - 300
        {
            continue;
        }
        let body = fs::read_to_string(entry.path()).ok();
        let Some(receipt) = body.and_then(|text| serde_json::from_str::<Value>(&text).ok()) else {
            continue;
        };
        let submitted = receipt["submittedAt"].as_str().and_then(time::parse);
        receipts += 1;
        if submitted.is_some_and(|at| (window.0..=window.1).contains(&at)) {
            tally(&mut repos, &receipt);
        }
    }
    for (repo_name, repo) in &mut repos {
        let was = prior.get(repo_name).and_then(|mark| mark.units);
        repo.lost = repo.units.zip(was).filter(|(now, was)| was > now);
    }
    let pauses = lifecycle.and_then(|log| read_pauses(log, window));
    let flags = flags(name, &repos, disk, prior, pauses.as_ref());
    Ok(Host {
        name: name.to_owned(),
        receipts,
        pauses,
        repos,
        flags,
    })
}

/// Remember this run as the baseline for the next one. A repository keeps its last usable hit
/// rate, unit count and cohort when this run has too few lookups or none of that signal.
pub fn remember(state: &mut State, host: &Host) {
    for (name, repo) in &host.repos {
        let mut mark = state.get(name).cloned().unwrap_or_default();
        if rate((repo.hits, repo.misses)).is_some() {
            mark.hits = repo.hits;
            mark.misses = repo.misses;
        }
        if repo.units.is_some() {
            mark.units = repo.units;
        }
        let cohort = repo.cohort_key();
        if !cohort.is_empty() {
            mark.cohort = cohort;
        }
        state.insert(name.clone(), mark);
    }
}
