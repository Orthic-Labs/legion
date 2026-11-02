//! Broker warmth per host and repository, from the build-control receipts (read-only). Only
//! what is off becomes a flag: unexplained cold starts and rebuilt units, a low or falling
//! cache hit rate against the previous run, low disk, and refusals by code.
use super::time;
use serde_json::Value;
use std::{collections::BTreeMap, fs, path::Path};

pub const RUSTRIGHT: &str = "Orthic-Labs/rustright";
pub const RIGHTKIT: &str = "Orthic-Labs/rightkit";
const DISK_FLOOR: u64 = 50 << 30;
const MIN_LOOKUPS: u64 = 20;

/// `~/.legion/daily/warmth-<host>.json`: each repository's (hits, misses) at the previous run.
pub type State = BTreeMap<String, (u64, u64)>;

#[derive(Default)]
pub struct Repo {
    hits: u64,
    misses: u64,
    refused: BTreeMap<String, u64>,
    /// Flag slug -> how many (jobs or units).
    odd: BTreeMap<&'static str, u64>,
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

#[derive(Default)]
pub struct Host {
    pub name: String,
    pub receipts: usize,
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

/// The `RK_`/`RR_` code of a refused job; a plain `FAILED` is the build's own result.
fn refusal(receipt: &Value) -> Option<String> {
    let text = |key: &str| receipt[key].as_str().unwrap_or("").trim_start();
    let first = |key: &str| {
        let word =
            text(key).split(|c: char| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'));
        word.into_iter()
            .next()
            .filter(|w| w.len() > 3 && (w.starts_with("RK_") || w.starts_with("RR_")))
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

/// Count one job receipt into its repository.
fn tally(repos: &mut BTreeMap<String, Repo>, receipt: &Value) {
    let workspace = receipt["workspace"].as_str().unwrap_or("");
    let repo = repos.entry(repo_of(workspace)).or_default();
    let (fresh, reuse) = (&receipt["freshness"], &receipt["cache"]["reuse"]);
    if matches!(reuse["status"].as_str(), Some("PROVEN" | "MIXED" | "MISS")) {
        repo.hits += reuse["hits"].as_u64().unwrap_or(0);
        repo.misses += reuse["misses"].as_u64().unwrap_or(0);
    }
    if receipt["coldStart"] == true {
        let reason = fresh["coldCause"]
            .as_str()
            .or(receipt["coldStartReason"].as_str());
        let explained = ["empty", "missing", "first", "new", "absent"];
        let words = reason.unwrap_or("").split(['-', '_', ' ']);
        if !words.into_iter().any(|word| explained.contains(&word)) {
            *repo.odd.entry("unexplained-cold-starts").or_default() += 1;
        }
    }
    *repo.odd.entry("unexplained-rebuilt-units").or_default() +=
        fresh["unexplainedCount"].as_u64().unwrap_or(0);
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
        let before = prior.get(name).and_then(|saved| rate(*saved));
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
        for (code, count) in &repo.refused {
            let slug = format!("refusal-{}", code.to_lowercase().replace('_', "-"));
            flag(name, slug, format!("{code}: {count} job(s)"));
        }
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

/// Measure one host from the receipts in `dir` submitted inside `window`.
pub fn measure(
    name: &str,
    dir: &Path,
    window: (i64, i64),
    disk: Option<u64>,
    prior: &State,
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
    let flags = flags(name, &repos, disk, prior);
    Ok(Host {
        name: name.to_owned(),
        receipts,
        repos,
        flags,
    })
}

/// Remember this run's hit counts as the baseline for the next one.
pub fn remember(state: &mut State, host: &Host) {
    for (name, repo) in &host.repos {
        if rate((repo.hits, repo.misses)).is_some() {
            state.insert(name.clone(), (repo.hits, repo.misses));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A `heardright` receipt with the fields of `extra` merged in.
    fn receipt(extra: &Value) -> Value {
        let mut base =
            json!({"workspace": "/Volumes/D/claude/heardright/app", "status": "SUCCEEDED"});
        base.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        base
    }

    fn reuse(hits: u64, misses: u64) -> Value {
        json!({"cache": {"reuse": {"status": "PROVEN", "hits": hits, "misses": misses}}})
    }

    /// The `slug owner` of each flag raised on the Dell by receipts with these `extras`.
    fn flagged(extras: &[Value], prior: &State, gib: u64) -> Vec<String> {
        let mut repos = BTreeMap::new();
        extras
            .iter()
            .for_each(|extra| tally(&mut repos, &receipt(extra)));
        let found = flags("dell", &repos, Some(gib << 30), prior);
        found
            .iter()
            .map(|flag| format!("{} {}", flag.slug, flag.owner))
            .collect()
    }

    #[test]
    fn unexplained_cold_starts_and_rebuilds_are_flagged_and_a_quiet_day_is_not() {
        let cold = |why| json!({"coldStart": true, "freshness": {"coldCause": why}});
        let rebuilt = json!({"freshness": {"unexplainedCount": 2}});
        let rustright = |slug: &str| format!("{slug} {RUSTRIGHT}");
        let found = flagged(
            &[cold("target-empty"), cold("target-nonempty")],
            &State::new(),
            500,
        );
        assert_eq!(found, [rustright("unexplained-cold-starts")]);
        let found = flagged(&[rebuilt], &State::new(), 500);
        assert_eq!(found, [rustright("unexplained-rebuilt-units")]);
        assert!(flagged(&[json!({})], &State::new(), 500).is_empty());
        assert_eq!(repo_of(r"D:\Claude\RustRight"), "rustright");
    }

    #[test]
    fn a_low_or_falling_hit_rate_needs_enough_lookups() {
        let prior = State::from([("heardright".to_owned(), (95, 5))]);
        let none = State::new();
        let low = [format!("low-cache-hit-rate {RUSTRIGHT}")];
        assert_eq!(flagged(&[reuse(60, 40)], &prior, 500), low);
        assert_eq!(flagged(&[reuse(5, 30)], &none, 500), low);
        assert!(flagged(&[reuse(1, 4)], &none, 500).is_empty());
        assert!(flagged(&[reuse(90, 10)], &prior, 500).is_empty());
    }

    #[test]
    fn refusals_go_to_the_owning_repo_low_disk_is_flagged_and_the_baseline_is_remembered() {
        let refused = |code: &str| json!({"status": "FAILED", "error": format!("{code}: nope")});
        let plain = json!({"status": "FAILED", "error": "tests failed"});
        let (rk, rr) = (refused("RK_GATE_DENIED"), refused("RR_COLD"));
        let found = flagged(&[rk, rr, plain], &State::new(), 10);
        let got: Vec<String> = found
            .iter()
            .map(|flag| flag.replace("Orthic-Labs/", ""))
            .collect();
        assert_eq!(
            got,
            [
                "refusal-rk-gate-denied rightkit",
                "refusal-rr-cold rustright",
                "disk-low rustright"
            ]
        );
        let mut host = Host::default();
        tally(&mut host.repos, &receipt(&reuse(30, 10)));
        let mut state = State::new();
        remember(&mut state, &host);
        assert_eq!(state["heardright"], (30, 10));
    }
}
