//! Broker warmth per host and repository, from the build-control receipts (read-only). Only
//! what is off becomes a flag: unexplained cold starts and rebuilt units, rebuilds with no
//! source, lockfile, toolchain or feature change, a warm target that went cold or shrank, a low
//! or falling cache hit rate against the previous run, low disk, and refusals by code.
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

#[derive(Default)]
pub struct Repo {
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

/// True when the receipt names a positive cause for every rebuilt unit and none of them is a
/// changed source or dependency: the cause evidence is complete, `causeCounts` is a non-empty
/// object, and no key is `source-or-dependency-changed`. The input closure only compares a job's
/// inputs before and after that one job, so it is not evidence about the previous build.
fn inputs_unchanged(receipt: &Value) -> bool {
    let fresh = &receipt["freshness"];
    let causes = fresh["causeCounts"].as_object();
    fresh["causeEvidence"]["state"] == "complete"
        && causes
            .is_some_and(|map| !map.is_empty() && !map.contains_key("source-or-dependency-changed"))
        && receipt["inputClosure"]["status"] == "verified"
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
        let lost = repo
            .units
            .zip(saved.and_then(|mark| mark.units))
            .filter(|(now, was)| was > now);
        if let Some((now, was)) = lost {
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

    fn mark(hits: u64, misses: u64) -> Mark {
        Mark {
            hits,
            misses,
            ..Mark::default()
        }
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
        let prior = State::from([("heardright".to_owned(), mark(95, 5))]);
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
        assert_eq!(
            (state["heardright"].hits, state["heardright"].misses),
            (30, 10)
        );
    }

    #[test]
    fn an_admission_rejection_is_a_refusal_owned_by_rustright() {
        let rejected = json!({"status": "FAILED", "error": "ADMISSION_REJECTED: queue full"});
        assert_eq!(
            flagged(&[rejected], &State::new(), 500),
            [format!("refusal-admission-rejected {RUSTRIGHT}")]
        );
    }

    #[test]
    fn a_warm_target_that_went_cold_or_shrank_is_reported_against_the_previous_run() {
        let warm = |units: u64| json!({"freshness": {"unitsAtStart": units}});
        let prior = State::from([(
            "heardright".to_owned(),
            Mark {
                units: Some(800),
                ..Mark::default()
            },
        )]);
        let lost = [format!("warm-target-units-lost {RUSTRIGHT}")];
        assert_eq!(flagged(&[warm(300)], &prior, 500), lost);
        assert_eq!(flagged(&[warm(0)], &prior, 500), lost);
        assert!(flagged(&[warm(790), warm(810)], &prior, 500).is_empty());
        let mut repos = BTreeMap::new();
        tally(&mut repos, &receipt(&warm(0)));
        let found = flags("dell", &repos, Some(500 << 30), &prior);
        assert!(found[0].detail.contains("800 -> 0") && found[0].detail.contains("went cold"));
    }

    #[test]
    fn a_rebuild_with_no_input_change_is_flagged_only_against_the_same_cohort() {
        // A rebuild of two units, with the given input verdict, changed inputs and causes.
        let rebuilt = |status: &str, changed: Value, causes: Value| {
            json!({
                "freshness": {"notFresh": 2, "causeCounts": causes,
                              "causeEvidence": {"state": "complete"}},
                "inputClosure": {"status": status, "changed": changed, "added": [],
                                 "removed": [], "extrasChanged": []},
                "cacheCohort": {"toolchain": "1.99.1", "profile": "release",
                                "targetTriple": "aarch64-apple-darwin",
                                "features": [], "defaultFeatures": true}
            })
        };
        let clean = rebuilt("verified", json!([]), json!({"fingerprint-missing": 2}));
        let cohort = {
            let mut repos = BTreeMap::new();
            tally(&mut repos, &receipt(&clean));
            repos["heardright"].cohort_key()
        };
        let same = State::from([(
            "heardright".to_owned(),
            Mark {
                cohort: cohort.clone(),
                ..Mark::default()
            },
        )]);
        let other = State::from([(
            "heardright".to_owned(),
            Mark {
                cohort: "\"1.98.0\"".into(),
                ..Mark::default()
            },
        )]);
        let flag = [format!("not-fresh-without-change {RUSTRIGHT}")];
        let lockfile = rebuilt("verified", json!(["Cargo.lock"]), json!({}));
        let unproven = rebuilt("unrequested", json!([]), json!({}));
        let mut incomplete = clean.clone();
        incomplete["freshness"]["causeEvidence"] = json!({"state": "incomplete"});
        let source = json!({"source-or-dependency-changed": 2});
        let source = rebuilt("verified", json!([]), source);
        assert_eq!(flagged(std::slice::from_ref(&clean), &same, 500), flag);
        assert!(flagged(&[lockfile], &same, 500).is_empty());
        assert!(flagged(&[unproven], &same, 500).is_empty());
        assert!(flagged(&[incomplete], &same, 500).is_empty());
        assert!(flagged(&[source], &same, 500).is_empty());
        assert!(flagged(std::slice::from_ref(&clean), &State::new(), 500).is_empty());
        assert!(flagged(std::slice::from_ref(&clean), &other, 500).is_empty());
    }
}
