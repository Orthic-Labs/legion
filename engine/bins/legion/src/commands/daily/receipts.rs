//! Broker warmth for `legion daily` (Orthic-Labs/legion#138), read from the
//! RustRight broker's receipts on each host. Reports cold starts, rebuilt units
//! that nothing explains, warm units lost since the previous run, cache hit
//! rate and trend, disk, and refusals by code, per host and repository. Read
//! only: the job never builds, cuts over, or touches broker state.
use super::{
    clock, proc,
    text::{self, clip},
    transcripts::Window,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const GIB: u64 = 1024 * 1024 * 1024;
/// Free space below this on the build drive is a flag.
pub const DISK_FLOOR_BYTES: u64 = 50 * GIB;
/// A cache hit rate needs this many compiles before it is judged.
const HIT_RATE_MIN_SAMPLES: u64 = 20;
const HIT_RATE_FLOOR: f64 = 0.5;
const HIT_RATE_DROP: f64 = 0.2;
const TREND_DAYS: usize = 7;
const EVENTS_TAIL_BYTES: u64 = 8 * 1024 * 1024;
const WORST_JOBS: usize = 3;

pub const RUSTRIGHT_REPO: &str = "Orthic-Labs/rustright";
pub const RIGHTKIT_REPO: &str = "Orthic-Labs/rightkit";

// ---------------------------------------------------------------------------
// One receipt
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default)]
pub struct Job {
    pub id: String,
    pub status: String,
    pub submitted: i64,
    pub workspace: String,
    pub repo: String,
    pub command: String,
    pub total_ms: u64,
    pub refusal: Option<String>,
    pub has_freshness: bool,
    pub cold: bool,
    pub cold_reason: Option<String>,
    pub units_at_start: Option<u64>,
    pub not_fresh: u64,
    pub unexplained: u64,
    pub fingerprint_missing: u64,
    pub tree: String,
    pub toolchain: String,
    pub profile: String,
    pub features: String,
    pub argv_key: String,
    pub generation: Option<u64>,
    pub rotation_reason: Option<String>,
    pub hits: u64,
    pub misses: u64,
}

fn str_at<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// The repository a workspace path belongs to: the folder under `/claude/`
/// (Mac `/Volumes/D/claude/<repo>`, Dell `D:\Claude\<repo>`), `(temp)` for a
/// scratch checkout, else the last path segment.
pub fn repo_of(workspace: &str) -> String {
    let normal = workspace.replace('\\', "/");
    if normal.trim().is_empty() {
        return "(none)".to_owned();
    }
    let lower = normal.to_ascii_lowercase();
    if let Some(index) = lower.find("/claude/") {
        let rest = &normal[index + "/claude/".len()..];
        if let Some(first) = rest.split('/').find(|part| !part.is_empty()) {
            return first.to_owned();
        }
    }
    let temporary = ["/var/folders/", "/tmp/", "/temp/", "/appdata/local/temp"];
    if temporary.iter().any(|marker| lower.contains(marker)) {
        return "(temp)".to_owned();
    }
    normal
        .rsplit('/')
        .find(|part| !part.is_empty())
        .unwrap_or("(none)")
        .to_owned()
}

fn is_broker_code(text: &str) -> bool {
    (text.starts_with("RK_") || text.starts_with("RR_"))
        && text.len() > 3
        && text.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        })
}

fn leading_code(error: &str) -> Option<String> {
    let code: String = error
        .trim_start()
        .chars()
        .take_while(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || *character == '_'
        })
        .collect();
    if is_broker_code(&code) {
        Some(code)
    } else {
        None
    }
}

/// The code of a refused or timed-out job. A plain `FAILED` tool exit is the
/// build's own result, not a refusal; only a broker-coded failure counts.
fn refusal_code(status: &str, reason: Option<&str>, error: Option<&str>) -> Option<String> {
    let coded = error.and_then(leading_code).or_else(|| {
        reason
            .filter(|text| is_broker_code(text))
            .map(str::to_owned)
    });
    match status {
        "REJECTED" | "TIMED_OUT" => Some(coded.unwrap_or_else(|| {
            format!(
                "{}-{}",
                text::slugify(status, 20),
                text::slugify(reason.unwrap_or("none"), 40)
            )
        })),
        "FAILED" => coded,
        _ => None,
    }
}

fn argv_key(value: &Value) -> String {
    let argv = value
        .get("effectiveArgv")
        .or_else(|| value.get("argv"))
        .and_then(Value::as_array);
    let Some(items) = argv else {
        return String::new();
    };
    let mut parts: Vec<&str> = Vec::new();
    let mut skip_next = false;
    for item in items.iter().filter_map(Value::as_str) {
        if skip_next {
            skip_next = false;
            continue;
        }
        if item == "--target-dir" {
            skip_next = true;
            continue;
        }
        if item.starts_with("--target-dir=") {
            continue;
        }
        parts.push(item);
    }
    parts.join(" ")
}

/// Parse one receipt. `None` when it has no submit time (not a job receipt).
pub fn parse_job(value: &Value) -> Option<Job> {
    let submitted = str_at(value, "submittedAt").and_then(clock::parse_rfc3339)?;
    let workspace = str_at(value, "workspace")
        .or_else(|| {
            value
                .pointer("/writeLocations/WORKSPACE")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            value
                .pointer("/cacheCohort/workspace")
                .and_then(Value::as_str)
        })
        .unwrap_or("")
        .to_owned();
    let status = str_at(value, "status").unwrap_or("").to_owned();
    let freshness = value.get("freshness").filter(|fresh| fresh.is_object());
    let count = |key: &str| -> u64 {
        freshness
            .and_then(|fresh| fresh.get(key))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    let cold_reason = freshness
        .and_then(|fresh| fresh.get("coldCause"))
        .and_then(Value::as_str)
        .or_else(|| str_at(value, "coldStartReason"))
        .map(str::to_owned);
    let tree = value
        .pointer("/snapshot/treeAtStart")
        .and_then(Value::as_str)
        .or_else(|| value.pointer("/commit/tree").and_then(Value::as_str))
        .unwrap_or("")
        .to_owned();
    let reuse = |key: &str| -> u64 {
        value
            .pointer(&format!("/cache/reuse/{key}"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    };
    let reuse_status = value
        .pointer("/cache/reuse/status")
        .and_then(Value::as_str)
        .unwrap_or("");
    let counted = matches!(reuse_status, "PROVEN" | "MIXED" | "MISS");
    Some(Job {
        id: str_at(value, "id").unwrap_or("").to_owned(),
        refusal: refusal_code(&status, str_at(value, "reason"), str_at(value, "error")),
        status,
        submitted,
        repo: repo_of(&workspace),
        workspace,
        command: clip(str_at(value, "command").unwrap_or(""), 160),
        total_ms: value.get("totalMs").and_then(Value::as_u64).unwrap_or(0),
        has_freshness: freshness.is_some(),
        cold: value
            .get("coldStart")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        cold_reason,
        units_at_start: freshness
            .and_then(|fresh| fresh.get("unitsAtStart"))
            .and_then(Value::as_u64),
        not_fresh: count("notFresh"),
        unexplained: count("unexplainedCount"),
        fingerprint_missing: freshness
            .and_then(|fresh| fresh.pointer("/invalidationCounts/FingerprintMissing"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        tree,
        toolchain: str_at(value, "toolchain").unwrap_or("").to_owned(),
        profile: str_at(value, "profile").unwrap_or("").to_owned(),
        features: value
            .pointer("/cacheCohort/features")
            .map(Value::to_string)
            .unwrap_or_default(),
        argv_key: argv_key(value),
        generation: value.pointer("/target/generation").and_then(Value::as_u64),
        rotation_reason: value
            .pointer("/target/rotationReason")
            .and_then(Value::as_str)
            .map(str::to_owned),
        hits: if counted { reuse("hits") } else { 0 },
        misses: if counted { reuse("misses") } else { 0 },
    })
}

/// Read the receipts in `dir` submitted inside the window. Returns the jobs, the
/// number of files parsed, and any warning.
pub fn read_receipts(dir: &Path, window: &Window) -> (Vec<Job>, usize, Option<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return (
            Vec::new(),
            0,
            Some(format!("receipts directory unreadable: {}", dir.display())),
        );
    };
    let mut jobs: Vec<Job> = Vec::new();
    let mut parsed = 0usize;
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.ends_with(".json") || name.contains("evidence") {
            continue;
        }
        let fresh = entry
            .metadata()
            .ok()
            .and_then(|meta| meta.modified().ok())
            .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
            .is_some_and(|elapsed| elapsed.as_secs() as i64 >= window.since - 300);
        if !fresh {
            continue;
        }
        let Ok(body) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&body) else {
            continue;
        };
        parsed += 1;
        if let Some(job) = parse_job(&value) {
            if job.submitted >= window.since && job.submitted <= window.until {
                jobs.push(job);
            }
        }
    }
    (jobs, parsed, None)
}

// ---------------------------------------------------------------------------
// Persisted state (`~/.legion/daily/warmth-<host>.json`)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct WarmPoint {
    pub units: u64,
    pub at: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DayRepo {
    #[serde(default)]
    pub jobs: u64,
    #[serde(default)]
    pub cold_starts: u64,
    #[serde(default)]
    pub unexplained_units: u64,
    #[serde(default)]
    pub hits: u64,
    #[serde(default)]
    pub misses: u64,
    #[serde(default)]
    pub warm: BTreeMap<String, WarmPoint>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WarmthState {
    #[serde(default)]
    pub days: BTreeMap<String, BTreeMap<String, DayRepo>>,
}

impl WarmthState {
    /// A missing file is an empty state; a corrupt one is an error the caller
    /// reports (the daily job then runs without a baseline).
    pub fn load(path: &Path) -> Result<WarmthState, String> {
        match fs::read_to_string(path) {
            Ok(body) => serde_json::from_str(&body)
                .map_err(|error| format!("{} is not valid: {error}", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(WarmthState::default())
            }
            Err(error) => Err(format!("cannot read {}: {error}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), String> {
        let body = serde_json::to_vec_pretty(self).map_err(|error| error.to_string())?;
        write_atomic(path, &body)
    }

    /// The most recent saved day before `today` (the previous run's baseline).
    pub fn baseline(&self, today: &str) -> Option<(&String, &BTreeMap<String, DayRepo>)> {
        self.days
            .iter()
            .rev()
            .find(|(date, _)| date.as_str() < today)
    }

    /// Up to `TREND_DAYS` saved days before `today`, newest first.
    fn prior_days(&self, today: &str) -> Vec<&BTreeMap<String, DayRepo>> {
        self.days
            .iter()
            .rev()
            .filter(|(date, _)| date.as_str() < today)
            .take(TREND_DAYS)
            .map(|(_, repos)| repos)
            .collect()
    }

    /// Replace today's entry with this run's measurements and drop old days.
    pub fn record(&mut self, today: &str, warmth: &HostWarmth) {
        let mut repos: BTreeMap<String, DayRepo> = BTreeMap::new();
        for (name, stats) in &warmth.repos {
            repos.insert(
                name.clone(),
                DayRepo {
                    jobs: stats.jobs,
                    cold_starts: stats.cold_starts,
                    unexplained_units: stats.unexplained_units,
                    hits: stats.hits,
                    misses: stats.misses,
                    warm: stats.warm.clone(),
                },
            );
        }
        self.days.insert(today.to_owned(), repos);
        let cutoff = clock::shift_date(today, -60);
        if let Some(cutoff) = cutoff {
            self.days.retain(|date, _| date.as_str() >= cutoff.as_str());
        }
    }
}

/// Write `bytes` to `path` through a temporary file and a rename.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".to_owned());
    let temporary = parent.join(format!(".{name}.{}.tmp", std::process::id()));
    fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.to_string());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct WorstJob {
    pub id: String,
    pub command: String,
    pub total_ms: u64,
    pub why: String,
}

#[derive(Clone, Debug, Default)]
pub struct RepoStats {
    pub jobs: u64,
    pub build_jobs: u64,
    pub cold_starts: u64,
    pub unexplained_cold: u64,
    pub unexplained_units: u64,
    pub unchanged_input_rebuilds: u64,
    pub unchanged_input_units: u64,
    pub fingerprint_missing_unchanged: u64,
    pub units_lost: u64,
    pub shrink_events: u64,
    pub shrink_units: u64,
    pub lost_detail: Vec<String>,
    pub hits: u64,
    pub misses: u64,
    pub refusals: BTreeMap<String, u64>,
    pub failed_jobs: u64,
    pub worst: Vec<WorstJob>,
    pub warm: BTreeMap<String, WarmPoint>,
}

impl RepoStats {
    pub fn hit_rate(&self) -> Option<f64> {
        let total = self.hits + self.misses;
        if total == 0 {
            None
        } else {
            Some(self.hits as f64 / total as f64)
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct HostWarmth {
    pub host: String,
    pub receipts: usize,
    pub repos: BTreeMap<String, RepoStats>,
    pub disk_free_bytes: Option<u64>,
    pub pauses: BTreeMap<String, u64>,
}

/// A cold start with no stated cause beyond a fresh or empty target.
fn cold_is_explained(reason: Option<&str>) -> bool {
    reason.is_some_and(|text| {
        text.split(['-', '_', ' '])
            .any(|token| matches!(token, "empty" | "missing" | "first" | "new" | "absent"))
    })
}

fn same_inputs(previous: &Job, current: &Job) -> bool {
    !current.tree.is_empty()
        && previous.tree == current.tree
        && previous.toolchain == current.toolchain
        && previous.profile == current.profile
        && previous.features == current.features
}

fn add_worst(list: &mut Vec<WorstJob>, job: &Job, why: &str) {
    list.push(WorstJob {
        id: job.id.clone(),
        command: job.command.clone(),
        total_ms: job.total_ms,
        why: why.to_owned(),
    });
}

/// Measure one host from its jobs. `baseline` is the previous run's per-repo
/// warm-unit points; it decides "units lost since the previous run".
pub fn summarize(
    host: &str,
    receipts_read: usize,
    mut jobs: Vec<Job>,
    baseline: Option<&BTreeMap<String, DayRepo>>,
) -> HostWarmth {
    jobs.sort_by(|left, right| {
        left.submitted
            .cmp(&right.submitted)
            .then_with(|| left.id.cmp(&right.id))
    });
    let mut warmth = HostWarmth {
        host: host.to_owned(),
        receipts: receipts_read,
        ..HostWarmth::default()
    };

    // Counts, refusals, cache reuse.
    for job in &jobs {
        let stats = warmth.repos.entry(job.repo.clone()).or_default();
        stats.jobs += 1;
        if job.has_freshness {
            stats.build_jobs += 1;
        }
        if job.cold {
            stats.cold_starts += 1;
            if !cold_is_explained(job.cold_reason.as_deref()) {
                stats.unexplained_cold += 1;
                add_worst(&mut stats.worst, job, "cold start with no stated cause");
            }
        }
        if job.unexplained > 0 {
            stats.unexplained_units += job.unexplained;
            add_worst(
                &mut stats.worst,
                job,
                &format!("{} unexplained rebuilt unit(s)", job.unexplained),
            );
        }
        stats.hits += job.hits;
        stats.misses += job.misses;
        if let Some(code) = &job.refusal {
            *stats.refusals.entry(code.clone()).or_insert(0) += 1;
        }
        if job.status == "FAILED" {
            stats.failed_jobs += 1;
        }
    }

    // Rebuilds with unchanged inputs, against the previous run of the same
    // workspace and argv.
    let mut previous: HashMap<(String, String), &Job> = HashMap::new();
    for job in jobs.iter().filter(|job| job.has_freshness) {
        let key = (job.workspace.clone(), job.argv_key.clone());
        if let Some(prior) = previous.get(&key) {
            if job.not_fresh > 0 && same_inputs(prior, job) {
                let stats = warmth.repos.entry(job.repo.clone()).or_default();
                stats.unchanged_input_rebuilds += 1;
                stats.unchanged_input_units += job.not_fresh;
                if job.fingerprint_missing > 0 {
                    stats.fingerprint_missing_unchanged += 1;
                }
                add_worst(
                    &mut stats.worst,
                    job,
                    &format!("{} unit(s) rebuilt with unchanged inputs", job.not_fresh),
                );
            }
        }
        previous.insert(key, job);
    }

    // Warm units: lost since the previous run, and shrunk within the window.
    let mut last_by_workspace: HashMap<String, &Job> = HashMap::new();
    let mut first_after_baseline: HashMap<String, bool> = HashMap::new();
    for job in jobs.iter() {
        let Some(units) = job.units_at_start else {
            continue;
        };
        let repo_baseline = baseline.and_then(|repos| repos.get(&job.repo));
        let prior_point = repo_baseline.and_then(|day| day.warm.get(&job.workspace));
        let stats = warmth.repos.entry(job.repo.clone()).or_default();
        if let Some(point) = prior_point {
            let judged = first_after_baseline.contains_key(&job.workspace);
            if !judged && job.submitted > point.at {
                first_after_baseline.insert(job.workspace.clone(), true);
                if point.units > units {
                    let lost = point.units - units;
                    stats.units_lost += lost;
                    let cause = job
                        .rotation_reason
                        .clone()
                        .unwrap_or_else(|| "cause not recorded".to_owned());
                    stats.lost_detail.push(format!(
                        "{}: {} -> {} warm units ({})",
                        job.workspace, point.units, units, cause
                    ));
                }
            }
        }
        if let Some(previous_job) = last_by_workspace.get(&job.workspace) {
            let before = previous_job.units_at_start.unwrap_or(0);
            let same_generation = previous_job.generation == job.generation;
            let margin = (before / 50).max(5);
            if same_generation && before > units + margin {
                stats.shrink_events += 1;
                stats.shrink_units += before - units;
            }
        }
        last_by_workspace.insert(job.workspace.clone(), job);
        stats.warm.insert(
            job.workspace.clone(),
            WarmPoint {
                units,
                at: job.submitted,
            },
        );
    }

    // The three slowest flagged jobs per repository.
    for stats in warmth.repos.values_mut() {
        stats
            .worst
            .sort_by(|left, right| right.total_ms.cmp(&left.total_ms));
        stats.worst.truncate(WORST_JOBS);
    }
    warmth
}

// ---------------------------------------------------------------------------
// Broker events and disk
// ---------------------------------------------------------------------------

/// Counts of admission refusals, pauses and stalls in broker event lines
/// inside the window, by event type.
pub fn pause_counts(events: &str, window: &Window) -> BTreeMap<String, u64> {
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for line in events.lines() {
        if !line.starts_with('{') {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        let Some(kind) = str_at(&value, "type") else {
            continue;
        };
        let admission = kind.contains("ADMISSION")
            && ["REJECTED", "PAUSED", "BLOCKED", "REFUSED", "TIMEOUT"]
                .iter()
                .any(|word| kind.contains(word));
        if !(admission || kind == "JOB_STALLED") {
            continue;
        }
        let Some(at) = str_at(&value, "at").and_then(clock::parse_rfc3339) else {
            continue;
        };
        if at >= window.since && at <= window.until {
            *counts.entry(kind.to_owned()).or_insert(0) += 1;
        }
    }
    counts
}

/// The last `EVENTS_TAIL_BYTES` of a broker events file, from a line start.
pub fn read_events_tail(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    let length = file.metadata().ok()?.len();
    let start = length.saturating_sub(EVENTS_TAIL_BYTES);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut buffer: Vec<u8> = Vec::new();
    file.read_to_end(&mut buffer).ok()?;
    let body = String::from_utf8_lossy(&buffer).into_owned();
    if start == 0 {
        return Some(body);
    }
    Some(
        body.split_once('\n')
            .map(|(_, rest)| rest.to_owned())
            .unwrap_or_default(),
    )
}

/// Free bytes on the volume holding `path` (`df -Pk`), on Unix hosts.
pub fn disk_free_bytes(path: &str) -> Option<u64> {
    let mut command = proc::command("df");
    command.args(["-Pk", path]);
    let ran = proc::run(command).ok()?;
    if !ran.ok {
        return None;
    }
    let line = ran.stdout.lines().nth(1)?;
    let kilobytes = line.split_whitespace().nth(3)?.parse::<u64>().ok()?;
    kilobytes.checked_mul(1024)
}

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// A warmth finding that is off. Reported every day it is off; it becomes an
/// issue in the owning repository when it repeats on two or more days.
#[derive(Clone, Debug)]
pub struct Flag {
    pub host: String,
    pub repo: String,
    pub slug: String,
    pub label: String,
    pub detail: String,
    pub owner: &'static str,
}

impl Flag {
    pub fn fingerprint(&self) -> String {
        format!(
            "warmth/{}-{}-{}",
            self.slug,
            text::slugify(&self.host, 12),
            text::slugify(&self.repo, 40)
        )
    }
}

fn owner_for(slug: &str) -> &'static str {
    if slug.starts_with("refusal-rk-") {
        RIGHTKIT_REPO
    } else {
        RUSTRIGHT_REPO
    }
}

fn gib(bytes: u64) -> String {
    format!("{:.1} GiB", bytes as f64 / GIB as f64)
}

fn mean_prior_rate(prior: &[&BTreeMap<String, DayRepo>], repo: &str) -> Option<f64> {
    let rates: Vec<f64> = prior
        .iter()
        .filter_map(|repos| repos.get(repo))
        .filter(|day| day.hits + day.misses >= 10)
        .map(|day| day.hits as f64 / (day.hits + day.misses) as f64)
        .collect();
    if rates.is_empty() {
        None
    } else {
        Some(rates.iter().sum::<f64>() / rates.len() as f64)
    }
}

/// Everything off on this host. `state` supplies prior days for the trend.
pub fn flags(warmth: &HostWarmth, state: &WarmthState, today: &str) -> Vec<Flag> {
    let prior = state.prior_days(today);
    let mut out: Vec<Flag> = Vec::new();
    let mut push = |repo: &str, slug: String, label: &str, detail: String| {
        out.push(Flag {
            host: warmth.host.clone(),
            repo: repo.to_owned(),
            owner: owner_for(&slug),
            slug,
            label: label.to_owned(),
            detail,
        });
    };
    for (repo, stats) in &warmth.repos {
        if stats.unexplained_cold > 0 {
            push(
                repo,
                "cold-start".to_owned(),
                "unexplained cold start",
                format!(
                    "{} of {} cold start(s) have no stated cause",
                    stats.unexplained_cold, stats.cold_starts
                ),
            );
        }
        if stats.unexplained_units > 0 || stats.unchanged_input_rebuilds > 0 {
            push(
                repo,
                "unexplained-rebuild".to_owned(),
                "unexplained rebuilt units",
                format!(
                    "{} unit(s) the broker could not explain; {} job(s) rebuilt {} unit(s) with unchanged inputs ({} with FingerprintMissing)",
                    stats.unexplained_units,
                    stats.unchanged_input_rebuilds,
                    stats.unchanged_input_units,
                    stats.fingerprint_missing_unchanged
                ),
            );
        }
        if stats.units_lost > 0 || stats.shrink_units > 0 {
            let mut detail = format!(
                "{} warm unit(s) lost since the previous run; {} shrink event(s) in the window ({} unit(s))",
                stats.units_lost, stats.shrink_events, stats.shrink_units
            );
            if let Some(first) = stats.lost_detail.first() {
                detail.push_str(&format!("; e.g. {first}"));
            }
            push(repo, "units-lost".to_owned(), "warm units lost", detail);
        }
        if let Some(rate) = stats.hit_rate() {
            let samples = stats.hits + stats.misses;
            let trend = mean_prior_rate(&prior, repo);
            let low = samples >= HIT_RATE_MIN_SAMPLES && rate < HIT_RATE_FLOOR;
            let dropped = samples >= HIT_RATE_MIN_SAMPLES
                && trend.is_some_and(|before| before - rate >= HIT_RATE_DROP);
            if low || dropped {
                push(
                    repo,
                    "hit-rate-low".to_owned(),
                    "compiler cache hit rate is off",
                    format!(
                        "{:.0}% over {} compile(s); prior days {}",
                        rate * 100.0,
                        samples,
                        trend.map_or("n/a".to_owned(), |before| format!("{:.0}%", before * 100.0))
                    ),
                );
            }
        }
        for (code, count) in &stats.refusals {
            push(
                repo,
                format!("refusal-{}", text::slugify(code, 48)),
                "broker refusal",
                format!("{count} job(s) refused or failed with {code}"),
            );
        }
    }
    if let Some(free) = warmth.disk_free_bytes {
        if free < DISK_FLOOR_BYTES {
            push(
                "(host)",
                "disk-low".to_owned(),
                "build drive is low on space",
                format!("{} free, floor {}", gib(free), gib(DISK_FLOOR_BYTES)),
            );
        }
    }
    let paused: u64 = warmth.pauses.values().sum();
    if paused > 0 {
        let list = warmth
            .pauses
            .iter()
            .map(|(kind, count)| format!("{kind} x{count}"))
            .collect::<Vec<_>>()
            .join(", ");
        push(
            "(host)",
            "admission-pause".to_owned(),
            "broker admission refused, paused or stalled",
            list,
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn receipt(id: &str, at: &str, workspace: &str) -> Value {
        json!({
            "id": id,
            "status": "SUCCEEDED",
            "submittedAt": at,
            "workspace": workspace,
            "command": "cargo test",
            "totalMs": 1000,
            "coldStart": false,
            "snapshot": {"treeAtStart": "tree-a"},
            "toolchain": "stable",
            "profile": "development",
            "effectiveArgv": ["test", "--target-dir", "/x/g/001/target", "-p", "a"],
            "target": {"generation": 1},
            "freshness": {"unitsAtStart": 100, "notFresh": 0, "unexplainedCount": 0}
        })
    }

    fn job(value: Value) -> Job {
        parse_job(&value).expect("job")
    }

    #[test]
    fn repo_comes_from_the_claude_folder_or_temp() {
        assert_eq!(repo_of("/Volumes/D/claude/rustright/engine"), "rustright");
        assert_eq!(
            repo_of(r"D:\Claude\heardright\tauri-app-next"),
            "heardright"
        );
        assert_eq!(
            repo_of("/private/var/folders/xp/T/rk-fmt-1/engine"),
            "(temp)"
        );
        assert_eq!(repo_of(""), "(none)");
        assert_eq!(repo_of("/srv/builds/thing"), "thing");
    }

    #[test]
    fn refusal_codes_ignore_plain_failures() {
        assert_eq!(
            refusal_code(
                "REJECTED",
                Some("RK_INTERNAL_DRIVE_REFUSED"),
                Some("RK_INTERNAL_DRIVE_REFUSED: WORKSPACE=/x")
            )
            .as_deref(),
            Some("RK_INTERNAL_DRIVE_REFUSED")
        );
        assert_eq!(
            refusal_code(
                "FAILED",
                None,
                Some("RR_UNEXPLAINED_COLD: 1 rebuilt unit(s)")
            )
            .as_deref(),
            Some("RR_UNEXPLAINED_COLD")
        );
        assert_eq!(refusal_code("FAILED", Some("tool-exit"), None), None);
        assert_eq!(
            refusal_code(
                "REJECTED",
                Some("pre-execution-rejected"),
                Some("conflicting CARGO_TARGET_DIR")
            )
            .as_deref(),
            Some("rejected-pre-execution-rejected")
        );
        assert_eq!(
            refusal_code("TIMED_OUT", Some("deadline"), None).as_deref(),
            Some("timed-out-deadline")
        );
        assert_eq!(refusal_code("SUCCEEDED", None, None), None);
        assert_eq!(
            refusal_code("CANCELLED", Some("explicit-cancel"), None),
            None
        );
    }

    #[test]
    fn argv_key_drops_the_target_dir() {
        let value =
            json!({"effectiveArgv": ["test", "--target-dir", "/a/g/001/target", "-p", "x"]});
        assert_eq!(argv_key(&value), "test -p x");
        let other = json!({"argv": ["build", "--target-dir=/b", "--locked"]});
        assert_eq!(argv_key(&other), "build --locked");
    }

    #[test]
    fn cold_causes_with_a_first_build_token_are_explained() {
        assert!(cold_is_explained(Some("first-build")));
        assert!(cold_is_explained(Some("target-empty")));
        assert!(!cold_is_explained(Some(
            "target-nonempty-but-no-fresh-artifacts"
        )));
        assert!(!cold_is_explained(None));
    }

    #[test]
    fn counts_cold_starts_and_unexplained_units() {
        let mut cold = receipt("a", "2026-11-02T10:00:00Z", "/Volumes/D/claude/rustright");
        cold["coldStart"] = json!(true);
        cold["coldStartReason"] = json!("target-nonempty-but-no-fresh-artifacts");
        let mut unexplained = receipt("b", "2026-11-02T11:00:00Z", "/Volumes/D/claude/rustright");
        unexplained["freshness"]["unexplainedCount"] = json!(2);
        let warmth = summarize("mac", 2, vec![job(cold), job(unexplained)], None);
        let stats = &warmth.repos["rustright"];
        assert_eq!(stats.jobs, 2);
        assert_eq!(stats.cold_starts, 1);
        assert_eq!(stats.unexplained_cold, 1);
        assert_eq!(stats.unexplained_units, 2);
        assert_eq!(stats.worst.len(), 2);
    }

    #[test]
    fn rebuilds_with_unchanged_inputs_are_flagged_and_changed_inputs_are_not() {
        let first = receipt("a", "2026-11-02T10:00:00Z", "/Volumes/D/claude/rustright");
        let mut same = receipt("b", "2026-11-02T11:00:00Z", "/Volumes/D/claude/rustright");
        same["freshness"]["notFresh"] = json!(7);
        same["freshness"]["invalidationCounts"] = json!({"FingerprintMissing": 7});
        let mut changed = receipt("c", "2026-11-02T12:00:00Z", "/Volumes/D/claude/rustright");
        changed["freshness"]["notFresh"] = json!(7);
        changed["snapshot"]["treeAtStart"] = json!("tree-b");
        let warmth = summarize("mac", 3, vec![job(first), job(same), job(changed)], None);
        let stats = &warmth.repos["rustright"];
        assert_eq!(stats.unchanged_input_rebuilds, 1);
        assert_eq!(stats.unchanged_input_units, 7);
        assert_eq!(stats.fingerprint_missing_unchanged, 1);
    }

    #[test]
    fn units_lost_are_measured_against_the_previous_run() {
        let mut baseline: BTreeMap<String, DayRepo> = BTreeMap::new();
        let mut day = DayRepo::default();
        day.warm.insert(
            "/Volumes/D/claude/rustright".to_owned(),
            WarmPoint {
                units: 1700,
                at: clock::parse_rfc3339("2026-11-01T20:00:00Z").unwrap(),
            },
        );
        baseline.insert("rustright".to_owned(), day);
        let mut first = receipt("a", "2026-11-02T10:00:00Z", "/Volumes/D/claude/rustright");
        first["freshness"]["unitsAtStart"] = json!(1000);
        first["target"]["rotationReason"] = json!("disk-floor-eviction");
        let warmth = summarize("mac", 1, vec![job(first)], Some(&baseline));
        let stats = &warmth.repos["rustright"];
        assert_eq!(stats.units_lost, 700);
        assert!(stats.lost_detail[0].contains("disk-floor-eviction"));
        assert_eq!(stats.warm["/Volumes/D/claude/rustright"].units, 1000);
    }

    #[test]
    fn flags_report_only_what_is_off() {
        let healthy = summarize(
            "mac",
            1,
            vec![job(receipt(
                "a",
                "2026-11-02T10:00:00Z",
                "/Volumes/D/claude/rustright",
            ))],
            None,
        );
        let state = WarmthState::default();
        assert!(flags(&healthy, &state, "2026-11-02").is_empty());

        let mut bad = healthy.clone();
        bad.disk_free_bytes = Some(10 * GIB);
        bad.pauses.insert("ADMISSION_REJECTED".to_owned(), 3);
        bad.repos
            .get_mut("rustright")
            .unwrap()
            .refusals
            .insert("RK_INTERNAL_DRIVE_REFUSED".to_owned(), 2);
        let found = flags(&bad, &state, "2026-11-02");
        let prints: Vec<String> = found.iter().map(Flag::fingerprint).collect();
        assert!(prints.contains(&"warmth/disk-low-mac-host".to_owned()));
        assert!(prints.contains(&"warmth/admission-pause-mac-host".to_owned()));
        assert!(
            prints.contains(&"warmth/refusal-rk-internal-drive-refused-mac-rustright".to_owned())
        );
        let refusal = found
            .iter()
            .find(|flag| flag.slug.starts_with("refusal-"))
            .unwrap();
        assert_eq!(refusal.owner, RIGHTKIT_REPO);
        let disk = found.iter().find(|flag| flag.slug == "disk-low").unwrap();
        assert_eq!(disk.owner, RUSTRIGHT_REPO);
    }

    #[test]
    fn hit_rate_flags_a_low_or_dropping_rate() {
        let mut warmth = HostWarmth {
            host: "mac".to_owned(),
            ..HostWarmth::default()
        };
        let stats = RepoStats {
            hits: 30,
            misses: 10,
            ..RepoStats::default()
        };
        warmth.repos.insert("rustright".to_owned(), stats);
        let mut state = WarmthState::default();
        let mut day: BTreeMap<String, DayRepo> = BTreeMap::new();
        day.insert(
            "rustright".to_owned(),
            DayRepo {
                hits: 98,
                misses: 2,
                ..DayRepo::default()
            },
        );
        state.days.insert("2026-11-01".to_owned(), day);
        let found = flags(&warmth, &state, "2026-11-02");
        assert!(found.iter().any(|flag| flag.slug == "hit-rate-low"));

        let steady = WarmthState::default();
        assert!(flags(&warmth, &steady, "2026-11-02").is_empty());
    }

    #[test]
    fn pauses_count_only_admission_and_stall_events_in_the_window() {
        let window = Window {
            since: clock::parse_rfc3339("2026-11-02T00:00:00Z").unwrap(),
            until: clock::parse_rfc3339("2026-11-03T00:00:00Z").unwrap(),
        };
        let events = [
            r#"{"at":"2026-11-02T10:00:00Z","type":"ADMISSION_REJECTED"}"#,
            r#"{"at":"2026-11-02T11:00:00Z","type":"JOB_STALLED"}"#,
            r#"{"at":"2026-11-02T11:00:01Z","type":"STARTED"}"#,
            r#"{"at":"2026-10-01T11:00:00Z","type":"ADMISSION_REJECTED"}"#,
            "not json",
        ]
        .join("\n");
        let counts = pause_counts(&events, &window);
        assert_eq!(counts.len(), 2);
        assert_eq!(counts["ADMISSION_REJECTED"], 1);
        assert_eq!(counts["JOB_STALLED"], 1);
    }

    #[test]
    fn state_records_today_and_finds_the_previous_day() {
        let mut state = WarmthState::default();
        let warmth = summarize(
            "mac",
            1,
            vec![job(receipt(
                "a",
                "2026-11-02T10:00:00Z",
                "/Volumes/D/claude/rustright",
            ))],
            None,
        );
        state.record("2026-11-02", &warmth);
        assert_eq!(
            state.baseline("2026-11-03").map(|(date, _)| date.as_str()),
            Some("2026-11-02")
        );
        assert!(state.baseline("2026-11-02").is_none());
        state.record("2026-11-02", &warmth);
        assert_eq!(state.days.len(), 1);
    }
}
