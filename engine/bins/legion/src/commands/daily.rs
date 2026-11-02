//! `legion daily`: the M9 daily closed loop (Orthic-Labs/legion#138).
//!
//! One run reads the last day of transcripts and broker receipts on the Mac and
//! the Dell, finds every failure (a corrected agent turn, a hook denial, a red
//! build, CI run or install, an `UNRESOLVED:` line), places each in a B1-B11
//! bucket with a keyword map, measures broker warmth per host and repository,
//! matches each recurring fingerprint to an issue, and writes one short digest.
//!
//! Safe by default: without `--apply` nothing is written to GitHub and no state
//! under `~/.legion/daily/` changes; only the digest and the copied Dell files
//! land in scratch. The job never builds, cuts over, or changes broker state.
//!
//! A scheduled task runs: `legion daily --since 24h --apply`
mod buckets;
mod clock;
mod digest;
mod impact;
mod issues;
mod ledger;
mod proc;
mod receipts;
mod remote;
mod text;
mod transcripts;

use super::{CommandError, CommandResult};
use clap::Args;
use digest::{DigestInput, HostLine, Outcome, WarmthView};
use issues::{Known, PlanOptions, LEGION_REPO};
use ledger::Ledger;
use receipts::{Flag, HostWarmth, WarmthState};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use transcripts::{Failure, Window};

/// The command a scheduled task runs.
pub const SCHEDULED_COMMAND: &str = "legion daily --since 24h --apply";

#[derive(Debug, Args)]
pub struct DailyArgs {
    /// How far back to scan: `24h`, `90m`, `2d` or `1w`.
    #[arg(long, default_value = "24h")]
    pub since: String,
    /// Plan only: write no issue and save no state. This is the default.
    #[arg(long, conflicts_with = "apply")]
    pub dry_run: bool,
    /// Write issues and comments to GitHub and save the ledger and warmth state.
    #[arg(long)]
    pub apply: bool,
    #[arg(long)]
    pub json: bool,
    /// Where the digest and copied Dell files go (default: scratch).
    #[arg(long)]
    pub out: Option<PathBuf>,
    /// Skip the Dell.
    #[arg(long)]
    pub no_dell: bool,
    /// Do not call GitHub: no issue is listed, so none is filed.
    #[arg(long)]
    pub no_github: bool,
    /// Distinct UTC days a fingerprint must appear on before it opens an issue.
    #[arg(long, default_value_t = 2)]
    pub min_days: usize,
    /// Most new issues one run may file.
    #[arg(long, default_value_t = 5)]
    pub max_new_issues: usize,
    /// How many days of merged changes the digest measures.
    #[arg(long, default_value_t = 7)]
    pub impact_days: i64,
    /// The Legion checkout whose commits are measured.
    #[arg(long)]
    pub repo_root: Option<PathBuf>,
    /// The broker receipts directory on this machine.
    #[arg(long)]
    pub receipts: Option<PathBuf>,
}

struct Paths {
    home: PathBuf,
    state: PathBuf,
    daily: PathBuf,
    out_root: PathBuf,
    broker_root: PathBuf,
    repo_root: PathBuf,
}

fn local_host() -> &'static str {
    if cfg!(target_os = "macos") {
        "mac"
    } else if cfg!(windows) {
        "dell"
    } else {
        "linux"
    }
}

impl Paths {
    fn resolve(args: &DailyArgs) -> Result<Paths, CommandError> {
        let home = std::env::var_os("HOME")
            .filter(|value| !value.is_empty())
            .or_else(|| std::env::var_os("USERPROFILE").filter(|value| !value.is_empty()))
            .map(PathBuf::from)
            .ok_or_else(|| CommandError::incomplete("no home directory (HOME or USERPROFILE)"))?;
        let state = std::env::var_os("LEGION_STATE_DIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".legion"));
        let windows = cfg!(windows);
        let out_root = args.out.clone().unwrap_or_else(|| {
            PathBuf::from(if windows {
                r"D:\scratch\legion-daily"
            } else {
                "/Volumes/D/scratch/legion-daily"
            })
        });
        let broker_root = args
            .receipts
            .as_ref()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| {
                PathBuf::from(if windows {
                    r"D:\.rightkit-managed\rightkit-build-control"
                } else {
                    "/Volumes/D/.rightkit-managed/rightkit-build-control"
                })
            });
        let repo_root = args
            .repo_root
            .clone()
            .or_else(|| {
                std::env::var_os("LEGION_REPO_ROOT")
                    .filter(|value| !value.is_empty())
                    .map(PathBuf::from)
            })
            .unwrap_or_else(|| {
                PathBuf::from(if windows {
                    r"D:\Claude\legion"
                } else {
                    "/Volumes/D/claude/legion"
                })
            });
        Ok(Paths {
            daily: state.join("daily"),
            home,
            state,
            out_root,
            broker_root,
            repo_root,
        })
    }
}

/// A run is stale after this long; a crashed `--apply` must not block forever.
const LOCK_STALE_SECONDS: u64 = 3 * 3600;

/// Held for the whole of an `--apply` run; removed when it drops.
struct RunLock {
    path: PathBuf,
}

impl RunLock {
    fn acquire(dir: &Path) -> Result<RunLock, String> {
        fs::create_dir_all(dir)
            .map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
        let path = dir.join("run.lock");
        for _ in 0..2 {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    let _ = writeln!(file, "{}", std::process::id());
                    return Ok(RunLock { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = fs::metadata(&path)
                        .and_then(|meta| meta.modified())
                        .ok()
                        .and_then(|modified| modified.elapsed().ok())
                        .is_some_and(|age| age.as_secs() > LOCK_STALE_SECONDS);
                    if !stale {
                        return Err(format!(
                            "another `legion daily --apply` holds {}",
                            path.display()
                        ));
                    }
                    let _ = fs::remove_file(&path);
                }
                Err(error) => {
                    return Err(format!("cannot take {}: {error}", path.display()));
                }
            }
        }
        Err(format!("could not take {}", path.display()))
    }
}

impl Drop for RunLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// One host's warmth measurement and the state file it updates.
struct WarmthRun {
    warmth: HostWarmth,
    state: WarmthState,
    state_path: PathBuf,
    flags: Vec<Flag>,
}

struct WarmthInput<'a> {
    host: &'a str,
    receipts_dir: &'a Path,
    disk_free: Option<u64>,
    events: Option<String>,
}

fn warmth_for_host(
    input: &WarmthInput,
    daily_dir: &Path,
    window: &Window,
    today: &str,
    warnings: &mut Vec<String>,
) -> WarmthRun {
    let state_path = daily_dir.join(format!("warmth-{}.json", input.host));
    let state = match WarmthState::load(&state_path) {
        Ok(state) => state,
        Err(error) => {
            warnings.push(format!(
                "{}: warmth state {error}; measuring without a baseline",
                input.host
            ));
            WarmthState::default()
        }
    };
    let (jobs, read, warning) = receipts::read_receipts(input.receipts_dir, window);
    if let Some(warning) = warning {
        warnings.push(format!("{}: {warning}", input.host));
    }
    let baseline = state.baseline(today).map(|(_, repos)| repos);
    let mut warmth = receipts::summarize(input.host, read, jobs, baseline);
    warmth.disk_free_bytes = input.disk_free;
    if let Some(events) = &input.events {
        warmth.pauses = receipts::pause_counts(events, window);
    }
    let flags = receipts::flags(&warmth, &state, today);
    WarmthRun {
        warmth,
        state,
        state_path,
        flags,
    }
}

fn warmth_json(warmth: &HostWarmth, flags: &[Flag]) -> Value {
    let mut repos = serde_json::Map::new();
    for (name, stats) in &warmth.repos {
        let refusals: serde_json::Map<String, Value> = stats
            .refusals
            .iter()
            .map(|(code, count)| (code.clone(), json!(count)))
            .collect();
        let worst: Vec<Value> = stats
            .worst
            .iter()
            .map(|job| {
                json!({"id": job.id, "command": job.command, "totalMs": job.total_ms, "why": job.why})
            })
            .collect();
        repos.insert(
            name.clone(),
            json!({
                "jobs": stats.jobs,
                "buildJobs": stats.build_jobs,
                "coldStarts": stats.cold_starts,
                "unexplainedColdStarts": stats.unexplained_cold,
                "unexplainedUnits": stats.unexplained_units,
                "unchangedInputRebuilds": stats.unchanged_input_rebuilds,
                "unchangedInputUnits": stats.unchanged_input_units,
                "fingerprintMissingUnchanged": stats.fingerprint_missing_unchanged,
                "unitsLostSincePreviousRun": stats.units_lost,
                "shrinkEvents": stats.shrink_events,
                "shrinkUnits": stats.shrink_units,
                "lostDetail": stats.lost_detail,
                "cacheHits": stats.hits,
                "cacheMisses": stats.misses,
                "cacheHitRate": stats.hit_rate(),
                "refusals": refusals,
                "failedJobs": stats.failed_jobs,
                "worstJobs": worst,
            }),
        );
    }
    let flag_values: Vec<Value> = flags
        .iter()
        .map(|flag| {
            json!({
                "fingerprint": flag.fingerprint(),
                "repo": flag.repo,
                "slug": flag.slug,
                "label": flag.label,
                "detail": flag.detail,
                "owner": flag.owner,
            })
        })
        .collect();
    json!({
        "host": warmth.host,
        "receiptsRead": warmth.receipts,
        "diskFreeBytes": warmth.disk_free_bytes,
        "admissionPauses": warmth.pauses,
        "repos": repos,
        "flags": flag_values,
    })
}

fn failure_json(failure: &Failure) -> Value {
    json!({
        "id": failure.id,
        "host": failure.host,
        "kind": failure.kind.label(),
        "at": clock::rfc3339(failure.epoch),
        "session": failure.session,
        "project": failure.project,
        "fingerprint": failure.fingerprint(),
        "catchAll": failure.catch_all,
        "quote": failure.quote,
        "context": failure.context,
    })
}

fn action_json(outcome: &Outcome) -> Value {
    json!({
        "action": outcome.action.verb(),
        "fingerprint": outcome.action.fingerprint(),
        "description": outcome.action.describe(),
        "result": outcome.result,
    })
}

fn bucket_counts(failures: &[Failure]) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for failure in failures {
        *counts.entry(failure.bucket.to_owned()).or_insert(0) += 1;
    }
    counts
}

fn console_text(
    header: &str,
    failures: &[Failure],
    runs: &[WarmthRun],
    outcomes: &[Outcome],
    digest_path: &Path,
    warnings: &[String],
) -> String {
    let mut out = String::new();
    out.push_str(header);
    out.push('\n');
    let counts = bucket_counts(failures)
        .iter()
        .map(|(bucket, count)| format!("{bucket} {count}"))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!(
        "failures: {}{}\n",
        failures.len(),
        if counts.is_empty() {
            String::new()
        } else {
            format!(" ({counts})")
        }
    ));
    let flag_count: usize = runs.iter().map(|run| run.flags.len()).sum();
    out.push_str(&format!("warmth flags: {flag_count}\n"));
    let mut verbs: BTreeMap<&str, usize> = BTreeMap::new();
    for outcome in outcomes {
        *verbs.entry(outcome.action.verb()).or_insert(0) += 1;
    }
    let tally = verbs
        .iter()
        .map(|(verb, count)| format!("{count} {verb}"))
        .collect::<Vec<_>>()
        .join(", ");
    out.push_str(&format!(
        "issue actions: {}\n",
        if tally.is_empty() {
            "none".to_owned()
        } else {
            tally
        }
    ));
    for outcome in outcomes
        .iter()
        .filter(|outcome| outcome.action.verb() != "skip")
    {
        let result = if outcome.result.is_empty() {
            String::new()
        } else {
            format!(" -> {}", outcome.result)
        };
        out.push_str(&format!("  {}{result}\n", outcome.action.describe()));
    }
    out.push_str(&format!("digest: {}\n", digest_path.display()));
    for warning in warnings {
        out.push_str(&format!("warning: {warning}\n"));
    }
    out
}

pub fn run(args: DailyArgs) -> CommandResult {
    let since_seconds = clock::parse_duration(&args.since).ok_or_else(|| {
        CommandError::usage(format!(
            "--since must look like 24h, 90m, 2d or 1w, not {:?}",
            args.since
        ))
    })?;
    let now = clock::now_epoch();
    let window = Window {
        since: now - since_seconds,
        until: now,
    };
    let today = clock::date_of(now);
    let paths = Paths::resolve(&args)?;
    let out_day = paths.out_root.join(&today);
    let mut warnings: Vec<String> = Vec::new();
    // Two --apply runs at once could each file the same issue, so a run that
    // cannot take the lock falls back to a dry run.
    let _lock: Option<RunLock> = if args.apply && !args.dry_run {
        match RunLock::acquire(&paths.daily) {
            Ok(lock) => Some(lock),
            Err(error) => {
                warnings.push(format!("{error}; running as a dry run"));
                None
            }
        }
    } else {
        None
    };
    let apply = _lock.is_some();
    if let Err(error) = fs::create_dir_all(&out_day) {
        warnings.push(format!("cannot create {}: {error}", out_day.display()));
    }

    // 1. Transcripts and the evidence ledger, this machine then the Dell.
    let local = local_host();
    let mut failures: Vec<Failure> = Vec::new();
    let mut host_lines: Vec<HostLine> = Vec::new();
    let sources = transcripts::local_sources(&paths.home, &paths.state, window.since);
    let local_failures = transcripts::scan_host(local, &sources, &window);
    host_lines.push(HostLine {
        host: local.to_owned(),
        transcripts: sources.claude.len() + sources.codex.len() + sources.evidence.len(),
        failures: local_failures.len(),
        receipts: 0,
    });
    failures.extend(local_failures);

    let mut dell: Option<remote::Collected> = None;
    if cfg!(target_os = "macos") && !args.no_dell {
        let collected = remote::collect(&out_day.join("dell"), window.since);
        let copied = transcripts::copied_sources(&collected.root);
        let dell_failures = transcripts::scan_host("dell", &copied, &window);
        host_lines.push(HostLine {
            host: "dell".to_owned(),
            transcripts: copied.claude.len() + copied.codex.len() + copied.evidence.len(),
            failures: dell_failures.len(),
            receipts: 0,
        });
        failures.extend(dell_failures);
        warnings.extend(collected.warnings.iter().cloned());
        dell = Some(collected);
    } else if !args.no_dell {
        warnings.push(format!(
            "the Dell is read from the Mac; this host ({local}) scanned only itself"
        ));
    }
    let dell_clean = dell
        .as_ref()
        .is_some_and(|collected| collected.warnings.is_empty());
    let failures = transcripts::finish(failures);

    // 2. Broker warmth per host.
    let mut runs: Vec<WarmthRun> = Vec::new();
    let local_receipts = args
        .receipts
        .clone()
        .unwrap_or_else(|| paths.broker_root.join("receipts"));
    let local_events =
        receipts::read_events_tail(&paths.broker_root.join("logs").join("events.ndjson"));
    let local_free = if cfg!(windows) {
        None
    } else {
        receipts::disk_free_bytes("/Volumes/D")
    };
    runs.push(warmth_for_host(
        &WarmthInput {
            host: local,
            receipts_dir: &local_receipts,
            disk_free: local_free,
            events: local_events,
        },
        &paths.daily,
        &window,
        &today,
        &mut warnings,
    ));
    let dell_listing_failed = dell
        .as_ref()
        .is_some_and(|collected| collected.listed == 0 && !collected.warnings.is_empty());
    if dell_listing_failed {
        warnings
            .push("dell: broker warmth skipped because the Dell could not be listed".to_owned());
    }
    if let Some(collected) = dell.as_ref().filter(|_| !dell_listing_failed) {
        if let Err(error) = fs::create_dir_all(&collected.receipts_dir) {
            warnings.push(format!("dell: cannot create receipts folder: {error}"));
        }
        let events = collected
            .events_file
            .as_ref()
            .and_then(|path| fs::read_to_string(path).ok());
        runs.push(warmth_for_host(
            &WarmthInput {
                host: "dell",
                receipts_dir: &collected.receipts_dir,
                disk_free: collected.disk_free_bytes,
                events,
            },
            &paths.daily,
            &window,
            &today,
            &mut warnings,
        ));
    }
    for run in &runs {
        if let Some(line) = host_lines
            .iter_mut()
            .find(|line| line.host == run.warmth.host)
        {
            line.receipts = run.warmth.receipts;
        }
    }
    let all_flags: Vec<Flag> = runs
        .iter()
        .flat_map(|run| run.flags.iter().cloned())
        .collect();

    // 3. The ledger: merge this scan, then match fingerprints to issues.
    let ledger_path = paths.daily.join("ledger.json");
    let (mut ledger, ledger_ok) = match Ledger::load(&ledger_path) {
        Ok(ledger) => (ledger, true),
        Err(error) => {
            warnings.push(format!(
                "ledger: {error}; GitHub writes and state saves are off until it is fixed or removed"
            ));
            (Ledger::default(), false)
        }
    };
    for failure in &failures {
        ledger.add_failure(failure);
    }
    for flag in &all_flags {
        ledger.add_flag(&flag.fingerprint(), &today, &flag.host, &flag.detail, now);
    }
    let mut candidates = issues::candidates_from_failures(&failures, &ledger);
    candidates.extend(issues::candidates_from_flags(
        &all_flags, &ledger, &today, now,
    ));

    let mut known: Vec<Known> = Vec::new();
    let mut unavailable: Vec<String> = Vec::new();
    let mut repos: Vec<&'static str> = candidates.iter().map(|candidate| candidate.repo).collect();
    repos.push(LEGION_REPO);
    repos.sort_unstable();
    repos.dedup();
    if args.no_github {
        unavailable.extend(repos.iter().map(|repo| (*repo).to_owned()));
    } else {
        for repo in &repos {
            match issues::list_known(repo) {
                Ok(list) => known.extend(list),
                Err(error) => {
                    warnings.push(format!("github: could not list issues in {repo}: {error}"));
                    unavailable.push((*repo).to_owned());
                }
            }
        }
        for (repo, number) in issues::unlisted_ledger_issues(&candidates, &known, &ledger) {
            if unavailable.contains(&repo) {
                continue;
            }
            match issues::view_known(&repo, number) {
                Ok(issue) => known.push(issue),
                Err(error) => {
                    warnings.push(format!("github: could not read {repo}#{number}: {error}"))
                }
            }
        }
    }
    let planned = issues::plan(
        &candidates,
        &known,
        &ledger,
        &PlanOptions {
            min_days: args.min_days.max(1),
            max_new: args.max_new_issues,
            today: today.clone(),
            unavailable,
        },
    );

    // 4. Apply (only with --apply): each write is saved to the ledger at once.
    let github_writes = apply && ledger_ok && !args.no_github;
    let mut outcomes: Vec<Outcome> = Vec::new();
    for action in planned {
        let mut result = String::new();
        if action.verb() != "skip" {
            if github_writes {
                match issues::apply(&action, &mut ledger, &today) {
                    Ok(text) => result = text,
                    Err(error) => {
                        warnings.push(format!("github: {} failed: {error}", action.describe()));
                        result = format!("failed: {error}");
                    }
                }
                if let Err(error) = ledger.save(&ledger_path) {
                    warnings.push(format!("ledger: {error}"));
                }
            } else if apply {
                result = "not written: GitHub or the ledger is unavailable".to_owned();
            }
        }
        outcomes.push(Outcome { action, result });
    }

    // 5. Impact of recent changes.
    let changes = match impact::recent_commits(
        &paths.repo_root,
        now - args.impact_days.max(1) * clock::DAY_SECONDS,
    ) {
        Ok(commits) => commits
            .iter()
            .map(|commit| {
                let change = impact::attribute(commit, &ledger);
                let measured = impact::measure(&change, &failures, &ledger, &window);
                (change, measured)
            })
            .collect::<Vec<_>>(),
        Err(error) => {
            warnings.push(format!("changes: could not read the Legion log: {error}"));
            Vec::new()
        }
    };

    // 6. Save state (only with --apply, and only when the ledger was readable).
    if apply && ledger_ok {
        if dell_clean {
            ledger.record_scan(window.since, window.until);
        }
        ledger.prune(&today);
        if let Err(error) = ledger.save(&ledger_path) {
            warnings.push(format!("ledger: {error}"));
        }
        for run in runs.iter_mut() {
            // A host with no receipts keeps its last real measurement as the
            // baseline rather than recording an empty day over it.
            if run.warmth.repos.is_empty() {
                continue;
            }
            run.state.record(&today, &run.warmth);
            if let Err(error) = run.state.save(&run.state_path) {
                warnings.push(format!("{}: warmth state: {error}", run.warmth.host));
            }
        }
    }

    // 7. The digest and the failure list, in scratch.
    let views: Vec<WarmthView> = runs
        .iter()
        .map(|run| WarmthView {
            warmth: &run.warmth,
            flags: &run.flags,
        })
        .collect();
    let digest_path = out_day.join("digest.md");
    let rendered = digest::render(&DigestInput {
        date: &today,
        window,
        apply,
        hosts: &host_lines,
        failures: &failures,
        ledger: &ledger,
        candidates: &candidates,
        outcomes: &outcomes,
        known: &known,
        warmth: &views,
        changes: &changes,
        warnings: &warnings,
    });
    if let Err(error) = fs::write(&digest_path, rendered.as_bytes()) {
        warnings.push(format!("cannot write {}: {error}", digest_path.display()));
    }
    let list: String = failures
        .iter()
        .map(|failure| format!("{}\n", failure_json(failure)))
        .collect();
    if let Err(error) = fs::write(out_day.join("failures.jsonl"), list.as_bytes()) {
        warnings.push(format!("cannot write failures.jsonl: {error}"));
    }

    if args.json {
        let dell_json = dell.as_ref().map(|collected| {
            json!({
                "listed": collected.listed,
                "copied": collected.copied,
                "unchanged": collected.unchanged,
                "diskFreeBytes": collected.disk_free_bytes,
            })
        });
        let mode = if apply { "apply" } else { "dry-run" };
        let hosts: Vec<Value> = host_lines
            .iter()
            .map(|line| {
                json!({
                    "host": line.host,
                    "transcriptFiles": line.transcripts,
                    "failures": line.failures,
                    "receiptsRead": line.receipts,
                })
            })
            .collect();
        let warmth: Vec<Value> = runs
            .iter()
            .map(|run| warmth_json(&run.warmth, &run.flags))
            .collect();
        let actions: Vec<Value> = outcomes.iter().map(action_json).collect();
        let changed: Vec<Value> = changes
            .iter()
            .map(|(change, measured)| {
                json!({
                    "commit": change.short,
                    "subject": change.subject,
                    "bucket": change.bucket,
                    "basis": change.basis,
                    "beforeDaily": measured.as_ref().and_then(|item| item.before_daily()),
                    "afterDaily": measured.as_ref().and_then(|item| item.after_daily()),
                    "inWindow": measured.as_ref().and_then(|item| item.in_window),
                })
            })
            .collect();
        let counts = bucket_counts(&failures);
        let digest_text = digest_path.display().to_string();
        return Ok(json!({
            "mode": mode,
            "date": today,
            "window": {
                "since": clock::rfc3339(window.since),
                "until": clock::rfc3339(window.until),
            },
            "hosts": hosts,
            "failures": {"total": failures.len(), "byBucket": counts},
            "warmth": warmth,
            "actions": actions,
            "changes": changed,
            "dell": dell_json,
            "digest": digest_text,
            "applied": github_writes,
            "scheduledCommand": SCHEDULED_COMMAND,
            "warnings": warnings,
        }));
    }
    let header = format!(
        "legion daily {today} ({}; window {})",
        if apply {
            "apply"
        } else {
            "dry run, nothing written to GitHub or state"
        },
        args.since
    );
    Ok(json!({
        "__raw": console_text(&header, &failures, &runs, &outcomes, &digest_path, &warnings)
    }))
}
