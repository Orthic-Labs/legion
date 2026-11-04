//! `legion daily`: the daily closed loop (Orthic-Labs/legion#138, fix-plan M9).
//!
//! Reads the last day of Claude Code and Codex transcripts and the broker receipts on the Mac
//! and the Dell (copied read-only into scratch), finds the failures (a corrected agent turn, a
//! hook denial, a red build, an `UNRESOLVED:` line), buckets them B1-B11, measures broker
//! warmth and gate cache reuse (`rightkit.gate-coverage/1` reports), matches each fingerprint
//! to a GitHub issue, and writes one short digest. A dry run unless `--apply`; it never builds
//! or changes broker or gate state.
//!
//! A scheduled task runs: `legion daily --since 24h --apply`
mod buckets;
mod dell;
mod digest;
mod gate;
mod issues;
#[cfg(target_os = "macos")]
mod probe;
mod scan;
pub(super) mod time;
mod warmth;

use super::{CommandError, CommandResult};
use clap::Args;
use issues::{Group, Ledger};
use scan::Failure;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const BROKER: &str = "/Volumes/D/.rightkit-managed/rightkit-build-control/receipts";
const OUT: &str = "/Volumes/D/scratch/legion-daily";
const REPO: &str = "/Volumes/D/claude/legion";
/// Gate coverage reports on the Mac. The Dell's default is
/// `D:\.rightkit-managed\runs\rightkit-gate-coverage` (see `dell.rs`); a gate run with
/// `RIGHTKIT_SCRATCH_ROOT` or a moved data root writes elsewhere, which this scan does not see.
const GATE_COVERAGE: &str = "/Volumes/D/.rightkit-managed/runs/rightkit-gate-coverage";
/// The broker's control root on the Mac, under `$HOME`; its `logs/lifecycle.ndjson` records
/// admission pauses. The Dell's is `%LOCALAPPDATA%\RightKit\build-control` (see `dell.rs`).
const MAC_CONTROL: &str = "Library/Application Support/RightKit/build-control";

#[derive(Debug, Args)]
pub struct DailyArgs {
    /// How far back to scan: 90m, 24h, 2d or 1w.
    #[arg(long, default_value = "24h")]
    pub since: String,
    /// Write issues and comments and save state. Without it: a dry run.
    #[arg(long)]
    pub apply: bool,
    #[arg(long)]
    pub json: bool,
    /// Skip the Dell.
    #[arg(long)]
    pub no_dell: bool,
    /// First run the bounded warm-cache probe cells of the plan (macOS only). This runs real
    /// gate builds, so it is run only where builds are approved.
    #[arg(long)]
    pub probe: bool,
    /// The probe plan; default `~/.legion/daily/probe-plan.json`.
    #[arg(long)]
    pub probe_plan: Option<PathBuf>,
}

/// Run a child process (no stdin) and return its stdout, or its exit status and stderr.
fn exec(command: &mut Command) -> Result<String, String> {
    let output = command.output().map_err(|e| e.to_string())?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    Err(scan::clip(
        &format!(
            "{} {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ),
        300,
    ))
}

/// A missing file is the default; an unreadable one is an error, so a damaged ledger is never
/// overwritten.
fn load<T: DeserializeOwned + Default>(path: &Path) -> Result<T, String> {
    match fs::read_to_string(path) {
        Ok(text) => serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Write a temp file, then rename it over `path`.
fn save<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let text = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    let temp = path.with_extension("tmp");
    fs::create_dir_all(path.parent().unwrap_or(Path::new("."))).map_err(|e| e.to_string())?;
    let done = fs::write(&temp, text).and_then(|()| fs::rename(&temp, path));
    done.map_err(|e| format!("{}: {e}", path.display()))
}

/// One host's scan and warmth, and the warmth baseline file it came from.
struct HostRun {
    host: warmth::Host,
    gate: gate::Host,
    state: warmth::State,
    path: PathBuf,
}

/// What one run collects from every host.
struct Collect {
    window: (i64, i64),
    dir: PathBuf,
    failures: Vec<Failure>,
    notes: Vec<String>,
}

impl Collect {
    fn note(&mut self, text: String) {
        self.notes.push(text);
    }

    /// Scan one host's transcripts (`files` is Claude Code, then Codex) and its receipts.
    fn host(
        &mut self,
        name: &'static str,
        files: [Vec<PathBuf>; 2],
        (receipts, coverage): (&Path, &Path),
        lifecycle: &Path,
        disk: Option<u64>,
    ) -> HostRun {
        let found = scan::scan(name, &files, self.window);
        let path = self.dir.join(format!("warmth-{name}.json"));
        let state = load::<warmth::State>(&path).unwrap_or_else(|e| {
            self.note(format!("{name}: warmth state {e}; no baseline"));
            warmth::State::default()
        });
        let host = warmth::measure(name, receipts, self.window, disk, &state, Some(lifecycle))
            .unwrap_or_else(|e| {
                self.note(format!("{name}: {e}"));
                warmth::Host {
                    name: name.to_owned(),
                    ..warmth::Host::default()
                }
            });
        if host.pauses.is_none() {
            self.note(format!(
                "{name}: broker lifecycle log not read; admission pauses unknown"
            ));
        }
        let gate = gate::measure(name, coverage, self.window).unwrap_or_else(|e| {
            self.note(format!("{name}: {e}; gate reuse unknown"));
            gate::Host {
                name: name.to_owned(),
                ..gate::Host::default()
            }
        });
        if gate.unreadable > 0 {
            self.note(format!(
                "{name}: {} gate coverage report(s) unreadable or not {}",
                gate.unreadable,
                gate::SCHEMA
            ));
        }
        let run = HostRun {
            host,
            gate,
            state,
            path,
        };
        self.failures.extend(found);
        run
    }
}

/// This Mac's transcripts (Claude Code, its profiles, Codex) modified since `since`.
fn mac_files(home: &Path, since: i64) -> [Vec<PathBuf>; 2] {
    let (mut roots, mut claude, mut codex) = (vec![home.join(".claude/projects")], vec![], vec![]);
    if let Ok(profiles) = fs::read_dir(home.join("ClaudeProfiles")) {
        roots.extend(
            profiles
                .flatten()
                .map(|p| p.path().join(".claude/projects")),
        );
    }
    for root in &roots {
        scan::files(root, 2, since, &mut claude);
    }
    scan::files(&home.join(".codex/sessions"), 6, since, &mut codex);
    [claude, codex]
}

fn mac_disk_free() -> Option<u64> {
    let text = exec(Command::new("df").args(["-Pk", "/Volumes/D"])).ok()?;
    let fields: Vec<&str> = text.lines().nth(1)?.split_whitespace().collect();
    Some(fields.get(3)?.parse::<u64>().ok()? * 1024)
}

/// One group per fingerprint seen in this run: failures from the transcripts, warmth flags
/// from the receipts. An event is new when it came after the last saved run.
fn groups(failures: &[Failure], hosts: &[HostRun], ledger: &Ledger, until: i64) -> Vec<Group> {
    let today = time::date(until);
    let mut by_fp: BTreeMap<&str, Vec<&Failure>> = BTreeMap::new();
    for failure in failures {
        by_fp.entry(failure.fp.as_str()).or_default().push(failure);
    }
    let mut groups = Vec::new();
    for (fp, mut list) in by_fp {
        list.sort_by_key(|failure| failure.epoch);
        let line = |f: &&Failure| (f.epoch, f.epoch > ledger.last, f.text.clone());
        let lines = list.iter().map(line);
        let (bucket, cause) = fp.split_once('/').unwrap_or(("B11", fp));
        let title = format!("[daily] {}: {cause}", buckets::name(bucket));
        groups.push(Group::new(fp, issues::LEGION, title, lines, ledger, &today));
    }
    let mut flags: BTreeMap<String, Vec<&warmth::Flag>> = BTreeMap::new();
    for flag in hosts.iter().flat_map(|h| h.host.flags.iter().chain(&h.gate.flags)) {
        flags.entry(flag.fingerprint()).or_default().push(flag);
    }
    for (fp, list) in flags {
        let what = if list[0].kind == "gate" {
            "gate cache"
        } else {
            "broker warmth"
        };
        let title = format!("[daily] {what}: {} ({})", list[0].slug, list[0].repo);
        let text = |f: &&warmth::Flag| {
            format!("{} {} {}: {}", time::stamp(until), f.host, f.repo, f.detail)
        };
        let lines = list.iter().map(|f| (until, until > ledger.last, text(f)));
        groups.push(Group::new(&fp, list[0].owner, title, lines, ledger, &today));
    }
    groups
}

pub fn run(args: DailyArgs) -> CommandResult {
    let message = format!("--since {:?} is not 90m, 24h, 2d or 1w", args.since);
    let span = time::duration(&args.since).ok_or_else(|| CommandError::usage(message))?;
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let home = home.ok_or_else(|| CommandError::incomplete("HOME is not set"))?;
    let until = time::now();
    let (since, today, apply) = (until - span, time::date(until), args.apply);
    let state =
        std::env::var_os("LEGION_STATE_DIR").map_or_else(|| home.join(".legion"), PathBuf::from);
    let (dir, out) = (state.join("daily"), Path::new(OUT).join(&today));
    let mut col = Collect {
        window: (since, until),
        dir: dir.clone(),
        failures: vec![],
        notes: vec![],
    };

    // Probe first, so the scan below also reads the receipts and coverage it produced.
    let mut probes = Vec::new();
    if args.probe {
        let plan = args
            .probe_plan
            .clone()
            .unwrap_or_else(|| dir.join("probe-plan.json"));
        probes = run_probe(&plan, &out.join("probe"), &mut col);
    }

    // Collect: this Mac, then the Dell copied read-only into scratch.
    let mut hosts = vec![col.host(
        "mac",
        mac_files(&home, since),
        (Path::new(BROKER), Path::new(GATE_COVERAGE)),
        &home.join(MAC_CONTROL).join("logs/lifecycle.ndjson"),
        mac_disk_free(),
    )];
    let mut complete = false;
    if !args.no_dell {
        let copy = out.join("dell");
        let dell = dell::collect(&copy, since);
        complete = dell.warnings.is_empty();
        col.notes.extend(dell.warnings);
        if dell.files > 0 || complete {
            let (mut claude, mut codex) = (Vec::new(), Vec::new());
            scan::files(&copy.join("claude"), 1, since, &mut claude);
            scan::files(&copy.join("codex"), 1, since, &mut codex);
            hosts.push(col.host(
                "dell",
                [claude, codex],
                (copy.join("receipts").as_path(), copy.join("coverage").as_path()),
                &copy.join("lifecycle/lifecycle.ndjson"),
                dell.disk_free,
            ));
        }
    }

    // Match: the ledger gives each fingerprint its days, GitHub its issue.
    let ledger_path = dir.join("ledger.json");
    let loaded = load::<Ledger>(&ledger_path);
    let ledger_ok = loaded.is_ok();
    let mut ledger = loaded.unwrap_or_else(|e| {
        col.note(format!("ledger {e}; nothing will be saved"));
        Ledger::default()
    });
    let groups = groups(&col.failures, &hosts, &ledger, until);
    ledger.record(&today, &groups, until, complete);
    let mut repos: Vec<&str> = groups.iter().map(|group| group.repo).collect();
    repos.push(issues::LEGION);
    repos.sort_unstable();
    repos.dedup();
    let (mut known, mut fixed) = (BTreeMap::new(), Vec::new());
    for repo in repos {
        match issues::list(repo) {
            Ok(listing) => {
                fixed.extend(issues::fixed(repo, &listing, &ledger));
                known.insert(repo, listing);
            }
            Err(e) => col.note(format!("github: {e}")),
        }
    }
    let mut gh = |args: &[&str]| {
        if apply {
            issues::gh(args)
        } else {
            Ok(String::new())
        }
    };
    let results = issues::sync(&groups, &known, &mut ledger, &mut gh);
    let root =
        std::env::var_os("LEGION_REPO_ROOT").map_or_else(|| PathBuf::from(REPO), PathBuf::from);
    let impact = digest::impact(&root, until, &ledger).unwrap_or_else(|e| {
        col.note(format!("impact: {e}"));
        Vec::new()
    });

    // Save state only on --apply, and never over an unreadable ledger.
    if apply {
        if ledger_ok {
            if let Err(e) = save(&ledger_path, &ledger) {
                col.note(format!("ledger: {e}"));
            }
        }
        for h in hosts.iter_mut().filter(|h| !h.host.repos.is_empty()) {
            warmth::remember(&mut h.state, &h.host);
            if let Err(e) = save(&h.path, &h.state) {
                col.note(format!("warmth state: {e}"));
            }
        }
    }

    let jobs: Vec<String> = hosts.iter().flat_map(|h| warmth::report(&h.host)).collect();
    let gates: Vec<String> = hosts.iter().flat_map(|h| gate::report(&h.gate)).collect();
    let hosts: Vec<String> = hosts.iter().map(host_line).collect();
    let mode = if apply {
        "Applied."
    } else {
        "Dry run: nothing written to GitHub or state."
    };
    let (from, to) = (time::stamp(since), time::stamp(until));
    let header = format!("# Legion daily {today}\n\nScanned {from} to {to}. {mode}\n\n");
    let header = format!("{header}{}\n", digest::bullets(&hosts).join("\n"));
    let actions = if apply {
        "Issue actions"
    } else {
        "Issue actions (run with --apply)"
    };
    let sections = [
        (
            "Fixes that worked (closed, 7 runs with no recurrence)",
            digest::bullets(&fixed),
        ),
        ("Impact of changes in the last 7 days", impact),
        (
            "Broker jobs in repositories with warmth flags",
            digest::bullets(&jobs),
        ),
        ("Warm-cache probe", digest::bullets(&probes)),
        (
            "Gate runs and cache reuse (scan phase only; no per-scan time or broker join)",
            digest::bullets(&gates),
        ),
        (actions, digest::bullets(&results)),
        ("Notes", digest::bullets(&col.notes)),
    ];
    let text = digest::render(&header, &groups, (&ledger, &known), &sections);
    let path = out.join("digest.md");
    let written = fs::create_dir_all(&out).and_then(|()| fs::write(&path, &text));
    if !args.json {
        let failed = written.err().map_or(String::new(), |e| {
            format!("Could not write the digest: {e}\n")
        });
        return Ok(json!({"__raw": format!("{text}\nDigest: {}\n{failed}", path.display())}));
    }
    let file = path.display().to_string();
    Ok(
        json!({"digest": file, "written": written.is_ok(), "failures": groups.len(),
        "actions": results, "fixed": fixed, "notes": col.notes}),
    )
}

/// Run the probe plan and return its digest rows; a probe that cannot start is a note.
#[cfg(target_os = "macos")]
fn run_probe(plan: &Path, out: &Path, col: &mut Collect) -> Vec<String> {
    match probe::run(plan, out) {
        Ok(records) => probe::rows(&records),
        Err(e) => {
            col.note(format!("probe: {e}; nothing ran"));
            Vec::new()
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn run_probe(_plan: &Path, _out: &Path, col: &mut Collect) -> Vec<String> {
    col.note("probe: not supported on this host (cancellation is macOS only); nothing ran".into());
    Vec::new()
}

/// One host's summary line for the digest.
fn host_line(h: &HostRun) -> String {
    format!(
        "{}: {} receipts and {} gate coverage reports read, {} flags",
        h.host.name,
        h.host.receipts,
        h.gate.reports,
        h.host.flags.len() + h.gate.flags.len()
    )
}
