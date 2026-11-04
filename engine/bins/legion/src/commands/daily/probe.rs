//! `legion daily --probe`: the active, bounded warm-cache measurement (Orthic-Labs/legion#138).
//!
//! Each cell of an explicit plan (`~/.legion/daily/probe-plan.json`) runs the installed host
//! gate once, in the repository's primary checkout at its current commit, so Class A runs before
//! the broker admits anything, on the one warm target, with no cache option. Rules:
//! - A cell is skipped, never retried, when the broker is unreadable or already has a job for
//!   that workspace. The first cell that does not pass stops the run.
//! - The gate gets a 900 s deadline, then one 60 s cleanup budget covering signals, stream
//!   joins and broker queries. Only processes this probe started (checked by pid and start
//!   time) are signalled, never a broker. The broker itself is never cancelled: it cancels a
//!   disconnected gate client's job, and a coalesced job may belong to other clients.
//! - The gate's snapshot ownership record (pid and start time verified) gives the lease to
//!   check. The next cell starts only on proof of no active owned work, which needs all four:
//!   `rustright list` shows no job in flight and `broker.tokens.held` 0; every observed lease's
//!   members are empty or all `REAPED`; no ownership record remains for a probe process; no
//!   probe process is alive. Anything less is unknown and halts the run. An owner record's
//!   `broker.submitted: false` is a sample, not proof that nothing was submitted.
//! - The record joins the cell's coverage report (file named by the gate's own pid) and the
//!   broker receipts of the jobs the lease names. Nothing is read from log text; a missing
//!   join stays unknown.
//!
//! macOS and Windows. macOS signals INT, TERM, then KILL. Windows follows the proven Dell
//! harness (`rk-hr-performance-sweep/controls/dell-gate-safe.ps1`): the gate is `node` running
//! the host entry `.mjs` directly, so the root is a held child handle; on cancel the root is
//! killed through that handle, then each owned descendant is killed only through a handle whose
//! start time equals the creation time recorded when it was first seen (never by pid alone,
//! never a tree, never a broker). The RustRight client is its runtime executable, not the shim.
//! Every child runs with no window.
use super::{gate, time};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const PLAN_SCHEMA: &str = "legion.daily-probe-plan/1";
#[cfg(not(windows))]
mod paths {
    pub const HOST_GATE: &str = "/Volumes/D/.rightkit-managed/agent-bin/rightkit-host-gate";
    pub const RUSTRIGHT: &str = "rustright";
    pub const OWNERSHIP: &str = "/Volumes/D/.rightkit-managed/build-ownership";
    pub const RECEIPTS: &str = "/Volumes/D/.rightkit-managed/rightkit-build-control/receipts";
    pub const COVERAGE: &str = "/Volumes/D/.rightkit-managed/runs/rightkit-gate-coverage";
    pub const TRUSTED_GATES: &str = "/Volumes/D/.rightkit-managed/trusted-gates";
    pub const REPOS: &str = "/Volumes/D/claude/";
    /// RustRight's default roots (`rustright-config` `managed_roots` and `identity`): the
    /// legacy data root, the renamed data root, and the control roots under the home.
    pub const LEGACY_DATA: &str = "/Volumes/D/.rightkit-managed";
    pub const RENAMED_DATA: &str = "/Volumes/D/.rustright";
    pub const CONTROL_UNDER_HOME: [&str; 2] = [
        "Library/Application Support/RightKit/build-control",
        "Library/Application Support/RustRight/broker",
    ];
}
#[cfg(windows)]
mod paths {
    /// Run by `node` (from `PATH`), as the Dell harness does.
    pub const HOST_GATE: &str = r"D:\.rightkit-managed\agent-bin\rightkit-host-gate.mjs";
    pub const RUSTRIGHT: &str = r"D:\.rustright\runtime\rustright.exe";
    pub const OWNERSHIP: &str = r"D:\.rightkit-managed\build-ownership";
    pub const RECEIPTS: &str = r"D:\.rightkit-managed\rightkit-build-control\receipts";
    pub const COVERAGE: &str = r"D:\.rightkit-managed\runs\rightkit-gate-coverage";
    pub const TRUSTED_GATES: &str = r"D:\.rightkit-managed\trusted-gates";
    pub const REPOS: &str = r"d:\claude\";
    pub const LEGACY_DATA: &str = r"D:\.rightkit-managed";
    pub const RENAMED_DATA: &str = r"D:\.rustright";
    /// Under `%LOCALAPPDATA%` (else `%USERPROFILE%\AppData\Local`).
    pub const CONTROL_UNDER_HOME: [&str; 1] = [r"RightKit\build-control"];
}
use paths::{COVERAGE, HOST_GATE, OWNERSHIP, RECEIPTS, REPOS, RUSTRIGHT, TRUSTED_GATES};
const DEADLINE_SECS: u64 = 900;
const CLEANUP_SECS: u64 = 60;
/// The only environment a plan may set.
const KNOBS: [&str; 1] = ["RK_GATE_JOBS"];
/// A process start from `ps etime` is whole seconds; the ownership record is milliseconds.
const START_SLACK_MS: i64 = 2500;

#[derive(Deserialize)]
struct Plan {
    schema: String,
    cells: Vec<Cell>,
}

/// One gate run. `argv[0]` must be the installed host gate; `{HEAD}` in an argument is replaced
/// by the checkout's current commit. The plan names the selection (changed units or a canonical
/// probe fixture); the probe never widens it.
#[derive(Deserialize)]
struct Cell {
    id: String,
    repo: PathBuf,
    #[serde(default)]
    cwd: Option<PathBuf>,
    argv: Vec<String>,
    /// When set, the cell runs only if the checkout's HEAD is this commit (a full or abbreviated
    /// hash); otherwise it is skipped, never moved.
    #[serde(default)]
    commit: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
    deadline_seconds: u64,
    #[serde(default = "default_grace")]
    grace_seconds: u64,
}

fn default_grace() -> u64 {
    15
}

fn validate(plan: &Plan) -> Result<(), String> {
    if plan.schema != PLAN_SCHEMA {
        return Err(format!("probe plan schema is not {PLAN_SCHEMA}"));
    }
    if plan.cells.is_empty() {
        return Err("probe plan has no cells".into());
    }
    let mut ids = Vec::new();
    for cell in &plan.cells {
        let id_ok = !cell.id.is_empty()
            && cell.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !id_ok || ids.contains(&cell.id) {
            return Err(format!("probe cell id {:?} is empty, invalid or repeated", cell.id));
        }
        ids.push(cell.id.clone());
        let repo = cell.repo.to_string_lossy();
        let under = if cfg!(windows) {
            repo.to_lowercase().starts_with(REPOS)
        } else {
            repo.starts_with(REPOS)
        };
        if !under || repo.contains("..") {
            return Err(format!("{}: repo must be a primary checkout under {REPOS}", cell.id));
        }
        if cell.cwd.as_ref().is_some_and(|cwd| !cwd.starts_with(&cell.repo)) {
            return Err(format!("{}: cwd must be inside the repo", cell.id));
        }
        if cell.argv.first().map(String::as_str) != Some(HOST_GATE) {
            return Err(format!("{}: argv[0] must be {HOST_GATE}", cell.id));
        }
        if cell.argv.iter().any(|arg| arg.contains("no-cache") || arg.contains("cold")) {
            return Err(format!("{}: a probe never runs a no-cache or cold build", cell.id));
        }
        if cell.env.keys().any(|key| !KNOBS.contains(&key.as_str())) {
            return Err(format!("{}: env may set only {}", cell.id, KNOBS.join(", ")));
        }
        let pin_ok = cell.commit.as_deref().is_none_or(|pin| {
            pin.len() >= 7 && pin.len() <= 40 && pin.bytes().all(|b| b.is_ascii_hexdigit())
        });
        if !pin_ok {
            return Err(format!("{}: commit must be 7-40 hex characters", cell.id));
        }
        if cell.deadline_seconds != DEADLINE_SECS {
            return Err(format!("{}: deadline_seconds must be {DEADLINE_SECS}", cell.id));
        }
        if !(1..=30).contains(&cell.grace_seconds) {
            return Err(format!("{}: grace_seconds must be 1-30", cell.id));
        }
    }
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

/// `YYYY-MM-DDTHH:MM:SS.mmmZ`.
fn utc() -> String {
    let ms = now_ms();
    let secs = (ms / 1000).rem_euclid(86_400);
    let clock = format!("{:02}:{:02}:{:02}", secs / 3600, secs % 3600 / 60, secs % 60);
    format!("{}T{clock}.{:03}Z", time::date(ms / 1000), ms % 1000)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn digest_file(path: &Path) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0; 1 << 20];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(hex(&hasher.finalize()))
}

/// Run a short command with a deadline; stdout on success. A command still running at the
/// deadline is killed and reported as a timeout.
fn bounded(command: &mut Command, limit: Duration) -> Result<Vec<u8>, String> {
    let mut child = quiet(command)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let mut stdout = child.stdout.take().ok_or("no stdout")?;
    let reader = thread::spawn(move || {
        let mut out = Vec::new();
        let _ = stdout.read_to_end(&mut out);
        out
    });
    let end = Instant::now() + limit;
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => {
                let out = reader.join().unwrap_or_default();
                return if status.success() {
                    Ok(out)
                } else {
                    Err(format!("exit {status}"))
                };
            }
            None if Instant::now() >= end => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("timed out".into());
            }
            None => thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// No console window on Windows (`CREATE_NO_WINDOW`); nothing elsewhere.
#[cfg(windows)]
fn quiet(command: &mut Command) -> &mut Command {
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0800_0000)
}

#[cfg(not(windows))]
fn quiet(command: &mut Command) -> &mut Command {
    command
}

/// The gate in its own process group, with no window on Windows.
#[cfg(windows)]
fn detach(command: &mut Command) -> &mut Command {
    use std::os::windows::process::CommandExt;
    // CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    command.creation_flags(0x0000_0200 | 0x0800_0000)
}

#[cfg(not(windows))]
fn detach(command: &mut Command) -> &mut Command {
    use std::os::unix::process::CommandExt;
    command.process_group(0)
}

/// A `file://` URL for a local path (drive letters get the third slash).
fn file_url(path: &Path) -> String {
    let text = path.display().to_string();
    let text = text.strip_prefix(r"\\?\").unwrap_or(&text).replace('\\', "/");
    if text.starts_with('/') {
        format!("file://{text}")
    } else {
        format!("file:///{text}")
    }
}

fn git(repo: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    bounded(Command::new("git").arg("-C").arg(repo).args(args), Duration::from_secs(30))
}

fn git_text(repo: &Path, args: &[&str]) -> Result<String, String> {
    git(repo, args).map(|out| String::from_utf8_lossy(&out).trim().to_owned())
}

/// The gate the host entry selects (`trustedGate()` of the host gate module), its package
/// manifest, the trusted-gate manifests and the broker config, each by digest.
fn gate_identity(repo: &Path, host: Option<&Path>) -> Value {
    let selected = host.and_then(|host| {
        let script = "const m = await import(process.argv[1]); console.log(m.trustedGate())";
        let url = file_url(host);
        let mut node = Command::new("node");
        node.args(["--input-type=module", "-e", script, &url]).current_dir(repo);
        let out = bounded(&mut node, Duration::from_secs(30)).ok()?;
        let path = PathBuf::from(String::from_utf8_lossy(&out).trim());
        fs::canonicalize(path).ok()
    });
    let package = selected
        .as_deref()
        .and_then(Path::parent)
        .and_then(Path::parent)
        .map(|dir| dir.join("package.json"));
    let mut trusted = BTreeMap::new();
    for entry in fs::read_dir(TRUSTED_GATES).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".manifest.txt") {
            trusted.insert(name, digest_file(&entry.path()));
        }
    }
    let candidates = broker_config_candidates();
    let resolved = candidates.iter().find(|path| path.is_file());
    let listed: Vec<Value> = candidates
        .iter()
        .map(|path| json!({"path": path.display().to_string(), "exists": path.is_file()}))
        .collect();
    json!({
        "selectedGate": selected.as_ref().map(|p| p.display().to_string()),
        "selectedGateSha256": selected.as_deref().and_then(digest_file),
        "selectedPackageSha256": package.as_deref().and_then(digest_file),
        "trustedManifests": trusted,
        "brokerConfig": {
            "resolved": resolved.map(|p| p.display().to_string()),
            "sha256": resolved.and_then(|p| digest_file(p)),
            "candidates": listed,
        },
    })
}

/// `config.json` under each root RustRight would try, in its order: the control root it is
/// told (`RUSTRIGHT_`/`RIGHTKIT_CONTROL_ROOT`), the platform's control root under the home, the
/// data root it is told (`DATA_ROOT`, `MANAGED_ROOT`, `EXTERNAL_ROOT`), the legacy data root
/// (the Windows legacy control root), then the renamed roots.
fn broker_config_candidates() -> Vec<PathBuf> {
    let named = |name: &str| {
        ["RUSTRIGHT_", "RIGHTKIT_"]
            .iter()
            .find_map(|prefix| std::env::var_os(format!("{prefix}{name}")))
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    };
    let home = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()).map(PathBuf::from).or_else(
            || std::env::var_os("USERPROFILE").map(|p| PathBuf::from(p).join(r"AppData\Local")),
        )
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    };
    let mut roots: Vec<PathBuf> = named("CONTROL_ROOT").into_iter().collect();
    if let Some(home) = &home {
        roots.extend(paths::CONTROL_UNDER_HOME.iter().map(|under| home.join(under)));
    }
    roots.extend(["DATA_ROOT", "MANAGED_ROOT", "EXTERNAL_ROOT"].iter().filter_map(|n| named(n)));
    roots.push(PathBuf::from(paths::LEGACY_DATA));
    roots.push(PathBuf::from(paths::RENAMED_DATA));
    let mut seen = Vec::new();
    for root in roots {
        let config = root.join("config.json");
        if !seen.contains(&config) {
            seen.push(config);
        }
    }
    seen
}

/// What must not change during a cell: the commit, tree, tracked edits, lockfiles, the host
/// gate entry that is executed and the gate, trust and broker config it resolves to.
fn identity(repo: &Path) -> Value {
    let tracked = git(repo, &["diff", "--binary", "HEAD", "--"]).map(|d| hex(&Sha256::digest(d)));
    let mut locks = BTreeMap::new();
    for name in ["Cargo.lock", "pnpm-lock.yaml"] {
        for found in [repo.join(name), repo.join("tauri-app-next").join(name)] {
            if let Some(sum) = digest_file(&found) {
                locks.insert(found.display().to_string(), sum);
            }
        }
    }
    let gate = fs::canonicalize(HOST_GATE).ok();
    // On macOS `rustright` is found on PATH, so there is no fixed client file to hash.
    let client = fs::canonicalize(RUSTRIGHT).ok();
    json!({
        "head": git_text(repo, &["rev-parse", "HEAD"]).ok(),
        "tree": git_text(repo, &["rev-parse", "HEAD^{tree}"]).ok(),
        "status": git_text(repo, &["status", "--porcelain=v1", "-uno"]).ok(),
        "trackedDiffSha256": tracked.ok(),
        "locks": locks,
        "hostEntry": HOST_GATE,
        "hostEntryResolved": gate.as_ref().map(|p| p.display().to_string()),
        "hostEntrySha256": gate.as_deref().and_then(digest_file),
        "gate": gate_identity(repo, gate.as_deref()),
        "rustrightClient": RUSTRIGHT,
        "rustrightClientSha256": client.as_deref().and_then(digest_file),
        "node": node_version(),
        "brokerPids": broker_pids(),
    })
}

fn node_version() -> Option<String> {
    let out = bounded(Command::new("node").arg("--version"), Duration::from_secs(5)).ok()?;
    Some(String::from_utf8_lossy(&out).trim().to_owned())
}

/// The running broker processes as `pid@start`: a restarted broker changes the identity.
fn broker_pids() -> Option<Vec<String>> {
    let rows = processes()?;
    let brokers = rows
        .iter()
        .filter(|(_, row)| row.comm.to_lowercase().contains("rustright-broker"))
        .map(|(pid, row)| format!("{pid}@{}", row.lstart))
        .collect();
    Some(brokers)
}

/// One `ps` row: `lstart` is the identity text, `start_ms` the start from `etime`.
#[derive(Clone)]
struct Proc {
    ppid: u32,
    lstart: String,
    start_ms: i64,
    comm: String,
}

/// `[[dd-]hh:]mm:ss` as seconds.
#[cfg(not(windows))]
fn etime(text: &str) -> Option<i64> {
    let (days, rest) = match text.split_once('-') {
        Some((days, rest)) => (days.parse::<i64>().ok()?, rest),
        None => (0, text),
    };
    let mut secs = 0;
    for part in rest.split(':') {
        secs = secs * 60 + part.parse::<i64>().ok()?;
    }
    Some(days * 86_400 + secs)
}

/// Every process from CIM: `pid|ppid|creation epoch ms|name`. The creation time is exact, so
/// it is both the identity text and the start.
#[cfg(windows)]
fn processes() -> Option<BTreeMap<u32, Proc>> {
    let script = "Get-CimInstance Win32_Process -OperationTimeoutSec 1 | ForEach-Object { '{0}|{1}|{2}|{3}' -f \
        $_.ProcessId, $_.ParentProcessId, \
        ([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds(), $_.Name }";
    let mut ps = Command::new("powershell");
    ps.args(["-NoProfile", "-NonInteractive", "-Command", script]);
    let out = bounded(&mut ps, Duration::from_secs(15)).ok()?;
    let mut rows = BTreeMap::new();
    for line in String::from_utf8_lossy(&out).lines() {
        let fields: Vec<&str> = line.trim().splitn(4, '|').collect();
        let &[pid, ppid, start, name] = fields.as_slice() else {
            continue;
        };
        let (Ok(pid), Ok(ppid), Ok(start)) =
            (pid.parse::<u32>(), ppid.parse::<u32>(), start.parse::<i64>())
        else {
            continue;
        };
        let row = Proc {
            ppid,
            lstart: start.to_string(),
            start_ms: start,
            comm: name.to_owned(),
        };
        rows.insert(pid, row);
    }
    (!rows.is_empty()).then_some(rows)
}

#[cfg(not(windows))]
fn processes() -> Option<BTreeMap<u32, Proc>> {
    let mut ps = Command::new("ps");
    ps.args(["-axo", "pid=,ppid=,etime=,lstart=,comm="]);
    let out = bounded(&mut ps, Duration::from_secs(2)).ok()?;
    let now = now_ms();
    let mut rows = BTreeMap::new();
    for line in String::from_utf8_lossy(&out).lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 9 {
            continue;
        }
        let (Ok(pid), Ok(ppid), Some(age)) =
            (fields[0].parse::<u32>(), fields[1].parse::<u32>(), etime(fields[2]))
        else {
            continue;
        };
        rows.insert(
            pid,
            Proc {
                ppid,
                lstart: fields[3..8].join(" "),
                start_ms: now - age * 1000,
                comm: fields[8..].join(" "),
            },
        );
    }
    Some(rows)
}

/// The gate's snapshot ownership record, matched to a process this probe started.
#[derive(Clone, serde::Serialize)]
struct Owner {
    file: String,
    handle: String,
    snapshot: String,
    pid: u32,
    #[serde(rename = "startedMs")]
    started_ms: i64,
}

/// The processes this probe started and the ownership records they hold.
struct Tracker {
    /// pid -> (`lstart`, start ms) at first sight.
    owned: BTreeMap<u32, (String, i64)>,
    owners: BTreeMap<String, Owner>,
    commit: String,
    log: PathBuf,
    overhead: Duration,
}

impl Tracker {
    /// Add descendants of owned processes and any new ownership record; `None` when `ps`
    /// could not be read, so liveness is unknown.
    fn observe(&mut self) -> Option<BTreeMap<u32, Proc>> {
        let started = Instant::now();
        let rows = processes();
        if let Some(rows) = &rows {
            loop {
                let mut changed = false;
                for (pid, row) in rows {
                    let parent = self.owned.get(&row.ppid);
                    let parent_same = parent.is_some_and(|(lstart, _)| {
                        rows.get(&row.ppid).is_some_and(|p| &p.lstart == lstart)
                    });
                    if parent_same && !self.owned.contains_key(pid) {
                        self.owned.insert(*pid, (row.lstart.clone(), row.start_ms));
                        changed = true;
                    }
                }
                if !changed {
                    break;
                }
            }
            self.find_owners(rows);
        }
        self.overhead += started.elapsed();
        rows
    }

    fn find_owners(&mut self, rows: &BTreeMap<u32, Proc>) {
        let Ok(dirs) = fs::read_dir(OWNERSHIP) else { return };
        for dir in dirs.flatten() {
            let file = dir.path().join("owner.json");
            let Some(record) = fs::read_to_string(&file)
                .ok()
                .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            else {
                continue;
            };
            let pid = record["pid"].as_u64().and_then(|pid| u32::try_from(pid).ok());
            let (Some(pid), Some(started), Some(handle), Some(snapshot)) = (
                pid,
                record["startedMs"].as_f64().map(|ms| ms as i64),
                record["handle"].as_str().filter(|h| !h.is_empty()),
                record["snapshot"].as_str().filter(|s| !s.is_empty()),
            ) else {
                continue;
            };
            let mine = self.owned.get(&pid).is_some_and(|(lstart, _)| {
                rows.get(&pid).is_some_and(|row| {
                    &row.lstart == lstart && (row.start_ms - started).abs() <= START_SLACK_MS
                })
            });
            if record["schema"] != "rightkit.build-ownership/1"
                || record["commit"] != self.commit.as_str()
                || !mine
                || self.owners.contains_key(handle)
            {
                continue;
            }
            let owner = Owner {
                file: file.display().to_string(),
                handle: handle.to_owned(),
                snapshot: snapshot.to_owned(),
                pid,
                started_ms: started,
            };
            append(&self.log, &json!({"observedUtc": utc(), "owner": &owner}));
            self.owners.insert(handle.to_owned(), owner);
        }
    }

    /// Owned processes still running with the start they had when first seen.
    fn alive(&self, rows: &BTreeMap<u32, Proc>) -> Vec<u32> {
        let same = |pid: &u32, lstart: &String| rows.get(pid).is_some_and(|r| &r.lstart == lstart);
        self.owned
            .iter()
            .filter(|(pid, (lstart, _))| same(pid, lstart))
            .map(|(pid, _)| *pid)
            .collect()
    }

    /// Signal the owned processes still alive, never a broker.
    fn signal(&mut self, signal: &str) {
        let Some(rows) = self.observe() else { return };
        for pid in self.alive(&rows) {
            if rows[&pid].comm.to_lowercase().contains("rustright-broker") {
                continue;
            }
            let start = self.owned.get(&pid).map_or(0, |(_, start)| *start);
            if let Some(mut command) = kill(signal, pid, start) {
                let _ = bounded(&mut command, Duration::from_secs(5));
            }
        }
    }
}

/// macOS: `kill -s <signal> <pid>` (the pid's start was checked by the caller's `ps` read).
/// Windows: only KILL acts. One PowerShell process opens the pid, kills it only when its start
/// time is the recorded creation time and its name is not the broker, all on the one handle,
/// so a reused pid is never touched. INT and TERM have no console to reach, so they do nothing.
#[cfg(windows)]
fn kill(signal: &str, pid: u32, start_ms: i64) -> Option<Command> {
    if signal != "KILL" {
        return None;
    }
    let script = format!(
        "$ErrorActionPreference='Stop'; $p = Get-Process -Id {pid}; $h = $p.Handle; \
         if (([DateTimeOffset]$p.StartTime).ToUnixTimeMilliseconds() -eq {start_ms} \
         -and $p.ProcessName -ne 'rustright-broker') {{ $p.Kill() }}"
    );
    let mut command = Command::new("powershell");
    command.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
    Some(command)
}

#[cfg(not(windows))]
fn kill(signal: &str, pid: u32, _start_ms: i64) -> Option<Command> {
    let mut command = Command::new("kill");
    command.args(["-s", signal]).arg(pid.to_string());
    Some(command)
}

/// The gate process: the host entry itself on macOS, `node <entry.mjs>` on Windows.
#[cfg(windows)]
fn gate_command(argv: &[String]) -> Command {
    let mut command = Command::new("node");
    command.args(argv);
    command
}

#[cfg(not(windows))]
fn gate_command(argv: &[String]) -> Command {
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    command
}

/// True when any ownership record names a pid this probe started, whatever its start time.
fn owner_record_names(owned: &BTreeMap<u32, (String, i64)>) -> bool {
    let Ok(dirs) = fs::read_dir(OWNERSHIP) else {
        // Unreadable: a record cannot be ruled out.
        return true;
    };
    dirs.flatten().any(|dir| {
        fs::read_to_string(dir.path().join("owner.json"))
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok())
            .and_then(|record| record["pid"].as_u64())
            .and_then(|pid| u32::try_from(pid).ok())
            .is_some_and(|pid| owned.contains_key(&pid))
    })
}

fn append(path: &Path, record: &Value) {
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{record}");
        let _ = file.sync_all();
    }
}

/// The broker's in-flight jobs as `(id, workspace)` and `broker.tokens.held`, or why they are
/// unknown.
type Broker = (Vec<(String, String)>, Option<u64>);

fn broker_jobs() -> Result<Broker, String> {
    let out = bounded(Command::new(RUSTRIGHT).arg("list"), Duration::from_secs(2))?;
    let listing: Value = serde_json::from_slice(&out).map_err(|e| e.to_string())?;
    let rows = listing["inFlight"].as_array().ok_or("inFlight is not a list")?;
    let jobs = rows
        .iter()
        .map(|row| match (row["id"].as_str(), row["workspace"].as_str()) {
            (Some(id), Some(workspace)) => Ok((id.to_owned(), workspace.to_owned())),
            _ => Err("an in-flight job has no id or workspace".to_owned()),
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok((jobs, listing["broker"]["tokens"]["held"].as_u64()))
}

/// The lease of one ownership record, checked against its snapshot and handle.
fn lease(owner: &Owner, limit: Duration) -> Value {
    let mut command = Command::new(RUSTRIGHT);
    command.args(["snapshot-lease", "status", "--snapshot", &owner.snapshot]);
    command.args(["--ownership", &owner.handle]);
    let checked = bounded(&mut command, limit).and_then(|out| {
        let status: Value = serde_json::from_slice(&out).map_err(|e| e.to_string())?;
        if status["schema"] != "rustright.snapshot-lease-status.v1"
            || status["snapshot"] != owner.snapshot.as_str()
            || status["ownership"] != owner.handle.as_str()
        {
            return Err("lease identity mismatch".to_owned());
        }
        let members = status["members"].as_array().ok_or("lease has no members")?;
        let prefix = format!("{}#", owner.handle);
        for member in members {
            let handle = member["handle"].as_str().unwrap_or("");
            let state = member["state"].as_str().unwrap_or("");
            if !(handle == owner.handle || handle.starts_with(&prefix))
                || !matches!(state, "ACTIVE" | "REAPED" | "UNKNOWN")
            {
                return Err("invalid lease member".to_owned());
            }
        }
        let state = |s: &str| members.iter().filter(move |m| m["state"] == s).count();
        let aggregate = if state("ACTIVE") > 0 {
            "ACTIVE"
        } else if !members.is_empty() && state("REAPED") == members.len() {
            "REAPED"
        } else {
            "UNKNOWN"
        };
        if status["state"] != aggregate {
            return Err("lease aggregate does not match its members".to_owned());
        }
        Ok(json!({"ok": true, "state": aggregate, "members": members}))
    });
    checked.unwrap_or_else(|e| json!({"ok": false, "state": "UNKNOWN", "error": e}))
}

/// Copy a child stream to a raw log and a timestamped one, line by line.
fn pump(stream: impl Read + Send + 'static, raw: PathBuf, stamped: PathBuf) -> JoinHandle<()> {
    thread::spawn(move || {
        let (Ok(mut raw), Ok(mut stamped)) = (File::create(raw), File::create(stamped)) else {
            return;
        };
        let mut reader = BufReader::new(stream);
        let mut line = Vec::new();
        while reader.read_until(b'\n', &mut line).is_ok_and(|read| read > 0) {
            let _ = raw.write_all(&line);
            let text = String::from_utf8_lossy(&line);
            let _ = writeln!(stamped, "{} {}", utc(), text.trim_end_matches('\n'));
            line.clear();
        }
    })
}

/// The coverage report the gate wrote: named by an owned pid, for this commit.
fn coverage_of(tracker: &Tracker, since_ms: i64) -> Value {
    let Ok(entries) = fs::read_dir(COVERAGE) else {
        return json!({"state": "unknown", "reason": "coverage directory unreadable"});
    };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let pid = name
            .strip_suffix(".json")
            .and_then(|stem| stem.rsplit('-').next())
            .and_then(|pid| pid.parse::<u32>().ok());
        let modified = entry.metadata().map_or(0, |meta| time::modified(&meta)) * 1000;
        if !pid.is_some_and(|pid| tracker.owned.contains_key(&pid)) || modified < since_ms - 5000 {
            continue;
        }
        let report = fs::read_to_string(entry.path())
            .ok()
            .and_then(|text| serde_json::from_str::<Value>(&text).ok());
        let Some(report) = report.filter(|r| {
            r["schema"] == gate::SCHEMA && r["commit"] == tracker.commit.as_str()
        }) else {
            continue;
        };
        let (mut keyed_hit, mut keyed_ran) = (0, 0);
        for row in report["scans"].as_array().into_iter().flatten() {
            if row["key"].as_str().is_some_and(|key| !key.is_empty()) {
                match row["coverage"].as_str() {
                    Some("hit") => keyed_hit += 1,
                    Some("ran") => keyed_ran += 1,
                    _ => {}
                }
            }
        }
        found.push(json!({
            "file": entry.path().display().to_string(),
            "startedAt": report["startedAt"], "endedAt": report["endedAt"],
            "totals": report["totals"], "keyedHit": keyed_hit, "keyedRan": keyed_ran,
        }));
    }
    if found.is_empty() {
        json!({"state": "unknown", "reason": "no report named by a probe pid for this commit"})
    } else {
        json!({"state": "joined", "reports": found})
    }
}

/// The broker receipts of the jobs the leases name; a job with no receipt stays unknown.
fn broker_refs(leases: &BTreeMap<String, Value>) -> Value {
    let mut refs = Vec::new();
    for lease in leases.values() {
        for member in lease["members"].as_array().into_iter().flatten() {
            let Some(job) = member["job"].as_str() else { continue };
            let path = Path::new(RECEIPTS).join(format!("{job}.json"));
            let receipt = fs::read_to_string(&path)
                .ok()
                .and_then(|text| serde_json::from_str::<Value>(&text).ok());
            refs.push(match receipt.filter(|r| r["id"] == job) {
                Some(r) => json!({
                    "job": job, "receipt": path.display().to_string(), "status": r["status"],
                    "stage": r["stage"]["name"], "queueMs": r["queueMs"], "runMs": r["runMs"],
                    "totalMs": r["totalMs"], "coalescedClients": r["coalescedClients"],
                    "coldStart": r["coldStart"], "reuse": r["cache"]["reuse"],
                    "notFresh": r["freshness"]["notFresh"],
                }),
                None => {
                    json!({"job": job, "state": "unknown", "reason": "no receipt for this job"})
                }
            });
        }
    }
    json!(refs)
}

fn wait_bounded(child: &mut Child, until: Instant) -> Option<i32> {
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status.code().unwrap_or(-1));
        }
        if Instant::now() >= until {
            return None;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Run one cell and write its record; the record's `status` decides whether the next cell runs.
fn run_cell(cell: &Cell, commit: &str, out: &Path, before: Value) -> Value {
    let dir = out.join(&cell.id);
    let _ = fs::create_dir_all(&dir);
    let argv: Vec<String> = cell.argv.iter().map(|a| a.replace("{HEAD}", commit)).collect();
    let cwd = cell.cwd.clone().unwrap_or_else(|| cell.repo.clone());
    let mut tracker = Tracker {
        owned: BTreeMap::new(),
        owners: BTreeMap::new(),
        commit: commit.to_owned(),
        log: dir.join("ownership.jsonl"),
        overhead: Duration::ZERO,
    };
    let mut command = gate_command(&argv);
    detach(command.current_dir(&cwd));
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for (key, _) in std::env::vars_os() {
        let key = key.to_string_lossy().into_owned();
        if key.starts_with("RK_GATE_") || key == "RUSTRIGHT_CANCEL_ON_DISCONNECT" {
            command.env_remove(&key);
        }
    }
    command.envs(&cell.env);
    let (start_utc, start_ms, started) = (utc(), now_ms(), Instant::now());
    let deadline = started + Duration::from_secs(cell.deadline_seconds);
    let (mut error, mut timed_out, mut streams) = (None::<String>, false, Vec::new());
    let mut child = match command.spawn() {
        Ok(child) => Some(child),
        Err(e) => {
            error = Some(format!("spawn: {e}"));
            None
        }
    };
    if let Some(child) = child.as_mut() {
        match processes().and_then(|rows| rows.get(&child.id()).cloned()) {
            Some(row) => {
                tracker.owned.insert(child.id(), (row.lstart, row.start_ms));
            }
            None => error = Some("cannot establish the gate process identity".into()),
        }
        if let Some(stdout) = child.stdout.take() {
            streams.push(pump(stdout, dir.join("stdout.log"), dir.join("stdout.stamped.log")));
        }
        if let Some(stderr) = child.stderr.take() {
            streams.push(pump(stderr, dir.join("stderr.log"), dir.join("stderr.stamped.log")));
        }
        while error.is_none() && matches!(child.try_wait(), Ok(None)) {
            tracker.observe();
            if Instant::now() >= deadline {
                timed_out = true;
                break;
            }
            let _ = wait_bounded(child, Instant::now() + Duration::from_secs(1));
        }
    }
    let workload_ms = started.elapsed().as_millis() as u64;

    // One cleanup budget for everything after the workload.
    let cleanup_end = Instant::now() + Duration::from_secs(CLEANUP_SECS);
    let running = child.as_mut().is_some_and(|c| matches!(c.try_wait(), Ok(None)));
    let cancelled = running || timed_out || error.is_some();
    if cancelled && child.is_some() {
        tracker.signal("INT");
        let grace_end = cleanup_end.min(Instant::now() + Duration::from_secs(cell.grace_seconds));
        while Instant::now() < grace_end {
            match tracker.observe() {
                Some(rows) if tracker.alive(&rows).is_empty() => break,
                _ => thread::sleep(Duration::from_secs(1)),
            }
        }
        tracker.signal("TERM");
        thread::sleep(Duration::from_secs(1).min(cleanup_end - Instant::now().min(cleanup_end)));
        // The root through the handle this probe holds, then the descendants by identity.
        if let Some(root) = child.as_mut() {
            let _ = root.kill();
        }
        tracker.signal("KILL");
    }
    let exit = child.as_mut().and_then(|c| {
        let until = cleanup_end.min(Instant::now() + Duration::from_secs(2));
        let code = wait_bounded(c, until);
        if code.is_none() {
            error.get_or_insert_with(String::new).push_str(" gate not reaped");
        }
        code
    });
    while streams.iter().any(|s| !s.is_finished()) && Instant::now() < cleanup_end {
        thread::sleep(Duration::from_millis(100));
    }
    let streams_open = streams.iter().any(|s| !s.is_finished());
    let remaining: Value = match tracker.observe() {
        Some(rows) => json!(tracker.alive(&rows)),
        None => json!("unknown"),
    };
    let mut leases = BTreeMap::new();
    while !tracker.owners.is_empty() && Instant::now() < cleanup_end {
        leases.clear();
        for (handle, owner) in &tracker.owners {
            let left = cleanup_end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            leases.insert(handle.clone(), lease(owner, left.min(Duration::from_secs(2))));
        }
        let reaped = leases.len() == tracker.owners.len()
            && leases.values().all(|l| {
                l["ok"] == true
                    && l["members"]
                        .as_array()
                        .is_some_and(|members| members.iter().all(|m| m["state"] == "REAPED"))
            });
        if reaped {
            break;
        }
        thread::sleep(Duration::from_secs(1).min(cleanup_end - Instant::now().min(cleanup_end)));
    }
    // No active owned work, proven only by all four checks together.
    let broker_after = broker_jobs();
    let broker_idle = broker_after
        .as_ref()
        .is_ok_and(|(jobs, held)| jobs.is_empty() && *held == Some(0));
    let leases_clear = leases.len() == tracker.owners.len()
        && leases.values().all(|l| {
            l["ok"] == true
                && l["members"]
                    .as_array()
                    .is_some_and(|members| members.iter().all(|m| m["state"] == "REAPED"))
        });
    let owner_records_removed = tracker.owners.values().all(|o| !Path::new(&o.file).exists())
        && !owner_record_names(&tracker.owned);
    let no_owned_alive = remaining == json!([]);
    let no_active_owned_work =
        broker_idle && leases_clear && owner_records_removed && no_owned_alive;
    let after = identity(&cell.repo);
    let identity_changed = before != after;
    let status = if streams_open || !no_active_owned_work {
        "halt_process_uncertain"
    } else if error.is_some() {
        "error"
    } else if identity_changed {
        "invalid_identity"
    } else if timed_out {
        "timeout"
    } else if exit == Some(0) {
        "pass"
    } else {
        "fail"
    };
    let record = json!({
        "schema": "legion.daily-probe-cell/1", "id": cell.id, "status": status,
        "repo": cell.repo.display().to_string(), "cwd": cwd.display().to_string(),
        "argv": argv, "env": cell.env, "commit": commit,
        "deadlineSeconds": cell.deadline_seconds, "cleanupSeconds": CLEANUP_SECS,
        "startUtc": start_utc, "endUtc": utc(), "wallMs": workload_ms,
        "cleanupMs": started.elapsed().as_millis() as u64 - workload_ms,
        "observationOverheadMs": tracker.overhead.as_millis() as u64,
        "exitCode": exit, "timedOut": timed_out, "cancelled": cancelled, "error": error,
        "remainingOwnedPids": remaining, "streamsOpen": streams_open,
        "ownership": tracker.owners.values().collect::<Vec<_>>(), "leases": leases,
        "activeOwnedWork": if no_active_owned_work { "none" } else { "unknown" },
        "activeOwnedWorkChecks": {"brokerIdle": broker_idle, "leasesClear": leases_clear,
            "ownerRecordsRemoved": owner_records_removed, "noOwnedProcessAlive": no_owned_alive},
        "brokerAfter": broker_after.map_or_else(|e| json!({"ok": false, "error": e}),
            |(jobs, held)| json!({"ok": true, "inFlight": jobs.len(), "tokensHeld": held})),
        "identityBefore": before, "identityAfter": after, "identityChanged": identity_changed,
        "coverage": coverage_of(&tracker, start_ms),
        "brokerJobs": broker_refs(&leases),
    });
    let text = serde_json::to_string_pretty(&record).unwrap_or_default();
    let _ = fs::write(dir.join("result.json"), text + "\n");
    record
}

/// Run the plan's cells in order into `out`. Returns one record per cell attempted or skipped,
/// or why nothing ran.
pub fn run(plan_path: &Path, out: &Path) -> Result<Vec<Value>, String> {
    let text = fs::read_to_string(plan_path)
        .map_err(|e| format!("probe plan {}: {e}", plan_path.display()))?;
    let plan: Plan = serde_json::from_str(&text).map_err(|e| format!("probe plan: {e}"))?;
    validate(&plan)?;
    fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let lock = File::create(out.join("probe.lock")).map_err(|e| e.to_string())?;
    lock.try_lock().map_err(|_| "another probe holds the lock".to_owned())?;
    // Named by date so the Mac can copy the Dell's file without a name collision.
    let results = out.join(format!("probe-results-{}.jsonl", time::date(time::now())));
    let mut records = Vec::new();
    for cell in &plan.cells {
        let skip = |status: &str, detail: String| {
            json!({"schema": "legion.daily-probe-cell/1", "id": cell.id, "status": status,
                "detail": detail, "utc": utc()})
        };
        let before = identity(&cell.repo);
        let Some(commit) = before["head"].as_str().map(str::to_owned) else {
            let record = skip("skipped", "repository HEAD unreadable".into());
            append(&results, &record);
            records.push(record);
            continue;
        };
        if let Some(pin) = cell.commit.as_deref().filter(|pin| !commit.starts_with(*pin)) {
            let record = skip("skipped", format!("HEAD is {commit}; the plan pins {pin}"));
            append(&results, &record);
            records.push(record);
            continue;
        }
        let workspace = cell.repo.to_string_lossy().to_lowercase();
        let busy = match broker_jobs() {
            Err(e) => Some(format!("broker list unreadable: {e}")),
            Ok((jobs, _)) => jobs
                .iter()
                .find(|(_, w)| w.to_lowercase().starts_with(&workspace))
                .map(|(id, _)| format!("broker job {id} already runs in this workspace")),
        };
        if let Some(detail) = busy {
            let record = skip("skipped", detail);
            append(&results, &record);
            records.push(record);
            continue;
        }
        let record = run_cell(cell, &commit, out, before);
        append(&results, &record);
        let passed = record["status"] == "pass";
        records.push(record);
        if !passed {
            break;
        }
    }
    Ok(records)
}

/// One digest row per cell.
pub fn rows(records: &[Value]) -> Vec<String> {
    records
        .iter()
        .map(|r| {
            let joined = |key: &str| r[key]["state"].as_str().unwrap_or("listed").to_owned();
            format!(
                "{} {}: wall {} ms, cleanup {} ms, exit {}, coverage {}, broker jobs {}{}",
                r["id"].as_str().unwrap_or("?"),
                r["status"].as_str().unwrap_or("?"),
                r["wallMs"],
                r["cleanupMs"],
                r["exitCode"],
                joined("coverage"),
                r["brokerJobs"].as_array().map_or(0, Vec::len),
                r["detail"].as_str().map_or(String::new(), |d| format!(" ({d})")),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(cell: Value) -> Plan {
        serde_json::from_value(json!({"schema": PLAN_SCHEMA, "cells": [cell]})).unwrap()
    }

    fn cell() -> Value {
        json!({"id": "rk", "repo": format!("{REPOS}rightkit"),
            "argv": [HOST_GATE, "--to", "compile", "--commit", "{HEAD}"],
            "env": {"RK_GATE_JOBS": "8"}, "deadline_seconds": 900})
    }

    #[test]
    fn plan_accepts_the_bounded_cell_only() {
        assert!(validate(&plan(cell())).is_ok());
        let mut other = cell();
        other["deadline_seconds"] = json!(1800);
        assert!(validate(&plan(other)).is_err());
        let mut env = cell();
        env["env"] = json!({"CARGO_TARGET_DIR": "/tmp/x"});
        assert!(validate(&plan(env)).is_err());
        let mut argv = cell();
        argv["argv"] = json!(["cargo", "build"]);
        assert!(validate(&plan(argv)).is_err());
        let mut repo = cell();
        repo["repo"] = json!("/Volumes/D/scratch/clone");
        assert!(validate(&plan(repo)).is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn elapsed_time_forms() {
        assert_eq!(etime("05"), Some(5));
        assert_eq!(etime("01:05"), Some(65));
        assert_eq!(etime("02:01:05"), Some(7265));
        assert_eq!(etime("1-00:00:01"), Some(86_401));
        assert_eq!(etime("x"), None);
    }
}
