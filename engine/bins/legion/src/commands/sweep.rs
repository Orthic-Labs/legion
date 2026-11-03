//! `legion sweep`: find tool calls and processes that have run for hours and ask the chat that
//! owns each one to decide. It never kills or signals anything; it is a dry run unless
//! `--notify`, which sends the owning chat one Pulse message per item at most every 2 hours.
//!
//! A scheduled task runs: `legion sweep --notify` (see `--install-schedule`).
use super::daily::time;
use super::{CommandError, CommandResult};
use clap::Args;
use serde::Serialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const PULSE: &str = "/Applications/Pulse.app/Contents/Helpers/pulse";
const HOUR: u64 = 3600;
const RESEND: i64 = 2 * 3600;
/// Only the end of a transcript is read: an open call is always near it.
const TAIL: u64 = 4 << 20;
/// Seconds a shell may start after the Bash call that owns it.
const SKEW: u64 = 120;
const BUILDERS: [&str; 5] = [
    "rightkit-gate",
    "rightkit-host-gate",
    "rustright",
    "rightkit-build-control",
    "build-broker",
];

#[derive(Debug, Args)]
pub struct SweepArgs {
    /// Message the owning chat about each long-running item. Without it: a dry run.
    #[arg(long)]
    pub notify: bool,
    #[arg(long)]
    pub json: bool,
    /// Print the launchd plist and the schtasks line for a 30 minute sweep; installs nothing.
    #[arg(long)]
    pub install_schedule: bool,
}

struct Proc {
    pid: u32,
    ppid: u32,
    pgid: u32,
    age: u64,
    cmd: String,
}

struct Call {
    session: String,
    id: String,
    tool: String,
    cmd: String,
    age: u64,
    open: bool,
    background: bool,
    last: bool,
}

/// A live Pulse chat: kind, session id, title.
type Peer = (String, String, String);

#[derive(Serialize)]
struct Item {
    key: String,
    what: String,
    age: u64,
    pid: Option<u32>,
    pgid: Option<u32>,
    session: Option<String>,
    /// The chat is inside this call and cannot read messages.
    blocked: bool,
    /// Listed but never messaged (the broker owns builds, or it has its own timeout).
    report_only: bool,
}

fn clip(text: &str, max: usize) -> String {
    text.chars().take(max).collect()
}

fn hm(secs: u64) -> String {
    format!("{}h{:02}m", secs / HOUR, secs % HOUR / 60)
}

/// `[[dd-]hh:]mm:ss` from `ps`, or plain seconds.
fn etime(text: &str) -> Option<u64> {
    let (days, rest) = text
        .split_once('-')
        .map_or((0, text), |(d, r)| (d.parse().unwrap_or(0), r));
    let mut secs = 0;
    for part in rest.split(':') {
        secs = secs * 60 + part.parse::<u64>().ok()?;
    }
    Some(days * 86_400 + secs)
}

/// Rows of `pid ppid pgid etime command`; the header and odd rows are skipped.
fn parse_ps(text: &str) -> Vec<Proc> {
    let row = |line: &str| {
        let (mut rest, mut f) = (line, [""; 4]);
        for slot in &mut f {
            let (word, tail) = rest.trim_start().split_once(char::is_whitespace)?;
            (*slot, rest) = (word, tail);
        }
        let n = |i: usize| f[i].parse::<u32>().ok();
        Some(Proc {
            pid: n(0)?,
            ppid: n(1)?,
            pgid: n(2)?,
            age: etime(f[3])?,
            cmd: rest.trim().to_owned(),
        })
    };
    text.lines().filter_map(row).collect()
}

fn program(cmd: &str) -> &str {
    let word = cmd.split_whitespace().next().unwrap_or("");
    word.rsplit(['/', '\\'])
        .next()
        .unwrap_or(word)
        .trim_end_matches(".exe")
}

fn is_snapshot(cmd: &str) -> bool {
    cmd.contains("shell-snapshots/") || cmd.contains("shell-snapshots\\")
}

fn exempt(cmd: &str) -> bool {
    BUILDERS.iter().any(|b| cmd.contains(b)) || cmd.contains("mcp")
}

/// What a process is (`shell`, `chat` or `orphan`) and whether it is report-only.
fn classify(p: &Proc, parent: Option<&Proc>) -> Option<(&'static str, bool)> {
    let temp = p.cmd.contains("/Volumes/D/.rightkit-managed/tmp/")
        || (p.cmd.contains("/var/folders/") && p.cmd.contains("/T/.tmp"));
    if p.ppid == 1 && p.age > 24 * HOUR && temp {
        return Some(("orphan", true));
    }
    let nested = parent
        .is_some_and(|q| is_snapshot(&q.cmd) || matches!(program(&q.cmd), "claude" | "codex"));
    let one_shot = p
        .cmd
        .split_whitespace()
        .any(|w| matches!(w, "-p" | "--print" | "exec"));
    let (class, min) = if is_snapshot(&p.cmd) {
        ("shell", 2 * HOUR)
    } else if matches!(program(&p.cmd), "claude" | "codex") && !one_shot && nested {
        ("chat", HOUR / 2)
    } else {
        return None;
    };
    // Commands with their own limit are left alone until 6 hours.
    let own = (p.cmd.contains("gh run watch") && p.cmd.contains("--exit-status"))
        || p.cmd.contains("timeout ")
        || p.cmd.contains("--max-time");
    (p.age >= min).then(|| (class, exempt(&p.cmd) || (own && p.age < 6 * HOUR)))
}

/// The Bash, Agent and terminal calls of one transcript tail, flagging those with no result.
fn read_calls(session: &str, lines: &str, now: i64) -> Vec<Call> {
    let (mut calls, mut last): (Vec<Call>, Option<String>) = (vec![], None);
    for record in lines
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
    {
        if !matches!(record["type"].as_str(), Some("assistant" | "user")) {
            continue;
        }
        last = None;
        let at = record["timestamp"]
            .as_str()
            .and_then(time::parse)
            .unwrap_or(now);
        for part in record["message"]["content"]
            .as_array()
            .into_iter()
            .flatten()
        {
            let id = part["id"]
                .as_str()
                .or(part["tool_use_id"].as_str())
                .unwrap_or("");
            let tool = part["name"].as_str().unwrap_or("");
            let wanted =
                matches!(tool, "Bash" | "Agent" | "Task") || tool.starts_with("mcp__terminal__");
            if part["type"] == "tool_result" {
                calls
                    .iter_mut()
                    .filter(|c| c.id == id)
                    .for_each(|c| c.open = false);
            } else if part["type"] == "tool_use" && wanted {
                let input = &part["input"];
                let text = ["command", "description", "prompt"]
                    .iter()
                    .find_map(|k| input[*k].as_str());
                last = Some(id.to_owned());
                calls.push(Call {
                    session: session.to_owned(),
                    id: id.to_owned(),
                    tool: tool.to_owned(),
                    cmd: clip(text.unwrap_or(""), 200),
                    age: (now - at).max(0) as u64,
                    open: true,
                    background: input["run_in_background"] == true,
                    last: false,
                });
            }
        }
    }
    calls
        .iter_mut()
        .filter(|c| Some(&c.id) == last.as_ref())
        .for_each(|c| c.last = true);
    calls
}

/// The Bash call that started this shell: its first line, cut at a quote, is in the shell's own
/// command line and it started within `SKEW` of the shell. None unless exactly one session
/// matches, so an unmatched item is listed but never messaged.
fn owner<'a>(shell: &Proc, calls: &'a [Call]) -> Option<&'a Call> {
    fn needle(c: &Call) -> Option<&str> {
        let head = c.cmd.lines().next()?.split('\'').next()?.trim();
        let end = head.char_indices().nth(40).map_or(head.len(), |(i, _)| i);
        Some(&head[..end]).filter(|n| n.len() >= 8)
    }
    let hits: Vec<&Call> = calls
        .iter()
        .filter(|c| c.tool == "Bash" && c.age.abs_diff(shell.age) <= SKEW)
        .filter(|c| needle(c).is_some_and(|n| shell.cmd.contains(n)))
        .collect();
    let last = hits.last()?;
    hits.iter()
        .all(|c| c.session == last.session)
        .then_some(*last)
}

/// The session's chat is inside a foreground call and cannot read messages.
fn blocked(session: &str, calls: &[Call]) -> bool {
    calls
        .iter()
        .any(|c| c.session == session && c.open && c.last && !c.background)
}

fn item(
    key: String,
    what: String,
    age: u64,
    ids: Option<(u32, u32)>,
    call: Option<&Call>,
    calls: &[Call],
    quiet: bool,
) -> Item {
    Item {
        key,
        what,
        age,
        pid: ids.map(|i| i.0),
        pgid: ids.map(|i| i.1),
        session: call.map(|c| c.session.clone()),
        blocked: call.is_some_and(|c| blocked(&c.session, calls)),
        report_only: quiet,
    }
}

/// Long-running items, and the orphans grouped by command.
fn find(procs: &[Proc], calls: &[Call]) -> (Vec<Item>, BTreeMap<String, usize>) {
    let (mut out, mut orphans, mut used) = (vec![], BTreeMap::new(), vec![]);
    for p in procs {
        let parent = procs.iter().find(|q| q.pid == p.ppid);
        let Some((class, quiet)) = classify(p, parent) else {
            continue;
        };
        if class == "orphan" {
            *orphans.entry(clip(&p.cmd, 60)).or_insert(0) += 1;
            continue;
        }
        let shell = if class == "shell" {
            Some(p)
        } else {
            parent.filter(|q| is_snapshot(&q.cmd))
        };
        let call = shell.and_then(|s| owner(s, calls));
        used.extend(call.map(|c| c.id.clone()));
        let what = clip(p.cmd.split(" eval ").nth(1).unwrap_or(&p.cmd), 80);
        out.push(item(
            format!("pid:{}", p.pid),
            what,
            p.age,
            Some((p.pid, p.pgid)),
            call,
            calls,
            quiet,
        ));
    }
    for c in calls.iter().filter(|c| c.open && !used.contains(&c.id)) {
        let limit = match c.tool.as_str() {
            "Bash" => 900,
            "Agent" | "Task" => 3 * HOUR,
            _ => 1800,
        };
        if c.age >= limit {
            let what = format!("{}: {}", c.tool, clip(&c.cmd, 80));
            out.push(item(
                format!("call:{}", c.id),
                what,
                c.age,
                None,
                Some(c),
                calls,
                exempt(&c.cmd),
            ));
        }
    }
    (out, orphans)
}

fn message(item: &Item) -> String {
    let (who, stop) = match item.pgid {
        Some(g) => (
            format!("pid {}, process group {g}", item.pid.unwrap_or(0)),
            format!("KillShell/TaskStop for your own background task, or `kill -- -{g}` for your own process group"),
        ),
        None => ("a tool call in this chat".to_owned(), "TaskStop for your own task".to_owned()),
    };
    let what = &item.what;
    let age = hm(item.age);
    format!("Information from Legion's sweep, not Adrian's words. This has run {age}: {what} ({who}). Decide: keep it, stop it yourself ({stop}), or say why it needs longer. Legion kills nothing.")
}

/// Message each owned, unblocked, non-exempt item at most once per `RESEND`; returns the keys
/// sent and leaves a gap note for an owner Pulse does not list as live.
fn notify(
    items: &[Item],
    peers: &[Peer],
    sent: &mut BTreeMap<String, i64>,
    now: i64,
    gaps: &mut Vec<String>,
    send: &mut dyn FnMut(&Peer, &str) -> Result<(), String>,
) -> Vec<String> {
    let mut done = vec![];
    for it in items.iter().filter(|i| !i.report_only && !i.blocked) {
        let Some(session) = &it.session else { continue };
        let Some(peer) = peers.iter().find(|p| &p.1 == session) else {
            gaps.push(format!(
                "no live Pulse chat for session {session} ({})",
                it.key
            ));
            continue;
        };
        let key = format!("{session}/{}", it.key);
        if sent.get(&key).is_some_and(|at| now - at < RESEND) {
            continue;
        }
        match send(peer, &message(it)) {
            Ok(()) => {
                sent.insert(key.clone(), now);
                done.push(key);
            }
            Err(e) => gaps.push(format!("send to {session}: {e}")),
        }
    }
    done
}

fn exec(command: &mut Command) -> Result<String, String> {
    let output = command.output().map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(clip(&String::from_utf8_lossy(&output.stderr), 200));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn processes() -> Result<Vec<Proc>, String> {
    let text = if cfg!(windows) {
        let row = r#""$($_.ProcessId) $($_.ParentProcessId) 0 $([int]((Get-Date)-$_.CreationDate).TotalSeconds) $($_.CommandLine)""#;
        exec(Command::new("powershell").args([
            "-NoProfile",
            "-Command",
            &format!("Get-CimInstance Win32_Process | % {{ {row} }}"),
        ]))
    } else {
        exec(Command::new("ps").args(["-axo", "pid,ppid,pgid,etime,command"]))
    };
    text.map(|t| parse_ps(&t))
}

fn peers() -> Result<Vec<Peer>, String> {
    let text = exec(Command::new(PULSE).args(["chat", "peers", "--json"]))?;
    let value: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let s = |c: &Value, k: &str| c[k].as_str().unwrap_or("").to_owned();
    let chats = value["chats"].as_array().into_iter().flatten();
    Ok(chats
        .filter(|c| c["liveness"] == "live")
        .map(|c| (s(c, "kind"), s(c, "session"), s(c, "name")))
        .collect())
}

fn send(peer: &Peer, text: &str) -> Result<(), String> {
    let target = format!("{}:{}", peer.0, peer.1);
    let mut child = Command::new(PULSE)
        .args(["chat", "send", &target, "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child
        .stdin
        .take()
        .ok_or("no stdin")?
        .write_all(text.as_bytes())
        .map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    out.status
        .success()
        .then_some(())
        .ok_or_else(|| clip(&String::from_utf8_lossy(&out.stderr), 200))
}

/// The last `TAIL` bytes of a file, starting at a line boundary.
fn tail(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let skip = file.metadata()?.len().saturating_sub(TAIL);
    file.seek(SeekFrom::Start(skip))?;
    let mut bytes = vec![];
    file.read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes).into_owned();
    Ok(if skip > 0 {
        text.split_once('\n')
            .map_or(String::new(), |(_, r)| r.to_owned())
    } else {
        text
    })
}

/// Transcripts modified since `since`, under `~/.claude` and every `~/ClaudeProfiles/*/.claude`.
fn transcripts(home: &Path, since: i64) -> Vec<PathBuf> {
    let list = |dir: &Path| {
        fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .collect::<Vec<_>>()
    };
    let mut roots = vec![home.join(".claude/projects")];
    roots.extend(
        list(&home.join("ClaudeProfiles"))
            .iter()
            .map(|p| p.join(".claude/projects")),
    );
    let files = roots.iter().flat_map(|r| list(r)).flat_map(|d| list(&d));
    let recent = |p: &PathBuf| fs::metadata(p).is_ok_and(|m| time::modified(&m) >= since);
    files
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl") && recent(p))
        .collect()
}

fn schedule() -> CommandResult {
    let exe = std::env::current_exe().map_err(|e| CommandError::incomplete(e.to_string()))?;
    let exe = exe.display();
    let plist = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>com.orthiclabs.legion.sweep</string>\n<key>ProgramArguments</key><array><string>{exe}</string><string>sweep</string><string>--notify</string></array>\n<key>StartInterval</key><integer>1800</integer>\n</dict></plist>");
    let task = format!(
        "schtasks /Create /TN \"Legion sweep\" /SC MINUTE /MO 30 /TR \"\\\"{exe}\\\" sweep\""
    );
    let text = format!("Nothing installed. Save as ~/Library/LaunchAgents/com.orthiclabs.legion.sweep.plist, then launchctl load it:\n{plist}\n\nWindows (report only; notify there is later):\n{task}\n");
    Ok(json!({"__raw": text}))
}

/// Write a temp file, then rename it over `path`.
fn save(path: &Path, text: &str) -> Result<(), String> {
    let temp = path.with_extension("tmp");
    fs::create_dir_all(path.parent().unwrap_or(Path::new("."))).map_err(|e| e.to_string())?;
    fs::write(&temp, text)
        .and_then(|()| fs::rename(&temp, path))
        .map_err(|e| e.to_string())
}

fn table(r: &Value) -> String {
    let mut out = format!("Legion sweep ({})\n", r["mode"].as_str().unwrap_or(""));
    for i in r["items"].as_array().into_iter().flatten() {
        let flag = if i["blocked"] == true {
            " [blocked]"
        } else if i["report_only"] == true {
            " [report only]"
        } else {
            ""
        };
        let (age, who) = (
            hm(i["age"].as_u64().unwrap_or(0)),
            i["session"].as_str().unwrap_or("unowned"),
        );
        out += &format!("{age} {who} {}{flag}\n", i["what"].as_str().unwrap_or(""));
    }
    for key in [
        "blocked chats (needs Adrian)",
        "orphans",
        "notified",
        "gaps",
    ] {
        for line in r[key]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            out += &format!("{key}: {line}\n");
        }
    }
    out
}

pub fn run(args: SweepArgs) -> CommandResult {
    if args.install_schedule {
        return schedule();
    }
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    let home = home.ok_or_else(|| CommandError::incomplete("HOME is not set"))?;
    let state =
        std::env::var_os("LEGION_STATE_DIR").map_or_else(|| home.join(".legion"), PathBuf::from);
    let (dir, now, mut gaps) = (state.join("sweep"), time::now(), vec![]);
    let mut gap = |what: &str, e: String| gaps.push(format!("{what}: {e}"));
    let procs = processes().unwrap_or_else(|e| {
        gap("processes", e);
        vec![]
    });
    let mut calls = vec![];
    for path in transcripts(&home, now - time::DAY) {
        let session = path
            .file_stem()
            .map_or(String::new(), |s| s.to_string_lossy().into_owned());
        match tail(&path) {
            Ok(text) => calls.extend(read_calls(&session, &text, now)),
            Err(e) => gap(&path.display().to_string(), e.to_string()),
        }
    }
    let (items, orphans) = find(&procs, &calls);
    let peers = peers().unwrap_or_else(|e| {
        gap("pulse peers", e);
        vec![]
    });
    let ledger = dir.join("notified.json");
    let mut sent: BTreeMap<String, i64> = fs::read_to_string(&ledger)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or_default();
    let mut notified = vec![];
    if args.notify && cfg!(windows) {
        gap("notify", "on Windows it is later; report only".to_owned());
    } else if args.notify {
        let mut notify_gaps = vec![];
        notified = notify(&items, &peers, &mut sent, now, &mut notify_gaps, &mut send);
        notify_gaps.into_iter().for_each(|g| gap("notify", g));
        sent.retain(|_, at| now - *at < time::DAY);
        if let Err(e) = save(&ledger, &serde_json::to_string(&sent).unwrap_or_default()) {
            gap("notified.json", e);
        }
    }
    let title = |s: &str| {
        peers
            .iter()
            .find(|p| p.1 == s)
            .map_or(s.to_owned(), |p| format!("{s} ({})", p.2))
    };
    let blocked: Vec<String> = items
        .iter()
        .filter(|i| i.blocked)
        .map(|i| {
            format!(
                "{} {} for {}",
                title(i.session.as_deref().unwrap_or("?")),
                i.what,
                hm(i.age)
            )
        })
        .collect();
    let orphans: Vec<String> = orphans
        .iter()
        .map(|(cmd, n)| format!("{n} x {cmd}"))
        .collect();
    let mode = if args.notify { "notify" } else { "dry run" };
    let report = json!({"at": time::stamp(now), "mode": mode, "items": items, "blocked chats (needs Adrian)": blocked, "orphans": orphans, "notified": notified, "gaps": gaps});
    let log = fs::create_dir_all(&dir).and_then(|()| {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("log.jsonl"))
    });
    if let Err(e) = log.and_then(|mut f| writeln!(f, "{report}")) {
        eprintln!("sweep log: {e}");
    }
    Ok(if args.json {
        report
    } else {
        json!({"__raw": table(&report)})
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(ppid: u32, age: u64, cmd: &str) -> Proc {
        Proc {
            pid: 5,
            ppid,
            pgid: 5,
            age,
            cmd: cmd.to_owned(),
        }
    }

    fn shell(command: &str) -> String {
        format!(
            "/bin/zsh -c source /h/.claude/shell-snapshots/s.sh && eval '{command}' < /dev/null"
        )
    }

    #[test]
    fn ps_rows_parse_with_padding_and_day_etimes() {
        let rows = parse_ps("  PID PPID PGID ELAPSED COMMAND\n  12   1  12 1-02:03:04 /bin/x -a\n 7 6 7 05:09 y\nbad row\n");
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (rows[0].pid, rows[0].age, rows[0].cmd.as_str()),
            (12, 93_784, "/bin/x -a")
        );
        assert_eq!(rows[1].age, 309);
    }

    #[test]
    fn classify_applies_the_ages_exemptions_and_orphan_rule() {
        let sh = |age, cmd: &str| classify(&proc(4, age, &shell(cmd)), None);
        assert_eq!(sh(HOUR, "sleep 9"), None);
        assert_eq!(sh(3 * HOUR, "sleep 9"), Some(("shell", false)));
        assert_eq!(sh(3 * HOUR, "rightkit-gate check"), Some(("shell", true)));
        assert_eq!(sh(3 * HOUR, "timeout 9000 x"), Some(("shell", true)));
        assert_eq!(sh(7 * HOUR, "timeout 9000 x"), Some(("shell", false)));
        assert_eq!(
            sh(3 * HOUR, "gh run watch 1 --exit-status"),
            Some(("shell", true))
        );
        let parent = proc(1, 9, &shell("claude"));
        let chat = |cmd: &str, age| classify(&proc(4, age, cmd), Some(&parent)).map(|r| r.0);
        assert_eq!(chat("claude --model x", 2000), Some("chat"));
        assert_eq!(
            (
                chat("claude --model x", 600),
                chat("claude -p hi", 2000),
                chat("codex exec x", 2000)
            ),
            (None, None, None)
        );
        let tmp = "/Volumes/D/.rightkit-managed/tmp/x/run";
        assert_eq!(
            classify(&proc(1, 25 * HOUR, tmp), None),
            Some(("orphan", true))
        );
        assert_eq!(classify(&proc(1, 23 * HOUR, tmp), None), None);
        assert_eq!(classify(&proc(9, 25 * HOUR, tmp), None), None);
    }

    fn transcript() -> String {
        let use_ = |id: &str, cmd: &str, bg: bool| json!({"type":"assistant","timestamp":"2026-11-02T10:00:00.000Z","message":{"content":[{"type":"tool_use","id":id,"name":"Bash","input":{"command":cmd,"run_in_background":bg}}]}});
        let done = |id: &str| json!({"type":"user","timestamp":"2026-11-02T10:01:00Z","message":{"content":[{"type":"tool_result","tool_use_id":id}]}});
        let lines = [
            use_("a", "echo first done", false),
            done("a"),
            use_("b", "cargo build --release", true),
            done("b"),
            use_("c", "sleep 99999 && echo late", false),
        ];
        lines.map(|v| v.to_string()).join("\n")
    }

    #[test]
    fn a_shell_maps_to_its_one_session_by_command_and_age_and_a_foreground_call_blocks_it() {
        let now = time::parse("2026-11-02T12:00:00Z").unwrap();
        let mut calls = read_calls("one", &transcript(), now);
        let state: Vec<_> = calls
            .iter()
            .map(|c| (c.open, c.background, c.last))
            .collect();
        assert_eq!(
            state,
            [
                (false, false, false),
                (false, true, false),
                (true, false, true)
            ]
        );
        assert_eq!(calls[2].age, 2 * HOUR);
        let at = |age| Proc {
            pid: 5,
            ppid: 4,
            pgid: 5,
            age,
            cmd: shell("cargo build --release"),
        };
        let build = [at(2 * HOUR + 30)];
        let (items, _) = find(&build, &calls);
        assert_eq!(
            (items[0].session.as_deref(), items[0].blocked),
            (Some("one"), true),
            "session one is inside its foreground call c, so it is not messaged"
        );
        let (items, _) = find(&[at(3 * HOUR)], &calls);
        assert_eq!(
            items[0].session, None,
            "a call an hour older is not the owner"
        );
        let late = [Proc {
            pid: 5,
            ppid: 4,
            pgid: 5,
            age: 2 * HOUR,
            cmd: shell("sleep 99999 && echo late"),
        }];
        let (items, _) = find(&late, &calls);
        assert!(
            items[0].blocked && items.len() == 1,
            "the matched call is not listed twice"
        );
        calls.extend(read_calls("two", &transcript(), now));
        assert_eq!(
            find(&build, &calls).0[0].session,
            None,
            "two sessions match: no owner"
        );
    }

    #[test]
    fn notify_skips_blocked_exempt_unowned_and_recent_items() {
        let it = |key: &str, session: Option<&str>, blocked, report_only| Item {
            key: key.into(),
            what: "w".into(),
            age: 3 * HOUR,
            pid: Some(9),
            pgid: Some(9),
            session: session.map(Into::into),
            blocked,
            report_only,
        };
        let items = [
            it("a", Some("s1"), false, false),
            it("b", Some("s1"), true, false),
            it("c", Some("s1"), false, true),
            it("d", None, false, false),
            it("e", Some("gone"), false, false),
        ];
        let peers = [("claude".to_owned(), "s1".to_owned(), "n".to_owned())];
        let (mut sent, mut gaps, mut texts) = (BTreeMap::new(), vec![], vec![]);
        let mut send = |_: &Peer, t: &str| -> Result<(), String> {
            texts.push(t.to_owned());
            Ok(())
        };
        assert_eq!(
            notify(&items, &peers, &mut sent, 1000, &mut gaps, &mut send),
            ["s1/a"]
        );
        assert_eq!(gaps.len(), 1);
        assert!(notify(
            &items,
            &peers,
            &mut sent,
            1000 + RESEND - 1,
            &mut gaps,
            &mut send
        )
        .is_empty());
        assert_eq!(
            notify(
                &items,
                &peers,
                &mut sent,
                1000 + RESEND,
                &mut gaps,
                &mut send
            )
            .len(),
            1
        );
        assert!(
            texts[0].starts_with("Information from Legion's sweep, not Adrian's words.")
                && texts[0].contains("kill -- -9")
        );
    }
}
