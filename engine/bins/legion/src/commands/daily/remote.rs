//! Dell collection for `legion daily`, run from the Mac over `ssh win`. Strictly
//! read-only on the Dell: PowerShell lists files and reads two values, and `scp`
//! copies the files into `<out>/<date>/dell/` before anything parses them.
//! Nothing is written, moved or deleted on the Dell.
use super::proc;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

pub const SSH_ALIAS: &str = "win";
const RECEIPTS_DIR: &str = r"D:\.rightkit-managed\rightkit-build-control\receipts";
const EVENTS_FILE: &str = r"D:\.rightkit-managed\rightkit-build-control\logs\events.ndjson";
const COPY_BATCH: usize = 80;

/// One PowerShell line per file modified since the window start:
/// `tag|length|full path`. Transcripts, the evidence ledger and receipts.
const LIST_SCRIPT: &str = r#"$ErrorActionPreference='SilentlyContinue';
$s=[DateTimeOffset]::FromUnixTimeSeconds(@@EPOCH@@).UtcDateTime;
$h=$env:USERPROFILE;
function L($tag,$items){ $items | Where-Object { $_.LastWriteTimeUtc -ge $s } | ForEach-Object { $tag + '|' + $_.Length + '|' + $_.FullName } };
L 'claude' (Get-ChildItem -Path "$h\.claude\projects\*\*.jsonl" -File);
L 'profiles' (Get-ChildItem -Path "$h\ClaudeProfiles\*\.claude\projects\*\*.jsonl" -File);
L 'codex' (Get-ChildItem -Path "$h\.codex\sessions" -Recurse -Filter '*.jsonl' -File);
L 'evidence' (Get-ChildItem -Path "$h\.legion\evidence\*.jsonl" -File);
L 'receipts' (Get-ChildItem -LiteralPath '@@RECEIPTS@@' -Filter '*.json' -File)"#;

/// The broker events that mean admission was refused, paused or stalled.
const EVENTS_SCRIPT: &str = r#"Get-Content -LiteralPath '@@EVENTS@@' -Tail 20000 | Where-Object { $_ -match 'ADMISSION_(REJECTED|PAUSED|BLOCKED|REFUSED|TIMEOUT)|JOB_STALLED' }"#;

const FREE_SCRIPT: &str = "(Get-PSDrive -Name D).Free";

/// What the Dell pass produced. Everything lives under `root`.
#[derive(Debug, Default)]
pub struct Collected {
    pub root: PathBuf,
    pub receipts_dir: PathBuf,
    pub events_file: Option<PathBuf>,
    pub disk_free_bytes: Option<u64>,
    pub listed: usize,
    pub copied: usize,
    pub unchanged: usize,
    pub warnings: Vec<String>,
}

fn ssh_options() -> [&'static str; 8] {
    [
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=4",
    ]
}

fn ssh(script: &str) -> Result<proc::Ran, String> {
    let mut command = proc::command("ssh");
    command.args(ssh_options());
    command.arg(SSH_ALIAS);
    // One line: the remote shell gets a single PowerShell command string.
    command.arg(script.replace(['\r', '\n'], " "));
    proc::run(command)
}

/// One listed remote file.
#[derive(Debug, PartialEq, Eq)]
pub struct Listed {
    pub tag: String,
    pub length: u64,
    pub path: String,
}

pub fn parse_listing(output: &str) -> Vec<Listed> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.trim().splitn(3, '|');
            let tag = parts.next()?.trim();
            let length = parts.next()?.trim().parse::<u64>().ok()?;
            let path = parts.next()?.trim();
            let known = matches!(
                tag,
                "claude" | "profiles" | "codex" | "evidence" | "receipts"
            );
            if !known || path.is_empty() {
                return None;
            }
            Some(Listed {
                tag: tag.to_owned(),
                length,
                path: path.to_owned(),
            })
        })
        .collect()
}

fn sanitize(name: &str) -> String {
    name.chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn file_name(remote: &str) -> &str {
    remote.rsplit('\\').next().unwrap_or(remote)
}

/// Where a remote file lands locally. Transcripts keep their project folder
/// (`claude/<project>/<session>.jsonl`); the rest are flat per tag.
pub fn local_dir(root: &Path, listed: &Listed) -> PathBuf {
    match listed.tag.as_str() {
        "claude" | "profiles" => {
            let project = listed.path.rsplit('\\').nth(1).unwrap_or("project");
            root.join(&listed.tag).join(sanitize(project))
        }
        other => root.join(other),
    }
}

/// The `scp` source for a Windows path: `C:\a\b` becomes `win:C:/a/b`.
pub fn scp_source(remote: &str) -> String {
    format!("{SSH_ALIAS}:{}", remote.replace('\\', "/"))
}

fn copy_batch(dest: &Path, batch: &[&Listed]) -> Result<(), String> {
    let mut command = proc::command("scp");
    command.args(["-q", "-p"]);
    command.args(ssh_options());
    for listed in batch {
        command.arg(scp_source(&listed.path));
    }
    command.arg(dest);
    let ran = proc::run(command)?;
    if ran.ok {
        Ok(())
    } else {
        Err(proc::failure_text(&ran))
    }
}

/// List, copy and measure the Dell. `since` is the window start (epoch
/// seconds). Failures become warnings; the caller continues with the Mac.
pub fn collect(root: &Path, since: i64) -> Collected {
    let mut collected = Collected {
        root: root.to_path_buf(),
        receipts_dir: root.join("receipts"),
        ..Collected::default()
    };
    if let Err(error) = fs::create_dir_all(root) {
        collected
            .warnings
            .push(format!("dell: cannot create {}: {error}", root.display()));
        return collected;
    }

    let script = LIST_SCRIPT
        .replace("@@EPOCH@@", &since.to_string())
        .replace("@@RECEIPTS@@", RECEIPTS_DIR);
    let listing = match ssh(&script) {
        Ok(ran) if ran.ok => ran.stdout,
        Ok(ran) => {
            collected.warnings.push(format!(
                "dell: listing failed: {}",
                proc::failure_text(&ran)
            ));
            return collected;
        }
        Err(error) => {
            collected
                .warnings
                .push(format!("dell: ssh unavailable: {error}"));
            return collected;
        }
    };
    let files = parse_listing(&listing);
    collected.listed = files.len();

    let mut groups: BTreeMap<PathBuf, Vec<&Listed>> = BTreeMap::new();
    for listed in &files {
        let dir = local_dir(root, listed);
        let local = dir.join(sanitize(file_name(&listed.path)));
        let same = fs::metadata(&local).is_ok_and(|meta| meta.len() == listed.length);
        if same {
            collected.unchanged += 1;
            continue;
        }
        groups.entry(dir).or_default().push(listed);
    }
    for (dir, group) in &groups {
        if let Err(error) = fs::create_dir_all(dir) {
            collected
                .warnings
                .push(format!("dell: cannot create {}: {error}", dir.display()));
            continue;
        }
        for batch in group.chunks(COPY_BATCH) {
            match copy_batch(dir, batch) {
                Ok(()) => collected.copied += batch.len(),
                Err(error) => collected.warnings.push(format!(
                    "dell: copy of {} file(s) into {} failed: {error}",
                    batch.len(),
                    dir.display()
                )),
            }
        }
    }

    let events = EVENTS_SCRIPT.replace("@@EVENTS@@", EVENTS_FILE);
    match ssh(&events) {
        Ok(ran) if ran.ok => {
            let path = root.join("events-tail.ndjson");
            match fs::write(&path, ran.stdout.as_bytes()) {
                Ok(()) => collected.events_file = Some(path),
                Err(error) => collected
                    .warnings
                    .push(format!("dell: cannot save events: {error}")),
            }
        }
        Ok(ran) => collected.warnings.push(format!(
            "dell: events tail failed: {}",
            proc::failure_text(&ran)
        )),
        Err(error) => collected
            .warnings
            .push(format!("dell: events tail failed: {error}")),
    }

    match ssh(FREE_SCRIPT) {
        Ok(ran) if ran.ok => {
            collected.disk_free_bytes = ran.stdout.trim().parse::<u64>().ok();
            if collected.disk_free_bytes.is_none() {
                collected
                    .warnings
                    .push("dell: could not read free space on D:".to_owned());
            }
        }
        _ => collected
            .warnings
            .push("dell: could not read free space on D:".to_owned()),
    }
    collected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_listing_and_ignores_noise() {
        let output = "claude|1204|C:\\Users\\adrds\\.claude\\projects\\C--x\\abc.jsonl\r\n\
                      receipts|35609|D:\\.rightkit-managed\\rightkit-build-control\\receipts\\r1.json\n\
                      other|1|C:\\x\n\
                      claude|nope|C:\\bad\n\
                      \n\
                      codex|9|C:\\Users\\adrds\\.codex\\sessions\\2026\\11\\02\\rollout-1.jsonl\n";
        let listed = parse_listing(output);
        assert_eq!(listed.len(), 3);
        assert_eq!(listed[0].tag, "claude");
        assert_eq!(listed[0].length, 1204);
        assert_eq!(listed[1].tag, "receipts");
        assert_eq!(listed[2].tag, "codex");
    }

    #[test]
    fn maps_remote_paths_to_local_dirs_and_scp_sources() {
        let root = Path::new("/scratch/dell");
        let claude = Listed {
            tag: "claude".to_owned(),
            length: 1,
            path: r"C:\Users\adrds\.claude\projects\C--Volumes-D\abc.jsonl".to_owned(),
        };
        assert_eq!(
            local_dir(root, &claude),
            root.join("claude").join("C--Volumes-D")
        );
        let receipt = Listed {
            tag: "receipts".to_owned(),
            length: 1,
            path: r"D:\.rightkit-managed\rightkit-build-control\receipts\r.json".to_owned(),
        };
        assert_eq!(local_dir(root, &receipt), root.join("receipts"));
        assert_eq!(
            scp_source(r"C:\Users\adrds\.claude\projects\p\a.jsonl"),
            "win:C:/Users/adrds/.claude/projects/p/a.jsonl"
        );
        assert_eq!(file_name(&claude.path), "abc.jsonl");
        assert_eq!(sanitize("a b/c"), "a_b_c");
    }
}
