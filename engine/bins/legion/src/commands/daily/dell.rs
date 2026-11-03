//! The Dell, strictly read-only, from the Mac: `ssh win` lists the files modified in the window
//! and `scp -p` copies them into `<dir>/<tag>/`. Nothing is written, moved or deleted there.
use super::exec;
use std::{collections::BTreeMap, fs, path::Path, process::Command};

const HOST: &str = "win";
#[rustfmt::skip]
const OPTIONS: [&str; 8] = [
    "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15",
    "-o", "ServerAliveCountMax=4",
];

/// One `tag|length|full path` line per file modified since `@EPOCH@`.
const LIST: &str = r#"$ErrorActionPreference='SilentlyContinue'; $h=$env:USERPROFILE;
$s=[DateTimeOffset]::FromUnixTimeSeconds(@EPOCH@).UtcDateTime;
function L($tag,$items){ $items | Where-Object { $_.LastWriteTimeUtc -ge $s } |
  ForEach-Object { $tag+'|'+$_.Length+'|'+$_.FullName } };
L 'claude' (Get-ChildItem -Path "$h\.claude\projects\*\*.jsonl" -File);
L 'claude' (Get-ChildItem -Path "$h\ClaudeProfiles\*\.claude\projects\*\*.jsonl" -File);
L 'codex' (Get-ChildItem -Path "$h\.codex\sessions" -Recurse -Filter '*.jsonl' -File);
L 'receipts' (Get-ChildItem -Filter '*.json' -File
  -LiteralPath 'D:\.rightkit-managed\rightkit-build-control\receipts')"#;

#[derive(Default)]
pub struct Dell {
    pub files: usize,
    pub disk_free: Option<u64>,
    pub warnings: Vec<String>,
}

fn ssh(script: &str) -> Result<String, String> {
    // One line: the remote PowerShell gets a single command string.
    let script = script.replace(['\r', '\n'], " ");
    exec(Command::new("ssh").args(OPTIONS).arg(HOST).arg(script))
}

/// `(tag, length, path)` for each listed file with a known tag.
fn parse(listing: &str) -> Vec<(&str, u64, &str)> {
    let mut rows = Vec::new();
    for line in listing.lines() {
        let parts: Vec<&str> = line.trim().splitn(3, '|').collect();
        let &[tag, length, path] = parts.as_slice() else {
            continue;
        };
        if let (true, Ok(length)) = (
            ["claude", "codex", "receipts"].contains(&tag),
            length.trim().parse(),
        ) {
            rows.push((tag, length, path));
        }
    }
    rows
}

/// List, copy and measure the Dell into `dir`. A failure is a warning; the Mac carries on.
pub fn collect(dir: &Path, since: i64) -> Dell {
    let script = LIST.replace("@EPOCH@", &(since - 300).to_string());
    let listing = match ssh(&script) {
        Ok(text) => text,
        Err(e) => {
            return Dell {
                warnings: vec![format!("dell: listing failed: {e}")],
                ..Dell::default()
            }
        }
    };
    let rows = parse(&listing);
    let mut wanted: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for &(tag, length, path) in &rows {
        let local = dir.join(tag).join(path.rsplit('\\').next().unwrap_or(path));
        if fs::metadata(local).map_or(true, |meta| meta.len() != length) {
            wanted.entry(tag).or_default().push(path);
        }
    }
    let mut warnings = Vec::new();
    for (tag, paths) in wanted {
        let dest = dir.join(tag);
        if let Err(e) = fs::create_dir_all(&dest) {
            warnings.push(format!("dell: cannot create {}: {e}", dest.display()));
            continue;
        }
        let mut scp = Command::new("scp");
        scp.args(["-q", "-p"]).args(OPTIONS);
        for path in paths {
            scp.arg(format!("{HOST}:{}", path.replace('\\', "/")));
        }
        if let Err(e) = exec(scp.arg(&dest)) {
            warnings.push(format!("dell: copying {tag} failed: {e}"));
        }
    }
    let free = ssh("(Get-PSDrive -Name D).Free").ok();
    Dell {
        files: rows.len(),
        disk_free: free.and_then(|text| text.trim().parse().ok()),
        warnings,
    }
}
