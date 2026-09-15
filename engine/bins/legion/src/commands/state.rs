use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SNAPSHOT_SCHEMA: &str = "legion-state-snapshot.v1";

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let (sub, rest) = argv
        .split_first()
        .map_or((None, &[][..]), |(s, r)| (Some(s.as_str()), r));
    match sub {
        Some("snapshot") => snapshot(rest),
        Some("verify") => verify(rest),
        Some(other) => Err(CommandError::usage(format!(
            "state requires a subcommand: snapshot|verify (got {other})"
        ))),
        None => Err(CommandError::usage(
            "state requires a subcommand: snapshot|verify (got <none>)",
        )),
    }
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Match node:path.resolve while still allowing an absent surface.
fn resolve_path(cwd: &Path, value: &str) -> PathBuf {
    let input = Path::new(value);
    let joined = if input.is_absolute() {
        input.to_path_buf()
    } else {
        cwd.join(input)
    };
    let mut output = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::Prefix(prefix) => output.push(prefix.as_os_str()),
            Component::RootDir => output.push(Path::new(std::path::MAIN_SEPARATOR_STR)),
            Component::CurDir => {}
            Component::ParentDir => {
                let _ = output.pop();
            }
            Component::Normal(part) => output.push(part),
        }
    }
    output
}

fn collect(root: &Path) -> Map<String, Value> {
    let mut entries = Map::new();
    let Ok(metadata) = std::fs::metadata(root) else {
        return entries;
    };
    if metadata.is_file() {
        if let Ok(bytes) = std::fs::read(root) {
            entries.insert(
                ".".into(),
                json!({"sha256":sha256(&bytes),"size":metadata.len()}),
            );
        }
        return entries;
    }
    if metadata.is_dir() {
        collect_dir(root, Path::new(""), &mut entries);
    }
    entries
}

fn collect_dir(root: &Path, prefix: &Path, entries: &mut Map<String, Value>) {
    let Ok(children) = std::fs::read_dir(root.join(prefix)) else {
        return;
    };
    for child in children.flatten() {
        let name = child.file_name();
        let relative = prefix.join(&name);
        let full = root.join(&relative);
        // Node's stat follows links; state records observable files.
        let Ok(metadata) = std::fs::metadata(&full) else {
            continue;
        };
        if metadata.is_dir() {
            collect_dir(root, &relative, entries);
        } else if metadata.is_file() {
            if let Ok(bytes) = std::fs::read(&full) {
                entries.insert(
                    relative.to_string_lossy().replace('\\', "/"),
                    json!({"sha256":sha256(&bytes),"size":metadata.len()}),
                );
            }
        }
    }
}

fn iso_now() -> String {
    if let Ok(value) = std::env::var("LEGION_PARITY_NOW") {
        if !value.is_empty() {
            return value;
        }
    }
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2).div_euclid(153);
    let d = doy - (153 * mp + 2).div_euclid(5) + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    let year = y + if m <= 2 { 1 } else { 0 };
    let hour = day_seconds / 3_600;
    let minute = day_seconds % 3_600 / 60;
    let second = day_seconds % 60;
    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}.000Z")
}

fn snapshot(args: &[String]) -> CommandResult {
    let cwd = std::env::current_dir().map_err(super::io_error)?;
    let mut paths = Vec::new();
    let mut out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            value if value.starts_with("--path=") => {
                paths.push(value["--path=".len()..].to_owned());
            }
            value if value.starts_with("--out=") => {
                out = Some(value["--out=".len()..].to_owned());
            }
            "--path" => {
                i += 1;
                let Some(path) = args.get(i) else {
                    return Err(CommandError::usage("state snapshot requires --path <file-or-dir> (repeatable) and --out <snapshot.json>"));
                };
                if path.starts_with('-') && path != "-" {
                    return Err(CommandError::usage("state snapshot requires a value after --path; use --path=<value> for a value beginning with '-'"));
                }
                paths.push(path.clone());
            }
            "--out" => {
                i += 1;
                let Some(path) = args.get(i) else {
                    return Err(CommandError::usage("state snapshot requires --path <file-or-dir> (repeatable) and --out <snapshot.json>"));
                };
                if path.starts_with('-') && path != "-" {
                    return Err(CommandError::usage("state snapshot requires a value after --out; use --out=<value> for a value beginning with '-'"));
                }
                out = Some(path.clone());
            }
            other => return Err(CommandError::usage(format!("unknown option: {other}"))),
        }
        i += 1;
    }
    let Some(out) = out.filter(|value| !value.is_empty()) else {
        return Err(CommandError::usage(
            "state snapshot requires --path <file-or-dir> (repeatable) and --out <snapshot.json>",
        ));
    };
    if paths.is_empty() {
        return Err(CommandError::usage(
            "state snapshot requires --path <file-or-dir> (repeatable) and --out <snapshot.json>",
        ));
    }
    let mut surfaces = Map::new();
    for path in &paths {
        let resolved = resolve_path(&cwd, path);
        let entries = collect(&resolved);
        let surface = std::env::var("LEGION_PARITY_ROOT")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| resolved.to_string_lossy().into_owned());
        surfaces.insert(surface, Value::Object(entries));
    }
    // Repeated/aliased --path arguments resolve to one observed surface in the
    // artifact. Count the final map, as Node does, not discarded duplicates.
    let files: usize = surfaces.values().filter_map(Value::as_object).map(Map::len).sum();
    let snapshot = json!({"schema":SNAPSHOT_SCHEMA,"takenAt":iso_now(),"surfaces":surfaces});
    let output = resolve_path(&cwd, &out);
    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).map_err(super::io_error)?;
    }
    std::fs::write(
        &output,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&snapshot).map_err(super::io_error)?
        ),
    )
    .map_err(super::io_error)?;
    let rendered = serde_json::to_string(&json!({"kind":"legion-state-snapshot","surfaces":paths.len(),"files":files,"out":output}))
        .map_err(super::io_error)?;
    Ok(json!({"__raw": format!("{rendered}\n")}))
}

fn verify(args: &[String]) -> CommandResult {
    let cwd = std::env::current_dir().map_err(super::io_error)?;
    let mut supplied = None;
    let mut i = 0;
    while i < args.len() {
        if let Some(value) = args[i].strip_prefix("--snapshot=") {
            supplied = Some(value);
        } else if args[i] == "--snapshot" {
            i += 1;
            supplied = args.get(i).map(String::as_str);
            if supplied.is_none() {
                return Err(CommandError::usage("state verify requires --snapshot <snapshot.json>"));
            }
        } else {
            return Err(CommandError::usage(format!("unknown option: {}", args[i])));
        }
        i += 1;
    }
    let supplied = supplied.filter(|value| !value.is_empty()).ok_or_else(|| {
        CommandError::usage("state verify requires --snapshot <snapshot.json>")
    })?;
    let snapshot_path = resolve_path(&cwd, supplied);
    let snapshot: Value =
        serde_json::from_slice(&std::fs::read(&snapshot_path).map_err(|error| {
            CommandError::usage(format!("state verify cannot read snapshot: {error}"))
        })?)
        .map_err(|error| {
            CommandError::usage(format!("state verify cannot read snapshot: {error}"))
        })?;
    if snapshot.get("schema").and_then(Value::as_str) != Some(SNAPSHOT_SCHEMA) {
        return Err(CommandError::usage(
            "snapshot schema must be legion-state-snapshot.v1",
        ));
    }
    let Some(surfaces) = snapshot.get("surfaces").and_then(Value::as_object) else {
        return Err(CommandError::usage(
            "snapshot surfaces must be a JSON object",
        ));
    };
    let mut deltas = Vec::new();
    for (surface, before) in surfaces {
        let Some(before) = before.as_object() else {
            return Err(CommandError::usage(
                "snapshot surface entries must be JSON objects",
            ));
        };
        let after = collect(Path::new(surface));
        for (relative, old) in before {
            match after.get(relative) {
                None => deltas.push(json!({"surface":surface,"path":relative,"change":"deleted"})),
                Some(new) if new.get("sha256") != old.get("sha256") => {
                    deltas.push(json!({"surface":surface,"path":relative,"change":"modified"}))
                }
                _ => {}
            }
        }
        for relative in after.keys() {
            if !before.contains_key(relative) {
                deltas.push(json!({"surface":surface,"path":relative,"change":"created"}));
            }
        }
    }
    if deltas.is_empty() {
        Ok(json!({"kind":"legion-state-verify","verdict":"clean","deltas":[]}))
    } else {
        eprintln!("STATE BOUNDARY BREACH: {} delta(s) under snapshotted production state", deltas.len());
        for delta in deltas.iter().take(20) {
            eprintln!("  {}: {} :: {}",
                delta["change"].as_str().unwrap_or_default(),
                delta["surface"].as_str().unwrap_or_default(),
                delta["path"].as_str().unwrap_or_default());
        }
        Ok(json!({"kind":"legion-state-verify","verdict":"breach","deltas":deltas}))
    }
}
