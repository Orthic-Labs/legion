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

/// Files observed under one surface, plus every entry that could not be read.
/// An unreadable entry is recorded, never silently absent from the snapshot.
#[derive(Default)]
struct Observed {
    entries: Map<String, Value>,
    /// `{"path": <relative>, "reason": <error>}` per entry that could not be observed.
    unreadable: Vec<Value>,
}

/// A relative path as recorded in a snapshot; the surface root is ".".
fn display_rel(path: &Path) -> String {
    if path.as_os_str().is_empty() {
        ".".to_owned()
    } else {
        path.to_string_lossy().replace('\\', "/")
    }
}

fn unreadable_entry(path: &Path, reason: impl std::fmt::Display) -> Value {
    json!({"path": display_rel(path), "reason": reason.to_string()})
}

/// The relative paths named by a list of unreadable entries.
fn entry_paths(entries: &[Value]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|entry| entry["path"].as_str().map(str::to_owned))
        .collect()
}

fn collect(root: &Path) -> Observed {
    let mut observed = Observed::default();
    let metadata = match std::fs::metadata(root) {
        Ok(metadata) => metadata,
        // An absent surface is observed as empty; any other failure is not.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return observed,
        Err(error) => {
            observed
                .unreadable
                .push(unreadable_entry(Path::new(""), error));
            return observed;
        }
    };
    if metadata.is_file() {
        match std::fs::read(root) {
            Ok(bytes) => {
                observed.entries.insert(
                    ".".into(),
                    json!({"sha256":sha256(&bytes),"size":metadata.len()}),
                );
            }
            Err(error) => observed
                .unreadable
                .push(unreadable_entry(Path::new(""), error)),
        }
    } else if metadata.is_dir() {
        collect_dir(root, Path::new(""), &mut observed);
    }
    observed
}

fn collect_dir(root: &Path, prefix: &Path, observed: &mut Observed) {
    let children = match std::fs::read_dir(root.join(prefix)) {
        Ok(children) => children,
        Err(error) => {
            observed.unreadable.push(unreadable_entry(prefix, error));
            return;
        }
    };
    for child in children {
        let child = match child {
            Ok(child) => child,
            Err(error) => {
                observed.unreadable.push(unreadable_entry(prefix, error));
                continue;
            }
        };
        let name = child.file_name();
        let relative = prefix.join(&name);
        let full = root.join(&relative);
        // Node's stat follows links; state records observable files.
        let metadata = match std::fs::metadata(&full) {
            Ok(metadata) => metadata,
            Err(error) => {
                observed.unreadable.push(unreadable_entry(&relative, error));
                continue;
            }
        };
        if metadata.is_dir() {
            collect_dir(root, &relative, observed);
        } else if metadata.is_file() {
            match std::fs::read(&full) {
                Ok(bytes) => {
                    observed.entries.insert(
                        display_rel(&relative),
                        json!({"sha256":sha256(&bytes),"size":metadata.len()}),
                    );
                }
                Err(error) => observed.unreadable.push(unreadable_entry(&relative, error)),
            }
        }
    }
}

/// The base that relative surface keys are taken against, when parity mode is on.
fn parity_root(cwd: &Path) -> Option<PathBuf> {
    std::env::var("LEGION_PARITY_ROOT")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| resolve_path(cwd, &value))
}

/// The key a surface is recorded under. Distinct surfaces get distinct keys.
/// With LEGION_PARITY_ROOT set, a surface under that root is keyed by its path
/// relative to it, so snapshots stay portable across checkouts; any other
/// surface keeps its resolved path.
fn surface_key(cwd: &Path, resolved: &Path) -> String {
    if let Some(parity) = parity_root(cwd) {
        if let Ok(relative) = resolved.strip_prefix(&parity) {
            return display_rel(relative);
        }
    }
    resolved.to_string_lossy().into_owned()
}

/// The filesystem path a recorded surface key refers to at verify time.
fn surface_path(cwd: &Path, key: &str) -> PathBuf {
    match parity_root(cwd) {
        Some(parity) if !Path::new(key).is_absolute() => resolve_path(&parity, key),
        _ => PathBuf::from(key),
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
    let mut unreadable = Vec::new();
    for path in &paths {
        let resolved = resolve_path(&cwd, path);
        let key = surface_key(&cwd, &resolved);
        let observed = collect(&resolved);
        for mut entry in observed.unreadable {
            entry["surface"] = json!(&key);
            unreadable.push(entry);
        }
        surfaces.insert(key, Value::Object(observed.entries));
    }
    // Repeated/aliased --path arguments resolve to one observed surface in the
    // artifact. Count the final map, as Node does, not discarded duplicates.
    let files: usize = surfaces
        .values()
        .filter_map(Value::as_object)
        .map(Map::len)
        .sum();
    let unreadable_count = unreadable.len();
    let snapshot = json!({"schema":SNAPSHOT_SCHEMA,"takenAt":iso_now(),"surfaces":surfaces,"unreadable":unreadable});
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
    // Unreadable entries are listed here and make verify unproven; the snapshot
    // itself only records what it could observe.
    let rendered = serde_json::to_string(&json!({
        "kind":"legion-state-snapshot",
        "surfaces":paths.len(),
        "files":files,
        "unreadable":unreadable_count,
        "out":output
    }))
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
                return Err(CommandError::usage(
                    "state verify requires --snapshot <snapshot.json>",
                ));
            }
        } else {
            return Err(CommandError::usage(format!("unknown option: {}", args[i])));
        }
        i += 1;
    }
    let supplied = supplied
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CommandError::usage("state verify requires --snapshot <snapshot.json>"))?;
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
    // A snapshot that records no files inspected nothing, so an absence of
    // deltas is not evidence of a clean boundary.
    let snapshotted: usize = surfaces
        .values()
        .filter_map(Value::as_object)
        .map(Map::len)
        .sum();
    // Entries that were unreadable when the snapshot was taken, or are unreadable
    // now, are unknown: they are neither deleted nor created, and they keep the
    // verdict from being clean.
    let mut unknown: Vec<Value> = snapshot
        .get("unreadable")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut deltas = Vec::new();
    for (surface, before) in surfaces {
        let Some(before) = before.as_object() else {
            return Err(CommandError::usage(
                "snapshot surface entries must be JSON objects",
            ));
        };
        let observed = collect(&surface_path(&cwd, surface));
        let unobservable = entry_paths(&observed.unreadable);
        let recorded = entry_paths(
            &unknown
                .iter()
                .filter(|entry| entry["surface"].as_str() == Some(surface.as_str()))
                .cloned()
                .collect::<Vec<_>>(),
        );
        let after = observed.entries;
        for (relative, old) in before {
            match after.get(relative) {
                None if unobservable.contains(relative) => {}
                None => deltas.push(json!({"surface":surface,"path":relative,"change":"deleted"})),
                Some(new) if new.get("sha256") != old.get("sha256") => {
                    deltas.push(json!({"surface":surface,"path":relative,"change":"modified"}))
                }
                _ => {}
            }
        }
        for relative in after.keys() {
            if !before.contains_key(relative) && !recorded.contains(relative) {
                deltas.push(json!({"surface":surface,"path":relative,"change":"created"}));
            }
        }
        for mut entry in observed.unreadable {
            entry["surface"] = json!(surface);
            unknown.push(entry);
        }
    }
    if deltas.is_empty() && unknown.is_empty() && snapshotted == 0 {
        return Ok(json!({
            "kind":"legion-state-verify",
            "verdict":"unproven",
            "complete":false,
            "deltas":[],
            "gaps":["snapshot records no files; nothing was verified"]
        }));
    }
    if deltas.is_empty() && unknown.is_empty() {
        return Ok(json!({"kind":"legion-state-verify","verdict":"clean","deltas":[]}));
    }
    if deltas.is_empty() {
        let gaps = unknown
            .iter()
            .map(|entry| {
                format!(
                    "unreadable: {} :: {} ({})",
                    entry["surface"].as_str().unwrap_or_default(),
                    entry["path"].as_str().unwrap_or_default(),
                    entry["reason"].as_str().unwrap_or_default()
                )
            })
            .collect::<Vec<_>>();
        return Ok(json!({
            "kind":"legion-state-verify",
            "verdict":"unproven",
            "complete":false,
            "deltas":[],
            "unreadable":unknown,
            "gaps":gaps
        }));
    }
    eprintln!(
        "STATE BOUNDARY BREACH: {} delta(s) under snapshotted production state",
        deltas.len()
    );
    for delta in deltas.iter().take(20) {
        eprintln!(
            "  {}: {} :: {}",
            delta["change"].as_str().unwrap_or_default(),
            delta["surface"].as_str().unwrap_or_default(),
            delta["path"].as_str().unwrap_or_default()
        );
    }
    Ok(
        json!({"kind":"legion-state-verify","verdict":"breach","deltas":deltas,"unreadable":unknown}),
    )
}
