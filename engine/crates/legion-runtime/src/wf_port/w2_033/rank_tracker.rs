//! Rust port of `skills/seo/scripts/rank_tracker.py` (packet `r42` closes the
//! filesystem/CLI gap this module used to defer).
//!
//! `rank_tracker.py` is a provider-neutral longitudinal rank observation store: it reads
//! JSON/CSV observation rows, normalizes them, writes dated snapshot files under
//! `.legion/seo/rank-tracking/`, and diffs the two most recent snapshots. The pure
//! `normalize()` row-shaping logic and `compare()` diff logic are ported verbatim below;
//! [`read_input`], [`ingest`], [`snapshots`], [`state_dir`], and [`run`] now port the
//! filesystem IO, CSV/JSON parsing, and `argparse` CLI (`ingest`/`compare` subcommands)
//! around them, closing the `main()` gap.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use serde_json::{Map, Value};

/// Defaults applied when a row omits a field, mirroring the Python `defaults` dict built
/// from `--market/--language/--device/--provider/--collected-at`.
#[derive(Debug, Clone, Default)]
pub struct NormalizeDefaults {
    pub market: Option<String>,
    pub language: Option<String>,
    pub device: Option<String>,
    pub provider: Option<String>,
    pub collected_at: Option<String>,
}

/// The normalized shape written into a snapshot, matching the Python `normalize()` output
/// dict field-for-field.
#[derive(Debug, Clone, PartialEq, Serialize, serde::Deserialize)]
pub struct NormalizedObservation {
    pub keyword: String,
    pub market: String,
    pub language: String,
    pub device: String,
    pub intended_page: Option<String>,
    pub observed_url: Option<String>,
    pub organic_position: Option<f64>,
    pub serp_features: Vec<Value>,
    pub provider: String,
    pub collected_at: String,
}

fn str_field(row: &Value, key: &str) -> Option<String> {
    match row.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(v) if !v.is_null() => Some(v.to_string()),
        _ => None,
    }
}

fn trim_or_empty(v: Option<String>) -> String {
    v.map(|s| s.trim().to_string()).unwrap_or_default()
}

/// Error raised for a row missing both `keyword` and `query`, matching the Python
/// `ValueError('rank observation missing keyword/query')`.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("rank observation missing keyword/query")]
pub struct MissingKeywordError;

/// Port of `normalize(row, defaults)`.
pub fn normalize(
    row: &Value,
    defaults: &NormalizeDefaults,
    now: &str,
) -> Result<NormalizedObservation, MissingKeywordError> {
    let keyword = trim_or_empty(str_field(row, "keyword").or_else(|| str_field(row, "query")));
    if keyword.is_empty() {
        return Err(MissingKeywordError);
    }

    let position_raw = row.get("position");
    let organic_position = match position_raw {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(s)) => s.parse::<f64>().ok(),
        _ => None,
    };

    let serp_features = match row.get("serp_features") {
        Some(Value::Array(arr)) => arr.clone(),
        _ => Vec::new(),
    };

    Ok(NormalizedObservation {
        keyword,
        market: trim_or_empty(str_field(row, "market").or_else(|| defaults.market.clone())),
        language: trim_or_empty(str_field(row, "language").or_else(|| defaults.language.clone())),
        device: {
            let d = str_field(row, "device")
                .or_else(|| defaults.device.clone())
                .unwrap_or_else(|| "desktop".to_string());
            d.trim().to_string()
        },
        intended_page: str_field(row, "intended_page").or_else(|| str_field(row, "target_url")),
        observed_url: str_field(row, "observed_url")
            .or_else(|| str_field(row, "url"))
            .or_else(|| str_field(row, "page")),
        organic_position,
        serp_features,
        provider: str_field(row, "provider")
            .or_else(|| defaults.provider.clone())
            .unwrap_or_else(|| "unknown".to_string()),
        collected_at: str_field(row, "collected_at")
            .or_else(|| defaults.collected_at.clone())
            .unwrap_or_else(|| now.to_string()),
    })
}

fn round3(v: f64) -> f64 {
    (v * 1000.0).round() / 1000.0
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(untagged)]
pub enum RankChange {
    New {
        #[serde(rename = "type")]
        change_type: &'static str,
        current: NormalizedObservation,
    },
    Tracked {
        keyword: String,
        market: String,
        language: String,
        device: String,
        previous_position: Option<f64>,
        current_position: Option<f64>,
        position_improvement: Option<f64>,
        previous_url: Option<String>,
        current_url: Option<String>,
        ownership_changed: bool,
        intended_page_mismatch: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CompareResult {
    pub status: &'static str,
    pub changes: Vec<RankChange>,
    pub ownership_changes: usize,
    pub intended_page_mismatches: usize,
}

/// Port of the diff loop inside `compare()` — given the previous and current snapshot's
/// already-parsed observation lists, produce the same change records. The "fewer than two
/// snapshots exist" `not_testable` branch is filesystem-driven (snapshot discovery) and is
/// the caller's responsibility.
pub fn compare(prev: &[NormalizedObservation], curr: &[NormalizedObservation]) -> CompareResult {
    use std::collections::HashMap;

    let key = |o: &NormalizedObservation| -> (String, String, String, String) {
        (
            o.keyword.clone(),
            o.market.clone(),
            o.language.clone(),
            o.device.clone(),
        )
    };

    let pmap: HashMap<_, _> = prev.iter().map(|o| (key(o), o)).collect();
    let mut changes = Vec::with_capacity(curr.len());
    let mut ownership_changes = 0usize;
    let mut intended_page_mismatches = 0usize;

    for cur in curr {
        match pmap.get(&key(cur)) {
            None => {
                changes.push(RankChange::New {
                    change_type: "new_keyword_observation",
                    current: cur.clone(),
                });
            }
            Some(old) => {
                let old_pos = old.organic_position;
                let new_pos = cur.organic_position;
                let delta = match (old_pos, new_pos) {
                    (Some(o), Some(n)) => Some(round3(o - n)),
                    _ => None,
                };
                let ownership_changed = matches!(
                    (&old.observed_url, &cur.observed_url),
                    (Some(o), Some(c)) if !o.is_empty() && !c.is_empty() && o != c
                );
                let intended_mismatch = matches!(
                    (&cur.intended_page, &cur.observed_url),
                    (Some(i), Some(o)) if !i.is_empty() && !o.is_empty() && i != o
                );
                if ownership_changed {
                    ownership_changes += 1;
                }
                if intended_mismatch {
                    intended_page_mismatches += 1;
                }
                changes.push(RankChange::Tracked {
                    keyword: cur.keyword.clone(),
                    market: cur.market.clone(),
                    language: cur.language.clone(),
                    device: cur.device.clone(),
                    previous_position: old_pos,
                    current_position: new_pos,
                    position_improvement: delta,
                    previous_url: old.observed_url.clone(),
                    current_url: cur.observed_url.clone(),
                    ownership_changed,
                    intended_page_mismatch: intended_mismatch,
                });
            }
        }
    }

    CompareResult {
        status: "ok",
        changes,
        ownership_changes,
        intended_page_mismatches,
    }
}

/// Port of `now()`: pure integer civil-from-days conversion, no external crate —
/// same technique as `legion_audit::wf_port::wf065::audit_store::utc_now_from_unix`.
pub fn now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    utc_now_from_unix(secs)
}

fn utc_now_from_unix(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

fn stamp_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // `datetime.strftime('%Y%m%dT%H%M%SZ')`: same civil conversion, compact form.
    let iso = utc_now_from_unix(secs);
    iso.replace(['-', ':'], "")
}

/// Port of `state_dir(root)`: `Path(root).resolve() / '.legion' / 'seo' / 'rank-tracking'`.
pub fn state_dir(root: &Path) -> PathBuf {
    let resolved = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    resolved.join(".legion").join("seo").join("rank-tracking")
}

/// Minimal RFC-4180 CSV parser (quoted fields, `""` escaping, CRLF/LF), sufficient for
/// `csv.DictReader`'s use here: first row is the header, every other row becomes a
/// `{header: value}` object, matching Python's `dict(zip(header, row))` semantics
/// (a `csv.DictReader` row shorter than the header leaves the rest `None`/missing).
fn parse_csv(text: &str) -> Vec<Value> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut field = String::new();
    let mut row: Vec<String> = Vec::new();
    let mut in_quotes = false;
    let mut chars = text.chars().peekable();
    // Strip a UTF-8 BOM, matching Python's `encoding='utf-8-sig'`.
    if text.starts_with('\u{feff}') {
        chars.next();
    }
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => {
                    row.push(std::mem::take(&mut field));
                }
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        chars.next();
                    }
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                _ => field.push(c),
            }
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    // Drop a single trailing fully-empty row (final newline).
    if rows.last().map(|r| r.len() == 1 && r[0].is_empty()).unwrap_or(false) {
        rows.pop();
    }

    if rows.is_empty() {
        return Vec::new();
    }
    let header = rows.remove(0);
    rows.into_iter()
        .map(|r| {
            let mut obj = Map::new();
            for (i, key) in header.iter().enumerate() {
                let v = r.get(i).cloned().unwrap_or_default();
                obj.insert(key.clone(), Value::String(v));
            }
            Value::Object(obj)
        })
        .collect()
}

/// Port of `read_input(path)`: `.csv` via `csv.DictReader`, else JSON accepting a bare
/// list, `{"rows": [...]}`, or `{"observations": [...]}`.
pub fn read_input(path: &Path) -> Result<Vec<Value>, String> {
    let is_csv = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("csv"))
        .unwrap_or(false);
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    if is_csv {
        return Ok(parse_csv(&text));
    }
    let payload: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    match payload {
        Value::Array(rows) => Ok(rows),
        Value::Object(ref obj) => {
            if let Some(Value::Array(rows)) = obj.get("rows") {
                return Ok(rows.clone());
            }
            if let Some(Value::Array(rows)) = obj.get("observations") {
                return Ok(rows.clone());
            }
            Err("expected list or object with rows[]/observations[]".to_string())
        }
        _ => Err("expected list or object with rows[]/observations[]".to_string()),
    }
}

/// Port of `snapshots(root)`: sorted `*.json` files under `state_dir(root)`.
pub fn snapshots(root: &Path) -> Vec<PathBuf> {
    let dir = state_dir(root);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut paths: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
}

/// Port of `ingest(root, observations, defaults)`: normalizes every row, writes the
/// dated snapshot file, and returns its path.
pub fn ingest(
    root: &Path,
    observations: &[Value],
    defaults: &NormalizeDefaults,
    snapshot_stamp: Option<&str>,
) -> Result<PathBuf, String> {
    let out_dir = state_dir(root);
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;
    let ts = now();
    let normalized: Result<Vec<NormalizedObservation>, MissingKeywordError> = observations
        .iter()
        .map(|row| normalize(row, defaults, &ts))
        .collect();
    let normalized = normalized.map_err(|e| e.to_string())?;
    let stamp = snapshot_stamp
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(stamp_now);
    let path = out_dir.join(format!("{stamp}.json"));
    let body = serde_json::json!({ "created_at": ts, "observations": normalized });
    let text = serde_json::to_string_pretty(&body).map_err(|e| e.to_string())? + "\n";
    let mut f = std::fs::File::create(&path).map_err(|e| e.to_string())?;
    f.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(path)
}

fn load_observations(path: &Path) -> Result<Vec<NormalizedObservation>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let value: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let obs = value.get("observations").cloned().unwrap_or(Value::Array(vec![]));
    serde_json::from_value(obs).map_err(|e| e.to_string())
}

/// Port of `compare(root)`'s filesystem-driven wrapper around the pure [`compare`]
/// diff, including the `not_testable` ("fewer than two snapshots") branch.
pub fn compare_root(root: &Path) -> Result<Value, String> {
    let snaps = snapshots(root);
    if snaps.len() < 2 {
        return Ok(serde_json::json!({
            "status": "not_testable",
            "reason": "at least two rank snapshots are required",
            "snapshots": snaps.len(),
        }));
    }
    let prev = load_observations(&snaps[snaps.len() - 2])?;
    let curr = load_observations(&snaps[snaps.len() - 1])?;
    let result = compare(&prev, &curr);
    let mut value = serde_json::to_value(&result).map_err(|e| e.to_string())?;
    if let Value::Object(ref mut obj) = value {
        obj.insert(
            "previous_snapshot".to_string(),
            Value::String(snaps[snaps.len() - 2].file_name().unwrap().to_string_lossy().into_owned()),
        );
        obj.insert(
            "current_snapshot".to_string(),
            Value::String(snaps[snaps.len() - 1].file_name().unwrap().to_string_lossy().into_owned()),
        );
    }
    Ok(value)
}

/// CLI options for [`run`], mirroring `rank_tracker.py`'s `argparse` surface.
pub enum Command {
    Ingest {
        input: PathBuf,
        market: String,
        language: String,
        device: String,
        provider: String,
        snapshot: Option<String>,
    },
    Compare,
}

/// Port of `main()`: dispatches `ingest`/`compare` against `root`, printing the same
/// pretty-JSON result and returning the same exit code (`0` for `ok`/`not_testable`,
/// `1` otherwise).
pub fn run(root: &Path, command: Command) -> (i32, String) {
    let out = match command {
        Command::Ingest {
            input,
            market,
            language,
            device,
            provider,
            snapshot,
        } => {
            let rows = match read_input(&input) {
                Ok(r) => r,
                Err(e) => return (1, format!("Error: {e}\n")),
            };
            let defaults = NormalizeDefaults {
                market: Some(market),
                language: Some(language),
                device: Some(device),
                provider: Some(provider),
                collected_at: None,
            };
            match ingest(root, &rows, &defaults, snapshot.as_deref()) {
                Ok(path) => serde_json::json!({"status": "ok", "path": path.to_string_lossy()}),
                Err(e) => return (1, format!("Error: {e}\n")),
            }
        }
        Command::Compare => match compare_root(root) {
            Ok(v) => v,
            Err(e) => return (1, format!("Error: {e}\n")),
        },
    };
    let status_ok = matches!(out.get("status").and_then(|s| s.as_str()), Some("ok") | Some("not_testable"));
    let text = serde_json::to_string_pretty(&out).unwrap_or_default();
    (if status_ok { 0 } else { 1 }, text)
}

/// Port of `main()`'s `argparse` surface: `--root` global flag, then `ingest <input>
/// --market M --language L [--device D] --provider P [--snapshot S]` or `compare`.
/// Prints the same pretty-JSON `run()` produces and returns the same exit code; a
/// missing/invalid argument prints `Error: <message>` to match the module's own
/// `Error: {e}` convention (argparse's own usage errors are not reproduced verbatim,
/// since this CLI has no interactive terminal to print them to).
pub fn run_argv(args: &[String]) -> i32 {
    let mut root = PathBuf::from(".");
    let mut idx = 0;
    while idx < args.len() {
        if args[idx] == "--root" {
            match args.get(idx + 1) {
                Some(v) => {
                    root = PathBuf::from(v);
                    idx += 2;
                }
                None => {
                    eprintln!("Error: --root requires a value");
                    return 1;
                }
            }
        } else {
            break;
        }
    }
    let Some(sub) = args.get(idx) else {
        eprintln!("Error: a command is required (ingest|compare)");
        return 1;
    };
    idx += 1;
    let command = match sub.as_str() {
        "compare" => Command::Compare,
        "ingest" => {
            let mut input: Option<PathBuf> = None;
            let mut market: Option<String> = None;
            let mut language: Option<String> = None;
            let mut device = "desktop".to_string();
            let mut provider: Option<String> = None;
            let mut snapshot: Option<String> = None;
            while idx < args.len() {
                let a = args[idx].as_str();
                macro_rules! next_val {
                    () => {{
                        idx += 1;
                        match args.get(idx) {
                            Some(v) => v.clone(),
                            None => {
                                eprintln!("Error: {a} requires a value");
                                return 1;
                            }
                        }
                    }};
                }
                match a {
                    "--market" => market = Some(next_val!()),
                    "--language" => language = Some(next_val!()),
                    "--device" => device = next_val!(),
                    "--provider" => provider = Some(next_val!()),
                    "--snapshot" => snapshot = Some(next_val!()),
                    other if !other.starts_with("--") => input = Some(PathBuf::from(other)),
                    other => {
                        eprintln!("Error: unrecognized argument: {other}");
                        return 1;
                    }
                }
                idx += 1;
            }
            let (Some(input), Some(market), Some(language), Some(provider)) =
                (input, market, language, provider)
            else {
                eprintln!("Error: ingest requires input, --market, --language, --provider");
                return 1;
            };
            Command::Ingest {
                input,
                market,
                language,
                device,
                provider,
                snapshot,
            }
        }
        other => {
            eprintln!("Error: unknown command: {other}");
            return 1;
        }
    };
    let (code, text) = run(&root, command);
    println!("{text}");
    code
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn normalize_requires_keyword_or_query() {
        let err = normalize(&json!({}), &NormalizeDefaults::default(), "now").unwrap_err();
        assert_eq!(err, MissingKeywordError);
    }

    #[test]
    fn normalize_applies_defaults_and_trims() {
        let row = json!({"query": "  buy widgets  ", "position": "4.5"});
        let defaults = NormalizeDefaults {
            market: Some("US".into()),
            language: Some("en".into()),
            device: None,
            provider: Some("acme".into()),
            collected_at: Some("2026-01-01T00:00:00Z".into()),
        };
        let out = normalize(&row, &defaults, "unused").unwrap();
        assert_eq!(out.keyword, "buy widgets");
        assert_eq!(out.market, "US");
        assert_eq!(out.device, "desktop");
        assert_eq!(out.organic_position, Some(4.5));
        assert_eq!(out.provider, "acme");
        assert_eq!(out.collected_at, "2026-01-01T00:00:00Z");
    }

    #[test]
    fn compare_flags_new_ownership_and_mismatch() {
        let defaults = NormalizeDefaults::default();
        let prev = vec![normalize(
            &json!({"keyword": "k1", "market": "US", "language": "en", "device": "desktop",
                     "organic_position": 5, "position": 5, "observed_url": "https://a.example/x"}),
            &defaults,
            "t",
        )
        .unwrap()];
        let curr = vec![
            normalize(
                &json!({"keyword": "k1", "market": "US", "language": "en", "device": "desktop",
                         "position": 3, "observed_url": "https://a.example/y",
                         "intended_page": "https://a.example/x"}),
                &defaults,
                "t",
            )
            .unwrap(),
            normalize(&json!({"keyword": "k2", "position": 10}), &defaults, "t").unwrap(),
        ];
        let result = compare(&prev, &curr);
        assert_eq!(result.status, "ok");
        assert_eq!(result.ownership_changes, 1);
        assert_eq!(result.intended_page_mismatches, 1);
        assert_eq!(result.changes.len(), 2);
        match &result.changes[0] {
            RankChange::Tracked {
                position_improvement,
                ownership_changed,
                intended_page_mismatch,
                ..
            } => {
                assert_eq!(*position_improvement, Some(2.0));
                assert!(*ownership_changed);
                assert!(*intended_page_mismatch);
            }
            other => panic!("expected Tracked, got {other:?}"),
        }
        match &result.changes[1] {
            RankChange::New { change_type, .. } => assert_eq!(*change_type, "new_keyword_observation"),
            other => panic!("expected New, got {other:?}"),
        }
    }

    static TEST_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    fn temp_root() -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("r42-rank-tracker-{}-{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parse_csv_handles_quotes_and_header() {
        let rows = parse_csv("keyword,position\n\"buy, widgets\",4\nk2,\"5\"\n");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["keyword"], "buy, widgets");
        assert_eq!(rows[1]["position"], "5");
    }

    #[test]
    fn ingest_then_compare_round_trip() {
        let root = temp_root();
        let defaults = NormalizeDefaults {
            market: Some("US".into()),
            language: Some("en".into()),
            device: Some("desktop".into()),
            provider: Some("acme".into()),
            collected_at: None,
        };
        let rows1 = vec![json!({"keyword": "k1", "position": 5, "observed_url": "https://a.example/x"})];
        let p1 = ingest(&root, &rows1, &defaults, Some("snap1")).unwrap();
        assert!(p1.ends_with("snap1.json"));

        let rows2 = vec![json!({"keyword": "k1", "position": 3, "observed_url": "https://a.example/y"})];
        ingest(&root, &rows2, &defaults, Some("snap2")).unwrap();

        let cmp = compare_root(&root).unwrap();
        assert_eq!(cmp["status"], "ok");
        assert_eq!(cmp["ownership_changes"], 1);
    }

    #[test]
    fn compare_root_not_testable_with_fewer_than_two_snapshots() {
        let root = temp_root();
        let out = compare_root(&root).unwrap();
        assert_eq!(out["status"], "not_testable");
    }

    #[test]
    fn run_argv_ingest_then_compare() {
        let root = temp_root();
        let root_str = root.to_string_lossy().to_string();
        let input1 = root.join("in1.json");
        std::fs::write(&input1, r#"[{"keyword":"k1","position":5,"observed_url":"https://a.example/x"}]"#).unwrap();
        let code = run_argv(&[
            "--root".into(), root_str.clone(), "ingest".into(), input1.to_string_lossy().into_owned(),
            "--market".into(), "US".into(), "--language".into(), "en".into(),
            "--provider".into(), "acme".into(), "--snapshot".into(), "snap1".into(),
        ]);
        assert_eq!(code, 0);

        let input2 = root.join("in2.json");
        std::fs::write(&input2, r#"[{"keyword":"k1","position":3,"observed_url":"https://a.example/y"}]"#).unwrap();
        let code = run_argv(&[
            "--root".into(), root_str.clone(), "ingest".into(), input2.to_string_lossy().into_owned(),
            "--market".into(), "US".into(), "--language".into(), "en".into(),
            "--provider".into(), "acme".into(), "--snapshot".into(), "snap2".into(),
        ]);
        assert_eq!(code, 0);

        let code = run_argv(&["--root".into(), root_str, "compare".into()]);
        assert_eq!(code, 0);
    }

    #[test]
    fn run_argv_missing_command_errors() {
        assert_eq!(run_argv(&[]), 1);
    }

    #[test]
    fn read_input_rejects_bad_shape() {
        let root = temp_root();
        let path = root.join("bad.json");
        std::fs::write(&path, "{\"nope\": true}").unwrap();
        assert!(read_input(&path).is_err());
    }
}
