// Port of `scripts/native-cli/gate.mjs`. Shared machinery for the native CLI
// installed-parity and Rust-characterization gates: manifest/fixture
// hashing, source-tree identity, sandboxed bounded process execution,
// filesystem snapshotting, and parity-row evaluation.
//
// Pure/content-addressing helpers here are platform-neutral; the pieces that
// name the installer-owned Windows install root are behind `#[cfg(windows)]`
// (matching the Node script, which is meaningless off Windows: it names
// `%LOCALAPPDATA%\Orthic Labs\Legion\current\bin\legion.exe` and always
// operates against a Windows-built `legion.exe`).

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

const ALLOWED_NORMALIZATION_KEYS: [&str; 4] =
    ["lineEndings", "stackFrames", "trailingWhitespace", "timestamps"];
// `tempRoots` is also allowed by the Node script; kept separate below since
// it is checked by name, not iterated generically.
const ALLOWED_NORMALIZATION_KEY_TEMP_ROOTS: &str = "tempRoots";

pub fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(sha256(&bytes))
}

/// Recursively sort object keys (arrays keep order) — matches the Node
/// script's `canonical()`.
fn canonical(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonical(&map[key]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Compact JSON of the canonical (key-sorted) form — matches
/// `JSON.stringify(canonical(value))` (no whitespace).
pub fn canonical_json(value: &Value) -> String {
    serde_json::to_string(&canonical(value)).unwrap()
}

pub fn fixture_digest(fixture: &Value) -> String {
    sha256(canonical_json(fixture).as_bytes())
}

pub struct ManifestRow {
    pub fixture: Value,
    pub id: String,
    pub fixture_sha256: String,
}

pub struct Manifest {
    pub value: Value,
    #[allow(dead_code)]
    pub path: PathBuf,
    pub manifest_sha256: String,
    pub row_count: usize,
    pub row_ids: Vec<String>,
    pub rows: Vec<ManifestRow>,
}

pub fn load_manifest(manifest_path: &Path) -> Result<Manifest, String> {
    let bytes = fs::read(manifest_path).map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    let text = String::from_utf8_lossy(&bytes).to_string();
    let value: Value = serde_json::from_str(&text).map_err(|e| format!("manifest is invalid JSON: {e}"))?;
    let schema_ok = value.get("schemaVersion").and_then(Value::as_i64) == Some(1);
    let fixtures = value.get("fixtures").and_then(Value::as_array);
    if !schema_ok || fixtures.map(|f| f.is_empty()).unwrap_or(true) {
        return Err("manifest must be schemaVersion 1 with a non-empty fixtures array".to_string());
    }
    let fixtures = fixtures.unwrap();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut rows = Vec::with_capacity(fixtures.len());
    for (index, fixture) in fixtures.iter().enumerate() {
        let id = fixture
            .get("id")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| format!("manifest row {index} has no id"))?
            .to_string();
        if seen.contains(&id) {
            return Err(format!("manifest row id is duplicated: {id}"));
        }
        seen.insert(id.clone());
        let argv_ok = fixture
            .get("argv")
            .and_then(Value::as_array)
            .map(|a| a.iter().all(|v| v.is_string()))
            .unwrap_or(false);
        if !argv_ok {
            return Err(format!("manifest row {id} has invalid argv"));
        }
        let fixture_sha256 = fixture_digest(fixture);
        rows.push(ManifestRow { fixture: fixture.clone(), id, fixture_sha256 });
    }
    Ok(Manifest {
        value: value.clone(),
        path: manifest_path.to_path_buf(),
        manifest_sha256: sha256(&bytes),
        row_count: rows.len(),
        row_ids: rows.iter().map(|r| r.id.clone()).collect(),
        rows,
    })
}

fn git(root: &Path, args: &[&str]) -> String {
    Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

pub struct SourceIdentity {
    pub source_revision: String,
    pub source_tree_sha256: String,
}

pub fn source_identity(root: &Path) -> Result<SourceIdentity, String> {
    let source_revision = git(root, &["rev-parse", "HEAD"]).trim().to_lowercase();
    let revision_ok = source_revision.len() >= 40
        && source_revision.len() <= 64
        && source_revision.chars().all(|c| c.is_ascii_hexdigit());
    if !revision_ok {
        return Err(format!("cannot determine current source revision for {}", root.display()));
    }
    let listing = Command::new("git")
        .args(["ls-files", "-z", "--cached", "--others", "--exclude-standard"])
        .current_dir(root)
        .output()
        .map_err(|e| e.to_string())?;
    let mut paths: Vec<String> = listing
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).to_string())
        .collect();
    paths.sort();
    let mut hasher = Sha256::new();
    for path in &paths {
        let full = root.join(path);
        let meta = match fs::symlink_metadata(&full) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if !meta.is_file() || meta.file_type().is_symlink() {
            continue;
        }
        hasher.update(path.replace('\\', "/").as_bytes());
        hasher.update([0u8]);
        let bytes = fs::read(&full).map_err(|e| format!("{}: {e}", full.display()))?;
        hasher.update(&bytes);
        hasher.update([0u8]);
    }
    Ok(SourceIdentity {
        source_revision,
        source_tree_sha256: hex::encode(hasher.finalize()),
    })
}

#[cfg(windows)]
pub struct InstalledExecutable {
    #[allow(dead_code)]
    pub install_root: PathBuf,
    pub current_root: PathBuf,
    pub executable: PathBuf,
}

#[cfg(windows)]
pub fn installed_executable_path(local_app_data: Option<&str>) -> Result<InstalledExecutable, String> {
    let local_app_data =
        local_app_data.ok_or_else(|| "LOCALAPPDATA is required for installed qualification".to_string())?;
    let root = Path::new(local_app_data).join("Orthic Labs").join("Legion");
    let current = root.join("current");
    let executable = current.join("bin").join("legion.exe");
    let meta = fs::symlink_metadata(&executable).ok();
    let ok = meta.as_ref().map(|m| m.is_file() && !m.file_type().is_symlink()).unwrap_or(false);
    if !ok {
        return Err(format!("stable installed executable is missing or unsafe: {}", executable.display()));
    }
    Ok(InstalledExecutable { install_root: root, current_root: current, executable })
}

pub fn developer_executable_path(legion_exe: Option<&str>) -> Result<PathBuf, String> {
    let candidate = legion_exe
        .filter(|c| !c.is_empty() && Path::new(c).is_absolute())
        .ok_or_else(|| "LEGION_EXE must be an absolute executable path for developer characterization".to_string())?;
    let path = Path::new(candidate).to_path_buf();
    let meta = fs::symlink_metadata(&path).ok();
    let ok = meta.as_ref().map(|m| m.is_file() && !m.file_type().is_symlink()).unwrap_or(false);
    if !ok {
        return Err(format!("developer executable is missing or unsafe: {}", path.display()));
    }
    Ok(path)
}

fn get_field<'a>(value: &'a Value, paths: &[&str]) -> Option<&'a str> {
    for path in paths {
        let mut current = value;
        let mut found = true;
        for part in path.split('.') {
            match current.get(part) {
                Some(v) => current = v,
                None => {
                    found = false;
                    break;
                }
            }
        }
        if found {
            if let Some(s) = current.as_str() {
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
    }
    None
}

pub struct Evidence {
    pub path: PathBuf,
    pub value: Value,
    pub sha256: String,
}

pub fn read_evidence(path: Option<&Path>) -> Result<Evidence, String> {
    let path = match path {
        Some(p) if fs::symlink_metadata(p).map(|m| m.is_file() && !m.file_type().is_symlink()).unwrap_or(false) => p,
        _ => return Err(format!("qualification evidence is missing or unsafe: {}", path.map(|p| p.display().to_string()).unwrap_or_else(|| "<unset>".to_string()))),
    };
    let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|e| format!("qualification evidence is invalid JSON: {e}"))?;
    Ok(Evidence { path: path.to_path_buf(), value, sha256: sha256(&bytes) })
}

pub struct Provenance {
    pub path: PathBuf,
    #[allow(dead_code)]
    pub receipt_sha256: String,
    #[allow(dead_code)]
    pub source_revision: String,
    #[allow(dead_code)]
    pub source_tree_sha256: String,
    #[allow(dead_code)]
    pub manifest_sha256: String,
    pub executable_sha256: String,
    pub executable: PathBuf,
    pub mode: String,
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_revision(value: &str) -> bool {
    value.len() >= 40 && value.len() <= 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

#[allow(clippy::too_many_arguments)]
pub fn validate_executable_provenance(
    executable: &Path,
    evidence_path: Option<&Path>,
    manifest_sha256: &str,
    source: &SourceIdentity,
    mode: &str,
    // Only consulted on Windows (`mode == "installed"` is otherwise a no-op
    // below); kept as a plain parameter rather than `#[cfg(windows)]` since
    // `cfg` on function parameters isn't available on stable Rust.
    #[allow(unused_variables)] local_app_data: Option<&str>,
) -> Result<Provenance, String> {
    let evidence = read_evidence(evidence_path)?;
    let value = &evidence.value;
    let status_ok = value
        .get("status")
        .and_then(Value::as_str)
        .map(|s| matches!(s.to_lowercase().as_str(), "pass" | "qualified" | "verified"))
        .unwrap_or(false);
    if !status_ok {
        return Err("qualification evidence does not report a completed status".to_string());
    }
    let source_revision = get_field(value, &["sourceRevision", "source_revision", "build.sourceRevision"]);
    let source_tree_sha256 = get_field(value, &["sourceTreeSha256", "sourceTreeDigest", "build.sourceTreeSha256"]);
    let recorded_manifest = get_field(value, &["manifestSha256", "manifest.sha256", "behaviorManifestSha256", "build.manifestSha256"]);
    let recorded_executable = get_field(value, &["executableSha256", "installedExecutableSha256", "executable.sha256", "build.executableSha256"]);
    let recorded_path = get_field(value, &["installedExecutable", "executable.path", "build.executablePath"]);

    let source_revision = source_revision.filter(|s| is_revision(s)).ok_or("qualification evidence is missing a valid source revision")?;
    let source_tree_sha256 = source_tree_sha256.filter(|s| is_sha256(s)).ok_or("qualification evidence is missing sourceTreeSha256")?;
    let recorded_manifest = recorded_manifest.filter(|m| m.to_lowercase() == manifest_sha256.to_lowercase()).ok_or("qualification evidence manifest SHA-256 does not match frozen manifest")?;
    let recorded_executable = recorded_executable.filter(|e| is_sha256(e)).ok_or("qualification evidence is missing executableSha256")?;

    let actual_executable = sha256_file(executable)?;
    if recorded_executable.to_lowercase() != actual_executable {
        return Err("qualification evidence executable SHA-256 does not match executable".to_string());
    }
    let normalized_executable = fs::canonicalize(executable).unwrap_or_else(|_| executable.to_path_buf());

    #[cfg(windows)]
    if mode == "installed" {
        let stable = installed_executable_path(local_app_data)?;
        let stable_executable = fs::canonicalize(&stable.executable).unwrap_or(stable.executable.clone());
        if normalized_executable != stable_executable {
            return Err("installed qualification executable is not the installer-owned stable current executable".to_string());
        }
        let recorded_path_ok = recorded_path
            .map(|p| fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p)) == normalized_executable)
            .unwrap_or(false);
        if !recorded_path_ok {
            return Err("qualification evidence does not name the stable current executable".to_string());
        }
        let origin_ok = value.get("origin").and_then(Value::as_str) == Some("installed")
            || value.get("activation").and_then(|a| a.get("status")).and_then(|s| s.get("origin")).and_then(Value::as_str) == Some("installed");
        if !origin_ok {
            return Err("qualification evidence does not prove installed origin".to_string());
        }
    } else if let Some(p) = recorded_path {
        let recorded_norm = fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p));
        if recorded_norm != normalized_executable {
            return Err("qualification evidence executable path does not match requested executable".to_string());
        }
    }
    #[cfg(not(windows))]
    if let Some(p) = recorded_path {
        let recorded_norm = fs::canonicalize(p).unwrap_or_else(|_| PathBuf::from(p));
        if recorded_norm != normalized_executable {
            return Err("qualification evidence executable path does not match requested executable".to_string());
        }
    }

    if !source.source_revision.is_empty() && source_revision.to_lowercase() != source.source_revision.to_lowercase() {
        return Err("qualification evidence source revision is not the current tree".to_string());
    }
    if !source.source_tree_sha256.is_empty() && source_tree_sha256.to_lowercase() != source.source_tree_sha256.to_lowercase() {
        return Err("qualification evidence source tree hash is not the current tree".to_string());
    }

    Ok(Provenance {
        path: evidence.path,
        receipt_sha256: evidence.sha256,
        source_revision: source_revision.to_lowercase(),
        source_tree_sha256: source_tree_sha256.to_lowercase(),
        manifest_sha256: recorded_manifest.to_lowercase(),
        executable_sha256: actual_executable,
        executable: normalized_executable,
        mode: mode.to_string(),
    })
}

fn normalize_text(value: &str, normalization: &Value, temp_roots: &[String]) -> Result<String, String> {
    if !normalization.is_object() {
        return Ok(value.to_string());
    }
    let obj = normalization.as_object().unwrap();
    for key in obj.keys() {
        if !ALLOWED_NORMALIZATION_KEYS.contains(&key.as_str()) && key != ALLOWED_NORMALIZATION_KEY_TEMP_ROOTS {
            return Err(format!("unsupported normalization field: {key}"));
        }
    }
    let mut text = value.to_string();
    if obj.get("lineEndings").and_then(Value::as_bool) == Some(true) {
        text = text.replace("\r\n", "\n").replace('\r', "\n");
    }
    if obj.get("trailingWhitespace").and_then(Value::as_bool) == Some(true) {
        text = text
            .split('\n')
            .map(|line| line.trim_end_matches([' ', '\t']))
            .collect::<Vec<_>>()
            .join("\n");
    }
    if obj.get("stackFrames").and_then(Value::as_bool) == Some(true) {
        text = text
            .split('\n')
            .filter(|line| {
                let trimmed = line.trim_start();
                !(trimmed.len() != line.len() && trimmed.starts_with("at "))
            })
            .collect::<Vec<_>>()
            .join("\n");
    }
    if obj.get("timestamps").and_then(Value::as_bool) == Some(true) {
        let re = regex::Regex::new(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z\b").unwrap();
        text = re.replace_all(&text, "<TIMESTAMP>").to_string();
    }
    if obj.get("tempRoots").and_then(Value::as_bool) == Some(true) {
        let mut roots: Vec<&String> = temp_roots.iter().filter(|r| !r.is_empty()).collect();
        roots.sort_by(|a, b| b.len().cmp(&a.len()));
        for root in roots {
            text = text.replace(root.as_str(), "<TEMP_ROOT>");
            let json_escaped = serde_json::to_string(root).unwrap();
            let json_escaped = &json_escaped[1..json_escaped.len() - 1];
            text = text.replace(json_escaped, "<TEMP_ROOT>");
        }
    }
    Ok(text)
}

fn normalize_evidence_value(value: &Value, normalization: &Value, temp_roots: &[String]) -> Value {
    match value {
        Value::String(s) => Value::String(normalize_text(s, normalization, temp_roots).unwrap_or_else(|_| s.clone())),
        Value::Array(items) => Value::Array(items.iter().map(|i| normalize_evidence_value(i, normalization, temp_roots)).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                out.insert(k.clone(), normalize_evidence_value(v, normalization, temp_roots));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

pub struct Observation {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
    #[allow(dead_code)]
    pub signal: Option<String>,
    pub timed_out: bool,
    pub output_limit_exceeded: bool,
    pub filesystem: Value, // { before, after }
    pub sandbox_roots: Vec<String>,
}

pub fn compare_observations(
    expected: &Value,
    actual: &Observation,
    fixture: &Value,
    temp_roots: &[String],
) -> Vec<String> {
    let mut mismatches = Vec::new();
    let baseline_problems = observation_value_problems(expected, "baseline");
    let actual_problems_v = observation_to_value(actual);
    let actual_problems = observation_value_problems(&actual_problems_v, "native");
    mismatches.extend(baseline_problems.clone());
    mismatches.extend(actual_problems.clone());
    if !baseline_problems.is_empty() || !actual_problems.is_empty() {
        return mismatches;
    }
    let expected_exit = expected.get("exitCode").and_then(Value::as_i64);
    if expected_exit != actual.exit_code.map(|c| c as i64) {
        mismatches.push(format!(
            "exit {} != baseline {}",
            actual.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "null".to_string()),
            expected_exit.map(|c| c.to_string()).unwrap_or_else(|| "null".to_string())
        ));
    }
    let normalization = fixture
        .get("normalization")
        .or_else(|| fixture.get("normalize"))
        .cloned()
        .unwrap_or(json!({}));
    let mut all_temp_roots: Vec<String> = temp_roots.to_vec();
    for r in expected.get("sandboxRoots").and_then(Value::as_array).into_iter().flatten() {
        if let Some(s) = r.as_str() {
            all_temp_roots.push(s.to_string());
        }
    }
    all_temp_roots.extend(actual.sandbox_roots.clone());
    all_temp_roots.sort();
    all_temp_roots.dedup();

    let expected_stdout = normalize_text(expected.get("stdout").and_then(Value::as_str).unwrap_or(""), &normalization, &all_temp_roots).unwrap_or_default();
    let actual_stdout = normalize_text(&actual.stdout, &normalization, &all_temp_roots).unwrap_or_default();
    let expected_stderr = normalize_text(expected.get("stderr").and_then(Value::as_str).unwrap_or(""), &normalization, &all_temp_roots).unwrap_or_default();
    let actual_stderr = normalize_text(&actual.stderr, &normalization, &all_temp_roots).unwrap_or_default();
    if expected_stdout != actual_stdout {
        mismatches.push("stdout differs from baseline".to_string());
    }
    if expected_stderr != actual_stderr {
        mismatches.push("stderr differs from baseline".to_string());
    }

    let empty = json!({});
    let expected_fs = expected.get("filesystem").unwrap_or(&empty);
    let expected_mutation = mutation_diff(expected_fs);
    let actual_mutation = mutation_diff(&actual.filesystem);
    let expected_mutation = normalize_evidence_value(&expected_mutation, &normalization, &all_temp_roots);
    let actual_mutation = normalize_evidence_value(&actual_mutation, &normalization, &all_temp_roots);
    if canonical_json(&expected_mutation) != canonical_json(&actual_mutation) {
        mismatches.push("filesystem mutation differs from baseline".to_string());
    }
    mismatches
}

fn mutation_diff(filesystem: &Value) -> Value {
    let empty = json!({});
    let before = filesystem.get("before").unwrap_or(&empty);
    let after = filesystem.get("after").unwrap_or(&empty);
    let mut changed = Map::new();
    let mut roots: BTreeSet<String> = BTreeSet::new();
    if let Some(o) = before.as_object() {
        roots.extend(o.keys().cloned());
    }
    if let Some(o) = after.as_object() {
        roots.extend(o.keys().cloned());
    }
    for root in roots {
        let left = before.get(&root);
        let right = after.get(&root);
        match (left.and_then(Value::as_array), right.and_then(Value::as_array)) {
            (Some(left_arr), Some(right_arr)) => {
                let mut left_by_path: std::collections::BTreeMap<&str, &Value> = std::collections::BTreeMap::new();
                for entry in left_arr {
                    if let Some(p) = entry.get("path").and_then(Value::as_str) {
                        left_by_path.insert(p, entry);
                    }
                }
                let mut right_by_path: std::collections::BTreeMap<&str, &Value> = std::collections::BTreeMap::new();
                for entry in right_arr {
                    if let Some(p) = entry.get("path").and_then(Value::as_str) {
                        right_by_path.insert(p, entry);
                    }
                }
                let mut paths: BTreeSet<&str> = BTreeSet::new();
                paths.extend(left_by_path.keys());
                paths.extend(right_by_path.keys());
                let null = Value::Null;
                let mut entries = Vec::new();
                for path in paths {
                    let l = *left_by_path.get(path).unwrap_or(&&null);
                    let r = *right_by_path.get(path).unwrap_or(&&null);
                    if canonical_json(l) != canonical_json(r) {
                        entries.push(json!({ "path": path, "before": l, "after": r }));
                    }
                }
                if !entries.is_empty() {
                    changed.insert(root, Value::Array(entries));
                }
            }
            _ => {
                let l = left.cloned().unwrap_or(Value::Null);
                let r = right.cloned().unwrap_or(Value::Null);
                if canonical_json(&l) != canonical_json(&r) {
                    changed.insert(root, json!({ "before": l, "after": r }));
                }
            }
        }
    }
    Value::Object(changed)
}

fn normalized_windows_path(value: &str) -> String {
    let stripped = value.strip_prefix(r"\\?\").unwrap_or(value);
    stripped.replace('/', "\\").to_lowercase()
}

pub fn validate_installed_skill_links(filesystem: &Value, installed_skills_root: &Path, forbidden_root: &Path) -> Vec<String> {
    let entries = filesystem.get("after").and_then(|a| a.get("cwd")).and_then(Value::as_array);
    let entries = match entries {
        Some(e) => e,
        None => return vec!["installed filesystem evidence has no cwd inventory".to_string()],
    };
    let link_re = regex::Regex::new(r"^\.agents/skills/[^/]+$").unwrap();
    let links: Vec<&Value> = entries
        .iter()
        .filter(|e| {
            e.get("type").and_then(Value::as_str) == Some("symlink")
                && link_re.is_match(e.get("path").and_then(Value::as_str).unwrap_or_default())
        })
        .collect();
    if links.is_empty() {
        return vec!["installed harness created no skill links".to_string()];
    }
    let required = format!("{}\\", normalized_windows_path(&installed_skills_root.to_string_lossy()));
    let forbidden = format!("{}\\", normalized_windows_path(&forbidden_root.to_string_lossy()));
    let mut problems = Vec::new();
    for link in links {
        let path = link.get("path").and_then(Value::as_str).unwrap_or_default();
        let target = normalized_windows_path(link.get("target").and_then(Value::as_str).unwrap_or_default());
        if !target.starts_with(&required) {
            problems.push(format!("{path} does not target installed plugin skills"));
        }
        if target.starts_with(&forbidden) {
            problems.push(format!("{path} targets development checkout"));
        }
    }
    problems
}

pub struct ParityRowResult {
    pub status: &'static str,
    pub comparison: &'static str,
    pub mismatch: Vec<String>,
}

pub fn evaluate_parity_row(
    fixture: &Value,
    record: &Observation,
    baseline: Option<&Value>,
    baseline_id_matches_and_digest: Option<(&str, &str)>, // (baseline.id, baseline.fixtureSha256)
    fixture_sha256: &str,
    fixture_id: &str,
    temp_roots: &[String],
) -> ParityRowResult {
    let record_value = observation_to_value(record);
    let problems = observation_value_problems(&record_value, "native");
    if !problems.is_empty() {
        return ParityRowResult { status: "blocked", comparison: "invalid-observation", mismatch: problems };
    }
    if fixture.get("rust").and_then(Value::as_bool) == Some(false) {
        return ParityRowResult {
            status: "blocked",
            comparison: "unsupported-native-row",
            mismatch: vec!["manifest row has no asserted native implementation".to_string()],
        };
    }
    if fixture.get("nativeOnly").and_then(Value::as_bool) == Some(true) {
        let mut mismatch = Vec::new();
        match assert_native_oracle(fixture, record) {
            Ok(m) => mismatch.extend(m),
            Err(e) => mismatch.push(e),
        }
        let before = record.filesystem.get("before").cloned().unwrap_or(Value::Null);
        let after = record.filesystem.get("after").cloned().unwrap_or(Value::Null);
        if canonical_json(&before) != canonical_json(&after) {
            mismatch.push("native-only row has unasserted filesystem mutations".to_string());
        }
        return ParityRowResult {
            status: if mismatch.is_empty() { "matched" } else { "blocked" },
            comparison: "native-oracle",
            mismatch,
        };
    }
    let baseline = match baseline {
        Some(b) => b,
        None => {
            return ParityRowResult {
                status: "unmatched",
                comparison: "node-parity",
                mismatch: vec!["Node baseline row is missing".to_string()],
            }
        }
    };
    if let Some((baseline_id, baseline_digest)) = baseline_id_matches_and_digest {
        if baseline_digest != fixture_sha256 || baseline_id != fixture_id {
            return ParityRowResult {
                status: "unmatched",
                comparison: "node-parity",
                mismatch: vec!["Node baseline identity does not match frozen manifest row".to_string()],
            };
        }
    }
    let mismatch = compare_observations(baseline, record, fixture, temp_roots);
    ParityRowResult {
        status: if mismatch.is_empty() { "matched" } else { "mismatched" },
        comparison: "node-parity",
        mismatch,
    }
}

fn valid_exit_code(value: Option<i64>) -> bool {
    matches!(value, Some(v) if (0..=255).contains(&v))
}

fn valid_string_list(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_array)
        .map(|a| !a.is_empty() && a.iter().all(|v| v.as_str().map(|s| !s.is_empty()).unwrap_or(false)))
        .unwrap_or(false)
}

fn valid_digest(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).map(is_sha256).unwrap_or(false)
}

fn observation_to_value(observation: &Observation) -> Value {
    json!({
        "exitCode": observation.exit_code,
        "stdout": observation.stdout,
        "stderr": observation.stderr,
        "error": observation.error,
        "signal": observation.signal,
        "timedOut": observation.timed_out,
        "outputLimitExceeded": observation.output_limit_exceeded,
        "mismatch": Vec::<String>::new(),
        "filesystem": observation.filesystem,
    })
}

fn observation_value_problems(observation: &Value, label: &str) -> Vec<String> {
    observation_problems_inner(observation, label, true)
}

fn observation_problems_inner(observation: &Value, label: &str, require_evidence: bool) -> Vec<String> {
    let mut problems = Vec::new();
    if !observation.is_object() {
        return vec![format!("{label} observation is not an object")];
    }
    if !valid_exit_code(observation.get("exitCode").and_then(Value::as_i64)) {
        problems.push(format!("{label} observation has no valid integer exitCode"));
    }
    let stdout_ok = observation.get("stdout").map(Value::is_string).unwrap_or(false);
    let stderr_ok = observation.get("stderr").map(Value::is_string).unwrap_or(false);
    if !stdout_ok || !stderr_ok {
        problems.push(format!("{label} observation streams are missing or not strings"));
    }
    if require_evidence {
        if !observation.get("error").map(Value::is_null).unwrap_or(false) {
            problems.push(format!("{label} observation reports an error"));
        }
        if !observation.get("signal").map(Value::is_null).unwrap_or(false) {
            problems.push(format!("{label} observation reports a signal"));
        }
        if observation.get("timedOut").and_then(Value::as_bool) != Some(false) {
            problems.push(format!("{label} observation timed out or has invalid timeout state"));
        }
        if observation.get("outputLimitExceeded").and_then(Value::as_bool) != Some(false) {
            problems.push(format!("{label} observation exceeded the output limit or has invalid limit state"));
        }
        let mismatch_ok = observation.get("mismatch").and_then(Value::as_array).map(|a| a.is_empty()).unwrap_or(false);
        if !mismatch_ok {
            problems.push(format!("{label} observation reports a mismatch"));
        }
        match observation.get("filesystem") {
            Some(fsv) if fsv.is_object() => {
                let obj = fsv.as_object().unwrap();
                if !obj.get("before").map(|v| v.is_object()).unwrap_or(false) {
                    problems.push(format!("{label} filesystem before evidence is missing or invalid"));
                }
                if !obj.get("after").map(|v| v.is_object()).unwrap_or(false) {
                    problems.push(format!("{label} filesystem after evidence is missing or invalid"));
                }
            }
            _ => problems.push(format!("{label} filesystem evidence is missing")),
        }
    } else {
        let error = observation.get("error");
        if !matches!(error, None | Some(Value::Null)) && error != Some(&Value::String(String::new())) {
            problems.push(format!("{label} observation reports an error"));
        }
        let signal = observation.get("signal");
        if !matches!(signal, None | Some(Value::Null)) {
            problems.push(format!("{label} observation reports a signal"));
        }
        let timed_out = observation.get("timedOut");
        if timed_out.is_some() && timed_out.and_then(Value::as_bool) != Some(false) {
            problems.push(format!("{label} observation timed out or has invalid timeout state"));
        }
        let limit = observation.get("outputLimitExceeded");
        if limit.is_some() && limit.and_then(Value::as_bool) != Some(false) {
            problems.push(format!("{label} observation exceeded the output limit or has invalid limit state"));
        }
    }
    problems
}

const NATIVE_ORACLE_KEYS: [&str; 6] =
    ["exitCode", "stdoutIncludes", "stderrIncludes", "kind", "stdoutSha256", "stderrSha256"];

pub fn assert_native_oracle(fixture: &Value, observation: &Observation) -> Result<Vec<String>, String> {
    let oracle = fixture
        .get("nativeOracle")
        .filter(|o| o.is_object())
        .ok_or_else(|| format!("row {} has no valid native behavior oracle object", fixture.get("id").and_then(Value::as_str).unwrap_or("?")))?;
    let obj = oracle.as_object().unwrap();
    let unknown: Vec<&String> = obj.keys().filter(|k| !NATIVE_ORACLE_KEYS.contains(&k.as_str())).collect();
    if !unknown.is_empty() {
        return Err(format!(
            "row {} native oracle has unknown assertion fields: {}",
            fixture.get("id").and_then(Value::as_str).unwrap_or("?"),
            unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        ));
    }
    let id = fixture.get("id").and_then(Value::as_str).unwrap_or("?");
    if !valid_exit_code(obj.get("exitCode").and_then(Value::as_i64)) {
        return Err(format!("row {id} native oracle requires a valid integer exitCode"));
    }
    if obj.contains_key("stdoutIncludes") && !valid_string_list(obj.get("stdoutIncludes")) {
        return Err(format!("row {id} native oracle stdoutIncludes must be a non-empty string array"));
    }
    if obj.contains_key("stderrIncludes") && !valid_string_list(obj.get("stderrIncludes")) {
        return Err(format!("row {id} native oracle stderrIncludes must be a non-empty string array"));
    }
    if let Some(kind) = obj.get("kind") {
        if kind.as_str().map(|s| s.is_empty()).unwrap_or(true) {
            return Err(format!("row {id} native oracle kind must be a non-empty string"));
        }
    }
    if obj.contains_key("stdoutSha256") && !valid_digest(obj.get("stdoutSha256")) {
        return Err(format!("row {id} native oracle stdoutSha256 is invalid"));
    }
    if obj.contains_key("stderrSha256") && !valid_digest(obj.get("stderrSha256")) {
        return Err(format!("row {id} native oracle stderrSha256 is invalid"));
    }
    let observation_value = observation_to_value(observation);
    let issues = observation_problems_inner(&observation_value, "native", false);
    if !issues.is_empty() {
        return Err(issues.join("; "));
    }
    let mut mismatches = Vec::new();
    let expected_exit = obj.get("exitCode").and_then(Value::as_i64);
    if observation.exit_code.map(|c| c as i64) != expected_exit {
        mismatches.push(format!(
            "exit {} != native oracle {}",
            observation.exit_code.map(|c| c.to_string()).unwrap_or_else(|| "null".into()),
            expected_exit.map(|c| c.to_string()).unwrap_or_else(|| "null".into())
        ));
    }
    if let Some(needles) = obj.get("stdoutIncludes").and_then(Value::as_array) {
        if needles.iter().any(|n| !observation.stdout.contains(n.as_str().unwrap_or_default())) {
            mismatches.push("stdout native oracle assertion failed".to_string());
        }
    }
    if let Some(needles) = obj.get("stderrIncludes").and_then(Value::as_array) {
        if needles.iter().any(|n| !observation.stderr.contains(n.as_str().unwrap_or_default())) {
            mismatches.push("stderr native oracle assertion failed".to_string());
        }
    }
    if let Some(kind) = obj.get("kind").and_then(Value::as_str) {
        match serde_json::from_str::<Value>(&observation.stdout) {
            Ok(parsed) => {
                if parsed.get("kind").and_then(Value::as_str) != Some(kind) {
                    mismatches.push(format!("stdout kind != native oracle {kind}"));
                }
            }
            Err(_) => mismatches.push("native oracle requires JSON stdout".to_string()),
        }
    }
    if let Some(expected) = obj.get("stdoutSha256").and_then(Value::as_str) {
        if sha256(observation.stdout.as_bytes()) != expected {
            mismatches.push("stdout SHA-256 != native oracle".to_string());
        }
    }
    if let Some(expected) = obj.get("stderrSha256").and_then(Value::as_str) {
        if sha256(observation.stderr.as_bytes()) != expected {
            mismatches.push("stderr SHA-256 != native oracle".to_string());
        }
    }
    Ok(mismatches)
}

pub struct RowSummaryInput {
    pub id: String,
    pub status: String,
    pub mismatch: Vec<String>,
    pub error: Option<String>,
}

pub fn summarize_results(results: &[RowSummaryInput], expected_ids: Option<&[String]>, expected_count: Option<usize>) -> Value {
    let result_ids: Vec<&str> = results.iter().map(|r| r.id.as_str()).collect();
    let invalid_ids: Vec<&str> = result_ids.iter().filter(|id| id.is_empty()).copied().collect();
    let mut seen_once: BTreeSet<&str> = BTreeSet::new();
    let mut duplicate_ids: Vec<&str> = Vec::new();
    for id in &result_ids {
        if !id.is_empty() {
            if !seen_once.insert(id) && !duplicate_ids.contains(id) {
                duplicate_ids.push(id);
            }
        }
    }
    let result_id_set: BTreeSet<&str> = result_ids.iter().copied().collect();
    let missing_ids: Vec<&str> = expected_ids
        .map(|ids| ids.iter().filter(|id| !result_id_set.contains(id.as_str())).map(|s| s.as_str()).collect())
        .unwrap_or_default();
    let mut unexpected_ids: Vec<&str> = Vec::new();
    if let Some(ids) = expected_ids {
        let expected_set: BTreeSet<&str> = ids.iter().map(|s| s.as_str()).collect();
        let mut seen = BTreeSet::new();
        for id in &result_ids {
            if !expected_set.contains(id) && seen.insert(*id) {
                unexpected_ids.push(id);
            }
        }
    }
    let expected_ids_unique = expected_ids
        .map(|ids| {
            ids.iter().all(|id| !id.is_empty()) && {
                let set: BTreeSet<&str> = ids.iter().map(|s| s.as_str()).collect();
                set.len() == ids.len()
            }
        })
        .unwrap_or(true);
    let coverage_valid = invalid_ids.is_empty()
        && duplicate_ids.is_empty()
        && expected_ids_unique
        && expected_count.map(|c| c == results.len()).unwrap_or(true)
        && expected_ids
            .map(|ids| missing_ids.is_empty() && unexpected_ids.is_empty() && ids.len() == results.len())
            .unwrap_or(true);

    let normalized: Vec<(&str, Vec<String>)> = results
        .iter()
        .map(|r| {
            let has_issue = !r.mismatch.is_empty() || r.error.as_ref().map(|e| !e.is_empty()).unwrap_or(false);
            if r.status == "matched" && has_issue {
                let mismatch = if !r.mismatch.is_empty() {
                    r.mismatch.clone()
                } else {
                    vec!["matched row contains an error or invalid mismatch state".to_string()]
                };
                ("mismatched", mismatch)
            } else {
                (r.status.as_str(), r.mismatch.clone())
            }
        })
        .collect();

    let counts = json!({
        "total": normalized.len(),
        "matched": normalized.iter().filter(|(s, _)| *s == "matched").count(),
        "mismatched": normalized.iter().filter(|(s, _)| *s == "mismatched").count(),
        "blocked": normalized.iter().filter(|(s, _)| *s == "blocked").count(),
        "unmatched": normalized.iter().filter(|(s, _)| *s == "unmatched").count(),
        "skipped": normalized.iter().filter(|(s, _)| *s == "skipped").count(),
    });
    let matched = normalized.iter().filter(|(s, _)| *s == "matched").count();
    let total = normalized.len();
    let qualifying = coverage_valid
        && total > 0
        && matched == total
        && normalized.iter().all(|(s, _)| *s == "matched");

    json!({
        "duplicateIds": duplicate_ids,
        "invalidIds": invalid_ids,
        "missingIds": missing_ids,
        "unexpectedIds": unexpected_ids,
        "coverageValid": coverage_valid,
        "qualifying": qualifying,
        "counts": counts,
        "resultsNormalized": normalized.iter().map(|(s, m)| json!({ "status": s, "mismatch": m })).collect::<Vec<_>>(),
    })
}

pub fn snapshot_root(root: &Path, label: &str) -> Result<Value, String> {
    const MAX_FILES: usize = 2000;
    const MAX_BYTES: u64 = 32 * 1024 * 1024;
    const MAX_DEPTH: u32 = 16;
    let root_meta = fs::symlink_metadata(root).map_err(|e| format!("filesystem snapshot root vanished at {label}: {e}"))?;
    if !root_meta.is_dir() || root_meta.file_type().is_symlink() {
        return Err(format!("filesystem snapshot root is not a directory at {label}"));
    }
    let mut records = Vec::new();
    let mut bytes: u64 = 0;
    walk_snapshot(root, root, 0, MAX_DEPTH, MAX_FILES, MAX_BYTES, label, &mut records, &mut bytes)?;
    Ok(Value::Array(records))
}

#[allow(clippy::too_many_arguments)]
fn walk_snapshot(
    root: &Path,
    current: &Path,
    depth: u32,
    max_depth: u32,
    max_files: usize,
    max_bytes: u64,
    label: &str,
    records: &mut Vec<Value>,
    bytes: &mut u64,
) -> Result<(), String> {
    if depth > max_depth {
        return Err(format!("filesystem snapshot depth limit exceeded at {label}/{}", current.strip_prefix(root).unwrap_or(current).display()));
    }
    let mut entries: Vec<_> = fs::read_dir(current)
        .map_err(|e| format!("filesystem snapshot directory vanished at {label}/{}: {e}", current.strip_prefix(root).unwrap_or(current).display()))?
        .flatten()
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        if records.len() >= max_files {
            return Err(format!("filesystem snapshot file bound exceeded at {label}"));
        }
        let path = entry.path();
        let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().replace('\\', "/");
        let observed = fs::symlink_metadata(&path).map_err(|e| format!("filesystem snapshot entry vanished at {label}/{rel}: {e}"))?;
        let actual_type = if observed.file_type().is_symlink() {
            "symlink"
        } else if observed.is_dir() {
            "directory"
        } else if observed.is_file() {
            "file"
        } else {
            "other"
        };
        match actual_type {
            "directory" => {
                records.push(json!({ "path": rel, "type": "directory" }));
                walk_snapshot(root, &path, depth + 1, max_depth, max_files, max_bytes, label, records, bytes)?;
            }
            "symlink" => {
                let target = fs::read_link(&path).ok().map(|t| t.to_string_lossy().to_string());
                records.push(json!({ "path": rel, "type": "symlink", "target": target }));
            }
            "file" => {
                let size = observed.len();
                if *bytes + size > max_bytes {
                    return Err(format!("filesystem snapshot output limit exceeded at {label}/{rel}"));
                }
                *bytes += size;
                let digest = sha256_file(&path).map_err(|e| format!("filesystem snapshot file vanished at {label}/{rel}: {e}"))?;
                records.push(json!({ "path": rel, "type": "file", "size": size, "sha256": digest }));
            }
            _ => records.push(json!({ "path": rel, "type": "other" })),
        }
    }
    Ok(())
}

pub struct Sandbox {
    pub cwd: PathBuf,
    #[allow(dead_code)]
    pub home: PathBuf,
    #[allow(dead_code)]
    pub local_app_data: PathBuf,
    #[allow(dead_code)]
    pub state_root: PathBuf,
    pub env: std::collections::HashMap<String, String>,
    pub temp_roots: Vec<String>,
    base: PathBuf,
}

fn copy_fixture(source: &Path, destination: &Path) -> Result<(), String> {
    if !source.is_dir() {
        return Ok(());
    }
    copy_dir_filtered(source, destination)
}

fn copy_dir_filtered(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(source).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == ".git" || name_str == "node_modules" || name_str == "target" || name_str == "dist" {
            continue;
        }
        let src_path = entry.path();
        let dst_path = destination.join(&name);
        let meta = entry.file_type().map_err(|e| e.to_string())?;
        if meta.is_dir() {
            copy_dir_filtered(&src_path, &dst_path)?;
        } else if meta.is_file() {
            fs::copy(&src_path, &dst_path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

pub fn create_sandbox(root: &Path, fixture: &Value) -> Result<Sandbox, String> {
    let pid = std::process::id();
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let base = std::env::temp_dir().join(format!("legion-native-cli-gate-{pid}-{n}"));
    let cwd = base.join("cwd");
    let home = base.join("home");
    let local_app_data = base.join("local-app-data");
    let state_root = base.join("state");
    for path in [&cwd, &home, &local_app_data, &state_root] {
        fs::create_dir_all(path).map_err(|e| e.to_string())?;
    }
    let fixture_cwd_rel = fixture.get("cwd").and_then(Value::as_str).unwrap_or(".");
    if fixture_cwd_rel != "." {
        copy_fixture(&root.join(fixture_cwd_rel), &cwd)?;
    }
    let mut env: std::collections::HashMap<String, String> = std::env::vars().collect();
    if let Some(extra) = fixture.get("env").and_then(Value::as_object) {
        for (k, v) in extra {
            if let Some(s) = v.as_str() {
                env.insert(k.clone(), s.to_string());
            }
        }
    }
    env.insert("HOME".into(), home.to_string_lossy().to_string());
    env.insert("USERPROFILE".into(), home.to_string_lossy().to_string());
    env.insert("LOCALAPPDATA".into(), local_app_data.to_string_lossy().to_string());
    env.insert("APPDATA".into(), home.join("AppData").join("Roaming").to_string_lossy().to_string());
    env.insert("XDG_CONFIG_HOME".into(), home.join(".config").to_string_lossy().to_string());
    env.insert("XDG_DATA_HOME".into(), home.join(".local").join("share").to_string_lossy().to_string());
    env.insert("XDG_STATE_HOME".into(), home.join(".local").join("state").to_string_lossy().to_string());
    env.insert("LEGION_STATE_ROOT".into(), state_root.to_string_lossy().to_string());
    env.insert("ARCANE_STATE_ROOT".into(), state_root.to_string_lossy().to_string());
    env.insert("ARCANE_KEY_DIR".into(), state_root.join("keys").to_string_lossy().to_string());
    env.insert("LEGION_INSTALL_EVENT_LOG".into(), state_root.join("install-events.jsonl").to_string_lossy().to_string());
    let temp_dir = base.join("temp");
    env.insert("TEMP".into(), temp_dir.to_string_lossy().to_string());
    env.insert("TMP".into(), temp_dir.to_string_lossy().to_string());
    env.remove("LEGION_EXE");
    fs::create_dir_all(&temp_dir).map_err(|e| e.to_string())?;

    let temp_roots = vec![
        base.to_string_lossy().to_string(),
        cwd.to_string_lossy().to_string(),
        home.to_string_lossy().to_string(),
        local_app_data.to_string_lossy().to_string(),
        state_root.to_string_lossy().to_string(),
    ];
    Ok(Sandbox { cwd, home, local_app_data, state_root, env, temp_roots, base })
}

pub fn remove_sandbox(sandbox: &Sandbox) {
    let _ = fs::remove_dir_all(&sandbox.base);
}

pub fn snapshot_sandbox(sandbox: &Sandbox) -> Result<Value, String> {
    let cwd = snapshot_root(&sandbox.cwd, "cwd")?;
    let home = snapshot_root(&sandbox.home, "home")?;
    let local_app_data = snapshot_root(&sandbox.local_app_data, "localAppData")?;
    let state = snapshot_root(&sandbox.state_root, "state")?;
    Ok(json!({ "cwd": cwd, "home": home, "localAppData": local_app_data, "state": state }))
}

/// Bounded process execution: kills the child if it exceeds `timeout_ms` or
/// produces more than `max_output_bytes` combined stdout+stderr, matching
/// `spawnSync`'s `timeout`/`maxBuffer` semantics.
pub fn run_bounded(
    command: &Path,
    args: &[String],
    cwd: &Path,
    env: &std::collections::HashMap<String, String>,
    timeout_ms: u64,
    max_output_bytes: usize,
) -> Observation {
    let mut cmd = Command::new(command);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .envs(env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return Observation {
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some(e.to_string()),
                signal: None,
                timed_out: false,
                output_limit_exceeded: false,
                filesystem: json!({}),
                sandbox_roots: vec![],
            }
        }
    };

    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();
    let (stdout_tx, stdout_rx) = mpsc::channel();
    let (stderr_tx, stderr_rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        let _ = stdout_tx.send(buf);
    });
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        let _ = stderr_tx.send(buf);
    });

    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let mut timed_out = false;
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    timed_out = true;
                    let _ = kill_child(&mut child);
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break None,
        }
    };

    let stdout_bytes = stdout_rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let stderr_bytes = stderr_rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default();
    let output_bytes = stdout_bytes.len() + stderr_bytes.len();
    let output_limit_exceeded = output_bytes > max_output_bytes;

    let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
    let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();

    let mut error = None;
    if output_limit_exceeded {
        error = Some(format!("output limit exceeded ({max_output_bytes} bytes)"));
    } else if timed_out {
        error = Some(format!("timeout exceeded ({timeout_ms} ms)"));
    }

    Observation {
        exit_code: exit_status.and_then(|s| exit_code_of(&s)),
        stdout,
        stderr,
        error,
        signal: exit_status.and_then(|s| signal_of(&s)),
        timed_out: timed_out && !output_limit_exceeded,
        output_limit_exceeded,
        filesystem: json!({}),
        sandbox_roots: vec![],
    }
}

fn kill_child(child: &mut Child) -> std::io::Result<()> {
    child.kill()
}

#[cfg(unix)]
fn exit_code_of(status: &std::process::ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    status.code().or_else(|| status.signal().map(|_| -1))
}
#[cfg(not(unix))]
fn exit_code_of(status: &std::process::ExitStatus) -> Option<i32> {
    status.code()
}

#[cfg(unix)]
fn signal_of(status: &std::process::ExitStatus) -> Option<String> {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map(|s| s.to_string())
}
#[cfg(not(unix))]
fn signal_of(_status: &std::process::ExitStatus) -> Option<String> {
    None
}

pub fn validate_normalization(fixture: &Value) -> Result<(), String> {
    let normalization = fixture.get("normalization").or_else(|| fixture.get("normalize"));
    if let Some(obj) = normalization.and_then(Value::as_object) {
        for key in obj.keys() {
            if !ALLOWED_NORMALIZATION_KEYS.contains(&key.as_str()) && key != ALLOWED_NORMALIZATION_KEY_TEMP_ROOTS {
                return Err(format!(
                    "row {} uses unsupported normalization: {key}",
                    fixture.get("id").and_then(Value::as_str).unwrap_or("?")
                ));
            }
        }
    }
    Ok(())
}

pub fn resolve_evidence_path(explicit: Option<&str>, root: &Path) -> PathBuf {
    if let Some(explicit) = explicit.filter(|s| !s.is_empty()) {
        return PathBuf::from(explicit);
    }
    root.join("dist").join("local-windows").join("local-verification.json")
}

/// Brotli-decompress the frozen Node baselines bundle
/// (`tests/native-cli-characterization/node-baselines.br.json`), matching
/// `node:zlib.brotliDecompressSync` in the JS runners.
pub fn read_node_baselines(path: &Path) -> Result<Map<String, Value>, String> {
    let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let frozen: Value = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    let encoding = frozen.get("encoding").and_then(Value::as_str).unwrap_or("");
    let payload = frozen.get("payload").and_then(Value::as_str).unwrap_or("");
    let compressed: Vec<u8> = if encoding == "brotli-base64" {
        base64_decode(payload)?
    } else {
        payload.as_bytes().to_vec()
    };
    let mut decompressed = Vec::new();
    brotli::Decompressor::new(compressed.as_slice(), 4096)
        .read_to_end(&mut decompressed)
        .map_err(|e| format!("brotli decompress failed: {e}"))?;
    let value: Value = serde_json::from_slice(&decompressed).map_err(|e| e.to_string())?;
    Ok(value.as_object().cloned().unwrap_or_default())
}

/// Minimal base64 (standard alphabet, with padding) decoder — avoids adding
/// a dedicated base64 crate dependency for this one call site.
fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let clean: Vec<u8> = input.bytes().filter(|b| *b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    for chunk in clean.chunks(4) {
        let mut nums = [0u8; 4];
        let mut n = 0;
        for (i, b) in chunk.iter().enumerate() {
            nums[i] = val(*b).ok_or("invalid base64 payload")?;
            n += 1;
        }
        let buf = ((nums[0] as u32) << 18) | ((nums[1] as u32) << 12) | ((nums[2] as u32) << 6) | (nums[3] as u32);
        if n > 1 {
            out.push((buf >> 16) as u8);
        }
        if n > 2 {
            out.push((buf >> 8) as u8);
        }
        if n > 3 {
            out.push(buf as u8);
        }
    }
    Ok(out)
}
