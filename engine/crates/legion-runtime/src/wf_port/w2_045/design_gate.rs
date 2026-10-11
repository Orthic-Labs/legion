//! Port of `skills/designer/scripts/design-gate.mjs`. The historical script was
//! a wrapper over `src/lib/design-gate.mjs` (Phase 5d deterministic design gate,
//! recovered from Legion history at `ebb349ae^`).
//!
//! Route: `legion script designer/design-gate [--root <dir>] [--surface <dir>]`.
//! `--root` (default: cwd) locates `skills/designer/references/banned-words.md`.
//! `--surface` (default: cwd) is the built surface that is scanned and where
//! `artifacts/qa/gate.json` is written. Exit 0 when the verdict is `pass`; exit
//! 1 when it is `fail`, or when the surface cannot be read or the report cannot
//! be written.
//!
//! Structure: [`evaluate`] is pure over a [`GateInput`] that already holds file
//! contents and listings. [`load_input`] and [`run_cli`] are the thin filesystem
//! and process wrapper.
//!
//! The historical script ran no detector and no verify module. Its only
//! external probes are `lighthouse` and `axe`, and both always report
//! `unavailable` ("no run target configured"). An unavailable required check
//! blocks the gate, so the gate cannot pass without a waiver for those two ids
//! in `artifacts/qa/gate-waivers.json`. That behaviour is kept as-is.
//!
//! Deviations from the script:
//! - `--help` / `-h` prints usage and exits 0 (the script had no usage output).
//! - An unreadable `bundle-baseline.json` is a `bundle-delta` fail carrying the
//!   parse error. The script threw an uncaught exception. Both exit 1, but this
//!   port still writes a report.

use super::path_utils;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

pub const BREAKPOINTS: [u32; 5] = [360, 768, 1024, 1440, 1920];

const BANNED_WORDS_PATH: &str = "skills/designer/references/banned-words.md";
const MOTION_PLAN_FILE: &str = "motion-plan.md";
const MOTION_GATE_FILE: &str = "motion-gate.json";
const SCREENSHOTS_DIR: &str = "artifacts/qa/screenshots";
const BASELINE_PATH: &str = "artifacts/qa/bundle-baseline.json";
const SIBLING_DIFF_PATH: &str = "artifacts/qa/sibling-diff.json";
const WAIVERS_PATH: &str = "artifacts/qa/gate-waivers.json";
const REPORT_PATH: &str = "artifacts/qa/gate.json";
const DETAIL_LIMIT: usize = 25;
const TEXT_EXTS: &[&str] = &["html", "htm", "md", "txt"];
const ASSET_EXTS: &[&str] = &["js", "mjs", "cjs", "css"];
const IMAGE_EXTS: &[&str] = &["png", "jpg", "jpeg", "webp"];
/// (check id, executable probed with `--version`).
const TOOLS: &[(&str, &str)] = &[("lighthouse", "lighthouse"), ("axe-core", "axe")];

pub const USAGE: &str = "usage: legion script designer/design-gate [--root <dir>] [--surface <dir>]\n  --root     directory holding skills/designer/references/banned-words.md (default: cwd)\n  --surface  built surface to scan; artifacts/qa/gate.json is written under it (default: cwd)\nexit: 0 gate pass, 1 gate fail or I/O failure";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
    Warn,
    Unavailable,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
            Status::Warn => "warn",
            Status::Unavailable => "unavailable",
        }
    }
}

/// One gate check. `detail` holds the script's per-check fields in insertion
/// order; `waiver` is set only for a non-pass check that has a waiver reason.
#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub id: &'static str,
    pub status: Status,
    pub detail: Map<String, Value>,
    pub waiver: Option<String>,
}

impl Check {
    fn new(id: &'static str, status: Status) -> Self {
        Self {
            id,
            status,
            detail: Map::new(),
            waiver: None,
        }
    }

    fn with(mut self, key: &str, value: Value) -> Self {
        self.detail.insert(key.to_string(), value);
        self
    }

    fn reason(id: &'static str, status: Status, reason: impl Into<String>) -> Self {
        Self::new(id, status).with("reason", json!(reason.into()))
    }

    /// Blocking when not pass, not warn, and not waived.
    pub fn is_blocking(&self) -> bool {
        self.status != Status::Pass && self.status != Status::Warn && self.waiver.is_none()
    }

    fn to_json(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("id".to_string(), json!(self.id));
        obj.insert("status".to_string(), json!(self.status.as_str()));
        for (key, value) in &self.detail {
            obj.insert(key.clone(), value.clone());
        }
        if let Some(reason) = &self.waiver {
            obj.insert("waived".to_string(), json!(true));
            obj.insert("waiverReason".to_string(), json!(reason));
        }
        Value::Object(obj)
    }
}

/// A text file under the surface: `path` is relative to the surface.
#[derive(Debug, Clone, PartialEq)]
pub struct TextFile {
    pub path: String,
    pub text: String,
}

/// State of `motion-gate.json`: absent, unreadable (read or parse error), or a
/// parsed JSON document.
#[derive(Debug, Clone, PartialEq)]
pub enum MotionGateFile {
    Absent,
    Unreadable(String),
    Parsed(Value),
}

/// Everything [`evaluate`] reads. All filesystem access happens in
/// [`load_input`]; the evaluator itself never touches the disk.
#[derive(Debug, Clone, PartialEq)]
pub struct GateInput {
    pub motion_plan_present: bool,
    pub motion_gate: MotionGateFile,
    /// Every HTML/markdown/text file under the surface. Empty means none found.
    pub text_files: Vec<TextFile>,
    /// Contents of banned-words.md, or `None` when the file is absent.
    pub banned_words_source: Option<String>,
    /// Sizes of every js/mjs/cjs/css file under the surface.
    pub asset_sizes: Vec<u64>,
    /// Contents of bundle-baseline.json, or `None` when absent.
    pub baseline_source: Option<String>,
    /// Full paths of image files under `artifacts/qa/screenshots`.
    pub screenshot_paths: Vec<String>,
    pub sibling_diff_present: bool,
    /// (executable name, present on this host).
    pub tool_present: Vec<(String, bool)>,
    /// Check id -> waiver reason, already filtered to non-empty strings.
    pub waivers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BannedWords {
    pub structural: Vec<String>,
    pub vocabulary: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GateReport {
    pub checks: Vec<Check>,
}

impl GateReport {
    pub fn blocking(&self) -> Vec<&'static str> {
        self.checks
            .iter()
            .filter(|c| c.is_blocking())
            .map(|c| c.id)
            .collect()
    }

    pub fn passed(&self) -> bool {
        self.blocking().is_empty()
    }

    /// The report written to `artifacts/qa/gate.json` and printed to stdout.
    pub fn to_json(&self) -> Value {
        let blocking = self.blocking();
        let verdict = if blocking.is_empty() { "pass" } else { "fail" };
        let count = |status: Status| self.checks.iter().filter(|c| c.status == status).count();
        let checks: Vec<Value> = self.checks.iter().map(Check::to_json).collect();
        json!({
            "schemaVersion": 1,
            "kind": "legion-design-gate",
            "phase": "5d",
            "verdict": verdict,
            "counts": {
                "total": self.checks.len(),
                "pass": count(Status::Pass),
                "fail": count(Status::Fail),
                "unavailable": count(Status::Unavailable),
                "warn": count(Status::Warn),
                "waived": self.checks.iter().filter(|c| c.waiver.is_some()).count(),
            },
            "blocking": blocking,
            "checks": checks,
        })
    }
}

/// Pure evaluation of the gate over already-loaded inputs.
pub fn evaluate(input: &GateInput) -> GateReport {
    let mut checks = Vec::new();
    checks.extend(motion_checks(input));
    checks.extend(text_checks(input));
    checks.extend(tool_checks(input));
    checks.extend(budget_checks(input));
    for check in &mut checks {
        if check.status != Status::Pass {
            if let Some(reason) = input.waivers.get(check.id) {
                check.waiver = Some(reason.clone());
            }
        }
    }
    GateReport { checks }
}

fn motion_checks(input: &GateInput) -> Vec<Check> {
    let mut out = Vec::new();
    out.push(if input.motion_plan_present {
        Check::new("motion-plan-present", Status::Pass)
    } else {
        Check::reason("motion-plan-present", Status::Fail, "motion-plan.md absent")
    });
    let gate = match &input.motion_gate {
        MotionGateFile::Absent => {
            out.push(Check::reason(
                "motion-gate-verdict",
                Status::Fail,
                "motion-gate.json absent",
            ));
            return out;
        }
        MotionGateFile::Unreadable(message) => {
            out.push(Check::reason(
                "motion-gate-verdict",
                Status::Fail,
                format!("motion-gate.json unreadable: {}", message),
            ));
            return out;
        }
        MotionGateFile::Parsed(doc) => doc,
    };
    let verdict = gate.get("verdict").filter(|v| !v.is_null());
    let verdict_is_pass = matches!(verdict, Some(Value::String(s)) if s.as_str() == "pass");
    out.push(if verdict_is_pass {
        Check::new("motion-gate-verdict", Status::Pass)
    } else {
        let shown = match verdict {
            None => "absent".to_string(),
            Some(Value::String(s)) => s.clone(),
            Some(other) => other.to_string(),
        };
        Check::reason(
            "motion-gate-verdict",
            Status::Fail,
            format!("motion gate verdict is {}", shown),
        )
    });
    out
}

fn unavailable_text(reason: &str) -> Vec<Check> {
    vec![
        Check::reason("banned-words", Status::Unavailable, reason),
        Check::reason("typography", Status::Unavailable, reason),
        Check::reason("anti-patterns", Status::Unavailable, reason),
    ]
}

fn limited(hits: &[Value]) -> Vec<Value> {
    hits.iter().take(DETAIL_LIMIT).cloned().collect()
}

fn text_checks(input: &GateInput) -> Vec<Check> {
    // No text to scan is not a pass: the gate would report green over nothing.
    if input.text_files.is_empty() {
        return unavailable_text("no built HTML/markdown found under the surface");
    }
    let Some(source) = input.banned_words_source.as_deref() else {
        return unavailable_text("skills/designer/references/banned-words.md absent");
    };
    let banned = parse_banned_words(source);
    let files = &input.text_files;
    let mut out = Vec::new();

    let mut vocab_hits: Vec<Value> = Vec::new();
    for file in files {
        for term in &banned.vocabulary {
            let count = count_word_matches(&file.text, term);
            if count > 0 {
                vocab_hits.push(json!({"path": file.path, "term": term, "count": count}));
            }
        }
    }
    out.push(if vocab_hits.is_empty() {
        Check::new("banned-words", Status::Pass)
            .with("scanned", json!(files.len()))
            .with("terms", json!(banned.vocabulary.len()))
    } else {
        Check::new("banned-words", Status::Fail)
            .with("hits", json!(limited(&vocab_hits)))
            .with("total", json!(vocab_hits.len()))
    });

    let mut typo_hits: Vec<Value> = Vec::new();
    for spec in &banned.structural {
        let Some(glyphs) = bytes_to_pattern(spec) else {
            continue;
        };
        for file in files {
            let count = file.text.chars().filter(|c| glyphs.contains(*c)).count();
            if count > 0 {
                typo_hits.push(json!({"path": file.path, "pattern": spec, "count": count}));
            }
        }
    }
    out.push(if typo_hits.is_empty() {
        Check::new("typography", Status::Pass)
            .with("scanned", json!(files.len()))
            .with("patterns", json!(banned.structural.len()))
    } else {
        Check::new("typography", Status::Fail)
            .with("hits", json!(limited(&typo_hits)))
            .with("total", json!(typo_hits.len()))
    });

    // Anti-patterns: structural tells that survive vocabulary and typography.
    let mut anti_hits: Vec<Value> = Vec::new();
    for file in files {
        let long = split_sentences(&file.text)
            .iter()
            .filter(|s| s.split_whitespace().count() > 40)
            .count();
        if long > 0 {
            anti_hits
                .push(json!({"path": file.path, "pattern": "sentence > 40 words", "count": long}));
        }
    }
    out.push(if anti_hits.is_empty() {
        Check::new("anti-patterns", Status::Pass).with("scanned", json!(files.len()))
    } else {
        Check::new("anti-patterns", Status::Warn)
            .with("hits", json!(limited(&anti_hits)))
            .with("total", json!(anti_hits.len()))
    });

    out
}

fn tool_checks(input: &GateInput) -> Vec<Check> {
    let mut out = Vec::new();
    for &(id, bin) in TOOLS {
        let present = input
            .tool_present
            .iter()
            .any(|(name, found)| name.as_str() == bin && *found);
        // A probe that finds the executable still has no run target, so the
        // check is unavailable either way. It is never a pass.
        let reason = if present {
            format!("{} present but no run target configured", bin)
        } else {
            format!("{} not on PATH", bin)
        };
        out.push(Check::reason(id, Status::Unavailable, reason));
    }
    out
}

fn budget_checks(input: &GateInput) -> Vec<Check> {
    let mut out = Vec::new();
    let total: u64 = input.asset_sizes.iter().sum();

    if input.asset_sizes.is_empty() {
        out.push(Check::reason(
            "bundle-delta",
            Status::Unavailable,
            "no js/css assets found under the surface",
        ));
    } else {
        match input.baseline_source.as_deref() {
            None => out.push(
                Check::reason(
                    "bundle-delta",
                    Status::Unavailable,
                    "artifacts/qa/bundle-baseline.json absent",
                )
                .with("totalBytes", json!(total)),
            ),
            Some(raw) => match baseline_total(raw) {
                Err(message) => out.push(Check::reason(
                    "bundle-delta",
                    Status::Fail,
                    format!("artifacts/qa/bundle-baseline.json unreadable: {}", message),
                )),
                Ok(baseline) => {
                    let total_signed = total as i64;
                    let delta = total_signed - baseline;
                    let status = if delta as f64 > baseline as f64 * 0.1 {
                        Status::Fail
                    } else {
                        Status::Pass
                    };
                    out.push(
                        Check::new("bundle-delta", status)
                            .with("baseline", json!(baseline))
                            .with("totalBytes", json!(total_signed))
                            .with("delta", json!(delta)),
                    );
                }
            },
        }
    }

    let shots: Vec<u32> = input
        .screenshot_paths
        .iter()
        .filter_map(|p| breakpoint_in_path(p))
        .collect();
    let missing: Vec<String> = BREAKPOINTS
        .iter()
        .filter(|bp| !shots.contains(*bp))
        .map(|bp| bp.to_string())
        .collect();
    out.push(if missing.is_empty() {
        Check::new("touch-targets", Status::Pass).with("breakpoints", json!(BREAKPOINTS))
    } else {
        Check::reason(
            "touch-targets",
            Status::Unavailable,
            format!(
                "screenshots missing for breakpoints: {}",
                missing.join(", ")
            ),
        )
    });

    out.push(if input.sibling_diff_present {
        Check::new("sibling-diff", Status::Pass).with("source", json!(SIBLING_DIFF_PATH))
    } else {
        Check::reason(
            "sibling-diff",
            Status::Unavailable,
            format!("{} absent", SIBLING_DIFF_PATH),
        )
    });

    out
}

/// Total bytes recorded in the baseline. A missing or non-numeric
/// `totalBytes` reads as 0, matching the script's `?? 0`.
fn baseline_total(raw: &str) -> Result<i64, String> {
    let doc: Value = serde_json::from_str(raw).map_err(|e| e.to_string())?;
    Ok(doc
        .get("totalBytes")
        .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
        .unwrap_or(0))
}

/// First 3-4 digit run in a path, as the script's `/(\d{3,4})/` match.
fn breakpoint_in_path(path: &str) -> Option<u32> {
    let re = Regex::new("[0-9]{3,4}").expect("static digit pattern is valid");
    re.find(path).and_then(|m| m.as_str().parse::<u32>().ok())
}

/// Parses banned-words.md. Structural rows come from the third column of
/// `## Structural` tables and must start with `\` or `[`. Vocabulary rows come
/// from the first column of `## Vocabulary` tables, with backticks and double
/// quotes removed.
pub fn parse_banned_words(markdown: &str) -> BannedWords {
    let structural: Vec<String> = table_rows(markdown, |heading| {
        heading.to_lowercase().contains("structural")
    })
    .into_iter()
    .filter_map(|cells| cells.get(2).cloned())
    .map(|detection| detection.replace('`', "").trim().to_string())
    .filter(|d| d.starts_with('\\') || d.starts_with('['))
    .collect();

    let vocabulary: Vec<String> = table_rows(markdown, |heading| {
        heading.to_lowercase().contains("vocabulary")
    })
    .into_iter()
    .filter_map(|cells| cells.first().cloned())
    .map(|term| {
        term.replace(|c: char| c == '`' || c == '"', "")
            .trim()
            .to_string()
    })
    .filter(|t| !t.is_empty())
    .collect();

    BannedWords {
        structural,
        vocabulary,
    }
}

fn is_level2_heading(line: &str) -> bool {
    line.strip_prefix("##")
        .map_or(false, |rest| rest.starts_with(char::is_whitespace))
}

fn is_header_label(first: &str) -> bool {
    matches!(
        first.to_lowercase().as_str(),
        "pattern" | "word / phrase" | "rule"
    )
}

/// Pipe-table rows under each `## ` heading whose line satisfies
/// `heading_matches`. Divider rows and header rows are skipped.
fn table_rows(markdown: &str, heading_matches: impl Fn(&str) -> bool) -> Vec<Vec<String>> {
    let mut rows = Vec::new();
    let mut in_section = false;
    for line in markdown.split('\n') {
        if is_level2_heading(line) {
            in_section = heading_matches(line);
        } else if in_section && line.starts_with('|') {
            let parts: Vec<&str> = line.split('|').collect();
            let cells: Vec<String> = parts[1..parts.len() - 1]
                .iter()
                .map(|c| c.trim().to_string())
                .collect();
            let Some(first) = cells.first() else {
                continue;
            };
            let divider = !first.is_empty() && first.chars().all(|c| c == '-');
            if divider || is_header_label(first) {
                continue;
            }
            rows.push(cells);
        }
    }
    rows
}

/// Converts `\xE2\x80\x94`-style byte escapes to the non-ASCII characters they
/// spell. ASCII-only results are dropped. Malformed escapes decode lossily, so
/// they can never flag ordinary spaces. Returns `None` when nothing remains.
fn bytes_to_pattern(spec: &str) -> Option<String> {
    let b = spec.as_bytes();
    let mut bytes: Vec<u8> = Vec::new();
    let mut i = 0usize;
    while i < b.len() {
        if i + 3 < b.len() && b[i] == b'\\' && b[i + 1] == b'x' {
            let hex = std::str::from_utf8(&b[i + 2..i + 4])
                .ok()
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(byte) = hex {
                bytes.push(byte);
                i += 4;
                continue;
            }
        }
        i += 1;
    }
    if bytes.is_empty() {
        return None;
    }
    let decoded = String::from_utf8_lossy(&bytes).into_owned();
    let glyphs: String = decoded.chars().filter(|c| (*c as u32) > 0x7f).collect();
    if glyphs.is_empty() {
        None
    } else {
        Some(glyphs)
    }
}

/// Non-overlapping, case-insensitive whole-word occurrences of `term`, using
/// ASCII word boundaries as the script's JavaScript `\b` did.
pub fn count_word_matches(text: &str, term: &str) -> usize {
    let pattern = format!("(?i)(?-u:\\b){}(?-u:\\b)", regex::escape(term));
    Regex::new(&pattern)
        .expect("escaped literal with ASCII word boundaries is a valid pattern")
        .find_iter(text)
        .count()
}

/// Splits after `.`, `!` or `?` followed by whitespace, as the script's
/// `split(/(?<=[.!?])\s+/)`.
pub fn split_sentences(text: &str) -> Vec<&str> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut i = 0usize;
    while i < chars.len() {
        let (pos, c) = chars[i];
        let after_terminator = i > 0 && matches!(chars[i - 1].1, '.' | '!' | '?');
        if c.is_whitespace() && after_terminator {
            out.push(&text[start..pos]);
            while i < chars.len() && chars[i].1.is_whitespace() {
                i += 1;
            }
            start = if i < chars.len() {
                chars[i].0
            } else {
                text.len()
            };
        } else {
            i += 1;
        }
    }
    out.push(&text[start..]);
    out
}

/// Waiver map from `gate-waivers.json`. Only string reasons with non-blank
/// text count. Missing or malformed input yields no waivers.
pub fn parse_waivers(raw: Option<&str>) -> BTreeMap<String, String> {
    let Some(text) = raw else {
        return BTreeMap::new();
    };
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(map)) => map
            .into_iter()
            .filter_map(|(id, reason)| match reason {
                Value::String(r) if !r.trim().is_empty() => Some((id, r)),
                _ => None,
            })
            .collect(),
        _ => BTreeMap::new(),
    }
}

/// Probes whether an executable is on this host. Injected so the wrapper stays
/// testable.
pub trait ToolProbe {
    fn present(&self, binary: &str) -> bool;
}

/// Real probe: runs `<binary> --version` with argv and no shell. Any spawn
/// error except "not found" counts as present, matching the script's ENOENT
/// check.
pub struct PathToolProbe;

impl ToolProbe for PathToolProbe {
    fn present(&self, binary: &str) -> bool {
        match std::process::Command::new(binary)
            .arg("--version")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        {
            Ok(_) => true,
            Err(e) => e.kind() != std::io::ErrorKind::NotFound,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateArgs {
    pub root: PathBuf,
    pub surface: PathBuf,
}

fn absolutize(raw: &str, cwd: &Path) -> PathBuf {
    path_utils::resolve(&cwd.join(raw).to_string_lossy())
}

/// Mirrors the script's `at(flag, fallback)`: the first occurrence of the flag
/// with a non-empty following value, otherwise the fallback. Unknown arguments
/// are ignored, as in the script.
pub fn parse_args(argv: &[String], cwd: &Path) -> GateArgs {
    let at = |flag: &str| -> PathBuf {
        argv.iter()
            .position(|a| a.as_str() == flag)
            .and_then(|i| argv.get(i + 1))
            .filter(|v| !v.is_empty())
            .map(|v| absolutize(v, cwd))
            .unwrap_or_else(|| cwd.to_path_buf())
    };
    GateArgs {
        root: at("--root"),
        surface: at("--surface"),
    }
}

fn has_extension(name: &str, exts: &[&str]) -> bool {
    let lower = name.to_ascii_lowercase();
    exts.iter().any(|ext| lower.ends_with(&format!(".{}", ext)))
}

/// Recursive listing matching the script's `walk`: skips `node_modules` and
/// dot-entries, and sorts for deterministic output. A missing directory is
/// empty, not an error.
fn walk(dir: &Path, exts: &[&str]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    let read = fs::read_dir(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    let mut entries = Vec::new();
    for entry in read {
        entries.push(entry.map_err(|e| e.to_string())?);
    }
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "node_modules" || name.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let meta = fs::metadata(&path).map_err(|e| format!("{}: {}", path.display(), e))?;
        if meta.is_dir() {
            out.extend(walk(&path, exts)?);
        } else if has_extension(&name, exts) {
            out.push(path);
        }
    }
    Ok(out)
}

fn read_lossy(path: &Path) -> Result<String, String> {
    fs::read(path)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|e| format!("{}: {}", path.display(), e))
}

fn relative_display(path: &Path, base: &Path) -> String {
    path.strip_prefix(base)
        .ok()
        .map(|r| r.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| path.to_string_lossy().into_owned())
}

/// Reads everything the evaluator needs from disk.
pub fn load_input(args: &GateArgs, tools: &dyn ToolProbe) -> Result<GateInput, String> {
    let surface = args.surface.as_path();

    let motion_plan_present = surface.join(MOTION_PLAN_FILE).exists();

    let gate_path = surface.join(MOTION_GATE_FILE);
    let motion_gate = if !gate_path.exists() {
        MotionGateFile::Absent
    } else {
        match fs::read_to_string(&gate_path) {
            Err(e) => MotionGateFile::Unreadable(e.to_string()),
            Ok(text) => match serde_json::from_str::<Value>(&text) {
                Ok(doc) => MotionGateFile::Parsed(doc),
                Err(e) => MotionGateFile::Unreadable(e.to_string()),
            },
        }
    };

    let mut text_files = Vec::new();
    for path in walk(surface, TEXT_EXTS)? {
        let text = read_lossy(&path)?;
        text_files.push(TextFile {
            path: relative_display(&path, surface),
            text,
        });
    }

    let banned_path = args.root.join(BANNED_WORDS_PATH);
    let banned_words_source = if banned_path.exists() {
        Some(read_lossy(&banned_path)?)
    } else {
        None
    };

    let mut asset_sizes = Vec::new();
    for path in walk(surface, ASSET_EXTS)? {
        let len = fs::metadata(&path)
            .map_err(|e| format!("{}: {}", path.display(), e))?
            .len();
        asset_sizes.push(len);
    }

    let baseline_path = surface.join(BASELINE_PATH);
    let baseline_source = if baseline_path.exists() {
        Some(read_lossy(&baseline_path)?)
    } else {
        None
    };

    let mut screenshot_paths = Vec::new();
    for path in walk(&surface.join(SCREENSHOTS_DIR), IMAGE_EXTS)? {
        screenshot_paths.push(path.to_string_lossy().into_owned());
    }

    let sibling_diff_present = surface.join(SIBLING_DIFF_PATH).exists();

    let mut tool_present = Vec::new();
    for &(_, bin) in TOOLS {
        tool_present.push((bin.to_string(), tools.present(bin)));
    }

    let waivers_path = surface.join(WAIVERS_PATH);
    let waivers_text = if waivers_path.exists() {
        fs::read_to_string(&waivers_path).ok()
    } else {
        None
    };
    let waivers = parse_waivers(waivers_text.as_deref());

    Ok(GateInput {
        motion_plan_present,
        motion_gate,
        text_files,
        banned_words_source,
        asset_sizes,
        baseline_source,
        screenshot_paths,
        sibling_diff_present,
        tool_present,
        waivers,
    })
}

fn write_report(report: &Value, surface: &Path) -> Result<PathBuf, String> {
    let path = surface.join(REPORT_PATH);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("{}: {}", dir.display(), e))?;
    }
    let body = serde_json::to_string_pretty(report).map_err(|e| e.to_string())?;
    fs::write(&path, format!("{}\n", body)).map_err(|e| format!("{}: {}", path.display(), e))?;
    Ok(path)
}

/// Process entry for `designer/design-gate`. Returns the exit code.
pub fn run_cli(
    argv: &[String],
    cwd: &Path,
    tools: &dyn ToolProbe,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    if argv
        .iter()
        .any(|a| a.as_str() == "--help" || a.as_str() == "-h")
    {
        let _ = writeln!(out, "{}", USAGE);
        return 0;
    }
    let args = parse_args(argv, cwd);
    let input = match load_input(&args, tools) {
        Ok(input) => input,
        Err(message) => {
            let _ = writeln!(err, "design-gate: {}", message);
            return 1;
        }
    };
    let gate = evaluate(&input);
    let report = gate.to_json();
    let written = match write_report(&report, &args.surface) {
        Ok(path) => path,
        Err(message) => {
            let _ = writeln!(err, "design-gate: cannot write report: {}", message);
            return 1;
        }
    };
    let body = serde_json::to_string_pretty(&report).unwrap_or_default();
    let _ = writeln!(out, "{}", body);
    let shown = written
        .strip_prefix(cwd)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| written.to_string_lossy().into_owned());
    let _ = writeln!(err, "gate report: {}", shown);
    if gate.passed() {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BANNED_FIXTURE: &str = "## How to use\n\nnotes\n\n## Structural (all brands — hard block)\n\n| Pattern | Reason | Detection |\n| --- | --- | --- |\n| `—` (U+2014) | LLM tell | `\\xE2\\x80\\x94` |\n| `\"smart\"` | smart quotes | `[\\xE2\\x80\\x9C\\xE2\\x80\\x9D]` |\n\n## Vocabulary (all brands — hard block)\n\n| Word / phrase | Reason | Replacement |\n| --- | --- | --- |\n| \"elevate\" | filler | remove |\n| \"AI-powered (unless product literally is AI)\" | inflated | remove |\n\n## Voice (per brand)\n\n| \"ignored\" | x | y |\n";

    struct FakeTools(Vec<&'static str>);

    impl ToolProbe for FakeTools {
        fn present(&self, binary: &str) -> bool {
            self.0.iter().any(|p| *p == binary)
        }
    }

    fn clean_input() -> GateInput {
        GateInput {
            motion_plan_present: true,
            motion_gate: MotionGateFile::Parsed(json!({"verdict": "pass"})),
            text_files: vec![TextFile {
                path: "index.html".to_string(),
                text: "Plain copy about the product.".to_string(),
            }],
            banned_words_source: Some(BANNED_FIXTURE.to_string()),
            asset_sizes: vec![1000],
            baseline_source: Some("{\"totalBytes\": 1000}".to_string()),
            screenshot_paths: BREAKPOINTS
                .iter()
                .map(|bp| format!("/surface/artifacts/qa/screenshots/shot-{}.png", bp))
                .collect(),
            sibling_diff_present: true,
            tool_present: vec![
                ("lighthouse".to_string(), false),
                ("axe".to_string(), false),
            ],
            waivers: BTreeMap::new(),
        }
    }

    fn find<'a>(report: &'a GateReport, id: &str) -> &'a Check {
        report
            .checks
            .iter()
            .find(|c| c.id == id)
            .expect("check present in report")
    }

    #[test]
    fn banned_words_parse_structural_and_vocabulary_tables_only() {
        let parsed = parse_banned_words(BANNED_FIXTURE);
        assert_eq!(
            parsed.structural,
            vec![
                "\\xE2\\x80\\x94".to_string(),
                "[\\xE2\\x80\\x9C\\xE2\\x80\\x9D]".to_string()
            ]
        );
        assert_eq!(
            parsed.vocabulary,
            vec![
                "elevate".to_string(),
                "AI-powered (unless product literally is AI)".to_string()
            ]
        );
    }

    #[test]
    fn byte_escapes_decode_to_typographic_glyphs() {
        assert_eq!(
            bytes_to_pattern("\\xE2\\x80\\x94"),
            Some("\u{2014}".to_string())
        );
        assert_eq!(
            bytes_to_pattern("[\\xE2\\x80\\x9C\\xE2\\x80\\x9D]"),
            Some("\u{201C}\u{201D}".to_string())
        );
        assert_eq!(bytes_to_pattern("no escapes here"), None);
        // A malformed escape decodes to replacement characters only, never ASCII.
        let malformed = bytes_to_pattern("\\xE2\\x2019").unwrap_or_default();
        assert!(!malformed.contains(' '));
    }

    #[test]
    fn vocabulary_counts_whole_words_case_insensitively() {
        assert_eq!(
            count_word_matches("We elevate. Elevated work, elevate!", "elevate"),
            2
        );
        // Faithful to the script's JavaScript \b semantics: a term that ends in a
        // non-word character (here ')') cannot satisfy a trailing \b before a space,
        // so this vocabulary row never matches. Reported as a known script quirk.
        assert_eq!(
            count_word_matches(
                "An AI-powered (unless product literally is AI) tool",
                "AI-powered (unless product literally is AI)"
            ),
            0
        );
    }

    #[test]
    fn em_dash_fails_typography_and_vocabulary_hit_fails_banned_words() {
        let mut input = clean_input();
        input.text_files = vec![TextFile {
            path: "index.html".to_string(),
            text: "We elevate\u{2014}fast.".to_string(),
        }];
        let report = evaluate(&input);
        assert_eq!(find(&report, "banned-words").status, Status::Fail);
        assert_eq!(find(&report, "typography").status, Status::Fail);
        assert!(report.blocking().contains(&"typography"));
        assert!(!report.passed());
    }

    #[test]
    fn missing_text_and_missing_banned_words_are_unavailable_not_pass() {
        let mut none = clean_input();
        none.text_files.clear();
        let report = evaluate(&none);
        assert_eq!(find(&report, "banned-words").status, Status::Unavailable);

        let mut no_list = clean_input();
        no_list.banned_words_source = None;
        let report = evaluate(&no_list);
        assert_eq!(
            find(&report, "typography").detail.get("reason"),
            Some(&json!("skills/designer/references/banned-words.md absent"))
        );
    }

    #[test]
    fn absent_motion_gate_fails_with_its_reason() {
        let mut input = clean_input();
        input.motion_gate = MotionGateFile::Absent;
        let report = evaluate(&input);
        let check = find(&report, "motion-gate-verdict");
        assert_eq!(check.status, Status::Fail);
        assert_eq!(
            check.detail.get("reason"),
            Some(&json!("motion-gate.json absent"))
        );
        assert!(report
            .checks
            .iter()
            .all(|c| c.id != "motion-plan-present" || c.status == Status::Pass));
    }

    #[test]
    fn bundle_growth_beyond_ten_percent_fails() {
        let mut grew = clean_input();
        grew.asset_sizes = vec![1200];
        assert_eq!(find(&evaluate(&grew), "bundle-delta").status, Status::Fail);

        let mut within = clean_input();
        within.asset_sizes = vec![1050];
        assert_eq!(
            find(&evaluate(&within), "bundle-delta").status,
            Status::Pass
        );
    }

    #[test]
    fn breakpoint_is_first_three_or_four_digit_run_in_path() {
        assert_eq!(breakpoint_in_path("/a/home-1440.png"), Some(1440));
        assert_eq!(breakpoint_in_path("/a/12345.png"), Some(1234));
        assert_eq!(breakpoint_in_path("/a/none.png"), None);
    }

    #[test]
    fn long_sentence_is_warn_only_and_sentences_split_on_terminators() {
        assert_eq!(
            split_sentences("One. Two three.  Four"),
            vec!["One.", "Two three.", "Four"]
        );
        let long: String = std::iter::repeat("word ").take(41).collect::<String>() + "end.";
        let mut input = clean_input();
        input.text_files = vec![TextFile {
            path: "index.html".to_string(),
            text: long,
        }];
        let report = evaluate(&input);
        assert_eq!(find(&report, "anti-patterns").status, Status::Warn);
        assert!(!report.blocking().contains(&"anti-patterns"));
    }

    #[test]
    fn tool_checks_never_pass_and_waivers_only_clear_non_pass_checks() {
        let mut input = clean_input();
        input.tool_present = vec![("lighthouse".to_string(), true), ("axe".to_string(), false)];
        let report = evaluate(&input);
        assert_eq!(find(&report, "lighthouse").status, Status::Unavailable);
        assert_eq!(
            find(&report, "lighthouse").detail.get("reason"),
            Some(&json!("lighthouse present but no run target configured"))
        );
        assert_eq!(report.blocking(), vec!["lighthouse", "axe-core"]);

        let waivers = parse_waivers(Some(
            "{\"lighthouse\": \"no run target yet\", \"axe-core\": \"  \", \"typography\": 3}",
        ));
        input.waivers = waivers;
        let waived = evaluate(&input);
        assert_eq!(waived.blocking(), vec!["axe-core"]);
        assert!(find(&waived, "lighthouse").waiver.is_some());
        assert!(find(&waived, "typography").waiver.is_none());
    }

    #[test]
    fn fully_waived_surface_passes_and_report_counts_are_consistent() {
        let mut input = clean_input();
        input.waivers = parse_waivers(Some(
            "{\"lighthouse\": \"no run target\", \"axe-core\": \"no run target\"}",
        ));
        let report = evaluate(&input);
        assert!(report.passed());
        let json = report.to_json();
        assert_eq!(json["verdict"], json!("pass"));
        assert_eq!(json["counts"]["waived"], json!(2));
        assert_eq!(json["counts"]["total"], json!(report.checks.len()));
        assert_eq!(json["blocking"], json!([]));
    }

    #[test]
    fn default_inputs_fail_closed_on_unavailable_tool_checks() {
        let report = evaluate(&clean_input());
        assert!(!report.passed());
        assert_eq!(report.to_json()["verdict"], json!("fail"));
    }

    #[test]
    fn unreadable_baseline_is_a_bundle_fail_with_reason() {
        let mut input = clean_input();
        input.baseline_source = Some("{not json".to_string());
        let check = find(&evaluate(&input), "bundle-delta").clone();
        assert_eq!(check.status, Status::Fail);
        assert!(check
            .detail
            .get("reason")
            .and_then(Value::as_str)
            .map_or(false, |r| r
                .starts_with("artifacts/qa/bundle-baseline.json unreadable")));
    }

    #[test]
    fn fake_tool_probe_reports_configured_presence() {
        let tools = FakeTools(vec!["axe"]);
        assert!(tools.present("axe"));
        assert!(!tools.present("lighthouse"));
    }
}
