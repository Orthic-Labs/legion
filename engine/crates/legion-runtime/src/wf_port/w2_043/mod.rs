//! Port of chunk `w2_043` (area `src/lib/design-gate.mjs`, target crate
//! `legion-runtime`).
//!
//! Phase 5d deterministic design gate. Delegated to Designer craft plus QA's
//! functional/runtime validation, with
//! `skills/designer/specialists/surface-design/GUIDE.md` §5d. Contract:
//! verify `motion-plan.md` and `motion-gate.json` exist and the motion gate
//! passed, run the deterministic checks over the built surface, emit
//! `artifacts/qa/gate.json` with per-check results aggregated into one
//! verdict; `pass` requires every check green or explicitly waived with a
//! reason.
//!
//! A check that cannot run reports `Unavailable`, never `Pass`: a
//! verification that found nothing to check has not checked anything, so an
//! unavailable required check fails the gate rather than silently clearing
//! it. This mirrors `runDesignGate`/`loadBannedWords`/`writeGateReport` in
//! `src/lib/design-gate.mjs` line for line; no browser (`lighthouse`/`axe`)
//! run target is wired here either, matching the JS, which only probes for
//! the binaries on `PATH` and reports `unavailable` either way.
//!
//! Not ported: nothing. The whole file is deterministic Node `fs`/`child_process`
//! glue with no DOM dependency, so it all ported.

use regex::Regex;
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// `BREAKPOINTS` from the JS module.
pub const BREAKPOINTS: [u32; 5] = [360, 768, 1024, 1440, 1920];

fn text_ext_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\.(?:html?|md|txt)$").unwrap())
}

fn asset_ext_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\.(?:js|mjs|cjs|css)$").unwrap())
}

fn heading_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^##\s").unwrap())
}

fn pipe_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^\|").unwrap())
}

fn dash_only_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"^-+$").unwrap())
}

fn header_word_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)^(Pattern|Word / phrase|Rule)$").unwrap())
}

fn xhex_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)\\x([0-9A-Fa-f]{2})").unwrap())
}

/// Rows of a pipe table under `## <heading>`, first column only (mirrors
/// `tableRows`). `heading_matches` is applied to the full `## ...` heading
/// line, exactly as the JS regex is (it is not anchored to the heading
/// text alone).
fn table_rows(markdown: &str, heading_matches: impl Fn(&str) -> bool) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    let mut in_section = false;
    for line in markdown.split('\n') {
        if heading_line_re().is_match(line) {
            in_section = heading_matches(line);
        } else if in_section && pipe_line_re().is_match(line) {
            let mut cells: Vec<String> = line.split('|').map(|c| c.trim().to_string()).collect();
            // JS: line.split('|').slice(1, -1) — drop the leading/trailing
            // empty cells produced by a line that starts and ends with '|'.
            if cells.len() >= 2 {
                cells.remove(0);
                cells.pop();
            } else {
                cells.clear();
            }
            if cells.is_empty() {
                continue;
            }
            let first = &cells[0];
            if dash_only_re().is_match(first) || header_word_re().is_match(first) {
                continue;
            }
            out.push(cells);
        }
    }
    out
}

/// Banned vocabulary read from the documented source of truth (mirrors
/// `loadBannedWords`).
#[derive(Debug, Clone, Default)]
pub struct BannedWords {
    pub available: bool,
    pub structural: Vec<String>,
    pub vocabulary: Vec<String>,
}

/// Reads banned vocabulary from `skills/designer/references/banned-words.md`
/// under `root` rather than duplicating it here — the markdown is what
/// authors maintain, so a second copy would drift.
pub fn load_banned_words(root: &Path) -> BannedWords {
    let path = root.join("skills/designer/references/banned-words.md");
    let md = match fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return BannedWords::default(),
    };
    let structural_re = Regex::new(r"(?i)structural").unwrap();
    let vocabulary_re = Regex::new(r"(?i)vocabulary").unwrap();
    let leading_backslash_or_bracket = Regex::new(r"^[\\\[]").unwrap();

    let structural = table_rows(&md, |line| structural_re.is_match(line))
        .into_iter()
        .filter_map(|row| row.get(2).cloned())
        .filter(|d| !d.is_empty())
        .map(|d| d.replace('`', "").trim().to_string())
        .filter(|d| leading_backslash_or_bracket.is_match(d))
        .collect();

    let vocabulary = table_rows(&md, |line| vocabulary_re.is_match(line))
        .into_iter()
        .filter_map(|row| row.first().cloned())
        .map(|t| t.replace(['`', '"'], "").trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();

    BannedWords {
        available: true,
        structural,
        vocabulary,
    }
}

/// Decodes `\xE2\x80\x94`-style byte escapes into the characters they
/// match, keeping only non-ASCII glyphs (mirrors `bytesToPattern`). Every
/// structural rule targets a typographic glyph, and at least one row in
/// `banned-words.md` is malformed (`\xE2\x2019` for U+2019), which decodes
/// to a space and would otherwise flag every space in the build as a smart
/// quote — the ASCII filter is load-bearing, not decorative.
pub fn bytes_to_pattern(spec: &str) -> Option<String> {
    let bytes: Vec<u8> = xhex_re()
        .captures_iter(spec)
        .filter_map(|c| u8::from_str_radix(&c[1], 16).ok())
        .collect();
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

fn walk(dir: &Path, test: &Regex, out: &mut Vec<PathBuf>) {
    if !dir.exists() {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut names: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    names.sort_by_key(|e| e.file_name());
    for entry in names {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str == "node_modules" || name_str.starts_with('.') {
            continue;
        }
        let path = entry.path();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if is_dir {
            walk(&path, test, out);
        } else if test.is_match(&name_str) {
            out.push(path);
        }
    }
}

/// Status of one check (mirrors the `status` strings used throughout the
/// JS: `"pass" | "fail" | "unavailable" | "warn"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Fail,
    Unavailable,
    Warn,
}

/// One vocabulary hit (mirrors the `{ path, term, count }` objects pushed
/// to `vocabHits`).
#[derive(Debug, Clone, Serialize)]
pub struct VocabHit {
    pub path: String,
    pub term: String,
    pub count: usize,
}

/// One structural/typography hit (mirrors `typoHits`).
#[derive(Debug, Clone, Serialize)]
pub struct TypoHit {
    pub path: String,
    pub pattern: String,
    pub count: usize,
}

/// One anti-pattern hit (mirrors `antiHits`).
#[derive(Debug, Clone, Serialize)]
pub struct AntiHit {
    pub path: String,
    pub pattern: String,
    pub count: usize,
}

/// One check result (mirrors the loose `check(id, status, detail)` object
/// shape; fields are `None`/empty unless that check populates them).
#[derive(Debug, Clone, Serialize)]
pub struct Check {
    pub id: String,
    pub status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patterns: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub vocab_hits: Vec<VocabHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vocab_total: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub typo_hits: Vec<TypoHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typo_total: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub anti_hits: Vec<AntiHit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anti_total: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub breakpoints: Vec<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waived: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub waiver_reason: Option<String>,
}

impl Check {
    fn new(id: &str, status: Status) -> Self {
        Check {
            id: id.to_string(),
            status,
            reason: None,
            scanned: None,
            terms: None,
            patterns: None,
            vocab_hits: Vec::new(),
            vocab_total: None,
            typo_hits: Vec::new(),
            typo_total: None,
            anti_hits: Vec::new(),
            anti_total: None,
            baseline: None,
            total_bytes: None,
            delta: None,
            breakpoints: Vec::new(),
            source: None,
            waived: None,
            waiver_reason: None,
        }
    }

    fn fail(id: &str, reason: impl Into<String>) -> Self {
        let mut c = Check::new(id, Status::Fail);
        c.reason = Some(reason.into());
        c
    }

    fn unavailable(id: &str, reason: impl Into<String>) -> Self {
        let mut c = Check::new(id, Status::Unavailable);
        c.reason = Some(reason.into());
        c
    }
}

fn motion_checks(surface: &Path) -> Vec<Check> {
    let plan = surface.join("motion-plan.md");
    let gate = surface.join("motion-gate.json");
    let mut results = Vec::new();
    results.push(if plan.exists() {
        Check::new("motion-plan-present", Status::Pass)
    } else {
        Check::fail("motion-plan-present", "motion-plan.md absent")
    });
    let gate_text = match fs::read_to_string(&gate) {
        Ok(t) => t,
        Err(_) => {
            results.push(Check::fail("motion-gate-verdict", "motion-gate.json absent"));
            return results;
        }
    };
    match serde_json::from_str::<serde_json::Value>(&gate_text) {
        Ok(v) => {
            let verdict = v.get("verdict").and_then(|x| x.as_str());
            if verdict == Some("pass") {
                results.push(Check::new("motion-gate-verdict", Status::Pass));
            } else {
                let shown = verdict.unwrap_or("absent");
                results.push(Check::fail(
                    "motion-gate-verdict",
                    format!("motion gate verdict is {shown}"),
                ));
            }
        }
        Err(e) => {
            results.push(Check::fail(
                "motion-gate-verdict",
                format!("motion-gate.json unreadable: {e}"),
            ));
        }
    }
    results
}

fn text_checks(root: &Path, surface: &Path) -> Vec<Check> {
    let mut files = Vec::new();
    walk(surface, text_ext_re(), &mut files);
    let banned = load_banned_words(root);

    if files.is_empty() {
        // No text to scan is not a pass: the gate would report green over
        // nothing.
        return vec![
            Check::unavailable("banned-words", "no built HTML/markdown found under the surface"),
            Check::unavailable("typography", "no built HTML/markdown found under the surface"),
            Check::unavailable("anti-patterns", "no built HTML/markdown found under the surface"),
        ];
    }
    if !banned.available {
        return vec![
            Check::unavailable("banned-words", "skills/designer/references/banned-words.md absent"),
            Check::unavailable("typography", "skills/designer/references/banned-words.md absent"),
            Check::unavailable("anti-patterns", "skills/designer/references/banned-words.md absent"),
        ];
    }

    let read: Vec<(String, String)> = files
        .iter()
        .map(|f| {
            let rel = f
                .strip_prefix(surface)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| f.to_string_lossy().into_owned());
            let path_str = if rel.is_empty() {
                f.to_string_lossy().into_owned()
            } else {
                rel
            };
            let text = fs::read_to_string(f).unwrap_or_default();
            (path_str, text)
        })
        .collect();

    let mut results = Vec::new();

    let mut vocab_hits = Vec::new();
    for (path, text) in &read {
        for term in &banned.vocabulary {
            let escaped = regex::escape(term);
            let re = Regex::new(&format!(r"(?i)\b{escaped}\b")).unwrap();
            let n = re.find_iter(text).count();
            if n > 0 {
                vocab_hits.push(VocabHit {
                    path: path.clone(),
                    term: term.clone(),
                    count: n,
                });
            }
        }
    }
    if vocab_hits.is_empty() {
        let mut c = Check::new("banned-words", Status::Pass);
        c.scanned = Some(read.len());
        c.terms = Some(banned.vocabulary.len());
        results.push(c);
    } else {
        let total = vocab_hits.len();
        let mut c = Check::new("banned-words", Status::Fail);
        c.vocab_total = Some(total);
        c.vocab_hits = vocab_hits.into_iter().take(25).collect();
        results.push(c);
    }

    let mut typo_hits = Vec::new();
    for spec in &banned.structural {
        let literal = match bytes_to_pattern(spec) {
            Some(l) => l,
            None => continue,
        };
        for (path, text) in &read {
            let n = text.chars().filter(|c| literal.contains(*c)).count();
            if n > 0 {
                typo_hits.push(TypoHit {
                    path: path.clone(),
                    pattern: spec.clone(),
                    count: n,
                });
            }
        }
    }
    if typo_hits.is_empty() {
        let mut c = Check::new("typography", Status::Pass);
        c.scanned = Some(read.len());
        c.patterns = Some(banned.structural.len());
        results.push(c);
    } else {
        let total = typo_hits.len();
        let mut c = Check::new("typography", Status::Fail);
        c.typo_total = Some(total);
        c.typo_hits = typo_hits.into_iter().take(25).collect();
        results.push(c);
    }

    // Anti-patterns: structural tells that survive vocabulary and
    // typography.
    let sentence_split_re = Regex::new(r"(?:[.!?])\s+").unwrap();
    let mut anti_hits = Vec::new();
    for (path, text) in &read {
        // JS uses a lookbehind split `(?<=[.!?])\s+`, keeping the
        // punctuation on the preceding sentence; `regex` has no lookbehind
        // support, but word counts per split segment are unaffected by
        // where the punctuation lands, so this yields the same counts.
        let long = sentence_split_re
            .split(text)
            .filter(|s| s.trim().split_whitespace().count() > 40)
            .count();
        if long > 0 {
            anti_hits.push(AntiHit {
                path: path.clone(),
                pattern: "sentence > 40 words".to_string(),
                count: long,
            });
        }
    }
    if anti_hits.is_empty() {
        let mut c = Check::new("anti-patterns", Status::Pass);
        c.scanned = Some(read.len());
        results.push(c);
    } else {
        let total = anti_hits.len();
        let mut c = Check::new("anti-patterns", Status::Warn);
        c.anti_total = Some(total);
        c.anti_hits = anti_hits.into_iter().take(25).collect();
        results.push(c);
    }

    results
}

fn tool_checks(env: &HashMap<String, String>) -> Vec<Check> {
    let mut results = Vec::new();
    for (id, bin) in [("lighthouse", "lighthouse"), ("axe-core", "axe")] {
        // Probe an argv executable directly, exactly like the JS
        // (`spawnSync(bin, ['--version'], { shell: false })`): an
        // executable that returns non-zero to `--version` is still
        // present, only a spawn error means it is missing.
        let mut cmd = Command::new(bin);
        cmd.arg("--version");
        cmd.env_clear();
        cmd.envs(env.iter());
        let present = cmd.output().is_ok();
        let reason = if present {
            format!("{bin} present but no run target configured")
        } else {
            format!("{bin} not on PATH")
        };
        // Capability-gate rather than assume: an absent toolchain is
        // reported loudly and is not a pass.
        results.push(Check::unavailable(id, reason));
    }
    results
}

fn budget_checks(surface: &Path) -> Vec<Check> {
    let mut assets = Vec::new();
    walk(surface, asset_ext_re(), &mut assets);
    let mut results = Vec::new();
    let baseline_path = surface.join("artifacts/qa/bundle-baseline.json");
    let total: u64 = assets
        .iter()
        .filter_map(|f| fs::metadata(f).ok())
        .map(|m| m.len())
        .sum();

    if assets.is_empty() {
        results.push(Check::unavailable(
            "bundle-delta",
            "no js/css assets found under the surface",
        ));
    } else if !baseline_path.exists() {
        let mut c = Check::unavailable("bundle-delta", "artifacts/qa/bundle-baseline.json absent");
        c.total_bytes = Some(total);
        results.push(c);
    } else {
        let baseline: u64 = fs::read_to_string(&baseline_path)
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .and_then(|v| v.get("totalBytes").and_then(|x| x.as_u64()))
            .unwrap_or(0);
        let delta = total as i64 - baseline as i64;
        let status = if (delta as f64) > (baseline as f64) * 0.1 {
            Status::Fail
        } else {
            Status::Pass
        };
        let mut c = Check::new("bundle-delta", status);
        c.baseline = Some(baseline);
        c.total_bytes = Some(total);
        c.delta = Some(delta);
        results.push(c);
    }

    let screenshots_dir = surface.join("artifacts/qa/screenshots");
    let img_re = Regex::new(r"(?i)\.(?:png|jpe?g|webp)$").unwrap();
    let mut shot_files = Vec::new();
    walk(&screenshots_dir, &img_re, &mut shot_files);
    let digits_re = Regex::new(r"(\d{3,4})").unwrap();
    let shots: Vec<u32> = shot_files
        .iter()
        .filter_map(|f| {
            let name = f.file_name()?.to_string_lossy().into_owned();
            digits_re
                .captures(&name)
                .and_then(|c| c.get(1))
                .and_then(|m| m.as_str().parse::<u32>().ok())
        })
        .collect();
    let missing: Vec<u32> = BREAKPOINTS
        .iter()
        .copied()
        .filter(|bp| !shots.contains(bp))
        .collect();
    if missing.is_empty() {
        let mut c = Check::new("touch-targets", Status::Pass);
        c.breakpoints = BREAKPOINTS.to_vec();
        results.push(c);
    } else {
        let list = missing.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ");
        results.push(Check::unavailable(
            "touch-targets",
            format!("screenshots missing for breakpoints: {list}"),
        ));
    }

    let sibling_path = surface.join("artifacts/qa/sibling-diff.json");
    if sibling_path.exists() {
        let mut c = Check::new("sibling-diff", Status::Pass);
        c.source = Some("artifacts/qa/sibling-diff.json".to_string());
        results.push(c);
    } else {
        results.push(Check::unavailable("sibling-diff", "artifacts/qa/sibling-diff.json absent"));
    }

    results
}

/// Waivers: `{ "<check-id>": "reason" }` at `artifacts/qa/gate-waivers.json`
/// (mirrors `loadWaivers`).
fn load_waivers(surface: &Path) -> HashMap<String, String> {
    let path = surface.join("artifacts/qa/gate-waivers.json");
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return HashMap::new(),
    };
    let raw: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(_) => return HashMap::new(),
    };
    let mut out = HashMap::new();
    if let Some(map) = raw.as_object() {
        for (k, v) in map {
            if let Some(s) = v.as_str() {
                if !s.trim().is_empty() {
                    out.insert(k.clone(), s.to_string());
                }
            }
        }
    }
    out
}

/// Counts of each status across all checks (mirrors `report.counts`).
#[derive(Debug, Clone, Serialize)]
pub struct Counts {
    pub total: usize,
    pub pass: usize,
    pub fail: usize,
    pub unavailable: usize,
    pub warn: usize,
    pub waived: usize,
}

/// The full gate report (mirrors the object returned by `runDesignGate`).
#[derive(Debug, Clone, Serialize)]
pub struct GateReport {
    pub schema_version: u32,
    pub kind: String,
    pub phase: String,
    pub verdict: Status,
    pub counts: Counts,
    pub blocking: Vec<String>,
    pub checks: Vec<Check>,
}

/// Inputs to [`run_design_gate`] (mirrors the `{ root, surface, env }`
/// options object). `env` defaults to `process.env` in JS; callers here
/// pass an explicit map (e.g. from `std::env::vars().collect()`).
pub struct GateOptions<'a> {
    pub root: &'a Path,
    pub surface: &'a Path,
    pub env: HashMap<String, String>,
}

/// Runs every deterministic check and aggregates one verdict (mirrors
/// `runDesignGate`). A waiver must carry a reason; anything else non-green
/// blocks. `warn` never blocks on its own, matching the JS's `blocking`
/// filter (`status !== 'pass' && status !== 'warn' && !waived`).
pub fn run_design_gate(opts: GateOptions<'_>) -> GateReport {
    let mut checks = Vec::new();
    checks.extend(motion_checks(opts.surface));
    checks.extend(text_checks(opts.root, opts.surface));
    checks.extend(tool_checks(&opts.env));
    checks.extend(budget_checks(opts.surface));

    let waivers = load_waivers(opts.surface);
    for c in checks.iter_mut() {
        if c.status != Status::Pass {
            if let Some(reason) = waivers.get(&c.id) {
                c.waived = Some(true);
                c.waiver_reason = Some(reason.clone());
            }
        }
    }

    let blocking: Vec<String> = checks
        .iter()
        .filter(|c| c.status != Status::Pass && c.status != Status::Warn && c.waived != Some(true))
        .map(|c| c.id.clone())
        .collect();
    let verdict = if blocking.is_empty() { Status::Pass } else { Status::Fail };

    let counts = Counts {
        total: checks.len(),
        pass: checks.iter().filter(|c| c.status == Status::Pass).count(),
        fail: checks.iter().filter(|c| c.status == Status::Fail).count(),
        unavailable: checks.iter().filter(|c| c.status == Status::Unavailable).count(),
        warn: checks.iter().filter(|c| c.status == Status::Warn).count(),
        waived: checks.iter().filter(|c| c.waived == Some(true)).count(),
    };

    GateReport {
        schema_version: 1,
        kind: "legion-design-gate".to_string(),
        phase: "5d".to_string(),
        verdict,
        counts,
        blocking,
        checks,
    }
}

/// Writes `artifacts/qa/gate.json` under `surface` (mirrors
/// `writeGateReport`). Returns the written path.
pub fn write_gate_report(report: &GateReport, surface: &Path) -> std::io::Result<PathBuf> {
    let dir = surface.join("artifacts/qa");
    fs::create_dir_all(&dir)?;
    let path = dir.join("gate.json");
    let json = serde_json::to_string_pretty(report).unwrap_or_default();
    fs::write(&path, format!("{json}\n"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_pattern_decodes_em_dash() {
        assert_eq!(bytes_to_pattern(r"\xE2\x80\x94"), Some("\u{2014}".to_string()));
    }

    #[test]
    fn bytes_to_pattern_decodes_multiple_escapes_in_one_spec() {
        // The real banned-words.md smart-quote row: `[\xE2\x80\x98\xE2\x80\x99]`
        // (U+2018 and U+2019 inside a character class); bytes_to_pattern
        // extracts every `\xHH` run regardless of the surrounding literal
        // bracket syntax.
        assert_eq!(
            bytes_to_pattern(r"[\xE2\x80\x98\xE2\x80\x99]"),
            Some("\u{2018}\u{2019}".to_string())
        );
    }

    #[test]
    fn bytes_to_pattern_drops_a_decode_that_is_pure_ascii() {
        // \x41\x42 decodes to "AB", both ASCII; only non-ASCII glyphs
        // survive the filter, so this must be None, not "flag every A/B".
        assert_eq!(bytes_to_pattern(r"\x41\x42"), None);
    }

    #[test]
    fn bytes_to_pattern_none_without_escapes() {
        assert_eq!(bytes_to_pattern("no escapes here"), None);
    }

    #[test]
    fn table_rows_reads_pipe_table_under_matching_heading() {
        let md = "## Structural\n\n| Pattern | Reason | Detection |\n|---|---|---|\n| `\u{2014}` | x | `\\xE2\\x80\\x94` |\n\n## Other\n\n| A | B |\n|---|---|\n| z | y |\n";
        let rows = table_rows(md, |l| l.to_lowercase().contains("structural"));
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][2], "`\\xE2\\x80\\x94`");
    }
}
