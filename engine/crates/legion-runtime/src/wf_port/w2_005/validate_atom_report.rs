//! Port of `skills/foundation/scripts/validate_atom_report.py`: structural,
//! contamination, and high-risk semantic checks for Atom reports (markdown
//! pipe tables).
//!
//! Kept in this module's directory (rather than a fresh top-level `wf_port`
//! packet) because the porting brief forbids editing `wf_port/mod.rs`, and
//! `w2_005` is already the home for the sibling "validate a markdown report,
//! print `FAIL: N defect(s)` or `PASS: ...`" shape (`validate-external-review-packet.py`).
//!
//! All filesystem access (reading the report/manifest, checking evidence
//! files exist, hashing files for the PASS receipt, the clock) is behind
//! [`ReportFs`] so [`validate`] itself stays pure and unit-testable; only
//! [`run`] touches the trait.

use std::collections::{BTreeMap, HashMap};

use regex::Regex;

pub fn headers(mode: &str) -> Option<&'static [&'static str]> {
    match mode {
        "inventory" => Some(&[
            "Platform",
            "Domain",
            "Atom",
            "Definition / boundary",
            "Source evidence",
        ]),
        "stage2" => Some(&[
            "Scope",
            "Domain",
            "Atom",
            "Repository mechanisms",
            "Best observed",
            "Best combined",
            "Rationale / tradeoffs",
            "Source evidence",
        ]),
        "stage3" => Some(&[
            "Scope",
            "Domain",
            "Atom",
            "Current product",
            "Repository mechanisms",
            "Best observed",
            "Best combined",
            "Rationale / tradeoffs",
            "Source evidence",
        ]),
        "final" => Some(&[
            "Scope",
            "Domain",
            "Atom",
            "Best observed",
            "Recommended implementation",
            "Why / tradeoffs",
            "Source evidence",
            "Confidence",
        ]),
        // Header lists below are exactly those of the historical validator
        // (`267bae38:tools/skills/foundation/scripts/validate_atom_report.py`, `HEADERS`).
        "repo-ledger" => Some(&[
            "Repository",
            "Behavior ID",
            "Platform",
            "Domain hint",
            "Observable behavior",
            "Boundary clues",
            "Production evidence",
            "Live consumer",
            "State / fallback / safeguards",
        ]),
        "canon" => Some(&[
            "Scope",
            "Domain",
            "Atom ID",
            "Atom",
            "Boundary",
            "Repository provenance",
        ]),
        "mechanism-cards" => Some(&[
            "Scope",
            "Domain",
            "Atom ID",
            "Repository",
            "Platform",
            "Status",
            "Production evidence",
            "Live consumer",
            "Mechanism",
            "State / fallback / safeguards",
            "Criteria assessment",
        ]),
        "handoff" => Some(&[
            "Scope",
            "Domain",
            "Atom ID",
            "Deficit",
            "Scope / promotion",
            "Required state / action",
            "Recommended behavior",
            "Reuse disposition",
            "Acceptance / qualification",
            "Source evidence",
        ]),
        _ => None,
    }
}

const FORBIDDEN_EVIDENCE: &[&str] = &[
    ".cache/",
    ".right-release/",
    ".fingerprint/",
    "node_modules/",
    "target/debug/",
    "target/release/",
    "deriveddata/",
    "heardright-recording-lifecycle-review/",
];

const BOILERPLATE: &[&str] = &[
    "combine observed strengths without assuming parity",
    "combine strongest observed mechanism with explicit state",
    "strongest dedicated source match; recovery/persistence depth remains qualified",
    "state/persistence/fallback: unclear unless separately evidenced",
    "keep boundary explicit, observable, and testable",
];

/// `atom label (lowercase) -> AND-of-OR token groups`, matching Python's
/// `SEMANTIC_SIGNATURES`.
fn semantic_signatures() -> HashMap<&'static str, Vec<Vec<&'static str>>> {
    let mut m: HashMap<&'static str, Vec<Vec<&'static str>>> = HashMap::new();
    m.insert(
        "pill motion & relocation",
        vec![
            vec!["drag", "snap", "relocat", "move", "position", "anchor"],
            vec![
                "screen",
                "display",
                "coordinate",
                "geometry",
                "position",
                "anchor",
            ],
        ],
    );
    m.insert(
        "spoken send parser",
        vec![
            vec![
                "parse",
                "parser",
                "phrase",
                "utterance",
                "intent",
                "command",
            ],
            vec!["send", "submit"],
        ],
    );
    m.insert(
        "post-insert submit",
        vec![
            vec!["enter", "return", "submit"],
            vec!["insert", "delivery"],
            vec!["confirm", "verif", "evidence", "success"],
        ],
    );
    m.insert(
        "target snapshot & revalidation",
        vec![
            vec!["target", "focus"],
            vec!["revalid", "identity", "same target", "snapshot"],
        ],
    );
    m.insert(
        "clipboard transaction",
        vec![
            vec!["clipboard"],
            vec!["snapshot", "preserve", "save"],
            vec!["restore"],
        ],
    );
    m.insert(
        "background model download",
        vec![
            vec!["download", "transfer"],
            vec!["model", "artifact"],
            vec!["background", "resume", "resumable", "checkpoint"],
            vec!["validat", "checksum", "signature", "atomic"],
        ],
    );
    m.insert(
        "watchconnectivity bridge",
        vec![
            vec!["wcsession", "watchconnectivity", "watch session"],
            vec![
                "message",
                "applicationcontext",
                "userinfo",
                "file transfer",
                "payload",
            ],
            vec!["reachab", "ack", "retry", "queue", "dedup"],
        ],
    );
    m.insert(
        "watchconnectivity relay",
        vec![
            vec!["wcsession", "watchconnectivity", "watch session"],
            vec![
                "message",
                "applicationcontext",
                "userinfo",
                "file transfer",
                "payload",
            ],
            vec!["ack", "retry", "queue", "dedup", "idempot"],
        ],
    );
    m.insert(
        "forward queue retry",
        vec![
            vec!["queue"],
            vec!["retry", "backoff"],
            vec!["idempot", "dedup", "stable id", "operation id"],
        ],
    );
    m.insert(
        "device registration",
        vec![
            vec!["device", "identity"],
            vec!["register", "pair", "token", "credential"],
        ],
    );
    m.insert(
        "ime microphone key",
        vec![
            vec!["ime", "keyboard", "input method"],
            vec!["microphone", "mic"],
            vec!["start", "stop", "toggle", "capture"],
        ],
    );
    m.insert(
        "action_recognize_speech",
        vec![
            vec![
                "action_recognize_speech",
                "recognition intent",
                "recognizer intent",
            ],
            vec!["result", "caller", "activity result"],
        ],
    );
    m.insert(
        "vad/silence endpointing",
        vec![
            vec!["vad", "voice activity", "speech"],
            vec!["silence", "endpoint"],
        ],
    );
    m.insert(
        "verified update install",
        vec![
            vec!["signature", "signed", "checksum", "hash", "verif"],
            vec!["artifact", "package", "bundle", "release", "update"],
            vec!["install", "replace", "activate", "relaunch"],
            vec!["rollback", "last-good", "prior working", "resume"],
        ],
    );
    m
}

/// One parsed table row: `(1-based line number, cells)`.
pub type Row = (usize, Vec<String>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    CellCountMismatch {
        line: usize,
        expected: usize,
        got: usize,
    },
    MissingHeader(Vec<String>),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CellCountMismatch {
                line,
                expected,
                got,
            } => {
                write!(f, "line {line}: expected {expected} cells, got {got}")
            }
            Self::MissingHeader(header) => {
                write!(f, "missing table header: {}", header.join(" | "))
            }
        }
    }
}

/// Port of `parse_table`: scans `|`-prefixed lines for the expected header,
/// skips the `---`/`:--:` divider row, then collects body rows until EOF.
pub fn parse_table(text: &str, expected_header: &[&str]) -> Result<Vec<Row>, ParseError> {
    let mut rows = Vec::new();
    let mut in_table = false;
    for (idx, raw) in text.lines().enumerate() {
        let line_number = idx + 1;
        if !raw.starts_with('|') {
            continue;
        }
        let trimmed = raw.trim().trim_matches('|');
        let cells: Vec<String> = trimmed.split('|').map(|c| c.trim().to_string()).collect();
        if cells
            .iter()
            .map(|s| s.as_str())
            .eq(expected_header.iter().copied())
        {
            in_table = true;
            continue;
        }
        if in_table
            && cells
                .iter()
                .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
        {
            continue;
        }
        if in_table {
            if cells.len() != expected_header.len() {
                return Err(ParseError::CellCountMismatch {
                    line: line_number,
                    expected: expected_header.len(),
                    got: cells.len(),
                });
            }
            rows.push((line_number, cells));
        }
    }
    if !in_table {
        return Err(ParseError::MissingHeader(
            expected_header.iter().map(|s| s.to_string()).collect(),
        ));
    }
    Ok(rows)
}

/// Filesystem/clock boundary `run` needs; `validate` itself stays pure.
pub trait ReportFs {
    fn read_to_string(&self, path: &str) -> std::io::Result<String>;
    fn is_file(&self, path: &str) -> bool;
    /// Resolves `path` to an absolute, `.`/`..`-collapsed form (Python's
    /// `Path.resolve()`), used for the evidence-path containment check.
    fn resolve(&self, path: &str) -> String;
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub repo_roots: BTreeMap<String, String>,
    pub scope_repos: BTreeMap<String, Vec<String>>,
}

/// Options mirroring the CLI flags (`--expected-rows`, `--max-repeat`,
/// manifest content already parsed).
#[derive(Debug, Clone, Default)]
pub struct ValidateOptions {
    pub expected_rows: Option<usize>,
    pub max_repeat: usize,
    pub manifest: Option<Manifest>,
}

fn contains_evidence_repo(evidence: &str, repo: &str) -> bool {
    evidence.contains(repo)
}

/// Port of `main()`'s per-row/per-column checks (everything after
/// `parse_table` succeeds). `resolve_evidence_path` and `evidence_file_exists`
/// close over the manifest's repo roots via `fs`.
pub fn validate(
    rows: &[Row],
    header: &[&str],
    opts: &ValidateOptions,
    fs: &dyn ReportFs,
) -> Vec<String> {
    let mut errors = Vec::new();
    let index: HashMap<&str, usize> = header.iter().enumerate().map(|(i, h)| (*h, i)).collect();
    let signatures = semantic_signatures();

    if let Some(expected) = opts.expected_rows {
        if rows.len() != expected {
            errors.push(format!("expected {expected} rows, found {}", rows.len()));
        }
    }

    let scope_name = if index.contains_key("Scope") {
        "Scope"
    } else {
        "Platform"
    };
    let mut seen: HashMap<(String, String, String), usize> = HashMap::new();

    for (line_number, cells) in rows {
        let key = (
            cells[index[scope_name]].clone(),
            cells[index["Domain"]].clone(),
            cells[index["Atom"]].clone(),
        );
        if let Some(first) = seen.get(&key) {
            errors.push(format!(
                "line {line_number}: duplicate atom tuple; first at line {first}"
            ));
        } else {
            seen.insert(key, *line_number);
        }

        let evidence = cells[index["Source evidence"]].to_lowercase();
        for token in FORBIDDEN_EVIDENCE {
            if evidence.contains(token) {
                errors.push(format!(
                    "line {line_number}: forbidden evidence path `{token}`"
                ));
            }
        }

        let joined = cells.join(" ").to_lowercase();
        for phrase in BOILERPLATE {
            if joined.contains(phrase) {
                errors.push(format!(
                    "line {line_number}: prohibited boilerplate `{phrase}`"
                ));
            }
        }

        let recommendation_name = if index.contains_key("Best combined") {
            Some("Best combined")
        } else if index.contains_key("Recommended implementation") {
            Some("Recommended implementation")
        } else {
            None
        };
        let atom_raw = &cells[index["Atom"]];
        let atom_key = atom_raw.trim().to_lowercase();
        if let (Some(rec_name), Some(groups)) =
            (recommendation_name, signatures.get(atom_key.as_str()))
        {
            let mut body = cells[index[rec_name]].trim().to_lowercase();
            let prefix = format!("{atom_key}:");
            if let Some(stripped) = body.strip_prefix(&prefix) {
                body = stripped.trim().to_string();
            }
            body = body.replace(&atom_key, "");
            let missing: Vec<String> = groups
                .iter()
                .filter(|group| !group.iter().any(|token| body.contains(token)))
                .map(|group| group.join("/"))
                .collect();
            if !missing.is_empty() {
                let expected = missing.join(" + ");
                errors.push(format!(
                    "line {line_number}: `{atom_raw}` recommendation lacks semantic signature: {expected}"
                ));
            }
        }

        if (header == headers("stage2").unwrap() || header == headers("stage3").unwrap())
            && opts
                .manifest
                .as_ref()
                .is_some_and(|m| !m.scope_repos.is_empty())
        {
            let manifest = opts.manifest.as_ref().unwrap();
            let scope = &cells[index["Scope"]];
            let Some(expected_repos) = manifest.scope_repos.get(scope) else {
                errors.push(format!(
                    "line {line_number}: scope `{scope}` missing from manifest"
                ));
                continue;
            };

            let mechanism_entries: Vec<&str> = cells[index["Repository mechanisms"]]
                .split("<br>")
                .collect();
            for repo in expected_repos {
                let prefix = format!("{repo}:");
                let matches: Vec<&&str> = mechanism_entries
                    .iter()
                    .filter(|e| e.starts_with(&prefix))
                    .collect();
                if matches.len() != 1 {
                    errors.push(format!(
                        "line {line_number}: expected exactly one `{repo}:` mechanism entry, found {}",
                        matches.len()
                    ));
                    continue;
                }
                let entry = matches[0];
                if entry.contains(": Observed ") {
                    let cited = extract_backticked(entry);
                    if cited.is_empty() {
                        errors.push(format!(
                            "line {line_number}: `{repo}` Observed entry lacks backticked production path/symbol"
                        ));
                    }
                    if !contains_evidence_repo(&cells[index["Source evidence"]], repo) {
                        errors.push(format!(
                            "line {line_number}: `{repo}` Observed entry missing source-evidence entry"
                        ));
                    }
                }
            }

            let evidence_cell = &cells[index["Source evidence"]];
            for (repo, cited) in extract_evidence_citations(evidence_cell) {
                let Some(root) = manifest.repo_roots.get(&repo) else {
                    errors.push(format!("line {line_number}: evidence repository `{repo}` missing from manifest roots"));
                    continue;
                };
                let relative = cited.split('#').next().unwrap_or("");
                let candidate_str = format!("{}/{}", root.trim_end_matches('/'), relative);
                let candidate = fs.resolve(&candidate_str);
                let root_resolved = fs.resolve(root);
                if !candidate.starts_with(&root_resolved) {
                    errors.push(format!(
                        "line {line_number}: evidence path escapes `{repo}` root: {relative}"
                    ));
                    continue;
                }
                if !fs.is_file(&candidate) {
                    errors.push(format!(
                        "line {line_number}: missing evidence file for `{repo}`: {relative}"
                    ));
                }
            }
        }
    }

    let repeat_columns: Vec<&str> = [
        "Best observed",
        "Best combined",
        "Recommended implementation",
        "Rationale / tradeoffs",
        "Why / tradeoffs",
    ]
    .into_iter()
    .filter(|name| index.contains_key(name))
    .collect();
    let sentinels = ["not found", "unclear", "n/a", "no proven winner"];
    for name in repeat_columns {
        let mut counter: HashMap<String, usize> = HashMap::new();
        for (_, cells) in rows {
            *counter
                .entry(cells[index[name]].trim().to_string())
                .or_insert(0) += 1;
        }
        for (value, count) in counter {
            if value.is_empty() || sentinels.contains(&value.to_lowercase().as_str()) {
                continue;
            }
            if count > opts.max_repeat {
                let sample: String = value
                    .chars()
                    .take(100)
                    .collect::<String>()
                    .replace('\n', " ");
                errors.push(format!("column `{name}` repeats {count} times: {sample:?}"));
            }
        }
    }

    errors
}

/// Port of the regex `` r"`([^`]+)`" `` used to pull backticked spans out of a mechanism entry.
fn extract_backticked(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in text.char_indices() {
        if c == '`' {
            match start {
                None => start = Some(i + 1),
                Some(s) => {
                    out.push(text[s..i].to_string());
                    start = None;
                }
            }
        }
    }
    out
}

/// Port of the regex `` r"(?:^|;\s*)([^:;]+):\s*`([^`]+)`" `` used to pull
/// `repo: `path`` citations out of the Source evidence cell.
fn extract_evidence_citations(cell: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for segment in split_on_semicolon_boundaries(cell) {
        let segment = segment.trim_start();
        let Some(colon) = segment.find(':') else {
            continue;
        };
        let (repo_part, rest) = segment.split_at(colon);
        if repo_part.contains(';') {
            continue;
        }
        let rest = rest[1..].trim_start();
        if let Some(stripped) = rest.strip_prefix('`') {
            if let Some(end) = stripped.find('`') {
                out.push((repo_part.trim().to_string(), stripped[..end].to_string()));
            }
        }
    }
    out
}

/// Splits on `;` boundaries the way the Python regex's `(?:^|;\s*)` anchor
/// does, keeping each candidate `repo: \`path\`` span as its own segment.
fn split_on_semicolon_boundaries(cell: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    for (i, c) in cell.char_indices() {
        if c == ';' {
            out.push(&cell[start..i]);
            start = i + 1;
        }
    }
    out.push(&cell[start..]);
    out
}

/// Modes ported from the historical validator that need only the table, the manifest repo
/// roots, and evidence files. The historical cross-file checks (`--canon`, `--ledgers`,
/// `--repository`, manifest `product` / `repo_targets`) have no input on the current route and
/// are not applied; see [`validate_table_mode`].
pub fn is_table_mode(mode: &str) -> bool {
    matches!(
        mode,
        "repo-ledger" | "canon" | "mechanism-cards" | "handoff"
    )
}

/// Historical `BOILERPLATE` phrases (`267bae38`), applied to every table-mode row.
const HISTORICAL_BOILERPLATE: &[&str] = &[
    "combine observed strengths without assuming parity",
    "combine strongest observed mechanism with explicit state",
    "strongest dedicated source match",
    "keep boundary explicit, observable, and testable",
];

/// Historical `FORBIDDEN_PATH_TOKENS` and `FORBIDDEN_EVIDENCE_SUFFIXES`.
const HISTORICAL_FORBIDDEN_PATH_TOKENS: &[&str] = &[
    ".cache/",
    ".right-release/",
    ".fingerprint/",
    "node_modules/",
    "target/debug/",
    "target/release/",
    "deriveddata/",
    "build/",
    "dist/",
];
const HISTORICAL_FORBIDDEN_SUFFIXES: &[&str] = &[".md", ".markdown", ".rst", ".txt"];

/// Historical `STATUS_VALUES` (mechanism-cards) and `SENTINELS`.
const STATUS_VALUES: &[&str] = &["OBSERVED", "UNCLEAR", "NOT FOUND", "N/A"];
const SENTINEL_VALUES: &[&str] = &["not found", "unclear", "n/a", "no proven winner"];

/// Historical repeat-checked columns (`repeat_columns` in `main()`).
const HISTORICAL_REPEAT_COLUMNS: &[&str] = &[
    "Observable behavior",
    "Mechanism",
    "Criteria assessment",
    "Best observed",
    "Recommended implementation",
    "Why / tradeoffs",
];

fn cell(cells: &[String], index: &HashMap<&str, usize>, name: &str) -> String {
    cells[index[name]].trim().to_string()
}

/// Port of `ID_RE` (`[A-Za-z0-9][A-Za-z0-9._:-]*`, full match).
fn is_stable_id(value: &str) -> bool {
    Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
        .map(|re| re.is_match(value))
        .unwrap_or(false)
}

/// The manifest repo root for `repo`, when the manifest declares one.
fn manifest_root<'a>(opts: &'a ValidateOptions, repo: &str) -> Option<&'a str> {
    opts.manifest
        .as_ref()
        .and_then(|m| m.repo_roots.get(repo))
        .map(String::as_str)
}

/// Port of `validate_citation`: `path#symbol` must name a non-prose, in-root evidence file
/// that exists and whose contents contain `symbol`.
fn validate_citation(
    errors: &mut Vec<String>,
    line_number: usize,
    repo: &str,
    cited: &str,
    root: &str,
    fs: &dyn ReportFs,
) {
    let (raw_relative, symbol) = match cited.split_once('#') {
        Some((path, symbol)) => (path, symbol.trim()),
        None => (cited, ""),
    };
    if symbol.is_empty() {
        errors.push(format!(
            "line {line_number}: evidence for `{repo}` lacks path#symbol: {cited}"
        ));
    }
    let relative = raw_relative.replace('\\', "/");
    let lowered = relative.to_lowercase();
    if HISTORICAL_FORBIDDEN_PATH_TOKENS
        .iter()
        .any(|token| lowered.contains(*token))
    {
        errors.push(format!(
            "line {line_number}: forbidden evidence path for `{repo}`: {relative}"
        ));
    }
    if HISTORICAL_FORBIDDEN_SUFFIXES
        .iter()
        .any(|suffix| lowered.ends_with(*suffix))
    {
        errors.push(format!(
            "line {line_number}: prose evidence is forbidden for `{repo}`: {relative}"
        ));
    }

    let root = root.trim_end_matches('/');
    let candidate = fs.resolve(&format!("{root}/{relative}"));
    let root_resolved = fs.resolve(root);
    if candidate != root_resolved && !candidate.starts_with(&format!("{root_resolved}/")) {
        errors.push(format!(
            "line {line_number}: evidence path escapes `{repo}` root: {relative}"
        ));
        return;
    }
    if !fs.is_file(&candidate) {
        errors.push(format!(
            "line {line_number}: missing evidence file for `{repo}`: {relative}"
        ));
        return;
    }
    if symbol.is_empty() {
        return;
    }
    match fs.read_to_string(&candidate) {
        Ok(content) if !content.contains(symbol) => errors.push(format!(
            "line {line_number}: symbol `{symbol}` not found for `{repo}` in {relative}"
        )),
        Ok(_) => {}
        Err(e) => errors.push(format!(
            "line {line_number}: unreadable evidence file for `{repo}`: {e}"
        )),
    }
}

/// Port of `require_repo_citations`: the cell must hold at least one backticked citation, and
/// each one must pass [`validate_citation`].
fn require_citations(
    errors: &mut Vec<String>,
    line_number: usize,
    repo: &str,
    root: &str,
    cell_text: &str,
    label: &str,
    fs: &dyn ReportFs,
) {
    let found = extract_backticked(cell_text);
    if found.is_empty() {
        errors.push(format!(
            "line {line_number}: `{repo}` {label} lacks backticked path#symbol"
        ));
        return;
    }
    for cited in &found {
        validate_citation(errors, line_number, repo, cited, root, fs);
    }
}

/// Row checks for the `repo-ledger`, `canon`, `mechanism-cards`, and `handoff` modes, ported
/// from the historical `main()` (`267bae38`). Applies the per-row rules that need only the
/// table, `opts.manifest` repo roots and scope map, and evidence files on disk. Not applied
/// (their inputs are not on this route): the ledger/canon cross-checks (`--ledgers`,
/// `--canon`), the `--repository` match, the mechanism-card expected-set check, and the
/// product-applicability check (manifest `product` is not parsed).
pub fn validate_table_mode(
    mode: &str,
    rows: &[Row],
    header: &[&str],
    opts: &ValidateOptions,
    fs: &dyn ReportFs,
) -> Vec<String> {
    let mut errors = Vec::new();
    let index: HashMap<&str, usize> = header.iter().enumerate().map(|(i, h)| (*h, i)).collect();
    let ledger_prose = Regex::new(
        r"\b(best observed|winner|outperform(?:s|ed|ing)?|better than)\b|\b(?:versus|compared (?:to|with))\s+(?:another|other|repository|repo)\b|★",
    )
    .unwrap();
    let winner_prose = Regex::new(r"\b(best observed|winner|outperform(?:s|ed|ing)?)\b|★").unwrap();
    let committed_promotion = Regex::new(r"promotion=(?:promote|yes|committed)").unwrap();

    if matches!(mode, "repo-ledger" | "canon" | "mechanism-cards") && opts.manifest.is_none() {
        errors.push(format!("mode `{mode}` requires --manifest"));
    }
    if rows.is_empty() {
        errors.push("table has no data rows".to_string());
    }
    if let Some(expected) = opts.expected_rows {
        if rows.len() != expected {
            errors.push(format!("expected {expected} rows, found {}", rows.len()));
        }
    }

    let mut seen: HashMap<Vec<String>, usize> = HashMap::new();
    for (line_number, row_cells) in rows {
        let line = *line_number;
        let cells: &[String] = row_cells;
        let c = |name: &str| cell(cells, &index, name);

        let joined = cells.join(" ").to_lowercase();
        for phrase in HISTORICAL_BOILERPLATE {
            if joined.contains(phrase) {
                errors.push(format!("line {line}: prohibited boilerplate `{phrase}`"));
            }
        }

        let key = match mode {
            "repo-ledger" => vec![c("Repository"), c("Behavior ID")],
            "mechanism-cards" => vec![
                c("Scope"),
                c("Domain"),
                c("Atom ID"),
                c("Repository"),
                c("Platform"),
            ],
            _ => vec![c("Scope"), c("Domain"), c("Atom ID")],
        };
        if let Some(first) = seen.get(&key) {
            errors.push(format!(
                "line {line}: duplicate row key; first at line {first}"
            ));
        } else {
            seen.insert(key, line);
        }

        match mode {
            "repo-ledger" => {
                let repo = c("Repository");
                let behavior_id = c("Behavior ID");
                if !is_stable_id(&behavior_id) {
                    errors.push(format!("line {line}: invalid behavior ID `{behavior_id}`"));
                }
                match manifest_root(opts, &repo) {
                    None => errors.push(format!(
                        "line {line}: repository `{repo}` missing from manifest roots"
                    )),
                    Some(root) => {
                        require_citations(
                            &mut errors,
                            line,
                            &repo,
                            root,
                            &c("Production evidence"),
                            "production evidence",
                            fs,
                        );
                        require_citations(
                            &mut errors,
                            line,
                            &repo,
                            root,
                            &c("Live consumer"),
                            "live consumer",
                            fs,
                        );
                    }
                }
                for name in [
                    "Platform",
                    "Observable behavior",
                    "Boundary clues",
                    "State / fallback / safeguards",
                ] {
                    if c(name).is_empty() {
                        errors.push(format!("line {line}: `{name}` is empty"));
                    }
                }
                let discovery = [
                    c("Observable behavior"),
                    c("Boundary clues"),
                    c("State / fallback / safeguards"),
                ]
                .join(" ")
                .to_lowercase();
                if ledger_prose.is_match(&discovery) {
                    errors.push(format!(
                        "line {line}: repo ledger contains ranking/comparison prose"
                    ));
                }
            }
            "canon" => {
                let scope = c("Scope");
                let scope_known = opts
                    .manifest
                    .as_ref()
                    .is_some_and(|m| m.scope_repos.contains_key(&scope));
                if !scope_known {
                    errors.push(format!(
                        "line {line}: scope `{scope}` missing from manifest"
                    ));
                }
                let atom_id = c("Atom ID");
                if !is_stable_id(&atom_id) {
                    errors.push(format!("line {line}: invalid atom ID `{atom_id}`"));
                }
                let provenance_text = c("Repository provenance");
                let entries: Vec<&str> = provenance_text.split("<br>").collect();
                if entries.iter().any(|entry| !entry.contains(':')) {
                    errors.push(format!(
                        "line {line}: repository provenance lacks `Repository:Behavior ID`"
                    ));
                }
                for entry in entries {
                    let (repo, behavior_id) = entry.split_once(':').unwrap_or((entry, ""));
                    let (repo, behavior_id) = (repo.trim(), behavior_id.trim());
                    if manifest_root(opts, repo).is_none() {
                        errors.push(format!(
                            "line {line}: provenance repository `{repo}` is unknown"
                        ));
                    }
                    if !is_stable_id(behavior_id) {
                        errors.push(format!(
                            "line {line}: invalid provenance behavior ID `{behavior_id}`"
                        ));
                    }
                }
            }
            "mechanism-cards" => {
                let repo = c("Repository");
                let status_raw = c("Status");
                let status = status_raw.to_uppercase();
                if !STATUS_VALUES.contains(&status.as_str()) {
                    errors.push(format!(
                        "line {line}: invalid mechanism status `{status_raw}`"
                    ));
                }
                match manifest_root(opts, &repo) {
                    None => errors.push(format!(
                        "line {line}: repository `{repo}` missing from manifest roots"
                    )),
                    Some(root) => {
                        if status == "OBSERVED" {
                            require_citations(
                                &mut errors,
                                line,
                                &repo,
                                root,
                                &c("Production evidence"),
                                "production evidence",
                                fs,
                            );
                            require_citations(
                                &mut errors,
                                line,
                                &repo,
                                root,
                                &c("Live consumer"),
                                "live consumer",
                                fs,
                            );
                            for name in [
                                "Mechanism",
                                "State / fallback / safeguards",
                                "Criteria assessment",
                            ] {
                                let value = c(name);
                                if value.is_empty()
                                    || SENTINEL_VALUES.contains(&value.to_lowercase().as_str())
                                {
                                    errors
                                        .push(format!("line {line}: Observed card lacks `{name}`"));
                                }
                            }
                        } else {
                            if c("Criteria assessment").is_empty() {
                                errors.push(format!("line {line}: non-Observed card lacks reason"));
                            }
                            for name in ["Production evidence", "Live consumer"] {
                                for cited in extract_backticked(&c(name)) {
                                    validate_citation(&mut errors, line, &repo, &cited, root, fs);
                                }
                            }
                        }
                    }
                }
                let narrative =
                    format!("{} {}", c("Mechanism"), c("Criteria assessment")).to_lowercase();
                if winner_prose.is_match(&narrative) {
                    errors.push(format!("line {line}: mechanism card contains winner prose"));
                }
            }
            "handoff" => {
                let atom_id = c("Atom ID");
                if !is_stable_id(&atom_id) {
                    errors.push(format!("line {line}: invalid stable atom ID `{atom_id}`"));
                }
                let state_action = c("Required state / action").to_lowercase();
                for token in [
                    "implementation=",
                    "verification=",
                    "qualification=",
                    "delivery=",
                    "action=",
                ] {
                    if !state_action.contains(token) {
                        errors.push(format!(
                            "line {line}: required state/action lacks `{token}`"
                        ));
                    }
                }
                let promotion = c("Scope / promotion").to_lowercase();
                for token in ["scope=", "promotion="] {
                    if !promotion.contains(token) {
                        errors.push(format!("line {line}: scope/promotion lacks `{token}`"));
                    }
                }
                if committed_promotion.is_match(&promotion) && !promotion.contains("authority=") {
                    errors.push(format!(
                        "line {line}: committed promotion lacks `authority=`"
                    ));
                }
            }
            _ => {}
        }
    }

    for name in HISTORICAL_REPEAT_COLUMNS
        .iter()
        .copied()
        .filter(|name| index.contains_key(name))
    {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for (_, row_cells) in rows {
            *counts
                .entry(row_cells[index[name]].trim().to_string())
                .or_insert(0) += 1;
        }
        for (value, count) in counts {
            if value.is_empty() || SENTINEL_VALUES.contains(&value.to_lowercase().as_str()) {
                continue;
            }
            if count > opts.max_repeat {
                let sample: String = value
                    .chars()
                    .take(100)
                    .collect::<String>()
                    .replace('\n', " ");
                errors.push(format!("column `{name}` repeats {count} times: {sample:?}"));
            }
        }
    }

    errors
}

pub struct RunOutcome {
    pub stdout: String,
    pub code: i32,
}

/// Port of `main()`: parse the report, run [`validate`], and format the
/// `FAIL: N issue(s)` / `PASS: ...` output. Receipt writing (`--write-receipt`)
/// is left to the caller (it needs sha256 + an isolated-clock timestamp,
/// which belong at the process boundary, not in this pure module).
pub fn run(
    report_text: &str,
    mode: &str,
    opts: &ValidateOptions,
    fs: &dyn ReportFs,
    report_path: &str,
) -> RunOutcome {
    let Some(header) = headers(mode) else {
        return RunOutcome {
            stdout: format!("FAIL: unknown mode `{mode}`"),
            code: 1,
        };
    };
    let rows = match parse_table(report_text, header) {
        Ok(r) => r,
        Err(e) => {
            return RunOutcome {
                stdout: format!("FAIL: {e}"),
                code: 1,
            }
        }
    };
    let errors = if is_table_mode(mode) {
        validate_table_mode(mode, &rows, header, opts, fs)
    } else {
        validate(&rows, header, opts, fs)
    };
    if !errors.is_empty() {
        let mut out = format!("FAIL: {} issue(s)\n", errors.len());
        for issue in &errors {
            out.push_str(&format!("- {issue}\n"));
        }
        return RunOutcome {
            stdout: out.trim_end().to_string(),
            code: 1,
        };
    }
    RunOutcome {
        stdout: format!("PASS: {report_path} ({} rows, mode={mode})", rows.len()),
        code: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoFs;
    impl ReportFs for NoFs {
        fn read_to_string(&self, _path: &str) -> std::io::Result<String> {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "n/a"))
        }
        fn is_file(&self, _path: &str) -> bool {
            false
        }
        fn resolve(&self, path: &str) -> String {
            path.to_string()
        }
    }

    #[test]
    fn parse_table_reads_inventory_rows() {
        let text = "\
| Platform | Domain | Atom | Definition / boundary | Source evidence |
| --- | --- | --- | --- | --- |
| macOS | Paste | Clipboard transaction | boundary text | some/path.rs |
";
        let rows = parse_table(text, headers("inventory").unwrap()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1[2], "Clipboard transaction");
    }

    #[test]
    fn parse_table_missing_header_errors() {
        let err = parse_table("no tables here", headers("inventory").unwrap()).unwrap_err();
        assert!(matches!(err, ParseError::MissingHeader(_)));
    }

    #[test]
    fn validate_flags_duplicate_atom_and_forbidden_evidence() {
        let header = headers("inventory").unwrap();
        let rows = vec![
            (
                2usize,
                vec![
                    "macOS".into(),
                    "Paste".into(),
                    "X".into(),
                    "d".into(),
                    ".cache/foo".into(),
                ],
            ),
            (
                3usize,
                vec![
                    "macOS".into(),
                    "Paste".into(),
                    "X".into(),
                    "d".into(),
                    "ok/path".into(),
                ],
            ),
        ];
        let opts = ValidateOptions {
            max_repeat: 8,
            ..Default::default()
        };
        let errors = validate(&rows, header, &opts, &NoFs);
        assert!(errors.iter().any(|e| e.contains("duplicate atom tuple")));
        assert!(errors.iter().any(|e| e.contains("forbidden evidence path")));
    }

    #[test]
    fn run_reports_pass_on_clean_report() {
        let text = "\
| Platform | Domain | Atom | Definition / boundary | Source evidence |
| --- | --- | --- | --- | --- |
| macOS | Paste | Clipboard transaction | boundary text | some/path.rs |
";
        let opts = ValidateOptions {
            max_repeat: 8,
            ..Default::default()
        };
        let outcome = run(text, "inventory", &opts, &NoFs, "report.md");
        assert_eq!(outcome.code, 0);
        assert!(outcome.stdout.starts_with("PASS: report.md (1 rows"));
    }

    struct TableFs {
        files: HashMap<String, String>,
    }
    impl ReportFs for TableFs {
        fn read_to_string(&self, path: &str) -> std::io::Result<String> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
        }
        fn is_file(&self, path: &str) -> bool {
            self.files.contains_key(path)
        }
        fn resolve(&self, path: &str) -> String {
            path.to_string()
        }
    }

    fn table_fs() -> TableFs {
        TableFs {
            files: HashMap::from([
                (
                    "/repo/a/src/paste.rs".to_string(),
                    "fn paste() {}".to_string(),
                ),
                (
                    "/repo/a/src/ui.rs".to_string(),
                    "fn paste_button() {}".to_string(),
                ),
            ]),
        }
    }

    fn table_opts() -> ValidateOptions {
        ValidateOptions {
            max_repeat: 8,
            manifest: Some(Manifest {
                repo_roots: BTreeMap::from([("repoA".to_string(), "/repo/a".to_string())]),
                scope_repos: BTreeMap::from([("S1".to_string(), vec!["repoA".to_string()])]),
            }),
            ..Default::default()
        }
    }

    const LEDGER: &str = "\
| Repository | Behavior ID | Platform | Domain hint | Observable behavior | Boundary clues | Production evidence | Live consumer | State / fallback / safeguards |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| repoA | B-1 | macOS | Paste | copies the selection | clipboard buffer | repoA: `src/paste.rs#fn paste` | repoA: `src/ui.rs#paste_button` | restores the prior clipboard |
";

    const LEDGER_MISSING_COLUMN: &str = "\
| Repository | Behavior ID | Platform | Domain hint | Observable behavior | Boundary clues | Production evidence | State / fallback / safeguards |
| --- | --- | --- | --- | --- | --- | --- | --- |
| repoA | B-1 | macOS | Paste | copies the selection | clipboard buffer | repoA: `src/paste.rs#fn paste` | restores the prior clipboard |
";

    const CANON: &str = "\
| Scope | Domain | Atom ID | Atom | Boundary | Repository provenance |
| --- | --- | --- | --- | --- | --- |
| S1 | Paste | A-1 | Clipboard transaction | snapshot and restore | repoA:B-1<br>repoA:B-2 |
";

    const CANON_MISSING_COLUMN: &str = "\
| Scope | Domain | Atom ID | Atom | Boundary |
| --- | --- | --- | --- | --- |
| S1 | Paste | A-1 | Clipboard transaction | snapshot and restore |
";

    const CARDS: &str = "\
| Scope | Domain | Atom ID | Repository | Platform | Status | Production evidence | Live consumer | Mechanism | State / fallback / safeguards | Criteria assessment |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | Paste | A-1 | repoA | macOS | OBSERVED | repoA: `src/paste.rs#fn paste` | repoA: `src/ui.rs#paste_button` | copies through the buffer | restores the clipboard | meets the criteria |
";

    const CARDS_MISSING_COLUMN: &str = "\
| Scope | Domain | Atom ID | Repository | Platform | Production evidence | Live consumer | Mechanism | State / fallback / safeguards | Criteria assessment |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | Paste | A-1 | repoA | macOS | repoA: `src/paste.rs#fn paste` | repoA: `src/ui.rs#paste_button` | copies through the buffer | restores the clipboard | meets the criteria |
";

    const HANDOFF: &str = "\
| Scope | Domain | Atom ID | Deficit | Scope / promotion | Required state / action | Recommended behavior | Reuse disposition | Acceptance / qualification | Source evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | Paste | A-1 | restore step missing | scope=S1; promotion=no | implementation=partial; verification=none; qualification=open; delivery=blocked; action=add restore | add the restore step | reuse repoA | unit test | repoA: `src/paste.rs#fn paste` |
";

    const HANDOFF_MISSING_COLUMN: &str = "\
| Scope | Domain | Atom ID | Deficit | Scope / promotion | Required state / action | Recommended behavior | Reuse disposition | Acceptance / qualification |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| S1 | Paste | A-1 | restore step missing | scope=S1; promotion=no | implementation=partial; verification=none; qualification=open; delivery=blocked; action=add restore | add the restore step | reuse repoA | unit test |
";

    #[test]
    fn repo_ledger_valid_table_passes() {
        let outcome = run(
            LEDGER,
            "repo-ledger",
            &table_opts(),
            &table_fs(),
            "ledger.md",
        );
        assert_eq!(outcome.code, 0, "{}", outcome.stdout);
        assert_eq!(outcome.stdout, "PASS: ledger.md (1 rows, mode=repo-ledger)");
    }

    #[test]
    fn repo_ledger_missing_column_fails() {
        let outcome = run(
            LEDGER_MISSING_COLUMN,
            "repo-ledger",
            &table_opts(),
            &table_fs(),
            "ledger.md",
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.starts_with("FAIL: missing table header"));
    }

    #[test]
    fn repo_ledger_unknown_repository_fails() {
        let text = LEDGER
            .replace("repoA | B-1", "repoZ | B-1")
            .replace("repoA: `", "repoZ: `");
        let outcome = run(
            &text,
            "repo-ledger",
            &table_opts(),
            &table_fs(),
            "ledger.md",
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome
            .stdout
            .contains("repository `repoZ` missing from manifest roots"));
    }

    #[test]
    fn canon_valid_table_passes() {
        let outcome = run(CANON, "canon", &table_opts(), &table_fs(), "canon.md");
        assert_eq!(outcome.code, 0, "{}", outcome.stdout);
        assert_eq!(outcome.stdout, "PASS: canon.md (1 rows, mode=canon)");
    }

    #[test]
    fn canon_missing_column_fails() {
        let outcome = run(
            CANON_MISSING_COLUMN,
            "canon",
            &table_opts(),
            &table_fs(),
            "canon.md",
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.starts_with("FAIL: missing table header"));
    }

    #[test]
    fn canon_unknown_provenance_repository_fails() {
        let text = CANON.replace("repoA:B-1", "repoZ:B-1");
        let outcome = run(&text, "canon", &table_opts(), &table_fs(), "canon.md");
        assert_eq!(outcome.code, 1);
        assert!(outcome
            .stdout
            .contains("provenance repository `repoZ` is unknown"));
    }

    #[test]
    fn mechanism_cards_valid_table_passes() {
        let outcome = run(
            CARDS,
            "mechanism-cards",
            &table_opts(),
            &table_fs(),
            "cards.md",
        );
        assert_eq!(outcome.code, 0, "{}", outcome.stdout);
        assert_eq!(
            outcome.stdout,
            "PASS: cards.md (1 rows, mode=mechanism-cards)"
        );
    }

    #[test]
    fn mechanism_cards_missing_column_fails() {
        let outcome = run(
            CARDS_MISSING_COLUMN,
            "mechanism-cards",
            &table_opts(),
            &table_fs(),
            "cards.md",
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.starts_with("FAIL: missing table header"));
    }

    #[test]
    fn observed_card_with_uncited_live_consumer_fails() {
        let text = CARDS.replace("repoA: `src/ui.rs#paste_button`", "repoA: no citation here");
        let outcome = run(
            &text,
            "mechanism-cards",
            &table_opts(),
            &table_fs(),
            "cards.md",
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome
            .stdout
            .contains("`repoA` live consumer lacks backticked path#symbol"));
    }

    #[test]
    fn handoff_valid_table_passes() {
        let outcome = run(HANDOFF, "handoff", &table_opts(), &table_fs(), "handoff.md");
        assert_eq!(outcome.code, 0, "{}", outcome.stdout);
        assert_eq!(outcome.stdout, "PASS: handoff.md (1 rows, mode=handoff)");
    }

    #[test]
    fn handoff_missing_column_fails() {
        let outcome = run(
            HANDOFF_MISSING_COLUMN,
            "handoff",
            &table_opts(),
            &table_fs(),
            "handoff.md",
        );
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.starts_with("FAIL: missing table header"));
    }

    #[test]
    fn handoff_committed_promotion_requires_authority() {
        let text = HANDOFF.replace("promotion=no", "promotion=committed");
        let outcome = run(&text, "handoff", &table_opts(), &table_fs(), "handoff.md");
        assert_eq!(outcome.code, 1);
        assert!(outcome
            .stdout
            .contains("committed promotion lacks `authority=`"));
    }

    #[test]
    fn table_modes_require_manifest() {
        let opts = ValidateOptions {
            max_repeat: 8,
            ..Default::default()
        };
        let outcome = run(CANON, "canon", &opts, &table_fs(), "canon.md");
        assert_eq!(outcome.code, 1);
        assert!(outcome.stdout.contains("mode `canon` requires --manifest"));
    }

    #[test]
    fn extract_backticked_pairs() {
        assert_eq!(
            extract_backticked("Observed `src/a.rs#L1`"),
            vec!["src/a.rs#L1".to_string()]
        );
    }
}
