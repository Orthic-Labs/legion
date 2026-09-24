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

pub fn headers(mode: &str) -> Option<&'static [&'static str]> {
    match mode {
        "inventory" => Some(&["Platform", "Domain", "Atom", "Definition / boundary", "Source evidence"]),
        "stage2" => Some(&[
            "Scope", "Domain", "Atom", "Repository mechanisms", "Best observed", "Best combined",
            "Rationale / tradeoffs", "Source evidence",
        ]),
        "stage3" => Some(&[
            "Scope", "Domain", "Atom", "Current product", "Repository mechanisms", "Best observed",
            "Best combined", "Rationale / tradeoffs", "Source evidence",
        ]),
        "final" => Some(&[
            "Scope", "Domain", "Atom", "Best observed", "Recommended implementation",
            "Why / tradeoffs", "Source evidence", "Confidence",
        ]),
        _ => None,
    }
}

const FORBIDDEN_EVIDENCE: &[&str] = &[
    ".cache/", ".right-release/", ".fingerprint/", "node_modules/", "target/debug/",
    "target/release/", "deriveddata/", "heardright-recording-lifecycle-review/",
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
    m.insert("pill motion & relocation", vec![
        vec!["drag", "snap", "relocat", "move", "position", "anchor"],
        vec!["screen", "display", "coordinate", "geometry", "position", "anchor"],
    ]);
    m.insert("spoken send parser", vec![
        vec!["parse", "parser", "phrase", "utterance", "intent", "command"],
        vec!["send", "submit"],
    ]);
    m.insert("post-insert submit", vec![
        vec!["enter", "return", "submit"],
        vec!["insert", "delivery"],
        vec!["confirm", "verif", "evidence", "success"],
    ]);
    m.insert("target snapshot & revalidation", vec![
        vec!["target", "focus"],
        vec!["revalid", "identity", "same target", "snapshot"],
    ]);
    m.insert("clipboard transaction", vec![
        vec!["clipboard"],
        vec!["snapshot", "preserve", "save"],
        vec!["restore"],
    ]);
    m.insert("background model download", vec![
        vec!["download", "transfer"],
        vec!["model", "artifact"],
        vec!["background", "resume", "resumable", "checkpoint"],
        vec!["validat", "checksum", "signature", "atomic"],
    ]);
    m.insert("watchconnectivity bridge", vec![
        vec!["wcsession", "watchconnectivity", "watch session"],
        vec!["message", "applicationcontext", "userinfo", "file transfer", "payload"],
        vec!["reachab", "ack", "retry", "queue", "dedup"],
    ]);
    m.insert("watchconnectivity relay", vec![
        vec!["wcsession", "watchconnectivity", "watch session"],
        vec!["message", "applicationcontext", "userinfo", "file transfer", "payload"],
        vec!["ack", "retry", "queue", "dedup", "idempot"],
    ]);
    m.insert("forward queue retry", vec![
        vec!["queue"],
        vec!["retry", "backoff"],
        vec!["idempot", "dedup", "stable id", "operation id"],
    ]);
    m.insert("device registration", vec![
        vec!["device", "identity"],
        vec!["register", "pair", "token", "credential"],
    ]);
    m.insert("ime microphone key", vec![
        vec!["ime", "keyboard", "input method"],
        vec!["microphone", "mic"],
        vec!["start", "stop", "toggle", "capture"],
    ]);
    m.insert("action_recognize_speech", vec![
        vec!["action_recognize_speech", "recognition intent", "recognizer intent"],
        vec!["result", "caller", "activity result"],
    ]);
    m.insert("vad/silence endpointing", vec![
        vec!["vad", "voice activity", "speech"],
        vec!["silence", "endpoint"],
    ]);
    m.insert("verified update install", vec![
        vec!["signature", "signed", "checksum", "hash", "verif"],
        vec!["artifact", "package", "bundle", "release", "update"],
        vec!["install", "replace", "activate", "relaunch"],
        vec!["rollback", "last-good", "prior working", "resume"],
    ]);
    m
}

/// One parsed table row: `(1-based line number, cells)`.
pub type Row = (usize, Vec<String>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    CellCountMismatch { line: usize, expected: usize, got: usize },
    MissingHeader(Vec<String>),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CellCountMismatch { line, expected, got } => {
                write!(f, "line {line}: expected {expected} cells, got {got}")
            }
            Self::MissingHeader(header) => write!(f, "missing table header: {}", header.join(" | ")),
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
        if cells.iter().map(|s| s.as_str()).eq(expected_header.iter().copied()) {
            in_table = true;
            continue;
        }
        if in_table && cells.iter().all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':')) {
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
        return Err(ParseError::MissingHeader(expected_header.iter().map(|s| s.to_string()).collect()));
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
pub fn validate(rows: &[Row], header: &[&str], opts: &ValidateOptions, fs: &dyn ReportFs) -> Vec<String> {
    let mut errors = Vec::new();
    let index: HashMap<&str, usize> = header.iter().enumerate().map(|(i, h)| (*h, i)).collect();
    let signatures = semantic_signatures();

    if let Some(expected) = opts.expected_rows {
        if rows.len() != expected {
            errors.push(format!("expected {expected} rows, found {}", rows.len()));
        }
    }

    let scope_name = if index.contains_key("Scope") { "Scope" } else { "Platform" };
    let mut seen: HashMap<(String, String, String), usize> = HashMap::new();

    for (line_number, cells) in rows {
        let key = (
            cells[index[scope_name]].clone(),
            cells[index["Domain"]].clone(),
            cells[index["Atom"]].clone(),
        );
        if let Some(first) = seen.get(&key) {
            errors.push(format!("line {line_number}: duplicate atom tuple; first at line {first}"));
        } else {
            seen.insert(key, *line_number);
        }

        let evidence = cells[index["Source evidence"]].to_lowercase();
        for token in FORBIDDEN_EVIDENCE {
            if evidence.contains(token) {
                errors.push(format!("line {line_number}: forbidden evidence path `{token}`"));
            }
        }

        let joined = cells.join(" ").to_lowercase();
        for phrase in BOILERPLATE {
            if joined.contains(phrase) {
                errors.push(format!("line {line_number}: prohibited boilerplate `{phrase}`"));
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
        if let (Some(rec_name), Some(groups)) = (recommendation_name, signatures.get(atom_key.as_str())) {
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
            && opts.manifest.as_ref().is_some_and(|m| !m.scope_repos.is_empty())
        {
            let manifest = opts.manifest.as_ref().unwrap();
            let scope = &cells[index["Scope"]];
            let Some(expected_repos) = manifest.scope_repos.get(scope) else {
                errors.push(format!("line {line_number}: scope `{scope}` missing from manifest"));
                continue;
            };

            let mechanism_entries: Vec<&str> = cells[index["Repository mechanisms"]].split("<br>").collect();
            for repo in expected_repos {
                let prefix = format!("{repo}:");
                let matches: Vec<&&str> = mechanism_entries.iter().filter(|e| e.starts_with(&prefix)).collect();
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
                    errors.push(format!("line {line_number}: evidence path escapes `{repo}` root: {relative}"));
                    continue;
                }
                if !fs.is_file(&candidate) {
                    errors.push(format!("line {line_number}: missing evidence file for `{repo}`: {relative}"));
                }
            }
        }
    }

    let repeat_columns: Vec<&str> = ["Best observed", "Best combined", "Recommended implementation", "Rationale / tradeoffs", "Why / tradeoffs"]
        .into_iter()
        .filter(|name| index.contains_key(name))
        .collect();
    let sentinels = ["not found", "unclear", "n/a", "no proven winner"];
    for name in repeat_columns {
        let mut counter: HashMap<String, usize> = HashMap::new();
        for (_, cells) in rows {
            *counter.entry(cells[index[name]].trim().to_string()).or_insert(0) += 1;
        }
        for (value, count) in counter {
            if value.is_empty() || sentinels.contains(&value.to_lowercase().as_str()) {
                continue;
            }
            if count > opts.max_repeat {
                let sample: String = value.chars().take(100).collect::<String>().replace('\n', " ");
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
        let Some(colon) = segment.find(':') else { continue };
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

pub struct RunOutcome {
    pub stdout: String,
    pub code: i32,
}

/// Port of `main()`: parse the report, run [`validate`], and format the
/// `FAIL: N issue(s)` / `PASS: ...` output. Receipt writing (`--write-receipt`)
/// is left to the caller (it needs sha256 + an isolated-clock timestamp,
/// which belong at the process boundary, not in this pure module).
pub fn run(report_text: &str, mode: &str, opts: &ValidateOptions, fs: &dyn ReportFs, report_path: &str) -> RunOutcome {
    let Some(header) = headers(mode) else {
        return RunOutcome { stdout: format!("FAIL: unknown mode `{mode}`"), code: 1 };
    };
    let rows = match parse_table(report_text, header) {
        Ok(r) => r,
        Err(e) => return RunOutcome { stdout: format!("FAIL: {e}"), code: 1 },
    };
    let errors = validate(&rows, header, opts, fs);
    if !errors.is_empty() {
        let mut out = format!("FAIL: {} issue(s)\n", errors.len());
        for issue in &errors {
            out.push_str(&format!("- {issue}\n"));
        }
        return RunOutcome { stdout: out.trim_end().to_string(), code: 1 };
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
            (2usize, vec!["macOS".into(), "Paste".into(), "X".into(), "d".into(), ".cache/foo".into()]),
            (3usize, vec!["macOS".into(), "Paste".into(), "X".into(), "d".into(), "ok/path".into()]),
        ];
        let opts = ValidateOptions { max_repeat: 8, ..Default::default() };
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
        let opts = ValidateOptions { max_repeat: 8, ..Default::default() };
        let outcome = run(text, "inventory", &opts, &NoFs, "report.md");
        assert_eq!(outcome.code, 0);
        assert!(outcome.stdout.starts_with("PASS: report.md (1 rows"));
    }

    #[test]
    fn extract_backticked_pairs() {
        assert_eq!(extract_backticked("Observed `src/a.rs#L1`"), vec!["src/a.rs#L1".to_string()]);
    }
}
