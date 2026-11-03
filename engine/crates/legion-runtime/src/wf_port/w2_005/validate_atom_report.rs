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
//! `ReportFs` so `validate` itself stays pure and unit-testable; only
//! [`run`] touches the trait.

use std::collections::{BTreeMap, BTreeSet, HashMap};

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
    "example-app-recording-lifecycle-review/",
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
    /// Resolves existing paths to canonical absolute paths (including symlinks),
    /// and collapses missing paths lexically, for evidence containment checks.
    fn resolve(&self, path: &str) -> String;
    /// Returns the checked-out commit and whether tracked/untracked worktree
    /// changes are absent. Implementations that cannot inspect Git may keep
    /// the default; strict revision binding will reject the unavailable source.
    fn revision_snapshot(&self, _root: &str) -> Result<RevisionSnapshot, String> {
        Err("repository revision snapshot unavailable".to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionSnapshot {
    pub commit: String,
    pub clean: bool,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    /// Product name (`product`, default `Current product`).
    pub product: String,
    pub repo_roots: BTreeMap<String, String>,
    pub scope_repos: BTreeMap<String, Vec<String>>,
    /// `repo -> scope -> platforms` (`repo_targets`).
    pub repo_targets: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    /// Exact full Git commit IDs for repositories in the frozen corpus.
    pub repo_revisions: BTreeMap<String, String>,
    /// Whether the current product root was explicitly supplied by the caller.
    pub product_root_declared: bool,
}

/// Options mirroring the CLI flags (`--expected-rows`, `--max-repeat`,
/// `--repository`, `--canon`, `--ledgers`, manifest content already parsed).
#[derive(Debug, Clone, Default)]
pub struct ValidateOptions {
    pub expected_rows: Option<usize>,
    pub max_repeat: usize,
    pub manifest: Option<Manifest>,
    /// `--repository`: the repository every ledger row / mechanism card must name.
    pub repository: Option<String>,
    /// `--canon`: canon table path, read for the mechanism-card and final coverage checks.
    pub canon: Option<String>,
    /// `--ledgers`: repo-ledger table paths, read for the canon provenance checks.
    pub ledgers: Option<Vec<String>>,
    /// Refuse PASS unless every source root used by this report is pinned to
    /// its declared commit and has a clean tracked/untracked worktree.
    pub require_revisions: bool,
}

/// Historical 11-column `final` header (`267bae38`). The current 8-column form stays accepted.
const FINAL_HISTORICAL_HEADER: &[&str] = &[
    "Scope",
    "Domain",
    "Atom ID",
    "Atom",
    "Current product",
    "Best observed",
    "Recommended implementation",
    "Material gap",
    "Why / tradeoffs",
    "Source evidence",
    "Confidence",
];

/// Header a report is parsed against: the historical 11-column `final` shape when the report
/// carries it, otherwise [`headers`].
pub fn effective_header(report_text: &str, mode: &str) -> Option<&'static [&'static str]> {
    if mode == "final" && has_table_header(report_text, FINAL_HISTORICAL_HEADER) {
        return Some(FINAL_HISTORICAL_HEADER);
    }
    headers(mode)
}

fn has_table_header(text: &str, header: &[&str]) -> bool {
    text.lines().any(|raw| {
        if !raw.starts_with('|') {
            return false;
        }
        let cells: Vec<&str> = raw
            .trim()
            .trim_matches('|')
            .split('|')
            .map(str::trim)
            .collect();
        cells.as_slice() == header
    })
}

/// Historical `repr` of a tuple of strings for error text: `('a', 'b')`.
pub fn py_tuple(items: &[&str]) -> String {
    let body: Vec<String> = items.iter().map(|item| format!("'{item}'")).collect();
    format!("({})", body.join(", "))
}

/// Port of `load_manifest`'s cross-field checks. A declared `current_product_root` becomes the
/// product's repo root, and then every scope repository (and the product, when a root is declared)
/// needs a non-empty platform list under `repo_targets`.
pub fn finish_manifest(
    mut manifest: Manifest,
    current_product_root: Option<String>,
) -> Result<Manifest, String> {
    let product_root_declared = current_product_root.is_some();
    if let Some(root) = current_product_root {
        manifest.repo_roots.insert(manifest.product.clone(), root);
        manifest.product_root_declared = true;
    }
    for (repo, revision) in &manifest.repo_revisions {
        if !manifest.repo_roots.contains_key(repo) {
            return Err(format!(
                "REVISION_UNPROVEN: repo_revisions references unknown repository `{repo}`"
            ));
        }
        if !valid_commit_id(revision) {
            return Err(format!(
                "REVISION_UNPROVEN: repo_revisions has invalid full commit ID for `{repo}`"
            ));
        }
    }
    for (scope, repos) in &manifest.scope_repos {
        for repo in repos {
            if !manifest.repo_roots.contains_key(repo) {
                return Err(format!(
                    "scope `{scope}` references unknown repository `{repo}`"
                ));
            }
            if !platforms_nonempty(&manifest, repo, scope) {
                return Err(format!(
                    "repo_targets lacks non-empty `{repo}` / `{scope}` platform list"
                ));
            }
        }
        if product_root_declared && !platforms_nonempty(&manifest, &manifest.product, scope) {
            return Err(format!(
                "repo_targets lacks non-empty `{}` / `{scope}` platform list",
                manifest.product
            ));
        }
    }
    Ok(manifest)
}

fn valid_commit_id(commit: &str) -> bool {
    matches!(commit.len(), 40 | 64)
        && commit == commit.to_ascii_lowercase()
        && commit.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn platforms_nonempty(manifest: &Manifest, repo: &str, scope: &str) -> bool {
    manifest
        .repo_targets
        .get(repo)
        .and_then(|per_scope| per_scope.get(scope))
        .is_some_and(|platforms| {
            !platforms.is_empty() && platforms.iter().all(|p| !p.trim().is_empty())
        })
}

/// Product name used by the applicability and evidence checks.
fn manifest_product(opts: &ValidateOptions) -> &str {
    opts.manifest
        .as_ref()
        .map(|m| m.product.as_str())
        .unwrap_or("Current product")
}

fn pos(header: &[&str], name: &str) -> usize {
    header
        .iter()
        .position(|h| *h == name)
        .expect("static header column")
}

/// Reads and parses a companion table (`--canon`, `--ledgers`) through the injected filesystem.
fn read_table_file(fs: &dyn ReportFs, path: &str, header: &[&str]) -> Result<Vec<Row>, String> {
    let text = fs.read_to_string(path).map_err(|e| e.to_string())?;
    parse_table(&text, header).map_err(|e| e.to_string())
}

/// Port of `evidence_pairs`: `repo: \`path#symbol\`` citations, split on `;` boundaries.
fn evidence_pairs(cell: &str) -> Vec<(String, String)> {
    let pattern = Regex::new(r"(?:^|;\s*)([^:;]+):\s*`([^`]+)`").expect("static pattern is valid");
    pattern
        .captures_iter(cell)
        .map(|caps| (caps[1].trim().to_string(), caps[2].to_string()))
        .collect()
}

/// `(scope, domain, atom, repo)` expected or actual mechanism-card key.
type CardBase = (String, String, String, String);
/// `(scope, domain, atom, repo, platform)` expected or actual mechanism-card key.
type CardExact = (String, String, String, String, String);

/// Port of `expected_card_keys`: every canon atom needs a card for the product and for each
/// scope repository, plus one per configured platform. `repository` narrows the set when given.
fn expected_card_keys(
    canon_rows: &[Row],
    manifest: &Manifest,
    repository: Option<&str>,
) -> (BTreeSet<CardBase>, BTreeSet<CardExact>) {
    let header = headers("canon").unwrap_or(&[]);
    let (scope_at, domain_at, atom_at) = (
        pos(header, "Scope"),
        pos(header, "Domain"),
        pos(header, "Atom ID"),
    );
    let mut base: BTreeSet<CardBase> = BTreeSet::new();
    let mut exact: BTreeSet<CardExact> = BTreeSet::new();
    for (_, cells) in canon_rows {
        let scope = cells[scope_at].clone();
        let domain = cells[domain_at].clone();
        let atom = cells[atom_at].clone();
        let mut candidates: Vec<String> = vec![manifest.product.clone()];
        if let Some(repos) = manifest.scope_repos.get(&scope) {
            candidates.extend(repos.iter().cloned());
        }
        if let Some(filter) = repository {
            candidates.retain(|name| name.as_str() == filter);
        }
        for repo in candidates {
            base.insert((scope.clone(), domain.clone(), atom.clone(), repo.clone()));
            if let Some(platforms) = manifest
                .repo_targets
                .get(&repo)
                .and_then(|per_scope| per_scope.get(&scope))
            {
                for platform in platforms {
                    exact.insert((
                        scope.clone(),
                        domain.clone(),
                        atom.clone(),
                        repo.clone(),
                        platform.clone(),
                    ));
                }
            }
        }
    }
    (base, exact)
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
                if !std::path::Path::new(&candidate)
                    .starts_with(std::path::Path::new(&root_resolved))
                {
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
    let placeholders = ["not found", "unclear", "n/a", "no proven winner"];
    for name in repeat_columns {
        let mut counter: HashMap<String, usize> = HashMap::new();
        for (_, cells) in rows {
            *counter
                .entry(cells[index[name]].trim().to_string())
                .or_insert(0) += 1;
        }
        for (value, count) in counter {
            if value.is_empty() || placeholders.contains(&value.to_lowercase().as_str()) {
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

fn provenance_entries(cell: &str) -> Vec<&str> {
    cell.split("<br>").collect()
}

fn collect_referenced_roots(
    rows: &[Row],
    header: &[&str],
    manifest: &Manifest,
    roots: &mut BTreeSet<String>,
) {
    if let Some(column) = header.iter().position(|name| *name == "Repository") {
        for (_, cells) in rows {
            let repo = cells[column].trim();
            if manifest.repo_roots.contains_key(repo) {
                roots.insert(repo.to_string());
            }
        }
    }
    if let Some(column) = header.iter().position(|name| *name == "Source evidence") {
        for (_, cells) in rows {
            for (repo, _) in extract_evidence_citations(&cells[column]) {
                if manifest.repo_roots.contains_key(&repo) {
                    roots.insert(repo);
                }
            }
        }
    }
    if let Some(column) = header
        .iter()
        .position(|name| *name == "Repository provenance")
    {
        for (_, cells) in rows {
            for entry in provenance_entries(&cells[column]) {
                if let Some((repo, _)) = entry.split_once(':') {
                    let repo = repo.trim();
                    if manifest.repo_roots.contains_key(repo) {
                        roots.insert(repo.to_string());
                    }
                }
            }
        }
    }
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

/// Modes ported from the historical validator (`267bae38`) that run through
/// [`validate_table_mode`]. `final` takes that path only for the historical 11-column shape
/// (see [`effective_header`]); the current 8-column form keeps the `validate` path.
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

/// Historical `STATUS_VALUES` (mechanism-cards) and its placeholder values.
const STATUS_VALUES: &[&str] = &["OBSERVED", "UNCLEAR", "NOT FOUND", "N/A"];
const PLACEHOLDER_VALUES: &[&str] = &["not found", "unclear", "n/a", "no proven winner"];

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
    if !std::path::Path::new(&candidate).starts_with(std::path::Path::new(&root_resolved)) {
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

/// Row checks for the `repo-ledger`, `canon`, `mechanism-cards`, `handoff`, and historical
/// 11-column `final` modes, ported from the historical `main()` (`267bae38`). Covers the per-row
/// rules, the `--repository` match, the canon/ledger cross-checks (`--canon`, `--ledgers`), the
/// mechanism-card expected-set check, the product-applicability check, and final canon coverage.
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

    if matches!(mode, "repo-ledger" | "canon" | "mechanism-cards" | "final")
        && opts.manifest.is_none()
    {
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

    let repository = opts.repository.as_deref().filter(|r| !r.is_empty());
    if mode == "repo-ledger" && repository.is_none() {
        errors.push("repo-ledger mode requires --repository".to_string());
    }
    if let Some(repo) = repository {
        if manifest_root(opts, repo).is_none() {
            errors.push(format!("repository `{repo}` missing from manifest roots"));
        }
    }
    let product = manifest_product(opts).to_string();
    let mut ledger_behaviors: BTreeSet<(String, String)> = BTreeSet::new();
    let mut used_behaviors: BTreeSet<(String, String)> = BTreeSet::new();
    let mut actual_card_base: BTreeSet<CardBase> = BTreeSet::new();
    let mut actual_card_exact: BTreeSet<CardExact> = BTreeSet::new();
    let mut actual_final_keys: BTreeSet<(String, String, String)> = BTreeSet::new();
    if mode == "canon" {
        match opts.ledgers.as_ref() {
            None => errors.push("canon mode requires --ledgers".to_string()),
            Some(ledgers) => {
                for ledger in ledgers {
                    match read_table_file(fs, ledger, headers("repo-ledger").unwrap_or(&[])) {
                        Ok(ledger_rows) => {
                            let header = headers("repo-ledger").unwrap_or(&[]);
                            let (repo_at, behavior_at) =
                                (pos(header, "Repository"), pos(header, "Behavior ID"));
                            for (_, cells) in &ledger_rows {
                                let key = (cells[repo_at].clone(), cells[behavior_at].clone());
                                if ledger_behaviors.contains(&key) {
                                    errors.push(format!(
                                        "duplicate repo-ledger behavior: {}",
                                        py_tuple(&[key.0.as_str(), key.1.as_str()])
                                    ));
                                }
                                ledger_behaviors.insert(key);
                            }
                        }
                        Err(e) => {
                            errors.push(format!("invalid repo ledger: {e}"));
                            break;
                        }
                    }
                }
            }
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
                if opts.repository.as_deref() != Some(repo.as_str()) {
                    errors.push(format!(
                        "line {line}: ledger repository `{repo}` does not match `{}`",
                        opts.repository.as_deref().unwrap_or("None")
                    ));
                }
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
                let entries = provenance_entries(&provenance_text);
                if entries.iter().any(|entry| !entry.contains(':')) {
                    errors.push(format!(
                        "line {line}: repository provenance lacks `Repository:Behavior ID`"
                    ));
                }
                for entry in entries {
                    let (repo, behavior_id) = entry.split_once(':').unwrap_or((entry, ""));
                    let (repo, behavior_id) = (repo.trim(), behavior_id.trim());
                    let provenance_key = (repo.to_string(), behavior_id.to_string());
                    used_behaviors.insert(provenance_key.clone());
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
                    if !ledger_behaviors.is_empty() && !ledger_behaviors.contains(&provenance_key) {
                        errors.push(format!(
                            "line {line}: provenance behavior not found in ledgers: {}",
                            py_tuple(&[repo, behavior_id])
                        ));
                    }
                }
            }
            "mechanism-cards" => {
                let repo = c("Repository");
                let scope = c("Scope");
                if let Some(expected_repo) = repository {
                    if repo != expected_repo {
                        errors.push(format!(
                            "line {line}: card repository `{repo}` does not match `{expected_repo}`"
                        ));
                    }
                }
                let status_raw = c("Status");
                let status = status_raw.to_uppercase();
                actual_card_base.insert((scope.clone(), c("Domain"), c("Atom ID"), repo.clone()));
                actual_card_exact.insert((
                    scope.clone(),
                    c("Domain"),
                    c("Atom ID"),
                    repo.clone(),
                    c("Platform"),
                ));
                if !STATUS_VALUES.contains(&status.as_str()) {
                    errors.push(format!(
                        "line {line}: invalid mechanism status `{status_raw}`"
                    ));
                }
                let applicable = repo == product
                    || opts
                        .manifest
                        .as_ref()
                        .and_then(|m| m.scope_repos.get(&scope))
                        .is_some_and(|repos| repos.contains(&repo));
                if !applicable {
                    errors.push(format!(
                        "line {line}: `{repo}` is not applicable to scope `{scope}`"
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
                                    || PLACEHOLDER_VALUES.contains(&value.to_lowercase().as_str())
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
            "final" => {
                let scope = c("Scope");
                actual_final_keys.insert((scope, c("Domain"), c("Atom ID")));
                let baseline = c("Current product").to_lowercase();
                for token in [
                    "implementation=",
                    "verification=",
                    "qualification=",
                    "delivery=",
                ] {
                    if !baseline.contains(token) {
                        errors.push(format!(
                            "line {line}: current-product baseline lacks `{token}`"
                        ));
                    }
                }
                let pairs = evidence_pairs(&c("Source evidence"));
                let evidence_repos: BTreeSet<String> =
                    pairs.iter().map(|(repo, _)| repo.clone()).collect();
                if !evidence_repos.contains(&product) {
                    errors.push(format!(
                        "line {line}: current-product evidence lacks `{product}:` entry"
                    ));
                }
                for (repo, cited) in &pairs {
                    match manifest_root(opts, repo) {
                        None => errors.push(format!(
                            "line {line}: evidence repository `{repo}` is unknown"
                        )),
                        Some(root) => validate_citation(&mut errors, line, repo, cited, root, fs),
                    }
                }
                let gap = c("Material gap").to_uppercase();
                if !matches!(gap.as_str(), "YES" | "NO" | "UNRESOLVED") {
                    errors.push(format!(
                        "line {line}: material gap must be YES, NO, or UNRESOLVED"
                    ));
                }
                if gap == "YES" {
                    let best = c("Best observed").to_lowercase();
                    if best.is_empty() || PLACEHOLDER_VALUES.contains(&best.as_str()) {
                        errors.push(format!(
                            "line {line}: material gap YES requires a proven winner"
                        ));
                    }
                    if !evidence_repos.iter().any(|repo| *repo != product) {
                        errors.push(format!(
                            "line {line}: material gap YES lacks donor evidence"
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    if mode == "mechanism-cards" {
        match (opts.manifest.as_ref(), opts.canon.as_deref()) {
            (_, None) => errors.push("mechanism-cards mode requires --canon".to_string()),
            (None, Some(_)) => {}
            (Some(manifest), Some(canon_path)) => {
                match read_table_file(fs, canon_path, headers("canon").unwrap_or(&[])) {
                    Ok(canon_rows) => {
                        let (expected_base, expected_exact) =
                            expected_card_keys(&canon_rows, manifest, opts.repository.as_deref());
                        for item in expected_base.difference(&actual_card_base) {
                            errors.push(format!(
                                "missing mechanism card: {}",
                                py_tuple(&[
                                    item.0.as_str(),
                                    item.1.as_str(),
                                    item.2.as_str(),
                                    item.3.as_str()
                                ])
                            ));
                        }
                        for item in expected_exact.difference(&actual_card_exact) {
                            errors.push(format!(
                                "missing mechanism card: {}",
                                py_tuple(&[
                                    item.0.as_str(),
                                    item.1.as_str(),
                                    item.2.as_str(),
                                    item.3.as_str(),
                                    item.4.as_str(),
                                ])
                            ));
                        }
                        for item in actual_card_base.difference(&expected_base) {
                            errors.push(format!(
                                "unexpected mechanism card: {}",
                                py_tuple(&[
                                    item.0.as_str(),
                                    item.1.as_str(),
                                    item.2.as_str(),
                                    item.3.as_str()
                                ])
                            ));
                        }
                        let configured: BTreeSet<CardBase> = expected_exact
                            .iter()
                            .map(|e| (e.0.clone(), e.1.clone(), e.2.clone(), e.3.clone()))
                            .collect();
                        for item in actual_card_exact.iter() {
                            let base_key = (
                                item.0.clone(),
                                item.1.clone(),
                                item.2.clone(),
                                item.3.clone(),
                            );
                            if configured.contains(&base_key) && !expected_exact.contains(item) {
                                errors.push(format!(
                                    "unexpected mechanism card: {}",
                                    py_tuple(&[
                                        item.0.as_str(),
                                        item.1.as_str(),
                                        item.2.as_str(),
                                        item.3.as_str(),
                                        item.4.as_str(),
                                    ])
                                ));
                            }
                        }
                    }
                    Err(e) => errors.push(format!("invalid canon: {e}")),
                }
            }
        }
    }

    if mode == "final" {
        match opts.canon.as_deref() {
            None => errors.push("final mode requires --canon".to_string()),
            Some(canon_path) => {
                let header = headers("canon").unwrap_or(&[]);
                match read_table_file(fs, canon_path, header) {
                    Ok(canon_rows) => {
                        let (scope_at, domain_at, atom_at) = (
                            pos(header, "Scope"),
                            pos(header, "Domain"),
                            pos(header, "Atom ID"),
                        );
                        let expected: BTreeSet<(String, String, String)> = canon_rows
                            .iter()
                            .map(|(_, cells)| {
                                (
                                    cells[scope_at].clone(),
                                    cells[domain_at].clone(),
                                    cells[atom_at].clone(),
                                )
                            })
                            .collect();
                        for item in expected.difference(&actual_final_keys) {
                            errors.push(format!(
                                "final report missing canon atom: {}",
                                py_tuple(&[item.0.as_str(), item.1.as_str(), item.2.as_str()])
                            ));
                        }
                        for item in actual_final_keys.difference(&expected) {
                            errors.push(format!(
                                "final report contains unexpected atom: {}",
                                py_tuple(&[item.0.as_str(), item.1.as_str(), item.2.as_str()])
                            ));
                        }
                    }
                    Err(e) => errors.push(format!("invalid canon: {e}")),
                }
            }
        }
    }

    if mode == "canon" {
        for item in ledger_behaviors.difference(&used_behaviors) {
            errors.push(format!(
                "repo-ledger behavior missing from canon provenance: {}",
                py_tuple(&[item.0.as_str(), item.1.as_str()])
            ));
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
            if value.is_empty() || PLACEHOLDER_VALUES.contains(&value.to_lowercase().as_str()) {
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
    pub revision_bound: bool,
    pub declared_revisions: BTreeMap<String, String>,
    pub observed_revisions: BTreeMap<String, RevisionSnapshot>,
}

struct RevisionBinding {
    errors: Vec<String>,
    revision_bound: bool,
    declared_revisions: BTreeMap<String, String>,
    observed_revisions: BTreeMap<String, RevisionSnapshot>,
}

fn revision_unproven(reason: impl Into<String>) -> String {
    format!("REVISION_UNPROVEN: {}", reason.into())
}

fn bind_report_revisions(
    rows: &[Row],
    header: &[&str],
    mode: &str,
    opts: &ValidateOptions,
    fs: &dyn ReportFs,
) -> RevisionBinding {
    let mut binding = RevisionBinding {
        errors: Vec::new(),
        revision_bound: false,
        declared_revisions: BTreeMap::new(),
        observed_revisions: BTreeMap::new(),
    };
    let Some(manifest) = opts.manifest.as_ref() else {
        if opts.require_revisions {
            binding
                .errors
                .push(revision_unproven("--require-revisions requires --manifest"));
        }
        return binding;
    };

    let mut roots = BTreeSet::new();
    let mut scope_mapping_complete = true;
    if mode == "repo-ledger" {
        if let Some(repo) = opts.repository.as_ref() {
            roots.insert(repo.clone());
        }
    } else {
        let scope_column = header
            .iter()
            .position(|name| *name == "Scope" || *name == "Platform");
        if let Some(scope_column) = scope_column {
            for (_, cells) in rows {
                let scope = &cells[scope_column];
                match manifest.scope_repos.get(scope) {
                    Some(repositories) if !repositories.is_empty() => {
                        roots.extend(repositories.iter().cloned());
                    }
                    Some(_) => {
                        scope_mapping_complete = false;
                        if opts.require_revisions {
                            binding.errors.push(revision_unproven(format!(
                                "manifest has no source repositories for report scope `{scope}`"
                            )));
                        }
                    }
                    None => {
                        scope_mapping_complete = false;
                        if opts.require_revisions {
                            binding.errors.push(revision_unproven(format!(
                                "manifest lacks source repository mapping for report scope `{scope}`"
                            )));
                        }
                    }
                }
            }
        }
    }
    if manifest.product_root_declared {
        roots.insert(manifest.product.clone());
    }
    collect_referenced_roots(rows, header, manifest, &mut roots);

    match mode {
        "canon" => {
            if let Some(ledgers) = opts.ledgers.as_ref() {
                let ledger_header = headers("repo-ledger").unwrap_or(&[]);
                for ledger in ledgers {
                    if let Ok(ledger_rows) = read_table_file(fs, ledger, ledger_header) {
                        collect_referenced_roots(&ledger_rows, ledger_header, manifest, &mut roots);
                    }
                }
            }
        }
        "mechanism-cards" | "final" => {
            if let Some(canon_path) = opts.canon.as_deref() {
                let canon_header = headers("canon").unwrap_or(&[]);
                if let Ok(canon_rows) = read_table_file(fs, canon_path, canon_header) {
                    collect_referenced_roots(&canon_rows, canon_header, manifest, &mut roots);
                }
            }
        }
        _ => {}
    }

    if opts.require_revisions && roots.is_empty() {
        binding.errors.push(revision_unproven(
            "--require-revisions found no source roots used by the report",
        ));
        return binding;
    }

    let strict = opts.require_revisions;
    let mut all_bound = !roots.is_empty() && scope_mapping_complete;
    for repo in roots {
        let root = manifest.repo_roots.get(&repo);
        let declared = manifest.repo_revisions.get(&repo);
        if let Some(revision) = declared {
            binding
                .declared_revisions
                .insert(repo.clone(), revision.clone());
            if !valid_commit_id(revision) {
                binding.errors.push(revision_unproven(format!(
                    "manifest has invalid full commit ID for `{repo}`"
                )));
                all_bound = false;
                continue;
            }
        } else if strict {
            binding.errors.push(revision_unproven(format!(
                "manifest lacks exact repository revision for `{repo}`"
            )));
            all_bound = false;
            continue;
        } else {
            all_bound = false;
            continue;
        }

        let Some(root) = root else {
            binding.errors.push(revision_unproven(format!(
                "manifest lacks source root for revision-bound repository `{repo}`"
            )));
            all_bound = false;
            continue;
        };
        let snapshot = match fs.revision_snapshot(root) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                binding.errors.push(revision_unproven(format!(
                    "could not inspect repository snapshot for `{repo}`: {error}"
                )));
                all_bound = false;
                continue;
            }
        };
        binding
            .observed_revisions
            .insert(repo.clone(), snapshot.clone());
        if !valid_commit_id(&snapshot.commit) {
            binding.errors.push(revision_unproven(format!(
                "source snapshot returned invalid full commit ID for `{repo}`"
            )));
            all_bound = false;
            continue;
        }
        if !snapshot.commit.eq_ignore_ascii_case(declared.unwrap()) {
            binding.errors.push(revision_unproven(format!(
                "repository `{repo}` revision mismatch: manifest declares {}, source is {}",
                declared.unwrap(),
                snapshot.commit
            )));
            all_bound = false;
        }
        if !snapshot.clean {
            if strict {
                binding.errors.push(revision_unproven(format!(
                    "repository `{repo}` source snapshot has tracked or untracked changes"
                )));
            }
            all_bound = false;
        }
    }
    binding.revision_bound = all_bound && binding.errors.is_empty();
    binding
}

/// Port of `main()`: parse the report, run `validate`, and format the
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
    let Some(header) = effective_header(report_text, mode) else {
        return RunOutcome {
            stdout: format!("FAIL: unknown mode `{mode}`"),
            code: 1,
            revision_bound: false,
            declared_revisions: BTreeMap::new(),
            observed_revisions: BTreeMap::new(),
        };
    };
    let rows = match parse_table(report_text, header) {
        Ok(r) => r,
        Err(e) => {
            return RunOutcome {
                stdout: format!("FAIL: {e}"),
                code: 1,
                revision_bound: false,
                declared_revisions: BTreeMap::new(),
                observed_revisions: BTreeMap::new(),
            }
        }
    };
    let revision_binding = bind_report_revisions(&rows, header, mode, opts, fs);
    let historical_final = mode == "final" && header == FINAL_HISTORICAL_HEADER;
    let mut errors = if is_table_mode(mode) || historical_final {
        validate_table_mode(mode, &rows, header, opts, fs)
    } else {
        validate(&rows, header, opts, fs)
    };
    errors.extend(revision_binding.errors.iter().cloned());
    if !errors.is_empty() {
        let mut out = format!("FAIL: {} issue(s)\n", errors.len());
        for issue in &errors {
            out.push_str(&format!("- {issue}\n"));
        }
        return RunOutcome {
            stdout: out.trim_end().to_string(),
            code: 1,
            revision_bound: revision_binding.revision_bound,
            declared_revisions: revision_binding.declared_revisions,
            observed_revisions: revision_binding.observed_revisions,
        };
    }
    RunOutcome {
        stdout: format!("PASS: {report_path} ({} rows, mode={mode})", rows.len()),
        code: 0,
        revision_bound: revision_binding.revision_bound,
        declared_revisions: revision_binding.declared_revisions,
        observed_revisions: revision_binding.observed_revisions,
    }
}
