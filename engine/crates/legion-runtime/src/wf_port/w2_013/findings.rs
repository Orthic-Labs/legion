//! Port of `skills/designer/engine/scripts/detector/findings.mjs`.
//!
//! The JS `finding(id, filePath, snippet, line = 0)` looks up antipattern
//! metadata (`name`, `description`, `severity`) from the shared
//! `registry/antipatterns.mjs` table and assembles a finding record. That
//! registry is a large, cross-chunk, shared data table not owned by this
//! chunk (`w2_013`) and has no Rust port in this tree yet, so the lookup
//! itself is left to the caller: [`build_finding`] takes the already
//! resolved antipattern metadata (`name`, `description`, `severity`)
//! rather than performing the id -> metadata lookup, and mirrors the JS
//! assembly logic exactly (including the `severity` default of
//! `"warning"` when the registry entry's severity is empty, and the
//! `line = 0` default).

/// Mirrors the JS finding object shape:
/// `{ antipattern, name, description, severity, file, line, snippet }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Finding {
    pub antipattern: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub file: String,
    pub line: u32,
    pub snippet: String,
}

/// Faithful port of `finding(id, filePath, snippet, line = 0)` given the
/// antipattern's already-resolved `name`/`description`/`severity` (in JS,
/// `ap.severity || 'warning'`). Pass an empty string for `severity` to get
/// the same `"warning"` default the JS code falls back to.
pub fn build_finding(
    antipattern_id: &str,
    name: &str,
    description: &str,
    severity: &str,
    file_path: &str,
    snippet: &str,
    line: u32,
) -> Finding {
    let severity = if severity.is_empty() {
        "warning"
    } else {
        severity
    };
    Finding {
        antipattern: antipattern_id.to_string(),
        name: name.to_string(),
        description: description.to_string(),
        severity: severity.to_string(),
        file: file_path.to_string(),
        line,
        snippet: snippet.to_string(),
    }
}

/// Convenience wrapper matching the JS default-parameter call site
/// `finding(id, filePath, snippet)` (line defaults to 0).
pub fn build_finding_default_line(
    antipattern_id: &str,
    name: &str,
    description: &str,
    severity: &str,
    file_path: &str,
    snippet: &str,
) -> Finding {
    build_finding(
        antipattern_id,
        name,
        description,
        severity,
        file_path,
        snippet,
        0,
    )
}
