//! Port of `main.mjs`'s output formatting: `formatFindingSummary` and
//! `formatFindings`.

use serde::Serialize;
use serde_json::Value;

/// The finding shape the CLI formats. A unifying record over the several
/// per-engine `Finding` shapes in this tree (`wf_port::r07::findings::Finding`,
/// `wf_port::w2_013::findings::Finding`, `wf_port::w2_011::design_system::
/// DesignFinding`, `wf_port::r08::sweep_live::SweepFinding`) so `main.mjs`'s
/// single findings array — which in JS holds whatever shape each engine's
/// `finding()` call produced, since JS is untyped — has one Rust type to
/// flow through `filterDetectionFindings`/`formatFindings`/
/// `filterByProviders` here. `imported_by` mirors the ad hoc
/// `f.importedBy = importerNames` annotation `main.mjs` adds to directory
/// scan results.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CliFinding {
    pub antipattern: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    pub file: String,
    pub line: u32,
    pub snippet: String,
    #[serde(skip_serializing_if = "Option::is_none", rename = "ignoreValue")]
    pub ignore_value: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", rename = "importedBy")]
    pub imported_by: Vec<String>,
}

impl CliFinding {
    pub fn new(antipattern: impl Into<String>, file: impl Into<String>, line: u32, snippet: impl Into<String>) -> Self {
        CliFinding {
            antipattern: antipattern.into(),
            name: None,
            description: None,
            severity: None,
            file: file.into(),
            line,
            snippet: snippet.into(),
            ignore_value: None,
            imported_by: Vec::new(),
        }
    }
}

/// Port of `formatFindingSummary(count)`.
pub fn format_finding_summary(count: usize) -> String {
    format!("{count} anti-pattern{} found.", if count == 1 { "" } else { "s" })
}

/// Port of `formatFindings(findings, jsonMode)`'s JSON branch:
/// `JSON.stringify(findings, null, 2)`.
pub fn format_findings_json(findings: &[CliFinding]) -> String {
    // serde's struct field order matches declaration order, mirroring the
    // JS object's own key order in `JSON.stringify`.
    let values: Vec<Value> = findings
        .iter()
        .map(|f| serde_json::to_value(f).expect("CliFinding serializes"))
        .collect();
    serde_json::to_string_pretty(&Value::Array(values)).expect("findings serialize")
}

/// Port of `formatFindings(findings, jsonMode=false)`'s text branch: groups
/// by `file` (insertion order, matching JS `Object.entries` over a plain
/// object populated in iteration order), prints an `(imported by ...)` note
/// taken from the first item in each group, then each finding's
/// `line`/`antipattern`/`snippet`/`description`, and a trailing summary.
pub fn format_findings_text(findings: &[CliFinding]) -> String {
    let mut order: Vec<String> = Vec::new();
    // Map<file, Vec<&CliFinding>>, but keep insertion order without pulling
    // in indexmap: track key order separately, matching JS's own
    // insertion-ordered plain-object grouping.
    let mut groups: std::collections::HashMap<String, Vec<&CliFinding>> = std::collections::HashMap::new();
    for f in findings {
        if !groups.contains_key(&f.file) {
            order.push(f.file.clone());
        }
        groups.entry(f.file.clone()).or_default().push(f);
    }

    let mut out: Vec<String> = Vec::new();
    for file in &order {
        let items = &groups[file];
        let import_note = match items.first().map(|f| &f.imported_by) {
            Some(v) if !v.is_empty() => format!(" (imported by {})", v.join(", ")),
            _ => String::new(),
        };
        out.push(format!("\n{file}{import_note}"));
        for item in items {
            let line_prefix = if item.line != 0 {
                format!("line {}: ", item.line)
            } else {
                String::new()
            };
            out.push(format!("  {line_prefix}[{}] {}", item.antipattern, item.snippet));
            out.push(format!("    \u{2192} {}", item.description.clone().unwrap_or_default()));
        }
    }
    out.push(format!("\n{}", format_finding_summary(findings.len())));
    out.join("\n")
}

/// Port of `formatFindings(findings, jsonMode)`: dispatches to the JSON or
/// text branch.
pub fn format_findings(findings: &[CliFinding], json_mode: bool) -> String {
    if json_mode {
        format_findings_json(findings)
    } else {
        format_findings_text(findings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_pluralizes() {
        assert_eq!(format_finding_summary(0), "0 anti-patterns found.");
        assert_eq!(format_finding_summary(1), "1 anti-pattern found.");
        assert_eq!(format_finding_summary(2), "2 anti-patterns found.");
    }

    #[test]
    fn text_groups_by_file_in_first_seen_order() {
        let mut a = CliFinding::new("side-tab", "b.css", 3, "border-l-4");
        a.description = Some("desc-a".into());
        let mut c = CliFinding::new("gradient-text", "a.css", 0, "bg-clip-text");
        c.description = Some("desc-c".into());
        let out = format_findings_text(&[a, c]);
        assert!(out.find("b.css").unwrap() < out.find("a.css").unwrap());
        assert!(out.contains("line 3: [side-tab] border-l-4"));
        assert!(out.contains("[gradient-text] bg-clip-text"));
        assert!(!out.contains("line 0:"));
        assert!(out.ends_with("2 anti-patterns found."));
    }

    #[test]
    fn text_notes_imported_by_from_first_item() {
        let mut f = CliFinding::new("side-tab", "x.css", 1, "s");
        f.description = Some("d".into());
        f.imported_by = vec!["a.js".into(), "b.js".into()];
        let out = format_findings_text(&[f]);
        assert!(out.contains("x.css (imported by a.js, b.js)"));
    }

    #[test]
    fn json_round_trips_findings() {
        let mut f = CliFinding::new("side-tab", "x.css", 1, "s");
        f.ignore_value = Some("v".into());
        let out = format_findings_json(&[f]);
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed[0]["antipattern"], "side-tab");
        assert_eq!(parsed[0]["ignoreValue"], "v");
    }
}
