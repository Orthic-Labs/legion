//! Rust port of the pure, data-shape validation core of `skills/seo/scripts/seo_closure.py`.
//!
//! `seo_closure.py` is a repository-structure closure gate: it walks the live `skills/seo`
//! tree, reads several JSON config files and markdown references, and cross-checks them
//! against required-file sets. The filesystem walking/reading is not ported; what is ported
//! verbatim is the pure validation logic that operates on already-loaded data: the
//! `##`-heading slug extractor and the phase catalog's structural checks (status
//! vocabulary, critical-gate set, and contiguous, non-overlapping `source_lines` ranges).
//! A host wrapper reads the files and hands their parsed contents to these functions.

use std::collections::BTreeSet;

/// Port of `headings(path)`: for each `## Heading Text` line, produce the same slug as
/// Python's `re.sub(r'[^a-z0-9]+', '-', match.group(1).lower()).strip('-')`.
pub fn headings(markdown: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in markdown.lines() {
        let Some(rest) = line.strip_prefix("## ") else {
            continue;
        };
        let heading = rest.trim_end();
        if heading.is_empty() {
            continue;
        }
        out.insert(slugify(heading));
    }
    out
}

fn slugify(heading: &str) -> String {
    let mut slug = String::with_capacity(heading.len());
    let mut last_was_sep = false;
    for ch in heading.to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch);
            last_was_sep = false;
        } else if !last_was_sep {
            slug.push('-');
            last_was_sep = true;
        }
    }
    slug.trim_matches('-').to_string()
}

/// A phase entry's minimal shape needed for the structural checks, mirroring the fields of
/// `control-catalog.json`'s `phases[]` that `check()` validates.
#[derive(Debug, Clone)]
pub struct PhaseRange {
    pub id: i64,
    pub source_lines: Option<(i64, i64)>,
    pub has_owners: bool,
}

/// Port of the phase-id, status-vocabulary, critical-gate, and `source_lines` contiguity
/// checks inside `check()`. Returns the same error strings the Python tool prints (prefixed
/// `FAIL:` there; unprefixed here — the caller formats).
pub fn validate_phases(
    phases: &[PhaseRange],
    statuses: &BTreeSet<String>,
    critical_gates: &BTreeSet<String>,
    required_critical_gates: &BTreeSet<String>,
    source_line_count: i64,
) -> Vec<String> {
    let mut errors = Vec::new();

    let ids: Vec<i64> = phases.iter().map(|p| p.id).collect();
    let expected: Vec<i64> = (1..=30).collect();
    if ids != expected {
        errors.push(format!("checklist phases must be exactly 1..30; got {ids:?}"));
    }

    let expected_statuses: BTreeSet<String> = ["pass", "partial", "fail", "na", "not_testable"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if statuses != &expected_statuses {
        errors.push("status vocabulary does not match canonical five-state contract".to_string());
    }

    if critical_gates != required_critical_gates {
        errors.push("critical gate set differs from governed SEO closure contract".to_string());
    }

    let mut previous_end: i64 = 73;
    for phase in phases {
        match phase.source_lines {
            None => errors.push(format!("phase {} missing exact source_lines", phase.id)),
            Some((start, end)) => {
                if start != previous_end + 1 {
                    errors.push(format!(
                        "phase {} source range is not contiguous after line {previous_end}: [{start}, {end}]",
                        phase.id
                    ));
                }
                if end < start {
                    errors.push(format!(
                        "phase {} has invalid source range: [{start}, {end}]",
                        phase.id
                    ));
                }
                previous_end = end;
            }
        }
        if !phase.has_owners {
            errors.push(format!("phase {} has no owner", phase.id));
        }
    }
    if previous_end != source_line_count {
        errors.push(format!(
            "phase source ranges stop at {previous_end}, source line count is {source_line_count}"
        ));
    }

    errors
}

/// Port of the "required set has entries not present in the discovered set" checks used
/// repeatedly by `check()` (required scripts / refs / test fixtures / workflow packs), given
/// the set of names already discovered on disk.
pub fn missing_required<'a>(required: &BTreeSet<&'a str>, present: &BTreeSet<String>) -> Vec<&'a str> {
    required
        .iter()
        .copied()
        .filter(|name| !present.contains(*name))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headings_slugifies_like_python() {
        let md = "# Title\n\n## Bot Policy & Logs\n\nbody\n\n## Search-Appearance\n";
        let hs = headings(md);
        assert!(hs.contains("bot-policy-logs"));
        assert!(hs.contains("search-appearance"));
        assert_eq!(hs.len(), 2);
    }

    #[test]
    fn validate_phases_flags_gaps_and_bad_ids() {
        let phases = vec![
            PhaseRange {
                id: 1,
                source_lines: Some((74, 100)),
                has_owners: true,
            },
            PhaseRange {
                id: 2,
                source_lines: Some((105, 120)),
                has_owners: false,
            },
        ];
        let statuses: BTreeSet<String> = ["pass", "partial", "fail", "na", "not_testable"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let gates: BTreeSet<String> = ["indexability"].iter().map(|s| s.to_string()).collect();
        let required_gates = gates.clone();
        let errors = validate_phases(&phases, &statuses, &gates, &required_gates, 120);
        assert!(errors.iter().any(|e| e.contains("must be exactly 1..30")));
        assert!(errors.iter().any(|e| e.contains("not contiguous")));
        assert!(errors.iter().any(|e| e.contains("phase 2 has no owner")));
    }

    #[test]
    fn validate_phases_clean_input_has_no_errors() {
        let mut phases = Vec::new();
        let mut start = 74i64;
        for id in 1..=30 {
            let end = start + 4;
            phases.push(PhaseRange {
                id,
                source_lines: Some((start, end)),
                has_owners: true,
            });
            start = end + 1;
        }
        let statuses: BTreeSet<String> = ["pass", "partial", "fail", "na", "not_testable"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let gates: BTreeSet<String> = BTreeSet::new();
        let errors = validate_phases(&phases, &statuses, &gates, &gates, start - 1);
        assert!(errors.is_empty(), "unexpected errors: {errors:?}");
    }

    #[test]
    fn missing_required_reports_gaps() {
        let required: BTreeSet<&str> = ["a.py", "b.py", "c.py"].into_iter().collect();
        let present: BTreeSet<String> = ["a.py".to_string()].into_iter().collect();
        let mut missing = missing_required(&required, &present);
        missing.sort();
        assert_eq!(missing, vec!["b.py", "c.py"]);
    }
}
