//! Native implementation of `legacy.accessibility.internal-suite`.

use std::{collections::BTreeMap, path::Path};

use legion_contracts::{FindingRef, ProviderStatus};
use serde_json::{json, Value};

use super::common::{
    denominator, finding, has_ascii_case_insensitive, line_at, occurrences_ascii_case_insensitive,
    source_files, ProviderInput,
};

const EXTENSIONS: &[&str] = &[
    "html", "htm", "jsx", "tsx", "vue", "svelte", "astro", "css", "scss", "sass", "less",
];

fn extension(path: &str) -> Option<&str> {
    path.rsplit_once('.')
        .map(|(_, ext)| ext)
        .filter(|ext| !ext.is_empty())
}
fn is_source(path: &str) -> bool {
    extension(path).is_some_and(|ext| {
        EXTENSIONS
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(ext))
    })
}
fn is_non_dom(file: &str, text: &str) -> bool {
    let lower = file.to_ascii_lowercase();
    (lower
        .split(['/', '\\'])
        .any(|part| part == "remotion" || part == ".remotion"))
        || has_ascii_case_insensitive(text, "from 'remotion'")
        || has_ascii_case_insensitive(text, "from \"remotion\"")
        || has_ascii_case_insensitive(text, "require('remotion')")
        || has_ascii_case_insensitive(text, "require(\"remotion\")")
        || has_ascii_case_insensitive(text, "@remotion/")
}

fn tag_ranges(text: &str, tag: &str) -> Vec<(usize, usize)> {
    let lower = text.to_ascii_lowercase();
    let needle = format!("<{tag}");
    occurrences_ascii_case_insensitive(&lower, &needle)
        .into_iter()
        .filter_map(|start| lower[start..].find('>').map(|end| (start, start + end + 1)))
        .collect()
}

fn has_attr(tag: &str, names: &[&str]) -> bool {
    let lower = tag.to_ascii_lowercase();
    names
        .iter()
        .any(|name| lower.contains(&format!("{name}=")) || lower.contains(&format!("{name} =")))
}

fn push(
    finding_list: &mut Vec<FindingRef>,
    locations: &mut BTreeMap<String, (String, usize)>,
    rule: &str,
    severity: &str,
    file: &str,
    line: usize,
) {
    let item = finding(rule, severity, file, line);
    locations.insert(item.id.to_string(), (file.to_owned(), line));
    finding_list.push(item);
}

fn scan_file(
    file: &str,
    text: &str,
    findings: &mut Vec<FindingRef>,
    locations: &mut BTreeMap<String, (String, usize)>,
) {
    for (start, end) in tag_ranges(text, "img") {
        if !has_attr(&text[start..end], &["alt"]) {
            push(
                findings,
                locations,
                "a11y.image-alt",
                "error",
                file,
                line_at(text, start),
            );
        }
    }
    for offset in occurrences_ascii_case_insensitive(text, "tabindex") {
        let suffix = &text[offset..text.len().min(offset + 40)];
        let digits = suffix
            .split(|ch: char| !ch.is_ascii_digit())
            .find(|value| !value.is_empty());
        if digits.is_some_and(|value| value.parse::<u64>().unwrap_or(0) > 0) {
            push(
                findings,
                locations,
                "a11y.positive-tabindex",
                "error",
                file,
                line_at(text, offset),
            );
        }
    }
    for (start, end) in tag_ranges(text, "button") {
        let open = &text[start..end];
        if has_attr(open, &["aria-label", "aria-labelledby", "title"]) {
            continue;
        }
        let lower = text.to_ascii_lowercase();
        let close = lower[end..]
            .find("</button>")
            .map(|index| end + index)
            .unwrap_or(end);
        let body = &text[end..close];
        let visible = body
            .chars()
            .any(|ch| !ch.is_whitespace() && ch != '<' && ch != '>');
        if !visible {
            push(
                findings,
                locations,
                "a11y.empty-button-name",
                "error",
                file,
                line_at(text, start),
            );
        }
    }
    for tag in ["div", "span"] {
        for (start, end) in tag_ranges(text, tag) {
            let value = &text[start..end];
            if has_attr(value, &["onclick", "@click", "v-on:click"])
                && !has_attr(
                    value,
                    &[
                        "onkeydown",
                        "onkeyup",
                        "@keydown",
                        "@keyup",
                        "role",
                        "tabindex",
                    ],
                )
            {
                push(
                    findings,
                    locations,
                    "a11y.pointer-only-handler",
                    "warning",
                    file,
                    line_at(text, start),
                );
            }
        }
    }
    for offset in occurrences_ascii_case_insensitive(text, "onmouseover")
        .into_iter()
        .chain(occurrences_ascii_case_insensitive(text, "onmouseenter"))
        .chain(occurrences_ascii_case_insensitive(text, "@mouseover"))
        .chain(occurrences_ascii_case_insensitive(text, "@mouseenter"))
    {
        let start = text[..offset].rfind('<').unwrap_or(offset);
        let end = text[offset..]
            .find('>')
            .map(|index| offset + index)
            .unwrap_or(offset);
        if !has_attr(&text[start..end], &["onfocus", "@focus"]) {
            push(
                findings,
                locations,
                "a11y.hover-without-focus",
                "warning",
                file,
                line_at(text, offset),
            );
        }
    }
    for needle in ["autofocus", "autoFocus"] {
        for offset in occurrences_ascii_case_insensitive(text, needle) {
            push(
                findings,
                locations,
                "a11y.autofocus",
                "warning",
                file,
                line_at(text, offset),
            );
        }
    }
    let global_focus_restore = text.to_ascii_lowercase().contains(":focus")
        && (text.to_ascii_lowercase().contains("box-shadow:")
            || text.to_ascii_lowercase().contains("border:")
            || text.to_ascii_lowercase().contains("outline:")
                && !text.to_ascii_lowercase().contains("outline: none"));
    for needle in [
        "outline-none",
        "outline: none",
        "outline:none",
        "outline: 0",
        "outline:0",
    ] {
        for offset in occurrences_ascii_case_insensitive(text, needle) {
            let window = &text[offset.saturating_sub(400)..text.len().min(offset + 400)];
            let local_restore = has_ascii_case_insensitive(window, "focus:ring")
                || has_ascii_case_insensitive(window, "focus:shadow")
                || has_ascii_case_insensitive(window, "focus-visible:ring")
                || has_ascii_case_insensitive(window, "focus {")
                    && has_ascii_case_insensitive(window, "outline:")
                    && !has_ascii_case_insensitive(window, "outline: none");
            if !global_focus_restore && !local_restore {
                push(
                    findings,
                    locations,
                    "a11y.focus-outline-removed",
                    "error",
                    file,
                    line_at(text, offset),
                );
            }
        }
    }
    if extension(file).is_some_and(|ext| {
        ["css", "scss", "sass", "less"]
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(ext))
    }) && (has_ascii_case_insensitive(text, "animation:")
        || has_ascii_case_insensitive(text, "@keyframes"))
        && !has_ascii_case_insensitive(text, "prefers-reduced-motion")
    {
        push(
            findings,
            locations,
            "a11y.reduced-motion",
            "warning",
            file,
            1,
        );
    }
}

/// Run scanner over explicit frozen denominator paths.
pub fn run_accessibility_suite(
    input: &ProviderInput<'_>,
) -> Result<serde_json::Value, crate::error::AuditError> {
    let selected = denominator(input)?;
    let (files, mut gaps) = source_files(input, &selected);
    let mut findings = Vec::new();
    let mut locations = BTreeMap::new();
    let mut scanned = Vec::new();
    for (entry, text) in &files {
        if !is_source(&entry.path) || is_non_dom(&entry.path, text) {
            continue;
        }
        scanned.push(entry.path.clone());
        scan_file(&entry.path, text, &mut findings, &mut locations);
    }
    if selected.entries.is_empty() {
        gaps.push("accessibility-denominator-zero".into());
    }
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(
        json!({"provider":"accessibility.internal-suite", "phase":"runtime", "applicable":!scanned.is_empty(), "required":!scanned.is_empty(), "status":if findings.is_empty(){"pass"}else{"fail"}, "complete":gaps.is_empty(), "coverage":{"expectedFiles":selected.entries.len(),"scannedFiles":scanned.len(),"scanned":scanned}, "findings":findings, "coverageGaps":gaps, "degradation":[] }),
    )
}

pub fn execute(
    input: &ProviderInput<'_>,
) -> Result<legion_contracts::ProviderResult, crate::error::AuditError> {
    let selected = denominator(input)?;
    let (files, mut gaps) = source_files(input, &selected);
    let mut findings = Vec::new();
    let mut locations = BTreeMap::new();
    for (entry, text) in &files {
        if is_source(&entry.path) && !is_non_dom(&entry.path, text) {
            scan_file(&entry.path, text, &mut findings, &mut locations);
        }
    }
    if selected.entries.is_empty() {
        gaps.push("accessibility-denominator-zero".into());
    }
    findings.sort_by(|left, right| left.id.cmp(&right.id));
    let mut details = super::common::details_for_findings(&findings, &locations);
    details.insert("analysis".into(), run_accessibility_suite(input)?);
    let complete = gaps.is_empty() && files.len() == selected.entries.len();
    super::common::result(
        input,
        if findings.is_empty() {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Complete
        },
        complete,
        &selected,
        files.len(),
        findings,
        gaps.clone(),
        gaps,
        details,
    )
}
