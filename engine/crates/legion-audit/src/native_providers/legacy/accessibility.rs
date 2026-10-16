//! Native implementation of `legacy.accessibility.internal-suite`.

use std::collections::BTreeMap;

use legion_contracts::{FindingRef, ProviderStatus};
use serde_json::json;

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

/// Recognize direct integer assignments without interpreting surrounding source syntax.
fn positive_tabindex_offsets(text: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut offsets = Vec::new();
    for offset in occurrences_ascii_case_insensitive(text, "tabindex") {
        if offset > 0
            && (bytes[offset - 1].is_ascii_alphanumeric()
                || matches!(bytes[offset - 1], b'_' | b'-' | b':'))
        {
            continue;
        }
        let mut cursor = offset + "tabindex".len();
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes.get(cursor) != Some(&b'=') {
            continue;
        }
        cursor += 1;
        while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        let closing = match bytes.get(cursor) {
            Some(b'\'') => Some(b'\''),
            Some(b'"') => Some(b'"'),
            Some(b'{') => Some(b'}'),
            _ => None,
        };
        if closing.is_some() {
            cursor += 1;
            while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
        }
        if bytes.get(cursor) == Some(&b'-') {
            continue;
        }
        if bytes.get(cursor) == Some(&b'+') {
            cursor += 1;
        }
        let mut positive = false;
        while let Some(byte) = bytes.get(cursor).filter(|byte| byte.is_ascii_digit()) {
            positive |= *byte != b'0';
            cursor += 1;
        }
        if !positive {
            continue;
        }
        let whole_value = if let Some(closing) = closing {
            while bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                cursor += 1;
            }
            bytes.get(cursor) == Some(&closing)
        } else {
            bytes
                .get(cursor)
                .map_or(true, |byte| byte.is_ascii_whitespace() || *byte == b'>')
        };
        if whole_value {
            offsets.push(offset);
        }
    }
    offsets
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
    if let std::collections::btree_map::Entry::Vacant(entry) = locations.entry(item.id.to_string())
    {
        entry.insert((file.to_owned(), line));
        finding_list.push(item);
    }
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
    for offset in positive_tabindex_offsets(text) {
        push(
            findings,
            locations,
            "a11y.positive-tabindex",
            "error",
            file,
            line_at(text, offset),
        );
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
        json!({"provider":"accessibility.internal-suite", "phase":"static-source", "applicable":!scanned.is_empty(), "required":!scanned.is_empty(), "status":if findings.is_empty(){"pass"}else{"fail"}, "complete":gaps.is_empty(), "coverage":{"expectedFiles":selected.entries.len(),"scannedFiles":scanned.len(),"scanned":scanned}, "findings":findings, "coverageGaps":gaps, "degradation":[] }),
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
        // Findings do not make a run partial; unproven coverage does.
        if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
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

#[cfg(test)]
mod tests {
    use super::*;

    fn findings_for(text: &str) -> (Vec<FindingRef>, BTreeMap<String, (String, usize)>) {
        let mut findings = Vec::new();
        let mut locations = BTreeMap::new();
        scan_file("fixture.tsx", text, &mut findings, &mut locations);
        (findings, locations)
    }

    #[test]
    fn negative_tabindex_selectors_are_not_positive_assignments() {
        let text = r#"
const focusable = host.querySelectorAll('[tabindex]:not([tabindex="-1"])');
const first = dialog.querySelector('[tabindex]:not([tabindex="-1"])');
const last = node.querySelectorAll('button, [tabindex]:not([tabindex="-1"])');
"#;
        assert!(positive_tabindex_offsets(text).is_empty());
    }

    #[test]
    fn tabindex_requires_a_whole_positive_integer_attribute_value() {
        for value in ["1", "+2", "001", "9999999999999999999999999999999999999"] {
            for attribute in [
                format!("tabindex=\"{value}\""),
                format!("tabindex='{value}'"),
                format!("tabindex={value}"),
                format!("tabIndex={{ {value} }}"),
            ] {
                let text = format!("<div {attribute}>");
                assert_eq!(positive_tabindex_offsets(&text), vec![5]);
            }
        }
        for value in [
            "-1", "-20", "0", "+0", "000", "1px", "1.5", "1e2", "1 + 2", "value2",
        ] {
            for attribute in [
                format!("tabindex=\"{value}\""),
                format!("tabIndex={{ {value} }}"),
            ] {
                assert!(positive_tabindex_offsets(&format!("<div {attribute}>")).is_empty());
            }
        }
        for text in [
            "<div tabindex=-1>",
            "<div tabindex=0>",
            "<div tabindex=1px>",
            "<div tabindex=value2>",
            "<div tabIndex={index + 1}>",
            "<div tabIndex={'1'}>",
            "<div data-tabindex=1>",
            "<div tabindex aria-label='item1'>",
            "<div tabindex=\"1",
            "<div tabindex={12",
        ] {
            assert!(positive_tabindex_offsets(text).is_empty());
        }
    }

    #[test]
    fn repeated_same_line_findings_have_one_canonical_id() {
        let (findings, locations) =
            findings_for("<input tabIndex={1} autoFocus /><input tabindex='2' autofocus />");
        assert_eq!(findings.len(), 2);
        assert_eq!(locations.len(), 2);
        assert!(findings.iter().all(|item| locations
            .get(&item.id.to_string())
            .is_some_and(|(_, line)| *line == 1)));
    }

    #[test]
    fn multiline_assignments_keep_attribute_lines() {
        let text = "<div\n title=\"tabIndex=-9 > ignored\"\n onClick={() => 2 > 1}\n tabIndex={\n +3\n }\n>\n<input\n tabindex = '-1'\n>\n<input\n tabindex = '4'\n>";
        let offsets = positive_tabindex_offsets(text);
        assert_eq!(
            offsets
                .iter()
                .map(|offset| line_at(text, *offset))
                .collect::<Vec<_>>(),
            vec![4, 12]
        );
        let (findings, locations) = findings_for(text);
        assert_eq!(findings.len(), 2);
        assert_eq!(
            locations
                .values()
                .map(|(_, line)| *line)
                .collect::<std::collections::BTreeSet<_>>(),
            [4, 12].into_iter().collect()
        );
    }

    #[test]
    fn nested_jsx_attribute_markup_keeps_its_location() {
        let text = "<Panel content={\n <input tabIndex={2} />\n} />";
        let offsets = positive_tabindex_offsets(text);
        assert_eq!(offsets.len(), 1);
        assert_eq!(line_at(text, offsets[0]), 2);
    }

    #[test]
    fn jsx_text_apostrophes_do_not_hide_positive_assignments() {
        let text = "<div>Don't <input tabIndex={1} /></div>";
        let offsets = positive_tabindex_offsets(text);
        assert_eq!(offsets.len(), 1);
        assert_eq!(&text[offsets[0]..offsets[0] + 8], "tabIndex");
    }

    #[test]
    fn deep_jsx_attribute_nesting_uses_no_recursive_rescans() {
        let depth = 4096;
        let text = format!(
            "{}<input tabIndex={{1}} />{}",
            "<Panel content={\n".repeat(depth),
            "\n} />".repeat(depth),
        );
        let offsets = positive_tabindex_offsets(&text);
        assert_eq!(offsets.len(), 1);
        assert_eq!(line_at(&text, offsets[0]), depth + 1);
    }
}
