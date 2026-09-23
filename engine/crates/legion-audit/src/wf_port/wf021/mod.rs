//! Port of `src/lib/report/families/supply-chain.mjs`,
//! `src/lib/report/families/test-quality.mjs` (both re-export
//! `buildFamilySummary` from `families/shared.mjs` unchanged — this module
//! ports `shared.mjs`'s `buildFamilySummary` once, as `build_family_summary`,
//! and both family names are callers of it, not distinct behaviour),
//! `src/lib/report/html/index.mjs`, `src/lib/report/markdown/index.mjs`, and
//! `src/lib/report/model.mjs`.
//!
//! The JS report pipeline operates on loosely-typed, dynamically-shaped
//! report JSON (`input.findings ?? []`, `finding.rootCause ?? finding.ruleId
//! ?? finding.id`, etc.). This port keeps that shape: report/finding/gap
//! payloads are `serde_json::Value`, and every accessor mirrors the JS
//! nullish-coalescing fallback chain exactly, including which value wins
//! when several are present and how absence/`null`/wrong-type are each
//! treated (JS `??` only falls through on `null`/`undefined` — not on `0`,
//! `""`, or `false`).

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------
// model.mjs — buildReportModel
// ---------------------------------------------------------------------

/// `const ids=(rows)=>[...new Set((rows??[]).map(({id})=>id).filter(Boolean))].sort();`
///
/// JS `Boolean(x)` filters out `undefined`, `null`, `""`, `0`, `false`,
/// `NaN`. Here `id` is read as a JSON string field, so the only falsy JSON
/// values reachable are: missing/`null` (no `id` key or JSON `null`), and
/// the empty string. Non-string `id`s (numbers, objects) are not filtered
/// by `Boolean` in JS as long as they are truthy, but `id` is `undefined`
/// unless the field truly exists; this port only ever produced string ids
/// from the callers in this codebase, so a non-string `id` is treated as
/// absent (mirrors JS reading a shape that never carries non-string ids in
/// practice, while never panicking on one it doesn't expect).
fn ids(rows: &Value) -> Vec<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    if let Some(arr) = rows.as_array() {
        for row in arr {
            if let Some(id) = row.get("id").and_then(Value::as_str) {
                if !id.is_empty() {
                    set.insert(id.to_string());
                }
            }
        }
    }
    set.into_iter().collect()
}

fn opt_array(input: &Value, key: &str) -> Value {
    match input.get(key) {
        Some(Value::Null) | None => Value::Array(Vec::new()),
        Some(v) => v.clone(),
    }
}

fn opt_or_null(input: &Value, key: &str) -> Value {
    match input.get(key) {
        Some(Value::Null) | None => Value::Null,
        Some(v) => v.clone(),
    }
}

fn opt_object(input: &Value, key: &str) -> Value {
    match input.get(key) {
        Some(Value::Null) | None => Value::Object(Map::new()),
        Some(v) => v.clone(),
    }
}

fn string_array(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn sorted_unique(mut items: Vec<String>) -> Vec<String> {
    let set: BTreeSet<String> = items.drain(..).collect();
    set.into_iter().collect()
}

/// `rootCauseGroups`: `Object.values(findings.reduce(...))`, preserving the
/// insertion order of first-seen group keys (JS object key order = first
/// insertion, for string keys that aren't array indices).
struct RootCauseGroup {
    root_cause: String,
    finding_ids: Vec<String>,
    target_ids: Vec<String>,
    control_ids: Vec<String>,
}

fn build_root_cause_groups(findings: &Value) -> Vec<Value> {
    let mut order: Vec<String> = Vec::new();
    let mut groups: std::collections::HashMap<String, RootCauseGroup> =
        std::collections::HashMap::new();

    if let Some(arr) = findings.as_array() {
        for finding in arr {
            // `finding.rootCause ?? finding.ruleId ?? finding.id`
            let key = finding
                .get("rootCause")
                .filter(|v| !v.is_null())
                .or_else(|| finding.get("ruleId").filter(|v| !v.is_null()))
                .or_else(|| finding.get("id").filter(|v| !v.is_null()))
                .cloned()
                .unwrap_or(Value::Null);
            // JS uses the raw value as an object key (implicitly stringified).
            let key_str = match &key {
                Value::String(s) => s.clone(),
                Value::Null => "undefined".to_string(),
                other => other.to_string(),
            };

            if !groups.contains_key(&key_str) {
                order.push(key_str.clone());
                groups.insert(
                    key_str.clone(),
                    RootCauseGroup {
                        root_cause: key_str.clone(),
                        finding_ids: Vec::new(),
                        target_ids: Vec::new(),
                        control_ids: Vec::new(),
                    },
                );
            }
            let group = groups.get_mut(&key_str).unwrap();
            if let Some(id) = finding.get("id").and_then(Value::as_str) {
                group.finding_ids.push(id.to_string());
            }
            group
                .target_ids
                .extend(string_array(&opt_array(finding, "targetIds")));
            group
                .control_ids
                .extend(string_array(&opt_array(finding, "controlIds")));
        }
    }

    order
        .into_iter()
        .map(|key| {
            let group = groups.remove(&key).unwrap();
            json!({
                "rootCause": group.root_cause,
                "findingIds": sorted_unique(group.finding_ids),
                "targetIds": sorted_unique(group.target_ids),
                "controlIds": sorted_unique(group.control_ids),
            })
        })
        .collect()
}

/// Port of `buildReportModel(input = {})` in `model.mjs`.
///
/// `input` defaults to `{}` on the JS side when called with no argument;
/// callers here pass `&Value::Null` or `&json!({})` for that case (both are
/// treated identically: every field read falls back to its default).
pub fn build_report_model(input: &Value) -> Value {
    let empty = json!({});
    let input = if input.is_null() { &empty } else { input };

    let targets = opt_array(input, "targets");
    let controls = opt_array(input, "controls");

    let mut gaps: Vec<Value> = opt_array(input, "gaps")
        .as_array()
        .cloned()
        .unwrap_or_default();
    if targets.as_array().map(Vec::len).unwrap_or(0) == 0 {
        gaps.push(json!({"kind": "missing-target-denominator"}));
    }
    if controls.as_array().map(Vec::len).unwrap_or(0) == 0 {
        gaps.push(json!({"kind": "missing-control-denominator"}));
    }

    let denominators = json!({
        "targets": ids(&targets),
        "controls": ids(&controls),
    });

    let findings = opt_array(input, "findings");
    let groups = build_root_cause_groups(&findings);

    let findings_len = findings.as_array().map(Vec::len).unwrap_or(0);
    let audit_status = if !gaps.is_empty() {
        Value::String("incomplete".to_string())
    } else {
        match input.get("auditStatus") {
            Some(v) if !v.is_null() => v.clone(),
            _ => Value::String(if findings_len > 0 { "fail" } else { "pass" }.to_string()),
        }
    };

    let gaps_empty = gaps.is_empty();

    json!({
        "schemaVersion": 1,
        "kind": "legion-report",
        "targets": targets,
        "components": opt_array(input, "components"),
        "stacks": opt_array(input, "stacks"),
        "externalSystems": opt_array(input, "externalSystems"),
        "releaseContract": opt_or_null(input, "releaseContract"),
        "productContext": opt_or_null(input, "productContext"),
        "controls": controls,
        "denominators": denominators,
        "scenarios": opt_array(input, "scenarios"),
        "evidenceCapabilities": opt_array(input, "evidenceCapabilities"),
        "findings": findings,
        "rootCauseGroups": groups,
        "gaps": gaps,
        "claims": opt_object(input, "claims"),
        "auditStatus": audit_status,
        "integrity": match input.get("integrity") {
            Some(v) if !v.is_null() => v.clone(),
            _ => json!({"valid": gaps_empty}),
        },
        "completeness": match input.get("completeness") {
            Some(v) if !v.is_null() => v.clone(),
            _ => json!({"complete": gaps_empty}),
        },
    })
}

// ---------------------------------------------------------------------
// families/shared.mjs — buildFamilySummary
// (re-exported unchanged by families/supply-chain.mjs and
// families/test-quality.mjs)
// ---------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub struct FamilySummaryOptions {
    pub required_provider_ids: Vec<String>,
    pub selected_provider_ids: Vec<String>,
}

fn result_id(result: &Value) -> Option<String> {
    // `result.id ?? result.provider`
    result
        .get("id")
        .filter(|v| !v.is_null())
        .or_else(|| result.get("provider").filter(|v| !v.is_null()))
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Port of `buildFamilySummary(results, family, {requiredProviderIds=[],
/// selectedProviderIds=[]}={})` in `families/shared.mjs`.
pub fn build_family_summary(
    results: &Value,
    family: Option<&str>,
    options: &FamilySummaryOptions,
) -> Value {
    let empty_results: Vec<Value> = Vec::new();
    let results_arr = results.as_array().unwrap_or(&empty_results);

    let expected: BTreeSet<String> = if !options.selected_provider_ids.is_empty() {
        options.selected_provider_ids.iter().cloned().collect()
    } else {
        options.required_provider_ids.iter().cloned().collect()
    };

    let selected: Vec<&Value> = results_arr
        .iter()
        .filter(|result| {
            let family_matches = match family {
                None => true,
                Some(f) => result.get("family").and_then(Value::as_str) == Some(f),
            };
            if !family_matches {
                return false;
            }
            if expected.is_empty() {
                true
            } else {
                match result_id(result) {
                    Some(id) => expected.contains(&id),
                    None => false,
                }
            }
        })
        .collect();

    let selected_ids: BTreeSet<String> = selected.iter().filter_map(|r| result_id(r)).collect();

    // `[...new Set([...requiredProviderIds, ...selectedProviderIds])].filter(id => !selectedIds.has(id))`
    // JS `Set` preserves insertion order; `missing` order here follows
    // required-then-selected first-seen order, filtered to those not
    // present among selected results.
    let mut seen_union: Vec<String> = Vec::new();
    let mut union_set: BTreeSet<String> = BTreeSet::new();
    for id in options
        .required_provider_ids
        .iter()
        .chain(options.selected_provider_ids.iter())
    {
        if union_set.insert(id.clone()) {
            seen_union.push(id.clone());
        }
    }
    let missing: Vec<String> = seen_union
        .into_iter()
        .filter(|id| !selected_ids.contains(id))
        .collect();

    let mut gaps: Vec<Value> = Vec::new();
    if selected.is_empty() {
        gaps.push(json!({
            "kind": "family-denominator-zero",
            "family": family,
        }));
    }
    for provider_id in &missing {
        let kind = if options.selected_provider_ids.contains(provider_id) {
            "selected-provider-result-missing"
        } else {
            "required-provider-missing"
        };
        gaps.push(json!({"kind": kind, "providerId": provider_id}));
    }

    let is_incomplete = |result: &Value| -> bool {
        let complete_true = result.get("complete").and_then(Value::as_bool) == Some(true);
        let status_pass = result.get("status").and_then(Value::as_str) == Some("pass");
        let denominator = result.get("denominator");
        let denominator_present = matches!(denominator, Some(v) if !v.is_null());
        let denominator_valid = denominator_present
            && {
                let d = denominator.unwrap();
                let expected = d.get("expected").and_then(Value::as_i64);
                let examined = d.get("examined").and_then(Value::as_i64);
                matches!(expected, Some(e) if e >= 1) && expected == examined
            };
        !complete_true || !status_pass || !denominator_valid
    };

    let incomplete: Vec<&Value> = selected
        .iter()
        .copied()
        .filter(|r| is_incomplete(r))
        .collect();
    for result in &incomplete {
        gaps.push(json!({
            "kind": "provider-result-incomplete",
            "providerId": result_id(result),
        }));
    }

    let clean = incomplete.is_empty() && gaps.is_empty();

    let providers: Vec<Value> = selected
        .iter()
        .map(|result| {
            json!({
                "id": result_id(result),
                "status": result.get("status").cloned().unwrap_or(Value::Null),
                "complete": result.get("complete").cloned().unwrap_or(Value::Null),
                "denominator": result.get("denominator").cloned().unwrap_or(Value::Null),
                "tool": result.get("tool").cloned().unwrap_or(Value::Null),
                "rawArtifacts": opt_array(result, "rawArtifacts"),
                "componentIds": opt_array(result, "componentIds"),
                "limitations": opt_array(result, "limitations"),
            })
        })
        .collect();

    let incomplete_providers: Vec<Value> = incomplete
        .iter()
        .map(|r| result_id(r).map(Value::String).unwrap_or(Value::Null))
        .chain(missing.iter().cloned().map(Value::String))
        .collect();

    json!({
        "family": family,
        "status": if clean { "complete" } else { "incomplete" },
        "providers": providers,
        "incompleteProviders": incomplete_providers,
        "gaps": gaps,
        "clean": clean,
    })
}

// ---------------------------------------------------------------------
// html/index.mjs
// ---------------------------------------------------------------------

const MAX_ITEMS: usize = 2_000;

/// Port of `escapeHtml`.
pub fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Port of `cspMeta`.
pub fn csp_meta(script_hash: &str) -> String {
    format!(
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'sha256-{script_hash}'\">"
    )
}

/// Port of `const anchor = (value) => String(value ?? '').replace(/[^a-zA-Z0-9_.:-]/g, '-');`
fn anchor(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn value_to_display_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
    }
}

fn links(ids: &[String]) -> String {
    ids.iter()
        .map(|id| format!("<a href=\"#evidence-{}\">{}</a>", anchor(id), escape_html(id)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `const evidenceIds = (item) => [...new Set([...(item?.evidenceIds ?? []), ...(item?.evidence ?? []).map((entry) => entry.id ?? entry)].filter(Boolean))];`
fn evidence_ids(item: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for id in string_array(&opt_array(item, "evidenceIds")) {
        if seen.insert(id.clone()) {
            out.push(id);
        }
    }
    if let Some(evidence) = item.get("evidence").and_then(Value::as_array) {
        for entry in evidence {
            let id = match entry.get("id") {
                Some(v) if !v.is_null() => value_to_display_string(v),
                _ => value_to_display_string(entry),
            };
            if !id.is_empty() && seen.insert(id.clone()) {
                out.push(id);
            }
        }
    }
    out
}

fn section(title: &str, value: &Value) -> String {
    let as_list: Vec<Value> = match value {
        Value::Array(arr) => arr.clone(),
        Value::Null => Vec::new(),
        other => vec![other.clone()],
    };
    let total_len = as_list.len();
    let items: Vec<&Value> = as_list.iter().take(MAX_ITEMS).collect();

    let rows: String = items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            let label = match item.get("title").or_else(|| item.get("name")).or_else(|| item.get("id")) {
                Some(v) if !v.is_null() => value_to_display_string(v),
                _ => format!("{title} {}", index + 1),
            };
            let search = escape_html(&serde_json::to_string(item).unwrap_or_default().to_lowercase());
            let body = escape_html(&serde_json::to_string_pretty(item).unwrap_or_default());
            let ev = evidence_ids(item);
            let ev_html = if ev.is_empty() { "none".to_string() } else { links(&ev) };
            format!(
                "<details data-search=\"{search}\"><summary>{}</summary><pre>{body}</pre><p>Evidence: {ev_html}</p></details>",
                escape_html(&label)
            )
        })
        .collect();

    let truncated = if total_len > MAX_ITEMS {
        format!("<p>Showing first {MAX_ITEMS} records.</p>")
    } else {
        String::new()
    };

    let kind = anchor(&title.to_lowercase().replace(' ', "-"));
    let rows_or_placeholder = if rows.is_empty() { "<p>Unavailable.</p>".to_string() } else { rows };
    format!(
        "<section data-kind=\"{kind}\"><h2>{}</h2>{rows_or_placeholder}{truncated}</section>",
        escape_html(title)
    )
}

/// Port of `renderHtmlReport(report)`.
pub fn render_html_report(report: &Value) -> String {
    let empty = json!({});
    let report = if report.is_null() { &empty } else { report };

    let findings = opt_array(report, "findings");
    let finding_rows: String = findings
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .map(|finding| {
            let get_str = |k: &str| -> String {
                finding.get(k).map(value_to_display_string).unwrap_or_default()
            };
            let search = escape_html(
                &[get_str("id"), get_str("ruleId"), get_str("title"), get_str("file")]
                    .join(" ")
                    .to_lowercase(),
            );
            let evidence_link_ids: Vec<String> = finding
                .get("evidence")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|e| e.get("id").map(value_to_display_string))
                        .collect()
                })
                .unwrap_or_default();
            format!(
                "\n    <tr data-search=\"{search}\">\n      <td>{}</td>\n      <td>{}</td>\n      <td>{}</td>\n      <td>{}</td>\n      <td>{}</td><td>{}</td>\n    </tr>",
                escape_html(&get_str("id")),
                escape_html(&get_str("ruleId")),
                escape_html(&get_str("severity")),
                escape_html(&get_str("title")),
                escape_html(&get_str("file")),
                links(&evidence_link_ids),
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    // `[...new Map(findings.flatMap(f => f.evidence ?? []).map(item => [item.id, item])).values()].slice(0, MAX_ITEMS)`
    // Map preserves first-insertion order per key but a *later* duplicate
    // key overwrites the *value* while keeping the original position.
    let mut order: Vec<String> = Vec::new();
    let mut map: std::collections::HashMap<String, Value> = std::collections::HashMap::new();
    if let Some(arr) = findings.as_array() {
        for finding in arr {
            if let Some(evidence) = finding.get("evidence").and_then(Value::as_array) {
                for item in evidence {
                    let key = item.get("id").map(value_to_display_string).unwrap_or_default();
                    if !map.contains_key(&key) {
                        order.push(key.clone());
                    }
                    map.insert(key, item.clone());
                }
            }
        }
    }
    let evidence_items: Vec<Value> = order
        .into_iter()
        .filter_map(|k| map.remove(&k))
        .take(MAX_ITEMS)
        .collect();
    let evidence: String = evidence_items
        .iter()
        .map(|item| {
            let id = item.get("id").map(value_to_display_string).unwrap_or_default();
            let search = escape_html(&serde_json::to_string(item).unwrap_or_default().to_lowercase());
            let body = escape_html(&serde_json::to_string_pretty(item).unwrap_or_default());
            format!(
                "<details id=\"evidence-{}\" data-search=\"{search}\"><summary>{}</summary><pre>{body}</pre></details>",
                anchor(&id),
                escape_html(&id)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");

    let coverage: String = report
        .get("familyCoverage")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|family| {
                    let id = family.get("id").map(value_to_display_string).unwrap_or_default();
                    let status = family.get("status").map(value_to_display_string).unwrap_or_default();
                    let ev_ids = string_array(&opt_array(family, "evidenceIds"));
                    format!("<li>{}: {} {}</li>", escape_html(&id), escape_html(&status), links(&ev_ids))
                })
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default();

    let gaps: String = report
        .get("coverage_gaps")
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .map(|gap| {
                    let kind = gap.get("kind").map(value_to_display_string).unwrap_or_default();
                    let detail = match gap.get("detail") {
                        Some(v) if !v.is_null() => format!(
                            ": {}",
                            escape_html(&serde_json::to_string(v).unwrap_or_default())
                        ),
                        _ => String::new(),
                    };
                    format!("\n    <li>{}{detail}</li>", escape_html(&kind))
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();

    let script = "const rows=[...document.querySelectorAll('[data-search]')];const q=document.getElementById('search');document.getElementById('count').textContent=String(document.querySelectorAll('tbody [data-search]').length);q.addEventListener('input',()=>{const value=q.value.toLowerCase();for(const row of rows)row.hidden=!row.dataset.search.includes(value);});";
    let script_hash = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(script.as_bytes());
        base64_encode(&hasher.finalize())
    };

    let audit_status = report
        .get("audit_status")
        .map(value_to_display_string)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    let quality_gate = report
        .get("quality_gate")
        .map(value_to_display_string)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    format!(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Legion audit report</title>\n{}\n<style>body{{font-family:system-ui,sans-serif;margin:2rem;color:#1a1a1a}}table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ddd;padding:.4rem;text-align:left}}th{{background:#f5f5f5}}</style>\n</head>\n<body>\n<h1>Legion audit report</h1>\n<p>Status: {} · Quality gate: {} · Findings: <span id=\"count\">0</span></p>\n<label>Search <input id=\"search\" type=\"search\" autocomplete=\"off\"></label>\n<table>\n<thead><tr><th>ID</th><th>Rule</th><th>Severity</th><th>Title</th><th>File</th><th>Evidence</th></tr></thead>\n<tbody>\n{}\n</tbody>\n</table>\n<h2>Family coverage</h2><ul>{}</ul>\n<h2>Evidence</h2>{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n<h2>Coverage gaps</h2>\n<ul>\n{}\n</ul>\n<script>{}</script>\n</body>\n</html>\n",
        csp_meta(&script_hash),
        escape_html(&audit_status),
        escape_html(&quality_gate),
        if finding_rows.is_empty() { "<tr><td colspan=\"6\">No findings.</td></tr>".to_string() } else { finding_rows },
        if coverage.is_empty() { "<li>Unavailable.</li>".to_string() } else { coverage },
        if evidence.is_empty() { "<p>No evidence records.</p>".to_string() } else { evidence },
        section("Flow diagrams", report.get("flows").unwrap_or(&Value::Null)),
        section("Path diagrams", report.get("paths").unwrap_or(&Value::Null)),
        section("Screenshot views", report.get("screenshots").unwrap_or(&Value::Null)),
        section("Copy and narrative maps", report.get("copyNarrativeMaps").unwrap_or(&Value::Null)),
        section("Baselines", report.get("baselines").unwrap_or(&Value::Null)),
        section("Remediation previews", report.get("remediationPreviews").unwrap_or(&Value::Null)),
        section("Verification state", report.get("verification").unwrap_or(&Value::Null)),
        if gaps.is_empty() { "<li>None.</li>".to_string() } else { gaps },
        script,
    )
}

/// Standard base64 (matches Node `Buffer#digest('base64')`), no external
/// crate needed for this one call site.
fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((bytes.len() + 2) / 3 * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = ((b0 as u32) << 16) | ((b1 as u32) << 8) | (b2 as u32);
        out.push(TABLE[((n >> 18) & 0x3f) as usize] as char);
        out.push(TABLE[((n >> 12) & 0x3f) as usize] as char);
        out.push(if chunk.len() > 1 { TABLE[((n >> 6) & 0x3f) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[(n & 0x3f) as usize] as char } else { '=' });
    }
    out
}

// ---------------------------------------------------------------------
// markdown/index.mjs
// ---------------------------------------------------------------------

/// Port of `escapeMarkdown`.
pub fn escape_markdown(value: &Value) -> String {
    let s = match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('\\', "\\\\")
        .replace('|', "\\|")
        .replace('\n', " ")
}

/// Port of `renderMarkdownReport(report = {})`.
pub fn render_markdown_report(report: &Value) -> String {
    let empty = json!({});
    let report = if report.is_null() { &empty } else { report };

    let mut findings: Vec<Value> = opt_array(report, "findings").as_array().cloned().unwrap_or_default();
    findings.sort_by(|a, b| {
        let ka = a.get("id").map(value_to_display_string).unwrap_or_default();
        let kb = b.get("id").map(value_to_display_string).unwrap_or_default();
        ka.cmp(&kb)
    });

    let mut gaps: Vec<Value> = report
        .get("coverage_gaps")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    gaps.sort_by(|a, b| {
        let ka = a.get("kind").map(value_to_display_string).unwrap_or_default();
        let kb = b.get("kind").map(value_to_display_string).unwrap_or_default();
        ka.cmp(&kb)
    });

    let status = report.get("audit_status").map(|v| escape_markdown(v)).unwrap_or_else(|| "unknown".to_string());
    let status = if status.is_empty() { "unknown".to_string() } else { status };
    let quality_gate = match report.get("quality_gate") {
        Some(v) if !v.is_null() => escape_markdown(v),
        _ => "unknown".to_string(),
    };

    let mut lines: Vec<String> = vec![
        "# Legion audit report".to_string(),
        String::new(),
        format!("- Status: {status}"),
        format!("- Quality gate: {quality_gate}"),
        format!("- Findings: {}", findings.len()),
        String::new(),
        "## Findings".to_string(),
        String::new(),
        "| ID | Rule | Severity | Title | File |".to_string(),
        "|---|---|---|---|---|".to_string(),
    ];

    for finding in &findings {
        let id = finding.get("id").map(|v| escape_markdown(v)).unwrap_or_default();
        let rule = finding.get("ruleId").map(|v| escape_markdown(v)).unwrap_or_default();
        let severity = finding.get("severity").map(|v| escape_markdown(v)).unwrap_or_default();
        // `finding.title ?? finding.detail`
        let title = match finding.get("title") {
            Some(v) if !v.is_null() => escape_markdown(v),
            _ => match finding.get("detail") {
                Some(v) if !v.is_null() => escape_markdown(v),
                _ => escape_markdown(&Value::Null),
            },
        };
        let file = finding.get("file").map(|v| escape_markdown(v)).unwrap_or_default();
        lines.push(format!("| {id} | {rule} | {severity} | {title} | {file} |"));
    }
    if findings.is_empty() {
        lines.push("| — | — | — | No findings | — |".to_string());
    }

    lines.push(String::new());
    lines.push("## Coverage gaps".to_string());
    lines.push(String::new());
    if !gaps.is_empty() {
        for gap in &gaps {
            let kind = gap.get("kind").map(|v| escape_markdown(v)).unwrap_or_default();
            let detail = match gap.get("detail") {
                Some(v) if !v.is_null() => format!(": {}", escape_markdown(&Value::String(serde_json::to_string(v).unwrap_or_default()))),
                _ => String::new(),
            };
            lines.push(format!("- {kind}{detail}"));
        }
    } else {
        lines.push("- None.".to_string());
    }

    format!("{}\n", lines.join("\n"))
}
