//! Native implementation of `legacy.visual.core`.
//!
//! Artifact topology and coverage are native.  Pixel decoding is intentionally
//! bounded: equal bytes prove a match; unequal PNGs remain a typed visual
//! regression rather than being treated as a clean comparison.

use std::{collections::BTreeMap, path::PathBuf};

use legion_contracts::ProviderStatus;
use serde_json::{json, Value};

use super::common::{denominator, digest_bytes, digest_text, finding, ProviderInput};

fn case_key(value: &Value) -> String {
    ["route", "state", "viewport", "theme", "locale", "platform"]
        .iter()
        .map(|key| {
            value
                .get(*key)
                .and_then(Value::as_str)
                .unwrap_or(if *key == "route" { "/" } else { "default" })
        })
        .collect::<Vec<_>>()
        .join("|")
}

fn expected_cases(spec: &Value) -> Vec<Value> {
    if let Some(cases) = spec
        .get("expected")
        .and_then(|value| value.get("cases"))
        .and_then(Value::as_array)
    {
        return cases.clone();
    }
    let expected = spec.get("expected").and_then(Value::as_object);
    let dimensions = [
        "routes",
        "states",
        "viewports",
        "themes",
        "locales",
        "platforms",
    ];
    let mut rows = vec![Value::Object(Default::default())];
    for dimension in dimensions {
        let key = dimension.trim_end_matches('s');
        let values = expected
            .and_then(|object| object.get(dimension))
            .and_then(Value::as_array)
            .filter(|values| !values.is_empty())
            .cloned()
            .unwrap_or_else(|| {
                vec![Value::String(if key == "route" {
                    "/".into()
                } else {
                    "default".into()
                })]
            });
        let mut next = Vec::new();
        for row in rows {
            for value in &values {
                let mut object = row.as_object().cloned().unwrap_or_default();
                object.insert(key.into(), value.clone());
                next.push(Value::Object(object));
                if next.len() > 10_000 {
                    return next;
                }
            }
        }
        rows = next;
    }
    rows
}

pub fn build_coverage_matrix(spec: &Value) -> Value {
    let expected = expected_cases(spec);
    let captures = spec
        .get("captures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let capture_keys = captures
        .iter()
        .map(|capture| case_key(capture))
        .collect::<std::collections::BTreeSet<_>>();
    let cases = expected.iter().map(|item| {
        let key = case_key(item);
        json!({"route":item.get("route").and_then(Value::as_str).unwrap_or("/"),"state":item.get("state").and_then(Value::as_str).unwrap_or("default"),"viewport":item.get("viewport").and_then(Value::as_str).unwrap_or("default"),"theme":item.get("theme").and_then(Value::as_str).unwrap_or("default"),"locale":item.get("locale").and_then(Value::as_str).unwrap_or("default"),"platform":item.get("platform").and_then(Value::as_str).unwrap_or("default"),"covered":capture_keys.contains(&key)})
    }).collect::<Vec<_>>();
    let covered = cases
        .iter()
        .filter(|item| item.get("covered").and_then(Value::as_bool) == Some(true))
        .count();
    json!({"expectedCount":cases.len(),"coveredCount":covered,"missingCount":cases.len()-covered,"complete":cases.len()==covered,"cases":cases})
}

fn read_capture(root: &std::path::Path, path: &str) -> Result<Vec<u8>, String> {
    let path = PathBuf::from(path);
    if path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err("capture path escapes root".into());
    }
    std::fs::read(root.join(path)).map_err(|error| error.to_string())
}

pub fn audit_visual_artifacts(input: &ProviderInput<'_>, spec: &Value) -> Value {
    let coverage = build_coverage_matrix(spec);
    let captures = spec
        .get("captures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut rows = Vec::new();
    let mut findings = Vec::new();
    for capture in captures {
        let id = capture.get("id").cloned().unwrap_or(Value::Null);
        let path = capture.get("path").and_then(Value::as_str);
        let Some(path) = path else {
            rows.push(json!({"id":id,"status":"unproven","reason":"capture-missing","path":null}));
            continue;
        };
        let actual = match read_capture(input.root, path) {
            Ok(bytes) => bytes,
            Err(_) => {
                rows.push(
                    json!({"id":id,"status":"unproven","reason":"capture-missing","path":path}),
                );
                continue;
            }
        };
        let Some(baseline) = capture.get("baseline").and_then(Value::as_str) else {
            rows.push(json!({"id":id,"status":"captured-no-baseline","path":path,"digest":digest_bytes(&actual)}));
            continue;
        };
        let baseline_bytes = match read_capture(input.root, baseline) {
            Ok(bytes) => bytes,
            Err(_) => {
                rows.push(json!({"id":id,"status":"unproven","reason":"baseline-missing","path":path,"baseline":baseline}));
                continue;
            }
        };
        let same = baseline_bytes == actual;
        rows.push(json!({"id":id,"status":if same {"match"} else {"different"},"path":path,"baseline":baseline,"diff":{"status":if same{"match"}else{"different"},"changedRatio":if same {0.0}else{1.0}}}));
        if !same {
            let id_string = id.as_str().unwrap_or("unknown");
            findings.push(json!({"id":digest_text(&format!("visual-regression\0{id_string}")),"ruleId":"visual.regression","severity":if baseline_bytes.len()!=actual.len(){"high"}else{"medium"},"title":format!("Visual regression in {id_string}"),"detail":"Rendered pixels differ from the baseline.","evidence":[{"actual":path,"baseline":baseline}]}));
        }
    }
    let empty = coverage.get("expectedCount").and_then(Value::as_u64) == Some(0);
    let incomplete_matrix = coverage.get("complete").and_then(Value::as_bool) != Some(true);
    let review = rows
        .iter()
        .any(|row| row.get("status").and_then(Value::as_str) == Some("captured-no-baseline"));
    let unproven = empty
        || incomplete_matrix
        || review
        || rows
            .iter()
            .any(|row| row.get("status").and_then(Value::as_str) == Some("unproven"));
    let mut gaps = Vec::new();
    if empty {
        gaps.push(json!({"kind":"visual-cases-missing","detail":"visual spec declares no expected cases; nothing is proven"}));
    }
    if incomplete_matrix {
        if let Some(cases) = coverage.get("cases").and_then(Value::as_array) {
            gaps.extend(
                cases
                    .iter()
                    .filter(|case| case.get("covered").and_then(Value::as_bool) != Some(true))
                    .map(|case| json!({"kind":"missing-visual-case","case":case})),
            );
        }
    }
    gaps.extend(rows.iter().filter(|row| row.get("status").and_then(Value::as_str)==Some("unproven")).map(|row| json!({"kind":row.get("reason").and_then(Value::as_str).unwrap_or("capture-missing"),"captureId":row.get("id")})));
    gaps.extend(rows.iter().filter(|row| row.get("status").and_then(Value::as_str)==Some("captured-no-baseline")).map(|row| json!({"kind":"visual-review-or-baseline-required","captureId":row.get("id")})));
    json!({"schemaVersion":1,"kind":"audit-visual-result","status":if !findings.is_empty(){"fail"}else if unproven{"unproven"}else{"pass"},"complete":!unproven,"reviewRequired":review,"coverage":coverage,"denominator":{"kind":"visual-artifacts","expected":expected_cases(spec).len(),"examined":rows.iter().filter(|row|row.get("status").and_then(Value::as_str)!=Some("unproven")).count()},"captures":rows,"findings":findings,"coverageGaps":gaps})
}

pub fn execute(
    input: &ProviderInput<'_>,
) -> Result<legion_contracts::ProviderResult, crate::error::AuditError> {
    let selected = denominator(input)?;
    let Some(spec) = input.artifacts.get("visualSpec") else {
        return super::common::result(
            input,
            ProviderStatus::Partial,
            false,
            &selected,
            0,
            Vec::new(),
            vec!["visual-spec-missing".into()],
            vec!["visual-spec-missing".into()],
            BTreeMap::new(),
        );
    };
    if !spec.is_object() {
        return super::common::result(
            input,
            ProviderStatus::Partial,
            false,
            &selected,
            0,
            Vec::new(),
            vec!["visual-spec-invalid".into()],
            vec!["visual-spec-invalid".into()],
            BTreeMap::new(),
        );
    }
    let analysis = audit_visual_artifacts(input, spec);
    let gaps = analysis
        .get("coverageGaps")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    item.get("kind")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let findings = analysis
        .get("findings")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    finding(
                        "visual.regression",
                        item.get("severity")
                            .and_then(Value::as_str)
                            .unwrap_or("medium"),
                        item.get("title")
                            .and_then(Value::as_str)
                            .unwrap_or("visual"),
                        index + 1,
                    )
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let complete = analysis.get("complete").and_then(Value::as_bool) == Some(true);
    let status = if analysis.get("status").and_then(Value::as_str) == Some("fail") {
        ProviderStatus::Complete
    } else if complete {
        ProviderStatus::Complete
    } else {
        ProviderStatus::Partial
    };
    let mut details = BTreeMap::new();
    details.insert("analysis".into(), analysis);
    super::common::result(
        input,
        status,
        complete,
        &selected,
        selected.entries.len(),
        findings,
        gaps.clone(),
        gaps,
        details,
    )
}
