//! Native implementation of `legacy.visual.core`.
//!
//! Artifact topology and coverage are native.  Pixel decoding is intentionally
//! bounded: equal bytes prove a match; unequal PNGs remain a typed visual
//! regression rather than being treated as a clean comparison.
//!
//! Inputs reach the provider frozen in its sealed plan under `runner.visual`:
//! `spec` (the parsed `--visual-spec` document) with `specDigest` (sha256 of
//! its raw bytes), and `baselines` (the `--visual-baselines` directory path,
//! its listing digest, and the sorted per-file sha256 values).  Captures are
//! the spec's `captures` entries, read relative to the audited root.

use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

use legion_contracts::ProviderStatus;
use serde_json::{json, Value};

use super::common::{denominator, digest_bytes, digest_text, finding, ProviderInput};
use crate::{inventory::InventoryDenominator, plan::AuditProvider};

/// Registry id of this provider.
pub const VISUAL_PROVIDER_ID: &str = "legacy.visual.core";
/// Unavailable reason when no visual spec was frozen for this run.
pub const SPEC_NOT_SUPPLIED: &str = "visual-spec-not-supplied";
/// Unavailable reason when a spec was supplied but declares no captures.
pub const CAPTURES_NOT_AVAILABLE: &str = "visual-captures-not-available";

const DIMENSIONS: [&str; 6] = [
    "routes",
    "states",
    "viewports",
    "themes",
    "locales",
    "platforms",
];
const CASE_FIELDS: [&str; 6] = ["route", "state", "viewport", "theme", "locale", "platform"];

fn case_key(value: &Value) -> String {
    CASE_FIELDS
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
    let mut rows = vec![Value::Object(Default::default())];
    for dimension in DIMENSIONS {
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

/// A relative path that stays inside the directory it is joined to.
fn is_safe_relative(value: &str) -> bool {
    let path = Path::new(value);
    !value.is_empty()
        && !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn read_capture(root: &Path, path: &str) -> Result<Vec<u8>, String> {
    if !is_safe_relative(path) {
        return Err("capture path escapes root".into());
    }
    std::fs::read(root.join(PathBuf::from(path))).map_err(|error| error.to_string())
}

/// Shape check for one case or capture object. Every present case field must
/// be a string, because the comparison would otherwise default it silently.
fn validate_entry(value: &Value, label: &str, capture: bool) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{label} must be a JSON object"))?;
    for field in CASE_FIELDS {
        if let Some(text) = object.get(field) {
            if !text.is_string() {
                return Err(format!("{label}.{field} must be a string"));
            }
        }
    }
    if !capture {
        return Ok(());
    }
    if !object.get("id").is_some_and(Value::is_string) {
        return Err(format!("{label}.id must be a string"));
    }
    match object.get("path").and_then(Value::as_str) {
        Some(path) if is_safe_relative(path) => {}
        _ => {
            return Err(format!(
                "{label}.path must be a relative path inside the audited root"
            ))
        }
    }
    if let Some(baseline) = object.get("baseline") {
        match baseline.as_str() {
            Some(name) if is_safe_relative(name) => {}
            _ => {
                return Err(format!(
                    "{label}.baseline must be a relative path (under the baselines directory when one is supplied)"
                ))
            }
        }
    }
    Ok(())
}

/// Shape check for a visual spec document: an object whose optional
/// `expected` (cases or dimension string arrays) and `captures` (objects with
/// string `id` and a safe relative `path`) have the types the comparison reads.
pub fn validate_spec(spec: &Value) -> Result<(), String> {
    let object = spec
        .as_object()
        .ok_or_else(|| "visual spec must be a JSON object".to_owned())?;
    if let Some(expected) = object.get("expected") {
        let expected = expected
            .as_object()
            .ok_or_else(|| "expected must be a JSON object".to_owned())?;
        if let Some(cases) = expected.get("cases") {
            let cases = cases
                .as_array()
                .ok_or_else(|| "expected.cases must be an array".to_owned())?;
            for (index, case) in cases.iter().enumerate() {
                validate_entry(case, &format!("expected.cases[{index}]"), false)?;
            }
        }
        for dimension in DIMENSIONS {
            if let Some(values) = expected.get(dimension) {
                let values = values
                    .as_array()
                    .ok_or_else(|| format!("expected.{dimension} must be an array"))?;
                if values.iter().any(|value| !value.is_string()) {
                    return Err(format!("expected.{dimension} must contain only strings"));
                }
            }
        }
    }
    if let Some(captures) = object.get("captures") {
        let captures = captures
            .as_array()
            .ok_or_else(|| "captures must be an array".to_owned())?;
        for (index, capture) in captures.iter().enumerate() {
            validate_entry(capture, &format!("captures[{index}]"), true)?;
        }
    }
    Ok(())
}

/// Parses and shape-checks the bytes of a `--visual-spec` file. The returned
/// object is the frozen `runner.visual` fragment: the parsed spec and the
/// sha256 of the raw bytes, so the plan seal covers both.
pub fn freeze_spec(bytes: &[u8]) -> Result<Value, String> {
    let spec: Value =
        serde_json::from_slice(bytes).map_err(|error| format!("not valid JSON: {error}"))?;
    validate_spec(&spec)?;
    Ok(json!({"spec": spec, "specDigest": digest_bytes(bytes)}))
}

fn collect_baseline_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, String)>,
) -> Result<(), String> {
    let entries = std::fs::read_dir(dir)
        .map_err(|error| format!("cannot read baselines directory: {error}"))?;
    for entry in entries {
        let entry = entry.map_err(|error| format!("cannot read baselines directory: {error}"))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot read baselines directory: {error}"))?;
        let path = entry.path();
        if file_type.is_dir() {
            collect_baseline_files(root, &path, out)?;
        } else if file_type.is_file() {
            let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
            let name = relative.to_string_lossy().replace('\\', "/");
            let bytes = std::fs::read(&path)
                .map_err(|error| format!("cannot read baseline {name}: {error}"))?;
            out.push((name, digest_bytes(&bytes)));
        } else {
            return Err(format!(
                "baseline entry is not a regular file or directory: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

/// Freezes a `--visual-baselines` directory: its canonical path, the sorted
/// per-file sha256 listing, and a digest over that listing. Symlinks and other
/// special entries are refused. Nothing is written.
pub fn freeze_baselines(dir: &Path) -> Result<Value, String> {
    let canonical = std::fs::canonicalize(dir)
        .map_err(|error| format!("{} is not an existing directory: {error}", dir.display()))?;
    if !canonical.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let mut files = Vec::new();
    collect_baseline_files(&canonical, &canonical, &mut files)?;
    files.sort();
    let listing = files
        .iter()
        .map(|(name, digest)| format!("{name}\0{digest}\n"))
        .collect::<String>();
    let entries = files
        .iter()
        .map(|(name, digest)| json!({"path": name, "sha256": digest}))
        .collect::<Vec<_>>();
    Ok(json!({
        "path": canonical.to_string_lossy().into_owned(),
        "digest": digest_text(&listing),
        "files": entries,
    }))
}

/// The provider's `artifacts` view: host-supplied artifacts overlaid with the
/// inputs frozen into this provider's sealed `runner.visual` object.
pub fn frozen_artifacts(base: &Value, provider: &AuditProvider) -> Value {
    let mut artifacts = base.as_object().cloned().unwrap_or_default();
    let visual = provider
        .configuration
        .get("runner")
        .and_then(|runner| runner.get("visual"));
    if let Some(visual) = visual {
        if let Some(spec) = visual.get("spec") {
            artifacts.insert("visualSpec".into(), spec.clone());
        }
        if let Some(baselines) = visual.get("baselines") {
            artifacts.insert("visualBaselines".into(), baselines.clone());
        }
    }
    Value::Object(artifacts)
}

/// Reads the baseline a capture names. With frozen baselines the name must be
/// a file of the frozen listing and its bytes must still match the digest
/// frozen with it. Without them the name resolves under the audited root.
fn read_baseline(input: &ProviderInput<'_>, name: &str) -> Result<Vec<u8>, &'static str> {
    let Some(frozen) = input.artifacts.get("visualBaselines") else {
        return read_capture(input.root, name).map_err(|_| "baseline-missing");
    };
    if !is_safe_relative(name) {
        return Err("baseline-missing");
    }
    let directory = frozen
        .get("path")
        .and_then(Value::as_str)
        .ok_or("baseline-missing")?;
    let expected = frozen
        .get("files")
        .and_then(Value::as_array)
        .and_then(|files| {
            files
                .iter()
                .find(|file| file.get("path").and_then(Value::as_str) == Some(name))
        })
        .and_then(|file| file.get("sha256"))
        .and_then(Value::as_str)
        .ok_or("baseline-missing")?;
    let bytes = std::fs::read(Path::new(directory).join(name)).map_err(|_| "baseline-missing")?;
    if digest_bytes(&bytes) != expected {
        return Err("baseline-changed-since-freeze");
    }
    Ok(bytes)
}

fn has_captures(spec: &Value) -> bool {
    spec.get("captures")
        .and_then(Value::as_array)
        .is_some_and(|captures| !captures.is_empty())
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
        let baseline_bytes = match read_baseline(input, baseline) {
            Ok(bytes) => bytes,
            Err(reason) => {
                rows.push(json!({"id":id,"status":"unproven","reason":reason,"path":path,"baseline":baseline}));
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

/// A provider that cannot run reports `unavailable:<reason>` with no findings.
fn unavailable(
    input: &ProviderInput<'_>,
    selected: &InventoryDenominator,
    reason: &str,
) -> Result<legion_contracts::ProviderResult, crate::error::AuditError> {
    let mut result = super::common::result(
        input,
        ProviderStatus::Partial,
        false,
        selected,
        0,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        BTreeMap::new(),
    )?;
    crate::native_providers::availability::mark_unavailable(&mut result, reason);
    Ok(result)
}

pub fn execute(
    input: &ProviderInput<'_>,
) -> Result<legion_contracts::ProviderResult, crate::error::AuditError> {
    let selected = denominator(input)?;
    let Some(spec) = input.artifacts.get("visualSpec") else {
        return unavailable(input, &selected, SPEC_NOT_SUPPLIED);
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
    if !has_captures(spec) {
        return unavailable(input, &selected, CAPTURES_NOT_AVAILABLE);
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
    // A regression verdict is a finding, not completeness: only a fully
    // proven capture matrix (every case covered, every capture compared)
    // reports Complete.
    let status = if complete {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        execution::ProviderExecutor,
        inventory::{InventoryEntry, InventoryEnvelope},
        native_providers::{
            availability::unavailable_reason, legacy::common::ProviderExecutorAdapter,
        },
        plan::ProviderKind,
    };

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("legion-visual-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn provider(runner: Value) -> AuditProvider {
        AuditProvider {
            id: VISUAL_PROVIDER_ID.into(),
            version: "2.0.0".into(),
            role: "deterministic".into(),
            phase: "runtime".into(),
            lens_ids: vec!["visual".into()],
            dependencies: Vec::new(),
            kind: ProviderKind::RustAlgorithm,
            configuration: BTreeMap::from([
                ("selector".into(), json!({"op": "always"})),
                ("runner".into(), runner),
            ]),
            bounds: BTreeMap::new(),
            clean_claim: "evidence-only".into(),
            benchmark_status: "unproven".into(),
            benchmark_required_for_clean_claim: false,
            qualification_digest: None,
            required: false,
        }
    }

    fn inventory() -> InventoryEnvelope {
        InventoryEnvelope::new(
            "visual-fixture",
            "generation",
            vec![InventoryEntry {
                path: "src/app.ts".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            }],
        )
        .unwrap()
    }

    /// The runner exactly as the bins freeze it: spec plus optional baselines.
    fn frozen_runner(spec: &Value, baselines: Option<&Path>) -> Value {
        let mut visual = freeze_spec(&serde_json::to_vec(spec).unwrap()).unwrap();
        if let Some(dir) = baselines {
            visual["baselines"] = freeze_baselines(dir).unwrap();
        }
        json!({"kind": "runtime-script", "module": VISUAL_PROVIDER_ID, "visual": visual})
    }

    fn run(root: &Path, runner: Value) -> legion_contracts::ProviderResult {
        ProviderExecutorAdapter::new(root.to_path_buf())
            .execute(&provider(runner), &inventory())
            .unwrap()
    }

    fn two_case_spec() -> Value {
        json!({
            "expected": {"cases": [
                {"route": "/", "state": "default"},
                {"route": "/nav", "state": "default"}
            ]},
            "captures": [
                {"id": "home", "path": "shots/home.png", "baseline": "home.png", "route": "/", "state": "default"},
                {"id": "nav", "path": "shots/nav.png", "baseline": "nav.png", "route": "/nav", "state": "default"}
            ]
        })
    }

    #[test]
    fn spec_baselines_and_captures_yield_a_per_entry_comparison() {
        let root = scratch("compare-root");
        std::fs::create_dir_all(root.join("shots")).unwrap();
        std::fs::write(root.join("shots/home.png"), b"same-pixels").unwrap();
        std::fs::write(root.join("shots/nav.png"), b"new-pixels").unwrap();
        let baselines = scratch("compare-baselines");
        std::fs::write(baselines.join("home.png"), b"same-pixels").unwrap();
        std::fs::write(baselines.join("nav.png"), b"old-pixels").unwrap();

        let result = run(
            &root,
            frozen_runner(&two_case_spec(), Some(baselines.as_path())),
        );

        let rows = &result.details["analysis"]["captures"];
        assert_eq!(rows[0]["id"], "home");
        assert_eq!(rows[0]["status"], "match");
        assert_eq!(rows[1]["id"], "nav");
        assert_eq!(rows[1]["status"], "different");
        assert_eq!(result.findings.len(), 1, "one regression finding");
        // Every case covered and every capture compared: Complete, with the
        // regression carried as a finding rather than as incompleteness.
        assert!(result.complete);
        assert_eq!(result.status, ProviderStatus::Complete);
        assert!(unavailable_reason(&result).is_none());
    }

    #[test]
    fn changed_baseline_after_freeze_is_unproven_not_compared() {
        let root = scratch("drift-root");
        std::fs::create_dir_all(root.join("shots")).unwrap();
        std::fs::write(root.join("shots/home.png"), b"pixels").unwrap();
        let baselines = scratch("drift-baselines");
        std::fs::write(baselines.join("home.png"), b"v1").unwrap();
        let spec = json!({"expected": {"routes": ["/"]}, "captures": [
            {"id": "home", "path": "shots/home.png", "baseline": "home.png"}
        ]});
        let runner = frozen_runner(&spec, Some(baselines.as_path()));
        std::fs::write(baselines.join("home.png"), b"v2").unwrap();

        let result = run(&root, runner);

        assert!(!result.complete);
        assert_eq!(result.status, ProviderStatus::Partial);
        assert_eq!(
            result.details["analysis"]["captures"][0]["reason"],
            "baseline-changed-since-freeze"
        );
        assert!(result
            .coverage_gaps
            .iter()
            .any(|gap| gap == "baseline-changed-since-freeze"));
    }

    #[test]
    fn capture_without_baseline_requires_review_and_is_not_complete() {
        let root = scratch("review-root");
        std::fs::create_dir_all(root.join("shots")).unwrap();
        std::fs::write(root.join("shots/home.png"), b"pixels").unwrap();
        let spec = json!({"expected": {"routes": ["/"]}, "captures": [
            {"id": "home", "path": "shots/home.png"}
        ]});

        let result = run(&root, frozen_runner(&spec, None));

        assert!(!result.complete);
        assert_eq!(
            result.details["analysis"]["captures"][0]["status"],
            "captured-no-baseline"
        );
        assert_eq!(result.details["analysis"]["reviewRequired"], true);
    }

    #[test]
    fn missing_spec_is_unavailable_with_the_spec_reason() {
        let root = scratch("no-spec");
        let result = ProviderExecutorAdapter::new(root.clone())
            .execute(&provider(json!({"kind": "runtime-script"})), &inventory())
            .unwrap();
        assert_eq!(unavailable_reason(&result), Some(SPEC_NOT_SUPPLIED));
        assert!(!result.complete);
        assert_ne!(result.status, ProviderStatus::Complete);
    }

    #[test]
    fn spec_without_captures_is_unavailable_with_the_captures_reason() {
        let root = scratch("no-captures");
        let spec = json!({"expected": {"routes": ["/"]}});

        let result = run(&root, frozen_runner(&spec, None));

        assert_eq!(unavailable_reason(&result), Some(CAPTURES_NOT_AVAILABLE));
        assert!(!result.complete);
    }

    #[test]
    fn malformed_specs_are_refused_with_the_problem_named() {
        let not_object = freeze_spec(b"[1,2]").unwrap_err();
        assert!(not_object.contains("JSON object"), "{not_object}");
        let not_json = freeze_spec(b"{").unwrap_err();
        assert!(not_json.contains("not valid JSON"), "{not_json}");
        let bad_dimension = freeze_spec(br#"{"expected":{"routes":"/"}}"#).unwrap_err();
        assert!(bad_dimension.contains("expected.routes"), "{bad_dimension}");
        let escaping = freeze_spec(br#"{"captures":[{"id":"a","path":"../x.png"}]}"#).unwrap_err();
        assert!(escaping.contains("captures[0].path"), "{escaping}");
        let no_id = freeze_spec(br#"{"captures":[{"path":"a.png"}]}"#).unwrap_err();
        assert!(no_id.contains("captures[0].id"), "{no_id}");
    }

    #[test]
    fn freeze_records_the_raw_spec_digest() {
        let bytes = br#"{"expected":{"routes":["/"]}}"#;
        let frozen = freeze_spec(bytes).unwrap();
        assert_eq!(frozen["specDigest"], digest_bytes(bytes));
        assert_eq!(frozen["spec"]["expected"]["routes"][0], "/");
    }

    #[test]
    fn baselines_digest_changes_when_a_baseline_file_changes() {
        let dir = scratch("digest-baselines");
        std::fs::create_dir_all(dir.join("nested")).unwrap();
        std::fs::write(dir.join("a.png"), b"one").unwrap();
        std::fs::write(dir.join("nested/b.png"), b"two").unwrap();
        let first = freeze_baselines(&dir).unwrap();
        let again = freeze_baselines(&dir).unwrap();
        assert_eq!(first["digest"], again["digest"], "stable when unchanged");
        assert_eq!(first["files"][0]["path"], "a.png", "sorted listing");
        assert_eq!(first["files"][1]["path"], "nested/b.png");

        std::fs::write(dir.join("nested/b.png"), b"changed").unwrap();
        let after = freeze_baselines(&dir).unwrap();
        assert_ne!(first["digest"], after["digest"]);
        assert_ne!(first["files"][1]["sha256"], after["files"][1]["sha256"]);
    }

    #[test]
    fn baselines_must_be_an_existing_directory() {
        let dir = scratch("not-a-dir");
        std::fs::write(dir.join("file.png"), b"x").unwrap();
        assert!(freeze_baselines(&dir.join("file.png")).is_err());
        assert!(freeze_baselines(&dir.join("missing")).is_err());
    }
}
