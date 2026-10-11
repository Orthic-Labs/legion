//! Native implementation of `legacy.visual.core`.
//!
//! Artifact topology and coverage are native. PNGs are decoded within fixed
//! bounds and compared as pixels; artifact digests remain separate evidence.
//!
//! Inputs reach the provider frozen in its sealed plan under `runner.visual`:
//! `spec` (the parsed `--visual-spec` document) with `specDigest` (sha256 of
//! its raw bytes), and `baselines` (the `--visual-baselines` directory path,
//! its listing digest, and the sorted per-file sha256 values).  Captures are
//! the spec's `captures` entries, read relative to the audited root.

use std::{
    collections::BTreeMap,
    fs::File,
    io::Read,
    path::{Component, Path, PathBuf},
};

use legion_contracts::ProviderStatus;
use serde_json::{json, Value};

use super::{
    common::{denominator, digest_bytes, digest_text, finding, ProviderInput},
    visual_png::{self, MAX_ENCODED_PNG_BYTES},
};
use crate::execution::ProviderExecution;
use crate::{inventory::InventoryDenominator, plan::AuditProvider};

/// Registry id of this provider.
pub const VISUAL_PROVIDER_ID: &str = "legacy.visual.core";
/// Unavailable reason when no visual spec was frozen for this run.
pub const SPEC_NOT_SUPPLIED: &str = "visual-spec-not-supplied";
/// Unavailable reason when a spec was supplied but declares no captures.
pub const CAPTURES_NOT_AVAILABLE: &str = "visual-captures-not-available";

const RUNTIME_PROVIDER_ID: &str = "legacy.runtime.app";

/// Validated same-plan runtime output offered to the visual provider. The
/// capture remains supplemental evidence; it never changes a frozen visual
/// specification or source-location map.
#[derive(Clone, Debug)]
pub struct RuntimeVisualCapture {
    pub plan_digest: String,
    pub inventory_digest: String,
    pub source_provider_id: String,
    pub runtime_inputs: Value,
    pub prior_execution: Option<ProviderExecution>,
    pub artifact_dir: Option<PathBuf>,
    pub scratch_tmp_dir: Option<PathBuf>,
}

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
    read_fenced_regular(root, &root.join(PathBuf::from(path)), MAX_ENCODED_PNG_BYTES)
}

fn read_fenced_regular(root: &Path, path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let canonical_root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
    let mut current = canonical_root.clone();
    let relative = path
        .strip_prefix(root)
        .or_else(|_| path.strip_prefix(&canonical_root))
        .map_err(|_| "path is outside evidence root".to_owned())?;
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                current.push(part);
                let metadata =
                    std::fs::symlink_metadata(&current).map_err(|error| error.to_string())?;
                if metadata.file_type().is_symlink() {
                    return Err("evidence path contains a symlink".into());
                }
            }
            Component::CurDir => {}
            _ => return Err("evidence path escapes root".into()),
        }
    }
    let canonical = std::fs::canonicalize(&current).map_err(|error| error.to_string())?;
    if !canonical.starts_with(&canonical_root) {
        return Err("evidence path escapes root".into());
    }
    let mut file = File::open(&canonical).map_err(|error| error.to_string())?;
    if !file
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err("evidence is not a regular file".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > maximum {
        return Err(format!("evidence exceeds {maximum} bytes"));
    }
    Ok(bytes)
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
            ));
        }
    }
    if let Some(baseline) = object.get("baseline") {
        match baseline.as_str() {
            Some(name) if is_safe_relative(name) => {}
            _ => {
                return Err(format!(
                    "{label}.baseline must be a relative path (under the baselines directory when one is supplied)"
                ));
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
    if let Some(diff) = object.get("diff") {
        diff_options(Some(diff))?;
    }
    if let Some(captures) = object.get("captures").and_then(Value::as_array) {
        for (index, capture) in captures.iter().enumerate() {
            if let Some(diff) = capture.get("diff") {
                diff_options(Some(diff)).map_err(|error| format!("captures[{index}].{error}"))?;
            }
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
    let directory = Path::new(directory);
    let bytes = read_fenced_regular(directory, &directory.join(name), MAX_ENCODED_PNG_BYTES)
        .map_err(|_| "baseline-missing")?;
    if digest_bytes(&bytes) != expected {
        return Err("baseline-changed-since-freeze");
    }
    Ok(bytes)
}

fn diff_options(value: Option<&Value>) -> Result<visual_png::DiffOptions, String> {
    let Some(value) = value else {
        return Ok(visual_png::DiffOptions::default());
    };
    let object = value
        .as_object()
        .ok_or_else(|| "diff options must be an object".to_owned())?;
    let number = |name: &str, default: f64| match object.get(name) {
        None => Ok(default),
        Some(value) => value
            .as_f64()
            .ok_or_else(|| format!("diff.{name} must be a number")),
    };
    let channel_threshold = number("channelThreshold", 0.0)?;
    let max_changed_ratio = number("maxChangedRatio", 0.0)?;
    let masks = object
        .get("masks")
        .map(|value| {
            value
                .as_array()
                .ok_or_else(|| "diff masks must be an array".to_owned())?
                .iter()
                .enumerate()
                .map(|(index, mask)| {
                    let coordinate = |name: &str| {
                        mask.get(name)
                            .and_then(Value::as_u64)
                            .and_then(|number| u32::try_from(number).ok())
                            .ok_or_else(|| format!("diff mask {index}.{name} must be a u32"))
                    };
                    Ok(visual_png::MaskRect {
                        x: coordinate("x")?,
                        y: coordinate("y")?,
                        width: coordinate("width")?,
                        height: coordinate("height")?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()
        })
        .transpose()?
        .unwrap_or_default();
    let options = visual_png::DiffOptions {
        channel_threshold,
        max_changed_ratio,
        masks,
    };
    visual_png::validate_options(&options)?;
    Ok(options)
}

fn capture_diff_options(spec: &Value, capture: &Value) -> Result<visual_png::DiffOptions, String> {
    let options = capture
        .get("diff")
        .filter(|value| !value.is_null())
        .or_else(|| spec.get("diff").filter(|value| !value.is_null()));
    diff_options(options)
}

fn has_captures(spec: &Value) -> bool {
    spec.get("captures")
        .and_then(Value::as_array)
        .is_some_and(|captures| !captures.is_empty())
}

#[derive(Clone, Debug)]
struct RuntimeVisualCase {
    index: usize,
    label: String,
    url: Option<String>,
    width: u32,
    height: u32,
    unsupported: bool,
}

fn runtime_visual_cases(inputs: &Value) -> Vec<RuntimeVisualCase> {
    let width = inputs.get("width").and_then(Value::as_u64).unwrap_or(1280) as u32;
    let height = inputs.get("height").and_then(Value::as_u64).unwrap_or(800) as u32;
    let mut cases = vec![RuntimeVisualCase {
        index: 0,
        label: "entry".into(),
        url: inputs
            .get("url")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        width,
        height,
        unsupported: false,
    }];
    if let Some(surfaces) = inputs.get("surfaces").and_then(Value::as_array) {
        for (index, surface) in surfaces.iter().enumerate() {
            cases.push(RuntimeVisualCase {
                index: index + 1,
                label: surface
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_owned(),
                url: surface
                    .get("url")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                width,
                height,
                unsupported: false,
            });
        }
    }
    if let Some(unsupported) = inputs.get("unsupportedSurfaces").and_then(Value::as_array) {
        let first = cases.len();
        for (offset, label) in unsupported.iter().enumerate() {
            cases.push(RuntimeVisualCase {
                index: first + offset,
                label: label.as_str().unwrap_or("unknown").to_owned(),
                url: None,
                width,
                height,
                unsupported: true,
            });
        }
    }
    cases
}

fn path_has_symlink_component(root: &Path, path: &Path) -> Result<(), String> {
    let canonical_root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
    let relative = path
        .strip_prefix(root)
        .or_else(|_| path.strip_prefix(&canonical_root))
        .map_err(|_| "runtime screenshot is outside its evidence root".to_owned())?;
    let mut current = canonical_root;
    for component in relative.components() {
        match component {
            Component::Normal(part) => {
                current.push(part);
                if std::fs::symlink_metadata(&current)
                    .map_err(|error| error.to_string())?
                    .file_type()
                    .is_symlink()
                {
                    return Err("runtime screenshot path contains a symlink".into());
                }
            }
            _ => return Err("runtime screenshot path is not canonical".into()),
        }
    }
    Ok(())
}

fn read_runtime_screenshot(
    capture: &RuntimeVisualCapture,
    surface: &Value,
    case: &RuntimeVisualCase,
) -> Result<(Vec<u8>, PathBuf, visual_png::PngDimensions), String> {
    let metadata = surface
        .get("screenshot")
        .ok_or_else(|| "runtime screenshot metadata is missing".to_owned())?;
    let path_text = metadata
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| "runtime screenshot path is missing".to_owned())?;
    let path = PathBuf::from(path_text);
    let filename = format!("runtime-shot-{}.png", case.index);
    let root = if let Some(artifact_dir) = capture.artifact_dir.as_deref() {
        let expected = artifact_dir.join(&filename);
        if path != expected {
            return Err("runtime screenshot path does not match frozen artifact directory".into());
        }
        artifact_dir
    } else {
        let tmp = capture
            .scratch_tmp_dir
            .as_deref()
            .ok_or_else(|| "runtime screenshot scratch root is unavailable".to_owned())?;
        let shot_dir = path
            .parent()
            .ok_or_else(|| "runtime screenshot path is malformed".to_owned())?;
        let run_dir = shot_dir
            .parent()
            .ok_or_else(|| "runtime screenshot run directory is malformed".to_owned())?;
        let run_name = run_dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "runtime screenshot run directory is malformed".to_owned())?;
        if !run_name.strip_prefix("runtime-").is_some_and(|suffix| {
            !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
        }) || path.file_name().and_then(|name| name.to_str()) != Some(filename.as_str())
            || shot_dir.file_name().and_then(|name| name.to_str()) != Some("shots")
        {
            return Err("runtime screenshot path does not match run-owned scratch layout".into());
        }
        let canonical_tmp = std::fs::canonicalize(tmp).map_err(|error| error.to_string())?;
        let canonical_path = std::fs::canonicalize(&path).map_err(|error| error.to_string())?;
        if !canonical_path.starts_with(&canonical_tmp) {
            return Err("runtime screenshot escapes run-owned scratch".into());
        }
        // The checker below must inspect all components beneath this root.
        // `path` remains the exact receipt-bound path, while `tmp` is its fence.
        tmp
    };
    path_has_symlink_component(root, &path)?;
    let bytes = read_fenced_regular(root, &path, MAX_ENCODED_PNG_BYTES)?;
    let expected_bytes = metadata
        .get("bytes")
        .and_then(Value::as_u64)
        .ok_or_else(|| "runtime screenshot byte length is missing".to_owned())?;
    if bytes.len() as u64 != expected_bytes {
        return Err("runtime screenshot byte length changed".into());
    }
    let expected_digest = metadata
        .get("sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| "runtime screenshot digest is missing".to_owned())?;
    if digest_bytes(&bytes) != expected_digest {
        return Err("runtime screenshot digest changed".into());
    }
    let dimensions = visual_png::inspect_png(&bytes).map_err(|error| error.to_string())?;
    if dimensions.width != case.width || dimensions.height != case.height {
        return Err("runtime screenshot dimensions differ from frozen viewport".into());
    }
    Ok((bytes, path, dimensions))
}

fn runtime_surface_for<'a>(
    capture: &'a RuntimeVisualCapture,
    case: &RuntimeVisualCase,
) -> Result<&'a Value, String> {
    let prior = capture
        .prior_execution
        .as_ref()
        .ok_or_else(|| "runtime provider did not produce a prior result".to_owned())?;
    if prior.provider != capture.source_provider_id
        || prior.result.provider.to_string() != capture.source_provider_id
        || prior.result.complete
    {
        return Err("runtime provider result identity or completeness is invalid".into());
    }
    let surfaces = prior
        .result
        .details
        .get("runtime")
        .and_then(|runtime| runtime.get("surfaces"))
        .and_then(Value::as_array)
        .ok_or_else(|| "runtime surface results are missing".to_owned())?;
    let surface = surfaces
        .iter()
        .find(|surface| surface.get("index").and_then(Value::as_u64) == Some(case.index as u64))
        .ok_or_else(|| "expected runtime surface is missing".to_owned())?;
    if surface.get("label").and_then(Value::as_str) != Some(case.label.as_str())
        || surface.get("url").and_then(Value::as_str) != case.url.as_deref()
        || surface.get("status").and_then(Value::as_str) != Some("captured")
        || surface
            .get("viewport")
            .and_then(|viewport| viewport.get("width"))
            .and_then(Value::as_u64)
            != Some(case.width as u64)
        || surface
            .get("viewport")
            .and_then(|viewport| viewport.get("height"))
            .and_then(Value::as_u64)
            != Some(case.height as u64)
    {
        return Err("runtime surface binding differs from frozen input".into());
    }
    let receipt_id = surface
        .get("receiptId")
        .and_then(Value::as_str)
        .ok_or_else(|| "runtime surface receipt id is missing".to_owned())?;
    let receipt = prior
        .result
        .details
        .get("executionReceipts")
        .and_then(Value::as_array)
        .and_then(|receipts| {
            receipts.iter().find(|receipt| {
                receipt.get("receiptId").and_then(Value::as_str) == Some(receipt_id)
            })
        })
        .ok_or_else(|| "runtime surface receipt is missing".to_owned())?;
    let expected_request = format!(
        "audit:{}:{}:{}:surface-{}",
        capture.source_provider_id, capture.plan_digest, capture.inventory_digest, case.index
    );
    if receipt.get("providerId").and_then(Value::as_str)
        != Some(capture.source_provider_id.as_str())
        || receipt.get("planId").and_then(Value::as_str) != Some(capture.plan_digest.as_str())
        || receipt.get("requestId").and_then(Value::as_str) != Some(expected_request.as_str())
        || receipt
            .get("processTree")
            .and_then(|tree| tree.get("started"))
            .and_then(Value::as_bool)
            != Some(true)
        || receipt
            .get("processTree")
            .and_then(|tree| tree.get("reaped"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        return Err("runtime receipt does not bind this plan and surface".into());
    }
    Ok(surface)
}

fn audit_runtime_visual(capture: Option<&RuntimeVisualCapture>) -> Value {
    let cases = capture
        .map(|capture| runtime_visual_cases(&capture.runtime_inputs))
        .unwrap_or_default();
    let mut rows = Vec::new();
    let mut gaps = Vec::new();
    for case in &cases {
        let identity = format!("runtime-surface-{}", case.index);
        if case.unsupported {
            rows.push(json!({"id":identity,"index":case.index,"label":case.label,"url":null,"status":"unproven","reason":"runtime-surface-unsupported"}));
            gaps.push(json!({"kind":"runtime-surface-unsupported","case":identity}));
            continue;
        }
        let Some(capture) = capture else {
            rows.push(json!({"id":identity,"index":case.index,"label":case.label,"url":case.url,"status":"unproven","reason":"runtime-source-missing"}));
            gaps.push(json!({"kind":"runtime-source-missing","case":identity}));
            continue;
        };
        let result = runtime_surface_for(capture, case)
            .and_then(|surface| read_runtime_screenshot(capture, surface, case));
        match result {
            Ok((bytes, path, dimensions)) => rows.push(json!({
                "id":identity,
                "index":case.index,
                "label":case.label,
                "url":case.url,
                "viewport":{"width":case.width,"height":case.height},
                "status":"captured-no-baseline",
                "path":path,
                "sha256":digest_bytes(&bytes),
                "bytes":bytes.len(),
                "dimensions":dimensions,
            })),
            Err(reason) => {
                rows.push(json!({"id":identity,"index":case.index,"label":case.label,"url":case.url,"status":"unproven","reason":"runtime-capture-unproven","detail":reason}));
                gaps.push(json!({"kind":"runtime-capture-unproven","case":identity}));
            }
        }
    }
    let captured = rows
        .iter()
        .filter(|row| row.get("status").and_then(Value::as_str) == Some("captured-no-baseline"))
        .count();
    for row in rows
        .iter()
        .filter(|row| row.get("status").and_then(Value::as_str) == Some("captured-no-baseline"))
    {
        gaps.push(json!({"kind":"visual-review-or-baseline-required","case":row["id"]}));
    }
    if cases.is_empty() {
        gaps.push(json!({"kind":"runtime-source-missing","detail":"no frozen runtime surfaces are available"}));
    }
    json!({
        "schemaVersion":1,
        "kind":"audit-visual-result",
        "status":"unproven",
        "complete":false,
        "reviewRequired":true,
        "captureSource":{"providerId":capture.map(|capture| capture.source_provider_id.as_str()).unwrap_or(RUNTIME_PROVIDER_ID),"planDigest":capture.map(|capture| capture.plan_digest.as_str()).unwrap_or("")},
        "coverage":{"expectedCount":cases.len(),"capturedCount":captured,"missingCount":cases.len().saturating_sub(captured),"complete":false,"cases":rows.iter().map(|row|json!({"index":row["index"],"label":row["label"],"url":row["url"],"viewport":row["viewport"],"covered":row["status"]=="captured-no-baseline"})).collect::<Vec<_>>()},
        "denominator":{"kind":"runtime-surfaces","expected":cases.len(),"examined":captured},
        "captures":rows,
        "findings":[],
        "coverageGaps":gaps,
    })
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
        let options = match capture_diff_options(spec, &capture) {
            Ok(options) => options,
            Err(reason) => {
                rows.push(json!({"id":id,"status":"unproven","reason":"diff-options-invalid","detail":reason,"path":path}));
                continue;
            }
        };
        let Some(baseline) = capture.get("baseline").and_then(Value::as_str) else {
            match visual_png::inspect_png(&actual) {
                Ok(dimensions) => rows.push(json!({"id":id,"status":"captured-no-baseline","path":path,"digest":digest_bytes(&actual),"bytes":actual.len(),"width":dimensions.width,"height":dimensions.height})),
                Err(error) => rows.push(json!({"id":id,"status":"unproven","reason":"capture-decode-failed","detail":error.to_string(),"path":path})),
            }
            continue;
        };
        let baseline_bytes = match read_baseline(input, baseline) {
            Ok(bytes) => bytes,
            Err(reason) => {
                rows.push(json!({"id":id,"status":"unproven","reason":reason,"path":path,"baseline":baseline}));
                continue;
            }
        };
        let id_string = id.as_str().unwrap_or("unknown");
        match visual_png::compare_png(&actual, &baseline_bytes, &options) {
            visual_png::PngComparison::Compared(diff) => {
                let different = diff.status == visual_png::PixelStatus::Different;
                let diff_evidence = serde_json::to_value(&diff).unwrap_or(Value::Null);
                rows.push(json!({"id":id,"status":if different {"different"} else {"match"},"path":path,"baseline":baseline,"diff":diff}));
                if different {
                    findings.push(json!({"id":digest_text(&format!("visual-regression\0{id_string}")),"ruleId":"visual.regression","severity":"medium","title":format!("Visual regression in {id_string}"),"detail":"Rendered pixels differ from the baseline.","evidence":{"kind":"visual-artifact-difference","captureId":id,"actual":{"path":path,"digest":digest_bytes(&actual),"bytes":actual.len()},"baseline":{"path":baseline,"digest":digest_bytes(&baseline_bytes),"bytes":baseline_bytes.len()},"diff":diff_evidence}}));
                }
            }
            visual_png::PngComparison::DifferentDimensions { actual: actual_dimensions, baseline: baseline_dimensions } => {
                rows.push(json!({"id":id,"status":"different","path":path,"baseline":baseline,"reason":"dimensions-differ","actualDimensions":actual_dimensions,"baselineDimensions":baseline_dimensions}));
                findings.push(json!({"id":digest_text(&format!("visual-regression\0{id_string}")),"ruleId":"visual.regression","severity":"high","title":format!("Visual dimensions changed in {id_string}"),"detail":"Rendered image dimensions differ from the baseline.","evidence":{"kind":"visual-artifact-difference","captureId":id,"actual":{"path":path,"digest":digest_bytes(&actual),"bytes":actual.len()},"baseline":{"path":baseline,"digest":digest_bytes(&baseline_bytes),"bytes":baseline_bytes.len()},"diff":{"reason":"dimensions-differ","actual":actual_dimensions,"baseline":baseline_dimensions}}}));
            }
            visual_png::PngComparison::Unproven(error) => rows.push(json!({"id":id,"status":"unproven","reason":"pixel-comparison-unproven","detail":error.to_string(),"path":path,"baseline":baseline})),
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

fn projected_findings(
    analysis: &Value,
    spec_digest: &str,
) -> (
    Vec<legion_contracts::FindingRef>,
    BTreeMap<String, Value>,
    BTreeMap<String, Value>,
    BTreeMap<String, Value>,
    BTreeMap<String, Value>,
) {
    let items = analysis
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut findings = Vec::with_capacity(items.len());
    let mut evidence = BTreeMap::new();
    let mut locations = BTreeMap::new();
    let mut titles = BTreeMap::new();
    let mut messages = BTreeMap::new();
    for (index, item) in items.iter().enumerate() {
        let title = item
            .get("title")
            .and_then(Value::as_str)
            .unwrap_or("visual");
        let finding = finding(
            "visual.regression",
            item.get("severity")
                .and_then(Value::as_str)
                .unwrap_or("medium"),
            title,
            index + 1,
        );
        if let Some(mut value) = item.get("evidence").cloned() {
            if let Some(object) = value.as_object_mut() {
                object.insert("specDigest".into(), json!(spec_digest));
            }
            evidence.insert(finding.id.to_string(), value);
        }
        locations.insert(finding.id.to_string(), json!([]));
        titles.insert(finding.id.to_string(), json!(title));
        messages.insert(
            finding.id.to_string(),
            item.get("detail")
                .cloned()
                .unwrap_or_else(|| json!("Rendered pixels differ from the baseline.")),
        );
        findings.push(finding);
    }
    (findings, evidence, locations, titles, messages)
}

/// Re-evaluates an explicit visual spec from its signed provider spec and
/// current bounded image bytes. Runtime-generated captures are deliberately
/// excluded because they are an execution-time handoff, not sealed inputs.
pub fn verify_explicit_visual_execution(
    root: &Path,
    provider: &AuditProvider,
    generation: &str,
    stored: &legion_contracts::ProviderResult,
) -> Result<(), String> {
    let visual = provider
        .configuration
        .get("runner")
        .and_then(|runner| runner.get("visual"))
        .ok_or_else(|| "frozen visual runner is missing".to_owned())?;
    let spec = visual
        .get("spec")
        .filter(|spec| spec.is_object())
        .ok_or_else(|| "frozen explicit visual spec is missing".to_owned())?;
    if !has_captures(spec) {
        if stored.complete
            || !stored.findings.is_empty()
            || crate::native_providers::availability::unavailable_reason(stored)
                != Some(CAPTURES_NOT_AVAILABLE)
        {
            return Err("empty frozen visual spec must remain unavailable and incomplete".into());
        }
        return Ok(());
    }
    let spec_digest = visual
        .get("specDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| "frozen visual spec digest is missing".to_owned())?;
    let inventory =
        crate::inventory::InventoryEnvelope::new("visual-verification", generation, Vec::new())
            .map_err(|error| error.to_string())?;
    let artifacts = frozen_artifacts(&Value::Null, provider);
    let input = ProviderInput {
        provider,
        inventory: &inventory,
        root,
        artifacts: &artifacts,
        runtime_visual_capture: None,
        now: None,
    };
    let analysis = audit_visual_artifacts(&input, spec);
    if stored.details.get("analysis") != Some(&analysis) {
        return Err("stored visual analysis differs from fresh bounded image comparison".into());
    }
    let complete = analysis.get("complete").and_then(Value::as_bool) == Some(true);
    let mut expected_gaps = analysis
        .get("coverageGaps")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("kind").and_then(Value::as_str).map(str::to_owned))
        .collect::<Vec<_>>();
    expected_gaps.sort();
    expected_gaps.dedup();
    let expected_status = if complete {
        ProviderStatus::Complete
    } else {
        ProviderStatus::Partial
    };
    if stored.complete != complete
        || stored.status != expected_status
        || stored.coverage_gaps != expected_gaps
    {
        return Err("stored visual completion state differs from frozen-spec projection".into());
    }
    let (findings, evidence, locations, titles, messages) =
        projected_findings(&analysis, spec_digest);
    let expected_findings = serde_json::to_value(findings).map_err(|error| error.to_string())?;
    if serde_json::to_value(&stored.findings).map_err(|error| error.to_string())?
        != expected_findings
    {
        return Err("stored visual findings differ from frozen-spec projection".into());
    }
    for (field, expected) in [
        ("findingEvidence", evidence),
        ("findingLocations", locations),
        ("findingTitles", titles),
        ("findingMessages", messages),
    ] {
        let expected = serde_json::to_value(expected).map_err(|error| error.to_string())?;
        if stored.details.get(field) != Some(&expected) {
            return Err(format!(
                "stored visual {field} differs from frozen-spec projection"
            ));
        }
    }
    Ok(())
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
        let capture_source = input
            .provider
            .configuration
            .get("runner")
            .and_then(|runner| runner.get("visual"))
            .and_then(|visual| visual.get("captureSource"));
        if capture_source.is_some() {
            let analysis = audit_runtime_visual(input.runtime_visual_capture);
            let gaps = analysis
                .get("coverageGaps")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|gap| {
                    gap.get("kind")
                        .and_then(Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .collect::<Vec<_>>();
            let mut details = BTreeMap::new();
            details.insert("analysis".into(), analysis);
            return super::common::result(
                input,
                ProviderStatus::Partial,
                false,
                &selected,
                selected.entries.len(),
                Vec::new(),
                gaps.clone(),
                gaps,
                details,
            );
        }
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
    let mut details = BTreeMap::new();
    let spec_digest = input
        .provider
        .configuration
        .get("runner")
        .and_then(|runner| runner.get("visual"))
        .and_then(|visual| visual.get("specDigest"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let (findings, evidence, locations, titles, messages) =
        projected_findings(&analysis, spec_digest);
    details.insert("findingEvidence".into(), json!(evidence));
    details.insert("findingLocations".into(), json!(locations));
    details.insert("findingTitles".into(), json!(titles));
    details.insert("findingMessages".into(), json!(messages));
    let complete = analysis.get("complete").and_then(Value::as_bool) == Some(true);
    details.insert("analysis".into(), analysis);
    // A regression verdict is a finding, not completeness: only a fully
    // proven capture matrix (every case covered, every capture compared)
    // reports Complete.
    let status = if complete {
        ProviderStatus::Complete
    } else {
        ProviderStatus::Partial
    };
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
    use image::{DynamicImage, ImageFormat, Rgba, RgbaImage};
    use legion_contracts::{ProviderId, ProviderResult};
    use std::io::Cursor;

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

    fn png(width: u32, height: u32, color: [u8; 4]) -> Vec<u8> {
        let image = RgbaImage::from_pixel(width, height, Rgba(color));
        let mut cursor = Cursor::new(Vec::new());
        DynamicImage::ImageRgba8(image)
            .write_to(&mut cursor, ImageFormat::Png)
            .unwrap();
        cursor.into_inner()
    }

    fn runtime_execution(
        artifact_dir: &Path,
        plan_digest: &str,
        inventory_digest: &str,
        surface_count: usize,
        findings: Vec<legion_contracts::FindingRef>,
    ) -> ProviderExecution {
        let mut surfaces = Vec::new();
        let mut receipts = Vec::new();
        for index in 0..surface_count {
            let (label, url) = if index == 0 {
                ("entry".to_owned(), "https://example.test/".to_owned())
            } else {
                (
                    "settings".to_owned(),
                    "https://example.test/settings".to_owned(),
                )
            };
            let screenshot_path = artifact_dir.join(format!("runtime-shot-{index}.png"));
            let bytes = png(16, 12, [index as u8, 10, 20, 255]);
            std::fs::write(&screenshot_path, &bytes).unwrap();
            let receipt_id = format!("receipt-{index}");
            let request_id = format!(
                "audit:{RUNTIME_PROVIDER_ID}:{plan_digest}:{inventory_digest}:surface-{index}"
            );
            receipts.push(json!({
                "receiptId":receipt_id,
                "requestId":request_id,
                "providerId":RUNTIME_PROVIDER_ID,
                "planId":plan_digest,
                "processTree":{"started":true,"reaped":true},
            }));
            surfaces.push(json!({
                "index":index,
                "label":label,
                "url":url,
                "viewport":{"width":16,"height":12},
                "status":"captured",
                "screenshot":{"path":screenshot_path,"sha256":digest_bytes(&bytes),"bytes":bytes.len()},
                "receiptId":receipt_id,
            }));
        }
        ProviderExecution {
            provider: RUNTIME_PROVIDER_ID.into(),
            skipped: false,
            result: ProviderResult {
                schema_version: 1,
                provider: ProviderId::new(RUNTIME_PROVIDER_ID).unwrap(),
                applicable: true,
                required: false,
                status: ProviderStatus::Partial,
                complete: false,
                coverage: None,
                findings,
                coverage_gaps: vec!["runtime-intentionally-incomplete".into()],
                degradation: Vec::new(),
                details: BTreeMap::from([
                    ("runtime".into(), json!({"surfaces":surfaces})),
                    ("executionReceipts".into(), Value::Array(receipts)),
                ]),
            },
        }
    }

    fn auto_capture(root: &Path, count: usize) -> RuntimeVisualCapture {
        let digest = inventory().digest;
        RuntimeVisualCapture {
            plan_digest: "plan-digest".into(),
            inventory_digest: digest.clone(),
            source_provider_id: RUNTIME_PROVIDER_ID.into(),
            runtime_inputs: json!({
                "url":"https://example.test/",
                "surfaces":[{"label":"settings","url":"https://example.test/settings"}],
                "width":16,
                "height":12,
                "artifactDir":root,
            }),
            prior_execution: Some(runtime_execution(
                root,
                "plan-digest",
                &digest,
                count,
                Vec::new(),
            )),
            artifact_dir: Some(root.to_path_buf()),
            scratch_tmp_dir: None,
        }
    }

    fn scratch_auto_capture(root: &Path, count: usize) -> RuntimeVisualCapture {
        let tmp = root.join("tmp");
        let shots = tmp.join("runtime-123").join("shots");
        std::fs::create_dir_all(&shots).unwrap();
        let digest = inventory().digest;
        RuntimeVisualCapture {
            plan_digest: "plan-digest".into(),
            inventory_digest: digest.clone(),
            source_provider_id: RUNTIME_PROVIDER_ID.into(),
            runtime_inputs: json!({
                "url":"https://example.test/",
                "surfaces":[{"label":"settings","url":"https://example.test/settings"}],
                "width":16,
                "height":12,
            }),
            prior_execution: Some(runtime_execution(
                &shots,
                "plan-digest",
                &digest,
                count,
                Vec::new(),
            )),
            artifact_dir: None,
            scratch_tmp_dir: Some(tmp),
        }
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
        std::fs::write(root.join("shots/home.png"), png(16, 12, [1, 2, 3, 255])).unwrap();
        std::fs::write(root.join("shots/nav.png"), png(16, 12, [4, 5, 6, 255])).unwrap();
        let baselines = scratch("compare-baselines");
        std::fs::write(baselines.join("home.png"), png(16, 12, [1, 2, 3, 255])).unwrap();
        std::fs::write(baselines.join("nav.png"), png(16, 12, [7, 8, 9, 255])).unwrap();

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
        let finding_id = result.findings[0].id.to_string();
        let artifact_evidence = &result.details["findingEvidence"][&finding_id];
        assert_eq!(artifact_evidence["kind"], "visual-artifact-difference");
        assert_eq!(artifact_evidence["captureId"], "nav");
        assert_eq!(artifact_evidence["actual"]["path"], "shots/nav.png");
        assert_eq!(
            artifact_evidence["actual"]["bytes"],
            std::fs::read(root.join("shots/nav.png")).unwrap().len()
        );
        assert_eq!(result.details["findingLocations"][&finding_id], json!([]));
        assert_eq!(
            result.details["findingTitles"][&finding_id],
            "Visual regression in nav"
        );
        let signed_provider = provider(frozen_runner(&two_case_spec(), Some(baselines.as_path())));
        verify_explicit_visual_execution(&root, &signed_provider, "generation", &result)
            .expect("fresh frozen-spec projection verifies");
        let mut removed = result.clone();
        removed.findings.clear();
        assert!(
            verify_explicit_visual_execution(&root, &signed_provider, "generation", &removed,)
                .is_err(),
            "deleted visual finding is detected"
        );
        let mut tampered = result.clone();
        tampered.details["findingEvidence"][&finding_id]["actual"]["digest"] =
            json!(format!("sha256:{}", "0".repeat(64)));
        assert!(
            verify_explicit_visual_execution(&root, &signed_provider, "generation", &tampered,)
                .is_err(),
            "tampered artifact digest is detected"
        );
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
        std::fs::write(root.join("shots/home.png"), png(16, 12, [1, 2, 3, 255])).unwrap();
        let baselines = scratch("drift-baselines");
        std::fs::write(baselines.join("home.png"), png(16, 12, [1, 2, 3, 255])).unwrap();
        let spec = json!({"expected": {"routes": ["/"]}, "captures": [
            {"id": "home", "path": "shots/home.png", "baseline": "home.png"}
        ]});
        let runner = frozen_runner(&spec, Some(baselines.as_path()));
        std::fs::write(baselines.join("home.png"), png(16, 12, [2, 3, 4, 255])).unwrap();

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
        std::fs::write(root.join("shots/home.png"), png(16, 12, [1, 2, 3, 255])).unwrap();
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

    fn auto_runner() -> Value {
        json!({
            "kind":"runtime-script",
            "module":VISUAL_PROVIDER_ID,
            "visual":{"captureSource":{"kind":"runtime-provider","providerId":RUNTIME_PROVIDER_ID}},
        })
    }

    #[test]
    fn zero_finding_partial_runtime_hands_off_every_valid_capture_for_review() {
        let root = scratch("runtime-handoff-zero");
        let capture = auto_capture(&root, 2);
        let result = ProviderExecutorAdapter::new(root.clone())
            .execute_with_runtime_visual_capture(
                &provider(auto_runner()),
                &inventory(),
                Some(&capture),
            )
            .unwrap();

        assert!(result.findings.is_empty());
        assert_eq!(result.status, ProviderStatus::Partial);
        assert!(
            !result.complete,
            "capture alone cannot certify visual review"
        );
        assert_eq!(
            result.details["analysis"]["captures"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            result.details["analysis"]["captures"][0]["status"],
            "captured-no-baseline"
        );
        assert_eq!(
            result.details["analysis"]["captures"][1]["status"],
            "captured-no-baseline"
        );
        assert_eq!(result.details["analysis"]["reviewRequired"], true);
    }

    #[test]
    fn runtime_scratch_capture_path_is_accepted_within_run_owned_tree() {
        let root = scratch("runtime-handoff-scratch");
        let capture = scratch_auto_capture(&root, 2);
        let result = ProviderExecutorAdapter::new(root)
            .execute_with_runtime_visual_capture(
                &provider(auto_runner()),
                &inventory(),
                Some(&capture),
            )
            .unwrap();
        assert_eq!(result.details["analysis"]["coverage"]["capturedCount"], 2);
        assert_eq!(
            result.details["analysis"]["captures"][0]["status"],
            "captured-no-baseline"
        );
    }

    #[test]
    fn missing_runtime_surface_remains_in_expected_visual_denominator() {
        let root = scratch("runtime-handoff-missing");
        let capture = auto_capture(&root, 1);
        let result = ProviderExecutorAdapter::new(root.clone())
            .execute_with_runtime_visual_capture(
                &provider(auto_runner()),
                &inventory(),
                Some(&capture),
            )
            .unwrap();
        let analysis = &result.details["analysis"];
        assert_eq!(analysis["coverage"]["expectedCount"], 2);
        assert_eq!(analysis["coverage"]["capturedCount"], 1);
        assert_eq!(
            analysis["captures"][1]["reason"],
            "runtime-capture-unproven"
        );
        assert!(!result.complete);
    }

    #[test]
    fn wrong_plan_url_receipt_or_screenshot_digest_is_unproven() {
        for tamper in ["plan", "url", "receipt", "digest", "path", "index"] {
            let root = scratch(&format!("runtime-handoff-{tamper}"));
            let mut capture = auto_capture(&root, 2);
            let prior = capture.prior_execution.as_mut().unwrap();
            match tamper {
                "plan" => {
                    prior.result.details["executionReceipts"][0]["planId"] = json!("other-plan")
                }
                "url" => {
                    prior.result.details["runtime"]["surfaces"][0]["url"] =
                        json!("https://evil.test/")
                }
                "receipt" => {
                    prior.result.details["executionReceipts"][0]["requestId"] =
                        json!("wrong-request")
                }
                "digest" => {
                    prior.result.details["runtime"]["surfaces"][0]["screenshot"]["sha256"] =
                        json!("sha256:wrong")
                }
                "path" => {
                    prior.result.details["runtime"]["surfaces"][0]["screenshot"]["path"] =
                        json!("/tmp/outside/runtime-shot-0.png")
                }
                "index" => prior.result.details["runtime"]["surfaces"][0]["index"] = json!(9),
                _ => unreachable!(),
            }
            let result = ProviderExecutorAdapter::new(root.clone())
                .execute_with_runtime_visual_capture(
                    &provider(auto_runner()),
                    &inventory(),
                    Some(&capture),
                )
                .unwrap();
            assert_eq!(
                result.details["analysis"]["captures"][0]["status"], "unproven",
                "tamper={tamper}"
            );
            assert!(!result.complete);
        }
    }

    #[test]
    fn explicit_visual_spec_remains_authoritative_over_runtime_capture() {
        let root = scratch("runtime-handoff-explicit");
        let capture = auto_capture(&root, 2);
        std::fs::write(root.join("actual.png"), png(16, 12, [3, 4, 5, 255])).unwrap();
        std::fs::write(root.join("baseline.png"), png(16, 12, [3, 4, 5, 255])).unwrap();
        let spec = json!({
            "expected":{"cases":[{"route":"/"}]},
            "captures":[{"id":"explicit","path":"actual.png","baseline":"baseline.png","route":"/"}],
        });
        let mut runner = frozen_runner(&spec, None);
        runner["visual"]["captureSource"] =
            json!({"kind":"runtime-provider","providerId":RUNTIME_PROVIDER_ID});
        let result = ProviderExecutorAdapter::new(root)
            .execute_with_runtime_visual_capture(&provider(runner), &inventory(), Some(&capture))
            .unwrap();

        assert_eq!(
            result.details["analysis"]["captures"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(result.details["analysis"]["captures"][0]["id"], "explicit");
        assert!(result.complete);
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
