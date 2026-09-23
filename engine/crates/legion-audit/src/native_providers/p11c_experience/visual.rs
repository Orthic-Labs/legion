//! Port of `src/providers/visual/{color,geometry,geometry-tokens,capture,
//! diff,hierarchy-static,motion,responsive,reviewer,stacking,tokens,
//! typography}.mjs` plus the `src/lib/design/{geometry,baselines}.mjs`
//! helpers they depend on.

use super::visual_core::{decode_png, sha256_digest};
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashSet};

fn arr<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value.get(key).and_then(Value::as_array).map(|items| items.iter().collect()).unwrap_or_default()
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) | Some(Value::Bool(false)) => false,
        Some(Value::Bool(true)) => true,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|n| n != 0.0),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(_)) => true,
    }
}

fn finite(value: Option<&Value>) -> Option<f64> {
    value.and_then(Value::as_f64).filter(|n| n.is_finite())
}

// ---------------------------------------------------------------------
// lib/design/geometry.mjs
// ---------------------------------------------------------------------

pub fn normalize_geometry(elements: &[Value]) -> Vec<Value> {
    fn round3(value: Option<f64>) -> Value {
        match value {
            Some(v) if v.is_finite() => serde_json::json!((v * 1000.0).round() / 1000.0),
            _ => Value::Null,
        }
    }
    elements
        .iter()
        .map(|item| {
            let mut object = item.as_object().cloned().unwrap_or_default();
            for key in ["x", "y", "width", "height", "scrollWidth", "scrollHeight"] {
                let rounded = round3(item.get(key).and_then(Value::as_f64));
                if item.get(key).is_some() {
                    object.insert(key.to_string(), rounded);
                }
            }
            Value::Object(object)
        })
        .collect()
}

fn get_f64(value: &Value, key: &str) -> f64 {
    value.get(key).and_then(Value::as_f64).unwrap_or(0.0)
}

pub fn intersect_bounds(left: &Value, right: &Value) -> Option<Value> {
    let x = get_f64(left, "x").max(get_f64(right, "x"));
    let y = get_f64(left, "y").max(get_f64(right, "y"));
    let width = (get_f64(left, "x") + get_f64(left, "width")).min(get_f64(right, "x") + get_f64(right, "width")) - x;
    let height = (get_f64(left, "y") + get_f64(left, "height")).min(get_f64(right, "y") + get_f64(right, "height")) - y;
    if width > 0.0 && height > 0.0 {
        Some(serde_json::json!({ "x": x, "y": y, "width": width, "height": height, "area": width * height }))
    } else {
        None
    }
}

// ---------------------------------------------------------------------
// lib/design/baselines.mjs
// ---------------------------------------------------------------------

const IDENTITY_KEYS: [&str; 6] = ["route", "state", "viewport", "platform", "browserPolicy", "baselineId"];

pub fn baseline_identity(value: &Value) -> String {
    let mut identity = Map::new();
    for key in IDENTITY_KEYS {
        identity.insert(key.to_string(), value.get(key).cloned().unwrap_or(Value::Null));
    }
    sha256_digest(serde_json::to_string(&Value::Object(identity)).unwrap_or_default().as_bytes())
}

pub fn baseline_compatibility(baseline: &Value, actual: &Value) -> Value {
    let mismatches: Vec<Value> = IDENTITY_KEYS
        .iter()
        .filter(|key| baseline.get(**key) != actual.get(**key))
        .map(|key| Value::String((*key).to_string()))
        .collect();
    serde_json::json!({ "compatible": mismatches.is_empty(), "mismatches": mismatches })
}

// ---------------------------------------------------------------------
// visual/color.mjs
// ---------------------------------------------------------------------

fn is_hex_color(value: Option<&str>) -> bool {
    let Some(value) = value else { return false };
    if value.len() != 7 || !value.starts_with('#') {
        return false;
    }
    value[1..].bytes().all(|b| b.is_ascii_hexdigit())
}

fn channel(hex: &str) -> f64 {
    u32::from_str_radix(hex, 16).unwrap_or(0) as f64 / 255.0
}

fn luminance(hex: &str) -> f64 {
    let components = [&hex[1..3], &hex[3..5], &hex[5..7]];
    let mut total = 0.0;
    let weights = [0.2126, 0.7152, 0.0722];
    for (component, weight) in components.iter().zip(weights.iter()) {
        let v = channel(component);
        let v = if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) };
        total += weight * v;
    }
    total
}

pub fn contrast_ratio(foreground: &str, background: &str) -> f64 {
    let a = luminance(foreground);
    let b = luminance(background);
    (a.max(b) + 0.05) / (a.min(b) + 0.05)
}

pub fn analyze_color_pairs(pairs: &[Value]) -> Value {
    let resolved = pairs
        .iter()
        .filter(|pair| is_hex_color(pair.get("foreground").and_then(Value::as_str)) && is_hex_color(pair.get("background").and_then(Value::as_str)))
        .count();
    let findings: Vec<Value> = pairs
        .iter()
        .filter(|pair| is_hex_color(pair.get("foreground").and_then(Value::as_str)) && is_hex_color(pair.get("background").and_then(Value::as_str)))
        .filter_map(|pair| {
            let fg = pair.get("foreground").and_then(Value::as_str)?;
            let bg = pair.get("background").and_then(Value::as_str)?;
            let ratio = contrast_ratio(fg, bg);
            let minimum = pair.get("minimum").and_then(Value::as_f64).unwrap_or(4.5);
            if ratio < minimum {
                let mut object = pair.as_object().cloned().unwrap_or_default();
                object.insert("ratio".into(), serde_json::json!(ratio));
                Some(Value::Object(object))
            } else {
                None
            }
        })
        .collect();
    let coverage_gaps: Vec<Value> = pairs
        .iter()
        .filter(|pair| !is_hex_color(pair.get("foreground").and_then(Value::as_str)) || !is_hex_color(pair.get("background").and_then(Value::as_str)))
        .map(|_| Value::String("color-pair-unresolved".into()))
        .collect();
    let status = if !findings.is_empty() { "candidates" } else if !coverage_gaps.is_empty() { "unproven" } else { "pass" };
    serde_json::json!({
        "provider": "visual.color", "status": status,
        "complete": !pairs.is_empty() && coverage_gaps.is_empty(),
        "denominator": { "kind": "color-pairs", "expected": pairs.len(), "examined": resolved },
        "findings": findings, "coverageGaps": coverage_gaps,
    })
}

// ---------------------------------------------------------------------
// visual/geometry-tokens.mjs
// ---------------------------------------------------------------------

fn observed_scale(instances: &[Value]) -> Vec<Value> {
    let mut counts: Vec<(Value, u32)> = Vec::new();
    for item in instances {
        let value = item.get("value").cloned().unwrap_or(Value::Null);
        if let Some(entry) = counts.iter_mut().find(|(v, _)| *v == value) {
            entry.1 += 1;
        } else {
            counts.push((value, 1));
        }
    }
    counts.into_iter().filter(|(_, count)| *count > 1).map(|(value, _)| value).collect()
}

fn instance_key(item: &Value) -> String {
    format!(
        "{}:{}:{}",
        item.get("component").and_then(Value::as_str).unwrap_or_default(),
        item.get("property").and_then(Value::as_str).unwrap_or_default(),
        item.get("value").map(|v| v.to_string()).unwrap_or_default(),
    )
}

pub fn analyze_geometry_tokens(input: &Value) -> Value {
    let instances: Vec<Value> = arr(input, "instances").into_iter().cloned().collect();
    let declared_scale: Vec<Value> = arr(input, "declaredScale").into_iter().cloned().collect();
    let exceptions: Vec<Value> = arr(input, "exceptions").into_iter().cloned().collect();
    let scale = if !declared_scale.is_empty() { declared_scale.clone() } else { observed_scale(&instances) };
    let excepted: HashSet<String> = exceptions.iter().map(instance_key).collect();
    let affected: Vec<&Value> = instances
        .iter()
        .filter(|item| {
            let value = item.get("value").cloned().unwrap_or(Value::Null);
            !scale.is_empty() && !scale.contains(&value) && !excepted.contains(&instance_key(item))
        })
        .collect();
    let scale_source = if !declared_scale.is_empty() { "declared" } else { "observed-candidate" };
    let mut candidates: Vec<Value> = affected
        .iter()
        .map(|item| {
            let property = item.get("property").cloned().unwrap_or(Value::Null);
            let denominator = instances.iter().filter(|candidate| candidate.get("property") == Some(&property)).count();
            serde_json::json!({
                "ruleId": "visual.geometry-token-off-scale",
                "value": item.get("value").cloned().unwrap_or(Value::Null),
                "property": property,
                "denominator": denominator,
                "affectedInstances": [item],
                "evidenceClass": if truthy(item.get("rendered")) { "source+rendered" } else { "source-only" },
                "scaleSource": scale_source,
            })
        })
        .collect();
    let flags = [
        ("nestedRadiusConflict", "visual.geometry-nested-radius"),
        ("inconsistentPadding", "visual.geometry-padding-drift"),
        ("misalignedBaseline", "visual.geometry-baseline-misalignment"),
        ("ambiguousElevation", "visual.geometry-elevation-order"),
    ];
    for item in &instances {
        for (flag, rule_id) in flags {
            if truthy(item.get(flag)) {
                let property = item.get("property").cloned().unwrap_or(Value::Null);
                let denominator = instances.iter().filter(|candidate| candidate.get("property") == Some(&property)).count();
                candidates.push(serde_json::json!({
                    "ruleId": rule_id,
                    "value": item.get("value").cloned().unwrap_or(Value::Null),
                    "property": property,
                    "denominator": denominator,
                    "affectedInstances": [item],
                    "evidenceClass": if truthy(item.get("rendered")) { "source+rendered" } else { "source-only" },
                    "scaleSource": scale_source,
                }));
            }
        }
    }
    let status = if !candidates.is_empty() { "candidates" } else if !scale.is_empty() { "pass" } else { "unproven" };
    serde_json::json!({
        "provider": "visual.geometry-tokens", "status": status, "complete": !scale.is_empty(),
        "denominator": instances.len(), "scale": scale, "inventedStandard": false, "candidates": candidates,
        "coverageGaps": if scale.is_empty() { vec![Value::String("declared-or-clustered-scale-missing".into())] } else { vec![] },
    })
}

// ---------------------------------------------------------------------
// visual/geometry.mjs
// ---------------------------------------------------------------------

pub fn analyze_geometry_evidence(input: &Value) -> Value {
    let surface_id = input.get("surfaceId").cloned().unwrap_or(Value::Null);
    let viewport = input.get("viewport").cloned().unwrap_or(Value::Null);
    let elements: Vec<Value> = arr(input, "elements").into_iter().cloned().collect();
    let tolerances = input.get("tolerances").cloned().unwrap_or(Value::Object(Map::new()));
    let intentional_overlaps: Vec<Value> = arr(input, "intentionalOverlaps").into_iter().cloned().collect();

    let mut findings: Vec<Value> = Vec::new();
    let mut coverage_gaps: Vec<Value> = Vec::new();
    let intentional: HashSet<String> = intentional_overlaps
        .iter()
        .map(|pair| {
            let mut items: Vec<String> = pair.as_array().unwrap_or(&vec![]).iter().map(|v| v.as_str().unwrap_or_default().to_string()).collect();
            items.sort();
            items.join(":")
        })
        .collect();
    let measurable: Vec<&Value> = elements.iter().filter(|item| !truthy(item.get("primitive"))).collect();
    if elements.is_empty() {
        coverage_gaps.push(Value::String("geometry-elements-missing".into()));
    }
    let overflow_tolerance = tolerances.get("overflow").and_then(Value::as_f64).unwrap_or(0.0);
    let minimum_touch = tolerances.get("minimumTouchTarget").and_then(Value::as_f64).unwrap_or(24.0);
    let layout_shift_tolerance = tolerances.get("layoutShift").and_then(Value::as_f64).unwrap_or(0.0);
    let viewport_width = get_f64(&viewport, "width");
    let viewport_height = get_f64(&viewport, "height");

    for element in &elements {
        let element_id = element.get("id").cloned().unwrap_or(Value::Null);
        let source_component = element.get("sourceComponent").cloned().unwrap_or(Value::Null);
        if let Some(primitive) = element.get("primitive").and_then(Value::as_str) {
            if ["canvas", "webgl", "cross-origin"].contains(&primitive) {
                coverage_gaps.push(Value::String(format!("unsupported-geometry:{}:{}", element_id.as_str().unwrap_or_default(), primitive)));
            }
        }
        let (Some(x), Some(width)) = (finite(element.get("x")), finite(element.get("width"))) else { continue };
        let y = get_f64(element, "y");
        let height = get_f64(element, "height");
        let overflow_right = (x + width - viewport_width - overflow_tolerance).max(0.0);
        let overflow_bottom = (y + height - viewport_height - overflow_tolerance).max(0.0);
        if overflow_right > 0.0 || overflow_bottom > 0.0 {
            findings.push(serde_json::json!({ "ruleId": "visual.geometry-viewport-overflow", "surfaceId": surface_id, "elementId": element_id, "measurement": { "overflowRight": overflow_right, "overflowBottom": overflow_bottom }, "sourceComponent": source_component }));
        }
        if truthy(element.get("clippedText")) {
            findings.push(serde_json::json!({ "ruleId": "visual.geometry-clipped-text", "surfaceId": surface_id, "elementId": element_id, "measurement": { "bounds": { "x": x, "y": y, "width": width, "height": height } }, "sourceComponent": source_component }));
        }
        if truthy(element.get("focusable")) && (overflow_right > 0.0 || overflow_bottom > 0.0 || x < 0.0 || y < 0.0) {
            findings.push(serde_json::json!({ "ruleId": "visual.geometry-offscreen-focus", "surfaceId": surface_id, "elementId": element_id, "measurement": { "x": x, "y": y, "overflowRight": overflow_right, "overflowBottom": overflow_bottom }, "sourceComponent": source_component }));
        }
        if truthy(element.get("touchTarget")) && (width < minimum_touch || height < minimum_touch) {
            findings.push(serde_json::json!({ "ruleId": "visual.geometry-touch-target", "surfaceId": surface_id, "elementId": element_id, "measurement": { "width": width, "height": height, "minimum": minimum_touch }, "sourceComponent": source_component }));
        }
        if let Some(layout_shift) = finite(element.get("layoutShift")) {
            if layout_shift > layout_shift_tolerance {
                findings.push(serde_json::json!({ "ruleId": "visual.geometry-layout-shift", "surfaceId": surface_id, "elementId": element_id, "measurement": { "layoutShift": layout_shift, "tolerance": layout_shift_tolerance }, "sourceComponent": source_component }));
            }
        }
    }
    for region in arr(&tolerances, "protectedRegions") {
        for element in measurable.iter().filter(|item| truthy(item.get("fixed"))) {
            if let Some(overlap) = intersect_bounds(region, element) {
                findings.push(serde_json::json!({ "ruleId": "visual.geometry-protected-region", "surfaceId": surface_id, "elementId": element.get("id").cloned().unwrap_or(Value::Null), "regionId": region.get("id").cloned().unwrap_or(Value::Null), "measurement": overlap }));
            }
        }
    }
    for left in 0..measurable.len() {
        for right in (left + 1)..measurable.len() {
            let a = measurable[left];
            let b = measurable[right];
            if let Some(overlap) = intersect_bounds(a, b) {
                let mut ids = vec![a.get("id").and_then(Value::as_str).unwrap_or_default().to_string(), b.get("id").and_then(Value::as_str).unwrap_or_default().to_string()];
                ids.sort();
                let key = ids.join(":");
                if !intentional.contains(&key) && (truthy(a.get("control")) || truthy(b.get("control"))) {
                    findings.push(serde_json::json!({ "ruleId": "visual.geometry-control-overlap", "surfaceId": surface_id, "elementIds": [a.get("id").cloned().unwrap_or(Value::Null), b.get("id").cloned().unwrap_or(Value::Null)], "measurement": overlap }));
                }
            }
        }
    }
    let examined = elements.iter().filter(|item| finite(item.get("x")).is_some() && finite(item.get("width")).is_some()).count();
    let status = if !findings.is_empty() { "candidates" } else if !coverage_gaps.is_empty() { "unproven" } else { "pass" };
    serde_json::json!({
        "provider": "visual.geometry", "status": status, "complete": !elements.is_empty(),
        "denominator": { "kind": "geometry-elements", "expected": elements.len(), "examined": examined },
        "findings": findings, "coverageGaps": coverage_gaps, "tolerances": tolerances,
    })
}

// ---------------------------------------------------------------------
// visual/capture.mjs
// ---------------------------------------------------------------------

fn redact(value: &Value, sensitive_values: &[Value]) -> Value {
    let mut output = value.as_str().map(str::to_string).unwrap_or_else(|| if value.is_null() { String::new() } else { value.to_string() });
    for secret in sensitive_values.iter().filter(|v| truthy(Some(*v))) {
        let secret = secret.as_str().map(str::to_string).unwrap_or_else(|| secret.to_string());
        output = output.replace(&secret, "[REDACTED]");
    }
    Value::String(output)
}

pub fn capture_visual_evidence(input: &Value, screenshot_bytes: &[u8]) -> Result<Value, String> {
    if input.get("surfaceId").is_none() || screenshot_bytes.is_empty() || input.get("browser").is_none() || input.get("viewport").is_none() || input.get("binding").is_none() {
        return Err("surface, screenshot, browser, viewport, and binding are required".to_string());
    }
    let decoded = decode_png(screenshot_bytes)?;
    let sensitive_values: Vec<Value> = arr(input, "sensitiveValues").into_iter().cloned().collect();
    let dom = redact(&input.get("dom").cloned().unwrap_or(Value::Null), &sensitive_values);
    let geometry: Vec<Value> = arr(input, "geometry").into_iter().cloned().collect();
    let normalized_geometry = normalize_geometry(&geometry);
    let raw = serde_json::json!({
        "dom": dom,
        "styles": input.get("styles").cloned().unwrap_or(Value::Object(Map::new())),
        "geometry": geometry,
        "stacking": input.get("stacking").cloned().unwrap_or(Value::Array(vec![])),
        "scrollExtents": input.get("scrollExtents").cloned().unwrap_or(Value::Null),
    });
    let normalized = serde_json::json!({
        "dom": dom,
        "styles": raw.get("styles").cloned().unwrap_or(Value::Null),
        "geometry": normalized_geometry,
        "stacking": raw.get("stacking").cloned().unwrap_or(Value::Null),
        "scrollExtents": raw.get("scrollExtents").cloned().unwrap_or(Value::Null),
    });
    Ok(serde_json::json!({
        "schemaVersion": 1, "kind": "legion-visual-evidence",
        "surfaceId": input.get("surfaceId").cloned().unwrap_or(Value::Null),
        "screenshot": {
            "path": input.get("screenshotPath").cloned().unwrap_or(Value::Null),
            "digest": sha256_digest(screenshot_bytes),
            "bytes": screenshot_bytes.len(),
            "width": decoded.width, "height": decoded.height,
        },
        "browser": input.get("browser").cloned().unwrap_or(Value::Null),
        "route": input.get("route").cloned().unwrap_or(Value::Null),
        "viewport": input.get("viewport").cloned().unwrap_or(Value::Null),
        "state": input.get("state").and_then(Value::as_str).unwrap_or("default"),
        "locale": input.get("locale").cloned().unwrap_or(Value::Null),
        "direction": input.get("direction").cloned().unwrap_or(Value::Null),
        "tokenDigest": input.get("tokenDigest").cloned().unwrap_or(Value::Null),
        "baselineDigest": input.get("baselineDigest").cloned().unwrap_or(Value::Null),
        "accessibilityRef": input.get("accessibilityRef").cloned().unwrap_or(Value::Null),
        "contentItemIds": input.get("contentItemIds").cloned().unwrap_or(Value::Array(vec![])),
        "raw": raw, "normalized": normalized,
        "binding": input.get("binding").cloned().unwrap_or(Value::Null),
    }))
}

// ---------------------------------------------------------------------
// visual/diff.mjs
// ---------------------------------------------------------------------

fn unproven_diff(gaps: Vec<&str>) -> Value {
    serde_json::json!({
        "provider": "visual.diff", "status": "unproven", "baselineAccepted": false,
        "denominator": { "kind": "baseline-comparisons", "expected": 1, "examined": 0 },
        "coverageGaps": gaps, "components": {},
    })
}

pub fn compare_visual_evidence(input: &Value) -> Value {
    let baseline = input.get("baseline").filter(|v| !v.is_null());
    let Some(baseline) = baseline else { return unproven_diff(vec!["baseline-missing"]) };
    if truthy(baseline.get("stale")) {
        return unproven_diff(vec!["baseline-stale"]);
    }
    let actual = input.get("actual").cloned().unwrap_or(Value::Object(Map::new()));
    let compatibility = baseline_compatibility(baseline, &actual);
    if compatibility.get("compatible") != Some(&Value::Bool(true)) {
        let gaps: Vec<Value> = compatibility.get("mismatches").and_then(Value::as_array).cloned().unwrap_or_default().into_iter().map(|m| Value::String(format!("environment-mismatch:{}", m.as_str().unwrap_or_default()))).collect();
        return serde_json::json!({ "provider": "visual.diff", "status": "unproven", "baselineAccepted": false, "denominator": { "kind": "baseline-comparisons", "expected": 1, "examined": 0 }, "coverageGaps": gaps, "components": {} });
    }
    let approved_masks: HashSet<String> = arr(baseline, "approvedMasks").into_iter().filter_map(|m| m.get("id").and_then(Value::as_str)).map(str::to_string).collect();
    let masks: Vec<Value> = arr(input, "masks").into_iter().cloned().collect();
    let unapproved: Vec<&Value> = masks.iter().filter(|m| m.get("id").and_then(Value::as_str).map(|id| !approved_masks.contains(id)).unwrap_or(true)).collect();
    if !unapproved.is_empty() {
        return unproven_diff(vec!["dynamic-mask-unapproved"]);
    }
    let pixel = input.get("pixel").cloned().unwrap_or(Value::Null);
    let perceptual = input.get("perceptual").cloned().unwrap_or(Value::Null);
    let geometry = input.get("geometry").cloned().unwrap_or(Value::Null);
    let text = input.get("text").cloned().unwrap_or(Value::Null);
    let components = serde_json::json!({ "pixel": pixel, "perceptual": perceptual, "geometry": geometry, "text": text });
    let has_any = [&pixel, &perceptual, &geometry, &text].iter().any(|c| !c.is_null());
    if !has_any {
        return serde_json::json!({ "provider": "visual.diff", "status": "unproven", "baselineAccepted": false, "baselineIdentity": baseline_identity(baseline), "masks": masks, "components": {}, "denominator": { "kind": "baseline-comparisons", "expected": 1, "examined": 0 }, "coverageGaps": ["comparison-components-missing"] });
    }
    let changed = [&pixel, &perceptual, &geometry, &text].iter().any(|component| {
        !component.is_null()
            && (component.get("changed").and_then(Value::as_f64).unwrap_or(0.0) > 0.0
                || component.get("changedPixels").and_then(Value::as_f64).unwrap_or(0.0) > 0.0
                || component.get("status") == Some(&Value::String("changed".into())))
    });
    serde_json::json!({
        "provider": "visual.diff", "status": if changed { "candidates" } else { "pass" }, "baselineAccepted": false,
        "baselineIdentity": baseline_identity(baseline), "masks": masks, "components": components,
        "denominator": { "kind": "baseline-comparisons", "expected": 1, "examined": 1 }, "coverageGaps": [],
    })
}

// ---------------------------------------------------------------------
// visual/hierarchy-static.mjs
// ---------------------------------------------------------------------

pub fn analyze_hierarchy(input: &Value) -> Value {
    let signals: Vec<Value> = arr(input, "signals").into_iter().cloned().collect();
    let rendered_evidence = input.get("renderedEvidence").filter(|v| !v.is_null());
    let coverage_gaps: Vec<Value> = if signals.is_empty() { vec![Value::String("hierarchy-signals-missing".into())] } else { vec![] };
    let mut findings: Vec<Value> = signals
        .iter()
        .filter(|item| {
            let sr = finite(item.get("semanticRank"));
            let vr = finite(item.get("visualRank"));
            sr.is_some() && vr.is_some() && sr != vr
        })
        .map(|item| serde_json::json!({
            "ruleId": "visual.hierarchy-rank-mismatch",
            "component": item.get("component").cloned().unwrap_or(Value::Null),
            "source": item.get("source").cloned().unwrap_or(Value::Null),
            "semanticRank": item.get("semanticRank").cloned().unwrap_or(Value::Null),
            "visualRank": item.get("visualRank").cloned().unwrap_or(Value::Null),
            "judgmentClass": "deterministic",
        }))
        .collect();
    let primaries: Vec<&Value> = signals.iter().filter(|item| truthy(item.get("strongPrimary"))).collect();
    let mut candidates: Vec<Value> = primaries
        .iter()
        .map(|item| serde_json::json!({
            "ruleId": if primaries.len() > 1 { "visual.hierarchy-competing-primary" } else { "visual.hierarchy-primary-review" },
            "component": item.get("component").cloned().unwrap_or(Value::Null),
            "source": item.get("source").cloned().unwrap_or(Value::Null),
            "copyItemId": item.get("copyItemId").cloned().unwrap_or(Value::Null),
            "judgmentClass": "interpretive",
            "evidenceLimitation": if rendered_evidence.is_some() { Value::Null } else { Value::String("rendered-evidence-missing".into()) },
        }))
        .collect();
    if signals.iter().any(|item| truthy(item.get("requiresPrimary"))) && primaries.is_empty() {
        if let Some(item) = signals.iter().find(|item| truthy(item.get("requiresPrimary"))) {
            findings.push(serde_json::json!({ "ruleId": "visual.hierarchy-primary-missing", "component": item.get("component").cloned().unwrap_or(Value::Null), "source": item.get("source").cloned().unwrap_or(Value::Null), "judgmentClass": "deterministic" }));
        }
    }
    for item in signals.iter().filter(|entry| truthy(entry.get("hiddenDestructive")) || truthy(entry.get("repeatedStrongEmphasis"))) {
        candidates.push(serde_json::json!({
            "ruleId": if truthy(item.get("hiddenDestructive")) { "visual.hierarchy-hidden-destructive" } else { "visual.hierarchy-repeated-emphasis" },
            "component": item.get("component").cloned().unwrap_or(Value::Null),
            "source": item.get("source").cloned().unwrap_or(Value::Null),
            "copyItemId": item.get("copyItemId").cloned().unwrap_or(Value::Null),
            "judgmentClass": "interpretive",
            "evidenceLimitation": if rendered_evidence.is_some() { Value::Null } else { Value::String("rendered-evidence-missing".into()) },
        }));
    }
    let status = if !findings.is_empty() || !candidates.is_empty() { "candidates" } else if !coverage_gaps.is_empty() { "unproven" } else { "pass" };
    let review_required = !candidates.is_empty();
    serde_json::json!({
        "provider": "visual.hierarchy-static", "status": status, "complete": !signals.is_empty(),
        "denominator": { "kind": "hierarchy-signals", "expected": signals.len(), "examined": signals.len() },
        "findings": findings, "candidates": candidates, "coverageGaps": coverage_gaps, "reviewRequired": review_required,
    })
}

// ---------------------------------------------------------------------
// visual/motion.mjs
// ---------------------------------------------------------------------

pub fn analyze_motion(input: &Value) -> Value {
    let transitions: Vec<Value> = arr(input, "transitions").into_iter().cloned().collect();
    let reduced_motion_exercised = truthy(input.get("reducedMotionExercised"));
    let mut findings: Vec<Value> = Vec::new();
    for transition in &transitions {
        let id = transition.get("id").cloned().unwrap_or(Value::Null);
        let from = transition.get("from").cloned().unwrap_or(Value::Null);
        let to = transition.get("to").cloned().unwrap_or(Value::Null);
        let duration = transition.get("durationMs").cloned().unwrap_or(Value::Null);
        if truthy(transition.get("blocksInteraction")) || truthy(transition.get("obscuresState")) {
            findings.push(serde_json::json!({ "ruleId": "visual.motion-blocking", "transitionId": id, "from": from, "to": to, "timing": { "durationMs": duration }, "evidenceClass": if truthy(transition.get("frameEvidence")) { "runtime-frames" } else { "runtime-timing" } }));
        }
        if let (Some(budget), Some(actual)) = (finite(transition.get("budgetMs")), finite(transition.get("durationMs"))) {
            if actual > budget {
                findings.push(serde_json::json!({ "ruleId": "visual.motion-budget", "transitionId": id, "from": from, "to": to, "timing": { "durationMs": duration, "budgetMs": budget }, "performanceLink": true }));
            }
        }
        if truthy(transition.get("layoutShift")) {
            findings.push(serde_json::json!({ "ruleId": "visual.motion-layout-shift", "transitionId": id, "from": from, "to": to, "timing": { "durationMs": duration }, "performanceLink": true }));
        }
    }
    let coverage_gaps: Vec<Value> = if reduced_motion_exercised { vec![] } else { vec![Value::String("reduced-motion-unproven".into())] };
    let status = if !findings.is_empty() { "candidates" } else if !coverage_gaps.is_empty() { "unproven" } else { "pass" };
    serde_json::json!({
        "provider": "visual.motion", "status": status, "complete": !transitions.is_empty() && reduced_motion_exercised,
        "denominator": { "kind": "motion-transitions", "expected": transitions.len(), "examined": transitions.len() },
        "findings": findings, "coverageGaps": coverage_gaps, "decorativeRecommendations": [],
    })
}

// ---------------------------------------------------------------------
// visual/responsive.mjs
// ---------------------------------------------------------------------

pub fn analyze_responsive(input: &Value) -> Value {
    let surfaces: Vec<Value> = arr(input, "surfaces").into_iter().cloned().collect();
    let required_viewports: Vec<Value> = arr(input, "requiredViewports").into_iter().cloned().collect();
    let tested: HashSet<String> = surfaces.iter().filter_map(|s| s.get("viewport").and_then(Value::as_str)).map(str::to_string).collect();
    let mut coverage_gaps: Vec<Value> = required_viewports
        .iter()
        .filter(|v| v.as_str().map(|v| !tested.contains(v)).unwrap_or(true))
        .map(|v| Value::String(format!("viewport-untested:{}", v.as_str().unwrap_or_default())))
        .collect();
    if surfaces.is_empty() {
        coverage_gaps.push(Value::String("responsive-surfaces-missing".into()));
    }
    let mut findings: Vec<Value> = Vec::new();
    let conditions = [
        ("overflowX", "visual.responsive-horizontal-overflow"),
        ("clipped", "visual.responsive-clipped-content"),
        ("offscreenControl", "visual.responsive-offscreen-control"),
        ("fixedChromeOverlap", "visual.responsive-fixed-overlap"),
        ("unsafeProtectedRegion", "visual.responsive-protected-region"),
        ("missingMobileAlternative", "visual.responsive-mobile-alternative-missing"),
    ];
    for surface in &surfaces {
        if surface.get("safeAreaMeasured") != Some(&Value::Bool(true)) {
            coverage_gaps.push(Value::String(format!("safe-area-unmeasured:{}:{}", surface.get("id").and_then(Value::as_str).unwrap_or_default(), surface.get("viewport").and_then(Value::as_str).unwrap_or_default())));
        }
        for (condition, rule_id) in conditions {
            if truthy(surface.get(condition)) {
                findings.push(serde_json::json!({
                    "ruleId": rule_id, "surfaceId": surface.get("id").cloned().unwrap_or(Value::Null),
                    "viewport": surface.get("viewport").cloned().unwrap_or(Value::Null),
                    "state": surface.get("state").and_then(Value::as_str).unwrap_or("default"),
                    "evidenceClass": if truthy(surface.get("geometry")) { "rendered" } else { "source-heuristic" },
                }));
            }
        }
    }
    let status = if !findings.is_empty() { "candidates" } else if !coverage_gaps.is_empty() { "unproven" } else { "pass" };
    serde_json::json!({
        "provider": "visual.responsive", "status": status, "complete": !surfaces.is_empty() && coverage_gaps.is_empty(),
        "denominator": { "kind": "responsive-surfaces", "expected": surfaces.len().max(required_viewports.len()), "examined": surfaces.len() },
        "findings": findings, "coverageGaps": coverage_gaps, "testedViewports": tested.into_iter().collect::<Vec<_>>(),
    })
}

// ---------------------------------------------------------------------
// visual/reviewer.mjs
// ---------------------------------------------------------------------

fn digest_value(value: &Value) -> String {
    sha256_digest(serde_json::to_string(value).unwrap_or_default().as_bytes())
}

pub fn build_review_packet(input: &Value) -> Value {
    let state_group = input.get("stateGroup").filter(|v| !v.is_null());
    let mut packet = serde_json::json!({
        "schemaVersion": 1, "kind": "legion-visual-review-packet",
        "scope": if state_group.is_some() { "state-group" } else { "surface" },
        "surfaceId": input.get("surfaceId").cloned().unwrap_or(Value::Null),
        "stateGroup": state_group.cloned().unwrap_or(Value::Null),
        "screenshots": input.get("screenshots").cloned().unwrap_or(Value::Array(vec![])),
        "route": input.get("route").cloned().unwrap_or(Value::Null),
        "state": input.get("state").cloned().unwrap_or(Value::Null),
        "viewport": input.get("viewport").cloned().unwrap_or(Value::Null),
        "designContext": input.get("designContext").cloned().unwrap_or(Value::Null),
        "geometry": input.get("geometry").cloned().unwrap_or(Value::Null),
        "accessibility": input.get("accessibility").cloned().unwrap_or(Value::Null),
        "copyItemIds": input.get("copyItemIds").cloned().unwrap_or(Value::Array(vec![])),
        "baselineResults": input.get("baselineResults").cloned().unwrap_or(Value::Null),
        "omittedEvidence": input.get("omittedEvidence").cloned().unwrap_or(Value::Array(vec![])),
    });
    let digest = digest_value(&packet);
    packet.as_object_mut().unwrap().insert("digest".into(), Value::String(digest));
    packet
}

pub fn validate_judgment_receipt(packet: &Value, input: &Value) -> Value {
    let reviewer = input.get("reviewer").cloned().unwrap_or(Value::Object(Map::new()));
    let renderer_identity = input.get("rendererIdentity").cloned().unwrap_or(Value::Null);
    let implementer_identity = input.get("implementerIdentity").cloned().unwrap_or(Value::Null);
    let independent = reviewer.get("fresh") == Some(&Value::Bool(true))
        && truthy(reviewer.get("provider"))
        && reviewer.get("provider") != Some(&renderer_identity)
        && reviewer.get("provider") != Some(&implementer_identity)
        && truthy(reviewer.get("contextId"));
    let evidence_refs: Vec<Value> = arr(input, "evidenceRefs").into_iter().cloned().collect();
    let screenshots: Vec<Value> = arr(packet, "screenshots").into_iter().cloned().collect();
    let packet_digest = packet.get("digest").cloned().unwrap_or(Value::Null);
    let evidence_valid = evidence_refs.iter().all(|reference| screenshots.contains(reference) || *reference == packet_digest);
    let uncertainty = input.get("uncertainty").and_then(Value::as_array).cloned();
    let valid = independent && evidence_valid && truthy(input.get("counterargument")) && uncertainty.is_some();
    let claim_limits: Vec<Value> = if truthy(packet.get("designContext")) { vec![] } else { vec![Value::String("brand-context-missing".into())] };
    let mut receipt = serde_json::json!({
        "schemaVersion": 1, "kind": "legion-judgment-receipt", "family": "visual",
        "subjectId": packet.get("surfaceId").cloned().unwrap_or(Value::Null),
        "candidateId": packet_digest,
        "reviewer": reviewer,
        "evidenceRefs": evidence_refs,
        "omittedEvidence": packet.get("omittedEvidence").cloned().unwrap_or(Value::Array(vec![])),
        "verdict": input.get("verdict").and_then(Value::as_str).unwrap_or("UNPROVEN"),
        "rationaleClaims": input.get("rationaleClaims").cloned().unwrap_or(Value::Array(vec![])),
        "counterargument": input.get("counterargument").cloned().unwrap_or(Value::Null),
        "uncertainty": uncertainty.clone().unwrap_or_default(),
        "claimLimits": claim_limits,
        "policyEffect": input.get("policyEffect").and_then(Value::as_str).unwrap_or("advisory"),
        "binding": input.get("binding").cloned().unwrap_or(Value::Object(Map::new())),
    });
    let digest = digest_value(&receipt);
    receipt.as_object_mut().unwrap().insert("digest".into(), Value::String(digest));
    let mut errors: Vec<Value> = Vec::new();
    if !independent { errors.push(Value::String("reviewer-not-independent-or-fresh".into())); }
    if !evidence_valid { errors.push(Value::String("evidence-reference-invalid".into())); }
    if !truthy(input.get("counterargument")) { errors.push(Value::String("counterargument-missing".into())); }
    serde_json::json!({ "valid": valid, "errors": errors, "receipt": receipt })
}

// ---------------------------------------------------------------------
// visual/stacking.mjs
// ---------------------------------------------------------------------

pub fn analyze_stacking(input: &Value) -> Value {
    let contexts: Vec<Value> = arr(input, "contexts").into_iter().cloned().collect();
    let mut findings: Vec<Value> = Vec::new();
    let coverage_gaps: Vec<Value> = if contexts.is_empty() { vec![Value::String("stacking-contexts-missing".into())] } else { vec![] };
    for context in &contexts {
        let chain: Vec<f64> = arr(context, "zIndexChain").into_iter().filter_map(Value::as_f64).collect();
        if chain.iter().enumerate().skip(1).any(|(i, value)| (value - chain[i - 1]).abs() > 1000.0) {
            findings.push(serde_json::json!({ "ruleId": "visual.stacking-fragile-chain", "contextId": context.get("id").cloned().unwrap_or(Value::Null), "chain": context.get("zIndexChain").cloned().unwrap_or(Value::Array(vec![])) }));
        }
        if truthy(context.get("overlap")) {
            findings.push(serde_json::json!({ "ruleId": "visual.stacking-overlap", "contextId": context.get("id").cloned().unwrap_or(Value::Null), "elements": context.get("overlap").cloned().unwrap_or(Value::Null) }));
        }
    }
    let status = if !findings.is_empty() { "candidates" } else if !coverage_gaps.is_empty() { "unproven" } else { "pass" };
    serde_json::json!({
        "provider": "visual.stacking", "status": status, "complete": !contexts.is_empty(),
        "denominator": { "kind": "stacking-contexts", "expected": contexts.len(), "examined": contexts.len() },
        "findings": findings, "coverageGaps": coverage_gaps,
    })
}

// ---------------------------------------------------------------------
// visual/tokens.mjs
// ---------------------------------------------------------------------

pub fn inventory_tokens(input: &Value) -> Value {
    let token_re = Regex::new(r"--([\w-]+)\s*:\s*([^;]+);").unwrap();
    let files: Vec<Value> = arr(input, "files").into_iter().cloned().collect();
    let mut tokens: Vec<Value> = Vec::new();
    let mut seen: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for file in &files {
        let text = file.get("text").and_then(Value::as_str).unwrap_or_default();
        let path = file.get("path").cloned().unwrap_or(Value::Null);
        for capture in token_re.captures_iter(text) {
            let name = capture[1].to_string();
            let value = capture[2].trim().to_string();
            tokens.push(serde_json::json!({ "name": name, "value": value, "file": path }));
            let key = format!("{name}\0{value}");
            seen.entry(key).or_default().push(path.clone());
        }
    }
    let candidates: Vec<Value> = seen
        .into_iter()
        .filter(|(_, paths)| paths.len() > 1)
        .map(|(key, paths)| serde_json::json!({ "ruleId": "visual.token-duplicate", "key": key, "paths": paths }))
        .collect();
    let gaps: Vec<Value> = if files.is_empty() { vec![Value::String("token-files-missing".into())] } else { vec![] };
    let status = if !candidates.is_empty() { "candidates" } else if !gaps.is_empty() { "unproven" } else { "pass" };
    serde_json::json!({
        "schemaVersion": 1, "provider": "visual.tokens", "status": status, "complete": gaps.is_empty(),
        "denominator": { "kind": "css-token-files", "expected": files.len(), "examined": files.len() },
        "tokens": tokens, "candidates": candidates, "coverageGaps": gaps,
    })
}

// ---------------------------------------------------------------------
// visual/typography.mjs
// ---------------------------------------------------------------------

pub fn analyze_typography(input: &Value) -> Value {
    let text_items: Vec<Value> = arr(input, "textItems").into_iter().cloned().collect();
    let font_evidence = input.get("fontEvidence").filter(|v| !v.is_null());
    let mut findings: Vec<Value> = Vec::new();
    for item in &text_items {
        let context = serde_json::json!({
            "role": item.get("role").and_then(Value::as_str).unwrap_or("unknown"),
            "surfaceId": item.get("surfaceId").cloned().unwrap_or(Value::Null),
            "viewport": item.get("viewport").cloned().unwrap_or(Value::Null),
            "locale": item.get("locale").cloned().unwrap_or(Value::Null),
        });
        let id = item.get("id").cloned().unwrap_or(Value::Null);
        let copy_item_id = item.get("copyItemId").cloned().unwrap_or(Value::Null);
        if truthy(item.get("clipped")) || truthy(item.get("overflow")) || truthy(item.get("truncatedUnexpectedly")) {
            findings.push(serde_json::json!({ "ruleId": "visual.typography-text-layout", "itemId": id, "context": context, "copyItemId": copy_item_id, "evidence": item.get("evidence").cloned().unwrap_or(Value::Null) }));
        }
        if truthy(item.get("fauxHierarchy")) || truthy(item.get("semanticRankMismatch")) {
            findings.push(serde_json::json!({ "ruleId": "visual.typography-role-mismatch", "itemId": id, "context": context, "copyItemId": copy_item_id }));
        }
        if truthy(item.get("lineLengthExceeded")) || truthy(item.get("localeBreakage")) || truthy(item.get("wrappingFailure")) {
            findings.push(serde_json::json!({ "ruleId": "visual.typography-readability", "itemId": id, "context": context, "copyItemId": copy_item_id }));
        }
        if truthy(item.get("fontFlash")) || truthy(item.get("missingFallback")) {
            findings.push(serde_json::json!({ "ruleId": "visual.typography-font-loading", "itemId": id, "context": context, "copyItemId": copy_item_id }));
        }
    }
    let mut coverage_gaps: Vec<Value> = Vec::new();
    if font_evidence.is_none() {
        coverage_gaps.push(Value::String("font-evidence-missing".into()));
    }
    for item in text_items.iter().filter(|entry| !truthy(entry.get("viewport")) || !truthy(entry.get("locale"))) {
        coverage_gaps.push(Value::String(format!("render-context-incomplete:{}", item.get("id").and_then(Value::as_str).unwrap_or_default())));
    }
    let status = if !findings.is_empty() { "candidates" } else if !coverage_gaps.is_empty() { "unproven" } else { "pass" };
    serde_json::json!({
        "provider": "visual.typography", "status": status, "complete": coverage_gaps.is_empty(),
        "denominator": { "kind": "typography-text-items", "expected": text_items.len(), "examined": text_items.len() },
        "findings": findings, "coverageGaps": coverage_gaps,
    })
}
