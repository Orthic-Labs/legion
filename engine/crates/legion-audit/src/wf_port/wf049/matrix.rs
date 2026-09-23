//! Port of `src/providers/runtime/web/matrix/index.mjs`
//! (`isWebMatrixCombinationId`, `compileWebMatrix`).
//!
//! Like `journey_plan.rs`, the backing registry
//! (`src/registry/platform-matrices/web.json`) is embedded with
//! `include_str!` rather than read at runtime, mirroring the JS module's
//! `readFileSync(new URL(..., import.meta.url))` at import time.

use serde_json::{Map, Value};
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use super::shared::{denominator, exact_binding, finalize, same_binding, sort_by_id};

const REGISTRY_JSON: &str = include_str!("../../../../../../src/registry/platform-matrices/web.json");

struct Registry {
    data: Value,
    dimensions: Vec<String>,
    browsers: HashMap<String, Value>,
    vitals_classes: HashMap<String, Value>,
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let data: Value = serde_json::from_str(REGISTRY_JSON).expect("registry/platform-matrices/web.json must be valid JSON");
        let dimensions: Vec<String> = data
            .get("dimensions")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).map(str::to_string).collect())
            .unwrap_or_default();
        let browsers: HashMap<String, Value> = data
            .get("browserPolicy")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.get("id").and_then(Value::as_str).map(|id| (id.to_string(), item.clone())))
                    .collect()
            })
            .unwrap_or_default();
        let mut vitals_classes: HashMap<String, Value> = HashMap::new();
        if let Some(map) = data.get("vitalsDenominators").and_then(Value::as_object) {
            for (device_class, value) in map {
                if !value.is_object() {
                    continue;
                }
                let Some(ids) = value.get("combinationIds").and_then(Value::as_array) else { continue };
                for id in ids.iter().filter_map(Value::as_str) {
                    let mut entry = value.as_object().cloned().unwrap_or_default();
                    entry.insert("deviceClass".to_string(), Value::String(device_class.clone()));
                    vitals_classes.insert(id.to_string(), Value::Object(entry));
                }
            }
        }
        Registry { data, dimensions, browsers, vitals_classes }
    })
}

fn dimension_values(dimension: &str) -> Vec<Value> {
    registry()
        .data
        .get("dimensionValues")
        .and_then(|v| v.get(dimension))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn allowed(dimension: &str, value: &Value) -> bool {
    dimension_values(dimension).iter().any(|candidate| candidate == value)
}

fn vector(row: &Value) -> String {
    let values: Vec<Value> = registry().dimensions.iter().map(|dim| row.get(dim).cloned().unwrap_or(Value::Null)).collect();
    serde_json::to_string(&Value::Array(values)).unwrap_or_default()
}

fn covers(row: &Value, requirement: &[(String, Value)]) -> bool {
    requirement.iter().all(|(key, value)| row.get(key) == Some(value))
}

struct Plan {
    rows: Vec<Value>,
    uncovered: Vec<Vec<(String, Value)>>,
}

fn registry_plan() -> &'static Plan {
    static PLAN: OnceLock<Plan> = OnceLock::new();
    PLAN.get_or_init(build_registry_plan)
}

fn build_registry_plan() -> Plan {
    let reg = registry();
    let mandatory: Vec<Value> = reg
        .data
        .get("mandatoryCombinations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let pairs: Vec<(String, String)> = reg
        .data
        .get("pairwisePolicy")
        .and_then(|p| p.get("pairs"))
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|pair| {
                    let arr = pair.as_array()?;
                    Some((arr.first()?.as_str()?.to_string(), arr.get(1)?.as_str()?.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    let max_combinations = reg
        .data
        .get("pairwisePolicy")
        .and_then(|p| p.get("maxCombinations"))
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX) as usize;

    let mut requirements: Vec<Vec<(String, Value)>> = Vec::new();
    for (left, right) in &pairs {
        for left_value in dimension_values(left) {
            for right_value in dimension_values(right) {
                requirements.push(vec![(left.clone(), left_value.clone()), (right.clone(), right_value.clone())]);
            }
        }
    }

    let witness = |requirement: &[(String, Value)]| -> Value {
        let mut row = mandatory.first().and_then(Value::as_object).cloned().unwrap_or_default();
        for (key, value) in requirement {
            row.insert(key.clone(), value.clone());
        }
        row.remove("id");
        let browser_id = row.get("browser").and_then(Value::as_str).unwrap_or_default().to_string();
        if let Some(browser) = reg.browsers.get(&browser_id) {
            if let Some(version) = browser.get("versions").and_then(Value::as_array).and_then(|v| v.first()) {
                row.insert("browserVersion".to_string(), version.clone());
            }
            if let Some(binary) = browser.get("binaryPolicy") {
                row.insert("binary".to_string(), binary.clone());
            }
        }
        let mut out = Map::new();
        for dim in &reg.dimensions {
            out.insert(dim.clone(), row.get(dim).cloned().unwrap_or(Value::Null));
        }
        Value::Object(out)
    };

    let mandatory_vectors: HashSet<String> = mandatory.iter().map(vector).collect();
    let mut candidate_map: HashMap<String, Value> = HashMap::new();
    for requirement in &requirements {
        let row = witness(requirement);
        let vec_key = vector(&row);
        if mandatory_vectors.contains(&vec_key) {
            continue;
        }
        candidate_map.entry(vec_key).or_insert(row);
    }
    let mut candidates: Vec<Value> = candidate_map.into_values().collect();
    candidates.sort_by(|a, b| vector(a).cmp(&vector(b)));

    let mut selected: Vec<Value> = mandatory.clone();
    let mut uncovered: Vec<Vec<(String, Value)>> =
        requirements.into_iter().filter(|requirement| !selected.iter().any(|row| covers(row, requirement))).collect();
    let mut pool: Vec<Value> = candidates;

    while !uncovered.is_empty() && selected.len() < max_combinations {
        let mut ranked: Vec<(usize, &Value)> = pool
            .iter()
            .map(|row| (uncovered.iter().filter(|requirement| covers(row, requirement)).count(), row))
            .collect();
        ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| vector(a.1).cmp(&vector(b.1))));
        let Some((score, best)) = ranked.first().copied() else { break };
        if score == 0 {
            break;
        }
        let best = best.clone();
        uncovered.retain(|requirement| !covers(&best, requirement));
        pool.retain(|row| row != &best);
        selected.push(best);
    }

    let mut generated: Vec<Value> = selected.iter().filter(|row| row.get("id").is_none()).cloned().collect();
    generated.sort_by(|a, b| vector(a).cmp(&vector(b)));
    let generated: Vec<Value> = generated
        .into_iter()
        .enumerate()
        .map(|(index, row)| {
            let mut out = Map::new();
            out.insert("id".to_string(), Value::String(format!("pairwise-{:03}", index + 1)));
            if let Some(map) = row.as_object() {
                for (k, v) in map {
                    out.insert(k.clone(), v.clone());
                }
            }
            Value::Object(out)
        })
        .collect();

    let mut rows = mandatory;
    rows.extend(generated);
    Plan { rows: sort_by_id(&rows), uncovered }
}

/// Port of `isWebMatrixCombinationId`.
pub fn is_web_matrix_combination_id(id: &str) -> bool {
    registry_plan().rows.iter().any(|row| row.get("id").and_then(Value::as_str) == Some(id))
}

fn valid_policy_shape(policy: &Value) -> bool {
    let Some(_) = policy.as_object() else { return false };
    let dims = &registry().dimensions;
    if let Some(mandatory_dimensions) = policy.get("mandatoryDimensions") {
        if mandatory_dimensions.is_null() {
            // undefined in JS is skipped; explicit null fails the object check below.
        }
        let Some(map) = mandatory_dimensions.as_object() else { return false };
        for (dimension, values) in map {
            if !dims.contains(dimension) {
                return false;
            }
            let Some(values) = values.as_array() else { return false };
            for value in values {
                let ok = match value {
                    Value::Null => false,
                    Value::String(_) | Value::Bool(_) => true,
                    Value::Number(n) => n.as_f64().map(f64::is_finite).unwrap_or(false),
                    _ => false,
                };
                if !ok {
                    return false;
                }
            }
        }
    }
    if let Some(pairwise) = policy.get("pairwise") {
        let Some(pairs) = pairwise.as_array() else { return false };
        for pair in pairs {
            let Some(arr) = pair.as_array() else { return false };
            if arr.len() != 2 {
                return false;
            }
            for dimension in arr {
                match dimension.as_str() {
                    Some(d) if dims.contains(&d.to_string()) => {}
                    _ => return false,
                }
            }
        }
    }
    true
}

fn typed_scalar(value: &Value) -> bool {
    match value {
        Value::String(_) | Value::Bool(_) => true,
        Value::Number(n) => n.as_f64().map(f64::is_finite).unwrap_or(false),
        _ => false,
    }
}

fn typed_policy_item(item: &Value, omitted: bool) -> bool {
    let Some(_) = item.as_object() else { return false };
    let id_ok = matches!(item.get("id"), Some(Value::String(id)) if !id.is_empty());
    if !id_ok {
        return false;
    }
    if omitted {
        let reason_ok = item.get("reason").map(|r| r.is_string()).unwrap_or(true);
        let evidence_ok = match item.get("evidence") {
            None => true,
            Some(e) => e.is_object(),
        };
        reason_ok && evidence_ok
    } else {
        let status_ok = item.get("status").map(|s| s.is_string()).unwrap_or(true);
        let terminal_ok = item.get("terminal").map(|t| t.is_boolean()).unwrap_or(true);
        let binding_ok = match item.get("binding") {
            None => true,
            Some(b) => b.is_object(),
        };
        let vitals_ok = match item.get("vitals") {
            None => true,
            Some(v) => v.is_object(),
        };
        let dims_ok = registry().dimensions.iter().all(|dim| match item.get(dim) {
            None => true,
            Some(v) => typed_scalar(v),
        });
        status_ok && terminal_ok && binding_ok && vitals_ok && dims_ok
    }
}

/// Port of `compileWebMatrix`.
pub fn compile_web_matrix(binding: Value, policy: Value, capabilities: Vec<Value>) -> Value {
    let dims = registry().dimensions.clone();
    let policy_valid = valid_policy_shape(&policy);
    let capabilities_ok = capabilities.iter().all(|item| item.is_object());
    let combinations_ok = policy.get("combinations").map_or(true, |c| {
        c.as_array().map(|items| items.iter().all(|item| typed_policy_item(item, false))).unwrap_or(false)
    });
    let omitted_ok = policy.get("omitted").map_or(true, |c| {
        c.as_array().map(|items| items.iter().all(|item| typed_policy_item(item, true))).unwrap_or(false)
    });
    let collections_valid = policy_valid && capabilities_ok && combinations_ok && omitted_ok;

    if !collections_valid {
        let mut gaps: Vec<String> = exact_binding(&binding).gaps.iter().map(|g| format!("binding-missing:{g}")).collect();
        if !policy_valid {
            gaps.push("matrix-policy-invalid".to_string());
        }
        gaps.push("matrix-collections-invalid".to_string());
        gaps.sort();
        return finalize(
            "legion-web-runtime-matrix",
            serde_json::json!({
                "binding": binding,
                "terminal": true,
                "complete": false,
                "status": "error",
                "combinations": [],
                "omitted": [],
                "denominator": denominator(&[], &[], &[]).to_value(),
                "vitalsDenominators": {},
                "vitalsByDeviceClass": {},
                "coverageGaps": gaps,
            }),
        );
    }

    let plan = registry_plan();
    let supplied = sort_by_id(&policy.get("combinations").and_then(Value::as_array).cloned().unwrap_or_default());
    let omitted = sort_by_id(&policy.get("omitted").and_then(Value::as_array).cloned().unwrap_or_default());

    let mut supplied_groups: HashMap<String, Vec<&Value>> = HashMap::new();
    for item in &supplied {
        let id = item.get("id").and_then(Value::as_str).unwrap_or("").to_string();
        supplied_groups.entry(id).or_default().push(item);
    }
    let planned_by_id: HashMap<String, &Value> =
        plan.rows.iter().filter_map(|item| item.get("id").and_then(Value::as_str).map(|id| (id.to_string(), item))).collect();

    let capability_ids: Vec<String> = capabilities.iter().filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string)).collect();
    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut duplicate_capability_ids: Vec<String> = Vec::new();
    for id in &capability_ids {
        if !seen_ids.insert(id.clone()) {
            duplicate_capability_ids.push(id.clone());
        }
    }
    duplicate_capability_ids.sort();
    duplicate_capability_ids.dedup();
    let capability_by_id: Option<HashMap<String, &Value>> = if duplicate_capability_ids.is_empty() {
        Some(capabilities.iter().filter_map(|item| item.get("id").and_then(Value::as_str).map(|id| (id.to_string(), item))).collect())
    } else {
        None
    };

    let combinations: Vec<Value> = sort_by_id(
        &plan
            .rows
            .iter()
            .map(|definition| {
                let id = definition.get("id").and_then(Value::as_str).unwrap_or("");
                let observation = supplied_groups.get(id).and_then(|group| group.first()).copied();
                let mut out = definition.as_object().cloned().unwrap_or_default();
                out.insert(
                    "status".to_string(),
                    observation.and_then(|o| o.get("status")).cloned().unwrap_or(Value::String("unproven".to_string())),
                );
                out.insert(
                    "terminal".to_string(),
                    Value::Bool(observation.and_then(|o| o.get("terminal")) == Some(&Value::Bool(true))),
                );
                out.insert("observed".to_string(), Value::Bool(observation.is_some()));
                if let Some(o) = observation {
                    if let Some(map) = o.as_object() {
                        if map.contains_key("deviceClass") {
                            out.insert("deviceClass".to_string(), map["deviceClass"].clone());
                        }
                        if map.contains_key("vitals") {
                            out.insert("vitals".to_string(), map["vitals"].clone());
                        }
                    }
                }
                Value::Object(out)
            })
            .collect::<Vec<Value>>(),
    );

    let ids: Vec<String> = combinations.iter().filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string)).collect();
    let receipts: Vec<Value> = combinations
        .iter()
        .filter(|item| {
            let observed = item.get("observed") == Some(&Value::Bool(true));
            let terminal = item.get("terminal") == Some(&Value::Bool(true));
            if !observed || !terminal {
                return false;
            }
            let status = item.get("status").and_then(Value::as_str).unwrap_or("");
            let browser_id = item.get("browser").and_then(Value::as_str).unwrap_or("");
            let capability_status = capability_by_id
                .as_ref()
                .and_then(|map| map.get(browser_id))
                .and_then(|cap| cap.get("status"))
                .and_then(Value::as_str);
            (status == "pass" && capability_status == Some("available")) || (status == "unsupported" && capability_status == Some("unsupported"))
        })
        .cloned()
        .collect();
    let base_counts = denominator(&ids, &receipts, &[]);
    let mut counts = base_counts.to_value();
    let omitted_id_set: HashSet<String> = omitted.iter().filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string)).collect();
    if let Value::Object(map) = &mut counts {
        map.insert("omitted".to_string(), Value::from(omitted_id_set.len()));
    }

    let mut gaps: Vec<String> = exact_binding(&binding).gaps.iter().map(|g| format!("binding-missing:{g}")).collect();
    if plan.rows.is_empty() {
        gaps.push("matrix-denominator-empty".to_string());
    }
    gaps.extend(duplicate_capability_ids.iter().map(|id| format!("capability-id-duplicate:{id}")));
    if supplied.is_empty() && omitted.is_empty() {
        gaps.push("matrix-denominator-empty".to_string());
    }
    if !plan.uncovered.is_empty() {
        gaps.push("registry-pairwise-bound-incomplete".to_string());
    }
    let registry_max = registry()
        .data
        .get("pairwisePolicy")
        .and_then(|p| p.get("maxCombinations"))
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX) as usize;
    let policy_max = policy.get("maxCombinations").and_then(Value::as_u64).map(|v| v as usize).unwrap_or(registry_max);
    if plan.rows.len() > registry_max || plan.rows.len() > policy_max {
        gaps.push("matrix-bound-exceeded".to_string());
    }

    let caller_ids: Vec<String> = supplied
        .iter()
        .chain(omitted.iter())
        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
        .collect();
    let mut seen_caller_ids: HashSet<String> = HashSet::new();
    let mut duplicate_caller_ids: Vec<String> = Vec::new();
    for id in &caller_ids {
        if caller_ids.iter().filter(|x| *x == id).count() > 1 && seen_caller_ids.insert(id.clone()) {
            duplicate_caller_ids.push(id.clone());
        }
    }
    gaps.extend(duplicate_caller_ids.iter().map(|id| format!("matrix-id-duplicate:{id}")));
    for item in supplied.iter().chain(omitted.iter()) {
        if item.get("id").and_then(Value::as_str).map(str::len).unwrap_or(0) == 0 {
            gaps.push("matrix-id-missing".to_string());
        }
    }
    for capability in &capabilities {
        if !same_binding(&binding, capability.get("binding").unwrap_or(&Value::Null)) {
            gaps.push(format!("capability-binding-mismatch:{}", capability.get("id").and_then(Value::as_str).unwrap_or("")));
        }
    }
    for dimension in &dims {
        if let Some(mandatory_dimensions) = policy.get("mandatoryDimensions") {
            let has_values = mandatory_dimensions.get(dimension).and_then(Value::as_array).map(|v| !v.is_empty()).unwrap_or(false);
            if !has_values {
                gaps.push(format!("dimension-missing:{dimension}"));
            }
            for value in mandatory_dimensions.get(dimension).and_then(Value::as_array).into_iter().flatten() {
                if !allowed(dimension, value) {
                    gaps.push(format!("dimension-policy-value-outside-registry:{dimension}"));
                }
            }
        }
    }
    if policy.get("mandatoryDimensions").is_some()
        && policy.get("pairwise").and_then(Value::as_array).map(|v| !v.is_empty()).unwrap_or(false) == false
    {
        gaps.push("pairwise-policy-missing".to_string());
    }

    const TERMINAL: &[&str] = &["pass", "fail", "partial", "unproven", "blocked", "error", "unsupported"];
    for item in &supplied {
        let id = item.get("id").and_then(Value::as_str).unwrap_or("");
        let definition = planned_by_id.get(id).copied();
        if !same_binding(&binding, item.get("binding").unwrap_or(&Value::Null)) {
            gaps.push(format!("observation-binding-mismatch:{id}"));
        }
        if definition.is_none() {
            gaps.push(format!("combination-unplanned:{id}"));
        }
        if item.get("terminal") != Some(&Value::Bool(true)) {
            gaps.push(format!("combination-nonterminal:{id}"));
        }
        let status = item.get("status").and_then(Value::as_str);
        if status == Some("pending") {
            gaps.push(format!("combination-status-pending:{id}"));
        } else if !status.map(|s| TERMINAL.contains(&s)).unwrap_or(false) {
            gaps.push(format!("combination-status-invalid:{id}"));
        } else if !matches!(status, Some("pass") | Some("unsupported")) {
            gaps.push(format!("combination-status-{}:{id}", status.unwrap_or("")));
        }
        for dimension in &dims {
            if item.get(dimension).is_none() {
                gaps.push(format!("observation-dimension-missing:{id}:{dimension}"));
                continue;
            }
            let value = item.get(dimension).unwrap();
            if !allowed(dimension, value) {
                gaps.push(format!("dimension-value-outside-registry:{id}:{dimension}"));
            }
            if let Some(mandatory_values) = policy.get("mandatoryDimensions").and_then(|m| m.get(dimension)).and_then(Value::as_array) {
                if !mandatory_values.is_empty() && !mandatory_values.iter().any(|v| v == value) {
                    gaps.push(format!("dimension-value-outside-policy:{id}:{dimension}"));
                }
            }
            if let Some(def) = definition {
                if def.get(dimension) != Some(value) {
                    gaps.push(format!("observation-definition-mismatch:{id}:{dimension}"));
                }
            }
        }
        let browser_id = item
            .get("browser")
            .and_then(Value::as_str)
            .or_else(|| definition.and_then(|d| d.get("browser")).and_then(Value::as_str))
            .unwrap_or("")
            .to_string();
        let browser = registry().browsers.get(&browser_id);
        let version = item.get("browserVersion").cloned().or_else(|| definition.and_then(|d| d.get("browserVersion")).cloned());
        let binary = item.get("binary").cloned().or_else(|| definition.and_then(|d| d.get("binary")).cloned());
        let capability = capability_by_id.as_ref().and_then(|map| map.get(&browser_id)).copied();
        if browser.is_none() {
            gaps.push(format!("browser-outside-policy:{id}"));
        } else {
            let browser = browser.unwrap();
            let versions_ok = browser.get("versions").and_then(Value::as_array).map(|v| version.as_ref().map(|ver| v.contains(ver)).unwrap_or(false)).unwrap_or(false);
            if !versions_ok {
                gaps.push(format!("browser-version-outside-policy:{id}"));
            }
            if binary.as_ref() != browser.get("binaryPolicy") {
                gaps.push(format!("browser-binary-outside-policy:{id}"));
            }
        }
        if capability.is_none() {
            gaps.push(format!("browser-capability-missing:{browser_id}"));
        } else {
            let capability = capability.unwrap();
            let cap_status = capability.get("status").and_then(Value::as_str);
            if !matches!(cap_status, Some("available") | Some("unsupported")) {
                gaps.push(format!("browser-capability-{}:{browser_id}", cap_status.unwrap_or("")));
            }
            if cap_status == Some("unsupported") && status != Some("unsupported") {
                gaps.push(format!("browser-capability-unsupported-but-{}:{browser_id}:{id}", status.unwrap_or("")));
            }
            if status == Some("unsupported") && cap_status != Some("unsupported") {
                gaps.push(format!("combination-unsupported-without-policy:{id}"));
            }
            if capability.get("browserVersion") != version.as_ref() {
                gaps.push(format!("browser-capability-version-mismatch:{id}"));
            }
            if capability.get("binary") != binary.as_ref() {
                gaps.push(format!("browser-capability-binary-mismatch:{id}"));
            }
        }
    }

    if let Some(pairwise) = policy.get("pairwise").and_then(Value::as_array) {
        for pair in pairwise {
            let Some(arr) = pair.as_array() else { continue };
            let (Some(left), Some(right)) = (arr.first().and_then(Value::as_str), arr.get(1).and_then(Value::as_str)) else { continue };
            let left_values = policy.get("mandatoryDimensions").and_then(|m| m.get(left)).and_then(Value::as_array).cloned().unwrap_or_default();
            let right_values = policy.get("mandatoryDimensions").and_then(|m| m.get(right)).and_then(Value::as_array).cloned().unwrap_or_default();
            for left_value in &left_values {
                for right_value in &right_values {
                    let covered = supplied.iter().any(|item| item.get(left) == Some(left_value) && item.get(right) == Some(right_value));
                    if !covered {
                        gaps.push(format!("pairwise-uncovered:{left}={left_value}:{right}={right_value}"));
                    }
                }
            }
        }
    }

    gaps.extend(omitted.iter().map(|item| format!("combination-omitted:{}", item.get("id").and_then(Value::as_str).unwrap_or(""))));
    gaps.extend(
        supplied
            .iter()
            .filter(|item| !planned_by_id.contains_key(item.get("id").and_then(Value::as_str).unwrap_or("")))
            .map(|item| format!("combination-unplanned:{}", item.get("id").and_then(Value::as_str).unwrap_or(""))),
    );
    gaps.extend(base_counts.missing.iter().map(|id| format!("combination-missing:{id}")));

    let mut vitals_by_device_class: HashMap<String, Vec<Value>> = HashMap::new();
    let mut vitals_classes_sorted: Vec<(&String, &Value)> = registry().vitals_classes.iter().collect();
    vitals_classes_sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (id, denominator_policy) in vitals_classes_sorted {
        let definition = planned_by_id.get(id).copied();
        let observation = supplied_groups.get(id).and_then(|group| group.first()).copied();
        let vitals = observation.and_then(|o| o.get("vitals"));
        if observation.is_none() || vitals.map(|v| !v.is_object()).unwrap_or(true) {
            gaps.push(format!("vitals-observation-missing:{id}"));
        } else {
            let observation = observation.unwrap();
            let vitals = vitals.unwrap();
            if !same_binding(&binding, vitals.get("binding").unwrap_or(&Value::Null)) {
                gaps.push(format!("vitals-binding-mismatch:{id}"));
            }
            let device_mismatch = observation.get("device").is_some() && observation.get("device") != definition.and_then(|d| d.get("device"));
            let physicality_mismatch = observation.get("physicality").is_some() && observation.get("physicality") != definition.and_then(|d| d.get("physicality"));
            if device_mismatch || physicality_mismatch {
                gaps.push(format!("vitals-trusted-classification-mismatch:{id}"));
            }
            if let Some(device_class) = observation.get("deviceClass") {
                if device_class != denominator_policy.get("deviceClass").unwrap_or(&Value::Null) {
                    gaps.push(format!("vitals-device-class-mismatch:{id}"));
                }
            }
            if let Some(required_metrics) = denominator_policy.get("requiredMetrics").and_then(Value::as_array) {
                for metric in required_metrics.iter().filter_map(Value::as_str) {
                    match vitals.get(metric) {
                        None => gaps.push(format!("vitals-metric-missing:{id}:{metric}")),
                        Some(value) => {
                            let ok = value.as_f64().map(|n| n.is_finite() && n >= 0.0).unwrap_or(false);
                            if !ok {
                                gaps.push(format!("vitals-metric-invalid:{id}:{metric}"));
                            }
                        }
                    }
                }
            }
            let denominator_id = denominator_policy.get("id").cloned().unwrap_or(Value::Null);
            vitals_by_device_class
                .entry(denominator_policy.get("deviceClass").and_then(Value::as_str).unwrap_or("").to_string())
                .or_default()
                .push(serde_json::json!({ "id": id, "denominatorId": denominator_id, "vitals": vitals.clone() }));
        }
    }
    for item in supplied.iter().filter(|row| row.get("vitals").is_some() && !registry().vitals_classes.contains_key(row.get("id").and_then(Value::as_str).unwrap_or(""))) {
        gaps.push(format!("vitals-denominator-id-untrusted:{}", item.get("id").and_then(Value::as_str).unwrap_or("")));
    }

    let vitals_denominators: Map<String, Value> = registry()
        .data
        .get("vitalsDenominators")
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter(|(_, value)| value.is_object())
                .map(|(device_class, value)| {
                    let mut observed_ids: Vec<String> = vitals_by_device_class
                        .get(device_class)
                        .into_iter()
                        .flatten()
                        .filter_map(|item| item.get("id").and_then(Value::as_str).map(str::to_string))
                        .collect();
                    observed_ids.sort();
                    let expected_ids: Vec<Value> = value.get("combinationIds").and_then(Value::as_array).cloned().unwrap_or_default();
                    let missing_ids: Vec<Value> = expected_ids
                        .iter()
                        .filter(|id| !observed_ids.iter().any(|o| Some(o.as_str()) == id.as_str()))
                        .cloned()
                        .collect();
                    (
                        device_class.clone(),
                        serde_json::json!({
                            "id": value.get("id").cloned().unwrap_or(Value::Null),
                            "expectedIds": expected_ids,
                            "observedIds": observed_ids,
                            "missingIds": missing_ids,
                        }),
                    )
                })
                .collect()
        })
        .unwrap_or_default();

    let terminal_statuses: Vec<&str> = supplied
        .iter()
        .filter(|item| item.get("terminal") == Some(&Value::Bool(true)))
        .filter_map(|item| item.get("status").and_then(Value::as_str))
        .collect();
    let worst_status = ["error", "fail", "blocked", "partial", "unproven"].iter().find(|s| terminal_statuses.contains(s));

    let mut gaps_sorted = gaps;
    gaps_sorted.sort();
    gaps_sorted.dedup();
    let complete = gaps_sorted.is_empty();

    let vitals_by_device_class_value: Map<String, Value> = vitals_by_device_class.into_iter().map(|(k, v)| (k, Value::Array(v))).collect();

    finalize(
        "legion-web-runtime-matrix",
        serde_json::json!({
            "binding": binding,
            "registryPolicyId": registry().data.get("id").cloned().unwrap_or(Value::Null),
            "terminal": true,
            "combinations": combinations,
            "omitted": omitted,
            "denominator": counts,
            "vitalsDenominators": Value::Object(vitals_denominators),
            "vitalsByDeviceClass": Value::Object(vitals_by_device_class_value),
            "complete": complete,
            "status": worst_status.map(|s| s.to_string()).unwrap_or_else(|| if !complete { "partial".to_string() } else { "pass".to_string() }),
            "coverageGaps": gaps_sorted,
        }),
    )
}
