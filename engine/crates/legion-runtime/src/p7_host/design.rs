//! Port of src/lib/design/{baselines,brand-context,context,geometry,
//! runtime-spec,skill-compiler,surfaces,ux-flow}.mjs.

use super::{sha256_hex, sha256_prefixed};
use regex::Regex;
use serde_json::{json, Value};
use std::sync::LazyLock;

// ---- baselines.mjs ----

const IDENTITY_KEYS: [&str; 6] = ["route", "state", "viewport", "platform", "browserPolicy", "baselineId"];

pub fn baseline_identity(value: &Value) -> String {
    let mut identity = serde_json::Map::new();
    for key in IDENTITY_KEYS {
        identity.insert(key.to_string(), value.get(key).cloned().unwrap_or(Value::Null));
    }
    sha256_hex(serde_json::to_string(&identity).unwrap_or_default().as_bytes())
}

pub fn baseline_compatibility(baseline: &Value, actual: &Value) -> Value {
    let mismatches: Vec<Value> = IDENTITY_KEYS
        .iter()
        .filter(|key| {
            baseline.get(*key).unwrap_or(&Value::Null) != actual.get(*key).unwrap_or(&Value::Null)
        })
        .map(|key| json!(key))
        .collect();
    json!({"compatible": mismatches.is_empty(), "mismatches": mismatches})
}

// ---- brand-context.mjs ----

pub fn brand_context(design_context: &Value) -> Value {
    let brand = design_context.get("declared").and_then(|d| d.get("brand"));
    let has_brand = brand.is_some_and(|b| !b.is_null());
    json!({
        "schemaVersion": 1,
        "kind": "legion-brand-context",
        "values": brand.cloned().unwrap_or(json!({})),
        "source": design_context.get("source").cloned().unwrap_or(Value::Null),
        "authoritative": has_brand,
        "status": if has_brand { "pass" } else { "unproven" },
    })
}

// ---- context.mjs ----

pub fn create_design_context(source: Option<&str>, declared: &Value, inferred: &Value, binding: &Value) -> Value {
    let declared_len = declared.as_object().map(|o| o.len()).unwrap_or(0);
    let digest = sha256_prefixed("", &json!({"declared": declared, "binding": binding}));
    json!({
        "schemaVersion": 1,
        "kind": "legion-design-context",
        "source": source,
        "declared": declared,
        "inferred": inferred,
        "binding": binding,
        "status": if declared_len > 0 { "pass" } else { "unproven" },
        "coverageGaps": if declared_len > 0 { json!([]) } else { json!(["brand-context-missing"]) },
        "digest": digest,
    })
}

// ---- geometry.mjs ----

#[derive(Debug, Clone, Copy, Default)]
pub struct Bounds {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

fn round(value: f64, precision: i32) -> f64 {
    if !value.is_finite() {
        return value;
    }
    let factor = 10f64.powi(precision);
    (value * factor).round() / factor
}

pub fn normalize_geometry(elements: &[Value], precision: i32) -> Vec<Value> {
    elements
        .iter()
        .map(|item| {
            let mut merged = item.clone();
            if let Value::Object(ref mut map) = merged {
                for field in ["x", "y", "width", "height", "scrollWidth", "scrollHeight"] {
                    if let Some(v) = map.get(field).and_then(Value::as_f64) {
                        map.insert(field.into(), json!(round(v, precision)));
                    }
                }
            }
            merged
        })
        .collect()
}

pub fn intersect_bounds(left: Bounds, right: Bounds) -> Option<Value> {
    let x = left.x.max(right.x);
    let y = left.y.max(right.y);
    let width = (left.x + left.width).min(right.x + right.width) - x;
    let height = (left.y + left.height).min(right.y + right.height) - y;
    if width > 0.0 && height > 0.0 {
        Some(json!({"x": x, "y": y, "width": width, "height": height, "area": width * height}))
    } else {
        None
    }
}

// ---- runtime-spec.mjs ----

const REQUIRED_STATES: [&str; 9] = [
    "default", "loading", "empty", "error", "success", "disabled", "focused", "opened", "offline",
];

pub fn build_runtime_specs(inventory: &Value, options: &Value) -> Value {
    let empty = Vec::new();
    let surfaces = inventory
        .get("surfaces")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    let required_states_opt: Vec<&str> = options
        .get("requiredStates")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let viewports = options.get("viewports").cloned().unwrap_or(json!(["desktop"]));
    let specs: Vec<Value> = surfaces
        .iter()
        .filter(|surface| surface.get("runtimeEligible").and_then(Value::as_bool).unwrap_or(false))
        .map(|surface| {
            let mut states: Vec<String> = surface
                .get("states")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default();
            for state in REQUIRED_STATES {
                if required_states_opt.contains(&state) && !states.iter().any(|s| s == state) {
                    states.push(state.to_string());
                }
            }
            let controls = surface.get("controls").and_then(Value::as_array).cloned().unwrap_or_default();
            let risky: Vec<&Value> = controls
                .iter()
                .filter(|c| {
                    c.get("destructive").and_then(Value::as_bool).unwrap_or(false)
                        || c.get("external").and_then(Value::as_bool).unwrap_or(false)
                        || c.get("nativeDialog").and_then(Value::as_bool).unwrap_or(false)
                })
                .collect();
            let surface_id = surface.get("id").cloned().unwrap_or(Value::Null);
            let entry_route = surface.get("route").cloned().unwrap_or(Value::Null);
            json!({
                "surfaceId": surface_id,
                "entryRoute": entry_route,
                "states": states,
                "viewports": viewports,
                "authentication": options.get("authentication").and_then(|a| a.get(surface.get("id").and_then(Value::as_str).unwrap_or(""))).cloned().unwrap_or(json!("unknown")),
                "actions": risky.iter().map(|c| json!({
                    "id": c.get("id").cloned().unwrap_or(Value::Null),
                    "selector": c.get("selector").cloned().unwrap_or(Value::Null),
                    "prohibited": true,
                })).collect::<Vec<_>>(),
                "terminalState": options.get("terminalStates").and_then(|t| t.get(surface.get("id").and_then(Value::as_str).unwrap_or(""))).cloned().unwrap_or(Value::Null),
            })
        })
        .collect();
    let coverage_gaps: Vec<Value> = specs
        .iter()
        .filter(|spec| spec["entryRoute"].is_null())
        .map(|spec| json!(format!("route-missing:{}", spec["surfaceId"].as_str().unwrap_or(""))))
        .collect();
    json!({
        "schemaVersion": 1,
        "kind": "legion-runtime-surface-spec",
        "specs": specs,
        "coverageGaps": coverage_gaps,
    })
}

// ---- skill-compiler.mjs ----

static DIRECTIVE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b(?:edit|write|publish|deploy|create|delete)\b").unwrap());

#[derive(Debug, Clone, Default)]
pub struct SkillEntry {
    pub id: Option<String>,
    pub text: Option<String>,
    pub audit: Option<bool>,
    pub family: Option<String>,
    pub kind: Option<String>,
    pub evidence_requirement: Option<String>,
    pub remediation_owner: Option<String>,
    pub source_uri: Option<String>,
}

pub fn compile_designer_audit_profile(entries: &[SkillEntry], source_uri: &str) -> Value {
    let mut rules = Vec::new();
    let mut exclusions = Vec::new();
    for entry in entries {
        let (Some(id), Some(text)) = (&entry.id, &entry.text) else {
            exclusions.push(json!({"id": entry.id, "reason": "skill-entry-incomplete"}));
            continue;
        };
        if DIRECTIVE_RE.is_match(text) || entry.audit == Some(false) {
            exclusions.push(json!({"id": id, "reason": "authoring-instruction-excluded"}));
            continue;
        }
        rules.push(json!({
            "id": format!("designer.{id}"),
            "family": entry.family.clone().unwrap_or_else(|| "visual".into()),
            "kind": entry.kind.clone().unwrap_or_else(|| "interpretive".into()),
            "evidenceRequirement": entry.evidence_requirement.clone().unwrap_or_else(|| "rendered-surface".into()),
            "remediationOwner": entry.remediation_owner.clone().unwrap_or_else(|| "design".into()),
            "sourceUri": entry.source_uri.clone().unwrap_or_else(|| source_uri.to_string()),
        }));
    }
    json!({
        "schemaVersion": 1,
        "kind": "legion-designer-audit-profile",
        "sourceUri": source_uri,
        "rules": rules,
        "exclusions": exclusions,
        "status": if entries.is_empty() { "unproven" } else { "pass" },
        "coverageGaps": if entries.is_empty() { json!(["designer-skill-bundle-missing"]) } else { json!([]) },
    })
}

// ---- surfaces.mjs ----

#[derive(Debug, Clone, Default)]
pub struct SurfaceArtifact {
    pub file: Option<String>,
    pub route: Option<String>,
    pub surface_type: Option<String>,
    pub framework: Option<String>,
    pub states: Option<Vec<String>>,
    pub controls: Value,
    pub protected_regions: Value,
    pub runtime_eligible: Option<bool>,
    pub visibility: Option<String>,
}

pub fn build_surface_inventory(artifacts: &[SurfaceArtifact], binding: &Value) -> Value {
    let surfaces: Vec<Value> = artifacts
        .iter()
        .map(|a| {
            let file = a.file.clone().unwrap_or_default();
            let route = a.route.clone().unwrap_or_default();
            let surface_type = a.surface_type.clone().unwrap_or_else(|| "surface".into());
            let id_source = [file.as_str(), route.as_str(), surface_type.as_str()].join("\0");
            json!({
                "id": sha256_hex(id_source.as_bytes()),
                "file": a.file,
                "route": a.route,
                "type": surface_type,
                "framework": a.framework,
                "states": a.states.clone().unwrap_or_else(|| vec!["default".into()]),
                "controls": a.controls,
                "protectedRegions": a.protected_regions,
                "runtimeEligible": a.runtime_eligible.unwrap_or(true),
                "visibility": a.visibility.clone().unwrap_or_else(|| "user-facing".into()),
            })
        })
        .collect();
    let denominator_digest = sha256_hex(serde_json::to_string(&surfaces).unwrap_or_default().as_bytes());
    let complete = artifacts.iter().all(|a| a.file.is_some());
    let coverage_gaps: Vec<Value> = artifacts
        .iter()
        .filter(|a| a.file.is_none())
        .map(|_| json!("surface-source-missing"))
        .collect();
    json!({
        "schemaVersion": 1,
        "kind": "legion-surface-inventory",
        "binding": binding,
        "surfaces": surfaces,
        "denominatorDigest": denominator_digest,
        "complete": complete,
        "coverageGaps": coverage_gaps,
    })
}

// ---- ux-flow.mjs ----

pub fn build_ux_flow(input: &Value) -> Value {
    let steps: Vec<Value> = input
        .get("steps")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .enumerate()
        .map(|(index, step)| {
            json!({
                "index": index,
                "surfaceId": step.get("surfaceId").cloned().unwrap_or(Value::Null),
                "componentId": step.get("componentId").cloned().unwrap_or(Value::Null),
                "action": step.get("action").cloned().unwrap_or(Value::Null),
                "expectedState": step.get("expectedState").cloned().unwrap_or(Value::Null),
                "actualState": step.get("actualState").cloned().unwrap_or(Value::Null),
                "errorPath": step.get("errorPath").cloned().unwrap_or(Value::Null),
                "recoveryPath": step.get("recoveryPath").cloned().unwrap_or(Value::Null),
                "prerequisites": step.get("prerequisites").cloned().unwrap_or(json!([])),
                "sideEffects": step.get("sideEffects").cloned().unwrap_or(json!([])),
                "evidenceRefs": step.get("evidenceRefs").cloned().unwrap_or(json!([])),
            })
        })
        .collect();
    let goal_source = input.get("goalSource").and_then(Value::as_str).unwrap_or("explicit").to_string();
    let identity = json!({
        "goal": input.get("goal").cloned().unwrap_or(Value::Null),
        "cohort": input.get("cohort").cloned().unwrap_or(json!("unspecified")),
        "entrySurfaceId": input.get("entrySurfaceId").cloned().unwrap_or(Value::Null),
        "steps": steps,
    });
    let id = sha256_prefixed("", &identity);
    let terminal_state_in = input.get("terminalState").and_then(Value::as_str);
    let has_behavior_evidence = input.get("behaviorEvidence").is_some_and(|v| !v.is_null());
    let terminal_state = if terminal_state_in == Some("success") && !has_behavior_evidence {
        "unproven".to_string()
    } else {
        terminal_state_in.unwrap_or("unproven").to_string()
    };
    json!({
        "schemaVersion": 1,
        "kind": "legion-ux-flow",
        "id": id,
        "goal": input.get("goal").cloned().unwrap_or(Value::Null),
        "goalSource": goal_source,
        "goalInferred": goal_source != "explicit",
        "cohort": input.get("cohort").cloned().unwrap_or(json!("unspecified")),
        "context": input.get("context").cloned().unwrap_or(Value::Null),
        "priorKnowledge": input.get("priorKnowledge").cloned().unwrap_or(Value::Null),
        "assistance": input.get("assistance").cloned().unwrap_or(Value::Null),
        "successCriteria": input.get("successCriteria").cloned().unwrap_or(json!([])),
        "expectedEffort": input.get("expectedEffort").cloned().unwrap_or(Value::Null),
        "entrySurfaceId": input.get("entrySurfaceId").cloned().unwrap_or(Value::Null),
        "steps": steps,
        "alternatePaths": input.get("alternatePaths").cloned().unwrap_or(json!([])),
        "terminalState": terminal_state,
        "measurements": input.get("measurements").cloned().unwrap_or(Value::Null),
        "denominatorDigest": input.get("denominatorDigest").cloned().unwrap_or(json!(id)),
        "binding": input.get("binding").cloned().unwrap_or(json!({})),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_compatibility_finds_mismatches() {
        let baseline = json!({"route": "/a", "state": "default"});
        let actual = json!({"route": "/b", "state": "default"});
        let result = baseline_compatibility(&baseline, &actual);
        assert_eq!(result["compatible"], false);
        assert_eq!(result["mismatches"][0], "route");
    }

    #[test]
    fn brand_context_reports_unproven_without_declared_brand() {
        let ctx = brand_context(&json!({}));
        assert_eq!(ctx["status"], "unproven");
    }

    #[test]
    fn design_context_status_depends_on_declared() {
        let ctx = create_design_context(None, &json!({}), &json!({}), &json!({}));
        assert_eq!(ctx["status"], "unproven");
        let ctx2 = create_design_context(None, &json!({"brand": "x"}), &json!({}), &json!({}));
        assert_eq!(ctx2["status"], "pass");
    }

    #[test]
    fn normalize_geometry_rounds_to_precision() {
        let elements = vec![json!({"x": 1.23456, "y": 0.0, "width": 10.0, "height": 20.0})];
        let out = normalize_geometry(&elements, 3);
        assert_eq!(out[0]["x"], 1.235);
    }

    #[test]
    fn intersect_bounds_returns_none_when_disjoint() {
        let a = Bounds { x: 0.0, y: 0.0, width: 10.0, height: 10.0 };
        let b = Bounds { x: 20.0, y: 20.0, width: 5.0, height: 5.0 };
        assert!(intersect_bounds(a, b).is_none());
    }

    #[test]
    fn intersect_bounds_computes_overlap_area() {
        let a = Bounds { x: 0.0, y: 0.0, width: 10.0, height: 10.0 };
        let b = Bounds { x: 5.0, y: 5.0, width: 10.0, height: 10.0 };
        let result = intersect_bounds(a, b).unwrap();
        assert_eq!(result["area"], 25.0);
    }

    #[test]
    fn runtime_specs_flags_risky_controls_and_missing_routes() {
        let inventory = json!({"surfaces": [
            {"id": "s1", "route": null, "runtimeEligible": true, "controls": [{"id": "c1", "destructive": true}], "states": []}
        ]});
        let specs = build_runtime_specs(&inventory, &json!({}));
        assert_eq!(specs["specs"][0]["actions"][0]["prohibited"], true);
        assert!(specs["coverageGaps"][0].as_str().unwrap().starts_with("route-missing:"));
    }

    #[test]
    fn designer_skill_compiler_excludes_directives() {
        let entries = vec![
            SkillEntry { id: Some("d1".into()), text: Some("edit the hero image".into()), ..Default::default() },
            SkillEntry { id: Some("d2".into()), text: Some("check contrast ratio".into()), ..Default::default() },
        ];
        let profile = compile_designer_audit_profile(&entries, "legion-skill://designer/");
        assert_eq!(profile["rules"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn surface_inventory_flags_missing_file() {
        let artifacts = vec![SurfaceArtifact { file: None, ..Default::default() }];
        let inv = build_surface_inventory(&artifacts, &json!({}));
        assert_eq!(inv["complete"], false);
        assert_eq!(inv["coverageGaps"][0], "surface-source-missing");
    }

    #[test]
    fn ux_flow_terminal_state_unproven_without_behavior_evidence() {
        let input = json!({"goal": "sign up", "terminalState": "success"});
        let flow = build_ux_flow(&input);
        assert_eq!(flow["terminalState"], "unproven");
    }

    #[test]
    fn ux_flow_terminal_state_success_with_evidence() {
        let input = json!({"goal": "sign up", "terminalState": "success", "behaviorEvidence": {"screenshot": "x"}});
        let flow = build_ux_flow(&input);
        assert_eq!(flow["terminalState"], "success");
    }
}
