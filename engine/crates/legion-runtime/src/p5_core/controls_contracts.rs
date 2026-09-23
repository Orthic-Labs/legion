//! Ported from src/lib/controls/contracts.mjs (packet P5b-controls-config).
//!
//! Faithful port of `validateControl`, `validatePack`, and `controlDigest`.
//! Operates on the dynamic `Value` type (see `controls_support`) because
//! controls/packs are open JSON documents in the JS source, not fixed Rust
//! structs.

use super::controls_support::{digest, Value};
use std::collections::BTreeSet;

const CONTROL_KEYS: &[&str] = &[
    "id", "version", "selector", "denominator", "evidence", "families", "lenses", "providers",
    "rules", "scenarios", "decisionMode", "missingEvidenceEffect", "claimLevels",
    "remediationOwner", "sourceConcepts", "benchmark", "provenance", "stopShip", "unimplemented",
];
const PACK_KEYS: &[&str] = &[
    "id", "version", "class", "dependencies", "source", "qualification", "controls",
];
const PACK_CLASSES: &[&str] = &[
    "universal", "target", "component", "stack", "environment", "conditional", "policy",
];
const DECISIONS: &[&str] = &["deterministic", "measured", "reasoning", "human"];
const EFFECTS: &[&str] = &["unproven", "fail", "not-applicable"];
const OWNERS: &[&str] = &["code", "design", "writing", "architecture", "manual"];
const QUALIFICATIONS: &[&str] = &["unproven", "source-tested", "measured"];
const REQUIRED_CONTROL_KEYS: &[&str] = &[
    "id", "version", "selector", "denominator", "evidence", "families", "lenses", "providers",
    "rules", "scenarios", "decisionMode", "missingEvidenceEffect", "claimLevels",
    "remediationOwner", "sourceConcepts", "stopShip", "benchmark", "provenance",
];
const NON_EMPTY_ARRAY_KEYS: &[&str] = &[
    "evidence", "families", "lenses", "rules", "scenarios", "claimLevels", "sourceConcepts",
];

fn as_object(value: &Value) -> Result<&std::collections::BTreeMap<String, Value>, String> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err("expected object".to_string()),
    }
}

fn get<'a>(map: &'a std::collections::BTreeMap<String, Value>, key: &str) -> Option<&'a Value> {
    map.get(key)
}

fn is_missing(value: Option<&Value>) -> bool {
    matches!(value, None | Some(Value::Null))
}

fn as_array(value: &Value) -> Option<&Vec<Value>> {
    match value {
        Value::Array(items) => Some(items),
        _ => None,
    }
}

fn as_str(value: &Value) -> Option<&str> {
    match value {
        Value::String(s) => Some(s.as_str()),
        _ => None,
    }
}

/// Port of `validateControl(control)`. Returns `Ok(())` (JS returns the
/// control unchanged) or `Err(message)` matching the thrown `Error` text.
pub fn validate_control(control: &Value) -> Result<(), String> {
    let map = as_object(control).map_err(|_| "control must be an object".to_string())?;

    for key in map.keys() {
        if !CONTROL_KEYS.contains(&key.as_str()) {
            return Err(format!("unknown control field: {key}"));
        }
    }
    for key in REQUIRED_CONTROL_KEYS {
        if is_missing(get(map, key)) {
            return Err(format!("control missing {key}"));
        }
    }
    for key in NON_EMPTY_ARRAY_KEYS {
        let ok = matches!(get(map, key), Some(Value::Array(items)) if !items.is_empty());
        if !ok {
            return Err(format!("control {key} must be a non-empty array"));
        }
    }
    if !matches!(get(map, "providers"), Some(Value::Array(_))) {
        return Err("control providers must be an array".to_string());
    }
    if !matches!(get(map, "selector"), Some(Value::Object(_))) {
        return Err("control selector must be an object".to_string());
    }

    if let Some(Value::Array(levels)) = get(map, "claimLevels") {
        let mut seen = BTreeSet::new();
        for level in levels {
            if let Some(s) = as_str(level) {
                if !seen.insert(s.to_string()) {
                    let id = get(map, "id").and_then(as_str).unwrap_or("");
                    return Err(format!("duplicate control claim level: {id}"));
                }
            }
        }
    }

    let decision_ok = get(map, "decisionMode")
        .and_then(as_str)
        .is_some_and(|v| DECISIONS.contains(&v));
    let effect_ok = get(map, "missingEvidenceEffect")
        .and_then(as_str)
        .is_some_and(|v| EFFECTS.contains(&v));
    let owner_ok = get(map, "remediationOwner")
        .and_then(as_str)
        .is_some_and(|v| OWNERS.contains(&v));
    if !decision_ok || !effect_ok || !owner_ok {
        let id = get(map, "id").and_then(as_str).unwrap_or("");
        return Err(format!("control policy enum invalid: {id}"));
    }

    let stop_ship_ok = matches!(get(map, "stopShip"), Some(Value::Bool(_)));
    let benchmark_ok = match get(map, "benchmark") {
        Some(Value::Object(bench)) => bench
            .get("status")
            .and_then(as_str)
            .is_some_and(|s| QUALIFICATIONS.contains(&s)),
        _ => false,
    };
    let provenance_ok = match get(map, "provenance") {
        Some(Value::Object(prov)) => {
            !matches!(prov.get("source"), None | Some(Value::Null))
                && matches!(prov.get("lineage"), Some(Value::Array(_)))
        }
        _ => false,
    };
    if !stop_ship_ok || !benchmark_ok || !provenance_ok {
        let id = get(map, "id").and_then(as_str).unwrap_or("");
        return Err(format!("control evidence contract invalid: {id}"));
    }

    Ok(())
}

/// Port of `validatePack(pack)`.
pub fn validate_pack(pack: &Value) -> Result<(), String> {
    let map = as_object(pack).map_err(|_| "invalid control pack".to_string())?;

    for key in map.keys() {
        if !PACK_KEYS.contains(&key.as_str()) {
            return Err(format!("unknown control pack field: {key}"));
        }
    }

    let id = get(map, "id").and_then(as_str);
    let version = get(map, "version");
    let controls = get(map, "controls").and_then(as_array);
    let dependencies = get(map, "dependencies").and_then(as_array);
    let class_ok = get(map, "class")
        .and_then(as_str)
        .is_some_and(|c| PACK_CLASSES.contains(&c));
    if id.map(str::is_empty).unwrap_or(true)
        || is_missing(version)
        || controls.is_none()
        || dependencies.is_none()
        || !class_ok
    {
        return Err("invalid control pack".to_string());
    }

    let source_ok = matches!(get(map, "source"), Some(Value::Object(src))
        if !is_missing(src.get("kind")) && !is_missing(src.get("rights")));
    if !source_ok {
        return Err("invalid control pack source".to_string());
    }

    let qualification_ok = get(map, "qualification")
        .and_then(as_str)
        .is_some_and(|q| QUALIFICATIONS.contains(&q));
    if !qualification_ok {
        return Err("invalid control pack qualification".to_string());
    }

    let mut ids = BTreeSet::new();
    for control in controls.unwrap() {
        validate_control(control)?;
        if let Some(control_id) = as_object(control).ok().and_then(|m| get(m, "id")).and_then(as_str) {
            if !ids.insert(control_id.to_string()) {
                return Err(format!("duplicate control in pack: {control_id}"));
            }
        }
    }

    Ok(())
}

/// Port of `controlDigest(control)`: validates, then digests.
pub fn control_digest(control: &Value) -> Result<String, String> {
    validate_control(control)?;
    Ok(digest(control))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_control() -> Value {
        Value::object([
            ("id", Value::str("ctl.1")),
            ("version", Value::Number(1.0)),
            ("selector", Value::object([("op", Value::str("always"))])),
            ("denominator", Value::str("d")),
            ("evidence", Value::array([Value::str("e1")])),
            ("families", Value::array([Value::str("f1")])),
            ("lenses", Value::array([Value::str("l1")])),
            ("providers", Value::array([])),
            ("rules", Value::array([Value::str("r1")])),
            ("scenarios", Value::array([Value::str("s1")])),
            ("decisionMode", Value::str("deterministic")),
            ("missingEvidenceEffect", Value::str("unproven")),
            ("claimLevels", Value::array([Value::str("inventory")])),
            ("remediationOwner", Value::str("code")),
            ("sourceConcepts", Value::array([Value::str("sc1")])),
            ("stopShip", Value::Bool(false)),
            (
                "benchmark",
                Value::object([("status", Value::str("unproven"))]),
            ),
            (
                "provenance",
                Value::object([
                    ("source", Value::str("src")),
                    ("lineage", Value::array([])),
                ]),
            ),
        ])
    }

    #[test]
    fn accepts_a_well_formed_control() {
        assert!(validate_control(&valid_control()).is_ok());
    }

    #[test]
    fn rejects_unknown_field() {
        let mut control = valid_control();
        if let Value::Object(map) = &mut control {
            map.insert("bogus".into(), Value::Bool(true));
        }
        let err = validate_control(&control).unwrap_err();
        assert_eq!(err, "unknown control field: bogus");
    }

    #[test]
    fn rejects_missing_required_field() {
        let mut control = valid_control();
        if let Value::Object(map) = &mut control {
            map.remove("stopShip");
        }
        assert_eq!(validate_control(&control).unwrap_err(), "control missing stopShip");
    }

    #[test]
    fn rejects_empty_required_array() {
        let mut control = valid_control();
        if let Value::Object(map) = &mut control {
            map.insert("evidence".into(), Value::Array(vec![]));
        }
        assert_eq!(
            validate_control(&control).unwrap_err(),
            "control evidence must be a non-empty array"
        );
    }

    #[test]
    fn rejects_duplicate_claim_level() {
        let mut control = valid_control();
        if let Value::Object(map) = &mut control {
            map.insert(
                "claimLevels".into(),
                Value::array([Value::str("inventory"), Value::str("inventory")]),
            );
        }
        assert_eq!(
            validate_control(&control).unwrap_err(),
            "duplicate control claim level: ctl.1"
        );
    }

    #[test]
    fn rejects_invalid_enum() {
        let mut control = valid_control();
        if let Value::Object(map) = &mut control {
            map.insert("decisionMode".into(), Value::str("nonsense"));
        }
        assert_eq!(
            validate_control(&control).unwrap_err(),
            "control policy enum invalid: ctl.1"
        );
    }

    fn valid_pack() -> Value {
        Value::object([
            ("id", Value::str("pack.1")),
            ("version", Value::Number(1.0)),
            ("class", Value::str("universal")),
            ("dependencies", Value::array([])),
            (
                "source",
                Value::object([("kind", Value::str("internal")), ("rights", Value::str("cleared"))]),
            ),
            ("qualification", Value::str("unproven")),
            ("controls", Value::array([valid_control()])),
        ])
    }

    #[test]
    fn accepts_a_well_formed_pack() {
        assert!(validate_pack(&valid_pack()).is_ok());
    }

    #[test]
    fn rejects_duplicate_control_id_in_pack() {
        let mut pack = valid_pack();
        if let Value::Object(map) = &mut pack {
            map.insert(
                "controls".into(),
                Value::array([valid_control(), valid_control()]),
            );
        }
        assert_eq!(
            validate_pack(&pack).unwrap_err(),
            "duplicate control in pack: ctl.1"
        );
    }

    #[test]
    fn control_digest_is_deterministic() {
        let control = valid_control();
        let a = control_digest(&control).unwrap();
        let b = control_digest(&control).unwrap();
        assert_eq!(a, b);
        assert!(a.starts_with("sha256:"));
    }

    #[test]
    fn control_digest_propagates_validation_error() {
        let mut control = valid_control();
        if let Value::Object(map) = &mut control {
            map.remove("id");
        }
        assert_eq!(control_digest(&control).unwrap_err(), "control missing id");
    }
}
