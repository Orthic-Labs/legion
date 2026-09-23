//! Ported from src/lib/controls/baseline/selectors.mjs and
//! src/lib/controls/baseline/trace.mjs (packet P5b-controls-config).

use super::controls_support::Value;

const SELECTOR_KEYS: &[&str] = &[
    "op",
    "targetKinds",
    "componentKinds",
    "facets",
    "stackIds",
    "environments",
    "policyFlags",
];

/// Minimal view of a selection subject: mirrors the fields
/// `matchesSelector` reads off `target`/`component`/`contract`.
#[derive(Debug, Default, Clone)]
pub struct SelectorContext<'a> {
    pub target_kind: Option<&'a str>,
    pub target_facets: &'a [String],
    pub component_kind: Option<&'a str>,
    pub stack_ids: &'a [String],
    pub contract_environments: &'a [String],
    pub contract_policy_flags: &'a [String],
}

fn as_str_list(value: Option<&Value>) -> Option<Vec<&str>> {
    match value {
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .filter_map(|item| match item {
                    Value::String(s) => Some(s.as_str()),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

fn overlap(required: Option<Vec<&str>>, observed: &[String]) -> bool {
    match required {
        None => true,
        Some(values) => values.iter().all(|v| observed.iter().any(|o| o == v)),
    }
}

/// Port of `matchesSelector(selector, { target, component, stacks, contract })`.
/// Returns `Err` for an unknown selector key/op, matching the JS `throw`.
pub fn matches_selector(selector: &Value, ctx: &SelectorContext) -> Result<bool, String> {
    let map = match selector {
        Value::Object(map) => map,
        Value::Null => return Ok(true), // `selector = {}` default
        _ => return Err("selector must be an object".to_string()),
    };

    for key in map.keys() {
        if !SELECTOR_KEYS.contains(&key.as_str()) {
            return Err(format!("unknown selector key: {key}"));
        }
    }

    if let Some(Value::String(op)) = map.get("op") {
        if op != "always" {
            return Err(format!("unknown selector operation: {op}"));
        }
        return Ok(true);
    }

    if let Some(kinds) = as_str_list(map.get("targetKinds")) {
        if !ctx.target_kind.is_some_and(|k| kinds.contains(&k)) {
            return Ok(false);
        }
    }
    if let Some(kinds) = as_str_list(map.get("componentKinds")) {
        if !ctx.component_kind.is_some_and(|k| kinds.contains(&k)) {
            return Ok(false);
        }
    }
    if let Some(facets) = as_str_list(map.get("facets")) {
        if !facets.iter().any(|f| ctx.target_facets.iter().any(|tf| tf == f)) {
            return Ok(false);
        }
    }
    if !overlap(as_str_list(map.get("stackIds")), ctx.stack_ids) {
        return Ok(false);
    }
    if !overlap(as_str_list(map.get("environments")), ctx.contract_environments) {
        return Ok(false);
    }
    if !overlap(as_str_list(map.get("policyFlags")), ctx.contract_policy_flags) {
        return Ok(false);
    }

    Ok(true)
}

/// Port of `selectionTrace(control, subject, selected)`.
pub fn selection_trace(control_id: &str, selector: Value, subject_id: Option<&str>, selected: bool) -> Value {
    Value::object([
        ("controlId", Value::str(control_id)),
        ("subjectId", Value::str(subject_id.unwrap_or("product"))),
        ("selected", Value::Bool(selected)),
        ("selector", selector),
        (
            "reason",
            Value::str(if selected {
                "selector-matched-frozen-inventory"
            } else {
                "selector-not-matched"
            }),
        ),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> SelectorContext<'static> {
        SelectorContext::default()
    }

    #[test]
    fn always_op_matches_everything() {
        let selector = Value::object([("op", Value::str("always"))]);
        assert!(matches_selector(&selector, &ctx()).unwrap());
    }

    #[test]
    fn unknown_op_errors() {
        let selector = Value::object([("op", Value::str("sometimes"))]);
        assert_eq!(
            matches_selector(&selector, &ctx()).unwrap_err(),
            "unknown selector operation: sometimes"
        );
    }

    #[test]
    fn unknown_key_errors() {
        let selector = Value::object([("bogus", Value::Bool(true))]);
        assert_eq!(
            matches_selector(&selector, &ctx()).unwrap_err(),
            "unknown selector key: bogus"
        );
    }

    #[test]
    fn target_kind_mismatch_excludes() {
        let selector = Value::object([(
            "targetKinds",
            Value::array([Value::str("web")]),
        )]);
        let mut c = ctx();
        c.target_kind = Some("mobile");
        assert!(!matches_selector(&selector, &c).unwrap());
        c.target_kind = Some("web");
        assert!(matches_selector(&selector, &c).unwrap());
    }

    #[test]
    fn empty_selector_matches() {
        let selector = Value::object([]);
        assert!(matches_selector(&selector, &ctx()).unwrap());
    }

    #[test]
    fn stack_ids_require_full_overlap() {
        let selector = Value::object([(
            "stackIds",
            Value::array([Value::str("s1"), Value::str("s2")]),
        )]);
        let mut c = ctx();
        let ids = vec!["s1".to_string()];
        c.stack_ids = &ids;
        assert!(!matches_selector(&selector, &c).unwrap());
        let ids2 = vec!["s1".to_string(), "s2".to_string()];
        c.stack_ids = &ids2;
        assert!(matches_selector(&selector, &c).unwrap());
    }

    #[test]
    fn selection_trace_reports_reason() {
        let selector = Value::object([("op", Value::str("always"))]);
        let trace = selection_trace("ctl.1", selector, Some("t1"), true);
        if let Value::Object(map) = &trace {
            assert_eq!(map.get("reason"), Some(&Value::str("selector-matched-frozen-inventory")));
            assert_eq!(map.get("subjectId"), Some(&Value::str("t1")));
        } else {
            panic!("expected object");
        }
    }

    #[test]
    fn selection_trace_defaults_subject_to_product() {
        let trace = selection_trace("ctl.1", Value::object([]), None, false);
        if let Value::Object(map) = &trace {
            assert_eq!(map.get("subjectId"), Some(&Value::str("product")));
            assert_eq!(map.get("reason"), Some(&Value::str("selector-not-matched")));
        } else {
            panic!("expected object");
        }
    }
}
