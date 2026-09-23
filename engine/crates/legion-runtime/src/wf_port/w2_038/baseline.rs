//! Ported from src/lib/controls/baseline/compile.mjs (chunk w2_038).

use super::util::{arr, as_str, get, str_list};
use crate::p5_core::controls_selectors::{matches_selector, selection_trace, SelectorContext};
use crate::p5_core::controls_support::{digest, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

const CONTRACT_KEYS: &[&str] = &[
    "version",
    "selector",
    "denominator",
    "evidence",
    "families",
    "lenses",
    "claimLevels",
    "missingEvidenceEffect",
    "decisionMode",
    "providers",
    "rules",
    "scenarios",
    "stopShip",
    "provenance",
    "benchmark",
    "remediationOwner",
    "sourceConcepts",
    "unimplemented",
];

/// Port of `canonical(value)`: sorted-key `JSON.stringify`, recursing into
/// every object (arrays keep element order). Distinct from
/// `controls_support::Value::to_canonical_string`, which additionally
/// replaces `\` with `/` in strings (that extra step is specific to
/// `digest()`'s own `canonicalize()` and is not part of this module's local
/// `canonical()` helper).
fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if n.fract() == 0.0 && n.is_finite() && n.abs() < 1e15 {
                let _ = write!(out, "{}", *n as i64);
            } else {
                let _ = write!(out, "{n}");
            }
        }
        Value::String(s) => write_json_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(out, k);
                out.push(':');
                write_canonical(v, out);
            }
            out.push('}');
        }
    }
}

fn write_json_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Port of `compatible(left, right)`.
fn compatible(left: &Value, right: &Value) -> bool {
    CONTRACT_KEYS.iter().all(|key| {
        let l = get(left, key).cloned().unwrap_or(Value::Null);
        let r = get(right, key).cloned().unwrap_or(Value::Null);
        canonical_json(&l) == canonical_json(&r)
    })
}

struct SelectedEntry {
    control: Value,
    target_ids: Vec<String>,
    component_ids: Vec<String>,
    pack_ids: Vec<String>,
}

struct Context<'a> {
    subject: &'a Value,
    target: &'a Value,
    component: Option<&'a Value>,
}

/// Port of `compileBaseline({ packs, portfolio, components, stacks,
/// contract, binding })`. `packs` defaults to `&[]`, `stacks` to `&[]`, and
/// `contract` to `Value::Object(BTreeMap::new())` at the call site, matching
/// the JS destructuring defaults.
pub fn compile_baseline(
    packs: &[Value],
    portfolio: &Value,
    components: &Value,
    stacks: &[Value],
    contract: &Value,
    binding: Option<&Value>,
) -> Result<Value, String> {
    // Duplicate pack id check.
    let mut pack_ids: Vec<String> = Vec::new();
    let mut pack_id_set: BTreeSet<String> = BTreeSet::new();
    for pack in packs {
        let id = get(pack, "id").and_then(as_str).unwrap_or("").to_string();
        if !pack_id_set.insert(id.clone()) {
            return Err("duplicate control pack ID".to_string());
        }
        pack_ids.push(id);
    }

    // Missing pack dependency check.
    for pack in packs {
        let pid = get(pack, "id").and_then(as_str).unwrap_or("");
        let deps = get(pack, "dependencies").map(arr).unwrap_or(&[]);
        for dep in deps {
            if let Some(dep_id) = as_str(dep) {
                if !pack_id_set.contains(dep_id) {
                    return Err(format!("missing pack dependency: {pid}:{dep_id}"));
                }
            }
        }
    }

    // Pack dependency cycle detection (DFS, port of `visit`).
    let mut dep_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for pack in packs {
        let pid = get(pack, "id").and_then(as_str).unwrap_or("").to_string();
        let deps: Vec<String> = get(pack, "dependencies")
            .map(arr)
            .unwrap_or(&[])
            .iter()
            .filter_map(as_str)
            .map(str::to_string)
            .collect();
        dep_map.insert(pid, deps);
    }
    fn visit(
        id: &str,
        dep_map: &BTreeMap<String, Vec<String>>,
        visiting: &mut BTreeSet<String>,
        visited: &mut BTreeSet<String>,
    ) -> Result<(), String> {
        if visiting.contains(id) {
            return Err(format!("control pack dependency cycle: {id}"));
        }
        if visited.contains(id) {
            return Ok(());
        }
        visiting.insert(id.to_string());
        if let Some(deps) = dep_map.get(id) {
            for dep in deps {
                visit(dep, dep_map, visiting, visited)?;
            }
        }
        visiting.remove(id);
        visited.insert(id.to_string());
        Ok(())
    }
    let mut visiting = BTreeSet::new();
    let mut visited = BTreeSet::new();
    for pid in &pack_ids {
        visit(pid, &dep_map, &mut visiting, &mut visited)?;
    }

    // Incompatible-duplicate-control check across packs (the JS
    // `definitions` map is built purely for this side effect: its values
    // are never read afterward).
    let mut definitions: BTreeMap<String, Value> = BTreeMap::new();
    for pack in packs {
        for control in get(pack, "controls").map(arr).unwrap_or(&[]) {
            let cid = get(control, "id").and_then(as_str).unwrap_or("").to_string();
            match definitions.get(&cid) {
                Some(prior) if !compatible(prior, control) => {
                    return Err(format!("incompatible duplicate control: {cid}"));
                }
                Some(_) => {}
                None => {
                    definitions.insert(cid, control.clone());
                }
            }
        }
    }

    // Selection contexts: every target, plus every component paired with
    // each of its known target ids.
    let targets = get(portfolio, "targets").map(arr).unwrap_or(&[]);
    let mut target_by_id: BTreeMap<&str, &Value> = BTreeMap::new();
    for target in targets {
        if let Some(id) = get(target, "id").and_then(as_str) {
            target_by_id.insert(id, target);
        }
    }
    let mut contexts: Vec<Context> = Vec::new();
    for target in targets {
        contexts.push(Context { subject: target, target, component: None });
    }
    for component in get(components, "components").map(arr).unwrap_or(&[]) {
        for target_id_value in get(component, "targetIds").map(arr).unwrap_or(&[]) {
            if let Some(target_id) = as_str(target_id_value) {
                if let Some(&target) = target_by_id.get(target_id) {
                    contexts.push(Context { subject: component, target, component: Some(component) });
                }
            }
        }
    }

    // `{...(contract.observed??{}), ...(contract.declared??{}), ...contract}`.
    let mut merged: BTreeMap<String, Value> = BTreeMap::new();
    let merge_in = |target: &mut BTreeMap<String, Value>, overlay: &Value| {
        if let Value::Object(map) = overlay {
            for (k, v) in map {
                target.insert(k.clone(), v.clone());
            }
        }
    };
    if let Some(observed) = get(contract, "observed") {
        merge_in(&mut merged, observed);
    }
    if let Some(declared) = get(contract, "declared") {
        merge_in(&mut merged, declared);
    }
    merge_in(&mut merged, contract);
    let merged_contract = Value::Object(merged);

    let contract_environments = str_list(get(&merged_contract, "environments"));
    let contract_policy_flags = str_list(get(&merged_contract, "policyFlags"));
    let stack_ids: Vec<String> = stacks
        .iter()
        .filter_map(|s| get(s, "id").and_then(as_str))
        .map(str::to_string)
        .collect();

    let mut sorted_packs: Vec<&Value> = packs.iter().collect();
    sorted_packs.sort_by(|a, b| {
        let ai = get(a, "id").and_then(as_str).unwrap_or("");
        let bi = get(b, "id").and_then(as_str).unwrap_or("");
        ai.cmp(bi)
    });

    let mut selected: BTreeMap<String, SelectedEntry> = BTreeMap::new();
    let mut traces: Vec<Value> = Vec::new();

    for &pack in &sorted_packs {
        let pack_id = get(pack, "id").and_then(as_str).unwrap_or("").to_string();
        for control in get(pack, "controls").map(arr).unwrap_or(&[]) {
            let control_id = get(control, "id").and_then(as_str).unwrap_or("").to_string();
            let selector = get(control, "selector").cloned().unwrap_or_else(|| Value::Object(BTreeMap::new()));
            for ctx in &contexts {
                let target_facets = str_list(get(ctx.target, "facets"));
                let sel_ctx = SelectorContext {
                    target_kind: get(ctx.target, "kind").and_then(as_str),
                    target_facets: &target_facets,
                    component_kind: ctx.component.and_then(|c| get(c, "kind")).and_then(as_str),
                    stack_ids: &stack_ids,
                    contract_environments: &contract_environments,
                    contract_policy_flags: &contract_policy_flags,
                };
                let selected_now = matches_selector(&selector, &sel_ctx)?;

                let subject_id = get(ctx.subject, "id").and_then(as_str);
                let target_id = get(ctx.target, "id").and_then(as_str).unwrap_or("").to_string();
                let mut trace = selection_trace(&control_id, selector.clone(), subject_id, selected_now);
                if let Value::Object(map) = &mut trace {
                    map.insert("targetId".to_string(), Value::str(target_id.clone()));
                }
                traces.push(trace);

                if !selected_now {
                    continue;
                }
                let entry = selected.entry(control_id.clone()).or_insert_with(|| SelectedEntry {
                    control: control.clone(),
                    target_ids: Vec::new(),
                    component_ids: Vec::new(),
                    pack_ids: Vec::new(),
                });
                entry.target_ids.push(target_id);
                if let Some(component) = ctx.component {
                    if let Some(cid) = get(component, "id").and_then(as_str) {
                        entry.component_ids.push(cid.to_string());
                    }
                }
                entry.pack_ids.push(pack_id.clone());
            }
        }
    }

    let mut controls_out: Vec<Value> = Vec::new();
    for entry in selected.values() {
        let mut map = match &entry.control {
            Value::Object(m) => m.clone(),
            _ => BTreeMap::new(),
        };
        let mut target_ids = entry.target_ids.clone();
        target_ids.sort();
        target_ids.dedup();
        let mut component_ids = entry.component_ids.clone();
        component_ids.sort();
        component_ids.dedup();
        let mut pack_ids_used = entry.pack_ids.clone();
        pack_ids_used.sort();
        pack_ids_used.dedup();
        let unimplemented = !matches!(map.get("providers"), Some(Value::Array(items)) if !items.is_empty());

        map.insert("targetIds".to_string(), Value::Array(target_ids.into_iter().map(Value::str).collect()));
        map.insert("componentIds".to_string(), Value::Array(component_ids.into_iter().map(Value::str).collect()));
        map.insert("packIds".to_string(), Value::Array(pack_ids_used.into_iter().map(Value::str).collect()));
        map.insert("unimplemented".to_string(), Value::Bool(unimplemented));
        controls_out.push(Value::Object(map));
    }
    controls_out.sort_by(|a, b| {
        let ai = get(a, "id").and_then(as_str).unwrap_or("");
        let bi = get(b, "id").and_then(as_str).unwrap_or("");
        ai.cmp(bi)
    });

    let denominator: Vec<String> = controls_out
        .iter()
        .filter_map(|c| get(c, "id").and_then(as_str))
        .map(str::to_string)
        .collect();
    let unimplemented_ids: Vec<String> = controls_out
        .iter()
        .filter(|c| matches!(get(c, "unimplemented"), Some(Value::Bool(true))))
        .filter_map(|c| get(c, "id").and_then(as_str))
        .map(str::to_string)
        .collect();

    traces.sort_by(|a, b| canonical_json(a).cmp(&canonical_json(b)));

    let mut value_map: BTreeMap<String, Value> = BTreeMap::new();
    value_map.insert("schemaVersion".to_string(), Value::Number(1.0));
    value_map.insert("kind".to_string(), Value::str("legion-control-baseline"));
    value_map.insert("controls".to_string(), Value::Array(controls_out));
    value_map.insert("traces".to_string(), Value::Array(traces));
    value_map.insert("binding".to_string(), binding.cloned().unwrap_or(Value::Null));
    value_map.insert("denominator".to_string(), Value::Array(denominator.into_iter().map(Value::str).collect()));
    value_map.insert(
        "unimplemented".to_string(),
        Value::Array(unimplemented_ids.into_iter().map(Value::str).collect()),
    );
    let value = Value::Object(value_map);
    let d = digest(&value);
    let mut final_map = match value {
        Value::Object(m) => m,
        _ => unreachable!(),
    };
    final_map.insert("digest".to_string(), Value::str(d));
    Ok(Value::Object(final_map))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn always_selector() -> Value {
        Value::object([("op", Value::str("always"))])
    }

    fn control(id: &str, providers: Vec<Value>) -> Value {
        Value::object([
            ("id", Value::str(id)),
            ("selector", always_selector()),
            ("providers", Value::array(providers)),
        ])
    }

    fn pack(id: &str, deps: Vec<&str>, controls: Vec<Value>) -> Value {
        Value::object([
            ("id", Value::str(id)),
            ("dependencies", Value::array(deps.into_iter().map(Value::str))),
            ("controls", Value::array(controls)),
        ])
    }

    fn portfolio_one_target() -> Value {
        Value::object([("targets", Value::array([Value::object([("id", Value::str("t1"))])]))])
    }

    fn empty_components() -> Value {
        Value::object([("components", Value::array([]))])
    }

    #[test]
    fn duplicate_pack_id_errors() {
        let packs = vec![pack("p1", vec![], vec![]), pack("p1", vec![], vec![])];
        let err = compile_baseline(&packs, &portfolio_one_target(), &empty_components(), &[], &Value::object([]), None)
            .unwrap_err();
        assert_eq!(err, "duplicate control pack ID");
    }

    #[test]
    fn missing_dependency_errors() {
        let packs = vec![pack("p1", vec!["p2"], vec![])];
        let err = compile_baseline(&packs, &portfolio_one_target(), &empty_components(), &[], &Value::object([]), None)
            .unwrap_err();
        assert_eq!(err, "missing pack dependency: p1:p2");
    }

    #[test]
    fn dependency_cycle_errors() {
        let packs = vec![pack("p1", vec!["p2"], vec![]), pack("p2", vec!["p1"], vec![])];
        let err = compile_baseline(&packs, &portfolio_one_target(), &empty_components(), &[], &Value::object([]), None)
            .unwrap_err();
        assert_eq!(err, "control pack dependency cycle: p1");
    }

    #[test]
    fn incompatible_duplicate_control_errors() {
        let packs = vec![
            pack("p1", vec![], vec![control("c1", vec![])]),
            pack("p2", vec![], vec![control("c1", vec![Value::str("prov.x")])]),
        ];
        let err = compile_baseline(&packs, &portfolio_one_target(), &empty_components(), &[], &Value::object([]), None)
            .unwrap_err();
        assert_eq!(err, "incompatible duplicate control: c1");
    }

    #[test]
    fn selected_control_gets_target_and_pack_ids_and_unimplemented_flag() {
        let packs = vec![pack("p1", vec![], vec![control("c1", vec![])])];
        let result = compile_baseline(&packs, &portfolio_one_target(), &empty_components(), &[], &Value::object([]), None)
            .unwrap();
        let controls = get(&result, "controls").unwrap();
        if let Value::Array(items) = controls {
            assert_eq!(items.len(), 1);
            let c = &items[0];
            assert_eq!(get(c, "targetIds"), Some(&Value::array([Value::str("t1")])));
            assert_eq!(get(c, "packIds"), Some(&Value::array([Value::str("p1")])));
            assert_eq!(get(c, "unimplemented"), Some(&Value::Bool(true)));
        } else {
            panic!("expected controls array");
        }
        assert_eq!(get(&result, "denominator"), Some(&Value::array([Value::str("c1")])));
        assert_eq!(get(&result, "unimplemented"), Some(&Value::array([Value::str("c1")])));
    }

    #[test]
    fn control_with_providers_is_not_unimplemented() {
        let packs = vec![pack("p1", vec![], vec![control("c1", vec![Value::str("prov.x")])])];
        let result = compile_baseline(&packs, &portfolio_one_target(), &empty_components(), &[], &Value::object([]), None)
            .unwrap();
        if let Value::Array(items) = get(&result, "controls").unwrap() {
            assert_eq!(get(&items[0], "unimplemented"), Some(&Value::Bool(false)));
        } else {
            panic!("expected controls array");
        }
        assert_eq!(get(&result, "unimplemented"), Some(&Value::array([])));
    }

    #[test]
    fn non_matching_selector_produces_trace_but_no_selected_control() {
        let never_selector = Value::object([("targetKinds", Value::array([Value::str("mobile")]))]);
        let ctl = Value::object([
            ("id", Value::str("c1")),
            ("selector", never_selector),
            ("providers", Value::array([])),
        ]);
        let packs = vec![pack("p1", vec![], vec![ctl])];
        let result = compile_baseline(&packs, &portfolio_one_target(), &empty_components(), &[], &Value::object([]), None)
            .unwrap();
        assert_eq!(get(&result, "controls"), Some(&Value::array([])));
        if let Value::Array(traces) = get(&result, "traces").unwrap() {
            assert_eq!(traces.len(), 1);
            assert_eq!(get(&traces[0], "selected"), Some(&Value::Bool(false)));
            assert_eq!(get(&traces[0], "targetId"), Some(&Value::str("t1")));
        } else {
            panic!("expected traces array");
        }
    }

    #[test]
    fn digest_is_present_and_stable() {
        let packs = vec![pack("p1", vec![], vec![control("c1", vec![])])];
        let a = compile_baseline(&packs, &portfolio_one_target(), &empty_components(), &[], &Value::object([]), None).unwrap();
        let b = compile_baseline(&packs, &portfolio_one_target(), &empty_components(), &[], &Value::object([]), None).unwrap();
        assert_eq!(get(&a, "digest"), get(&b, "digest"));
        if let Some(Value::String(d)) = get(&a, "digest") {
            assert!(d.starts_with("sha256:"));
        } else {
            panic!("expected digest string");
        }
    }

    #[test]
    fn compatible_ignores_keys_outside_contract_keys() {
        let a = Value::object([("id", Value::str("c1")), ("providers", Value::array([]))]);
        let b = Value::object([("id", Value::str("c2")), ("providers", Value::array([]))]);
        // `id` is not in CONTRACT_KEYS, so differing ids alone do not make
        // two control records incompatible.
        assert!(compatible(&a, &b));
    }
}
