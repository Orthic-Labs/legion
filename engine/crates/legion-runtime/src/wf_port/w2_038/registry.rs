//! Ported from src/lib/controls/packs/registry.mjs (chunk w2_038).

use crate::p5_core::controls_contracts::validate_pack;
use crate::p5_core::controls_support::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Converts a `serde_json::Value` (used only for file I/O in this module)
/// into the shared `controls_support::Value` that the ported
/// `validate_pack`/`validate_control`/`compile_baseline` all operate on.
fn from_json(value: &serde_json::Value) -> Value {
    match value {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => Value::Number(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(items) => Value::Array(items.iter().map(from_json).collect()),
        serde_json::Value::Object(map) => {
            Value::Object(map.iter().map(|(k, v)| (k.clone(), from_json(v))).collect())
        }
    }
}

/// Port of `loadControlPacks(root)`. The JS source's `async`/`readFile`
/// become synchronous `std::fs::read_to_string`; every thrown `Error`
/// becomes an `Err(message)`, matching text where the JS source's message is
/// data-independent (`invalid control pack index`, `missing control pack
/// dependency: ...`). A file-not-found or JSON-parse failure has no JS
/// equivalent message to match (the JS `readFile`/`JSON.parse` rejection
/// would propagate the host's own error text), so those are reported with a
/// path-qualified message instead of an empty catch -- unlike
/// `legion-topology`'s `load_control_packs`, which silently drops such
/// errors and returns an empty list (see this chunk's `mod.rs` finding).
pub fn load_control_packs(root: &Path) -> Result<Vec<Value>, String> {
    let index_path = root.join("registry/controls/packs/index.json");
    let index_text = std::fs::read_to_string(&index_path)
        .map_err(|e| format!("failed to read {}: {e}", index_path.display()))?;
    let index: serde_json::Value = serde_json::from_str(&index_text)
        .map_err(|e| format!("failed to parse {}: {e}", index_path.display()))?;

    let schema_ok = index.get("schemaVersion").and_then(serde_json::Value::as_f64) == Some(1.0);
    let packs_field = index.get("packs").and_then(serde_json::Value::as_array);
    let no_duplicates = packs_field
        .map(|items| {
            let set: BTreeSet<Option<&str>> = items.iter().map(serde_json::Value::as_str).collect();
            set.len() == items.len()
        })
        .unwrap_or(false);
    if !schema_ok || packs_field.is_none() || !no_duplicates {
        return Err("invalid control pack index".to_string());
    }

    let mut packs = Vec::new();
    for path_value in packs_field.unwrap() {
        let rel = path_value
            .as_str()
            .ok_or_else(|| "invalid control pack index".to_string())?;
        let pack_path = root.join(rel);
        let text = std::fs::read_to_string(&pack_path)
            .map_err(|e| format!("failed to read {}: {e}", pack_path.display()))?;
        let json: serde_json::Value = serde_json::from_str(&text)
            .map_err(|e| format!("failed to parse {}: {e}", pack_path.display()))?;
        let pack = from_json(&json);
        validate_pack(&pack)?;
        packs.push(pack);
    }

    let ids: BTreeSet<String> = packs
        .iter()
        .filter_map(|pack| pack_id(pack).map(str::to_string))
        .collect();
    for pack in &packs {
        let pid = pack_id(pack).unwrap_or("");
        if let Value::Object(map) = pack {
            if let Some(Value::Array(deps)) = map.get("dependencies") {
                for dep in deps {
                    if let Value::String(dep_id) = dep {
                        if !ids.contains(dep_id) {
                            return Err(format!("missing control pack dependency: {pid}:{dep_id}"));
                        }
                    }
                }
            }
        }
    }

    Ok(packs)
}

fn pack_id(pack: &Value) -> Option<&str> {
    match pack {
        Value::Object(map) => match map.get("id") {
            Some(Value::String(s)) => Some(s.as_str()),
            _ => None,
        },
        _ => None,
    }
}

/// Port of `packIndex(packs)`.
///
/// Deviation: the JS source flags a duplicate control id as incompatible by
/// comparing `JSON.stringify(old) !== JSON.stringify(control)`, i.e. a
/// literal-text compare that is sensitive to source object key order. This
/// port compares with `Value`'s derived `PartialEq` instead, which (since
/// `Value::Object` is a `BTreeMap`) is a structural, key-order-independent
/// comparison. That makes this port strictly *more* permissive than the JS
/// source (a harmlessly re-ordered duplicate control would pass here but
/// throw in JS); it can never accept two controls that actually differ in
/// value, and it matches how `compileBaseline`'s own `compatible()`
/// duplicate-control check (a canonical, sorted-key compare) treats equality
/// elsewhere in this same JS module family.
pub fn pack_index(packs: &[Value]) -> Result<BTreeMap<String, Value>, String> {
    let mut controls: BTreeMap<String, Value> = BTreeMap::new();
    for pack in packs {
        let control_list = match pack {
            Value::Object(map) => match map.get("controls") {
                Some(Value::Array(items)) => items.as_slice(),
                _ => &[],
            },
            _ => &[],
        };
        for control in control_list {
            // A control record carries a top-level "id" string field, same
            // shape as a pack's own "id" -- `pack_id` reads either.
            let Some(id) = pack_id(control).map(str::to_string) else {
                continue;
            };
            if let Some(old) = controls.get(&id) {
                if old != control {
                    return Err(format!("incompatible duplicate control: {id}"));
                }
            }
            controls.insert(id, control.clone());
        }
    }
    Ok(controls)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control(id: &str) -> Value {
        Value::object([("id", Value::str(id)), ("version", Value::Number(1.0))])
    }

    fn pack(id: &str, deps: Vec<&str>, controls: Vec<Value>) -> Value {
        Value::object([
            ("id", Value::str(id)),
            ("dependencies", Value::array(deps.into_iter().map(Value::str))),
            ("controls", Value::array(controls)),
        ])
    }

    #[test]
    fn pack_index_collects_controls_across_packs() {
        let packs = vec![
            pack("p1", vec![], vec![control("c1")]),
            pack("p2", vec![], vec![control("c2")]),
        ];
        let index = pack_index(&packs).unwrap();
        assert_eq!(index.len(), 2);
        assert!(index.contains_key("c1"));
        assert!(index.contains_key("c2"));
    }

    #[test]
    fn pack_index_allows_identical_duplicate_control() {
        let packs = vec![
            pack("p1", vec![], vec![control("c1")]),
            pack("p2", vec![], vec![control("c1")]),
        ];
        assert!(pack_index(&packs).is_ok());
    }

    #[test]
    fn pack_index_rejects_incompatible_duplicate_control() {
        let mut other = control("c1");
        if let Value::Object(map) = &mut other {
            map.insert("version".into(), Value::Number(2.0));
        }
        let packs = vec![
            pack("p1", vec![], vec![control("c1")]),
            pack("p2", vec![], vec![other]),
        ];
        let err = pack_index(&packs).unwrap_err();
        assert_eq!(err, "incompatible duplicate control: c1");
    }

    #[test]
    fn load_control_packs_reads_index_and_validates_dependencies() {
        let dir = std::env::temp_dir().join(format!(
            "w2_038_registry_test_{}_{}",
            std::process::id(),
            "ok"
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let packs_dir = dir.join("registry/controls/packs");
        std::fs::create_dir_all(&packs_dir).unwrap();
        std::fs::write(
            packs_dir.join("index.json"),
            r#"{"schemaVersion":1,"packs":["registry/controls/packs/a.json"]}"#,
        )
        .unwrap();
        std::fs::write(
            packs_dir.join("a.json"),
            r#"{
                "id":"pack.a","version":1,"class":"universal","dependencies":[],
                "source":{"kind":"internal","rights":"cleared"},
                "qualification":"unproven",
                "controls":[]
            }"#,
        )
        .unwrap();
        let packs = load_control_packs(&dir).unwrap();
        assert_eq!(packs.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_control_packs_rejects_missing_dependency() {
        let dir = std::env::temp_dir().join(format!(
            "w2_038_registry_test_{}_{}",
            std::process::id(),
            "missing_dep"
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let packs_dir = dir.join("registry/controls/packs");
        std::fs::create_dir_all(&packs_dir).unwrap();
        std::fs::write(
            packs_dir.join("index.json"),
            r#"{"schemaVersion":1,"packs":["registry/controls/packs/a.json"]}"#,
        )
        .unwrap();
        std::fs::write(
            packs_dir.join("a.json"),
            r#"{
                "id":"pack.a","version":1,"class":"universal","dependencies":["pack.missing"],
                "source":{"kind":"internal","rights":"cleared"},
                "qualification":"unproven",
                "controls":[]
            }"#,
        )
        .unwrap();
        let err = load_control_packs(&dir).unwrap_err();
        assert_eq!(err, "missing control pack dependency: pack.a:pack.missing");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_control_packs_rejects_duplicate_index_entries() {
        let dir = std::env::temp_dir().join(format!(
            "w2_038_registry_test_{}_{}",
            std::process::id(),
            "dup_index"
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let packs_dir = dir.join("registry/controls/packs");
        std::fs::create_dir_all(&packs_dir).unwrap();
        std::fs::write(
            packs_dir.join("index.json"),
            r#"{"schemaVersion":1,"packs":["a.json","a.json"]}"#,
        )
        .unwrap();
        let err = load_control_packs(&dir).unwrap_err();
        assert_eq!(err, "invalid control pack index");
        std::fs::remove_dir_all(&dir).ok();
    }
}
