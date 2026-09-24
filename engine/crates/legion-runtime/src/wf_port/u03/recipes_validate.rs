//! Port of `src/lib/recipes/validate.mjs`.
//!
//! Depends on `hasSlashSkill` (already ported as
//! `p7_host::lenses::has_slash_skill`) and, indirectly, on
//! `validateCommercialLenses(root).lensIds` — which JS computes as the
//! sorted list of `id` fields read from each lens file named in
//! `src/registry/lenses/commercial-routing.json`. This port reads that same
//! narrow slice (ids only) rather than re-running full lens validation,
//! which belongs to a different file/packet (`src/lib/lenses/routing.mjs`,
//! partially ported in `p7_host::lenses::validate_lens_records`).

use crate::p7_host::lenses::has_slash_skill;
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

static PRIVATE_FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9-]*$").unwrap());

const EXPECTED_RECIPES: [&str; 4] = [
    "brand-assets",
    "frontend-design",
    "product-validation",
    "research-workflow",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipeFinding {
    pub code: String,
    pub recipe_id: Option<String>,
    pub detail: String,
}

/// File-reading seam so tests never touch a real filesystem.
pub trait RecipeSource {
    /// `src/registry/recipes/index.json` — must return `{"recipes": [...]}`.
    fn recipes_index(&self) -> Result<Value, String>;
    /// `src/recipes/<id>.json`.
    fn recipe(&self, id: &str) -> Result<Value, String>;
    /// The sorted lens ids that `validateCommercialLenses(root).lensIds`
    /// would return.
    fn lens_ids(&self) -> Result<Vec<String>, String>;
}

/// Port of `validateInternalRecipes(root)`.
pub fn validate_internal_recipes(source: &dyn RecipeSource) -> Result<(bool, Vec<RecipeFinding>, Vec<String>), String> {
    let mut findings = Vec::new();
    let lens_ids: HashSet<String> = source.lens_ids()?.into_iter().collect();

    let index = source.recipes_index()?;
    let listed: Vec<String> = index
        .get("recipes")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let mut records = Vec::new();
    for id in &listed {
        records.push(source.recipe(id)?);
    }
    let by_id: HashMap<String, Value> = records
        .iter()
        .filter_map(|record| record.get("id").and_then(Value::as_str).map(|id| (id.to_string(), record.clone())))
        .collect();

    let unique_listed: HashSet<&String> = listed.iter().collect();
    let expected: HashSet<&str> = EXPECTED_RECIPES.iter().copied().collect();
    if unique_listed.len() != EXPECTED_RECIPES.len() || listed.iter().any(|id| !expected.contains(id.as_str())) {
        findings.push(RecipeFinding {
            code: "recipe-roster".into(),
            recipe_id: None,
            detail: "registry must contain only four internal recipes".into(),
        });
    }

    for record in &records {
        let recipe_id = record.get("id").and_then(Value::as_str).unwrap_or_default().to_string();

        let internal_ok = record.get("internal").and_then(Value::as_bool) == Some(true);
        let availability_ok = record.get("availability").and_then(Value::as_str) == Some("unavailable");
        if !internal_ok || !availability_ok {
            findings.push(RecipeFinding {
                code: "recipe-availability".into(),
                recipe_id: Some(recipe_id.clone()),
                detail: "Wave 1 recipes remain internal & unavailable".into(),
            });
        }

        let private_fields_ok = match record.get("privateFields").and_then(Value::as_array) {
            Some(fields) => fields.iter().all(|f| f.as_str().is_some_and(|s| PRIVATE_FIELD.is_match(s))),
            None => false,
        };
        if !private_fields_ok {
            findings.push(RecipeFinding {
                code: "private-fields".into(),
                recipe_id: Some(recipe_id.clone()),
                detail: "private fields must use safe explicit names".into(),
            });
        }

        for lens in record.get("lenses").and_then(Value::as_array).unwrap_or(&Vec::new()) {
            if let Some(lens_id) = lens.as_str() {
                if !lens_ids.contains(lens_id) {
                    findings.push(RecipeFinding {
                        code: "recipe-reference".into(),
                        recipe_id: Some(recipe_id.clone()),
                        detail: format!("unknown lens: {lens_id}"),
                    });
                }
            }
        }

        for dep in record.get("dependsOn").and_then(Value::as_array).unwrap_or(&Vec::new()) {
            if let Some(dep_id) = dep.as_str() {
                if !by_id.contains_key(dep_id) {
                    findings.push(RecipeFinding {
                        code: "recipe-reference".into(),
                        recipe_id: Some(recipe_id.clone()),
                        detail: format!("unknown recipe: {dep_id}"),
                    });
                }
            }
        }

        if has_slash_skill(record) {
            findings.push(RecipeFinding {
                code: "slash-skill".into(),
                recipe_id: Some(recipe_id.clone()),
                detail: "recipe leaks a slash skill".into(),
            });
        }
    }

    let mut ids: Vec<String> = by_id.keys().cloned().collect();
    ids.sort();
    for id in &ids {
        let mut active = HashSet::new();
        let mut done = HashSet::new();
        visit(id, &by_id, &mut active, &mut done, &mut findings);
    }

    let ok = findings.is_empty();
    Ok((ok, findings, ids))
}

fn visit(
    id: &str,
    by_id: &HashMap<String, Value>,
    active: &mut HashSet<String>,
    done: &mut HashSet<String>,
    findings: &mut Vec<RecipeFinding>,
) {
    if done.contains(id) {
        return;
    }
    if active.contains(id) {
        findings.push(RecipeFinding {
            code: "recipe-dag".into(),
            recipe_id: Some(id.to_string()),
            detail: "recipe dependency cycle".into(),
        });
        return;
    }
    active.insert(id.to_string());
    if let Some(record) = by_id.get(id) {
        for dep in record.get("dependsOn").and_then(Value::as_array).unwrap_or(&Vec::new()) {
            if let Some(dep_id) = dep.as_str() {
                if by_id.contains_key(dep_id) {
                    visit(dep_id, by_id, active, done, findings);
                }
            }
        }
    }
    active.remove(id);
    done.insert(id.to_string());
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashMap as StdHashMap;

    struct FakeSource {
        index: Value,
        recipes: StdHashMap<String, Value>,
        lens_ids: Vec<String>,
    }

    impl RecipeSource for FakeSource {
        fn recipes_index(&self) -> Result<Value, String> {
            Ok(self.index.clone())
        }
        fn recipe(&self, id: &str) -> Result<Value, String> {
            self.recipes
                .get(id)
                .cloned()
                .ok_or_else(|| format!("missing recipe {id}"))
        }
        fn lens_ids(&self) -> Result<Vec<String>, String> {
            Ok(self.lens_ids.clone())
        }
    }

    fn good_recipe(id: &str) -> Value {
        json!({
            "id": id,
            "internal": true,
            "availability": "unavailable",
            "privateFields": ["safe-field"],
            "lenses": [],
            "dependsOn": [],
        })
    }

    fn valid_source() -> FakeSource {
        let mut recipes = StdHashMap::new();
        for id in EXPECTED_RECIPES {
            recipes.insert(id.to_string(), good_recipe(id));
        }
        FakeSource {
            index: json!({"recipes": EXPECTED_RECIPES}),
            recipes,
            lens_ids: vec![],
        }
    }

    #[test]
    fn valid_roster_has_no_findings() {
        let source = valid_source();
        let (ok, findings, ids) = validate_internal_recipes(&source).unwrap();
        assert!(ok, "unexpected findings: {findings:?}");
        assert_eq!(ids, {
            let mut v: Vec<String> = EXPECTED_RECIPES.iter().map(|s| s.to_string()).collect();
            v.sort();
            v
        });
    }

    #[test]
    fn flags_wrong_roster() {
        let mut source = valid_source();
        source.index = json!({"recipes": ["brand-assets"]});
        let (ok, findings, _) = validate_internal_recipes(&source).unwrap();
        assert!(!ok);
        assert!(findings.iter().any(|f| f.code == "recipe-roster"));
    }

    #[test]
    fn flags_availability_and_private_fields() {
        let mut source = valid_source();
        source.recipes.insert(
            "brand-assets".to_string(),
            json!({"id": "brand-assets", "internal": false, "availability": "available", "privateFields": ["Bad Field"]}),
        );
        let (ok, findings, _) = validate_internal_recipes(&source).unwrap();
        assert!(!ok);
        assert!(findings.iter().any(|f| f.code == "recipe-availability"));
        assert!(findings.iter().any(|f| f.code == "private-fields"));
    }

    #[test]
    fn flags_unknown_lens_and_dependency_and_slash_skill() {
        let mut source = valid_source();
        source.recipes.insert(
            "brand-assets".to_string(),
            json!({
                "id": "brand-assets",
                "internal": true,
                "availability": "unavailable",
                "privateFields": [],
                "lenses": ["no-such-lens"],
                "dependsOn": ["no-such-recipe"],
                "note": "run /audit-fix now",
            }),
        );
        let (ok, findings, _) = validate_internal_recipes(&source).unwrap();
        assert!(!ok);
        assert!(findings.iter().any(|f| f.code == "recipe-reference" && f.detail.contains("unknown lens")));
        assert!(findings.iter().any(|f| f.code == "recipe-reference" && f.detail.contains("unknown recipe")));
        assert!(findings.iter().any(|f| f.code == "slash-skill"));
    }

    #[test]
    fn detects_dependency_cycle() {
        let mut source = valid_source();
        source.recipes.insert(
            "brand-assets".to_string(),
            json!({"id": "brand-assets", "internal": true, "availability": "unavailable", "privateFields": [], "dependsOn": ["frontend-design"]}),
        );
        source.recipes.insert(
            "frontend-design".to_string(),
            json!({"id": "frontend-design", "internal": true, "availability": "unavailable", "privateFields": [], "dependsOn": ["brand-assets"]}),
        );
        let (ok, findings, _) = validate_internal_recipes(&source).unwrap();
        assert!(!ok);
        assert!(findings.iter().any(|f| f.code == "recipe-dag"));
    }

    #[test]
    fn accepts_known_lens() {
        let mut source = valid_source();
        source.lens_ids = vec!["known-lens".to_string()];
        source.recipes.insert(
            "brand-assets".to_string(),
            json!({"id": "brand-assets", "internal": true, "availability": "unavailable", "privateFields": [], "lenses": ["known-lens"], "dependsOn": []}),
        );
        let (ok, findings, _) = validate_internal_recipes(&source).unwrap();
        assert!(ok, "unexpected findings: {findings:?}");
    }
}
