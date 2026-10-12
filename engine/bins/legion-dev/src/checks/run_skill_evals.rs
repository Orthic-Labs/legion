// Deterministic executor for the skill-eval corpus (`skills/**/evals/*.json`).
//
// Legion has no native natural-language classifier: per `doctrine/legion.md`
// the always-on orchestration model performs semantic routing, and the
// deterministic runtime only validates selected ids and resolves explicit
// aliases. This runner therefore executes the one deterministic router that
// exists, explicit slash-alias resolution (`/name` at the start of a prompt,
// optionally namespaced `/legion:name`), against the packaged skill names.
//
// Alias resolution is reported separately from behavioral evaluation. It can
// establish only the explicit alias target; it cannot pass output-quality,
// safety, pressure, compatibility, or natural-language routing expectations.
// Exit status is nonzero on any deterministic mismatch.
//
// Optional observation input uses `legion-skill-routing-observations/v1` with
// top-level producer/model_config metadata and per-row source_path, category,
// case_id, three SHA-256 bindings, output_ref, trace_ref, and all six observed
// dimensions. It records observations supplied by a caller; it never invokes a model.

use super::skill_evals::{is_eval_file, known_names};
use super::tracked_files;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

const OBSERVATION_SCHEMA: &str = "legion-skill-routing-observations/v1";
const DIMENSIONS: [&str; 6] = [
    "shouldRoute",
    "firstRankedCapability",
    "authority",
    "routeMode",
    "semanticRequirement",
    "contextSelection",
];

const CASE_ARRAYS: [&str; 7] = [
    "should_trigger",
    "should_not_trigger",
    "output_quality",
    "safety",
    "pressure",
    "compatibility",
    "human_quality",
];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BundleResult {
    pub passed: usize,
    pub alias_passed: usize,
    pub observed_cases: usize,
    pub failed: usize,
    pub requires_model: usize,
    pub skipped: usize,
}

#[derive(Debug, Default)]
pub struct Summary {
    pub bundles: BTreeMap<String, BundleResult>,
    pub mismatches: Vec<String>,
    pub provenance: Option<Value>,
}

impl Summary {
    pub fn ok(&self) -> bool {
        self.mismatches.is_empty() && !self.bundles.is_empty()
    }
}

/// Explicit-alias router: the leading `/name` of a prompt, without a
/// `legion:` namespace, or `None` when the prompt is not an alias invocation.
fn alias_name(prompt: &str) -> Option<String> {
    let rest = prompt.trim_start().strip_prefix('/')?;
    let end = rest
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ':')))
        .unwrap_or(rest.len());
    let name = &rest[..end];
    if name.is_empty() {
        return None;
    }
    Some(name.strip_prefix("legion:").unwrap_or(name).to_string())
}

/// Eval files that are specifications rather than case corpora. Each is
/// named here explicitly; every other eval file must yield at least one case.
const NON_CASE_EVAL_FILES: &[&str] = &[
    // Specification only, not runnable (its own `purpose` says so).
    "skills/commit/evals/evidence-gauntlet.json",
];

enum Outcome {
    Pass,
    AliasPass,
    Fail(String),
    RequiresModel,
    Skip,
}

fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn required_text<'a>(value: Option<&'a Value>, label: &str) -> Result<&'a str, String> {
    value
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| format!("{label} must be a non-empty string"))
}

fn assertion_value<'a>(case: &'a Value, kind: &str) -> Option<&'a Value> {
    case.get("assertions")?
        .as_array()?
        .iter()
        .find(|assertion| assertion.get("type").and_then(Value::as_str) == Some(kind))?
        .get("value")
}

fn observation_key(source: &str, category: &str, case_id: &str) -> String {
    format!("{source}#{category}/{case_id}")
}

fn tracked_bundle_hash(root: &Path, files: &[String], source: &str) -> Result<String, String> {
    let bundle_dir = source
        .rsplit_once("/evals/")
        .map(|(dir, _)| dir)
        .ok_or_else(|| format!("observation source is not under an evals directory: {source}"))?;
    let prefix = format!("{bundle_dir}/");
    let mut hasher = Sha256::new();
    let mut found = false;
    let mut sources: Vec<&str> = files
        .iter()
        .filter(|path| path.starts_with(&prefix))
        .map(String::as_str)
        .collect();
    sources.sort_unstable();
    for rel in sources {
        let bytes =
            std::fs::read(root.join(rel)).map_err(|e| format!("read bundle source {rel}: {e}"))?;
        hasher.update(rel.as_bytes());
        hasher.update([0]);
        hasher.update(&bytes);
        hasher.update([0]);
        found = true;
    }
    if !found {
        return Err(format!(
            "no tracked source files found for bundle `{bundle_dir}`"
        ));
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn load_observations(
    path: &Path,
    root: &Path,
    files: &[String],
) -> Result<(BTreeMap<String, Value>, Value), String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("read observations {}: {e}", path.display()))?;
    let document: Value = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse observations {}: {e}", path.display()))?;
    if required_text(document.get("schema"), "schema")? != OBSERVATION_SCHEMA {
        return Err(format!(
            "observations schema must be `{OBSERVATION_SCHEMA}`"
        ));
    }
    let producer = document
        .get("producer")
        .and_then(Value::as_object)
        .ok_or_else(|| "observations producer must be an object".to_string())?;
    required_text(producer.get("name"), "producer.name")?;
    required_text(producer.get("version"), "producer.version")?;
    let model_config = document
        .get("model_config")
        .and_then(Value::as_object)
        .ok_or_else(|| "observations model_config must be an object".to_string())?;
    required_text(model_config.get("model"), "model_config.model")?;
    required_text(model_config.get("config_ref"), "model_config.config_ref")?;
    let rows = document
        .get("observations")
        .and_then(Value::as_array)
        .ok_or_else(|| "observations must be an array".to_string())?;
    let mut indexed = BTreeMap::new();
    for row in rows {
        let source = required_text(row.get("source_path"), "observation.source_path")?;
        if !is_eval_file(source) || !files.iter().any(|file| file == source) {
            return Err(format!(
                "observation source is not a tracked eval file: {source}"
            ));
        }
        let category = required_text(row.get("category"), "observation.category")?;
        if !CASE_ARRAYS.contains(&category) {
            return Err(format!("unknown observation category `{category}`"));
        }
        let id = required_text(row.get("case_id"), "observation.case_id")?;
        required_text(row.get("output_ref"), "observation.output_ref")?;
        required_text(row.get("trace_ref"), "observation.trace_ref")?;
        let source_bytes = std::fs::read(root.join(source))
            .map_err(|e| format!("read observation source {source}: {e}"))?;
        let source_doc: Value = serde_json::from_slice(&source_bytes)
            .map_err(|e| format!("parse observation source {source}: {e}"))?;
        let matches: Vec<&Value> = source_doc
            .get(category)
            .and_then(Value::as_array)
            .map(|cases| {
                cases
                    .iter()
                    .filter(|case| case.get("id").and_then(Value::as_str) == Some(id))
                    .collect()
            })
            .unwrap_or_default();
        if matches.len() != 1 {
            return Err(format!(
                "observation case must have one unique fixture: {source}#{category}/{id}"
            ));
        }
        let case = matches[0];
        let prompt = required_text(case.get("prompt"), "fixture prompt")?;
        let prompt_hash = sha256(prompt.as_bytes());
        let fixture_hash = sha256(&serde_json::to_vec(case).map_err(|e| e.to_string())?);
        let bundle_hash = tracked_bundle_hash(root, files, source)?;
        for (field, expected) in [
            ("prompt_sha256", prompt_hash),
            ("fixture_sha256", fixture_hash),
            ("source_bundle_sha256", bundle_hash),
        ] {
            if required_text(row.get(field), &format!("observation.{field}"))? != expected {
                return Err(format!(
                    "observation provenance mismatch for {source}#{category}/{id}: {field}"
                ));
            }
        }
        let raw_observation = row
            .get("observation")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                format!("observation dimensions missing for {source}#{category}/{id}")
            })?;
        let observation = normalize_observation(raw_observation);
        for dimension in DIMENSIONS {
            if !observation.contains_key(dimension) {
                return Err(format!(
                    "observation missing `{dimension}` for {source}#{category}/{id}"
                ));
            }
        }
        validate_observed_dimensions(&observation)
            .map_err(|error| format!("invalid dimensions for {source}#{category}/{id}: {error}"))?;
        let key = observation_key(source, category, id);
        if indexed.insert(key.clone(), row.clone()).is_some() {
            return Err(format!("duplicate observation: {key}"));
        }
    }
    let provenance = json!({
        "schema": OBSERVATION_SCHEMA,
        "producer": producer,
        "model_config": model_config,
        "observations_file_sha256": sha256(&bytes),
        "observation_count": rows.len(),
        "records": rows.iter().map(|row| json!({
            "source_path": row["source_path"],
            "category": row["category"],
            "case_id": row["case_id"],
            "prompt_sha256": row["prompt_sha256"],
            "fixture_sha256": row["fixture_sha256"],
            "source_bundle_sha256": row["source_bundle_sha256"],
            "output_ref": row["output_ref"],
            "trace_ref": row["trace_ref"]
        })).collect::<Vec<_>>()
    });
    Ok((indexed, provenance))
}

fn expected_dimensions(case: &Value, category: &str) -> Map<String, Value> {
    let mut expected = Map::new();
    let routing = ["routing", "expected_routing", "expectedRouting", "expected"]
        .iter()
        .find_map(|key| case.get(*key).and_then(Value::as_object));
    let lookup = |camel: &str, snake: &str, direct: &[&str]| -> Option<Value> {
        routing
            .and_then(|map| {
                map.get(camel).or_else(|| map.get(snake)).or_else(|| {
                    (camel == "authority")
                        .then(|| map.get("authorities"))
                        .flatten()
                })
            })
            .or_else(|| direct.iter().find_map(|key| case.get(*key)))
            .cloned()
    };
    if let Some(value) = lookup(
        "shouldRoute",
        "should_route",
        &[
            "expected_route",
            "expectedRoute",
            "should_route",
            "shouldRoute",
        ],
    )
    .or_else(|| assertion_value(case, "should_route").cloned())
    {
        expected.insert("shouldRoute".into(), value);
    } else if category == "should_trigger" {
        expected.insert("shouldRoute".into(), json!(true));
    } else if category == "should_not_trigger" {
        expected.insert("shouldRoute".into(), json!(false));
    } else if let Some(skill) = case.get("expected_skill") {
        expected.insert("shouldRoute".into(), json!(skill.as_str().is_some()));
    }
    if let Some(value) = lookup(
        "firstRankedCapability",
        "first_ranked_capability",
        &[
            "expected_first_ranked_capability",
            "expectedFirstRankedCapability",
            "expected_first_capability",
            "expectedFirstCapability",
            "expected_skill",
            "expectedSkill",
        ],
    )
    .or_else(|| assertion_value(case, "expected_skill").cloned())
    .or_else(|| assertion_value(case, "first_ranked_capability").cloned())
    .or_else(|| assertion_value(case, "first_capability").cloned())
    {
        expected.insert("firstRankedCapability".into(), value);
    }
    for (dimension, snake, direct) in [
        (
            "authority",
            "authority",
            &[
                "expected_authority",
                "expectedAuthority",
                "expected_attached_authority",
                "expected_attached_authorities",
                "expected_authorities",
                "expectedAttachedAuthority",
                "expectedAttachedAuthorities",
                "authority",
                "authorities",
                "attached_authority",
                "attached_authorities",
            ][..],
        ),
        (
            "routeMode",
            "route_mode",
            &[
                "expected_route_mode",
                "expectedRouteMode",
                "execution_mode",
                "executionMode",
                "expected_execution_mode",
                "expectedExecutionMode",
                "route_mode",
                "routeMode",
            ][..],
        ),
        (
            "semanticRequirement",
            "semantic_requirement",
            &[
                "expected_semantic_requirement",
                "expectedSemanticRequirement",
                "semantic_requirement_classification",
                "semanticRequirementClassification",
                "semantic_requirement",
                "semanticRequirement",
            ][..],
        ),
        (
            "contextSelection",
            "context_selection",
            &[
                "expected_context_selection",
                "expectedContextSelection",
                "expected_context_sources",
                "expectedContextSources",
                "context_sources",
                "contextSources",
                "context_selection",
                "contextSelection",
            ][..],
        ),
    ] {
        if let Some(value) = lookup(dimension, snake, direct).or_else(|| {
            match dimension {
                "authority" => assertion_value(case, "authority")
                    .or_else(|| assertion_value(case, "attached_authority"))
                    .or_else(|| assertion_value(case, "attached_authorities")),
                _ => None,
            }
            .cloned()
        }) {
            expected.insert(dimension.into(), value);
        }
    }
    expected
}

fn normalize_observation(raw: &Map<String, Value>) -> Map<String, Value> {
    let route = raw.get("route").and_then(Value::as_object).unwrap_or(raw);
    let first = [
        "firstRankedCapability",
        "first_ranked_capability",
        "selectedCapability",
        "selected_capability",
    ]
    .iter()
    .find_map(|key| route.get(*key))
    .cloned()
    .or_else(|| {
        let ranked = [
            "rankedCapabilities",
            "ranked_capabilities",
            "capabilities",
            "selectedCapabilities",
            "selected_capabilities",
            "ranked",
        ]
        .iter()
        .find_map(|key| route.get(*key));
        ranked.and_then(|ranked| ranked.as_array()).map(|items| {
            let item = items.first();
            item.map(|item| {
                item.as_object()
                    .and_then(|object| {
                        ["id", "capability", "name"]
                            .iter()
                            .find_map(|key| object.get(*key))
                    })
                    .cloned()
                    .unwrap_or_else(|| item.clone())
            })
            .unwrap_or(Value::Null)
        })
    });
    let copy_alias = |target: &str, aliases: &[&str]| -> Option<Value> {
        aliases
            .iter()
            .find_map(|key| route.get(*key))
            .cloned()
            .map(|value| {
                if matches!(target, "routeMode" | "semanticRequirement") {
                    value
                        .as_str()
                        .map(|text| json!(text.to_ascii_uppercase()))
                        .unwrap_or(value)
                } else {
                    value
                }
            })
    };
    let mut normalized = Map::new();
    if let Some(value) = copy_alias("shouldRoute", &["shouldRoute", "should_route", "routed"]) {
        normalized.insert("shouldRoute".into(), value);
    }
    if let Some(value) = first {
        normalized.insert("firstRankedCapability".into(), value);
    }
    if let Some(value) = copy_alias(
        "authority",
        &[
            "authority",
            "authorities",
            "attachedAuthority",
            "attached_authority",
            "attachedAuthorities",
            "attached_authorities",
        ],
    ) {
        normalized.insert("authority".into(), value);
    }
    if let Some(value) = copy_alias(
        "routeMode",
        &[
            "routeMode",
            "route_mode",
            "mode",
            "execution_mode",
            "executionMode",
            "execution",
        ],
    ) {
        normalized.insert("routeMode".into(), value);
    }
    if let Some(value) = copy_alias(
        "semanticRequirement",
        &["semanticRequirement", "semantic_requirement"],
    ) {
        normalized.insert("semanticRequirement".into(), value);
    }
    if let Some(value) = copy_alias(
        "contextSelection",
        &[
            "contextSelection",
            "context_selection",
            "context",
            "contextSources",
            "context_sources",
            "selectedContext",
            "selected_context",
        ],
    ) {
        let value = value
            .as_object()
            .and_then(|object| {
                ["selected", "sources", "selectedSources", "selected_sources"]
                    .iter()
                    .find_map(|key| object.get(*key))
                    .cloned()
            })
            .unwrap_or(value);
        normalized.insert("contextSelection".into(), value);
    }
    normalized
}

fn validate_observed_dimensions(observation: &Map<String, Value>) -> Result<(), String> {
    let observation = normalize_observation(observation);
    let observation = &observation;
    let should_route = observation
        .get("shouldRoute")
        .or_else(|| observation.get("should_route"));
    if !should_route.is_some_and(Value::is_boolean) {
        return Err("shouldRoute must be boolean".into());
    }
    let first = observation
        .get("firstRankedCapability")
        .or_else(|| observation.get("first_ranked_capability"));
    if !first.is_some_and(|value| value.is_null() || value.is_string()) {
        return Err("firstRankedCapability must be a string or null".into());
    }
    let authority = observation
        .get("authority")
        .or_else(|| observation.get("attachedAuthority"));
    if !authority.is_some_and(|value| {
        value.as_array().is_some_and(|items| {
            items.iter().all(|item| {
                item.as_str()
                    .is_some_and(|role| ["sage", "alchemist", "oracle"].contains(&role))
            })
        }) || value.as_object().is_some_and(|map| {
            ["sage", "alchemist", "oracle"]
                .iter()
                .all(|role| map.get(*role).is_some_and(Value::is_boolean))
        })
    }) {
        return Err("authority must list known roles or map each role to boolean".into());
    }
    for (field, allowed) in [
        ("routeMode", &["DIRECT", "MACHINERY"][..]),
        (
            "semanticRequirement",
            &["FORBIDDEN", "CONDITIONAL", "REQUIRED"][..],
        ),
    ] {
        let value = observation
            .get(field)
            .or_else(|| {
                observation.get(if field == "routeMode" {
                    "route_mode"
                } else {
                    "semantic_requirement"
                })
            })
            .and_then(Value::as_str)
            .map(str::to_ascii_uppercase);
        if !value.is_some_and(|value| allowed.contains(&value.as_str())) {
            return Err(format!("{field} has invalid or missing value"));
        }
    }
    let context = observation
        .get("contextSelection")
        .or_else(|| observation.get("context_selection"));
    if !context.is_some_and(|value| {
        value
            .as_array()
            .is_some_and(|items| items.iter().all(Value::is_string))
            || value.as_object().is_some_and(|map| {
                map.get("selected")
                    .and_then(Value::as_array)
                    .is_some_and(|items| items.iter().all(Value::is_string))
            })
    }) {
        return Err("contextSelection must be string[] or an object with selected[]".into());
    }
    Ok(())
}

fn score_observation(case: &Value, category: &str, observed: &Value) -> Result<Outcome, String> {
    let raw = observed
        .get("observation")
        .and_then(Value::as_object)
        .ok_or_else(|| "observation dimensions missing".to_string())?;
    let actual = normalize_observation(raw);
    let mut specified = 0;
    let mut failures = Vec::new();
    for (dimension, expected) in expected_dimensions(case, category) {
        let actual_value = actual.get(&dimension).cloned().unwrap_or(Value::Null);
        let expected = if matches!(dimension.as_str(), "routeMode" | "semanticRequirement") {
            expected
                .as_str()
                .map(|s| json!(s.to_ascii_uppercase()))
                .unwrap_or(expected)
        } else {
            expected
        };
        let actual_value = if matches!(dimension.as_str(), "routeMode" | "semanticRequirement") {
            actual_value
                .as_str()
                .map(|s| json!(s.to_ascii_uppercase()))
                .unwrap_or(actual_value)
        } else {
            actual_value
        };
        specified += 1;
        let matches = if dimension == "contextSelection" {
            context_matches(&expected, &actual_value)
        } else {
            expected == actual_value
        };
        if !matches {
            failures.push(format!(
                "{dimension}: expected {expected}, observed {actual_value}"
            ));
        }
    }
    if specified == 0 {
        return Ok(Outcome::RequiresModel);
    }
    if failures.is_empty() {
        Ok(Outcome::Pass)
    } else {
        Ok(Outcome::Fail(failures.join("; ")))
    }
}

fn context_matches(expected: &Value, actual: &Value) -> bool {
    if let (Some(expected), Some(actual)) = (expected.as_array(), actual.as_array()) {
        return expected == actual;
    }
    let Some(expected) = expected.as_object() else {
        return false;
    };
    let selected = actual
        .as_array()
        .or_else(|| actual.get("selected").and_then(Value::as_array));
    if selected.is_none() {
        return false;
    }
    let selected = selected.unwrap();
    if let Some(required) = expected.get("required").and_then(Value::as_array) {
        if !required.iter().all(|value| selected.contains(value)) {
            return false;
        }
    }
    if let Some(forbidden) = expected.get("forbidden").and_then(Value::as_array) {
        if forbidden.iter().any(|value| selected.contains(value)) {
            return false;
        }
    }
    expected
        .get("selected")
        .and_then(Value::as_array)
        .map_or(true, |want| want == selected)
}

/// `skills/<parent>/specialists/<branch>/evals/..` → `(parent, branch)`.
/// A specialist is a branch of its parent skill, not a skill of its own, so
/// an alias resolves to the parent and the fixture names the branch.
fn specialist_of(path: &str) -> Option<(&str, &str)> {
    let rest = path.strip_prefix("skills/")?;
    let (parent, rest) = rest.split_once("/specialists/")?;
    let (branch, _) = rest.split_once("/evals/")?;
    (!parent.contains('/') && !branch.contains('/')).then_some((parent, branch))
}

/// Explicit aliases from `src/config/capability-aliases.json` that point at a
/// skill (`"/jury": "/council quick"` → `jury` → `council`). Hook and tool
/// targets are not skills and are left out.
fn skill_aliases(root: &Path) -> BTreeMap<String, String> {
    let Ok(text) = std::fs::read_to_string(root.join("src/config/capability-aliases.json")) else {
        return BTreeMap::new();
    };
    let Ok(document) = serde_json::from_str::<Value>(&text) else {
        return BTreeMap::new();
    };
    document
        .get("aliases")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(alias, target)| {
            let alias = alias.strip_prefix('/')?;
            let target = target.as_str()?.strip_prefix('/')?;
            let skill = target.split_whitespace().next()?;
            Some((alias.to_string(), skill.to_string()))
        })
        .collect()
}

fn evaluate_case(
    case: &Value,
    known: &BTreeSet<String>,
    aliases: &BTreeMap<String, String>,
    rel: &str,
    category: &str,
) -> Outcome {
    let expected = case
        .get("expected_skill")
        .or_else(|| assertion_value(case, "expected_skill"));
    if let Some(value) = expected {
        if !value.is_string() && !value.is_null() {
            return Outcome::Fail("expected_skill must be a string or null".to_string());
        }
    }
    let Some(prompt) = case.get("prompt").and_then(Value::as_str) else {
        return if expected.is_some() {
            Outcome::Fail("case has expected_skill but no prompt".to_string())
        } else {
            Outcome::Fail("case has no prompt".to_string())
        };
    };
    let mut forbidden: Vec<&str> = case
        .get("forbidden_skills")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if let Some(assertion) = assertion_value(case, "forbidden_skill") {
        match assertion {
            Value::String(skill) => forbidden.push(skill),
            Value::Array(skills) => forbidden.extend(skills.iter().filter_map(Value::as_str)),
            _ => {
                return Outcome::Fail("forbidden_skill assertion must be a string or array".into())
            }
        }
    }
    let Some(name) = alias_name(prompt) else {
        return Outcome::RequiresModel;
    };
    if !matches!(
        category,
        "should_trigger" | "should_not_trigger" | "compatibility"
    ) {
        return Outcome::RequiresModel;
    }
    let selected = if known.contains(&name) {
        Some(name)
    } else {
        aliases
            .get(&name)
            .filter(|skill| known.contains(*skill))
            .cloned()
    };
    if let Some(sel) = &selected {
        if forbidden.contains(&sel.as_str()) {
            return Outcome::Fail(format!("selected forbidden skill `{sel}`"));
        }
    }
    match expected {
        Some(Value::String(want))
            if selected.as_deref() != Some(want.as_str())
                && !specialist_of(rel).is_some_and(|(parent, branch)| {
                    want == branch && selected.as_deref() == Some(parent)
                }) =>
        {
            Outcome::Fail(format!(
                "expected `{want}`, router selected {}",
                selected.map_or("nothing".to_string(), |s| format!("`{s}`"))
            ))
        }
        Some(Value::Null) if selected.is_some() => Outcome::Fail(format!(
            "expected no skill, router selected `{}`",
            selected.unwrap_or_default()
        )),
        _ => Outcome::AliasPass,
    }
}

fn bundle_of(path: &str) -> String {
    let dir = path.rsplit_once("/evals/").map(|(d, _)| d).unwrap_or("");
    dir.rsplit('/').next().unwrap_or(dir).to_string()
}

pub fn evaluate(root: &Path, files: &[String], bundles: &[String]) -> Summary {
    evaluate_with_observations(root, files, bundles, &BTreeMap::new(), None)
}

fn evaluate_with_observations(
    root: &Path,
    files: &[String],
    bundles: &[String],
    observations: &BTreeMap<String, Value>,
    provenance: Option<Value>,
) -> Summary {
    let known = known_names(files);
    let aliases = skill_aliases(root);
    let mut summary = Summary {
        provenance,
        ..Summary::default()
    };
    for rel in files.iter().filter(|f| is_eval_file(f)) {
        let bundle = bundle_of(rel);
        if !bundles.is_empty() && !bundles.contains(&bundle) {
            continue;
        }
        let entry = summary.bundles.entry(bundle).or_default();
        let doc: Value = match std::fs::read_to_string(root.join(rel))
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
        {
            Ok(d) => d,
            Err(e) => {
                entry.failed += 1;
                summary.mismatches.push(format!("{rel}: unreadable ({e})"));
                continue;
            }
        };
        let case_count: usize = CASE_ARRAYS
            .iter()
            .filter_map(|array| doc.get(*array).and_then(Value::as_array))
            .map(Vec::len)
            .sum();
        if case_count == 0 && !NON_CASE_EVAL_FILES.contains(&rel.as_str()) {
            entry.failed += 1;
            summary.mismatches.push(format!("no cases found in {rel}"));
            continue;
        }
        for array in CASE_ARRAYS {
            let Some(cases) = doc.get(array).and_then(Value::as_array) else {
                continue;
            };
            for case in cases {
                let id = case.get("id").and_then(Value::as_str).unwrap_or("?");
                let alias = evaluate_case(case, &known, &aliases, rel, array);
                match &alias {
                    Outcome::AliasPass => entry.alias_passed += 1,
                    Outcome::Skip => entry.skipped += 1,
                    Outcome::Fail(why) => {
                        entry.failed += 1;
                        summary
                            .mismatches
                            .push(format!("{rel}: {array}/{id}: {why}"));
                        continue;
                    }
                    Outcome::Pass | Outcome::RequiresModel => {}
                }
                let needs_output_judgment = matches!(
                    array,
                    "output_quality" | "safety" | "pressure" | "human_quality"
                );
                let key = observation_key(rel, array, id);
                match observations.get(&key) {
                    Some(observed) => match score_observation(case, array, observed) {
                        Ok(Outcome::Pass) => {
                            entry.passed += 1;
                            entry.observed_cases += 1;
                        }
                        Ok(Outcome::Fail(why)) => {
                            entry.failed += 1;
                            entry.observed_cases += 1;
                            summary.mismatches.push(format!("{key}: {why}"));
                        }
                        Ok(Outcome::RequiresModel | Outcome::Skip) => {
                            if !needs_output_judgment {
                                entry.requires_model += 1;
                            }
                        }
                        Ok(Outcome::AliasPass) => {
                            unreachable!("scorer never returns alias results")
                        }
                        Err(why) => {
                            entry.failed += 1;
                            summary
                                .mismatches
                                .push(format!("{key}: invalid observation ({why})"));
                        }
                    },
                    None => {
                        if !needs_output_judgment && !matches!(alias, Outcome::Skip) {
                            entry.requires_model += 1;
                        }
                    }
                }
                if needs_output_judgment {
                    // Routing observations cannot establish response/output quality.
                    entry.requires_model += 1;
                }
            }
        }
    }
    summary.mismatches.sort();
    summary
}

pub fn run(root: &Path, bundles: &[String], as_json: bool) -> bool {
    run_with_observations(root, bundles, as_json, None)
}

pub fn run_with_observations(
    root: &Path,
    bundles: &[String],
    as_json: bool,
    observations_path: Option<&Path>,
) -> bool {
    let files = match tracked_files(root) {
        Ok(files) => files,
        Err(e) => {
            eprintln!("run-skill-evals: {e}");
            return false;
        }
    };
    let loaded = match observations_path {
        Some(path) => match load_observations(path, root, &files) {
            Ok(loaded) => Some(loaded),
            Err(error) => {
                eprintln!("run-skill-evals: invalid observations: {error}");
                return false;
            }
        },
        None => None,
    };
    let (observations, provenance) = match loaded {
        Some((observations, provenance)) => (observations, Some(provenance)),
        None => (BTreeMap::new(), None),
    };
    let summary = evaluate_with_observations(root, &files, bundles, &observations, provenance);
    if as_json {
        let rows: BTreeMap<_, _> = summary
            .bundles
            .iter()
            .map(|(b, r)| {
                (
                    b.clone(),
                    json!({"observed-passed": r.passed, "alias-passed": r.alias_passed,
                           "observed-cases": r.observed_cases, "failed": r.failed,
                           "requires-model": r.requires_model, "skipped": r.skipped}),
                )
            })
            .collect();
        let out = json!({"ok": summary.ok(), "observation_provenance": summary.provenance,
            "bundles": rows, "mismatches": summary.mismatches});
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
        return summary.ok();
    }
    if summary.bundles.is_empty() {
        eprintln!("run-skill-evals: no matching skills/**/evals/*.json bundles found");
        return false;
    }
    println!(
        "{:<28} {:>7} {:>7} {:>9} {:>6} {:>14} {:>8}",
        "bundle", "obs-pass", "obs-cases", "alias-pass", "fail", "requires-model", "skipped"
    );
    let mut total = BundleResult::default();
    for (b, r) in &summary.bundles {
        println!(
            "{:<28} {:>7} {:>7} {:>9} {:>6} {:>14} {:>8}",
            b, r.passed, r.observed_cases, r.alias_passed, r.failed, r.requires_model, r.skipped
        );
        total.passed += r.passed;
        total.alias_passed += r.alias_passed;
        total.observed_cases += r.observed_cases;
        total.failed += r.failed;
        total.requires_model += r.requires_model;
        total.skipped += r.skipped;
    }
    println!(
        "{:<28} {:>7} {:>7} {:>9} {:>6} {:>14} {:>8}",
        "TOTAL",
        total.passed,
        total.observed_cases,
        total.alias_passed,
        total.failed,
        total.requires_model,
        total.skipped
    );
    println!(
        "observed results compare supplied six-dimension routing observations; this command does not run a model. Alias-pass is separate, and routing observations cannot pass output-quality cases."
    );
    for m in &summary.mismatches {
        eprintln!("{m}");
    }
    if !summary.ok() {
        eprintln!(
            "\nrun-skill-evals failed: {} deterministic mismatch(es)",
            summary.mismatches.len()
        );
    }
    summary.ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn setup(label: &str, cases: &str) -> (std::path::PathBuf, Vec<String>) {
        let dir =
            std::env::temp_dir().join(format!("legion-runevals-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("skills/alpha/evals")).unwrap();
        fs::write(dir.join("skills/alpha/SKILL.md"), "---\nname: alpha\n---\n").unwrap();
        fs::write(
            dir.join("skills/alpha/evals/evals.json"),
            format!(r#"{{"should_trigger":[{cases}]}}"#),
        )
        .unwrap();
        let files = vec![
            "skills/alpha/SKILL.md".to_string(),
            "skills/alpha/evals/evals.json".to_string(),
        ];
        (dir, files)
    }

    #[test]
    fn alias_case_passes() {
        let (dir, files) = setup(
            "pass",
            r#"{"id":"a","prompt":"/alpha do it","expected_skill":"alpha","forbidden_skills":[]}"#,
        );
        let s = evaluate(&dir, &files, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert!(s.ok(), "{:?}", s.mismatches);
        assert_eq!(s.bundles["alpha"].alias_passed, 1);
    }

    #[test]
    fn assertion_only_expected_skill_is_used_for_alias_resolution() {
        let (dir, files) = setup(
            "assertion-alias",
            r#"{"id":"a","prompt":"/alpha do it","assertions":[{"type":"expected_skill","value":"alpha"}]}"#,
        );
        let s = evaluate(&dir, &files, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert!(s.ok(), "{:?}", s.mismatches);
        assert_eq!(s.bundles["alpha"].alias_passed, 1);
        assert_eq!(s.bundles["alpha"].requires_model, 1);
    }

    #[test]
    fn unobserved_behavioral_case_without_top_level_expectation_requires_model() {
        let (dir, files) = setup(
            "missing-explicit-expectation",
            r#"{"id":"a","prompt":"please choose a capability"}"#,
        );
        let s = evaluate(&dir, &files, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert!(s.ok(), "{:?}", s.mismatches);
        assert_eq!(s.bundles["alpha"].skipped, 0);
        assert_eq!(s.bundles["alpha"].requires_model, 1);
    }

    #[test]
    fn forbidden_skill_assertion_is_checked_for_alias_resolution() {
        let (dir, files) = setup(
            "forbidden-assertion",
            r#"{"id":"a","prompt":"/alpha do it","assertions":[{"type":"forbidden_skill","value":"alpha"}]}"#,
        );
        let s = evaluate(&dir, &files, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(s.bundles["alpha"].failed, 1);
        assert!(s.mismatches[0].contains("selected forbidden skill"));
    }

    #[test]
    fn alias_mismatch_fails() {
        let (dir, files) = setup(
            "fail",
            r#"{"id":"a","prompt":"/alpha do it","expected_skill":"beta","forbidden_skills":[]}"#,
        );
        let s = evaluate(&dir, &files, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert!(!s.ok());
        assert_eq!(s.bundles["alpha"].failed, 1);
    }

    #[test]
    fn natural_language_requires_model_and_never_fails() {
        let (dir, files) = setup(
            "nl",
            r#"{"id":"a","prompt":"please do the thing","expected_skill":"beta","forbidden_skills":[]}"#,
        );
        let s = evaluate(&dir, &files, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert!(s.ok());
        assert_eq!(s.bundles["alpha"].requires_model, 1);
    }

    #[test]
    fn namespaced_alias_and_bundle_filter() {
        assert_eq!(alias_name("/legion:alpha x").as_deref(), Some("alpha"));
        assert_eq!(alias_name("no alias"), None);
        let (dir, files) = setup(
            "filter",
            r#"{"id":"a","prompt":"/zzz","expected_skill":"alpha"}"#,
        );
        let s = evaluate(&dir, &files, &["other".to_string()]);
        let _ = fs::remove_dir_all(&dir);
        assert!(s.bundles.is_empty());
    }

    #[test]
    fn mode_alias_selects_parent_skill_only() {
        let (dir, files) = setup(
            "mode-parent",
            r#"{"id":"a","prompt":"/legacy do it","expected_skill":"alpha"}"#,
        );
        std::fs::create_dir_all(dir.join("src/config")).unwrap();
        std::fs::write(
            dir.join("src/config/capability-aliases.json"),
            r#"{"aliases":{"/legacy":"/alpha implementation-plan"}}"#,
        )
        .unwrap();
        let s = evaluate(&dir, &files, &[]);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(s.ok(), "{:?}", s.mismatches);
        assert_eq!(s.bundles["alpha"].alias_passed, 1);
    }

    #[test]
    fn non_skill_alias_target_is_not_reported_as_skill_behavior() {
        let (dir, files) = setup(
            "tool-target",
            r#"{"id":"a","prompt":"/legacy do it","expected_skill":null}"#,
        );
        std::fs::create_dir_all(dir.join("src/config")).unwrap();
        std::fs::write(
            dir.join("src/config/capability-aliases.json"),
            r#"{"aliases":{"/legacy":"tool:execution-preflight"}}"#,
        )
        .unwrap();
        let s = evaluate(&dir, &files, &[]);
        let _ = std::fs::remove_dir_all(&dir);
        assert!(s.ok(), "{:?}", s.mismatches);
        assert_eq!(s.bundles["alpha"].alias_passed, 1);
    }

    #[test]
    fn expected_skill_without_prompt_is_a_mismatch() {
        let (dir, files) = setup("noprompt", r#"{"id":"a","expected_skill":"alpha"}"#);
        let s = evaluate(&dir, &files, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert!(!s.ok());
        assert_eq!(s.bundles["alpha"].failed, 1);
        assert!(s.mismatches[0].contains("expected_skill but no prompt"));
    }

    #[test]
    fn non_string_expected_skill_is_a_mismatch() {
        let (dir, files) = setup(
            "badtype",
            r#"{"id":"a","prompt":"/alpha x","expected_skill":5}"#,
        );
        let s = evaluate(&dir, &files, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert!(!s.ok());
        assert!(s.mismatches[0].contains("must be a string or null"));
    }

    #[test]
    fn eval_file_without_cases_is_a_mismatch() {
        let (dir, files) = setup("empty", "");
        let s = evaluate(&dir, &files, &[]);
        let _ = fs::remove_dir_all(&dir);
        assert!(!s.ok());
        assert!(s.mismatches[0].starts_with("no cases found in skills/alpha/evals/evals.json"));
    }

    #[test]
    fn observation_scores_all_six_dimensions_and_keeps_output_quality_unproven() {
        let case = json!({
            "expected_skill": "alpha",
            "routing": {
                "authority": [],
                "routeMode": "DIRECT",
                "semanticRequirement": "CONDITIONAL",
                "contextSelection": ["skill-index"]
            }
        });
        let observation = json!({
            "observation": {
                "shouldRoute": true,
                "rankedCapabilities": ["alpha"],
                "authority": [],
                "routeMode": "DIRECT",
                "semanticRequirement": "CONDITIONAL",
                "contextSelection": ["skill-index"]
            }
        });
        assert!(matches!(
            score_observation(&case, "should_trigger", &observation).unwrap(),
            Outcome::Pass
        ));

        let (dir, files) = setup(
            "quality",
            r#"{"id":"a","prompt":"/alpha do it","expected_skill":"alpha"}"#,
        );
        fs::write(
            dir.join(&files[1]),
            r#"{"output_quality":[{"id":"a","prompt":"/alpha do it","expected_skill":"alpha"}]}"#,
        )
        .unwrap();
        let key = observation_key(&files[1], "output_quality", "a");
        let mut observations = BTreeMap::new();
        observations.insert(key, observation);
        let summary = evaluate_with_observations(&dir, &files, &[], &observations, None);
        let _ = fs::remove_dir_all(&dir);
        let result = &summary.bundles["alpha"];
        assert_eq!(
            result.passed, 1,
            "routing observation may score only routing"
        );
        assert_eq!(result.requires_model, 1, "output quality remains ungraded");
        assert_eq!(
            result.alias_passed, 0,
            "quality fixtures cannot pass as aliases"
        );
    }

    #[test]
    fn invalid_observation_provenance_is_rejected_before_scoring() {
        let (dir, files) = setup(
            "provenance",
            r#"{"id":"a","prompt":"please route","expected_skill":"alpha"}"#,
        );
        let input = dir.join("observations.json");
        fs::write(
            &input,
            r#"{"schema":"legion-skill-routing-observations/v1","producer":{"name":"fixture","version":"1"},"model_config":{"model":"recorded","config_ref":"test"},"observations":[{}]}"#,
        )
        .unwrap();
        assert!(load_observations(&input, &dir, &files).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
