//! Shared implementation for the accounting-only language providers.
//!
//! This mirrors `src/providers/code/shared.mjs` without evaluating JavaScript.
//! The input and output stay JSON-shaped because the host adapter owns the
//! ProviderResult envelope while these providers preserve the source module's
//! permissive input contract.

use serde_json::{Map, Number, Value};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug)]
pub struct LanguageConfig {
    pub id: &'static str,
    pub extensions: &'static [&'static str],
    pub variants: &'static [(&'static str, &'static [&'static str])],
    pub tools: &'static [&'static str],
    pub required_context: &'static [&'static str],
}

impl LanguageConfig {
    pub const fn new(
        id: &'static str,
        extensions: &'static [&'static str],
        variants: &'static [(&'static str, &'static [&'static str])],
        tools: &'static [&'static str],
        required_context: &'static [&'static str],
    ) -> Self {
        Self {
            id,
            extensions,
            variants,
            tools,
            required_context,
        }
    }
}

/// Apply the exact accounting semantics of `analyzeLanguage(config, input)`.
pub fn analyze_language(config: &LanguageConfig, input: &Value) -> Value {
    let files = input
        .get("files")
        .filter(|value| !value.is_null())
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let selected = files
        .iter()
        .filter(|file| config.extensions.contains(&extension(file).as_str()))
        .collect::<Vec<_>>();

    let mut variants = Map::new();
    for (variant, extensions) in config.variants {
        let count = selected
            .iter()
            .filter(|file| extensions.contains(&extension(file).as_str()))
            .count();
        variants.insert((*variant).into(), Value::Number(Number::from(count)));
    }

    let mut tools = Vec::with_capacity(config.tools.len());
    for tool_id in config.tools {
        let tool = input
            .get("tools")
            .and_then(Value::as_object)
            .and_then(|tools| tools.get(*tool_id))
            .and_then(Value::as_object);
        let status = tool
            .and_then(|tool| tool.get("status"))
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or_else(|| Value::String("unavailable".into()));
        let identity = tool
            .and_then(|tool| tool.get("identity"))
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or(Value::Null);
        let artifact_digest = tool
            .and_then(|tool| tool.get("artifactDigest"))
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or(Value::Null);
        let scope = tool
            .and_then(|tool| tool.get("scope"))
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or(Value::Null);
        tools.push(Value::Object(Map::from_iter([
            ("id".into(), Value::String((*tool_id).into())),
            ("status".into(), status),
            ("identity".into(), identity),
            ("artifactDigest".into(), artifact_digest),
            ("scope".into(), scope),
        ])));
    }

    let mut coverage_gaps = Vec::new();
    if selected.is_empty() {
        coverage_gaps.push(Value::Object(Map::from_iter([
            ("kind".into(), Value::String("denominator-gap".into())),
            ("language".into(), Value::String(config.id.into())),
        ])));
    }
    for tool in &tools {
        let status = tool.get("status").unwrap_or(&Value::Null);
        let identity = tool.get("identity").and_then(Value::as_object);
        let executable_digest = identity.and_then(|value| value.get("executableDigest"));
        let artifact_digest = tool.get("artifactDigest");
        if !is_pass(status)
            || !identity
                .and_then(|value| value.get("version"))
                .is_some_and(js_truthy)
            || !is_sha256_digest(executable_digest)
            || !is_sha256_digest(artifact_digest)
        {
            coverage_gaps.push(Value::Object(Map::from_iter([
                ("kind".into(), Value::String("tool-evidence-gap".into())),
                (
                    "tool".into(),
                    tool.get("id").cloned().unwrap_or(Value::Null),
                ),
                ("status".into(), status.clone()),
            ])));
        }
    }
    let context = input.get("context").and_then(Value::as_object);
    for required in config.required_context {
        if context
            .and_then(|context| context.get(*required))
            .is_none_or(Value::is_null)
        {
            coverage_gaps.push(Value::Object(Map::from_iter([
                ("kind".into(), Value::String("context-gap".into())),
                ("context".into(), Value::String((*required).into())),
            ])));
        }
    }

    let boundaries = |key: &str| {
        Value::Array(
            input
                .get(key)
                .and_then(Value::as_array)
                .map(|values| values.iter().map(path_value).collect())
                .unwrap_or_default(),
        )
    };
    let facts = input
        .get("facts")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let components = input
        .get("components")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let platforms = input
        .get("platforms")
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));

    Value::Object(Map::from_iter([
        ("schemaVersion".into(), Value::Number(Number::from(1))),
        (
            "provider".into(),
            Value::String(format!("code.{}", config.id)),
        ),
        (
            "denominator".into(),
            Value::Object(Map::from_iter([
                ("kind".into(), Value::String(format!("{}-files", config.id))),
                (
                    "expected".into(),
                    Value::Number(Number::from(selected.len())),
                ),
                (
                    "examined".into(),
                    Value::Number(Number::from(selected.len())),
                ),
                ("variants".into(), Value::Object(variants)),
            ])),
        ),
        ("toolEvidence".into(), Value::Array(tools)),
        (
            "boundaries".into(),
            Value::Object(Map::from_iter([
                ("generated".into(), boundaries("generated")),
                ("vendor".into(), boundaries("vendor")),
                ("components".into(), components),
                ("platforms".into(), platforms),
            ])),
        ),
        ("facts".into(), facts),
        ("coverageGaps".into(), Value::Array(coverage_gaps.clone())),
        (
            "complete".into(),
            Value::Bool(!selected.is_empty() && coverage_gaps.is_empty()),
        ),
    ]))
}

fn path_value(file: &Value) -> Value {
    Value::String(path_of(file))
}

fn path_of(file: &Value) -> String {
    let value = file
        .get("path")
        .filter(|value| !value.is_null())
        .unwrap_or(file);
    js_string(value).replace('\\', "/")
}

fn extension(file: &Value) -> String {
    path_of(file)
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

fn js_string(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => values.iter().map(js_string).collect::<Vec<_>>().join(","),
        Value::Object(_) => "[object Object]".into(),
    }
}

fn is_pass(value: &Value) -> bool {
    value.as_str() == Some("pass")
}

fn js_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(value) => value.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(_) | Value::Object(_) => true,
    }
}

fn is_sha256_digest(value: Option<&Value>) -> bool {
    let Some(Value::String(value)) = value else {
        return false;
    };
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Convert a source-style analysis object into the stable fields consumed by
/// a `ProviderExecutor` adapter. This deliberately does not invent findings,
/// candidates, errors, or coverage gaps beyond those emitted by analysis.
pub fn provider_details(analysis: Value) -> BTreeMap<String, Value> {
    BTreeMap::from([("analysis".into(), analysis)])
}
