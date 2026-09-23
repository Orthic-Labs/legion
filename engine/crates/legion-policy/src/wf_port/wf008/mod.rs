//! Chunk wf008 (area `src/lib/guard`, target crate `legion-policy`).
//!
//! Rust port of:
//!   - `src/lib/guard/compat/rules/policy-compiler.mjs`
//!
//! This module is additive only: the JS file remains source of truth until
//! CI parity is proven and a later packet deletes it.
//!
//! ## Dependency gap (see the wf008 report)
//!
//! This module needs `serde_json` in `legion-policy`'s *runtime*
//! dependencies (it is currently only a `[dev-dependencies]` entry). The
//! owner of this chunk may not edit `Cargo.toml`; the exact patch is filed
//! in the wf008 report for the integrator.
//!
//! ## Validation scope gap
//!
//! The JS compiler validates the *whole* compiled bundle with
//! `validatePolicyBundle` from `src/lib/guard/compat/policy/policy.mjs`
//! (a full JSON-Schema check against `policy-bundle-v1.schema.json`). That
//! module is a separate file, out of this chunk's ownership, and has not
//! been ported. This port instead validates only the `effectRules` array
//! this compiler actually rewrites, against the `effectRules.items` subset
//! of the same schema (see [`validate_effect_rules`]). A bundle whose
//! *other* top-level fields are malformed will not be caught here the way
//! the JS `compilePolicyRules` would catch it — that is a real, intentional
//! scope reduction, not an oversight, and should be closed by porting
//! `policy.mjs` and swapping this validation out for it.

use std::collections::{HashMap, HashSet};
use std::fmt;

use serde::Serialize;
use serde_json::Value;

/// Mirrors JS `PolicyRuleCompileError` (`src/lib/guard/compat/rules/policy-compiler.mjs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRuleCompileError(pub String);

impl fmt::Display for PolicyRuleCompileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyRuleCompileError {}

impl PolicyRuleCompileError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

/// One parsed controlled-English rule line. Field names and order mirror
/// the JS rule object's `{ effectClass, rule, approvalRequired,
/// trustMinimum, requiredEnforcement, note? }` shape exactly, so
/// `serde_json::to_value` round-trips into the same JSON the JS compiler
/// would emit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ParsedRule {
    pub effect_class: String,
    /// `"allow"` or `"deny"`.
    pub rule: String,
    pub approval_required: bool,
    pub trust_minimum: String,
    pub required_enforcement: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

// Mirrors the JS `LINE` regex exactly, including the permissive
// `enforcement=` alternation (`advisory` and `degraded` parse cleanly here;
// whether they are *valid* is a question for bundle/effect-rule
// validation, not the line grammar).
fn line_regex() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    RE.get_or_init(|| {
        regex::Regex::new(
            r#"^(allow|deny) ([A-Z_]+) approval=(required|none) trust=(capability-signature) enforcement=(strong|observed|advisory|unsupported|degraded)(?: note="((?:[^"\\]|\\.)*)")?$"#,
        )
        .expect("static LINE regex is valid")
    })
}

fn parse_note(value: &str, line_number: usize) -> Result<String, PolicyRuleCompileError> {
    // JS: `JSON.parse('"' + value + '"')` — the captured text is the
    // *interior* of a JSON string literal (already `\"`-escaped by the
    // grammar), so re-quoting and running it through a JSON string parser
    // is the faithful decode (handles `\"`, `\\`, `\n`, `\uXXXX`, ...).
    let wrapped = format!("\"{value}\"");
    serde_json::from_str::<String>(&wrapped)
        .map_err(|_| PolicyRuleCompileError::new(format!("line {line_number}: invalid note string")))
}

/// Parse controlled-English effect rules; comments and blank lines are
/// ignored. Mirrors JS `parsePolicyRules`.
pub fn parse_policy_rules(source: &str) -> Result<Vec<ParsedRule>, PolicyRuleCompileError> {
    let mut rules = Vec::new();
    let re = line_regex();
    // JS splits on `/\r?\n/`; `str::lines()` splits on `\n` and strips a
    // trailing `\r`, which is the same partition for both line endings.
    for (index, raw) in source.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line_number = index + 1;
        let caps = re
            .captures(line)
            .ok_or_else(|| PolicyRuleCompileError::new(format!("line {line_number}: invalid rule")))?;
        let rule = caps.get(1).unwrap().as_str().to_string();
        let effect_class = caps.get(2).unwrap().as_str().to_string();
        let approval = caps.get(3).unwrap().as_str();
        let trust_minimum = caps.get(4).unwrap().as_str().to_string();
        let required_enforcement = caps.get(5).unwrap().as_str().to_string();
        let note = match caps.get(6) {
            Some(m) => Some(parse_note(m.as_str(), line_number)?),
            None => None,
        };
        rules.push(ParsedRule {
            effect_class,
            rule,
            approval_required: approval == "required",
            trust_minimum,
            required_enforcement,
            note,
        });
    }
    Ok(rules)
}

const EFFECT_CLASS_ENUM: &[&str] = &[
    "FILE_WRITE",
    "FILE_DELETE",
    "FILE_MOVE",
    "COMMAND_EXEC",
    "NETWORK_EGRESS",
    "PROCESS_SPAWN",
    "CREDENTIAL_ACCESS",
    "DEPENDENCY_INSTALL",
    "VCS_COMMIT",
    "VCS_PUSH",
    "PUBLISH",
    "EXTERNAL_SIDE_EFFECT",
];
const RULE_ENUM: &[&str] = &["allow", "deny"];
const TRUST_MINIMUM_ENUM: &[&str] = &["host-connection-trust", "capability-signature", "unauthenticated"];
const REQUIRED_ENFORCEMENT_ENUM: &[&str] = &["strong", "observed", "read_only", "unsupported"];
const EFFECT_RULE_KEYS: &[&str] = &["effectClass", "rule", "approvalRequired", "trustMinimum", "requiredEnforcement", "note"];

/// Structural validation of a compiled `effectRules` array against the
/// `effectRules.items` subset of `policy-bundle-v1.schema.json`. See the
/// module-level "Validation scope gap" note: this is narrower than JS's
/// `validatePolicyBundle`, which checks the entire bundle.
fn validate_effect_rules(effect_rules: &[Value]) -> Vec<String> {
    let mut issues = Vec::new();
    for (i, entry) in effect_rules.iter().enumerate() {
        let Some(obj) = entry.as_object() else {
            issues.push(format!("effectRules[{i}]: must be an object"));
            continue;
        };
        for key in obj.keys() {
            if !EFFECT_RULE_KEYS.contains(&key.as_str()) {
                issues.push(format!("effectRules[{i}]: additional property '{key}' is not allowed"));
            }
        }
        for required in ["effectClass", "rule", "approvalRequired", "trustMinimum", "requiredEnforcement"] {
            if !obj.contains_key(required) {
                issues.push(format!("effectRules[{i}]: missing required property '{required}'"));
            }
        }
        if let Some(v) = obj.get("effectClass") {
            match v.as_str() {
                Some(s) if EFFECT_CLASS_ENUM.contains(&s) => {}
                _ => issues.push(format!("effectRules[{i}].effectClass: must be one of {EFFECT_CLASS_ENUM:?}")),
            }
        }
        if let Some(v) = obj.get("rule") {
            match v.as_str() {
                Some(s) if RULE_ENUM.contains(&s) => {}
                _ => issues.push(format!("effectRules[{i}].rule: must be one of {RULE_ENUM:?}")),
            }
        }
        if let Some(v) = obj.get("approvalRequired") {
            if !v.is_boolean() {
                issues.push(format!("effectRules[{i}].approvalRequired: must be a boolean"));
            }
        }
        if let Some(v) = obj.get("trustMinimum") {
            match v.as_str() {
                Some(s) if TRUST_MINIMUM_ENUM.contains(&s) => {}
                _ => issues.push(format!("effectRules[{i}].trustMinimum: must be one of {TRUST_MINIMUM_ENUM:?}")),
            }
        }
        if let Some(v) = obj.get("requiredEnforcement") {
            match v.as_str() {
                Some(s) if REQUIRED_ENFORCEMENT_ENUM.contains(&s) => {}
                _ => issues.push(format!(
                    "effectRules[{i}].requiredEnforcement: must be one of {REQUIRED_ENFORCEMENT_ENUM:?}"
                )),
            }
        }
        if let Some(v) = obj.get("note") {
            if !v.is_string() {
                issues.push(format!("effectRules[{i}].note: must be a string"));
            }
        }
    }
    issues
}

/// Replace only `effectRules` in a valid base policy, preserving every
/// other policy decision. Mirrors JS `compilePolicyRules`.
pub fn compile_policy_rules(source: &str, base: &Value) -> Result<Value, PolicyRuleCompileError> {
    let parsed = parse_policy_rules(source)?;

    let base_effect_rules = base.get("effectRules").and_then(Value::as_array);
    let Some(base_effect_rules) = base_effect_rules else {
        return Err(PolicyRuleCompileError::new("base policy has no effectRules"));
    };
    let base_classes: Vec<String> = base_effect_rules
        .iter()
        .map(|r| {
            r.get("effectClass")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        })
        .collect();

    let allowed: HashSet<&str> = base_classes.iter().map(String::as_str).collect();
    let mut seen: HashSet<String> = HashSet::new();
    for rule in &parsed {
        if !allowed.contains(rule.effect_class.as_str()) {
            return Err(PolicyRuleCompileError::new(format!(
                "unknown effect class: {}",
                rule.effect_class
            )));
        }
        if !seen.insert(rule.effect_class.clone()) {
            return Err(PolicyRuleCompileError::new(format!(
                "duplicate effect class: {}",
                rule.effect_class
            )));
        }
    }

    let missing: Vec<&String> = base_classes.iter().filter(|c| !seen.contains(c.as_str())).collect();
    if !missing.is_empty() {
        let joined = missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
        return Err(PolicyRuleCompileError::new(format!("missing effect class(es): {joined}")));
    }

    let by_class: HashMap<&str, &ParsedRule> = parsed.iter().map(|r| (r.effect_class.as_str(), r)).collect();
    let effect_rules: Vec<Value> = base_classes
        .iter()
        .map(|c| serde_json::to_value(by_class.get(c.as_str()).expect("every base class was checked above")))
        .collect::<Result<_, _>>()
        .expect("ParsedRule always serializes");

    let mut bundle = base.clone();
    match bundle.as_object_mut() {
        Some(obj) => {
            obj.insert("effectRules".to_string(), Value::Array(effect_rules.clone()));
        }
        None => return Err(PolicyRuleCompileError::new("base policy has no effectRules")),
    }

    let issues = validate_effect_rules(&effect_rules);
    if !issues.is_empty() {
        return Err(PolicyRuleCompileError::new(format!(
            "compiled policy failed validation: {}",
            issues.join("; ")
        )));
    }

    Ok(bundle)
}

/// Mirrors JS `compilePolicyFiles`: reads a base policy JSON file and a
/// rule-source text file from disk and compiles them.
pub fn compile_policy_files(source_path: &std::path::Path, base_path: &std::path::Path) -> Result<Value, PolicyRuleCompileError> {
    let base_text = std::fs::read_to_string(base_path).map_err(|error| {
        PolicyRuleCompileError::new(format!("base policy unreadable: {} ({error})", base_path.display()))
    })?;
    let base: Value = serde_json::from_str(&base_text).map_err(|error| {
        PolicyRuleCompileError::new(format!("base policy unreadable: {} ({error})", base_path.display()))
    })?;

    let source = std::fs::read_to_string(source_path).map_err(|error| {
        PolicyRuleCompileError::new(format!("rule source unreadable: {} ({error})", source_path.display()))
    })?;

    compile_policy_rules(&source, &base)
}

/// Mirrors JS `renderPolicy`: `JSON.stringify(bundle, null, 2) + "\n"`.
pub fn render_policy(bundle: &Value) -> String {
    let mut rendered = serde_json::to_string_pretty(bundle).expect("bundle is already valid JSON");
    rendered.push('\n');
    rendered
}
