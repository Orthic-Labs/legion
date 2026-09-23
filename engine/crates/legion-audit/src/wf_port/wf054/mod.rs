//! Port of the security-surface-model extractor chunk wf054:
//!
//! - `src/providers/security/model-extractors/common.mjs` — the shared `entity`/`relation`/
//!   `fact`/`controlEntity` constructors (Security Appendix §10.3, deterministic ids,
//!   assertion-labeled) plus `extractCommon` (Security Appendix §11.1): repository-artifact
//!   entities from the file list and package manifests.
//! - `src/providers/security/model-extractors/cloud.mjs` — cloud extractor (B7-007):
//!   Terraform/Kubernetes/cloud-config text plus package-manifest cloud-SDK dependency and
//!   release-file evidence. Extracts cloud identities/roles, public exposure, workload
//!   identity, storage/secret assets, and deployment contexts.
//! - `src/providers/security/model-extractors/data.mjs` — data extractor (Security Appendix
//!   §11.4): database/cache/vector store clients and sensitive-data-class field-name
//!   signals.
//! - `src/providers/security/model-extractors/developer-machine.mjs` — developer-machine
//!   extractor (B7-007): package lifecycle hooks, editor/agent config discovery, local
//!   filesystem/process/network tool grants, and sandbox-bypass signals.
//! - `src/providers/security/model-extractors/http.mjs` — HTTP entrypoint extractor
//!   (Security Appendix §11.2): Express/FastAPI/Flask/Go-web route entities with an
//!   observed-protected or unknown-reachability auth state.
//!
//! IMPORTANT correctness note carried over from the JS source, preserved faithfully here
//! rather than silently fixed: `common.mjs`'s own `entity`/`relation`/`fact` constructors do
//! **not** call `assertEntityKind`/`assertRelationKind`/`assertFactKind` from `contracts.mjs`.
//! Only `cloud.mjs` and `developer-machine.mjs` define local `typedEntity`/`typedRelation`/
//! `typedFact`/`typedControlEntity` wrappers that add that validation; `http.mjs` and
//! `data.mjs` call the raw, unvalidated constructors directly. Two consequences ported
//! byte-for-byte here:
//!   1. `http.mjs`'s `protected-by` relation kind is **not** a member of `RELATION_KINDS`
//!      (only `protects` is registered) — an unvalidated, effectively out-of-contract
//!      relation kind reaches the model whenever a route's source text matches the auth
//!      signal regex. This is a pre-existing JS defect (dead/incorrect kind name), not a
//!      porting error; flagged in the wf054 report rather than corrected here.
//!   2. `data.mjs`'s `data-class` entity kind is likewise **not** a member of
//!      `ENTITY_KINDS` (no `data-class` there), and reaches the model unvalidated for the
//!      same reason.
//! `entity`/`relation`/`fact`/`control_entity` below are therefore unchecked, mirroring
//! `common.mjs` exactly; `cloud` and `developer_machine` each define their own checked
//! `typed_*` wrappers locally, mirroring the JS files that do so.
//!
//! `model-builder.mjs`'s `EXTRACTORS` array wires eight extractors; this chunk owns five
//! of them (`common`, `cloud`, `data`, `developer_machine`, `http`). `mobile.mjs` and
//! `ai-agent.mjs` are owned elsewhere (`ai-agent.mjs` is ported in wf053); `identity.mjs`
//! and `native-workspace.mjs` are owned elsewhere again. No assembly/wiring of the full
//! `EXTRACTORS` pipeline is attempted here — that is an integration step outside this
//! chunk's owned paths.
//!
//! Everything here is pure: it reads only the `files`/`source_text`/`package_manifests`/
//! `release_files` values the caller passes in (mirroring `projection.sourceText` and
//! `projection.auditFacts`), does no filesystem walk, and makes no model call, tool
//! execution, MCP connection, or network probe of any kind — matching every source file's
//! own header comment.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest as _, Sha256};

// =================================================================================================
// contracts.mjs (the subset this chunk depends on)
// =================================================================================================

pub const ENTITY_KINDS: &[&str] = &[
    "actor",
    "principal",
    "identity",
    "entrypoint",
    "asset",
    "crown-jewel",
    "trust-boundary",
    "control",
    "source",
    "sink",
    "service",
    "process",
    "repository-artifact",
    "data-store",
    "tool-capability",
    "permission-scope",
    "deployment-context",
    "workflow-state",
];

pub const RELATION_KINDS: &[&str] = &[
    "assumes-role",
    "authenticates-as",
    "authorizes",
    "calls",
    "contains",
    "crosses",
    "delegates-to",
    "derives-from",
    "executes",
    "exposes",
    "flows-to",
    "grants",
    "loads",
    "protects",
    "publishes-to",
    "reaches",
    "reads",
    "retrieves-from",
    "runs-as",
    "stores",
    "trusts",
    "validates",
    "writes",
];

pub const FACT_KINDS: &[&str] = &[
    "attacker-position",
    "knowledge",
    "capability",
    "credential-possession",
    "principal-access",
    "network-reachability",
    "data-access",
    "object-access",
    "code-execution",
    "workflow-state",
    "control-bypass",
    "persistence",
    "availability-impact",
    "integrity-impact",
    "confidentiality-impact",
];

/// Mirrors `assertEnum` / `assertEntityKind`.
pub fn assert_entity_kind(value: &str) -> Result<&str, String> {
    if ENTITY_KINDS.contains(&value) {
        Ok(value)
    } else {
        Err(format!("unknown security entity kind: {value}"))
    }
}

/// Mirrors `assertRelationKind`.
pub fn assert_relation_kind(value: &str) -> Result<&str, String> {
    if RELATION_KINDS.contains(&value) {
        Ok(value)
    } else {
        Err(format!("unknown security relation kind: {value}"))
    }
}

/// Mirrors `assertFactKind`.
pub fn assert_fact_kind(value: &str) -> Result<&str, String> {
    if FACT_KINDS.contains(&value) {
        Ok(value)
    } else {
        Err(format!("unknown security fact kind: {value}"))
    }
}

/// Mirrors `canonicalize`: arrays map element-wise, objects get their keys sorted
/// (recursively), everything else passes through unchanged. `serde_json::Map` preserves
/// insertion order, so inserting in sorted-key order reproduces
/// `Object.fromEntries(Object.keys(value).sort().map(...))` exactly.
pub fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = Map::new();
            for key in keys {
                out.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// Mirrors `stableId(namespace, value)`: `sha256:` + hex sha256 of
/// `` `${namespace}\0${JSON.stringify(canonicalize(value))}` ``.
pub fn stable_id(namespace: &str, value: &Value) -> String {
    let body = serde_json::to_string(&canonicalize(value)).expect("json values always serialize");
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0u8]);
    hasher.update(body.as_bytes());
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

// =================================================================================================
// model-extractors/common.mjs
// =================================================================================================

fn sorted_unique_refs(evidence_refs: &[String]) -> Vec<String> {
    let set: BTreeSet<String> = evidence_refs.iter().cloned().collect();
    set.into_iter().collect()
}

#[derive(Default, Clone, Copy)]
pub struct EntityOptions<'a> {
    pub assertion: Option<&'a str>,
    pub evidence_strength: Option<&'a str>,
}

/// Mirrors `entity(kind, name, attributes, evidenceRefs, options = {})`. Deliberately
/// **unchecked** — `common.mjs`'s own `entity` never calls `assertEntityKind` (see the
/// module header note); callers that want validation use the local `typed_entity`
/// wrappers defined in `cloud` and `developer_machine` below, mirroring the JS files that
/// do the same.
pub fn entity(
    kind: &str,
    name: &str,
    attributes: Value,
    evidence_refs: &[String],
    options: EntityOptions<'_>,
) -> Value {
    let body = json!({
        "kind": kind,
        "name": name,
        "attributes": attributes,
        "assertion": options.assertion.unwrap_or("observed"),
        "evidenceStrength": options.evidence_strength.unwrap_or("verified"),
        "evidenceRefs": sorted_unique_refs(evidence_refs),
    });
    let id = stable_id("security-model-entity", &body);
    let mut out = body.as_object().cloned().unwrap();
    out.insert("id".to_string(), Value::String(id));
    Value::Object(out)
}

/// Mirrors `relation(kind, from, to, evidenceRefs, attributes = {}, options = {})`.
/// Unchecked, like `entity` above (see module header note).
pub fn relation(
    kind: &str,
    from: &str,
    to: &str,
    evidence_refs: &[String],
    attributes: Value,
    options: EntityOptions<'_>,
) -> Value {
    let body = json!({
        "kind": kind,
        "from": from,
        "to": to,
        "attributes": attributes,
        "assertion": options.assertion.unwrap_or("observed"),
        "evidenceStrength": options.evidence_strength.unwrap_or("verified"),
        "evidenceRefs": sorted_unique_refs(evidence_refs),
    });
    let id = stable_id("security-model-relation", &body);
    let mut out = body.as_object().cloned().unwrap();
    out.insert("id".to_string(), Value::String(id));
    Value::Object(out)
}

pub struct FactFields<'a> {
    pub subject: Option<&'a str>,
    pub action: Option<&'a str>,
    pub object: Option<&'a str>,
    pub scope: Option<&'a str>,
    pub environment: Option<&'a str>,
    pub tenant: Option<&'a str>,
    pub attributes: Value,
}

impl<'a> Default for FactFields<'a> {
    fn default() -> Self {
        FactFields {
            subject: None,
            action: None,
            object: None,
            scope: None,
            environment: None,
            tenant: None,
            attributes: json!({}),
        }
    }
}

/// Mirrors `fact(kind, fields, evidenceRefs = [])`. Unchecked, like `entity` above.
pub fn fact(kind: &str, fields: FactFields<'_>, evidence_refs: &[String]) -> Value {
    let body = json!({
        "kind": kind,
        "subject": fields.subject,
        "action": fields.action,
        "object": fields.object,
        "scope": fields.scope,
        "environment": fields.environment,
        "tenant": fields.tenant,
        "attributes": fields.attributes,
        "evidenceRefs": sorted_unique_refs(evidence_refs),
    });
    let id = stable_id("security-fact", &body);
    let mut out = body.as_object().cloned().unwrap();
    out.insert("id".to_string(), Value::String(id));
    Value::Object(out)
}

/// Mirrors `controlEntity(controlType, name, evidenceRefs, attributes = {})`: an `entity`
/// of kind `control` with `controlType` merged into `attributes`.
pub fn control_entity(control_type: &str, name: &str, evidence_refs: &[String], attributes: Value) -> Value {
    let mut attrs = match attributes {
        Value::Object(m) => m,
        _ => Map::new(),
    };
    attrs.insert("controlType".to_string(), Value::String(control_type.to_string()));
    entity("control", name, Value::Object(attrs), evidence_refs, EntityOptions::default())
}

/// The five arrays every extractor returns, ported as one struct. Mirrors the object
/// literal `{ entities, relations, evidence, initialFacts, coverageGaps }` every
/// `extract*` function returns.
#[derive(Default, Clone, Debug, PartialEq)]
pub struct ExtractorOutput {
    pub entities: Vec<Value>,
    pub relations: Vec<Value>,
    pub evidence: Vec<Value>,
    pub initial_facts: Vec<Value>,
    pub coverage_gaps: Vec<Value>,
}

/// Mirrors JS `String(value)` coercion closely enough for the shapes `extractCommon`'s
/// `packageManifests` entries can take in this codebase: a bare string manifest path
/// (the common case), or (matching the loose typing `extractCommon` actually has — it
/// never destructures `.path`/`.dependencies` the way `cloud.mjs`/`developer-machine.mjs`
/// do) an object, which JS `String()` coerces to the literal `"[object Object]"`. Ported
/// faithfully rather than "fixed" to destructure `.path`, since that is not what the JS
/// source does.
fn js_manifest_to_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        Value::Array(items) => items
            .iter()
            .map(|v| match v {
                Value::Null => String::new(),
                other => js_manifest_to_string(other),
            })
            .collect::<Vec<_>>()
            .join(","),
        Value::Object(_) => "[object Object]".to_string(),
    }
}

/// Mirrors `extractCommon({ root, plan, projection, files, lensRegistry })` (Security
/// Appendix §11.1). `manifests` mirrors `projection.auditFacts.packageManifests` — passed
/// as raw JSON values (see `js_manifest_to_string` above for why).
pub fn extract_common(files: &[String], manifests: &[Value]) -> ExtractorOutput {
    let mut out = ExtractorOutput::default();

    for file in files {
        let evidence_ref = stable_id("artifact-evidence", &json!({ "file": file }));
        out.entities.push(entity(
            "repository-artifact",
            file,
            json!({ "path": file }),
            &[evidence_ref.clone()],
            EntityOptions::default(),
        ));
        out.evidence.push(json!({
            "id": evidence_ref,
            "kind": "source-location",
            "file": file,
            "description": "Repository artifact",
        }));
    }

    for manifest in manifests {
        let evidence_ref = stable_id("manifest-evidence", &json!({ "manifest": manifest }));
        let manifest_str = js_manifest_to_string(manifest);
        out.entities.push(entity(
            "repository-artifact",
            &format!("manifest {manifest_str}"),
            json!({ "manifest": true }),
            &[evidence_ref.clone()],
            EntityOptions::default(),
        ));
        out.evidence.push(json!({
            "id": evidence_ref,
            "kind": "source-location",
            "file": manifest_str,
            "description": "Package manifest",
        }));
    }

    out
}

/// A package manifest as `cloud.mjs` and `developer-machine.mjs` destructure it:
/// `{ path, dependencies, scripts }` (any missing field defaults to `[]` in JS via `?? []`).
#[derive(Default, Clone, Debug)]
pub struct PackageManifest {
    pub path: String,
    pub dependencies: Vec<String>,
    pub scripts: Vec<String>,
}

// =================================================================================================
// model-extractors/http.mjs
// =================================================================================================

pub mod http {
    use super::*;

    struct RoutePattern {
        framework: &'static str,
        regex: fn() -> &'static Regex,
    }

    // None of the four JS `ROUTE_PATTERNS` regexes carry the `/i` flag — ported without
    // `(?i)` to match exactly (express/fastapi require lowercase `get|post|...`, go-web
    // requires uppercase `GET|POST|...`, both case-sensitively).
    fn express_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r#"(?:app|router)\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]"#).unwrap())
    }
    fn fastapi_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r#"@(?:app|router)\.(get|post|put|patch|delete)\(\s*['"]([^'"]+)['"]"#).unwrap())
    }
    fn flask_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r#"@(?:app|route)\.route\(\s*['"]([^'"]+)['"]"#).unwrap())
    }
    fn go_web_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r#"(?:r|router|e|app)\.(GET|POST|PUT|DELETE|PATCH)\(\s*['"]([^'"]+)['"]"#).unwrap()
        })
    }

    fn route_patterns() -> [RoutePattern; 4] {
        [
            RoutePattern { framework: "express", regex: express_re },
            RoutePattern { framework: "fastapi", regex: fastapi_re },
            RoutePattern { framework: "flask", regex: flask_re },
            RoutePattern { framework: "go-web", regex: go_web_re },
        ]
    }

    fn auth_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"auth|session|jwt|passport|getServerSession|requireAuth|@login_required").unwrap()
        })
    }

    /// Mirrors `extractHttp({ root, plan, projection, files, lensRegistry })`. `source_text`
    /// stands in for `projection.sourceText`.
    ///
    /// Flask's pattern has only one capture group — `@(?:app|route)\.route(...)` carries no
    /// HTTP-method group — so unlike the other three frameworks it yields `path` only (as
    /// `match[1]`). The JS loop body destructures `match[1]` as `method` and `match[2]` as
    /// `path` uniformly across all four patterns regardless, so for a flask match `method`
    /// actually becomes the (wrongly) upper-cased path text and `path` becomes JS
    /// `undefined`. `undefined` is not the string `"undefined"` here: interpolated into a
    /// template literal (`${method} ${path}`, entity/description names) it *does* coerce to
    /// the literal text `"undefined"`, but as an **object property value** (the `path` key in
    /// the evidence-ref hash input and in the entrypoint/source's `attributes`) `undefined`
    /// is dropped entirely by `JSON.stringify` — the key never appears in the hashed or
    /// serialized JSON at all. Both behaviors are preserved below via `path: Option<String>`:
    /// `None` renders as the literal text `"undefined"` in names/descriptions but is omitted
    /// from every JSON object that would otherwise carry a `"path"` key.
    pub fn extract(files: &[String], source_text: &HashMap<String, String>) -> ExtractorOutput {
        let mut out = ExtractorOutput::default();

        for file in files {
            let text = match source_text.get(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };
            let has_auth = auth_re().is_match(text);

            for pattern in route_patterns() {
                for caps in pattern.regex().captures_iter(text) {
                    let (method, path): (String, Option<String>) = if pattern.framework == "flask" {
                        let only_group = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string();
                        (only_group.to_uppercase(), None)
                    } else {
                        let method = caps.get(1).map(|m| m.as_str()).unwrap_or("").to_uppercase();
                        let path = caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string();
                        (method, Some(path))
                    };
                    // Display form only: JS `${undefined}` -> the literal text "undefined".
                    let path_display: &str = path.as_deref().unwrap_or("undefined");

                    let mut evidence_key = Map::new();
                    evidence_key.insert("file".to_string(), Value::String(file.clone()));
                    evidence_key.insert("method".to_string(), Value::String(method.clone()));
                    if let Some(p) = &path {
                        evidence_key.insert("path".to_string(), Value::String(p.clone()));
                    }
                    let evidence_ref = stable_id("http-route-evidence", &Value::Object(evidence_key));

                    let mut entrypoint_attrs = Map::new();
                    entrypoint_attrs.insert("protocol".to_string(), Value::String("http".to_string()));
                    entrypoint_attrs.insert("method".to_string(), Value::String(method.clone()));
                    if let Some(p) = &path {
                        entrypoint_attrs.insert("path".to_string(), Value::String(p.clone()));
                    }
                    entrypoint_attrs.insert("environment".to_string(), Value::String("application".to_string()));
                    entrypoint_attrs.insert("framework".to_string(), Value::String(pattern.framework.to_string()));

                    let entrypoint = entity(
                        "entrypoint",
                        &format!("{method} {path_display}"),
                        Value::Object(entrypoint_attrs),
                        &[evidence_ref.clone()],
                        EntityOptions::default(),
                    );
                    let source = entity(
                        "source",
                        &format!("{method} {path_display} input"),
                        json!({ "inputKind": "request", "framework": pattern.framework }),
                        &[evidence_ref.clone()],
                        EntityOptions::default(),
                    );
                    let process = entity(
                        "process",
                        &format!("{method} {path_display} handler"),
                        json!({ "framework": pattern.framework, "environment": "application" }),
                        &[evidence_ref.clone()],
                        EntityOptions::default(),
                    );
                    let entrypoint_id = entrypoint["id"].as_str().unwrap().to_string();
                    let source_id = source["id"].as_str().unwrap().to_string();
                    let process_id = process["id"].as_str().unwrap().to_string();
                    out.entities.push(entrypoint);
                    out.entities.push(source);
                    out.entities.push(process);
                    out.relations.push(relation(
                        "accepts-input-from",
                        &entrypoint_id,
                        &source_id,
                        &[evidence_ref.clone()],
                        json!({}),
                        EntityOptions::default(),
                    ));
                    out.relations.push(relation(
                        "invokes",
                        &entrypoint_id,
                        &process_id,
                        &[evidence_ref.clone()],
                        json!({}),
                        EntityOptions::default(),
                    ));

                    if has_auth {
                        // `protected-by` — not a member of `RELATION_KINDS` (see module
                        // header note); ported unchecked, matching JS.
                        let auth_control_id = stable_id("auth-control", &json!({ "file": file }));
                        out.relations.push(relation(
                            "protected-by",
                            &entrypoint_id,
                            &auth_control_id,
                            &[evidence_ref.clone()],
                            json!({}),
                            EntityOptions { assertion: Some("observed"), evidence_strength: None },
                        ));
                    } else {
                        out.initial_facts.push(fact(
                            "network-reachability",
                            FactFields {
                                subject: Some("actor:external"),
                                action: Some("connect"),
                                object: Some(&entrypoint_id),
                                environment: Some("application"),
                                ..FactFields::default()
                            },
                            &[evidence_ref.clone()],
                        ));
                    }

                    out.evidence.push(json!({
                        "id": evidence_ref,
                        "kind": "source-location",
                        "file": file,
                        "description": format!("Route {method} {path_display}"),
                    }));
                }
            }
        }

        out
    }
}

// =================================================================================================
// model-extractors/data.mjs
// =================================================================================================

pub mod data {
    use super::*;

    struct StorePattern {
        kind: &'static str,
        name: &'static str,
        regex: fn() -> &'static Regex,
    }

    fn db_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?:db|database|client|pool|engine|session)\.").unwrap())
    }
    fn cache_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?:redis|memcached|cache)\.").unwrap())
    }
    fn vector_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?:vector|embedding|index)\.").unwrap())
    }
    fn sensitive_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)\b(?:password|token|secret|apiKey|ssn|email)\b").unwrap())
    }

    fn store_patterns() -> [StorePattern; 3] {
        [
            StorePattern { kind: "data-store", name: "database client", regex: db_re },
            StorePattern { kind: "data-store", name: "cache client", regex: cache_re },
            StorePattern { kind: "data-store", name: "vector store client", regex: vector_re },
        ]
    }

    /// Mirrors `extractData({ root, plan, projection, files, lensRegistry })` (Security
    /// Appendix §11.4). `source_text` stands in for `projection.sourceText`.
    ///
    /// `data-class` (used for the sensitive-field-name entity kind below) is not a member
    /// of `ENTITY_KINDS` — ported unchecked, matching JS (see module header note).
    pub fn extract(files: &[String], source_text: &HashMap<String, String>) -> ExtractorOutput {
        let mut out = ExtractorOutput::default();

        for file in files {
            let text = match source_text.get(file) {
                Some(t) if !t.is_empty() => t,
                _ => continue,
            };

            for pattern in store_patterns() {
                if !pattern.regex().is_match(text) {
                    continue;
                }
                let evidence_ref = stable_id("data-evidence", &json!({ "file": file, "kind": pattern.kind }));
                let store = entity(
                    pattern.kind,
                    &format!("{} {file}", pattern.name),
                    json!({ "environment": "application" }),
                    &[evidence_ref.clone()],
                    EntityOptions::default(),
                );
                out.entities.push(store);
                out.evidence.push(json!({
                    "id": evidence_ref,
                    "kind": "source-location",
                    "file": file,
                    "description": pattern.name,
                }));
            }

            if sensitive_re().is_match(text) {
                let evidence_ref = stable_id("sensitive-evidence", &json!({ "file": file }));
                let data_class = entity(
                    "data-class",
                    &format!("sensitive data {file}"),
                    json!({ "sensitive": true }),
                    &[evidence_ref.clone()],
                    EntityOptions::default(),
                );
                out.entities.push(data_class);
                out.evidence.push(json!({
                    "id": evidence_ref,
                    "kind": "source-location",
                    "file": file,
                    "description": "Sensitive data class",
                }));
            }
        }

        out
    }
}

// =================================================================================================
// model-extractors/cloud.mjs
// =================================================================================================

pub mod cloud {
    use super::*;

    fn typed_entity(kind: &str, name: &str, attributes: Value, evidence_refs: &[String], opts: EntityOptions<'_>) -> Value {
        assert_entity_kind(kind).expect("entity kind must be valid");
        entity(kind, name, attributes, evidence_refs, opts)
    }
    fn typed_relation(kind: &str, from: &str, to: &str, evidence_refs: &[String], attributes: Value, opts: EntityOptions<'_>) -> Value {
        assert_relation_kind(kind).expect("relation kind must be valid");
        relation(kind, from, to, evidence_refs, attributes, opts)
    }
    fn typed_fact(kind: &str, fields: FactFields<'_>, evidence_refs: &[String]) -> Value {
        assert_fact_kind(kind).expect("fact kind must be valid");
        fact(kind, fields, evidence_refs)
    }
    fn typed_control_entity(control_type: &str, name: &str, evidence_refs: &[String], attributes: Value) -> Value {
        assert_entity_kind("control").expect("control is a valid entity kind");
        control_entity(control_type, name, evidence_refs, attributes)
    }

    fn cloud_file_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)\.(tf|tfvars|yaml|yml|json)$").unwrap())
    }
    fn cloud_sdk_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)^(?:@?aws-sdk/|aws-sdk$|@google-cloud/|@azure/|kubernetes-client|@kubernetes/client-node|@pulumi/|aws-cdk-lib|cdktf)").unwrap()
        })
    }
    fn cloud_signal_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)terraform|kubernetes|k8s|helm|cloudformation|serverless\.yml|pulumi|iam|role|policy|principal|assume_role|serviceaccount|s3|bucket|storage|blob|ingress|0\.0\.0\.0/0|secretsmanager|secret_manager|vault|kms").unwrap()
        })
    }
    fn public_exposure_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)0\.0\.0\.0/0|public").unwrap())
    }
    fn network_context_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)ingress|security_group|firewall|network|expose").unwrap())
    }
    fn iam_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)iam|role|policy|principal|assume_role|serviceaccount").unwrap())
    }
    fn policy_scope_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)action|resource").unwrap())
    }
    fn workload_identity_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)workload[_ -]?identity|irsa|federated[_ -]?identity|oidc[_ -]?provider").unwrap())
    }
    fn storage_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)s3|bucket|storage|blob").unwrap())
    }
    fn secret_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)secretsmanager|secret_manager|vault|kms|ssm[_ ]?parameter|parameter[_ -]?store|secret").unwrap())
    }
    fn secret_control_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)kms|encrypt|rotation").unwrap())
    }
    fn deployment_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)dockerfile|docker-compose|kind:\s*deployment|kind:\s*pod|serverless\.yml|\bpulumi\b|\bhelm\b").unwrap()
        })
    }

    struct CloudSdkDep {
        manifest: String,
        dependency: String,
    }

    fn cloud_sdk_dependencies(package_manifests: &[PackageManifest]) -> Vec<CloudSdkDep> {
        let mut found = Vec::new();
        for manifest in package_manifests {
            for dep in &manifest.dependencies {
                if cloud_sdk_re().is_match(dep) {
                    found.push(CloudSdkDep { manifest: manifest.path.clone(), dependency: dep.clone() });
                }
            }
        }
        found
    }

    /// Mirrors `extractCloud({ root, plan, projection, files, lensRegistry })` (B7-007).
    /// `source_text` stands in for `projection.sourceText`, `package_manifests` for
    /// `projection.auditFacts.packageManifests`, `release_files` for
    /// `projection.auditFacts.releaseFiles`.
    pub fn extract(
        files: &[String],
        source_text: &HashMap<String, String>,
        package_manifests: &[PackageManifest],
        release_files: &HashSet<String>,
    ) -> ExtractorOutput {
        let mut out = ExtractorOutput::default();

        let cloud_sdk_deps = cloud_sdk_dependencies(package_manifests);
        let mut saw_cloud_signal = !cloud_sdk_deps.is_empty();

        for dep in &cloud_sdk_deps {
            let evidence_ref = stable_id(
                "cloud-sdk-evidence",
                &json!({ "manifest": dep.manifest, "dependency": dep.dependency }),
            );
            let svc = typed_entity(
                "service",
                &format!("cloud SDK dependency {}", dep.dependency),
                json!({ "environment": "cloud", "manifest": dep.manifest, "dependency": dep.dependency }),
                &[evidence_ref.clone()],
                EntityOptions::default(),
            );
            out.entities.push(svc);
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": dep.manifest,
                "description": format!("Cloud SDK dependency {}", dep.dependency),
            }));
        }

        for file in files {
            let looks_like_cloud_config =
                cloud_file_re().is_match(file) || (release_files.contains(file) && file.to_lowercase().contains("dockerfile"));
            if !looks_like_cloud_config {
                continue;
            }

            let text = match source_text.get(file) {
                Some(t) => t,
                None => {
                    out.coverage_gaps.push(json!({
                        "kind": "missing-rendered-configuration",
                        "domain": "cloud",
                        "file": file,
                        "reason": "file matched a cloud configuration pattern but no source text was projected for it",
                    }));
                    continue;
                }
            };
            let is_deployment_file = file.to_lowercase().contains("dockerfile");
            if text.is_empty() || !(cloud_signal_re().is_match(text) || is_deployment_file) {
                continue;
            }
            saw_cloud_signal = true;

            if public_exposure_re().is_match(text) && network_context_re().is_match(text) {
                let evidence_ref = stable_id("cloud-public-evidence", &json!({ "file": file }));
                let entrypoint = typed_entity(
                    "entrypoint",
                    &format!("public cloud entrypoint {file}"),
                    json!({ "environment": "cloud", "entrypointType": "network-ingress" }),
                    &[evidence_ref.clone()],
                    EntityOptions::default(),
                );
                let entrypoint_id = entrypoint["id"].as_str().unwrap().to_string();
                out.entities.push(entrypoint);
                out.evidence.push(json!({
                    "id": evidence_ref,
                    "kind": "source-location",
                    "file": file,
                    "description": "Public cloud network entrypoint",
                }));
                out.initial_facts.push(typed_fact(
                    "network-reachability",
                    FactFields {
                        subject: Some("actor:external"),
                        action: Some("reach"),
                        object: Some(&entrypoint_id),
                        scope: Some("cloud"),
                        attributes: json!({ "source": file }),
                        ..FactFields::default()
                    },
                    &[evidence_ref.clone()],
                ));
            }

            if iam_re().is_match(text) {
                let evidence_ref = stable_id("cloud-iam-evidence", &json!({ "file": file }));
                let principal = typed_entity(
                    "principal",
                    &format!("IAM principal {file}"),
                    json!({ "environment": "cloud" }),
                    &[evidence_ref.clone()],
                    EntityOptions::default(),
                );
                let role = typed_entity(
                    "identity",
                    &format!("IAM role {file}"),
                    json!({ "environment": "cloud" }),
                    &[evidence_ref.clone()],
                    EntityOptions::default(),
                );
                let principal_id = principal["id"].as_str().unwrap().to_string();
                let role_id = role["id"].as_str().unwrap().to_string();
                out.entities.push(principal);
                out.entities.push(role);
                out.relations.push(typed_relation(
                    "assumes-role",
                    &principal_id,
                    &role_id,
                    &[evidence_ref.clone()],
                    json!({}),
                    EntityOptions::default(),
                ));
                out.evidence.push(json!({
                    "id": evidence_ref,
                    "kind": "source-location",
                    "file": file,
                    "description": "IAM principal/role",
                }));
                out.initial_facts.push(typed_fact(
                    "principal-access",
                    FactFields {
                        subject: Some(&principal_id),
                        action: Some("assume"),
                        object: Some(&role_id),
                        scope: Some("cloud"),
                        ..FactFields::default()
                    },
                    &[evidence_ref.clone()],
                ));

                if policy_scope_re().is_match(text) {
                    let scope_ref = stable_id("cloud-policy-scope-evidence", &json!({ "file": file }));
                    let scope = typed_entity(
                        "permission-scope",
                        &format!("IAM policy scope {file}"),
                        json!({ "environment": "cloud" }),
                        &[scope_ref.clone()],
                        EntityOptions::default(),
                    );
                    let scope_id = scope["id"].as_str().unwrap().to_string();
                    out.entities.push(scope);
                    out.relations.push(typed_relation(
                        "grants",
                        &role_id,
                        &scope_id,
                        &[scope_ref.clone()],
                        json!({}),
                        EntityOptions::default(),
                    ));
                    out.evidence.push(json!({
                        "id": scope_ref,
                        "kind": "source-location",
                        "file": file,
                        "description": "IAM policy action/resource scope",
                    }));
                }
            }

            if workload_identity_re().is_match(text) {
                let evidence_ref = stable_id("cloud-workload-identity-evidence", &json!({ "file": file }));
                let workload = typed_entity(
                    "identity",
                    &format!("workload identity {file}"),
                    json!({ "environment": "cloud", "workloadIdentity": true }),
                    &[evidence_ref.clone()],
                    EntityOptions::default(),
                );
                let workload_process = typed_entity(
                    "process",
                    &format!("cloud workload {file}"),
                    json!({ "environment": "cloud" }),
                    &[evidence_ref.clone()],
                    EntityOptions::default(),
                );
                let workload_id = workload["id"].as_str().unwrap().to_string();
                let workload_process_id = workload_process["id"].as_str().unwrap().to_string();
                out.entities.push(workload);
                out.entities.push(workload_process);
                out.relations.push(typed_relation(
                    "runs-as",
                    &workload_process_id,
                    &workload_id,
                    &[evidence_ref.clone()],
                    json!({}),
                    EntityOptions::default(),
                ));
                out.evidence.push(json!({
                    "id": evidence_ref,
                    "kind": "source-location",
                    "file": file,
                    "description": "Workload identity binding",
                }));
            }

            if storage_re().is_match(text) {
                let evidence_ref = stable_id("cloud-storage-evidence", &json!({ "file": file }));
                let storage = typed_entity(
                    "asset",
                    &format!("storage {file}"),
                    json!({ "assetKind": "storage" }),
                    &[evidence_ref.clone()],
                    EntityOptions::default(),
                );
                out.entities.push(storage);
                out.evidence.push(json!({
                    "id": evidence_ref,
                    "kind": "source-location",
                    "file": file,
                    "description": "Storage asset",
                }));
            }

            if secret_re().is_match(text) {
                let evidence_ref = stable_id("cloud-secret-evidence", &json!({ "file": file }));
                let secret = typed_entity(
                    "asset",
                    &format!("cloud secret {file}"),
                    json!({ "assetKind": "secret" }),
                    &[evidence_ref.clone()],
                    EntityOptions::default(),
                );
                let control = typed_control_entity(
                    "secret-management",
                    &format!("secret handling {file}"),
                    &[evidence_ref.clone()],
                    json!({ "controlState": if secret_control_re().is_match(text) { "enforced" } else { "unknown" } }),
                );
                let secret_id = secret["id"].as_str().unwrap().to_string();
                let control_id = control["id"].as_str().unwrap().to_string();
                out.entities.push(secret);
                out.entities.push(control);
                out.relations.push(typed_relation(
                    "protects",
                    &control_id,
                    &secret_id,
                    &[evidence_ref.clone()],
                    json!({}),
                    EntityOptions::default(),
                ));
                out.evidence.push(json!({
                    "id": evidence_ref,
                    "kind": "source-location",
                    "file": file,
                    "description": "Cloud secret reference",
                }));
            }

            if deployment_re().is_match(text) || is_deployment_file {
                let evidence_ref = stable_id("cloud-deployment-evidence", &json!({ "file": file }));
                let deployment = typed_entity(
                    "deployment-context",
                    &format!("deployment context {file}"),
                    json!({ "environment": "cloud" }),
                    &[evidence_ref.clone()],
                    EntityOptions::default(),
                );
                out.entities.push(deployment);
                out.evidence.push(json!({
                    "id": evidence_ref,
                    "kind": "source-location",
                    "file": file,
                    "description": "Deployment context",
                }));
            }
        }

        if !saw_cloud_signal {
            out.coverage_gaps.push(json!({
                "kind": "cloud-context-not-detected",
                "domain": "cloud",
                "reason": "no infrastructure-as-code, cloud SDK dependency, or cloud deployment file found in the denominator",
            }));
        }

        out
    }
}

// =================================================================================================
// model-extractors/developer-machine.mjs
// =================================================================================================

pub mod developer_machine {
    use super::*;

    fn typed_entity(kind: &str, name: &str, attributes: Value, evidence_refs: &[String], opts: EntityOptions<'_>) -> Value {
        assert_entity_kind(kind).expect("entity kind must be valid");
        entity(kind, name, attributes, evidence_refs, opts)
    }
    fn typed_relation(kind: &str, from: &str, to: &str, evidence_refs: &[String], attributes: Value, opts: EntityOptions<'_>) -> Value {
        assert_relation_kind(kind).expect("relation kind must be valid");
        relation(kind, from, to, evidence_refs, attributes, opts)
    }
    fn typed_fact(kind: &str, fields: FactFields<'_>, evidence_refs: &[String]) -> Value {
        assert_fact_kind(kind).expect("fact kind must be valid");
        fact(kind, fields, evidence_refs)
    }
    fn typed_control_entity(control_type: &str, name: &str, evidence_refs: &[String], attributes: Value) -> Value {
        assert_entity_kind("control").expect("control is a valid entity kind");
        control_entity(control_type, name, evidence_refs, attributes)
    }

    fn editor_agent_config_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r"(?i)(^|/)(\.vscode|\.idea|\.cursor|\.claude|\.github/copilot|\.mcp\.json|mcp\.json|CLAUDE\.md|AGENTS\.md|\.husky|\.git/hooks)(/|$)").unwrap()
        })
    }
    const LIFECYCLE_HOOK_NAMES: &[&str] = &["preinstall", "postinstall", "prepare"];
    fn filesystem_grant_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)\bfs\.|filesystem|readFile|writeFile|readdir").unwrap())
    }
    fn process_grant_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)\bexec\s*\(|\bspawn\s*\(|child_process|Bash\s*\(|shell\s*=\s*true").unwrap())
    }
    fn network_grant_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| Regex::new(r"(?i)\bfetch\s*\(|\bhttp[s]?\b|axios|network").unwrap())
    }
    fn sandbox_bypass_re() -> &'static Regex {
        static RE: OnceLock<Regex> = OnceLock::new();
        RE.get_or_init(|| {
            Regex::new(r#"(?i)dangerouslySkipPermissions|--no-sandbox|bypassPermissions|trust\s*[:=]\s*(?:false|"?off"?|disabled)"#).unwrap()
        })
    }

    struct HookScript {
        manifest: String,
        script: String,
    }

    fn lifecycle_hook_scripts(package_manifests: &[PackageManifest]) -> Vec<HookScript> {
        let mut found = Vec::new();
        for manifest in package_manifests {
            for script in &manifest.scripts {
                if LIFECYCLE_HOOK_NAMES.contains(&script.as_str()) {
                    found.push(HookScript { manifest: manifest.path.clone(), script: script.clone() });
                }
            }
        }
        found
    }

    fn grant_kinds_in(text: &str) -> Vec<&'static str> {
        let mut kinds = Vec::new();
        if filesystem_grant_re().is_match(text) {
            kinds.push("filesystem");
        }
        if process_grant_re().is_match(text) {
            kinds.push("process");
        }
        if network_grant_re().is_match(text) {
            kinds.push("network");
        }
        kinds
    }

    /// Mirrors `extractDeveloperMachine({ root, plan, projection, files, lensRegistry })`
    /// (B7-007). `source_text` stands in for `projection.sourceText`, `package_manifests`
    /// for `projection.auditFacts.packageManifests`.
    pub fn extract(
        files: &[String],
        source_text: &HashMap<String, String>,
        package_manifests: &[PackageManifest],
    ) -> ExtractorOutput {
        let mut out = ExtractorOutput::default();

        let hook_scripts = lifecycle_hook_scripts(package_manifests);
        let mut saw_dev_machine_signal = !hook_scripts.is_empty();

        for hook in &hook_scripts {
            let evidence_ref = stable_id(
                "devmachine-lifecycle-hook-evidence",
                &json!({ "manifest": hook.manifest, "script": hook.script }),
            );
            let artifact = typed_entity(
                "repository-artifact",
                &format!("package manifest {}", hook.manifest),
                json!({ "path": hook.manifest }),
                &[evidence_ref.clone()],
                EntityOptions::default(),
            );
            let hook_process = typed_entity(
                "process",
                &format!("package lifecycle hook {}:{}", hook.manifest, hook.script),
                json!({
                    "environment": "developer-machine",
                    "processKind": "package-lifecycle-hook",
                    "script": hook.script,
                }),
                &[evidence_ref.clone()],
                EntityOptions::default(),
            );
            let artifact_id = artifact["id"].as_str().unwrap().to_string();
            let hook_process_id = hook_process["id"].as_str().unwrap().to_string();
            out.entities.push(artifact);
            out.entities.push(hook_process);
            out.relations.push(typed_relation(
                "executes",
                &artifact_id,
                &hook_process_id,
                &[evidence_ref.clone()],
                json!({}),
                EntityOptions::default(),
            ));
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": hook.manifest,
                "description": format!("Package lifecycle hook {}", hook.script),
            }));
            out.initial_facts.push(typed_fact(
                "code-execution",
                FactFields {
                    subject: Some(&hook_process_id),
                    action: Some("run-on-install"),
                    object: Some(&hook.manifest),
                    scope: Some("developer-machine"),
                    ..FactFields::default()
                },
                &[evidence_ref.clone()],
            ));
        }

        for file in files {
            if !editor_agent_config_re().is_match(file) {
                continue;
            }
            saw_dev_machine_signal = true;

            let evidence_ref = stable_id("devmachine-config-evidence", &json!({ "file": file }));
            let artifact = typed_entity(
                "repository-artifact",
                &format!("editor/agent config {file}"),
                json!({ "path": file, "configKind": "editor-agent-config" }),
                &[evidence_ref.clone()],
                EntityOptions::default(),
            );
            let loader = typed_entity(
                "entrypoint",
                &format!("developer-machine config load {file}"),
                json!({ "entrypointType": "developer-machine-config-load" }),
                &[evidence_ref.clone()],
                EntityOptions::default(),
            );
            let artifact_id = artifact["id"].as_str().unwrap().to_string();
            let loader_id = loader["id"].as_str().unwrap().to_string();
            out.entities.push(artifact);
            out.entities.push(loader);
            out.relations.push(typed_relation(
                "loads",
                &loader_id,
                &artifact_id,
                &[evidence_ref.clone()],
                json!({}),
                EntityOptions::default(),
            ));
            out.evidence.push(json!({
                "id": evidence_ref,
                "kind": "source-location",
                "file": file,
                "description": "Editor/agent config discovery",
            }));

            let text = match source_text.get(file) {
                Some(t) => t,
                None => {
                    out.coverage_gaps.push(json!({
                        "kind": "missing-rendered-configuration",
                        "domain": "developer-machine",
                        "file": file,
                        "reason": "file matched an editor/agent config pattern but no source text was projected for it",
                    }));
                    continue;
                }
            };
            if text.is_empty() {
                continue;
            }

            for grant_kind in grant_kinds_in(text) {
                let grant_ref = stable_id("devmachine-grant-evidence", &json!({ "file": file, "grantKind": grant_kind }));
                let scope = typed_entity(
                    "permission-scope",
                    &format!("local tool grant {grant_kind} {file}"),
                    json!({ "file": file, "grantKind": grant_kind }),
                    &[grant_ref.clone()],
                    EntityOptions::default(),
                );
                let scope_id = scope["id"].as_str().unwrap().to_string();
                out.entities.push(scope);
                out.relations.push(typed_relation(
                    "grants",
                    &artifact_id,
                    &scope_id,
                    &[grant_ref.clone()],
                    json!({}),
                    EntityOptions::default(),
                ));
                out.evidence.push(json!({
                    "id": grant_ref,
                    "kind": "source-location",
                    "file": file,
                    "description": format!("Local {grant_kind} grant"),
                }));
            }

            if sandbox_bypass_re().is_match(text) {
                let bypass_ref = stable_id("devmachine-sandbox-bypass-evidence", &json!({ "file": file }));
                let control = typed_control_entity(
                    "local-sandbox",
                    &format!("local sandbox policy {file}"),
                    &[bypass_ref.clone()],
                    json!({ "controlState": "absent" }),
                );
                out.entities.push(control);
                out.evidence.push(json!({
                    "id": bypass_ref,
                    "kind": "source-location",
                    "file": file,
                    "description": "Local sandbox/permission bypass",
                }));
            }
        }

        if !saw_dev_machine_signal {
            out.coverage_gaps.push(json!({
                "kind": "developer-machine-context-not-detected",
                "domain": "developer-machine",
                "reason": "no editor/agent config, plugin/hook discovery, or package lifecycle hook found in the denominator",
            }));
        }

        out
    }
}
