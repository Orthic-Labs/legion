//! Port of `src/providers/runtime/web/api/index.mjs` (`verifyApiExercise`).
//!
//! **Known gap for the integrator:** the JS source imports
//! `sanitizeProducedArtifact` from `lib/platform/artifact-sanitize.mjs`
//! (not in this chunk, no native port found by `git grep`). It is used
//! here only to decide `produced.valid`/`produced.sensitive`/
//! `produced.artifact` for `rawArtifacts` entries. This port models it the
//! same way `data.rs` in this chunk does (see that file's
//! `sanitize_produced_artifact` doc comment): sanitized artifact =
//! `redact(artifact, "")`, `sensitive` = redaction changed the value,
//! `valid` = the artifact is a non-null object. Swap in a real port of
//! `sanitizeProducedArtifact` if/when one lands.

use super::shared::{canonicalize, denominator, exact_binding, finalize, redact, same_binding, sort_by_id};
use serde_json::{Map, Value};

const RESILIENCE: &[&str] = &["idempotency", "pagination", "retry", "rateLimit", "malformed", "partialFailure"];
const PROTOCOLS: &[&str] = &["rest", "graphql", "websocket", "webhook"];
const HTTP_METHODS: &[&str] = &["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"];

fn sha256_re() -> regex::Regex {
    regex::Regex::new(r"^sha256:[a-f0-9]{64}$").unwrap()
}
fn safe_identifier_re() -> regex::Regex {
    regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$").unwrap()
}
fn sensitive_path_re() -> regex::Regex {
    regex::Regex::new(r"^\$(?:(?:\.[A-Za-z_$][A-Za-z0-9_$-]*)|\[(?:\*|0|[1-9]\d*)\])+$").unwrap()
}

fn equal(left: &Value, right: &Value) -> bool {
    canonicalize(left) == canonicalize(right)
}

fn schema_valid(value: &Value) -> bool {
    let id_ok = value.get("id").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    let version_ok = value.get("version").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    let digest_ok = value.get("digest").is_some_and(|d| d.as_str().is_some_and(|s| sha256_re().is_match(s)));
    value.is_object() && id_ok && version_ok && digest_ok
}

fn operation_valid(value: &Value, types: &[&str]) -> bool {
    let name_ok = value.get("name").and_then(Value::as_str).is_some_and(|s| !s.is_empty());
    let type_ok = value.get("type").and_then(Value::as_str).is_some_and(|t| types.contains(&t));
    value.is_object() && name_ok && type_ok
}

fn canonical_path_valid(value: &Value) -> bool {
    let Some(s) = value.as_str() else { return false };
    if !s.starts_with('/') || s.starts_with("//") || s.contains('\\') || s.contains("://") || s.contains('?') || s.contains('#') {
        return false;
    }
    if s.chars().any(|c| (c as u32) <= 0x1f || c as u32 == 0x7f) {
        return false;
    }
    match urlencoding_decode(s) {
        Some(decoded) if decoded == s => {}
        _ => return false,
    }
    if s == "/" {
        return true;
    }
    if s.ends_with('/') {
        return false;
    }
    let segments: Vec<&str> = s.split('/').skip(1).collect();
    segments.iter().all(|seg| !seg.is_empty() && *seg != "." && *seg != ".." && !seg.contains(':'))
}

/// Minimal `decodeURIComponent`-equivalent: percent-decodes; returns `None`
/// on a malformed escape (mirrors JS throwing inside the `try`).
fn urlencoding_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return None;
            }
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).ok()?;
            let byte = u8::from_str_radix(hex, 16).ok()?;
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn raw_artifact_binding_valid(artifact: &Value, kind: &str, binding: &Value, item: &Value) -> bool {
    let item_path = item.get("path").cloned().unwrap_or(Value::Null);
    let artifact_path = artifact.get("path").cloned().unwrap_or(Value::Null);
    artifact.get("kind").and_then(Value::as_str) == Some(kind)
        && artifact.get("redacted") == Some(&Value::Bool(true))
        && artifact.get("caseId") == item.get("id")
        && artifact.get("protocol") == item.get("protocol")
        && artifact.get("method") == item.get("method")
        && artifact_path == item_path
        && equal(artifact.get("operation").unwrap_or(&Value::Null), item.get("operation").unwrap_or(&Value::Null))
        && artifact.get("correlationId") == item.get("correlationId")
        && same_binding(binding, artifact.get("binding").unwrap_or(&Value::Null))
}

fn sanitized_scalar(value: &Value) -> bool {
    value.is_null()
        || value.as_str().is_some_and(|s| s == "[REDACTED]" || (!s.is_empty() && s.chars().all(|c| c == '*')))
}

fn common_pii_key(key: &str) -> bool {
    let normalized: String = key.chars().filter(|c| *c != '-' && *c != '_').flat_map(|c| c.to_lowercase()).collect();
    ["email", "phone", "phonenumber", "socialsecuritynumber", "ssn"].contains(&normalized.as_str())
}

/// Port of `configuredPath(root, path)`.
fn configured_path(root: &Value, path: &str) -> (bool, Vec<Value>) {
    let bytes: Vec<char> = path.chars().collect();
    if bytes.first() != Some(&'$') || bytes.len() == 1 {
        return (false, vec![]);
    }
    #[derive(Clone)]
    enum Token {
        Key(String),
        Star,
        Index(usize),
    }
    let mut tokens = Vec::new();
    let mut index = 1usize;
    let matcher = regex::Regex::new(r"^(?:\.([A-Za-z_$][A-Za-z0-9_$-]*)|\[(\*|0|[1-9]\d*)\])").unwrap();
    let rest: String = bytes[1..].iter().collect();
    let mut cursor = 0usize;
    while cursor < rest.chars().count() {
        let slice: String = rest.chars().skip(cursor).collect();
        let Some(caps) = matcher.captures(&slice) else { return (false, vec![]) };
        let whole = caps.get(0).unwrap().as_str();
        if let Some(key) = caps.get(1) {
            tokens.push(Token::Key(key.as_str().to_string()));
        } else if let Some(idx) = caps.get(2) {
            if idx.as_str() == "*" {
                tokens.push(Token::Star);
            } else {
                tokens.push(Token::Index(idx.as_str().parse().unwrap()));
            }
        }
        cursor += whole.chars().count();
    }
    let _ = index; // unused after refactor to char-cursor loop
    index = cursor;
    let _ = index;

    fn resolve(current: &Value, tokens: &[Token], token_index: usize, broaden_indices: bool) -> (bool, Vec<Value>) {
        if token_index == tokens.len() {
            return (true, vec![current.clone()]);
        }
        match &tokens[token_index] {
            Token::Star => {
                let Some(arr) = current.as_array() else { return (false, vec![]) };
                if arr.is_empty() {
                    return (false, vec![]);
                }
                let mut all_valid = true;
                let mut values = Vec::new();
                for item in arr {
                    let (v, vals) = resolve(item, tokens, token_index + 1, broaden_indices);
                    all_valid &= v;
                    values.extend(vals);
                }
                (all_valid, values)
            }
            Token::Index(i) if broaden_indices => {
                let Some(arr) = current.as_array() else { return (false, vec![]) };
                if arr.is_empty() {
                    return (false, vec![]);
                }
                let mut all_valid = true;
                let mut values = Vec::new();
                for item in arr {
                    let (v, vals) = resolve(item, tokens, token_index + 1, broaden_indices);
                    all_valid &= v;
                    values.extend(vals);
                }
                let _ = i;
                (all_valid, values)
            }
            Token::Index(i) => {
                let Some(arr) = current.as_array() else { return (false, vec![]) };
                match arr.get(*i) {
                    Some(v) => resolve(v, tokens, token_index + 1, broaden_indices),
                    None => (false, vec![]),
                }
            }
            Token::Key(key) => match current.as_object() {
                Some(obj) if obj.contains_key(key) => resolve(&obj[key], tokens, token_index + 1, broaden_indices),
                _ => (false, vec![]),
            },
        }
    }

    let exact = resolve(root, &tokens, 0, false);
    if !exact.0 {
        return exact;
    }
    let has_index = tokens.iter().any(|t| matches!(t, Token::Index(_)));
    if has_index {
        resolve(root, &tokens, 0, true)
    } else {
        exact
    }
}

static SENSITIVE_HEADERS_RE: &str = r"(?i)authorization|bearer|password|clientsecret|apitoken|privatekey|accesstoken|refreshtoken|sessioncookie";

fn raw_pii_leak(content: &str, configured: &[Value]) -> bool {
    if regex::Regex::new(SENSITIVE_HEADERS_RE).unwrap().is_match(content) {
        return true;
    }
    match serde_json::from_str::<Value>(content) {
        Err(_) => {
            let date_re = regex::Regex::new(r"\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2}))?\b").unwrap();
            let without_dates = date_re.replace_all(content, "");
            let leak_re = regex::Regex::new(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}|\b\d{3}-\d{2}-\d{4}\b|\+?\d[\d\s().-]{6,}\d").unwrap();
            leak_re.is_match(&without_dates)
        }
        Ok(parsed) => {
            let mut leaked = false;
            fn visit(value: &Value, leaked: &mut bool) {
                let Some(obj) = value.as_object() else { return };
                for (key, child) in obj {
                    if common_pii_key(key) && !sanitized_scalar(child) {
                        *leaked = true;
                    }
                    visit(child, leaked);
                }
            }
            visit(&parsed, &mut leaked);
            for field in configured {
                let (path, type_) = if let Some(s) = field.as_str() {
                    (s.to_string(), "string".to_string())
                } else if let Some(obj) = field.as_object() {
                    (
                        obj.get("path").and_then(Value::as_str).unwrap_or("").to_string(),
                        obj.get("type").and_then(Value::as_str).unwrap_or("").to_string(),
                    )
                } else {
                    leaked = true;
                    continue;
                };
                if !["email", "phone", "ssn", "string"].contains(&type_.as_str()) {
                    leaked = true;
                    continue;
                }
                let (valid, values) = configured_path(&parsed, &path);
                if !valid || values.is_empty() || values.iter().any(|v| !sanitized_scalar(v)) {
                    leaked = true;
                }
            }
            leaked
        }
    }
}

fn graphql_pack_valid(pack: &Value, item: &Value, binding: &Value) -> bool {
    let is_graphql = pack.get("kind").and_then(Value::as_str) == Some("graphql");
    let binding_ok = same_binding(binding, pack.get("binding").unwrap_or(&Value::Null));
    let depth = pack.get("depth");
    let depth_limit = depth.and_then(|d| d.get("limit")).and_then(Value::as_f64);
    let depth_observed = depth.and_then(|d| d.get("observed")).and_then(Value::as_f64);
    let depth_ok = depth_limit.is_some_and(f64::is_finite)
        && depth_observed.is_some_and(f64::is_finite)
        && depth_limit.unwrap() > 0.0
        && depth_observed.unwrap() >= 0.0
        && depth_observed.unwrap() <= depth_limit.unwrap()
        && depth.and_then(|d| d.get("passed")) == Some(&Value::Bool(true));
    let cost = pack.get("cost");
    let cost_limit = cost.and_then(|c| c.get("limit")).and_then(Value::as_f64);
    let cost_observed = cost.and_then(|c| c.get("observed")).and_then(Value::as_f64);
    let cost_ok = cost_limit.is_some_and(f64::is_finite)
        && cost_observed.is_some_and(f64::is_finite)
        && cost_limit.unwrap() > 0.0
        && cost_observed.unwrap() >= 0.0
        && cost_observed.unwrap() <= cost_limit.unwrap()
        && cost.and_then(|c| c.get("passed")) == Some(&Value::Bool(true));
    let compat = pack.get("schemaCompatibility");
    let compat_ok = compat.and_then(|c| c.get("status")).and_then(Value::as_str) == Some("compatible")
        && compat.and_then(|c| c.get("requestDigest")) == item.get("requestSchema").and_then(|s| s.get("digest"))
        && compat.and_then(|c| c.get("responseDigest")) == item.get("responseSchema").and_then(|s| s.get("digest"));
    is_graphql && binding_ok && depth_ok && cost_ok && compat_ok
}

fn websocket_pack_valid(pack: &Value, binding: &Value) -> bool {
    pack.get("kind").and_then(Value::as_str) == Some("websocket")
        && same_binding(binding, pack.get("binding").unwrap_or(&Value::Null))
        && pack.get("auth") == Some(&Value::Bool(true))
        && pack.get("backpressure") == Some(&Value::Bool(true))
        && pack.get("reconnect") == Some(&Value::Bool(true))
}

fn webhook_pack_valid(pack: &Value, binding: &Value) -> bool {
    pack.get("kind").and_then(Value::as_str) == Some("webhook")
        && same_binding(binding, pack.get("binding").unwrap_or(&Value::Null))
        && pack.get("signature") == Some(&Value::Bool(true))
        && pack.get("replay") == Some(&Value::Bool(true))
        && pack.get("idempotency") == Some(&Value::Bool(true))
        && pack.get("delivery") == Some(&Value::Bool(true))
}

fn sensitive_fields_valid(value: Option<&Value>) -> bool {
    let Some(value) = value else { return true };
    let Some(arr) = value.as_array() else { return false };
    arr.iter().all(|field| {
        if let Some(s) = field.as_str() {
            sensitive_path_re().is_match(s)
        } else if let Some(obj) = field.as_object() {
            !field.is_array()
                && obj.get("path").and_then(Value::as_str).is_some_and(|p| sensitive_path_re().is_match(p))
                && obj.get("type").and_then(Value::as_str).is_some_and(|t| ["email", "phone", "ssn", "string"].contains(&t))
        } else {
            false
        }
    })
}

/// Local re-implementation of `sanitizeProducedArtifact`'s externally
/// visible contract for this call site — see the module doc comment.
fn sanitize_produced_artifact(artifact: Option<&Value>, _sensitive_fields: &[Value]) -> (bool, bool, Value) {
    match artifact {
        None => (false, false, Value::Null),
        Some(a) => {
            let sanitized = redact(a, "");
            let sensitive = sanitized != *a;
            (true, sensitive, sanitized)
        }
    }
}

/// Port of `verifyApiExercise(input)`.
pub fn verify_api_exercise(binding: &Value, cases: &Value, applicability: &Value) -> Value {
    let binding_out = if binding.is_object() { binding.clone() } else { Value::Object(Map::new()) };

    let cases_is_array = cases.is_array();
    let cases_valid = cases_is_array && cases.as_array().unwrap().iter().all(Value::is_object);
    if !cases_valid {
        let mut gaps: Vec<String> = exact_binding(&binding_out).gaps.iter().map(|k| format!("binding-missing:{k}")).collect();
        gaps.push("api-cases-invalid".to_string());
        gaps.sort();
        gaps.dedup();
        return finalize(
            "legion-web-api-exercise",
            serde_json::json!({
                "status": "error", "applicable": Value::Null, "terminal": true, "binding": binding_out,
                "denominator": denominator(&[], &[], &[]).to_value(), "receipts": [], "coverageGaps": gaps,
            }),
        );
    }

    let cases_arr = cases.as_array().unwrap();

    let ids_all_safe = cases_arr.iter().all(|item| {
        item.get("id").and_then(Value::as_str).is_some_and(|s| safe_identifier_re().is_match(s))
    });

    if !ids_all_safe {
        let safe_cases: Vec<&Value> = cases_arr
            .iter()
            .filter(|item| item.get("id").and_then(Value::as_str).is_some_and(|s| safe_identifier_re().is_match(s)))
            .collect();
        let safe_ids: Vec<String> = safe_cases.iter().map(|item| item.get("id").unwrap().as_str().unwrap().to_string()).collect();
        let mut gaps = vec!["api-case-id-invalid".to_string()];
        if cases_arr.iter().any(|item| item.get("id").is_none() || item.get("id") == Some(&Value::Null) || item.get("id") == Some(&Value::String(String::new()))) {
            gaps.push("api-case-id-missing".to_string());
        }
        for id in safe_ids.iter().collect::<std::collections::BTreeSet<_>>() {
            if safe_ids.iter().filter(|v| *v == id).count() > 1 {
                gaps.push(format!("api-case-id-duplicate:{id}"));
            }
        }
        for item in &safe_cases {
            let id = item.get("id").unwrap().as_str().unwrap();
            if item.get("actorId") != binding_out.get("actorId") {
                gaps.push(format!("{id}:actor-binding-mismatch"));
            }
            if item.get("tenantId") != binding_out.get("tenantId") {
                gaps.push(format!("{id}:tenant-binding-mismatch"));
            }
        }
        gaps.sort();
        gaps.dedup();
        return finalize(
            "legion-web-api-exercise",
            serde_json::json!({
                "status": "error", "applicable": Value::Null, "terminal": true, "binding": binding_out,
                "denominator": denominator(&safe_ids, &[], &[]).to_value(), "receipts": [], "coverageGaps": gaps,
            }),
        );
    }

    if cases_arr.is_empty() {
        let source = applicability.get("source");
        let valid = applicability.get("status").and_then(Value::as_str) == Some("not-applicable")
            && applicability.get("reason").and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            && source.and_then(|s| s.get("kind")).and_then(Value::as_str) == Some("configured")
            && source.and_then(|s| s.get("id")).and_then(Value::as_str).is_some_and(|s| !s.is_empty())
            && source.and_then(|s| s.get("digest")).is_some_and(|d| d.as_str().is_some_and(|s| sha256_re().is_match(s)))
            && same_binding(&binding_out, source.and_then(|s| s.get("binding")).unwrap_or(&Value::Null));
        let mut gaps: Vec<String> = exact_binding(&binding_out).gaps.iter().map(|k| format!("binding-missing:{k}")).collect();
        if !valid {
            gaps.push("api-case-denominator-empty".to_string());
            gaps.push("applicability-source-unproven".to_string());
        }
        gaps.sort();
        return finalize(
            "legion-web-api-exercise",
            serde_json::json!({
                "status": if gaps.is_empty() { "pass" } else { "unproven" },
                "applicable": if valid { Value::Bool(false) } else { Value::Null },
                "terminal": true, "binding": binding_out, "applicability": applicability,
                "denominator": denominator(&[], &[], &[]).to_value(), "receipts": [], "coverageGaps": gaps,
            }),
        );
    }

    let sorted_cases = sort_by_id(cases_arr);
    let receipts: Vec<Value> = sorted_cases.iter().map(|item| build_case_receipt(item, &binding_out)).collect();

    let case_ids: Vec<String> = cases_arr.iter().map(|item| item.get("id").and_then(Value::as_str).unwrap_or("").to_string()).collect();
    let receipt_ids: Vec<String> = receipts.iter().map(|r| r.get("id").and_then(Value::as_str).unwrap_or("").to_string()).collect();
    let counts = denominator(&case_ids, &receipt_ids, &[]);

    let mut gaps: Vec<String> = exact_binding(&binding_out).gaps.iter().map(|k| format!("binding-missing:{k}")).collect();
    for receipt in &receipts {
        let id = receipt.get("id").and_then(Value::as_str).unwrap_or("");
        if let Some(rgaps) = receipt.get("coverageGaps").and_then(Value::as_array) {
            for gap in rgaps {
                gaps.push(format!("{id}:{}", gap.as_str().unwrap_or("")));
            }
        }
    }
    if case_ids.iter().any(|id| id.is_empty()) {
        gaps.push("api-case-id-missing".to_string());
    }
    for id in case_ids.iter().filter(|id| !id.is_empty()).collect::<std::collections::BTreeSet<_>>() {
        if case_ids.iter().filter(|v| *v == id).count() > 1 {
            gaps.push(format!("api-case-id-duplicate:{id}"));
        }
    }
    gaps.sort();
    gaps.dedup();

    let has_error = receipts.iter().any(|r| r.get("status").and_then(Value::as_str) == Some("error"));
    let status = if has_error { "error" } else if !gaps.is_empty() { "unproven" } else { "pass" };

    finalize(
        "legion-web-api-exercise",
        serde_json::json!({
            "status": status, "applicable": true, "terminal": true, "binding": binding_out,
            "denominator": counts.to_value(), "receipts": receipts, "coverageGaps": gaps,
        }),
    )
}

fn build_case_receipt(item: &Value, binding: &Value) -> Value {
    let mut gaps: Vec<String> = Vec::new();
    let sensitive_fields_ok = sensitive_fields_valid(item.get("sensitiveFields"));
    let sensitive_fields: Vec<Value> = if sensitive_fields_ok {
        item.get("sensitiveFields").and_then(Value::as_array).cloned().unwrap_or_default()
    } else {
        vec![]
    };
    if !sensitive_fields_ok {
        gaps.push("sensitive-fields-invalid".to_string());
    }
    for key in ["actorId", "tenantId", "dataScope", "lifecycle"] {
        if item.get(key).is_none() || item.get(key) == Some(&Value::Null) {
            gaps.push(format!("missing-{key}"));
        }
    }
    if item.get("actorId") != binding.get("actorId") {
        gaps.push("actor-binding-mismatch".to_string());
    }
    if item.get("tenantId") != binding.get("tenantId") {
        gaps.push("tenant-binding-mismatch".to_string());
    }
    let protocol = item.get("protocol").and_then(Value::as_str).unwrap_or("");
    if !PROTOCOLS.contains(&protocol) {
        gaps.push("protocol-unsupported".to_string());
    }
    let method = item.get("method").and_then(Value::as_str);
    if method.unwrap_or("").is_empty() {
        gaps.push("missing-method".to_string());
    } else {
        let m = method.unwrap();
        match protocol {
            "rest" if !HTTP_METHODS.contains(&m) => gaps.push("rest-method-invalid".to_string()),
            "graphql" if !["GET", "POST"].contains(&m) => gaps.push("graphql-method-invalid".to_string()),
            "websocket" if m != "CONNECT" => gaps.push("websocket-method-invalid".to_string()),
            "webhook" if m != "POST" => gaps.push("webhook-method-invalid".to_string()),
            _ => {}
        }
    }
    if protocol == "rest" && !canonical_path_valid(item.get("path").unwrap_or(&Value::Null)) {
        gaps.push("rest-path-invalid".to_string());
    }
    if protocol == "graphql" && !operation_valid(item.get("operation").unwrap_or(&Value::Null), &["mutation", "query", "subscription"]) {
        gaps.push("graphql-operation-invalid".to_string());
    }
    if protocol == "websocket"
        && (!canonical_path_valid(item.get("path").unwrap_or(&Value::Null))
            || !operation_valid(item.get("operation").unwrap_or(&Value::Null), &["message", "subscribe"]))
    {
        gaps.push("websocket-contract-invalid".to_string());
    }
    if protocol == "webhook"
        && (!canonical_path_valid(item.get("path").unwrap_or(&Value::Null))
            || !operation_valid(item.get("operation").unwrap_or(&Value::Null), &["event"]))
    {
        gaps.push("webhook-contract-invalid".to_string());
    }
    if !schema_valid(item.get("requestSchema").unwrap_or(&Value::Null)) {
        gaps.push("request-schema-unproven".to_string());
    }
    if !schema_valid(item.get("responseSchema").unwrap_or(&Value::Null)) {
        gaps.push("response-schema-unproven".to_string());
    }
    let compat = item.get("compatibility");
    if compat.and_then(|c| c.get("status")).and_then(Value::as_str) != Some("compatible")
        || compat.and_then(|c| c.get("requestDigest")) != item.get("requestSchema").and_then(|s| s.get("digest"))
        || compat.and_then(|c| c.get("responseDigest")) != item.get("responseSchema").and_then(|s| s.get("digest"))
    {
        gaps.push("schema-compatibility-unproven".to_string());
    }
    let has_expected_error = item.as_object().is_some_and(|o| o.contains_key("expectedError"));
    let has_observed_error = item.as_object().is_some_and(|o| o.contains_key("observedError"));
    if !has_expected_error
        || !has_observed_error
        || !equal(item.get("expectedError").unwrap_or(&Value::Null), item.get("observedError").unwrap_or(&Value::Null))
    {
        gaps.push("error-contract-unproven".to_string());
    }
    let correlation_id = item.get("correlationId").and_then(Value::as_str).unwrap_or("");
    if correlation_id.is_empty() {
        gaps.push("correlation-id-missing".to_string());
    }
    let dep = item.get("dependencyBehavior");
    if dep.and_then(|d| d.get("status")).and_then(Value::as_str) != Some("pass")
        || dep.and_then(|d| d.get("terminal")) != Some(&Value::Bool(true))
        || !dep.and_then(|d| d.get("dependencies")).is_some_and(Value::is_array)
        || !same_binding(binding, dep.and_then(|d| d.get("binding")).unwrap_or(&Value::Null))
    {
        gaps.push("dependency-behavior-unproven".to_string());
    }
    if protocol == "graphql" && !graphql_pack_valid(item.get("protocolPack").unwrap_or(&Value::Null), item, binding) {
        gaps.push("graphql-pack-unproven".to_string());
    }
    if protocol == "websocket" && !websocket_pack_valid(item.get("protocolPack").unwrap_or(&Value::Null), binding) {
        gaps.push("websocket-pack-unproven".to_string());
    }
    if protocol == "webhook" && !webhook_pack_valid(item.get("protocolPack").unwrap_or(&Value::Null), binding) {
        gaps.push("webhook-pack-unproven".to_string());
    }

    let raw_artifacts_is_array = item.get("rawArtifacts").is_some_and(Value::is_array);
    let mut raw_artifacts: Vec<Value> = item.get("rawArtifacts").and_then(Value::as_array).cloned().unwrap_or_default();
    raw_artifacts.sort_by(|a, b| {
        serde_json::to_string(&canonicalize(a)).unwrap_or_default().cmp(&serde_json::to_string(&canonicalize(b)).unwrap_or_default())
    });
    if !raw_artifacts_is_array {
        gaps.push("raw-artifact-collection-invalid".to_string());
    }
    for artifact in raw_artifacts.iter().filter(|a| !["request", "response"].contains(&a.get("kind").and_then(Value::as_str).unwrap_or(""))) {
        gaps.push(format!("raw-artifact-unplanned:{}", artifact.get("kind").and_then(Value::as_str).unwrap_or("missing")));
    }
    let mut safe_raw_artifacts: Vec<Value> = Vec::new();
    for kind in ["request", "response"] {
        let matches: Vec<&Value> = raw_artifacts.iter().filter(|a| a.get("kind").and_then(Value::as_str) == Some(kind)).collect();
        if matches.len() > 1 {
            gaps.push(format!("raw-{kind}-evidence-duplicate"));
        }
        let artifact = if matches.len() == 1 && raw_artifact_binding_valid(matches[0], kind, binding, item) {
            Some(matches[0])
        } else {
            None
        };
        let (valid, sensitive, produced) = sanitize_produced_artifact(artifact, &sensitive_fields);
        if artifact.is_none() || !valid {
            gaps.push(format!("raw-{kind}-evidence-invalid"));
        } else {
            safe_raw_artifacts.push(produced);
            let content = artifact
                .and_then(|a| a.get("content"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| {
                    let b64 = artifact.and_then(|a| a.get("bytesBase64")).and_then(Value::as_str).unwrap_or("");
                    base64_decode_utf8(b64)
                });
            let configured: Vec<Value> = sensitive_fields
                .iter()
                .map(|f| {
                    if let Some(s) = f.as_str() {
                        serde_json::json!({ "path": s, "type": "string" })
                    } else {
                        f.clone()
                    }
                })
                .collect();
            if sensitive || raw_pii_leak(&content, &configured) {
                gaps.push(format!("raw-{kind}-pii-leak"));
            }
        }
    }

    if item.get("boundaries") != Some(&Value::Bool(true)) {
        gaps.push("boundaries-unproven".to_string());
    }
    let expected = item.get("expected");
    let observed = item.get("observed");
    let durable = item.get("durableEffect");
    let expected_exists = expected.and_then(|e| e.get("exists"));
    if !matches!(expected_exists, Some(Value::Bool(_))) {
        gaps.push("expected-exists-unbound".to_string());
    }
    let exists_true = expected_exists == Some(&Value::Bool(true));
    let exists_false = expected_exists == Some(&Value::Bool(false));
    if exists_true && !observed.and_then(Value::as_object).is_some_and(|o| o.contains_key("value")) {
        gaps.push("observed-value-missing".to_string());
    }
    if exists_true && !durable.and_then(Value::as_object).is_some_and(|o| o.contains_key("value")) {
        gaps.push("durable-effect-missing".to_string());
    }
    if exists_true && observed.and_then(|o| o.get("exists")) != Some(&Value::Bool(true)) {
        gaps.push("observed-exists-not-true".to_string());
    }
    if exists_true && durable.and_then(|d| d.get("exists")) != Some(&Value::Bool(true)) {
        gaps.push("durable-exists-not-true".to_string());
    }
    if exists_false && observed.and_then(|o| o.get("exists")) != Some(&Value::Bool(false)) {
        gaps.push("observed-exists-not-false".to_string());
    }
    if exists_false && durable.and_then(|d| d.get("exists")) != Some(&Value::Bool(false)) {
        gaps.push("durable-exists-not-false".to_string());
    }
    if exists_false && observed.and_then(Value::as_object).is_some_and(|o| o.contains_key("value")) {
        gaps.push("observed-value-present".to_string());
    }
    if exists_false && durable.and_then(Value::as_object).is_some_and(|o| o.contains_key("value")) {
        gaps.push("durable-effect-present".to_string());
    }
    let expected_has_value = expected.and_then(Value::as_object).is_some_and(|o| o.contains_key("value"));
    let observed_has_value = observed.and_then(Value::as_object).is_some_and(|o| o.contains_key("value"));
    let durable_has_value = durable.and_then(Value::as_object).is_some_and(|o| o.contains_key("value"));
    if expected_has_value && observed_has_value && !equal(&expected.unwrap()["value"], &observed.unwrap()["value"]) {
        gaps.push("observed-value-mismatch".to_string());
    }
    if expected_has_value && durable_has_value && !equal(&expected.unwrap()["value"], &durable.unwrap()["value"]) {
        gaps.push("durable-effect-mismatch".to_string());
    }
    for key in RESILIENCE {
        if item.get(*key) != Some(&Value::Bool(true)) {
            gaps.push(format!("{key}-unproven"));
        }
    }

    gaps.sort();
    gaps.dedup();
    let status = if gaps.contains(&"sensitive-fields-invalid".to_string()) {
        "error"
    } else if !gaps.is_empty() {
        "unproven"
    } else {
        "pass"
    };

    let checks = serde_json::json!({
        "boundaries": item.get("boundaries") == Some(&Value::Bool(true)),
        "idempotency": item.get("idempotency").cloned().unwrap_or(Value::Null),
        "pagination": item.get("pagination").cloned().unwrap_or(Value::Null),
        "retry": item.get("retry").cloned().unwrap_or(Value::Null),
        "rateLimit": item.get("rateLimit").cloned().unwrap_or(Value::Null),
        "malformed": item.get("malformed").cloned().unwrap_or(Value::Null),
        "partialFailure": item.get("partialFailure").cloned().unwrap_or(Value::Null),
    });

    redact(
        &serde_json::json!({
            "id": item.get("id").cloned().unwrap_or(Value::Null),
            "protocol": protocol,
            "method": item.get("method").cloned().unwrap_or(Value::Null),
            "path": item.get("path").cloned().unwrap_or(Value::Null),
            "operation": item.get("operation").cloned().unwrap_or(Value::Null),
            "protocolPack": item.get("protocolPack").cloned().unwrap_or(Value::Null),
            "status": status,
            "terminal": true,
            "actorId": item.get("actorId").cloned().unwrap_or(Value::Null),
            "tenantId": item.get("tenantId").cloned().unwrap_or(Value::Null),
            "dataScope": item.get("dataScope").cloned().unwrap_or(Value::Null),
            "lifecycle": item.get("lifecycle").cloned().unwrap_or(Value::Null),
            "requestSchema": item.get("requestSchema").cloned().unwrap_or(Value::Null),
            "responseSchema": item.get("responseSchema").cloned().unwrap_or(Value::Null),
            "compatibility": item.get("compatibility").cloned().unwrap_or(Value::Null),
            "expectedError": if has_expected_error { item.get("expectedError").cloned().unwrap_or(Value::Null) } else { Value::Null },
            "observedError": if has_observed_error { item.get("observedError").cloned().unwrap_or(Value::Null) } else { Value::Null },
            "correlationId": item.get("correlationId").cloned().unwrap_or(Value::Null),
            "dependencyBehavior": item.get("dependencyBehavior").cloned().unwrap_or(Value::Null),
            "rawArtifacts": safe_raw_artifacts,
            "checks": checks,
            "observed": item.get("observed").cloned().unwrap_or(Value::Null),
            "durableEffect": item.get("durableEffect").cloned().unwrap_or(Value::Null),
            "coverageGaps": gaps,
        }),
        "",
    )
}

fn base64_decode_utf8(s: &str) -> String {
    // Minimal standard-alphabet base64 decoder (no padding assumptions
    // beyond `=`), sufficient for the PII sweep's `Buffer.from(..., 'base64')`.
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lookup = [255u8; 256];
    for (i, &c) in TABLE.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }
    let clean: Vec<u8> = s.bytes().filter(|b| *b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0u32;
    for b in clean {
        let v = lookup[b as usize];
        if v == 255 {
            continue;
        }
        buffer = (buffer << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_binding() -> Value {
        let mut m = Map::new();
        for key in super::super::shared::BINDING_KEYS {
            m.insert(key.to_string(), Value::String(format!("{key}-v")));
        }
        Value::Object(m)
    }

    #[test]
    fn invalid_cases_collection_is_error() {
        let out = verify_api_exercise(&Value::Null, &Value::String("nope".to_string()), &Value::Null);
        assert_eq!(out["status"], "error");
        assert!(out["coverageGaps"].as_array().unwrap().iter().any(|g| g == "api-cases-invalid"));
    }

    #[test]
    fn empty_cases_without_applicability_is_unproven() {
        let binding = full_binding();
        let out = verify_api_exercise(&binding, &Value::Array(vec![]), &Value::Null);
        assert_eq!(out["status"], "unproven");
        assert_eq!(out["applicable"], Value::Null);
    }

    #[test]
    fn empty_cases_with_valid_applicability_is_pass_not_applicable() {
        let binding = full_binding();
        let applicability = serde_json::json!({
            "status": "not-applicable", "reason": "no endpoints",
            "source": { "kind": "configured", "id": "src-1", "digest": format!("sha256:{}", "a".repeat(64)), "binding": binding },
        });
        let out = verify_api_exercise(&binding, &Value::Array(vec![]), &applicability);
        assert_eq!(out["status"], "pass");
        assert_eq!(out["applicable"], false);
    }

    #[test]
    fn invalid_case_id_is_error() {
        let cases = serde_json::json!([{ "id": "bad id" }]);
        let out = verify_api_exercise(&Value::Null, &cases, &Value::Null);
        assert_eq!(out["status"], "error");
        assert!(out["coverageGaps"].as_array().unwrap().iter().any(|g| g == "api-case-id-invalid"));
    }

    #[test]
    fn canonical_path_rejects_double_slash_and_dot_segments() {
        assert!(!canonical_path_valid(&Value::String("//x".to_string())));
        assert!(!canonical_path_valid(&Value::String("/a/../b".to_string())));
        assert!(canonical_path_valid(&Value::String("/a/b".to_string())));
        assert!(canonical_path_valid(&Value::String("/".to_string())));
    }
}
