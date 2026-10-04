//! Native App Store Connect API adapter.
//!
//! This module deliberately does not shell out to `asc` or `ascctl`.  It keeps
//! request planning separate from transport so callers can inspect a plan
//! before setting `execute: true`, while host policy remains the authority for
//! whether a write is allowed.

use reqwest::{Client, Method, Url};
use serde_json::{json, Map, Value};
use std::env;
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "app_store_openapi.rs"]
mod app_store_openapi;
#[path = "app_store_upload.rs"]
mod app_store_upload;

const API_ORIGIN: &str = "https://api.appstoreconnect.apple.com";
const API_HOST: &str = "api.appstoreconnect.apple.com";
const DEFAULT_MAX_PAGES: usize = 20;
const MAX_MAX_PAGES: usize = 100;
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_REQUEST_BODY_BYTES: usize = 8 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES: u64 = 64 * 1024;
const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone)]
struct RequestPlan {
    method: Method,
    url: Url,
    body: Option<Value>,
}

/// Return the local operation catalog.  Discovery is intentionally offline.
pub fn catalog() -> Value {
    json!({
        "adapter": "legion-apple-app-store-connect",
        "apiOrigin": API_ORIGIN,
        "actions": {
            "discover": "Return this catalog without network access",
            "request": "Plan or execute one GET/POST/PATCH/DELETE request",
            "paginate": "Follow bounded same-origin GET links.next pages",
            "template": "Build a redacted request template without network access",
            "dry-run": "Alias for template",
            "openapi": "Discover or select operationId from bounded local JSON OpenAPI spec",
            "operations": "Alias for openapi discovery",
            "upload": "Reserve, transfer, and commit IPA/PKG build upload using Apple presigned operations",
            "apps": "Alias for /v1/apps resources",
            "builds": "Alias for /v1/builds resources",
            "buildUpload": "Native action=upload reserves, transfers, and commits IPA/PKG files with Apple presigned operations",
            "testflight": "Alias for beta groups/testers resources",
            "metadata": "Alias for app/version localization resources",
            "submission": "Alias for review submission resources",
            "signing": "Alias for bundle IDs/certificates/profiles resources"
        },
        "methods": ["GET", "POST", "PATCH", "DELETE"],
        "defaults": {
            "mutationsDryRun": true,
            "maxPages": DEFAULT_MAX_PAGES,
            "maxResponseBytes": MAX_RESPONSE_BYTES,
            "maxRequestBodyBytes": MAX_REQUEST_BODY_BYTES,
            "redirects": "disabled"
        },
        "credentials": [
            "ASC_TOKEN",
            "ASC_ISSUER_ID + ASC_KEY_ID + ASC_PRIVATE_KEY_PATH"
        ],
        "inputSchema": {
            "request": {
                "required": ["path"],
                "properties": {
                    "action": {"const": "request"},
                    "method": {"enum": ["GET", "POST", "PATCH", "DELETE"], "default": "GET"},
                    "path": {"pattern": "^/v(1|2)/", "origin": API_ORIGIN},
                    "query": {"type": "object", "values": ["string", "number", "boolean", "null", "array"]},
                    "body": {"type": "object-or-array-or-scalar", "maxBytes": MAX_REQUEST_BODY_BYTES},
                    "execute": {"type": "boolean", "default": false}
                }
            },
            "paginate": {
                "required": ["path"],
                "fixedMethod": "GET",
                "maxPages": {"type": "integer", "minimum": 1, "maximum": MAX_MAX_PAGES}
            },
            "upload": {
                "required": ["artifact", "appId", "version", "buildNumber"],
                "artifact": {"extensions": [".ipa", ".pkg"], "maxBytes": 8589934592_u64},
                "platform": {"enum": ["IOS", "MAC_OS", "TV_OS", "VISION_OS"]},
                "execute": {"type": "boolean", "default": false},
                "notes": ["Apple API reserves upload operations before presigned transfer", "processing remains separate from publication"]
            },
            "alias": {
                "required": ["action"],
                "operation": {"enum": ["list", "view", "create", "update", "delete", "submit"]},
                "resource": {"type": "string"},
                "id": {"type": "string"},
                "parentId": {"type": "string", "description": "Parent resource ID for relationship routes"},
                "execute": {"type": "boolean", "default": false}
            }
        },
        "routes": {
            "apps": ["/v1/apps", "/v1/apps/{id}"],
            "builds": ["/v1/builds", "/v1/builds/{id}"],
            "testflight": ["/v1/betaGroups", "/v1/betaGroups/{id}", "/v1/betaTesters", "/v1/betaTesters/{id}", "/v1/preReleaseVersions", "/v1/preReleaseVersions/{id}"],
            "metadata": ["/v1/appStoreVersions", "/v1/appStoreVersions/{id}/appStoreVersionLocalizations", "/v1/appStoreVersionLocalizations/{id}", "/v1/appInfos/{id}/appInfoLocalizations", "/v1/appInfoLocalizations/{id}"],
            "submission": ["/v1/appStoreVersionSubmissions", "/v1/appStoreVersionSubmissions/{id}", "/v1/appStoreVersions/{id}/appStoreVersionSubmission"],
            "signing": ["/v1/bundleIds", "/v1/bundleIds/{id}", "/v1/certificates", "/v1/certificates/{id}", "/v1/profiles", "/v1/profiles/{id}"]
        },
        "notes": [
            "execute=true is the caller's explicit effect request; host Guard remains authoritative",
            "upload or transport does not imply processing, review, approval, or publication",
            "successful responses retain HTTP status, data, links.next, and recognized processing state"
        ]
    })
}

/// Invoke the native App Store Connect adapter.
///
/// Arguments are JSON so the same contract can be used by CLI and MCP hosts.
/// Every operation is a dry run unless `execute` is explicitly true.  Network
/// and credential failures are returned as `Err`; HTTP responses retain their
/// exact status and decoded body in `Ok`.
pub async fn invoke(arguments: &Value) -> Result<Value, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;
    let action = object
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("discover")
        .to_ascii_lowercase();
    if object.contains_key("spec_path") || matches!(action.as_str(), "openapi" | "operations") {
        return app_store_openapi::invoke(arguments).await;
    }
    if action == "upload"
        || (action == "builds"
            && object
                .get("operation")
                .and_then(Value::as_str)
                .is_some_and(|operation| operation.eq_ignore_ascii_case("upload")))
    {
        return app_store_upload::invoke(arguments).await;
    }
    ensure_action(&action)?;

    match action.as_str() {
        "discover" | "catalog" => Ok(catalog()),
        "template" | "dry-run" => {
            let plan = plan_for(object, false)?;
            Ok(template_result(&plan, object))
        }
        "request" => invoke_request(object).await,
        "paginate" => invoke_paginate(object).await,
        "apps" | "builds" | "testflight" | "metadata" | "submission" | "signing" => {
            invoke_alias(action.as_str(), object).await
        }
        _ => unreachable!("ensure_action validates action"),
    }
}

fn ensure_action(action: &str) -> Result<(), String> {
    match action {
        "discover" | "catalog" | "template" | "dry-run" | "request" | "paginate" | "openapi"
        | "operations" | "upload" | "apps" | "builds" | "testflight" | "metadata" | "submission"
        | "signing" => Ok(()),
        other => Err(format!("unknown action: {other}")),
    }
}

async fn invoke_alias(action: &str, object: &Map<String, Value>) -> Result<Value, String> {
    let mut request = object.clone();
    request.insert("action".to_string(), Value::String("request".to_string()));
    let operation = object
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("list");
    let path = object
        .get("path")
        .and_then(Value::as_str)
        .map(str::to_string)
        .map(Ok)
        .unwrap_or_else(|| alias_path(action, operation, object))?;
    request.insert("path".to_string(), Value::String(path));
    if !request.contains_key("method") {
        request.insert(
            "method".to_string(),
            Value::String(default_alias_method(operation).to_string()),
        );
    }
    invoke_request(&request).await
}

fn default_alias_method(operation: &str) -> &'static str {
    match operation.to_ascii_lowercase().as_str() {
        "create" | "upload" | "submit" | "add" => "POST",
        "update" | "edit" | "patch" => "PATCH",
        "delete" | "remove" => "DELETE",
        _ => "GET",
    }
}

fn alias_path(action: &str, operation: &str, object: &Map<String, Value>) -> Result<String, String> {
    let id = safe_segment(object, "id")?.unwrap_or_default();
    let parent_id = if object.contains_key("parentId") {
        safe_segment(object, "parentId")?
    } else if object.contains_key("appStoreVersionId") {
        safe_segment(object, "appStoreVersionId")?
    } else if object.contains_key("versionId") {
        safe_segment(object, "versionId")?
    } else {
        None
    };
    let resource = object
        .get("resource")
        .or_else(|| object.get("type"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let base = match (action, resource.as_str()) {
        ("testflight", "tester" | "testers" | "betatester" | "betatesters") => "/v1/betaTesters",
        ("testflight", "prerelease" | "prereleases" | "prereleaseversion" | "prereleaseversions") => "/v1/preReleaseVersions",
        ("metadata", "version" | "versions") => "/v1/appStoreVersions",
        ("metadata", "localization" | "localizations" | "versionlocalization" | "versionlocalizations") => "/v1/appStoreVersionLocalizations",
        ("metadata", "appinfo" | "appinfos" | "appinfolocalization" | "appinfolocalizations") => "/v1/appInfoLocalizations",
        ("submission", "version" | "versions") => "/v1/appStoreVersions",
        ("signing", "certificate" | "certificates") => "/v1/certificates",
        ("signing", "profile" | "profiles") => "/v1/profiles",
        ("signing", "bundleid" | "bundleids" | "bundle") => "/v1/bundleIds",
        ("apps", _) => "/v1/apps",
        ("builds", _) => "/v1/builds",
        ("testflight", _) => "/v1/betaGroups",
        ("metadata", _) => "/v1/appStoreVersionLocalizations",
        ("submission", _) => "/v1/appStoreVersionSubmissions",
        ("signing", _) => "/v1/bundleIds",
        _ => "/v1/apps",
    };
    let relationship = match (action, resource.as_str()) {
        ("testflight", "group" | "groups" | "betagroup" | "betagroups") => {
            parent_id.as_deref().map(|value| format!("/v1/apps/{value}/betaGroups"))
        }
        ("testflight", "tester" | "testers" | "betatester" | "betatesters") => {
            parent_id.as_deref().map(|value| format!("/v1/betaGroups/{value}/betaTesters"))
        }
        ("metadata", "localization" | "localizations" | "versionlocalization" | "versionlocalizations") => {
            parent_id.as_deref().map(|value| format!("/v1/appStoreVersions/{value}/appStoreVersionLocalizations"))
        }
        ("metadata", "appinfo" | "appinfos" | "appinfolocalization" | "appinfolocalizations") => {
            parent_id.as_deref().map(|value| format!("/v1/appInfos/{value}/appInfoLocalizations"))
        }
        ("submission", "version" | "versions") => {
            parent_id.as_deref().map(|value| format!("/v1/appStoreVersions/{value}/appStoreVersionSubmission"))
        }
        ("submission", _) if parent_id.is_some() => {
            parent_id.as_deref().map(|value| format!("/v1/appStoreVersions/{value}/appStoreVersionSubmission"))
        }
        _ => None,
    };
    let base = relationship.as_deref().unwrap_or(base);
    let singular = matches!(
        operation.to_ascii_lowercase().as_str(),
        "get" | "view" | "update" | "edit" | "delete" | "remove" | "submit"
    );
    if singular && !id.is_empty() {
        Ok(format!("{base}/{id}"))
    } else {
        Ok(base.to_string())
    }
}

fn safe_segment(object: &Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    let Some(value) = object.get(key) else { return Ok(None) };
    let Some(value) = value.as_str() else { return Err(format!("{key} must be a string")) };
    if value.is_empty() {
        return Ok(None);
    }
    if value == "."
        || value == ".."
        || value.chars().any(|character| character.is_control() || matches!(character, '/' | '\\' | '?' | '#'))
    {
        return Err(format!("{key} contains an unsafe path segment"));
    }
    Ok(Some(value.to_string()))
}

async fn invoke_request(object: &Map<String, Value>) -> Result<Value, String> {
    let plan = plan_for(object, true)?;
    let execute = object
        .get("execute")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !execute {
        return Ok(template_result(&plan, object));
    }
    execute_plan(&plan).await
}

async fn invoke_paginate(object: &Map<String, Value>) -> Result<Value, String> {
    let mut request = object.clone();
    request.insert("method".into(), Value::String("GET".into()));
    let first = plan_for(&request, false)?;
    let execute = object
        .get("execute")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let max_pages = bounded_pages(object.get("maxPages"))?;
    if !execute {
        let mut result = template_result(&first, object);
        if let Some(map) = result.as_object_mut() {
            map.insert("maxPages".into(), json!(max_pages));
            map.insert("pagination".into(), json!("same-origin links.next"));
        }
        return Ok(result);
    }

    let client = http_client()?;
    let auth = authorization_header()?;
    let mut next = Some(first.url);
    let mut pages = Vec::new();
    for _ in 0..max_pages {
        let url = match next.take() {
            Some(url) => url,
            None => break,
        };
        let response = send_get(&client, &url, auth.as_deref()).await?;
        if !response.get("ok").and_then(Value::as_bool).unwrap_or(false) {
            let mut failure = response;
            if let Some(map) = failure.as_object_mut() {
                map.remove("next");
                let page_count = pages.len() + 1;
                map.insert("pages".into(), Value::Array(pages));
                map.insert("pageCount".into(), json!(page_count));
                map.insert("maxPages".into(), json!(max_pages));
                map.insert("truncated".into(), Value::Bool(false));
            }
            return Ok(failure);
        }
        let next_url = response.get("next").and_then(Value::as_str).map(str::to_string);
        pages.push(response);
        next = match next_url {
            Some(raw) => Some(same_origin_next(&raw)?),
            None => None,
        };
    }
    let truncated = next.is_some();
    Ok(json!({
        "ok": !truncated && pages.iter().all(|page| page.get("ok").and_then(Value::as_bool).unwrap_or(false)),
        "pages": pages,
        "pageCount": pages.len(),
        "maxPages": max_pages,
        "truncated": truncated
    }))
}

fn plan_for(object: &Map<String, Value>, allow_missing_path: bool) -> Result<RequestPlan, String> {
    let method = parse_method(object.get("method").and_then(Value::as_str).unwrap_or("GET"))?;
    let raw_path = object
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            if allow_missing_path {
                "path is required for request".to_string()
            } else {
                "path is required for template".to_string()
            }
        })?;
    let path = normalize_path(raw_path)?;
    let mut url = Url::parse(&format!("{API_ORIGIN}{path}"))
        .map_err(|_| "invalid App Store Connect path".to_string())?;
    validate_origin(&url)?;
    append_query(&mut url, object.get("query"))?;
    let body = object.get("body").cloned();
    if body.is_some() && method == Method::GET {
        return Err("GET requests cannot include body".to_string());
    }
    if let Some(body) = &body {
        let bytes = serde_json::to_vec(body).map_err(|_| "request body is not serializable".to_string())?;
        if bytes.len() > MAX_REQUEST_BODY_BYTES {
            return Err(format!("request body exceeds {MAX_REQUEST_BODY_BYTES} bytes"));
        }
    }
    Ok(RequestPlan { method, url, body })
}

fn parse_method(raw: &str) -> Result<Method, String> {
    match raw.to_ascii_uppercase().as_str() {
        "GET" => Ok(Method::GET),
        "POST" => Ok(Method::POST),
        "PATCH" => Ok(Method::PATCH),
        "DELETE" => Ok(Method::DELETE),
        _ => Err("method must be GET, POST, PATCH, or DELETE".to_string()),
    }
}

fn normalize_path(raw: &str) -> Result<String, String> {
    if !raw.starts_with("/v1/") && !raw.starts_with("/v2/") {
        return Err("path must begin with /v1/ or /v2/".to_string());
    }
    if raw.contains("//") || raw.contains("..") || raw.contains('#') || raw.contains('?') {
        return Err("path contains an unsafe or separately encoded component".to_string());
    }
    if raw.chars().any(|c| c.is_control() || c == '\\') {
        return Err("path contains control characters".to_string());
    }
    Ok(raw.to_string())
}

fn append_query(url: &mut Url, query: Option<&Value>) -> Result<(), String> {
    let Some(query) = query else { return Ok(()) };
    let object = query
        .as_object()
        .ok_or_else(|| "query must be a JSON object".to_string())?;
    let mut pairs = Vec::new();
    for (key, value) in object {
        if key.is_empty() || key.chars().any(|c| c.is_control()) {
            return Err("query contains an invalid key".to_string());
        }
        match value {
            Value::Array(values) => {
                for value in values {
                    pairs.push((key.clone(), scalar_string(value)?));
                }
            }
            _ => pairs.push((key.clone(), scalar_string(value)?)),
        }
    }
    pairs.sort_by(|left, right| left.cmp(right));
    {
        let mut serializer = url.query_pairs_mut();
        for (key, value) in pairs {
            serializer.append_pair(&key, &value);
        }
    }
    Ok(())
}

fn scalar_string(value: &Value) -> Result<String, String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        Value::Null => Ok(String::new()),
        _ => Err("query values must be strings, numbers, booleans, null, or arrays of these".into()),
    }
}

fn template_result(plan: &RequestPlan, object: &Map<String, Value>) -> Value {
    json!({
        "ok": true,
        "dryRun": true,
        "executeRequired": true,
        "request": {
            "method": plan.method.as_str(),
            "url": plan.url.as_str(),
            "body": plan.body.clone(),
            "headers": {"Authorization": "<redacted>", "Content-Type": "application/json"}
        },
        "mutation": plan.method != Method::GET,
        "callerFields": object.keys().cloned().collect::<Vec<_>>()
    })
}

fn bounded_pages(value: Option<&Value>) -> Result<usize, String> {
    let pages = value
        .and_then(Value::as_u64)
        .map(|value| value as usize)
        .unwrap_or(DEFAULT_MAX_PAGES);
    if pages == 0 || pages > MAX_MAX_PAGES {
        return Err(format!("maxPages must be between 1 and {MAX_MAX_PAGES}"));
    }
    Ok(pages)
}

fn http_client() -> Result<Client, String> {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|_| "could not construct App Store Connect HTTP client".to_string())
}

fn authorization_header() -> Result<Option<String>, String> {
    if let Ok(token) = env::var("ASC_TOKEN") {
        if token.trim().is_empty() {
            return Err("ASC_TOKEN is empty".to_string());
        }
        if token.len() > MAX_CREDENTIAL_BYTES {
            return Err("ASC_TOKEN exceeds credential size limit".to_string());
        }
        let token = token.trim();
        return Ok(Some(if token.to_ascii_lowercase().starts_with("bearer ") {
            token.to_string()
        } else {
            format!("Bearer {token}")
        }));
    }
    let issuer = bounded_env("ASC_ISSUER_ID", MAX_CREDENTIAL_BYTES)?;
    let key_id = bounded_env("ASC_KEY_ID", MAX_CREDENTIAL_BYTES)?;
    let path = bounded_env("ASC_PRIVATE_KEY_PATH", MAX_CREDENTIAL_BYTES)?;
    let metadata = fs::metadata(&path).map_err(|_| "could not read App Store Connect private key".to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_PRIVATE_KEY_BYTES {
        return Err("App Store Connect private key exceeds file size limit".to_string());
    }
    let pem = fs::read(&path).map_err(|_| "could not read App Store Connect private key".to_string())?;
    if pem.len() as u64 > MAX_PRIVATE_KEY_BYTES {
        return Err("App Store Connect private key exceeds file size limit".to_string());
    }
    let encoding = jsonwebtoken::EncodingKey::from_ec_pem(&pem)
        .map_err(|_| "could not parse App Store Connect private key".to_string())?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system clock is before Unix epoch".to_string())?
        .as_secs();
    let claims = json!({"iss": issuer, "iat": now, "exp": now + 60 * 18, "aud": "appstoreconnect-v1"});
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some(key_id);
    header.typ = Some("JWT".to_string());
    let token = jsonwebtoken::encode(&header, &claims, &encoding)
        .map_err(|_| "could not sign App Store Connect request".to_string())?;
    Ok(Some(format!("Bearer {token}")))
}

fn bounded_env(name: &str, max_bytes: usize) -> Result<String, String> {
    let value = env::var(name).map_err(|_| "missing App Store Connect credentials".to_string())?;
    if value.trim().is_empty() {
        return Err(format!("{name} is empty"));
    }
    if value.len() > max_bytes {
        return Err(format!("{name} exceeds credential size limit"));
    }
    Ok(value)
}

async fn execute_plan(plan: &RequestPlan) -> Result<Value, String> {
    let client = http_client()?;
    let auth = authorization_header()?.ok_or_else(|| "missing App Store Connect credentials".to_string())?;
    let mut request = client.request(plan.method.clone(), plan.url.clone());
    request = request.header(reqwest::header::AUTHORIZATION, auth);
    if let Some(body) = &plan.body {
        request = request
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .json(body);
    }
    let response = request
        .send()
        .await
        .map_err(|_| "App Store Connect request failed".to_string())?;
    decode_response(response).await
}

async fn send_get(client: &Client, url: &Url, auth: Option<&str>) -> Result<Value, String> {
    let mut request = client.get(url.clone());
    if let Some(auth) = auth {
        request = request.header(reqwest::header::AUTHORIZATION, auth);
    }
    let response = request
        .send()
        .await
        .map_err(|_| "App Store Connect pagination request failed".to_string())?;
    decode_response(response).await
}

async fn decode_response(mut response: reqwest::Response) -> Result<Value, String> {
    let status = response.status().as_u16();
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(format!("App Store Connect response exceeds {MAX_RESPONSE_BYTES} bytes"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "could not read App Store Connect response".to_string())?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(format!("App Store Connect response exceeds {MAX_RESPONSE_BYTES} bytes"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(decode_payload(status, &bytes))
}

fn decode_payload(status: u16, bytes: &[u8]) -> Value {
    let body = serde_json::from_slice::<Value>(bytes).unwrap_or_else(|_| {
        json!({"rawBodyAvailable": true, "byteLength": bytes.len()})
    });
    let mut result = json!({
        "ok": (200..300).contains(&status),
        "status": status,
        "data": body.clone()
    });
    if let Some(state) = find_processing_state(&body) {
        result["processingState"] = Value::String(state);
    }
    if let Some(next) = body.get("links").and_then(|links| links.get("next")).and_then(Value::as_str) {
        result["next"] = Value::String(next.to_string());
    }
    result
}

fn find_processing_state(value: &Value) -> Option<String> {
    match value {
        Value::Object(map) => {
            for key in ["processingState", "processingStateValue", "state"] {
                if let Some(value) = map.get(key).and_then(Value::as_str) {
                    if ["PROCESSING", "VALID", "INVALID", "FAILED", "COMPLETE", "COMPLETE_WITH_ERRORS"]
                        .contains(&value)
                    {
                        return Some(value.to_string());
                    }
                }
            }
            map.values().find_map(find_processing_state)
        }
        Value::Array(values) => values.iter().find_map(find_processing_state),
        _ => None,
    }
}

fn validate_origin(url: &Url) -> Result<(), String> {
    if url.scheme() != "https"
        || url.host_str() != Some(API_HOST)
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("request URL is outside App Store Connect origin".to_string());
    }
    Ok(())
}

fn same_origin_next(raw: &str) -> Result<Url, String> {
    let url = match Url::parse(raw) {
        Ok(url) => url,
        Err(_) if raw.starts_with('/') => Url::parse(&format!("{API_ORIGIN}{raw}"))
            .map_err(|_| "pagination next link is not a URL".to_string())?,
        Err(_) => return Err("pagination next link is not a URL".to_string()),
    };
    validate_origin(&url).map_err(|_| "pagination next link is outside App Store Connect origin".to_string())?;
    if (!url.path().starts_with("/v1/") && !url.path().starts_with("/v2/"))
        || url.path().contains("//")
        || url.path().contains("..")
    {
        return Err("pagination next link is outside supported API paths".to_string());
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn catalog_is_local_and_lists_native_actions() {
        let value = catalog();
        assert_eq!(value["apiOrigin"], API_ORIGIN);
        assert!(value["actions"]["paginate"].is_string());
        assert_eq!(value["defaults"]["redirects"], "disabled");
    }

    #[test]
    fn mutation_defaults_to_redacted_dry_run() {
        let args = json!({"action":"request","method":"POST","path":"/v1/apps","body":{"data":{"type":"apps"}}});
        let plan = plan_for(args.as_object().unwrap(), true).unwrap();
        let result = template_result(&plan, args.as_object().unwrap());
        assert_eq!(result["dryRun"], true);
        assert_eq!(result["request"]["headers"]["Authorization"], "<redacted>");
        assert_eq!(result["request"]["method"], "POST");
    }

    #[test]
    fn paths_are_restricted_to_supported_https_api() {
        assert!(normalize_path("https://evil.example/v1/apps").is_err());
        assert!(normalize_path("/v1/apps/../keys").is_err());
        assert!(normalize_path("/v3/apps").is_err());
        assert!(normalize_path("/v1/apps").is_ok());
    }

    #[test]
    fn query_is_sorted_and_arrays_repeat() {
        let args = json!({"action":"request","path":"/v1/apps","query":{"filter":["b","a"],"limit":2}});
        let plan = plan_for(args.as_object().unwrap(), true).unwrap();
        assert_eq!(plan.url.as_str(), "https://api.appstoreconnect.apple.com/v1/apps?filter=a&filter=b&limit=2");
    }

    #[test]
    fn next_links_are_same_origin_and_bounded() {
        let url = same_origin_next("https://api.appstoreconnect.apple.com/v1/apps?cursor=1").unwrap();
        assert_eq!(url.path(), "/v1/apps");
        assert!(same_origin_next("https://evil.example/v1/apps").is_err());
        assert!(same_origin_next("https://api.appstoreconnect.apple.com:8443/v1/apps").is_err());
        assert!(bounded_pages(Some(&json!(0))).is_err());
        assert!(bounded_pages(Some(&json!(MAX_MAX_PAGES + 1))).is_err());
    }

    #[test]
    fn aliases_resolve_common_paths() {
        let args = json!({"action":"builds","operation":"view","id":"build-1"});
        let mut object = args.as_object().unwrap().clone();
        object.insert("action".into(), Value::String("request".into()));
        object.insert("path".into(), Value::String(alias_path("builds", "view", args.as_object().unwrap()).unwrap()));
        let plan = plan_for(&object, true).unwrap();
        assert_eq!(plan.url.path(), "/v1/builds/build-1");
    }

    #[test]
    fn relationship_aliases_use_actual_store_connect_routes() {
        let args = json!({"action":"metadata","resource":"localization","operation":"list","parentId":"version-1"});
        assert_eq!(alias_path("metadata", "list", args.as_object().unwrap()).unwrap(), "/v1/appStoreVersions/version-1/appStoreVersionLocalizations");
        let args = json!({"action":"testflight","resource":"tester","operation":"list","parentId":"group-1"});
        assert_eq!(alias_path("testflight", "list", args.as_object().unwrap()).unwrap(), "/v1/betaGroups/group-1/betaTesters");
    }

    #[test]
    fn initial_request_origin_rejects_nonstandard_port() {
        let url = Url::parse("https://api.appstoreconnect.apple.com:8443/v1/apps").unwrap();
        assert!(validate_origin(&url).is_err());
    }

    #[test]
    fn processing_state_is_found_in_fixture_response() {
        let fixture = br#"{"data":{"attributes":{"processingState":"PROCESSING"}},"links":{"next":"https://api.appstoreconnect.apple.com/v1/apps?cursor=2"}}"#;
        let result = decode_payload(202, fixture);
        assert_eq!(result["status"], 202);
        assert_eq!(result["processingState"], "PROCESSING");
        assert!(result["data"].is_object());
        assert!(result["next"].as_str().unwrap().contains("cursor=2"));
    }

    #[test]
    fn unknown_action_is_rejected_without_transport() {
        let error = ensure_action("unknown").unwrap_err();
        assert!(error.contains("unknown action"));
    }
}
