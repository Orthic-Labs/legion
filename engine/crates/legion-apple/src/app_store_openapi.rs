//! Bounded local OpenAPI operation discovery for App Store Connect.
//!
//! The specification is caller supplied, read locally, and never treated as
//! an authority for network origin.  The adapter accepts JSON OpenAPI 3 or
//! Swagger 2 documents; Apple request execution still goes through the parent
//! fixed-origin request planner.

use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;

const MAX_SPEC_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REF_DEPTH: usize = 32;
const MAX_REFS: usize = 2_000;
const MAX_OPERATIONS: usize = 4_000;

#[derive(Debug, Clone)]
struct Operation {
    operation_id: String,
    method: String,
    path: String,
    value: Value,
}

pub async fn invoke(arguments: &Value) -> Result<Value, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "arguments must be a JSON object".to_string())?;
    let spec_path = object
        .get("spec_path")
        .or_else(|| object.get("specPath"))
        .and_then(Value::as_str)
        .ok_or_else(|| "spec_path is required for OpenAPI actions".to_string())?;
    let spec = read_spec(spec_path)?;
    let operations = operations(&spec)?;
    let action = object
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("discover")
        .to_ascii_lowercase();
    if matches!(action.as_str(), "discover" | "catalog" | "openapi" | "operations")
        && !has_selector(object)
    {
        return Ok(discovery(spec_path, &operations));
    }
    let operation = select_operation(object, &operations)?;
    let request = build_request(object, &spec, &operation)?;
    let execute = object
        .get("execute")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let request = request
        .as_object()
        .ok_or_else(|| "OpenAPI request planner returned a non-object".to_string())?;
    let mut result = super::invoke_request(request).await?;
    if let Some(map) = result.as_object_mut() {
        map.insert("operationId".into(), Value::String(operation.operation_id));
        map.insert("specPath".into(), Value::String(spec_path.to_string()));
        map.insert("openapiExecute".into(), Value::Bool(execute));
    }
    Ok(result)
}

fn has_selector(object: &Map<String, Value>) -> bool {
    ["operationId", "operation_id", "operation", "method", "path"]
        .iter()
        .any(|key| object.contains_key(*key))
}

fn read_spec(path: &str) -> Result<Value, String> {
    if path.trim().is_empty() || path.len() > 4 * 1024 {
        return Err("spec_path is empty or exceeds path limit".to_string());
    }
    let path = Path::new(path);
    let metadata = fs::metadata(path).map_err(|_| "could not read local OpenAPI spec".to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_SPEC_BYTES {
        return Err("local OpenAPI spec exceeds file limit".to_string());
    }
    let bytes = fs::read(path).map_err(|_| "could not read local OpenAPI spec".to_string())?;
    if bytes.len() as u64 > MAX_SPEC_BYTES {
        return Err("local OpenAPI spec exceeds file limit".to_string());
    }
    let value = serde_json::from_slice::<Value>(&bytes)
        .map_err(|_| "OpenAPI spec must be bounded JSON; YAML is unsupported without a parser dependency".to_string())?;
    if !value.get("paths").map(Value::is_object).unwrap_or(false) {
        return Err("OpenAPI spec must contain a paths object".to_string());
    }
    Ok(value)
}

fn discovery(spec_path: &str, operations: &[Operation]) -> Value {
    let operations = operations
        .iter()
        .map(|operation| {
            json!({
                "operationId": operation.operation_id,
                "method": operation.method,
                "path": operation.path,
                "summary": operation.value.get("summary").cloned().unwrap_or(Value::Null),
                "tags": operation.value.get("tags").cloned().unwrap_or_else(|| json!([]))
            })
        })
        .collect::<Vec<_>>();
    json!({
        "ok": true,
        "dryRun": true,
        "specPath": spec_path,
        "operationCount": operations.len(),
        "operations": operations,
        "origin": "https://api.appstoreconnect.apple.com",
        "selection": "operationId, operation_id, or operation"
    })
}

fn operations(spec: &Value) -> Result<Vec<Operation>, String> {
    let paths = spec
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| "OpenAPI spec paths must be an object".to_string())?;
    let mut result = Vec::new();
    for (path, path_value) in paths {
        if !path.starts_with("/v1/") && !path.starts_with("/v2/") {
            continue;
        }
        let methods = path_value
            .as_object()
            .ok_or_else(|| format!("OpenAPI path {path} must be an object"))?;
        for (method, value) in methods {
            if !matches!(method.to_ascii_lowercase().as_str(), "get" | "post" | "patch" | "delete") {
                continue;
            }
            let mut operation = resolve_bounded(value, spec)?;
            if let Some(path_parameters) = methods.get("parameters") {
                let path_parameters = resolve_bounded(path_parameters, spec)?;
                if let Some(map) = operation.as_object_mut() {
                    map.insert("__pathParameters".into(), path_parameters);
                }
            }
            let operation_id = operation
                .get("operationId")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("{} {}", method.to_ascii_uppercase(), path));
            result.push(Operation {
                operation_id,
                method: method.to_ascii_uppercase(),
                path: path.to_string(),
                value: operation,
            });
            if result.len() > MAX_OPERATIONS {
                return Err("OpenAPI operation count exceeds limit".to_string());
            }
        }
    }
    result.sort_by(|left, right| left.operation_id.cmp(&right.operation_id));
    Ok(result)
}

fn select_operation<'a>(object: &Map<String, Value>, operations: &'a [Operation]) -> Result<Operation, String> {
    let selector = object
        .get("operationId")
        .or_else(|| object.get("operation_id"))
        .or_else(|| object.get("operation"))
        .and_then(Value::as_str)
        .ok_or_else(|| "operationId is required for OpenAPI execution".to_string())?;
    operations
        .iter()
        .find(|operation| operation.operation_id == selector)
        .cloned()
        .ok_or_else(|| format!("unknown OpenAPI operationId: {selector}"))
}

fn build_request(object: &Map<String, Value>, spec: &Value, operation: &Operation) -> Result<Value, String> {
    let mut path = operation.path.clone();
    let parameters = operation_parameters(spec, &operation.value)?;
    let path_params = object
        .get("pathParams")
        .or_else(|| object.get("path_params"))
        .or_else(|| object.get("params"))
        .and_then(Value::as_object);
    let query = object.get("query").and_then(Value::as_object);
    let mut query_values = Map::new();
    for parameter in &parameters {
        let name = parameter.get("name").and_then(Value::as_str).unwrap_or("");
        let location = parameter.get("in").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() || !matches!(location, "path" | "query") {
            continue;
        }
        let source = if location == "path" { path_params } else { query };
        let value = source.and_then(|values| values.get(name)).or_else(|| parameter.get("schema").and_then(|schema| schema.get("default")));
        if parameter.get("required").and_then(Value::as_bool).unwrap_or(false) && value.is_none() {
            return Err(format!("required OpenAPI {location} parameter is missing: {name}"));
        }
        let Some(value) = value else { continue };
        if location == "path" {
            let rendered = scalar(value)?;
            path = path.replace(&format!("{{{name}}}"), &percent_encode_path(&rendered));
        } else {
            query_values.insert(name.to_string(), value.clone());
        }
    }
    if path.contains('{') || path.contains('}') {
        return Err("required OpenAPI path parameter is missing".to_string());
    }
    let body = object.get("body").cloned();
    for parameter in &parameters {
        if parameter.get("in").and_then(Value::as_str) == Some("body") {
            let required = parameter.get("required").and_then(Value::as_bool).unwrap_or(false);
            if required && body.is_none() {
                return Err("required OpenAPI request body is missing".to_string());
            }
            if let (Some(body), Some(schema)) = (&body, parameter.get("schema")) {
                validate_schema(body, schema, "body", spec)?;
            }
        }
    }
    if let Some(request_body) = operation.value.get("requestBody") {
        let request_body = resolve_bounded(request_body, spec)?;
        let required = request_body.get("required").and_then(Value::as_bool).unwrap_or(false);
        if required && body.is_none() {
            return Err("required OpenAPI request body is missing".to_string());
        }
        if let Some(body) = &body {
            let schema = request_body
                .get("content")
                .and_then(Value::as_object)
                .and_then(|content| content.get("application/json").or_else(|| content.values().next()))
                .and_then(|content| content.get("schema"));
            if let Some(schema) = schema {
                let schema = resolve_bounded(schema, spec)?;
                validate_schema(body, &schema, "body", spec)?;
            }
        }
    }
    let mut request = Map::new();
    request.insert("action".into(), Value::String("request".into()));
    request.insert("method".into(), Value::String(operation.method.clone()));
    request.insert("path".into(), Value::String(path));
    if !query_values.is_empty() {
        request.insert("query".into(), Value::Object(query_values));
    }
    if let Some(body) = body {
        request.insert("body".into(), body);
    }
    request.insert("execute".into(), object.get("execute").cloned().unwrap_or(Value::Bool(false)));
    Ok(Value::Object(request))
}

fn operation_parameters(spec: &Value, operation: &Value) -> Result<Vec<Value>, String> {
    let mut parameters = Vec::new();
    if let Some(values) = operation.get("__pathParameters").and_then(Value::as_array) {
        for value in values {
            parameters.push(resolve_bounded(value, spec)?);
        }
    }
    if let Some(values) = operation.get("parameters").and_then(Value::as_array) {
        for value in values {
            parameters.push(resolve_bounded(value, spec)?);
        }
    }
    Ok(parameters)
}

fn validate_schema(value: &Value, schema: &Value, label: &str, root: &Value) -> Result<(), String> {
    let schema = resolve_bounded(schema, root)?;
    if let Some(enums) = schema.get("enum").and_then(Value::as_array) {
        if !enums.iter().any(|candidate| candidate == value) {
            return Err(format!("{label} does not match OpenAPI enum"));
        }
    }
    if let Some(types) = schema.get("type").and_then(Value::as_str) {
        let valid = match types {
            "object" => value.is_object(),
            "array" => value.is_array(),
            "string" => value.is_string(),
            "integer" | "number" => value.is_number(),
            "boolean" => value.is_boolean(),
            "null" => value.is_null(),
            _ => true,
        };
        if !valid {
            return Err(format!("{label} does not match OpenAPI type {types}"));
        }
    }
    if let Some(object) = value.as_object() {
        if let Some(required) = schema.get("required").and_then(Value::as_array) {
            for name in required.iter().filter_map(Value::as_str) {
                if !object.contains_key(name) {
                    return Err(format!("{label}.{name} is required by OpenAPI schema"));
                }
            }
        }
        if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
            for (name, child) in properties {
                if let Some(value) = object.get(name) {
                    validate_schema(value, child, &format!("{label}.{name}"), root)?;
                }
            }
        }
        if schema.get("additionalProperties") == Some(&Value::Bool(false)) {
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                if let Some(name) = object.keys().find(|name| !properties.contains_key(*name)) {
                    return Err(format!("{label}.{name} is not allowed by OpenAPI schema"));
                }
            }
        }
    }
    if let Some(items) = schema.get("items") {
        if let Some(values) = value.as_array() {
            for (index, value) in values.iter().enumerate() {
                validate_schema(value, items, &format!("{label}[{index}]"), root)?;
            }
        }
    }
    Ok(())
}

fn scalar(value: &Value) -> Result<String, String> {
    match value {
        Value::String(value) => Ok(value.clone()),
        Value::Number(value) => Ok(value.to_string()),
        Value::Bool(value) => Ok(value.to_string()),
        _ => Err("OpenAPI path/query parameter must be scalar".to_string()),
    }
}

fn percent_encode_path(value: &str) -> String {
    let mut result = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            result.push(byte as char);
        } else {
            result.push_str(&format!("%{byte:02X}"));
        }
    }
    result
}

fn resolve_bounded(value: &Value, root: &Value) -> Result<Value, String> {
    let mut refs = 0;
    resolve(value, root, &mut Vec::new(), 0, &mut refs)
}

fn resolve(value: &Value, root: &Value, stack: &mut Vec<String>, depth: usize, refs: &mut usize) -> Result<Value, String> {
    if depth > MAX_REF_DEPTH {
        return Err("OpenAPI local reference depth exceeds limit".to_string());
    }
    if let Some(reference) = value.get("$ref").and_then(Value::as_str) {
        if !reference.starts_with("#/") {
            return Err("OpenAPI external references are not supported".to_string());
        }
        if stack.iter().any(|item| item == reference) {
            return Err("OpenAPI local reference cycle detected".to_string());
        }
        *refs += 1;
        if *refs > MAX_REFS {
            return Err("OpenAPI reference count exceeds limit".to_string());
        }
        let target = pointer(root, reference).ok_or_else(|| format!("OpenAPI reference not found: {reference}"))?;
        stack.push(reference.to_string());
        let result = resolve(target, root, stack, depth + 1, refs);
        stack.pop();
        return result;
    }
    match value {
        Value::Object(map) => {
            let mut result = Map::new();
            for (key, value) in map {
                result.insert(key.clone(), resolve(value, root, stack, depth + 1, refs)?);
            }
            Ok(Value::Object(result))
        }
        Value::Array(values) => Ok(Value::Array(
            values.iter().map(|value| resolve(value, root, stack, depth + 1, refs)).collect::<Result<Vec<_>, _>>()?,
        )),
        _ => Ok(value.clone()),
    }
}

fn pointer<'a>(root: &'a Value, reference: &str) -> Option<&'a Value> {
    let mut value = root;
    for segment in reference.strip_prefix("#/")?.split('/') {
        let segment = segment.replace("~1", "/").replace("~0", "~");
        value = value.get(&segment)?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolves_local_refs_and_rejects_external_refs() {
        let spec = json!({"paths": {"/v1/apps": {"get": {"operationId": "listApps", "parameters": [{"$ref": "#/components/parameters/Limit"}]}}}, "components": {"parameters": {"Limit": {"name": "limit", "in": "query", "schema": {"type": "integer"}}}}});
        let operations = operations(&spec).unwrap();
        assert_eq!(operations[0].operation_id, "listApps");
        let external = json!({"$ref": "https://example.invalid/spec.json"});
        assert!(resolve_bounded(&external, &spec).is_err());
    }

    #[test]
    fn validates_required_body_schema() {
        let spec = json!({"paths": {"/v1/apps": {"post": {"operationId": "createApp", "requestBody": {"required": true, "content": {"application/json": {"schema": {"type": "object", "required": ["data"]}}}}}}}});
        let operation = operations(&spec).unwrap().remove(0);
        let args = json!({"body": {"wrong": true}});
        assert!(build_request(args.as_object().unwrap(), &spec, &operation).is_err());
    }
}
