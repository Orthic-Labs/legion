//! Shared policy gate for native Apple CLI & MCP calls.
//!
//! This module owns request normalization & effect classification.  Apple
//! adapters remain deliberately unaware of host policy; every execute request
//! therefore crosses this gate before reaching `legion_apple`.

use legion_policy::{PolicyEvaluator, PolicyPack};
use legion_policy_model::{
    CanonicalPath, DecisionOutcome, EffectClass, PathOperation, PolicyContext,
    SymlinkState,
};
use legion_runtime::RuntimeError;
use serde_json::{json, Value};
use std::{env, fs, path::{Path, PathBuf}};

const CONFIG_ENVS: [&str; 2] = ["LEGION_M1_CONFIG_PATH", "LEGION_M1_CONFIG"];

/// Invoke one canonical Apple operation from CLI or MCP request shape.
pub async fn invoke(request: &Value) -> Result<Value, RuntimeError> {
    let (operation, arguments) = request_parts(request).map_err(RuntimeError::InvalidTask)?;
    let (effects, plan) = derive_effects(&operation, &arguments).await?;
    let receipts = authorize(request, &operation, &arguments, &effects, plan.as_ref())
        .map_err(RuntimeError::Policy)?;
    let mut result = legion_apple::invoke(&operation, &arguments)
        .await
        .map_err(RuntimeError::InvalidTask)?;
    if !receipts.is_empty() {
        if let Some(object) = result.as_object_mut() {
            object.insert("guardReceipts".into(), Value::Array(receipts));
        } else {
            result = json!({"result": result, "guardReceipts": receipts});
        }
    }
    Ok(result)
}

/// Validate MCP-specific scope before dispatch.  This is intentionally
/// synchronous because `NativeApi::validate_tool_scope` runs before its async
/// invocation hook.
pub fn validate_scope(request: &Value) -> Result<(), String> {
    let (operation, arguments) = request_parts(request)?;
    let effects = required_effects(&operation, &arguments)?;
    if effects.is_empty() {
        return Ok(());
    }
    let context_value = request
        .as_object()
        .and_then(|object| object.get("policyContext"))
        .filter(|value| !value.is_null())
        .ok_or_else(|| "policyContext is required for Apple execution".to_string())?;
    let context: PolicyContext = serde_json::from_value(context_value.clone())
        .map_err(|error| format!("policyContext is invalid: {error}"))?;
    if context.operation != PathOperation::Execute {
        return Err("Apple execution requires policyContext operation execute".to_string());
    }
    if !effects.contains(&context.effect_class) {
        return Err("policyContext effect does not match any coarse Apple effect".to_string());
    }
    Ok(())
}

fn request_parts(request: &Value) -> Result<(String, Value), String> {
    let object = request
        .as_object()
        .ok_or_else(|| "Apple request must be an object".to_string())?;
    let operation = object
        .get("operation")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| "Apple operation is required".to_string())?
        .to_owned();
    let arguments = object
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| Value::Object(Default::default()));
    if !arguments.is_object() {
        return Err("Apple arguments must be an object".to_string());
    }
    Ok((operation, arguments))
}

fn authorize(
    request: &Value,
    operation: &str,
    arguments: &Value,
    effects: &[EffectClass],
    plan: Option<&Value>,
) -> Result<Vec<Value>, String> {
    if effects.is_empty() {
        return Ok(Vec::new());
    };
    let context_value = request
        .as_object()
        .and_then(|object| object.get("policyContext"))
        .filter(|value| !value.is_null())
        .cloned()
        .ok_or_else(|| "policyContext is required for Apple execution".to_string())?;
    let context: PolicyContext = serde_json::from_value(context_value)
        .map_err(|error| format!("policyContext is invalid: {error}"))?;
    if let Some(path) = context.path.as_ref() {
        validate_context_path(path)?;
    }

    if context.operation != PathOperation::Execute {
        return Err("Apple execution requires policyContext operation execute".to_string());
    }
    if !effects.contains(&context.effect_class) {
        return Err("policyContext effect does not match any derived Apple effect".to_string());
    }
    let grant = context
        .grant
        .as_ref()
        .ok_or_else(|| "policyContext grant is required for Apple execution".to_string())?;
    if !effects.iter().all(|effect| grant.effects.contains(effect)) {
        return Err("policyContext grant does not cover all derived Apple effects".to_string());
    }

    let targets = trusted_target_paths(operation, arguments, plan, &context)?;
    let path_bound = effects.iter().any(|effect| {
        matches!(effect, EffectClass::FileWrite | EffectClass::FileDelete)
    });
    if path_bound && targets.is_empty() {
        return Err("Apple operation has a file effect but no bound target path".to_string());
    }

    let evaluator = load_policy_evaluator()?;
    let path_variants: Vec<Option<CanonicalPath>> = if targets.is_empty() {
        vec![context.path.clone()]
    } else {
        targets.into_iter().map(Some).collect()
    };
    let mut receipts = Vec::with_capacity(effects.len() * path_variants.len());
    for target in path_variants {
        for effect in effects {
            // Effect class is derived from operation & arguments, never trusted
            // from caller context. Each derived class gets its own Guard decision.
            let mut effect_context = context.clone();
            effect_context.effect_class = *effect;
            if target.is_some() {
                effect_context.path = target.clone();
            }
            let decision = evaluator.evaluate(&effect_context).decision;
            if decision.outcome != DecisionOutcome::Allow {
                return Err(format!(
                    "Apple operation denied by canonical policy for {:?}: {:?}",
                    effect,
                    decision.outcome
                ));
            }
            receipts.push(json!({
                "effectClass": effect,
                "path": effect_context.path,
                "decision": decision,
            }));
        }
    }
    Ok(receipts)
}

/// Extract filesystem targets only after the native adapter has accepted the
/// typed request & produced its dry plan. Relative targets use canonical
/// policy classification; absolute targets must remain below host context's
/// canonical path. Network identifiers (ASC paths/app IDs) are not converted
/// into fake filesystem paths.
fn trusted_target_paths(
    operation: &str,
    arguments: &Value,
    plan: Option<&Value>,
    context: &PolicyContext,
) -> Result<Vec<CanonicalPath>, String> {
    let canonical = plan
        .and_then(|value| value.get("operation"))
        .and_then(Value::as_str)
        .unwrap_or_else(|| canonical_operation(operation));
    let object = arguments
        .as_object()
        .ok_or_else(|| "Apple arguments must be an object".to_string())?;
    let mut raw_targets = Vec::new();

    let upload = operation == "app-store"
        && (object
            .get("action")
            .and_then(Value::as_str)
            .is_some_and(|action| action.eq_ignore_ascii_case("upload"))
            || (object
                .get("action")
                .and_then(Value::as_str)
                .is_some_and(|action| action.eq_ignore_ascii_case("builds"))
                && object
                    .get("operation")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case("upload"))));
    if upload {
        for key in ["artifact", "filePath", "file_path", "ipa", "pkg", "path"] {
            if let Some(value) = object.get(key).and_then(Value::as_str) {
                raw_targets.push(value);
                break;
            }
        }
    } else {
        let keys: &[&str] = match canonical {
            "project.build" | "project.test" => &[
                "project",
                "project_path",
                "workspace",
                "workspace_path",
                "derived_data_path",
                "result_bundle_path",
            ],
            "project.clean" => &["project", "project_path", "workspace", "workspace_path"],
            "swiftpm.clean" => &["package_path"],
            "project.archive" => &[
                "project",
                "project_path",
                "workspace",
                "workspace_path",
                "archive_path",
            ],
            "project.export" => &["archive_path", "export_path", "export_options_plist"],
            "swiftpm.build" | "swiftpm.test" | "swiftpm.run" => &["package_path"],
            "simulator.install" | "device.install" => &["app_path"],
            "simulator.screenshot" | "simulator.record_video" => &["output", "path"],
            "profile" => &["output"],
            "profile.export" => &["output_path"],
            _ => &[],
        };
        for key in keys {
            if let Some(value) = object.get(*key).and_then(Value::as_str) {
                raw_targets.push(value);
            }
        }
        if raw_targets.is_empty()
            && matches!(
                canonical,
                "project.build"
                    | "project.test"
                    | "project.clean"
                    | "swiftpm.clean"
                    | "swiftpm.build"
                    | "swiftpm.test"
                    | "swiftpm.run"
            )
        {
            if let Some(cwd) = plan.and_then(|value| value.get("cwd")).and_then(Value::as_str) {
                raw_targets.push(cwd);
            }
        }
    }
    if raw_targets.is_empty() {
        return Ok(Vec::new());
    }
    let base = context
        .path
        .as_ref()
        .ok_or_else(|| "Apple target requires policyContext.path".to_string())?;
    let trusted_cwd = plan
        .and_then(|value| value.get("cwd"))
        .and_then(Value::as_str);
    raw_targets
        .into_iter()
        .map(|raw| {
            if matches!(raw.trim(), "." | "./") {
                if let Some(cwd) = plan.and_then(|value| value.get("cwd")).and_then(Value::as_str) {
                    return canonical_target_with_cwd(cwd, base, trusted_cwd);
                }
            }
            canonical_target_with_cwd(raw, base, trusted_cwd)
        })
        .collect()
}

fn canonical_target(raw: &str, base: &CanonicalPath) -> Result<CanonicalPath, String> {
    canonical_target_with_cwd(raw, base, None)
}

fn canonical_target_with_cwd(
    raw: &str,
    base: &CanonicalPath,
    cwd: Option<&str>,
) -> Result<CanonicalPath, String> {
    let input = PathBuf::from(raw);
    let absolute = if input.is_absolute()
        || (raw.len() >= 3
            && raw.as_bytes()[1] == b':'
            && matches!(raw.as_bytes()[2], b'/' | b'\\'))
    {
        input
    } else {
        let root = cwd
            .map(PathBuf::from)
            .or_else(|| env::current_dir().ok())
            .ok_or_else(|| "Apple target has no trusted working directory".to_string())?;
        root.join(input)
    };
    let resolved = resolve_existing_target(&absolute)?;
    let resolved_string = host_path_string(&resolved);
    let candidate = CanonicalPath::new(
        base.root_identity.clone(),
        base.scope.clone(),
        &resolved_string,
        SymlinkState::Resolved {
            target: resolved_string.clone(),
        },
    )
    .map_err(|error| format!("Apple target path is invalid: {error}"))?;
    if base.root_identity != candidate.root_identity
        || base.scope != candidate.scope
        || !(candidate.normalized_absolute_path == base.normalized_absolute_path
            || candidate
                .normalized_absolute_path
                .starts_with(&(base.normalized_absolute_path.clone() + "/")))
    {
        return Err("Apple target path is outside policyContext.path".to_string());
    }
    Ok(candidate)
}

fn resolve_existing_target(path: &Path) -> Result<PathBuf, String> {
    let mut missing = Vec::new();
    let mut cursor = path;
    while fs::symlink_metadata(cursor).is_err() {
        let name = cursor
            .file_name()
            .ok_or_else(|| "Apple target has no existing parent".to_string())?;
        missing.push(name.to_os_string());
        cursor = cursor
            .parent()
            .ok_or_else(|| "Apple target has no existing parent".to_string())?;
    }
    let mut resolved = fs::canonicalize(cursor)
        .map_err(|error| format!("Apple target parent cannot be canonicalized: {error}"))?;
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    Ok(resolved)
}

fn host_path_string(path: &Path) -> String {
    let value = path.to_string_lossy().replace('\\', "/");
    if let Some(rest) = value.strip_prefix("//?/UNC/") {
        return format!("/{rest}");
    }
    value
        .strip_prefix("//?/")
        .map(str::to_owned)
        .unwrap_or(value)
}

fn validate_context_path(path: &CanonicalPath) -> Result<(), String> {
    let rebuilt = CanonicalPath::new(
        path.root_identity.clone(),
        path.scope.clone(),
        &path.normalized_absolute_path,
        path.symlink.clone(),
    )
    .map_err(|error| format!("policyContext.path is invalid: {error}"))?;
    if rebuilt.normalized_relative_path != path.normalized_relative_path {
        return Err("policyContext.path absolute and relative forms disagree".to_string());
    }
    Ok(())
}

async fn derive_effects(
    operation: &str,
    arguments: &Value,
) -> Result<(Vec<EffectClass>, Option<Value>), RuntimeError> {
    let coarse = required_effects(operation, arguments).map_err(RuntimeError::InvalidTask)?;
    if !arguments.get("execute").and_then(Value::as_bool).unwrap_or(false) {
        return Ok((coarse, None));
    }
    let mut dry_arguments = arguments.clone();
    if let Some(object) = dry_arguments.as_object_mut() {
        object.insert("execute".into(), Value::Bool(false));
    }
    let plan = match legion_apple::invoke(operation, &dry_arguments).await {
        Ok(plan) => plan,
        Err(error) if operation == "memgraph" || operation == "memgraph-leaks" => {
            // Native memgraph capture intentionally rejects dry-run because
            // its plan is the bounded `/usr/bin/leaks` process itself.
            let _ = error;
            return Ok((coarse, None));
        }
        Err(error) => {
            return Err(RuntimeError::InvalidTask(format!(
                "cannot derive Apple effects from operation plan: {error}"
            )))
        }
    };
    Ok((effects_from_plan(operation, arguments, &plan, coarse), Some(plan)))
}

fn effects_from_plan(
    operation: &str,
    arguments: &Value,
    plan: &Value,
    coarse: Vec<EffectClass>,
) -> Vec<EffectClass> {
    let canonical = plan
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or(operation);
    // App Store upload plans expose `build-upload`, which is an adapter plan
    // name rather than a policy operation. Keep coarse ASC credential/network
    // effects when plan metadata uses such a name.
    let mut effects = if canonical == "build-upload" {
        coarse.clone()
    } else {
        required_effects(canonical, arguments).unwrap_or(coarse)
    };
    if let Some(classifications) = plan
        .get("effectClassification")
        .and_then(|value| value.get("classifications"))
        .and_then(Value::as_array)
    {
        let planned = classifications
            .iter()
            .filter_map(Value::as_str)
            .filter_map(effect_from_classification)
            .collect::<Vec<_>>();
        if !planned.is_empty() {
            effects.clear();
            effects.extend(planned);
        }
    }
    if let Some(mutation) = plan.get("mutation").and_then(Value::as_bool) {
        effects.retain(|effect| {
            !matches!(effect, EffectClass::ExternalSideEffect | EffectClass::Publish)
        });
        if mutation {
            let action = arguments.get("action").and_then(Value::as_str).unwrap_or("");
            let request = plan.get("request").and_then(Value::as_object);
            let method = request
                .and_then(|value| value.get("method"))
                .and_then(Value::as_str)
                .or_else(|| arguments.get("method").and_then(Value::as_str))
                .unwrap_or("GET");
            let path = request
                .and_then(|value| value.get("url"))
                .and_then(Value::as_str)
                .or_else(|| arguments.get("path").and_then(Value::as_str))
                .unwrap_or("");
            let body = request
                .and_then(|value| value.get("body"))
                .or_else(|| arguments.get("body"));
            let operation_id = plan
                .get("operationId")
                .and_then(Value::as_str)
                .or_else(|| arguments.get("operationId").and_then(Value::as_str))
                .or_else(|| arguments.get("operation").and_then(Value::as_str))
                .unwrap_or("");
            effects.push(if is_publish_route(action, operation_id, method, path, body) {
                EffectClass::Publish
            } else {
                EffectClass::ExternalSideEffect
            });
        }
    }
    if operation == "app-store" && is_upload_request(arguments) {
        effects.push(EffectClass::CredentialAccess);
        effects.push(EffectClass::NetworkEgress);
        effects.push(EffectClass::ExternalSideEffect);
    }
    effects.sort();
    effects.dedup();
    effects
}

fn is_upload_request(arguments: &Value) -> bool {
    let Some(object) = arguments.as_object() else {
        return false;
    };
    let action = object.get("action").and_then(Value::as_str).unwrap_or("");
    action.eq_ignore_ascii_case("upload")
        || (action.eq_ignore_ascii_case("builds")
            && object
                .get("operation")
                .and_then(Value::as_str)
                .is_some_and(|value| value.eq_ignore_ascii_case("upload")))
}

fn is_publish_route(
    action: &str,
    operation: &str,
    method: &str,
    raw_path: &str,
    body: Option<&Value>,
) -> bool {
    if method.eq_ignore_ascii_case("GET") {
        return false;
    }
    if action.eq_ignore_ascii_case("submission")
        || matches!(
            operation.to_ascii_lowercase().as_str(),
            "submit" | "submission" | "release" | "review"
        )
    {
        return true;
    }
    let path = route_path(raw_path).to_ascii_lowercase();
    if [
        "submission",
        "submit",
        "release",
        "reviewsubmission",
        "releaserequest",
    ]
    .iter()
    .any(|segment| path.contains(segment))
    {
        return true;
    }
    let operation = operation.to_ascii_lowercase();
    if ["submit", "submission", "release", "review"]
        .iter()
        .any(|label| operation.contains(label))
    {
        return true;
    }
    body_implies_publish(body)
}

fn route_path(raw: &str) -> &str {
    let Some(scheme_end) = raw.find("://") else {
        return raw;
    };
    raw[scheme_end + 3..]
        .find('/')
        .map(|offset| &raw[scheme_end + 3 + offset..])
        .unwrap_or("")
}

fn body_implies_publish(body: Option<&Value>) -> bool {
    let Some(value) = body else {
        return false;
    };
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            let signal = matches!(
                key.as_str(),
                "publish"
                    | "release"
                    | "releasenow"
                    | "submit"
                    | "submitted"
                    | "submitforreview"
                    | "sendforreview"
                    | "reviewsubmission"
            );
            (signal && !matches!(value, Value::Bool(false) | Value::Null))
                || body_implies_publish(Some(value))
        }),
        Value::Array(values) => values.iter().any(|value| body_implies_publish(Some(value))),
        _ => false,
    }
}

fn effect_from_classification(classification: &str) -> Option<EffectClass> {
    match classification.to_ascii_lowercase().as_str() {
        "credentialaccess" | "credential_access" => Some(EffectClass::CredentialAccess),
        "networkegress" | "network_egress" => Some(EffectClass::NetworkEgress),
        "externalsideeffect" | "external_side_effect" => Some(EffectClass::ExternalSideEffect),
        "publish" => Some(EffectClass::Publish),
        "processspawn" | "process_spawn" => Some(EffectClass::ProcessSpawn),
        "filewrite" | "file_write" => Some(EffectClass::FileWrite),
        "filedelete" | "file_delete" => Some(EffectClass::FileDelete),
        _ => None,
    }
}

/// Process-backed Apple operations require PROCESS_SPAWN. App Store Connect
/// execution derives credential, network, & consequential mutation effects.
fn required_effects(operation: &str, arguments: &Value) -> Result<Vec<EffectClass>, String> {
    let object = arguments
        .as_object()
        .ok_or_else(|| "Apple arguments must be an object".to_string())?;
    let execute = object.get("execute").and_then(Value::as_bool).unwrap_or(false);
    if !execute {
        return Ok(Vec::new());
    }
    if operation == "app-store" {
        let action = object
            .get("action")
            .and_then(Value::as_str)
            .unwrap_or("discover")
            .to_ascii_lowercase();
        let has_selector = ["operationId", "operation_id", "operation", "method", "path"]
            .iter()
            .any(|key| object.contains_key(*key));
        if matches!(action.as_str(), "catalog" | "template" | "dry-run")
            || (matches!(action.as_str(), "discover" | "openapi" | "operations") && !has_selector)
        {
            return Ok(Vec::new());
        }
        let mut effects = vec![EffectClass::CredentialAccess, EffectClass::NetworkEgress];
        let is_build_upload = action == "upload"
            || (action == "builds"
                && object
                    .get("operation")
                    .and_then(Value::as_str)
                    .is_some_and(|value| value.eq_ignore_ascii_case("upload")));
        if is_build_upload {
            // Upload plans intentionally report an empty classification during
            // dry-run, but reservation, transfer & commit always mutate ASC.
            effects.push(EffectClass::ExternalSideEffect);
        }
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET")
            .to_ascii_uppercase();
        let operation_name = object
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or("list")
            .to_ascii_lowercase();
        let operation_id = object
            .get("operationId")
            .or_else(|| object.get("operation_id"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let publish_operation = if operation_id.is_empty() {
            operation_name.as_str()
        } else {
            operation_id
        };
        let path = object.get("path").and_then(Value::as_str).unwrap_or("");
        if method != "GET" || matches!(operation_name.as_str(), "create" | "update" | "delete" | "submit") {
            effects.push(if is_publish_route(
                &action,
                publish_operation,
                &method,
                path,
                object.get("body"),
            ) {
                EffectClass::Publish
            } else {
                EffectClass::ExternalSideEffect
            });
        }
        if matches!(action.as_str(), "openapi" | "operations")
            && ["operationId", "operation_id", "operation", "method", "path"]
                .iter()
                .any(|key| object.contains_key(*key))
            && !effects.contains(&EffectClass::ExternalSideEffect)
            && !effects.contains(&EffectClass::Publish)
        {
            // Synchronous MCP scope validation cannot resolve local OpenAPI
            // operation. Keep mutation coverage conservative; async dispatch
            // replaces it with resolved dry-run metadata before execution.
            effects.push(EffectClass::ExternalSideEffect);
            effects.push(EffectClass::Publish);
        }
        return Ok(effects);
    }
    if matches!(operation, "catalog" | "preflight" | "docs" | "build-analysis" | "flamegraph" | "flamegraph-json" | "build-log" | "build_log" | "memgraph.parse" | "memgraph-text" | "profile.parse" | "swiftui-trace") {
        return Ok(Vec::new());
    }
    let operation = canonical_operation(operation);
    if operation == "ui.read" {
        return Ok(vec![EffectClass::ProcessSpawn]);
    }
    if matches!(operation, "ui.tap" | "ui.type" | "ui.swipe" | "ui.key" | "ui.key_sequence" | "ui.button" | "ui.drag" | "ui.gesture" | "ui.long_press" | "ui.touch") {
        return Ok(vec![EffectClass::ProcessSpawn, EffectClass::ExternalSideEffect]);
    }
    let mut effects = vec![EffectClass::ProcessSpawn];
    if matches!(operation,
        "project.build" | "project.test" | "project.archive" | "project.export"
        | "simulator.install" | "device.install" | "simulator.screenshot"
        | "simulator.record_video" | "profile" | "profile.export"
    ) {
        effects.push(EffectClass::FileWrite);
    }
    if matches!(operation, "project.clean" | "swiftpm.clean") {
        effects.push(EffectClass::FileDelete);
    }
    if matches!(operation, "swiftpm.resolve" | "swiftpm.update") {
        effects.push(EffectClass::NetworkEgress);
    }
    if matches!(operation, "swiftpm.build" | "swiftpm.test" | "swiftpm.run") {
        // SwiftPM may write .build products & resolve package dependencies
        // during an ordinary build/test/run; no disable-resolution control is
        // exposed by native adapter, so both effects stay explicit.
        effects.push(EffectClass::FileWrite);
        effects.push(EffectClass::NetworkEgress);
    }
    if matches!(operation,
        "simulator.boot" | "simulator.install" | "simulator.launch"
        | "simulator.terminate" | "simulator.location" | "simulator.appearance"
        | "simulator.location_reset" | "simulator.statusbar" | "device.install" | "device.launch"
        | "device.terminate" | "mac.launch" | "mac.stop" | "debug.breakpoint"
        | "swiftpm.stop" | "debug.batch"
    ) {
        effects.push(EffectClass::ExternalSideEffect);
    }
    effects.sort();
    effects.dedup();
    Ok(effects)
}

fn canonical_operation(operation: &str) -> &str {
    match operation {
        "inspect.project" => "project.inspect",
        "list_schemes" => "project.schemes",
        "show_build_settings" => "project.settings",
        "list_destinations" => "project.destinations",
        "build" => "project.build",
        "build_sim" | "build_device" | "build_macos" => "project.build",
        "test" => "project.test",
        "test_sim" | "test_device" | "test_macos" => "project.test",
        "archive" => "project.archive",
        "export" => "project.export",
        "swift_package_build" => "swiftpm.build",
        "swift_package_test" => "swiftpm.test",
        "swift_package_run" => "swiftpm.run",
        "clean" => "project.clean",
        "swift_package_clean" => "swiftpm.clean",
        "simulator.list_devices" | "simulator.list_sims" => "simulator.list",
        "simulator.install_app" => "simulator.install",
        "simulator.launch_app" => "simulator.launch",
        "simulator.stop_app" => "simulator.terminate",
        "simulator.set_location" => "simulator.location",
        "simulator.set_appearance" => "simulator.appearance",
        "simulator.set_statusbar" => "simulator.statusbar",
        "set_sim_location" => "simulator.location",
        "set_sim_appearance" => "simulator.appearance",
        "sim_statusbar" => "simulator.statusbar",
        "reset_sim_location" => "simulator.location_reset",
        "record_sim_video" => "simulator.record_video",
        "boot_sim" => "simulator.boot",
        "list_sims" => "simulator.list",
        "install_app_sim" => "simulator.install",
        "launch_app_sim" => "simulator.launch",
        "stop_app_sim" => "simulator.terminate",
        "device.list_devices" => "device.list",
        "device.install_app" => "device.install",
        "device.launch_app" => "device.launch",
        "device.stop_app" | "stop_app_device" => "device.terminate",
        "install_app_device" => "device.install",
        "launch_app_device" => "device.launch",
        "launch_mac_app" => "mac.launch",
        "stop_mac_app" => "mac.stop",
        "swift_package_list" => "swiftpm.list",
        "swift_package_stop" => "swiftpm.stop",
        "tap" => "ui.tap",
        "type_text" | "type" => "ui.type",
        "swipe" => "ui.swipe",
        "key_press" | "key" => "ui.key",
        "key_sequence" => "ui.key_sequence",
        "button" => "ui.button",
        "drag" => "ui.drag",
        "gesture" => "ui.gesture",
        "long_press" => "ui.long_press",
        "touch" => "ui.touch",
        "snapshot_ui" => "ui.read",
        "symbolicate.atos" => "symbolicate",
        "debug_breakpoint_add" => "debug.breakpoint.add",
        "debug_breakpoint_remove" => "debug.breakpoint.remove",
        other => other,
    }
}

fn load_policy_evaluator() -> Result<PolicyEvaluator, String> {
    let config_path = if let Some(path) = CONFIG_ENVS
        .iter()
        .find_map(|name| env::var_os(name).filter(|value| !value.is_empty()))
    {
        PathBuf::from(path)
    } else {
        let installed = legion_runtime::release_binding::load_installed_release()
            .map_err(|error| format!("installed release binding unavailable: {error}"))?;
        let config_path = installed
            .manifest_path
            .parent()
            .map(|parent| parent.join("composition.json"))
            .ok_or_else(|| "installed release has no composition path".to_string())?;
        legion_runtime::release_binding::verify_stable_current_path(
            &installed.origin_evidence(),
            &config_path,
            "stable current composition",
        )
        .map_err(|error| format!("installed release binding unavailable: {error}"))?;
        config_path
    };
    let bytes = fs::read(&config_path)
        .map_err(|error| format!("policy composition unavailable: {error}"))?;
    let composition: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("policy composition is invalid: {error}"))?;
    let policy = composition
        .get("policyPack")
        .cloned()
        .ok_or_else(|| "policy composition has no policyPack".to_string())?;
    let pack: PolicyPack = serde_json::from_value(policy)
        .map_err(|error| format!("policy pack is invalid: {error}"))?;
    PolicyEvaluator::new(pack).map_err(|error| format!("canonical policy unavailable: {error}"))
}

/// Canonical Apple MCP schema source, shared with release assembly.
pub fn tool_definitions() -> Vec<Value> {
    legion_apple::tool_definitions()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn read_only_operation_does_not_require_context() {
        let request = json!({"operation": "preflight", "arguments": {}});
        assert!(validate_scope(&request).is_ok());
    }

    #[test]
    fn execution_without_context_fails_closed() {
        let request = json!({
            "operation": "project.build",
            "arguments": {"execute": true}
        });
        assert!(validate_scope(&request).is_err());
    }

    #[test]
    fn caller_cannot_relabel_process_as_read() {
        let request = json!({
            "operation": "project.build",
            "arguments": {"execute": true},
            "policyContext": {
                "schema_version": 1,
                "contract": {"name": "m1", "major": 1, "minor": 0},
                "effect_class": "FILE_WRITE",
                "operation": "read",
                "path": null,
                "repository": "repo",
                "worktree": "main",
                "trust": "capability-signature",
                "enforcement": "observed",
                "approval": "none",
                "lease": "active",
                "receipt": "present",
                "grant": null,
                "tags": []
            }
        });
        assert!(validate_scope(&request).is_err());
    }

    #[test]
    fn app_store_derives_network_and_mutation_independently_of_credentials() {
        let effects = required_effects(
            "app-store",
            &json!({"action": "request", "method": "POST", "execute": true}),
        )
        .unwrap();
        assert!(effects.contains(&EffectClass::CredentialAccess));
        assert!(effects.contains(&EffectClass::NetworkEgress));
        assert!(effects.contains(&EffectClass::ExternalSideEffect));
    }

    #[test]
    fn build_derives_process_and_write_effects() {
        let effects = required_effects("project.build", &json!({"execute": true})).unwrap();
        assert!(effects.contains(&EffectClass::ProcessSpawn));
        assert!(effects.contains(&EffectClass::FileWrite));
    }

    #[test]
    fn swiftpm_build_covers_products_and_dependency_resolution() {
        let effects = required_effects("swiftpm.build", &json!({"execute": true})).unwrap();
        assert!(effects.contains(&EffectClass::ProcessSpawn));
        assert!(effects.contains(&EffectClass::FileWrite));
        assert!(effects.contains(&EffectClass::NetworkEgress));
    }

    #[test]
    fn aliases_keep_ui_mutation_effects() {
        let effects = required_effects("tap", &json!({"execute": true})).unwrap();
        assert!(effects.contains(&EffectClass::ProcessSpawn));
        assert!(effects.contains(&EffectClass::ExternalSideEffect));
    }

    #[test]
    fn upload_keeps_external_effect_when_dry_plan_has_no_classifications() {
        let arguments = json!({
            "action": "upload",
            "artifact": "build/Demo.ipa",
            "execute": true
        });
        let coarse = required_effects("app-store", &arguments).unwrap();
        let plan = json!({
            "operation": "build-upload",
            "effectClassification": {"classifications": []}
        });
        let effects = effects_from_plan("app-store", &arguments, &plan, coarse);
        assert!(effects.contains(&EffectClass::CredentialAccess));
        assert!(effects.contains(&EffectClass::NetworkEgress));
        assert!(effects.contains(&EffectClass::ExternalSideEffect));
    }

    #[test]
    fn release_request_is_publish_even_without_submission_alias() {
        let effects = required_effects(
            "app-store",
            &json!({
                "action": "request",
                "method": "POST",
                "path": "/v1/appStoreVersionReleaseRequests",
                "execute": true
            }),
        )
        .unwrap();
        assert!(effects.contains(&EffectClass::Publish));
        assert!(!effects.contains(&EffectClass::ExternalSideEffect));
    }

    #[test]
    fn resolved_openapi_release_route_is_publish() {
        let arguments = json!({
            "action": "openapi",
            "method": "POST",
            "execute": true
        });
        let plan = json!({
            "request": {
                "method": "POST",
                "url": "https://api.appstoreconnect.apple.com/v1/appStoreVersionSubmissions",
                "body": {"data": {"type": "appStoreVersionSubmissions"}}
            },
            "mutation": true,
            "operationId": "createSubmission"
        });
        let effects = effects_from_plan(
            "app-store",
            &arguments,
            &plan,
            vec![EffectClass::CredentialAccess, EffectClass::NetworkEgress],
        );
        assert!(effects.contains(&EffectClass::Publish));
        assert!(!effects.contains(&EffectClass::ExternalSideEffect));
    }

    #[test]
    fn absolute_target_cannot_escape_canonical_context() {
        let root = env::current_dir().unwrap();
        let base = CanonicalPath::new(
            "root",
            legion_policy_model::PathScope {
                repository: "repo".into(),
                worktree: "main".into(),
            },
            &host_path_string(&root),
            SymlinkState::Unknown,
        )
        .unwrap();
        let outside = root.parent().unwrap().join("apple-mcp-outside");
        assert!(canonical_target(&host_path_string(&outside), &base).is_err());
        assert!(canonical_target("../outside", &base).is_err());
        assert!(canonical_target("build/Products", &base).is_ok());
    }
}
