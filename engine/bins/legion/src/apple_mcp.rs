//! Shared policy gate for native Apple CLI & MCP calls.
//!
//! This module owns request normalization & effect classification.  Apple
//! adapters remain deliberately unaware of host policy; every execute request
//! therefore crosses this gate before reaching `legion_apple`.

use legion_policy::{PolicyEvaluator, PolicyPack};
use legion_policy_model::{DecisionOutcome, EffectClass, PathOperation, PolicyContext};
use legion_runtime::RuntimeError;
use serde_json::{json, Value};
use std::{env, fs, path::PathBuf};

const CONFIG_ENVS: [&str; 2] = ["LEGION_M1_CONFIG_PATH", "LEGION_M1_CONFIG"];

/// Invoke one canonical Apple operation from CLI or MCP request shape.
pub async fn invoke(request: &Value) -> Result<Value, RuntimeError> {
    let (operation, arguments) = request_parts(request).map_err(RuntimeError::InvalidTask)?;
    let effects = derive_effects(&operation, &arguments).await?;
    let receipts = authorize(request, &effects).map_err(RuntimeError::Policy)?;
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
    let _ = request_parts(request)?;
    let (operation, arguments) = request_parts(request)?;
    let effects = required_effects(&operation, &arguments)?;
    authorize(request, &effects).map(|_| ())
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

fn authorize(request: &Value, effects: &[EffectClass]) -> Result<Vec<Value>, String> {
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

    let evaluator = load_policy_evaluator()?;
    let mut receipts = Vec::with_capacity(effects.len());
    for effect in effects {
        // Effect class is derived from operation & arguments, never trusted
        // from caller context. Each derived class gets its own Guard decision.
        let mut effect_context = context.clone();
        effect_context.effect_class = *effect;
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
            "decision": decision,
        }));
    }
    Ok(receipts)
}

async fn derive_effects(operation: &str, arguments: &Value) -> Result<Vec<EffectClass>, RuntimeError> {
    let coarse = required_effects(operation, arguments).map_err(RuntimeError::InvalidTask)?;
    if !arguments.get("execute").and_then(Value::as_bool).unwrap_or(false) {
        return Ok(coarse);
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
            return Ok(coarse);
        }
        Err(error) => {
            return Err(RuntimeError::InvalidTask(format!(
                "cannot derive Apple effects from operation plan: {error}"
            )))
        }
    };
    Ok(effects_from_plan(operation, arguments, &plan, coarse))
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
    let mut effects = required_effects(canonical, arguments).unwrap_or(coarse);
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
            let operation_id = plan
                .get("operationId")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_ascii_lowercase();
            effects.push(if action.eq_ignore_ascii_case("submission")
                || operation_id.contains("submit")
                || operation_id.contains("submission")
            {
                EffectClass::Publish
            } else {
                EffectClass::ExternalSideEffect
            });
        }
    }
    effects.sort();
    effects.dedup();
    effects
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
        if method != "GET" || matches!(operation_name.as_str(), "create" | "update" | "delete" | "submit") {
            effects.push(if action == "submission" || operation_name == "submit" {
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
    fn aliases_keep_ui_mutation_effects() {
        let effects = required_effects("tap", &json!({"execute": true})).unwrap();
        assert!(effects.contains(&EffectClass::ProcessSpawn));
        assert!(effects.contains(&EffectClass::ExternalSideEffect));
    }
}
