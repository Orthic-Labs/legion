//! Legion's policy binding for `rightkit-apple-ops`.
//!
//! The package derives each call's effects and bound targets; this module is the host
//! [`Gate`]: it checks the caller's `policyContext` and grant, binds targets below the
//! context path, and asks Legion's canonical policy for one decision per effect.

use legion_policy::{PolicyEvaluator, PolicyPack};
use legion_policy_model::{
    CanonicalPath, DecisionOutcome, EffectClass, PathOperation, PolicyContext, SymlinkState,
};
use legion_runtime::RuntimeError;
use rightkit_apple_ops::gate::{self, Call, Effect, Gate, GateError};
use serde_json::{json, Value};
use std::fs;

/// Invoke one canonical Apple operation from CLI or MCP request shape.
pub async fn invoke(request: &Value) -> Result<Value, RuntimeError> {
    gate::invoke(&LegionGate, request)
        .await
        .map_err(|error| match error {
            GateError::Invalid(message) => RuntimeError::InvalidTask(message),
            GateError::Denied(message) => RuntimeError::Policy(message),
        })
}

/// Validate MCP-specific scope before dispatch.
pub fn validate_scope(request: &Value) -> Result<(), String> {
    gate::validate_scope(&LegionGate, request)
}

/// Canonical Apple MCP schema source, shared with release assembly. Legion keeps its own tool
/// name, which its skills and hosts' permission rules name.
pub fn tool_definitions() -> Vec<Value> {
    let mut tools = rightkit_apple_ops::tool_definitions();
    for tool in &mut tools {
        tool["name"] = json!("legion_apple");
    }
    tools
}

struct LegionGate;

impl Gate for LegionGate {
    fn authorize(&self, request: &Value, call: &Call<'_>) -> Result<Vec<Value>, String> {
        let effects: Vec<EffectClass> = call.effects.iter().map(|e| effect_class(*e)).collect();
        let context = execute_context(request, &effects, "derived")?;
        if let Some(path) = context.path.as_ref() {
            validate_context_path(path)?;
        }
        let grant = context
            .grant
            .as_ref()
            .ok_or_else(|| "policyContext grant is required for Apple execution".to_string())?;
        if !effects.iter().all(|effect| grant.effects.contains(effect)) {
            return Err("policyContext grant does not cover all derived Apple effects".to_string());
        }

        let (raw, cwd) = gate::bound_targets(call.operation, call.arguments, call.plan)?;
        let targets = if raw.is_empty() {
            Vec::new()
        } else {
            let base = context
                .path
                .as_ref()
                .ok_or_else(|| "Apple target requires policyContext.path".to_string())?;
            raw.iter()
                .map(|target| {
                    canonical_target(&gate::resolve_target(target, cwd.as_deref())?, base)
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        let path_bound = effects
            .iter()
            .any(|effect| matches!(effect, EffectClass::FileWrite | EffectClass::FileDelete));
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
            for effect in &effects {
                // The effect class comes from the package's derivation, never from the caller's
                // context, and each derived class gets its own Guard decision.
                let mut effect_context = context.clone();
                effect_context.effect_class = *effect;
                if target.is_some() {
                    effect_context.path = target.clone();
                }
                let decision = evaluator.evaluate(&effect_context).decision;
                if decision.outcome != DecisionOutcome::Allow {
                    return Err(format!(
                        "Apple operation denied by canonical policy for {:?}: {:?}",
                        effect, decision.outcome
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

    fn validate_scope(&self, request: &Value, effects: &[Effect]) -> Result<(), String> {
        let effects: Vec<EffectClass> = effects.iter().map(|e| effect_class(*e)).collect();
        execute_context(request, &effects, "coarse").map(|_| ())
    }
}

fn effect_class(effect: Effect) -> EffectClass {
    match effect {
        Effect::FileWrite => EffectClass::FileWrite,
        Effect::FileDelete => EffectClass::FileDelete,
        Effect::NetworkEgress => EffectClass::NetworkEgress,
        Effect::ProcessSpawn => EffectClass::ProcessSpawn,
        Effect::CredentialAccess => EffectClass::CredentialAccess,
        Effect::Publish => EffectClass::Publish,
        Effect::ExternalSideEffect => EffectClass::ExternalSideEffect,
    }
}

/// The caller's `policyContext`, required to be an execute context whose effect is one of
/// `effects` (`kind` names them in the refusal).
fn execute_context(
    request: &Value,
    effects: &[EffectClass],
    kind: &str,
) -> Result<PolicyContext, String> {
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
        return Err(format!(
            "policyContext effect does not match any {kind} Apple effect"
        ));
    }
    Ok(context)
}

/// Bind a resolved host path below the context's canonical path.
fn canonical_target(resolved: &str, base: &CanonicalPath) -> Result<CanonicalPath, String> {
    let candidate = CanonicalPath::new(
        base.root_identity.clone(),
        base.scope.clone(),
        resolved,
        SymlinkState::Resolved {
            target: resolved.to_owned(),
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

/// The policy pack of the verified installed release's composition.
fn load_policy_evaluator() -> Result<PolicyEvaluator, String> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn context(effect: &str, operation: &str) -> Value {
        json!({
            "schema_version": 1,
            "contract": {"name": "m1", "major": 1, "minor": 0},
            "effect_class": effect,
            "operation": operation,
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
        })
    }

    #[test]
    fn read_only_operation_does_not_require_context() {
        let request = json!({"operation": "preflight", "arguments": {}});
        assert!(validate_scope(&request).is_ok());
    }

    #[test]
    fn execution_without_context_fails_closed() {
        let request = json!({"operation": "project.build", "arguments": {"execute": true}});
        assert!(validate_scope(&request).is_err());
    }

    #[test]
    fn caller_cannot_relabel_process_as_read() {
        let request = json!({
            "operation": "project.build",
            "arguments": {"execute": true},
            "policyContext": context("FILE_WRITE", "read"),
        });
        assert!(validate_scope(&request).is_err());
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
            &gate::host_path_string(&root),
            SymlinkState::Unknown,
        )
        .unwrap();
        let bind = |raw: &str| canonical_target(&gate::resolve_target(raw, None).unwrap(), &base);
        let outside = root.parent().unwrap().join("apple-mcp-outside");
        assert!(bind(&gate::host_path_string(&outside)).is_err());
        assert!(bind("../outside").is_err());
        assert!(bind("build/Products").is_ok());
    }
}
