pub mod assurance;
pub mod audit;
pub mod catalog;
pub mod decision;
pub mod handoff;
pub mod host;
pub mod policy;
pub mod research;
pub mod review;
pub mod rules;
pub mod setup;
use serde_json::{json, Value};
use std::{path::Path, sync::Arc};
pub type CommandResult = Result<Value, CommandError>;
pub fn native_application_for(
    repository_id: &str,
) -> Result<Arc<legion_application::NativeApplication>, CommandError> {
    if let Ok(configured) = std::env::var("LEGION_NATIVE_APPLICATION_CONFIG") {
        return legion_application::NativeApplicationConfig::from_versioned_source(&configured)
            .and_then(legion_application::NativeApplicationConfig::build)
            .map(Arc::new)
            .map_err(|error| {
                CommandError::incomplete(format!("native application rejected: {error}"))
            });
    }
    Err(CommandError::incomplete(format!(
        "native application config is required for repository {repository_id}"
    )))
}
pub fn audit_signing_key() -> Result<Vec<u8>, CommandError> {
    std::env::var_os("AUDIT_PLAN_SIGNING_KEY")
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string_lossy().as_bytes().to_vec())
        .ok_or_else(|| {
            CommandError::incomplete("native audit requires host-injected AUDIT_PLAN_SIGNING_KEY")
        })
}
pub fn audit_inventory_source(
    root: &Path,
    packet: Option<&Path>,
    expected_generation: Option<String>,
) -> Result<(Arc<dyn legion_audit::BlueprintInventorySource>, Vec<String>), CommandError> {
    if let Some(packet) = packet {
        let blueprint = std::fs::canonicalize(packet)
            .map_err(|error| error.to_string())
            .and_then(|path| {
                legion_audit::FileBlueprintInventorySource::new(path, expected_generation)
                    .map_err(|error| error.to_string())
            });
        match blueprint {
            Ok(source) => return Ok((Arc::new(source), Vec::new())),
            Err(error) => {
                let fallback = legion_audit::FilesystemInventorySource::new(root)
                    .map_err(|fallback| CommandError::incomplete(fallback.to_string()))?;
                return Ok((
                    Arc::new(fallback),
                    vec![format!(
                        "Blueprint was unavailable ({error}). Audit continued with its own read-only repository inventory. Use Membrane as context engine and provide a fresh Blueprint packet for richer context."
                    )],
                ));
            }
        }
    }
    let fallback = legion_audit::FilesystemInventorySource::new(root)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    Ok((
        Arc::new(fallback),
        vec![
            "Blueprint was not provided. Audit continued with its own read-only repository inventory. Use Membrane as context engine and provide a fresh Blueprint packet for richer context."
                .into(),
        ],
    ))
}

/// Stable, machine-readable degradation projection. Text notices remain for humans,
/// while this object is the only semantic representation consumed by Audit clients.
pub fn audit_blueprint_degradations(
    providers: &[legion_contracts::ProviderSpec],
    operation: &str,
    reason_code: &str,
) -> Vec<Value> {
    let unaffected = providers
        .iter()
        .filter(|provider| {
            !provider
                .consumes
                .iter()
                .any(|item| item == "blueprint-packet")
        })
        .map(|provider| provider.id.to_string())
        .collect::<Vec<_>>();
    let mut unaffected = unaffected;
    unaffected.sort();
    unaffected.dedup();
    let mut dependent = providers
        .iter()
        .filter(|provider| {
            provider
                .consumes
                .iter()
                .any(|item| item == "blueprint-packet")
        })
        .map(|provider| provider.id.to_string())
        .collect::<Vec<_>>();
    dependent.sort();
    dependent.dedup();
    dependent
        .into_iter()
        .map(|provider| {
            json!({
                "provider": provider,
                "operation": operation,
                "reasonCode": reason_code,
                "structuralCoverageLimits": ["symbols", "dependencies", "graph relationships"],
                "recommendation": "Provide a fresh host-published Blueprint packet for structural coverage.",
                "unaffectedProviders": unaffected.clone(),
            })
        })
        .collect()
}
#[derive(Debug)]
pub struct CommandError {
    pub code: i32,
    pub message: String,
}
impl CommandError {
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 4,
            message: message.into(),
        }
    }
    pub fn incomplete(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: 3,
            message: message.into(),
        }
    }
    pub fn cancelled() -> Self {
        Self {
            code: 2,
            message: "CANCELLED: task cancelled by Ctrl-C".into(),
        }
    }
    pub fn integrity(message: impl Into<String>) -> Self {
        Self {
            code: 5,
            message: message.into(),
        }
    }
    pub fn policy(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
        }
    }
}
pub fn io_error(error: impl std::fmt::Display) -> CommandError {
    CommandError::internal(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(id: &str, consumes: &[&str]) -> legion_contracts::ProviderSpec {
        legion_contracts::ProviderSpec {
            schema_version: 2,
            id: legion_contracts::ProviderId::new(id).expect("provider id"),
            provider_version: "1".into(),
            family: "fixture".into(),
            lens_ids: Vec::new(),
            role: "deterministic".into(),
            phase: "source".into(),
            depends_on: Vec::new(),
            consumes: consumes.iter().map(|item| (*item).into()).collect(),
            produces: vec!["provider-result".into()],
            selector: json!({"op": "always"}),
            denominator_kind: "repository-inventory".into(),
            runner: json!({"kind": "built-in"}),
            host_capabilities: Vec::new(),
            execution: json!({}),
            reasoning: json!({}),
            benchmark: json!({}),
            clean_claim: "finding-producing".into(),
            control_ids: Vec::new(),
            scopes: Vec::new(),
            selectable: true,
        }
    }

    #[test]
    fn blueprint_degradation_is_per_dependent_provider() {
        let degradations = audit_blueprint_degradations(
            &[
                provider("blueprint.second", &["blueprint-packet"]),
                provider("unaffected", &["repository-inventory"]),
                provider("blueprint.first", &["blueprint-packet"]),
            ],
            "audit",
            "blueprint-unavailable",
        );
        assert_eq!(degradations.len(), 2);
        assert_eq!(
            degradations
                .iter()
                .map(|item| item["provider"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["blueprint.first", "blueprint.second"]
        );
        for degradation in degradations {
            assert_eq!(degradation["operation"], "audit");
            assert_eq!(degradation["reasonCode"], "blueprint-unavailable");
            assert_eq!(degradation["unaffectedProviders"], json!(["unaffected"]));
        }
    }
}
