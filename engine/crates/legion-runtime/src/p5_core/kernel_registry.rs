//! Ported from src/packages/kernel/lib/registry.mjs (packet P5d).

use std::collections::BTreeMap;

use legion_catalog::json::Value;

use crate::p5_core::kernel_contracts::assert_contract;
use crate::p5_core::kernel_errors::{KernelError, KernelErrorOptions};

fn usage_error(message: impl Into<String>) -> KernelError {
    KernelError::new(
        "INVALID_ARGUMENT",
        message,
        KernelErrorOptions {
            category: Some("usage".to_string()),
            ..Default::default()
        },
    )
}

/// Port of `class OperationRegistry`.
#[derive(Default)]
pub struct OperationRegistry {
    operations: BTreeMap<String, Value>,
}

impl OperationRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Port of `register(descriptor)`.
    pub fn register(&mut self, descriptor: Value) -> Result<Value, KernelError> {
        let object = descriptor
            .as_object()
            .ok_or_else(|| usage_error("operation descriptor must be an object"))?;
        let envelope = object.get("envelope").cloned().unwrap_or(Value::Null);
        assert_contract("operation-envelope-v1", &envelope, Some("operation envelope"))?;

        let operation_id = object.get("operationId").and_then(Value::as_str).unwrap_or_default();
        let envelope_operation_id = envelope.get("operationId").and_then(Value::as_str).unwrap_or_default();
        let version = object.get("version");
        let envelope_version = envelope.get("operationVersion");
        if operation_id != envelope_operation_id || version != envelope_version {
            return Err(usage_error("operation descriptor identity does not match envelope"));
        }
        let handler_binding = object.get("handlerBinding").and_then(Value::as_str).unwrap_or_default();
        if handler_binding.is_empty() {
            return Err(usage_error("operation handler binding is required"));
        }
        if self.operations.contains_key(operation_id) {
            return Err(KernelError::new(
                "SCOPE_CONFLICT",
                format!("operation already registered: {operation_id}"),
                KernelErrorOptions {
                    category: Some("conflict".to_string()),
                    ..Default::default()
                },
            ));
        }
        self.operations.insert(operation_id.to_string(), descriptor.clone());
        Ok(descriptor)
    }

    /// Port of `lookup(operationId)`.
    pub fn lookup(&self, operation_id: &str) -> Result<Value, KernelError> {
        self.operations.get(operation_id).cloned().ok_or_else(|| {
            KernelError::new(
                "OPERATION_NOT_AVAILABLE",
                format!("unknown operation: {operation_id}"),
                KernelErrorOptions {
                    category: Some("usage".to_string()),
                    remediation: Some("Call capability discovery and select a registered operation ID.".to_string()),
                    ..Default::default()
                },
            )
        })
    }

    /// Port of `list()` (already sorted, since `operations` is a `BTreeMap`).
    pub fn list(&self) -> Vec<Value> {
        self.operations.values().cloned().collect()
    }
}

fn normalize_capabilities(value: &[String], label: &str) -> Result<Vec<String>, KernelError> {
    if value.iter().any(|c| c.is_empty()) {
        return Err(usage_error(format!("{label} must be a non-empty string array")));
    }
    let mut unique: Vec<String> = value.iter().cloned().collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    unique.sort();
    Ok(unique)
}

#[derive(Debug)]
pub struct CapabilityNegotiation {
    pub available: Vec<String>,
    pub missing: Vec<String>,
    pub compatible: bool,
}

/// Port of `negotiateCapabilities({ required, supported })`.
pub fn negotiate_capabilities(required: &[String], supported: &[String]) -> Result<CapabilityNegotiation, KernelError> {
    let required = normalize_capabilities(required, "required capabilities")?;
    let supported = normalize_capabilities(supported, "supported capabilities")?;
    let supported_set: std::collections::BTreeSet<&String> = supported.iter().collect();
    let available: Vec<String> = required.iter().filter(|c| supported_set.contains(c)).cloned().collect();
    let missing: Vec<String> = required.iter().filter(|c| !supported_set.contains(c)).cloned().collect();
    let compatible = missing.is_empty();
    Ok(CapabilityNegotiation { available, missing, compatible })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_capabilities_reports_missing_and_compatible() {
        let required = vec!["a".to_string(), "b".to_string()];
        let supported = vec!["a".to_string()];
        let result = negotiate_capabilities(&required, &supported).unwrap();
        assert_eq!(result.available, vec!["a".to_string()]);
        assert_eq!(result.missing, vec!["b".to_string()]);
        assert!(!result.compatible);
    }

    #[test]
    fn negotiate_capabilities_dedupes_and_sorts() {
        let required = vec!["b".to_string(), "a".to_string(), "a".to_string()];
        let supported = vec!["b".to_string(), "a".to_string()];
        let result = negotiate_capabilities(&required, &supported).unwrap();
        assert_eq!(result.available, vec!["a".to_string(), "b".to_string()]);
        assert!(result.compatible);
    }

    #[test]
    fn negotiate_capabilities_rejects_empty_string_entries() {
        let required = vec!["".to_string()];
        let error = negotiate_capabilities(&required, &[]).unwrap_err();
        assert_eq!(error.code, "INVALID_ARGUMENT");
    }

    #[test]
    fn registry_lookup_reports_not_available_for_unknown_operation() {
        let registry = OperationRegistry::new();
        let error = registry.lookup("nope").unwrap_err();
        assert_eq!(error.code, "OPERATION_NOT_AVAILABLE");
        assert!(error.remediation.is_some());
    }

    #[test]
    fn registry_rejects_non_object_descriptor() {
        let mut registry = OperationRegistry::new();
        let error = registry.register(legion_catalog::json::Value::Null).unwrap_err();
        assert_eq!(error.code, "INVALID_ARGUMENT");
    }
}
