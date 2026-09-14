pub mod c_family;
pub mod common;
pub mod dotnet;
pub mod go;
pub mod javascript;
pub mod jvm;
pub mod long_tail;
pub mod mobile;
pub mod php_ruby;
pub mod python;
pub mod rust;

use crate::{AuditError, AuditProvider, InventoryEnvelope, ProviderExecutor};
use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderStatus};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct ProviderExecutorAdapter;

impl ProviderExecutor for ProviderExecutorAdapter {
    fn execute(
        &self,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        let input = json!({"files": inventory.entries.iter().map(|e| json!({"path": e.path})).collect::<Vec<_>>()});
        let analysis = match provider.id.as_str() {
            "code.c-family" => c_family::analyze(&input),
            "code.dotnet" => dotnet::analyze(&input),
            "code.go" => go::analyze(&input),
            "code.javascript" => javascript::analyze(&input),
            "code.jvm" => jvm::analyze(&input),
            "code.long-tail" => long_tail::analyze(&input),
            "code.mobile" => mobile::analyze(&input),
            "code.php-ruby" => php_ruby::analyze(&input),
            "code.python" => python::analyze(&input),
            "code.rust" => rust::analyze(&input),
            other => {
                return Err(AuditError::Provider(format!(
                    "unsupported native code provider: {other}"
                )))
            }
        };
        let id = ProviderId::new(provider.id.clone())?;
        let complete = analysis
            .get("complete")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let status = if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
        };
        Ok(ProviderResult {
            schema_version: 1,
            provider: id,
            applicable: true,
            required: provider.required,
            status,
            complete,
            coverage: Some(Coverage {
                denominator_digest: inventory.digest.clone(),
                expected: inventory.entries.len() as u64,
                examined: inventory.entries.len() as u64,
                gaps: Vec::new(),
            }),
            findings: Vec::new(),
            coverage_gaps: Vec::new(),
            degradation: Vec::new(),
            details: BTreeMap::from([("nativeAnalysis".into(), analysis)]),
        })
    }
}
