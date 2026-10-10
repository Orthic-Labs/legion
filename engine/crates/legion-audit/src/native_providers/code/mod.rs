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
        // Carry the analyzer's own gaps into the result instead of dropping
        // them: a language analyzer given only file paths has no tool
        // evidence, and that must read as a gap, not as silent partial.
        let mut gaps = analysis
            .get("coverageGaps")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|gap| {
                let kind = gap.get("kind").and_then(Value::as_str).unwrap_or("gap");
                let detail = ["tool", "context", "language"]
                    .iter()
                    .find_map(|key| gap.get(*key).and_then(Value::as_str));
                match detail {
                    Some(detail) => format!("{}:{kind}:{detail}", provider.id),
                    None => format!("{}:{kind}", provider.id),
                }
            })
            .collect::<Vec<_>>();
        gaps.sort();
        gaps.dedup();
        let tool_evidence_missing = analysis
            .get("coverageGaps")
            .and_then(Value::as_array)
            .is_some_and(|items| {
                items
                    .iter()
                    .any(|gap| gap.get("kind").and_then(Value::as_str) == Some("tool-evidence-gap"))
            });
        let mut result = ProviderResult {
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
                gaps: gaps.clone(),
            }),
            findings: Vec::new(),
            coverage_gaps: gaps,
            degradation: Vec::new(),
            details: BTreeMap::from([("nativeAnalysis".into(), analysis)]),
        };
        if tool_evidence_missing {
            super::availability::mark_unavailable(
                &mut result,
                &format!("tool-evidence-not-produced:{}", provider.id),
            );
        }
        Ok(result)
    }
}
