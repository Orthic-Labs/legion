//! Audit execution uses Alchemist tiers; independent verification keeps Oracle
//! authority without inheriting its frontier model tier.
use super::{invalid, RuntimeOptions};
use crate::{error::AuditError, native_providers::reasoning::PendingLensWork};
use serde::Serialize;
use serde_json::Value;
use std::{fs, path::Path};

const MODEL_TIERS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../src/config/model-tiers.json"
));

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ExecutionSelection {
    pub role: &'static str,
    pub model_tier: &'static str,
    pub model: String,
    pub reasoning_effort: String,
    pub host: &'static str,
    pub stage: &'static str,
}

pub(super) fn current_host() -> Result<&'static str, AuditError> {
    legion_host::current_harness()
        .map(legion_host::CurrentHarness::as_str)
        .map_err(|error| invalid(format!("incomplete:host-identity:{error}")))
}

fn tier_model(tier: &str, host: &str) -> Result<String, AuditError> {
    if !matches!(host, "claude-code" | "codex") {
        return Err(invalid("incomplete:host-identity:unsupported harness"));
    }
    serde_json::from_str::<Value>(MODEL_TIERS)
        .ok()
        .and_then(|map| map.pointer(&format!("/tiers/{tier}/hosts/{host}")).cloned())
        .and_then(|value| value.as_str().map(str::to_owned))
        .filter(|model| !model.trim().is_empty())
        .ok_or_else(|| invalid(format!("incomplete:model-policy-unavailable:{tier}:{host}")))
}

pub(super) fn validate_options(options: &RuntimeOptions) -> Result<(), AuditError> {
    validate_options_for_host(options, current_host()?)
}

fn validate_options_for_host(options: &RuntimeOptions, host: &str) -> Result<(), AuditError> {
    if options
        .reasoning_effort
        .as_deref()
        .is_some_and(|effort| !matches!(effort, "low" | "medium" | "high"))
    {
        return Err(invalid(
            "incomplete:reasoning-effort-unsupported:expected low, medium or high",
        ));
    }
    if let Some(model) = &options.model {
        let allowed = [
            tier_model("mechanical-cheap", host)?,
            tier_model("balanced-executor", host)?,
        ];
        if !allowed.contains(model) {
            return Err(invalid("incomplete:model-policy:Audit execution permits only canonical Alchemist models; frontier overrides are prohibited"));
        }
    }
    Ok(())
}

fn selection(
    mechanical: bool,
    verifier: bool,
    options: &RuntimeOptions,
) -> Result<ExecutionSelection, AuditError> {
    selection_for_host(mechanical, verifier, options, current_host()?)
}

fn selection_for_host(
    mechanical: bool,
    verifier: bool,
    options: &RuntimeOptions,
    host: &'static str,
) -> Result<ExecutionSelection, AuditError> {
    validate_options_for_host(options, host)?;
    // Only settled dead-file inventory currently has a mechanical lens
    // contract. Naming, source semantics, security & adjudication stay balanced.
    let cheap = mechanical && !verifier;
    let tier = if cheap {
        "mechanical-cheap"
    } else {
        "balanced-executor"
    };
    let cheap_model = tier_model("mechanical-cheap", host)?;
    let balanced_model = tier_model("balanced-executor", host)?;
    let model = if verifier {
        balanced_model
    } else if let Some(model) = &options.model {
        if !cheap && model == &cheap_model && model != &balanced_model {
            return Err(invalid(
                "incomplete:model-policy:semantic/security Audit requires balanced-executor",
            ));
        }
        model.clone()
    } else {
        tier_model(tier, host)?
    };
    let model_tier = if cheap && model == cheap_model {
        "mechanical-cheap"
    } else {
        "balanced-executor"
    };
    Ok(ExecutionSelection {
        role: if verifier {
            "oracle"
        } else if model_tier == "mechanical-cheap" {
            "alchemist"
        } else {
            "alchemist-specialist"
        },
        model_tier,
        model,
        reasoning_effort: options
            .reasoning_effort
            .clone()
            .unwrap_or_else(|| "high".into()),
        host,
        stage: if verifier {
            "finding-verification"
        } else {
            "source-review"
        },
    })
}

pub(super) fn author<'a>(
    providers: impl IntoIterator<Item = &'a str>,
    options: &RuntimeOptions,
) -> Result<ExecutionSelection, AuditError> {
    author_for_host(providers, options, current_host()?)
}

pub(super) fn author_for_host<'a>(
    providers: impl IntoIterator<Item = &'a str>,
    options: &RuntimeOptions,
    host: &'static str,
) -> Result<ExecutionSelection, AuditError> {
    let mut any = false;
    let mechanical = providers.into_iter().all(|provider| {
        any = true;
        provider == "reasoning.dead-file"
    });
    selection_for_host(any && mechanical, false, options, host)
}

pub(super) fn verifier(options: &RuntimeOptions) -> Result<ExecutionSelection, AuditError> {
    selection(false, true, options)
}

pub(super) fn gatherer(options: &RuntimeOptions) -> Result<ExecutionSelection, AuditError> {
    let mut execution = selection(
        true,
        false,
        &RuntimeOptions {
            model: None,
            ..options.clone()
        },
    )?;
    execution.stage = "evidence-gathering";
    Ok(execution)
}

pub(super) fn observed_model_matches(execution: &ExecutionSelection, observed: &str) -> bool {
    observed == execution.model
        || (execution.host == "claude-code"
            && observed.strip_prefix("claude-").is_some_and(|name| {
                name.strip_prefix(&execution.model)
                    .is_some_and(|suffix| suffix.starts_with('-'))
            }))
}

pub(crate) fn validate_metadata(value: &Value) -> Result<(), AuditError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("runtime execution metadata missing"))?;
    let tier = value["modelTier"].as_str().unwrap_or("");
    let role = value["role"].as_str().unwrap_or("");
    let stage = value["stage"].as_str().unwrap_or("");
    let host = value["host"].as_str().unwrap_or("");
    let valid_boundary = matches!(
        (stage, role, tier),
        ("evidence-gathering", "alchemist", "mechanical-cheap")
            | ("source-review", "alchemist", "mechanical-cheap")
            | ("source-review", "alchemist-specialist", "balanced-executor")
            | ("finding-verification", "oracle", "balanced-executor")
    );
    if object.len() != 6
        || !object.keys().all(|key| {
            [
                "role",
                "modelTier",
                "model",
                "reasoningEffort",
                "host",
                "stage",
            ]
            .contains(&key.as_str())
        })
        || !valid_boundary
        || value["model"] != tier_model(tier, host)?
        || !matches!(
            value["reasoningEffort"].as_str(),
            Some("low" | "medium" | "high")
        )
    {
        return Err(invalid(
            "runtime execution role/model/effort binding invalid",
        ));
    }
    Ok(())
}

pub(super) fn validate_execution_host(execution: &ExecutionSelection) -> Result<(), AuditError> {
    if execution.host != current_host()? {
        return Err(invalid(
            "incomplete:host-identity:execution host differs from current harness",
        ));
    }
    Ok(())
}

fn validate_receipt_host(receipt: &Value, host: &str) -> Result<(), AuditError> {
    let execution = receipt
        .get("execution")
        .ok_or_else(|| invalid("incomplete:host-identity:prior receipt execution missing"))?;
    validate_metadata(execution)?;
    if execution["host"].as_str() != Some(host) {
        return Err(invalid("incomplete:host-identity:prior receipt host differs from current harness; prepare a new run"));
    }
    Ok(())
}

pub(super) fn enforce_prior_receipts(run: &Path) -> Result<(), AuditError> {
    let host = current_host()?;
    let entries = match fs::read_dir(run.join("runtime-calls")) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(invalid(error.to_string())),
    };
    for (index, entry) in entries.enumerate() {
        if index >= 4096 {
            return Err(invalid(
                "incomplete:model-policy:prior receipt scan exceeds call bound",
            ));
        }
        let path = entry.map_err(|error| invalid(error.to_string()))?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let receipt = super::read_json(&path)?;
        let receipt =
            crate::native_providers::reasoning::ingest::verify_runtime_call(run, &receipt)?;
        validate_receipt_host(&receipt, host)?;
        // New receipts carry typed policy status even when refusal/protocol
        // errors remain primary. Retain compatibility with old mismatch receipts.
        if receipt
            .pointer("/observation/modelPolicyViolation")
            .is_some_and(|violation| !violation.is_null())
            || receipt
                .pointer("/observation/error")
                .and_then(Value::as_str)
                .is_some_and(|error| {
                    error.contains("native observed model differs from authorized executor tier")
                })
        {
            return Err(invalid("incomplete:model-policy:prior authenticated native model mismatch; prepare a new run after correcting host model selection"));
        }
    }
    Ok(())
}

/// Planning candidates are local metadata for numeric bounds only. They are
/// never launch authority, actual host observations or persisted provenance.
pub(super) fn planning_author_candidates(
    works: &[PendingLensWork],
) -> Result<Vec<ExecutionSelection>, AuditError> {
    ["claude-code", "codex"]
        .into_iter()
        .map(|host| {
            author_for_host(
                works.iter().map(|work| work.provider_id.as_str()),
                &RuntimeOptions::default(),
                host,
            )
        })
        .collect()
}

pub(super) fn planning_gatherer_candidates() -> Result<Vec<ExecutionSelection>, AuditError> {
    ["claude-code", "codex"]
        .into_iter()
        .map(|host| {
            let mut execution = selection_for_host(true, false, &RuntimeOptions::default(), host)?;
            execution.stage = "evidence-gathering";
            Ok(execution)
        })
        .collect()
}

#[cfg(test)]
pub(super) fn verifier_for_host(host: &'static str) -> Result<ExecutionSelection, AuditError> {
    selection_for_host(false, true, &RuntimeOptions::default(), host)
}

#[cfg(test)]
pub(super) fn test_largest_planning_execution(
    works: &[PendingLensWork],
) -> Result<ExecutionSelection, AuditError> {
    planning_author_candidates(works)?
        .into_iter()
        .max_by_key(|candidate| serde_json::to_vec(candidate).unwrap().len())
        .ok_or_else(|| invalid("planning candidates missing"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_host_columns_preserve_role_tier_policy() {
        for host in ["claude-code", "codex"] {
            let options = RuntimeOptions::default();
            let cheap = selection_for_host(true, false, &options, host).unwrap();
            assert_eq!(cheap.role, "alchemist");
            assert_eq!(cheap.model_tier, "mechanical-cheap");
            assert_eq!(cheap.model, tier_model("mechanical-cheap", host).unwrap());
            assert_eq!(cheap.host, host);
            for provider in [
                "reasoning.naming",
                "reasoning.correctness",
                "reasoning.security",
                "legacy.security.adjudication",
            ] {
                assert_eq!(
                    author_for_host([provider], &options, host)
                        .unwrap()
                        .model_tier,
                    "balanced-executor"
                );
            }
            assert_eq!(
                author_for_host(
                    ["reasoning.dead-file", "reasoning.security"],
                    &options,
                    host
                )
                .unwrap()
                .model_tier,
                "balanced-executor"
            );
            let semantic = author_for_host(["reasoning.correctness"], &options, host).unwrap();
            assert_eq!(semantic.role, "alchemist-specialist");
            assert_eq!(semantic.model_tier, "balanced-executor");
            assert_eq!(
                semantic.model,
                tier_model("balanced-executor", host).unwrap()
            );
            let oracle = selection_for_host(false, true, &options, host).unwrap();
            assert_eq!(oracle.role, "oracle");
            assert_eq!(oracle.model_tier, "balanced-executor");
            assert_eq!(oracle.reasoning_effort, "high");
            for execution in [cheap, semantic, oracle] {
                validate_metadata(&serde_json::to_value(&execution).unwrap()).unwrap();
                assert!(observed_model_matches(&execution, &execution.model));
            }
        }
        assert!(tier_model("mechanical-cheap", "missing").is_err());
    }

    #[test]
    fn overrides_refuse_frontier_cross_host_and_semantic_downgrade() {
        for host in ["claude-code", "codex"] {
            for model in ["opus", "claude-fable-5-1", "gpt-6-astra", "sonnet[1m]", ""] {
                assert!(validate_options_for_host(
                    &RuntimeOptions {
                        model: Some(model.into()),
                        ..Default::default()
                    },
                    host
                )
                .is_err());
            }
            let other = if host == "codex" {
                "claude-code"
            } else {
                "codex"
            };
            assert!(validate_options_for_host(
                &RuntimeOptions {
                    model: Some(tier_model("balanced-executor", other).unwrap()),
                    ..Default::default()
                },
                host
            )
            .is_err());
            let options = RuntimeOptions {
                model: Some(tier_model("mechanical-cheap", host).unwrap()),
                ..Default::default()
            };
            assert!(selection_for_host(false, false, &options, host).is_err());
            assert_eq!(
                selection_for_host(false, true, &options, host)
                    .unwrap()
                    .model,
                tier_model("balanced-executor", host).unwrap()
            );
        }
    }

    #[test]
    fn metadata_and_receipts_bind_host_column_without_relabeling() {
        for host in ["claude-code", "codex"] {
            let execution =
                selection_for_host(false, true, &RuntimeOptions::default(), host).unwrap();
            let value = serde_json::to_value(&execution).unwrap();
            let receipt = serde_json::json!({"execution": value});
            validate_receipt_host(&receipt, host).unwrap();
            let other = if host == "codex" {
                "claude-code"
            } else {
                "codex"
            };
            assert!(validate_receipt_host(&receipt, other).is_err());
            let mut wrong_column = value.clone();
            wrong_column["host"] = serde_json::json!(other);
            assert!(validate_metadata(&wrong_column).is_err());
            let mut frontier = value;
            frontier["modelTier"] = serde_json::json!("frontier-judgment");
            assert!(validate_metadata(&frontier).is_err());
            assert!(!observed_model_matches(&execution, "gpt-6-astra"));
            assert!(!observed_model_matches(&execution, "claude-opus-5"));
        }
        assert!(validate_receipt_host(&serde_json::json!({}), "codex").is_err());
    }
}
