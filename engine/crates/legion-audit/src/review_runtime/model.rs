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

fn tier_model(tier: &str) -> Result<String, AuditError> {
    serde_json::from_str::<Value>(MODEL_TIERS)
        .ok()
        .and_then(|map| {
            map.pointer(&format!("/tiers/{tier}/hosts/claude-code"))
                .cloned()
        })
        .and_then(|value| value.as_str().map(str::to_owned))
        .filter(|model| !model.trim().is_empty())
        .ok_or_else(|| {
            invalid(format!(
                "incomplete:model-policy-unavailable:{tier}:claude-code"
            ))
        })
}

pub(super) fn validate_options(options: &RuntimeOptions) -> Result<(), AuditError> {
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
            tier_model("mechanical-cheap")?,
            tier_model("balanced-executor")?,
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
    validate_options(options)?;
    // Only settled dead-file inventory currently has a mechanical lens
    // contract. Naming, source semantics, security & adjudication stay balanced.
    let cheap = mechanical && !verifier;
    let tier = if cheap {
        "mechanical-cheap"
    } else {
        "balanced-executor"
    };
    let cheap_model = tier_model("mechanical-cheap")?;
    let balanced_model = tier_model("balanced-executor")?;
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
        tier_model(tier)?
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
        host: "claude-code",
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
    let mut any = false;
    let mechanical = providers.into_iter().all(|provider| {
        any = true;
        provider == "reasoning.dead-file"
    });
    selection(any && mechanical, false, options)
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
        || observed.strip_prefix("claude-").is_some_and(|name| {
            name.strip_prefix(&execution.model)
                .is_some_and(|suffix| suffix.starts_with('-'))
        })
}

pub(crate) fn validate_metadata(value: &Value) -> Result<(), AuditError> {
    let object = value
        .as_object()
        .ok_or_else(|| invalid("runtime execution metadata missing"))?;
    let tier = value["modelTier"].as_str().unwrap_or("");
    let role = value["role"].as_str().unwrap_or("");
    let stage = value["stage"].as_str().unwrap_or("");
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
        || value["host"] != "claude-code"
        || value["model"] != tier_model(tier)?
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

pub(super) fn enforce_prior_receipts(run: &Path) -> Result<(), AuditError> {
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
        if receipt
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

pub(super) fn default_execution_for_works(
    works: &[PendingLensWork],
) -> Result<ExecutionSelection, AuditError> {
    author(
        works.iter().map(|work| work.provider_id.as_str()),
        &RuntimeOptions::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_and_models_follow_work_instead_of_orchestrator_defaults() {
        let options = RuntimeOptions::default();
        let cheap = author(["reasoning.dead-file"], &options).unwrap();
        assert_eq!(cheap.role, "alchemist");
        assert_eq!(cheap.model_tier, "mechanical-cheap");
        assert_eq!(cheap.model, tier_model("mechanical-cheap").unwrap());
        for provider in [
            "reasoning.naming",
            "reasoning.correctness",
            "reasoning.security",
            "legacy.security.adjudication",
        ] {
            let semantic = author([provider], &options).unwrap();
            assert_eq!(semantic.role, "alchemist-specialist");
            assert_eq!(semantic.model_tier, "balanced-executor");
        }
        assert_eq!(
            author(["reasoning.dead-file", "reasoning.security"], &options)
                .unwrap()
                .model_tier,
            "balanced-executor"
        );
        let oracle = verifier(&options).unwrap();
        assert_eq!(oracle.role, "oracle");
        assert_eq!(oracle.model_tier, "balanced-executor");
        assert_eq!(oracle.reasoning_effort, "high");
    }

    #[test]
    fn overrides_cannot_buy_frontier_audits_or_downgrade_semantic_work() {
        for model in ["opus", "claude-fable-5-1", "gpt-6-astra", "sonnet[1m]", ""] {
            assert!(validate_options(&RuntimeOptions {
                model: Some(model.into()),
                ..Default::default()
            })
            .is_err());
        }
        let options = RuntimeOptions {
            model: Some(tier_model("mechanical-cheap").unwrap()),
            ..Default::default()
        };
        assert!(author(["reasoning.correctness"], &options).is_err());
        assert_eq!(
            verifier(&options).unwrap().model,
            tier_model("balanced-executor").unwrap()
        );
    }

    #[test]
    fn execution_metadata_and_observed_models_preserve_role_tier_boundary() {
        let execution = verifier(&RuntimeOptions::default()).unwrap();
        let mut value = serde_json::to_value(&execution).unwrap();
        validate_metadata(&value).unwrap();
        value["modelTier"] = serde_json::json!("frontier-judgment");
        assert!(validate_metadata(&value).is_err());
        let execution = gatherer(&RuntimeOptions::default()).unwrap();
        assert_eq!(execution.role, "alchemist");
        assert_eq!(execution.stage, "evidence-gathering");
        assert!(observed_model_matches(&execution, &execution.model));
        assert!(!observed_model_matches(&execution, "claude-opus-5"));
        assert!(!observed_model_matches(&execution, "claude-fable-5-1"));
    }
}
