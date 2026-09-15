use super::{CommandError, CommandResult};
use clap::Args;
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Args)]
pub struct VerifyArgs {
    pub run: PathBuf,
}

/// Verify persisted Audit artifacts and reconcile facts against its frozen plan.
/// Provider execution cryptographic checks remain owned by `legion-audit`.
pub async fn run(args: VerifyArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() {
        return Err(CommandError::cancelled());
    }
    let supplied = if args.run.is_absolute() {
        args.run
    } else {
        std::env::current_dir().map_err(super::io_error)?.join(args.run)
    };
    let (root, facts_path, plan_path) = if supplied.is_dir() {
        (
            supplied.clone(),
            supplied.join("facts.json"),
            supplied.join("plan.json"),
        )
    } else {
        let parent = supplied
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .to_path_buf();
        (
            parent,
            supplied.clone(),
            supplied.with_file_name("plan.json"),
        )
    };
    if !facts_path.is_file() {
        return Err(CommandError::usage(format!(
            "verify facts artifact missing: {}",
            facts_path.display()
        )));
    }
    if !plan_path.is_file() && supplied.is_dir() {
        return Err(CommandError::usage(format!(
            "verify plan artifact missing: {}",
            plan_path.display()
        )));
    }
    let facts: Value = serde_json::from_slice(
        &std::fs::read(&facts_path).map_err(super::io_error)?,
    )
    .map_err(|error| CommandError::usage(format!("invalid verify facts artifact: {error}")))?;
    let plan: Value = if plan_path.is_file() {
        serde_json::from_slice(&std::fs::read(&plan_path).map_err(super::io_error)?).map_err(
            |error| CommandError::usage(format!("invalid verify plan artifact: {error}")),
        )?
    } else {
        facts.get("plan").cloned().ok_or_else(|| {
            CommandError::usage(format!(
                "verify plan artifact missing: {}",
                plan_path.display()
            ))
        })?
    };
    let mut errors = Vec::new();
    if facts.get("kind").and_then(Value::as_str) != Some("audit-facts") {
        errors.push("facts.kind must be audit-facts".into());
    }
    if !facts.get("checks").is_some_and(Value::is_array) {
        errors.push("facts.checks must be an array".into());
    }
    if !facts
        .get("provider_reconciliation")
        .and_then(Value::as_object)
        .and_then(|v| v.get("providerResults"))
        .is_some_and(Value::is_array)
    {
        errors.push("facts.provider_reconciliation.providerResults must be an array".into());
    }
    if plan.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        errors.push("plan.schemaVersion must be 1".into());
    }
    if plan.get("kind").and_then(Value::as_str) != Some("audit-provider-plan") {
        errors.push("plan.kind must be audit-provider-plan".into());
    }
    if plan.get("providers").and_then(Value::as_array).is_none() {
        errors.push("plan.providers must be an array".into());
    }
    if !plan
        .get("seal")
        .and_then(|v| v.get("digest"))
        .and_then(Value::as_str)
        .is_some_and(|v| v.starts_with("sha256:") && v.len() == 71)
    {
        errors.push("plan.seal.digest must use canonical sha256 form".into());
    }
    if !plan
        .get("binding")
        .and_then(|v| v.get("repositoryRevision"))
        .and_then(Value::as_str)
        .is_some_and(|v| !v.trim().is_empty())
    {
        errors.push("plan.binding.repositoryRevision is required".into());
    }
    let facts_plan = facts.get("plan");
    if let (Some(a), Some(b)) = (
        facts_plan
            .and_then(|v| v.get("seal"))
            .and_then(|v| v.get("digest")),
        plan.get("seal").and_then(|v| v.get("digest")),
    ) {
        if a != b {
            errors.push("facts.plan seal differs from plan seal".into());
        }
    }
    if facts_plan
        .and_then(|v| v.get("binding"))
        .and_then(|v| v.get("repositoryRevision"))
        != plan
            .get("binding")
            .and_then(|v| v.get("repositoryRevision"))
    {
        errors.push("facts.plan binding differs from plan binding".into());
    }
    let facts_digest = legion_contracts::canonical_digest_hex(&facts)
        .map_err(|e| CommandError::integrity(e.to_string()))?;
    let plan_digest = legion_contracts::canonical_digest_hex(&plan)
        .map_err(|e| CommandError::integrity(e.to_string()))?;
    let repository_id = facts
        .get("workspace")
        .and_then(Value::as_str)
        .or_else(|| plan.get("repository").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| root.to_string_lossy().into_owned());
    if errors.is_empty() {
        let application = super::native_application_for(&repository_id)?;
        let verification = application
            .invoke_with_cancellation(
                legion_application::NativeOperation::VerifyRequest {
                    repository_id: repository_id.clone(),
                    providers: application.provider_specs(),
                    signing_key: None,
                    facts: facts.clone(),
                    plan: plan.clone(),
                },
                cancellation,
            )
            .await
            .map_err(|error| CommandError::incomplete(error.to_string()));
        if let Err(error) = verification {
            errors.push(error.message);
        }
    }
    Ok(json!({"schemaVersion":1,"kind":"legion-verify","status":if errors.is_empty(){"complete"}else{"failed"},"repository":repository_id,"factsDigest":facts_digest,"planContentDigest":plan_digest,"valid":errors.is_empty(),"contentErrors":errors}))
}
