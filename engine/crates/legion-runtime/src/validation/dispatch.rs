use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::{Diagnostic, ValidationReport};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub path: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRouting {
    pub model_tier: String,
    pub worker_profile: String,
    pub routing_rationale: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerScope {
    pub id: String,
    pub executor: String,
    pub own: Vec<String>,
    #[serde(default)]
    pub read: Vec<String>,
    #[serde(default)]
    pub forbidden: Vec<String>,
    pub checks: Vec<String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recovery {
    pub max_retries: u8,
    pub stop_conditions: Vec<String>,
    pub return_fields: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchDocument {
    pub schema_version: u32,
    pub kind: String,
    pub packet_type: String,
    pub source_revision: String,
    pub prompt_digest: String,
    pub model_routing: ModelRouting,
    pub repository_root: String,
    pub prompt_artifact: ArtifactRef,
    #[serde(default)]
    pub source_artifact: Option<ArtifactRef>,
    pub objective: String,
    pub integration_owner: String,
    pub authority: Vec<String>,
    pub workers: Vec<WorkerScope>,
    pub recovery: Recovery,
}

pub fn validate_dispatch(document: &DispatchDocument) -> ValidationReport {
    let mut errors = Vec::new();
    let source = document.objective.as_str();
    if document.schema_version != 1 || document.kind != "legion-authority-dispatch" {
        errors.push(Diagnostic::error(
            source,
            0,
            "schema_version/kind",
            "INVALID_INPUT_OR_SCHEMA",
            "schema version 1 and legion-authority-dispatch kind are required",
        ));
    }
    if !matches!(
        document.packet_type.as_str(),
        "direct" | "sage" | "seer" | "alchemist" | "worker"
    ) {
        errors.push(Diagnostic::error(
            source,
            0,
            "packet_type",
            "INVALID_INPUT_OR_SCHEMA",
            "unsupported authority packet type",
        ));
    }
    if document.source_revision.trim().is_empty() || !valid_digest(&document.prompt_digest) {
        errors.push(Diagnostic::error(
            source,
            0,
            "source_revision/prompt_digest",
            "INTEGRITY_OR_HASH_MISMATCH",
            "immutable source and SHA-256 prompt binding are required",
        ));
    }
    if document.repository_root.trim().is_empty()
        || document.objective.trim().is_empty()
        || document.integration_owner.trim().is_empty()
    {
        errors.push(Diagnostic::error(
            source,
            0,
            "objective",
            "INVALID_INPUT_OR_SCHEMA",
            "repository root, objective, and integration owner are required",
        ));
    }
    if document.authority.is_empty() || document.authority.iter().any(|item| item.trim().is_empty())
    {
        errors.push(Diagnostic::error(
            source,
            0,
            "authority",
            "REFERENCE_RESOLUTION_FAILED",
            "at least one non-empty authority source is required",
        ));
    }
    validate_artifact(
        &document.prompt_artifact,
        source,
        "prompt_artifact",
        &mut errors,
    );
    if let Some(artifact) = &document.source_artifact {
        validate_artifact(artifact, source, "source_artifact", &mut errors);
    }
    if document.model_routing.model_tier.trim().is_empty()
        || document.model_routing.worker_profile.trim().is_empty()
        || document.model_routing.routing_rationale.trim().is_empty()
    {
        errors.push(Diagnostic::error(
            source,
            0,
            "model_routing",
            "INVALID_INPUT_OR_SCHEMA",
            "model tier, worker profile, and rationale are required",
        ));
    }
    validate_workers(&document.workers, source, &mut errors);
    if document.recovery.max_retries > 2
        || document.recovery.stop_conditions.is_empty()
        || document.recovery.return_fields.is_empty()
    {
        errors.push(Diagnostic::error(
            source,
            0,
            "recovery",
            "SEMANTIC_BOUNDS_FAILED",
            "recovery must be bounded with stop and return fields",
        ));
    }
    ValidationReport::from_diagnostics(errors)
}

fn validate_workers(workers: &[WorkerScope], source: &str, errors: &mut Vec<Diagnostic>) {
    if workers.is_empty() {
        errors.push(Diagnostic::error(
            source,
            0,
            "workers",
            "INVALID_INPUT_OR_SCHEMA",
            "at least one worker is required",
        ));
        return;
    }
    let mut ids = BTreeSet::new();
    let mut owners: Vec<(String, String)> = Vec::new();
    for worker in workers {
        if !ids.insert(worker.id.clone()) {
            errors.push(Diagnostic::error(
                source,
                0,
                "workers.id",
                "IDENTITY_NOT_UNIQUE",
                format!("duplicate worker id: {}", worker.id),
            ));
        }
        if worker.id.trim().is_empty()
            || worker.executor.trim().is_empty()
            || worker.own.is_empty()
            || worker.checks.is_empty()
        {
            errors.push(Diagnostic::error(
                source,
                0,
                format!("workers.{}", worker.id),
                "INVALID_INPUT_OR_SCHEMA",
                "worker id, executor, OWN scope, and checks are required",
            ));
        }
        let own = normalize_scope(&worker.own, source, "own", errors);
        let read = normalize_scope(&worker.read, source, "read", errors);
        let forbidden = normalize_scope(&worker.forbidden, source, "forbidden", errors);
        if own.iter().any(|item| forbidden.contains(item))
            || read.iter().any(|item| forbidden.contains(item))
        {
            errors.push(Diagnostic::error(
                source,
                0,
                format!("workers.{}", worker.id),
                "OWNERSHIP_OR_CAPABILITY_FAILED",
                "scope overlaps FORBIDDEN",
            ));
        }
        for path in own {
            for (existing, owner) in &owners {
                if overlaps(&path, existing) {
                    errors.push(Diagnostic::error(
                        source,
                        0,
                        "workers.own",
                        "OWNERSHIP_COLLISION",
                        format!("{path} overlaps {existing} owned by {owner}"),
                    ));
                }
            }
            owners.push((path, worker.id.clone()));
        }
    }
    for worker in workers {
        for dependency in &worker.dependencies {
            if dependency == &worker.id || !ids.contains(dependency) {
                errors.push(Diagnostic::error(
                    source,
                    0,
                    "workers.dependencies",
                    "REFERENCE_RESOLUTION_FAILED",
                    format!("unknown or self dependency: {dependency}"),
                ));
            }
        }
    }
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
}

fn validate_artifact(
    artifact: &ArtifactRef,
    source: &str,
    field: &str,
    errors: &mut Vec<Diagnostic>,
) {
    if artifact.path.trim().is_empty() || !valid_digest(&artifact.digest) {
        errors.push(Diagnostic::error(
            source,
            0,
            field,
            "INTEGRITY_OR_HASH_MISMATCH",
            "artifact requires non-empty path and lowercase sha256 digest",
        ));
    }
}

fn normalize_scope(
    values: &[String],
    source: &str,
    field: &str,
    errors: &mut Vec<Diagnostic>,
) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for value in values {
        let normalized = value.replace('\\', "/");
        if normalized.is_empty()
            || normalized.starts_with('/')
            || normalized.split('/').any(|part| part == "..")
        {
            errors.push(Diagnostic::error(
                source,
                0,
                field,
                "INVALID_INPUT_OR_SCHEMA",
                format!("invalid relative scope path: {value}"),
            ));
            continue;
        }
        if !result.insert(normalized) {
            errors.push(Diagnostic::error(
                source,
                0,
                field,
                "IDENTITY_NOT_UNIQUE",
                format!("duplicate scope path: {value}"),
            ));
        }
    }
    result
}

fn overlaps(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    let prefix = |value: &str| {
        value
            .split('/')
            .take_while(|part| {
                !part
                    .chars()
                    .any(|character| matches!(character, '*' | '?' | '['))
            })
            .collect::<Vec<_>>()
            .join("/")
    };
    let a = prefix(left);
    let b = prefix(right);
    a.is_empty()
        || b.is_empty()
        || a == b
        || a.starts_with(&(b.clone() + "/"))
        || b.starts_with(&(a + "/"))
}
