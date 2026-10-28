//! GitHub boundary normalization for one native delivery observation.
use super::{engineering::{self, ObserveArgs}, CommandError, CommandResult};
use legion_provider_sdk::{
    github::{GitHubObservation, GitHubObserver, GitHubObserverLimits},
    EnvironmentSecretProvider, ScopedCredentialAuthorizer,
};
use legion_runtime::delivery::{
    assess_delivery, BranchPolicy, CheckObservation, CheckStatus, DeliveryAssessmentRequest,
    DeliverySnapshot, HumanReview, Mergeability, MergeState, ObservationCompleteness,
    PullRequestState, RequiredCheck, RevisionProof,
};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::{BTreeMap, BTreeSet}, time::{Duration, SystemTime, UNIX_EPOCH}};
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeliveryProofs {
    schema_version: u32,
    verification: RevisionProof,
    independent_review: RevisionProof,
}

fn missing_proof(now: u64) -> RevisionProof {
    RevisionProof { completed: false, head: String::new(), base: String::new(),
        observed_at_unix_seconds: now, implementer: String::new(), reviewer: String::new(),
        evidence_refs: Vec::new() }
}

pub async fn run(args: ObserveArgs, cancellation: CancellationToken) -> CommandResult {
    if cancellation.is_cancelled() { return Err(CommandError::cancelled()); }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(super::io_error)?.as_secs();
    let (proofs, proof_digest) = if let Some(path) = &args.proofs {
        let bytes = engineering::read_bounded(path, engineering::MAX_INPUT_BYTES)?;
        let proofs: DeliveryProofs = engineering::parse(&bytes)?;
        if proofs.schema_version != 1 { return Err(CommandError::usage("unsupported proofs schemaVersion")); }
        (proofs, Some(engineering::digest(&bytes)))
    } else {
        (DeliveryProofs { schema_version: 1, verification: missing_proof(now), independent_review: missing_proof(now) }, None)
    };
    // Reuse the existing provider SDK's Guard-projected credential boundary.
    // Process variables are host bindings, not an independent proof of Guard enforcement.
    let scope = std::env::var("LEGION_AUTHORIZED_CREDENTIAL_PROVIDER")
        .map_err(|_| CommandError::incomplete("GitHub credential scope unavailable; the host must project the authorized github provider scope"))?;
    let authorizer = ScopedCredentialAuthorizer::new(scope)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let secrets = EnvironmentSecretProvider::new("LEGION_GITHUB_TOKEN")
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let limits = GitHubObserverLimits {
        max_pages: args.max_pages as usize,
        total_timeout: Duration::from_secs(args.timeout_seconds as u64),
        ..GitHubObserverLimits::default()
    };
    let (observer, credential) = GitHubObserver::authorized(&secrets, &authorizer, limits)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let observation = observer.observe(&args.repository, args.pr, cancellation.clone()).await
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    if cancellation.is_cancelled() { return Err(CommandError::cancelled()); }
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(super::io_error)?.as_secs();
    let (request, gaps) = normalize(&observation, &args, proofs, now)?;
    let assessment = assess_delivery(&request)
        .map_err(|error| CommandError::incomplete(error.to_string()))?;
    let observation_bytes = serde_json::to_vec(&observation).map_err(super::io_error)?;
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-delivery-observation",
        "provenance": {
            "origin": "github_api",
            "observationDigest": engineering::digest(&observation_bytes),
            "proofOrigin": if proof_digest.is_some() { "imported" } else { "absent" },
            "proofInputDigest": proof_digest,
            "credential": {"providerId": credential.provider_id, "effect": credential.effect,
                "scheme": credential.auth.scheme, "present": credential.auth.present},
            "requests": observation.receipts,
            "guardEnforcementAttested": false
        },
        "effectAuthority": "none",
        "request": request,
        "assessment": assessment,
        "observationGaps": gaps
    }))
}

fn string(value: &Value, key: &str) -> Result<String, CommandError> {
    value.get(key).and_then(Value::as_str).filter(|s| !s.is_empty())
        .map(str::to_owned).ok_or_else(|| CommandError::incomplete(format!("GitHub metadata missing {key}")))
}

fn normalize(observation: &GitHubObservation, args: &ObserveArgs, proofs: DeliveryProofs, now: u64)
    -> Result<(DeliveryAssessmentRequest, Vec<String>), CommandError> {
    let before = &observation.metadata_before;
    let after = if observation.metadata_after.is_null() { before } else { &observation.metadata_after };
    let mut gaps = observation.gaps.clone();
    let (policy, policy_gaps) = normalize_policy(observation);
    gaps.extend(policy_gaps);
    let (checks, checks_ok) = normalize_checks(observation, &mut gaps);
    let mut metadata_ok = observation.completeness.metadata;
    let state = match after["state"].as_str() {
        Some("OPEN") => PullRequestState::Open,
        Some("CLOSED") => PullRequestState::Closed,
        Some("MERGED") => PullRequestState::Merged,
        _ => { metadata_ok = false; gaps.push("unknown pull request state".into()); PullRequestState::Open }
    };
    let draft = after["isDraft"].as_bool().unwrap_or_else(|| { metadata_ok = false; true });
    let queued = after["isInMergeQueue"].as_bool().unwrap_or_else(|| { metadata_ok = false; true });
    let auto_merge_enabled = match after.get("autoMergeRequest") {
        Some(Value::Null) => false,
        Some(value) if value.is_object() => true,
        _ => { metadata_ok = false; true }
    };
    let mut reviews_ok = observation.completeness.reviews;
    let mut changes_requested = false;
    for review in &observation.reviews {
        match review["state"].as_str() {
            Some("CHANGES_REQUESTED") => changes_requested = true,
            Some("APPROVED" | "COMMENTED" | "DISMISSED" | "PENDING") => {},
            _ => { reviews_ok = false; gaps.push("unknown latest review state".into()); }
        }
    }
    let human_review = if changes_requested { HumanReview::ChangesRequested } else {
        match after.get("reviewDecision") {
            Some(Value::String(value)) if value == "APPROVED" => HumanReview::Satisfied,
            Some(Value::String(value)) if value == "CHANGES_REQUESTED" => HumanReview::ChangesRequested,
            Some(Value::String(value)) if value == "REVIEW_REQUIRED" => HumanReview::Pending,
            Some(Value::Null) if policy.known && !policy.human_review_required && reviews_ok => HumanReview::Satisfied,
            _ => HumanReview::Unknown,
        }
    };
    let mut threads_ok = observation.completeness.threads;
    let mut unresolved_threads = 0;
    for thread in &observation.review_threads {
        match thread["isResolved"].as_bool() {
            Some(false) => unresolved_threads += 1,
            Some(true) => {},
            None => { threads_ok = false; gaps.push("thread resolution is unknown".into()); }
        }
    }
    let expected_head = args.head.clone().unwrap_or(string(before, "headRefOid")?);
    let expected_base = args.base.clone().unwrap_or(string(before, "baseRefOid")?);
    let completeness = ObservationCompleteness {
        checks: metadata_ok && observation.completeness.checks && checks_ok,
        reviews: metadata_ok && reviews_ok,
        threads: metadata_ok && threads_ok,
        policy: metadata_ok && observation.completeness.policy && policy.known,
    };
    let snapshot = DeliverySnapshot {
        repository: observation.repository.clone(), pull_request: observation.pull_request,
        observed_at_unix_seconds: observation.observed_at_unix_seconds,
        head_before: string(before, "headRefOid")?, base_before: string(before, "baseRefOid")?,
        head_after: string(after, "headRefOid")?, base_after: string(after, "baseRefOid")?,
        state, draft,
        mergeability: match after["mergeable"].as_str() {
            Some("MERGEABLE") => Mergeability::Positive,
            Some("CONFLICTING") => Mergeability::Conflicting,
            _ => Mergeability::Unknown,
        },
        merge_state: if queued { MergeState::Queue } else { match after["mergeStateStatus"].as_str() {
            Some("CLEAN") => MergeState::Clear,
            Some("BEHIND") => MergeState::Behind,
            Some("BLOCKED" | "DIRTY" | "DRAFT" | "UNSTABLE" | "HAS_HOOKS") => MergeState::Blocked,
            _ => MergeState::Unknown,
        }},
        completeness, branch_policy: policy, checks, human_review, unresolved_threads,
        auto_merge_enabled, in_merge_queue: queued,
        merge_commit: after.pointer("/mergeCommit/oid").and_then(Value::as_str).map(str::to_owned),
    };
    Ok((DeliveryAssessmentRequest {
        schema_version: 1, repository: observation.repository.clone(), pull_request: args.pr,
        expected_head, expected_base, terminal_goal: args.goal.into(),
        now_unix_seconds: now, max_age_seconds: args.max_age_seconds as u64,
        snapshot, verification: proofs.verification, independent_review: proofs.independent_review,
    }, gaps))
}

fn optional_app(value: Option<&Value>) -> Result<Option<u64>, ()> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) if value.as_i64() == Some(-1) => Ok(None),
        Some(value) => value.as_u64().filter(|id| *id > 0).map(Some).ok_or(()),
    }
}

fn add_requirements(values: &Value, context: &str, app: &str,
    requirements: &mut BTreeMap<(String, Option<u64>), RequiredCheck>) -> bool {
    let Some(values) = values.as_array() else { return false };
    for value in values {
        let Some(name) = value[context].as_str().filter(|name| !name.trim().is_empty() && name.len() <= 2048) else { return false };
        let Ok(app_id) = optional_app(value.get(app)) else { return false };
        requirements.insert((name.to_owned(), app_id), RequiredCheck { name: name.to_owned(), app_id });
        if requirements.len() > 512 { return false; }
    }
    true
}

fn review_required(value: &Value) -> Option<bool> {
    let count = value["required_approving_review_count"].as_u64()?;
    Some(count > 0 || value["require_code_owner_reviews"].as_bool() == Some(true)
        || value["require_last_push_approval"].as_bool() == Some(true)
        || value["required_reviewers"].as_array().is_some_and(|reviewers| !reviewers.is_empty()))
}

fn normalize_policy(observation: &GitHubObservation) -> (BranchPolicy, Vec<String>) {
    let mut gaps = Vec::new();
    let mut requirements = BTreeMap::new();
    let mut human_review_required = false;
    let mut known = observation.completeness.policy;
    if let Some(classic) = &observation.classic_policy_after {
        if !classic.is_object() { known = false; }
        if let Some(checks) = classic.get("required_status_checks").filter(|v| !v.is_null()) {
            if let Some(items) = checks.get("checks") {
                known &= add_requirements(items, "context", "app_id", &mut requirements);
            } else if let Some(items) = checks["contexts"].as_array() {
                for item in items {
                    if let Some(name) = item.as_str().filter(|s| !s.trim().is_empty()) {
                        requirements.insert((name.to_owned(), None), RequiredCheck { name: name.to_owned(), app_id: None });
                    } else { known = false; }
                }
            } else { known = false; }
        }
        if let Some(reviews) = classic.get("required_pull_request_reviews").filter(|v| !v.is_null()) {
            if let Some(required) = review_required(reviews) { human_review_required |= required; }
            else { known = false; }
        }
        for field in ["required_signatures", "required_linear_history", "lock_branch"] {
            if classic.get(field).and_then(|v| v.get("enabled")).and_then(Value::as_bool) == Some(true) {
                known = false;
                gaps.push(format!("classic policy {field} requires an unmodeled readiness check"));
            }
        }
    }
    for rule in &observation.rules_after {
        match rule["type"].as_str() {
            Some("required_status_checks") => {
                known &= add_requirements(&rule["parameters"]["required_status_checks"], "context", "integration_id", &mut requirements);
            }
            Some("pull_request") => {
                if let Some(required) = review_required(&rule["parameters"]) { human_review_required |= required; }
                else { known = false; }
            }
            // These restrict other ref operations; this observer never performs them.
            Some("creation" | "deletion" | "non_fast_forward") => {},
            Some(kind) => { known = false; gaps.push(format!("unmodeled active branch rule: {kind}")); }
            None => { known = false; gaps.push("active branch rule lacks a type".into()); }
        }
    }
    if requirements.len() > 512 { known = false; }
    if !known { gaps.push("effective branch policy is incomplete or unsupported".into()); }
    (BranchPolicy { known, required_checks: requirements.into_values().take(512).collect(),
        human_review_required, allow_neutral: false, allow_skipped: false }, gaps)
}

fn normalize_checks(observation: &GitHubObservation, gaps: &mut Vec<String>) -> (Vec<CheckObservation>, bool) {
    let mut checks = Vec::new();
    let mut complete = true;
    for run in &observation.check_runs {
        let Some(name) = run["name"].as_str().filter(|s| !s.trim().is_empty() && s.len() <= 2048) else { complete = false; continue };
        let Some(head) = run["head_sha"].as_str() else { complete = false; continue };
        let app_id = run.pointer("/app/id").and_then(Value::as_u64).filter(|id| *id > 0);
        if app_id.is_none() { complete = false; }
        let status = match run["status"].as_str() {
            Some("queued" | "in_progress" | "waiting" | "pending" | "requested") => CheckStatus::Pending,
            Some("completed") => match run["conclusion"].as_str() {
                Some("success") => CheckStatus::Success,
                Some("neutral") => CheckStatus::Neutral,
                Some("skipped") => CheckStatus::Skipped,
                Some("cancelled") => CheckStatus::Cancelled,
                Some("timed_out") => CheckStatus::TimedOut,
                Some("failure" | "action_required" | "stale" | "startup_failure") => CheckStatus::Failure,
                _ => CheckStatus::Unknown,
            },
            _ => CheckStatus::Unknown,
        };
        checks.push(CheckObservation { name: name.to_owned(), app_id, head: head.to_owned(), status });
    }
    // REST commit statuses are history, newest first. Only the newest value of a
    // context is current; duplicate *current check runs* above remain separate.
    let mut contexts = BTreeSet::new();
    for status in &observation.statuses {
        let Some(name) = status["context"].as_str().filter(|s| !s.trim().is_empty() && s.len() <= 2048) else { complete = false; continue };
        if !contexts.insert(name) { continue; }
        let Some(head) = status["_legion_head"].as_str() else { complete = false; continue };
        let state = match status["state"].as_str() {
            Some("success") => CheckStatus::Success,
            Some("pending") => CheckStatus::Pending,
            Some("failure" | "error") => CheckStatus::Failure,
            _ => CheckStatus::Unknown,
        };
        checks.push(CheckObservation { name: name.to_owned(), app_id: None, head: head.to_owned(), status: state });
    }
    if checks.len() > 512 { checks.truncate(512); complete = false; }
    if !complete { gaps.push("check records contain missing metadata or exceed the supported bound".into()); }
    (checks, complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use legion_provider_sdk::github::GitHubObservationCompleteness;
    fn observation() -> GitHubObservation {
        GitHubObservation { repository: "owner/repo".into(), pull_request: 1,
            observed_at_unix_seconds: 100, metadata_before: json!({}), metadata_after: json!({}),
            classic_policy_before: None, classic_policy_after: None,
            rules_before: vec![], rules_after: vec![], check_runs: vec![], statuses: vec![],
            review_threads: vec![], reviews: vec![],
            completeness: GitHubObservationCompleteness { metadata: true, checks: true, reviews: true, threads: true, policy: true },
            gaps: vec![], receipts: vec![] }
    }
    #[test]
    fn effective_policy_keeps_application_identity_and_rejects_unmodeled_rules() {
        let mut observed = observation();
        observed.rules_after = vec![json!({"type":"required_status_checks","parameters":{"required_status_checks":[{"context":"ci","integration_id":42}]}})];
        let (policy, _) = normalize_policy(&observed);
        assert!(policy.known);
        assert_eq!(policy.required_checks[0].app_id, Some(42));
        observed.rules_after.push(json!({"type":"required_deployments","parameters":{}}));
        assert!(!normalize_policy(&observed).0.known);
    }
    #[test]
    fn unavailable_policy_and_malformed_requirements_cannot_become_empty_success() {
        let mut observed = observation();
        observed.completeness.policy = false;
        assert!(!normalize_policy(&observed).0.known);
        observed.completeness.policy = true;
        observed.rules_after.push(json!({"type":"required_status_checks","parameters":{}}));
        assert!(!normalize_policy(&observed).0.known);
    }
    #[test]
    fn check_runs_preserve_current_duplicates_but_status_history_uses_latest() {
        let mut observed = observation();
        for result in ["success", "failure"] {
            observed.check_runs.push(json!({"name":"ci","app":{"id":42},"head_sha":"a".repeat(40),"status":"completed","conclusion":result}));
        }
        observed.statuses = vec![
            json!({"context":"legacy","state":"success","_legion_head":"a".repeat(40)}),
            json!({"context":"legacy","state":"failure","_legion_head":"a".repeat(40)})];
        let (checks, complete) = normalize_checks(&observed, &mut vec![]);
        assert!(complete);
        assert_eq!(checks.len(), 3);
        assert_eq!(checks[1].status, CheckStatus::Failure);
        assert_eq!(checks[2].status, CheckStatus::Success);
    }
}
