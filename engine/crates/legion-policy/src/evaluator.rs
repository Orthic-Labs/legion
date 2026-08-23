use legion_contracts::{canonical_digest, canonical_json_bytes};
use legion_policy_model::{
    ApprovalRequirement, CapabilityGrant, DecisionOutcome, DenialReason, EffectClass,
    EnforcementLevel, LeaseState, PathOperation, PolicyContext, PolicyDecision, PolicyPack,
    PolicyRule, ReceiptState, RuleDecision, TrustLevel, POLICY_SCHEMA_VERSION,
};

use crate::{
    error::PolicyEvaluationError,
    explanation::Explanation,
    precedence::{matching_rules, EvaluationStage},
};

/// The immutable result of one policy evaluation, including its replay trace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyEvaluation {
    pub decision: PolicyDecision,
    pub explanation: Explanation,
    pub receipt: PolicyReceipt,
}

/// Receipt payload is exactly the canonical policy decision; no secret input is copied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyReceipt {
    pub decision: PolicyDecision,
}

/// Validated immutable evaluator. Cloning the pack is intentional: one
/// evaluation cannot observe a policy mutation from another execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyEvaluator {
    pack: PolicyPack,
}

impl PolicyEvaluator {
    pub fn new(pack: PolicyPack) -> Result<Self, PolicyEvaluationError> {
        pack.validate()
            .map_err(|error| PolicyEvaluationError::InvalidPolicy(error.to_string()))?;
        Ok(Self { pack })
    }

    pub fn pack(&self) -> &PolicyPack {
        &self.pack
    }

    pub fn evaluate(&self, ctx: &PolicyContext) -> PolicyEvaluation {
        evaluate(&self.pack, ctx)
    }
}

impl PolicyReceipt {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, legion_contracts::canonical::CanonicalError> {
        canonical_json_bytes(&self.decision)
    }

    pub fn digest(&self) -> Result<String, legion_contracts::canonical::CanonicalError> {
        canonical_digest(&self.decision)
    }
}

/// Evaluate a policy pack and return one terminal decision plus its explanation.
pub fn evaluate(pack: &PolicyPack, ctx: &PolicyContext) -> PolicyEvaluation {
    let digest = pack
        .digest()
        .unwrap_or_else(|_| "sha256:invalid-policy".into());
    let mut explanation = Explanation::new(pack.policy_id.clone(), pack.version, digest.clone());
    let mut matched = Vec::new();

    let decision = match evaluate_inner(pack, ctx, &mut explanation, &mut matched) {
        Ok(decision) => decision,
        Err(error) => {
            explanation.reason_code = reason_code(&error);
            let decision =
                PolicyDecision::deny(error.reason(), pack.policy_id.clone(), pack.version, digest);
            explanation.rejected_alternatives.push(error.to_string());
            decision
        }
    };
    let receipt = PolicyReceipt {
        decision: decision.clone(),
    };
    PolicyEvaluation {
        decision,
        explanation,
        receipt,
    }
}

/// Alias retained for callers that use the explicit decision-oriented name.
pub fn evaluate_decision(pack: &PolicyPack, ctx: &PolicyContext) -> PolicyEvaluation {
    evaluate(pack, ctx)
}

/// Alias retained for callers that use a verb rather than a noun.
pub fn decide(pack: &PolicyPack, ctx: &PolicyContext) -> PolicyEvaluation {
    evaluate(pack, ctx)
}

fn evaluate_inner<'a>(
    pack: &'a PolicyPack,
    ctx: &PolicyContext,
    explanation: &mut Explanation,
    matched: &mut Vec<&'a PolicyRule>,
) -> Result<PolicyDecision, PolicyEvaluationError> {
    if ctx.schema_version != POLICY_SCHEMA_VERSION || ctx.contract.validate().is_err() {
        return fail(
            EvaluationStage::SupportedContract,
            "unsupported_contract",
            PolicyEvaluationError::UnsupportedContract,
            explanation,
        );
    }
    if !pack
        .contract_versions
        .iter()
        .any(|version| version == &ctx.contract)
    {
        return fail(
            EvaluationStage::SupportedContract,
            "unsupported_contract",
            PolicyEvaluationError::UnsupportedContract,
            explanation,
        );
    }
    explanation.record(
        EvaluationStage::SupportedContract,
        "supported_contract",
        Vec::new(),
    );

    if !EffectClass::ALL.contains(&ctx.effect_class) {
        return fail(
            EvaluationStage::KnownEffect,
            "unknown_effect",
            PolicyEvaluationError::UnknownEffect,
            explanation,
        );
    }
    explanation.record(EvaluationStage::KnownEffect, "known_effect", Vec::new());

    if ctx.repository.trim().is_empty() || ctx.worktree.trim().is_empty() {
        return fail(
            EvaluationStage::ValidIdentityScope,
            "invalid_identity",
            PolicyEvaluationError::InvalidIdentity,
            explanation,
        );
    }
    if let Some(path) = &ctx.path {
        if path.scope.repository != ctx.repository || path.scope.worktree != ctx.worktree {
            return fail(
                EvaluationStage::ValidIdentityScope,
                "invalid_scope",
                PolicyEvaluationError::InvalidScope,
                explanation,
            );
        }
    }
    explanation.record(
        EvaluationStage::ValidIdentityScope,
        "valid_identity_scope",
        Vec::new(),
    );

    if pack.validate().is_err() {
        return fail(
            EvaluationStage::DefinitionCeiling,
            "evaluator_error",
            PolicyEvaluationError::InvalidPolicy("policy pack validation failed".into()),
            explanation,
        );
    }
    explanation.record(
        EvaluationStage::DefinitionCeiling,
        "definition_ceiling",
        Vec::new(),
    );

    let Some(grant) = ctx.grant.as_ref() else {
        return fail(
            EvaluationStage::InvocationGrant,
            "invocation_grant",
            PolicyEvaluationError::InvocationGrant,
            explanation,
        );
    };
    if grant.is_subset_of(&pack.capability).is_err() || !grant_covers(grant, ctx) {
        return fail(
            EvaluationStage::InvocationGrant,
            "invocation_grant",
            PolicyEvaluationError::InvocationGrant,
            explanation,
        );
    }
    explanation.record(
        EvaluationStage::InvocationGrant,
        "invocation_grant",
        Vec::new(),
    );

    if requires_canonical_path(ctx) {
        let Some(path) = &ctx.path else {
            return fail(
                EvaluationStage::CanonicalTarget,
                "invalid_path",
                PolicyEvaluationError::InvalidPath,
                explanation,
            );
        };
        if path.scope.repository != ctx.repository
            || path.scope.worktree != ctx.worktree
            || path.normalized_relative_path.trim().is_empty()
        {
            return fail(
                EvaluationStage::CanonicalTarget,
                "invalid_path",
                PolicyEvaluationError::InvalidPath,
                explanation,
            );
        }
    }
    explanation.record(
        EvaluationStage::CanonicalTarget,
        "canonical_target",
        Vec::new(),
    );

    matched.extend(matching_rules(pack, ctx));
    explanation.matched_rule_ids = matched.iter().map(|rule| rule.id.clone()).collect();

    let denied: Vec<_> = matched
        .iter()
        .filter(|rule| rule.rule == RuleDecision::Deny)
        .collect();
    let allowed: Vec<_> = matched
        .iter()
        .filter(|rule| rule.rule == RuleDecision::Allow)
        .collect();
    if !denied.is_empty() {
        let exception = denied.iter().any(|rule| rule.exception_capable) && !allowed.is_empty();
        if !exception {
            explanation
                .rejected_alternatives
                .extend(denied.iter().map(|rule| rule.id.clone()));
            return fail(
                EvaluationStage::ExplicitDeny,
                "explicit_deny",
                PolicyEvaluationError::ExplicitDeny,
                explanation,
            );
        }
        explanation
            .rejected_alternatives
            .extend(denied.iter().map(|rule| rule.id.clone()));
    }
    explanation.record(
        EvaluationStage::ExplicitDeny,
        "explicit_deny_checked",
        denied.iter().map(|rule| rule.id.clone()).collect(),
    );

    let Some(rule) = allowed.first().copied() else {
        return fail(
            EvaluationStage::DefaultDeny,
            "no_matching_rule",
            PolicyEvaluationError::NoMatchingRule,
            explanation,
        );
    };
    if rule.approval_required && !ctx.approval_satisfies(ApprovalRequirement::User) {
        explanation.reason_code = "approval_required".into();
        explanation.record(
            EvaluationStage::ApprovalLeaseProvenance,
            "approval_required",
            vec![rule.id.clone()],
        );
        return Ok(decision(
            pack,
            DecisionOutcome::RequireApproval,
            Some(DenialReason::ApprovalRequired),
            matched,
            &explanation.rejected_alternatives,
        ));
    }
    if !matches!(ctx.lease, LeaseState::Active) {
        return fail(
            EvaluationStage::ApprovalLeaseProvenance,
            "lease_invalid",
            PolicyEvaluationError::LeaseInvalid,
            explanation,
        );
    }
    if (rule.receipt_required || pack.receipt_requirements.effect_receipt)
        && !matches!(ctx.receipt, ReceiptState::Present)
    {
        return fail(
            EvaluationStage::ApprovalLeaseProvenance,
            "receipt_required",
            PolicyEvaluationError::ReceiptRequired,
            explanation,
        );
    }
    explanation.record(
        EvaluationStage::ApprovalLeaseProvenance,
        "approval_lease_provenance",
        vec![rule.id.clone()],
    );

    let minimum_trust = rule.trust_minimum.max(required_trust(pack, ctx));
    if !ctx.trust.satisfies(minimum_trust) {
        return fail(
            EvaluationStage::TrustSandboxNetwork,
            "trust_insufficient",
            PolicyEvaluationError::TrustInsufficient,
            explanation,
        );
    }
    let minimum_enforcement = rule
        .required_enforcement
        .max(required_enforcement(pack, ctx));
    if !ctx.enforcement.satisfies(minimum_enforcement) {
        return fail(
            EvaluationStage::TrustSandboxNetwork,
            "enforcement_insufficient",
            PolicyEvaluationError::EnforcementInsufficient,
            explanation,
        );
    }
    explanation.record(
        EvaluationStage::TrustSandboxNetwork,
        "trust_sandbox_network",
        vec![rule.id.clone()],
    );

    explanation.reason_code = "explicit_allow".into();
    explanation.record(
        EvaluationStage::ExplicitAllow,
        "explicit_allow",
        vec![rule.id.clone()],
    );
    Ok(decision(
        pack,
        DecisionOutcome::Allow,
        None,
        matched,
        &explanation.rejected_alternatives,
    ))
}

fn fail<T>(
    stage: EvaluationStage,
    code: &str,
    error: PolicyEvaluationError,
    explanation: &mut Explanation,
) -> Result<T, PolicyEvaluationError> {
    explanation.reason_code = code.into();
    explanation.record(stage, code, Vec::new());
    Err(error)
}

fn decision(
    pack: &PolicyPack,
    outcome: DecisionOutcome,
    reason: Option<DenialReason>,
    matched: &[&PolicyRule],
    rejected: &[String],
) -> PolicyDecision {
    let digest = pack
        .digest()
        .unwrap_or_else(|_| "sha256:invalid-policy".into());
    PolicyDecision {
        schema_version: 1,
        outcome,
        reason,
        matched_rule_ids: matched.iter().map(|rule| rule.id.clone()).collect(),
        rejected_alternatives: rejected.to_vec(),
        policy_id: pack.policy_id.clone(),
        policy_version: pack.version,
        policy_digest: digest,
    }
}

fn grant_covers(grant: &CapabilityGrant, ctx: &PolicyContext) -> bool {
    if !grant.effects.contains(&ctx.effect_class)
        || !grant.operations.contains(operation_name(ctx.operation))
    {
        return false;
    }
    if grant.targets.is_empty() {
        return true;
    }
    ctx.path.as_ref().is_some_and(|path| {
        grant.targets.iter().any(|target| {
            path.normalized_relative_path == *target
                || path
                    .normalized_relative_path
                    .starts_with(&(target.clone() + "/"))
        })
    })
}

fn operation_name(operation: PathOperation) -> &'static str {
    match operation {
        PathOperation::Read => "read",
        PathOperation::Write => "write",
        PathOperation::Delete => "delete",
        PathOperation::Move => "move",
        PathOperation::Execute => "execute",
    }
}

fn requires_canonical_path(ctx: &PolicyContext) -> bool {
    matches!(
        ctx.operation,
        PathOperation::Write | PathOperation::Delete | PathOperation::Move | PathOperation::Execute
    )
}

fn required_trust(pack: &PolicyPack, ctx: &PolicyContext) -> TrustLevel {
    match ctx.operation {
        PathOperation::Read => pack.trust_minima.read_only,
        _ => pack.trust_minima.mutation,
    }
}

fn required_enforcement(pack: &PolicyPack, ctx: &PolicyContext) -> EnforcementLevel {
    match ctx.operation {
        PathOperation::Read => pack.host_enforcement.required_for_read_only,
        _ => pack.host_enforcement.required_for_mutation,
    }
}

fn reason_code(error: &PolicyEvaluationError) -> String {
    match error {
        PolicyEvaluationError::UnsupportedContract => "unsupported_contract",
        PolicyEvaluationError::UnknownEffect => "unknown_effect",
        PolicyEvaluationError::InvalidIdentity => "invalid_identity",
        PolicyEvaluationError::InvalidScope => "invalid_scope",
        PolicyEvaluationError::DefinitionCeiling => "definition_ceiling",
        PolicyEvaluationError::InvocationGrant => "invocation_grant",
        PolicyEvaluationError::InvalidPath => "invalid_path",
        PolicyEvaluationError::ExplicitDeny => "explicit_deny",
        PolicyEvaluationError::ApprovalRequired => "approval_required",
        PolicyEvaluationError::LeaseInvalid => "lease_invalid",
        PolicyEvaluationError::TrustInsufficient => "trust_insufficient",
        PolicyEvaluationError::EnforcementInsufficient => "enforcement_insufficient",
        PolicyEvaluationError::ReceiptRequired => "receipt_required",
        PolicyEvaluationError::NoMatchingRule => "no_matching_rule",
        PolicyEvaluationError::InvalidPolicy(_) | PolicyEvaluationError::EvaluatorError(_) => {
            "evaluator_error"
        }
    }
    .into()
}

impl PolicyEvaluationError {
    fn reason(&self) -> DenialReason {
        match self {
            Self::UnsupportedContract => DenialReason::UnsupportedContract,
            Self::UnknownEffect => DenialReason::UnknownEffect,
            Self::InvalidIdentity => DenialReason::InvalidIdentity,
            Self::InvalidScope => DenialReason::InvalidScope,
            Self::DefinitionCeiling => DenialReason::DefinitionCeiling,
            Self::InvocationGrant => DenialReason::InvocationGrant,
            Self::InvalidPath => DenialReason::InvalidPath,
            Self::ExplicitDeny => DenialReason::ExplicitDeny,
            Self::ApprovalRequired => DenialReason::ApprovalRequired,
            Self::LeaseInvalid => DenialReason::LeaseInvalid,
            Self::TrustInsufficient => DenialReason::TrustInsufficient,
            Self::EnforcementInsufficient => DenialReason::EnforcementInsufficient,
            Self::ReceiptRequired => DenialReason::ReceiptRequired,
            Self::NoMatchingRule => DenialReason::NoMatchingRule,
            Self::InvalidPolicy(_) | Self::EvaluatorError(_) => DenialReason::MalformedPolicy,
        }
    }
}
