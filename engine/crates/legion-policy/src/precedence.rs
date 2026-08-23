use legion_policy_model::{PolicyContext, PolicyPack, PolicyRule};

/// Fixed, public evaluation order. This order is part of the replay contract.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum EvaluationStage {
    SupportedContract,
    KnownEffect,
    ValidIdentityScope,
    DefinitionCeiling,
    InvocationGrant,
    CanonicalTarget,
    ExplicitDeny,
    ApprovalLeaseProvenance,
    TrustSandboxNetwork,
    ExplicitAllow,
    DefaultDeny,
}

pub const EVALUATION_ORDER: [EvaluationStage; 11] = [
    EvaluationStage::SupportedContract,
    EvaluationStage::KnownEffect,
    EvaluationStage::ValidIdentityScope,
    EvaluationStage::DefinitionCeiling,
    EvaluationStage::InvocationGrant,
    EvaluationStage::CanonicalTarget,
    EvaluationStage::ExplicitDeny,
    EvaluationStage::ApprovalLeaseProvenance,
    EvaluationStage::TrustSandboxNetwork,
    EvaluationStage::ExplicitAllow,
    EvaluationStage::DefaultDeny,
];

/// Matching rules are always ordered by their stable identifiers.
pub fn matching_rules<'a>(pack: &'a PolicyPack, ctx: &PolicyContext) -> Vec<&'a PolicyRule> {
    let mut rules: Vec<_> = pack
        .effect_rules
        .iter()
        .filter(|rule| rule.matches(ctx))
        .collect();
    rules.sort_by(|left, right| left.id.cmp(&right.id));
    rules
}

pub fn matching_rule_ids(pack: &PolicyPack, ctx: &PolicyContext) -> Vec<String> {
    matching_rules(pack, ctx)
        .into_iter()
        .map(|rule| rule.id.clone())
        .collect()
}
