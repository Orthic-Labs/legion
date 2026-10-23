//! Signed plan amendments (CP section 15): a frozen plan is never mutated at
//! runtime. An amendment names the exact parent plan digest and generation,
//! lists a closed set of allowed operations, is HMAC-signed with the same key
//! as the plan, and applying it compiles, validates, seals and signs a brand
//! new plan generation. Verification walks the generation chain from the
//! original plan by replaying every amendment deterministically.
//!
//! Allowed operations: add an obligation (provider), add a follow-up provider
//! run, extend the token budget within the engagement authority ceiling, add a
//! scope exclusion with authority and reason. Anything else fails to parse.
//! Legacy (schema 1) plans cannot be amended: regenerate them.
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;

use crate::{
    dag::topological_with_artifacts,
    error::AuditError,
    integrity::{canonical_bytes, digest},
    plan::{
        AuditPlan, AuditProvider, AuthorityMode, Engagement, FrozenPlan, ProviderKind,
        ENGAGEMENT_BOUND, FOLLOWUP_RUNS_BOUND, LINEAGE_BOUND, PLAN_SCHEMA_V2,
    },
};

type HmacSha256 = Hmac<Sha256>;

pub const AMENDMENT_FORMAT: &str = "audit-plan-amendment/v1";
const SIGNATURE_PREFIX: &str = "hmac-sha256:";
const DOMAIN: &[u8] = b"audit-plan-amendment/v1\n";
const MAX_OPERATIONS: usize = 32;

fn invalid(message: impl Into<String>) -> AuditError {
    AuditError::Invalid(format!("plan amendment: {}", message.into()))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum AmendmentOperation {
    /// Add a provider obligation. A provider that escalates effects
    /// (external project tool / effect executor) additionally needs the
    /// engagement approval reference in `approval_refs`.
    #[serde(rename_all = "camelCase")]
    AddObligation { provider: AuditProvider },
    /// Add a follow-up provider run (e.g. variant analysis). `followup` is the
    /// binding frozen by the follow-up compiler; its `parentPlanDigest` must be
    /// the base plan digest.
    #[serde(rename_all = "camelCase")]
    AddFollowupRun {
        provider: AuditProvider,
        followup: Value,
    },
    /// Raise the engagement token budget, never above the authority ceiling.
    #[serde(rename_all = "camelCase")]
    ExtendBudget { max_tokens: u64 },
    /// Narrow scope by excluding a path pattern. Needs explicit authority, a
    /// reason, and the engagement approval reference as `authority_ref`.
    #[serde(rename_all = "camelCase")]
    AddExclusion {
        pattern: String,
        reason: String,
        authority_ref: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AmendmentBody {
    pub format: String,
    pub reason: String,
    pub base_plan_digest: String,
    pub base_generation: u64,
    /// Unix seconds; checked against engagement expiry, never against a clock
    /// at verification time, so old chains stay verifiable.
    pub issued_at_unix: u64,
    #[serde(default)]
    pub proposed_by: Option<String>,
    pub operations: Vec<AmendmentOperation>,
    #[serde(default)]
    pub approval_refs: Vec<String>,
}

impl AmendmentBody {
    pub fn new(
        base: &FrozenPlan,
        reason: impl Into<String>,
        issued_at_unix: u64,
        operations: Vec<AmendmentOperation>,
    ) -> Result<Self, AuditError> {
        Ok(Self {
            format: AMENDMENT_FORMAT.into(),
            reason: reason.into(),
            base_plan_digest: base.digest().to_owned(),
            base_generation: base.plan().generation()?,
            issued_at_unix,
            proposed_by: None,
            operations,
            approval_refs: Vec::new(),
        })
    }

    pub fn digest(&self) -> Result<String, AuditError> {
        digest(self)
    }

    /// Stable amendment id derived from the body digest.
    pub fn amendment_id(&self) -> Result<String, AuditError> {
        let digest = self.digest()?;
        Ok(format!(
            "amd_{}",
            &digest.strip_prefix("sha256:").unwrap_or(&digest)[..16]
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedAmendment {
    pub body: AmendmentBody,
    pub digest: String,
    pub signature: String,
}

fn mac(key: &[u8], body: &AmendmentBody) -> Result<HmacSha256, AuditError> {
    let mut mac =
        HmacSha256::new_from_slice(key).map_err(|_| invalid("empty or invalid signing key"))?;
    mac.update(DOMAIN);
    mac.update(&canonical_bytes(body)?);
    Ok(mac)
}

impl SignedAmendment {
    pub fn sign(body: AmendmentBody, key: &[u8]) -> Result<Self, AuditError> {
        if key.is_empty() {
            return Err(invalid("signing key is required"));
        }
        let signature = format!(
            "{SIGNATURE_PREFIX}{}",
            hex::encode(mac(key, &body)?.finalize().into_bytes())
        );
        Ok(Self {
            digest: body.digest()?,
            body,
            signature,
        })
    }

    /// Verify the body digest and HMAC. Unsigned or forged amendments fail.
    pub fn verify(&self, key: &[u8]) -> Result<(), AuditError> {
        if self.body.format != AMENDMENT_FORMAT {
            return Err(invalid("unsupported amendment format"));
        }
        if self.digest != self.body.digest()? {
            return Err(invalid("amendment digest mismatch"));
        }
        let provided = self
            .signature
            .strip_prefix(SIGNATURE_PREFIX)
            .and_then(|hex| hex::decode(hex).ok())
            .ok_or_else(|| invalid("amendment is unsigned or its signature is malformed"))?;
        mac(key, &self.body)?
            .verify_slice(&provided)
            .map_err(|_| invalid("amendment signature verification failed"))
    }
}

/// One applied link of the generation chain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AppliedAmendment {
    pub amendment: SignedAmendment,
    pub result_generation: u64,
    pub result_plan_digest: String,
}

fn require_authority(
    plan: &AuditPlan,
    issued_at_unix: u64,
    what: &str,
) -> Result<Engagement, AuditError> {
    let engagement = plan
        .engagement()?
        .ok_or_else(|| invalid(format!("{what} requires an engagement")))?;
    if engagement.authority.mode != AuthorityMode::Explicit {
        return Err(invalid(format!(
            "{what} requires explicit authority, not implicit read-only"
        )));
    }
    if engagement
        .authority
        .expires_at_unix
        .is_none_or(|expiry| issued_at_unix >= expiry)
    {
        return Err(invalid(format!("{what}: engagement authority expired")));
    }
    Ok(engagement)
}

fn store_engagement(plan: &mut AuditPlan, engagement: &Engagement) -> Result<(), AuditError> {
    engagement.validate()?;
    plan.bounds.insert(
        ENGAGEMENT_BOUND.into(),
        serde_json::to_value(engagement).map_err(|error| invalid(error.to_string()))?,
    );
    Ok(())
}

fn add_provider(
    plan: &mut AuditPlan,
    body: &AmendmentBody,
    provider: &AuditProvider,
) -> Result<(), AuditError> {
    if plan
        .providers
        .iter()
        .any(|existing| existing.id == provider.id)
    {
        return Err(invalid(format!(
            "provider {} is already in the plan",
            provider.id
        )));
    }
    if matches!(
        provider.kind,
        ProviderKind::TypedExternalProjectTool | ProviderKind::EffectExecutor
    ) {
        let engagement = require_authority(plan, body.issued_at_unix, "effect escalation")?;
        let approval = engagement
            .authority
            .approval_ref
            .as_deref()
            .ok_or_else(|| invalid("effect escalation needs an engagement approval reference"))?;
        if !body
            .approval_refs
            .iter()
            .any(|reference| reference == approval)
        {
            return Err(invalid("effect escalation lacks the engagement approval"));
        }
    }
    plan.providers.push(provider.clone());
    Ok(())
}

fn apply_operation(
    plan: &mut AuditPlan,
    body: &AmendmentBody,
    operation: &AmendmentOperation,
) -> Result<(), AuditError> {
    match operation {
        AmendmentOperation::AddObligation { provider } => add_provider(plan, body, provider),
        AmendmentOperation::AddFollowupRun { provider, followup } => {
            if provider.role != "variant-analysis" {
                return Err(invalid("follow-up run provider must be variant-analysis"));
            }
            let parent = followup.get("parentPlanDigest").and_then(Value::as_str);
            if parent != Some(body.base_plan_digest.as_str()) {
                return Err(invalid(
                    "follow-up binding is not bound to the base plan digest",
                ));
            }
            add_provider(plan, body, provider)?;
            let entry = serde_json::json!({
                "providerId": provider.id,
                "followup": followup,
            });
            match plan.bounds.get_mut(FOLLOWUP_RUNS_BOUND) {
                Some(Value::Array(runs)) => runs.push(entry),
                None => {
                    plan.bounds
                        .insert(FOLLOWUP_RUNS_BOUND.into(), Value::Array(vec![entry]));
                }
                Some(_) => return Err(invalid("followupRuns bound is malformed")),
            }
            Ok(())
        }
        AmendmentOperation::ExtendBudget { max_tokens } => {
            let mut engagement = require_authority(plan, body.issued_at_unix, "budget extension")?;
            let ceiling = engagement
                .authority
                .budget_ceiling_tokens
                .ok_or_else(|| invalid("authority declares no budget ceiling"))?;
            let current = engagement
                .stop_conditions
                .max_tokens
                .ok_or_else(|| invalid("engagement has no finite budget to extend"))?;
            if *max_tokens <= current {
                return Err(invalid("budget extension must increase the budget"));
            }
            if *max_tokens > ceiling {
                return Err(invalid("budget extension exceeds the authority ceiling"));
            }
            engagement.stop_conditions.max_tokens = Some(*max_tokens);
            store_engagement(plan, &engagement)
        }
        AmendmentOperation::AddExclusion {
            pattern,
            reason,
            authority_ref,
        } => {
            let mut engagement = require_authority(plan, body.issued_at_unix, "scope exclusion")?;
            if reason.trim().is_empty() || pattern.trim().is_empty() {
                return Err(invalid("exclusion needs a pattern and a reason"));
            }
            if pattern.starts_with('/') || pattern.split('/').any(|part| part == "..") {
                return Err(invalid("exclusion pattern must be repository-relative"));
            }
            if engagement.authority.approval_ref.as_deref() != Some(authority_ref.as_str()) {
                return Err(invalid(
                    "exclusion authority reference does not match the engagement",
                ));
            }
            if engagement.scope.exclude.contains(pattern) {
                return Err(invalid("pattern is already excluded"));
            }
            engagement.scope.exclude.push(pattern.clone());
            engagement.scope.exclude.sort();
            store_engagement(plan, &engagement)
        }
    }
}

/// Apply a signed amendment to a signed base plan, producing a new sealed,
/// signed plan generation and its chain link.
pub fn apply(
    base: &FrozenPlan,
    amendment: &SignedAmendment,
    key: &[u8],
) -> Result<(FrozenPlan, AppliedAmendment), AuditError> {
    if key.is_empty() {
        return Err(invalid("signing key is required"));
    }
    // The base must itself be an authenticated, signed generation.
    if base.signature().is_none() {
        return Err(invalid("base plan is unsigned"));
    }
    crate::integrity::verify(base.plan(), base.digest(), base.signature(), Some(key))?;
    amendment.verify(key)?;
    let body = &amendment.body;
    if body.base_plan_digest != base.digest() {
        return Err(invalid("amendment is bound to a different parent plan"));
    }
    let base_generation = base.plan().generation()?;
    if body.base_generation != base_generation {
        return Err(invalid(
            "amendment base generation does not match the parent plan",
        ));
    }
    if base.plan().schema_version < PLAN_SCHEMA_V2 {
        return Err(invalid(
            "legacy schema 1 plans cannot be amended; regenerate the plan",
        ));
    }
    if body.reason.trim().is_empty() {
        return Err(invalid("amendment reason is required"));
    }
    if body.operations.is_empty() || body.operations.len() > MAX_OPERATIONS {
        return Err(invalid("amendment needs between 1 and 32 operations"));
    }
    let mut plan = base.plan().clone();
    for operation in &body.operations {
        apply_operation(&mut plan, body, operation)?;
    }
    let order = topological_with_artifacts(&plan.providers)?;
    let mut by_id: std::collections::BTreeMap<_, _> = plan
        .providers
        .drain(..)
        .map(|provider| (provider.id.clone(), provider))
        .collect();
    plan.providers = order
        .into_iter()
        .map(|id| by_id.remove(&id).expect("ordered provider id"))
        .collect();
    plan.refresh_objective_graph()?;
    let result_generation = base_generation + 1;
    plan.bounds.insert(
        LINEAGE_BOUND.into(),
        serde_json::json!({
            "schemaVersion": 1,
            "generation": result_generation,
            "parentPlanDigest": base.digest(),
            "amendmentDigest": amendment.digest,
            "amendmentSignature": amendment.signature,
        }),
    );
    let frozen = plan.freeze(Some(key))?;
    let applied = AppliedAmendment {
        amendment: amendment.clone(),
        result_generation,
        result_plan_digest: frozen.digest().to_owned(),
    };
    Ok((frozen, applied))
}

/// Walk the generation chain from the original (generation 1) plan, replaying
/// and re-verifying every amendment. Returns the final generation; a forged,
/// reordered, skipped or re-parented link fails the whole chain.
pub fn verify_chain(
    genesis: &FrozenPlan,
    links: &[AppliedAmendment],
    key: &[u8],
) -> Result<FrozenPlan, AuditError> {
    crate::integrity::verify(
        genesis.plan(),
        genesis.digest(),
        genesis.signature(),
        Some(key),
    )?;
    if genesis.signature().is_none() || genesis.plan().generation()? != 1 {
        return Err(invalid("chain must start at a signed generation 1 plan"));
    }
    let mut current = genesis.clone();
    let mut last_issued = 0u64;
    for link in links {
        if link.amendment.body.issued_at_unix < last_issued {
            return Err(invalid("amendment chain is not chronologically ordered"));
        }
        last_issued = link.amendment.body.issued_at_unix;
        let (next, applied) = apply(&current, &link.amendment, key)?;
        if applied.result_generation != link.result_generation
            || applied.result_plan_digest != link.result_plan_digest
        {
            return Err(invalid(
                "amendment chain link does not reproduce its recorded result",
            ));
        }
        current = next;
    }
    Ok(current)
}

/// Adapter for follow-up plans (`reasoning/followup.rs`): build the body that
/// adds a follow-up variant-analysis run to a base plan. `followup_binding` is
/// the `bounds.followup` value of the compiled follow-up plan; its
/// `parentPlanDigest` must equal `base.digest()`.
///
/// Call shape:
/// ```ignore
/// let body = amendment::followup_amendment_body(&base, provider, binding, reason, now)?;
/// let signed = amendment::SignedAmendment::sign(body, key)?;
/// let (next_generation, link) = amendment::apply(&base, &signed, key)?;
/// // or in one step:
/// amendment::apply_followup(&base, provider, binding, reason, now, key)?;
/// ```
pub fn followup_amendment_body(
    base: &FrozenPlan,
    provider: AuditProvider,
    followup_binding: Value,
    reason: &str,
    issued_at_unix: u64,
) -> Result<AmendmentBody, AuditError> {
    AmendmentBody::new(
        base,
        reason,
        issued_at_unix,
        vec![AmendmentOperation::AddFollowupRun {
            provider,
            followup: followup_binding,
        }],
    )
}

pub fn apply_followup(
    base: &FrozenPlan,
    provider: AuditProvider,
    followup_binding: Value,
    reason: &str,
    issued_at_unix: u64,
    key: &[u8],
) -> Result<(FrozenPlan, AppliedAmendment), AuditError> {
    let body = followup_amendment_body(base, provider, followup_binding, reason, issued_at_unix)?;
    apply(base, &SignedAmendment::sign(body, key)?, key)
}
