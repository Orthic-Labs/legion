use std::sync::Arc;

use legion_contracts::{
    AgentId, EffectRequest, InvocationGrant, InvocationId, ProviderResult, TaskSpec,
};
use legion_provider_sdk::ProviderRegistry;

use crate::{
    error::RuntimeError,
    plan::{compile_plan, FrozenPlan},
    route::{select_route, RouteCandidate, SelectedRoute},
    scheduler::{Scheduler, SchedulerOutput, SchedulerPolicy},
    task::{validate_task, ContextRequest},
    AgentProfile,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateEvidence {
    pub provider: legion_contracts::ProviderId,
    pub result: ProviderResult,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Adjudication {
    pub candidates: Vec<CandidateEvidence>,
    pub complete: bool,
    pub gaps: Vec<String>,
}

/// Adjudication is deliberately observation-only: it sorts and summarizes results,
/// but never edits provider facts.
pub fn adjudicate(output: &SchedulerOutput) -> Adjudication {
    let mut candidates: Vec<_> = output
        .results
        .iter()
        .map(|(provider, result)| CandidateEvidence {
            provider: provider.clone(),
            result: result.clone(),
        })
        .collect();
    candidates.sort_by(|left, right| left.provider.cmp(&right.provider));
    let mut gaps = Vec::new();
    for receipt in &output.receipts {
        gaps.extend(receipt.gaps.iter().cloned());
    }
    gaps.sort();
    gaps.dedup();
    Adjudication {
        complete: !candidates.is_empty()
            && gaps.is_empty()
            && candidates.iter().all(|item| item.result.complete),
        candidates,
        gaps,
    }
}

pub trait EffectPolicy: Send + Sync {
    fn authorize(&self, request: &EffectRequest) -> Result<(), RuntimeError>;
}

#[derive(Clone)]
pub struct Invocation {
    pub invocation_id: InvocationId,
    pub task: TaskSpec,
    pub grant: InvocationGrant,
    pub context: ContextRequest,
    pub routes: Vec<RouteCandidate>,
}

#[derive(Clone, Debug)]
pub struct EngineOutcome {
    pub route: SelectedRoute,
    pub plan: FrozenPlan,
    pub scheduled: SchedulerOutput,
    pub adjudication: Adjudication,
}

pub struct LegionEngine {
    profile: AgentProfile,
    registry: Arc<ProviderRegistry>,
    policy: Option<Arc<dyn EffectPolicy>>,
}

impl LegionEngine {
    pub fn new(profile: AgentProfile, registry: Arc<ProviderRegistry>) -> Self {
        Self {
            profile,
            registry,
            policy: None,
        }
    }
    pub fn with_policy(mut self, policy: Arc<dyn EffectPolicy>) -> Self {
        self.policy = Some(policy);
        self
    }
    pub fn profile(&self) -> &AgentProfile {
        &self.profile
    }
    pub fn registry(&self) -> &ProviderRegistry {
        &self.registry
    }

    pub async fn execute(&self, invocation: Invocation) -> Result<EngineOutcome, RuntimeError> {
        let grant = self.profile.authorize(invocation.grant)?;
        validate_task(&invocation.task, &grant)?;
        invocation.context.ensure_available()?;
        let route = select_route(&invocation.routes, self.profile.definition(), &grant)?;
        let plan = compile_plan(&invocation.task, &self.registry, &route)?;
        let policy = SchedulerPolicy::new(
            invocation.context.deadline,
            invocation.context.cancellation.clone(),
            invocation.context.generation,
            invocation.context.repository.to_string(),
        );
        let scheduled = Scheduler::new(
            &self.registry,
            &plan,
            &invocation.context,
            &invocation.task,
            grant,
            invocation.invocation_id,
            policy,
        )
        .run()
        .await?;
        for receipt in &scheduled.receipts {
            receipt.validate().map_err(RuntimeError::from)?;
        }
        let adjudication = adjudicate(&scheduled);
        Ok(EngineOutcome {
            route,
            plan,
            scheduled,
            adjudication,
        })
    }

    pub async fn run(&self, invocation: Invocation) -> Result<EngineOutcome, RuntimeError> {
        self.execute(invocation).await
    }

    pub fn authorize_effect(&self, request: &EffectRequest) -> Result<(), RuntimeError> {
        self.policy
            .as_ref()
            .ok_or_else(|| RuntimeError::Policy("no injected effect policy".into()))?
            .authorize(request)
    }

    pub fn can_escalate(
        &self,
        target: &AgentId,
        grant: &crate::escalation::EscalationGrant,
    ) -> Result<(), RuntimeError> {
        crate::escalation::validate_target(self.profile.definition(), target, grant)
    }

    pub fn policy(&self) -> Option<&Arc<dyn EffectPolicy>> {
        self.policy.as_ref()
    }
}
