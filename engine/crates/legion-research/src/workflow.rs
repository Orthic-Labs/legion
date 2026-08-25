use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

use crate::{
    budget::{BudgetAccount, BudgetLimits, BudgetSnapshot},
    error::ResearchError,
    evidence::{Claim, EvidenceKind, EvidenceLedger, EvidenceRecord},
    report::{ReportBuilder, ResearchReport},
    source::InjectedSource,
};

#[derive(Clone, Debug, Default)]
pub struct Cancellation(Arc<AtomicBool>);

impl Cancellation {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStage {
    Created,
    Discovering,
    Reading,
    Recording,
    Reporting,
    Complete,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowStatus {
    Ok,
    Partial,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRequest {
    pub schema_version: u32,
    pub query: String,
    pub source_providers: Vec<String>,
    pub max_hits_per_provider: u32,
    pub max_source_bytes: u64,
}

impl WorkflowRequest {
    pub fn validate(&self) -> Result<(), ResearchError> {
        if self.schema_version != 1 {
            return Err(ResearchError::invalid(
                "unsupported workflow request schema version",
            ));
        }
        if self.query.trim().is_empty() {
            return Err(ResearchError::invalid("query must be non-empty"));
        }
        if self.source_providers.is_empty() {
            return Err(ResearchError::invalid(
                "at least one source provider is required",
            ));
        }
        if self
            .source_providers
            .iter()
            .any(|provider| provider.trim().is_empty())
        {
            return Err(ResearchError::invalid(
                "source provider names must be non-empty",
            ));
        }
        if self.max_hits_per_provider == 0 || self.max_source_bytes == 0 {
            return Err(ResearchError::invalid(
                "hit and byte bounds must be positive",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFailure {
    pub provider: String,
    pub stage: WorkflowStage,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StageRecord {
    pub stage: WorkflowStage,
    pub completed: bool,
    pub detail: Option<String>,
}

#[derive(Clone, Debug)]
pub struct WorkflowOutcome {
    pub status: WorkflowStatus,
    pub stage: WorkflowStage,
    pub ledger: EvidenceLedger,
    pub report: ResearchReport,
    pub failures: Vec<SourceFailure>,
    pub budget: BudgetSnapshot,
    pub stages: Vec<StageRecord>,
}

pub struct ResearchWorkflow {
    clients: BTreeMap<String, InjectedSource>,
    budget: BudgetAccount,
    cancellation: Cancellation,
}

impl ResearchWorkflow {
    pub fn new(limits: BudgetLimits, deadline: Instant, cancellation: Cancellation) -> Self {
        Self {
            clients: BTreeMap::new(),
            budget: BudgetAccount::new(limits, deadline),
            cancellation,
        }
    }

    pub fn register(&mut self, client: InjectedSource) -> Result<(), ResearchError> {
        let provider = client.provider().trim().to_owned();
        if provider.is_empty() {
            return Err(ResearchError::invalid(
                "injected source provider must be non-empty",
            ));
        }
        if self.clients.insert(provider, client).is_some() {
            return Err(ResearchError::invalid("duplicate injected source provider"));
        }
        Ok(())
    }

    pub fn cancellation(&self) -> Cancellation {
        self.cancellation.clone()
    }
    pub fn budget(&self) -> BudgetSnapshot {
        self.budget.snapshot()
    }

    pub fn run(mut self, request: WorkflowRequest) -> Result<WorkflowOutcome, ResearchError> {
        request.validate()?;
        let mut stage = WorkflowStage::Created;
        let mut stages = vec![StageRecord {
            stage,
            completed: true,
            detail: None,
        }];
        let mut failures = Vec::new();
        let mut ledger = EvidenceLedger::new();

        stage = WorkflowStage::Discovering;
        stages.push(StageRecord {
            stage,
            completed: false,
            detail: None,
        });
        let providers = request.source_providers.to_vec();
        for provider_name in &providers {
            if let Err(error) = self.budget.reserve_call(&self.cancellation) {
                failures.push(SourceFailure {
                    provider: provider_name.clone(),
                    stage,
                    reason: error.to_string(),
                });
                continue;
            }
            let Some(client) = self.clients.get(provider_name).cloned() else {
                failures.push(SourceFailure {
                    provider: provider_name.clone(),
                    stage,
                    reason: "no injected source client".into(),
                });
                continue;
            };
            if let Err(error) = self
                .budget
                .reserve_cost(client.estimated_call_cost_micros(), &self.cancellation)
            {
                failures.push(SourceFailure {
                    provider: provider_name.clone(),
                    stage,
                    reason: error.to_string(),
                });
                continue;
            }
            let result = client.search(
                &request.query,
                request.max_hits_per_provider,
                self.budget.deadline(),
                &self.cancellation,
            );
            let hits = match result {
                Ok(hits) => hits,
                Err(error) => {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
            };
            stage = WorkflowStage::Reading;
            for hit in hits {
                if self.cancellation.is_cancelled() {
                    stage = WorkflowStage::Cancelled;
                    break;
                }
                if let Err(error) = hit.validate() {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
                if hit.provider != provider_name.as_str() {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: "source hit provider does not match selected provider".into(),
                    });
                    continue;
                }
                if let Err(error) = self.budget.reserve_call(&self.cancellation) {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
                if let Err(error) = self
                    .budget
                    .reserve_cost(client.estimated_call_cost_micros(), &self.cancellation)
                {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
                if let Err(error) = self.budget.reserve_source(&self.cancellation) {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
                let reserved_bytes = client.estimated_bytes(&hit).max(1);
                if reserved_bytes > request.max_source_bytes {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: "source estimate exceeds per-source byte bound".into(),
                    });
                    continue;
                }
                if let Err(error) = self
                    .budget
                    .reserve_bytes(reserved_bytes, &self.cancellation)
                {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
                let source = match client.open(&hit, self.budget.deadline(), &self.cancellation) {
                    Ok(source) => source,
                    Err(error) => {
                        failures.push(SourceFailure {
                            provider: provider_name.clone(),
                            stage,
                            reason: error.to_string(),
                        });
                        continue;
                    }
                };
                if source.byte_length > request.max_source_bytes {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: format!(
                            "source exceeds per-source byte bound: {}",
                            source.byte_length
                        ),
                    });
                    continue;
                }
                if source.byte_length > reserved_bytes {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: "source exceeded declared byte estimate".into(),
                    });
                    continue;
                }
                if let Err(error) = source.validate() {
                    failures.push(SourceFailure {
                        provider: provider_name.clone(),
                        stage,
                        reason: error.to_string(),
                    });
                    continue;
                }
                let evidence_id = format!("{}:source:{}", provider_name, ledger.records().count());
                let evidence = EvidenceRecord::from_source(
                    &source,
                    evidence_id,
                    Some(source.uri.clone()),
                    EvidenceKind::SourceAssertion,
                )?;
                ledger.add(evidence)?;
            }
            if stage == WorkflowStage::Cancelled {
                break;
            }
            stage = WorkflowStage::Discovering;
        }

        if self.cancellation.is_cancelled() {
            stage = WorkflowStage::Cancelled;
        }
        if stage != WorkflowStage::Cancelled {
            stages.iter_mut().for_each(|record| record.completed = true);
            stages.push(StageRecord {
                stage: WorkflowStage::Reading,
                completed: true,
                detail: None,
            });
            stage = WorkflowStage::Recording;
            stages.push(StageRecord {
                stage,
                completed: true,
                detail: None,
            });
            let ids: Vec<_> = ledger
                .records()
                .map(|record| record.evidence_id.clone())
                .collect();
            for (index, evidence_id) in ids.iter().enumerate() {
                let claim = Claim {
                    schema_version: 1,
                    claim_id: format!("claim-{index}"),
                    text: ledger
                        .record(evidence_id)
                        .map(|record| record.text.clone())
                        .unwrap_or_default(),
                    kind: EvidenceKind::SourceAssertion,
                    evidence_ids: vec![evidence_id.clone()],
                    uncertainty: None,
                    provenance: BTreeMap::new(),
                };
                ledger.add_claim(claim)?;
            }
            stage = WorkflowStage::Reporting;
        }
        let status = if stage == WorkflowStage::Cancelled {
            WorkflowStatus::Cancelled
        } else if ledger.records().next().is_some() && !failures.is_empty() {
            WorkflowStatus::Partial
        } else if ledger.records().next().is_some() {
            WorkflowStatus::Ok
        } else {
            WorkflowStatus::Failed
        };
        let report = ReportBuilder::from_ledger(&request.query, status, &ledger, &failures)?;
        if stage != WorkflowStage::Cancelled {
            stages.push(StageRecord {
                stage: WorkflowStage::Reporting,
                completed: true,
                detail: None,
            });
            stage = WorkflowStage::Complete;
            stages.push(StageRecord {
                stage,
                completed: true,
                detail: None,
            });
        }
        Ok(WorkflowOutcome {
            status,
            stage,
            ledger,
            report,
            failures,
            budget: self.budget.snapshot(),
            stages,
        })
    }
}
