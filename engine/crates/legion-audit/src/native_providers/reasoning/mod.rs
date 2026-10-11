//! Host-backed execution for the frozen `reasoning-contract` providers.
//!
//! The audit crate owns the portable request/result boundary, while the host
//! owns model selection, credentials, context isolation, and receipt signing.
//! No model, process, shell, or network implementation lives here.  A host
//! implementation must return a signed terminal receipt for every invocation.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use legion_contracts::{
    canonical_digest, canonical_json_bytes, ProviderId, ProviderResult, ProviderStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Sha256;

use crate::{
    error::AuditError,
    execution::{ExecutionReport, ProviderExecutor},
    inventory::{InventoryDenominator, InventoryEnvelope},
    plan::{AuditProvider, FrozenPlan, ProviderKind},
};

pub mod excerpts;
pub mod followup;
pub mod ingest;
pub mod lens_plan;
pub mod lens_schemas;
pub mod security_adjudication;
pub mod triggers;

pub use security_adjudication::{ScannerCandidate, ADJUDICATOR_PROVIDER_ID};

pub const REASONING_RECEIPT_SCHEMA_VERSION: u32 = 1;
pub const REASONING_RECEIPT_KIND: &str = "legion-reasoning-receipt";
pub const REASONING_INVOCATION_KIND: &str = "legion-reasoning-invocation";
pub const REASONING_MAC_DOMAIN: &str = "legion-reasoning-receipt:v1";

/// The reasoning providers shipped by the native registry.  Keeping the
/// allowlist explicit prevents a future host-service provider from silently
/// inheriting this protocol without an integration decision.
pub const REASONING_PROVIDER_IDS: [&str; 17] = [
    "reasoning.doc-drift",
    "reasoning.architecture",
    "reasoning.correctness",
    "reasoning.ai-slop",
    "reasoning.naming",
    "reasoning.dead-file",
    "reasoning.schema",
    "reasoning.security",
    "reasoning.minimize",
    "reasoning.performance",
    "reasoning.a11y",
    "reasoning.data-safety",
    "reasoning.resilience",
    "reasoning.platform-parity",
    "reasoning.release-readiness",
    "legacy.security.adjudication",
    "legacy.security.variant-analysis",
];

/// Fields covered by the host MAC.  The list is part of the protocol: changing
/// it without changing the MAC domain would make old receipts ambiguous.
pub const REASONING_RECEIPT_BOUND_FIELDS: [&str; 17] = [
    "schemaVersion",
    "kind",
    "receiptId",
    "requestId",
    "providerId",
    "contract",
    "planDigest",
    "planSignature",
    "repositoryId",
    "inventoryGeneration",
    "inventoryDigest",
    "denominatorDigest",
    "denominatorCount",
    "resultDigest",
    "status",
    "complete",
    "gaps",
];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReasoningInvocation {
    pub schema_version: u32,
    pub kind: String,
    pub request_id: String,
    pub provider_id: String,
    pub contract: String,
    pub plan_digest: String,
    pub plan_signature: String,
    pub repository_id: String,
    pub inventory_generation: String,
    pub inventory_digest: String,
    pub denominator_digest: String,
    pub denominator_count: u64,
    pub denominator_paths: Vec<String>,
    /// This is deliberately data-only.  The host may use it as reviewer
    /// context, but it cannot use it as an authority or completion claim.
    pub packet: Value,
}

impl ReasoningInvocation {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != REASONING_RECEIPT_SCHEMA_VERSION
            || self.kind != REASONING_INVOCATION_KIND
            || self.request_id.trim().is_empty()
            || self.provider_id.trim().is_empty()
            || self.contract.trim().is_empty()
            || self.plan_digest.trim().is_empty()
            || self.plan_signature.trim().is_empty()
            || self.repository_id.trim().is_empty()
            || self.inventory_generation.trim().is_empty()
            || self.inventory_digest.trim().is_empty()
            || self.denominator_digest.trim().is_empty()
            || self.packet.is_null()
        {
            return Err("malformed reasoning invocation envelope".into());
        }
        if self
            .denominator_paths
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            return Err("reasoning denominator paths must be sorted and unique".into());
        }
        if self.denominator_count != self.denominator_paths.len() as u64 {
            return Err("reasoning denominator count does not match paths".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReasoningReceipt {
    pub schema_version: u32,
    pub kind: String,
    pub receipt_id: String,
    pub request_id: String,
    pub provider_id: String,
    pub contract: String,
    pub plan_digest: String,
    pub plan_signature: String,
    pub repository_id: String,
    pub inventory_generation: String,
    pub inventory_digest: String,
    pub denominator_digest: String,
    pub denominator_count: u64,
    pub result_digest: String,
    pub status: ProviderStatus,
    pub complete: bool,
    pub gaps: Vec<String>,
    pub authentication: Value,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReasoningHostResponse {
    pub result: ProviderResult,
    pub receipt: ReasoningReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReasoningHostError {
    Unavailable,
    Degraded(String),
    Invocation(String),
}

impl std::fmt::Display for ReasoningHostError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => formatter.write_str("reasoning host is unavailable"),
            Self::Degraded(reason) => write!(formatter, "reasoning host is degraded: {reason}"),
            Self::Invocation(reason) => {
                write!(formatter, "reasoning host invocation failed: {reason}")
            }
        }
    }
}

impl std::error::Error for ReasoningHostError {}

/// Native host service seam.  Implementations belong to the host/application
/// composition and must not return an unsigned or locally self-certified
/// response.
pub trait ReasoningHost: Send + Sync {
    fn invoke(
        &self,
        request: &ReasoningInvocation,
    ) -> Result<ReasoningHostResponse, ReasoningHostError>;
}

#[derive(Clone)]
pub struct ReasoningProviderExecutor {
    root: PathBuf,
    host: Option<Arc<dyn ReasoningHost>>,
    verification_key: Option<Vec<u8>>,
    used_requests: Arc<Mutex<BTreeSet<String>>>,
    invocation_epoch: String,
}

// Each executor lifetime is a fresh review attempt. Clones intentionally share
// its epoch and replay guard. A new process/executor cannot reuse a previously
// signed receipt for an otherwise identical frozen plan.
fn invocation_epoch() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!(
        "{}:{}:{}",
        std::process::id(),
        now.as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

impl std::fmt::Debug for ReasoningProviderExecutor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ReasoningProviderExecutor")
            .field("root", &self.root)
            .field("host_configured", &self.host.is_some())
            .field(
                "verification_key_configured",
                &self.verification_key.is_some(),
            )
            .finish_non_exhaustive()
    }
}

impl ReasoningProviderExecutor {
    pub fn new(
        root: impl Into<PathBuf>,
        host: Arc<dyn ReasoningHost>,
        verification_key: Vec<u8>,
    ) -> Self {
        Self {
            root: root.into(),
            host: Some(host),
            verification_key: (!verification_key.is_empty()).then_some(verification_key),
            used_requests: Arc::new(Mutex::new(BTreeSet::new())),
            invocation_epoch: invocation_epoch(),
        }
    }

    pub fn unavailable(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            host: None,
            verification_key: None,
            used_requests: Arc::new(Mutex::new(BTreeSet::new())),
            invocation_epoch: invocation_epoch(),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn execute_reasoning(
        &self,
        plan: &FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        if provider.kind != ProviderKind::HostService {
            return Err(AuditError::Provider(format!(
                "provider {} is not a host-service reasoning provider",
                provider.id
            )));
        }
        if !REASONING_PROVIDER_IDS.contains(&provider.id.as_str()) {
            return Err(AuditError::Provider(format!(
                "provider {} is not in the frozen reasoning provider registry",
                provider.id
            )));
        }
        let denominator = reasoning_denominator(plan, provider, inventory)?;
        // No in-process reasoning host: the lens is `pending-host` work for the
        // invoking session (see `pending_lens_work`). This is decided before the
        // signed-invocation envelope is built, because an unsigned plan cannot
        // form one and must still report the work as pending, not as an error.
        if self.host.is_none() {
            return pending_host_result(provider, &denominator);
        }
        let mut requests = build_invocations(
            plan,
            provider,
            inventory,
            &denominator,
            &self.invocation_epoch,
            &self.root,
            None,
        )?;
        // One in-process host invocation yields one receipt, which cannot
        // prove a partitioned denominator. Multi-part work is only ever
        // `pending-host` work for the invoking session.
        if requests.len() != 1
            || requests[0]
                .packet
                .get("part")
                .is_some_and(|part| !part.is_null())
        {
            return failure_result(
                provider,
                &denominator,
                format!(
                    "reasoning-parts-unsupported-in-process:{}:{} parts",
                    provider.id,
                    requests.len()
                ),
                "host-multipart-unsupported",
            );
        }
        let request = requests.remove(0);
        request
            .validate()
            .map_err(|error| AuditError::Invalid(error.to_owned()))?;
        {
            let mut used = self.used_requests.lock().map_err(|_| {
                AuditError::Provider("reasoning replay guard is unavailable".into())
            })?;
            if !used.insert(request.request_id.clone()) {
                return Ok(failure_result(
                    provider,
                    &denominator,
                    "reasoning-replay-detected",
                    "replay-detected",
                )?);
            }
        }
        let Some(host) = &self.host else {
            return Ok(failure_result(
                provider,
                &denominator,
                "reasoning-host-unavailable",
                "host-unavailable",
            )?);
        };
        // Never spend a host invocation whose response cannot be authenticated.
        let key = self.verification_key.as_deref().ok_or_else(|| {
            AuditError::Provider("reasoning receipt verification key is unavailable".into())
        })?;
        let response = match host.invoke(&request) {
            Ok(response) => response,
            Err(error) => {
                let (gap, degradation) = match error {
                    ReasoningHostError::Unavailable => {
                        ("reasoning-host-unavailable", "host-unavailable")
                    }
                    ReasoningHostError::Degraded(reason) => {
                        return Ok(failure_result(
                            provider,
                            &denominator,
                            format!("reasoning-host-degraded:{reason}"),
                            "host-degraded",
                        )?)
                    }
                    ReasoningHostError::Invocation(reason) => {
                        return Ok(failure_result(
                            provider,
                            &denominator,
                            format!("reasoning-host-invocation-failed:{reason}"),
                            "host-invocation-failed",
                        )?)
                    }
                };
                return Ok(failure_result(provider, &denominator, gap, degradation)?);
            }
        };
        verify_response(&request, &denominator, &response, key)
            .map_err(|error| AuditError::Provider(format!("reasoning receipt rejected: {error}")))
    }
}

impl ProviderExecutor for ReasoningProviderExecutor {
    fn execute(
        &self,
        _provider: &AuditProvider,
        _inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        Err(AuditError::Provider(
            "reasoning provider requires frozen plan binding".into(),
        ))
    }

    fn execute_bound(
        &self,
        plan: &FrozenPlan,
        provider: &AuditProvider,
        inventory: &InventoryEnvelope,
    ) -> Result<ProviderResult, AuditError> {
        self.execute_reasoning(plan, provider, inventory)
    }
}

fn reasoning_denominator(
    plan: &FrozenPlan,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
) -> Result<InventoryDenominator, AuditError> {
    let selector = provider.configuration.get("selector").ok_or_else(|| {
        AuditError::Invalid(format!("provider {} is missing selector", provider.id))
    })?;
    let candidates = plan
        .providers()
        .iter()
        .filter(|candidate| candidate.role == "candidate-generator")
        .filter_map(|candidate| candidate.configuration.get("selector"))
        .map(|selector| inventory.denominator_entries(selector))
        .collect::<Result<Vec<_>, _>>()?;
    let denominator = inventory.denominator_entries_with_candidates(selector, &candidates)?;
    let expected_digest = provider
        .configuration
        .get("denominatorDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AuditError::Invalid(format!(
                "provider {} is missing denominator digest",
                provider.id
            ))
        })?;
    let expected_count = provider
        .configuration
        .get("denominatorCount")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            AuditError::Invalid(format!(
                "provider {} is missing denominator count",
                provider.id
            ))
        })?;
    if denominator.digest != expected_digest || denominator.entries.len() as u64 != expected_count {
        return Err(AuditError::SourceDrift(format!(
            "provider {} denominator changed after plan freeze",
            provider.id
        )));
    }
    Ok(denominator)
}

/// Provider-level ceiling on packet parts: `bounds.maxReasoningParts` from the
/// frozen provider, else `excerpts::DEFAULT_MAX_PARTS`.
fn part_ceiling(provider: &AuditProvider) -> usize {
    provider
        .bounds
        .get("maxReasoningParts")
        .and_then(Value::as_u64)
        .map(|value| value.clamp(1, 100_000) as usize)
        .unwrap_or(excerpts::DEFAULT_MAX_PARTS)
}

/// Builds every packet part for one provider. The frozen denominator is
/// partitioned deterministically (stable path order) so each denominator path
/// is homed in exactly one part; a provider whose denominator fits one part
/// yields exactly one invocation with the pre-continuation packet shape (no
/// `part` key). Every part carries the full frozen denominator in its
/// envelope, so the plan digest binding and receipt denominator checks are
/// identical for every part.
fn build_invocations(
    plan: &FrozenPlan,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
    denominator: &InventoryDenominator,
    invocation_epoch: &str,
    root: &Path,
    scanner_candidates: Option<&[ScannerCandidate]>,
) -> Result<Vec<ReasoningInvocation>, AuditError> {
    let contract = provider
        .configuration
        .get("runner")
        .and_then(Value::as_object)
        .and_then(|runner| runner.get("contract"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            AuditError::Invalid(format!(
                "provider {} is missing reasoning contract",
                provider.id
            ))
        })?;
    let paths = denominator
        .entries
        .iter()
        .map(|entry| entry.path.clone())
        .collect::<Vec<_>>();
    // Per-lens work-packet planning (question, applicability trigger, excerpt
    // scoping, report schema, model tier, verify-pass requirement, ponytail
    // tags, cues) per skills/audit/references/{lens-routing,manual,
    // ponytail-lens,lens-cues}.md. `None` only for
    // `legacy.security.adjudication`, which carries its own independent
    // packet shape via `security_adjudication.rs`.
    let lens_plan = lens_plan::lens_plan_packet_value(&provider.id);
    let lens_id = lens_plan::lens_id_for_provider(&provider.id);
    // Scoped excerpts: RAW (bounded, file:line anchored, secret-redacted)
    // for security/schema/correctness/performance/minimize/doc-drift/architecture/ai-slop,
    // SKELETON (signatures/declarations, no bodies) for
    // naming/dead-file, per lens-routing.md's
    // "Excerpt compression" section. `None` only for
    // `legacy.security.adjudication`, which is not lens-routed here.
    let ceiling = part_ceiling(provider);
    let partition = lens_plan::lens_plan_excerpt_mode(&provider.id)
        .map(|mode| excerpts::partition_excerpts(root, &paths, mode, ceiling));
    // Scanner candidates for the adjudicator: one verdict per candidate.
    // `null` means the caller did not supply scanner results (unknown, not
    // "none"); ingest then refuses to treat the lens as covered.
    let candidates_value = (provider.id == ADJUDICATOR_PROVIDER_ID)
        .then(|| scanner_candidates.map(|candidates| json!(candidates)))
        .flatten();
    // Conditional-lens trigger evidence: the actual local check over this
    // provider's denominator, not just the trigger description carried in
    // `lensPlan`. `None` for always-applicable and unowned lenses.
    let trigger_evidence = lens_id
        .and_then(|lens| triggers::evaluate_trigger(root, lens, &paths))
        .map(|evaluation| {
            json!({
                "fired": evaluation.fired,
                "reason": evaluation.reason,
                "evidencePaths": evaluation.evidence_paths,
            })
        });
    // Full report-schema body for the lens's finding shape (id, lens,
    // severity, confidence, file:line evidence, failure scenario, action,
    // verify status, plus lens-specific extras), matching the id carried
    // in `lensPlan.reportSchema`.
    let report_schema_body = lens_id.and_then(lens_schemas::lens_report_schema);
    let semantic_contract = lens_id.and_then(lens_plan::semantic_review_contract);
    let change_risk_contract = lens_id.and_then(lens_plan::change_risk_contract);
    let projection = serde_json::to_value(inventory)
        .map_err(|error| AuditError::Invalid(format!("inventory projection failed: {error}")))?;
    let review_context = provider
        .configuration
        .get("reasoning")
        .and_then(Value::as_object)
        .and_then(|reasoning| reasoning.get("reviewContext"))
        .cloned()
        .unwrap_or(Value::Null);
    let part_slots: Vec<Option<&excerpts::ExcerptPart>> = match &partition {
        Some(partition) => partition.parts.iter().map(Some).collect(),
        None => vec![None],
    };
    let emitted_parts = part_slots.len();
    let required_parts = partition
        .as_ref()
        .map_or(1, |partition| partition.required_parts);
    let multi_part = required_parts > 1;
    let over_ceiling = partition
        .as_ref()
        .filter(|partition| partition.required_parts > partition.parts.len())
        .map(|partition| {
            json!({
                "requiredParts": partition.required_parts,
                "ceiling": ceiling,
                "unscheduledPathCount": partition.unscheduled_paths.len(),
                "unscheduledPaths": partition.unscheduled_paths,
            })
        })
        .unwrap_or(Value::Null);
    // Chunks of files continued from an earlier part, per part.
    let mut invocations = Vec::with_capacity(emitted_parts);
    for (index, part) in part_slots.into_iter().enumerate() {
        let number = index + 1;
        // What this packet actually carries, reconciled against the
        // denominator. Ingest derives examined coverage from this, never
        // from an attestation.
        let excerpt_coverage =
            excerpt_coverage_value(&provider.id, part, scanner_candidates, paths.len());
        let excerpts_value =
            part.map(|part| serde_json::to_value(&part.excerpts).unwrap_or(Value::Null));
        let part_meta = match (multi_part, part) {
            (true, Some(part)) => {
                let continued = part
                    .excerpts
                    .iter()
                    .filter(|excerpt| excerpt.chunk > 1)
                    .map(|excerpt| excerpt.path.clone())
                    .collect::<BTreeSet<_>>();
                json!({
                    "number": number,
                    "total": emitted_parts,
                    "requiredParts": required_parts,
                    "paths": part.paths,
                    "pathsDigest": canonical_digest(&part.paths)
                        .map_err(|error| AuditError::Invalid(error.to_string()))?,
                    "continuedPaths": continued,
                    "overCeiling": over_ceiling,
                    "indexFile": format!("{}.index.json", provider.id),
                    "findingIdPrefix": format!("p{number:04}-"),
                    "note": "this packet is one part of a partitioned denominator; finding ids must be unique across parts (use findingIdPrefix); the provider completes only when every part is ingested",
                })
            }
            _ => Value::Null,
        };
        let mut packet = json!({
            "schemaVersion": 1,
            "kind": "legion-reasoning-packet",
            "provider": provider.id,
            "contract": contract,
            "binding": {
                "repositoryId": inventory.repository_id,
                "inventoryGeneration": inventory.generation,
                "inventoryDigest": inventory.digest,
                "planDigest": plan.digest(),
                "planSignature": plan.signature(),
                "denominatorDigest": denominator.digest,
                "denominatorCount": denominator.entries.len(),
            },
            "lensPlan": lens_plan,
            "excerpts": excerpts_value,
            "excerptCoverage": excerpt_coverage,
            "scannerCandidates": candidates_value,
            "triggerEvidence": trigger_evidence,
            "reportSchemaBody": report_schema_body,
            "semanticReviewContract": semantic_contract,
            "changeRiskContract": change_risk_contract,
            "reviewContext": review_context,
            // Later parts reference part 1 for the inventory projection
            // rather than repeating it in every part.
            "projection": if number == 1 { projection.clone() } else { Value::Null },
            "artifactIds": [],
        });
        if multi_part {
            if let Some(object) = packet.as_object_mut() {
                object.insert("part".into(), part_meta);
            }
        }
        let identity = json!({
            "invocationEpoch": invocation_epoch,
            "packetDigest": canonical_digest(&packet).map_err(|error| AuditError::Invalid(error.to_string()))?,
            "providerId": provider.id,
            "contract": contract,
            "planDigest": plan.digest(),
            "planSignature": plan.signature(),
            "repositoryId": inventory.repository_id,
            "inventoryGeneration": inventory.generation,
            "inventoryDigest": inventory.digest,
            "denominatorDigest": denominator.digest,
            "denominatorCount": denominator.entries.len(),
            "denominatorPaths": paths,
        });
        let request_id =
            canonical_digest(&identity).map_err(|error| AuditError::Invalid(error.to_string()))?;
        invocations.push(ReasoningInvocation {
            schema_version: REASONING_RECEIPT_SCHEMA_VERSION,
            kind: REASONING_INVOCATION_KIND.into(),
            request_id,
            provider_id: provider.id.clone(),
            contract: contract.into(),
            plan_digest: plan.digest().into(),
            plan_signature: plan.signature().unwrap_or_default().into(),
            repository_id: inventory.repository_id.clone(),
            inventory_generation: inventory.generation.clone(),
            inventory_digest: inventory.digest.clone(),
            denominator_digest: denominator.digest.clone(),
            denominator_count: denominator.entries.len() as u64,
            denominator_paths: paths.clone(),
            packet,
        });
    }
    Ok(invocations)
}

/// Coverage the packet itself can prove. `examinedPaths` lists denominator
/// paths whose every chunk is present in this packet; `chunkedPaths` lists
/// the chunks of paths only partly present here (their remaining chunks are
/// in other parts, and the path counts as examined only once every chunk is
/// ingested); `omittedPaths` have no excerpt at all (named reason).
/// `truncatedPaths` is retained for consumers and is always empty: nothing is
/// truncated any more.
fn excerpt_coverage_value(
    provider_id: &str,
    part: Option<&excerpts::ExcerptPart>,
    scanner_candidates: Option<&[ScannerCandidate]>,
    denominator_count: usize,
) -> Value {
    if let Some(part) = part {
        let mut present: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for excerpt in &part.excerpts {
            let entry = present
                .entry(excerpt.path.as_str())
                .or_insert((0, excerpt.chunks));
            entry.0 += 1;
        }
        let mut examined = Vec::new();
        let mut seen = BTreeSet::new();
        for excerpt in &part.excerpts {
            let (count, chunks) = present[excerpt.path.as_str()];
            if count == chunks && seen.insert(excerpt.path.as_str()) {
                examined.push(excerpt.path.as_str());
            }
        }
        let chunked = part
            .excerpts
            .iter()
            .filter(|excerpt| {
                let (count, chunks) = present[excerpt.path.as_str()];
                count != chunks
            })
            .map(|excerpt| {
                json!({
                    "path": excerpt.path,
                    "chunk": excerpt.chunk,
                    "chunks": excerpt.chunks,
                    "startLine": excerpt.start_line,
                    "endLine": excerpt.end_line,
                })
            })
            .collect::<Vec<_>>();
        return json!({
            "basis": "bounded-excerpts",
            "denominatorCount": denominator_count,
            "examinedPaths": examined,
            "truncatedPaths": Vec::<&str>::new(),
            "chunkedPaths": chunked,
            "omittedPaths": part.omitted,
        });
    }
    if provider_id == ADJUDICATOR_PROVIDER_ID {
        return json!({
            "basis": "candidate-verdicts",
            "denominatorCount": denominator_count,
            "candidateCount": scanner_candidates.map(<[ScannerCandidate]>::len),
        });
    }
    Value::Null
}

pub(crate) fn verify_response(
    request: &ReasoningInvocation,
    denominator: &InventoryDenominator,
    response: &ReasoningHostResponse,
    key: &[u8],
) -> Result<ProviderResult, String> {
    request.validate()?;
    response
        .result
        .validate()
        .map_err(|error| error.to_string())?;
    if response.result.provider.to_string() != request.provider_id {
        return Err("host result provider identity mismatch".into());
    }
    if response.result.details.contains_key("executionReceipt") {
        return Err("host result must not contain an unbound execution receipt".into());
    }
    let result_digest =
        canonical_digest(&response.result_without_receipt()).map_err(|error| error.to_string())?;
    let receipt = &response.receipt;
    if receipt.schema_version != REASONING_RECEIPT_SCHEMA_VERSION
        || receipt.kind != REASONING_RECEIPT_KIND
        || receipt.receipt_id.trim().is_empty()
        || receipt.request_id != request.request_id
        || receipt.provider_id != request.provider_id
        || receipt.contract != request.contract
        || receipt.plan_digest != request.plan_digest
        || receipt.plan_signature != request.plan_signature
        || receipt.repository_id != request.repository_id
        || receipt.inventory_generation != request.inventory_generation
        || receipt.inventory_digest != request.inventory_digest
        || receipt.denominator_digest != request.denominator_digest
        || receipt.denominator_count != request.denominator_count
        || receipt.result_digest != result_digest
        || receipt.status != response.result.status
        || receipt.complete != response.result.complete
        || receipt.gaps != response.result.coverage_gaps
    {
        return Err(
            "reasoning receipt is not bound to request, plan, inventory, denominator, or result"
                .into(),
        );
    }
    if receipt.denominator_count != denominator.entries.len() as u64 {
        return Err("reasoning receipt denominator count mismatch".into());
    }
    verify_authenticated_receipt(receipt, key)?;
    // Reconciliation-path schema validation: when a host reports lens
    // findings under `details.lensFindings`, every finding must satisfy the
    // owning lens's full report schema (lens_schemas.rs) before it is
    // accepted. A lens with no registered schema, or a result that carries
    // no `lensFindings` at all (e.g. `legacy.security.adjudication`, which
    // has its own independent packet/result shape), is left unvalidated
    // here rather than rejected.
    if let Some(lens) = lens_plan::lens_id_for_provider(&request.provider_id) {
        if let Some(findings) = response.result.details.get("lensFindings") {
            let findings = findings.as_array().cloned().ok_or_else(|| {
                "reasoning result details.lensFindings must be an array".to_owned()
            })?;
            lens_schemas::validate_lens_output(lens, &findings).map_err(|errors| {
                let joined = errors
                    .iter()
                    .map(|error| format!("{}: {}", error.field, error.reason))
                    .collect::<Vec<_>>()
                    .join("; ");
                format!(
                    "reasoning result for lens {lens} failed report-schema validation: {joined}"
                )
            })?;
        }
        let details = serde_json::to_value(&response.result.details)
            .map_err(|error| format!("reasoning result details serialization failed: {error}"))?;
        if details
            .get("semanticReview")
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str)
            == Some("not-applicable")
            && request
                .packet
                .get("reviewContext")
                .and_then(|value| value.get("mode"))
                .and_then(Value::as_str)
                != Some("whole-repo")
        {
            return Err("semantic non-applicability requires frozen whole-repo context".into());
        }
        if let Some(detail_findings) = details.get("lensFindings").and_then(Value::as_array) {
            let top_level_ids = response
                .result
                .findings
                .iter()
                .filter_map(|finding| serde_json::to_value(finding).ok())
                .filter_map(|finding| finding.get("id").and_then(Value::as_str).map(str::to_owned))
                .collect::<BTreeSet<_>>();
            for (index, finding) in detail_findings.iter().enumerate() {
                if let Some(id) = finding.get("id").and_then(Value::as_str) {
                    if !top_level_ids.contains(id) {
                        return Err(format!("reasoning result for lens {lens} detail finding {index} is absent from top-level findings"));
                    }
                }
            }
        }
        lens_schemas::validate_semantic_review(lens, &details).map_err(|errors| {
            let joined = errors
                .iter()
                .map(|error| format!("{}: {}", error.field, error.reason))
                .collect::<Vec<_>>()
                .join("; ");
            format!("reasoning result for lens {lens} failed semantic-review validation: {joined}")
        })?;
        lens_schemas::validate_change_risk(lens, &details).map_err(|errors| {
            let joined = errors
                .iter()
                .map(|error| format!("{}: {}", error.field, error.reason))
                .collect::<Vec<_>>()
                .join("; ");
            format!("reasoning result for lens {lens} failed change-risk validation: {joined}")
        })?;
    }
    let mut result = response.result.clone();
    result.details.insert(
        "executionReceipt".into(),
        serde_json::to_value(receipt).map_err(|error| error.to_string())?,
    );
    Ok(result)
}

impl ReasoningHostResponse {
    fn result_without_receipt(&self) -> ProviderResult {
        let mut result = self.result.clone();
        result.details.remove("executionReceipt");
        result
    }
}

/// The exact message the receipt MAC covers: the bound fields of the receipt
/// under the protocol domain. Shared by signing and verification.
fn receipt_mac_message(receipt: &ReasoningReceipt) -> Result<Value, String> {
    let subject = serde_json::to_value(receipt).map_err(|error| error.to_string())?;
    let subject = subject
        .as_object()
        .ok_or_else(|| "reasoning receipt is not an object".to_owned())?;
    let mut bound = serde_json::Map::new();
    for field in REASONING_RECEIPT_BOUND_FIELDS {
        bound.insert(
            field.into(),
            subject
                .get(field)
                .cloned()
                .ok_or_else(|| format!("reasoning receipt missing {field}"))?,
        );
    }
    Ok(json!({
        "alg": "HMAC-SHA256",
        "boundFields": REASONING_RECEIPT_BOUND_FIELDS,
        "macDomain": REASONING_MAC_DOMAIN,
        "subject": bound,
    }))
}

/// Produces the `authentication` object for a receipt, MACed under `key`.
/// Used by the trusted CLI ingest path, where the CLI process is the host and
/// `key` is the per-run epoch key. `epoch_digest` is recorded for audit; it is
/// not part of the MAC message (the key itself binds the receipt to the epoch).
pub(crate) fn authenticate_receipt(
    receipt: &ReasoningReceipt,
    key: &[u8],
    host: &str,
    epoch_digest: &str,
) -> Result<Value, String> {
    if key.is_empty() {
        return Err("reasoning receipt signing key is empty".into());
    }
    let message = receipt_mac_message(receipt)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| "reasoning receipt key is invalid".to_owned())?;
    mac.update(&canonical_json_bytes(&message).map_err(|error| error.to_string())?);
    let bound_digest = canonical_digest(&REASONING_RECEIPT_BOUND_FIELDS.to_vec())
        .map_err(|error| error.to_string())?;
    Ok(json!({
        "alg": "HMAC-SHA256",
        "macDomain": REASONING_MAC_DOMAIN,
        "boundFieldsDigest": bound_digest,
        "mac": hex::encode(mac.finalize().into_bytes()),
        "host": host,
        "epochDigest": epoch_digest,
    }))
}

pub fn verify_authenticated_receipt(receipt: &ReasoningReceipt, key: &[u8]) -> Result<(), String> {
    if key.is_empty() {
        return Err("reasoning receipt verification key is empty".into());
    }
    let auth = receipt
        .authentication
        .as_object()
        .ok_or_else(|| "reasoning receipt authentication is missing".to_owned())?;
    if auth.get("alg").and_then(Value::as_str) != Some("HMAC-SHA256")
        || auth.get("macDomain").and_then(Value::as_str) != Some(REASONING_MAC_DOMAIN)
    {
        return Err("reasoning receipt authentication algorithm or domain is invalid".into());
    }
    let presented = auth
        .get("mac")
        .and_then(Value::as_str)
        .ok_or_else(|| "reasoning receipt MAC is missing".to_owned())?;
    let bound_digest = canonical_digest(&REASONING_RECEIPT_BOUND_FIELDS.to_vec())
        .map_err(|error| error.to_string())?;
    if auth.get("boundFieldsDigest").and_then(Value::as_str) != Some(bound_digest.as_str()) {
        return Err("reasoning receipt bound-field list does not match".into());
    }
    let message = receipt_mac_message(receipt)?;
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| "reasoning receipt key is invalid".to_owned())?;
    mac.update(&canonical_json_bytes(&message).map_err(|error| error.to_string())?);
    let presented =
        hex::decode(presented).map_err(|_| "reasoning receipt MAC is not hex".to_owned())?;
    mac.verify_slice(&presented)
        .map_err(|_| "reasoning receipt MAC verification failed".to_owned())
}

/// Result for a reasoning provider no in-process host can execute. The work is
/// not failed: it is `pending-host`, to be run by the invoking session from the
/// emitted lens packet. It is never complete and never clean.
fn pending_host_result(
    provider: &AuditProvider,
    denominator: &InventoryDenominator,
) -> Result<ProviderResult, AuditError> {
    let mut result = failure_result(
        provider,
        denominator,
        "reasoning-host-unavailable",
        "host-unavailable",
    )?;
    result.status = ProviderStatus::Partial;
    result.degradation.push("pending-host".into());
    result.details.insert(
        "reasoningHostState".into(),
        Value::String("pending-host".into()),
    );
    result.details.insert(
        "workItem".into(),
        json!({
            "status": "pending-host",
            "provider": provider.id,
            "lensIds": provider.lens_ids,
            "denominatorCount": denominator.entries.len(),
        }),
    );
    Ok(result)
}

/// One lens packet awaiting execution by the host session.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingLensWork {
    pub provider_id: String,
    pub lens_ids: Vec<String>,
    pub status: String,
    pub request: ReasoningInvocation,
}

/// Position of a packet within a partitioned denominator.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct LensPartRef {
    /// 1-based part number.
    pub number: u32,
    /// Parts emitted for the provider.
    pub total: u32,
}

impl PendingLensWork {
    /// `Some` when this packet is one part of a multi-part provider
    /// (`packet.part`); `None` for the single unnumbered packet.
    pub fn part(&self) -> Option<LensPartRef> {
        let part = self
            .request
            .packet
            .get("part")
            .filter(|part| !part.is_null())?;
        Some(LensPartRef {
            number: u32::try_from(part.get("number")?.as_u64()?).ok()?,
            total: u32::try_from(part.get("total")?.as_u64()?).ok()?,
        })
    }

    /// File stem under `lens-packets/`: `<provider>` for a single packet,
    /// `<provider>.part-NNNN` for a numbered part.
    pub fn packet_file_stem(&self) -> String {
        match self.part() {
            Some(part) => format!("{}.part-{:04}", self.provider_id, part.number),
            None => self.provider_id.clone(),
        }
    }

    /// `<packet_file_stem>.json`.
    pub fn packet_file_name(&self) -> String {
        format!("{}.json", self.packet_file_stem())
    }
}

/// Builds the `pending-host` work items for every reasoning provider of the
/// plan that applies to the repository: each carries the full invocation
/// packet (lens plan, scoped excerpts, trigger evidence, report schema) that a
/// subagent executes. Works for signed and unsigned plans; the packet binds the
/// plan digest and, when present, the signature.
pub fn pending_lens_work(
    root: &Path,
    plan: &FrozenPlan,
    inventory: &InventoryEnvelope,
) -> Result<Vec<PendingLensWork>, AuditError> {
    pending_lens_work_with_candidates(root, plan, inventory, None)
}

/// Scanner candidates raised by the plan's candidate-generator providers in
/// `execution`, for the security adjudicator's packet.
pub fn scanner_candidates_from_execution(
    root: &Path,
    plan: &FrozenPlan,
    execution: &ExecutionReport,
) -> Vec<ScannerCandidate> {
    let generators = plan
        .providers()
        .iter()
        .filter(|provider| provider.role == "candidate-generator")
        .map(|provider| provider.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut candidates = execution
        .results
        .iter()
        .filter(|entry| generators.contains(entry.provider.as_str()))
        .flat_map(|entry| {
            security_adjudication::scanner_candidates(root, &entry.provider, &entry.result)
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    candidates.dedup_by(|left, right| left.finding_id == right.finding_id);
    candidates
}

/// `pending_lens_work` plus the scanner candidates the security adjudicator
/// must close (`None` when scanner results are unavailable to the caller).
pub fn pending_lens_work_with_candidates(
    root: &Path,
    plan: &FrozenPlan,
    inventory: &InventoryEnvelope,
    scanner_candidates: Option<&[ScannerCandidate]>,
) -> Result<Vec<PendingLensWork>, AuditError> {
    let mut work = Vec::new();
    for provider in plan.providers() {
        if provider.kind != ProviderKind::HostService
            || !REASONING_PROVIDER_IDS.contains(&provider.id.as_str())
            || provider.not_applicable()
        {
            continue;
        }
        let denominator = reasoning_denominator(plan, provider, inventory)?;
        // One work item per packet part (a single item, with the unnumbered
        // packet shape, when the denominator fits one part).
        for request in build_invocations(
            plan,
            provider,
            inventory,
            &denominator,
            "pending-host",
            root,
            scanner_candidates,
        )? {
            work.push(PendingLensWork {
                provider_id: provider.id.clone(),
                lens_ids: provider.lens_ids.clone(),
                status: "pending-host".into(),
                request,
            });
        }
    }
    Ok(work)
}

fn failure_result(
    provider: &AuditProvider,
    denominator: &InventoryDenominator,
    gap: impl Into<String>,
    degradation: &str,
) -> Result<ProviderResult, AuditError> {
    let gap = gap.into();
    let mut details = BTreeMap::new();
    details.insert(
        "reasoningHostState".into(),
        Value::String(degradation.into()),
    );
    details.insert(
        "selector".into(),
        provider
            .configuration
            .get("selector")
            .cloned()
            .unwrap_or(Value::Null),
    );
    Ok(ProviderResult {
        schema_version: 1,
        provider: ProviderId::new(&provider.id).map_err(AuditError::from)?,
        applicable: true,
        required: provider.required,
        status: ProviderStatus::Failed,
        complete: false,
        coverage: Some(legion_contracts::Coverage {
            denominator_digest: denominator.digest.clone(),
            expected: denominator.entries.len() as u64,
            examined: 0,
            gaps: vec![gap.clone()],
        }),
        findings: Vec::new(),
        coverage_gaps: vec![gap],
        degradation: vec![degradation.into()],
        details,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_inventory_is_exactly_seventeen_entries() {
        assert_eq!(REASONING_PROVIDER_IDS.len(), 17);
        let unique = REASONING_PROVIDER_IDS.iter().collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), REASONING_PROVIDER_IDS.len());
    }

    #[test]
    fn missing_host_is_a_terminal_incomplete_result() {
        let executor = ReasoningProviderExecutor::unavailable(".");
        let result = failure_result(
            &AuditProvider {
                id: "reasoning.architecture".into(),
                version: "1".into(),
                role: "adjudicator".into(),
                phase: "judgment".into(),
                lens_ids: vec!["architecture".into()],
                dependencies: Vec::new(),
                kind: ProviderKind::HostService,
                configuration: BTreeMap::new(),
                bounds: BTreeMap::new(),
                clean_claim: "evidence-only".into(),
                benchmark_status: "unproven".into(),
                benchmark_required_for_clean_claim: true,
                qualification_digest: None,
                required: true,
            },
            &InventoryDenominator {
                entries: Vec::new(),
                digest: "sha256:empty".into(),
            },
            "reasoning-host-unavailable",
            "host-unavailable",
        )
        .unwrap();
        assert!(!result.complete);
        assert_eq!(result.status, ProviderStatus::Failed);
        let _ = executor;
    }
}
