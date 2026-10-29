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

pub mod candidate_routing;
pub mod coverage_plan;
#[cfg(test)]
mod coverage_regressions;
pub mod excerpts;
pub mod followup;
pub mod ingest;
pub mod lens_plan;
pub mod lens_schemas;
mod packet_context;
pub mod pattern_cards;
pub mod security_adjudication;
pub mod triggers;

pub use candidate_routing::pending_review_gaps as pending_candidate_review_gaps;
pub use security_adjudication::{ScannerCandidate, ADJUDICATOR_PROVIDER_ID};

/// Run-relative path of the inventory artifact that lens packets reference
/// (`inventoryRef.snapshotRef`); the CLI writes it next to `lens-packets/`.
pub const INVENTORY_SNAPSHOT_FILE: &str = "inventory.json";

/// Run-relative file that holds one lens's findings-promotion lists
/// (`promotionRef`). Packets carry only counts and the digest, never the lists:
/// the lists would otherwise be paid once per packet part by the dispatch
/// estimator. `write_lens_packets` writes it next to `lens-packets/`.
pub fn promotion_file_name(provider_id: &str) -> String {
    format!("promotion.{provider_id}.json")
}

/// Digest binding a promotion to the scanner candidates it came from.
fn promotion_digest_of(
    promoted: &[String],
    displaced: &[String],
    unpromoted: &[String],
    findings: &Value,
) -> Option<String> {
    canonical_digest(&json!({
        "promoted": promoted,
        "displaced": displaced,
        "unpromoted": unpromoted,
        "findings": findings,
    }))
    .ok()
}

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
    pub(crate) fn part(&self) -> Option<LensPartRef> {
        let part = self.packet.get("part").filter(|part| !part.is_null())?;
        Some(LensPartRef {
            number: u32::try_from(part.get("number")?.as_u64()?).ok()?,
            total: u32::try_from(part.get("total")?.as_u64()?).ok()?,
        })
    }

    /// Canonical run artifact holding this complete logical invocation.
    pub(crate) fn packet_file_name(&self) -> String {
        match self.part() {
            Some(part) => format!("{}.part-{:04}.json", self.provider_id, part.number),
            None => format!("{}.json", self.provider_id),
        }
    }

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
        let source = excerpts::SourceReader::new(&self.root)?;
        let mut sizer = crate::review_runtime::InitialRequestSizer::default();
        let materialized = sizer.with_operation(|sizer| {
            if let Some(admission) = source.admission() {
                sizer.use_admission(admission)?;
            }
            build_invocations(
                plan,
                provider,
                inventory,
                &denominator,
                &self.invocation_epoch,
                &source,
                sizer,
                None,
                false,
            )
        });
        source.revalidate()?;
        let (mut requests, _) = materialized?;
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
                        )?);
                    }
                    ReasoningHostError::Invocation(reason) => {
                        return Ok(failure_result(
                            provider,
                            &denominator,
                            format!("reasoning-host-invocation-failed:{reason}"),
                            "host-invocation-failed",
                        )?);
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

/// `reviewContext.changedHunks` of a diff-scoped audit
/// (`{path: [[start, end], ...]}`), empty for a whole-repository audit.
fn changed_hunks_from_review_context(provider: &AuditProvider) -> excerpts::ChangedHunks {
    let mut hunks = excerpts::ChangedHunks::new();
    let context = provider
        .configuration
        .get("reasoning")
        .and_then(Value::as_object)
        .and_then(|reasoning| reasoning.get("reviewContext"));
    if context
        .and_then(|value| value.get("mode"))
        .and_then(Value::as_str)
        != Some("diff")
    {
        return hunks;
    }
    let Some(map) = context
        .and_then(|value| value.get("changedHunks"))
        .and_then(Value::as_object)
    else {
        return hunks;
    };
    for (path, ranges) in map {
        let parsed = ranges
            .as_array()
            .map(|ranges| {
                ranges
                    .iter()
                    .filter_map(|range| {
                        let pair = range.as_array()?;
                        Some((
                            pair.first()?.as_u64()? as usize,
                            pair.get(1)?.as_u64()? as usize,
                        ))
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !parsed.is_empty() {
            hunks.insert(path.clone(), parsed);
        }
    }
    hunks
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

/// Per-part byte budget derived from the frozen seat budget: every lens of the
/// provider's bundle reads the same part in one seat, so the seat carries the
/// part's excerpts once plus each lens's own packet overhead. The cap is a
/// function of the frozen coverage config and review context only, so every
/// lens of a bundle derives the same cap and the same parts (and keeps sharing
/// seats). `None` without a frozen coverage config (legacy plans).
fn seat_part_budget(provider: &AuditProvider) -> Option<excerpts::PartBudget> {
    let coverage = provider.configuration.get("coverage")?;
    let seat_tokens = coverage.get("seatTokenBudget").and_then(Value::as_u64)?;
    let lenses = coverage
        .get("bundleLensCount")
        .and_then(Value::as_u64)
        .unwrap_or(1)
        .clamp(1, 16) as usize;
    let context_bytes = provider
        .configuration
        .get("reasoning")
        .and_then(|reasoning| reasoning.get("reviewContext"))
        .and_then(|context| serde_json::to_vec(context).ok())
        .map_or(0, |bytes| bytes.len());
    Some(excerpts::PartBudget {
        cap_bytes: coverage_plan::seat_part_cap_bytes(seat_tokens, lenses, context_bytes),
        listing_copies: 3 * lenses,
    })
}

/// Resolve frozen trigger evidence without re-evaluating a risk-selected set.
#[cfg(test)]
fn trigger_evidence_for(
    root: &Path,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
    denominator_paths: &[String],
) -> Result<Option<Value>, AuditError> {
    let source = excerpts::SourceReader::new(root)?;
    let result = trigger_evidence_with_source(&source, provider, inventory, denominator_paths);
    source.revalidate()?;
    result
}

fn trigger_evidence_with_source(
    source: &excerpts::SourceReader<'_>,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
    denominator_paths: &[String],
) -> Result<Option<Value>, AuditError> {
    let Some(lens) = lens_plan::lens_id_for_provider(&provider.id) else {
        return Ok(None);
    };
    if !lens_plan::is_conditional_lens_provider(&provider.id) {
        return Ok(None);
    }
    let evidence = match provider.configuration.get("triggerEvidence") {
        Some(evidence) => evidence.clone(),
        None => {
            let paths = inventory.paths().map(str::to_owned).collect::<Vec<_>>();
            let Some(evaluation) =
                triggers::evaluate_with_head(lens, &paths, &|path| source.head(path))
            else {
                return Ok(None);
            };
            let source_sides = source.source_sides();
            let source_sides = source_sides
                .into_iter()
                .filter(|(path, _)| paths.contains(path))
                .collect();
            let mut evidence =
                evaluation.snapshot_with_source_sides(&inventory.digest, &paths, &source_sides)?;
            evidence["binding"] = json!("unfrozen");
            evidence
        }
    };
    if provider.configuration.contains_key("triggerEvidence") {
        let mut unsigned = evidence.clone();
        let digest = unsigned
            .as_object_mut()
            .and_then(|object| object.remove("digest"));
        let expected =
            canonical_digest(&unsigned).map_err(|error| AuditError::Invalid(error.to_string()))?;
        let checked: BTreeSet<&str> = inventory.paths().collect();
        let actual_sides = source.source_sides();
        let actual_sides: BTreeMap<_, _> = actual_sides
            .into_iter()
            .filter(|(path, _)| checked.contains(path.as_str()))
            .collect();
        let checked_digest =
            canonical_digest(&checked).map_err(|error| AuditError::Invalid(error.to_string()))?;
        if digest.as_ref().and_then(Value::as_str) != Some(expected.as_str())
            || evidence.get("checkedPathsDigest").and_then(Value::as_str)
                != Some(checked_digest.as_str())
            || evidence
                .get("sourceSides")
                .cloned()
                .unwrap_or_else(|| json!({}))
                != json!(actual_sides)
            || evidence.get("lens").and_then(Value::as_str) != Some(lens)
        {
            return Err(AuditError::Invalid(format!(
                "provider {} trigger snapshot binding mismatch",
                provider.id
            )));
        }
    }
    let witnesses = evidence
        .get("mandatoryWitnessPaths")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            AuditError::Invalid(format!(
                "provider {} missing trigger witnesses",
                provider.id
            ))
        })?;
    let denominator: BTreeSet<&str> = denominator_paths.iter().map(String::as_str).collect();
    let frozen = provider
        .configuration
        .get("coverage")
        .and_then(coverage_plan::FrozenCoverage::from_value);
    for witness in witnesses {
        let path = witness
            .as_str()
            .ok_or_else(|| AuditError::Invalid("invalid trigger witness path".into()))?;
        if !denominator.contains(path)
            || frozen.as_ref().is_some_and(|coverage| {
                !coverage.review_set.contains(path)
                    && !(coverage.bounded && coverage.mandatory_deferred.contains(path))
            })
        {
            return Err(AuditError::Invalid(format!(
                "provider {} omits mandatory trigger witness {path}",
                provider.id
            )));
        }
    }
    if evidence.get("inventoryDigest").and_then(Value::as_str) != Some(inventory.digest.as_str()) {
        return Err(AuditError::SourceDrift(format!(
            "provider {} trigger inventory changed",
            provider.id
        )));
    }
    if evidence.get("fired").and_then(Value::as_bool) == Some(true) && witnesses.is_empty() {
        return Err(AuditError::Invalid(format!(
            "provider {} fired trigger has no witness",
            provider.id
        )));
    }
    Ok(Some(evidence))
}

/// Every scanner candidate belongs to one domain partition. Only security
/// uses threat adjudication; other domains use their existing lens contracts.
pub fn candidate_domain_partitions(candidates: &[ScannerCandidate]) -> Value {
    let mut partitions: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for candidate in candidates {
        let actual_domain = security_adjudication::effective_candidate_domain(candidate);
        let domain = if candidate_routing::target_lens(actual_domain).is_some() {
            actual_domain
        } else {
            "unknown"
        };
        partitions
            .entry(domain)
            .or_default()
            .push(candidate.finding_id.as_str());
    }
    let partitions = partitions.into_iter().map(|(domain, mut ids)| {
        ids.sort_unstable();
        let lens = candidate_routing::target_lens(domain);
        json!({
            "domain": domain,
            "candidateIds": ids,
            "targetLens": lens,
            "semanticReviewContract": lens.and_then(lens_plan::semantic_review_contract),
            "status": if domain == "security" { "candidate-adjudication" } else if lens.is_some() { "pending-lens-review" } else { "domain-review-unavailable" },
            "adjudicationDomainContract": if domain == "security" { json!(["threatModel", "attackerControl", "reachability", "impact", "proof", "evidence", "devilsAdvocate"]) } else { Value::Null },
        })
    }).collect::<Vec<_>>();
    json!({"schemaVersion": 1, "candidateCount": candidates.len(), "partitions": partitions})
}

/// Gaps packet construction can establish without claiming host delivery.
/// Ingest & direct host execution must carry these into terminal state.
pub fn required_packet_gaps(request: &ReasoningInvocation) -> Vec<String> {
    let mut gaps = Vec::new();
    if request.provider_id == ADJUDICATOR_PROVIDER_ID
        && request
            .packet
            .get("scannerCandidates")
            .is_none_or(Value::is_null)
    {
        gaps.push("scanner-candidates-unavailable".into());
    }
    if let Some(trigger) = request
        .packet
        .get("triggerEvidence")
        .filter(|value| !value.is_null())
    {
        if trigger.get("binding").and_then(Value::as_str) == Some("unfrozen") {
            gaps.push("trigger-evidence-unfrozen".into());
        }
        for path in trigger
            .get("unavailablePaths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            gaps.push(format!("trigger-check-unavailable:{path}"));
        }
    }
    for omission in request
        .packet
        .pointer("/excerptCoverage/omittedPaths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        gaps.push(format!(
            "reasoning-materialization-omitted:{}:{}",
            omission
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or("unknown"),
            omission
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        ));
    }
    for path in request
        .packet
        .pointer("/excerptCoverage/truncatedPaths")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        gaps.push(format!("reasoning-materialization-truncated:{path}"));
    }
    if request
        .packet
        .pointer("/part/overCeiling")
        .is_some_and(|value| !value.is_null())
    {
        gaps.push("reasoning-materialization-part-ceiling".into());
    }
    for partition in request
        .packet
        .pointer("/candidateRouting/partitions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if partition.get("status").and_then(Value::as_str) == Some("domain-review-unavailable") {
            gaps.push(format!(
                "candidate-domain-review-unavailable:{}",
                partition
                    .get("domain")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ));
        }
    }
    for route in request
        .packet
        .pointer("/candidateRouting/routes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if route.get("status").and_then(Value::as_str) == Some("domain-review-unavailable") {
            gaps.push(format!(
                "candidate-route-unavailable:{}:{}",
                route
                    .get("provider")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown"),
                route
                    .get("candidateId")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
            ));
        }
    }
    gaps
}

/// Expected excerpt identities for a transport delivery receipt. This records
/// exact materialized chunk bytes/ranges; it makes no claim about reading.
pub fn delivery_chunk_manifest(request: &ReasoningInvocation) -> Result<Vec<Value>, String> {
    let mut chunks = Vec::new();
    for excerpt in request
        .packet
        .get("excerpts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        chunks.push(json!({
            "path": excerpt.get("path"),
            "sourceSide": excerpt.get("sourceSide").and_then(Value::as_str).unwrap_or("selected"),
            "chunk": excerpt.get("chunk"),
            "chunks": excerpt.get("chunks"),
            "startLine": excerpt.get("startLine"),
            "endLine": excerpt.get("endLine"),
            "excerptDigest": canonical_digest(excerpt).map_err(|error| error.to_string())?,
        }));
    }
    Ok(chunks)
}

/// Validate host-reported delivery bindings. Caller must authenticate this
/// record through trusted host transport before using it; model-authored
/// metadata is never a transport receipt. Delivery still does not prove review.
pub fn validate_delivery_evidence(
    request: &ReasoningInvocation,
    evidence: &Value,
) -> Result<(), String> {
    if evidence.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || evidence.get("kind").and_then(Value::as_str) != Some("legion-evidence-delivery")
        || evidence.get("source").and_then(Value::as_str) != Some("host-transport")
        || evidence
            .get("receiptId")
            .and_then(Value::as_str)
            .is_none_or(|id| id.trim().is_empty())
        || evidence.get("requestId").and_then(Value::as_str) != Some(request.request_id.as_str())
        || evidence.get("complete").and_then(Value::as_bool) != Some(true)
        || evidence.get("truncated").and_then(Value::as_bool) != Some(false)
    {
        return Err("missing or incomplete host delivery evidence".into());
    }
    let digest = canonical_digest(&request.packet).map_err(|error| error.to_string())?;
    let bytes = canonical_json_bytes(&request.packet)
        .map_err(|error| error.to_string())?
        .len() as u64;
    if evidence.get("packetDigest").and_then(Value::as_str) != Some(digest.as_str()) {
        return Err("delivery evidence does not bind exact packet digest".into());
    }
    let encoding = evidence
        .get("transportEncoding")
        .and_then(Value::as_str)
        .unwrap_or("literal-packet-v1");
    let projected_packet;
    let expected_packet = if matches!(
        encoding,
        "audit-packet-reference-v1" | "shared-audit-packet-reference-v1"
    ) {
        crate::review_runtime::projection::validate(request, &evidence["projection"])?;
        if evidence.get("deliveredPacketBytes").is_some()
            || evidence
                .get("physicalRequestBytes")
                .and_then(Value::as_u64)
                .is_none_or(|bytes| bytes == 0)
            || evidence
                .get("physicalRequestDigest")
                .and_then(Value::as_str)
                .is_none_or(|digest| {
                    digest.strip_prefix("sha256:").is_none_or(|hex| {
                        hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
                })
            || evidence.get("physicalRequestDigest")
                != evidence.pointer("/host/physicalRequestDigest")
            || evidence.get("physicalRequestBytes")
                != evidence.pointer("/host/physicalRequestBytes")
        {
            return Err("projected delivery must bind actual physical transport separately from logical reconstruction".into());
        }
        projected_packet = crate::review_runtime::projection::packet(request)
            .map_err(|error| error.to_string())?
            .0;
        &projected_packet
    } else {
        &request.packet
    };
    match encoding {
        "audit-packet-reference-v1" => {}
        "literal-packet-v1" => {
            if evidence.get("deliveredPacketBytes").and_then(Value::as_u64) != Some(bytes) {
                return Err("literal delivery evidence does not bind exact packet bytes".into());
            }
        }
        "shared-context-v1" | "shared-audit-packet-reference-v1" => {
            let reconstruction = evidence
                .get("reconstruction")
                .ok_or_else(|| "shared delivery reconstruction missing".to_owned())?;
            let shared = reconstruction
                .get("sharedContext")
                .and_then(Value::as_object)
                .ok_or_else(|| "shared delivery context missing".to_owned())?;
            let compact = reconstruction
                .get("compactPacket")
                .and_then(Value::as_object)
                .ok_or_else(|| "shared delivery compact packet missing".to_owned())?;
            if !shared.contains_key("excerpts")
                || shared.iter().any(|(field, value)| {
                    !ingest::SHARED_PACKET_FIELDS.contains(&field.as_str())
                        || expected_packet.get(field) != Some(value)
                })
            {
                return Err("shared delivery must preserve exact whitelisted packet fields".into());
            }
            let shared_digest = canonical_digest(shared).map_err(|error| error.to_string())?;
            if evidence.get("sharedContextDigest").and_then(Value::as_str)
                != Some(shared_digest.as_str())
                || evidence
                    .get("reconstructedPacketBytes")
                    .and_then(Value::as_u64)
                    != Some(
                        canonical_json_bytes(expected_packet)
                            .map_err(|error| error.to_string())?
                            .len() as u64,
                    )
                || evidence.get("deliveredPacketBytes").is_some()
                || evidence
                    .get("physicalRequestBytes")
                    .and_then(Value::as_u64)
                    .is_none_or(|count| count == 0)
                || evidence
                    .get("physicalRequestDigest")
                    .and_then(Value::as_str)
                    .is_none_or(|digest| {
                        digest.strip_prefix("sha256:").is_none_or(|hex| {
                            hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                    })
            {
                return Err("shared delivery physical/logical byte binding invalid".into());
            }
            let mut restored = compact.clone();
            for (field, value) in compact {
                if let Some(reference) = value.get("$sharedContext") {
                    if !ingest::SHARED_PACKET_FIELDS.contains(&field.as_str())
                        || value.as_object().is_none_or(|object| object.len() != 1)
                        || reference.as_str() != Some(field.as_str())
                    {
                        return Err(
                            "shared delivery reference must name its exact top-level field".into(),
                        );
                    }
                    restored.insert(
                        field.clone(),
                        shared
                            .get(field)
                            .cloned()
                            .ok_or_else(|| "shared delivery reference is unavailable".to_owned())?,
                    );
                }
            }
            if Value::Object(restored) != *expected_packet {
                return Err("shared delivery cannot reconstruct exact original packet".into());
            }
        }
        _ => return Err("unsupported delivery transport encoding".into()),
    }
    let chunks = evidence
        .get("chunks")
        .and_then(Value::as_array)
        .ok_or_else(|| "delivery evidence missing chunk manifest".to_owned())?;
    let expected = delivery_chunk_manifest(request)?;
    let identities = |items: &[Value]| -> Result<BTreeSet<String>, String> {
        items
            .iter()
            .map(|item| canonical_digest(item).map_err(|error| error.to_string()))
            .collect()
    };
    let delivered = identities(chunks)?;
    let required = identities(&expected)?;
    if delivered.len() != chunks.len() || required.len() != expected.len() || delivered != required
    {
        return Err("delivery evidence omits, duplicates or changes excerpt chunks".into());
    }
    Ok(())
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
    source: &excerpts::SourceReader<'_>,
    sizer: &mut crate::review_runtime::InitialRequestSizer,
    scanner_candidates: Option<&[ScannerCandidate]>,
    allow_deferred: bool,
) -> Result<(Vec<ReasoningInvocation>, Option<Value>), AuditError> {
    if let Some(candidates) = scanner_candidates {
        candidate_routing::validate_identities(candidates).map_err(AuditError::Invalid)?;
    }
    // Pending sampled work may exceed one physical call: retain its exact
    // logical packets so dispatch can defer them explicitly & admit other
    // lenses. In-process invocation & exhaustive requests still refuse.
    let allow_deferred = allow_deferred
        && provider
            .configuration
            .get("coverage")
            .and_then(coverage_plan::FrozenCoverage::from_value)
            .is_some_and(|coverage| coverage.is_sampled());
    let budget = seat_part_budget(provider);
    let target = provider
        .configuration
        .get("coverage")
        .and_then(|coverage| coverage.get("seatTokenBudget"))
        .and_then(Value::as_u64)
        .map(ingest::physical_planning_input_bytes);
    let (Some(target), Some(budget)) = (target, budget) else {
        return build_invocations_with_budget(
            plan,
            provider,
            inventory,
            denominator,
            invocation_epoch,
            source,
            scanner_candidates,
            budget,
        );
    };
    let mut build = |budget, source_only| {
        let mut built = build_invocations_with_budget(
            plan,
            provider,
            inventory,
            denominator,
            invocation_epoch,
            source,
            scanner_candidates,
            budget,
        )?;
        if source_only {
            for (index, request) in built.0.iter_mut().enumerate() {
                request.packet["candidateContext"] = json!([]);
                number_continuation(request, index + 1, part_ceiling(provider), false)?;
                refresh_request_identity(request, invocation_epoch)?;
            }
        }
        let (largest, fits) = measure_invocations_required(&built.0, provider, sizer)?;
        // A non-fit reports its real byte requirement, floored just above the
        // target so every `<= target` comparison still reads it as a non-fit.
        let largest = if fits {
            largest
        } else {
            largest.max(target.saturating_add(1))
        };
        Ok((built, largest))
    };
    // Lenses of one bundle must derive the same excerpt parts so they keep
    // sharing seats. Their own pattern-card overhead differs by lens, so first
    // search the cap with every lens charged the largest possible card
    // overhead (only when the exact original packet does not already fit).
    // That measure never underestimates the real request, so any fit
    // it finds is a real fit; when it cannot fit, fall back to exact sizing.
    let first = build(Some(budget), false)?;
    if first.1 <= target {
        return Ok(first.0);
    }
    let card_reserve = pattern_cards::max_card_bytes_bound(Some(
        pattern_cards::packet_card_budget_bytes(target),
    ));
    let (normalized_built, normalized_largest) =
        refine_packet_materialization(budget, target, |budget| {
            let (built, largest) = build(Some(budget), false)?;
            let own_cards = built
                .0
                .iter()
                .map(|request| pattern_cards::bound_card_bytes(&request.packet["lensPlan"]))
                .min()
                .unwrap_or(0);
            let normalized = largest.saturating_add(card_reserve.saturating_sub(own_cards));
            Ok((built, normalized))
        })?;
    if normalized_largest <= target {
        return Ok(normalized_built);
    }
    let mut full_attempts = 0;
    let (built, largest) = refine_packet_materialization(budget, target, |budget| {
        full_attempts += 1;
        build(Some(budget), false)
    })?;
    if largest <= target {
        return Ok(built);
    }
    // Refine only source once candidates make their original ownership
    // physically impossible. Promotion still sees the complete scanner set.
    let separate_candidates = provider.id != ADJUDICATOR_PROVIDER_ID
        && scanner_candidates.is_some_and(|candidates| {
            !candidate_routing::routed_candidates(&provider.id, candidates).is_empty()
        });
    let (built, largest) = if separate_candidates {
        // A failed full-context search consumes its original & minimum
        // probes. Reuse the remaining eight-probe allowance for source only.
        refine_packet_materialization_with_limit(
            budget,
            target,
            8usize.saturating_sub(full_attempts),
            |budget| build(Some(budget), true),
        )?
    } else {
        (built, largest)
    };
    if largest > target && !allow_deferred {
        return Err(AuditError::BoundExceeded(format!(
            "audit packet for {} cannot fit: initial model-visible input estimate needs at least {largest} bytes; seat allows {target} input bytes while retaining minimum meaningful output & planning headroom. Increase seatTokenBudget or narrow scope; selected coverage was not truncated",
            provider.id
        )));
    }
    if separate_candidates {
        append_candidate_parts(
            built,
            plan,
            provider,
            invocation_epoch,
            scanner_candidates.unwrap(),
            sizer,
            allow_deferred,
        )
    } else {
        Ok(built)
    }
}

fn invocation_work(request: &ReasoningInvocation, provider: &AuditProvider) -> PendingLensWork {
    PendingLensWork {
        provider_id: provider.id.clone(),
        lens_ids: provider.lens_ids.clone(),
        status: "pending-host".into(),
        request: request.clone(),
        promotion: None,
    }
}

/// An over-host-ceiling or output-starved packet is also an input non-fit.
fn measure_invocations(
    requests: &[ReasoningInvocation],
    provider: &AuditProvider,
    sizer: &mut crate::review_runtime::InitialRequestSizer,
) -> Result<u64, AuditError> {
    let (largest, fits) = measure_invocations_required(requests, provider, sizer)?;
    Ok(if fits { largest } else { u64::MAX })
}

/// Largest measured byte requirement across `requests` and whether every
/// request fits the physical bounds. A non-fit reports the real requirement
/// (host envelope bytes when that bound is the one exceeded, else model input).
fn measure_invocations_required(
    requests: &[ReasoningInvocation],
    provider: &AuditProvider,
    sizer: &mut crate::review_runtime::InitialRequestSizer,
) -> Result<(u64, bool), AuditError> {
    let per_call = provider
        .configuration
        .get("coverage")
        .and_then(|coverage| coverage.get("seatTokenBudget"))
        .and_then(Value::as_u64)
        .unwrap_or(u64::MAX);
    let ceiling = ingest::dispatch_output_tokens(per_call);
    let mut largest = 0;
    let mut all_fit = true;
    for request in requests {
        let sizes = sizer.request_sizes(&[invocation_work(request, provider)])?;
        let minimum = ingest::minimum_output_tokens(ceiling, 1)
            .max(candidate_routing::disposition_output_tokens(request));
        let envelope_over = sizes.host_envelope_bytes > crate::review_runtime::MAX_REQUEST_BYTES as u64;
        if envelope_over
            || ingest::fitting_output_tokens(
                per_call,
                ceiling,
                sizes.model_visible_input_bytes,
                minimum,
            )
            .is_none()
        {
            all_fit = false;
        }
        largest = largest.max(if envelope_over {
            sizes.host_envelope_bytes.max(sizes.model_visible_input_bytes)
        } else {
            sizes.model_visible_input_bytes
        });
    }
    Ok((largest, all_fit))
}

fn refresh_request_identity(
    request: &mut ReasoningInvocation,
    epoch: &str,
) -> Result<(), AuditError> {
    let signature = if request.plan_signature.is_empty() {
        Value::Null
    } else {
        json!(request.plan_signature)
    };
    request.request_id = canonical_digest(&json!({
        "invocationEpoch": epoch, "packetDigest": canonical_digest(&request.packet)
            .map_err(|error| AuditError::Invalid(error.to_string()))?,
        "providerId": request.provider_id, "contract": request.contract,
        "planDigest": request.plan_digest, "planSignature": signature,
        "repositoryId": request.repository_id, "inventoryGeneration": request.inventory_generation,
        "inventoryDigest": request.inventory_digest, "denominatorDigest": request.denominator_digest,
        "denominatorCount": request.denominator_count, "denominatorPaths": request.denominator_paths,
    })).map_err(|error| AuditError::Invalid(error.to_string()))?;
    Ok(())
}

fn number_continuation(
    request: &mut ReasoningInvocation,
    number: usize,
    total: usize,
    candidate: bool,
) -> Result<(), AuditError> {
    if request.packet.get("part").is_none_or(Value::is_null) {
        let paths = request
            .packet
            .pointer("/excerptCoverage/selectedPaths")
            .cloned()
            .unwrap_or(json!([]));
        request.packet["part"] = json!({"pathsDigest": canonical_digest(&paths)
            .map_err(|error| AuditError::Invalid(error.to_string()))?, "paths": paths,
            "continuedPaths": [], "overCeiling": null,
            "indexFile": format!("{}.index.json", request.provider_id)});
    }
    let part = &mut request.packet["part"];
    part["number"] = json!(number);
    part["total"] = json!(total);
    part["requiredParts"] = json!(total);
    part["findingIdPrefix"] = json!(format!("p{number:04}-"));
    if candidate {
        part["kind"] = json!("candidate-context");
    }
    Ok(())
}

fn append_candidate_parts(
    mut built: (Vec<ReasoningInvocation>, Option<Value>),
    plan: &FrozenPlan,
    provider: &AuditProvider,
    epoch: &str,
    candidates: &[ScannerCandidate],
    sizer: &mut crate::review_runtime::InitialRequestSizer,
    allow_deferred: bool,
) -> Result<(Vec<ReasoningInvocation>, Option<Value>), AuditError> {
    let routed = candidate_routing::routed_candidates(&provider.id, candidates);
    let max_parts = part_ceiling(provider);
    let source_part_count = built.0.len();
    let mut template =
        built.0.first().cloned().ok_or_else(|| {
            AuditError::Invalid("candidate continuation has no source packet".into())
        })?;
    let domain_contract = template.packet.pointer("/lensPlan/domainContract").cloned();
    template.packet["excerpts"] = json!([]);
    template.packet["lensPlan"] = lens_plan_for_part_budgeted(
        lens_plan::lens_plan_packet_value(&provider.id).as_ref(),
        &[],
        provider_card_budget(provider),
    )
    .unwrap_or(Value::Null);
    if let (Some(domain_contract), Some(plan)) =
        (domain_contract, template.packet["lensPlan"].as_object_mut())
    {
        plan.insert("domainContract".into(), domain_contract);
    }
    template.packet["reviewContext"] = packet_context::review_context(plan, provider, &[])?;
    for field in [
        "selectedPaths",
        "materializedPaths",
        "examinedPaths",
        "chunkedPaths",
        "omittedPaths",
        "truncatedPaths",
        "aliasedPaths",
    ] {
        template.packet["excerptCoverage"][field] = json!([]);
    }
    template.packet["excerptCoverage"]["basis"] = json!("candidate-context");
    template.packet["part"] = Value::Null;
    number_continuation(&mut template, max_parts, max_parts, true)?;
    let mut offset = 0;
    while offset < routed.len() {
        if built.0.len() >= max_parts {
            return Err(AuditError::BoundExceeded(format!("candidate context for {} requires more than maxReasoningParts {max_parts}; first unscheduled identity {}:{}", provider.id, routed[offset].provider, routed[offset].finding_id)));
        }
        // Longest fitting prefix, preserving frozen records & order exactly.
        let mut low = 0;
        let mut high = routed.len() - offset;
        while low < high {
            let count = low + (high - low + 1) / 2;
            template.packet["candidateContext"] = json!(&routed[offset..offset + count]);
            refresh_request_identity(&mut template, epoch)?;
            if measure_invocations(std::slice::from_ref(&template), provider, sizer)? != u64::MAX {
                low = count;
            } else {
                high = count - 1;
            }
        }
        if low == 0 {
            template.packet["candidateContext"] = json!(&routed[offset..offset + 1]);
            refresh_request_identity(&mut template, epoch)?;
            let sizes = sizer.request_sizes(&[invocation_work(&template, provider)])?;
            return Err(AuditError::BoundExceeded(format!("candidate {}:{} for {} requires model input {} bytes, host envelope {} bytes & mandatory disposition {} tokens; frozen seat/output/host bounds refuse this indivisible record", routed[offset].provider, routed[offset].finding_id, provider.id, sizes.model_visible_input_bytes, sizes.host_envelope_bytes, candidate_routing::disposition_output_tokens(&template))));
        }
        template.packet["candidateContext"] = json!(&routed[offset..offset + low]);
        built.0.push(template.clone());
        offset += low;
    }
    let total = built.0.len();
    for (index, request) in built.0.iter_mut().enumerate() {
        let candidate = request.packet.pointer("/part/kind").and_then(Value::as_str)
            == Some("candidate-context");
        number_continuation(request, index + 1, total, candidate)?;
        refresh_request_identity(request, epoch)?;
        if candidate && !candidate_routing::is_candidate_part(request) {
            return Err(AuditError::Invalid("candidate continuation requires complete evidence-bound records for its target provider".into()));
        }
    }
    for (index, request) in built.0.iter().enumerate() {
        // Sampled source work may remain explicitly deferred. Appended
        // candidate continuations always satisfy every physical bound.
        if allow_deferred && index < source_part_count {
            continue;
        }
        if measure_invocations(std::slice::from_ref(request), provider, sizer)? == u64::MAX {
            return Err(AuditError::BoundExceeded(format!(
                "final candidate continuations for {} exceed frozen physical request bounds",
                provider.id
            )));
        }
    }
    Ok(built)
}

/// At most eight measured materializations: original, minimum, then six
/// bracket probes. Keep the fullest measured fit; a minimum-sized probe is
/// never the final choice merely because an iteration limit was reached.
/// No monotonicity assumption can admit an unmeasured or oversized packet.
fn refine_packet_materialization<T>(
    budget: excerpts::PartBudget,
    target: u64,
    measure: impl FnMut(excerpts::PartBudget) -> Result<(T, u64), AuditError>,
) -> Result<(T, u64), AuditError> {
    refine_packet_materialization_with_limit(budget, target, 8, measure)
}

fn refine_packet_materialization_with_limit<T>(
    budget: excerpts::PartBudget,
    target: u64,
    attempts: usize,
    mut measure: impl FnMut(excerpts::PartBudget) -> Result<(T, u64), AuditError>,
) -> Result<(T, u64), AuditError> {
    let original = measure(budget)?;
    if original.1 <= target || budget.cap_bytes <= 1 || attempts <= 1 {
        return Ok(original);
    }
    let minimum = measure(excerpts::PartBudget {
        cap_bytes: 1,
        ..budget
    })?;
    if minimum.1 > target {
        return Ok(minimum);
    }
    let mut best = minimum;
    let mut fit_cap = 1;
    let mut over_cap = budget.cap_bytes;
    for _ in 0..attempts.saturating_sub(2) {
        if over_cap - fit_cap <= 1 {
            break;
        }
        let cap_bytes = fit_cap + (over_cap - fit_cap) / 2;
        let candidate = measure(excerpts::PartBudget {
            cap_bytes,
            ..budget
        })?;
        if candidate.1 <= target {
            fit_cap = cap_bytes;
            best = candidate;
        } else {
            over_cap = cap_bytes;
        }
    }
    Ok(best)
}

fn selected_part_source_paths(part: Option<&excerpts::ExcerptPart>) -> Vec<String> {
    // A continuation still carries selected source even though another part
    // owns its denominator path. Include omissions homed in this part, too.
    part.into_iter()
        .flat_map(|part| {
            part.paths
                .iter()
                .chain(part.excerpts.iter().map(|excerpt| &excerpt.path))
        })
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Build the frozen domain-contract set from `.legion/domain-contracts/*`
/// (see `domain_contract::DOMAIN_CONTRACT_DIR`). `None` only when no contract
/// file is declared and none is required; a declared-but-unreadable file or a
/// required-but-missing set is an unresolved boundary inside the set.
fn domain_contract_set(
    source: &excerpts::SourceReader<'_>,
    inventory: &InventoryEnvelope,
    provider: &AuditProvider,
) -> Option<crate::domain_contract::DomainContractSet> {
    use crate::domain_contract as dc;
    let required = dc::contracts_required(inventory)
        || provider
            .configuration
            .get("domainContractsRequired")
            .and_then(Value::as_bool)
            == Some(true);
    let inputs = dc::contract_inputs_from_inventory(inventory, |path| {
        source
            .read(path, dc::DOMAIN_CONTRACT_MAX_BYTES)
            .ok()
            .map(|(bytes, _)| bytes)
    });
    if inputs.is_empty() && !required {
        return None;
    }
    Some(dc::DomainContractSet::build(
        &inputs,
        &[dc::inventory_snapshot(inventory)],
        required,
    ))
}

fn lens_plan_for_part(lens_plan: Option<&Value>, source_paths: &[String]) -> Option<Value> {
    lens_plan_for_part_budgeted(lens_plan, source_paths, None)
}

/// As `lens_plan_for_part`, spending at most `card_budget` bytes on pattern
/// cards when the provider's seat is frozen (see `provider_card_budget`).
fn lens_plan_for_part_budgeted(
    lens_plan: Option<&Value>,
    source_paths: &[String],
    card_budget: Option<u64>,
) -> Option<Value> {
    lens_plan.map(|lens_plan| {
        let mut bound = lens_plan.clone();
        pattern_cards::bind_packet_cards_to_paths_budgeted(&mut bound, source_paths, card_budget);
        bound
    })
}

/// Per-packet pattern-card byte budget derived from the provider's frozen seat
/// input target; `None` when the provider freezes no seat budget.
fn provider_card_budget(provider: &AuditProvider) -> Option<u64> {
    provider
        .configuration
        .get("coverage")
        .and_then(|coverage| coverage.get("seatTokenBudget"))
        .and_then(Value::as_u64)
        .map(|seat| {
            pattern_cards::packet_card_budget_bytes(ingest::physical_planning_input_bytes(seat))
        })
}

fn build_invocations_with_budget(
    plan: &FrozenPlan,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
    denominator: &InventoryDenominator,
    invocation_epoch: &str,
    source: &excerpts::SourceReader<'_>,
    scanner_candidates: Option<&[ScannerCandidate]>,
    part_budget: Option<excerpts::PartBudget>,
) -> Result<(Vec<ReasoningInvocation>, Option<Value>), AuditError> {
    if let Some(candidates) = scanner_candidates {
        candidate_routing::validate_identities(candidates).map_err(AuditError::Invalid)?;
    }
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
    let all_scanner_candidates = scanner_candidates;
    let routed_candidates = scanner_candidates
        .map(|candidates| candidate_routing::routed_candidates(&provider.id, candidates));
    let scanner_candidates = routed_candidates.as_deref();
    // Per-lens work-packet planning (question, applicability trigger, excerpt
    // scoping, report schema, model tier, verify-pass requirement, ponytail
    // tags, cues) per skills/audit/references/{lens-routing,manual,
    // ponytail-lens,lens-cues}.md. `None` only for
    // `legacy.security.adjudication`, which carries its own independent
    // packet shape via `security_adjudication.rs`.
    let lens_plan = lens_plan::lens_plan_packet_value(&provider.id);
    let lens_id = lens_plan::lens_id_for_provider(&provider.id);
    let domain_set = domain_contract_set(source, inventory, provider);
    // Scoped excerpts: RAW (bounded, file:line anchored, secret-redacted)
    // for security/schema/correctness/performance/minimize/doc-drift/architecture/ai-slop,
    // SKELETON (signatures/declarations, no bodies) for
    // naming/dead-file, per lens-routing.md's
    // "Excerpt compression" section. `None` only for
    // `legacy.security.adjudication`, which is not lens-routed here.
    let ceiling = part_ceiling(provider);
    // Diff-scoped audit: the frozen review context carries the changed hunks
    // per path; those paths are excerpted as hunks plus context, not whole.
    let changed_hunks = changed_hunks_from_review_context(provider);
    let base_mode = lens_plan::lens_plan_excerpt_mode(&provider.id);
    // Frozen coverage plan: a risk-sampled lens partitions only its review set
    // (plus files promoted by deterministic findings); an exhaustive lens, or a
    // plan without a coverage plan, partitions the whole denominator exactly as
    // before.
    // Trigger applicability & mandatory witnesses are frozen before risk
    // selection. Legacy plans expose their missing frozen binding explicitly.
    let actual_sides = source.source_sides();
    let actual_sides: BTreeMap<_, _> = actual_sides
        .into_iter()
        .filter(|(path, _)| paths.contains(path))
        .collect();
    let frozen_sides = provider
        .configuration
        .get("sourceSides")
        .cloned()
        .unwrap_or_else(|| json!({}));
    if frozen_sides != json!(actual_sides) {
        return Err(AuditError::SourceDrift(format!(
            "provider {} source-side identity changed",
            provider.id
        )));
    }
    let trigger_evidence = trigger_evidence_with_source(source, provider, inventory, &paths)?;
    let sampled = base_mode.and_then(|mode| {
        sampled_review(
            source,
            provider,
            denominator,
            // Any deterministic risk nomination may promote source into a
            // lens review. Only disposition context is domain-routed above.
            all_scanner_candidates,
            mode,
            &changed_hunks,
            part_budget.map_or(0, |budget| budget.listing_copies),
        )
    });
    let partition = match (&sampled, base_mode) {
        (Some(sampled), _) => Some(excerpts::partition_review_set_with_source(
            source,
            &sampled.items,
            &sampled.aliases,
            ceiling,
            &changed_hunks,
            &sampled.flags,
            part_budget,
        )),
        (None, Some(mode)) => Some(excerpts::partition_excerpts_with_source(
            source,
            &paths,
            mode,
            ceiling,
            &changed_hunks,
            part_budget,
        )),
        (None, None) => None,
    };
    let review_binding = sampled.as_ref().map(|sampled| &sampled.binding);
    // Scanner candidates for the adjudicator: one verdict per candidate.
    // `null` means the caller did not supply scanner results (unknown, not
    // "none"); ingest then refuses to treat the lens as covered.
    let candidates_value = (provider.id == ADJUDICATOR_PROVIDER_ID)
        .then(|| scanner_candidates.map(|candidates| json!(candidates)))
        .flatten();
    // Full report-schema body for the lens's finding shape (id, lens,
    // severity, confidence, file:line evidence, failure scenario, action,
    // verify status, plus lens-specific extras), matching the id carried
    // in `lensPlan.reportSchema`.
    let report_schema_body = lens_id.and_then(lens_schemas::lens_report_schema);
    let semantic_contract = lens_id.and_then(lens_plan::semantic_review_contract);
    let change_risk_contract = lens_id.and_then(lens_plan::change_risk_contract);
    // Seats read excerpts, not the inventory: packets carry the inventory
    // digest and the run-relative path of the one shared inventory artifact.
    let inventory_ref = json!({
        "inventoryDigest": inventory.digest,
        "snapshotRef": INVENTORY_SNAPSHOT_FILE,
    });
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
    // Architecture docs are context for the architecture lens only; they are
    // outside the source denominator & never counted as coverage.
    let doc_context = packet_context::doc_context(source, inventory, &provider.id);
    let candidate_part_paths = part_slots
        .iter()
        .map(|part| part.map(|part| part.paths.clone()).unwrap_or_default())
        .collect::<Vec<_>>();
    for (index, part) in part_slots.into_iter().enumerate() {
        let number = index + 1;
        // Continued chunks still need their selected file's graph hints even
        // though denominator ownership remains with the file's first part.
        let context_paths = selected_part_source_paths(part);
        let mut part_lens_plan = lens_plan_for_part_budgeted(
            lens_plan.as_ref(),
            &context_paths,
            provider_card_budget(provider),
        );
        // A12: repository-declared domain contracts reach every lens packet;
        // none declared is an explicit `absent`, never silence.
        if let Some(bound) = part_lens_plan.as_mut() {
            pattern_cards::bind_domain_contract_set(bound, domain_set.as_ref());
        }
        let review_context = packet_context::review_context(plan, provider, &context_paths)?;
        // Packet materialization is separate from host delivery & review.
        // Constructing an excerpt cannot prove a reviewer received it.
        let excerpt_coverage = excerpt_coverage_value(
            &provider.id,
            part,
            scanner_candidates,
            paths.len(),
            review_binding,
        );
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
            "lensPlan": part_lens_plan,
            "excerpts": excerpts_value,
            "excerptCoverage": excerpt_coverage,
            "scannerCandidates": candidates_value,
            "candidateContext": if provider.id == ADJUDICATOR_PROVIDER_ID { Value::Null } else {
                scanner_candidates.map(|candidates| json!(candidate_routing::candidates_for_part(candidates, &candidate_part_paths, index)))
                    .unwrap_or(Value::Null)
            },
            "candidateDispositionContract": if provider.id == ADJUDICATOR_PROVIDER_ID { Value::Null } else { json!({
                "resultField": "candidateDispositions",
                "identity": ["candidateId", "provider", "evidenceDigest"],
                "statuses": ["confirmed", "dismissed", "unresolved"],
                "required": ["reason", "evidence"],
                "confirmed": "findingId names a returned lens finding under this lens schema",
                "dismissed": "cite candidate-file counterevidence",
                "unresolved": "keeps candidate-review-pending; inclusion is not a disposition"
            }) },
            "triggerEvidence": trigger_evidence,
            "sourceSides": provider.configuration.get("sourceSides").cloned().unwrap_or_else(|| json!({})),
            "reportSchemaBody": report_schema_body,
            "semanticReviewContract": semantic_contract,
            "changeRiskContract": change_risk_contract,
            "reviewContext": review_context,
            "inventoryRef": inventory_ref.clone(),
            "artifactIds": [],
        });
        if let Some(doc_context) = &doc_context {
            packet["docContext"] = doc_context.clone();
        }
        if candidate_routing::accounting_owner(plan) == Some(provider.id.as_str()) {
            packet["candidateRouting"] = all_scanner_candidates
                .map(|candidates| candidate_routing::packet_accounting(plan, candidates))
                .transpose()
                .map_err(AuditError::Invalid)?
                .unwrap_or(Value::Null);
        }
        // === LANE B BOUNDARY: security adjudicator packet construction. ===
        // Everything inside this `if` belongs to security_adjudication.rs and
        // wf064 finalize (batched adjudication); lane A does not edit it.
        if provider.id == ADJUDICATOR_PROVIDER_ID {
            let child_work = match scanner_candidates {
                Some(candidates) => {
                    let parent_packet_digest =
                        security_adjudication::adjudication_parent_packet_digest(&packet)
                            .map_err(|error| AuditError::Invalid(error.to_string()))?;
                    // Deterministic triage, clusters and bounded batches.
                    // Confirmations and spot-checks depend on batch verdicts;
                    // the packet carries their rules and ingest derives them.
                    // The host supplies no resolved-fingerprint set yet, so
                    // only the path and placeholder triage rules can fire.
                    security_adjudication::build_adjudication_plan(
                        candidates,
                        &security_adjudication::TriageContext::default(),
                        &parent_packet_digest,
                    )
                    .map_err(|error| AuditError::Invalid(error.to_string()))?
                    .to_value()
                }
                // Keep unavailable scanner output distinct from a known empty
                // candidate set. In particular, null must never mean no work.
                None => Value::Null,
            };
            packet["candidateWorkItems"] = child_work;
        }
        // === END LANE B BOUNDARY ===
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
    let promotion = review_binding.and_then(|binding| binding.promotion_doc.clone());
    Ok((invocations, promotion))
}

/// What a risk-sampled lens packet records about its frozen review set.
#[derive(Clone, Debug)]
pub(crate) struct ReviewBinding {
    bundle: String,
    /// Digest of the frozen review set (`configuration.coverage`).
    digest: String,
    /// Frozen review-set size; promoted paths are counted separately.
    review_count: usize,
    declared_unsampled: usize,
    excluded: usize,
    /// Paths promoted into the review set by deterministic findings, within
    /// the frozen run budget.
    promoted: Vec<String>,
    /// Frozen sampled (hotspot/remainder) paths displaced by the promotion,
    /// lowest-ranked first. Mandatory paths are never displaced.
    displaced: Vec<String>,
    /// Promotable paths the run budget could not take, in severity order;
    /// reported as the `lens-promotion-capped:<n>` gap.
    unpromoted: Vec<String>,
    /// Digest of the review set actually examined (frozen set minus displaced
    /// plus promoted); ingest re-derives it from the frozen plan.
    effective_digest: String,
    /// Digest binding the promotion to the scanner candidates it came from.
    promotion_digest: Option<String>,
    /// `{promoted, displaced, unpromoted, findings, digest}`, written once per
    /// lens as `promotionRef`; `None` when nothing was promoted or displaced.
    promotion_doc: Option<Value>,
    aliases: excerpts::AliasMap,
}

/// The partition inputs of a risk-sampled lens.
struct SampledReview {
    items: Vec<excerpts::ReviewItem>,
    aliases: excerpts::AliasMap,
    flags: excerpts::FlaggedRegions,
    binding: ReviewBinding,
}

fn mode_strength(mode: lens_plan::ExcerptMode) -> u8 {
    match mode {
        lens_plan::ExcerptMode::Raw => 3,
        lens_plan::ExcerptMode::Regions => 2,
        lens_plan::ExcerptMode::Skeleton => 1,
    }
}

/// Builds the sampled review of `provider`, or `None` when the provider has no
/// frozen risk-sampled coverage plan (exhaustive, or a plan without one).
///
/// Findings promotion stays inside the frozen run budget. The budget is the
/// estimated excerpt cost of the frozen review set; mandatory paths never
/// shrink and stay in. A deterministic scanner candidate outside the review
/// set may be promoted only by displacing frozen sampled paths (remainder
/// first, then hotspots, each from its lowest rank) whose estimated cost covers
/// the promoted file. Candidates that point at frozen sampled paths protect
/// those paths from displacement. When the displaceable cost cannot cover every
/// candidate, promotion is capped in severity order and the rest is reported
/// as `unpromoted`; nothing is dropped silently.
///
/// Files with identical content digests are excerpted once under their first
/// path and credited to every path that shares the digest.
fn sampled_review(
    source: &excerpts::SourceReader<'_>,
    provider: &AuditProvider,
    denominator: &InventoryDenominator,
    scanner_candidates: Option<&[ScannerCandidate]>,
    base_mode: lens_plan::ExcerptMode,
    hunks: &excerpts::ChangedHunks,
    listing_copies: usize,
) -> Option<SampledReview> {
    let frozen = provider
        .configuration
        .get("coverage")
        .and_then(coverage_plan::FrozenCoverage::from_value)
        .filter(coverage_plan::FrozenCoverage::is_sampled)?;
    let in_denominator: BTreeSet<&str> = denominator
        .entries
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    let default_mode = frozen.default_mode.unwrap_or(base_mode);
    let mandatory_mode = frozen.mandatory_mode.unwrap_or(default_mode);
    let mode_of = |path: &str| {
        if frozen.mandatory.contains(path) {
            mandatory_mode
        } else {
            default_mode
        }
    };
    // Candidate paths: flags for every in-denominator candidate; promotion
    // candidates (with their highest severity) only outside the review set.
    let mut flags = excerpts::FlaggedRegions::new();
    let mut promotion_basis: Vec<(String, u64)> = Vec::new();
    let mut promotable: BTreeMap<String, u8> = BTreeMap::new();
    let mut protected: BTreeSet<String> = BTreeSet::new();
    for candidate in scanner_candidates.unwrap_or(&[]) {
        let Some(path) = candidate.path.as_deref() else {
            continue;
        };
        if !in_denominator.contains(path) {
            continue;
        }
        if frozen.review_set.contains(path) {
            protected.insert(path.to_owned());
        } else {
            let rank = coverage_plan::promotion_severity_rank(&candidate.severity);
            let slot = promotable.entry(path.to_owned()).or_insert(rank);
            *slot = (*slot).max(rank);
        }
        let line = candidate.line.unwrap_or(0) as usize;
        if line > 0 {
            flags
                .entry(path.to_owned())
                .or_default()
                .push((line.saturating_sub(1).max(1), line + 1));
            promotion_basis.push((path.to_owned(), line as u64));
        }
    }
    promotion_basis.sort();
    promotion_basis.dedup();

    // Cost is what the dispatch estimator will charge: the measured excerpt
    // JSON of the file in its packet mode (flagged regions included).
    // Promoted files carry their finding's raw window and can cost several
    // times a skeleton sampled file, so file size is no stand-in. Per-path
    // listings only appear in multi-part packets, so a promoted file is
    // charged its listings while a displaced file frees only its excerpt
    // bytes: displacing many small files must never buy listings that a
    // single-part packet never emitted.
    let measured = |path: &str, copies: usize| {
        excerpts::review_item_cost_with_source(
            source,
            &excerpts::ReviewItem {
                path: path.to_owned(),
                mode: mode_of(path),
            },
            hunks,
            &flags,
            copies,
        ) as u64
    };
    let promote_cost = |path: &str| measured(path, listing_copies);
    let freed_by = |path: &str| measured(path, 0);

    // Displaceable sampled paths, lowest-ranked first: unranked leftovers,
    // then the remainder stratum from its end, then the hotspot stratum from
    // its end. Mandatory and candidate-flagged paths never displace.
    let remainder = frozen.stratum_paths("remainder");
    let hotspot = frozen.stratum_paths("hotspot");
    let ranked: BTreeSet<&str> = remainder
        .iter()
        .chain(hotspot.iter())
        .map(String::as_str)
        .collect();
    let eligible = |path: &str| {
        frozen.review_set.contains(path)
            && !frozen.mandatory.contains(path)
            && !protected.contains(path)
    };
    let mut displace_order: Vec<&str> = frozen
        .review_set
        .iter()
        .map(String::as_str)
        .filter(|path| eligible(path) && !ranked.contains(path))
        .collect();
    displace_order.reverse();
    displace_order.extend(
        remainder
            .iter()
            .rev()
            .map(String::as_str)
            .filter(|path| eligible(path)),
    );
    displace_order.extend(
        hotspot
            .iter()
            .rev()
            .map(String::as_str)
            .filter(|path| eligible(path)),
    );
    // Nothing to promote: nothing is measured and nothing is displaced.
    if promotable.is_empty() {
        displace_order.clear();
    }
    // Candidates inside the frozen review set add their flagged windows to
    // files the plan already priced without them; that growth is charged
    // against the same displaceable budget.
    let flag_growth: u64 = if promotable.is_empty() {
        0
    } else {
        let unflagged = excerpts::FlaggedRegions::new();
        protected
            .iter()
            .map(|path| {
                let item = excerpts::ReviewItem {
                    path: path.clone(),
                    mode: mode_of(path),
                };
                let plain = excerpts::review_item_cost_with_source(
                    source,
                    &item,
                    hunks,
                    &unflagged,
                    listing_copies,
                );
                measured(path, listing_copies).saturating_sub(plain as u64)
            })
            .sum()
    };
    let displaceable_cost: u64 = displace_order.iter().map(|path| freed_by(path)).sum();

    // Promote by severity (then path) until the displaceable cost is spent.
    let mut order: Vec<(&String, u8)> = promotable.iter().map(|(p, r)| (p, *r)).collect();
    order.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(right.0)));
    let mut promoted: BTreeSet<String> = BTreeSet::new();
    let mut unpromoted: Vec<String> = Vec::new();
    let mut promoted_cost = flag_growth;
    for (path, _) in order {
        let cost = promote_cost(path);
        if promoted_cost.saturating_add(cost) <= displaceable_cost {
            promoted_cost += cost;
            promoted.insert(path.clone());
        } else {
            unpromoted.push(path.clone());
        }
    }
    let mut displaced: Vec<String> = Vec::new();
    let mut freed = 0u64;
    for path in displace_order {
        if freed >= promoted_cost {
            break;
        }
        freed += freed_by(path);
        displaced.push(path.to_owned());
    }
    let displaced_set: BTreeSet<&str> = displaced.iter().map(String::as_str).collect();
    let promoted_list: Vec<String> = promoted.iter().cloned().collect();
    let promotion_digest = if promoted.is_empty() && displaced.is_empty() && unpromoted.is_empty() {
        None
    } else {
        promotion_digest_of(
            &promoted_list,
            &displaced,
            &unpromoted,
            &json!(promotion_basis),
        )
    };
    let promotion_doc = promotion_digest.as_ref().map(|digest| {
        json!({
            "promoted": promoted_list,
            "displaced": displaced,
            "unpromoted": unpromoted,
            "findings": promotion_basis,
            "digest": digest,
        })
    });
    let effective_digest =
        coverage_plan::effective_review_set_digest(&frozen.review_set, &displaced, &promoted_list)
            .ok()?;

    // Group review paths by content digest; a path without a digest is alone.
    let mut groups: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    for entry in &denominator.entries {
        let in_set = (frozen.review_set.contains(&entry.path)
            && !displaced_set.contains(entry.path.as_str()))
            || promoted.contains(&entry.path);
        if !in_set {
            continue;
        }
        let key = match (&entry.digest, frozen.dedup) {
            (Some(digest), true) => {
                let side = provider
                    .configuration
                    .get("sourceSides")
                    .and_then(|sides| sides.get(&entry.path))
                    .and_then(Value::as_str)
                    .unwrap_or("selected");
                format!("digest:{side}:{digest}")
            }
            _ => format!("path:{}", entry.path),
        };
        groups.entry(key).or_default().push(entry.path.as_str());
    }
    let mut ordered: Vec<(&str, Vec<&str>)> = groups
        .into_values()
        .map(|members| (members[0], members))
        .collect();
    ordered.sort_by(|left, right| left.0.cmp(right.0));
    let mut items = Vec::with_capacity(ordered.len());
    let mut aliases = excerpts::AliasMap::new();
    let mut merged_flags = excerpts::FlaggedRegions::new();
    for (canonical, members) in ordered {
        let mode = members
            .iter()
            .map(|member| mode_of(*member))
            .max_by_key(|mode| mode_strength(*mode))
            .unwrap_or(default_mode);
        for member in &members {
            if let Some(found) = flags.get(*member) {
                merged_flags
                    .entry(canonical.to_owned())
                    .or_default()
                    .extend(found.iter().copied());
            }
        }
        if members.len() > 1 {
            aliases.insert(
                canonical.to_owned(),
                members[1..]
                    .iter()
                    .map(|member| (*member).to_owned())
                    .collect(),
            );
        }
        items.push(excerpts::ReviewItem {
            path: canonical.to_owned(),
            mode,
        });
    }
    let effective_count =
        (frozen.review_set.len() + promoted.len()).saturating_sub(displaced.len());
    let declared_unsampled = denominator.entries.len().saturating_sub(effective_count);
    Some(SampledReview {
        items,
        aliases: aliases.clone(),
        flags: merged_flags,
        binding: ReviewBinding {
            bundle: frozen.bundle.clone(),
            digest: frozen.review_set_digest.clone(),
            review_count: frozen.review_set.len(),
            declared_unsampled,
            excluded: frozen.excluded,
            promoted: promoted_list,
            displaced,
            unpromoted,
            effective_digest,
            promotion_digest,
            promotion_doc,
            aliases,
        },
    })
}

/// Packet inclusion only: selected paths, fully materialized paths, partial
/// chunks & explicit omissions. Delivery needs trusted transport evidence;
/// semantic reading is never inferred from construction. `examinedPaths` is
/// retained as an empty legacy field so no consumer can mistake it for proof.
fn excerpt_coverage_value(
    provider_id: &str,
    part: Option<&excerpts::ExcerptPart>,
    scanner_candidates: Option<&[ScannerCandidate]>,
    denominator_count: usize,
    review: Option<&ReviewBinding>,
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
            if count == chunks && !excerpt.truncated && seen.insert(excerpt.path.as_str()) {
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
        let mut value = json!({
            "basis": "bounded-excerpts",
            "denominatorCount": denominator_count,
            "selectedPaths": part.paths,
            "materializedPaths": examined,
            "examinedPaths": Vec::<&str>::new(),
            "evidenceState": {
                "selection": "selected",
                "materialization": if part.omitted.is_empty() && chunked.is_empty() { "materialized" } else { "partial" },
                "delivery": "unverified",
                "review": "unverified",
            },
            "truncatedPaths": part.excerpts.iter().filter(|excerpt| excerpt.truncated).map(|excerpt| excerpt.path.as_str()).collect::<Vec<_>>(),
            "chunkedPaths": chunked,
            "omittedPaths": part.omitted,
        });
        if let (Some(review), Some(object)) = (review, value.as_object_mut()) {
            // Aliases (identical content) of every canonical path this part
            // carries; ingest credits an alias once its canonical path is
            // fully covered.
            let aliased: Vec<Value> = present
                .keys()
                .filter_map(|canonical| {
                    review.aliases.get(*canonical).map(|aliases| {
                        aliases
                            .iter()
                            .map(|alias| json!({"path": alias, "of": canonical}))
                            .collect::<Vec<_>>()
                    })
                })
                .flatten()
                .collect();
            object.insert(
                "coverageMode".into(),
                json!(coverage_plan::MODE_RISK_SAMPLED),
            );
            object.insert("bundle".into(), json!(review.bundle));
            object.insert("reviewSetDigest".into(), json!(review.digest));
            object.insert("reviewSetCount".into(), json!(review.review_count));
            // The lists live in the promotion file (`promotionRef`), written
            // once per lens; a packet part carries only counts and the digest.
            object.insert("promotedCount".into(), json!(review.promoted.len()));
            object.insert("displacedCount".into(), json!(review.displaced.len()));
            object.insert("unpromotedCount".into(), json!(review.unpromoted.len()));
            object.insert(
                "promotionRef".into(),
                match review.promotion_digest {
                    Some(_) => json!(promotion_file_name(provider_id)),
                    None => Value::Null,
                },
            );
            object.insert(
                "effectiveReviewSetDigest".into(),
                json!(review.effective_digest),
            );
            object.insert("promotionDigest".into(), json!(review.promotion_digest));
            object.insert(
                "declaredUnsampledCount".into(),
                json!(review.declared_unsampled),
            );
            object.insert("excludedCount".into(), json!(review.excluded));
            object.insert("aliasedPaths".into(), Value::Array(aliased));
        }
        return value;
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
    let candidate_gaps = pending_candidate_review_gaps(request, &response.result)?;
    if response.result.complete && !candidate_gaps.is_empty() {
        return Err("complete reasoning result has unresolved candidate dispositions".into());
    }
    if candidate_gaps
        .iter()
        .any(|gap| !response.result.coverage_gaps.contains(gap))
    {
        return Err("reasoning result omits candidate disposition gaps".into());
    }
    let packet_gaps = required_packet_gaps(request);
    if response.result.complete && !packet_gaps.is_empty() {
        return Err(format!(
            "complete reasoning result has required packet gaps: {}",
            packet_gaps.join(", ")
        ));
    }
    if packet_gaps
        .iter()
        .any(|gap| !response.result.coverage_gaps.contains(gap))
    {
        return Err("reasoning result omits required packet gaps".into());
    }
    let staged_gaps = if request.provider_id == ADJUDICATOR_PROVIDER_ID
        && response
            .result
            .details
            .contains_key("adjudicationDeliveryEvidence")
    {
        let candidates: Vec<ScannerCandidate> = serde_json::from_value(
            request
                .packet
                .get("scannerCandidates")
                .cloned()
                .unwrap_or(Value::Null),
        )
        .map_err(|error| format!("adjudication candidates malformed: {error}"))?;
        let context = serde_json::from_value(
            request
                .packet
                .pointer("/candidateWorkItems/triage/context")
                .cloned()
                .unwrap_or_else(|| json!({})),
        )
        .map_err(|error| format!("adjudication triage context malformed: {error}"))?;
        let digest = security_adjudication::adjudication_parent_packet_digest(&request.packet)
            .map_err(|error| error.to_string())?;
        let plan = security_adjudication::build_adjudication_plan(&candidates, &context, &digest)
            .map_err(|error| error.to_string())?;
        let raw = response
            .result
            .details
            .get("rawAdjudicationVerdicts")
            .and_then(Value::as_array)
            .ok_or_else(|| "adjudication raw verdict binding missing".to_owned())?;
        let observations = response
            .result
            .details
            .get("adjudicationDeliveryEvidence")
            .and_then(Value::as_array)
            .ok_or_else(|| "adjudication delivery ledger malformed".to_owned())?;
        Some(
            security_adjudication::validate_stage_observations(
                &plan,
                &candidates,
                raw,
                observations,
            )
            .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };
    if let Some(gaps) = &staged_gaps {
        if response.result.complete && !gaps.is_empty() {
            return Err("complete adjudication has unresolved delivery/verification gaps".into());
        }
        if gaps
            .iter()
            .any(|gap| !response.result.coverage_gaps.contains(gap))
        {
            return Err("adjudication result omits stage evidence gaps".into());
        }
    }
    if response.result.complete && staged_gaps.is_none() {
        let evidence = response
            .result
            .details
            .get("deliveryEvidence")
            .ok_or_else(|| {
                "complete reasoning result lacks authenticated host delivery evidence".to_owned()
            })?;
        validate_delivery_evidence(request, evidence)?;
    }
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
                        return Err(format!(
                            "reasoning result for lens {lens} detail finding {index} is absent from top-level findings"
                        ));
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
    if staged_gaps.is_none() {
        let proof = response.result.details.get("verificationEvidence");
        if let Some(proof) = proof {
            ingest::validate_runtime_verification(request, proof)
                .map_err(|error| error.to_string())?;
        }
        let findings = response
            .result
            .details
            .get("lensFindings")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let withdrawn = response
            .result
            .details
            .get("withdrawnFindings")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let gaps = ingest::verification_projection_gaps(
            &request.provider_id,
            proof,
            &findings,
            &withdrawn,
        )
        .map_err(|error| error.to_string())?;
        if response.result.complete && !gaps.is_empty() {
            return Err("complete reasoning result lacks resolved independent verification".into());
        }
        if gaps
            .iter()
            .any(|gap| !response.result.coverage_gaps.contains(gap))
        {
            return Err("reasoning result omits independent verification gaps".into());
        }
        // Top-level findings also need the detailed, host-verified projection;
        // a trusted receipt must never turn omitted detail rows into clean proof.
        for finding in &response.result.findings {
            let value = serde_json::to_value(finding).map_err(|error| error.to_string())?;
            let id = value.get("id").and_then(Value::as_str);
            if !findings
                .iter()
                .any(|detail| detail.get("id").and_then(Value::as_str) == id)
            {
                return Err(
                    "top-level finding lacks independently verified detailed finding".into(),
                );
            }
        }
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
    /// The provider's promotion document (`promotionRef` content). Never part
    /// of the serialized packet file; `write_lens_packets` writes it once.
    #[serde(skip)]
    pub promotion: Option<Value>,
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
        self.request.part()
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
        self.request.packet_file_name()
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
/// `execution`, preserving frozen generator context for domain lens routing.
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
            let generator = plan
                .providers()
                .iter()
                .find(|provider| provider.id == entry.provider.as_str());
            let source_sides =
                generator.and_then(|provider| provider.configuration.get("sourceSides"));
            security_adjudication::scanner_candidates(root, &entry.provider, &entry.result)
                .into_iter()
                .map(move |mut candidate| {
                    if !candidate.source_mapping.is_object() {
                        candidate.source_mapping =
                            json!({"originalMapping": candidate.source_mapping});
                    }
                    if let Some(generator) = generator {
                        candidate_routing::bind_generator(&mut candidate, generator, &entry.result);
                    }
                    if let Some(path) = &candidate.path {
                        let side = source_sides
                            .and_then(|sides| sides.get(path))
                            .and_then(Value::as_str)
                            .unwrap_or("selected");
                        if !candidate.source_mapping.is_object() {
                            candidate.source_mapping =
                                json!({"originalMapping": candidate.source_mapping});
                        }
                        candidate.source_mapping["sourceSide"] = json!(side);
                        candidate.source_mapping["sourceSideAuthority"] = json!("frozen-plan");
                    }
                    candidate
                })
        })
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.finding_id.cmp(&right.finding_id));
    // A duplicate ID is an accounting error for adjudication to reject,
    // never permission to silently erase a generator's candidate.
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
    let source = excerpts::SourceReader::new(root)?;
    let mut sizer = crate::review_runtime::InitialRequestSizer::default();
    let work = sizer.with_operation(|sizer| {
        if let Some(admission) = source.admission() {
            sizer.use_admission(admission)?;
        }
        pending_lens_work_from_source(plan, inventory, scanner_candidates, &source, sizer)
    });
    source.revalidate()?;
    work
}

fn pending_lens_work_from_source(
    plan: &FrozenPlan,
    inventory: &InventoryEnvelope,
    scanner_candidates: Option<&[ScannerCandidate]>,
    source: &excerpts::SourceReader<'_>,
    sizer: &mut crate::review_runtime::InitialRequestSizer,
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
        let (requests, promotion) = build_invocations(
            plan,
            provider,
            inventory,
            &denominator,
            "pending-host",
            source,
            sizer,
            scanner_candidates,
            true,
        )?;
        for request in requests {
            work.push(PendingLensWork {
                provider_id: provider.id.clone(),
                lens_ids: provider.lens_ids.clone(),
                status: "pending-host".into(),
                request,
                promotion: promotion.clone(),
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

    fn card_part(
        number: usize,
        homed_paths: &[&str],
        continued: Option<&str>,
    ) -> excerpts::ExcerptPart {
        excerpts::ExcerptPart {
            number,
            paths: homed_paths.iter().map(|path| (*path).into()).collect(),
            omitted: Vec::new(),
            excerpts: continued
                .into_iter()
                .map(|path| excerpts::Excerpt {
                    path: path.into(),
                    source_side: "selected",
                    mode: lens_plan::ExcerptMode::Raw,
                    language: "typescript",
                    anchors: vec![format!("{path}:21-40")],
                    content: "RAW source bytes preserved\n".into(),
                    truncated: false,
                    redacted: false,
                    start_line: 21,
                    end_line: 40,
                    chunk: 2,
                    chunks: 2,
                    redacted_ranges: Vec::new(),
                    redaction: excerpts::RedactionCounts::default(),
                })
                .collect(),
        }
    }

    #[test]
    fn pattern_cards_bind_to_each_selected_part_including_continued_source() {
        let base = lens_plan::lens_plan_packet_value("reasoning.correctness").unwrap();
        // A global JS/TS path cannot keep JS/TS cards in an unrelated Rust part.
        let rust = card_part(1, &["src/lib.rs"], None);
        let typescript = card_part(2, &["src/view.tsx"], None);
        // A continued JS/TS chunk must keep cards even with Rust denominator
        // ownership and no homed JS/TS path in this part.
        let continued = card_part(3, &["src/worker.rs"], Some("src/view.tsx"));
        let raw_before = serde_json::to_value(&continued.excerpts).unwrap();
        for (part, expected_count, expected_paths) in [
            (&rust, 2, json!(["src/lib.rs"])),
            (&typescript, 7, json!(["src/view.tsx"])),
            (&continued, 7, json!(["src/view.tsx", "src/worker.rs"])),
        ] {
            let bound =
                lens_plan_for_part(Some(&base), &selected_part_source_paths(Some(part))).unwrap();
            assert_eq!(
                bound["patternCards"].as_array().unwrap().len(),
                expected_count
            );
            assert_eq!(
                bound["patternCardApplicability"]["sourcePaths"],
                expected_paths
            );
        }
        assert_eq!(
            serde_json::to_value(&continued.excerpts).unwrap(),
            raw_before
        );
        assert_eq!(base["patternCards"].as_array().unwrap().len(), 10);
        let empty = lens_plan_for_part(Some(&base), &selected_part_source_paths(None)).unwrap();
        assert_eq!(empty["patternCards"].as_array().unwrap().len(), 10);
        assert!(lens_plan_for_part(None, &["src/lib.rs".into()]).is_none());
    }

    #[test]
    fn security_card_groups_bind_per_part_from_path_evidence() {
        // Totals: 18 security cards = 9 always-on core + 9 evidence-selected.
        // A part with only Rust source drops the 3 specialist cards (no strong
        // evidence) and the 2 JS/TS-only core cards, and keeps the 6 common
        // groups as `unknown`.
        let base = lens_plan::lens_plan_packet_value("reasoning.security").unwrap();
        assert_eq!(base["patternCards"].as_array().unwrap().len(), 18);
        let plain = lens_plan_for_part(Some(&base), &["src/lib.rs".into()]).unwrap();
        assert_eq!(plain["patternCards"].as_array().unwrap().len(), 13);
        let rows = plain["patternCardApplicability"]["cards"]
            .as_array()
            .unwrap();
        let state = |id: &str| {
            rows.iter()
                .find(|row| row["id"] == id)
                .map(|row| row["state"].as_str().unwrap().to_owned())
                .unwrap()
        };
        assert_eq!(state("ssrf-egress-url-fetch"), "unknown");
        assert_eq!(state("smart-contract-reentrancy-access-oracle"), "excluded");
        // Strong specialist evidence in the part keeps the card; empty source
        // stays unknown for every group and drops nothing.
        let contract = lens_plan_for_part(
            Some(&base),
            &["contracts/Vault.sol".into(), "src/lib.rs".into()],
        )
        .unwrap();
        // `.sol` is not a recognized source extension, so the part is no longer
        // all-recognized source and nothing is excluded: the contract card is
        // retained on evidence and every other group stays unknown (fail-safe).
        assert_eq!(contract["patternCards"].as_array().unwrap().len(), 18);
        let contract_state = contract["patternCardApplicability"]["cards"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["id"] == "smart-contract-reentrancy-access-oracle")
            .map(|row| row["state"].as_str().unwrap().to_owned())
            .unwrap();
        assert_eq!(contract_state, "retained");
        let empty = lens_plan_for_part(Some(&base), &selected_part_source_paths(None)).unwrap();
        assert_eq!(empty["patternCards"].as_array().unwrap().len(), 18);
    }

    #[test]
    fn language_card_binding_preserves_whole_lens_scope_and_packet_identity() {
        let base = lens_plan::lens_plan_packet_value("reasoning.correctness").unwrap();
        let mut bound = lens_plan_for_part(Some(&base), &["src/lib.rs".into()]).unwrap();
        let rust_digest = canonical_digest(&bound).unwrap();
        let other_rust = lens_plan_for_part(Some(&base), &["src/other.rs".into()]).unwrap();
        // Source identity, not only the retained-card set, enters packet seals.
        assert_ne!(rust_digest, canonical_digest(&other_rust).unwrap());
        let mut expected_scope = base;
        expected_scope
            .as_object_mut()
            .unwrap()
            .remove("patternCards");
        bound.as_object_mut().unwrap().remove("patternCards");
        bound
            .as_object_mut()
            .unwrap()
            .remove("patternCardApplicability");
        assert_eq!(bound, expected_scope);
    }

    #[test]
    fn seat_card_budget_makes_security_lens_fit_with_deferred_rows() {
        let base = lens_plan::lens_plan_packet_value("reasoning.security").unwrap();
        let seat = ingest::physical_planning_input_bytes(10_000);
        assert_eq!(seat, 15_000);
        let budget = pattern_cards::packet_card_budget_bytes(seat);
        let paths = ["run.sh".to_string(), "README.md".to_string()];
        let bound = lens_plan_for_part_budgeted(Some(&base), &paths, Some(budget)).unwrap();
        let rows = bound["patternCardApplicability"]["cards"].as_array().unwrap();
        assert!(rows
            .iter()
            .any(|row| row["state"] == pattern_cards::DEFERRED_CARD_STATE));
        // The normalized shared-seat reserve is the capped budget, so it is a
        // real bound below the seat target instead of the 24 KB uncapped sum.
        let reserve = pattern_cards::max_card_bytes_bound(Some(budget));
        assert!(pattern_cards::bound_card_bytes(&bound) <= reserve);
        assert!(reserve <= seat);
        assert!(reserve < pattern_cards::max_card_bytes_bound(None));
        // Unbudgeted binding is unchanged: all 18 cards keep bodies.
        let plain = lens_plan_for_part(Some(&base), &paths).unwrap();
        assert_eq!(plain["patternCards"].as_array().unwrap().len(), 18);
    }

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
