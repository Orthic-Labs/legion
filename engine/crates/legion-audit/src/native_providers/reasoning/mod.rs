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

pub mod coverage_plan;
#[cfg(test)]
mod coverage_regressions;
pub mod excerpts;
pub mod followup;
pub mod ingest;
pub mod lens_plan;
pub mod lens_schemas;
pub mod pattern_cards;
pub mod security_adjudication;
pub mod triggers;

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
        let (mut requests, _) = build_invocations(
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
fn trigger_evidence_for(
    root: &Path,
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
            let Some(evaluation) = triggers::evaluate_trigger(root, lens, &paths) else {
                return Ok(None);
            };
            let source_sides = crate::inventory::snapshot_source_sides(root)?;
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
        let actual_sides = crate::inventory::snapshot_source_sides(root)?;
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
            || frozen
                .as_ref()
                .is_some_and(|coverage| !coverage.review_set.contains(path))
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

/// Every scanner candidate belongs to exactly one domain partition. Existing
/// candidate adjudication remains lossless; nonsecurity semantic review needs
/// its own authority contract and is an explicit gap until that stage ships.
pub fn candidate_domain_partitions(candidates: &[ScannerCandidate]) -> Value {
    let mut partitions: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for candidate in candidates {
        let domain = match candidate.domain.as_str() {
            "security" | "data" | "reliability" | "release" => candidate.domain.as_str(),
            _ => "unknown",
        };
        partitions
            .entry(domain)
            .or_default()
            .push(candidate.finding_id.as_str());
    }
    let partitions = partitions.into_iter().map(|(domain, mut ids)| {
        ids.sort_unstable();
        let lens = match domain {
            "security" => Some("security"),
            "data" => Some("data-safety"),
            "reliability" => Some("resilience"),
            "release" => Some("release-readiness"),
            _ => None,
        };
        json!({
            "domain": domain,
            "candidateIds": ids,
            "targetLens": lens,
            "semanticReviewContract": lens.and_then(lens_plan::semantic_review_contract),
            "status": if domain != "unknown" { "candidate-adjudication" } else { "domain-review-unavailable" },
            "adjudicationDomainContract": if domain == "security" { json!(["threatModel", "attackerControl", "reachability", "impact", "proof", "evidence", "devilsAdvocate"]) } else if domain != "unknown" { json!(["domainProof.domain", "domainProof.invariant", "domainProof.trigger", "reachability", "impact", "proof", "evidence", "devilsAdvocate"]) } else { Value::Null },
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
    match evidence
        .get("transportEncoding")
        .and_then(Value::as_str)
        .unwrap_or("literal-packet-v1")
    {
        "literal-packet-v1" => {
            if evidence.get("deliveredPacketBytes").and_then(Value::as_u64) != Some(bytes) {
                return Err("literal delivery evidence does not bind exact packet bytes".into());
            }
        }
        "shared-context-v1" => {
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
            if shared.len() != 1 || !shared.contains_key("excerpts") {
                return Err("shared delivery supports only exact common excerpts".into());
            }
            let shared_digest = canonical_digest(shared).map_err(|error| error.to_string())?;
            if evidence.get("sharedContextDigest").and_then(Value::as_str)
                != Some(shared_digest.as_str())
                || evidence
                    .get("reconstructedPacketBytes")
                    .and_then(Value::as_u64)
                    != Some(bytes)
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
                    if field != "excerpts"
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
            if Value::Object(restored) != request.packet {
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
    root: &Path,
    scanner_candidates: Option<&[ScannerCandidate]>,
) -> Result<(Vec<ReasoningInvocation>, Option<Value>), AuditError> {
    let mut budget = seat_part_budget(provider);
    let seat_tokens = provider
        .configuration
        .get("coverage")
        .and_then(|coverage| coverage.get("seatTokenBudget"))
        .and_then(Value::as_u64);
    let target = seat_tokens.map(|tokens| {
        tokens.saturating_mul(4).saturating_sub(
            coverage_plan::SEAT_PACKET_RESERVE_BYTES as u64
                + crate::next::DEFAULT_OUTPUT_TOKENS.saturating_mul(4),
        )
    });
    // Refine only materialization, never the frozen review set, promotion order,
    // part ceiling or scope. Every candidate is rebuilt from the same inputs.
    // A single irreducible chunk still reaches normal explicit size refusal.
    for attempt in 0..8 {
        let built = build_invocations_with_budget(
            plan,
            provider,
            inventory,
            denominator,
            invocation_epoch,
            root,
            scanner_candidates,
            budget,
        )?;
        let (Some(target), Some(current)) = (target, budget) else {
            return Ok(built);
        };
        let mut largest = 0u64;
        for request in &built.0 {
            let work = PendingLensWork {
                provider_id: provider.id.clone(),
                lens_ids: provider.lens_ids.clone(),
                status: "pending-host".into(),
                request: request.clone(),
                promotion: None,
            };
            let size = serde_json::to_vec_pretty(&work)
                .map_err(|error| AuditError::Invalid(error.to_string()))?
                .len() as u64;
            largest = largest.max(size);
        }
        if largest <= target || attempt == 7 {
            return Ok(built);
        }
        let ratio_cap =
            (current.cap_bytes as u128).saturating_mul(target as u128) / largest.max(1) as u128;
        let next_cap = usize::try_from(ratio_cap)
            .unwrap_or(current.cap_bytes)
            .saturating_sub(1024)
            .max(1);
        if next_cap >= current.cap_bytes {
            return Ok(built);
        }
        budget = Some(excerpts::PartBudget {
            cap_bytes: next_cap,
            ..current
        });
    }
    unreachable!("bounded packet refinement returns on its final attempt")
}

fn build_invocations_with_budget(
    plan: &FrozenPlan,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
    denominator: &InventoryDenominator,
    invocation_epoch: &str,
    root: &Path,
    scanner_candidates: Option<&[ScannerCandidate]>,
    part_budget: Option<excerpts::PartBudget>,
) -> Result<(Vec<ReasoningInvocation>, Option<Value>), AuditError> {
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
    let actual_sides = crate::inventory::snapshot_source_sides(root)?;
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
    let trigger_evidence = trigger_evidence_for(root, provider, inventory, &paths)?;
    let sampled = base_mode.and_then(|mode| {
        sampled_review(
            root,
            provider,
            denominator,
            scanner_candidates,
            mode,
            &changed_hunks,
            part_budget.map_or(0, |budget| budget.listing_copies),
        )
    });
    let partition = match (&sampled, base_mode) {
        (Some(sampled), _) => Some(excerpts::partition_review_set_budgeted(
            root,
            &sampled.items,
            &sampled.aliases,
            ceiling,
            &changed_hunks,
            &sampled.flags,
            part_budget,
        )),
        (None, Some(mode)) => Some(excerpts::partition_excerpts_budgeted(
            root,
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
            "lensPlan": lens_plan,
            "excerpts": excerpts_value,
            "excerptCoverage": excerpt_coverage,
            "scannerCandidates": candidates_value,
            "triggerEvidence": trigger_evidence,
            "sourceSides": provider.configuration.get("sourceSides").cloned().unwrap_or_else(|| json!({})),
            "reportSchemaBody": report_schema_body,
            "semanticReviewContract": semantic_contract,
            "changeRiskContract": change_risk_contract,
            "reviewContext": review_context,
            "inventoryRef": inventory_ref.clone(),
            "artifactIds": [],
        });
        // === LANE B BOUNDARY: security adjudicator packet construction. ===
        // Everything inside this `if` belongs to security_adjudication.rs and
        // wf064 finalize (batched adjudication); lane A does not edit it.
        if provider.id == ADJUDICATOR_PROVIDER_ID {
            packet["candidateRouting"] = scanner_candidates
                .map(candidate_domain_partitions)
                .unwrap_or(Value::Null);
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
    root: &Path,
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
        excerpts::review_item_cost(
            root,
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
                let plain =
                    excerpts::review_item_cost(root, &item, hunks, &unflagged, listing_copies);
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
            let source_sides = plan
                .providers()
                .iter()
                .find(|provider| provider.id == entry.provider.as_str())
                .and_then(|provider| provider.configuration.get("sourceSides"));
            security_adjudication::scanner_candidates(root, &entry.provider, &entry.result)
                .into_iter()
                .map(move |mut candidate| {
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
            root,
            scanner_candidates,
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
