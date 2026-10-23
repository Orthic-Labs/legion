//! Dispatch for the three attack-path providers:
//! `security.surface-model` -> `security.attack-path-synthesis` ->
//! `security.chain-adjudication`.
//!
//! Each provider is derived only from the frozen inventory (and the audited
//! root's bytes, verified against inventory digests) plus host-injected
//! artifacts keyed by artifact kind. The pure builders live in
//! `surface_model`, `attack_paths` and `chain_adjudication`; this module owns
//! the provider contract around them and the fail-closed rules:
//!
//! * A missing root, unresolvable frozen denominator, missing or unbound
//!   model, or zero typed candidates is an explicit gap, never "no paths".
//! * Synthesis never adjudicates. Chain adjudication runs `adjudicate_chain`
//!   only on host-injected independent assessments
//!   (`artifacts["security.chain-adjudication"]`); without them every
//!   hypothesis is reported as pending and the provider as unproven. The
//!   deterministic pass never self-adjudicates.
//! * Results never carry findings, verdict-self-certification flags or a
//!   "proven" state beyond what `adjudicate_chain` itself returns.
//!
//! Host-injected artifacts (all optional, all treated as untrusted shape):
//! * `security-model`: a `legion-security-model` document replacing the
//!   derived model (its binding must match the frozen inventory).
//! * `security-candidates`: a candidate list or `{candidates: [...]}` (v2)
//!   replacing pack-derived candidates.
//! * `security.chain-adjudication`: `{adjudicator: {provider, contextId},
//!   memberVerdicts: [...], assessments: [{pathId, ...raw assessment}],
//!   requiredStrength?}`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderStatus};
use serde_json::{json, Value};

use crate::{
    error::AuditError,
    inventory::InventoryEnvelope,
    native_providers::{
        availability,
        p11d_quality::security_suite::{self, Limits},
    },
    plan::AuditProvider,
    source_cache::bytes_digest,
};

use super::{
    attack_paths::{self, Bounds, Registry},
    chain_adjudication::{self, adjudicate_chain, ChainAdjudicationInput, Strength},
    common::digest_json,
    packs,
    surface_model::{self, build_security_model, SurfaceModelInput},
};

pub const MODEL_ARTIFACT: &str = "security-model";
pub const CANDIDATES_ARTIFACT: &str = "security-candidates";
pub const VERDICTS_ARTIFACT: &str = "security-chain-verdicts";

const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

/// Whether `id` is dispatched through this module.
pub fn is_pipeline_provider(id: &str) -> bool {
    matches!(
        id,
        surface_model::PROVIDER_ID | attack_paths::PROVIDER_ID | chain_adjudication::PROVIDER_ID
    )
}

/// Execute one of the three providers. `root` is the audited root and
/// `injected` the host-injected artifacts (see module docs).
pub fn execute(
    root: Option<&Path>,
    injected: &BTreeMap<String, Value>,
    provider: &AuditProvider,
    inventory: &InventoryEnvelope,
) -> Result<ProviderResult, AuditError> {
    let provider_id = ProviderId::new(provider.id.clone())?;
    let base = |applicable: bool, coverage: Option<Coverage>| ProviderResult {
        schema_version: 1,
        provider: provider_id.clone(),
        applicable,
        required: provider.required,
        status: ProviderStatus::Partial,
        complete: false,
        coverage,
        findings: Vec::new(),
        coverage_gaps: Vec::new(),
        degradation: Vec::new(),
        details: Default::default(),
    };
    let Some(frozen) = Frozen::resolve(provider, inventory) else {
        let mut result = base(true, None);
        availability::mark_unavailable(
            &mut result,
            &format!("frozen-denominator-unresolvable:{}", provider.id),
        );
        return Ok(result);
    };
    if frozen.count == 0 || frozen.paths.is_empty() {
        // Selector matches nothing: not applicable, never complete.
        let mut result = base(false, None);
        result.details.insert("candidates".into(), json!([]));
        return Ok(result);
    }
    let coverage = |examined: u64, gaps: Vec<String>| Coverage {
        denominator_digest: frozen.digest.clone(),
        expected: frozen.count,
        examined: examined.min(frozen.count),
        gaps,
    };

    match provider.id.as_str() {
        surface_model::PROVIDER_ID => {
            let Some(root) = root else {
                let mut result = base(true, Some(coverage(0, Vec::new())));
                availability::mark_unavailable(
                    &mut result,
                    &format!("root-not-supplied:{}", provider.id),
                );
                return Ok(result);
            };
            let built = build_model(root, inventory);
            let model = &built.model;
            let examined = frozen
                .paths
                .iter()
                .filter(|path| built.verified.contains(*path))
                .count() as u64;
            let blocking: Vec<String> = model
                .gaps
                .iter()
                .filter(|gap| gap.blocking)
                .map(|gap| to_gap_string(&json!({"kind": gap.kind, "reason": gap.reason, "pathCount": gap.path_count})))
                .collect();
            let complete =
                blocking.is_empty() && !model.coverage.truncated && examined == frozen.count;
            let mut result = base(true, Some(coverage(examined, blocking.clone())));
            result.complete = complete;
            result.status = if complete {
                ProviderStatus::Complete
            } else {
                ProviderStatus::Partial
            };
            result.coverage_gaps = blocking;
            result.details.insert(
                "analysis".into(),
                json!({
                    "kind": "audit-security-surface-model",
                    "complete": complete,
                    "denominator": {"kind": "first-party-source-files", "expected": frozen.count, "examined": examined},
                    "entityCount": model.entities.len(),
                    "relationCount": model.relations.len(),
                    "gapCount": model.gaps.len(),
                    "modelDigest": model.digest,
                    "claims": {"exhaustive": false, "noAttackSurface": false},
                    "skippedUnreadable": built.skipped.len(),
                }),
            );
            result
                .details
                .insert(MODEL_ARTIFACT.into(), model.to_value());
            result.details.insert(
                "producer".into(),
                producer_detail(surface_model::PROVIDER_ID),
            );
            Ok(result)
        }
        attack_paths::PROVIDER_ID => {
            let synth = synthesize_from_frozen(root, injected, &frozen.paths, inventory);
            let doc = &synth.document;
            let unproven = doc["coverage"] == "UNPROVEN";
            let gaps = doc_gaps(doc);
            let complete = doc["coverage"] == "BOUNDED_COMPLETE" && gaps.is_empty();
            let examined = if unproven { 0 } else { frozen.count };
            let mut result = base(true, Some(coverage(examined, gaps.clone())));
            result.complete = complete;
            result.status = if complete {
                ProviderStatus::Complete
            } else {
                ProviderStatus::Partial
            };
            result.coverage_gaps = gaps;
            result.details.insert(
                "analysis".into(),
                json!({
                    "kind": "audit-attack-path-synthesis",
                    "status": doc["coverage"],
                    "complete": complete,
                    "denominator": {"kind": "attack-path-candidates", "expected": frozen.count, "examined": examined},
                    "hypothesisCount": doc["counts"]["hypotheses"],
                    "claims": doc["claims"],
                    "modelPresent": doc["inputs"]["modelPresent"],
                    "candidateCount": doc["inputs"]["candidateCount"],
                }),
            );
            result.details.insert("attackPaths".into(), synth.document);
            result.details.insert(
                "producer".into(),
                producer_detail(attack_paths::PROVIDER_ID),
            );
            Ok(result)
        }
        _ => {
            let synth = synthesize_from_frozen(root, injected, &frozen.paths, inventory);
            let doc = adjudicate_all(&synth, injected.get(chain_adjudication::PROVIDER_ID));
            let gaps = doc_gaps(&doc);
            let complete = gaps.is_empty();
            let examined = if complete { frozen.count } else { 0 };
            let mut result = base(true, Some(coverage(examined, gaps.clone())));
            result.complete = complete;
            result.status = if complete {
                ProviderStatus::Complete
            } else {
                ProviderStatus::Partial
            };
            result.coverage_gaps = gaps;
            result.details.insert(
                "analysis".into(),
                json!({
                    "kind": "audit-chain-adjudication",
                    "status": doc["status"],
                    "complete": complete,
                    "denominator": {"kind": "attack-path-hypotheses", "expected": frozen.count, "examined": examined},
                    "hypothesisCount": doc["hypothesisCount"],
                    "pendingCount": doc["pending"].as_array().map_or(0, Vec::len),
                    "claims": doc["claims"],
                }),
            );
            result.details.insert("chainVerdicts".into(), doc);
            result.details.insert(
                "producer".into(),
                producer_detail(chain_adjudication::PROVIDER_ID),
            );
            Ok(result)
        }
    }
}

fn producer_detail(provider: &str) -> Value {
    json!({
        "mode": "native-deterministic",
        "provider": provider,
        "evidence": "native-heuristic",
        "network": false,
        "selfAdjudicates": false,
    })
}

fn to_gap_string(gap: &Value) -> String {
    serde_json::to_string(gap).unwrap_or_else(|_| "coverage-gap".into())
}

fn doc_gaps(doc: &Value) -> Vec<String> {
    doc["coverageGaps"]
        .as_array()
        .map(|gaps| gaps.iter().map(to_gap_string).collect())
        .unwrap_or_default()
}

struct Frozen {
    digest: String,
    count: u64,
    paths: Vec<String>,
}

impl Frozen {
    fn resolve(provider: &AuditProvider, inventory: &InventoryEnvelope) -> Option<Self> {
        let selector = provider.configuration.get("selector")?;
        let computed = inventory.denominator_entries(selector).ok()?;
        let digest = provider
            .configuration
            .get("denominatorDigest")
            .and_then(Value::as_str)
            .map_or_else(|| computed.digest.clone(), str::to_owned);
        let count = provider
            .configuration
            .get("denominatorCount")
            .and_then(Value::as_u64)
            .unwrap_or(computed.entries.len() as u64);
        Some(Self {
            digest,
            count,
            paths: computed.entries.into_iter().map(|e| e.path).collect(),
        })
    }
}

fn safe_relative(path: &str) -> bool {
    let p = Path::new(path);
    !path.is_empty()
        && !p.is_absolute()
        && p.components().all(|c| matches!(c, Component::Normal(_)))
}

struct BuiltModel {
    model: surface_model::SecurityModel,
    /// Inventory paths whose frozen bytes were read and match the inventory digest.
    verified: BTreeSet<String>,
    skipped: Vec<String>,
}

/// Read the inventory's bytes from `root` (bounded, symlink-free) and build the
/// model. Anything unread becomes the model's own blocking gap.
fn build_model(root: &Path, inventory: &InventoryEnvelope) -> BuiltModel {
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut total = 0u64;
    for entry in &inventory.entries {
        let path = &entry.path;
        if !safe_relative(path) {
            skipped.push(path.clone());
            continue;
        }
        let full = root.join(path);
        let Ok(meta) = std::fs::symlink_metadata(&full) else {
            skipped.push(path.clone());
            continue;
        };
        if meta.file_type().is_symlink()
            || !meta.is_file()
            || meta.len() > MAX_FILE_BYTES
            || total.saturating_add(meta.len()) > MAX_TOTAL_BYTES
        {
            skipped.push(path.clone());
            continue;
        }
        match std::fs::read(&full) {
            Ok(bytes) => {
                total += bytes.len() as u64;
                files.insert(path.clone(), bytes);
            }
            Err(_) => skipped.push(path.clone()),
        }
    }
    let verified = inventory
        .entries
        .iter()
        .filter(|entry| {
            let Some(bytes) = files.get(&entry.path) else {
                return false;
            };
            entry
                .digest
                .as_deref()
                .and_then(|d| d.strip_prefix("sha256:"))
                == Some(bytes_digest(bytes).as_str())
        })
        .map(|entry| entry.path.clone())
        .collect();
    let model = build_security_model(&SurfaceModelInput {
        inventory,
        files: &files,
        graph: None,
        repository_revision: &inventory.generation,
        plan_digest: None,
        cortex_generation_id: None,
    });
    BuiltModel {
        model,
        verified,
        skipped,
    }
}

struct Synthesis {
    document: Value,
    binding: Value,
    context_id: String,
    model: Option<Value>,
}

fn plan_binding(inventory: &InventoryEnvelope) -> Value {
    json!({"repositoryRevision": inventory.generation, "digest": inventory.digest})
}

fn add_gap(doc: &mut Value, code: &str, detail: String) {
    if let Some(list) = doc.get_mut("coverageGaps").and_then(Value::as_array_mut) {
        list.push(json!({"code": code, "detail": detail}));
        let n = list.len();
        doc["counts"]["coverageGaps"] = json!(n);
    }
    if doc["coverage"] == "BOUNDED_COMPLETE" {
        doc["coverage"] = json!("TRUNCATED");
    }
}

/// Derive the synthesis document from the frozen inputs: injected or derived
/// model, injected or pack-derived candidates, default bounds. Pure given its
/// inputs, so the chain provider recomputes it instead of reading prior state.
fn synthesize_from_frozen(
    root: Option<&Path>,
    injected: &BTreeMap<String, Value>,
    synth_paths: &[String],
    inventory: &InventoryEnvelope,
) -> Synthesis {
    let binding = plan_binding(inventory);
    let mut extra_gaps: Vec<(&str, String)> = Vec::new();

    let mut model: Option<Value> = None;
    if let Some(injected_model) = injected.get(MODEL_ARTIFACT) {
        if chain_adjudication::model_binding_matches(injected_model, &binding) {
            model = Some(injected_model.clone());
        } else {
            extra_gaps.push((
                "security-model-binding-mismatch",
                "injected security model is not bound to the frozen inventory; it was discarded"
                    .into(),
            ));
        }
    } else if let Some(root) = root {
        model = Some(build_model(root, inventory).model.to_value());
    }

    let mut candidates: Option<Value> = injected.get(CANDIDATES_ARTIFACT).cloned();
    if candidates.is_none() {
        if let Some(root) = root {
            let mut all = Vec::new();
            for (provider_id, pack) in packs::PACK_PROVIDERS {
                match security_suite::generate_security_candidates_bounded(
                    root,
                    synth_paths,
                    pack,
                    Some(provider_id),
                    &Limits::default(),
                ) {
                    Ok(report) => {
                        if let Some(list) = report["candidates"].as_array() {
                            all.extend(list.iter().cloned());
                        }
                        if report["complete"] != true {
                            extra_gaps.push((
                                "candidate-generation-incomplete",
                                format!("pack {pack} reported coverage gaps"),
                            ));
                        }
                    }
                    Err(error) => extra_gaps.push((
                        "candidate-generation-failed",
                        format!("pack {pack}: {error}"),
                    )),
                }
            }
            candidates = Some(Value::Array(all));
        }
    }

    let mut document = match Registry::embedded() {
        Ok(registry) => attack_paths::synthesize(
            model.as_ref(),
            candidates.as_ref(),
            &Bounds::default(),
            &registry,
        ),
        // Cannot synthesize without the packaged objective/bridge registry.
        Err(error) => attack_paths::registry_unavailable(&Bounds::default(), &error),
    };
    for (code, detail) in extra_gaps {
        add_gap(&mut document, code, detail);
    }
    let context_id = format!(
        "ctx:synthesis:{}",
        &digest_json(&json!({
            "provider": attack_paths::PROVIDER_ID,
            "binding": binding,
            "inputs": document["inputs"],
        }))[7..39]
    );
    attack_paths::bind_hypotheses(&mut document, &binding, &context_id);
    Synthesis {
        document,
        binding,
        context_id,
        model,
    }
}

/// Adjudicate (or leave pending) every hypothesis. Only host-injected
/// independent assessments produce a verdict; otherwise the hypothesis is
/// pending and the document `UNPROVEN`.
fn adjudicate_all(synth: &Synthesis, injected: Option<&Value>) -> Value {
    let hypotheses: Vec<&Value> = synth.document["hypotheses"]
        .as_array()
        .map(|list| list.iter().collect())
        .unwrap_or_default();
    let list = |key: &str| -> Vec<Value> {
        injected
            .and_then(|i| i.get(key))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let member_verdicts = list("memberVerdicts");
    let assessments = list("assessments");
    let adjudicator = injected
        .and_then(|i| i.get("adjudicator"))
        .cloned()
        .unwrap_or(Value::Null);
    let required = injected
        .and_then(|i| i.get("requiredStrength"))
        .and_then(Value::as_str)
        .and_then(Strength::parse)
        .unwrap_or(Strength::StrongInference);
    let synthesizer = json!({
        "provider": attack_paths::PROVIDER_ID,
        "contextId": synth.context_id,
    });

    let mut verdicts = Vec::new();
    let mut pending = Vec::new();
    let mut proven = 0usize;
    for hypothesis in &hypotheses {
        let id = hypothesis["id"].as_str().unwrap_or_default();
        let raw = assessments
            .iter()
            .find(|a| a.get("pathId").and_then(Value::as_str) == Some(id));
        match raw {
            None => pending.push(json!({
                "pathId": id,
                "state": "PENDING_INDEPENDENT_ADJUDICATION",
                "reason": "no independent chain assessment was supplied; the deterministic pass never self-adjudicates",
                "requires": {
                    "memberVerdicts": hypothesis["memberCandidateIds"],
                    "joinIds": hypothesis["joins"].as_array().map(|j| j.iter().filter_map(|x| x.get("id").cloned()).collect::<Vec<_>>()),
                    "chainAssessment": true,
                    "distinctProviderAndContext": true,
                },
            })),
            Some(raw) => {
                let verdict = adjudicate_chain(ChainAdjudicationInput {
                    hypothesis,
                    member_verdicts: &member_verdicts,
                    expected_binding: &synth.binding,
                    synthesizer: &synthesizer,
                    adjudicator: &adjudicator,
                    raw_assessment: raw,
                    required_strength: required,
                });
                if verdict.verdict == "PROVEN" {
                    proven += 1;
                }
                verdicts.push(verdict.value);
            }
        }
    }

    let synthesis_coverage = synth.document["coverage"].as_str().unwrap_or("UNPROVEN");
    let mut gaps: Vec<Value> = Vec::new();
    if synthesis_coverage == "UNPROVEN" {
        gaps.push(json!({
            "code": "synthesis-unproven",
            "detail": "attack-path synthesis is unproven; there is nothing established to adjudicate and absence of chains is not shown",
            "synthesisGaps": synth.document["coverageGaps"],
        }));
    } else if synthesis_coverage == "TRUNCATED" {
        gaps.push(json!({
            "code": "synthesis-truncated",
            "detail": "attack-path synthesis was bounded or incomplete; adjudicated chains are not exhaustive",
        }));
    }
    if !pending.is_empty() {
        gaps.push(json!({
            "code": "chain-adjudication-pending",
            "detail": format!("{} hypothesis(es) await independent adjudication; no adjudicator verdicts were supplied", pending.len()),
        }));
    }
    let unproven_verdicts = verdicts
        .iter()
        .filter(|v| v["verdict"] == "UNPROVEN")
        .count();
    if unproven_verdicts > 0 {
        gaps.push(json!({
            "code": "chain-verdict-unproven",
            "detail": format!("{unproven_verdicts} adjudicated chain(s) failed a gate and remain unproven"),
        }));
    }
    let status = if gaps.is_empty() {
        "ADJUDICATED"
    } else {
        "UNPROVEN"
    };
    json!({
        "schemaVersion": 1,
        "kind": VERDICTS_ARTIFACT,
        "provider": chain_adjudication::PROVIDER_ID,
        "status": status,
        "authority": {"selfAdjudicates": false, "independentAdjudicationRequired": true},
        "binding": synth.binding,
        "synthesizer": synthesizer,
        "modelPresent": synth.model.is_some(),
        "hypothesisCount": hypotheses.len(),
        "verdicts": verdicts,
        "pending": pending,
        "claims": {"chainsProven": proven, "exhaustive": false},
        "coverageGaps": gaps,
    })
}
