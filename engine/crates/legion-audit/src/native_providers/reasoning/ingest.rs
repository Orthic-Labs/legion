//! Trusted ingest of reasoning-lens results produced by session subagents.
//!
//! `legion audit --out <dir>` freezes a run, writes one `pending-host` lens
//! packet per applicable reasoning provider, and generates a random per-run
//! epoch key. The CLI process is the trusted reasoning host: a subagent runs a
//! packet and hands back a result file, and `ingest_lens_result` validates it
//! against the frozen run, checks that every finding (and every withdrawal)
//! carries a verbatim code anchor that matches the file bytes at the frozen
//! revision, and only then MACs a receipt with the epoch key. `recompute_run`
//! rebuilds the verdict from the original execution plus the ingested
//! receipts, so a reasoning lens counts as having run only through an ingested,
//! MAC-verified receipt.
//!
//! The MAC proves the receipt was minted by the CLI during validation of this
//! run; the anchor check is what makes the result content falsifiable.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use hmac::{Hmac, KeyInit, Mac};
use legion_contracts::{
    canonical_digest, canonical_json_bytes, Coverage, FindingId, FindingRef, ProviderId,
    ProviderResult, ProviderStatus, ReportStatus, ReportV1,
};
use serde::Serialize;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::{
    authenticate_receipt, coverage_plan, followup, lens_plan, lens_schemas, promotion_digest_of,
    promotion_file_name,
    security_adjudication::{
        adjudicate_scanner_candidates, adjudication_parent_packet_digest, adjudication_work_items,
        build_adjudication_plan, confirmed_findings, confirmed_paths, evaluate_adjudication,
        ConfirmedSecurityFinding, ScannerCandidate, TriageContext, ADJUDICATOR_PROVIDER_ID,
    },
    verify_authenticated_receipt, verify_response, LensPartRef, PendingLensWork,
    ReasoningHostResponse, ReasoningInvocation, ReasoningReceipt, REASONING_PROVIDER_IDS,
    REASONING_RECEIPT_KIND, REASONING_RECEIPT_SCHEMA_VERSION,
};
use crate::plan::{AuditPlan, PROVIDER_UNIVERSE_BOUND};

const VISUAL_PROVIDER_ID: &str = "legacy.visual.core";
const VISUAL_PLAN_BINDING_UNAVAILABLE: &str = "visual-plan-binding-unavailable";
use crate::{
    error::AuditError,
    execution::ExecutionReport,
    inventory::{FilesystemInventorySource, InventoryDenominator, InventorySource},
    report::canonical_report,
};

pub const EPOCH_KEY_FILE: &str = "epoch.key";
pub const LENS_PACKET_DIR: &str = "lens-packets";
pub const LENS_RECEIPT_DIR: &str = "lens-receipts";
pub const INGEST_HOST: &str = "legion-cli-ingest";
pub const LENS_RESULT_KIND: &str = "legion-lens-result";
const EPOCH_DOMAIN: &[u8] = b"legion-audit-epoch:v1";
/// Prominent label of a risk-sampled run (Astra D2).
pub const SAMPLED_AUDIT_LABEL: &str = "whole-repository risk-sampled audit";
const NOT_COMPLETE_GAP: &str = "selected reasoning lenses did not complete";

const RUNTIME_DELIVERY_DIR: &str = "runtime-delivery";
const RUNTIME_DELIVERY_DOMAIN: &str = "legion-audit-runtime-delivery:v1";
const RUNTIME_CALL_DOMAIN: &str = "legion-audit-runtime-call:v1";

fn redact_call_diagnostic(value: &Value) -> Value {
    match value {
        Value::String(text) => json!(super::excerpts::redact_lines(text)
            .into_iter()
            .map(|line| line.text)
            .collect::<Vec<_>>()
            .join("\n")),
        Value::Array(items) => Value::Array(items.iter().map(redact_call_diagnostic).collect()),
        Value::Object(items) => Value::Object(
            items
                .iter()
                .map(|(key, value)| {
                    let normalized = key.to_ascii_lowercase().replace('-', "").replace('_', "");
                    let sensitive = [
                        "password",
                        "secret",
                        "apikey",
                        "accesstoken",
                        "refreshtoken",
                        "authorization",
                        "credential",
                        "privatekey",
                    ]
                    .iter()
                    .any(|part| normalized.contains(part));
                    let value = if sensitive && value.is_string() {
                        json!("[REDACTED]")
                    } else {
                        redact_call_diagnostic(value)
                    };
                    (key.clone(), value)
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn bounded_call_action(action: Option<&Value>) -> Value {
    let Some(action) = action else {
        return json!({"kind":"unavailable"});
    };
    let kind = action
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    let diagnostic = match kind {
        "toolRequest" => {
            let tool = action.get("toolRequest");
            json!({"kind":"toolRequest","toolRequest":{
                "tool":tool.and_then(|value|value.get("tool")).and_then(Value::as_str).filter(|name|["audit.read_file","audit.search_code","audit.list_files","audit.read_diff","audit.find_callers"].contains(name)),
                "arguments":redact_call_diagnostic(&tool.and_then(|value|value.get("arguments")).cloned().unwrap_or(Value::Null))
            },"truncated":action.get("truncated").and_then(Value::as_bool).unwrap_or(false)})
        }
        "finalResult" => {
            json!({"kind":"finalResult","complete":action.get("complete").and_then(Value::as_bool),"findingCount":action.get("findingCount").and_then(Value::as_u64)})
        }
        "other-structured-result" => json!({"kind":"other-structured-result"}),
        _ => json!({"kind":"unavailable"}),
    };
    if diagnostic.to_string().len() <= 8192 {
        diagnostic
    } else {
        json!({"kind":"toolRequest","toolRequest":{"tool":null,"arguments":null},"truncated":true})
    }
}

fn runtime_call_message(run_dir: &Path, receipt: &Value, epoch: &str) -> Result<Value, AuditError> {
    let sha256 = |value: Option<&Value>| {
        value.and_then(Value::as_str).is_some_and(|text| {
            text.strip_prefix("sha256:").is_some_and(|hex| {
                hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            })
        })
    };
    let call_id = receipt
        .get("callId")
        .and_then(Value::as_str)
        .filter(|id| !id.trim().is_empty() && id.len() <= 512)
        .ok_or_else(|| invalid("runtime call ID missing/invalid"))?;
    let allowed = [
        "schemaVersion",
        "kind",
        "callId",
        "seatId",
        "requestDigest",
        "snapshotKey",
        "requestBytes",
        "requestAccounting",
        "initialContext",
        "authorization",
        "observation",
        "modelAction",
        "budget",
        "execution",
    ];
    if receipt.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || receipt.get("kind").and_then(Value::as_str) != Some("legion-runtime-call")
        || !receipt
            .as_object()
            .is_some_and(|object| object.keys().all(|key| allowed.contains(&key.as_str())))
        || !sha256(receipt.get("requestDigest"))
        || !sha256(receipt.get("snapshotKey"))
        || receipt
            .get("requestBytes")
            .and_then(Value::as_u64)
            .is_none_or(|bytes| bytes == 0)
        || receipt.pointer("/observation/physicalRequestDigest") != receipt.get("requestDigest")
        || receipt.pointer("/observation/physicalRequestBytes") != receipt.get("requestBytes")
        || receipt.pointer("/authorization/authorized") != Some(&json!(true))
        || receipt
            .pointer("/authorization/callId")
            .and_then(Value::as_str)
            != Some(call_id)
    {
        return Err(invalid("runtime call identity/accounting binding invalid"));
    }
    let observation = receipt
        .get("observation")
        .and_then(Value::as_object)
        .ok_or_else(|| invalid("runtime call observation missing"))?;
    if let Some(execution) = receipt.get("execution") {
        crate::review_runtime::validate_execution_metadata(execution)?;
    }
    let observation_fields = [
        "contextId",
        "processId",
        "processCreated",
        "processCreationTicks",
        "processCreationTime",
        "responseDigest",
        "sent",
        "error",
        "usage",
        "rawUsage",
        "reportedApiEquivalentCostUsd",
        "invoiceChargeUsd",
        "physicalRequestDigest",
        "physicalRequestBytes",
        "observedModels",
        "modelPolicyViolation",
    ];
    if observation
        .keys()
        .any(|key| !observation_fields.contains(&key.as_str()))
    {
        return Err(invalid(
            "runtime call contains unbounded observation fields",
        ));
    }
    if observation.get("observedModels").is_some_and(|models| {
        !models.as_array().is_some_and(|models| {
            models.len() <= 16
                && models.iter().all(|model| {
                    model
                        .as_str()
                        .is_some_and(|model| !model.is_empty() && model.len() <= 256)
                })
        })
    }) {
        return Err(invalid("runtime observed models exceed bounded metadata"));
    }
    if observation
        .get("modelPolicyViolation")
        .is_some_and(|violation| {
            !violation.is_null()
                && !matches!(
                    violation.as_str(),
                    Some("missing-observation" | "unauthorized-model")
                )
        })
    {
        return Err(invalid("runtime model policy classification invalid"));
    }
    if observation
        .get("reportedApiEquivalentCostUsd")
        .is_some_and(|cost| {
            !cost.is_null()
                && !cost.as_str().is_some_and(|value| {
                    crate::review_runtime::cost::normalize(value).as_deref() == Some(value)
                })
        })
        || observation
            .get("invoiceChargeUsd")
            .is_some_and(|cost| !cost.is_null())
    {
        return Err(invalid(
            "runtime call cost must be bounded canonical USD or unknown",
        ));
    }
    if receipt
        .get("initialContext")
        .is_some_and(|context| context.to_string().len() > 32 * 1024)
    {
        return Err(invalid("runtime call initial context exceeds byte cap"));
    }
    let plan = read_json(&run_dir.join("plan.json"))?;
    if plan.pointer("/epoch/digest").and_then(Value::as_str) != Some(epoch)
        || plan.pointer("/reviewContext/snapshotKey") != receipt.get("snapshotKey")
    {
        return Err(invalid(
            "runtime call does not bind this run epoch/snapshot",
        ));
    }
    let mut evidence = redact_call_diagnostic(receipt);
    evidence["modelAction"] = bounded_call_action(receipt.get("modelAction"));
    if canonical_json_bytes(&evidence)
        .map_err(|error| invalid(error.to_string()))?
        .len()
        > 256 * 1024
    {
        return Err(invalid("runtime call diagnostic exceeds byte cap"));
    }
    Ok(
        json!({"schemaVersion":1,"kind":"legion-audit-runtime-call","macDomain":RUNTIME_CALL_DOMAIN,
        "epochDigest":epoch,"callId":call_id,"requestDigest":receipt.get("requestDigest"),
        "snapshotKey":receipt.get("snapshotKey"),"evidence":evidence}),
    )
}

/// Host-only diagnostic receipt. The MAC authenticates host observations;
/// modelAction remains redacted diagnostic data, never delivery/review proof.
/// Caller persists this returned envelope beside the existing call trace.
pub fn mint_runtime_call(run_dir: &Path, receipt: &Value) -> Result<Value, AuditError> {
    let (key, epoch) = load_epoch(run_dir)?;
    let message = runtime_call_message(run_dir, receipt, &epoch)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key).map_err(|error| invalid(error.to_string()))?;
    mac.update(&canonical_json_bytes(&message).map_err(|error| invalid(error.to_string()))?);
    let mut envelope = message["evidence"].clone();
    envelope["authentication"] = json!({"alg":"HMAC-SHA256","mac":hex::encode(mac.finalize().into_bytes()),"epochDigest":epoch,"macDomain":RUNTIME_CALL_DOMAIN});
    Ok(envelope)
}

/// Authenticate a persisted host call diagnostic against its run and snapshot.
pub fn verify_runtime_call(run_dir: &Path, envelope: &Value) -> Result<Value, AuditError> {
    let (key, epoch) = load_epoch(run_dir)?;
    let mut evidence = envelope.clone();
    evidence
        .as_object_mut()
        .ok_or_else(|| invalid("runtime call evidence missing"))?
        .remove("authentication");
    let expected = runtime_call_message(run_dir, &evidence, &epoch)?;
    if expected.get("evidence") != Some(&evidence)
        || envelope
            .pointer("/authentication/alg")
            .and_then(Value::as_str)
            != Some("HMAC-SHA256")
        || envelope
            .pointer("/authentication/epochDigest")
            .and_then(Value::as_str)
            != Some(epoch.as_str())
        || envelope
            .pointer("/authentication/macDomain")
            .and_then(Value::as_str)
            != Some(RUNTIME_CALL_DOMAIN)
    {
        return Err(invalid("runtime call binding mismatch"));
    }
    let presented = envelope
        .pointer("/authentication/mac")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("runtime call MAC missing"))?;
    let presented = hex::decode(presented).map_err(|_| invalid("runtime call MAC malformed"))?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key).map_err(|error| invalid(error.to_string()))?;
    mac.update(&canonical_json_bytes(&expected).map_err(|error| invalid(error.to_string()))?);
    mac.verify_slice(&presented)
        .map_err(|_| invalid("runtime call MAC invalid"))?;
    Ok(evidence)
}

fn runtime_delivery_name(request: &ReasoningInvocation) -> String {
    format!(
        "{}.json",
        hex::encode(Sha256::digest(request.request_id.as_bytes()))
    )
}

fn runtime_delivery_message(
    request: &ReasoningInvocation,
    evidence: &Value,
    epoch: &str,
) -> Result<Value, AuditError> {
    Ok(json!({
        "schemaVersion":1, "kind":"legion-audit-runtime-delivery", "macDomain":RUNTIME_DELIVERY_DOMAIN,
        "requestId":request.request_id, "planDigest":request.plan_digest,
        "inventoryDigest":request.inventory_digest, "inventoryGeneration":request.inventory_generation,
        "packetDigest":canonical_digest(&request.packet).map_err(|error| invalid(error.to_string()))?,
        "epochDigest":epoch, "evidence":evidence,
    }))
}

/// Trusted runtime only: mint AFTER actual transport delivers complete packet.
/// The epoch key remains in this host process; model output is never evidence.
pub fn mint_runtime_delivery(
    run_dir: &Path,
    request: &ReasoningInvocation,
    evidence: &Value,
) -> Result<Value, AuditError> {
    super::validate_delivery_evidence(request, evidence).map_err(invalid)?;
    request.validate().map_err(invalid)?;
    let (key, epoch) = load_epoch(run_dir)?;
    let message = runtime_delivery_message(request, evidence, &epoch)?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key).map_err(|error| invalid(error.to_string()))?;
    mac.update(&canonical_json_bytes(&message).map_err(|error| invalid(error.to_string()))?);
    let envelope = json!({"message":message,"authentication":{"alg":"HMAC-SHA256","mac":hex::encode(mac.finalize().into_bytes())}});
    let path = write_atomic(
        &run_dir.join(RUNTIME_DELIVERY_DIR),
        &runtime_delivery_name(request),
        &serde_json::to_vec_pretty(&envelope).map_err(|error| invalid(error.to_string()))?,
    )?;
    Ok(json!({"path":path,"receiptId":evidence.get("receiptId"),"requestId":request.request_id}))
}

fn runtime_delivery(
    run_dir: &Path,
    request: &ReasoningInvocation,
    key: &[u8],
    epoch: &str,
) -> Result<Option<Value>, AuditError> {
    let path = run_dir
        .join(RUNTIME_DELIVERY_DIR)
        .join(runtime_delivery_name(request));
    if !path.exists() {
        return Ok(None);
    }
    let envelope = read_json(&path)?;
    let evidence = envelope
        .pointer("/message/evidence")
        .ok_or_else(|| invalid("runtime delivery evidence missing"))?;
    let expected = runtime_delivery_message(request, evidence, epoch)?;
    if envelope.get("message") != Some(&expected)
        || envelope
            .pointer("/authentication/alg")
            .and_then(Value::as_str)
            != Some("HMAC-SHA256")
    {
        return Err(invalid("runtime delivery binding mismatch"));
    }
    let presented = envelope
        .pointer("/authentication/mac")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("runtime delivery MAC missing"))?;
    let presented =
        hex::decode(presented).map_err(|_| invalid("runtime delivery MAC malformed"))?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|error| invalid(error.to_string()))?;
    mac.update(&canonical_json_bytes(&expected).map_err(|error| invalid(error.to_string()))?);
    mac.verify_slice(&presented)
        .map_err(|_| invalid("runtime delivery MAC invalid"))?;
    super::validate_delivery_evidence(request, evidence).map_err(invalid)?;
    Ok(Some(evidence.clone()))
}

const RUNTIME_VERIFICATION_DIR: &str = "runtime-verification";
const RUNTIME_VERIFICATION_DOMAIN: &str = "legion-audit-runtime-verification:v1";

pub(super) fn validate_runtime_verification(
    request: &ReasoningInvocation,
    evidence: &Value,
) -> Result<(), AuditError> {
    let digest = canonical_digest(&request.packet).map_err(|error| invalid(error.to_string()))?;
    if evidence.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || evidence.get("kind").and_then(Value::as_str) != Some("legion-runtime-verification")
        || evidence.get("requestId").and_then(Value::as_str) != Some(request.request_id.as_str())
        || evidence.get("packetDigest").and_then(Value::as_str) != Some(digest.as_str())
    {
        return Err(invalid("runtime verification binding malformed"));
    }
    let rows = evidence
        .get("findings")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("runtime verification finding ledger missing"))?;
    let mut ids = BTreeSet::new();
    let actor = |value: &Value| -> Result<(String, u64), AuditError> {
        let context = value
            .get("contextId")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid("verification context ID missing"))?;
        let pid = value
            .get("processId")
            .and_then(Value::as_u64)
            .filter(|pid| *pid > 0)
            .ok_or_else(|| invalid("verification process ID missing"))?;
        if value.get("processCreated").and_then(Value::as_bool) != Some(true)
            || value
                .get("responseDigest")
                .and_then(Value::as_str)
                .is_none_or(|value| value.is_empty())
        {
            return Err(invalid(
                "verification host process/response observation missing",
            ));
        }
        Ok((context.to_owned(), pid))
    };
    for row in rows {
        let id = row
            .get("findingId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| invalid("verification finding ID missing"))?;
        if !ids.insert(id) {
            return Err(invalid("duplicate verification finding ID"));
        }
        let original = row
            .get("authorFinding")
            .ok_or_else(|| invalid("verification author finding missing"))?;
        let original_digest =
            canonical_digest(original).map_err(|error| invalid(error.to_string()))?;
        if original.get("id").and_then(Value::as_str) != Some(id)
            || row.get("findingDigest").and_then(Value::as_str) != Some(original_digest.as_str())
        {
            return Err(invalid(
                "verification author finding identity/digest mismatch",
            ));
        }
        if row
            .get("reason")
            .and_then(Value::as_str)
            .is_none_or(|reason| reason.trim().is_empty())
        {
            return Err(invalid("verification disposition reason missing"));
        }
        let author = actor(row.get("author").unwrap_or(&Value::Null))?;
        let verdict = row.get("verdict").and_then(Value::as_str).unwrap_or("");
        if !matches!(verdict, "upheld" | "contradicted" | "unresolved") {
            return Err(invalid("unknown host verification verdict"));
        }
        match row.get("reviewer").filter(|value| !value.is_null()) {
            Some(reviewer) => {
                let reviewer = actor(reviewer)?;
                if author.0 == reviewer.0 || author.1 == reviewer.1 {
                    return Err(invalid(
                        "verification requires distinct host-observed process & context",
                    ));
                }
            }
            None if verdict == "unresolved" => {}
            None => {
                return Err(invalid(
                    "verified disposition has no independent reviewer process",
                ))
            }
        }
        if verdict == "contradicted"
            && row
                .get("contradictionAnchorsVerified")
                .and_then(Value::as_bool)
                != Some(true)
        {
            return Err(invalid(
                "contradicted finding has no verified source contradiction",
            ));
        }
    }
    Ok(())
}

/// Host-only independent verification receipt, isolated from model output.
pub fn mint_runtime_verification(
    run_dir: &Path,
    request: &ReasoningInvocation,
    evidence: &Value,
) -> Result<Value, AuditError> {
    validate_runtime_verification(request, evidence)?;
    request.validate().map_err(invalid)?;
    let (key, epoch) = load_epoch(run_dir)?;
    let mut message = runtime_delivery_message(request, evidence, &epoch)?;
    message["kind"] = json!("legion-audit-runtime-verification");
    message["macDomain"] = json!(RUNTIME_VERIFICATION_DOMAIN);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key).map_err(|error| invalid(error.to_string()))?;
    mac.update(&canonical_json_bytes(&message).map_err(|error| invalid(error.to_string()))?);
    let envelope = json!({"message":message,"authentication":{"alg":"HMAC-SHA256","mac":hex::encode(mac.finalize().into_bytes())}});
    let path = write_atomic(
        &run_dir.join(RUNTIME_VERIFICATION_DIR),
        &runtime_delivery_name(request),
        &serde_json::to_vec_pretty(&envelope).map_err(|error| invalid(error.to_string()))?,
    )?;
    Ok(json!({"path":path,"requestId":request.request_id}))
}

fn runtime_verification(
    run_dir: &Path,
    request: &ReasoningInvocation,
    key: &[u8],
    epoch: &str,
) -> Result<Option<Value>, AuditError> {
    let path = run_dir
        .join(RUNTIME_VERIFICATION_DIR)
        .join(runtime_delivery_name(request));
    if !path.exists() {
        return Ok(None);
    }
    let envelope = read_json(&path)?;
    let evidence = envelope
        .pointer("/message/evidence")
        .ok_or_else(|| invalid("runtime verification evidence missing"))?;
    let mut expected = runtime_delivery_message(request, evidence, epoch)?;
    expected["kind"] = json!("legion-audit-runtime-verification");
    expected["macDomain"] = json!(RUNTIME_VERIFICATION_DOMAIN);
    if envelope.get("message") != Some(&expected)
        || envelope
            .pointer("/authentication/alg")
            .and_then(Value::as_str)
            != Some("HMAC-SHA256")
    {
        return Err(invalid("runtime verification binding mismatch"));
    }
    let presented = envelope
        .pointer("/authentication/mac")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("runtime verification MAC missing"))?;
    let presented =
        hex::decode(presented).map_err(|_| invalid("runtime verification MAC malformed"))?;
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).map_err(|error| invalid(error.to_string()))?;
    mac.update(&canonical_json_bytes(&expected).map_err(|error| invalid(error.to_string()))?);
    mac.verify_slice(&presented)
        .map_err(|_| invalid("runtime verification MAC invalid"))?;
    validate_runtime_verification(request, evidence)?;
    Ok(Some(evidence.clone()))
}

pub(super) fn verification_projection_gaps(
    provider_id: &str,
    proof: Option<&Value>,
    findings: &[Value],
    withdrawn: &[Value],
) -> Result<Vec<String>, AuditError> {
    let Some(proof) = proof else {
        return Ok(vec![format!("verification-unverified:{provider_id}:missing authenticated independent verification receipt")]);
    };
    let rows = proof["findings"]
        .as_array()
        .ok_or_else(|| invalid("verification ledger malformed"))?;
    let mut accounted = BTreeSet::new();
    let mut gaps = Vec::new();
    for row in rows {
        let id = row["findingId"]
            .as_str()
            .ok_or_else(|| invalid("verification ID missing"))?;
        let verdict = row["verdict"].as_str().unwrap_or("");
        let original = &row["authorFinding"];
        let live = findings
            .iter()
            .find(|finding| finding.get("id").and_then(Value::as_str) == Some(id));
        let dropped = withdrawn
            .iter()
            .find(|finding| finding.get("id").and_then(Value::as_str) == Some(id));
        match verdict {
            "upheld" | "unresolved" => {
                let finding =
                    live.ok_or_else(|| invalid(format!("verification lost live finding {id}")))?;
                if dropped.is_some() {
                    return Err(invalid("finding both live & withdrawn"));
                }
                let correctness = provider_id == "reasoning.correctness"
                    || original.get("lens").and_then(Value::as_str) == Some("correctness");
                let clean = |finding: &Value| {
                    let mut value = finding.clone();
                    if let Some(object) = value.as_object_mut() {
                        object.remove("verifyStatus");
                        if correctness {
                            object.remove("verificationMethod");
                        }
                    }
                    value
                };
                if clean(finding) != clean(original) {
                    return Err(invalid(format!(
                        "verification changed finding {id} beyond allowed status fields"
                    )));
                }
                let expected = if verdict == "upheld" {
                    "verified"
                } else {
                    "unverified"
                };
                if finding.get("verifyStatus").and_then(Value::as_str) != Some(expected)
                    || (correctness
                        && finding.get("verificationMethod").and_then(Value::as_str)
                            != Some("adversarial-skeptic-pass"))
                {
                    return Err(invalid(
                        "finding verification fields disagree with host receipt",
                    ));
                }
                if verdict == "unresolved" {
                    gaps.push(format!("verification-unresolved:{provider_id}:{id}"));
                }
            }
            "contradicted" => {
                if live.is_some() {
                    return Err(invalid("contradicted finding still marked live"));
                }
                let withdrawal = dropped.ok_or_else(|| {
                    invalid(format!("verified contradiction lost withdrawal {id}"))
                })?;
                let disproof = withdrawal
                    .get("disproof")
                    .ok_or_else(|| invalid("withdrawal disproof missing"))?;
                let anchors = row
                    .get("evidence")
                    .and_then(Value::as_array)
                    .ok_or_else(|| invalid("contradiction anchor evidence missing"))?;
                if !anchors.contains(disproof) {
                    return Err(invalid(
                        "withdrawal disproof differs from host contradiction evidence",
                    ));
                }
            }
            _ => return Err(invalid("unknown verification disposition")),
        }
        accounted.insert(id);
    }
    for finding in findings.iter().chain(withdrawn) {
        if finding
            .get("id")
            .and_then(Value::as_str)
            .is_none_or(|id| !accounted.contains(id))
        {
            return Err(invalid(
                "finding/withdrawal missing host verification disposition",
            ));
        }
    }
    Ok(gaps)
}

fn verification_result_gaps(
    provider_id: &str,
    proof: Option<&Value>,
    findings: &[Value],
    withdrawn: &[Value],
    frozen: &FrozenFiles<'_>,
) -> Result<Vec<String>, AuditError> {
    let gaps = verification_projection_gaps(provider_id, proof, findings, withdrawn)?;
    for row in proof
        .and_then(|proof| proof.get("findings"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if row.get("verdict").and_then(Value::as_str) == Some("contradicted") {
            for anchor in row
                .get("evidence")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                frozen.check("host verification contradiction", Some(anchor))?;
            }
        }
    }
    Ok(gaps)
}

const RUNTIME_ADJUDICATION_DIR: &str = "runtime-adjudication";
const RUNTIME_ADJUDICATION_DOMAIN: &str = "legion-audit-runtime-adjudication:v1";

fn validate_runtime_adjudication(
    request: &ReasoningInvocation,
    packet: &Value,
    observation: &Value,
) -> Result<(), AuditError> {
    if request.provider_id != ADJUDICATOR_PROVIDER_ID
        || observation.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || observation.get("kind").and_then(Value::as_str)
            != Some("legion-adjudication-stage-observation")
        || observation
            .get("workItemId")
            .and_then(Value::as_str)
            .is_none_or(|id| id.is_empty())
        || observation
            .get("observedContextId")
            .and_then(Value::as_str)
            .is_none_or(|id| id.is_empty())
        || observation
            .get("processId")
            .and_then(Value::as_u64)
            .is_none_or(|pid| pid == 0)
        || observation.get("processCreated").and_then(Value::as_bool) != Some(true)
        || observation
            .get("responseDigest")
            .and_then(Value::as_str)
            .is_none_or(|id| id.is_empty())
        || observation.get("complete").and_then(Value::as_bool) != Some(true)
        || observation.get("truncated").and_then(Value::as_bool) != Some(false)
    {
        return Err(invalid(
            "runtime adjudication observation malformed/incomplete",
        ));
    }
    let child =
        if packet.get("kind").and_then(Value::as_str) == Some("legion-audit-adjudication-seat") {
            packet
                .get("packet")
                .ok_or_else(|| invalid("runtime stage wrapper has no child packet"))?
        } else {
            packet
        };
    let packet_digest = canonical_digest(child).map_err(|error| invalid(error.to_string()))?;
    let bytes = canonical_json_bytes(child)
        .map_err(|error| invalid(error.to_string()))?
        .len() as u64;
    if observation.get("workPacketDigest").and_then(Value::as_str) != Some(packet_digest.as_str())
        || observation
            .get("deliveredPacketBytes")
            .and_then(Value::as_u64)
            != Some(bytes)
    {
        return Err(invalid(
            "runtime adjudication delivery does not bind exact child packet",
        ));
    }
    Ok(())
}

/// Authenticated observation of exactly the child packet actually sent. This
/// never claims delivery of the parent packet or of another stage's evidence.
pub fn mint_runtime_adjudication(
    run_dir: &Path,
    request: &ReasoningInvocation,
    stage_packet: &Value,
    observation: &Value,
) -> Result<Value, AuditError> {
    request.validate().map_err(invalid)?;
    validate_runtime_adjudication(request, stage_packet, observation)?;
    let (key, epoch) = load_epoch(run_dir)?;
    let payload = json!({"stagePacket":stage_packet,"observation":observation});
    let mut message = runtime_delivery_message(request, &payload, &epoch)?;
    message["kind"] = json!("legion-audit-runtime-adjudication");
    message["macDomain"] = json!(RUNTIME_ADJUDICATION_DOMAIN);
    let mut mac =
        Hmac::<Sha256>::new_from_slice(&key).map_err(|error| invalid(error.to_string()))?;
    mac.update(&canonical_json_bytes(&message).map_err(|error| invalid(error.to_string()))?);
    let envelope = json!({"message":message,"authentication":{"alg":"HMAC-SHA256","mac":hex::encode(mac.finalize().into_bytes())}});
    let identity = json!([
        request.request_id,
        observation.get("workItemId"),
        observation.get("observedContextId")
    ]);
    let name = format!(
        "{}.json",
        hex::encode(Sha256::digest(
            canonical_json_bytes(&identity).map_err(|error| invalid(error.to_string()))?
        ))
    );
    let path = write_atomic(
        &run_dir.join(RUNTIME_ADJUDICATION_DIR),
        &name,
        &serde_json::to_vec_pretty(&envelope).map_err(|error| invalid(error.to_string()))?,
    )?;
    Ok(json!({"path":path,"workItemId":observation.get("workItemId")}))
}

fn runtime_adjudication(
    run_dir: &Path,
    request: &ReasoningInvocation,
    key: &[u8],
    epoch: &str,
) -> Result<Vec<Value>, AuditError> {
    let directory = run_dir.join(RUNTIME_ADJUDICATION_DIR);
    if !directory.exists() {
        return Ok(Vec::new());
    }
    let mut paths = fs::read_dir(&directory)
        .map_err(|error| invalid(error.to_string()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| invalid(error.to_string()))?;
    paths.sort();
    let mut observations = Vec::new();
    for path in paths.into_iter().filter(|path| {
        path.extension()
            .is_some_and(|extension| extension == "json")
    }) {
        let envelope = read_json(&path)?;
        if envelope
            .pointer("/message/requestId")
            .and_then(Value::as_str)
            != Some(request.request_id.as_str())
        {
            continue;
        }
        let payload = envelope
            .pointer("/message/evidence")
            .ok_or_else(|| invalid("runtime stage payload missing"))?;
        let packet = payload
            .get("stagePacket")
            .ok_or_else(|| invalid("runtime stage packet missing"))?;
        let observation = payload
            .get("observation")
            .ok_or_else(|| invalid("runtime stage observation missing"))?;
        let mut expected = runtime_delivery_message(request, payload, epoch)?;
        expected["kind"] = json!("legion-audit-runtime-adjudication");
        expected["macDomain"] = json!(RUNTIME_ADJUDICATION_DOMAIN);
        if envelope.get("message") != Some(&expected)
            || envelope
                .pointer("/authentication/alg")
                .and_then(Value::as_str)
                != Some("HMAC-SHA256")
        {
            return Err(invalid("runtime stage parent binding mismatch"));
        }
        let presented = envelope
            .pointer("/authentication/mac")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("runtime stage MAC missing"))?;
        let presented =
            hex::decode(presented).map_err(|_| invalid("runtime stage MAC malformed"))?;
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key).map_err(|error| invalid(error.to_string()))?;
        mac.update(&canonical_json_bytes(&expected).map_err(|error| invalid(error.to_string()))?);
        mac.verify_slice(&presented)
            .map_err(|_| invalid("runtime stage MAC invalid"))?;
        validate_runtime_adjudication(request, packet, observation)?;
        observations.push(observation.clone());
    }
    Ok(observations)
}

/// Lens-schema finding fields (`lens_schemas.rs`: the shared shape plus the
/// per-lens extras `verificationMethod`, `ponytailTag`, `parentFindingId`)
/// that the consolidated finding projection carries in `evidence`.
/// `reviewAxis`/`sourceQuote`/`sourceLocation`/`disposition`/
/// `changeAttribution` are projected by `report.rs` from `lensFindings`.
const LENS_TRIAGE_FIELDS: &[&str] = &[
    "lens",
    "confidence",
    "verifyStatus",
    "verificationMethod",
    "ponytailTag",
    "parentFindingId",
    "action",
];

pub(super) fn invalid(message: impl Into<String>) -> AuditError {
    AuditError::Invalid(message.into())
}

pub(super) fn io(error: std::io::Error, what: &str) -> AuditError {
    AuditError::Invalid(format!("{what}: {error}"))
}

pub(super) fn read_json(path: &Path) -> Result<Value, AuditError> {
    let bytes =
        fs::read(path).map_err(|error| io(error, &format!("could not read {}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| invalid(format!("{} is not valid JSON: {error}", path.display())))
}

pub(super) fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, AuditError> {
    fs::create_dir_all(dir).map_err(|error| io(error, "could not create run directory"))?;
    let destination = dir.join(name);
    let temporary = dir.join(format!(".{name}.tmp-{}", std::process::id()));
    fs::write(&temporary, bytes).map_err(|error| io(error, "could not write run artifact"))?;
    fs::rename(&temporary, &destination)
        .map_err(|error| io(error, "could not publish run artifact"))?;
    Ok(destination)
}

// ---------------------------------------------------------------------------
// Epoch key
// ---------------------------------------------------------------------------

/// Digest recorded in the plan and report for an epoch key. It identifies the
/// key without revealing it.
pub fn epoch_digest(key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EPOCH_DOMAIN);
    hasher.update(key);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// A fresh 32-byte key for one audit run (plan signing or receipt MACs).
pub fn ephemeral_key() -> Vec<u8> {
    random_key()
}

fn random_key() -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::io::Read;
        let mut key = [0u8; 32];
        if let Ok(mut file) = fs::File::open("/dev/urandom") {
            if file.read_exact(&mut key).is_ok() {
                return key.to_vec();
            }
        }
    }
    // Portable fallback: std's per-process random hasher keys mixed with the
    // clock and process id.
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = Sha256::new();
    for round in 0..8u64 {
        let mut state = std::collections::hash_map::RandomState::new().build_hasher();
        state.write_u64(round);
        hasher.update(state.finish().to_le_bytes());
    }
    hasher.update(std::process::id().to_le_bytes());
    hasher.update(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
            .to_le_bytes(),
    );
    hasher.finalize().to_vec()
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), AuditError> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| io(error, "could not create epoch key"))?;
    file.write_all(bytes)
        .map_err(|error| io(error, "could not write epoch key"))
}

/// Generates a fresh per-run epoch key under `run_dir` (mode 0600 on Unix),
/// discarding any receipts a previous run left there, and returns its digest.
pub fn create_epoch(run_dir: &Path) -> Result<String, AuditError> {
    fs::create_dir_all(run_dir).map_err(|error| io(error, "could not create run directory"))?;
    let key = random_key();
    let path = run_dir.join(EPOCH_KEY_FILE);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir_all(run_dir.join(LENS_RECEIPT_DIR));
    write_private(&path, hex::encode(&key).as_bytes())?;
    Ok(epoch_digest(&key))
}

/// Loads the epoch key of a run and its digest.
pub fn load_epoch(run_dir: &Path) -> Result<(Vec<u8>, String), AuditError> {
    let path = run_dir.join(EPOCH_KEY_FILE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path)
            .map_err(|error| io(error, "run has no epoch key; rerun `legion audit --out`"))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(invalid(
                "epoch key is readable by group or others; refusing to use it",
            ));
        }
    }
    let text = fs::read_to_string(&path)
        .map_err(|error| io(error, "run has no epoch key; rerun `legion audit --out`"))?;
    let key = hex::decode(text.trim()).map_err(|_| invalid("epoch key is not hex"))?;
    if key.len() < 16 {
        return Err(invalid("epoch key is too short"));
    }
    let digest = epoch_digest(&key);
    Ok((key, digest))
}

// ---------------------------------------------------------------------------
// Anchors
// ---------------------------------------------------------------------------

fn safe_relative(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.contains(':')
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

struct FrozenFiles<'a> {
    root: &'a Path,
    digests: BTreeMap<String, String>,
    snapshot: Option<&'a crate::snapshot::FrozenSnapshot>,
    source_sides: BTreeMap<String, String>,
}

impl FrozenFiles<'_> {
    /// Verifies an anchor `{path, line, text}`: the path is in the frozen
    /// inventory, the file bytes still match the frozen digest, and `text`
    /// occurs verbatim starting on `line`. Returns the anchored path and line.
    fn check(&self, who: &str, anchor: Option<&Value>) -> Result<(String, u64), AuditError> {
        let object = anchor.and_then(Value::as_object).ok_or_else(|| {
            invalid(format!(
                "{who}: a code anchor {{path, line, text}} is required"
            ))
        })?;
        let path = object
            .get("path")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("{who}: anchor.path is required")))?;
        let line = object
            .get("line")
            .and_then(Value::as_u64)
            .filter(|line| *line >= 1)
            .ok_or_else(|| invalid(format!("{who}: anchor.line must be a 1-based line number")))?;
        let text = object
            .get("text")
            .and_then(Value::as_str)
            .filter(|text| !text.trim().is_empty())
            .ok_or_else(|| {
                invalid(format!(
                    "{who}: anchor.text must be non-empty verbatim code"
                ))
            })?;
        if !safe_relative(path) {
            return Err(invalid(format!(
                "{who}: anchor.path {path} is not a safe relative path"
            )));
        }
        let side = object
            .get("sourceSide")
            .and_then(Value::as_str)
            .or_else(|| self.source_sides.get(path).map(String::as_str))
            .unwrap_or("selected");
        let bytes = if let Some(snapshot) = self.snapshot {
            let selected_side = match side {
                "selected" => crate::snapshot::SnapshotSide::Selected,
                "base"
                    if snapshot.manifest.scope.changed_paths.contains(path)
                        && snapshot.manifest.base_files.contains_key(path) =>
                {
                    crate::snapshot::SnapshotSide::Base
                }
                _ => {
                    return Err(invalid(format!(
                        "{who}: source side {side} not available for {path}"
                    )))
                }
            };
            snapshot.read(path, selected_side, 32 * 1024 * 1024)?
        } else {
            if side != "selected" {
                return Err(invalid("base anchor requires immutable snapshot"));
            }
            let expected = self.digests.get(path).ok_or_else(|| {
                invalid(format!(
                    "{who}: anchor path {path} is not in the frozen inventory"
                ))
            })?;
            let bytes = fs::read(self.root.join(path))
                .map_err(|error| io(error, &format!("{who}: could not read anchor file {path}")))?;
            let actual = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
            if &actual != expected {
                return Err(AuditError::SourceDrift(format!(
                    "{who}: {path} differs from the frozen revision"
                )));
            }
            bytes
        };
        let content = String::from_utf8_lossy(&bytes).replace("\r\n", "\n");
        let needle = text.replace("\r\n", "\n");
        let found = content.match_indices(needle.as_str()).any(|(index, _)| {
            content[..index]
                .bytes()
                .filter(|byte| *byte == b'\n')
                .count() as u64
                + 1
                == line
        });
        if !found {
            return Err(invalid(format!(
                "{who}: anchor text does not appear verbatim at {path}:{line} in the frozen file"
            )));
        }
        Ok((path.to_owned(), line))
    }
}

fn evidence_covers(evidence: &[Value], path: &str, line: u64) -> bool {
    evidence.iter().filter_map(Value::as_str).any(|entry| {
        let Some((entry_path, range)) = entry.rsplit_once(':') else {
            return false;
        };
        if entry_path != path {
            return false;
        }
        let (start, end) = range.split_once('-').unwrap_or((range, range));
        match (start.parse::<u64>(), end.parse::<u64>()) {
            (Ok(start), Ok(end)) => start <= line && line <= end,
            _ => false,
        }
    })
}

fn ensure_variant_anchor_in_scope(
    provider_id: &str,
    denominator_paths: &[String],
    anchor_path: &str,
    label: &str,
) -> Result<(), AuditError> {
    if provider_id == followup::VARIANT_PROVIDER_ID
        && !denominator_paths.iter().any(|path| path == anchor_path)
    {
        return Err(invalid(format!(
            "{label}: variant anchor {anchor_path} is outside the frozen analysis scope"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Ingest
// ---------------------------------------------------------------------------

/// What an accepted ingest minted.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestedLens {
    pub provider: String,
    pub lens_ids: Vec<String>,
    pub findings: usize,
    pub withdrawn: usize,
    pub anchors_verified: usize,
    /// Denominator paths the packet proves were examined (see `packet_coverage`).
    pub examined: u64,
    pub expected: u64,
    pub complete: bool,
    pub coverage_gaps: Vec<String>,
    pub receipt_id: String,
    pub receipt_path: String,
    /// For a part of a multi-part provider: the part just ingested. The
    /// `examined`/`complete`/`coverage_gaps` above are then the PROVIDER-level
    /// aggregate over every ingested part, so the outstanding work is named
    /// (`reasoning-parts-pending:<provider>:<ingested>/<total>`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts_total: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts_ingested: Option<u32>,
    /// Part numbers still awaiting ingest.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub parts_pending: Vec<u32>,
}

/// Coverage derived from what the lens packet carried, never from the
/// submitter's attestation.
struct PacketCoverage {
    examined: u64,
    gaps: Vec<String>,
    detail: Value,
}

/// The risk-sampled fields a packet's `excerptCoverage` carries.
struct SampledPacket {
    bundle: String,
    review_set_digest: String,
    review_set_count: usize,
    /// Loaded from the promotion file by `load_promotion`; packets carry only
    /// counts, the digest and the file reference.
    promoted: Vec<String>,
    /// Frozen sampled paths displaced by the promotion.
    displaced: Vec<String>,
    promoted_count: usize,
    displaced_count: usize,
    promotion_ref: Option<String>,
    promotion_digest: Option<String>,
    /// Promotable paths the run budget could not take.
    unpromoted: usize,
    effective_review_set_digest: Option<String>,
    declared_unsampled: usize,
    excluded: usize,
    /// (alias path, canonical path)
    aliases: Vec<(String, String)>,
}

impl SampledPacket {
    fn from_coverage(coverage: Option<&Value>) -> Option<Self> {
        let coverage = coverage?;
        if coverage.get("coverageMode").and_then(Value::as_str)
            != Some(coverage_plan::MODE_RISK_SAMPLED)
        {
            return None;
        }
        let aliases = coverage
            .get("aliasedPaths")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        Some((
                            item.get("path")?.as_str()?.to_owned(),
                            item.get("of")?.as_str()?.to_owned(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            bundle: coverage
                .get("bundle")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            review_set_digest: coverage
                .get("reviewSetDigest")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            review_set_count: coverage
                .get("reviewSetCount")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize,
            promoted: Vec::new(),
            displaced: Vec::new(),
            promoted_count: coverage
                .get("promotedCount")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize,
            displaced_count: coverage
                .get("displacedCount")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize,
            promotion_ref: coverage
                .get("promotionRef")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            promotion_digest: coverage
                .get("promotionDigest")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            unpromoted: coverage
                .get("unpromotedCount")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize,
            effective_review_set_digest: coverage
                .get("effectiveReviewSetDigest")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned),
            declared_unsampled: coverage
                .get("declaredUnsampledCount")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize,
            excluded: coverage
                .get("excludedCount")
                .and_then(Value::as_u64)
                .unwrap_or(0) as usize,
            aliases,
        })
    }

    /// Loads the promoted and displaced lists from the run-level promotion
    /// file the packet references. Fails closed: a missing file, a file that
    /// is not the provider's own, a digest that differs from the packet's, or
    /// counts that differ from the packet's reject the packet.
    fn load_promotion(&mut self, run_dir: &Path, provider_id: &str) -> Result<(), AuditError> {
        let (reference, claimed) = match (&self.promotion_ref, &self.promotion_digest) {
            (Some(reference), Some(digest)) => (reference.clone(), digest.clone()),
            (None, None) => {
                if self.promoted_count != 0 || self.displaced_count != 0 || self.unpromoted != 0 {
                    return Err(invalid(format!(
                        "lens packet for {provider_id} counts promoted, displaced or unpromoted paths but names no promotion file"
                    )));
                }
                return Ok(());
            }
            _ => {
                return Err(invalid(format!(
                    "lens packet for {provider_id} carries only one of promotionRef and promotionDigest"
                )))
            }
        };
        if reference != promotion_file_name(provider_id) {
            return Err(invalid(format!(
                "lens packet for {provider_id} names an unexpected promotion file {reference}"
            )));
        }
        let document = read_json(&run_dir.join(&reference)).map_err(|error| {
            invalid(format!(
                "promotion file {reference} for {provider_id} is missing or unreadable: {error}"
            ))
        })?;
        let promoted = string_list(document.get("promoted"));
        let displaced = string_list(document.get("displaced"));
        let unpromoted = string_list(document.get("unpromoted"));
        let findings = document.get("findings").cloned().unwrap_or(Value::Null);
        let recomputed = promotion_digest_of(&promoted, &displaced, &unpromoted, &findings);
        let stored = document.get("digest").and_then(Value::as_str);
        if recomputed.as_deref() != Some(claimed.as_str()) || stored != Some(claimed.as_str()) {
            return Err(invalid(format!(
                "promotion file {reference} for {provider_id} does not match the packet's promotionDigest"
            )));
        }
        if promoted.len() != self.promoted_count
            || displaced.len() != self.displaced_count
            || unpromoted.len() != self.unpromoted
        {
            return Err(invalid(format!(
                "promotion file {reference} for {provider_id} disagrees with the packet's promotion counts"
            )));
        }
        self.promoted = promoted;
        self.displaced = displaced;
        Ok(())
    }

    /// Paths the lens must examine: the frozen review set, minus the sampled
    /// paths promotion displaced, plus the promoted paths.
    fn review_expected(&self) -> usize {
        (self.review_set_count + self.promoted.len()).saturating_sub(self.displaced.len())
    }

    /// The provider-level gap for promotion the run budget capped.
    fn promotion_gap(&self) -> Option<String> {
        (self.unpromoted > 0).then(|| format!("lens-promotion-capped:{}", self.unpromoted))
    }

    fn annotate(&self, object: &mut Map<String, Value>) {
        object.insert(
            "coverageMode".into(),
            json!(coverage_plan::MODE_RISK_SAMPLED),
        );
        object.insert("bundle".into(), json!(self.bundle));
        object.insert("reviewSetDigest".into(), json!(self.review_set_digest));
        object.insert("reviewSetCount".into(), json!(self.review_set_count));
        object.insert("reviewExpected".into(), json!(self.review_expected()));
        object.insert("promotedPaths".into(), json!(self.promoted));
        object.insert("displacedPaths".into(), json!(self.displaced));
        object.insert("unpromotedCount".into(), json!(self.unpromoted));
        object.insert("declaredUnsampled".into(), json!(self.declared_unsampled));
        object.insert("excluded".into(), json!(self.excluded));
        object.insert(
            "aliasedPaths".into(),
            Value::Array(
                self.aliases
                    .iter()
                    .map(|(alias, of)| json!({"path": alias, "of": of}))
                    .collect(),
            ),
        );
    }
}

/// The frozen coverage plan of `provider_id` from the persisted native plan.
fn frozen_coverage_for(plan: &Value, provider_id: &str) -> Option<coverage_plan::FrozenCoverage> {
    plan.pointer("/nativePlan/plan/providers")?
        .as_array()?
        .iter()
        .find(|provider| provider.get("id").and_then(Value::as_str) == Some(provider_id))?
        .pointer("/configuration/coverage")
        .and_then(coverage_plan::FrozenCoverage::from_value)
}

/// A risk-sampled lens packet must carry exactly the review set the plan
/// froze; promotions may only add paths inside the frozen denominator.
fn verify_review_binding(
    run_dir: &Path,
    plan: &Value,
    provider_id: &str,
    packet: &Value,
    denominator_paths: &[String],
) -> Result<(), AuditError> {
    let Some(frozen) = frozen_coverage_for(plan, provider_id).filter(|f| f.is_sampled()) else {
        return Ok(());
    };
    let coverage = packet.get("excerptCoverage").filter(|v| v.is_object());
    let mut carried = SampledPacket::from_coverage(coverage).ok_or_else(|| {
        invalid(format!(
            "lens packet for {provider_id} does not carry the frozen risk-sampled review set"
        ))
    })?;
    carried.load_promotion(run_dir, provider_id)?;
    if carried.review_set_digest != frozen.review_set_digest
        || carried.review_set_count != frozen.review_set.len()
    {
        return Err(invalid(format!(
            "lens packet for {provider_id} review set differs from the frozen plan"
        )));
    }
    let denominator: BTreeSet<&str> = denominator_paths.iter().map(String::as_str).collect();
    if carried
        .promoted
        .iter()
        .any(|path| !denominator.contains(path.as_str()) || frozen.review_set.contains(path))
    {
        return Err(invalid(format!(
            "lens packet for {provider_id} promotes a path outside the frozen denominator or already in the review set"
        )));
    }
    // Displacement only ever removes frozen sampled paths: never a path outside
    // the frozen review set and never a mandatory path.
    if carried
        .displaced
        .iter()
        .any(|path| !frozen.review_set.contains(path) || frozen.mandatory.contains(path))
    {
        return Err(invalid(format!(
            "lens packet for {provider_id} displaces a path outside the frozen sampled set or a mandatory path"
        )));
    }
    // The review set the packet claims to examine must re-derive from the
    // frozen plan, the displaced paths and the promoted paths alone.
    if let Some(carried_digest) = &carried.effective_review_set_digest {
        let expected = coverage_plan::effective_review_set_digest(
            &frozen.review_set,
            &carried.displaced,
            &carried.promoted,
        )?;
        if *carried_digest != expected {
            return Err(invalid(format!(
                "lens packet for {provider_id} effective review set does not match the frozen review set, displaced and promoted paths"
            )));
        }
    }
    Ok(())
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Examined coverage for one packet. `bounded-excerpts` packets count only
/// denominator paths whose excerpt is present and untruncated; omitted and
/// truncated paths become a coverage gap. `candidate-verdicts` packets (the
/// security adjudicator) are covered only when every scanner candidate got a
/// verdict. A packet that records no basis proves nothing.
fn packet_coverage(
    provider_id: &str,
    sampled: Option<SampledPacket>,
    packet: &Value,
    denominator_paths: &[String],
    candidates_supplied: bool,
    part: Option<LensPartRef>,
) -> PacketCoverage {
    let expected = denominator_paths.len() as u64;
    let coverage = packet
        .get("excerptCoverage")
        .filter(|value| value.is_object());
    let basis = coverage
        .and_then(|value| value.get("basis"))
        .and_then(Value::as_str)
        .unwrap_or("unrecorded");
    match basis {
        "bounded-excerpts" => {
            let mut included = string_list(coverage.and_then(|value| {
                value
                    .get("materializedPaths")
                    .or_else(|| value.get("examinedPaths"))
            }))
            .into_iter()
            .collect::<BTreeSet<_>>();
            if let Some(sampled) = &sampled {
                // Identical-content aliases are credited with their canonical
                // path's excerpt.
                for (alias, canonical) in &sampled.aliases {
                    if included.contains(canonical) {
                        included.insert(alias.clone());
                    }
                }
            }
            let examined = denominator_paths
                .iter()
                .filter(|path| included.contains(*path))
                .count() as u64;
            let truncated = string_list(coverage.and_then(|value| value.get("truncatedPaths")));
            let omitted = coverage
                .and_then(|value| value.get("omittedPaths"))
                .cloned()
                .unwrap_or(Value::Array(Vec::new()));
            if let Some(part) = part {
                // A part proves only what it carries. Provider-level
                // completeness is the union over parts (`merge_parts`).
                let denominator: BTreeSet<&str> =
                    denominator_paths.iter().map(String::as_str).collect();
                let examined_paths = denominator_paths
                    .iter()
                    .filter(|path| included.contains(*path))
                    .cloned()
                    .collect::<Vec<_>>();
                let chunked: Vec<Value> = coverage
                    .and_then(|value| value.get("chunkedPaths"))
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter(|item| {
                                item.get("path")
                                    .and_then(Value::as_str)
                                    .is_some_and(|path| denominator.contains(path))
                            })
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default();
                let part_meta = packet.get("part").cloned().unwrap_or(Value::Null);
                let mut detail = json!({
                    "basis": basis,
                    "examined": examined,
                    "expected": expected,
                    "part": {"number": part.number, "total": part.total},
                    "requiredParts": part_meta.get("requiredParts"),
                    "overCeiling": part_meta.get("overCeiling"),
                    "partPaths": part_meta.get("paths"),
                    "examinedPaths": examined_paths,
                    "chunkedPaths": chunked,
                    "omittedPaths": omitted,
                    "truncatedPaths": truncated,
                });
                if let (Some(sampled), Some(object)) = (&sampled, detail.as_object_mut()) {
                    sampled.annotate(object);
                }
                return PacketCoverage {
                    examined,
                    gaps: vec![format!(
                        "reasoning-part-scope:{provider_id}:part {}/{}",
                        part.number, part.total
                    )],
                    detail,
                };
            }
            // A risk-sampled lens is judged against its frozen review set;
            // paths outside it are declared unsampled, not gaps. The numeric
            // `examined` credits them so the provider-level reconciliation
            // (expected == denominator count) stays exact; the honest split is
            // in `detail` and the `lensCoverage` claim.
            let review_expected = sampled
                .as_ref()
                .map_or(expected, |sampled| sampled.review_expected() as u64);
            let mut gaps = if examined < review_expected {
                vec![format!(
                    "reasoning-excerpt-coverage:{provider_id}:{examined}/{review_expected} {}paths examined ({} omitted, {} truncated)",
                    if sampled.is_some() { "review-set " } else { "" },
                    omitted.as_array().map_or(0, Vec::len),
                    truncated.len()
                )]
            } else {
                Vec::new()
            };
            gaps.extend(sampled.as_ref().and_then(SampledPacket::promotion_gap));
            let credited = match &sampled {
                Some(sampled) => (examined + sampled.declared_unsampled as u64).min(expected),
                None => examined,
            };
            let mut detail = json!({
                "basis": basis,
                "examined": examined,
                "expected": expected,
                "omittedPaths": omitted,
                "truncatedPaths": truncated,
            });
            if let (Some(sampled), Some(object)) = (&sampled, detail.as_object_mut()) {
                sampled.annotate(object);
                object.insert("reviewExamined".into(), json!(examined));
            }
            PacketCoverage {
                examined: credited,
                gaps,
                detail,
            }
        }
        "candidate-verdicts" => {
            let examined = if candidates_supplied { expected } else { 0 };
            PacketCoverage {
                examined,
                gaps: if candidates_supplied {
                    Vec::new()
                } else {
                    vec![format!("scanner-candidates-unavailable:{provider_id}")]
                },
                detail: json!({"basis": basis, "examined": examined, "expected": expected}),
            }
        }
        _ => PacketCoverage {
            examined: 0,
            gaps: vec![format!("excerpt-coverage-unrecorded:{provider_id}")],
            detail: json!({"basis": "unrecorded", "examined": 0, "expected": expected}),
        },
    }
}

pub(super) fn expected_request_id(work: &PendingLensWork) -> Result<String, AuditError> {
    let request = &work.request;
    let packet_digest =
        canonical_digest(&request.packet).map_err(|error| invalid(error.to_string()))?;
    let signature = if request.plan_signature.is_empty() {
        Value::Null
    } else {
        Value::String(request.plan_signature.clone())
    };
    let identity = json!({
        "invocationEpoch": "pending-host",
        "packetDigest": packet_digest,
        "providerId": request.provider_id,
        "contract": request.contract,
        "planDigest": request.plan_digest,
        "planSignature": signature,
        "repositoryId": request.repository_id,
        "inventoryGeneration": request.inventory_generation,
        "inventoryDigest": request.inventory_digest,
        "denominatorDigest": request.denominator_digest,
        "denominatorCount": request.denominator_count,
        "denominatorPaths": request.denominator_paths,
    });
    canonical_digest(&identity).map_err(|error| invalid(error.to_string()))
}

fn string_field<'a>(value: &'a Value, field: &str, who: &str) -> Result<&'a str, AuditError> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid(format!("{who}: `{field}` is required")))
}

fn array_field(value: &Value, field: &str, who: &str) -> Result<Vec<Value>, AuditError> {
    match value.get(field) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => Ok(items.clone()),
        Some(_) => Err(invalid(format!("{who}: `{field}` must be an array"))),
    }
}

fn parse_packet(path: &Path) -> Result<PendingLensWork, AuditError> {
    serde_json::from_value(read_json(path)?)
        .map_err(|error| invalid(format!("lens packet is invalid: {error}")))
}

/// `<provider>.part-NNNN.json` files under `dir`, sorted by part number.
fn part_packet_files(dir: &Path, provider_id: &str) -> Vec<(u32, PathBuf)> {
    let prefix = format!("{provider_id}.part-");
    let mut files = fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let number = name
                .strip_prefix(prefix.as_str())?
                .strip_suffix(".json")?
                .parse::<u32>()
                .ok()?;
            Some((number, entry.path()))
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

/// Finds the lens packet a result was produced from. A single un-numbered
/// packet is `<provider>.json`; a partitioned provider has
/// `<provider>.part-NNNN.json` files plus `<provider>.index.json`, and the
/// result's `packetDigest` selects the part (the index is only a hint; the
/// part file's own digest decides).
fn locate_packet(
    run_dir: &Path,
    provider_id: &str,
    result: &Value,
) -> Result<PendingLensWork, AuditError> {
    let dir = run_dir.join(LENS_PACKET_DIR);
    let single = dir.join(format!("{provider_id}.json"));
    let parts = part_packet_files(&dir, provider_id);
    if single.is_file() {
        if !parts.is_empty() {
            return Err(invalid(format!(
                "lens packets for {provider_id} are ambiguous: both {provider_id}.json and numbered parts exist; rerun `legion audit --out`"
            )));
        }
        let work = parse_packet(&single)?;
        if let Some(part) = work.part() {
            return Err(invalid(format!(
                "{provider_id}.json is part {}/{} of a partitioned lens; part packets must be filed as {provider_id}.part-NNNN.json (rerun `legion audit --out` with a current CLI)",
                part.number, part.total
            )));
        }
        return Ok(work);
    }
    if parts.is_empty() {
        return parse_packet(&single);
    }
    let wanted = result.get("packetDigest").and_then(Value::as_str);
    let hinted = read_json(&dir.join(format!("{provider_id}.index.json")))
        .ok()
        .and_then(|index| {
            index
                .get("parts")?
                .as_array()?
                .iter()
                .find(|entry| entry.get("packetDigest").and_then(Value::as_str) == wanted)
                .and_then(|entry| entry.get("part")?.as_u64())
        })
        .and_then(|number| u32::try_from(number).ok());
    let mut ordered = parts.clone();
    if let Some(hint) = hinted {
        ordered.sort_by_key(|(number, _)| *number != hint);
    }
    for (number, path) in ordered {
        let work = parse_packet(&path)?;
        let digest =
            canonical_digest(&work.request.packet).map_err(|error| invalid(error.to_string()))?;
        if Some(digest.as_str()) == wanted {
            return match work.part() {
                Some(part) if part.number == number => Ok(work),
                _ => Err(invalid(format!(
                    "{} does not carry part number {number}",
                    path.display()
                ))),
            };
        }
    }
    Err(invalid(format!(
        "lens result for {provider_id}: packetDigest does not match any of the {} lens packet parts",
        parts.len()
    )))
}

/// Validates a lens result against the frozen run and, when accepted, writes a
/// MAC'd receipt to `<run>/lens-receipts/<provider>.json` (or
/// `<provider>.part-NNNN.json` for one part of a partitioned lens).
///
/// Result shape (`kind: legion-lens-result`):
/// `{schemaVersion:1, kind, provider, packetDigest, planDigest, complete:true,
///   findings:[{...lens schema fields, anchor:{path,line,text}}],
///   withdrawn:[{id, reason, disproof:{path,line,text}}],
///   verdicts:[{candidateId, verdict, ...}]  (legacy.security.adjudication only:
///     exactly one per packet `scannerCandidates` entry; a surviving verdict
///     also needs a finding with id `adjudicated:<candidateId>`),
///   details:{semanticReview?, changeRisk?}}`
///
/// `complete:true` only attests the submitter finished. Examined coverage is
/// computed from the paths the packet carried: omitted or truncated excerpts
/// leave a coverage gap and the receipt is `partial`, not `complete`.
pub fn ingest_lens_result(
    run_dir: &Path,
    provider_id: &str,
    result: &Value,
) -> Result<IngestedLens, AuditError> {
    if !REASONING_PROVIDER_IDS.contains(&provider_id) {
        return Err(invalid(format!(
            "{provider_id} is not a reasoning provider"
        )));
    }
    let who = format!("lens result for {provider_id}");

    // --- the frozen run -----------------------------------------------------
    let plan = read_json(&run_dir.join("plan.json"))?;
    let seal_digest = plan
        .pointer("/seal/digest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("plan.json has no seal digest"))?;
    let revision = plan
        .pointer("/binding/repositoryRevision")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("plan.json has no repository revision"))?;
    let plan_epoch = plan
        .pointer("/epoch/digest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("this run records no epoch; rerun `legion audit --out`"))?;
    let root = PathBuf::from(
        plan.get("repository")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("plan.json has no repository root"))?,
    );
    let (key, digest) = load_epoch(run_dir)?;
    if digest != plan_epoch {
        return Err(invalid(
            "epoch key does not match the epoch recorded in plan.json",
        ));
    }
    let execution: ExecutionReport =
        serde_json::from_value(read_json(&run_dir.join("execution.json"))?)
            .map_err(|error| invalid(format!("execution.json is invalid: {error}")))?;
    let stored_report: ReportV1 =
        legion_contracts::Report::read_any(&read_json(&run_dir.join("report.json"))?)
            .map(|report| report.v1_core())
            .map_err(|error| invalid(format!("report.json is invalid: {error}")))?;
    crate::verify::validate_effect_artifacts(run_dir, &plan, &stored_report, &execution)?;
    let slot = execution
        .results
        .iter()
        .find(|entry| entry.provider == provider_id)
        .ok_or_else(|| invalid(format!("{provider_id} is not part of this run")))?;
    if !execution
        .pending_host
        .iter()
        .any(|pending| pending == provider_id)
    {
        return Err(invalid(format!(
            "{provider_id} was not pending-host in this run"
        )));
    }
    let required = slot.result.required;

    // --- the lens packet -----------------------------------------------------
    let work = locate_packet(run_dir, provider_id, result)?;
    let part = work.part();
    let request = &work.request;
    request.validate().map_err(|error| {
        invalid(format!(
            "{error}; only signed plans can be ingested (set AUDIT_PLAN_SIGNING_KEY)"
        ))
    })?;
    if work.provider_id != provider_id
        || request.provider_id != provider_id
        || work.status != "pending-host"
    {
        return Err(invalid("lens packet does not belong to this provider"));
    }
    if request.plan_digest != seal_digest || request.inventory_generation != revision {
        return Err(invalid(
            "lens packet is not bound to this run's frozen plan",
        ));
    }
    if request.request_id != expected_request_id(&work)? {
        return Err(invalid(
            "lens packet binding was altered after the run froze",
        ));
    }
    verify_review_binding(
        run_dir,
        &plan,
        provider_id,
        &request.packet,
        &request.denominator_paths,
    )?;
    let packet_digest =
        canonical_digest(&request.packet).map_err(|error| invalid(error.to_string()))?;

    // --- the submitted result ------------------------------------------------
    if result.get("kind").and_then(Value::as_str) != Some(LENS_RESULT_KIND)
        || result.get("schemaVersion").and_then(Value::as_u64) != Some(1)
    {
        return Err(invalid(format!(
            "{who}: kind must be {LENS_RESULT_KIND} with schemaVersion 1"
        )));
    }
    if string_field(result, "provider", &who)? != provider_id {
        return Err(invalid(format!("{who}: provider does not match")));
    }
    if string_field(result, "packetDigest", &who)? != packet_digest {
        return Err(invalid(format!(
            "{who}: packetDigest does not match the lens packet (expected {packet_digest})"
        )));
    }
    if string_field(result, "planDigest", &who)? != request.plan_digest {
        return Err(invalid(format!(
            "{who}: planDigest does not match the frozen plan"
        )));
    }
    if result.get("complete").and_then(Value::as_bool) != Some(true) {
        return Err(invalid(format!(
            "{who}: must attest complete examination of the packet denominator; leave the lens pending instead"
        )));
    }
    let findings = array_field(result, "findings", &who)?;
    let withdrawn = array_field(result, "withdrawn", &who)?;
    let extra_details = match result.get("details") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(map)) => map.clone(),
        Some(_) => return Err(invalid(format!("{who}: `details` must be an object"))),
    };
    if let Some(key) = extra_details.keys().find(|key| {
        !matches!(
            key.as_str(),
            "semanticReview" | "changeRisk" | "candidateDispositions"
        )
    }) {
        return Err(invalid(format!(
            "{who}: details.{key} is not an accepted detail"
        )));
    }

    // --- findings against the lens schema -------------------------------------
    if let Some(lens) = lens_plan::lens_id_for_provider(provider_id) {
        lens_schemas::validate_lens_output(lens, &findings).map_err(|errors| {
            invalid(format!(
                "{who}: report-schema validation failed: {}",
                errors
                    .iter()
                    .map(|error| format!("{}: {}", error.field, error.reason))
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        })?;
    }

    // --- anchors against the frozen bytes ---------------------------------------
    let snapshot = plan
        .pointer("/reviewContext/snapshotManifest")
        .and_then(Value::as_str)
        .map(|path| crate::snapshot::FrozenSnapshot::open(Path::new(path)))
        .transpose()?;
    if let Some(snapshot) = &snapshot {
        let native = verify_persisted_native_plan(&plan, &execution, run_dir)?
            .ok_or_else(|| invalid("snapshot ingestion requires a sealed native plan"))?;
        let sealed_context = native
            .providers
            .iter()
            .find(|provider| provider.id.as_str() == provider_id)
            .and_then(|provider| provider.configuration.get("reasoning"))
            .and_then(|reasoning| reasoning.get("reviewContext"));
        if sealed_context != plan.get("reviewContext") {
            return Err(invalid(
                "anchor review context differs from sealed provider configuration",
            ));
        }
        snapshot.verify_source_current()?;
        if plan
            .pointer("/reviewContext/snapshotKey")
            .and_then(Value::as_str)
            != Some(snapshot.manifest.key.as_str())
        {
            return Err(invalid(
                "anchor snapshot key differs from frozen review context",
            ));
        }
    }
    // Restore the exact native inventory scope from the verified snapshot,
    // never from model-authored denominator paths or a mutable outer scope.
    let inventory = FilesystemInventorySource::new(&root)?
        .with_only_paths(
            snapshot
                .as_ref()
                .and_then(|snapshot| snapshot.manifest.scope.inventory_filter()),
        )
        .inventory(&request.repository_id)?;
    if inventory.generation != request.inventory_generation
        || inventory.digest != request.inventory_digest
    {
        return Err(AuditError::SourceDrift(
            "the scoped snapshot no longer matches the frozen inventory; rerun the audit".into(),
        ));
    }
    let frozen = FrozenFiles {
        root: &root,
        snapshot: snapshot.as_ref(),
        source_sides: request
            .packet
            .get("sourceSides")
            .cloned()
            .map(serde_json::from_value)
            .transpose()
            .map_err(|error| invalid(format!("packet sourceSides malformed: {error}")))?
            .unwrap_or_default(),
        digests: inventory
            .entries
            .iter()
            .filter_map(|entry| {
                entry
                    .digest
                    .clone()
                    .map(|digest| (entry.path.clone(), digest))
            })
            .collect(),
    };
    let mut anchors_verified = 0usize;
    let mut seen_ids = BTreeSet::new();
    let mut finding_refs = Vec::new();
    let mut titles = Map::new();
    let mut messages = Map::new();
    let mut locations = Map::new();
    let mut finding_evidence = Map::new();
    for (index, finding) in findings.iter().enumerate() {
        let id = string_field(finding, "id", &format!("{who} finding {index}"))?;
        let label = format!("{who} finding {id}");
        if !seen_ids.insert(id.to_owned()) {
            return Err(invalid(format!("{label}: duplicate finding id")));
        }
        let (path, line) = frozen.check(&label, finding.get("anchor"))?;
        ensure_variant_anchor_in_scope(provider_id, &request.denominator_paths, &path, &label)?;
        let evidence = finding
            .get("evidence")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !evidence_covers(&evidence, &path, line) {
            return Err(invalid(format!(
                "{label}: evidence must include a file:line entry covering the anchor {path}:{line}"
            )));
        }
        anchors_verified += 1;
        finding_refs.push(FindingRef {
            id: FindingId::new(id)?,
            severity: finding
                .get("severity")
                .and_then(Value::as_str)
                .unwrap_or("info")
                .to_owned(),
        });
        titles.insert(
            id.to_owned(),
            json!(finding
                .get("title")
                .or_else(|| finding.get("action"))
                .and_then(Value::as_str)
                .unwrap_or("Lens finding")),
        );
        messages.insert(
            id.to_owned(),
            json!(finding
                .get("failureScenario")
                .and_then(Value::as_str)
                .unwrap_or("Lens reported a finding")),
        );
        locations.insert(id.to_owned(), Value::Array(evidence));
        // Lens triage fields the lens schema defines, carried into the
        // public finding's evidence (the full finding stays in
        // `details.lensFindings`). Existing summary keys are unchanged.
        let mut triage = Map::new();
        for field in LENS_TRIAGE_FIELDS {
            if let Some(value) = finding.get(*field) {
                triage.insert((*field).to_owned(), value.clone());
            }
        }
        finding_evidence.insert(id.to_owned(), Value::Object(triage));
    }
    if let Some(part) = part {
        ensure_ids_unique_across_parts(run_dir, provider_id, part.number, &seen_ids)?;
    }
    for (index, entry) in withdrawn.iter().enumerate() {
        let id = string_field(entry, "id", &format!("{who} withdrawn {index}"))?;
        let label = format!("{who} withdrawn {id}");
        string_field(entry, "reason", &label)?;
        // A withdrawal is only accepted with the verbatim line that disproves the claim.
        let (path, _) = frozen.check(&label, entry.get("disproof"))?;
        ensure_variant_anchor_in_scope(provider_id, &request.denominator_paths, &path, &label)?;
        anchors_verified += 1;
    }

    // --- security verdicts (adjudicator only) --------------------------------------
    let submitted_verdicts = array_field(result, "verdicts", &who)?;
    let mut candidates_supplied = false;
    let mut verdict_details: Option<(Value, Value)> = None;
    // Staged adjudication: the per-stage ledger and any gaps it implies.
    let mut adjudication_ledger: Option<Value> = None;
    let mut ledger_gaps: Vec<String> = Vec::new();
    let stage_observations = if provider_id == ADJUDICATOR_PROVIDER_ID {
        runtime_adjudication(run_dir, request, &key, &digest)?
    } else {
        Vec::new()
    };
    let mut stage_context_attested = false;
    if provider_id == ADJUDICATOR_PROVIDER_ID {
        match request.packet.get("scannerCandidates") {
            Some(Value::Array(items))
                if request
                    .packet
                    .get("candidateWorkItems")
                    .is_some_and(|work| work.get("batches").is_some()) =>
            {
                // Triage, clusters, batches, confirmations and spot-checks:
                // rebuild the plan from the packet's own candidates and
                // frozen triage context, require it to match the packet, and
                // evaluate every submitted stage against it.
                let candidates: Vec<ScannerCandidate> =
                    serde_json::from_value(Value::Array(items.clone()))
                        .map_err(|error| invalid(format!("{who}: packet candidates: {error}")))?;
                let parent_packet_digest = adjudication_parent_packet_digest(&request.packet)
                    .map_err(|error| invalid(format!("{who}: {error}")))?;
                let triage_context: TriageContext = serde_json::from_value(
                    request
                        .packet
                        .pointer("/candidateWorkItems/triage/context")
                        .cloned()
                        .unwrap_or_else(|| json!({})),
                )
                .map_err(|error| invalid(format!("{who}: triage context: {error}")))?;
                let plan =
                    build_adjudication_plan(&candidates, &triage_context, &parent_packet_digest)
                        .map_err(|error| invalid(format!("{who}: {error}")))?;
                if request.packet.get("candidateWorkItems") != Some(&plan.to_value()) {
                    return Err(invalid(format!(
                        "{who}: adjudication plan does not match the batch candidates and parent packet digest"
                    )));
                }
                let stage_gaps = super::security_adjudication::validate_stage_observations(
                    &plan,
                    &candidates,
                    &submitted_verdicts,
                    &stage_observations,
                )
                .map_err(|error| invalid(format!("{who}: {error}")))?;
                stage_context_attested = !stage_observations.is_empty() && stage_gaps.is_empty();
                ledger_gaps.extend(stage_gaps);
                let mut outcome = evaluate_adjudication(&plan, &candidates, &submitted_verdicts)
                    .map_err(|error| invalid(format!("{who}: {error}")))?;
                if !stage_context_attested {
                    outcome.ledger.complete = false;
                }
                for verdict in outcome
                    .verdicts
                    .iter()
                    .filter(|verdict| verdict.verdict.is_surviving())
                {
                    let finding_id = format!("adjudicated:{}", verdict.candidate_id);
                    if !seen_ids.contains(&finding_id) {
                        return Err(invalid(format!(
                            "{who}: surviving verdict for {} needs an anchored finding with id {finding_id}",
                            verdict.candidate_id
                        )));
                    }
                }
                let confirmed = if stage_context_attested {
                    confirmed_findings(&candidates, &outcome.verdicts)
                } else {
                    Vec::new()
                };
                verdict_details = Some((
                    serde_json::to_value(&outcome.verdicts)
                        .map_err(|error| invalid(error.to_string()))?,
                    serde_json::to_value(&confirmed).map_err(|error| invalid(error.to_string()))?,
                ));
                let ledger = &outcome.ledger;
                if !ledger.complete {
                    let listed = ledger
                        .outstanding
                        .iter()
                        .take(5)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("; ");
                    ledger_gaps.push(format!(
                        "adjudication-incomplete:{provider_id}:{} outstanding item(s), {} contested, {} batch(es) voided; first: {listed}",
                        ledger.outstanding.len(),
                        ledger.contested.len(),
                        ledger.voided_batches.len()
                    ));
                }
                adjudication_ledger = Some(json!({
                    "ledger": ledger,
                    "autoTriaged": outcome.auto_triaged,
                }));
                candidates_supplied = true;
            }
            Some(Value::Array(items)) => {
                let candidates: Vec<ScannerCandidate> =
                    serde_json::from_value(Value::Array(items.clone()))
                        .map_err(|error| invalid(format!("{who}: packet candidates: {error}")))?;
                let parent_packet_digest = if request.packet.get("candidateWorkItems").is_some() {
                    let parent_packet_digest =
                        adjudication_parent_packet_digest(&request.packet)
                            .map_err(|error| invalid(format!("{who}: {error}")))?;
                    let child_work = adjudication_work_items(&candidates, &parent_packet_digest)
                        .map_err(|error| invalid(format!("{who}: {error}")))?;
                    let expected_child_binding = json!({
                        "parentPacketDigest": parent_packet_digest,
                        "items": child_work,
                    });
                    if request.packet.get("candidateWorkItems") != Some(&expected_child_binding) {
                        return Err(invalid(format!(
                            "{who}: isolated candidate work items do not match the batch candidates and parent packet digest"
                        )));
                    }
                    for (index, verdict) in submitted_verdicts.iter().enumerate() {
                        let candidate_id = verdict
                                .get("candidateId")
                                .and_then(Value::as_str)
                                .ok_or_else(|| {
                                    invalid(format!(
                                        "{who}: verdict {index} is missing candidateId for its isolated work item"
                                    ))
                                })?;
                        let item = child_work
                                .iter()
                                .find(|item| item.packet.candidate.id == candidate_id)
                                .ok_or_else(|| {
                                    invalid(format!(
                                        "{who}: verdict {index} names candidate {candidate_id} without isolated work"
                                    ))
                                })?;
                        let expected_packet_digest = canonical_digest(&item.packet)
                            .map_err(|error| invalid(error.to_string()))?;
                        if verdict.get("workItemId").and_then(Value::as_str)
                            != Some(item.item_id.as_str())
                            || verdict.get("workPacketDigest").and_then(Value::as_str)
                                != Some(expected_packet_digest.as_str())
                        {
                            return Err(invalid(format!(
                                "{who}: verdict for {candidate_id} is not bound to its isolated work item"
                            )));
                        }
                    }
                    parent_packet_digest
                } else {
                    // Historical packets contain only the batch candidate
                    // list. Keep their Derived behavior readable; the gap
                    // below still prevents a freshness claim.
                    packet_digest.clone()
                };
                let verdicts = adjudicate_scanner_candidates(
                    &candidates,
                    &submitted_verdicts,
                    &parent_packet_digest,
                )
                .map_err(|error| invalid(format!("{who}: {error}")))?;
                for verdict in verdicts
                    .iter()
                    .filter(|verdict| verdict.verdict.is_surviving())
                {
                    let finding_id = format!("adjudicated:{}", verdict.candidate_id);
                    if !seen_ids.contains(&finding_id) {
                        return Err(invalid(format!(
                            "{who}: surviving verdict for {} needs an anchored finding with id {finding_id}",
                            verdict.candidate_id
                        )));
                    }
                }
                // Legacy derived contexts carry no authenticated stage isolation.
                // Keep raw findings, but never promote them to host-confirmed.
                let confirmed: Vec<ConfirmedSecurityFinding> = Vec::new();
                verdict_details = Some((
                    serde_json::to_value(&verdicts).map_err(|error| invalid(error.to_string()))?,
                    serde_json::to_value(&confirmed).map_err(|error| invalid(error.to_string()))?,
                ));
                candidates_supplied = true;
            }
            Some(Value::Null) if submitted_verdicts.is_empty() => {
                if request
                    .packet
                    .get("candidateWorkItems")
                    .is_some_and(|value| !value.is_null())
                {
                    return Err(invalid(format!(
                        "{who}: unavailable scanner candidates require candidateWorkItems: null"
                    )));
                }
            }
            Some(_) => {
                return Err(invalid(format!(
                    "{who}: scannerCandidates must be an array or null"
                )));
            }
            None if submitted_verdicts.is_empty() => {
                if request
                    .packet
                    .get("candidateWorkItems")
                    .is_some_and(|value| !value.is_null())
                {
                    return Err(invalid(format!(
                        "{who}: unavailable scanner candidates require candidateWorkItems: null"
                    )));
                }
            }
            _ => {
                return Err(invalid(format!(
                    "{who}: verdicts submitted but the packet carries no scanner candidates"
                )));
            }
        }
    } else if !submitted_verdicts.is_empty() {
        return Err(invalid(format!(
            "{who}: only {ADJUDICATOR_PROVIDER_ID} accepts verdicts"
        )));
    }
    let mut sampled_packet = SampledPacket::from_coverage(
        request
            .packet
            .get("excerptCoverage")
            .filter(|value| value.is_object()),
    );
    if let Some(sampled_packet) = sampled_packet.as_mut() {
        sampled_packet.load_promotion(run_dir, provider_id)?;
    }
    let mut coverage = packet_coverage(
        provider_id,
        sampled_packet,
        &request.packet,
        &request.denominator_paths,
        candidates_supplied,
        part,
    );
    coverage.gaps.append(&mut ledger_gaps);
    coverage.gaps.extend(super::required_packet_gaps(request));
    if let Some(frozen) = frozen_coverage_for(&plan, provider_id) {
        if !frozen.mandatory_deferred.is_empty() {
            coverage.gaps.push(format!(
                "lens-mandatory-deferred:{provider_id}:{}",
                frozen.mandatory_deferred.len()
            ));
            coverage.detail["mandatoryDeferred"] = json!(frozen.mandatory_deferred);
        }
    }
    let verification = runtime_verification(run_dir, request, &key, &digest)?;
    if stage_observations.is_empty() {
        coverage.gaps.extend(verification_result_gaps(
            provider_id,
            verification.as_ref(),
            &findings,
            &withdrawn,
            &frozen,
        )?);
    }
    let delivery = runtime_delivery(run_dir, request, &key, &digest)?;
    if delivery.is_none() && stage_observations.is_empty() {
        coverage.gaps.push(format!(
            "delivery-unverified:{provider_id}:missing authenticated host transport receipt"
        ));
        coverage.examined = 0;
        coverage.detail["examined"] = json!(0);
        coverage.detail["examinedPaths"] = json!([]);
    }
    // Trigger witnesses are frozen before sampling; packets cannot replace
    // them with model-authored or post-freeze trigger claims.
    if let Some(provider) = plan
        .pointer("/nativePlan/plan/providers")
        .and_then(Value::as_array)
        .and_then(|providers| {
            providers
                .iter()
                .find(|provider| provider.get("id").and_then(Value::as_str) == Some(provider_id))
        })
    {
        if provider
            .pointer("/configuration/triggerEvidence")
            .filter(|value| !value.is_null())
            != request
                .packet
                .get("triggerEvidence")
                .filter(|value| !value.is_null())
        {
            coverage
                .gaps
                .push(format!("trigger-binding-mismatch:{provider_id}"));
        }
    }
    if let Some(witnesses) = request
        .packet
        .pointer("/triggerEvidence/mandatoryWitnessPaths")
        .and_then(Value::as_array)
    {
        let materialized: BTreeSet<String> = string_list(
            request
                .packet
                .pointer("/excerptCoverage/materializedPaths")
                .or_else(|| request.packet.pointer("/excerptCoverage/examinedPaths")),
        )
        .into_iter()
        .collect();
        let review: BTreeSet<String> = string_list(
            request
                .packet
                .pointer("/part/paths")
                .or_else(|| request.packet.pointer("/excerptCoverage/selectedPaths")),
        )
        .into_iter()
        .collect();
        for witness in witnesses.iter().filter_map(Value::as_str) {
            // Multi-part requests prove their own part; other parts reconcile
            // through their exact selected-path denominator.
            if (part.is_none() || review.contains(witness)) && !materialized.contains(witness) {
                coverage.gaps.push(format!(
                    "trigger-witness-undelivered:{provider_id}:{witness}"
                ));
            }
        }
    }
    // The batch entry point adjudicates under `ContextPolicy::Derived`: the
    // per-candidate context id is derived from the packet digest and the
    // candidate id, so naming it proves nothing about the context the verdict
    // was reached in. Record that as a coverage gap so the result can never be
    // read as a fresh-context attestation.
    let mut adjudication_context: Option<Value> = None;
    if provider_id == ADJUDICATOR_PROVIDER_ID
        && candidates_supplied
        && !submitted_verdicts.is_empty()
        && !stage_context_attested
    {
        let unnamed = submitted_verdicts
            .iter()
            .filter(|verdict| verdict.get("contextId").and_then(Value::as_str).is_none())
            .count();
        coverage.gaps.push(format!(
            "adjudication-context-derived:{provider_id}:{} verdicts under derived context policy, {unnamed} naming no context; not a fresh-context attestation",
            submitted_verdicts.len()
        ));
        adjudication_context = Some(json!({
            "policy": "derived",
            "attested": false,
            "verdicts": submitted_verdicts.len(),
            "verdictsNamingNoContext": unnamed,
        }));
    }
    let mut complete = coverage.gaps.is_empty();
    let mut status = if complete {
        ProviderStatus::Complete
    } else {
        ProviderStatus::Partial
    };

    // --- build the result and the MAC'd receipt ----------------------------------
    let expected = request.denominator_count;
    let mut details: BTreeMap<String, Value> = BTreeMap::new();
    details.insert("reasoningHostState".into(), json!("ingested"));
    details.insert("lensIds".into(), json!(work.lens_ids));
    details.insert("lensFindings".into(), Value::Array(findings.clone()));
    if let Some(dispositions) = result.get("candidateDispositions") {
        details.insert("candidateDispositions".into(), dispositions.clone());
    }
    details.insert("withdrawnFindings".into(), Value::Array(withdrawn.clone()));
    details.insert("findingTitles".into(), Value::Object(titles));
    details.insert("findingMessages".into(), Value::Object(messages));
    details.insert("findingLocations".into(), Value::Object(locations));
    details.insert("findingEvidence".into(), Value::Object(finding_evidence));
    details.insert(
        "ingest".into(),
        json!({
            "host": INGEST_HOST,
            "epochDigest": digest,
            "packetDigest": packet_digest,
            "anchorsVerified": anchors_verified,
        }),
    );
    details.insert("packetCoverage".into(), coverage.detail.clone());
    if let Some(evidence) = delivery {
        details.insert("deliveryEvidence".into(), evidence);
    }
    if let Some(evidence) = verification {
        details.insert("verificationEvidence".into(), evidence);
    }
    if !stage_observations.is_empty() {
        details.insert(
            "adjudicationDeliveryEvidence".into(),
            json!(stage_observations),
        );
        details.insert("rawAdjudicationVerdicts".into(), json!(submitted_verdicts));
    }
    if let Some((verdicts, confirmed)) = verdict_details {
        details.insert("securityVerdicts".into(), verdicts);
        details.insert("securityConfirmed".into(), confirmed);
    }
    if let Some(context) = adjudication_context {
        details.insert("adjudicationContext".into(), context);
    }
    if let Some(ledger) = adjudication_ledger {
        details.insert("adjudicationLedger".into(), ledger);
    }
    for (field, value) in extra_details {
        details.insert(field, value);
    }
    let provider = ProviderId::new(provider_id)?;
    let mut provider_result = ProviderResult {
        schema_version: 1,
        provider,
        applicable: true,
        required,
        status,
        complete,
        coverage: Some(Coverage {
            denominator_digest: request.denominator_digest.clone(),
            expected,
            examined: coverage.examined,
            gaps: coverage.gaps.clone(),
        }),
        findings: finding_refs,
        coverage_gaps: coverage.gaps.clone(),
        degradation: Vec::new(),
        details,
    };
    let candidate_gaps =
        super::pending_candidate_review_gaps(request, &provider_result).map_err(invalid)?;
    if !candidate_gaps.is_empty() {
        coverage.gaps.extend(candidate_gaps);
        complete = false;
        status = ProviderStatus::Partial;
        provider_result.complete = complete;
        provider_result.status = status;
        provider_result.coverage_gaps = coverage.gaps.clone();
        if let Some(value) = provider_result.coverage.as_mut() {
            value.gaps = coverage.gaps.clone();
        }
    }
    provider_result
        .validate()
        .map_err(|error| invalid(format!("{who}: {error}")))?;
    let result_digest =
        canonical_digest(&provider_result).map_err(|error| invalid(error.to_string()))?;
    let receipt_id = format!(
        "ingest-{}",
        canonical_digest(&json!({"requestId": request.request_id, "resultDigest": result_digest}))
            .map_err(|error| invalid(error.to_string()))?
            .trim_start_matches("sha256:")
            .chars()
            .take(32)
            .collect::<String>()
    );
    let mut receipt = ReasoningReceipt {
        schema_version: REASONING_RECEIPT_SCHEMA_VERSION,
        kind: REASONING_RECEIPT_KIND.into(),
        receipt_id: receipt_id.clone(),
        request_id: request.request_id.clone(),
        provider_id: provider_id.into(),
        contract: request.contract.clone(),
        plan_digest: request.plan_digest.clone(),
        plan_signature: request.plan_signature.clone(),
        repository_id: request.repository_id.clone(),
        inventory_generation: request.inventory_generation.clone(),
        inventory_digest: request.inventory_digest.clone(),
        denominator_digest: request.denominator_digest.clone(),
        denominator_count: request.denominator_count,
        result_digest,
        status,
        complete,
        gaps: coverage.gaps.clone(),
        authentication: Value::Null,
    };
    receipt.authentication =
        authenticate_receipt(&receipt, &key, INGEST_HOST, &digest).map_err(invalid)?;
    let paths: BTreeSet<&String> = request.denominator_paths.iter().collect();
    let denominator = InventoryDenominator {
        entries: inventory
            .entries
            .iter()
            .filter(|entry| paths.contains(&entry.path))
            .cloned()
            .collect(),
        digest: request.denominator_digest.clone(),
    };
    let response = ReasoningHostResponse {
        result: provider_result,
        receipt,
    };
    // The same reconciliation the in-process host path runs: receipt binding,
    // MAC, lens schema, semantic-review and change-risk validation.
    let accepted = verify_response(request, &denominator, &response, &key)
        .map_err(|error| invalid(format!("{who} rejected: {error}")))?;

    let mut stored = json!({
        "schemaVersion": 1,
        "kind": "legion-lens-receipt",
        "provider": provider_id,
        "result": accepted,
    });
    let receipt_name = match part {
        Some(part) => {
            stored["part"] = json!({"number": part.number, "total": part.total});
            format!("{provider_id}.part-{:04}.json", part.number)
        }
        None => format!("{provider_id}.json"),
    };
    let path = write_atomic(
        &run_dir.join(LENS_RECEIPT_DIR),
        &receipt_name,
        &serde_json::to_vec_pretty(&stored).map_err(|error| invalid(error.to_string()))?,
    )?;
    let mut ingested = IngestedLens {
        provider: provider_id.into(),
        lens_ids: work.lens_ids.clone(),
        findings: findings.len(),
        withdrawn: withdrawn.len(),
        anchors_verified,
        examined: coverage.examined,
        expected,
        complete,
        coverage_gaps: coverage.gaps,
        receipt_id,
        receipt_path: path.to_string_lossy().into_owned(),
        part: None,
        parts_total: None,
        parts_ingested: None,
        parts_pending: Vec::new(),
    };
    if let Some(part) = part {
        // Report the PROVIDER-level state after this part: the union over
        // every ingested part, with the outstanding work named.
        let loaded = load_receipts(run_dir, &plan, &execution, Some(provider_id))?;
        let merged = loaded
            .iter()
            .find(|entry| entry.provider == provider_id)
            .ok_or_else(|| invalid(format!("{who}: the ingested part receipt did not load")))?;
        ingested.examined = merged
            .result
            .coverage
            .as_ref()
            .map_or(0, |coverage| coverage.examined);
        ingested.complete = merged.result.complete;
        ingested.coverage_gaps = merged.result.coverage_gaps.clone();
        ingested.part = Some(part.number);
        if let Some(progress) = &merged.parts {
            ingested.parts_total = Some(progress.total);
            ingested.parts_ingested = Some(progress.ingested.len() as u32);
            ingested.parts_pending = progress.pending.clone();
        }
    }
    Ok(ingested)
}

/// Rejects a part whose finding ids collide with another ingested part's:
/// the consolidated report keys findings by id.
fn ensure_ids_unique_across_parts(
    run_dir: &Path,
    provider_id: &str,
    part_number: u32,
    ids: &BTreeSet<String>,
) -> Result<(), AuditError> {
    let dir = run_dir.join(LENS_RECEIPT_DIR);
    let prefix = format!("{provider_id}.part-");
    for entry in fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
    {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(other) = name
            .strip_prefix(prefix.as_str())
            .and_then(|rest| rest.strip_suffix(".json"))
            .and_then(|number| number.parse::<u32>().ok())
        else {
            continue;
        };
        if other == part_number {
            continue;
        }
        let Ok(value) = read_json(&entry.path()) else {
            continue;
        };
        let used = value
            .pointer("/result/details/lensFindings")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|finding| finding.get("id").and_then(Value::as_str));
        for id in used {
            if ids.contains(id) {
                return Err(invalid(format!(
                    "finding id {id} is already used by part {other} of {provider_id}; ids must be unique across parts (prefix with p{part_number:04}-)"
                )));
            }
        }
    }
    Ok(())
}

/// Reads `result_file` and ingests it. See `ingest_lens_result`.
/// Merges several result documents of the adjudicator into one result. The
/// adjudication evaluator needs the cumulative verdict set, so staged results
/// (batch stage, confirmation stage, ...) are ingested as one: verdict rows
/// are the union keyed by (`workItemId`, `stage`); a repeated key is rejected,
/// duplicate or conflicting alike. Findings and withdrawals are the union by
/// `id` (identical repeats collapse, differing repeats are rejected) and
/// `details` keys must agree. Header fields must be identical.
pub fn merge_adjudication_results(results: &[Value]) -> Result<Value, AuditError> {
    let Some(first) = results.first() else {
        return Err(invalid("no adjudication results to merge"));
    };
    if results.len() == 1 {
        return Ok(first.clone());
    }
    let who = format!("adjudication results for {ADJUDICATOR_PROVIDER_ID}");
    for result in results {
        for field in [
            "kind",
            "schemaVersion",
            "provider",
            "packetDigest",
            "planDigest",
        ] {
            if result.get(field) != first.get(field) {
                return Err(invalid(format!(
                    "{who}: `{field}` differs between results; results of one batch must share it"
                )));
            }
        }
        if result.get("complete").and_then(Value::as_bool) != Some(true) {
            return Err(invalid(format!(
                "{who}: every merged result must attest complete examination of its stage"
            )));
        }
    }
    let mut verdicts: Vec<Value> = Vec::new();
    let mut seen_rows: BTreeSet<(String, String)> = BTreeSet::new();
    let mut findings: BTreeMap<String, Value> = BTreeMap::new();
    let mut withdrawn: BTreeMap<String, Value> = BTreeMap::new();
    let mut details = Map::new();
    for result in results {
        for row in array_field(result, "verdicts", &who)? {
            let stage = row
                .get("stage")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            let item = row
                .get("workItemId")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .or_else(|| {
                    let candidate = row.get("candidateId").and_then(Value::as_str)?;
                    let batch = row.get("batchId").and_then(Value::as_str).unwrap_or("");
                    Some(format!("{batch}|{candidate}"))
                })
                .ok_or_else(|| invalid(format!("{who}: verdict row has no workItemId")))?;
            if !seen_rows.insert((item.clone(), stage.clone())) {
                return Err(invalid(format!(
                    "{who}: duplicate or conflicting verdict row for workItemId {item} stage {stage}"
                )));
            }
            verdicts.push(row);
        }
        for (field, into) in [("findings", &mut findings), ("withdrawn", &mut withdrawn)] {
            for entry in array_field(result, field, &who)? {
                let id = string_field(&entry, "id", &format!("{who} {field}"))?.to_owned();
                match into.get(&id) {
                    Some(existing) if *existing != entry => {
                        return Err(invalid(format!(
                            "{who}: conflicting {field} entries for id {id}"
                        )));
                    }
                    Some(_) => {}
                    None => {
                        into.insert(id, entry);
                    }
                }
            }
        }
        if let Some(Value::Object(map)) = result.get("details") {
            for (key, value) in map {
                match details.get(key) {
                    Some(existing) if existing != value => {
                        return Err(invalid(format!(
                            "{who}: conflicting details.{key} between results"
                        )));
                    }
                    _ => {
                        details.insert(key.clone(), value.clone());
                    }
                }
            }
        }
    }
    let mut merged = first.clone();
    if let Some(object) = merged.as_object_mut() {
        object.insert("verdicts".into(), Value::Array(verdicts));
        object.insert(
            "findings".into(),
            Value::Array(findings.into_values().collect()),
        );
        object.insert(
            "withdrawn".into(),
            Value::Array(withdrawn.into_values().collect()),
        );
        if !details.is_empty() {
            object.insert("details".into(), Value::Object(details));
        }
    }
    Ok(merged)
}

/// Ingests several adjudicator result files as one merged result (see
/// `merge_adjudication_results`).
pub fn ingest_adjudication_result_files(
    run_dir: &Path,
    result_files: &[PathBuf],
) -> Result<IngestedLens, AuditError> {
    let results = result_files
        .iter()
        .map(|file| read_json(file))
        .collect::<Result<Vec<_>, _>>()?;
    let merged = merge_adjudication_results(&results)?;
    ingest_lens_result(run_dir, ADJUDICATOR_PROVIDER_ID, &merged)
}

pub fn ingest_lens_result_file(
    run_dir: &Path,
    provider_id: &str,
    result_file: &Path,
) -> Result<IngestedLens, AuditError> {
    let result = read_json(result_file)?;
    ingest_lens_result(run_dir, provider_id, &result)
}

// ---------------------------------------------------------------------------
// Verdict recomputation
// ---------------------------------------------------------------------------

/// The verdict rebuilt from the original execution and the ingested receipts.
#[derive(Clone, Debug)]
pub struct Recomputed {
    pub report: ReportV1,
    pub execution: ExecutionReport,
    /// Providers whose lens is backed by a verified ingested receipt.
    pub ingested: Vec<String>,
    /// Reasoning providers still `pending-host`, including partitioned
    /// providers with parts not yet ingested (see `lens_parts`).
    pub pending: Vec<String>,
    /// Surviving security verdicts from ingested adjudication receipts: the
    /// trigger for variant analysis.
    pub confirmed_security: Vec<ConfirmedSecurityFinding>,
    /// Part progress of every partitioned provider with at least one
    /// ingested part (also reported as the `lensParts` report claim).
    pub lens_parts: BTreeMap<String, PartsProgress>,
}

fn verify_ingested(
    provider: &str,
    result: &ProviderResult,
    key: &[u8],
    epoch: &str,
    execution: &ExecutionReport,
) -> Result<(), AuditError> {
    let who = format!("lens receipt for {provider}");
    let receipt: ReasoningReceipt = serde_json::from_value(
        result
            .details
            .get("executionReceipt")
            .cloned()
            .ok_or_else(|| invalid(format!("{who}: result carries no receipt")))?,
    )
    .map_err(|error| invalid(format!("{who}: {error}")))?;
    verify_authenticated_receipt(&receipt, key)
        .map_err(|error| invalid(format!("{who}: {error}")))?;
    if receipt
        .authentication
        .get("epochDigest")
        .and_then(Value::as_str)
        != Some(epoch)
    {
        return Err(invalid(format!("{who}: minted under a different epoch")));
    }
    let mut bare = result.clone();
    bare.details.remove("executionReceipt");
    let bare_digest = canonical_digest(&bare).map_err(|error| invalid(error.to_string()))?;
    if bare_digest != receipt.result_digest {
        return Err(invalid(format!("{who}: result was altered after ingest")));
    }
    if receipt.provider_id != provider
        || result.provider.to_string() != provider
        || receipt.plan_digest != execution.plan_digest
        || receipt.inventory_digest != execution.inventory_digest
        || receipt.inventory_generation != execution.generation
        || receipt.complete != result.complete
        || receipt.status != result.status
        || receipt.gaps != result.coverage_gaps
        || (receipt.complete && !receipt.gaps.is_empty())
    {
        return Err(invalid(format!(
            "{who}: not bound to this run or its completeness is inconsistent"
        )));
    }
    if !execution
        .pending_host
        .iter()
        .any(|pending| pending == provider)
    {
        return Err(invalid(format!(
            "{who}: provider was not pending-host in this run"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Receipts: single and per-part
// ---------------------------------------------------------------------------

/// Progress of a partitioned provider.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PartsProgress {
    pub total: u32,
    pub ingested: Vec<u32>,
    pub pending: Vec<u32>,
}

/// One provider's verified receipt state: the result the verdict is rebuilt
/// from (the union over parts for a partitioned provider) and its progress.
struct LoadedReceipt {
    provider: String,
    result: ProviderResult,
    parts: Option<PartsProgress>,
}

fn string_at<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}

/// Merges the verified per-part results of one provider into the single
/// provider-level result: examined coverage is the union of the ingested
/// parts' paths (plus split files whose every chunk was covered), the provider
/// is complete only when every part is ingested and nothing is omitted or
/// unscheduled, and the outstanding work is named in the gaps.
fn merge_parts(
    provider: &str,
    mut parts: Vec<(u32, u32, ProviderResult)>,
) -> Result<(ProviderResult, PartsProgress), AuditError> {
    let who = format!("lens receipts for {provider}");
    parts.sort_by_key(|(number, _, _)| *number);
    let total = parts
        .first()
        .map(|(_, total, _)| *total)
        .ok_or_else(|| invalid(format!("{who}: no parts")))?;
    let template = parts[0].2.clone();
    let template_coverage = template
        .coverage
        .clone()
        .ok_or_else(|| invalid(format!("{who}: part result carries no coverage")))?;

    let mut examined_paths: BTreeSet<String> = BTreeSet::new();
    let mut chunk_state: BTreeMap<String, (u64, BTreeSet<u64>)> = BTreeMap::new();
    let mut omitted: BTreeMap<String, String> = BTreeMap::new();
    let mut over_ceiling = Value::Null;
    let mut finding_refs: Vec<FindingRef> = Vec::new();
    let mut finding_ids: BTreeSet<String> = BTreeSet::new();
    let mut lens_findings: Vec<Value> = Vec::new();
    let mut withdrawn: Vec<Value> = Vec::new();
    let mut titles = Map::new();
    let mut messages = Map::new();
    let mut locations = Map::new();
    let mut evidence = Map::new();
    let mut anchors_verified = 0u64;
    let mut part_receipts: Vec<Value> = Vec::new();
    let mut ingest_parts: Vec<Value> = Vec::new();
    let mut semantic_reviews: Vec<(u32, Value)> = Vec::new();
    let mut change_risks: Vec<(u32, Value)> = Vec::new();
    let mut ingested: Vec<u32> = Vec::new();
    let mut inherited_gaps = BTreeSet::new();
    // Risk-sampled lenses: review-set expectation and alias credit.
    let mut sampled_meta: Option<(usize, usize, usize, String, String, usize)> = None;
    let mut alias_pairs: Vec<(String, String)> = Vec::new();

    for (number, file_total, result) in &parts {
        let coverage = result
            .coverage
            .as_ref()
            .ok_or_else(|| invalid(format!("{who}: part {number} carries no coverage")))?;
        let packet_coverage = result
            .details
            .get("packetCoverage")
            .ok_or_else(|| invalid(format!("{who}: part {number} records no packet coverage")))?;
        let recorded_number = packet_coverage
            .pointer("/part/number")
            .and_then(Value::as_u64);
        let recorded_total = packet_coverage
            .pointer("/part/total")
            .and_then(Value::as_u64);
        if recorded_number != Some(u64::from(*number))
            || recorded_total != Some(u64::from(*file_total))
            || *file_total != total
            || coverage.denominator_digest != template_coverage.denominator_digest
            || coverage.expected != template_coverage.expected
        {
            return Err(invalid(format!(
                "{who}: part {number} is not consistent with the other parts of this run"
            )));
        }
        ingested.push(*number);
        // Only this deliberate part-scope gap is resolved by unioning parts.
        // Authentication, unresolved verification & source delivery gaps survive.
        let scope_gap = format!("reasoning-part-scope:{provider}:part {number}/{total}");
        inherited_gaps.extend(
            result
                .coverage_gaps
                .iter()
                .chain(coverage.gaps.iter())
                .filter(|gap| *gap != &scope_gap)
                .cloned(),
        );
        if !result.complete && result.coverage_gaps.is_empty() && coverage.gaps.is_empty() {
            inherited_gaps.insert(format!(
                "reasoning-part-incomplete:{provider}:part {number}/{total}"
            ));
        }
        if over_ceiling.is_null() {
            if let Some(value) = packet_coverage.get("overCeiling").filter(|v| !v.is_null()) {
                over_ceiling = value.clone();
            }
        }
        examined_paths.extend(string_list(packet_coverage.get("examinedPaths")));
        if packet_coverage.get("coverageMode").and_then(Value::as_str)
            == Some(coverage_plan::MODE_RISK_SAMPLED)
        {
            let field = |name: &str| {
                packet_coverage
                    .get(name)
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as usize
            };
            let meta = (
                field("reviewExpected"),
                field("declaredUnsampled"),
                field("excluded"),
                packet_coverage
                    .get("reviewSetDigest")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                packet_coverage
                    .get("bundle")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                field("unpromotedCount"),
            );
            if let Some(existing) = &sampled_meta {
                if *existing != meta {
                    return Err(invalid(format!(
                        "{who}: part {number} disagrees on the frozen review set"
                    )));
                }
            } else {
                sampled_meta = Some(meta);
            }
            for item in packet_coverage
                .get("aliasedPaths")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let (Some(path), Some(of)) = (
                    item.get("path").and_then(Value::as_str),
                    item.get("of").and_then(Value::as_str),
                ) {
                    alias_pairs.push((path.to_owned(), of.to_owned()));
                }
            }
        } else if sampled_meta.is_some() {
            return Err(invalid(format!(
                "{who}: part {number} mixes risk-sampled and exhaustive packets"
            )));
        }
        for item in packet_coverage
            .get("chunkedPaths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(path), Some(chunk), Some(chunks)) = (
                item.get("path").and_then(Value::as_str),
                item.get("chunk").and_then(Value::as_u64),
                item.get("chunks").and_then(Value::as_u64),
            ) else {
                return Err(invalid(format!(
                    "{who}: part {number} has a malformed chunk record"
                )));
            };
            let state = chunk_state
                .entry(path.to_owned())
                .or_insert((chunks, BTreeSet::new()));
            if state.0 != chunks {
                return Err(invalid(format!(
                    "{who}: part {number} disagrees on the chunk count of {path}"
                )));
            }
            state.1.insert(chunk);
        }
        for item in packet_coverage
            .get("omittedPaths")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(path) = item.get("path").and_then(Value::as_str) {
                omitted.insert(
                    path.to_owned(),
                    item.get("reason")
                        .and_then(Value::as_str)
                        .unwrap_or("omitted")
                        .to_owned(),
                );
            }
        }
        for finding in &result.findings {
            if !finding_ids.insert(finding.id.as_str().to_owned()) {
                return Err(invalid(format!(
                    "{who}: finding id {} appears in more than one part",
                    finding.id
                )));
            }
            finding_refs.push(finding.clone());
        }
        let detail_array = |field: &str| {
            result
                .details
                .get(field)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        lens_findings.extend(detail_array("lensFindings"));
        withdrawn.extend(detail_array("withdrawnFindings"));
        for (field, target) in [
            ("findingTitles", &mut titles),
            ("findingMessages", &mut messages),
            ("findingLocations", &mut locations),
            ("findingEvidence", &mut evidence),
        ] {
            if let Some(Value::Object(map)) = result.details.get(field) {
                for (key, value) in map {
                    target.insert(key.clone(), value.clone());
                }
            }
        }
        anchors_verified += result
            .details
            .get("ingest")
            .and_then(|ingest| ingest.get("anchorsVerified"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let receipt = result.details.get("executionReceipt");
        part_receipts.push(json!({
            "part": number,
            "receiptId": receipt.and_then(|r| r.get("receiptId")),
            "requestId": receipt.and_then(|r| r.get("requestId")),
        }));
        ingest_parts.push(json!({
            "part": number,
            "packetDigest": result.details.get("ingest").and_then(|i| i.get("packetDigest")),
        }));
        if let Some(review) = result.details.get("semanticReview") {
            semantic_reviews.push((*number, review.clone()));
        }
        if let Some(risk) = result.details.get("changeRisk") {
            change_risks.push((*number, risk.clone()));
        }
    }

    let mut covered = examined_paths;
    let mut partial: Vec<String> = Vec::new();
    for (path, (chunks, seen)) in &chunk_state {
        if covered.contains(path) {
            continue;
        }
        if (1..=*chunks).all(|chunk| seen.contains(&chunk)) {
            covered.insert(path.clone());
        } else {
            partial.push(path.clone());
        }
    }
    for (alias, canonical) in &alias_pairs {
        if covered.contains(canonical) {
            covered.insert(alias.clone());
        }
    }
    for path in omitted.keys() {
        covered.remove(path);
    }
    let expected = template_coverage.expected;
    // Risk-sampled: complete against the frozen review set; numeric `examined`
    // credits the declared-unsampled paths so expected == denominator count
    // stays exact (the honest split is in packetCoverage and `lensCoverage`).
    let (review_expected, declared_unsampled) = match &sampled_meta {
        Some((review, declared, _, _, _, _)) => (*review as u64, *declared as u64),
        None => (expected, 0),
    };
    let review_examined = (covered.len() as u64).min(review_expected);
    let examined = (review_examined + declared_unsampled).min(expected);
    let pending: Vec<u32> = (1..=total).filter(|n| !ingested.contains(n)).collect();

    let mut gaps = inherited_gaps.into_iter().collect::<Vec<_>>();
    if !pending.is_empty() {
        gaps.push(format!(
            "reasoning-parts-pending:{provider}:{}/{}",
            ingested.len(),
            total
        ));
    }
    if let Some(object) = over_ceiling.as_object() {
        gaps.push(format!(
            "reasoning-denominator-over-ceiling:{provider}:{} parts required, ceiling {}, {} paths unscheduled",
            object.get("requiredParts").and_then(Value::as_u64).unwrap_or(0),
            object.get("ceiling").and_then(Value::as_u64).unwrap_or(0),
            object.get("unscheduledPathCount").and_then(Value::as_u64).unwrap_or(0),
        ));
    }
    if pending.is_empty() && review_examined < review_expected {
        gaps.push(format!(
            "reasoning-excerpt-coverage:{provider}:{review_examined}/{review_expected} {}paths examined ({} omitted, {} partially covered)",
            if sampled_meta.is_some() { "review-set " } else { "" },
            omitted.len(),
            partial.len()
        ));
    }
    if let Some((_, _, _, _, _, capped)) = &sampled_meta {
        if *capped > 0 {
            gaps.push(format!("lens-promotion-capped:{capped}"));
        }
    }
    let complete = gaps.is_empty() && examined >= expected;

    let mut details: BTreeMap<String, Value> = BTreeMap::new();
    details.insert("reasoningHostState".into(), json!("ingested"));
    details.insert(
        "lensIds".into(),
        template
            .details
            .get("lensIds")
            .cloned()
            .unwrap_or(Value::Array(Vec::new())),
    );
    details.insert("lensFindings".into(), Value::Array(lens_findings));
    details.insert("withdrawnFindings".into(), Value::Array(withdrawn));
    details.insert("findingTitles".into(), Value::Object(titles));
    details.insert("findingMessages".into(), Value::Object(messages));
    details.insert("findingLocations".into(), Value::Object(locations));
    details.insert("findingEvidence".into(), Value::Object(evidence));
    details.insert(
        "ingest".into(),
        json!({
            "host": INGEST_HOST,
            "epochDigest": template.details.get("ingest").and_then(|i| i.get("epochDigest")),
            "anchorsVerified": anchors_verified,
            "parts": ingest_parts,
        }),
    );
    details.insert("partReceipts".into(), Value::Array(part_receipts));
    let sampled_detail =
        sampled_meta
            .as_ref()
            .map(|(review, declared, excluded, digest, bundle, capped)| {
                json!({
                    "coverageMode": coverage_plan::MODE_RISK_SAMPLED,
                    "reviewExpected": review,
                    "reviewExamined": review_examined,
                    "declaredUnsampled": declared,
                    "excluded": excluded,
                    "reviewSetDigest": digest,
                    "bundle": bundle,
                    "unpromoted": capped,
                })
            });
    details.insert(
        "packetCoverage".into(),
        json!({
            "basis": "bounded-excerpts",
            "examined": examined,
            "expected": expected,
            "sampled": sampled_detail,
            "partsTotal": total,
            "partsIngested": ingested,
            "partsPending": pending,
            "omittedPaths": omitted
                .iter()
                .map(|(path, reason)| json!({"path": path, "reason": reason}))
                .collect::<Vec<_>>(),
            "partiallyCoveredPaths": partial,
            "overCeiling": over_ceiling,
        }),
    );
    if !semantic_reviews.is_empty() {
        details.insert(
            "semanticReview".into(),
            merge_semantic_reviews(&semantic_reviews, !pending.is_empty()),
        );
    }
    if !change_risks.is_empty() {
        details.insert("changeRisk".into(), merge_change_risks(&change_risks));
    }

    let result = ProviderResult {
        schema_version: 1,
        provider: template.provider.clone(),
        applicable: true,
        required: template.required,
        status: if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
        },
        complete,
        coverage: Some(Coverage {
            denominator_digest: template_coverage.denominator_digest.clone(),
            expected,
            examined,
            gaps: gaps.clone(),
        }),
        findings: finding_refs,
        coverage_gaps: gaps,
        degradation: Vec::new(),
        details,
    };
    result
        .validate()
        .map_err(|error| invalid(format!("{who}: {error}")))?;
    Ok((
        result,
        PartsProgress {
            total,
            ingested,
            pending,
        },
    ))
}

/// Union of per-part semantic reviews: any unproven part (or an outstanding
/// part) leaves the axis unproven; otherwise findings > pass > not-applicable.
fn merge_semantic_reviews(reviews: &[(u32, Value)], parts_pending: bool) -> Value {
    let axis = reviews
        .iter()
        .find_map(|(_, review)| review.get("axis").and_then(Value::as_str))
        .unwrap_or("");
    let statuses: Vec<&str> = reviews
        .iter()
        .filter_map(|(_, review)| review.get("status").and_then(Value::as_str))
        .collect();
    let status = if parts_pending || statuses.contains(&"unproven") {
        "unproven"
    } else if statuses.contains(&"findings") {
        "findings"
    } else if statuses.contains(&"pass") {
        "pass"
    } else {
        "not-applicable"
    };
    let mut reasons = reviews
        .iter()
        .map(|(number, review)| {
            format!(
                "part {number}: {}",
                review.get("reason").and_then(Value::as_str).unwrap_or("")
            )
        })
        .collect::<Vec<_>>();
    if parts_pending {
        reasons.push("some packet parts are not yet reviewed".to_owned());
    }
    let sources = reviews
        .iter()
        .flat_map(|(_, review)| {
            review
                .get("sources")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        })
        .collect::<Vec<_>>();
    json!({"axis": axis, "status": status, "reason": reasons.join("; "), "sources": sources})
}

/// Union of per-part change-risk records: the most severe reversibility wins
/// (`one-way` > `unknown` > `reversible`), reasons and evidence concatenate.
fn merge_change_risks(risks: &[(u32, Value)]) -> Value {
    let reversibilities: Vec<&str> = risks
        .iter()
        .filter_map(|(_, risk)| risk.get("reversibility").and_then(Value::as_str))
        .collect();
    let reversibility = if reversibilities.contains(&"one-way") {
        "one-way"
    } else if reversibilities.contains(&"unknown") {
        "unknown"
    } else {
        "reversible"
    };
    let join = |field: &str| {
        let mut seen = Vec::new();
        for (_, risk) in risks {
            if let Some(text) = risk.get(field).and_then(Value::as_str) {
                if !seen.contains(&text) {
                    seen.push(text);
                }
            }
        }
        seen.join("; ")
    };
    let evidence = |field: &str| {
        let mut out: Vec<Value> = Vec::new();
        for (_, risk) in risks {
            for item in risk
                .get(field)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if !out.contains(item) {
                    out.push(item.clone());
                }
            }
        }
        out
    };
    json!({
        "reversibility": reversibility,
        "blastRadius": join("blastRadius"),
        "reason": join("reason"),
        "beforeEvidence": evidence("beforeEvidence"),
        "afterEvidence": evidence("afterEvidence"),
    })
}

/// Loads and verifies every lens receipt (optionally only `only`'s). A
/// partitioned provider's `<provider>.part-NNNN.json` receipts are each
/// verified independently (MAC, epoch, plan binding, result digest) and then
/// merged into one provider-level result.
fn load_receipts(
    run_dir: &Path,
    plan: &Value,
    execution: &ExecutionReport,
    only: Option<&str>,
) -> Result<Vec<LoadedReceipt>, AuditError> {
    let dir = run_dir.join(LENS_RECEIPT_DIR);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let plan_epoch = plan
        .pointer("/epoch/digest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("lens receipts are present but the run records no epoch"))?;
    let (key, digest) = load_epoch(run_dir)?;
    if digest != plan_epoch {
        return Err(invalid(
            "epoch key does not match the epoch recorded in plan.json",
        ));
    }
    let mut files = fs::read_dir(&dir)
        .map_err(|error| io(error, "could not list lens receipts"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".json") && !name.starts_with('.'))
        })
        .collect::<Vec<_>>();
    files.sort();
    let mut singles: Vec<LoadedReceipt> = Vec::new();
    let mut grouped: BTreeMap<String, Vec<(u32, u32, ProviderResult)>> = BTreeMap::new();
    for file in files {
        let value = read_json(&file)?;
        let provider = value
            .get("provider")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid(format!("{} names no provider", file.display())))?
            .to_owned();
        if only.is_some_and(|only| only != provider) {
            continue;
        }
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let part = value
            .get("part")
            .filter(|part| !part.is_null())
            .map(|part| {
                (
                    part.get("number").and_then(Value::as_u64),
                    part.get("total").and_then(Value::as_u64),
                )
            });
        let result: ProviderResult =
            serde_json::from_value(value.get("result").cloned().unwrap_or(Value::Null))
                .map_err(|error| invalid(format!("{}: {error}", file.display())))?;
        match part {
            None => {
                if name != format!("{provider}.json") {
                    return Err(invalid(format!(
                        "{} is filed under the wrong provider",
                        file.display()
                    )));
                }
                verify_ingested(&provider, &result, &key, &digest, execution)?;
                singles.push(LoadedReceipt {
                    provider,
                    result,
                    parts: None,
                });
            }
            Some((Some(number), Some(total))) => {
                let (number, total) = match (u32::try_from(number), u32::try_from(total)) {
                    (Ok(number), Ok(total)) if number >= 1 && number <= total => (number, total),
                    _ => {
                        return Err(invalid(format!(
                            "{} records an invalid part number",
                            file.display()
                        )));
                    }
                };
                if name != format!("{provider}.part-{number:04}.json") {
                    return Err(invalid(format!(
                        "{} is filed under the wrong provider or part",
                        file.display()
                    )));
                }
                verify_ingested(&provider, &result, &key, &digest, execution)?;
                grouped
                    .entry(provider)
                    .or_default()
                    .push((number, total, result));
            }
            Some(_) => {
                return Err(invalid(format!(
                    "{} records an invalid part",
                    file.display()
                )));
            }
        }
    }
    for (provider, parts) in grouped {
        if singles.iter().any(|single| single.provider == provider) {
            return Err(invalid(format!(
                "lens receipts for {provider} mix a whole-lens receipt with part receipts"
            )));
        }
        let (result, progress) = merge_parts(&provider, parts)?;
        singles.push(LoadedReceipt {
            provider,
            result,
            parts: Some(progress),
        });
    }
    singles.sort_by(|left, right| left.provider.cmp(&right.provider));
    Ok(singles)
}

// ---------------------------------------------------------------------------
// Packet files and the part index
// ---------------------------------------------------------------------------

pub const LENS_INDEX_KIND: &str = "legion-lens-packet-index";

/// The `<provider>.index.json` for a partitioned provider: every part, its
/// packet digest and request id, and the paths homed in it. `None` for a
/// provider whose denominator fits one un-numbered packet.
fn part_index(items: &[&PendingLensWork]) -> Result<Option<Value>, AuditError> {
    let Some(first) = items.first() else {
        return Ok(None);
    };
    if first.part().is_none() {
        return Ok(None);
    }
    let mut parts = Vec::new();
    for item in items {
        let Some(part) = item.part() else {
            return Err(invalid(format!(
                "{} mixes numbered and un-numbered packets",
                item.provider_id
            )));
        };
        let meta = item
            .request
            .packet
            .get("part")
            .cloned()
            .unwrap_or(Value::Null);
        let paths = meta.get("paths").cloned().unwrap_or(Value::Null);
        parts.push(json!({
            "part": part.number,
            "file": item.packet_file_name(),
            "packetDigest": canonical_digest(&item.request.packet)
                .map_err(|error| invalid(error.to_string()))?,
            "requestId": item.request.request_id,
            "pathCount": paths.as_array().map_or(0, Vec::len),
            "pathsDigest": meta.get("pathsDigest"),
            "paths": paths,
            "continuedPaths": meta.get("continuedPaths"),
            "chunkCount": item
                .request
                .packet
                .get("excerpts")
                .and_then(Value::as_array)
                .map_or(0, Vec::len),
            "omitted": item.request.packet.pointer("/excerptCoverage/omittedPaths"),
        }));
    }
    let meta = first
        .request
        .packet
        .get("part")
        .cloned()
        .unwrap_or(Value::Null);
    Ok(Some(json!({
        "schemaVersion": 1,
        "kind": LENS_INDEX_KIND,
        "provider": first.provider_id,
        "planDigest": first.request.plan_digest,
        "denominatorDigest": first.request.denominator_digest,
        "denominatorCount": first.request.denominator_count,
        "totalParts": items.len(),
        "requiredParts": meta.get("requiredParts"),
        "overCeiling": meta.get("overCeiling"),
        "parts": parts,
    })))
}

/// Per-provider status items for pending lens work, in the shape the CLI
/// reports (`provider`, `lensIds`, `status`, `packet`, `packetDigest`,
/// `planDigest`), plus for a partitioned provider `parts` (each with its
/// packet path, digest and path count), `partsTotal` and `index`. `packet` is
/// the single packet, or the first part, so existing consumers keep working.
/// `packet_dir` is where the packets were (or will be) written.
pub fn lens_packet_items(
    work: &[PendingLensWork],
    packet_dir: Option<&Path>,
) -> Result<Vec<Value>, AuditError> {
    let mut order: Vec<&str> = Vec::new();
    for item in work {
        if !order.contains(&item.provider_id.as_str()) {
            order.push(item.provider_id.as_str());
        }
    }
    let mut out = Vec::new();
    for provider in order {
        let items: Vec<&PendingLensWork> = work
            .iter()
            .filter(|item| item.provider_id == provider)
            .collect();
        let first = items[0];
        let path_of =
            |item: &PendingLensWork| packet_dir.map(|dir| dir.join(item.packet_file_name()));
        let digest_of = |item: &PendingLensWork| {
            canonical_digest(&item.request.packet).map_err(|error| invalid(error.to_string()))
        };
        let mut entry = json!({
            "provider": first.provider_id,
            "lensIds": first.lens_ids,
            "status": "pending-host",
            "packet": path_of(first),
            "packetDigest": digest_of(first)?,
            "planDigest": first.request.plan_digest,
        });
        if first.part().is_some() {
            let mut listed = Vec::new();
            for item in items.iter().copied() {
                let meta = item
                    .request
                    .packet
                    .get("part")
                    .cloned()
                    .unwrap_or(Value::Null);
                listed.push(json!({
                    "part": item.part().map(|part| part.number),
                    "packet": path_of(item),
                    "packetDigest": digest_of(item)?,
                    "requestId": item.request.request_id,
                    "pathCount": meta.get("paths").and_then(Value::as_array).map_or(0, Vec::len),
                    "status": "pending-host",
                }));
            }
            let meta = first
                .request
                .packet
                .get("part")
                .cloned()
                .unwrap_or(Value::Null);
            entry["partsTotal"] = json!(items.len());
            entry["requiredParts"] = meta.get("requiredParts").cloned().unwrap_or(Value::Null);
            entry["overCeiling"] = meta.get("overCeiling").cloned().unwrap_or(Value::Null);
            entry["index"] =
                json!(packet_dir.map(|dir| dir.join(format!("{provider}.index.json"))));
            entry["parts"] = Value::Array(listed);
        }
        out.push(entry);
    }
    Ok(out)
}

/// Limits a lens packet set is gated against before the plan is frozen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LensSizeLimits {
    /// Largest estimated token count one seat (one packet part) may carry.
    pub seat_token_budget: u64,
    /// Most seats (packet parts, summed over every lens) the host can run.
    pub max_seats: u64,
}

/// Default per-seat token budget (estimated tokens of one seat, 150k).
pub const DEFAULT_SEAT_TOKEN_BUDGET: u64 = coverage_plan::DEFAULT_SEAT_TOKEN_BUDGET;
/// Default host child-agent cap (`CHILD_AGENTS_MAX` in the Audit manual).
pub const DEFAULT_MAX_SEATS: u64 = coverage_plan::WAVE_WIDTH;
/// Default total admission budget: estimated rendered input plus reserved output
/// across every call, including follow-ups, verification & retries. Cached input
/// is a subset of input; actual overruns reconcile without refunding spend.
pub const DEFAULT_RUN_TOKEN_BUDGET: u64 = coverage_plan::DEFAULT_RUN_TOKEN_BUDGET;
/// Default cap on seats across all waves.
pub const DEFAULT_MAX_TOTAL_SEATS: u64 = coverage_plan::DEFAULT_MAX_TOTAL_SEATS;

/// Estimated tokens for `bytes` of packet JSON. A labelled estimate
/// (bytes / 4), not a tokenizer count.
pub fn estimate_tokens(bytes: u64) -> u64 {
    bytes.div_ceil(4)
}

/// Per-lens packet size report for a pending-work set: packet bytes, estimated
/// tokens, parts and required seats, plus `violations` naming every lens part
/// over the per-seat budget (refusing), and `warnings` for a total seat count over
/// the host cap (waves, not refusal). Pure and
/// deterministic; `violations` is empty exactly when the set fits `limits`.
pub fn lens_size_report(work: &[PendingLensWork], limits: &LensSizeLimits) -> Value {
    let mut order: Vec<&str> = Vec::new();
    for item in work {
        if !order.contains(&item.provider_id.as_str()) {
            order.push(item.provider_id.as_str());
        }
    }
    let mut lenses = Vec::new();
    let mut violations = Vec::new();
    let mut total_seats = 0u64;
    let mut total_bytes = 0u64;
    for provider in order {
        let mut part_sizes: Vec<(u32, u64)> = Vec::new();
        for item in work.iter().filter(|item| item.provider_id == provider) {
            // Full delivered packet envelope: request/schema/contracts included.
            let bytes = serde_json::to_vec_pretty(item)
                .map(|bytes| bytes.len() as u64)
                .unwrap_or(0);
            part_sizes.push((item.part().map_or(1, |part| part.number), bytes));
        }
        let bytes: u64 = part_sizes.iter().map(|(_, bytes)| bytes).sum();
        let seats = part_sizes.len() as u64;
        let largest = part_sizes.iter().max_by_key(|(_, bytes)| *bytes);
        let largest_tokens = largest.map_or(0, |(_, bytes)| estimate_tokens(*bytes));
        for (number, part_bytes) in &part_sizes {
            let tokens = estimate_tokens(*part_bytes);
            if tokens > limits.seat_token_budget {
                violations.push(format!(
                    "{provider} part {number}: ~{tokens} estimated tokens exceeds the per-seat budget of {}",
                    limits.seat_token_budget
                ));
            }
        }
        total_seats += seats;
        total_bytes += bytes;
        lenses.push(json!({
            "provider": provider,
            "parts": seats,
            "requiredSeats": seats,
            "packetBytes": bytes,
            "estimatedTokens": estimate_tokens(bytes),
            "largestPartBytes": largest.map_or(0, |(_, bytes)| *bytes),
            "largestPartEstimatedTokens": largest_tokens,
        }));
    }
    // Seats run in waves, so a total over the child-agent cap costs time, not
    // correctness: warn. Only a part no single seat can read refuses the freeze.
    let mut warnings = Vec::new();
    if total_seats > limits.max_seats {
        warnings.push(format!(
            "{total_seats} seats required (one per packet part) exceeds the host child-agent cap of {}; dispatch in waves",
            limits.max_seats
        ));
    }
    json!({
        "estimateBasis": "estimate: packet JSON bytes / 4",
        "limits": {
            "seatTokenBudget": limits.seat_token_budget,
            "maxSeats": limits.max_seats,
        },
        "lenses": lenses,
        "requiredSeats": total_seats,
        "packetBytes": total_bytes,
        "estimatedTokens": estimate_tokens(total_bytes),
        "withinLimits": violations.is_empty(),
        "violations": violations,
        "warnings": warnings,
    })
}

/// Limits a bundled dispatch plan is gated against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchLimits {
    /// Largest estimated token count one seat may carry.
    pub seat_token_budget: u64,
    /// Seats per wave (`CHILD_AGENTS_MAX`).
    pub wave_width: u64,
    /// Estimated input + reserved output tokens across all calls, including retries.
    pub run_token_budget: u64,
    /// Seats across all waves; the plan refuses past it.
    pub max_total_seats: u64,
}

impl Default for DispatchLimits {
    fn default() -> Self {
        Self {
            seat_token_budget: DEFAULT_SEAT_TOKEN_BUDGET,
            wave_width: DEFAULT_MAX_SEATS,
            run_token_budget: DEFAULT_RUN_TOKEN_BUDGET,
            max_total_seats: DEFAULT_MAX_TOTAL_SEATS,
        }
    }
}

fn bundle_share_bp(id: &str) -> u32 {
    lens_plan::COVERAGE_BUNDLES
        .iter()
        .chain(std::iter::once(&lens_plan::BUNDLE_ADJUDICATION))
        .find(|bundle| bundle.id == id)
        .map_or(0, |bundle| bundle.budget_share_bp)
}

fn tier_rank(tier: &str) -> u8 {
    match tier {
        "judgment" => 0,
        "specialist" => 1,
        _ => 2,
    }
}

/// Exact top-level packet fields eligible for physical sharing. The complete
/// logical packet & digest remain unchanged for delivery/ingest verification.
pub const SHARED_PACKET_FIELDS: &[&str] = &[
    "excerpts",
    "binding",
    "reviewContext",
    "sourceSides",
    "inventoryRef",
    "triggerEvidence",
    "part",
    "excerptCoverage",
    "reportSchemaBody",
    "semanticReviewContract",
    "changeRiskContract",
];

pub fn compact_shared_packet(packet: &Value, shared: &Value) -> Result<Value, AuditError> {
    let fields = shared
        .as_object()
        .ok_or_else(|| invalid("shared packet context must be an object"))?;
    let mut compact = packet.clone();
    for (field, value) in fields {
        if !SHARED_PACKET_FIELDS.contains(&field.as_str()) || packet.get(field) != Some(value) {
            return Err(invalid(
                "shared context must preserve exact original packet fields",
            ));
        }
        compact[field] = json!({"$sharedContext":field});
    }
    Ok(compact)
}

/// Physical shared-context-v1 payload consumed by the trusted host. Sharing
/// requires exact excerpt arrays; other identical metadata is transported once.
pub fn shared_seat_payload(work: &[PendingLensWork]) -> Result<Option<Value>, AuditError> {
    if !(2..=8).contains(&work.len()) {
        return Ok(None);
    }
    let Some(excerpts) = work[0]
        .request
        .packet
        .get("excerpts")
        .filter(|value| value.is_array())
    else {
        return Ok(None);
    };
    let mechanical = |item: &PendingLensWork| {
        lens_plan::lens_id_for_provider(&item.provider_id) == Some("dead-file")
    };
    if work.iter().any(|item| {
        item.provider_id == ADJUDICATOR_PROVIDER_ID
            || mechanical(item) != mechanical(&work[0])
            || item.request.packet.get("excerpts") != Some(excerpts)
    }) {
        return Ok(None);
    }
    let mut shared = json!({"excerpts":excerpts});
    for field in SHARED_PACKET_FIELDS
        .iter()
        .copied()
        .filter(|field| *field != "excerpts")
    {
        let Some(value) = work[0]
            .request
            .packet
            .get(field)
            .filter(|value| !value.is_null())
        else {
            continue;
        };
        if work
            .iter()
            .all(|item| item.request.packet.get(field) == Some(value))
            && value.to_string().len() > json!({"$sharedContext":field}).to_string().len()
        {
            shared[field] = value.clone();
        }
    }
    let mut requests = Vec::new();
    let mut identities = BTreeSet::new();
    for item in work {
        if !identities.insert(item.request.request_id.as_str()) {
            return Err(invalid("duplicate request IDs in shared seat"));
        }
        let compact = compact_shared_packet(&item.request.packet, &shared)?;
        let lens = lens_plan::lens_id_for_provider(&item.provider_id);
        let mut request = json!({"requestId":item.request.request_id,"providerId":item.provider_id,
            "planDigest":item.request.plan_digest,"packetDigest":canonical_digest(&item.request.packet).map_err(|error|invalid(error.to_string()))?,
            "packet":compact});
        // Preserve the signed per-lens schema in its packet & transport it
        // once. Legacy packets without it still need the generated schema.
        if item.request.packet["reportSchemaBody"].is_object() {
            request["findingSchemaRef"] = json!("packet.reportSchemaBody");
        } else {
            request["findingSchema"] = json!(lens.and_then(lens_schemas::lens_report_schema));
        }
        requests.push(request);
    }
    Ok(Some(
        json!({"sharedContext":shared,"sharedContextDigest":canonical_digest(&shared).map_err(|error|invalid(error.to_string()))?,"lenses":requests}),
    ))
}

struct SeatDraft {
    bundle: String,
    tier: String,
    part: u32,
    members: Vec<usize>,
    excerpt_bytes: u64,
    request_bytes: u64,
    shared_excerpt_bytes_saved: u64,
}

/// Bundled dispatch plan for a pending-work set: lens packets that read the
/// same excerpt part (same bundle, part number, review set, mode) share one
/// seat answering every lens using the host's shared-context-v1 encoding,
/// writing one result file per provider. Seats are ordered judgment tier
/// first and scheduled in waves of `wave_width`. The plan refuses (a
/// `violations` entry) when a seat exceeds the seat budget, the run exceeds
/// its estimated token budget, or the run needs more than `max_total_seats`
/// seats, and reports how far over each bundle is. Pure and deterministic.
///
/// `estimatedTokens` charges the host's complete initial rendered request,
/// including schemas, tools, framing, escaping & output reserve. Exact shared
/// excerpts are charged once only when the host consumes that encoding.
/// Bytes / 4 remains an estimate; each later physical call preflights again.
pub(crate) fn dispatch_output_tokens(seat_token_budget: u64) -> u64 {
    crate::next::DEFAULT_OUTPUT_TOKENS.min((seat_token_budget / 4).max(1))
}

pub(crate) fn physical_planning_limit(per_call: u64) -> u64 {
    // Reserve tokenization/host overhead headroom without reducing the
    // physical ledger allowance. Actual host usage still reconciles to cap.
    per_call.saturating_sub((per_call * 15 / 100).min(1500))
}

pub fn lens_dispatch_plan(work: &[PendingLensWork], limits: &DispatchLimits) -> Value {
    let output_tokens = dispatch_output_tokens(limits.seat_token_budget);
    let mut sizer = crate::review_runtime::InitialRequestSizer::default();
    let mut drafts: Vec<SeatDraft> = Vec::new();
    let mut by_key: BTreeMap<String, usize> = BTreeMap::new();
    let mut sampled = false;
    let mut unshared_request_bytes = 0u64;
    let mut planning_errors = Vec::new();
    for (position, item) in work.iter().enumerate() {
        let packet = &item.request.packet;
        let excerpt_bytes = packet
            .get("excerpts")
            .filter(|value| !value.is_null())
            .and_then(|value| serde_json::to_vec(value).ok())
            .map_or(0, |bytes| bytes.len() as u64);
        let request_bytes = match sizer.request_bytes(std::slice::from_ref(item)) {
            Ok(bytes) => bytes,
            Err(error) => {
                planning_errors.push(format!(
                    "{} initial request cannot render: {error}",
                    item.provider_id
                ));
                u64::MAX
            }
        };
        unshared_request_bytes = unshared_request_bytes.saturating_add(request_bytes);
        let adjudicator = item.provider_id == ADJUDICATOR_PROVIDER_ID;
        let bundle = packet
            .pointer("/lensPlan/bundle/id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| {
                if adjudicator {
                    lens_plan::BUNDLE_ADJUDICATION.id.to_owned()
                } else {
                    format!("X:{}", item.provider_id)
                }
            });
        let tier = packet
            .pointer("/lensPlan/bundle/tier")
            .and_then(Value::as_str)
            .unwrap_or("judgment")
            .to_owned();
        let part = item.part().map_or(1, |part| part.number);
        let coverage = packet.get("excerptCoverage");
        if coverage
            .and_then(|value| value.get("coverageMode"))
            .and_then(Value::as_str)
            == Some(coverage_plan::MODE_RISK_SAMPLED)
        {
            sampled = true;
        }
        // Physical sharing crosses historical bundle boundaries only when
        // exact raw excerpts match & executor routes are compatible.
        let route = if lens_plan::lens_id_for_provider(&item.provider_id) == Some("dead-file") {
            "mechanical"
        } else {
            "semantic"
        };
        let excerpt_digest = canonical_digest(&packet["excerpts"]).unwrap_or_default();
        let key = if excerpt_bytes > 0 && !adjudicator {
            format!("{route}|{excerpt_digest}")
        } else {
            format!("solo|{}|{part}|{position}", item.provider_id)
        };
        let merge = by_key.get(&key).copied().and_then(|index| {
            let mut members = drafts[index].members.clone();
            members.push(position);
            let items = members
                .iter()
                .map(|position| work[*position].clone())
                .collect::<Vec<_>>();
            // Strict physical compatibility, not merely equal path counts.
            let bytes = sizer.shared_request_bytes(&items).ok()??;
            let tokens = crate::next::estimated_request_tokens(bytes, output_tokens);
            (tokens <= physical_planning_limit(limits.seat_token_budget)).then_some((index, bytes))
        });
        if let Some((index, bytes)) = merge {
            let draft = &mut drafts[index];
            draft.members.push(position);
            draft.request_bytes = bytes;
            draft.shared_excerpt_bytes_saved = draft
                .shared_excerpt_bytes_saved
                .saturating_add(excerpt_bytes);
        } else {
            by_key.insert(key, drafts.len());
            drafts.push(SeatDraft {
                bundle,
                tier,
                part,
                members: vec![position],
                excerpt_bytes,
                request_bytes,
                shared_excerpt_bytes_saved: 0,
            });
        }
    }
    drafts.sort_by(|left, right| {
        tier_rank(&left.tier)
            .cmp(&tier_rank(&right.tier))
            .then_with(|| left.bundle.cmp(&right.bundle))
            .then_with(|| left.part.cmp(&right.part))
            .then_with(|| left.members.cmp(&right.members))
    });
    let wave_width = limits.wave_width.max(1);
    let mut seats = Vec::new();
    let mut violations = planning_errors;
    let mut bundles: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut total_tokens = 0u64;
    let mut gather_calls = 0u64;
    let mut total_bytes = 0u64;
    let mut unique_excerpt_bytes = 0u64;
    let mut shared_excerpt_bytes_saved = 0u64;
    let mut deferred_work = Vec::new();
    let mut selected_packets = Vec::new();
    let mut selected_unshared_bytes = 0u64;
    let initial_call_capacity = limits.max_total_seats.saturating_sub(1).min(
        limits
            .run_token_budget
            .saturating_sub(limits.seat_token_budget)
            / limits.seat_token_budget.max(1),
    );
    for draft in &drafts {
        let number = seats.len() as u64 + 1;
        let gathers = false;
        gather_calls += u64::from(gathers);
        let bytes = draft.request_bytes;
        let gather_bytes = 0u64;
        let tokens = crate::next::estimated_request_tokens(bytes, output_tokens);
        let gather_tokens = 0u64;
        let context_reserve = 0u64;
        let empty_source = draft.members.iter().all(|position| {
            let item = &work[*position];
            item.provider_id != ADJUDICATOR_PROVIDER_ID
                && item
                    .request
                    .packet
                    .get("excerpts")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)
        });
        let reason = if empty_source {
            Some("selected-source-empty")
        } else if tokens > physical_planning_limit(limits.seat_token_budget) {
            Some("physical-envelope-headroom")
        } else if seats.len() as u64 >= initial_call_capacity {
            Some("fresh-verification-reserve")
        } else {
            None
        };
        if sampled {
            if let Some(reason) = reason {
                for position in &draft.members {
                    let item = &work[*position];
                    deferred_work.push(json!({"providerId":item.provider_id,
                        "packet":item.packet_file_name(),"part":item.part().map_or(1, |part| part.number),
                        "reason":reason,"plannedRequestBytes":bytes,"estimatedTokens":tokens}));
                }
                continue;
            }
        }
        for position in &draft.members {
            let item = &work[*position];
            selected_packets.push(item.packet_file_name());
            if let Ok(bytes) = sizer.request_bytes(std::slice::from_ref(item)) {
                selected_unshared_bytes = selected_unshared_bytes.saturating_add(bytes);
            }
        }
        total_tokens = total_tokens
            .saturating_add(tokens)
            .saturating_add(gather_tokens)
            .saturating_add(context_reserve.div_ceil(4));
        total_bytes = total_bytes
            .saturating_add(bytes)
            .saturating_add(gather_bytes);
        unique_excerpt_bytes = unique_excerpt_bytes.saturating_add(draft.excerpt_bytes);
        shared_excerpt_bytes_saved =
            shared_excerpt_bytes_saved.saturating_add(draft.shared_excerpt_bytes_saved);
        let entry = bundles.entry(draft.bundle.clone()).or_insert((0, 0));
        entry.0 = entry.0.saturating_add(1);
        entry.1 = entry
            .1
            .saturating_add(tokens)
            .saturating_add(gather_tokens)
            .saturating_add(context_reserve.div_ceil(4));
        if tokens > physical_planning_limit(limits.seat_token_budget) {
            violations.push(format!(
                "seat {number} (bundle {} part {}): ~{tokens} estimated tokens exceeds planning allowance {} (physical cap {})",
                draft.bundle, draft.part, physical_planning_limit(limits.seat_token_budget), limits.seat_token_budget
            ));
        }
        seats.push(json!({
            "seat": number,
            "seatId": format!("seat-{number:03}"),
            "bundle": draft.bundle,
            "tier": draft.tier,
            "wave": (number - 1) / wave_width + 1,
            "part": draft.part,
            "estimatedTokens": tokens,
            "gatherPolicy": "deterministic",
            "initialPhysicalCalls": if gathers { 2 } else { 1 },
            "estimatedInitialTokens": tokens.saturating_add(gather_tokens).saturating_add(context_reserve.div_ceil(4)),
            "evidenceGatherer": if gathers { json!({"role":"alchemist", "modelTier":"mechanical-cheap", "reservedTokens":limits.seat_token_budget}) } else { Value::Null },
            "estimatedInputTokens": estimate_tokens(bytes),
            "outputTokenLimit": output_tokens,
            "perCallTokenAllowance": limits.seat_token_budget,
            "plannedRequestBytes": bytes,
            "plannedGatherRequestBytes": gather_bytes,
            "plannedInitialRequestBytes": bytes.saturating_add(gather_bytes),
            "gatheredContextReserveBytes": context_reserve,
            "transportEncoding": if draft.members.len() > 1 { "shared-context-v1" } else { "literal" },
            "providers": draft.members.iter().map(|i| work[*i].provider_id.clone()).collect::<Vec<_>>(),
            "lensIds": draft.members.iter().flat_map(|i| work[*i].lens_ids.clone()).collect::<Vec<_>>(),
            "packets": draft.members.iter().map(|i| work[*i].packet_file_name()).collect::<Vec<_>>(),
        }));
    }
    if sampled && !work.is_empty() && seats.is_empty() {
        violations.push(
            "bounded audit has no physical review call with source context admitted".to_owned(),
        );
    }
    let required_seats = seats.len() as u64;
    let waves = required_seats.div_ceil(wave_width);
    let initial_calls = required_seats.saturating_add(gather_calls);
    let followup_calls = u64::from(!seats.is_empty());
    let reserved_calls = initial_calls.saturating_add(followup_calls);
    let initial_reservation_tokens = initial_calls.saturating_mul(limits.seat_token_budget);
    let followup_reserve_tokens = followup_calls.saturating_mul(limits.seat_token_budget);
    if reserved_calls > limits.max_total_seats {
        violations.push(format!(
            "{required_seats} author seats + {gather_calls} cheap gathering calls + {followup_calls} verification/context reserve require {reserved_calls} calls; run cap is {}. Increase call budget or narrow lenses/scope; mandatory coverage was not reduced",
            limits.max_total_seats
        ));
    }
    if initial_reservation_tokens.saturating_add(followup_reserve_tokens) > limits.run_token_budget
    {
        violations.push(format!("initial calls reserve {initial_reservation_tokens} tokens plus {followup_reserve_tokens} verification/context tokens; run budget is {}", limits.run_token_budget));
    }
    let mut overruns = Vec::new();
    let bundle_rows: Vec<Value> = bundles
        .iter()
        .map(|(id, (seat_count, tokens))| {
            let budget = limits.run_token_budget.saturating_mul(u64::from(bundle_share_bp(id))) / 10_000;
            let over = tokens.saturating_sub(budget);
            if over > 0 && budget > 0 {
                // A share is an allocation target, not a limit: only the run
                // budget refuses. The overrun is reported, never fatal alone.
                overruns.push(format!(
                    "bundle {id}: ~{tokens} estimated tokens is {over} over its {budget} allocation target (borrowed from other bundles; the run budget is the limit)"
                ));
            }
            json!({
                "bundle": id,
                "shareBp": bundle_share_bp(id),
                "seats": seat_count,
                "estimatedTokens": tokens,
                "budgetTokens": budget,
                "overBy": over,
            })
        })
        .collect();
    if total_tokens > limits.run_token_budget {
        violations.push(format!(
            "run needs ~{total_tokens} estimated tokens, {} over the run budget of {}{}",
            total_tokens - limits.run_token_budget,
            limits.run_token_budget,
            if overruns.is_empty() {
                String::new()
            } else {
                format!(" ({})", overruns.join("; "))
            }
        ));
    }
    // Logical packet sizes remain diagnostics. Only complete physically
    // rendered requests gate dispatch; pretty logical copies can exceed an
    // exact shared envelope without exceeding physical context limits.
    let legacy = lens_size_report(
        work,
        &LensSizeLimits {
            seat_token_budget: limits.seat_token_budget,
            max_seats: wave_width,
        },
    );
    let per_lens_bytes = legacy["packetBytes"].as_u64().unwrap_or(0);
    let violation_count = violations.len();
    violations.truncate(8);
    if violation_count > violations.len() {
        violations.push(format!(
            "{} further budget violations omitted; increase budgets or narrow scope/lenses",
            violation_count - violations.len()
        ));
    }
    json!({
        "schemaVersion": 1,
        "kind": "legion-lens-dispatch",
        "planDigest": work.first().map(|item| item.request.plan_digest.clone()),
        "estimateBasis": "estimate: exact rendered author bytes / 4 plus output reserve; deterministic host selection costs no model calls; every physical call preflights actual rendered request",
        "requestEncoding": "runtime-initial-v1",
        "byteBasis": {
            "packetBytes": "rendered author physical requests including model, effort, system, schemas, tools, framing & escaping",
            "seatReadBytes": "same planned full physical requests; actual delivery requires authenticated host receipt",
            "perLensPacketBytes": "logical serialized packet envelopes, each retaining its own excerpts",
            "unsharedRequestBytes": "full initial rendered requests if every lens ran alone",
            "uniqueExcerptBytes": "serialized excerpt arrays once per physical seat",
            "sharedExcerptBytesSaved": "serialized excerpt array copies removed by actual shared-context-v1 host encoding",
            "physicalRequestBytesSaved": "unsharedRequestBytes minus planned full shared requests",
        },
        "reasoningBudget": {
            "schemaVersion": 2,
            "totalTokens": limits.run_token_budget,
            "perCallTokens": limits.seat_token_budget,
            "outputTokens": output_tokens,
            "maxSeats": limits.max_total_seats,
        },
        "coverageMode": if sampled { coverage_plan::MODE_RISK_SAMPLED } else { coverage_plan::MODE_EXHAUSTIVE },
        "boundedAudit": sampled,
        "selectedPackets": selected_packets,
        "deferredPackets": deferred_work.iter().filter_map(|row| row.get("packet")).collect::<Vec<_>>(),
        "deferredWork": deferred_work,
        "plannedSeats": drafts.len(),
        "limits": {
            "seatTokenBudget": limits.seat_token_budget,
            "waveWidth": wave_width,
            "runTokenBudget": limits.run_token_budget,
            "maxTotalSeats": limits.max_total_seats,
        },
        "lenses": legacy["lenses"],
        "bundles": bundle_rows,
        "seats": seats,
        "waves": waves,
        "requiredSeats": required_seats,
        "requiredInitialCalls": initial_calls,
        "gatherCalls": gather_calls,
        "followupReserveCalls": followup_calls,
        "initialCallReservationTokens": initial_reservation_tokens,
        "followupReserveTokens": followup_reserve_tokens,
        "packetBytes": total_bytes,
        "seatReadBytes": total_bytes,
        "perLensPacketBytes": per_lens_bytes,
        "uniqueExcerptBytes": unique_excerpt_bytes,
        "sharedExcerptBytesSaved": shared_excerpt_bytes_saved,
        "unsharedRequestBytes": selected_unshared_bytes,
        "universeUnsharedRequestBytes": unshared_request_bytes,
        "physicalRequestBytesSaved": selected_unshared_bytes.saturating_sub(total_bytes),
        "estimatedTokens": total_tokens,
        "withinLimits": violations.is_empty(),
        "violations": violations,
        "violationCount": violation_count,
        "warnings": overruns,
    })
}

/// `lens-dispatch.json` under `out_dir`: the dispatch plan for the packets in
/// `work` (bundles, waves, tiers, packet files per seat).
pub fn write_lens_dispatch(
    out_dir: &Path,
    work: &[PendingLensWork],
    limits: &DispatchLimits,
) -> Result<Value, AuditError> {
    let plan = lens_dispatch_plan(work, limits);
    let bytes = serde_json::to_vec_pretty(&plan).map_err(|error| invalid(error.to_string()))?;
    write_atomic(out_dir, "lens-dispatch.json", &bytes)?;
    Ok(plan)
}

/// Writes lens packets under `packet_dir` (`<out>/lens-packets`): the single
/// `<provider>.json` when a provider's denominator fits one part, otherwise
/// `<provider>.part-NNNN.json` for every part plus `<provider>.index.json`.
/// Stale packet files of a provider (an earlier run with a different part
/// count) are removed first. Returns the same items as `lens_packet_items`.
pub fn write_lens_packets(
    packet_dir: &Path,
    work: &[PendingLensWork],
) -> Result<Vec<Value>, AuditError> {
    let items = lens_packet_items(work, Some(packet_dir))?;
    let mut providers: Vec<&str> = Vec::new();
    for item in work {
        if !providers.contains(&item.provider_id.as_str()) {
            providers.push(item.provider_id.as_str());
        }
    }
    for provider in providers {
        let group: Vec<&PendingLensWork> = work
            .iter()
            .filter(|item| item.provider_id == provider)
            .collect();
        let _ = fs::remove_file(packet_dir.join(format!("{provider}.json")));
        let _ = fs::remove_file(packet_dir.join(format!("{provider}.index.json")));
        for (_, stale) in part_packet_files(packet_dir, provider) {
            let _ = fs::remove_file(stale);
        }
        // The promotion lists are written once per lens, next to
        // `lens-packets/`; packets reference them by `promotionRef`.
        if let Some(promotion) = group.iter().find_map(|item| item.promotion.as_ref()) {
            let run_dir = packet_dir.parent().unwrap_or(packet_dir);
            let bytes =
                serde_json::to_vec(promotion).map_err(|error| invalid(error.to_string()))?;
            write_atomic(run_dir, &promotion_file_name(provider), &bytes)?;
        }
        for item in &group {
            let bytes = serde_json::to_vec(item).map_err(|error| invalid(error.to_string()))?;
            write_atomic(packet_dir, &item.packet_file_name(), &bytes)?;
        }
        if let Some(index) = part_index(&group)? {
            let bytes = serde_json::to_vec(&index).map_err(|error| invalid(error.to_string()))?;
            write_atomic(packet_dir, &format!("{provider}.index.json"), &bytes)?;
        }
    }
    Ok(items)
}

/// Rebuilds the run verdict. Reasoning lenses count as ran only when a lens
/// receipt verifies (MAC, epoch, plan binding, result digest); everything else
/// stays exactly as the original execution reported it.
pub fn recompute_run(run_dir: &Path) -> Result<Recomputed, AuditError> {
    let mut execution: ExecutionReport =
        serde_json::from_value(read_json(&run_dir.join("execution.json"))?)
            .map_err(|error| invalid(format!("execution.json is invalid: {error}")))?;
    let stored: ReportV1 =
        legion_contracts::Report::read_any(&read_json(&run_dir.join("report.json"))?)
            .map(|report| report.v1_core())
            .map_err(|error| invalid(format!("report.json is invalid: {error}")))?;
    let plan = read_json(&run_dir.join("plan.json"))?;
    crate::verify::validate_effect_artifacts(run_dir, &plan, &stored, &execution)?;
    let native_plan = verify_persisted_native_plan(&plan, &execution, run_dir)?;
    let provider_coverage =
        verify_provider_selection_claim(&plan, &stored, &execution, native_plan.as_ref(), run_dir)?;
    verify_or_degrade_visual(&mut execution, native_plan.as_ref(), &plan, &stored)?;
    let loaded = load_receipts(run_dir, &plan, &execution, None)?;
    let lens_parts: BTreeMap<String, PartsProgress> = loaded
        .iter()
        .filter_map(|entry| {
            entry
                .parts
                .clone()
                .map(|progress| (entry.provider.clone(), progress))
        })
        .collect();
    let receipts: Vec<(String, ProviderResult)> = loaded
        .into_iter()
        .map(|entry| (entry.provider, entry.result))
        .collect();
    let repository = stored.targets.first().cloned().unwrap_or_default();
    let original = canonical_report(&repository, &execution)?;

    let ingested: BTreeSet<String> = receipts
        .iter()
        .map(|(provider, _)| provider.clone())
        .collect();
    let mut next = execution.clone();
    let mut resolved = BTreeSet::new();
    let mut partial: BTreeSet<String> = BTreeSet::new();
    let mut confirmed_security: Vec<ConfirmedSecurityFinding> = Vec::new();
    for (provider, result) in &receipts {
        let slot = next
            .results
            .iter_mut()
            .find(|entry| &entry.provider == provider)
            .ok_or_else(|| invalid(format!("{provider} is not part of this run")))?;
        resolved.extend(slot.result.coverage_gaps.iter().cloned());
        resolved.insert(format!("reasoning-lens-pending-host:{provider}"));
        slot.result = result.clone();
        slot.skipped = false;
        if let Some(confirmed) = result.details.get("securityConfirmed") {
            confirmed_security.extend(
                serde_json::from_value::<Vec<ConfirmedSecurityFinding>>(confirmed.clone())
                    .map_err(|error| invalid(format!("{provider}: securityConfirmed: {error}")))?,
            );
        }
        // Only a lens whose packet coverage is proven counts as having run; a
        // partial receipt stays incomplete and carries its own coverage gaps.
        if result.complete {
            resolved.insert(format!("provider-incomplete:{provider}"));
            if let Some(lenses) = result.details.get("lensIds").and_then(Value::as_array) {
                next.lenses_ran.extend(
                    lenses
                        .iter()
                        .filter_map(Value::as_str)
                        .map(ToOwned::to_owned),
                );
            }
        } else {
            partial.insert(provider.clone());
        }
    }
    // A gap another still-pending provider reports (the shared host-unavailable
    // gap) must survive.
    for entry in &next.results {
        if !ingested.contains(&entry.provider) {
            for gap in &entry.result.coverage_gaps {
                resolved.remove(gap);
            }
        }
    }
    next.gaps.retain(|gap| !resolved.contains(gap));
    for (provider, result) in &receipts {
        if partial.contains(provider) {
            next.gaps.extend(result.coverage_gaps.iter().cloned());
        }
    }
    next.gaps.sort();
    next.gaps.dedup();
    // A partitioned provider with parts still to ingest stays pending.
    next.pending_host.retain(|provider| {
        !ingested.contains(provider)
            || lens_parts
                .get(provider)
                .is_some_and(|progress| !progress.pending.is_empty())
    });
    next.lenses_ran.sort();
    next.lenses_ran.dedup();
    if next.lenses_ran == next.selected_reasoning_lenses {
        next.gaps.retain(|gap| gap != NOT_COMPLETE_GAP);
    }

    let rebuilt = canonical_report(&repository, &next)?;
    let original_gaps: BTreeSet<&String> = original.gaps.iter().collect();
    // Gaps the CLI added outside the engine (input, parity, packet gaps) carry over.
    let mut gaps: BTreeSet<String> = stored
        .gaps
        .iter()
        .filter(|gap| !original_gaps.contains(gap) && !gap.starts_with("reasoning-budget-"))
        .cloned()
        .collect();
    gaps.extend(rebuilt.gaps.iter().cloned());
    let budget_report = crate::next::persisted_budget_report(run_dir)?;
    if let Some(budget) = &budget_report {
        gaps.extend(string_list(budget.get("gaps")));
    }
    let variant_paths = confirmed_paths(&confirmed_security);
    let mut findings = rebuilt.findings.clone();
    let mut followup_claim: Option<Value> = None;
    if !confirmed_security.is_empty() {
        // Variant analysis is required for every surviving finding, and the
        // frozen plan's `confirmedSecurityFinding` denominator was empty, so
        // the lens cannot run inside this run: it runs in the follow-up plan
        // under `<run>/followup/`. The gap clears only when that follow-up is
        // complete and its digest chain (parent plan, confirmed verdicts,
        // signed follow-up plan, MAC'd variant receipt) verifies.
        let state = followup::evaluate(run_dir, &plan, &execution, &confirmed_security);
        followup_claim = Some(state.claim());
        match state {
            followup::FollowupState::Complete(done) => {
                let known: BTreeSet<String> = findings
                    .iter()
                    .map(|finding| finding.id.as_str().to_owned())
                    .collect();
                for finding in done.findings {
                    if known.contains(finding.id.as_str()) {
                        gaps.insert(format!("duplicate-finding-id:{}", finding.id));
                    } else {
                        findings.push(finding);
                    }
                }
                findings.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
            }
            _ => {
                gaps.insert(format!(
                    "security-variant-analysis-pending:{} confirmed finding(s)",
                    confirmed_security.len()
                ));
            }
        }
    }
    let status = if !gaps.is_empty() {
        ReportStatus::Incomplete
    } else if findings.is_empty() {
        ReportStatus::Clean
    } else {
        ReportStatus::Findings
    };

    let mut report = stored;
    report.status = status;
    if let Some(budget) = budget_report {
        report
            .claims
            .insert("reasoningBudget".into(), budget["budget"].clone());
    }
    report.findings = findings;
    report.gaps = gaps.into_iter().collect();
    for (name, value) in rebuilt.claims.iter() {
        report.claims.insert(name.clone(), value.clone());
    }
    for (name, value) in rebuilt.extensions.iter() {
        report.extensions.insert(name.clone(), value.clone());
    }
    let label = match status {
        ReportStatus::Clean => "pass",
        ReportStatus::Findings => "findings",
        _ => "incomplete",
    };
    let plan_complete = report.gaps.is_empty();
    set_derived_provider_coverage(
        &mut report,
        provider_coverage,
        plan_complete,
        next.results.len(),
    );
    let (lens_coverage, sampled_run) = match native_plan.as_ref() {
        Some(native) => lens_coverage_claims(native, &receipts),
        None => (Value::Null, false),
    };
    report.claims.insert("auditStatus".into(), json!(label));
    // `coverageMode` is reported separately from the quality outcome: a
    // sampled run keeps its findings/incomplete states, and a clean sampled
    // run is `sampled`, never `proven`.
    report.claims.insert(
        "qualityGate".into(),
        json!(if status != ReportStatus::Clean {
            "unproven"
        } else if sampled_run {
            "sampled"
        } else {
            "proven"
        }),
    );
    report.claims.insert(
        "coverageMode".into(),
        json!(if sampled_run { "sampled" } else { "exhaustive" }),
    );
    if sampled_run {
        report
            .claims
            .insert("auditLabel".into(), json!(SAMPLED_AUDIT_LABEL));
    } else {
        report.claims.remove("auditLabel");
    }
    if lens_coverage.as_object().is_some_and(|map| !map.is_empty()) {
        report.claims.insert("lensCoverage".into(), lens_coverage);
    }
    if !confirmed_security.is_empty() {
        report.claims.insert(
            "securityVariantTrigger".into(),
            json!({
                "selector": "confirmedSecurityFinding",
                "confirmed": confirmed_security,
                "paths": variant_paths,
            }),
        );
    }
    if let Some(claim) = followup_claim {
        report
            .claims
            .insert("securityVariantFollowup".into(), claim);
    }
    report.claims.insert(
        "ingestedLenses".into(),
        json!(ingested.iter().collect::<Vec<_>>()),
    );
    if !lens_parts.is_empty() {
        report.claims.insert("lensParts".into(), json!(lens_parts));
    }
    if let Some(Value::Array(items)) = report.claims.get_mut("lensWork") {
        for item in items {
            let provider = item
                .get("provider")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            if let (Some(provider), Some(object)) = (provider, item.as_object_mut()) {
                if ingested.contains(&provider) {
                    let state = if partial.contains(&provider) {
                        "ingested-partial"
                    } else {
                        "ingested"
                    };
                    object.insert("status".into(), json!(state));
                }
            }
        }
    }
    report.validate()?;
    Ok(Recomputed {
        report,
        pending: next.pending_host.clone(),
        confirmed_security,
        execution: next,
        ingested: ingested.into_iter().collect(),
        lens_parts,
    })
}

/// Per-lens coverage claim (`lensCoverage`) and whether any applicable lens is
/// risk-sampled. `results` are the verified ingested receipts (empty before any
/// ingest). A lens never claims that every lens judged every line: its mode,
/// frozen review set, examined count and per-stratum confidence are reported
/// as they are, and the status stays separate (`coverageMode` versus
/// `auditStatus`/`qualityGate`).
pub fn lens_coverage_claims(
    plan: &AuditPlan,
    results: &[(String, ProviderResult)],
) -> (Value, bool) {
    let mut claims = Map::new();
    let mut sampled = false;
    for provider in &plan.providers {
        if provider.not_applicable() {
            continue;
        }
        let Some(frozen) = provider
            .configuration
            .get("coverage")
            .and_then(coverage_plan::FrozenCoverage::from_value)
        else {
            continue;
        };
        let receipt = results
            .iter()
            .find(|(id, _)| *id == provider.id)
            .map(|(_, result)| result);
        let packet = receipt.and_then(|result| result.details.get("packetCoverage"));
        let merged = packet
            .and_then(|detail| detail.get("sampled"))
            .filter(|v| !v.is_null());
        let review_examined = if frozen.is_sampled() {
            merged
                .and_then(|value| value.get("reviewExamined"))
                .or_else(|| packet.and_then(|detail| detail.get("reviewExamined")))
                .and_then(Value::as_u64)
                .unwrap_or(0)
        } else {
            receipt
                .and_then(|result| result.coverage.as_ref())
                .map_or(0, |coverage| coverage.examined)
        };
        let review_total = merged
            .and_then(|value| value.get("reviewExpected"))
            .or_else(|| packet.and_then(|detail| detail.get("reviewExpected")))
            .and_then(Value::as_u64)
            .unwrap_or(frozen.review_set.len() as u64);
        let complete = receipt.is_some_and(|result| result.complete);
        // Findings by anchor path, for strata and the confidence statement.
        let anchored: Vec<(String, bool)> = receipt
            .and_then(|result| result.details.get("lensFindings"))
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|finding| {
                        let path = finding.pointer("/anchor/path")?.as_str()?.to_owned();
                        let high = matches!(
                            finding.get("severity").and_then(Value::as_str),
                            Some("high" | "critical")
                        );
                        Some((path, high))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut strata = Vec::new();
        let mut placed: BTreeSet<String> = BTreeSet::new();
        for stratum in frozen.strata.as_array().into_iter().flatten() {
            let name = stratum.get("name").and_then(Value::as_str).unwrap_or("?");
            let population = stratum.get("N").and_then(Value::as_u64).unwrap_or(0);
            let selected = stratum.get("n").and_then(Value::as_u64).unwrap_or(0);
            let paths: BTreeSet<String> = string_list(stratum.get("paths")).into_iter().collect();
            let (total, high) = anchored
                .iter()
                .filter(|(path, _)| paths.contains(path))
                .fold((0u64, 0u64), |(total, high), (_, is_high)| {
                    (total + 1, high + u64::from(*is_high))
                });
            placed.extend(paths.iter().cloned());
            let floor_met = frozen
                .strata
                .as_array()
                .and_then(|rows| rows.iter().find(|row| row["name"] == "remainder"))
                .is_none_or(|row| {
                    row["n"].as_u64().unwrap_or(0)
                        >= row["N"]
                            .as_u64()
                            .unwrap_or(0)
                            .min(coverage_plan::SAMPLE_FLOOR as u64)
                });
            let confidence = if frozen.bounded {
                json!({"claim":"none", "basis":"bounded-risk-selection"})
            } else if frozen.is_sampled() && !floor_met {
                json!({"claim":"none", "basis":"sample-floor-not-met"})
            } else if frozen.is_sampled() && complete {
                coverage_plan::stratum_confidence(name, population, selected, high)
            } else if frozen.is_sampled() {
                json!({"claim": "none", "basis": "lens-incomplete"})
            } else {
                json!({"claim": "none", "basis": "exhaustive-lens"})
            };
            strata.push(json!({
                "name": name,
                "N": population,
                "n": selected,
                "findings": total,
                "highFindings": high,
                "confidence": confidence,
            }));
        }
        let promoted_findings = anchored
            .iter()
            .filter(|(path, _)| frozen.is_sampled() && !placed.contains(path))
            .count();
        if promoted_findings > 0 {
            strata.push(json!({
                "name": "promoted",
                "N": review_total.saturating_sub(frozen.review_set.len() as u64),
                "n": review_total.saturating_sub(frozen.review_set.len() as u64),
                "findings": promoted_findings,
                "confidence": {"claim": "none", "basis": "promoted-by-deterministic-findings"},
            }));
        }
        sampled |= frozen.is_sampled();
        claims.insert(
            provider.id.clone(),
            json!({
                "mode": frozen.mode,
                "bundle": frozen.bundle,
                "denominator": frozen.denominator,
                "reviewSet": review_total,
                "reviewSetDigest": frozen.review_set_digest,
                "examined": review_examined,
                "declaredUnsampled": (frozen.denominator as u64).saturating_sub(review_total),
                "excluded": frozen.excluded,
                "boundedAudit": frozen.bounded,
                "mandatoryUniverse": frozen.mandatory_universe,
                "mandatoryDeferred": frozen.mandatory_deferred,
                "seed": frozen.seed,
                "status": match receipt {
                    None => "pending",
                    Some(result) if result.complete => "ingested",
                    Some(_) => "ingested-partial",
                },
                "strata": strata,
            }),
        );
    }
    (Value::Object(claims), sampled)
}

fn set_derived_provider_coverage(
    report: &mut ReportV1,
    coverage: Option<Value>,
    plan_complete: bool,
    executed_providers: usize,
) {
    // Stored report claims are presentation data, not an authority source.
    // Rebuild the claim from verified plans or omit it for legacy runs.
    report.claims.remove("providerCoverage");
    if let Some(mut coverage) = coverage {
        if let Some(object) = coverage.as_object_mut() {
            object.insert("planComplete".into(), json!(plan_complete));
            object.insert("executedProviders".into(), json!(executed_providers));
        }
        report.claims.insert("providerCoverage".into(), coverage);
    }
}

fn verify_persisted_native_plan(
    outer: &Value,
    execution: &ExecutionReport,
    run_dir: &Path,
) -> Result<Option<AuditPlan>, AuditError> {
    let Some(native) = outer.get("nativePlan") else {
        return Ok(None);
    };
    if native.get("schemaVersion").and_then(Value::as_u64) != Some(1) {
        return Err(invalid("nativePlan schema version is unsupported"));
    }
    let digest = native
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("nativePlan digest is missing"))?;
    let signature = native
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("nativePlan signature is missing"))?;
    if digest != execution.plan_digest || Some(signature) != execution.plan_signature.as_deref() {
        return Err(invalid("nativePlan does not match execution seal"));
    }
    let plan: AuditPlan = serde_json::from_value(
        native
            .get("plan")
            .cloned()
            .ok_or_else(|| invalid("nativePlan body is missing"))?,
    )
    .map_err(|error| invalid(format!("nativePlan body is invalid: {error}")))?;
    reject_provider_universe_execution_plan(&plan)?;
    let provider_ids = plan
        .providers
        .iter()
        .map(|provider| provider.id.clone())
        .collect::<Vec<_>>();
    let outer_ids = outer
        .get("providers")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("outer plan provider list is missing"))?
        .iter()
        .map(|item| {
            item.as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid("outer plan provider list is invalid"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if plan.inventory_generation != execution.generation
        || plan.inventory_digest != execution.inventory_digest
        || outer.get("repository").and_then(Value::as_str) != Some(plan.repository_id.as_str())
        || provider_ids != execution.planned_providers
        || provider_ids != outer_ids
        || outer.pointer("/seal/digest").and_then(Value::as_str) != Some(digest)
        || outer.pointer("/seal/signature").and_then(Value::as_str) != Some(signature)
        || outer
            .pointer("/binding/inventoryDigest")
            .and_then(Value::as_str)
            != Some(execution.inventory_digest.as_str())
    {
        return Err(invalid("nativePlan identity differs from frozen execution"));
    }
    let key = match std::env::var_os("AUDIT_PLAN_SIGNING_KEY") {
        Some(value) if !value.is_empty() => value.to_string_lossy().as_bytes().to_vec(),
        _ => load_epoch(run_dir)?.0,
    };
    crate::integrity::verify(&plan, digest, Some(signature), Some(&key))?;
    Ok(Some(plan))
}

fn verify_provider_selection_claim(
    outer: &Value,
    stored_report: &ReportV1,
    execution: &ExecutionReport,
    executed_plan: Option<&AuditPlan>,
    run_dir: &Path,
) -> Result<Option<Value>, AuditError> {
    let Some(selection) = outer.get("providerSelection") else {
        return Ok(None);
    };
    if selection.get("complete").and_then(Value::as_bool) != Some(true) {
        return Err(invalid("provider selection universe is incomplete"));
    }
    let scope_plan = selection
        .get("scopePlan")
        .ok_or_else(|| invalid("provider selection has no signed scope plan"))?;
    let digest = scope_plan
        .get("digest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("provider selection scope-plan digest is missing"))?;
    let signature = scope_plan
        .get("signature")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("provider selection scope-plan signature is missing"))?;
    let frozen: AuditPlan = serde_json::from_value(
        scope_plan
            .get("plan")
            .cloned()
            .ok_or_else(|| invalid("provider selection scope-plan body is missing"))?,
    )
    .map_err(|error| invalid(format!("provider selection scope-plan is invalid: {error}")))?;
    let key = match std::env::var_os("AUDIT_PLAN_SIGNING_KEY") {
        Some(value) if !value.is_empty() => value.to_string_lossy().as_bytes().to_vec(),
        _ => load_epoch(run_dir)?.0,
    };
    crate::integrity::verify(&frozen, digest, Some(signature), Some(&key))?;
    if frozen.inventory_generation != execution.generation
        || frozen.inventory_digest != execution.inventory_digest
        || outer.get("repository").and_then(Value::as_str) != Some(frozen.repository_id.as_str())
        || selection.get("inventoryDigest").and_then(Value::as_str)
            != Some(execution.inventory_digest.as_str())
    {
        return Err(invalid(
            "provider selection scope plan differs from the executed inventory",
        ));
    }
    if !verify_provider_universe_binding(&frozen, digest, signature, &key, &execution.plan_digest)?
    {
        // Old, correctly signed scope plans did not distinguish full-universe
        // purpose from an ordinary selected plan. Their coverage is unknown;
        // never upgrade their unsigned selection fields into a full-scope claim.
        return Ok(None);
    }
    let applicable = applicable_provider_ids(&frozen);
    let executed_plan = executed_plan.ok_or_else(|| {
        invalid("provider selection cannot be reconciled without a verified native plan")
    })?;
    let signed_executed = executed_plan
        .providers
        .iter()
        .map(|provider| provider.id.clone())
        .collect::<BTreeSet<_>>();
    let planned_provider_order = provider_ids_in_plan_order(executed_plan);
    let signed_nonfiring = executed_plan
        .excluded_conditional_providers
        .iter()
        .map(|provider| provider.id.clone())
        .collect::<BTreeSet<_>>();
    let full_universe = frozen
        .providers
        .iter()
        .map(|provider| provider.id.clone())
        .collect::<BTreeSet<_>>();
    let full_nonfiring = frozen
        .excluded_conditional_providers
        .iter()
        .map(|provider| provider.id.clone())
        .collect::<BTreeSet<_>>();
    let selected_specs = outer
        .get("providerSpecs")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("outer provider specifications are missing"))?
        .iter()
        .map(|value| {
            value
                .get("id")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid("outer provider specification has no id"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let signed_selected = verify_precompile_provider_selection(
        selection,
        &selected_specs,
        &signed_executed,
        &signed_nonfiring,
        &full_universe,
        &full_nonfiring,
    )?;
    let (selected_applicable, excluded) = derive_provider_scope(&applicable, &signed_selected);
    let full_scope = excluded.is_empty();
    if selection.get("applicableProviders") != Some(&json!(applicable))
        || selection.get("selectedApplicableProviders") != Some(&json!(selected_applicable))
        || selection.get("excludedApplicableProviders") != Some(&json!(excluded))
        || selection.get("fullScope").and_then(Value::as_bool) != Some(full_scope)
        || selection.get("excludedConditionalProviders")
            != Some(&json!(frozen.excluded_conditional_providers))
    {
        return Err(invalid(
            "provider selection scope does not reconcile to the signed provider universe",
        ));
    }
    if let Some(report_coverage) = stored_report.claims.get("providerCoverage") {
        let Some(report_coverage) = report_coverage.as_object() else {
            return Err(invalid("stored provider coverage claim is not an object"));
        };
        for (field, expected) in [
            ("fullScope", json!(full_scope)),
            ("applicableProviders", json!(applicable)),
            ("selectedApplicableProviders", json!(selected_applicable)),
            ("excludedApplicableProviders", json!(excluded)),
        ] {
            if report_coverage
                .get(field)
                .is_some_and(|actual| actual != &expected)
            {
                return Err(invalid(format!(
                    "stored provider coverage {field} differs from verified scope"
                )));
            }
        }
    }
    Ok(Some(json!({
        "scope": "frozen-native-provider-plan",
        "fullScope": full_scope,
        "applicableProviders": applicable,
        "selectedApplicableProviders": selected_applicable,
        "excludedApplicableProviders": excluded,
        "requestedOnly": selection.get("requestedOnly").cloned().unwrap_or(json!([])),
        "requestedSkip": selection.get("requestedSkip").cloned().unwrap_or(json!([])),
        "plannedProviders": planned_provider_order,
        "sourcePort": [
            "tools/audit/audit-complete.mjs",
            "tools/audit/audit-run.mjs",
            "tools/audit/audit-finalize.mjs"
        ],
    })))
}

fn provider_ids_in_plan_order(plan: &AuditPlan) -> Vec<String> {
    plan.providers
        .iter()
        .map(|provider| provider.id.clone())
        .collect()
}

/// Verify both the signed universe purpose and its binding to the selected
/// plan whose providers actually ran. Returns `false` only for an older signed
/// scope plan with no purpose marker; present-but-invalid markers fail closed.
fn verify_provider_universe_binding(
    scope_plan: &AuditPlan,
    digest: &str,
    signature: &str,
    key: &[u8],
    selected_plan_digest: &str,
) -> Result<bool, AuditError> {
    crate::integrity::verify(scope_plan, digest, Some(signature), Some(key))?;
    let Some(binding) = scope_plan.bounds.get(PROVIDER_UNIVERSE_BOUND) else {
        return Ok(false);
    };
    let object = binding
        .as_object()
        .ok_or_else(|| invalid("provider universe marker is not an object"))?;
    if object.len() != 3
        || binding.get("schemaVersion").and_then(Value::as_u64) != Some(1)
        || binding.get("purpose").and_then(Value::as_str) != Some("audit-provider-universe")
    {
        return Err(invalid(
            "provider universe marker is malformed or unsupported",
        ));
    }
    let bound_selected_digest = binding
        .get("selectedPlanDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("provider universe selected-plan binding is missing"))?;
    if !is_sha256_digest(bound_selected_digest) || bound_selected_digest != selected_plan_digest {
        return Err(invalid(
            "provider universe is not bound to the verified selected plan",
        ));
    }
    Ok(true)
}

fn is_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn reject_provider_universe_execution_plan(plan: &AuditPlan) -> Result<(), AuditError> {
    if plan.bounds.contains_key(PROVIDER_UNIVERSE_BOUND) {
        return Err(invalid(
            "native execution plan carries a provider-universe purpose marker",
        ));
    }
    Ok(())
}

fn derive_provider_scope(
    applicable: &BTreeSet<String>,
    selected: &BTreeSet<String>,
) -> (Vec<String>, Vec<String>) {
    (
        applicable.intersection(selected).cloned().collect(),
        applicable.difference(selected).cloned().collect(),
    )
}

/// Check the duplicated selection claim against provider IDs from the already
/// verified native plan. Coverage is always derived from that signed plan,
/// never from the outer report's unsigned provider lists.
fn verify_precompile_provider_selection(
    selection: &Value,
    outer_provider_specs: &BTreeSet<String>,
    signed_executed: &BTreeSet<String>,
    signed_nonfiring_conditionals: &BTreeSet<String>,
    full_universe: &BTreeSet<String>,
    full_nonfiring_conditionals: &BTreeSet<String>,
) -> Result<BTreeSet<String>, AuditError> {
    let claimed = selection
        .get("selectedProviderIds")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("provider selection has no selected provider ids"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| invalid("selected provider id is invalid"))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    if !signed_executed.is_disjoint(signed_nonfiring_conditionals) {
        return Err(invalid(
            "verified plan lists a conditional provider as both executed and nonfiring",
        ));
    }
    if !signed_executed.is_subset(full_universe)
        || !signed_nonfiring_conditionals.is_subset(full_nonfiring_conditionals)
    {
        return Err(invalid(
            "executed or nonfiring provider ids fall outside the signed full universe",
        ));
    }
    let expected_precompile = signed_executed
        .union(signed_nonfiring_conditionals)
        .cloned()
        .collect::<BTreeSet<_>>();
    if claimed != expected_precompile || outer_provider_specs != &expected_precompile {
        return Err(invalid(
            "precompile provider ids do not reconcile to verified execution and nonfiring conditionals",
        ));
    }
    Ok(signed_executed.clone())
}

fn applicable_provider_ids(plan: &AuditPlan) -> BTreeSet<String> {
    plan.providers
        .iter()
        .filter(|provider| {
            let declared = provider
                .configuration
                .get("hostDeclaration")
                .and_then(|value| value.get("declared"))
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let denominator_count = provider
                .configuration
                .get("denominatorCount")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let selector = provider.configuration.get("selector");
            let always = selector.is_some_and(|selector| {
                selector.as_str() == Some("always")
                    || selector.get("op").and_then(Value::as_str) == Some("always")
            });
            declared && (denominator_count > 0 || always)
        })
        .map(|provider| provider.id.clone())
        .collect()
}

fn verify_or_degrade_visual(
    execution: &mut ExecutionReport,
    native_plan: Option<&AuditPlan>,
    outer_plan: &Value,
    stored_report: &ReportV1,
) -> Result<(), AuditError> {
    let generation = execution.generation.clone();
    let Some(plan) = native_plan else {
        let index = visual_result_index_for_unbound_plan(execution, outer_plan)?;
        let Some(index) = index else {
            return Ok(());
        };
        return mark_visual_unproven(&mut execution.results[index]);
    };
    let Some(provider) = plan
        .providers
        .iter()
        .find(|provider| provider.id == VISUAL_PROVIDER_ID)
    else {
        return Ok(());
    };
    let Some(index) = unique_visual_result_index(&execution.results)? else {
        return Err(invalid(
            "nativePlan selected visual provider but execution result is missing",
        ));
    };
    let slot = &mut execution.results[index];
    if provider.not_applicable() {
        if slot.skipped || slot.result.applicable {
            return Err(invalid(
                "visual execution applicability differs from sealed nativePlan",
            ));
        }
        return Ok(());
    }
    if slot.skipped || !slot.result.applicable {
        return Err(invalid(
            "applicable visual provider was marked skipped or inapplicable",
        ));
    }
    let explicit_spec = provider
        .configuration
        .get("runner")
        .and_then(|runner| runner.get("visual"))
        .and_then(|visual| visual.get("spec"))
        .is_some_and(Value::is_object);
    if explicit_spec {
        if stored_report.targets.first().map(String::as_str) != Some(plan.repository_id.as_str()) {
            return Err(invalid(
                "visual report repository differs from sealed nativePlan",
            ));
        }
        let root = PathBuf::from(&plan.repository_id);
        crate::native_providers::legacy::visual::verify_explicit_visual_execution(
            &root,
            provider,
            &generation,
            &slot.result,
        )
        .map_err(|error| {
            invalid(format!(
                "visual result failed sealed-spec recomputation: {error}"
            ))
        })?;
    }
    Ok(())
}

fn unique_visual_result_index(
    results: &[crate::execution::ProviderExecution],
) -> Result<Option<usize>, AuditError> {
    let mut matches = results
        .iter()
        .enumerate()
        .filter(|(_, result)| result.provider == VISUAL_PROVIDER_ID)
        .map(|(index, _)| index);
    let first = matches.next();
    if matches.next().is_some() {
        return Err(invalid(
            "execution contains duplicate visual provider results",
        ));
    }
    Ok(first)
}

fn visual_result_index_for_unbound_plan(
    execution: &ExecutionReport,
    outer_plan: &Value,
) -> Result<Option<usize>, AuditError> {
    let selected_in_execution = execution
        .planned_providers
        .iter()
        .any(|provider| provider == VISUAL_PROVIDER_ID);
    let selected_in_outer = outer_plan
        .get("providers")
        .and_then(Value::as_array)
        .is_some_and(|providers| {
            providers
                .iter()
                .any(|provider| provider.as_str() == Some(VISUAL_PROVIDER_ID))
        });
    let index = unique_visual_result_index(&execution.results)?;
    if (selected_in_execution || selected_in_outer) && index.is_none() {
        return Err(invalid(
            "plan selected visual provider but execution result is missing",
        ));
    }
    Ok(index)
}

fn mark_visual_unproven(slot: &mut crate::execution::ProviderExecution) -> Result<(), AuditError> {
    slot.result.complete = false;
    slot.result.status = ProviderStatus::Partial;
    slot.result
        .coverage_gaps
        .push(VISUAL_PLAN_BINDING_UNAVAILABLE.into());
    slot.result.coverage_gaps.sort();
    slot.result.coverage_gaps.dedup();
    slot.result.details.insert(
        "visualVerification".into(),
        json!({"status":"unproven","reason":VISUAL_PLAN_BINDING_UNAVAILABLE}),
    );
    Ok(())
}

#[cfg(test)]
mod provider_universe_binding_tests {
    use super::{
        derive_provider_scope, provider_ids_in_plan_order, reject_provider_universe_execution_plan,
        verify_provider_universe_binding,
    };
    use crate::plan::{AuditPlan, AuditProvider, ProviderKind, PROVIDER_UNIVERSE_BOUND};
    use serde_json::{json, Value};
    use std::collections::{BTreeMap, BTreeSet};

    const KEY: &[u8] = b"provider-universe-test-key";

    fn plan(bounds: BTreeMap<String, Value>) -> AuditPlan {
        AuditPlan {
            schema_version: 1,
            repository_id: "/repo".into(),
            inventory_generation: "generation-1".into(),
            inventory_digest: format!("sha256:{}", "a".repeat(64)),
            providers: Vec::new(),
            bounds,
            excluded_conditional_providers: Vec::new(),
        }
    }

    fn signed(plan: &AuditPlan) -> (String, String) {
        (
            crate::integrity::plan_digest(plan).unwrap(),
            crate::integrity::sign(plan, KEY).unwrap(),
        )
    }

    fn marked_plan(selected_plan_digest: &str) -> AuditPlan {
        plan(BTreeMap::from([(
            PROVIDER_UNIVERSE_BOUND.into(),
            json!({
                "schemaVersion": 1,
                "purpose": "audit-provider-universe",
                "selectedPlanDigest": selected_plan_digest,
            }),
        )]))
    }

    #[test]
    fn signed_universe_marker_prevents_filtered_plan_substitution() {
        let selected = plan(BTreeMap::new());
        let selected_digest = crate::integrity::plan_digest(&selected).unwrap();
        let substituted = selected.clone();
        let (digest, signature) = signed(&substituted);
        assert!(!verify_provider_universe_binding(
            &substituted,
            &digest,
            &signature,
            KEY,
            &selected_digest,
        )
        .unwrap());

        let universe = marked_plan(&selected_digest);
        let (digest, signature) = signed(&universe);
        assert!(verify_provider_universe_binding(
            &universe,
            &digest,
            &signature,
            KEY,
            &selected_digest,
        )
        .unwrap());
    }

    #[test]
    fn changed_marker_signature_or_selected_plan_binding_is_rejected() {
        let selected = plan(BTreeMap::new());
        let selected_digest = crate::integrity::plan_digest(&selected).unwrap();
        let universe = marked_plan(&selected_digest);
        let (digest, signature) = signed(&universe);

        let mut changed = universe.clone();
        changed.bounds.get_mut(PROVIDER_UNIVERSE_BOUND).unwrap()["purpose"] =
            json!("ordinary-plan");
        assert!(verify_provider_universe_binding(
            &changed,
            &digest,
            &signature,
            KEY,
            &selected_digest,
        )
        .is_err());
        assert!(verify_provider_universe_binding(
            &universe,
            &digest,
            &format!("hmac-sha256:{}", "0".repeat(64)),
            KEY,
            &selected_digest,
        )
        .is_err());

        let unsupported = plan(BTreeMap::from([(
            PROVIDER_UNIVERSE_BOUND.into(),
            json!({
                "schemaVersion": 2,
                "purpose": "audit-provider-universe",
                "selectedPlanDigest": selected_digest,
            }),
        )]));
        let (digest, signature) = signed(&unsupported);
        assert!(verify_provider_universe_binding(
            &unsupported,
            &digest,
            &signature,
            KEY,
            &selected_digest,
        )
        .is_err());

        let wrong_binding = marked_plan(&format!("sha256:{}", "b".repeat(64)));
        let (digest, signature) = signed(&wrong_binding);
        assert!(verify_provider_universe_binding(
            &wrong_binding,
            &digest,
            &signature,
            KEY,
            &selected_digest,
        )
        .is_err());
    }

    #[test]
    fn legacy_scope_is_unknown_and_full_or_narrow_coverage_is_derived_from_signed_sets() {
        let selected = plan(BTreeMap::new());
        let selected_digest = crate::integrity::plan_digest(&selected).unwrap();
        let (digest, signature) = signed(&selected);
        assert!(!verify_provider_universe_binding(
            &selected,
            &digest,
            &signature,
            KEY,
            &selected_digest,
        )
        .unwrap());

        let applicable =
            BTreeSet::from(["security.source".to_owned(), "security.secrets".to_owned()]);
        let full_selected = applicable.clone();
        let (full, omitted) = derive_provider_scope(&applicable, &full_selected);
        assert_eq!(full, vec!["security.secrets", "security.source"]);
        assert!(omitted.is_empty());

        let narrow_selected = BTreeSet::from(["security.source".to_owned()]);
        let (selected, omitted) = derive_provider_scope(&applicable, &narrow_selected);
        assert_eq!(selected, vec!["security.source"]);
        assert_eq!(omitted, vec!["security.secrets"]);
    }

    #[test]
    fn universe_purpose_marker_cannot_be_reused_as_an_execution_plan() {
        let ordinary = plan(BTreeMap::new());
        assert!(reject_provider_universe_execution_plan(&ordinary).is_ok());

        let universe = marked_plan(&format!("sha256:{}", "a".repeat(64)));
        assert!(reject_provider_universe_execution_plan(&universe).is_err());
    }

    #[test]
    fn planned_provider_coverage_keeps_signed_dag_order() {
        let provider = |id: &str, dependencies: &[&str]| AuditProvider {
            id: id.into(),
            version: "1".into(),
            role: "scanner".into(),
            phase: "scan".into(),
            lens_ids: Vec::new(),
            dependencies: dependencies
                .iter()
                .map(|dependency| (*dependency).into())
                .collect(),
            kind: ProviderKind::BuiltIn,
            configuration: BTreeMap::new(),
            bounds: BTreeMap::new(),
            clean_claim: "none".into(),
            benchmark_status: "not-required".into(),
            benchmark_required_for_clean_claim: false,
            qualification_digest: None,
            required: true,
        };
        let mut signed_plan = plan(BTreeMap::new());
        signed_plan.providers = vec![provider("zeta", &[]), provider("alpha", &["zeta"])];

        assert_eq!(
            provider_ids_in_plan_order(&signed_plan),
            vec!["zeta".to_owned(), "alpha".to_owned()]
        );
    }
}

#[cfg(test)]
mod variant_anchor_scope_tests {
    use super::{
        ensure_variant_anchor_in_scope, set_derived_provider_coverage,
        verify_precompile_provider_selection,
    };
    use legion_contracts::ReportV1;
    use serde_json::json;
    use std::collections::BTreeSet;

    #[test]
    fn variant_anchors_must_be_inside_frozen_analysis_paths() {
        let denominator = vec!["src/db.rs".to_owned(), "src/db_sibling.rs".to_owned()];
        assert!(ensure_variant_anchor_in_scope(
            super::followup::VARIANT_PROVIDER_ID,
            &denominator,
            "src/db_sibling.rs",
            "variant finding",
        )
        .is_ok());
        assert!(ensure_variant_anchor_in_scope(
            super::followup::VARIANT_PROVIDER_ID,
            &denominator,
            "src/unrelated.rs",
            "variant finding",
        )
        .is_err());
    }

    #[test]
    fn other_lenses_keep_their_own_anchor_contract() {
        assert!(ensure_variant_anchor_in_scope(
            "reasoning.security",
            &["src/db.rs".to_owned()],
            "src/unrelated.rs",
            "security finding",
        )
        .is_ok());
    }

    #[test]
    fn legacy_ingest_drops_unbound_provider_coverage_claim() {
        let mut report: ReportV1 = serde_json::from_value(json!({
            "schema_version": 1,
            "report_id": "scope-claim-test",
            "status": "incomplete",
            "findings": [],
            "gaps": [],
            "claims": {
                "providerCoverage": {
                    "fullAudit": true,
                    "fullScope": false,
                    "excludedApplicableProviders": ["security.secret-scan"]
                }
            },
            "targets": []
        }))
        .unwrap();

        set_derived_provider_coverage(&mut report, None, true, 1);

        assert!(report.claims.get("providerCoverage").is_none());
    }

    #[test]
    fn ingest_rebuilds_provider_coverage_from_verified_scope() {
        let mut report: ReportV1 = serde_json::from_value(json!({
            "schema_version": 1,
            "report_id": "scope-claim-test",
            "status": "incomplete",
            "findings": [],
            "gaps": [],
            "claims": {
                "providerCoverage": {"fullAudit": true, "fullScope": true}
            },
            "targets": []
        }))
        .unwrap();

        set_derived_provider_coverage(
            &mut report,
            Some(json!({
                "scope": "frozen-native-provider-plan",
                "fullScope": false,
                "excludedApplicableProviders": ["security.secret-scan"]
            })),
            true,
            2,
        );

        let coverage = &report.claims["providerCoverage"];
        assert_eq!(coverage["planComplete"], json!(true));
        assert_eq!(coverage["fullScope"], json!(false));
        assert_eq!(coverage["executedProviders"], json!(2));
        assert_eq!(
            coverage["excludedApplicableProviders"],
            json!(["security.secret-scan"])
        );
        assert!(coverage.get("fullAudit").is_none());
    }

    #[test]
    fn checked_nonfiring_conditional_is_not_a_scope_omission() {
        let signed_executed = BTreeSet::from(["security.source".to_owned()]);
        let signed_nonfiring = BTreeSet::from(["reasoning.a11y".to_owned()]);
        let full_universe = BTreeSet::from(["security.source".to_owned()]);
        let full_nonfiring = BTreeSet::from(["reasoning.a11y".to_owned()]);
        let expected_precompile =
            BTreeSet::from(["security.source".to_owned(), "reasoning.a11y".to_owned()]);
        let selection = json!({
            "selectedProviderIds": ["reasoning.a11y", "security.source"],
            "fullScope": false,
            "excludedApplicableProviders": ["security.secret-scan"]
        });
        assert_eq!(
            verify_precompile_provider_selection(
                &selection,
                &expected_precompile,
                &signed_executed,
                &signed_nonfiring,
                &full_universe,
                &full_nonfiring,
            )
            .unwrap(),
            signed_executed.clone()
        );
        let applicable = BTreeSet::from(["security.source".to_owned()]);
        assert!(applicable.difference(&signed_executed).next().is_none());
    }

    #[test]
    fn tampered_outer_provider_lists_cannot_expand_signed_selection_scope() {
        let signed_executed = BTreeSet::from(["security.source".to_owned()]);
        let signed_nonfiring = BTreeSet::from(["reasoning.a11y".to_owned()]);
        let full_universe = BTreeSet::from(["security.source".to_owned()]);
        let full_nonfiring = BTreeSet::from(["reasoning.a11y".to_owned()]);
        let mut selection = json!({
            "selectedProviderIds": ["reasoning.a11y", "security.source"],
            "fullScope": false,
            "excludedApplicableProviders": ["security.secret-scan"]
        });
        // An attacker editing both unsigned copies to claim a full run still
        // cannot add a provider absent from the signed execution or checked
        // nonfiring conditional set.
        selection["selectedProviderIds"] =
            json!(["reasoning.a11y", "security.source", "security.secret-scan"]);
        selection["fullScope"] = json!(true);
        selection["excludedApplicableProviders"] = json!([]);
        let tampered_outer_specs = BTreeSet::from([
            "reasoning.a11y".to_owned(),
            "security.source".to_owned(),
            "security.secret-scan".to_owned(),
        ]);
        assert!(verify_precompile_provider_selection(
            &selection,
            &tampered_outer_specs,
            &signed_executed,
            &signed_nonfiring,
            &full_universe,
            &full_nonfiring,
        )
        .is_err());
    }
}

#[cfg(test)]
mod visual_execution_shape_tests {
    use super::*;
    use crate::execution::ProviderExecution;

    fn visual_result() -> ProviderExecution {
        ProviderExecution {
            provider: VISUAL_PROVIDER_ID.into(),
            skipped: false,
            result: ProviderResult {
                schema_version: 1,
                provider: ProviderId::new(VISUAL_PROVIDER_ID).unwrap(),
                applicable: true,
                required: true,
                status: ProviderStatus::Partial,
                complete: false,
                coverage: None,
                findings: Vec::new(),
                coverage_gaps: Vec::new(),
                degradation: Vec::new(),
                details: BTreeMap::new(),
            },
        }
    }

    #[test]
    fn selected_visual_requires_a_unique_execution_row() {
        assert_eq!(unique_visual_result_index(&[]).unwrap(), None);
        assert_eq!(
            unique_visual_result_index(&[visual_result()]).unwrap(),
            Some(0)
        );
        assert!(unique_visual_result_index(&[visual_result(), visual_result()]).is_err());
    }

    #[test]
    fn unbound_plan_selection_survives_deleted_execution_selection() {
        let execution = ExecutionReport::default();
        let outer = json!({"providers":[VISUAL_PROVIDER_ID]});
        assert!(visual_result_index_for_unbound_plan(&execution, &outer).is_err());

        let outer = json!({"providers":["legacy.other"]});
        assert_eq!(
            visual_result_index_for_unbound_plan(&execution, &outer).unwrap(),
            None
        );
    }
}

#[cfg(test)]
mod runtime_evidence_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn setup() -> (PathBuf, ReasoningInvocation) {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let run = std::env::temp_dir().join(format!(
            "legion-runtime-proof-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&run).unwrap();
        create_epoch(&run).unwrap();
        let request = ReasoningInvocation {
            schema_version: 1,
            kind: super::super::REASONING_INVOCATION_KIND.into(),
            request_id: "request-one".into(),
            provider_id: "reasoning.correctness".into(),
            contract: "review".into(),
            plan_digest: "plan".into(),
            plan_signature: "signature".into(),
            repository_id: "repo".into(),
            inventory_generation: "revision".into(),
            inventory_digest: "inventory".into(),
            denominator_digest: "denominator".into(),
            denominator_count: 0,
            denominator_paths: Vec::new(),
            packet: json!({"excerpts":[]}),
        };
        (run, request)
    }

    fn call_fixture(run: &Path) -> Value {
        let (_, epoch) = load_epoch(run).unwrap();
        let snapshot = format!("sha256:{}", "1".repeat(64));
        let request = format!("sha256:{}", "2".repeat(64));
        fs::write(
            run.join("plan.json"),
            serde_json::to_vec(&json!({
                "epoch":{"digest":epoch},"reviewContext":{"snapshotKey":snapshot}
            }))
            .unwrap(),
        )
        .unwrap();
        json!({"schemaVersion":1,"kind":"legion-runtime-call","callId":"seat:nonce:1","seatId":"seat-001",
            "requestDigest":request,"snapshotKey":snapshot,"requestBytes":17409,
            "requestAccounting":{"basis":"serialized-host-envelope","nativeFramingIncluded":false,"providerInputTokenCountBeforeSend":null},
            "authorization":{"authorized":true,"callId":"seat:nonce:1","reservedTokens":10000},
            "observation":{"physicalRequestDigest":request,"physicalRequestBytes":17409,
                "usage":{"inputTokens":7202,"outputTokens":122}},
            "modelAction":{"kind":"toolRequest","toolRequest":{"tool":"audit.read_file","arguments":{"path":"src/lib.rs","api_key":"private-value"}}},
            "budget":{"status":"reconciled"}})
    }

    #[test]
    fn runtime_call_receipt_authenticates_redacted_bounded_diagnostic() {
        let (run, _) = setup();
        let receipt = call_fixture(&run);
        let minted = mint_runtime_call(&run, &receipt).unwrap();
        assert!(!minted.to_string().contains("private-value"));
        assert_eq!(
            minted["modelAction"]["toolRequest"]["arguments"]["api_key"],
            "[REDACTED]"
        );
        let verified = verify_runtime_call(&run, &minted).unwrap();
        assert_eq!(verified["observation"]["usage"]["inputTokens"], 7202);
        assert_eq!(verified["requestBytes"], 17409);
        assert!(verified.get("authentication").is_none());
        for pointer in ["callId", "requestDigest", "snapshotKey"] {
            let mut tampered = minted.clone();
            tampered[pointer] = json!("changed");
            assert!(verify_runtime_call(&run, &tampered).is_err());
        }
        let mut tampered = minted.clone();
        tampered["modelAction"]["toolRequest"]["arguments"]["path"] = json!("src/other.rs");
        assert!(verify_runtime_call(&run, &tampered).is_err());
        let (other_run, _) = setup();
        call_fixture(&other_run);
        assert!(verify_runtime_call(&other_run, &minted).is_err());

        let mut oversized = receipt.clone();
        oversized["modelAction"]["toolRequest"]["arguments"]["path"] = json!("x".repeat(9000));
        let bounded = mint_runtime_call(&run, &oversized).unwrap();
        assert_eq!(bounded["modelAction"]["truncated"], true);
        assert!(bounded["modelAction"].to_string().len() < 8192);
        verify_runtime_call(&run, &bounded).unwrap();
        oversized["initialContext"] = json!("x".repeat(32769));
        assert!(mint_runtime_call(&run, &oversized).is_err());
        let mut result = receipt.clone();
        result["modelAction"] = json!({"kind":"finalResult","complete":false,"findingCount":1,"findings":[{"secret":"private-result-body"}]});
        let result = mint_runtime_call(&run, &result).unwrap();
        assert!(!result.to_string().contains("private-result-body"));
        verify_runtime_call(&run, &result).unwrap();
        let mut raw = receipt;
        raw["observation"]["reply"] = json!({"unbounded":"source"});
        assert!(mint_runtime_call(&run, &raw).is_err());
        let _ = fs::remove_dir_all(run);
        let _ = fs::remove_dir_all(other_run);
    }

    #[test]
    fn runtime_call_cost_fields_are_bounded_authenticated_and_preserve_unknown() {
        let (run, _) = setup();
        let mut receipt = call_fixture(&run);
        receipt["observation"]["reportedApiEquivalentCostUsd"] = json!("0.1234567890123456789");
        receipt["observation"]["invoiceChargeUsd"] = Value::Null;
        let minted = mint_runtime_call(&run, &receipt).unwrap();
        let verified = verify_runtime_call(&run, &minted).unwrap();
        assert_eq!(
            verified["observation"]["reportedApiEquivalentCostUsd"],
            "0.1234567890123456789"
        );
        assert!(verified["observation"]["invoiceChargeUsd"].is_null());
        let mut changed = minted;
        changed["observation"]["reportedApiEquivalentCostUsd"] = json!("0");
        assert!(verify_runtime_call(&run, &changed).is_err());
        for invalid_cost in [
            json!(0.1),
            json!("-1"),
            json!("NaN"),
            json!("0.10"),
            json!("1".repeat(129)),
        ] {
            receipt["observation"]["reportedApiEquivalentCostUsd"] = invalid_cost;
            assert!(mint_runtime_call(&run, &receipt).is_err());
        }
        receipt["observation"]["reportedApiEquivalentCostUsd"] = Value::Null;
        let unknown = mint_runtime_call(&run, &receipt).unwrap();
        assert!(verify_runtime_call(&run, &unknown).unwrap()["observation"]
            ["reportedApiEquivalentCostUsd"]
            .is_null());
        receipt["observation"]["invoiceChargeUsd"] = json!("0");
        assert!(mint_runtime_call(&run, &receipt).is_err());
        let _ = fs::remove_dir_all(run);
    }

    fn delivery(request: &ReasoningInvocation) -> Value {
        json!({"schemaVersion":1,"kind":"legion-evidence-delivery","source":"host-transport","receiptId":"delivery-one",
            "requestId":request.request_id,"packetDigest":canonical_digest(&request.packet).unwrap(),
            "deliveredPacketBytes":canonical_json_bytes(&request.packet).unwrap().len(),"complete":true,"truncated":false,"chunks":[]})
    }

    #[test]
    fn delivery_sidecar_authenticates_exact_binding_and_rejects_tampering() {
        let (run, request) = setup();
        let (key, epoch) = load_epoch(&run).unwrap();
        assert!(runtime_delivery(&run, &request, &key, &epoch)
            .unwrap()
            .is_none());
        let proof = delivery(&request);
        let minted = mint_runtime_delivery(&run, &request, &proof).unwrap();
        assert_eq!(
            runtime_delivery(&run, &request, &key, &epoch).unwrap(),
            Some(proof)
        );
        let path = PathBuf::from(minted["path"].as_str().unwrap());
        let mut tampered = read_json(&path).unwrap();
        tampered["message"]["evidence"]["receiptId"] = json!("forged");
        fs::write(path, serde_json::to_vec(&tampered).unwrap()).unwrap();
        assert!(runtime_delivery(&run, &request, &key, &epoch).is_err());
        let _ = fs::remove_dir_all(run);
    }

    fn verification(request: &ReasoningInvocation) -> Value {
        let original = json!({"id":"finding-one","title":"original","verifyStatus":"verified"});
        json!({"schemaVersion":1,"kind":"legion-runtime-verification","requestId":request.request_id,
            "packetDigest":canonical_digest(&request.packet).unwrap(),"findings":[{
                "findingId":"finding-one","findingDigest":canonical_digest(&original).unwrap(),"authorFinding":original,
                "verdict":"unresolved","author":{"contextId":"author","processId":100,"processCreated":true,"responseDigest":"author-response"},
                "reviewer":null,"reason":"budget exhausted before verifier","evidence":[],"contradictionAnchorsVerified":false}]})
    }

    #[test]
    fn unresolved_is_retained_and_id_only_or_same_context_proof_cannot_verify() {
        let (run, request) = setup();
        let proof = verification(&request);
        mint_runtime_verification(&run, &request, &proof).unwrap();
        let (key, epoch) = load_epoch(&run).unwrap();
        assert_eq!(
            runtime_verification(&run, &request, &key, &epoch).unwrap(),
            Some(proof.clone())
        );
        let frozen = FrozenFiles {
            root: &run,
            digests: BTreeMap::new(),
            snapshot: None,
            source_sides: BTreeMap::new(),
        };
        let finding = json!({"id":"finding-one","title":"original","verifyStatus":"unverified","verificationMethod":"adversarial-skeptic-pass"});
        let gaps = verification_result_gaps(
            "reasoning.correctness",
            Some(&proof),
            &[finding],
            &[],
            &frozen,
        )
        .unwrap();
        assert!(gaps[0].contains("verification-unresolved"));
        let mut forged = proof.clone();
        forged["findings"][0]["verdict"] = json!("upheld");
        assert!(mint_runtime_verification(&run, &request, &forged).is_err());
        forged["findings"][0]["reviewer"] = forged["findings"][0]["author"].clone();
        assert!(mint_runtime_verification(&run, &request, &forged).is_err());
        let mut id_only = proof;
        id_only["findings"][0]
            .as_object_mut()
            .unwrap()
            .remove("authorFinding");
        assert!(mint_runtime_verification(&run, &request, &id_only).is_err());
        let _ = fs::remove_dir_all(run);
    }
    fn planning_work(request: &ReasoningInvocation, provider: &str, text: &str) -> PendingLensWork {
        let mut request = request.clone();
        request.provider_id = provider.into();
        request.request_id = format!("request:{provider}");
        request.packet = json!({"lensPlan":{"bundle":{"id":"J1","tier":"judgment"}},
            "contractText":"quoted \" contract \n".repeat(1800),
            "excerpts":[{"path":"source.rs","mode":"raw","content":text}]});
        PendingLensWork {
            provider_id: provider.into(),
            lens_ids: vec![provider.into()],
            status: "pending-host".into(),
            request,
            promotion: None,
        }
    }

    #[test]
    fn dispatch_uses_actual_shared_encoding_and_splits_over_budget_members() {
        let (run, request) = setup();
        let text = "source \"line\" \n".repeat(1000);
        let work = vec![
            planning_work(&request, "reasoning.security", &text),
            planning_work(&request, "reasoning.correctness", &text),
        ];
        assert!(crate::review_runtime::shared_seat_supported(&work).unwrap());
        let shared = crate::review_runtime::initial_seat_request_bytes(&work).unwrap();
        let single = work
            .iter()
            .map(|work| {
                crate::review_runtime::initial_seat_request_bytes(std::slice::from_ref(work))
                    .unwrap()
            })
            .max()
            .unwrap();
        assert!(
            shared > single,
            "distinct lens contracts & schemas still consume bytes"
        );
        let roomy = DispatchLimits {
            // Shared author, output & minimum 2048-byte gathered context.
            seat_token_budget: shared.div_ceil(4) + 4096 + 1500 + 100,
            run_token_budget: 1_000_000,
            ..DispatchLimits::default()
        };
        let plan = lens_dispatch_plan(&work, &roomy);
        assert_eq!(plan["withinLimits"], true, "{}", plan["violations"]);
        assert_eq!(plan["requiredSeats"], 1);
        assert_eq!(plan["gatherCalls"], 0);
        assert_eq!(plan["requiredInitialCalls"], 1);
        assert_eq!(plan["followupReserveCalls"], 1);
        assert_eq!(plan["seats"][0]["plannedRequestBytes"], shared);
        assert_eq!(plan["seats"][0]["transportEncoding"], "shared-context-v1");
        assert!(plan["physicalRequestBytesSaved"].as_u64().unwrap() > 0);
        write_lens_packets(&run.join(LENS_PACKET_DIR), &work).unwrap();
        write_lens_dispatch(&run, &work, &roomy).unwrap();
        let issued = crate::next::next(
            &run,
            &crate::next::NextOptions {
                now_ms: 0,
                lease_ms: 1000,
            },
        )
        .unwrap();
        assert_eq!(issued["seats"][0]["budgetReservationTokens"],plan["seats"][0]["estimatedTokens"],
            "resume/admission must reconstruct the same physical shared request, not sum logical packet copies");
        let bounded = DispatchLimits {
            seat_token_budget: (single.div_ceil(4) + shared.div_ceil(4)) / 2 + 4096 + 1500,
            ..roomy
        };
        let split = lens_dispatch_plan(&work, &bounded);
        assert_eq!(split["withinLimits"], true, "{}", split["violations"]);
        assert_eq!(split["requiredSeats"], 2);
        assert_eq!(split["sharedExcerptBytesSaved"], 0);
        assert!(split["seats"]
            .as_array()
            .unwrap()
            .iter()
            .all(|seat| seat["estimatedTokens"].as_u64().unwrap() <= bounded.seat_token_budget));
        let mut different = work;
        different[1].request.packet["excerpts"][0]["content"] = json!("different source");
        assert!(shared_seat_payload(&different).unwrap().is_none());
        let plan = lens_dispatch_plan(&different, &roomy);
        assert_eq!(
            plan["requiredSeats"], 2,
            "equal excerpt counts do not prove equal bytes"
        );
        assert_eq!(plan["sharedExcerptBytesSaved"], 0);
        let _ = fs::remove_dir_all(run);
    }

    #[test]
    fn bounded_dispatch_packs_real_lens_contracts_across_bundles_and_retains_deferrals() {
        let (run, request) = setup();
        // Exact Ember executable entrypoint; raw bodies, not a toy schema or
        // a reconstructed summary. Contracts/schemas come from shipped lenses.
        let text = r##"#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::unimplemented, clippy::todo, clippy::unreachable)]

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[path = "native.rs"]
mod native;

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn main() {
    native::run();
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn main() {
    eprintln!("Ember native host is supported on macOS & Windows only");
}
"##;
        let ids = [
            "correctness",
            "security",
            "schema",
            "architecture",
            "doc-drift",
            "performance",
            "minimize",
            "ai-slop",
            "naming",
            "dead-file",
            "a11y",
            "data-safety",
            "resilience",
            "platform-parity",
            "release-readiness",
        ];
        let work = ids.iter().map(|lens| {
            let provider = format!("reasoning.{lens}");
            let mut item = planning_work(&request, &provider, text);
            item.request.packet = json!({
                "lensPlan":lens_plan::lens_plan_packet_value(&provider).unwrap(),
                "reportSchemaBody":lens_schemas::lens_report_schema(lens).unwrap(),
                "semanticReviewContract":lens_plan::semantic_review_contract(lens),
                "changeRiskContract":lens_plan::change_risk_contract(lens),
                "excerpts":[{"path":"apps/lightcraft-desktop/src/main.rs","mode":if *lens == "dead-file" {"skeleton"} else {"raw"},"content":text}],
                "excerptCoverage":{"coverageMode":"risk-sampled","reviewSetDigest":"sha256:ember","reviewSetCount":1}
            });
            item
        }).collect::<Vec<_>>();
        let limits = DispatchLimits {
            seat_token_budget: 10_000,
            run_token_budget: 50_000,
            max_total_seats: 5,
            wave_width: 1,
        };
        let plan = lens_dispatch_plan(&work, &limits);
        assert_eq!(plan["withinLimits"], true, "{}", plan["violations"]);
        assert!(plan["requiredInitialCalls"].as_u64().unwrap() <= 4);
        assert_eq!(plan["gatherCalls"], 0);
        assert_eq!(plan["followupReserveCalls"], 1);
        assert_eq!(plan["reasoningBudget"]["outputTokens"], 2500);
        let selected = plan["selectedPackets"].as_array().unwrap();
        let deferred = plan["deferredWork"].as_array().unwrap();
        assert_eq!(selected.len() + deferred.len(), work.len());
        assert!(
            selected.len() >= 2,
            "useful review needs multiple real contracts"
        );
        for seat in plan["seats"].as_array().unwrap() {
            assert_eq!(seat["gatherPolicy"], "deterministic");
            assert!(seat["estimatedTokens"].as_u64().unwrap() <= 8500);
            let members = seat["providers"].as_array().unwrap();
            if members
                .iter()
                .any(|provider| provider == "reasoning.dead-file")
            {
                assert_eq!(
                    members.len(),
                    1,
                    "mechanical survey keeps its executor boundary"
                );
            }
        }
        // A smaller call ledger retains all omitted work explicitly, with no
        // fictional successful result or erased provider denominator.
        let tight = lens_dispatch_plan(
            &work,
            &DispatchLimits {
                max_total_seats: 2,
                ..limits
            },
        );
        assert_eq!(tight["requiredInitialCalls"], 1);
        assert!(!tight["deferredWork"].as_array().unwrap().is_empty());
        assert_eq!(
            tight["selectedPackets"].as_array().unwrap().len()
                + tight["deferredWork"].as_array().unwrap().len(),
            work.len()
        );
        let _ = fs::remove_dir_all(run);
    }

    fn part_result(number: u32, extra_gap: Option<&str>) -> ProviderResult {
        let scope_gap = format!("reasoning-part-scope:reasoning.correctness:part {number}/2");
        let mut gaps = vec![scope_gap];
        gaps.extend(extra_gap.map(str::to_owned));
        ProviderResult {
            schema_version: 1,
            provider: ProviderId::new("reasoning.correctness").unwrap(),
            applicable: true,
            required: true,
            status: ProviderStatus::Partial,
            complete: false,
            coverage: Some(Coverage {
                denominator_digest: "denominator".into(),
                expected: 2,
                examined: 1,
                gaps: gaps.clone(),
            }),
            findings: Vec::new(),
            coverage_gaps: gaps,
            degradation: Vec::new(),
            details: BTreeMap::from([(
                "packetCoverage".into(),
                json!({"part":{"number":number,"total":2},"examinedPaths":[format!("file-{number}")]}),
            )]),
        }
    }

    #[test]
    fn merging_all_parts_preserves_unresolved_and_missing_delivery_gaps() {
        for gap in [
            "verification-unresolved:reasoning.correctness:finding-one",
            "delivery-unverified:reasoning.correctness",
        ] {
            let (merged, progress) = merge_parts(
                "reasoning.correctness",
                vec![
                    (1, 2, part_result(1, Some(gap))),
                    (2, 2, part_result(2, None)),
                ],
            )
            .unwrap();
            assert!(progress.pending.is_empty());
            assert!(!merged.complete);
            assert!(merged.coverage_gaps.iter().any(|value| value == gap));
            assert!(!merged
                .coverage_gaps
                .iter()
                .any(|value| value.starts_with("reasoning-part-scope:")));
            assert_eq!(merged.status, ProviderStatus::Partial);
        }
        let (merged, _) = merge_parts(
            "reasoning.correctness",
            vec![(1, 2, part_result(1, None)), (2, 2, part_result(2, None))],
        )
        .unwrap();
        assert!(merged.complete);
    }

    #[test]
    fn non_correctness_projection_uses_host_verdict_without_foreign_schema_fields() {
        let (run, request) = setup();
        let mut proof = verification(&request);
        proof["findings"][0]["authorFinding"]["lens"] = json!("data-safety");
        proof["findings"][0]["findingDigest"] =
            json!(canonical_digest(&proof["findings"][0]["authorFinding"]).unwrap());
        let mut finding = proof["findings"][0]["authorFinding"].clone();
        finding["verifyStatus"] = json!("unverified");
        let gaps = verification_projection_gaps(
            "reasoning.data-safety",
            Some(&proof),
            &[finding.clone()],
            &[],
        )
        .unwrap();
        assert!(gaps
            .iter()
            .any(|gap| gap.contains("verification-unresolved")));
        proof["findings"][0]["verdict"] = json!("upheld");
        finding["verifyStatus"] = json!("verified");
        assert!(verification_projection_gaps(
            "reasoning.data-safety",
            Some(&proof),
            &[finding],
            &[]
        )
        .unwrap()
        .is_empty());
        let _ = fs::remove_dir_all(run);
    }

    #[test]
    fn staged_delivery_is_authenticated_without_claiming_parent_delivery() {
        let (run, mut request) = setup();
        request.provider_id = ADJUDICATOR_PROVIDER_ID.into();
        let packet = json!({"kind":"legion-audit-adjudication-seat","itemId":"item-one","packet":{"candidate":"one"}});
        let observation = json!({"schemaVersion":1,"kind":"legion-adjudication-stage-observation","workItemId":"item-one",
            "observedContextId":"native-child-one","processId":100,"processCreated":true,"responseDigest":"response-one",
            "complete":true,"truncated":false,"workPacketDigest":canonical_digest(&packet["packet"]).unwrap(),
            "deliveredPacketBytes":canonical_json_bytes(&packet["packet"]).unwrap().len()});
        let minted = mint_runtime_adjudication(&run, &request, &packet, &observation).unwrap();
        let (key, epoch) = load_epoch(&run).unwrap();
        assert_eq!(
            runtime_adjudication(&run, &request, &key, &epoch).unwrap(),
            vec![observation]
        );
        assert!(runtime_delivery(&run, &request, &key, &epoch)
            .unwrap()
            .is_none());
        let path = PathBuf::from(minted["path"].as_str().unwrap());
        let mut envelope = read_json(&path).unwrap();
        envelope["message"]["evidence"]["stagePacket"]["packet"] = json!({"candidate":"other"});
        fs::write(path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(runtime_adjudication(&run, &request, &key, &epoch).is_err());
        let _ = fs::remove_dir_all(run);
    }
}
