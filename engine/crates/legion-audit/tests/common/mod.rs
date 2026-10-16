//! Explicit host receipts for integration fixtures. These helpers model a
//! successful fixture transport/reviewer; they are called only by tests whose
//! scenario includes those events.

use legion_audit::native_providers::reasoning::{
    delivery_chunk_manifest,
    ingest::{mint_runtime_delivery, mint_runtime_verification},
    ReasoningInvocation,
};
use legion_contracts::{canonical_digest, canonical_json_bytes};
use serde_json::{json, Value};
use std::{
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
};

#[derive(Clone, Copy)]
pub enum FindingDisposition {
    Upheld,
    Unresolved,
}

pub fn deliver(run: &Path, request: &ReasoningInvocation) {
    let proof = json!({
        "schemaVersion": 1,
        "kind": "legion-evidence-delivery",
        "source": "host-transport",
        "receiptId": format!("fixture-host:{}", request.request_id),
        "requestId": request.request_id,
        "packetDigest": canonical_digest(&request.packet).unwrap(),
        "deliveredPacketBytes": canonical_json_bytes(&request.packet).unwrap().len(),
        "complete": true,
        "truncated": false,
        "chunks": delivery_chunk_manifest(request).unwrap(),
    });
    mint_runtime_delivery(run, request, &proof).unwrap();
}

pub fn verify(
    run: &Path,
    request: &ReasoningInvocation,
    result: &mut Value,
    disposition: FindingDisposition,
) {
    let originals = result["findings"].as_array().cloned().unwrap_or_default();
    let withdrawn = result["withdrawn"].as_array().cloned().unwrap_or_default();
    let mut rows = Vec::new();
    for (index, original) in originals.iter().enumerate() {
        let id = original["id"].as_str().expect("fixture finding ID");
        let (verdict, status) = match disposition {
            FindingDisposition::Upheld => ("upheld", "verified"),
            FindingDisposition::Unresolved => ("unresolved", "unverified"),
        };
        result["findings"][index]["verifyStatus"] = json!(status);
        if request.provider_id == "reasoning.correctness"
            || original["lens"].as_str() == Some("correctness")
        {
            result["findings"][index]["verificationMethod"] = json!("adversarial-skeptic-pass");
        }
        rows.push(verification_row(request, id, original, verdict, None));
    }
    for original in &withdrawn {
        let id = original["id"].as_str().expect("fixture withdrawal ID");
        let author_finding = json!({"id": id});
        rows.push(verification_row(
            request,
            id,
            &author_finding,
            "contradicted",
            original.get("disproof"),
        ));
    }
    let proof = json!({
        "schemaVersion": 1,
        "kind": "legion-runtime-verification",
        "requestId": request.request_id,
        "packetDigest": canonical_digest(&request.packet).unwrap(),
        "findings": rows,
    });
    if !originals.is_empty() || !withdrawn.is_empty() {
        record_budget_usage(
            run,
            request,
            "fixture-verifier",
            canonical_json_bytes(&proof).unwrap().len() as u64,
        );
    }
    mint_runtime_verification(run, request, &proof).unwrap();
}

pub fn authenticate(
    run: &Path,
    request: &ReasoningInvocation,
    result: &mut Value,
    disposition: FindingDisposition,
) {
    record_budget_usage(
        run,
        request,
        "fixture-lens",
        canonical_json_bytes(&request.packet).unwrap().len() as u64 + 256,
    );
    deliver(run, request);
    verify(run, request, result, disposition);
}

pub fn record_budget_usage(run: &Path, request: &ReasoningInvocation, label: &str, bytes: u64) {
    if !run.join("lens-dispatch.json").is_file() {
        return;
    }
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let ordinal = NEXT.fetch_add(1, Ordering::Relaxed);
    let call_id = format!("{label}:{}:{ordinal}", request.request_id);
    let dispatch: Value =
        serde_json::from_slice(&std::fs::read(run.join("lens-dispatch.json")).unwrap()).unwrap();
    let output_ceiling = dispatch["reasoningBudget"]["outputTokens"]
        .as_u64()
        .expect("frozen dispatch output-token ceiling");
    // Invocation filename helpers are crate-private; mirror their serialized
    // public part contract, including both u32 fields, for fixture seat lookup.
    let part_number = request.packet.get("part").and_then(|part| {
        let number = u32::try_from(part.get("number")?.as_u64()?).ok()?;
        let _total = u32::try_from(part.get("total")?.as_u64()?).ok()?;
        Some(number)
    });
    let packet_file = match part_number {
        Some(number) => format!("{}.part-{:04}.json", request.provider_id, number),
        None => format!("{}.json", request.provider_id),
    };
    let selected_seat = dispatch["seats"].as_array().and_then(|seats| {
        seats.iter().find(|seat| {
            seat["packets"].as_array().is_some_and(|packets| {
                packets
                    .iter()
                    .any(|packet| packet.as_str() == Some(packet_file.as_str()))
            })
        })
    });
    if label == "fixture-lens" {
        assert!(
            selected_seat.is_some(),
            "fixture author packet {packet_file} needs a frozen physical seat; logical packet bytes are not model-input bytes"
        );
    }
    let (rendered_request_bytes, model_input_bytes, output_token_limit) = selected_seat
        .map_or_else(
            || (bytes.max(1), bytes.max(1), output_ceiling),
            |seat| {
                (
                    seat["plannedRequestBytes"]
                        .as_u64()
                        .expect("frozen selected-seat rendered request size"),
                    seat["plannedModelInputBytes"]
                        .as_u64()
                        .expect("frozen selected-seat projected input size"),
                    seat["outputTokenLimit"]
                        .as_u64()
                        .expect("frozen selected-seat output-token cap"),
                )
            },
        );
    assert!(output_token_limit >= output_ceiling.min(1000));
    let authorized = legion_audit::next::reserve_call(
        run,
        &legion_audit::next::BudgetCall {
            reservation_id: None,
            call_id: call_id.clone(),
            tier: "judgment".into(),
            rendered_request_bytes,
            model_input_bytes,
            output_token_limit,
            retry: false,
        },
    )
    .unwrap();
    assert_eq!(
        authorized["authorized"], true,
        "fixture call not budget-authorized: {authorized}"
    );
    let reservation_id = authorized["reservationId"].as_str().unwrap().to_owned();
    legion_audit::next::reconcile_usage(
        run,
        &legion_audit::next::UsageReceipt {
            reservation_id,
            receipt_id: format!("fixture-usage:{call_id}"),
            input_tokens: Some(1),
            output_tokens: Some(1),
            cached_input_tokens: Some(0),
            retry_tokens: Some(0),
            failed: false,
        },
    )
    .unwrap();
}

fn verification_row(
    request: &ReasoningInvocation,
    id: &str,
    author_finding: &Value,
    verdict: &str,
    contradiction: Option<&Value>,
) -> Value {
    let index = id
        .bytes()
        .fold(0u64, |value, byte| value.wrapping_add(byte as u64));
    let mut row = json!({
        "findingId": id,
        "findingDigest": canonical_digest(author_finding).unwrap(),
        "authorFinding": author_finding,
        "verdict": verdict,
        "author": {
            "contextId": format!("fixture-author:{}:{id}", request.request_id),
            "processId": 10_000 + index * 2,
            "processCreated": true,
            "responseDigest": format!("fixture-author-response:{id}"),
        },
        "reviewer": {
            "contextId": format!("fixture-reviewer:{}:{id}", request.request_id),
            "processId": 10_001 + index * 2,
            "processCreated": true,
            "responseDigest": format!("fixture-reviewer-response:{id}"),
        },
        "reason": "explicit fixture host disposition",
        "evidence": [],
        "contradictionAnchorsVerified": false,
    });
    if let Some(anchor) = contradiction {
        row["evidence"] = json!([anchor]);
        row["contradictionAnchorsVerified"] = json!(true);
    }
    row
}
