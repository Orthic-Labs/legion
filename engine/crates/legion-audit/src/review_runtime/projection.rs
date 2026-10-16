//! Deterministic physical encoding of an unchanged, authenticated invocation.
//! Only accounting & illustrative examples may be resolved from its artifact.
use super::{digest, invalid};
use crate::{
    error::AuditError,
    native_providers::reasoning::{ingest, ReasoningInvocation},
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

pub(crate) const ENCODING: &str = "audit-packet-reference-v1";

fn remove(packet: &mut Value, parent: &str, fields: &[&str], omitted: &mut Vec<String>) {
    if let Some(object) = packet.pointer_mut(parent).and_then(Value::as_object_mut) {
        for field in fields {
            if object.remove(*field).is_some() {
                omitted.push(format!("{parent}/{field}"));
            }
        }
    }
}

/// `manifest` is host accounting, never a claim that referenced data was sent.
pub(crate) fn packet(request: &ReasoningInvocation) -> Result<(Value, Value), AuditError> {
    let mut packet = request.packet.clone();
    let mut omitted = Vec::new();
    remove(
        &mut packet,
        "",
        &["binding", "inventoryRef", "candidateRouting"],
        &mut omitted,
    );
    remove(
        &mut packet,
        "/excerptCoverage",
        &[
            "denominatorCount",
            "bundle",
            "reviewSetDigest",
            "reviewSetCount",
            "promotedCount",
            "displacedCount",
            "unpromotedCount",
            "promotionRef",
            "effectiveReviewSetDigest",
            "promotionDigest",
            "declaredUnsampledCount",
            "excludedCount",
            "aliasedPaths",
        ],
        &mut omitted,
    );
    remove(
        &mut packet,
        "/part",
        &[
            "total",
            "requiredParts",
            "pathsDigest",
            "overCeiling",
            "indexFile",
        ],
        &mut omitted,
    );
    remove(
        &mut packet,
        "/reviewContext/graphContext",
        &[
            "scopedBytesDigest",
            "coveredFilesDigest",
            "resolverConfigDigest",
            "artifact",
        ],
        &mut omitted,
    );
    remove(
        &mut packet,
        "/reviewContext/graphContext/projection",
        &["selectedPathsDigest", "recordCounts", "fullContextRef"],
        &mut omitted,
    );
    let selected = request
        .packet
        .get("excerpts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|row| row.get("path").and_then(Value::as_str))
        .collect::<BTreeSet<_>>();
    // A repository-wide source-side ledger is not source context. Preserve
    // every side actually used by this packet, including continued chunks.
    for pointer in ["/sourceSides", "/triggerEvidence/sourceSides"] {
        if let Some(sides) = packet.pointer_mut(pointer).and_then(Value::as_object_mut) {
            if sides.keys().any(|path| !selected.contains(path.as_str())) {
                sides.retain(|path, _| selected.contains(path.as_str()));
                omitted.push(pointer.into());
            }
        }
    }
    // Trigger verdicts stay inline. Its complete checked universe & witness
    // ledger remain authenticated, not inferred from selected excerpts.
    for field in ["evidencePaths", "unavailablePaths", "mandatoryWitnessPaths"] {
        let pointer = format!("/triggerEvidence/{field}");
        if let Some(rows) = packet.pointer_mut(&pointer).and_then(Value::as_array_mut) {
            let original_count = rows.len();
            rows.retain(|row| row.as_str().is_some_and(|path| selected.contains(path)));
            let outside = original_count != rows.len();
            if outside {
                omitted.push(pointer);
            }
            if field == "unavailablePaths" && outside {
                packet["triggerEvidence"]["unavailableOutsidePacket"] = json!(true);
            }
        }
    }
    remove(
        &mut packet,
        "/triggerEvidence",
        &["checkedPathsDigest", "inventoryDigest", "digest"],
        &mut omitted,
    );
    let count = packet
        .pointer("/lensPlan/patternCards")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    for index in 0..count {
        remove(
            &mut packet,
            &format!("/lensPlan/patternCards/{index}"),
            &["pairedCases"],
            &mut omitted,
        );
    }
    omitted.sort();
    let reference = json!({"encoding":ENCODING,
        "artifact":format!("{}/{}",ingest::LENS_PACKET_DIR,request.packet_file_name()),
        "pointer":"/request", "invocationDigest":digest(&serde_json::to_value(request).map_err(|error|invalid(error.to_string()))?)?,
        "packetDigest":digest(&request.packet)?});
    let manifest = json!({"reference":reference,"omittedPointers":omitted,
        "referencedMaterialDelivered":false});
    Ok((packet, manifest))
}

pub(crate) fn invocation(request: &ReasoningInvocation) -> Result<Value, AuditError> {
    let (packet, manifest) = packet(request)?;
    Ok(
        json!({"requestId":request.request_id,"providerId":request.provider_id,
        "contract":request.contract,"packet":packet,"logicalReference":manifest["reference"]}),
    )
}

pub(crate) fn evidence(request: &ReasoningInvocation) -> Result<Value, AuditError> {
    let (packet, manifest) = packet(request)?;
    if reconstruct(request, &packet, &manifest)? != request.packet {
        return Err(invalid(
            "physical projection cannot reconstruct exact logical packet",
        ));
    }
    Ok(
        json!({"encoding":ENCODING,"manifest":manifest,"packet":packet,
        "projectedPacketBytes":legion_contracts::canonical_json_bytes(&packet).map_err(|error|invalid(error.to_string()))?.len(),
        "logicalReconstructedPacketBytes":legion_contracts::canonical_json_bytes(&request.packet).map_err(|error|invalid(error.to_string()))?.len()}),
    )
}

fn reconstruct(
    request: &ReasoningInvocation,
    packet: &Value,
    manifest: &Value,
) -> Result<Value, AuditError> {
    let mut restored = packet.clone();
    for pointer in manifest["omittedPointers"]
        .as_array()
        .ok_or_else(|| invalid("projection manifest missing pointers"))?
    {
        let pointer = pointer
            .as_str()
            .ok_or_else(|| invalid("projection pointer malformed"))?;
        let value = request
            .packet
            .pointer(pointer)
            .ok_or_else(|| invalid("projection reference missing logical value"))?;
        let (parent, field) = pointer
            .rsplit_once('/')
            .ok_or_else(|| invalid("projection reference malformed"))?;
        restored
            .pointer_mut(parent)
            .and_then(Value::as_object_mut)
            .ok_or_else(|| invalid("projection reference parent missing"))?
            .insert(field.into(), value.clone());
    }
    if request
        .packet
        .pointer("/triggerEvidence/unavailableOutsidePacket")
        .is_none()
    {
        if let Some(trigger) = restored
            .get_mut("triggerEvidence")
            .and_then(Value::as_object_mut)
        {
            trigger.remove("unavailableOutsidePacket");
        }
    }
    Ok(restored)
}

pub(crate) fn validate(request: &ReasoningInvocation, value: &Value) -> Result<(), String> {
    if evidence(request).map_err(|error| error.to_string())? != *value {
        return Err("delivery projection differs from allowed exact logical invocation".into());
    }
    Ok(())
}
