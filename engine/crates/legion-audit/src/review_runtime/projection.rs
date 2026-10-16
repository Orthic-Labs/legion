//! Deterministic physical encoding of an unchanged, authenticated invocation.
//! Only accounting, proven duplicates & examples resolve from its artifact.
use super::{digest, invalid};
use crate::{
    error::AuditError,
    native_providers::reasoning::{ingest, pattern_cards, ReasoningInvocation},
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

fn duplicate_card_language(card: &Value) -> bool {
    card.get("languageApplicability") == Some(&json!({"languages":["javascript","typescript"]}))
        && pattern_cards::PATTERN_CARDS.iter().any(|canonical| {
            matches!(
                canonical.language_applicability,
                Some(pattern_cards::LanguageApplicability::JavaScriptOrTypeScript)
            ) && card.get("id").and_then(Value::as_str) == Some(canonical.id)
                && card.get("applicability").and_then(Value::as_str)
                    == Some(canonical.applicability)
        })
}

fn zero_redaction_counts(excerpt: &Value) -> bool {
    excerpt.get("redacted") == Some(&Value::Bool(false))
        && excerpt
            .get("redactedRanges")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        && excerpt
            .get("redaction")
            .and_then(Value::as_object)
            .is_some_and(|counts| {
                counts.len() == 4
                    && [
                        "lines",
                        "pemBlocks",
                        "multilineSecrets",
                        "continuationLines",
                    ]
                    .iter()
                    .all(|key| counts.get(*key).and_then(Value::as_u64) == Some(0))
            })
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
    // Resolve host filesystem locations through the authenticated invocation.
    // Snapshot scope, execution policy & gaps remain model-visible, including
    // unavailable source outside this packet; none is mere host accounting.
    remove(
        &mut packet,
        "/reviewContext",
        &["snapshotManifest", "sourceRepository"],
        &mut omitted,
    );
    remove(
        &mut packet,
        "/reviewContext/snapshot",
        &["sourceRepository", "executionRoot", "baselineRoot"],
        &mut omitted,
    );
    remove(
        &mut packet,
        "/reviewContext/baseline",
        &["root"],
        &mut omitted,
    );
    if request
        .packet
        .pointer("/reviewContext/head")
        .and_then(Value::as_str)
        .is_some_and(|head| {
            !head.is_empty()
                && request
                    .packet
                    .pointer("/reviewContext/snapshot/head")
                    .and_then(Value::as_str)
                    == Some(head)
        })
    {
        remove(
            &mut packet,
            "/reviewContext/snapshot",
            &["head"],
            &mut omitted,
        );
    }
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
    remove(
        &mut packet,
        "/reviewContext/graphContext/blastRadius",
        &[
            "scopedBytesDigest",
            "coveredFilesDigest",
            "resolverConfigDigest",
        ],
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
    remove(
        &mut packet,
        "/lensPlan",
        &["patternCardApplicability"],
        &mut omitted,
    );
    let count = packet
        .pointer("/lensPlan/patternCards")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    for index in 0..count {
        let parent = format!("/lensPlan/patternCards/{index}");
        if packet.pointer(&parent).is_some_and(duplicate_card_language) {
            remove(
                &mut packet,
                &parent,
                &["languageApplicability"],
                &mut omitted,
            );
        }
        remove(&mut packet, &parent, &["pairedCases"], &mut omitted);
    }
    let count = packet
        .get("excerpts")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    for index in 0..count {
        let parent = format!("/excerpts/{index}");
        if packet.pointer(&parent).is_some_and(zero_redaction_counts) {
            remove(&mut packet, &parent, &["redaction"], &mut omitted);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn request(packet: Value) -> ReasoningInvocation {
        serde_json::from_value(json!({
            "schemaVersion":1,"kind":"legion-reasoning-invocation",
            "requestId":"fixture","providerId":"reasoning.correctness","contract":"fixture",
            "planDigest":"plan","planSignature":"signature","repositoryId":"repository",
            "inventoryGeneration":"generation","inventoryDigest":"inventory",
            "denominatorDigest":"denominator","denominatorCount":1,
            "denominatorPaths":["src/main.rs"],"packet":packet
        }))
        .unwrap()
    }

    #[test]
    fn duplicate_accounting_reconstructs_with_graph_source_and_contracts_inline() {
        let card = pattern_cards::packet_cards_for_lens("correctness")
            .into_iter()
            .find(|card| card.get("languageApplicability").is_some())
            .unwrap();
        let request = request(json!({
            "reviewContext":{
                "head":"same-head",
                "baseline":{"root":"/host/base","reference":"base-ref","gaps":["base-gap"]},
                "snapshot":{"head":"same-head","scope":{"kind":"whole-repo"},
                    "executionPolicy":"read-only","gaps":["missing-source"]},
                "graphContext":{"unknowns":[{"cause":"unresolved"}],
                    "blastRadius":{"scopedBytesDigest":"bytes","coveredFilesDigest":"files",
                        "resolverConfigDigest":"resolver","certain":[{"from":"a","to":"b"}],
                        "inferred":[{"from":"a","to":"b"}],"unknowns":[{"cause":"unresolved"}],
                        "provesDeadCode":false}}
            },
            "lensPlan":{"patternCards":[card]},
            "candidateDispositionContract":{"required":true,"everyCandidate":"disposition"},
            "semanticReviewContract":{"required":true},
            "excerpts":[{"path":"src/main.rs","mode":"raw","content":"pub fn raw() {}\n",
                "redacted":false,"redactedRanges":[],
                "redaction":{"lines":0,"pemBlocks":0,"multilineSecrets":0,"continuationLines":0}}]
        }));
        let physical = evidence(&request).unwrap();
        let packet = &physical["packet"];
        for pointer in [
            "/reviewContext/baseline/root",
            "/reviewContext/snapshot/head",
            "/reviewContext/graphContext/blastRadius/scopedBytesDigest",
            "/reviewContext/graphContext/blastRadius/coveredFilesDigest",
            "/reviewContext/graphContext/blastRadius/resolverConfigDigest",
            "/lensPlan/patternCards/0/languageApplicability",
            "/excerpts/0/redaction",
        ] {
            assert!(packet.pointer(pointer).is_none(), "{pointer}");
            assert!(physical["manifest"]["omittedPointers"]
                .as_array()
                .unwrap()
                .contains(&json!(pointer)));
        }
        for pointer in [
            "/reviewContext/head",
            "/reviewContext/baseline/reference",
            "/reviewContext/baseline/gaps",
            "/reviewContext/snapshot/scope",
            "/reviewContext/snapshot/executionPolicy",
            "/reviewContext/snapshot/gaps",
            "/reviewContext/graphContext/unknowns",
            "/reviewContext/graphContext/blastRadius/certain",
            "/reviewContext/graphContext/blastRadius/inferred",
            "/reviewContext/graphContext/blastRadius/unknowns",
            "/reviewContext/graphContext/blastRadius/provesDeadCode",
            "/lensPlan/patternCards/0/applicability",
            "/candidateDispositionContract",
            "/semanticReviewContract",
            "/excerpts/0/content",
            "/excerpts/0/mode",
            "/excerpts/0/redacted",
            "/excerpts/0/redactedRanges",
        ] {
            assert_eq!(
                packet.pointer(pointer),
                request.packet.pointer(pointer),
                "{pointer}"
            );
        }
        assert_eq!(
            reconstruct(&request, packet, &physical["manifest"]).unwrap(),
            request.packet
        );
        validate(&request, &physical).unwrap();
        let mut tampered = physical;
        tampered["packet"]["candidateDispositionContract"] = json!({});
        assert!(validate(&request, &tampered).is_err());
    }

    #[test]
    fn distinct_head_and_unproven_card_conditions_remain_inline() {
        let mut card = pattern_cards::packet_cards_for_lens("correctness")
            .into_iter()
            .find(|card| card.get("languageApplicability").is_some())
            .unwrap();
        card["applicability"] = json!("Different unresolved applicability conditions");
        let request = request(json!({
            "reviewContext":{"head":"current","snapshot":{"head":"different"}},
            "lensPlan":{"patternCards":[card]}
        }));
        let physical = evidence(&request).unwrap();
        assert_eq!(
            physical["packet"]["reviewContext"],
            request.packet["reviewContext"]
        );
        assert_eq!(
            physical["packet"]["lensPlan"]["patternCards"][0]["languageApplicability"],
            request.packet["lensPlan"]["patternCards"][0]["languageApplicability"]
        );
        assert_eq!(
            reconstruct(&request, &physical["packet"], &physical["manifest"]).unwrap(),
            request.packet
        );
    }

    #[test]
    fn nonzero_uncertain_or_redacted_counts_remain_inline_and_tamper_evident() {
        let zero = json!({"path":"src/main.rs","mode":"raw","content":"full raw source",
            "redacted":false,"redactedRanges":[],
            "redaction":{"lines":0,"pemBlocks":0,"multilineSecrets":0,"continuationLines":0}});
        let mut cases = Vec::new();
        for field in [
            "lines",
            "pemBlocks",
            "multilineSecrets",
            "continuationLines",
        ] {
            let mut row = zero.clone();
            row["redaction"][field] = json!(1);
            cases.push(row);
        }
        let mut row = zero.clone();
        row["redacted"] = json!(true);
        cases.push(row);
        let mut row = zero.clone();
        row["redactedRanges"] = json!(["src/main.rs:1-2"]);
        cases.push(row);
        let mut row = zero.clone();
        row["redaction"].as_object_mut().unwrap().remove("lines");
        cases.push(row);
        let mut row = zero.clone();
        row["redaction"]["unknownCounter"] = json!(0);
        cases.push(row);
        let mut row = zero.clone();
        row["redaction"]["lines"] = json!("0");
        cases.push(row);
        let mut row = zero;
        row.as_object_mut().unwrap().remove("redacted");
        cases.push(row);
        for row in cases {
            let request = request(json!({"excerpts":[row]}));
            let physical = evidence(&request).unwrap();
            assert_eq!(physical["packet"]["excerpts"], request.packet["excerpts"]);
            assert_eq!(
                reconstruct(&request, &physical["packet"], &physical["manifest"]).unwrap(),
                request.packet
            );
            let mut tampered = physical;
            tampered["packet"]["excerpts"][0]
                .as_object_mut()
                .unwrap()
                .remove("redaction");
            assert!(validate(&request, &tampered).is_err());
        }
    }

    #[test]
    fn host_snapshot_accounting_reconstructs_without_omitting_review_material() {
        let request: ReasoningInvocation = serde_json::from_value(json!({
            "schemaVersion":1,"kind":"legion-reasoning-invocation",
            "requestId":"fixture","providerId":"reasoning.correctness","contract":"fixture",
            "planDigest":"plan","planSignature":"signature","repositoryId":"repository",
            "inventoryGeneration":"generation","inventoryDigest":"inventory",
            "denominatorDigest":"denominator","denominatorCount":1,"denominatorPaths":["src/main.rs"],
            "packet":{
                "reviewContext":{"snapshotKey":"sha256:frozen",
                    "snapshot":{"schemaVersion":1,"headKind":"working-tree","head":"selected-oid",
                        "sourceRepository":"/host/source","executionRoot":"/host/immutable/selected",
                        "baselineRoot":"/host/immutable/base",
                        "executionPolicy":"read-only-no-project-execution-without-host-isolation",
                        "scope":{"kind":"whole-repo"},"mode":"frozen","truncated":false,
                        "gaps":["scope-symlink-unavailable:outside/linked.rs",
                            "scope-submodule-unavailable:outside/submodule",
                            "scope-lfs-content-unavailable:outside/large.dat"]},
                    "snapshotManifest":"/host/immutable/manifest.json",
                    "sourceRepository":"/host/source",
                    "graphContext":{"unknowns":[{"path":"src/main.rs","cause":"unresolved"}],
                        "blastRadius":{"inferred":[{"from":"src/main.rs","to":"src/other.rs"}],"provesDeadCode":false}}},
                "lensPlan":{"question":"Inspect observable failure","cues":["preserve all normative cues"],
                    "patternCards":[{"id":"return-key","instruction":"Preserve normative card contents"}],
                    "patternCardApplicability":{"sourcePaths":["src/main.rs"],
                        "cards":[{"id":"return-key","state":"retained","reason":"global"}]}},
                "semanticReviewContract":{"required":true,"axis":"spec"},
                "reportSchemaBody":{"type":"object","required":["findings"]},
                "excerpts":[{"path":"src/main.rs","mode":"raw","content":"pub fn value() -> u32 { 1 }\n"}]
            }
        })).unwrap();
        let before = request.clone();
        let physical = evidence(&request).unwrap();
        assert_eq!(
            physical["manifest"]["omittedPointers"],
            json!([
                "/lensPlan/patternCardApplicability",
                "/reviewContext/snapshot/baselineRoot",
                "/reviewContext/snapshot/executionRoot",
                "/reviewContext/snapshot/sourceRepository",
                "/reviewContext/snapshotManifest",
                "/reviewContext/sourceRepository"
            ])
        );
        let packet = &physical["packet"];
        for field in ["snapshotManifest", "sourceRepository"] {
            assert!(packet["reviewContext"].get(field).is_none());
        }
        let mut expected_snapshot = request.packet["reviewContext"]["snapshot"].clone();
        for field in ["sourceRepository", "executionRoot", "baselineRoot"] {
            assert!(packet["reviewContext"]["snapshot"].get(field).is_none());
            expected_snapshot.as_object_mut().unwrap().remove(field);
        }
        assert_eq!(packet["reviewContext"]["snapshot"], expected_snapshot);
        assert_eq!(
            packet["reviewContext"]["snapshot"]["gaps"],
            request.packet["reviewContext"]["snapshot"]["gaps"]
        );
        assert_eq!(packet["reviewContext"]["snapshotKey"], "sha256:frozen");
        assert!(packet["lensPlan"].get("patternCardApplicability").is_none());
        assert_eq!(
            packet["lensPlan"]["patternCards"],
            request.packet["lensPlan"]["patternCards"]
        );
        assert_eq!(
            packet["reviewContext"]["graphContext"],
            request.packet["reviewContext"]["graphContext"]
        );
        for field in ["semanticReviewContract", "reportSchemaBody", "excerpts"] {
            assert_eq!(packet[field], request.packet[field]);
        }
        let mut expected_lens_plan = request.packet["lensPlan"].clone();
        expected_lens_plan
            .as_object_mut()
            .unwrap()
            .remove("patternCardApplicability");
        assert_eq!(packet["lensPlan"], expected_lens_plan);
        assert_eq!(
            reconstruct(&request, packet, &physical["manifest"]).unwrap(),
            request.packet
        );
        assert_eq!(physical["manifest"]["referencedMaterialDelivered"], false);
        assert!(
            physical["projectedPacketBytes"].as_u64().unwrap()
                < physical["logicalReconstructedPacketBytes"]
                    .as_u64()
                    .unwrap()
        );
        validate(&request, &physical).unwrap();
        let mut missing_gaps = physical.clone();
        missing_gaps["packet"]["reviewContext"]["snapshot"]["gaps"] = json!([]);
        assert!(validate(&request, &missing_gaps).is_err());
        let mut tampered = physical;
        tampered["packet"]["reviewContext"]["graphContext"]["unknowns"] = json!([]);
        assert!(validate(&request, &tampered).is_err());
        assert_eq!(request, before);
    }
}
