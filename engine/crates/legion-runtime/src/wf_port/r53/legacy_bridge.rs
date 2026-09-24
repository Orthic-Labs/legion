//! Faithful port of `src/lib/host/arcane/legacy-bridge.mjs` — the Forge
//! compatibility adapter. This module TRANSLATES; it mints no verdicts (S01
//! action 7). See the `r53` module doc comment for the dependency history
//! and the `assertValid` narrowing this port makes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use serde_json::{Map, Value};

use legion_policy::arcane_port::errors::{ArcaneError, Detail};

use crate::wf_port::w2_040::kernel_binding::{KernelBinding, KernelStatus};
use crate::wf_port::w2_046::canonical::{canonical_json, digest_value};

// --- embedded fixtures/config, mirroring the JS module's `readFileSync` at
// import time ---------------------------------------------------------

const SCHEMA_MAP_JSON: &str = include_str!("assets/schema-map.json");
const OPERATION_MAP_JSON: &str = include_str!("assets/operation-map.json");
const LEGACY_ENVELOPE_SCHEMA_JSON: &str = include_str!("assets/legacy-envelope-v1.schema.json");

const FIXTURE_NAMES_AND_BODIES: &[(&str, &str)] = &[
    ("01-assess-response.json", include_str!("assets/fixtures/01-assess-response.json")),
    ("02-checkpoint-response.json", include_str!("assets/fixtures/02-checkpoint-response.json")),
    ("03-checkpoint-failure-response.json", include_str!("assets/fixtures/03-checkpoint-failure-response.json")),
    ("04-checkpoint-host-check-response.json", include_str!("assets/fixtures/04-checkpoint-host-check-response.json")),
    ("05-verify-signoff-blocked-response.json", include_str!("assets/fixtures/05-verify-signoff-blocked-response.json")),
    ("06-verify-high-risk-blocked-response.json", include_str!("assets/fixtures/06-verify-high-risk-blocked-response.json")),
    ("07-close-blocked-response.json", include_str!("assets/fixtures/07-close-blocked-response.json")),
    ("08-store-snapshot-scoped.json", include_str!("assets/fixtures/08-store-snapshot-scoped.json")),
    ("09-resolve-session-response.json", include_str!("assets/fixtures/09-resolve-session-response.json")),
    ("10-verify-signoff-passing-response.json", include_str!("assets/fixtures/10-verify-signoff-passing-response.json")),
    ("11-close-success-response.json", include_str!("assets/fixtures/11-close-success-response.json")),
    ("12-close-idempotent-response.json", include_str!("assets/fixtures/12-close-idempotent-response.json")),
];

fn schema_map() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| serde_json::from_str(SCHEMA_MAP_JSON).expect("bundled schema-map.json is valid JSON"))
}

fn operation_map() -> &'static Value {
    static V: OnceLock<Value> = OnceLock::new();
    V.get_or_init(|| serde_json::from_str(OPERATION_MAP_JSON).expect("bundled operation-map.json is valid JSON"))
}

const LEGACY_INVENTORY_REF: &str = "src/lib/host/arcane-compatibility/forge/schema-map.json";

/// Mirrors `DISPOSITIONS = Object.freeze(Object.keys(SCHEMA_MAP.dispositionVocabulary))`.
pub fn dispositions() -> Vec<String> {
    schema_map()["dispositionVocabulary"]
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default()
}

/// Mirrors `TABLE_ALIAS`.
fn table_alias(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "session_bindings" => "session_bindings / task_bindings",
        "task_bindings" => "session_bindings / task_bindings",
        _ => return None,
    })
}

/// Mirrors `OPERATION_RESPONSE_KINDS`.
const OPERATION_RESPONSE_KINDS: &[&str] = &[
    "forge.operation-response.assess",
    "forge.operation-response.checkpoint",
    "forge.operation-response.verify",
    "forge.operation-response.close",
    "forge.operation-response.resolveSession",
];

/// Mirrors `REJECTION_CODE`.
fn rejection_code_table(field: &str) -> Option<&'static str> {
    Some(match field {
        "authority" | "executor" | "origin" | "issuer_id" | "issuer_capability_digest" | "fingerprint"
        | "error_fingerprint" => "ARC_AUTHORITY_MODEL_CLAIMED",
        "signature_or_mac" => "ARC_AUTH_LEGACY_DIGEST",
        "trust_class" | "attested" => "ARC_EVIDENCE_INSUFFICIENT",
        "status" | "receipt" => "ARC_HOST_EVENT_UNTRUSTED",
        "waiver" => "ARC_CLAIM_PREREQUISITE_UNMET",
        _ => return None,
    })
}

/// Mirrors `resolveRejectionCode(legacyKind, legacyField)`.
fn resolve_rejection_code(legacy_kind: &str, legacy_field: &str) -> &'static str {
    if legacy_field == "status" && legacy_kind == "claims" {
        return "ARC_CLAIM_PREREQUISITE_UNMET";
    }
    rejection_code_table(legacy_field).unwrap_or("ARC_SCHEMA_INVALID")
}

fn record_types() -> &'static Vec<Value> {
    schema_map()["recordTypes"].as_array().expect("recordTypes is an array")
}

/// Mirrors `BY_KIND.get(...)` / `recordTypeFor(legacyKind)`.
fn record_type_for(legacy_kind: &str) -> Option<&'static Value> {
    let key = table_alias(legacy_kind).unwrap_or(legacy_kind);
    record_types().iter().find(|rt| rt["legacyKind"].as_str() == Some(key))
}

fn known_kinds() -> &'static BTreeSet<String> {
    static V: OnceLock<BTreeSet<String>> = OnceLock::new();
    V.get_or_init(|| {
        let mut set: BTreeSet<String> = record_types()
            .iter()
            .filter_map(|rt| rt["legacyKind"].as_str())
            .map(String::from)
            .collect();
        set.insert("session_bindings".to_string());
        set.insert("task_bindings".to_string());
        for k in OPERATION_RESPONSE_KINDS {
            set.insert((*k).to_string());
        }
        set
    })
}

/// Port of `dispositionFor(legacyKind, legacyField)`.
pub fn disposition_for(legacy_kind: &str, legacy_field: &str) -> String {
    let Some(rt) = record_type_for(legacy_kind) else {
        return "unmapped".to_string();
    };
    rt["fields"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|f| f["legacyField"].as_str() == Some(legacy_field))
        .and_then(|f| f["disposition"].as_str())
        .unwrap_or("unmapped")
        .to_string()
}

/// Port of `fieldMapping(legacyKind, legacyField)`.
pub fn field_mapping(legacy_kind: &str, legacy_field: &str) -> Option<Value> {
    let rt = record_type_for(legacy_kind)?;
    rt["fields"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|f| f["legacyField"].as_str() == Some(legacy_field))
        .cloned()
}

/// Input to [`envelope_for`]. Mirrors the JS `provenance` argument shape.
#[derive(Debug, Clone, Default)]
pub struct ProvenanceInput {
    pub source: Option<String>,
    pub captured_at: String,
    pub source_revision: Option<String>,
    pub imported_by: Option<String>,
}

/// Structural check of `legacy-envelope-v1`, mirroring `assertValid` for
/// exactly the shape [`envelope_for`] builds (see the `r53` module doc
/// comment for why this is a narrow, non-generic validator). Loads the
/// embedded schema text only to keep the `required`/`const` list visibly
/// anchored to the frozen contract; the checks themselves are hand-written
/// against it.
fn assert_valid_legacy_envelope(envelope: &Value) -> Result<(), ArcaneError> {
    let _schema_anchor = LEGACY_ENVELOPE_SCHEMA_JSON; // frozen contract this mirrors
    let mut issues = Vec::new();
    let obj = envelope.as_object();
    let required = ["schemaVersion", "kind", "legacyKind", "payload", "provenance", "provisionalMappingRef"];
    for field in required {
        if obj.map(|o| !o.contains_key(field)).unwrap_or(true) {
            issues.push(format!("$:required:{field}"));
        }
    }
    if envelope["schemaVersion"] != Value::from(1) {
        issues.push("$.schemaVersion:const".to_string());
    }
    if envelope["kind"] != Value::String("legion-legacy-envelope".to_string()) {
        issues.push("$.kind:const".to_string());
    }
    if !matches!(envelope["legacyKind"], Value::String(ref s) if !s.is_empty()) {
        issues.push("$.legacyKind:type-or-minLength".to_string());
    }
    let prov = envelope["provenance"].as_object();
    for field in ["source", "capturedAt", "authenticated"] {
        if prov.map(|o| !o.contains_key(field)).unwrap_or(true) {
            issues.push(format!("$.provenance:required:{field}"));
        }
    }
    if !matches!(envelope["provenance"]["source"], Value::String(ref s) if !s.is_empty()) {
        issues.push("$.provenance.source:type-or-minLength".to_string());
    }
    if envelope["provenance"]["authenticated"] != Value::Bool(false) {
        issues.push("$.provenance.authenticated:const".to_string());
    }
    if !issues.is_empty() {
        let mut detail: Detail = BTreeMap::new();
        detail.insert("schema".to_string(), "legacy-envelope-v1".to_string());
        detail.insert("issues".to_string(), issues.join(", "));
        return Err(ArcaneError::new(
            "ARC_SCHEMA_INVALID",
            "legacy envelope does not satisfy legacy-envelope-v1",
            detail,
        )
        .expect("ARC_SCHEMA_INVALID is a known code"));
    }
    Ok(())
}

/// Port of `envelopeFor(legacyKind, payload, provenance)`.
pub fn envelope_for(legacy_kind: &str, payload: Value, provenance: &ProvenanceInput) -> Result<Value, ArcaneError> {
    if !known_kinds().contains(legacy_kind) {
        let mut detail: Detail = BTreeMap::new();
        detail.insert("legacyKind".to_string(), legacy_kind.to_string());
        let known: Vec<&str> = known_kinds().iter().map(String::as_str).collect();
        detail.insert("known".to_string(), known.join(", "));
        return Err(ArcaneError::new(
            "ARC_SCHEMA_INVALID",
            format!("no S01 mapping for legacy kind '{legacy_kind}'"),
            detail,
        )
        .expect("ARC_SCHEMA_INVALID is a known code"));
    }
    let inventory_type = record_type_for(legacy_kind)
        .and_then(|rt| rt.get("inventoryRecordType"))
        .cloned()
        .unwrap_or(Value::Null);

    let mut provenance_obj = Map::new();
    provenance_obj.insert("source".to_string(), Value::String(provenance.source.clone().unwrap_or_else(|| "forge".to_string())));
    provenance_obj.insert("capturedAt".to_string(), Value::String(provenance.captured_at.clone()));
    provenance_obj.insert(
        "sourceRevision".to_string(),
        provenance.source_revision.clone().map(Value::String).unwrap_or(Value::Null),
    );
    provenance_obj.insert(
        "importedBy".to_string(),
        Value::String(provenance.imported_by.clone().unwrap_or_else(|| "arcane/legacy-bridge@1".to_string())),
    );
    provenance_obj.insert("legacyInventoryRef".to_string(), Value::String(LEGACY_INVENTORY_REF.to_string()));
    provenance_obj.insert("legacyInventoryRecordType".to_string(), inventory_type);
    provenance_obj.insert("authenticated".to_string(), Value::Bool(false));

    let mut envelope = Map::new();
    envelope.insert("schemaVersion".to_string(), Value::from(1));
    envelope.insert("kind".to_string(), Value::String("legion-legacy-envelope".to_string()));
    envelope.insert("legacyKind".to_string(), Value::String(legacy_kind.to_string()));
    envelope.insert("payload".to_string(), payload);
    envelope.insert("provenance".to_string(), Value::Object(provenance_obj));
    envelope.insert("provisionalMappingRef".to_string(), Value::Null);

    let envelope = Value::Object(envelope);
    assert_valid_legacy_envelope(&envelope)?;
    Ok(envelope)
}

/// Port of `reverseEnvelope(envelope)`.
pub fn reverse_envelope(envelope: &Value) -> (String, Value) {
    (
        envelope["legacyKind"].as_str().unwrap_or_default().to_string(),
        envelope["payload"].clone(),
    )
}

/// One entry of the rejection list `collectRejections`/`bridgeStoreSnapshot`
/// accumulate.
#[derive(Debug, Clone)]
pub struct Rejection {
    pub legacy_kind: String,
    pub legacy_field: String,
    pub code: &'static str,
    pub reason: Value,
    pub affects: Vec<Value>,
    pub quarantined_in_payload: bool,
}

fn collect_rejections(legacy_kind: &str, payload: &Value) -> Vec<Rejection> {
    let Some(rt) = record_type_for(legacy_kind) else { return Vec::new() };
    let mut out = Vec::new();
    for f in rt["fields"].as_array().into_iter().flatten() {
        if f["disposition"].as_str() != Some("rejected") {
            continue;
        }
        let Some(field_name) = f["legacyField"].as_str() else { continue };
        if payload.as_object().map(|o| !o.contains_key(field_name)).unwrap_or(true) {
            continue;
        }
        out.push(Rejection {
            legacy_kind: legacy_kind.to_string(),
            legacy_field: field_name.to_string(),
            code: resolve_rejection_code(legacy_kind, field_name),
            reason: f.get("reason").cloned().unwrap_or(Value::Null),
            affects: f.get("affects").and_then(Value::as_array).cloned().unwrap_or_default(),
            quarantined_in_payload: true,
        });
    }
    out
}

/// One correspondence pair. Mirrors `correspondenceFor`'s pushed entries.
#[derive(Debug, Clone)]
pub struct Correspondence {
    pub family: &'static str,
    pub legacy_id: String,
    pub legacy_kind: String,
    pub canonical_id: Option<String>,
    pub allocator: &'static str,
}

fn correspondence_for(legacy_kind: &str, payload: &Value, kernel: &KernelBinding) -> Vec<Correspondence> {
    let mut out = Vec::new();
    let status = kernel.kernel_status();
    let legacy_id = if legacy_kind == "runs" {
        payload.get("id").and_then(Value::as_str)
    } else {
        payload.get("run_id").and_then(Value::as_str)
    };
    if let Some(legacy_id) = legacy_id {
        out.push(Correspondence {
            family: "run",
            legacy_id: legacy_id.to_string(),
            legacy_kind: legacy_kind.to_string(),
            canonical_id: None,
            allocator: if status.identity { "kernel" } else { "kernel-unbound" },
        });
    }
    out
}

/// Result of [`bridge_store_snapshot`].
#[derive(Debug, Clone)]
pub struct StoreSnapshotBridge {
    pub envelopes: Vec<Value>,
    pub rejections: Vec<Rejection>,
    pub correspondence: Vec<Correspondence>,
    pub kernel: KernelStatus,
}

/// Port of `bridgeStoreSnapshot(snapshot, provenance)`. `snapshot` mirrors
/// the JS table-name -> rows[] object; `kernel` is the `KernelBinding` this
/// process consults for `kernelStatus()`/`correspondenceFor` (the JS source
/// reads a module-level singleton — see the `r53` module doc comment on why
/// this port takes it as an explicit dependency instead).
pub fn bridge_store_snapshot(
    snapshot: &Map<String, Value>,
    provenance: &ProvenanceInput,
    kernel: &KernelBinding,
) -> Result<StoreSnapshotBridge, ArcaneError> {
    let mut envelopes = Vec::new();
    let mut rejections = Vec::new();
    let mut correspondence = Vec::new();
    let mut tables: Vec<&String> = snapshot.keys().collect();
    tables.sort();
    for table in tables {
        let Some(rows) = snapshot[table].as_array() else { continue };
        for row in rows {
            envelopes.push(envelope_for(table, row.clone(), provenance)?);
            rejections.extend(collect_rejections(table, row));
            correspondence.extend(correspondence_for(table, row, kernel));
        }
    }
    Ok(StoreSnapshotBridge { envelopes, rejections, correspondence, kernel: kernel.kernel_status() })
}

/// Port of `classifyOperationResponse(body)`.
pub fn classify_operation_response(body: &Value) -> &'static str {
    let has = |k: &str| body.get(k).is_some();
    if has("via") {
        return "resolveSession";
    }
    if has("trigger_score") {
        return "assess";
    }
    if has("preflight") || has("rubric_id") {
        return "verify";
    }
    let decision_closed = body.get("decision").and_then(Value::as_str) == Some("closed");
    if has("gate") || has("ledger_hash") || has("idempotent") || decision_closed {
        return "close";
    }
    "checkpoint"
}

/// Result of [`bridge_operation_response`].
#[derive(Debug, Clone)]
pub struct OperationResponseBridge {
    pub legacy_operation: &'static str,
    pub canonical_operation_id: Option<String>,
    pub canonical_operation_version: Option<String>,
    pub disposition: Option<String>,
    pub conflicts: Vec<Value>,
    pub envelope: Value,
    pub rejections: Vec<Rejection>,
}

/// Port of `bridgeOperationResponse(body, provenance)`.
pub fn bridge_operation_response(body: &Value, provenance: &ProvenanceInput) -> Result<OperationResponseBridge, ArcaneError> {
    let legacy_operation = classify_operation_response(body);
    let entry = operation_map()["operations"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|o| o["legacyOperation"].as_str() == Some(legacy_operation));

    let legacy_kind = format!("forge.operation-response.{legacy_operation}");
    let envelope = envelope_for(&legacy_kind, body.clone(), provenance)?;

    let mut rejections = Vec::new();
    if body.get("authority").is_some() {
        rejections.push(Rejection {
            legacy_kind: legacy_kind.clone(),
            legacy_field: "authority".to_string(),
            code: "ARC_AUTHORITY_MODEL_CLAIMED",
            reason: Value::String(
                "Response-level authority is a caller-supplied string; canonical authority is kernel-asserted per turn."
                    .to_string(),
            ),
            affects: vec![Value::String("authority".to_string())],
            quarantined_in_payload: true,
        });
    }

    Ok(OperationResponseBridge {
        legacy_operation,
        canonical_operation_id: entry.and_then(|e| e["canonicalOperationId"].as_str()).map(String::from),
        canonical_operation_version: entry.and_then(|e| e["canonicalOperationVersion"].as_str()).map(String::from),
        disposition: entry.and_then(|e| e["disposition"].as_str()).map(String::from),
        conflicts: entry.and_then(|e| e["conflicts"].as_array()).cloned().unwrap_or_default(),
        envelope,
        rejections,
    })
}

fn list_fixtures() -> Vec<(&'static str, &'static str)> {
    let mut v: Vec<(&'static str, &'static str)> = FIXTURE_NAMES_AND_BODIES.to_vec();
    v.sort_by_key(|(name, _)| *name);
    v
}

/// Port of `migrationDryRun({ capturedAt })`.
pub fn migration_dry_run(captured_at: &str, kernel: &KernelBinding) -> Result<Value, ArcaneError> {
    let baseline = schema_map()["baseline"].clone();
    let provenance = ProvenanceInput {
        source: Some("forge".to_string()),
        captured_at: captured_at.to_string(),
        source_revision: baseline.get("forgeCommit").and_then(Value::as_str).map(String::from),
        imported_by: Some("arcane/legacy-bridge@1".to_string()),
    };

    let mut source_records: Vec<Value> = Vec::new();
    let mut envelopes: Vec<Value> = Vec::new();
    let mut rejections: Vec<Rejection> = Vec::new();
    let mut correspondence: Vec<Correspondence> = Vec::new();
    let mut per_fixture: Vec<Value> = Vec::new();

    for (file, body_text) in list_fixtures() {
        let body: Value = serde_json::from_str(body_text)
            .unwrap_or_else(|e| panic!("bundled fixture {file} is valid JSON: {e}"));
        if file == "08-store-snapshot-scoped.json" {
            let obj = body.as_object().cloned().unwrap_or_default();
            let r = bridge_store_snapshot(&obj, &provenance, kernel)?;
            let mut tables: Vec<&String> = obj.keys().collect();
            tables.sort();
            for table in tables {
                if let Some(rows) = obj[table].as_array() {
                    source_records.extend(rows.iter().cloned());
                }
            }
            per_fixture.push(serde_json::json!({
                "file": file, "kind": "store-snapshot",
                "records": r.envelopes.len(), "rejections": r.rejections.len(),
            }));
            envelopes.extend(r.envelopes);
            rejections.extend(r.rejections);
            correspondence.extend(r.correspondence);
        } else {
            let r = bridge_operation_response(&body, &provenance)?;
            source_records.push(body);
            per_fixture.push(serde_json::json!({
                "file": file, "kind": "operation-response",
                "legacyOperation": r.legacy_operation,
                "canonicalOperationId": r.canonical_operation_id,
                "records": 1, "rejections": r.rejections.len(),
            }));
            envelopes.push(r.envelope);
            rejections.extend(r.rejections);
        }
    }

    let reversed_matches = envelopes.iter().zip(source_records.iter()).all(|(e, s)| {
        let (_, payload) = reverse_envelope(e);
        canonical_json(&payload) == canonical_json(s)
    });

    let source_digest = digest_value(&Value::Array(source_records.clone()));
    let dest_digest = digest_value(&Value::Array(envelopes.clone()));
    let authenticated_count = envelopes
        .iter()
        .filter(|e| e["provenance"]["authenticated"] != Value::Bool(false))
        .count();
    let canonical_ids_allocated = correspondence.iter().filter(|c| c.canonical_id.is_some()).count();

    let mut rejected_fields: BTreeSet<String> = BTreeSet::new();
    for r in &rejections {
        rejected_fields.insert(format!("{}.{}", r.legacy_kind, r.legacy_field));
    }

    Ok(serde_json::json!({
        "schema": "arcane.forge-migration-dry-run.v1",
        "deliverable": "S01",
        "lane": "E-ARCANE",
        "destructive": false,
        "mappingVersion": schema_map()["schema"],
        "baseline": baseline,
        "capturedAt": captured_at,
        "source": {
            "root": "compatibility-fixture:bundled-s00",
            "fixtureCount": per_fixture.len(),
            "recordCount": source_records.len(),
            "digest": source_digest,
        },
        "destination": {
            "namespace": "arcane",
            "envelopeCount": envelopes.len(),
            "digest": dest_digest,
            "authenticatedCount": authenticated_count,
            "canonicalIdsAllocated": canonical_ids_allocated,
        },
        "parity": {
            "recordCountMatches": source_records.len() == envelopes.len(),
            "payloadsPreservedByteForByte": reversed_matches,
            "rejectedFieldCount": rejections.len(),
            "rejectedFields": rejected_fields.into_iter().collect::<Vec<_>>(),
        },
        "perFixture": per_fixture,
        "rollback": {
            "source": "bundled S00 compatibility fixtures (read-only)",
            "method": "reverseEnvelope(envelope) restores the legacy payload exactly; no destructive rewrite occurred, so rollback is a no-op on the source.",
            "reversible": reversed_matches,
        },
        "kernel": kernel_status_json(&kernel.kernel_status()),
    }))
}

fn kernel_status_json(status: &KernelStatus) -> Value {
    serde_json::json!({
        "bound": status.bound,
        "identity": status.identity,
        "events": status.events,
        "objects": status.objects,
        "note": status.note,
    })
}

/// Port of `parityReport()`.
pub fn parity_report() -> Value {
    let dispositions = dispositions();
    let mut totals: Map<String, Value> = dispositions.iter().map(|d| (d.clone(), Value::from(0))).collect();
    let mut record_types_out = Vec::new();
    for rt in record_types() {
        let mut counts: Map<String, Value> = dispositions.iter().map(|d| (d.clone(), Value::from(0))).collect();
        let mut trust_bearing_rejected = Vec::new();
        for f in rt["fields"].as_array().into_iter().flatten() {
            if let Some(d) = f["disposition"].as_str() {
                let c = counts.get(d).and_then(Value::as_i64).unwrap_or(0);
                counts.insert(d.to_string(), Value::from(c + 1));
                let t = totals.get(d).and_then(Value::as_i64).unwrap_or(0);
                totals.insert(d.to_string(), Value::from(t + 1));
                if d == "rejected" {
                    trust_bearing_rejected.push(f["legacyField"].clone());
                }
            }
        }
        record_types_out.push(serde_json::json!({
            "legacyKind": rt["legacyKind"],
            "primaryCanonicalTarget": rt["primaryCanonicalTarget"],
            "fieldCount": rt["fields"].as_array().map(|a| a.len()).unwrap_or(0),
            "counts": counts,
            "trustBearingRejected": trust_bearing_rejected,
        }));
    }
    serde_json::json!({
        "schema": "arcane.forge-parity-report.v1",
        "deliverable": "S01",
        "lane": "E-ARCANE",
        "mappingVersion": schema_map()["schema"],
        "baseline": schema_map()["baseline"],
        "unresolvedCount": schema_map()["unresolved"].as_array().map(|a| a.len()).unwrap_or(0),
        "totals": totals,
        "recordTypes": record_types_out,
        "vocabularyMappings": schema_map()["vocabularyMappings"].as_array().map(|a| a.len()).unwrap_or(0),
        "operationsMapped": operation_map()["operations"].as_array().map(|a| a.len()).unwrap_or(0),
        "knownDefectsNotReproduced": schema_map()["knownLegacyDefectsNotReproduced"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> ProvenanceInput {
        ProvenanceInput { source: None, captured_at: "2026-01-01T00:00:00Z".to_string(), source_revision: None, imported_by: None }
    }

    #[test]
    fn disposition_for_unknown_kind_is_unmapped() {
        assert_eq!(disposition_for("not-a-kind", "x"), "unmapped");
    }

    #[test]
    fn disposition_for_known_field_matches_schema_map() {
        assert_eq!(disposition_for("runs", "summary"), "canonical");
        assert_eq!(disposition_for("runs", "authority"), "rejected");
    }

    #[test]
    fn envelope_for_unknown_kind_is_arc_schema_invalid() {
        let err = envelope_for("nope", Value::Null, &provenance()).unwrap_err();
        assert_eq!(err.code, "ARC_SCHEMA_INVALID");
    }

    #[test]
    fn envelope_for_pins_authenticated_false_and_provisional_null() {
        let env = envelope_for("runs", serde_json::json!({"id": "r1"}), &provenance()).unwrap();
        assert_eq!(env["provenance"]["authenticated"], Value::Bool(false));
        assert_eq!(env["provisionalMappingRef"], Value::Null);
        assert_eq!(env["kind"], "legion-legacy-envelope");
        assert_eq!(env["schemaVersion"], 1);
    }

    #[test]
    fn reverse_envelope_round_trips() {
        let payload = serde_json::json!({"id": "r1", "x": 2});
        let env = envelope_for("runs", payload.clone(), &provenance()).unwrap();
        let (kind, out_payload) = reverse_envelope(&env);
        assert_eq!(kind, "runs");
        assert_eq!(out_payload, payload);
    }

    #[test]
    fn collect_rejections_flags_rejected_fields_present_in_payload() {
        let payload = serde_json::json!({"id": "r1", "authority": "model"});
        let rejections = collect_rejections("runs", &payload);
        assert!(rejections.iter().any(|r| r.legacy_field == "authority" && r.code == "ARC_AUTHORITY_MODEL_CLAIMED"));
    }

    #[test]
    fn resolve_rejection_code_special_cases_claims_status() {
        assert_eq!(resolve_rejection_code("claims", "status"), "ARC_CLAIM_PREREQUISITE_UNMET");
        assert_eq!(resolve_rejection_code("runs", "status"), "ARC_HOST_EVENT_UNTRUSTED");
    }

    #[test]
    fn classify_operation_response_matches_js_discriminators() {
        assert_eq!(classify_operation_response(&serde_json::json!({"via": "x"})), "resolveSession");
        assert_eq!(classify_operation_response(&serde_json::json!({"trigger_score": 1})), "assess");
        assert_eq!(classify_operation_response(&serde_json::json!({"rubric_id": "x"})), "verify");
        assert_eq!(classify_operation_response(&serde_json::json!({"gate": "signoff"})), "close");
        assert_eq!(classify_operation_response(&serde_json::json!({"decision": "closed"})), "close");
        assert_eq!(classify_operation_response(&serde_json::json!({})), "checkpoint");
    }

    #[test]
    fn bridge_store_snapshot_sorts_tables_and_collects_correspondence() {
        let kernel = KernelBinding::new();
        let mut snapshot = Map::new();
        snapshot.insert("runs".to_string(), serde_json::json!([{"id": "run-1"}]));
        let bridged = bridge_store_snapshot(&snapshot, &provenance(), &kernel).unwrap();
        assert_eq!(bridged.envelopes.len(), 1);
        assert_eq!(bridged.correspondence.len(), 1);
        assert_eq!(bridged.correspondence[0].legacy_id, "run-1");
        assert_eq!(bridged.correspondence[0].allocator, "kernel-unbound");
        assert!(bridged.correspondence[0].canonical_id.is_none());
    }

    #[test]
    fn bridge_operation_response_flags_caller_supplied_authority() {
        let body = serde_json::json!({"trigger_score": 3, "authority": "model"});
        let r = bridge_operation_response(&body, &provenance()).unwrap();
        assert_eq!(r.legacy_operation, "assess");
        assert!(r.rejections.iter().any(|x| x.legacy_field == "authority"));
    }

    #[test]
    fn migration_dry_run_reproduces_all_bundled_fixtures_losslessly() {
        let kernel = KernelBinding::new();
        let report = migration_dry_run("2026-01-01T00:00:00Z", &kernel).unwrap();
        assert_eq!(report["parity"]["payloadsPreservedByteForByte"], Value::Bool(true));
        assert_eq!(report["source"]["fixtureCount"], Value::from(12));
        assert_eq!(report["parity"]["recordCountMatches"], Value::Bool(true));
    }

    #[test]
    fn parity_report_totals_sum_to_schema_field_count() {
        let report = parity_report();
        let totals = report["totals"].as_object().unwrap();
        let sum: i64 = totals.values().map(|v| v.as_i64().unwrap_or(0)).sum();
        let field_count: usize = record_types().iter().map(|rt| rt["fields"].as_array().map(|a| a.len()).unwrap_or(0)).sum();
        assert_eq!(sum as usize, field_count);
    }
}
