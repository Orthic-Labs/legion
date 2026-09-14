use crate::advisory_judgment::{find_current_advisory_judgment, persist_advisory_judgment};
use crate::deficit_governance::{
    acknowledge_downstream_deficits, classify_acceptance_deficits, convert_deficits_to_debt,
    evaluate_outcome_closure,
};
use crate::decision::decision;
use crate::finding_lifecycle::{
    apply_scoped_recheck, filter_findings_by_threshold, verify_finding_closure,
    FindingLifecycleStore,
};
use crate::key_ring::KeyRing;
use crate::receipt_store::ReceiptStore;
use crate::scope_amendment::{
    consume_current_user_scope_amendment, verify_current_user_scope_amendment,
};
use serde_json::{json, Value};
use std::path::Path;

#[derive(Default)]
pub struct JudgmentHostFns {
    pub closure_evidence: Option<Box<dyn Fn() -> Value + Send + Sync>>,
    pub acceptance_items: Option<Box<dyn Fn() -> Vec<Value> + Send + Sync>>,
    pub deficit_acknowledgements: Option<Box<dyn Fn() -> Value + Send + Sync>>,
    pub acceptance_surface: Option<Box<dyn Fn() -> Value + Send + Sync>>,
    pub scoped_recheck_evidence: Option<Box<dyn Fn() -> Value + Send + Sync>>,
}

pub struct JudgmentControlCapability {
    finding_store: FindingLifecycleStore,
    receipt_store: ReceiptStore,
    _key_ring: Option<KeyRing>,
    host: JudgmentHostFns,
}

impl JudgmentControlCapability {
    pub fn from_cwd(cwd: &Path, key_ring: Option<KeyRing>) -> Result<Self, String> {
        let receipt_root = cwd.join(".audit").join("arcane").join("receipts");
        let receipt_store = ReceiptStore::new(receipt_root)?;
        let records = load_finding_records(&receipt_store);
        Ok(Self {
            finding_store: FindingLifecycleStore::new(records),
            receipt_store,
            _key_ring: key_ring,
            host: JudgmentHostFns::default(),
        })
    }

    pub fn with_host(mut self, host: JudgmentHostFns) -> Self {
        self.host = host;
        self
    }

    fn persist_findings(&self) {
        let records = self.finding_store.records();
        let _ = self.receipt_store.append(&json!({
            "kind": "arcane-governance-finding-state",
            "records": records,
            "recordedAt": millis_now(),
        }));
    }
}

fn millis_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().to_string())
        .unwrap_or_else(|_| "0".into())
}

fn load_finding_records(receipt_store: &ReceiptStore) -> Vec<Value> {
    receipt_store
        .list()
        .into_iter()
        .filter(|record| {
            record.get("kind").and_then(Value::as_str) == Some("arcane-governance-finding-state")
        })
        .filter_map(|record| record.get("records").and_then(Value::as_array).cloned())
        .last()
        .unwrap_or_default()
}

fn exact_payload(value: &Value) -> bool {
    let object = value.as_object();
    object.is_some_and(|object| {
        object.len() == 2
            && object.get("operation").and_then(Value::as_str).is_some_and(|op| !op.is_empty())
            && object.get("payload").is_some_and(Value::is_object)
    })
}

fn diagnostic_only(operation: &str) -> Value {
    json!({
        "allowed": false,
        "code": "ARC_DIAGNOSTIC_ONLY",
        "consumable": false,
        "diagnostic": {
            "operation": operation,
            "reason": "private host judgment-control capability required",
        },
    })
}

fn failed(message: impl Into<String>) -> Value {
    json!({
        "allowed": false,
        "code": "ARC_INTERNAL_ERROR",
        "message": message.into(),
        "detail": {},
    })
}

fn wrap_result(value: Value) -> Value {
    if value.get("allowed").is_some() {
        value
    } else {
        decision(true, None, None, value)
    }
}

fn call_host_value(host: &Option<Box<dyn Fn() -> Value + Send + Sync>>, label: &str) -> Result<Value, String> {
    host.as_ref()
        .map(|callback| callback())
        .ok_or_else(|| format!("{label} is unavailable"))
}

fn call_host_items(
    host: &Option<Box<dyn Fn() -> Vec<Value> + Send + Sync>>,
    label: &str,
) -> Result<Vec<Value>, String> {
    host.as_ref()
        .map(|callback| callback())
        .ok_or_else(|| format!("{label} is unavailable"))
}

fn dispatch_operation(
    operation: &str,
    payload: &Value,
    capability: &JudgmentControlCapability,
) -> Result<Value, String> {
    match operation {
        "finding.upsert" => {
            let finding = payload.get("finding").cloned().unwrap_or(Value::Null);
            let review_round_id = payload
                .get("reviewRoundId")
                .or_else(|| payload.get("review_round_id"))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| "reviewRoundId is required".to_string())?;
            let output = capability.finding_store.upsert(&finding, review_round_id);
            capability.persist_findings();
            Ok(output)
        }
        "finding.records" => Ok(json!({ "records": capability.finding_store.records() })),
        "finding.verify-closure" => {
            let evidence = call_host_value(&capability.host.closure_evidence, "closureEvidence")?;
            Ok(verify_finding_closure(&evidence))
        }
        "finding.filter-threshold" => filter_findings_by_threshold(payload).map_err(|error| error),
        "finding.scoped-recheck" => {
            let input = call_host_value(
                &capability.host.scoped_recheck_evidence,
                "scopedRecheckEvidence",
            )?;
            if !input.is_object() {
                return Ok(json!({
                    "allowed": false,
                    "code": "ARC_EVIDENCE_INSUFFICIENT",
                    "message": "host-scoped recheck evidence is unavailable",
                    "detail": {},
                }));
            }
            apply_scoped_recheck(&input).map_err(|error| error)
        }
        "deficit.classify" => {
            let items = call_host_items(&capability.host.acceptance_items, "acceptanceItems")?;
            Ok(classify_acceptance_deficits(&json!({ "acceptanceItems": items })))
        }
        "deficit.convert" => {
            let items = call_host_items(&capability.host.acceptance_items, "acceptanceItems")?;
            Ok(convert_deficits_to_debt(&json!({ "acceptanceItems": items })))
        }
        "deficit.acknowledge" => {
            let source = call_host_value(
                &capability.host.deficit_acknowledgements,
                "deficitAcknowledgements",
            )?;
            Ok(acknowledge_downstream_deficits(&source))
        }
        "outcome.evaluate-closure" => {
            let surface = call_host_value(&capability.host.acceptance_surface, "acceptanceSurface")?;
            Ok(evaluate_outcome_closure(&json!({ "acceptanceSurface": surface })))
        }
        "advisory.consume" => {
            let receipt = payload.get("receipt").cloned().unwrap_or(Value::Null);
            Ok(persist_advisory_judgment(&capability.receipt_store, &receipt))
        }
        "advisory.query" => {
            let expected = payload.get("expected").cloned().unwrap_or(json!({}));
            Ok(find_current_advisory_judgment(&capability.receipt_store, &expected))
        }
        "scope.verify" => Ok(verify_current_user_scope_amendment(
            payload,
            &capability.receipt_store,
        )),
        "scope.consume" => Ok(consume_current_user_scope_amendment(
            payload,
            &capability.receipt_store,
        )),
        _ => Ok(json!({
            "allowed": false,
            "code": "ARC_OPERATION_UNKNOWN",
            "consumable": false,
            "detail": { "operation": operation },
        })),
    }
}

pub fn dispatch_governance_judgment(
    request: &Value,
    capability: Option<&JudgmentControlCapability>,
) -> Value {
    if !exact_payload(request) {
        return json!({
            "allowed": false,
            "code": "ARC_SCHEMA_INVALID",
            "consumable": false,
            "detail": {},
        });
    }
    let operation = request["operation"].as_str().unwrap_or_default();
    if capability.is_none() {
        return diagnostic_only(operation);
    }
    match dispatch_operation(operation, request.get("payload").unwrap_or(&Value::Null), capability.unwrap()) {
        Ok(value) => wrap_result(value),
        Err(error) => failed(error),
    }
}

pub fn auth_unavailable_result() -> Value {
    json!({
        "allowed": false,
        "code": "ARC_AUTH_KEY_UNAVAILABLE",
        "message": "authenticated governance stores are unavailable",
        "detail": {},
    })
}

pub fn requires_authenticated_stores(operation: &str) -> bool {
    operation.starts_with("advisory.") || operation.starts_with("scope.")
}
