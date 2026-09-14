use crate::control_lifecycle::assess_control_retirement;
use crate::control_recovery::recover_control_state;
use crate::delivery_scheduler::{
    admit_capacity, admit_task_phase, assess_realization, classify_handoff,
};
use crate::durable_packet::DurablePacketAdmissionStore;
use crate::error::ArcaneError;
use crate::migration_cutover::assess_migration_cutover;
use serde_json::{json, Value};

pub type ProviderFn = dyn Fn(&Value) -> Value;

pub struct TrustedDeliveryEvidenceCapability {
    providers: std::collections::HashMap<String, Box<ProviderFn>>,
}

impl TrustedDeliveryEvidenceCapability {
    pub fn new(
        providers: std::collections::HashMap<String, Box<ProviderFn>>,
    ) -> Result<Self, String> {
        const ALLOWED: [&str; 4] = [
            "controlRetirementEvidence",
            "migrationCutoverEvidence",
            "phaseProofEvidence",
            "controlRecoveryAuthority",
        ];
        if providers.is_empty()
            || providers.keys().any(|name| !ALLOWED.contains(&name.as_str()))
        {
            return Err("trusted delivery providers must be known functions".into());
        }
        Ok(Self { providers })
    }

    fn call(&self, name: &str, input: &Value) -> Option<Value> {
        self.providers
            .get(name)
            .map(|provider| provider(input))
            .filter(Value::is_object)
    }
}

pub struct DeliveryGovernanceDispatcher {
    provider_capability: Option<TrustedDeliveryEvidenceCapability>,
    packet_store: Option<DurablePacketAdmissionStore>,
}

impl DeliveryGovernanceDispatcher {
    pub fn new() -> Self {
        Self {
            provider_capability: None,
            packet_store: None,
        }
    }

    pub fn with_provider(mut self, capability: TrustedDeliveryEvidenceCapability) -> Self {
        self.provider_capability = Some(capability);
        self
    }

    pub fn with_packet_store(mut self, store: DurablePacketAdmissionStore) -> Self {
        self.packet_store = Some(store);
        self
    }

    pub fn dispatch(&self, request: &Value) -> Value {
        if !request.is_object() {
            return denied("ARC_SCHEMA_INVALID", json!({ "message": "operation is required" }));
        }
        let operation = request
            .get("operation")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        if operation.is_none() {
            return denied("ARC_SCHEMA_INVALID", json!({ "message": "operation is required" }));
        }
        let operation = operation.unwrap();
        let input = request.get("input").unwrap_or(&Value::Null);
        match self.operation_result(operation, input) {
            Ok(value) => value,
            Err(error) => denied(
                error.code(),
                json!({ "operation": operation }),
            ),
        }
    }
}

impl Default for DeliveryGovernanceDispatcher {
    fn default() -> Self {
        Self::new()
    }
}

pub fn dispatch_delivery_governance(request: &Value) -> Value {
    DeliveryGovernanceDispatcher::new().dispatch(request)
}

fn denied(code: &str, detail: Value) -> Value {
    let mut object = serde_json::Map::new();
    object.insert("allowed".into(), json!(false));
    object.insert("code".into(), json!(code));
    for (key, value) in detail.as_object().cloned().unwrap_or_default() {
        object.insert(key, value);
    }
    Value::Object(object)
}

fn diagnostic(operation: &str, result: Value) -> Value {
    json!({
        "allowed": false,
        "consumable": false,
        "code": "ARC_DIAGNOSTIC_ONLY",
        "operation": operation,
        "diagnostic": result,
    })
}

fn consumable(result: Value) -> Value {
    let admitted = result.get("allowed").and_then(Value::as_bool) == Some(true)
        || result.get("ready").and_then(Value::as_bool) == Some(true)
        || result.get("outcome").and_then(Value::as_str) == Some("ACTIVATION_ADMITTED");
    if let Some(object) = result.as_object().cloned() {
        let mut map = object;
        map.insert("consumable".into(), json!(admitted));
        Value::Object(map)
    } else {
        result
    }
}

impl DeliveryGovernanceDispatcher {
    fn operation_result(&self, operation: &str, input: &Value) -> Result<Value, ArcaneError> {
        if !input.is_object() {
            return Ok(denied(
                "ARC_SCHEMA_INVALID",
                json!({ "operation": operation, "message": "operation input must be an object" }),
            ));
        }
        let provider = self.provider_capability.as_ref();
        Ok(match operation {
            "control-retirement" => {
                let trusted = provider.and_then(|cap| cap.call("controlRetirementEvidence", input));
                if let Some(trusted) = trusted {
                    consumable(assess_control_retirement(&trusted)?)
                } else {
                    diagnostic(operation, assess_control_retirement(input)?)
                }
            }
            "migration-cutover" => {
                let trusted = provider.and_then(|cap| cap.call("migrationCutoverEvidence", input));
                if let Some(trusted) = trusted {
                    consumable(assess_migration_cutover(&trusted)?)
                } else {
                    diagnostic(operation, assess_migration_cutover(input)?)
                }
            }
            "dispatch-capacity" => admit_capacity(input),
            "dispatch-phase" => {
                let trusted = provider.and_then(|cap| cap.call("phaseProofEvidence", input));
                if let Some(trusted) = trusted {
                    consumable(admit_task_phase(&trusted))
                } else {
                    diagnostic(operation, admit_task_phase(input))
                }
            }
            "dispatch-handoff" => classify_handoff(input),
            "dispatch-realization" => assess_realization(input),
            "dispatch-packet" => {
                let digest = input
                    .get("packetDigest")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if let Some(store) = &self.packet_store {
                    store.admit(digest)
                } else {
                    diagnostic(
                        operation,
                        denied(
                            "ARC_DURABLE_PACKET_REGISTRY_REQUIRED",
                            json!({ "packetDigest": input.get("packetDigest").cloned().unwrap_or(Value::Null) }),
                        ),
                    )
                }
            }
            "control-recovery" => {
                if input
                    .get("controlId")
                    .and_then(Value::as_str)
                    .filter(|value| !value.is_empty())
                    .is_none()
                    || !input.get("authorization").is_some_and(Value::is_object)
                {
                    diagnostic(
                        operation,
                        denied(
                            "ARC_SCHEMA_INVALID",
                            json!({ "controlId": input.get("controlId").cloned().unwrap_or(Value::Null) }),
                        ),
                    )
                } else {
                    diagnostic(
                        operation,
                        recover_control_state(
                            input,
                            &|_| false,
                            &|_, _| Err(ArcaneError::typed("ARC_RECOVERY_REPAIR_FAILED", "unreachable")),
                            &|_, _| false,
                        )?,
                    )
                }
            }
            _ => denied("ARC_OPERATION_UNKNOWN", json!({ "operation": operation })),
        })
    }
}
