//! Port of `src/packages/context/lib/context.mjs`.
//!
//! Thin Legion transport for Membrane context packets. Membrane owns packet
//! schema, evidence selection, reduction, continuity, receipt production, &
//! persistence. Legion validates only transport shape before forwarding
//! bytes; it never reconstructs or edits packet content.
//!
//! Distinct from `src/lib/design/context.mjs` (`create_design_context` in
//! `p7_host::design`), which is a different file with an unrelated purpose.

use serde_json::{json, Value};

const PACKET_SCHEMAS: [&str; 2] = [
    "membrane.context-packet.v1",
    "membrane.blueprint-packet.v1",
];

fn unavailable(reason: &str) -> Value {
    json!({
        "schema": "legion.context-result.v1",
        "status": "unavailable",
        "reason": reason,
    })
}

/// Port of `validateContextPacket(packet)`. Returns `Ok(())` on success and
/// `Err(message)` mirroring the JS `TypeError` message on failure.
pub fn validate_context_packet(packet: &Value) -> Result<(), String> {
    if !packet.is_object() {
        return Err("Membrane packet must be an object".to_string());
    }
    let schema = packet.get("schema").and_then(Value::as_str).unwrap_or("");
    if !PACKET_SCHEMAS.contains(&schema) {
        return Err("unsupported Membrane packet schema".to_string());
    }
    if packet.get("status").and_then(Value::as_str) == Some("unavailable") {
        return Err("Membrane packet is unavailable".to_string());
    }
    Ok(())
}

/// Port of `consumeMembranePacket(packet)`.
pub fn consume_membrane_packet(packet: &Value) -> Result<Value, String> {
    validate_context_packet(packet)?;
    Ok(packet.clone())
}

/// Port of the `transport` parameter of `requestMembraneContext`. JS accepts
/// an async function; Rust models it as a trait so callers can inject a
/// fake for tests and real transports can be sync or async underneath.
pub trait MembraneTransport {
    /// Returns `Err(())` on transport failure (JS: `catch {}` swallows the
    /// original error and reports `membrane-transport-failed`).
    fn request(&self, request: &Value) -> Result<Value, ()>;
}

/// Port of `requestMembraneContext({ transport, request })`.
pub fn request_membrane_context(transport: Option<&dyn MembraneTransport>, request: &Value) -> Value {
    let Some(transport) = transport else {
        return unavailable("membrane-transport-unavailable");
    };
    let packet = match transport.request(request) {
        Ok(packet) => packet,
        Err(()) => return unavailable("membrane-transport-failed"),
    };
    match consume_membrane_packet(&packet) {
        Ok(packet) => packet,
        Err(_) => unavailable("membrane-packet-invalid"),
    }
}

/// Port of `createUnavailableContextAdapter(capabilityName, reason)`. JS
/// returns an object with an async `read()` method; Rust returns the static
/// capability descriptor plus the `unavailable(reason)` result, since the
/// `read()` closure has no side effects to defer.
#[derive(Debug, Clone)]
pub struct UnavailableContextAdapter {
    pub capability: Value,
}

impl UnavailableContextAdapter {
    pub fn read(&self) -> Value {
        let reason = self.capability["reason"].as_str().unwrap_or_default();
        unavailable(reason)
    }
}

/// Port of `createUnavailableContextAdapter`. Returns `Err` mirroring the
/// JS `TypeError` when either argument is empty.
pub fn create_unavailable_context_adapter(
    capability_name: &str,
    reason: &str,
) -> Result<UnavailableContextAdapter, String> {
    if capability_name.is_empty() || reason.is_empty() {
        return Err("capabilityName & reason are required".to_string());
    }
    Ok(UnavailableContextAdapter {
        capability: json!({"capability": capability_name, "status": "absent", "reason": reason}),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeTransport {
        result: Result<Value, ()>,
    }
    impl MembraneTransport for FakeTransport {
        fn request(&self, _request: &Value) -> Result<Value, ()> {
            self.result.clone()
        }
    }

    #[test]
    fn validates_known_schemas() {
        assert!(validate_context_packet(&json!({"schema": "membrane.context-packet.v1"})).is_ok());
        assert!(validate_context_packet(&json!({"schema": "membrane.blueprint-packet.v1"})).is_ok());
    }

    #[test]
    fn rejects_non_object_unknown_schema_and_unavailable_status() {
        assert!(validate_context_packet(&json!("not-an-object")).is_err());
        assert!(validate_context_packet(&json!({"schema": "other"})).is_err());
        assert!(validate_context_packet(&json!([1, 2])).is_err());
        assert!(validate_context_packet(&json!({
            "schema": "membrane.context-packet.v1",
            "status": "unavailable",
        }))
        .is_err());
    }

    #[test]
    fn consume_returns_packet_unchanged_on_success() {
        let packet = json!({"schema": "membrane.context-packet.v1", "data": [1, 2, 3]});
        assert_eq!(consume_membrane_packet(&packet).unwrap(), packet);
    }

    #[test]
    fn request_reports_unavailable_without_transport() {
        let result = request_membrane_context(None, &json!({}));
        assert_eq!(result["status"], json!("unavailable"));
        assert_eq!(result["reason"], json!("membrane-transport-unavailable"));
    }

    #[test]
    fn request_reports_transport_failure() {
        let transport = FakeTransport { result: Err(()) };
        let result = request_membrane_context(Some(&transport), &json!({}));
        assert_eq!(result["reason"], json!("membrane-transport-failed"));
    }

    #[test]
    fn request_reports_invalid_packet() {
        let transport = FakeTransport {
            result: Ok(json!({"schema": "bogus"})),
        };
        let result = request_membrane_context(Some(&transport), &json!({}));
        assert_eq!(result["reason"], json!("membrane-packet-invalid"));
    }

    #[test]
    fn request_returns_valid_packet() {
        let packet = json!({"schema": "membrane.context-packet.v1", "data": true});
        let transport = FakeTransport { result: Ok(packet.clone()) };
        let result = request_membrane_context(Some(&transport), &json!({}));
        assert_eq!(result, packet);
    }

    #[test]
    fn unavailable_adapter_requires_both_arguments() {
        assert!(create_unavailable_context_adapter("", "reason").is_err());
        assert!(create_unavailable_context_adapter("cap", "").is_err());
        let adapter = create_unavailable_context_adapter("cap", "reason").unwrap();
        assert_eq!(adapter.capability["status"], json!("absent"));
        assert_eq!(adapter.read()["reason"], json!("reason"));
    }
}
