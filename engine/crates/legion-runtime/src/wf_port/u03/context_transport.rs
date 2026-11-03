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

const PACKET_SCHEMAS: [&str; 2] = ["membrane.context-packet.v1", "membrane.blueprint-packet.v1"];

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
    #[allow(clippy::result_unit_err)]
    fn request(&self, request: &Value) -> Result<Value, ()>;
}

/// Port of `requestMembraneContext({ transport, request })`.
pub fn request_membrane_context(
    transport: Option<&dyn MembraneTransport>,
    request: &Value,
) -> Value {
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
