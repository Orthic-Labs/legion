//! Full port of `src/lib/dispatch-validator/enforce_cheap_review_routing.py`.
//!
//! Only `routing_errors()` (the pure decision logic) is ported; the CLI
//! `main()` (argument parsing, JSON file reads, `PASS`/`FAIL` printing) is
//! caller-owned in Rust, same convention as other `wf_port` chunks.

use super::authority_packet::authority_packet_errors;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

/// Port of `TIERS`.
pub const TIERS: [&str; 4] = ["FRONTIER", "MID", "CHEAP_STRICT", "NONE"];
/// Port of `PROFILES`.
pub const PROFILES: [&str; 3] = ["strict", "standard", "advanced"];

/// Port of `routing_errors()`.
///
/// Inherits the `authority_packet_errors` scope note: for `packetType ==
/// "direct"`/`"worker"` packets, the returned error set omits the
/// packet-type-specific checks `validate-dispatch.py` also performs (see
/// `wf_port::w2_044`'s module doc).
pub fn routing_errors(packet: &Value, path: &Path) -> Vec<String> {
    let (errors, _) = authority_packet_errors(packet, path);
    let mut errors: BTreeSet<String> = errors.into_iter().collect();

    let routing = packet.get("modelRouting").and_then(|v| v.as_object());
    let routing = match routing {
        Some(r) => r,
        None => return errors.into_iter().collect(),
    };
    let tier = routing.get("modelTier").and_then(|v| v.as_str());
    let profile = routing.get("workerProfile").and_then(|v| v.as_str());
    if !tier.is_some_and(|t| TIERS.contains(&t)) {
        errors.insert("modelTier must be one of FRONTIER, MID, CHEAP_STRICT, NONE".to_string());
    }
    if !profile.is_some_and(|p| PROFILES.contains(&p)) {
        errors.insert("workerProfile must be one of strict, standard, advanced".to_string());
    }
    if tier == Some("CHEAP_STRICT") && profile != Some("strict") {
        errors.insert("CHEAP_STRICT requires strict workerProfile".to_string());
    }
    errors.into_iter().collect()
}
