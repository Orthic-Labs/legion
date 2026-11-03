//! Port of `src/lib/privacy/index.mjs`.
//!
//! Privacy controls: default telemetry is OFF; opt-in aggregate diagnostics
//! with a data dictionary; export/delete commands; every integration
//! documents exactly what leaves the machine.

use serde_json::{json, Value};

pub const TELEMETRY_DEFAULT: &str = "off";

/// Port of `privacyReceipt({ telemetry, integrations, egress })`.
pub fn privacy_receipt(
    telemetry: Option<&str>,
    integrations: &[String],
    egress: &[Value],
) -> Value {
    let mut sorted_integrations = integrations.to_vec();
    sorted_integrations.sort();
    let egress_out: Vec<Value> = egress
        .iter()
        .map(|entry| {
            json!({
                "integration": entry.get("integration").cloned().unwrap_or(Value::Null),
                "leavesMachine": entry.get("leavesMachine").cloned().unwrap_or_else(|| json!([])),
                "dataDictionary": entry
                    .get("dataDictionary")
                    .cloned()
                    .unwrap_or_else(|| json!("See the integration documentation.")),
            })
        })
        .collect();
    json!({
        "schemaVersion": 1,
        "kind": "legion-privacy-receipt",
        "telemetry": telemetry.unwrap_or(TELEMETRY_DEFAULT),
        "integrations": sorted_integrations,
        "egress": egress_out,
        "exportCommand": "legion privacy export",
        "deleteCommand": "legion privacy delete",
    })
}

/// Port of `privacyDataDictionary()`.
pub fn privacy_data_dictionary() -> Value {
    json!({
        "telemetry": {
            "default": TELEMETRY_DEFAULT,
            "content": ["provider ids", "duration", "outcome"],
        },
        "githubAction": {
            "leavesMachine": ["SARIF report", "audit summary"],
            "content": ["finding ids", "severities", "rule ids"],
        },
        "mcp": {
            "leavesMachine": ["none by default"],
            "content": [],
        },
    })
}
