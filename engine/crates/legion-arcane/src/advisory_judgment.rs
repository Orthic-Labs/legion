use crate::decision::{decision, deny};
use crate::receipt_store::ReceiptStore;
use serde_json::{json, Value};

const KIND: &str = "arcane-advisory-judgment";

pub fn find_current_advisory_judgment(
    receipt_store: &ReceiptStore,
    _expected: &Value,
) -> Value {
    let chain = receipt_store.verify_chain();
    if chain.get("ok").and_then(Value::as_bool) != Some(true) {
        return deny(
            "ARC_STORE_CORRUPT",
            "receipt store is unavailable or corrupt",
            json!({}),
        );
    }
    let records = receipt_store
        .list()
        .into_iter()
        .filter(|record| record.get("kind").and_then(Value::as_str) == Some(KIND))
        .collect::<Vec<_>>();
    let sages = records
        .iter()
        .filter(|record| record.get("authority").and_then(Value::as_str) == Some("sage"))
        .collect::<Vec<_>>();
    let oracles = records
        .iter()
        .filter(|record| record.get("authority").and_then(Value::as_str) == Some("oracle"))
        .collect::<Vec<_>>();
    for sage in sages.iter().rev() {
        for oracle in oracles.iter().rev() {
            if sage.get("judgment").is_some() && oracle.get("judgment").is_some() {
                return decision(
                    true,
                    None,
                    None,
                    json!({
                        "sageReceiptId": sage.get("receiptId").cloned().unwrap_or(Value::Null),
                        "oracleReceiptId": oracle.get("receiptId").cloned().unwrap_or(Value::Null),
                        "judgment": sage.get("judgment").cloned().unwrap_or(Value::Null),
                    }),
                );
            }
        }
    }
    deny(
        "ARC_EVIDENCE_INSUFFICIENT",
        "current independent Sage/Oracle judgment is unavailable",
        json!({}),
    )
}

pub fn persist_advisory_judgment(receipt_store: &ReceiptStore, receipt: &Value) -> Value {
    let chain = receipt_store.verify_chain();
    if chain.get("ok").and_then(Value::as_bool) != Some(true) {
        return deny(
            "ARC_STORE_CORRUPT",
            "receipt store is unavailable or corrupt",
            json!({}),
        );
    }
    if receipt.get("kind").and_then(Value::as_str) != Some(KIND) {
        return deny("ARC_SCHEMA_INVALID", "advisory judgment is invalid", json!({}));
    }
    let existing = receipt_store
        .list()
        .into_iter()
        .filter(|record| record.get("kind").and_then(Value::as_str) == Some(KIND))
        .collect::<Vec<_>>();
    let receipt_id = receipt.get("receiptId").and_then(Value::as_str);
    let agent_id = receipt.get("agentIdDigest").and_then(Value::as_str);
    let nonce = receipt.get("nonce").and_then(Value::as_str);
    if existing.iter().any(|record| {
        record.get("receiptId").and_then(Value::as_str) == receipt_id
            || (record.get("agentIdDigest").and_then(Value::as_str) == agent_id
                && record.get("nonce").and_then(Value::as_str) == nonce)
    }) {
        return deny(
            "ARC_REPLAY_NONCE_SEEN",
            "advisory judgment was already persisted",
            json!({}),
        );
    }
    decision(true, None, None, receipt_store.append(receipt))
}
