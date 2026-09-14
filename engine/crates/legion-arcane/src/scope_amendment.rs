use crate::decision::deny;
use crate::receipt_store::ReceiptStore;
use serde_json::{json, Value};

const KIND: &str = "arcane-current-user-scope-amendment";

pub fn verify_current_user_scope_amendment(
    expected: &Value,
    receipt_store: &ReceiptStore,
) -> Value {
    let chain = receipt_store.verify_chain();
    if chain.get("ok").and_then(Value::as_bool) != Some(true) {
        return deny(
            "ARC_STORE_CORRUPT",
            "scope amendment receipt chain is unavailable",
            json!({}),
        );
    }
    if !expected.is_object() {
        return missing();
    }
    let acceptance_id = expected.get("acceptanceId").and_then(Value::as_str);
    if acceptance_id.is_none_or(|value| value.is_empty()) {
        return missing();
    }
    let records = receipt_store
        .list()
        .into_iter()
        .filter(|record| {
            record.get("kind").and_then(Value::as_str) == Some(KIND)
                && record.get("acceptanceId").and_then(Value::as_str) == acceptance_id
        })
        .collect::<Vec<_>>();
    if records.is_empty() {
        return missing();
    }
    missing()
}

pub fn consume_current_user_scope_amendment(
    expected: &Value,
    receipt_store: &ReceiptStore,
) -> Value {
    let verified = verify_current_user_scope_amendment(expected, receipt_store);
    if verified.get("allowed").and_then(Value::as_bool) != Some(true) {
        return verified;
    }
    verified
}

fn missing() -> Value {
    deny(
        "ARC_APPROVAL_REQUIRED",
        "frozen acceptance scope amendment is OUT_OF_SCOPE without a current signed user challenge",
        json!({ "disposition": "OUT_OF_SCOPE" }),
    )
}
