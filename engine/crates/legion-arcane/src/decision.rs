use serde_json::{json, Map, Value};

pub fn decision(allowed: bool, code: Option<&str>, message: Option<&str>, detail: Value) -> Value {
    let mut object = Map::new();
    object.insert("allowed".into(), json!(allowed));
    if let Some(code) = code {
        object.insert("code".into(), json!(code));
    }
    if let Some(message) = message {
        object.insert("message".into(), json!(message));
    }
    if !detail.is_null() {
        object.insert("detail".into(), detail);
    }
    Value::Object(object)
}

pub fn deny(code: &str, message: &str, detail: Value) -> Value {
    decision(false, Some(code), Some(message), detail)
}

pub fn is_record(value: &Value) -> bool {
    value.is_object()
}
