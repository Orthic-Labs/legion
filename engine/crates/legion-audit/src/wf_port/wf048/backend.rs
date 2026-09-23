//! Port of `src/providers/runtime/web/backend/index.mjs`
//! (`inspectWebBackend`) — chunk wf048.

use serde_json::{json, Value};

use super::shared::{binding_missing_gaps, denominator, finalize, sort_by_id, unique_sorted};

/// Port of `inspectWebBackend({ binding, endpoints })`.
pub fn inspect_web_backend(binding: &Value, endpoints: &Value) -> Value {
    let endpoints_arr = match endpoints {
        Value::Array(items) => items.clone(),
        Value::Null => Vec::new(),
        _ => {
            return finalize(
                "legion-web-backend-inventory",
                json!({
                    "status": "error",
                    "terminal": true,
                    "binding": binding,
                    "denominator": denominator(&[], &[], &[]).to_value(),
                    "receipts": [],
                    "coverageGaps": ["backend-collection-invalid"],
                }),
            );
        }
    };
    if endpoints_arr.iter().any(|item| !item.is_object()) {
        return finalize(
            "legion-web-backend-inventory",
            json!({
                "status": "error",
                "terminal": true,
                "binding": binding,
                "denominator": denominator(&[], &[], &[]).to_value(),
                "receipts": [],
                "coverageGaps": ["backend-collection-invalid"],
            }),
        );
    }

    let sorted = sort_by_id(&endpoints_arr);
    let mut receipts: Vec<Value> = Vec::new();
    let mut receipt_gaps: Vec<String> = Vec::new();
    for item in &sorted {
        let id = item.get("id").cloned().unwrap_or(Value::Null);
        let mut gaps: Vec<String> = Vec::new();
        for key in ["id", "method", "path"] {
            if item.get(key).map(|v| v.is_null() || v == "").unwrap_or(true) {
                gaps.push(format!("missing-{key}"));
            }
        }
        let id_str = id.as_str().unwrap_or_default();
        for gap in &gaps {
            receipt_gaps.push(format!("{id_str}:{gap}"));
        }
        receipts.push(json!({
            "id": id,
            "method": item.get("method").cloned().unwrap_or(Value::Null),
            "path": item.get("path").cloned().unwrap_or(Value::Null),
            "status": if gaps.is_empty() { "pass" } else { "unproven" },
            "terminal": true,
            "coverageGaps": gaps,
        }));
    }

    let ids: Vec<String> = endpoints_arr
        .iter()
        .map(|item| item.get("id").and_then(Value::as_str).unwrap_or_default().to_string())
        .collect();
    let receipt_ids: Vec<String> = receipts
        .iter()
        .map(|r| r.get("id").and_then(Value::as_str).unwrap_or_default().to_string())
        .collect();
    let counts = denominator(&ids, &receipt_ids, &[]);

    let mut gaps = binding_missing_gaps(binding);
    gaps.extend(receipt_gaps);
    if endpoints_arr.is_empty() {
        gaps.push("backend-denominator-empty".to_string());
    }
    let mut seen_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for id in &ids {
        *seen_counts.entry(id.as_str()).or_insert(0) += 1;
    }
    let mut duplicate_ids: Vec<&str> = seen_counts.iter().filter(|(_, &count)| count > 1).map(|(id, _)| *id).collect();
    duplicate_ids.sort();
    for id in duplicate_ids {
        gaps.push(format!("backend-id-duplicate:{id}"));
    }
    if endpoints_arr
        .iter()
        .any(|item| !matches!(item.get("id"), Some(Value::String(s)) if !s.is_empty()))
    {
        gaps.push("backend-id-missing".to_string());
    }

    let gaps = unique_sorted(gaps);
    let status = if gaps.is_empty() { "pass" } else { "unproven" };

    finalize(
        "legion-web-backend-inventory",
        json!({
            "status": status,
            "terminal": true,
            "claimLevel": "source",
            "binding": binding,
            "denominator": counts.to_value(),
            "receipts": receipts,
            "coverageGaps": gaps,
        }),
    )
}
