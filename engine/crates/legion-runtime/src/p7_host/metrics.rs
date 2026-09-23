//! Port of src/lib/metrics/economics.mjs.

use serde_json::{json, Value};

#[derive(Debug, Clone, Default)]
pub struct EconomicsInputs {
    pub provider: String,
    pub duration_ms: f64,
    pub cpu_ms: f64,
    pub memory_mb: f64,
    pub tool_cost: f64,
    pub model_tokens: f64,
    pub model_cost: f64,
}

pub fn economics_receipt(input: &EconomicsInputs) -> Value {
    json!({
        "schemaVersion": 1,
        "kind": "legion-economics",
        "provider": input.provider,
        "durationMs": input.duration_ms,
        "cpuMs": input.cpu_ms,
        "memoryMb": input.memory_mb,
        "toolCost": input.tool_cost,
        "modelTokens": input.model_tokens,
        "modelCost": input.model_cost,
    })
}

pub fn run_summary(records: &[Value]) -> Value {
    let total = |field: &str| -> f64 {
        records.iter().filter_map(|r| r.get(field).and_then(Value::as_f64)).sum()
    };
    json!({
        "schemaVersion": 1,
        "kind": "legion-economics-summary",
        "providers": records.len(),
        "totalDurationMs": total("durationMs"),
        "totalCpuMs": total("cpuMs"),
        "totalMemoryMb": total("memoryMb"),
        "totalToolCost": total("toolCost"),
        "totalModelTokens": total("modelTokens"),
        "totalModelCost": total("modelCost"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn economics_receipt_carries_fields_through() {
        let receipt = economics_receipt(&EconomicsInputs { provider: "eslint".into(), duration_ms: 100.0, ..Default::default() });
        assert_eq!(receipt["provider"], "eslint");
        assert_eq!(receipt["durationMs"], 100.0);
    }

    #[test]
    fn run_summary_aggregates_across_records() {
        let records = vec![
            json!({"durationMs": 10, "toolCost": 1}),
            json!({"durationMs": 20, "toolCost": 2}),
        ];
        let summary = run_summary(&records);
        assert_eq!(summary["providers"], 2);
        assert_eq!(summary["totalDurationMs"], 30.0);
        assert_eq!(summary["totalToolCost"], 3.0);
    }
}
