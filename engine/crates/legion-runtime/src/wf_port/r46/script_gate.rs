//! Port of `script_gate_values()` from `validate-dispatch.py` (lines
//! ~1468-1486).

use super::labels::fenced_value_after;
use regex::Regex;
use std::sync::OnceLock;

fn gate_line_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r"(?i)^(GOAL|SELECTED_PATH|WHY_FASTEST_VALID|BOTTLENECK|PARALLEL|DEFERRED|GOAL_ROUTE_ARTIFACT|GOAL_ROUTE_RECEIPT|EXPECTED_TIME_TO_VERIFIED_B_MS|ROUTE_REVISION|TIER|PRE|SMOKE|CHECK|BLAST|OPT|SHIP):\s*(.+)$",
        )
        .unwrap()
    })
}

/// Port of `script_gate_values()`: parses `KEY: value` lines out of the
/// `**Gate evidence:**` fenced block within `## 5A. Script & Runner Gate`.
pub fn script_gate_values(text: &str) -> std::collections::HashMap<String, String> {
    let start = match text.find("## 5A. Script & Runner Gate") {
        Some(i) => i,
        None => return std::collections::HashMap::new(),
    };
    let end = match text
        .get(start..)
        .and_then(|rest| rest.find("## 6. Failure Decision & Recovery Matrix"))
    {
        Some(i) => start + i,
        None => return std::collections::HashMap::new(),
    };
    let block = &text[start..end];
    let gate = fenced_value_after(block, "**Gate evidence:**").unwrap_or_default();
    let mut values = std::collections::HashMap::new();
    for line in gate.lines() {
        if let Some(caps) = gate_line_re().captures(line.trim()) {
            let key = caps.get(1).unwrap().as_str().to_uppercase();
            let value = caps.get(2).unwrap().as_str().trim().to_string();
            values.insert(key, value);
        }
    }
    values
}
