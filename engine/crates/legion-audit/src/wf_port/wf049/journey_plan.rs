//! Port of `src/providers/runtime/web/journey-plan.mjs`.
//!
//! The JS module reads `src/registry/platform-scenarios/web.json` at import
//! time via `readFileSync(new URL('../../../registry/platform-scenarios/web.json', import.meta.url))`.
//! This port embeds the same file at compile time with `include_str!` (a
//! read, not an edit, of a file outside the owned `wf049` directory) so the
//! plan is available without adding a runtime file-path dependency.

use serde_json::Value;
use std::sync::OnceLock;

const WEB_JOURNEY_PLAN_JSON: &str = include_str!("../../../../../../src/registry/platform-scenarios/web.json");

fn plan() -> &'static Value {
    static PLAN: OnceLock<Value> = OnceLock::new();
    PLAN.get_or_init(|| serde_json::from_str(WEB_JOURNEY_PLAN_JSON).expect("registry/platform-scenarios/web.json must be valid JSON"))
}

/// Port of `WEB_JOURNEY_PLAN`.
pub fn web_journey_plan() -> &'static Value {
    plan()
}

/// Port of `WEB_JOURNEYS`.
pub fn web_journeys() -> &'static [Value] {
    static JOURNEYS: OnceLock<Vec<Value>> = OnceLock::new();
    JOURNEYS.get_or_init(|| plan().get("journeys").and_then(Value::as_array).cloned().unwrap_or_default())
}

/// Port of `WEB_PROTOCOLS`.
pub fn web_protocols() -> &'static Value {
    static PROTOCOLS: OnceLock<Value> = OnceLock::new();
    PROTOCOLS.get_or_init(|| plan().get("protocols").cloned().unwrap_or(Value::Null))
}

/// Port of `webJourneyForControl`.
pub fn web_journey_for_control(control_id: &str) -> Option<&'static Value> {
    web_journeys().iter().find(|row| row.get("controlId").and_then(Value::as_str) == Some(control_id))
}

#[derive(Default)]
pub struct WebJourneySurfaceMatchesInput<'a> {
    pub journey_id: Option<&'a str>,
    pub route: Option<&'a str>,
    pub state_id: Option<&'a str>,
    pub matrix_combination_id: Option<&'a str>,
}

/// Port of `webJourneySurfaceMatches`. `journey_id: None` mirrors the JS
/// `journeyId === undefined` short-circuit (matches any journey id); the
/// other three fields mirror JS `undefined` only when set to `None` here
/// too, but the JS never omits them from real call sites, so `None` for
/// `route`/`state_id`/`matrix_combination_id` simply means "match rows
/// whose field is JSON null", same as comparing `undefined` to a JSON value.
pub fn web_journey_surface_matches(input: WebJourneySurfaceMatchesInput<'_>) -> bool {
    web_journeys().iter().any(|row| {
        row.get("applicable") == Some(&Value::Bool(true))
            && (input.journey_id.is_none() || row.get("id").and_then(Value::as_str) == input.journey_id)
            && row.get("route").and_then(Value::as_str) == input.route
            && row.get("stateId").and_then(Value::as_str) == input.state_id
            && row.get("matrixCombinationId").and_then(Value::as_str) == input.matrix_combination_id
    })
}

/// Port of `webRouteEvidenceMatches`. `binding_matches` mirrors the JS
/// default `() => false` when the caller supplies none.
pub fn web_route_evidence_matches(row: &Value, evidence: &Value, binding_matches: impl Fn(&Value) -> bool) -> bool {
    evidence.get("kind").and_then(Value::as_str) == Some("web-route-navigation")
        && evidence.get("journeyId") == row.get("id")
        && evidence.get("routeId") == row.get("routeId")
        && evidence.get("control") == row.get("controlId")
        && evidence.get("actionId") == row.get("actionId")
        && evidence.get("route") == row.get("route")
        && evidence.get("stateId") == row.get("stateId")
        && evidence.get("matrixCombinationId") == row.get("matrixCombinationId")
        && binding_matches(evidence.get("binding").unwrap_or(&Value::Null))
}
