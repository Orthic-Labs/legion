//! Ported tests for chunk wf048 (area `src/providers/runtime/web`,
//! target crate `legion-audit`):
//!   - `src/providers/runtime/web/backend/index.mjs`
//!   - `src/providers/runtime/web/capture/index.mjs`
//!   - `src/providers/runtime/web/data/index.mjs`
//!   - `src/providers/runtime/web/discovery/index.mjs`
//!
//! No JS `.test.mjs` file targeting these four modules directly was found
//! under `tests/` in the JS tree, so these assertions are derived from the
//! source's own documented behaviour (binding validation, sanitize/redact
//! gaps, denominator accounting) rather than ported line-for-line from an
//! existing test file.
//!
//! Requires the integrator to wire `pub mod wf_port;` (with `pub mod
//! wf048;` inside it) into `legion_audit`'s crate root.

use legion_audit::wf_port::wf048::capture::{capture_web_evidence, WebJourneyRow};
use legion_audit::wf_port::wf048::data::{verify_data_exercise, DataExerciseAdapter, MissingAdapter};
use legion_audit::wf_port::wf048::discovery::discover_web_surfaces;
use legion_audit::wf_port::wf048::{inspect_web_backend, sanitize};
use serde_json::{json, Value};

fn full_binding() -> Value {
    json!({
        "targetId": "target-1",
        "environment": "staging",
        "actorId": "actor-1",
        "tenantId": "tenant-1",
        "browser": "chromium",
        "browserVersion": "120.0",
        "viewport": "1280x720",
        "locale": "en-US",
        "sourceRevision": "abc123",
        "artifactDigest": "sha256:0000000000000000000000000000000000000000000000000000000000000",
    })
}

// ---------------------------------------------------------------------
// backend/index.mjs (`inspectWebBackend`)
// ---------------------------------------------------------------------

#[test]
fn backend_pass_when_every_endpoint_has_id_method_path() {
    let result = inspect_web_backend(
        &full_binding(),
        &json!([
            {"id": "b", "method": "GET", "path": "/b"},
            {"id": "a", "method": "POST", "path": "/a"},
        ]),
    );
    assert_eq!(result["status"], json!("pass"));
    assert_eq!(result["coverageGaps"], json!([]));
    // sortById orders by id.
    assert_eq!(result["receipts"][0]["id"], json!("a"));
    assert_eq!(result["receipts"][1]["id"], json!("b"));
}

#[test]
fn backend_reports_missing_fields_and_empty_denominator() {
    let result = inspect_web_backend(&full_binding(), &json!([{"id": "x"}]));
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"x:missing-method".to_string()));
    assert!(gaps.contains(&"x:missing-path".to_string()));
    assert_eq!(result["status"], json!("unproven"));
}

#[test]
fn backend_flags_empty_and_invalid_collections() {
    let empty = inspect_web_backend(&full_binding(), &json!([]));
    let gaps: Vec<String> = empty["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"backend-denominator-empty".to_string()));

    let invalid = inspect_web_backend(&full_binding(), &json!(["not-an-object"]));
    assert_eq!(invalid["status"], json!("error"));
    assert_eq!(invalid["coverageGaps"], json!(["backend-collection-invalid"]));
}

#[test]
fn backend_flags_duplicate_and_missing_ids() {
    let result = inspect_web_backend(
        &full_binding(),
        &json!([
            {"id": "dup", "method": "GET", "path": "/a"},
            {"id": "dup", "method": "GET", "path": "/b"},
            {"method": "GET", "path": "/c"},
        ]),
    );
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.iter().any(|g| g == "backend-id-duplicate:dup"));
    assert!(gaps.contains(&"backend-id-missing".to_string()));
}

#[test]
fn backend_forces_error_on_invalid_binding() {
    let result = inspect_web_backend(&json!({}), &json!([{"id": "a", "method": "GET", "path": "/a"}]));
    assert_eq!(result["status"], json!("error"));
    assert_eq!(result["terminal"], json!(true));
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.iter().any(|g| g.starts_with("binding-invalid:")));
}

// ---------------------------------------------------------------------
// discovery/index.mjs (`discoverWebSurfaces`)
// ---------------------------------------------------------------------

#[test]
fn discovery_binds_components_and_derives_stable_ids() {
    let artifacts = json!([
        {"path": "/home", "kind": "page", "componentId": "home-page"},
        {"path": "/about", "kind": "page"},
    ]);
    let result = discover_web_surfaces(&artifacts, Some("target-1"), Some("fallback-component"));
    assert_eq!(result["complete"], json!(true));
    assert_eq!(result["surfaces"][0]["componentId"], json!("home-page"));
    assert_eq!(result["surfaces"][1]["componentId"], json!("fallback-component"));
    assert_eq!(result["coverageGaps"], json!([]));

    // id is a stable digest of (targetId, path, kind).
    let again = discover_web_surfaces(&artifacts, Some("target-1"), Some("fallback-component"));
    assert_eq!(result["surfaces"][0]["id"], again["surfaces"][0]["id"]);
    assert!(result["surfaces"][0]["id"].as_str().unwrap().starts_with("sha256:"));
}

#[test]
fn discovery_reports_component_unbound_gap_without_any_fallback() {
    let artifacts = json!([{"path": "/orphan"}]);
    let result = discover_web_surfaces(&artifacts, Some("target-1"), None);
    assert_eq!(result["complete"], json!(false));
    let gap = result["coverageGaps"][0].as_str().unwrap();
    assert!(gap.starts_with("component-unbound:"));
}

// ---------------------------------------------------------------------
// capture/index.mjs (`captureWebEvidence`)
// ---------------------------------------------------------------------

fn perf(lcp: f64) -> Value {
    json!({
        "longTasks": 0, "layoutShifts": 0.0, "paints": [1.0], "memory": 1024.0, "userTimings": [1.0], "lcp": lcp,
    })
}

fn full_capture(repeat: u64, lcp: f64) -> Value {
    json!({
        "repeat": repeat,
        "screenshot": format!("shot-{repeat}"),
        "dom": format!("dom-{repeat}"),
        "accessibilityTree": format!("ax-{repeat}"),
        "style": format!("style-{repeat}"),
        "geometry": format!("geo-{repeat}"),
        "trace": format!("trace-{repeat}"),
        "performance": perf(lcp),
    })
}

fn no_journeys() -> Vec<WebJourneyRow<'static>> {
    Vec::new()
}

#[test]
fn capture_rejects_invalid_surface_tool_and_collection_shapes() {
    let binding = full_binding();
    let bad_surface = capture_web_evidence(&binding, &json!(null), &json!({}), &json!([]), &no_journeys(), |_| false, |_| false);
    assert_eq!(bad_surface["coverageGaps"], json!(["capture-surface-invalid"]));

    let bad_tool = capture_web_evidence(&binding, &json!({}), &json!(null), &json!([]), &no_journeys(), |_| false, |_| false);
    assert_eq!(bad_tool["coverageGaps"], json!(["capture-tool-invalid"]));

    let bad_captures = capture_web_evidence(&binding, &json!({}), &json!({}), &json!("nope"), &no_journeys(), |_| false, |_| false);
    assert_eq!(bad_captures["coverageGaps"], json!(["capture-collection-invalid"]));
}

#[test]
fn capture_flags_missing_surface_and_tool_bindings_with_too_few_repeats() {
    let binding = full_binding();
    let surface = json!({});
    let tool = json!({});
    let captures = json!([full_capture(1, 100.0)]);
    let result = capture_web_evidence(&binding, &surface, &tool, &captures, &no_journeys(), |_| false, |_| false);
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"surface-binding-incomplete".to_string()));
    assert!(gaps.contains(&"capture-journey-id-missing".to_string()));
    assert!(gaps.contains(&"capture-state-binding-missing".to_string()));
    assert!(gaps.contains(&"capture-matrix-combination-binding-missing".to_string()));
    assert!(gaps.contains(&"capture-tool-unversioned".to_string()));
    assert!(gaps.contains(&"accessibility-engine-unversioned".to_string()));
    assert!(gaps.contains(&"capture-repeats-insufficient".to_string()));
    assert_eq!(result["status"], json!("partial"));
}

#[test]
fn capture_passes_with_two_distinct_repeats_and_a_matching_planned_journey() {
    let binding = full_binding();
    let surface = json!({
        "id": "journey-1", "route": "/home", "componentIds": ["home"],
        "journeyId": "journey-1", "stateId": "state-1", "matrixCombinationId": "combo-1",
        "controlId": "control-1", "routeId": "route-1", "actionId": "action-1",
        "protocolId": "protocol-1", "directApplicable": true, "deepApplicable": false,
        "binding": binding,
    });
    let tool = json!({
        "name": "playwright", "version": "1.40.0",
        "accessibilityEngine": "axe-core", "accessibilityEngineVersion": "4.8.0",
    });
    let captures = json!([full_capture(1, 100.0), full_capture(2, 200.0)]);
    let journey = WebJourneyRow {
        id: "journey-1",
        control_id: "control-1",
        route_id: "route-1",
        route: "/home",
        state_id: "state-1",
        action_id: "action-1",
        protocol_ids: &["protocol-1"],
        direct_applicable: true,
        deep_applicable: false,
        matrix_combination_id: "combo-1",
    };
    let result = capture_web_evidence(&binding, &surface, &tool, &captures, &[journey], |_| true, |_| true);
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.is_empty(), "unexpected gaps: {gaps:?}");
    assert_eq!(result["status"], json!("pass"));
    assert_eq!(result["performance"]["p75"], json!(200.0));
}

#[test]
fn capture_flags_unplanned_matrix_combination_and_non_matching_journey_surface() {
    let binding = full_binding();
    let surface = json!({
        "id": "surface-1", "route": "/home", "componentIds": ["home"],
        "journeyId": "j1", "stateId": "state-1", "matrixCombinationId": "combo-x",
    });
    let tool = json!({
        "name": "playwright", "version": "1.40.0",
        "accessibilityEngine": "axe-core", "accessibilityEngineVersion": "4.8.0",
    });
    let captures = json!([full_capture(1, 100.0), full_capture(2, 200.0)]);
    let result = capture_web_evidence(&binding, &surface, &tool, &captures, &no_journeys(), |_| false, |_| false);
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"capture-matrix-combination-unplanned".to_string()));
    assert!(gaps.contains(&"capture-journey-binding-unplanned".to_string()));
    assert!(gaps.contains(&"capture-journey-id-unplanned".to_string()));
}

#[test]
fn capture_redacts_sensitive_tool_fields_and_flags_sanitized() {
    let binding = full_binding();
    let surface = json!({
        "id": "surface-1", "route": "/home", "componentIds": ["home"],
        "journeyId": "", "stateId": "state-1", "matrixCombinationId": "combo-1",
    });
    let tool = json!({
        "name": "playwright", "version": "1.40.0",
        "accessibilityEngine": "axe-core", "accessibilityEngineVersion": "4.8.0",
        "apiKey": "super-secret-value",
    });
    let captures = json!([full_capture(1, 100.0), full_capture(2, 200.0)]);
    let result = capture_web_evidence(&binding, &surface, &tool, &captures, &no_journeys(), |_| true, |_| true);
    assert_eq!(result["tool"]["apiKey"], json!("[REDACTED]"));
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"capture-sensitive-data-sanitized".to_string()));
}

// ---------------------------------------------------------------------
// data/index.mjs (`verifyDataExercise`)
// ---------------------------------------------------------------------

struct FixtureAdapter {
    status: &'static str,
}

#[async_trait::async_trait]
impl DataExerciseAdapter for FixtureAdapter {
    async fn exercise(&self, binding: &Value, dataset: &str, schema_version: &str, cases: &[Value]) -> Value {
        let rows: Vec<Value> = cases
            .iter()
            .map(|case| {
                // `data-case-artifacts-invalid` fires whenever a case has
                // zero valid artifacts (`src/providers/runtime/web/data/
                // index.mjs`: `if (!artifactResults.length || ...)`), so a
                // "passes" fixture needs at least one artifact that
                // satisfies `sanitizeProducedArtifact` (matching
                // content/digest) and `artifactResult`'s own field checks
                // (kind, caseId, datasetId, schemaVersion, engineVersion,
                // binding).
                let content = "ok";
                let content_digest = format!(
                    "sha256:{}",
                    hex::encode(<sha2::Sha256 as sha2::Digest>::digest(content.as_bytes()))
                );
                let artifact = json!({
                    "kind": "data-result",
                    "caseId": case["id"],
                    "datasetId": dataset,
                    "schemaVersion": schema_version,
                    "engineVersion": case["engine"]["version"],
                    "binding": binding,
                    "content": content,
                    "digest": content_digest,
                });
                json!({
                    "id": case["id"], "operationType": case["operationType"], "terminal": true, "status": self.status,
                    "binding": binding, "observed": {"ok": true}, "durableResult": {"rows": 1},
                    "artifacts": [artifact],
                })
            })
            .collect();
        json!({"status": self.status, "terminal": true, "cases": rows, "dataset": dataset, "schemaVersion": schema_version})
    }
    async fn cleanup(&self, binding: &Value, dataset: &str, schema_version: &str) -> Result<Value, Value> {
        Ok(json!({"datasetId": dataset, "schemaVersion": schema_version, "environment": binding["environment"], "binding": binding, "residualDamage": []}))
    }
}

fn valid_case(id: &str) -> Value {
    let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    json!({
        "id": id, "operationType": "query", "statementDigest": digest,
        "dataset": {"id": "ds-1", "digest": digest},
        "schema": {"version": "v1", "digest": digest},
        "engine": {"name": "postgres", "version": "16", "digest": digest},
        "isolation": {"id": "iso-1", "environment": "staging", "binding": full_binding()},
        "cleanupBinding": {"datasetId": "ds-1", "schemaVersion": "v1", "environment": "staging", "binding": full_binding()},
    })
}

#[tokio::test]
async fn data_exercise_passes_with_valid_case_and_matching_adapter() {
    let binding = full_binding();
    let adapter = FixtureAdapter { status: "pass" };
    let cases = json!([valid_case("case-1")]);
    let result = verify_data_exercise(&binding, Some("ds-1"), Some("v1"), &adapter, &cases).await;
    assert_eq!(result["status"], json!("pass"), "gaps: {:?}", result["coverageGaps"]);
    assert_eq!(result["receipts"][0]["status"], json!("pass"));
    assert_eq!(result["cleanup"]["status"], json!("pass"));
}

#[tokio::test]
async fn data_exercise_blocks_on_preflight_invalid_dataset_or_schema() {
    let binding = full_binding();
    let adapter = FixtureAdapter { status: "pass" };
    let cases = json!([valid_case("case-1")]);
    let result = verify_data_exercise(&binding, None, Some("v1"), &adapter, &cases).await;
    assert_eq!(result["status"], json!("blocked"));
    assert_eq!(result["receipts"][0]["status"], json!("blocked"));
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"data-preflight-invalid".to_string()));
    assert!(gaps.contains(&"dataset-unbound".to_string()));
}

#[tokio::test]
async fn data_exercise_forbids_production_and_destructive_effects() {
    let mut binding = full_binding();
    binding["environment"] = json!("production");
    let adapter = FixtureAdapter { status: "pass" };
    let cases = json!([valid_case("case-1")]);
    let result = verify_data_exercise(&binding, Some("ds-1"), Some("v1"), &adapter, &cases).await;
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"production-effect-forbidden".to_string()));
    assert_eq!(result["status"], json!("blocked"));
}

#[tokio::test]
async fn data_exercise_reports_missing_adapter() {
    let binding = full_binding();
    let cases = json!([valid_case("case-1")]);
    let result = verify_data_exercise(&binding, Some("ds-1"), Some("v1"), &MissingAdapter, &cases).await;
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"adapter-exercise-missing".to_string()));
    assert_eq!(result["receipts"][0]["status"], json!("unproven"));
}

#[tokio::test]
async fn data_exercise_flags_unplanned_and_duplicate_case_rows() {
    let binding = full_binding();
    struct BadAdapter;
    #[async_trait::async_trait]
    impl DataExerciseAdapter for BadAdapter {
        async fn exercise(&self, binding: &Value, _dataset: &str, _schema_version: &str, _cases: &[Value]) -> Value {
            json!({
                "status": "pass", "terminal": true,
                "cases": [
                    {"id": "case-1", "operationType": "query", "terminal": true, "status": "pass", "binding": binding, "observed": {"a": 1}, "durableResult": {"a": 1}, "artifacts": []},
                    {"id": "case-1", "operationType": "query", "terminal": true, "status": "pass", "binding": binding, "observed": {"a": 1}, "durableResult": {"a": 1}, "artifacts": []},
                    {"id": "unplanned", "operationType": "query", "terminal": true, "status": "pass", "binding": binding, "observed": {"a": 1}, "durableResult": {"a": 1}, "artifacts": []},
                ],
            })
        }
        async fn cleanup(&self, binding: &Value, dataset: &str, schema_version: &str) -> Result<Value, Value> {
            Ok(json!({"datasetId": dataset, "schemaVersion": schema_version, "environment": binding["environment"], "binding": binding, "residualDamage": []}))
        }
    }
    let cases = json!([valid_case("case-1")]);
    let result = verify_data_exercise(&binding, Some("ds-1"), Some("v1"), &BadAdapter, &cases).await;
    let gaps: Vec<String> = result["coverageGaps"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(gaps.contains(&"data-case-duplicate:case-1".to_string()));
    assert!(gaps.contains(&"data-case-unplanned:unplanned".to_string()));
}

// ---------------------------------------------------------------------
// sanitize helpers (artifact-sanitize.mjs subset) used by capture/data.
// ---------------------------------------------------------------------

#[test]
fn sanitize_string_redacts_bearer_email_ssn_and_phone() {
    let input = "Bearer abc.def and jane@example.com and 123-45-6789 and 555-123-4567";
    let out = sanitize::sanitize_string(input);
    assert!(!out.contains("abc.def"));
    assert!(!out.contains("jane@example.com"));
    assert!(!out.contains("123-45-6789"));
    assert!(!out.contains("555-123-4567"));
    assert_eq!(out.matches("[REDACTED]").count(), 4);
}

#[test]
fn sanitize_produced_artifact_rejects_digest_mismatch() {
    let artifact = json!({"kind": "data-result", "content": "hello", "digest": "sha256:not-the-real-digest"});
    let result = sanitize::sanitize_produced_artifact(&artifact);
    assert!(!result.valid);
}

#[test]
fn sanitize_produced_artifact_accepts_matching_digest() {
    use sha2::{Digest, Sha256};
    let content = "hello world";
    let digest = format!("sha256:{}", hex::encode(Sha256::digest(content.as_bytes())));
    let artifact = json!({"kind": "data-result", "content": content, "digest": digest});
    let result = sanitize::sanitize_produced_artifact(&artifact);
    assert!(result.valid);
    assert!(!result.sensitive);
}
