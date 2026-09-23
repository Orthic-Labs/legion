//! Native Rust port of `src/providers/runtime/mobile/**/index.mjs`.
//!
//! Faithful, field-for-field port of the legacy JS mobile runtime providers:
//! commerce, compatibility, devices, host, lifecycle, network, performance,
//! platform-surfaces and release. No Membrane/Blueprint behavior existed in
//! the source files, so nothing was dropped on that account.
//!
//! Every entry point takes and returns `serde_json::Value` to mirror the
//! loosely-typed JS object shapes exactly (including the `?? []` / `?? {}`
//! default-coalescing behavior of the originals).

use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------

fn obj(input: &Value) -> Map<String, Value> {
    input.as_object().cloned().unwrap_or_default()
}

fn get<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a Value> {
    map.get(key)
}

fn get_obj(map: &Map<String, Value>, key: &str) -> Map<String, Value> {
    map.get(key)
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

fn get_bool(map: &Map<String, Value>, key: &str) -> bool {
    map.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn is_true(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::Bool(true)))
}

fn get_str_vec(map: &Map<String, Value>, key: &str) -> Vec<String> {
    map.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn get_array(map: &Map<String, Value>, key: &str) -> Vec<Value> {
    map.get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn covers(actual: &[String], required: &[&str]) -> bool {
    required.iter().all(|item| actual.iter().any(|a| a == item))
}

/// Mirrors JS template-literal stringification for the scalar `Value`
/// variants we expect here (string / number); anything else falls back to
/// its JSON text.
fn value_to_js_string(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null => "null".to_string(),
        other => other.to_string(),
    }
}

// ---------------------------------------------------------------------
// commerce
// ---------------------------------------------------------------------

/// Port of `verifyMobileCommerceOperations`.
pub fn verify_mobile_commerce_operations(input: &Value) -> Value {
    let root = obj(input);
    let entitlement = get_obj(&root, "entitlement");
    let push = get_obj(&root, "push");
    let analytics = get_obj(&root, "analytics");
    let operations = get_obj(&root, "operations");
    let provider = get_obj(&root, "provider");

    let mut gaps: Vec<String> = Vec::new();

    let entitlement_client_decision = is_true(get(&entitlement, "clientDecision"));
    let entitlement_server_verified = is_true(get(&entitlement, "serverVerified"));
    if entitlement_client_decision && !entitlement_server_verified {
        gaps.push("entitlement-server-verification-missing".to_string());
    }
    let entitlement_tested_states = get_str_vec(&entitlement, "testedStates");
    if !covers(
        &entitlement_tested_states,
        &["purchase", "restore", "refund", "revocation", "account-switch"],
    ) {
        gaps.push("entitlement-state-coverage-missing".to_string());
    }

    let push_account_bound = is_true(get(&push, "accountBound"));
    if !push_account_bound {
        gaps.push("push-account-binding-missing".to_string());
    }
    let push_privacy_safe = is_true(get(&push, "privacySafe"));
    if !push_privacy_safe {
        gaps.push("push-privacy-missing".to_string());
    }
    let push_tested_states = get_str_vec(&push, "testedStates");
    if !covers(
        &push_tested_states,
        &["token-rotation", "terminated", "replayed", "logout"],
    ) {
        gaps.push("push-state-coverage-missing".to_string());
    }

    let analytics_consent_bound = is_true(get(&analytics, "consentBound"));
    if !analytics_consent_bound {
        gaps.push("analytics-consent-missing".to_string());
    }
    let analytics_release_segmented = is_true(get(&analytics, "releaseSegmented"));
    let analytics_schema_validated = is_true(get(&analytics, "schemaValidated"));
    if !analytics_release_segmented || !analytics_schema_validated {
        gaps.push("analytics-operational-evidence-missing".to_string());
    }

    let operations_ready = is_true(get(&operations, "runbook"))
        && is_true(get(&operations, "alerting"))
        && is_true(get(&operations, "restoreEvidence"))
        && get(&operations, "owner").is_some_and(|v| !v.is_null());
    if !operations_ready {
        gaps.push("operations-readiness-missing".to_string());
    }

    let provider_required = is_true(get(&provider, "required"));
    let provider_sandbox_receipt = is_true(get(&provider, "sandboxReceipt"));
    if provider_required && !provider_sandbox_receipt {
        let provider_id = get(&provider, "id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        gaps.push(format!("provider-evidence-missing:{provider_id}"));
    }

    let hard_fail = gaps.iter().any(|gap| {
        gap.starts_with("entitlement-") || gap.starts_with("push-") || gap.starts_with("analytics-")
    });
    let status = if hard_fail {
        "fail"
    } else if !gaps.is_empty() {
        "partial"
    } else {
        "pass"
    };

    let mut sorted_gaps = gaps;
    sorted_gaps.sort();

    json!({
        "schemaVersion": 1,
        "kind": "legion-mobile-commerce-operations-evidence",
        "status": status,
        "terminal": true,
        "entitlement": {
            "serverVerified": entitlement_server_verified,
            "testedStates": entitlement_tested_states,
        },
        "push": {
            "accountBound": push_account_bound,
            "privacySafe": push_privacy_safe,
            "testedStates": push_tested_states,
        },
        "analytics": {
            "consentBound": analytics_consent_bound,
            "schemaValidated": analytics_schema_validated,
        },
        "operations": Value::Object(operations),
        "provider": Value::Object(provider),
        "coverageGaps": sorted_gaps,
    })
}

// ---------------------------------------------------------------------
// compatibility
// ---------------------------------------------------------------------

const ACCESSIBILITY_MODES: &[&str] = &[
    "voiceover",
    "talkback",
    "switch-control",
    "voice-control",
    "keyboard",
    "focus",
    "labels-announcements-errors",
    "dynamic-type",
    "contrast",
    "reduced-motion",
    "audio-media-alternatives",
    "accessibility-automation",
];
const PLATFORMS: &[&str] = &["ios", "android"];

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ExpectedCell {
    dimension: &'static str,
    value: String,
    journey_id: Option<String>,
    platform: &'static str,
}

impl ExpectedCell {
    fn key(&self) -> String {
        format!(
            "{}:{}:{}:{}",
            self.platform,
            self.dimension,
            self.value,
            self.journey_id.clone().unwrap_or_else(|| "*".to_string())
        )
    }

    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("dimension".into(), Value::String(self.dimension.into()));
        m.insert("value".into(), Value::String(self.value.clone()));
        if let Some(j) = &self.journey_id {
            m.insert("journeyId".into(), Value::String(j.clone()));
        }
        m.insert("platform".into(), Value::String(self.platform.into()));
        Value::Object(m)
    }
}

fn expected_cells_for_platform(
    platform: &'static str,
    critical_journeys: &[String],
    supported: &Map<String, Value>,
) -> Vec<ExpectedCell> {
    let mut out = Vec::new();
    for journey_id in critical_journeys {
        for mode in ACCESSIBILITY_MODES {
            out.push(ExpectedCell {
                dimension: "accessibility",
                value: (*mode).to_string(),
                journey_id: Some(journey_id.clone()),
                platform,
            });
        }
    }
    let platforms = get_str_vec(supported, "platforms");
    for p in platforms.iter().filter(|p| p.as_str() == platform) {
        out.push(ExpectedCell {
            dimension: "platform",
            value: p.clone(),
            journey_id: None,
            platform,
        });
    }
    for (key, dim) in [
        ("devices", "device"),
        ("displays", "display"),
        ("hardware", "hardware"),
        ("locales", "locale"),
        ("oemFamilies", "oem"),
    ] {
        for value in get_str_vec(supported, key) {
            out.push(ExpectedCell {
                dimension: dim,
                value,
                journey_id: None,
                platform,
            });
        }
    }
    out
}

/// Port of `compileMobileCompatibility`.
pub fn compile_mobile_compatibility(input: &Value) -> Value {
    let root = obj(input);
    let critical_journeys = get_str_vec(&root, "criticalJourneys");
    let executed = get_array(&root, "executed");
    let supported = get_obj(&root, "supported");

    let ios_expected = expected_cells_for_platform("ios", &critical_journeys, &supported);
    let android_expected = expected_cells_for_platform("android", &critical_journeys, &supported);

    // executedKeys: for each executed item, derive platform the same way the
    // JS does: item.platform ?? (item.dimension === 'platform' && PLATFORMS.includes(item.value) ? item.value : null)
    // then key by platform:dimension:value:journeyId, only when platform is truthy.
    let mut executed_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    for item in &executed {
        let item_obj = item.as_object().cloned().unwrap_or_default();
        let explicit_platform = item_obj.get("platform").and_then(Value::as_str);
        let dimension = item_obj.get("dimension").and_then(Value::as_str).unwrap_or("");
        let value = item_obj.get("value").and_then(Value::as_str).unwrap_or("");
        let derived_platform: Option<&str> = if let Some(p) = explicit_platform {
            Some(p)
        } else if dimension == "platform" && PLATFORMS.contains(&value) {
            Some(value)
        } else {
            None
        };
        if let Some(platform) = derived_platform {
            let journey_id = item_obj
                .get("journeyId")
                .and_then(Value::as_str)
                .map(|s| s.to_string())
                .unwrap_or_else(|| "*".to_string());
            executed_keys.insert(format!("{platform}:{dimension}:{value}:{journey_id}"));
        }
    }

    let all_expected: Vec<&ExpectedCell> = ios_expected.iter().chain(android_expected.iter()).collect();
    let omitted: Vec<Value> = all_expected
        .iter()
        .filter(|cell| !executed_keys.contains(&cell.key()))
        .map(|cell| {
            let mut m = cell.to_value().as_object().cloned().unwrap();
            m.insert("reason".into(), Value::String("device-evidence-unavailable".into()));
            Value::Object(m)
        })
        .collect();

    let omitted_count_for = |platform: &str| -> usize {
        omitted
            .iter()
            .filter(|item| item.get("platform").and_then(Value::as_str) == Some(platform))
            .count()
    };
    // JS: accounted = cells.length - omitted(count) + omitted(count) === cells.length always.
    let ios_accounted = ios_expected.len() - omitted_count_for("ios") + omitted_count_for("ios");
    let android_accounted = android_expected.len() - omitted_count_for("android") + omitted_count_for("android");

    let gaps: Vec<String> = critical_journeys
        .iter()
        .filter(|journey_id| {
            !executed.iter().any(|item| {
                let item_obj = item.as_object();
                item_obj.and_then(|m| m.get("dimension")).and_then(Value::as_str) == Some("accessibility")
                    && item_obj.and_then(|m| m.get("journeyId")).and_then(Value::as_str) == Some(journey_id.as_str())
                    && item_obj.and_then(|m| m.get("status")).and_then(Value::as_str) == Some("pass")
            })
        })
        .map(|journey_id| format!("accessibility-journey-missing:{journey_id}"))
        .collect();

    let expected_total = ios_expected.len() + android_expected.len();
    let status = if !omitted.is_empty() { "partial" } else { "pass" };

    json!({
        "schemaVersion": 1,
        "kind": "legion-mobile-compatibility-matrix",
        "status": status,
        "terminal": true,
        "executed": executed,
        "omitted": omitted,
        "denominator": {
            "total": expected_total,
            "accounted": ios_accounted + android_accounted,
            "ios": { "total": ios_expected.len(), "accounted": ios_accounted },
            "android": { "total": android_expected.len(), "accounted": android_accounted },
        },
        "coverageGaps": gaps,
    })
}

// ---------------------------------------------------------------------
// devices
// ---------------------------------------------------------------------

fn device_tier_valid(tier: &str) -> bool {
    matches!(
        tier,
        "simulator" | "emulator" | "physical" | "device-farm" | "imported"
    )
}

/// Port of `createMobileDeviceAdapter().capability`.
///
/// The JS original returns an object with a `capability` snapshot and an
/// async `execute` closure bound over `operations` (host-supplied functions
/// for acquire/install/execute/reset/uninstall/release). Rust has no direct
/// analogue for capturing arbitrary async host closures at this layer, so
/// this port splits the behavior into:
/// - `mobile_device_capability`: pure port of the `capability` object and
///   input validation (throws `TypeError` in JS -> returns `Err(String)`).
/// - `mobile_device_execute`: pure port of the `execute` state machine,
///   taking the *already-produced* operation outcomes as input (since the
///   operations themselves are host-side side effects out of this crate's
///   scope) rather than invoking callbacks itself.
pub fn mobile_device_capability(input: &Value) -> Result<Value, String> {
    let root = obj(input);
    let id = root.get("id").and_then(Value::as_str);
    let tier = root.get("tier").and_then(Value::as_str);
    let (id, tier) = match (id, tier) {
        (Some(id), Some(tier)) if !id.is_empty() && device_tier_valid(tier) => (id, tier),
        _ => return Err("mobile device id and supported tier are required".to_string()),
    };
    let platform = root.get("platform").cloned().unwrap_or(Value::Null);
    let exclusive_key = root.get("exclusiveKey").cloned().unwrap_or(Value::Null);
    let metadata = get_obj(&root, "metadata");
    let simulated = tier == "simulator" || tier == "emulator";

    let mut capability = Map::new();
    capability.insert("id".into(), Value::String(id.to_string()));
    capability.insert("tier".into(), Value::String(tier.to_string()));
    capability.insert("platform".into(), platform);
    capability.insert("exclusiveKey".into(), exclusive_key);
    capability.insert("simulated".into(), Value::Bool(simulated));
    for (k, v) in metadata {
        capability.insert(k, v);
    }
    Ok(Value::Object(capability))
}

/// Outcome of a single lifecycle operation callback, mirroring the JS
/// `cleanupStep` helper's three possible results plus the acquire/install/
/// execute phase's pass/fail/exception shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    Skipped,
    Pass,
    Error,
}

impl StepOutcome {
    fn as_str(self) -> &'static str {
        match self {
            StepOutcome::Skipped => "skipped",
            StepOutcome::Pass => "pass",
            StepOutcome::Error => "error",
        }
    }
}

/// Host-supplied outcomes for a device execution attempt, standing in for
/// the JS `operations` callbacks which this crate cannot invoke directly.
pub struct MobileDeviceExecutionOutcome {
    pub phase_error: Option<String>,
    pub evidence: Option<Value>,
    pub reset: StepOutcome,
    pub uninstall: StepOutcome,
    pub release: StepOutcome,
}

/// Port of the body of `execute({ target, scenarioId, physicalOnly })`,
/// given the outcomes of the host-side operation callbacks.
pub fn mobile_device_execute(
    input: &Value,
    outcome: Option<&MobileDeviceExecutionOutcome>,
) -> Value {
    let root = obj(input);
    let id = root.get("id").and_then(Value::as_str).unwrap_or_default();
    let tier = root.get("tier").and_then(Value::as_str).unwrap_or_default();
    let platform = root.get("platform").cloned().unwrap_or(Value::Null);
    let exclusive_key = root.get("exclusiveKey").cloned().unwrap_or(Value::Null);
    let target = get_obj(&root, "target");
    let scenario_id = root.get("scenarioId").cloned().unwrap_or(Value::Null);
    let physical_only = get_bool(&root, "physicalOnly");

    let binding = json!({
        "deviceId": id,
        "targetId": target.get("id").cloned().unwrap_or(Value::Null),
        "artifactDigest": target.get("artifactDigest").cloned().unwrap_or(Value::Null),
        "backendEnvironment": target.get("backendEnvironment").cloned().unwrap_or(Value::Null),
        "testAccountId": target.get("testAccountId").cloned().unwrap_or(Value::Null),
    });

    if physical_only && tier != "physical" {
        let scenario_label = if scenario_id.is_null() {
            "unknown".to_string()
        } else {
            value_to_js_string(&scenario_id)
        };
        return json!({
            "schemaVersion": 1,
            "kind": "legion-mobile-device-execution",
            "status": "blocked",
            "terminal": true,
            "tier": tier,
            "platform": platform,
            "binding": binding,
            "cleanup": {},
            "coverageGaps": [format!("physical-device-required:{scenario_label}")],
        });
    }

    let (status, evidence, error, cleanup) = match outcome {
        None => (
            "pass".to_string(),
            Value::Null,
            Value::Null,
            (StepOutcome::Skipped, StepOutcome::Skipped, StepOutcome::Skipped),
        ),
        Some(o) => {
            let mut status = "pass".to_string();
            let mut error = Value::Null;
            if let Some(cause) = &o.phase_error {
                status = "fail".to_string();
                error = Value::String(cause.clone());
            }
            let evidence = o.evidence.clone().unwrap_or(Value::Null);
            let cleanup = (o.reset, o.uninstall, o.release);
            if (cleanup.0 == StepOutcome::Error || cleanup.1 == StepOutcome::Error || cleanup.2 == StepOutcome::Error)
                && status == "pass"
            {
                status = "partial".to_string();
            }
            (status, evidence, error, cleanup)
        }
    };

    let cleanup_json = json!({
        "reset": cleanup.0.as_str(),
        "uninstall": cleanup.1.as_str(),
        "release": cleanup.2.as_str(),
    });

    let simulated = tier == "simulator" || tier == "emulator";
    let scenario_label = if scenario_id.is_null() {
        "unknown".to_string()
    } else {
        value_to_js_string(&scenario_id)
    };
    let coverage_gaps: Vec<String> = if status == "pass" {
        Vec::new()
    } else {
        vec![format!("device-execution-{status}:{scenario_label}")]
    };

    json!({
        "schemaVersion": 1,
        "kind": "legion-mobile-device-execution",
        "status": status,
        "terminal": true,
        "tier": tier,
        "platform": platform,
        "simulated": simulated,
        "exclusiveKey": exclusive_key,
        "binding": binding,
        "evidence": evidence,
        "error": error,
        "cleanup": cleanup_json,
        "coverageGaps": coverage_gaps,
    })
}

// ---------------------------------------------------------------------
// host
// ---------------------------------------------------------------------

/// Port of `planMobileHosts`.
pub fn plan_mobile_hosts(input: &Value) -> Value {
    let root = obj(input);
    let target = get_obj(&root, "target");
    let devices = get_array(&root, "devices");
    let requirements = get_array(&root, "requirements");
    let checked_at = root.get("checkedAt").cloned().unwrap_or(Value::Null);

    let normalized_devices: Vec<Map<String, Value>> = devices
        .iter()
        .filter_map(|item| {
            let m = item.as_object()?;
            let tier = m.get("tier").and_then(Value::as_str)?;
            if !device_tier_valid(tier) {
                return None;
            }
            let mut out = Map::new();
            out.insert("id".into(), m.get("id").cloned().unwrap_or(Value::Null));
            out.insert("tier".into(), Value::String(tier.to_string()));
            out.insert("platform".into(), m.get("platform").cloned().unwrap_or(Value::Null));
            out.insert("osVersion".into(), m.get("osVersion").cloned().unwrap_or(Value::Null));
            out.insert("model".into(), m.get("model").cloned().unwrap_or(Value::Null));
            out.insert("architecture".into(), m.get("architecture").cloned().unwrap_or(Value::Null));
            out.insert("formFactor".into(), m.get("formFactor").cloned().unwrap_or(Value::Null));
            out.insert("display".into(), m.get("display").cloned().unwrap_or(Value::Null));
            out.insert("cutout".into(), m.get("cutout").cloned().unwrap_or(Value::Null));
            out.insert("foldState".into(), m.get("foldState").cloned().unwrap_or(Value::Null));
            out.insert("locale".into(), m.get("locale").cloned().unwrap_or(Value::Null));
            out.insert(
                "accessibility".into(),
                m.get("accessibility").cloned().unwrap_or(json!({})),
            );
            out.insert("hardware".into(), m.get("hardware").cloned().unwrap_or(json!({})));
            out.insert("power".into(), m.get("power").cloned().unwrap_or(Value::Null));
            out.insert("thermal".into(), m.get("thermal").cloned().unwrap_or(Value::Null));
            out.insert("buildTrack".into(), m.get("buildTrack").cloned().unwrap_or(Value::Null));
            out.insert(
                "status".into(),
                m.get("status").cloned().unwrap_or(Value::String("unavailable".into())),
            );
            out.insert("exclusiveKey".into(), m.get("exclusiveKey").cloned().unwrap_or(Value::Null));
            out.insert("receipt".into(), m.get("receipt").cloned().unwrap_or(Value::Null));
            Some(out)
        })
        .collect();

    let planned: Vec<Value> = requirements
        .iter()
        .map(|requirement| {
            let r = requirement.as_object().cloned().unwrap_or_default();
            let requirement_tier = r.get("tier").and_then(Value::as_str).unwrap_or("");
            let evidence_tier = if device_tier_valid(requirement_tier) {
                requirement_tier.to_string()
            } else {
                "physical".to_string()
            };
            let device = normalized_devices.iter().find(|d| {
                d.get("tier").and_then(Value::as_str) == Some(evidence_tier.as_str())
                    && d.get("status").and_then(Value::as_str) == Some("available")
            });
            let device_id = device.and_then(|d| d.get("id").cloned()).unwrap_or(Value::Null);
            let status = if device.is_some() { "available" } else { "unavailable" };
            let gap = if device.is_some() {
                Value::Null
            } else {
                Value::String(format!("{evidence_tier}-device-unavailable"))
            };
            let id = r.get("id").cloned().unwrap_or(Value::Null);
            let control_ids = r.get("controlIds").cloned().unwrap_or_else(|| json!([]));
            let cleanup: Vec<&str> = if device.is_some() {
                vec!["uninstall", "reset-device-state", "release-exclusive-key"]
            } else {
                vec![]
            };
            json!({
                "id": id,
                "evidenceTier": evidence_tier,
                "controlIds": control_ids,
                "deviceId": device_id,
                "status": status,
                "gap": gap,
                "binding": {
                    "targetId": target.get("id").cloned().unwrap_or(Value::Null),
                    "artifactDigest": target.get("artifactDigest").cloned().unwrap_or(Value::Null),
                    "bundleId": target.get("bundleId").cloned().unwrap_or(Value::Null),
                    "packageId": target.get("packageId").cloned().unwrap_or(Value::Null),
                    "backendEnvironment": target.get("backendEnvironment").cloned().unwrap_or(Value::Null),
                    "testAccountId": target.get("testAccountId").cloned().unwrap_or(Value::Null),
                    "deviceId": device_id,
                    "deviceStateDigest": device.and_then(|d| d.get("deviceStateDigest").cloned()).unwrap_or(Value::Null),
                },
                "cleanup": cleanup,
            })
        })
        .collect();

    let gaps: Vec<&Value> = planned
        .iter()
        .filter(|item| item.get("status").and_then(Value::as_str) != Some("available"))
        .collect();

    let mut coverage_gaps: Vec<String> = gaps
        .iter()
        .map(|item| {
            let id = item.get("id").and_then(Value::as_str).unwrap_or_default();
            let gap = item.get("gap").and_then(Value::as_str).unwrap_or_default();
            format!("{id}:{gap}")
        })
        .collect();
    coverage_gaps.sort();

    let mut exclusive_keys: Vec<String> = normalized_devices
        .iter()
        .filter(|d| d.get("status").and_then(Value::as_str) == Some("available"))
        .filter_map(|d| d.get("exclusiveKey").and_then(Value::as_str).map(|s| s.to_string()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    exclusive_keys.sort();

    let planned_len = planned.len();
    let gaps_len = gaps.len();

    json!({
        "schemaVersion": 1,
        "kind": "legion-mobile-host-plan",
        "status": if gaps_len > 0 { "partial" } else { "pass" },
        "claimLevel": "runtime",
        "checkedAt": checked_at,
        "target": Value::Object(target),
        "devices": normalized_devices,
        "requirements": planned,
        "exclusiveDeviceKeys": exclusive_keys,
        "denominator": {
            "total": planned_len,
            "accounted": planned_len,
            "available": planned_len - gaps_len,
            "gaps": gaps_len,
        },
        "coverageGaps": coverage_gaps,
    })
}

// ---------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------

const LIFECYCLE_CASES: &[(&str, &str)] = &[
    ("fresh-install", "clean-install-state"),
    ("first-launch", "deterministic-onboarding"),
    ("authentication", "authorized-session"),
    ("primary-journey", "durable-completion"),
    ("save-resume", "durable-state-restored"),
    ("share-export", "bounded-user-visible-effect"),
    ("purchase-restore", "server-verified-entitlement"),
    ("logout-deletion", "actor-data-cleared"),
    ("reinstall-recovery", "account-state-reconstructed"),
    ("background-foreground", "operation-bounded"),
    ("lock-unlock", "sensitive-state-protected"),
    ("rotate", "state-preserved"),
    ("fold-unfold", "state-preserved"),
    ("split-screen-resize", "state-preserved"),
    ("system-interruption", "recover-or-cancel"),
    ("audio-route-change", "media-state-consistent"),
    ("process-death", "durable-state-restored"),
    ("force-stop", "durable-state-restored"),
    ("reboot", "durable-state-restored"),
    ("os-upgrade", "user-data-preserved"),
    ("app-upgrade", "user-data-preserved"),
    ("cold-deep-link", "authorization-rechecked"),
    ("cold-notification", "authorization-rechecked"),
    ("duplicate-event", "idempotent-effect"),
    ("background-job", "bounded-execution"),
    ("corrupt-partial-state", "safe-recovery"),
];

/// Port of `planMobileLifecycle`.
pub fn plan_mobile_lifecycle(input: &Value) -> Value {
    let root = obj(input);
    let target_id = root.get("targetId").cloned().unwrap_or(Value::Null);
    let journey_id = root.get("journeyId").cloned().unwrap_or(Value::Null);
    let device_capability = get_obj(&root, "deviceCapability");
    let binding = root.get("binding").cloned().unwrap_or(json!({}));

    let device_status = device_capability.get("status").and_then(Value::as_str);
    let available = device_status == Some("available");
    let scenario_status = if available { "unproven" } else { "blocked" };

    let scenarios: Vec<Value> = LIFECYCLE_CASES
        .iter()
        .map(|(id, expected_outcome)| {
            json!({
                "id": id,
                "targetId": target_id,
                "journeyId": journey_id,
                "expectedOutcome": expected_outcome,
                "status": scenario_status,
                "terminal": true,
                "binding": binding,
                "captures": ["crash", "hang", "visible-state", "backend-effects", "recovery"],
            })
        })
        .collect();

    let coverage_gaps: Vec<String> = if available {
        vec!["device-execution-not-run".to_string()]
    } else {
        vec![format!(
            "device-capability-{}",
            device_status.unwrap_or("missing")
        )]
    };

    json!({
        "schemaVersion": 1,
        "kind": "legion-mobile-lifecycle-plan",
        "targetId": target_id,
        "journeyId": journey_id,
        "status": scenario_status,
        "terminal": true,
        "scenarios": scenarios,
        "coverageGaps": coverage_gaps,
    })
}

// ---------------------------------------------------------------------
// network
// ---------------------------------------------------------------------

const NETWORK_CASES: &[&str] = &[
    "wifi-cellular-handoff",
    "airplane-mode",
    "vpn",
    "proxy",
    "captive-portal",
    "invalid-certificate",
    "hostname-mismatch",
    "slow-tls",
    "high-latency",
    "packet-loss",
    "low-bandwidth",
    "ipv6-only",
    "timeout",
    "provider-outage",
    "offline-online",
];
const STORAGE_CASES: &[&str] = &[
    "credentials",
    "database",
    "preferences",
    "files",
    "cache",
    "logs",
    "web-storage",
    "backup",
    "clipboard",
    "app-switcher-snapshot",
];

/// Port of `planMobileDataNetwork`.
pub fn plan_mobile_data_network(input: &Value) -> Value {
    let root = obj(input);
    let actor_id = root.get("actorId").cloned().unwrap_or(Value::Null);
    let supported_schema_versions: Vec<Value> = get_array(&root, "supportedSchemaVersions");

    let mut scenarios: Vec<Value> = Vec::new();
    for id in NETWORK_CASES {
        scenarios.push(json!({
            "id": format!("network:{id}"),
            "family": "network",
            "actorId": actor_id,
            "invariants": ["bounded-retry", "request-cancellation", "idempotent-effect", "auth-refresh-race-safe"],
            "status": "unproven",
        }));
    }
    scenarios.push(json!({
        "id": "sync:offline-replay",
        "family": "sync",
        "actorId": actor_id,
        "invariants": [
            "actor-scoped-queue", "ordered-replay", "expired-operation-dropped",
            "optimistic-rollback", "conflict-resolution", "logout-clears-queue", "unsynced-state-visible"
        ],
        "status": "unproven",
    }));
    for id in STORAGE_CASES {
        scenarios.push(json!({
            "id": format!("storage:{id}"),
            "family": "storage",
            "actorId": actor_id,
            "requiresPlatformEvidence": true,
            "invariants": ["account-isolation", "sensitive-data-protected"],
            "status": "unproven",
        }));
    }
    for version in &supported_schema_versions {
        let version_str = value_to_js_string(version);
        scenarios.push(json!({
            "id": format!("migration:{version_str}-to-current"),
            "family": "migration",
            "fromVersion": version,
            "invariants": ["preserve-user-data", "interrupt-safe", "corruption-bounded"],
            "status": "unproven",
        }));
    }
    scenarios.push(json!({
        "id": "pressure:low-disk-memory",
        "family": "pressure",
        "actorId": actor_id,
        "invariants": ["preserve-user-data", "orphan-cleanup", "bounded-streaming"],
        "status": "unproven",
    }));
    scenarios.push(json!({
        "id": "cache:unchanged-content",
        "family": "cache",
        "actorId": actor_id,
        "invariants": ["reuse-validated-content", "bounded-growth"],
        "status": "unproven",
    }));

    let coverage_gaps: Vec<String> = scenarios
        .iter()
        .map(|item| {
            let id = item.get("id").and_then(Value::as_str).unwrap_or_default();
            format!("{id}:device-execution-missing")
        })
        .collect();

    let total = scenarios.len();
    json!({
        "schemaVersion": 1,
        "kind": "legion-mobile-data-network-plan",
        "status": "unproven",
        "terminal": true,
        "actorId": actor_id,
        "scenarios": scenarios,
        "denominator": { "total": total, "accounted": total },
        "coverageGaps": coverage_gaps,
    })
}

// ---------------------------------------------------------------------
// performance
// ---------------------------------------------------------------------

const REQUIRED_METRICS: &[&str] = &[
    "cold-start", "warm-start", "resumed-start", "interactive-time", "responsiveness",
    "memory", "battery", "thermal", "network-per-session", "binary-size", "install-size",
];
const REQUIRED_PROFILES: &[&str] = &["main-thread", "idle-background", "long-session", "low-resource"];
const REQUIRED_ARTIFACT_INSPECTIONS: &[&str] = &[
    "architecture-slices", "resources-libraries", "symbols-media-locales", "delivery-update-size",
];

fn percentile(values: &[f64], rank: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    let mut sorted: Vec<f64> = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let idx = ((sorted.len() as f64) * rank).ceil() as isize - 1;
    let idx = idx.clamp(0, sorted.len() as isize - 1) as usize;
    Some(sorted[idx])
}

/// Port of `assessMobilePerformance`.
pub fn assess_mobile_performance(input: &Value) -> Value {
    let root = obj(input);
    let target_id = root.get("targetId").cloned().unwrap_or(Value::Null);
    let artifact_digest = root.get("artifactDigest").cloned().unwrap_or(Value::Null);
    let measurements = get_array(&root, "measurements");
    let budgets = get_obj(&root, "budgets");
    let profiles = get_str_vec(&root, "profiles");
    let artifact_inspection = get_obj(&root, "artifactInspection");

    struct Measurement {
        metric: String,
        value: f64,
        tier: Option<String>,
        build_type: Option<String>,
    }

    let valid: Vec<Measurement> = measurements
        .iter()
        .filter_map(|item| {
            let m = item.as_object()?;
            let value = m.get("value").and_then(Value::as_f64)?;
            if !value.is_finite() {
                return None;
            }
            let metric = m.get("metric").and_then(Value::as_str)?.to_string();
            Some(Measurement {
                metric,
                value,
                tier: m.get("tier").and_then(Value::as_str).map(|s| s.to_string()),
                build_type: m.get("buildType").and_then(Value::as_str).map(|s| s.to_string()),
            })
        })
        .collect();

    let physical: Vec<&Measurement> = valid.iter().filter(|m| m.tier.as_deref() == Some("physical")).collect();
    let release: Vec<&Measurement> = valid.iter().filter(|m| m.build_type.as_deref() == Some("release")).collect();

    let mut gaps: Vec<String> = Vec::new();
    if physical.is_empty() {
        gaps.push("physical-device-measurement-missing".to_string());
    }
    if release.is_empty() {
        gaps.push("release-build-measurement-missing".to_string());
    }
    if !physical.iter().any(|m| m.metric == "battery") {
        gaps.push("battery-measurement-missing".to_string());
    }
    if !physical.iter().any(|m| m.metric == "thermal") {
        gaps.push("thermal-measurement-missing".to_string());
    }
    if artifact_digest.is_null() {
        gaps.push("artifact-identity-missing".to_string());
    }
    for metric in REQUIRED_METRICS {
        if !valid.iter().any(|m| m.metric == *metric) {
            gaps.push(format!("metric-missing:{metric}"));
        }
    }
    for profile in REQUIRED_PROFILES {
        if !profiles.iter().any(|p| p == profile) {
            gaps.push(format!("profile-missing:{profile}"));
        }
    }
    for check in REQUIRED_ARTIFACT_INSPECTIONS {
        if artifact_inspection.get(*check) != Some(&Value::Bool(true)) {
            gaps.push(format!("artifact-inspection-missing:{check}"));
        }
    }

    let mut metric_names: Vec<String> = valid.iter().map(|m| m.metric.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    metric_names.sort();

    let mut metrics_map = Map::new();
    for metric in &metric_names {
        let values: Vec<f64> = valid.iter().filter(|m| &m.metric == metric).map(|m| m.value).collect();
        let budget = budgets.get(metric).cloned();
        let higher_is_better = budget
            .as_ref()
            .and_then(|b| b.get("direction"))
            .and_then(Value::as_str)
            == Some("higher-is-better");
        let worst = if higher_is_better {
            values.iter().cloned().fold(f64::INFINITY, f64::min)
        } else {
            values.iter().cloned().fold(f64::NEG_INFINITY, f64::max)
        };
        metrics_map.insert(
            metric.clone(),
            json!({
                "repeats": values.len(),
                "p50": percentile(&values, 0.5),
                "p95": percentile(&values, 0.95),
                "worst": worst,
                "budget": budget.unwrap_or(Value::Null),
            }),
        );
    }

    let mut sorted_gaps = gaps.clone();
    sorted_gaps.sort();

    json!({
        "schemaVersion": 1,
        "kind": "legion-mobile-performance-evidence",
        "targetId": target_id,
        "artifactDigest": artifact_digest.clone(),
        "status": if sorted_gaps.is_empty() { "pass" } else { "partial" },
        "terminal": true,
        "metrics": metrics_map,
        "claims": {
            "battery": if gaps.contains(&"battery-measurement-missing".to_string()) { "unproven" } else { "measured" },
            "thermal": if gaps.contains(&"thermal-measurement-missing".to_string()) { "unproven" } else { "measured" },
            "releaseArtifact": if !artifact_digest.is_null() && !release.is_empty() { "measured" } else { "unproven" },
        },
        "coverageGaps": sorted_gaps,
    })
}

// ---------------------------------------------------------------------
// platform-surfaces
// ---------------------------------------------------------------------

const PERMISSION_STATES: &[&str] = &[
    "not-requested", "granted", "denied", "permanently-denied", "later-granted",
    "settings-revoked", "restricted", "limited", "approximate",
];
const LINK_STATES: &[&str] = &[
    "logged-out", "expired", "background", "terminated", "duplicate", "malicious",
    "wrong-account", "hijack-risk",
];
const CHANNEL_STATES: &[&str] = &["foreground", "background", "terminated", "stale", "replayed"];
const WEBVIEW_CASES: &[&str] = &["origin", "navigation", "javascript", "bridge", "file-access", "cookies", "logout"];
const IPC_CASES: &[&str] = &[
    "android-exported-component", "android-intent", "android-provider",
    "ios-handler", "ios-shared-container", "cross-platform-channel",
];

/// Port of `planMobilePlatformSurfaces`.
pub fn plan_mobile_platform_surfaces(input: &Value) -> Value {
    let root = obj(input);
    let permissions = get_str_vec(&root, "permissions");
    let links = get_str_vec(&root, "links");
    let channels = get_str_vec(&root, "channels");
    let extensions = get_str_vec(&root, "extensions");

    let mut scenarios: Vec<Value> = Vec::new();

    for permission in &permissions {
        for state in PERMISSION_STATES {
            let expected = if *state == "denied" || *state == "permanently-denied" {
                "graceful-degradation"
            } else {
                "bounded-behavior"
            };
            scenarios.push(json!({
                "id": format!("permission:{permission}:{state}"),
                "family": "permission",
                "state": state,
                "expected": expected,
                "status": "unproven",
            }));
        }
    }
    for link in &links {
        for state in LINK_STATES {
            scenarios.push(json!({
                "id": format!("link:{link}:{state}"),
                "family": "link",
                "state": state,
                "requirements": ["route-validation", "server-authorization-recheck"],
                "status": "unproven",
            }));
        }
    }
    for channel in &channels {
        for state in CHANNEL_STATES {
            scenarios.push(json!({
                "id": format!("{channel}:{state}"),
                "family": channel,
                "state": state,
                "payloadAuthority": false,
                "requirements": ["schema-validation", "authorization-recheck"],
                "status": "unproven",
            }));
        }
    }
    for id in WEBVIEW_CASES {
        scenarios.push(json!({
            "id": format!("webview:{id}"),
            "family": "webview",
            "payloadAuthority": false,
            "requirements": ["trusted-origin", "least-privilege-bridge", "account-state-isolation"],
            "status": "unproven",
        }));
    }
    for id in IPC_CASES {
        scenarios.push(json!({
            "id": format!("ipc:{id}"),
            "family": "ipc",
            "payloadAuthority": false,
            "requirements": ["schema-validation", "authorization-recheck", "non-exported-by-default"],
            "status": "unproven",
        }));
    }
    for extension in &extensions {
        scenarios.push(json!({
            "id": format!("extension:{extension}"),
            "family": "extension",
            "sharedContainerAuthority": false,
            "status": "unproven",
        }));
    }

    let coverage_gaps: Vec<String> = scenarios
        .iter()
        .map(|item| {
            let id = item.get("id").and_then(Value::as_str).unwrap_or_default();
            format!("{id}:device-execution-missing")
        })
        .collect();

    let total = scenarios.len();
    json!({
        "schemaVersion": 1,
        "kind": "legion-mobile-platform-surface-plan",
        "status": "unproven",
        "terminal": true,
        "scenarios": scenarios,
        "denominator": { "total": total, "accounted": total },
        "coverageGaps": coverage_gaps,
    })
}

// ---------------------------------------------------------------------
// release
// ---------------------------------------------------------------------

/// Port of `verifyMobileRelease`.
pub fn verify_mobile_release(input: &Value) -> Value {
    let root = obj(input);
    let target_id = root.get("targetId").cloned().unwrap_or(Value::Null);
    let version = root.get("version").cloned().unwrap_or(Value::Null);
    let artifact = get_obj(&root, "artifact");
    let runtime_data_types = get_str_vec(&root, "runtimeDataTypes");
    let declared_data_types = get_str_vec(&root, "declaredDataTypes");
    let symbols = get_array(&root, "symbols");
    let build = get_obj(&root, "build");
    let store = get_obj(&root, "store");
    let promotion = get_obj(&root, "promotion");
    let privacy = get_obj(&root, "privacy");

    let mut gaps: Vec<String> = Vec::new();

    for data_type in &runtime_data_types {
        if !declared_data_types.iter().any(|d| d == data_type) {
            gaps.push(format!("privacy-declaration-mismatch:{data_type}"));
        }
    }
    let artifact_path = artifact.get("path");
    let artifact_digest = artifact.get("digest");
    if artifact_path.is_none_or_null() || artifact_digest.is_none_or_null() {
        gaps.push("exact-artifact-missing".to_string());
    }
    if symbols.is_empty() {
        gaps.push("symbols-missing".to_string());
    }
    let all_symbolicated = !symbols.is_empty()
        && symbols.iter().all(|item| {
            item.as_object()
                .and_then(|m| m.get("symbolicated"))
                .and_then(Value::as_bool)
                == Some(true)
        });
    if !all_symbolicated {
        gaps.push("symbolication-unproven".to_string());
    }
    if !is_true(privacy.get("manifest")) {
        gaps.push("privacy-manifest-unproven".to_string());
    }
    if !is_true(privacy.get("requiredReasonApis")) {
        gaps.push("required-reason-apis-unproven".to_string());
    }
    if !is_true(build.get("release")) {
        gaps.push("release-build-flags-unproven".to_string());
    }
    if build.get("toolchain").is_none_or_null() || build.get("lockfileDigest").is_none_or_null() {
        gaps.push("build-reproducibility-unproven".to_string());
    }
    if build.get("packageId").is_none_or_null() || build.get("signingIdentity").is_none_or_null() {
        gaps.push("signing-identity-unproven".to_string());
    }
    if store.get("track").is_none_or_null() {
        gaps.push("store-track-unproven".to_string());
    }
    if store.get("listing").is_none_or_null()
        || store.get("privacyUrl").is_none_or_null()
        || store.get("supportUrl").is_none_or_null()
    {
        gaps.push("store-metadata-unproven".to_string());
    }
    if store.get("declarations").is_none_or_null() || store.get("regionalVariants").is_none_or_null() {
        gaps.push("store-declarations-unproven".to_string());
    }
    if promotion.get("rolloutCriteria").is_none_or_null()
        || promotion.get("rollbackCriteria").is_none_or_null()
        || promotion.get("monitoring").is_none_or_null()
    {
        gaps.push("rollout-readiness-unproven".to_string());
    }
    let tested_digest = promotion.get("testedDigest");
    let promoted_digest = promotion.get("promotedDigest");
    if let (Some(t), Some(p)) = (tested_digest, promoted_digest) {
        if !t.is_null() && !p.is_null() && t != p {
            gaps.push("promotion-artifact-mismatch".to_string());
        }
    }

    let blocking = gaps
        .iter()
        .any(|gap| gap.starts_with("privacy-declaration-mismatch:") || gap == "promotion-artifact-mismatch");

    let mut sorted_gaps = gaps.clone();
    sorted_gaps.sort();

    let status = if blocking {
        "fail"
    } else if !gaps.is_empty() {
        "partial"
    } else {
        "pass"
    };

    json!({
        "schemaVersion": 1,
        "kind": "legion-mobile-release-evidence",
        "status": status,
        "terminal": true,
        "releaseBlocked": blocking,
        "identity": {
            "targetId": target_id,
            "version": version,
            "artifactDigest": artifact_digest.cloned().unwrap_or(Value::Null),
        },
        "artifact": Value::Object(artifact),
        "build": Value::Object(build),
        "store": Value::Object(store),
        "symbols": symbols,
        "promotion": Value::Object(promotion),
        "coverageGaps": sorted_gaps,
    })
}

/// Small helper trait to mirror JS's `!x` truthiness for "missing" checks
/// (`undefined`/`null` both count as missing).
trait IsNoneOrNull {
    fn is_none_or_null(&self) -> bool;
}
impl IsNoneOrNull for Option<&Value> {
    fn is_none_or_null(&self) -> bool {
        match self {
            None => true,
            Some(v) => v.is_null(),
        }
    }
}
