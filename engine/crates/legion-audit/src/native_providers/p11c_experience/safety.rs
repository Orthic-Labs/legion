//! Port of `src/providers/safety/{contracts,hazard-model,scanner,
//! schema-builder}.mjs` plus the `REASONING_REQUIREMENT` constant re-exported
//! from `src/lib/contracts/enums.mjs`. `generate-schema.mjs` is a CLI/file
//! writer wrapper around `schema-builder.mjs` and is not ported as a
//! standalone item (`build_hazard_model_schema` below is the port target).

use super::visual_core::sha256_digest;
use regex::Regex;
use serde_json::{Map, Value};
use std::collections::BTreeSet;

pub const REASONING_REQUIREMENT: [&str; 4] = ["none", "bounded-review", "independent-adjudication", "human-decision"];
pub const OUTCOME_CLASS: [&str; 7] = ["physical", "medical", "financial", "child-facing", "operational", "irreversible", "catastrophic-data-loss"];
pub const HAZARD_DISPOSITION: [&str; 7] = ["positive", "mitigated", "blocked", "unsafe-degraded", "missing-interlock", "human-override", "clean"];
pub const INTERLOCK_STATE: [&str; 3] = ["present", "missing", "not-applicable"];
pub const FAILSAFE_DEFAULT: [&str; 3] = ["safe", "unsafe", "unknown"];
pub const DEGRADED_MODE: [&str; 4] = ["safe", "unsafe", "unknown", "not-applicable"];
pub const EMERGENCY_STOP: [&str; 3] = ["present", "absent", "not-applicable"];
pub const HUMAN_OVERRIDE: [&str; 5] = ["present", "absent", "required-and-present", "required-and-absent", "not-applicable"];
pub const CONFIRMATION_STATE: [&str; 3] = ["present", "absent", "not-applicable"];
pub const RECOVERY_PATH: [&str; 3] = ["defined", "absent", "not-applicable"];
pub const INCIDENT_CONTROLS: [&str; 3] = ["defined", "absent", "not-applicable"];
pub const HAZARD_STATUS: [&str; 2] = ["review-required", "unproven"];
pub const CLOSURE_METHOD: [&str; 3] = ["human-decision", "model-verdict", "automated-verdict"];
pub const SEVERITY_HINTS: [&str; 5] = ["critical", "high", "medium", "low", "info"];

fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonicalize).collect()),
        Value::Object(map) => {
            let mut sorted = Map::new();
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), canonicalize(&map[key]));
            }
            Value::Object(sorted)
        }
        other => other.clone(),
    }
}

pub fn stable_id(namespace: &str, value: &Value) -> String {
    let body = serde_json::to_string(&canonicalize(value)).unwrap_or_default();
    let mut bytes = Vec::with_capacity(namespace.len() + 1 + body.len());
    bytes.extend_from_slice(namespace.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(body.as_bytes());
    sha256_digest(&bytes)
}

pub fn digest(value: &Value) -> String {
    stable_id("digest", value)
}

fn unique_sorted(values: &[String]) -> Vec<String> {
    let set: BTreeSet<String> = values.iter().cloned().collect();
    set.into_iter().collect()
}

// ---------------------------------------------------------------------
// hazard-model.mjs :: createHazardCandidate / assertHazard / closeHazard
// ---------------------------------------------------------------------

/// Builds one hazard candidate. Mirrors `createHazardCandidate`'s required-
/// field validation (`Err` in place of the JS `TypeError` throw) and its
/// non-negotiable `reasoningRequirement: 'human-decision'` /
/// `certifiable: false` invariants.
pub fn create_hazard_candidate(input: &Value) -> Result<Value, String> {
    let domain = input.get("domain").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("domain must be a non-empty string")?;
    let outcome_class = input.get("outcomeClass").and_then(Value::as_str).ok_or("outcomeClass required")?;
    if !OUTCOME_CLASS.contains(&outcome_class) {
        return Err(format!("unknown outcome class: {outcome_class}"));
    }
    let rule_id = input.get("ruleId").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("ruleId must be a non-empty string")?;
    let claim = input.get("claim").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("claim must be a non-empty string")?;
    let severity_hint = input.get("severityHint").and_then(Value::as_str).ok_or("severityHint required")?;
    if !SEVERITY_HINTS.contains(&severity_hint) {
        return Err(format!("invalid severity hint {severity_hint}"));
    }
    let scope = input.get("scope").and_then(Value::as_object).ok_or("scope must be an object")?;
    let scope_description = scope.get("description").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("scope.description must be a non-empty string")?;
    let scope_static = scope.get("static").and_then(Value::as_bool).ok_or("scope.static and scope.runtime must be booleans")?;
    let scope_runtime = scope.get("runtime").and_then(Value::as_bool).ok_or("scope.static and scope.runtime must be booleans")?;

    fn non_empty_strings(input: &Value, key: &str) -> Result<Vec<String>, String> {
        let items = input.get(key).and_then(Value::as_array).filter(|a| !a.is_empty()).ok_or_else(|| format!("{key} must be a non-empty array"))?;
        Ok(items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
    }
    let hazards = non_empty_strings(input, "hazards")?;
    let assumptions = non_empty_strings(input, "assumptions")?;
    let authority_limits = non_empty_strings(input, "authorityLimits")?;
    let misuse_scenarios = non_empty_strings(input, "misuseScenarios")?;

    let disposition = input.get("disposition").and_then(Value::as_str).ok_or("disposition required")?;
    if !HAZARD_DISPOSITION.contains(&disposition) {
        return Err(format!("invalid hazard disposition {disposition}"));
    }
    let interlock = input.get("interlock").and_then(Value::as_str).unwrap_or("not-applicable");
    if !INTERLOCK_STATE.contains(&interlock) { return Err(format!("invalid interlock state {interlock}")); }
    let failsafe_default = input.get("failsafeDefault").and_then(Value::as_str).unwrap_or("unknown");
    if !FAILSAFE_DEFAULT.contains(&failsafe_default) { return Err(format!("invalid failsafe default {failsafe_default}")); }
    let degraded_mode = input.get("degradedMode").and_then(Value::as_str).unwrap_or("not-applicable");
    if !DEGRADED_MODE.contains(&degraded_mode) { return Err(format!("invalid degraded mode {degraded_mode}")); }
    let emergency_stop = input.get("emergencyStop").and_then(Value::as_str).unwrap_or("not-applicable");
    if !EMERGENCY_STOP.contains(&emergency_stop) { return Err(format!("invalid emergency stop {emergency_stop}")); }
    let human_override = input.get("humanOverride").and_then(Value::as_str).unwrap_or("not-applicable");
    if !HUMAN_OVERRIDE.contains(&human_override) { return Err(format!("invalid human override {human_override}")); }
    let confirmation = input.get("confirmation").and_then(Value::as_str).unwrap_or("not-applicable");
    if !CONFIRMATION_STATE.contains(&confirmation) { return Err(format!("invalid confirmation state {confirmation}")); }
    let recovery_path = input.get("recoveryPath").and_then(Value::as_str).unwrap_or("not-applicable");
    if !RECOVERY_PATH.contains(&recovery_path) { return Err(format!("invalid recovery path {recovery_path}")); }
    let incident_controls = input.get("incidentControls").and_then(Value::as_str).unwrap_or("not-applicable");
    if !INCIDENT_CONTROLS.contains(&incident_controls) { return Err(format!("invalid incident controls {incident_controls}")); }

    let evidence_refs_raw: Vec<String> = input.get("evidenceRefs").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default();
    let refs = unique_sorted(&evidence_refs_raw);
    if refs.is_empty() {
        return Err("evidenceRefs must be a non-empty array".to_string());
    }

    let unsafe_states = unique_sorted(&input.get("unsafeStates").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default());
    let misuse_sorted = unique_sorted(&misuse_scenarios);
    let uncertainty = unique_sorted(&input.get("uncertainty").and_then(Value::as_array).map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect()).unwrap_or_default());
    let detector_metadata = input.get("detectorMetadata").cloned().unwrap_or(Value::Object(Map::new()));

    // Every outcome class here is high-consequence: the reasoning
    // requirement is asserted, not merely defaulted.
    let reasoning_requirement = "human-decision";
    // status is always 'review-required' in the JS source (both arms of its
    // ternary produce the same value); preserved verbatim.
    let status = "review-required";

    let identity = serde_json::json!({
        "domain": domain, "outcomeClass": outcome_class, "ruleId": rule_id,
        "disposition": disposition, "evidenceRefs": refs, "detectorMetadata": detector_metadata,
    });

    Ok(serde_json::json!({
        "schemaVersion": 1, "kind": "safety-hazard", "id": stable_id("safety-hazard", &identity),
        "domain": domain, "outcomeClass": outcome_class, "ruleId": rule_id, "claim": claim,
        "severityHint": severity_hint,
        "scope": { "static": scope_static, "runtime": scope_runtime, "description": scope_description },
        "hazards": hazards, "assumptions": assumptions, "authorityLimits": authority_limits,
        "disposition": disposition, "unsafeStates": unsafe_states, "interlock": interlock,
        "failsafeDefault": failsafe_default, "degradedMode": degraded_mode, "emergencyStop": emergency_stop,
        "humanOverride": human_override, "confirmation": confirmation, "misuseScenarios": misuse_sorted,
        "recoveryPath": recovery_path, "incidentControls": incident_controls,
        "reasoningRequirement": reasoning_requirement, "certifiable": false, "regulatoryClaim": Value::Null,
        "status": status, "evidenceRefs": refs, "detectorMetadata": detector_metadata,
        "uncertainty": uncertainty, "closed": false,
    }))
}

pub fn assert_hazard(hazard: &Value) -> Result<(), String> {
    let object = hazard.as_object().ok_or("hazard must be an object")?;
    if object.get("schemaVersion") != Some(&Value::from(1)) {
        return Err(format!("hazard schemaVersion must be 1; got {:?}", object.get("schemaVersion")));
    }
    if object.get("kind") != Some(&Value::String("safety-hazard".into())) {
        return Err(format!("hazard kind must be safety-hazard; got {:?}", object.get("kind")));
    }
    let outcome_class = object.get("outcomeClass").and_then(Value::as_str).unwrap_or_default();
    if !OUTCOME_CLASS.contains(&outcome_class) {
        return Err(format!("unknown outcome class: {outcome_class}"));
    }
    let reasoning_requirement = object.get("reasoningRequirement").and_then(Value::as_str).unwrap_or_default();
    if !REASONING_REQUIREMENT.contains(&reasoning_requirement) {
        return Err(format!("unknown reasoning requirement: {reasoning_requirement}"));
    }
    if reasoning_requirement != "human-decision" {
        return Err("every hazard in this model must require human-decision reasoning".to_string());
    }
    if object.get("certifiable") != Some(&Value::Bool(false)) {
        return Err("a hazard must never be marked certifiable".to_string());
    }
    if object.get("regulatoryClaim") != Some(&Value::Null) {
        return Err("a hazard must never assert a regulatory claim".to_string());
    }
    for key in ["hazards", "assumptions", "authorityLimits", "misuseScenarios", "evidenceRefs"] {
        if !object.get(key).and_then(Value::as_array).is_some_and(|a| !a.is_empty()) {
            return Err(format!("hazard.{key} must be a non-empty array"));
        }
    }
    let scope = object.get("scope").and_then(Value::as_object).ok_or("hazard.scope must be an object")?;
    if !scope.get("description").and_then(Value::as_str).is_some_and(|s| !s.is_empty()) {
        return Err("hazard.scope.description must be a non-empty string".to_string());
    }
    Ok(())
}

pub fn close_hazard(hazard: &Value, method: &str, decided_by: &str, decision: &str, rationale: &str) -> Result<Value, String> {
    assert_hazard(hazard)?;
    if !CLOSURE_METHOD.contains(&method) {
        return Err(format!("unknown closure method: {method}"));
    }
    let reasoning_requirement = hazard.get("reasoningRequirement").and_then(Value::as_str).unwrap_or_default();
    if reasoning_requirement == "human-decision" && method != "human-decision" {
        let hazard_id = hazard.get("id").and_then(Value::as_str).unwrap_or_default();
        return Err(format!(
            "hazard {hazard_id} requires reasoningRequirement 'human-decision'; closure method '{method}' is rejected — only a human-decision closure is accepted"
        ));
    }
    if decided_by.is_empty() { return Err("decidedBy must be a non-empty string".to_string()); }
    if decision.is_empty() { return Err("decision must be a non-empty string".to_string()); }
    if rationale.is_empty() { return Err("rationale must be a non-empty string".to_string()); }
    let hazard_id = hazard.get("id").cloned().unwrap_or(Value::Null);
    let closure_digest = digest(&serde_json::json!({ "hazardId": hazard_id, "method": method, "decidedBy": decided_by, "decision": decision }));
    Ok(serde_json::json!({
        "schemaVersion": 1, "kind": "safety-hazard-closure", "hazardId": hazard_id, "method": method,
        "decidedBy": decided_by, "decision": decision, "rationale": rationale, "closureDigest": closure_digest,
    }))
}

// ---------------------------------------------------------------------
// scanner.mjs :: scanSafetyHazards
// ---------------------------------------------------------------------

struct SafetyDomain {
    id: &'static str,
    outcome_class: &'static str,
    rule_id: &'static str,
    trigger: &'static str,
    claim: &'static str,
    hazards: &'static [&'static str],
    assumptions: &'static [&'static str],
    misuse_scenarios: &'static [&'static str],
    unsafe_state: &'static str,
    track_emergency_stop: bool,
    track_recovery: bool,
    track_incident_controls: bool,
}

const STANDARD_SCOPE_DESCRIPTION: &str = "Repository source/config text only; no device, chain, operational network, or live system connection was made.";

fn domains() -> Vec<SafetyDomain> {
    vec![
        SafetyDomain {
            id: "physical.direct-actuator-command", outcome_class: "physical", rule_id: "safety.physical.direct-actuator-command",
            trigger: r"\b(?:actuator|motor|valve|relay|servo)\.(?:start|open|close|enable|drive)\s*\(",
            claim: "A direct physical actuator/motor/valve/relay command is issued in this code path.",
            hazards: &["Uncontrolled actuation can cause crushing, entrapment, thermal, or other bodily-injury hazards to a nearby operator or bystander."],
            assumptions: &["Whether this call path is reachable from an untrusted, remote, or automated input (rather than a supervised local operator) is not established by this lens; only the local command site is observed."],
            misuse_scenarios: &["An attacker or malfunctioning upstream system could invoke this command repeatedly or out of sequence to cause mechanical damage or an unsafe physical state."],
            unsafe_state: "uncontrolled-physical-actuation", track_emergency_stop: true, track_recovery: false, track_incident_controls: false,
        },
        SafetyDomain {
            id: "medical.dose-administration", outcome_class: "medical", rule_id: "safety.medical.dose-administration",
            trigger: r"\b(?:administerDose|infusionPump\.(?:start|set)|insulinPump\.deliver)\s*\(",
            claim: "A medical-device dosing/administration action is issued in this code path.",
            hazards: &["An unmitigated or unchecked dosing command can cause patient over-dose, under-dose, or a missed-therapy adverse event."],
            assumptions: &["Dose-range validation performed by device firmware or a separate clinical-decision-support layer outside this repository is not observed by this lens."],
            misuse_scenarios: &["A compromised or misconfigured caller could issue a dosing command outside clinically safe bounds, or repeat a dose that should be one-time only."],
            unsafe_state: "unchecked-dose-administration", track_emergency_stop: false, track_recovery: false, track_incident_controls: false,
        },
        SafetyDomain {
            id: "financial.irreversible-transfer", outcome_class: "financial", rule_id: "safety.financial.irreversible-transfer",
            trigger: r"\b(?:transferFunds|executePayment|initiateWithdrawal|sendPayment)\s*\(",
            claim: "An irreversible funds-transfer or payment action is issued in this code path.",
            hazards: &["An unmitigated funds transfer executed in error, under attacker control, or against a compromised account can cause an irrecoverable financial loss to the account holder."],
            assumptions: &["Bank/network-side reversal or fraud-hold mechanisms outside this repository are not observed by this lens; the transfer is treated as irreversible from the application's own perspective."],
            misuse_scenarios: &["An attacker with API access or a compromised session could trigger unauthorized transfers, or replay a transfer request to move funds multiple times."],
            unsafe_state: "unmitigated-funds-transfer", track_emergency_stop: false, track_recovery: false, track_incident_controls: true,
        },
        SafetyDomain {
            id: "child-facing.minor-data-collection", outcome_class: "child-facing", rule_id: "safety.child-facing.minor-data-collection",
            trigger: r"\b(?:collectChildData|saveChildProfile|storeMinorData)\s*\(",
            claim: "Personal data belonging to a child/minor user is collected or stored in this code path.",
            hazards: &["Collecting or storing a minor's personal data without a verified parental-consent gate creates a child-safety and privacy exposure, and a durable record that cannot be un-collected after the fact."],
            assumptions: &["A parental-consent verification flow implemented in a separate service or vendor integration outside this repository is not observed by this lens."],
            misuse_scenarios: &["An attacker or a minor misrepresenting their age could cause child data to be collected and retained without a guardian ever consenting."],
            unsafe_state: "unconsented-minor-data-collection", track_emergency_stop: false, track_recovery: false, track_incident_controls: false,
        },
        SafetyDomain {
            id: "operational.production-disruption-command", outcome_class: "operational", rule_id: "safety.operational.production-disruption-command",
            trigger: r"\b(?:scaleDownCluster|shutdownProductionService|drainNode|terminateInstance)\s*\(",
            claim: "A production-infrastructure operational command (shutdown/scale-down/drain/terminate) is issued in this code path.",
            hazards: &["An unmitigated operational command executed against production can cause a service outage affecting every dependent user or downstream system."],
            assumptions: &["A staging/dry-run gate or change-management approval enforced by a separate deployment platform outside this repository is not observed by this lens."],
            misuse_scenarios: &["An attacker with deploy/ops access, or a misfiring automation, could trigger this command against the wrong target or at the wrong time, causing an avoidable outage."],
            unsafe_state: "unmitigated-production-disruption", track_emergency_stop: true, track_recovery: false, track_incident_controls: true,
        },
        SafetyDomain {
            id: "irreversible.destructive-account-action", outcome_class: "irreversible", rule_id: "safety.irreversible.destructive-account-action",
            trigger: r"\b(?:factoryReset|permanentBan|purgeAccount|hardDelete)\s*\(",
            claim: "An irreversible state-destroying action (factory reset, permanent ban, account purge, hard delete) is issued in this code path.",
            hazards: &["An irreversible action executed in error, under attacker control, or without confirmed operator intent cannot be undone by any recovery mechanism this lens observed."],
            assumptions: &["A soft-delete/undo window or administrative reversal process implemented elsewhere is not observed by this lens; the action is treated as irreversible from this call site."],
            misuse_scenarios: &["An attacker who gains the calling privilege, or a scripting error that iterates over the wrong record set, could trigger irreversible destruction at scale."],
            unsafe_state: "unmitigated-irreversible-action", track_emergency_stop: false, track_recovery: true, track_incident_controls: false,
        },
        SafetyDomain {
            id: "catastrophic-data-loss.bulk-destructive-operation", outcome_class: "catastrophic-data-loss", rule_id: "safety.catastrophic-data-loss.bulk-destructive-operation",
            trigger: r"\b(?:truncateTable|dropDatabase|deleteAllRecords|wipeVolume)\s*\(",
            claim: "A bulk/catastrophic data-destroying operation (truncate, drop, delete-all, wipe) is issued in this code path.",
            hazards: &["A catastrophic bulk-delete executed without a verified backup/recovery path can cause permanent, unrecoverable loss of the entire dataset."],
            assumptions: &["A point-in-time-recovery or replicated-backup system operated outside this repository is not observed by this lens; recovery is only credited when a local verification call is present."],
            misuse_scenarios: &["An attacker with database credentials, or an operator running the wrong script against production, could trigger irreversible data loss for every tenant sharing the target."],
            unsafe_state: "unverified-bulk-data-destruction", track_emergency_stop: false, track_recovery: true, track_incident_controls: true,
        },
    ]
}

struct Classification {
    disposition: &'static str,
    severity_hint: &'static str,
    interlock: &'static str,
    failsafe_default: &'static str,
    degraded_mode: &'static str,
    confirmation: &'static str,
    human_override: &'static str,
    note: &'static str,
}

fn classify(window: &str) -> Classification {
    let blocked = Regex::new(r"hazardActionBlocked\s*\(|preconditionFailed\s*\(\s*\)|refuseAction\s*\(").unwrap();
    let unsafe_degraded = Regex::new(r#"degradedModeUnsafe\s*\(|failOpen\s*\(|degradedMode\s*[:=]\s*["']unsafe["']"#).unwrap();
    let missing_interlock = Regex::new(r"interlockBypassed\s*\(|skipInterlock\s*\(|disableInterlock\s*\(").unwrap();
    let human_override_re = Regex::new(r"humanOverrideGranted\s*\(|operatorOverrideToken|requireHumanApproval\s*\(\s*\)\s*\.\s*granted").unwrap();
    let mitigated = Regex::new(r"interlockEnforced\s*\(|confirmationRequired\s*\(\s*\)\s*===\s*true|limitCheckPassed\s*\(").unwrap();

    if blocked.is_match(window) {
        Classification { disposition: "blocked", severity_hint: "low", interlock: "present", failsafe_default: "safe", degraded_mode: "not-applicable", confirmation: "present", human_override: "not-applicable",
            note: "A precondition/refusal guard is present in the surrounding window; the hazard action appears to be blocked before execution." }
    } else if unsafe_degraded.is_match(window) {
        Classification { disposition: "unsafe-degraded", severity_hint: "critical", interlock: "missing", failsafe_default: "unsafe", degraded_mode: "unsafe", confirmation: "absent", human_override: "not-applicable",
            note: "A degraded-mode/fail-open signal is present in the surrounding window; the observed fallback behavior is itself unsafe." }
    } else if missing_interlock.is_match(window) {
        Classification { disposition: "missing-interlock", severity_hint: "critical", interlock: "missing", failsafe_default: "unsafe", degraded_mode: "not-applicable", confirmation: "absent", human_override: "not-applicable",
            note: "An explicit interlock-bypass/skip signal is present in the surrounding window; an interlock exists elsewhere but is disabled on this path." }
    } else if human_override_re.is_match(window) {
        Classification { disposition: "human-override", severity_hint: "medium", interlock: "present", failsafe_default: "safe", degraded_mode: "not-applicable", confirmation: "present", human_override: "required-and-present",
            note: "A human-override-granted signal is present in the surrounding window; the action proceeds only after an observed human override." }
    } else if mitigated.is_match(window) {
        Classification { disposition: "mitigated", severity_hint: "medium", interlock: "present", failsafe_default: "safe", degraded_mode: "not-applicable", confirmation: "present", human_override: "not-applicable",
            note: "An interlock/confirmation/limit-check signal is present in the surrounding window; treated as a mitigating control pending adjudication." }
    } else {
        Classification { disposition: "positive", severity_hint: "high", interlock: "missing", failsafe_default: "unknown", degraded_mode: "not-applicable", confirmation: "absent", human_override: "not-applicable",
            note: "No interlock, confirmation, override, blocking, or degraded-mode signal was found in the surrounding window." }
    }
}

fn window_around(text: &str, index: usize, length: usize, radius: usize) -> String {
    let bytes = text.as_bytes();
    let start = index.saturating_sub(radius);
    let end = (index + length + radius).min(bytes.len());
    String::from_utf8_lossy(&bytes[start..end]).into_owned()
}

fn line_of(text: &str, index: usize) -> usize {
    text.get(..index).unwrap_or_default().matches('\n').count() + 1
}

/// `files`: list of `(path, contents)`. `denominator_digest`: caller-supplied
/// evidence-scoping digest, mirrored verbatim into each hazard's evidence
/// ref (matches `scanSafetyHazards({ files, readFile, denominatorDigest })`).
pub fn scan_safety_hazards(files: &[(String, String)], denominator_digest: &Value) -> Result<Vec<Value>, String> {
    let mut hazards = Vec::new();
    for domain in domains() {
        let trigger = Regex::new(domain.trigger).unwrap();
        let emergency_stop_re = Regex::new(r"emergencyStopEngaged\s*\(|eStopTriggered\s*\(").unwrap();
        let recovery_re = Regex::new(r"backupVerified\s*\(|recoveryPointConfirmed\s*\(|hasRecentBackup\s*\(\s*\)\s*===\s*true").unwrap();
        let incident_re = Regex::new(r"incidentResponsePlan\s*\(|pagerDutyAlert\s*\(|onCallNotified\s*\(").unwrap();
        for (file, text) in files {
            if text.is_empty() {
                continue;
            }
            for capture in trigger.find_iter(text) {
                if capture.as_str().is_empty() {
                    continue;
                }
                let window = window_around(text, capture.start(), capture.len(), 500);
                let classification = classify(&window);
                let evidence_ref = digest(&serde_json::json!({ "domain": domain.id, "file": file, "index": capture.start(), "denominatorDigest": denominator_digest }));

                let mut input = Map::new();
                input.insert("domain".into(), Value::String(domain.id.to_string()));
                input.insert("outcomeClass".into(), Value::String(domain.outcome_class.to_string()));
                input.insert("ruleId".into(), Value::String(domain.rule_id.to_string()));
                input.insert("claim".into(), Value::String(domain.claim.to_string()));
                input.insert("severityHint".into(), Value::String(classification.severity_hint.to_string()));
                input.insert("scope".into(), serde_json::json!({ "static": true, "runtime": false, "description": STANDARD_SCOPE_DESCRIPTION }));
                input.insert("hazards".into(), Value::Array(domain.hazards.iter().map(|s| Value::String((*s).to_string())).collect()));
                input.insert("assumptions".into(), Value::Array(domain.assumptions.iter().map(|s| Value::String((*s).to_string())).collect()));
                input.insert("authorityLimits".into(), serde_json::json!([
                    "This lens does not establish physical, medical, financial, child-safety, operational, or data-recovery adequacy under any standard.",
                    "A hazard here is an allegation requiring a qualified domain-authority human decision; it is never closable by a model or automated verdict.",
                ]));
                input.insert("disposition".into(), Value::String(classification.disposition.to_string()));
                input.insert("unsafeStates".into(), if classification.disposition == "clean" { Value::Array(vec![]) } else { Value::Array(vec![Value::String(domain.unsafe_state.to_string())]) });
                input.insert("interlock".into(), Value::String(classification.interlock.to_string()));
                input.insert("failsafeDefault".into(), Value::String(classification.failsafe_default.to_string()));
                input.insert("degradedMode".into(), Value::String(classification.degraded_mode.to_string()));
                input.insert("emergencyStop".into(), Value::String(if domain.track_emergency_stop { if emergency_stop_re.is_match(&window) { "present" } else { "absent" } } else { "not-applicable" }.to_string()));
                input.insert("humanOverride".into(), Value::String(classification.human_override.to_string()));
                input.insert("confirmation".into(), Value::String(classification.confirmation.to_string()));
                input.insert("misuseScenarios".into(), Value::Array(domain.misuse_scenarios.iter().map(|s| Value::String((*s).to_string())).collect()));
                input.insert("recoveryPath".into(), Value::String(if domain.track_recovery { if recovery_re.is_match(&window) { "defined" } else { "absent" } } else { "not-applicable" }.to_string()));
                input.insert("incidentControls".into(), Value::String(if domain.track_incident_controls { if incident_re.is_match(&window) { "defined" } else { "absent" } } else { "not-applicable" }.to_string()));
                input.insert("evidenceRefs".into(), Value::Array(vec![Value::String(evidence_ref)]));
                input.insert("detectorMetadata".into(), serde_json::json!({
                    "file": file, "line": line_of(text, capture.start()),
                    "matchDigest": digest(&Value::String(capture.as_str().to_string())),
                    "classificationNote": classification.note,
                }));
                input.insert("uncertainty".into(), serde_json::json!([
                    "Lexical pattern match only; not confirmed by device, clinical, financial-ledger, guardian-consent, operational, or backup-system verification (none was performed or permitted).",
                    "Whether this call site is reachable in a live deployment, and by whom, must be adjudicated by a qualified domain-authority human, never by this lens.",
                ]));

                let hazard = create_hazard_candidate(&Value::Object(input))?;
                assert_hazard(&hazard)?;
                hazards.push(hazard);
            }
        }
    }
    Ok(hazards)
}

pub fn safety_rule_ids() -> Vec<&'static str> {
    domains().into_iter().map(|d| d.rule_id).collect()
}

// ---------------------------------------------------------------------
// schema-builder.mjs :: buildHazardModelSchema
// ---------------------------------------------------------------------

pub fn build_hazard_model_schema() -> Value {
    fn strings() -> Value {
        serde_json::json!({ "type": "array", "items": { "type": "string" } })
    }
    fn non_empty_strings() -> Value {
        serde_json::json!({ "type": "array", "items": { "type": "string" }, "minItems": 1 })
    }
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://orthic.dev/schemas/safety/hazard-model-v1.json",
        "title": "SafetyHazardV1", "type": "object",
        "required": [
            "schemaVersion", "kind", "id", "domain", "outcomeClass", "ruleId", "claim",
            "severityHint", "scope", "hazards", "assumptions", "authorityLimits",
            "disposition", "reasoningRequirement", "certifiable", "regulatoryClaim",
            "status", "evidenceRefs", "misuseScenarios",
        ],
        "properties": {
            "schemaVersion": { "const": 1 }, "kind": { "const": "safety-hazard" },
            "id": { "type": "string", "pattern": "^sha256:" },
            "domain": { "type": "string", "minLength": 1 },
            "outcomeClass": { "enum": OUTCOME_CLASS }, "ruleId": { "type": "string", "minLength": 1 },
            "claim": { "type": "string", "minLength": 1 }, "severityHint": { "enum": SEVERITY_HINTS },
            "scope": {
                "type": "object", "required": ["static", "runtime", "description"],
                "properties": { "static": { "type": "boolean" }, "runtime": { "type": "boolean" }, "description": { "type": "string", "minLength": 1 } },
                "additionalProperties": false,
            },
            "hazards": non_empty_strings(), "assumptions": non_empty_strings(), "authorityLimits": non_empty_strings(),
            "disposition": { "enum": HAZARD_DISPOSITION }, "unsafeStates": strings(),
            "interlock": { "enum": INTERLOCK_STATE }, "failsafeDefault": { "enum": FAILSAFE_DEFAULT },
            "degradedMode": { "enum": DEGRADED_MODE }, "emergencyStop": { "enum": EMERGENCY_STOP },
            "humanOverride": { "enum": HUMAN_OVERRIDE }, "confirmation": { "enum": CONFIRMATION_STATE },
            "misuseScenarios": non_empty_strings(), "recoveryPath": { "enum": RECOVERY_PATH },
            "incidentControls": { "enum": INCIDENT_CONTROLS },
            "reasoningRequirement": { "const": "human-decision" }, "certifiable": { "const": false },
            "regulatoryClaim": { "const": Value::Null }, "status": { "enum": HAZARD_STATUS },
            "evidenceRefs": non_empty_strings(), "detectorMetadata": { "type": "object" },
            "uncertainty": strings(), "closed": { "type": "boolean" },
        },
        "additionalProperties": false,
    })
}
