//! Port of src/lib/host/{capabilities,fs,process,fixed-host,index,
//! sandbox-policy,surfaces}.mjs and src/lib/host/arcane/stop-disposition.mjs.

use serde_json::{json, Value};

// ---- host/capabilities.mjs ----

/// Port of `requireCapability`. `effect` defaults to `"blocked"` in JS; the
/// caller passes it explicitly here (no default-arg sugar in Rust).
pub fn require_capability(host: &Value, name: &str, effect: &str) -> Value {
    let capability = host.get("capabilities").and_then(|c| c.get(name));
    let is_active = capability
        .is_some_and(|c| c.as_bool() == Some(true) || c.get("active").and_then(Value::as_bool) == Some(true));
    let receipt = capability
        .and_then(|c| c.get("receipt"))
        .cloned()
        .unwrap_or(Value::Null);
    if is_active {
        json!({"available": true, "receipt": receipt})
    } else {
        json!({"available": false, "status": effect, "capability": name, "receipt": receipt})
    }
}

// ---- host/fs.mjs / process.mjs ----
// These wrap a caller-supplied filesystem/process facade with a runtime guard
// (`readFile` presence, executable allowlisting). In Rust the equivalent is a
// trait boundary owned by the concrete host adapter; `filesystem_host_error`
// and `process_run_allowed` below reproduce just the JS-level guard logic so a
// caller can compose it with whatever concrete I/O type it has.

#[derive(Debug, thiserror::Error)]
#[error("host filesystem requires readFile")]
pub struct FilesystemHostError;

pub fn require_filesystem_host(has_read_file: bool) -> Result<(), FilesystemHostError> {
    if has_read_file {
        Ok(())
    } else {
        Err(FilesystemHostError)
    }
}

pub fn process_run_allowed(executable: &str, allowed_executables: &std::collections::HashSet<String>) -> Option<Value> {
    if allowed_executables.contains(executable) {
        None
    } else {
        Some(json!({"status": "blocked", "error": "executable-not-allowlisted"}))
    }
}

// ---- host/fixed-host.mjs ----

/// Port of `fixedHost`'s capability-defaulting shape. `overrides` is merged
/// in JS-object-spread order: overrides win, with `capabilities` deep-merged.
pub fn fixed_host_capabilities(overrides: &Value) -> Value {
    let defaults = json!({
        "networkSandbox": {"active": false, "receipt": null},
        "mutation": false,
        "browser": false,
        "signing": false,
        "filesystem": {"active": false, "receipt": null},
        "process": {"active": false, "receipt": null},
        "artifact": {"active": false, "receipt": null},
        "reviewer": {"active": false, "receipt": null},
    });
    let mut merged = defaults;
    if let Some(over) = overrides.get("capabilities").and_then(Value::as_object) {
        if let Value::Object(base) = &mut merged {
            for (k, v) in over {
                base.insert(k.clone(), v.clone());
            }
        }
    }
    merged
}

// ---- host/index.mjs ----

pub fn create_host_capabilities(overrides: &Value) -> Value {
    let defaults = json!({
        "networkSandbox": {"active": false, "receipt": null},
        "mutation": false,
        "browser": false,
        "signing": false,
        "reviewing": false,
        "nativeSurface": false,
        "mobileDevice": false,
        "externalEvidence": false,
    });
    let mut merged = defaults;
    if let Some(over) = overrides.get("capabilities").and_then(Value::as_object) {
      if let Value::Object(base) = &mut merged {
        for (k, v) in over {
            base.insert(k.clone(), v.clone());
        }
      }
    }
    merged
}

// ---- host/sandbox-policy.mjs ----

#[derive(Debug, thiserror::Error)]
#[error("provider {provider} blocked: {reason}")]
pub struct ProviderBlockedError {
    pub provider: String,
    pub reason: String,
}

/// Port of `requireProjectExecutionSandbox`.
pub fn require_project_execution_sandbox(provider: &Value, host: &Value) -> Result<(), ProviderBlockedError> {
    let has_project_execution = provider
        .get("hostCapabilities")
        .and_then(Value::as_array)
        .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("project-execution")));
    if !has_project_execution {
        return Ok(());
    }
    let network_sandbox = host.get("capabilities").and_then(|c| c.get("networkSandbox"));
    let active = network_sandbox.and_then(|n| n.get("active")).and_then(Value::as_bool) == Some(true);
    let has_receipt = network_sandbox
        .and_then(|n| n.get("receipt"))
        .is_some_and(|r| !r.is_null());
    if !active || !has_receipt {
        return Err(ProviderBlockedError {
            provider: provider.get("id").and_then(Value::as_str).unwrap_or_default().to_string(),
            reason: "network-sandbox-receipt-missing".to_string(),
        });
    }
    Ok(())
}

// ---- host/surfaces.mjs ----

pub const SURFACES: [&str; 5] = ["instructions", "skills", "agents", "mcp", "hooks"];
pub const FIDELITY: [&str; 3] = ["strong", "degraded", "unsupported"];

pub fn assert_fidelity(value: &str, where_: &str) -> Result<(), String> {
    if FIDELITY.contains(&value) {
        Ok(())
    } else {
        Err(format!("{where_}: fidelity must be one of {}, got {value}", FIDELITY.join("|")))
    }
}

/// Port of `enforcementFidelity`.
pub fn enforcement_fidelity(mechanism: Option<&Value>) -> &'static str {
    match mechanism {
        None => "unsupported",
        Some(m) if m.get("kind").and_then(Value::as_str) == Some("none") => "unsupported",
        Some(m) if m.get("kind").and_then(Value::as_str) == Some("blocking-hook") => "strong",
        Some(_) => "degraded",
    }
}

// ---- host/arcane/stop-disposition.mjs ----

pub const STOP_DISPOSITIONS: [&str; 5] = ["completion", "question", "pause", "archive", "other"];

pub fn classify_stop_disposition(authenticated_claim: bool, intent: &str) -> &'static str {
    if ["QUESTION", "PLAN", "PAUSE", "REVOKE", "SCOPE_NARROW"].contains(&intent) {
        return "question";
    }
    if authenticated_claim {
        return "completion";
    }
    "other"
}

pub fn stop_outcome(authenticated_claim: bool, intent: &str) -> Value {
    let disposition = classify_stop_disposition(authenticated_claim, intent);
    json!({
        "disposition": disposition,
        "termination": {"allowed": true},
        "certification": if disposition == "completion" { "genuine" } else { "not_claimed" },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn require_capability_reports_available_when_active_true() {
        let host = json!({"capabilities": {"mutation": true}});
        let result = require_capability(&host, "mutation", "blocked");
        assert_eq!(result["available"], true);
    }

    #[test]
    fn require_capability_reports_blocked_when_absent() {
        let host = json!({"capabilities": {}});
        let result = require_capability(&host, "mutation", "blocked");
        assert_eq!(result["available"], false);
        assert_eq!(result["status"], "blocked");
    }

    #[test]
    fn require_capability_reads_nested_active_flag() {
        let host = json!({"capabilities": {"networkSandbox": {"active": true, "receipt": "r1"}}});
        let result = require_capability(&host, "networkSandbox", "blocked");
        assert_eq!(result["available"], true);
        assert_eq!(result["receipt"], "r1");
    }

    #[test]
    fn process_run_allowed_blocks_unlisted_executable() {
        let allowed = std::collections::HashSet::new();
        let result = process_run_allowed("rm", &allowed);
        assert!(result.is_some());
        assert_eq!(result.unwrap()["error"], "executable-not-allowlisted");
    }

    #[test]
    fn sandbox_policy_requires_receipt_for_project_execution_providers() {
        let provider = json!({"id": "eslint", "hostCapabilities": ["project-execution"]});
        let host = json!({"capabilities": {"networkSandbox": {"active": false}}});
        let err = require_project_execution_sandbox(&provider, &host).unwrap_err();
        assert_eq!(err.provider, "eslint");
        assert_eq!(err.reason, "network-sandbox-receipt-missing");
    }

    #[test]
    fn sandbox_policy_allows_providers_without_project_execution() {
        let provider = json!({"id": "docs-lint", "hostCapabilities": []});
        let host = json!({"capabilities": {}});
        assert!(require_project_execution_sandbox(&provider, &host).is_ok());
    }

    #[test]
    fn enforcement_fidelity_maps_mechanisms() {
        assert_eq!(enforcement_fidelity(None), "unsupported");
        assert_eq!(enforcement_fidelity(Some(&json!({"kind": "none"}))), "unsupported");
        assert_eq!(enforcement_fidelity(Some(&json!({"kind": "blocking-hook"}))), "strong");
        assert_eq!(enforcement_fidelity(Some(&json!({"kind": "advisory"}))), "degraded");
    }

    #[test]
    fn stop_disposition_classifies_question_intents() {
        assert_eq!(classify_stop_disposition(true, "QUESTION"), "question");
        assert_eq!(classify_stop_disposition(true, "UNKNOWN"), "completion");
        assert_eq!(classify_stop_disposition(false, "UNKNOWN"), "other");
    }

    #[test]
    fn stop_outcome_certifies_only_on_completion() {
        let outcome = stop_outcome(true, "UNKNOWN");
        assert_eq!(outcome["disposition"], "completion");
        assert_eq!(outcome["certification"], "genuine");
        let outcome2 = stop_outcome(false, "UNKNOWN");
        assert_eq!(outcome2["certification"], "not_claimed");
    }
}
