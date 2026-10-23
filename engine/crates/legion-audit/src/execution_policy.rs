//! Native Audit has no owner-backed external admission service yet. Freeze
//! that fact before effects; caller configuration cannot grant admission.
use legion_effects::{ExternalToolRequest, PolicyAuthorizer, PolicyDecision};
use serde_json::{json, Value};

pub const POLICY_ID: &str = "audit-native-owner-admission-v1";
/// Policy id carried by decisions of an owner-backed authorizer. Distinct from
/// `POLICY_ID` so a receipt can never claim owner admission via the fallback id.
pub const OWNER_POLICY_ID: &str = "audit-native-owner-admission-v2";
pub const OWNER_POLICY_VERSION: u32 = 2;
pub const ADMISSION_UNAVAILABLE: &str = "native-owner-admission-unavailable";
pub const NOTICE: &str = "External checks require native owner admission; unavailable checks remain explicit coverage gaps.";

pub fn resolved_policy() -> Value {
    json!({
        "externalProcesses": "owner-admission-required",
        "admissionStatus": "unavailable",
        "effectiveMode": "deny-external",
    })
}

pub fn binding() -> Value {
    let policy = resolved_policy();
    json!({
        "executionPolicy": policy,
        "executionPolicyIdentity": {
            "id": POLICY_ID,
            "version": 1,
            "digest": crate::digest(&policy).expect("static execution policy is serializable"),
        },
    })
}

#[derive(Clone, Copy, Debug, Default)]
pub struct OwnerAdmissionRequired;

impl PolicyAuthorizer for OwnerAdmissionRequired {
    fn authorize(&self, _: &ExternalToolRequest) -> PolicyDecision {
        PolicyDecision {
            allowed: false,
            policy_id: POLICY_ID.into(),
            policy_version: 1,
            policy_digest: binding()["executionPolicyIdentity"]["digest"]
                .as_str()
                .expect("static policy digest")
                .into(),
            reason: Some(ADMISSION_UNAVAILABLE.into()),
        }
    }
}

/// Frozen policy meaning for an owner-backed run. `descriptor` is the
/// authorizer's own description (owner identity, policy revision, roots,
/// limits); its digest is what receipts carry as the policy digest.
pub fn owner_binding(descriptor: &Value) -> Value {
    let policy = json!({
        "externalProcesses": "owner-admitted",
        "admissionStatus": "available",
        "effectiveMode": "owner-contained",
        "owner": descriptor,
    });
    json!({
        "executionPolicy": policy,
        "executionPolicyIdentity": {
            "id": OWNER_POLICY_ID,
            "version": OWNER_POLICY_VERSION,
            "digest": crate::digest(descriptor).expect("owner policy descriptor is serializable"),
        },
    })
}

/// Receipt projections retain both decision evidence & frozen policy meaning.
pub fn project_binding(receipt: &mut Value) {
    match receipt.pointer("/policy/id").and_then(Value::as_str) {
        Some(POLICY_ID) => {
            let binding = binding();
            receipt["executionPolicy"] = binding["executionPolicy"].clone();
            receipt["executionPolicyIdentity"] = binding["executionPolicyIdentity"].clone();
        }
        Some(OWNER_POLICY_ID) => {
            // The receipt's own decision evidence is the source of truth; the
            // owner descriptor is not reconstructible here, so only the
            // decision outcome & identity are projected.
            let policy = receipt["policy"].clone();
            receipt["executionPolicy"] = json!({
                "externalProcesses": "owner-admitted",
                "admissionStatus": if policy["allowed"].as_bool() == Some(true) { "granted" } else { "denied" },
                "effectiveMode": if policy["allowed"].as_bool() == Some(true) { "owner-contained" } else { "deny-external" },
                "reason": policy["reason"],
            });
            receipt["executionPolicyIdentity"] = json!({
                "id": policy["id"], "version": policy["version"], "digest": policy["digest"],
            });
        }
        _ => {}
    }
}

/// Retain effect evidence without replacing a denial with an analyzer summary.
pub(crate) fn receipt_json(receipt: &legion_effects::ExecutionReceipt) -> Value {
    let mut value = json!({
        "schemaVersion": receipt.schema_version,
        "receiptId": receipt.receipt_id, "requestId": receipt.request_id,
        "providerId": receipt.provider_id, "planId": receipt.plan_id,
        "policyId": receipt.policy_id,
        "policy": receipt.policy.as_ref().map(|p| json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
        "taskId": receipt.task_id, "state": receipt.state.as_str(), "complete": receipt.complete,
        "executable": receipt.executable.as_ref().map(|e| json!({"requestedPath":e.requested_path,"canonicalPath":e.canonical_path,"digest":e.digest,"digestState":format!("{:?}",e.digest_state).to_ascii_lowercase(),"signature":format!("{:?}",e.signature).to_ascii_lowercase(),"version":{"args":e.version.args,"output":e.version.output,"exitCode":e.version.exit_code,"qualified":e.version.qualified,"skippedByPolicy":e.version.skipped_by_policy}})),
        "command": receipt.command.as_ref().map(|c| json!({"executable":c.executable,"args":c.args,"environmentNames":c.environment_names,"redactedArgumentIndexes":c.redacted_argument_indexes,"redactedEnvironmentNames":c.redacted_environment_names})),
        "cwd": receipt.cwd, "environmentNames": receipt.environment_names,
        "sandbox": {"required":receipt.sandbox.required,"receiptId":receipt.sandbox.receipt_id,"networkEnabled":receipt.sandbox.network_enabled},
        "processTree": {"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,"hardKilled":receipt.process_tree.hard_killed,"reaped":receipt.process_tree.reaped,"detail":receipt.process_tree.detail},
        "timing": {"startedAtMs":receipt.timing.started_at_ms,"completedAtMs":receipt.timing.completed_at_ms,"durationMs":receipt.timing.duration_ms},
        "exitCode": receipt.exit_code, "signal": receipt.signal,
        "stdout": receipt.stdout.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "stderr": receipt.stderr.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "parser": {"attempted":receipt.parser.attempted,"succeeded":receipt.parser.succeeded,"error":receipt.parser.error},
        "gaps": receipt.gaps,
    });
    project_binding(&mut value);
    value
}

/// Obtain an actual policy decision receipt for a blocked native operation.
pub(crate) async fn deny(request: &ExternalToolRequest) -> legion_effects::ExecutionReceipt {
    struct NoArtifacts;
    impl legion_effects::ArtifactSink for NoArtifacts {
        fn write(
            &self,
            _: &str,
            _: &[u8],
        ) -> Result<legion_effects::ArtifactRecord, legion_effects::EffectError> {
            Err(legion_effects::EffectError::ArtifactFailed(
                "denied operation has no process artifacts".into(),
            ))
        }
    }
    #[cfg(unix)]
    let process = legion_effects::platform::unix::UnixProcess::new();
    #[cfg(windows)]
    let process = legion_effects::platform::windows::WindowsProcess::default();
    legion_effects::EffectExecutor::new(process, NoArtifacts, OwnerAdmissionRequired)
        .execute(request)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NeverRun;
    impl legion_effects::PlatformProcess for NeverRun {
        fn run<'a>(
            &'a self,
            _: legion_effects::ProcessLaunch,
        ) -> legion_effects::platform::ProcessFuture<'a> {
            panic!("denied admission must precede version probe & target spawn")
        }
    }
    struct NeverWrite;
    impl legion_effects::ArtifactSink for NeverWrite {
        fn write(
            &self,
            _: &str,
            _: &[u8],
        ) -> Result<legion_effects::ArtifactRecord, legion_effects::EffectError> {
            panic!("denied admission must not produce process artifacts")
        }
    }

    #[tokio::test]
    async fn denial_precedes_resolution_version_probe_and_spawn() {
        let request = ExternalToolRequest {
            request_id: "admission-denied".into(),
            provider_id: "legacy.quality.build".into(),
            plan_id: "frozen-plan".into(),
            policy_id: POLICY_ID.into(),
            executable: "definitely-missing-audit-executable".into(),
            cwd: std::env::temp_dir()
                .join("definitely-missing-audit-cwd")
                .to_string_lossy()
                .into_owned(),
            ..ExternalToolRequest::default()
        };
        let receipt =
            legion_effects::EffectExecutor::new(NeverRun, NeverWrite, OwnerAdmissionRequired)
                .execute(&request)
                .await;
        assert_eq!(
            receipt.state,
            legion_effects::ExecutionState::UnauthorizedEffect
        );
        assert!(!receipt.complete);
        assert!(!receipt.process_tree.started);
        assert!(!receipt.parser.attempted);
        assert!(receipt.executable.is_none());
        let decision = receipt.policy.unwrap();
        assert!(!decision.allowed);
        assert_eq!(decision.reason.as_deref(), Some(ADMISSION_UNAVAILABLE));
        assert_eq!(
            decision.digest,
            binding()["executionPolicyIdentity"]["digest"]
                .as_str()
                .unwrap()
        );
    }
}
