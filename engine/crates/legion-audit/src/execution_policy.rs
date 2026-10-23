//! Native Audit has no owner-backed external admission service yet. Freeze
//! that fact before effects; caller configuration cannot grant admission.
use crate::profiles::{
    validate_runtime_closure, LaunchStep, LaunchStepKind, RuntimeClass, RuntimeClosure,
    RuntimeConstraint, RuntimeViolation,
};
use legion_effects::{ExternalToolRequest, PolicyAuthorizer, PolicyDecision};
use serde_json::{json, Value};
use std::{io::Read, path::Path};

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

/// Runtime class of a program name (basename; `.exe`/`.cmd`/`.bat` and trailing
/// version digits ignored). Recognises Node and Python launchers/package
/// managers; every other name is `Native` (scripts are classified by shebang).
pub fn runtime_class_of_name(name: &str) -> RuntimeClass {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    let mut stem = base.as_str();
    for suffix in [".exe", ".cmd", ".bat", ".ps1"] {
        stem = stem.strip_suffix(suffix).unwrap_or(stem);
    }
    let stem = stem.trim_end_matches(|c: char| c.is_ascii_digit() || c == '.' || c == '-');
    match stem {
        "node" | "nodejs" | "npm" | "npx" | "pnpm" | "pnpx" | "yarn" | "yarnpkg" | "bun"
        | "bunx" | "deno" | "corepack" | "tsx" | "ts-node" => RuntimeClass::Node,
        "python" | "pythonw" | "pip" | "pipx" | "uv" | "uvx" | "poetry" | "pdm" | "conda"
        | "py" => RuntimeClass::Python,
        _ => RuntimeClass::Native,
    }
}

/// Programs that run another program named in their arguments.
fn is_generic_launcher(name: &str) -> bool {
    let base = name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    let stem = base.strip_suffix(".exe").unwrap_or(&base);
    matches!(
        stem,
        "env"
            | "sh"
            | "bash"
            | "zsh"
            | "dash"
            | "ksh"
            | "fish"
            | "cmd"
            | "powershell"
            | "pwsh"
            | "xargs"
            | "nice"
            | "nohup"
            | "timeout"
            | "time"
            | "command"
            | "exec"
            | "sudo"
            | "doas"
            | "setsid"
            | "stdbuf"
            | "script"
            | "busybox"
    )
}

/// Interpreter class of a `#!` line: Node/Python when any token (past `env`
/// and options) names one; any other interpreter is `Unknown` (a script is
/// never assumed native).
fn shebang_class(line: &str) -> RuntimeClass {
    let tokens = line
        .trim_start_matches("#!")
        .split_whitespace()
        .collect::<Vec<_>>();
    let mut other = false;
    for token in tokens {
        match runtime_class_of_name(token) {
            RuntimeClass::Native => {
                let base = token.rsplit('/').next().unwrap_or(token);
                if base != "env" && !token.starts_with('-') && !token.contains('=') {
                    other = true;
                }
            }
            class => return class,
        }
    }
    if other {
        RuntimeClass::Unknown
    } else {
        RuntimeClass::Native
    }
}

/// Derive the audit-owned launch closure of one request: the executable, its
/// script interpreter (shebang, read from the sealed file), and any program a
/// generic launcher (`env`, `sh -c`, `xargs` ...) is asked to run.
pub fn launch_closure(executable: &Path, args: &[String]) -> RuntimeClosure {
    let name = executable.to_string_lossy().into_owned();
    let mut steps = vec![LaunchStep {
        name: name.clone(),
        runtime: runtime_class_of_name(&name),
        kind: LaunchStepKind::Tool,
        audit_owned: true,
    }];
    let mut head = [0u8; 256];
    let count = std::fs::File::open(executable)
        .and_then(|mut file| file.read(&mut head))
        .unwrap_or(0);
    if head[..count].starts_with(b"#!") {
        let line = head[..count]
            .split(|b| *b == b'\n')
            .next()
            .unwrap_or_default();
        steps.push(LaunchStep {
            name: format!("{name}#!"),
            runtime: shebang_class(&String::from_utf8_lossy(line)),
            kind: LaunchStepKind::ChildInterpreter,
            audit_owned: true,
        });
    }
    if is_generic_launcher(&name) {
        for arg in args {
            for token in arg.split(|c: char| {
                c.is_whitespace()
                    || matches!(c, ';' | '&' | '|' | '(' | ')' | '`' | '"' | '\'' | '=')
            }) {
                if token.is_empty() {
                    continue;
                }
                let class = runtime_class_of_name(token);
                if class != RuntimeClass::Native {
                    steps.push(LaunchStep {
                        name: format!("{name} -> {token}"),
                        runtime: class,
                        kind: LaunchStepKind::ChildInterpreter,
                        audit_owned: true,
                    });
                }
            }
        }
    }
    RuntimeClosure { steps }
}

/// Process-admission closure check: violations (empty when admissible) of the
/// request's launch closure under the host-frozen constraint.
pub fn admission_runtime_violations(
    constraint: RuntimeConstraint,
    executable: &Path,
    args: &[String],
) -> Vec<RuntimeViolation> {
    validate_runtime_closure(constraint, &launch_closure(executable, args))
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
