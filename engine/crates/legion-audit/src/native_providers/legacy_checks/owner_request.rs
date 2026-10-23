//! Shared owner-admissible request construction for legacy-check launch
//! builders that do not go through the main check path (node outdated, runtime
//! capture). With an active owner context the request carries the host policy
//! pin, the owner policy id, the containment receipt and a canonical absolute
//! executable; without one callers keep their no-owner request shape.

use std::path::Path;

use super::{resolve_request, ExternalToolRequest};
use crate::host_owner::OwnerRequestContext;

/// Why an owner-backed request could not be built. `missing` marks an
/// absent/unpinned tool (typed missing-executable) rather than a policy denial.
#[derive(Debug)]
pub(super) struct OwnerGap {
    pub gap: String,
    pub missing: bool,
}

/// Rewrite `request` (still carrying the symbolic tool name) into an
/// owner-admissible request. Binds the frozen plan, resolves the tool to its
/// canonical path, takes the pin from the host policy entry only, drops
/// environment names the entry does not admit and sets containment.
pub(super) fn apply_owner(
    ctx: &OwnerRequestContext,
    root: &Path,
    provider_id: &str,
    plan_digest: &str,
    request: &mut ExternalToolRequest,
) -> Result<(), OwnerGap> {
    let symbolic = request.executable.clone();
    ctx.plan().bind(plan_digest).map_err(|error| OwnerGap {
        gap: format!("owner-plan-binding-conflict:{error}"),
        missing: false,
    })?;
    let resolved = resolve_request(root, &symbolic, &request.args).map_err(|error| OwnerGap {
        gap: error.message(),
        missing: true,
    })?;
    let canonical = std::fs::canonicalize(&resolved.executable).map_err(|_| OwnerGap {
        gap: format!("owner-policy-missing-tool:{symbolic}"),
        missing: true,
    })?;
    request.args = resolved.args;
    apply_pin(ctx, provider_id, &canonical, &symbolic, request)
}

/// Owner fields for a request whose executable is already resolved: the pin is
/// the host policy entry for the canonical path, never a digest of the file;
/// a caller-supplied digest that disagrees with the policy fails closed.
pub(super) fn apply_pin(
    ctx: &OwnerRequestContext,
    provider_id: &str,
    canonical: &Path,
    label: &str,
    request: &mut ExternalToolRequest,
) -> Result<(), OwnerGap> {
    let pin = ctx
        .pin_for(provider_id, canonical)
        .ok_or_else(|| OwnerGap {
            gap: format!("owner-policy-missing-tool:{label}"),
            missing: false,
        })?;
    if request
        .expected_digest
        .as_deref()
        .is_some_and(|expected| expected != pin.digest)
    {
        return Err(OwnerGap {
            gap: format!("owner-policy-digest-mismatch:{label}"),
            missing: false,
        });
    }
    request
        .environment
        .retain(|name, _| pin.environment_names.contains(name));
    request
        .environment_allowlist
        .retain(|name| pin.environment_names.contains(name));
    request.executable = canonical.to_string_lossy().into_owned();
    let cwd = std::path::PathBuf::from(&request.cwd);
    request.cwd = std::fs::canonicalize(&cwd)
        .unwrap_or(cwd)
        .to_string_lossy()
        .into_owned();
    request.policy_id = crate::execution_policy::OWNER_POLICY_ID.into();
    request.expected_digest = Some(pin.digest.clone());
    request.requires_network_sandbox = true;
    request.sandbox = Some(ctx.sandbox_receipt());
    Ok(())
}

/// Decide the attested-run preparation request. Without an owner context the
/// decision is exactly the pre-owner one (fixture authorizer, else deny). With
/// one, the request is rewritten to its owner-admissible shape (plan binding,
/// host-policy pin, containment) and decided only by the owner-backed
/// authorizer; a missing pin, plan conflict or missing authorizer denies.
pub(super) fn authorize_preparation(
    ctx: Option<&OwnerRequestContext>,
    owner_authorizer: Option<&dyn legion_effects::PolicyAuthorizer>,
    fixture_authorizer: Option<&dyn legion_effects::PolicyAuthorizer>,
    preparation: &mut ExternalToolRequest,
) -> legion_effects::PolicyDecision {
    use legion_effects::PolicyAuthorizer;
    let deny = crate::execution_policy::OwnerAdmissionRequired;
    let Some(ctx) = ctx else {
        return fixture_authorizer
            .map_or_else(|| deny.authorize(preparation), |a| a.authorize(preparation));
    };
    let gap = (|| {
        ctx.plan()
            .bind(&preparation.plan_id)
            .map_err(|error| format!("owner-plan-binding-conflict:{error}"))?;
        let path = Path::new(&preparation.executable);
        if !path.is_absolute() {
            return Err("owner-request-executable-not-absolute".to_string());
        }
        let canonical =
            std::fs::canonicalize(path).map_err(|_| "owner-policy-missing-tool".to_string())?;
        let label = preparation.executable.clone();
        let provider = preparation.provider_id.to_string();
        apply_pin(ctx, &provider, &canonical, &label, preparation).map_err(|gap| gap.gap)
    })();
    match (gap, owner_authorizer) {
        (Ok(()), Some(authorizer)) => authorizer.authorize(preparation),
        (Ok(()), None) => deny.authorize(preparation),
        (Err(gap), _) => {
            let mut decision = deny.authorize(preparation);
            decision.reason = Some(gap);
            decision
        }
    }
}

/// Tool adapter that makes every request an already-built launch path emits
/// owner-admissible (attested-run probe/submit/status/cancel/verify). The
/// executable must already be absolute; the plan is bound once per request.
pub(super) struct OwnerPinnedTool<'a> {
    pub inner: &'a dyn legion_provider_sdk::ExternalProjectTool,
    pub ctx: std::sync::Arc<OwnerRequestContext>,
}

#[async_trait::async_trait]
impl legion_provider_sdk::ExternalProjectTool for OwnerPinnedTool<'_> {
    async fn execute(
        &self,
        mut request: ExternalToolRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> legion_provider_sdk::ExecutionReceipt {
        use legion_provider_sdk::{ExecutionReceipt, ExecutionState};
        let provider = request.provider_id.to_string();
        let gap = (|| {
            self.ctx
                .plan()
                .bind(&request.plan_id)
                .map_err(|error| OwnerGap {
                    gap: format!("owner-plan-binding-conflict:{error}"),
                    missing: false,
                })?;
            let path = Path::new(&request.executable);
            if !path.is_absolute() {
                return Err(OwnerGap {
                    gap: "owner-request-executable-not-absolute".into(),
                    missing: false,
                });
            }
            let canonical = std::fs::canonicalize(path).map_err(|_| OwnerGap {
                gap: "owner-policy-missing-tool".into(),
                missing: true,
            })?;
            apply_pin(
                &self.ctx,
                &provider,
                &canonical,
                &request.executable.clone(),
                &mut request,
            )
        })();
        match gap {
            Ok(()) => self.inner.execute(request, cancellation).await,
            Err(gap) => ExecutionReceipt::failure(
                &request,
                if gap.missing {
                    ExecutionState::MissingExecutable
                } else {
                    ExecutionState::UnauthorizedEffect
                },
                gap.gap,
            ),
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use legion_provider_sdk::{ExecutionReceipt, ExternalProjectTool};
    use sha2::{Digest, Sha256};
    use std::{
        os::unix::fs::PermissionsExt,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    const PROVIDER: &str = "legacy.runtime.app";
    const PLAN: &str = "owner-builders-plan";

    struct Recorder(Mutex<Vec<ExternalToolRequest>>);
    #[async_trait::async_trait]
    impl ExternalProjectTool for Recorder {
        async fn execute(
            &self,
            request: ExternalToolRequest,
            _cancellation: tokio_util::sync::CancellationToken,
        ) -> ExecutionReceipt {
            let receipt = ExecutionReceipt::failure(
                &request,
                legion_provider_sdk::ExecutionState::Blocked,
                "recorded",
            );
            self.0.lock().unwrap().push(request);
            receipt
        }
    }

    fn context(tool: &Path) -> (Arc<OwnerRequestContext>, String, PathBuf) {
        let (ctx, digest, frozen, _) = context_with_authorizer(tool);
        (ctx, digest, frozen)
    }

    fn context_with_authorizer(
        tool: &Path,
    ) -> (
        Arc<OwnerRequestContext>,
        String,
        PathBuf,
        Arc<crate::owner_admission::NativeAuthorizer>,
    ) {
        let base = std::fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("legion-owner-builders-{}", std::process::id()));
        let (frozen, out, state) = (base.join("frozen"), base.join("out"), base.join("state"));
        for dir in [&frozen, &out, &state] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        let digest = format!(
            "sha256:{}",
            hex::encode(Sha256::digest(std::fs::read(tool).unwrap()))
        );
        let policy = state.join(crate::host_owner::POLICY_FILE);
        std::fs::write(
            &policy,
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 1, "policyRevision": "r1",
                "tools": [{"providers": [PROVIDER], "executable": tool,
                    "sha256": digest, "class": "read-only-static",
                    "environmentNames": ["HOME"]}]
            }))
            .unwrap(),
        )
        .unwrap();
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner =
            crate::host_owner::HostPolicyOwner::load(&policy, &[frozen.clone(), out.clone()])
                .unwrap()
                .unwrap();
        let config = owner.owner_config(PLAN, &frozen, &out).unwrap();
        let ctx = Arc::new(owner.request_context(&config));
        let authorizer = crate::owner_admission::NativeAuthorizer::resolve(
            Some(owner.into_trusted()),
            Some(config),
        );
        assert!(authorizer.is_owner_backed());
        (ctx, digest, frozen, Arc::new(authorizer))
    }

    fn base(tool: &Path, cwd: &Path) -> ExternalToolRequest {
        ExternalToolRequest {
            request_id: "r".into(),
            provider_id: PROVIDER.into(),
            plan_id: PLAN.into(),
            policy_id: "audit".into(),
            executable: tool.to_string_lossy().into_owned(),
            cwd: cwd.to_string_lossy().into_owned(),
            environment: [("HOME".into(), "/h".into()), ("SECRET".into(), "x".into())].into(),
            environment_allowlist: ["HOME".into(), "SECRET".into()].into(),
            ..ExternalToolRequest::default()
        }
    }

    fn assert_admissible(request: &ExternalToolRequest, ctx: &OwnerRequestContext, digest: &str) {
        assert_eq!(request.policy_id, crate::execution_policy::OWNER_POLICY_ID);
        assert_eq!(request.expected_digest.as_deref(), Some(digest));
        assert!(request.requires_network_sandbox);
        assert_eq!(
            request.sandbox.as_ref().map(|s| s.id.clone()),
            Some(ctx.sandbox_receipt().id)
        );
        assert!(Path::new(&request.executable).is_absolute());
        assert!(!request.environment.contains_key("SECRET"));
        assert!(!request.environment_allowlist.contains("SECRET"));
        assert!(request.environment.contains_key("HOME"));
    }

    #[test]
    fn apply_pin_emits_owner_admissible_request_and_rejects_foreign_digest() {
        let tool = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let (ctx, digest, frozen) = context(&tool);
        let mut request = base(&tool, &frozen);
        apply_pin(&ctx, PROVIDER, &tool, "tool", &mut request).unwrap();
        assert_admissible(&request, &ctx, &digest);
        let mut forged = base(&tool, &frozen);
        forged.expected_digest = Some(format!("sha256:{}", "0".repeat(64)));
        assert!(apply_pin(&ctx, PROVIDER, &tool, "tool", &mut forged).is_err());
        let mut other = base(&tool, &frozen);
        assert!(apply_pin(&ctx, "legacy.other", &tool, "tool", &mut other).is_err());
    }

    #[tokio::test]
    async fn pinned_tool_pins_every_attested_launch_and_refuses_relative_or_unpinned() {
        let tool = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let (ctx, digest, frozen) = context(&tool);
        let recorder = Recorder(Mutex::new(Vec::new()));
        let pinned = OwnerPinnedTool {
            inner: &recorder,
            ctx: ctx.clone(),
        };
        let token = tokio_util::sync::CancellationToken::new();
        pinned.execute(base(&tool, &frozen), token.clone()).await;
        {
            let seen = recorder.0.lock().unwrap();
            assert_eq!(seen.len(), 1);
            assert_admissible(&seen[0], &ctx, &digest);
        }
        let mut relative = base(&tool, &frozen);
        relative.executable = "legion".into();
        let receipt = pinned.execute(relative, token.clone()).await;
        assert_eq!(
            receipt.state,
            legion_provider_sdk::ExecutionState::UnauthorizedEffect
        );
        let mut unpinned = base(Path::new("/bin/sh"), &frozen);
        unpinned.executable = "/bin/sh".into();
        let receipt = pinned.execute(unpinned, token).await;
        assert_eq!(
            receipt.state,
            legion_provider_sdk::ExecutionState::UnauthorizedEffect
        );
        assert_eq!(recorder.0.lock().unwrap().len(), 1);
    }

    fn preparation(tool: &Path, cwd: &Path) -> ExternalToolRequest {
        ExternalToolRequest {
            request_id: "audit-prep-1".into(),
            provider_id: PROVIDER.into(),
            plan_id: PLAN.into(),
            policy_id: crate::execution_policy::POLICY_ID.into(),
            task_id: Some("managed-test-disposable-copy".into()),
            executable: tool.to_string_lossy().into_owned(),
            cwd: cwd.to_string_lossy().into_owned(),
            timeout_ms: 20_000,
            // HOME is admitted by the policy entry; SECRET is not and must be dropped.
            environment: [("HOME".into(), "/h".into()), ("SECRET".into(), "x".into())].into(),
            environment_allowlist: ["HOME".into(), "SECRET".into()].into(),
            ..ExternalToolRequest::default()
        }
    }

    #[test]
    fn preparation_is_admitted_for_pinned_tool_and_denied_when_unpinned_or_unbacked() {
        let tool = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let (ctx, digest, frozen, authorizer) = context_with_authorizer(&tool);
        let owner: &dyn legion_effects::PolicyAuthorizer = authorizer.as_ref();

        let mut request = preparation(&tool, &frozen);
        let decision = authorize_preparation(Some(&ctx), Some(owner), None, &mut request);
        assert!(decision.allowed, "{:?}", decision.reason);
        assert_admissible(&request, &ctx, &digest);

        // Unpinned executable: denied before the owner is asked.
        let mut unpinned = preparation(Path::new("/bin/sh"), &frozen);
        let decision = authorize_preparation(Some(&ctx), Some(owner), None, &mut unpinned);
        assert!(!decision.allowed);

        // Owner context without an owner-backed authorizer stays denied, and a
        // fixture authorizer cannot widen it.
        let allow = legion_effects::StaticPolicy {
            decision: legion_effects::PolicyDecision {
                allowed: true,
                policy_id: "fixture".into(),
                policy_version: 1,
                policy_digest: "d".into(),
                reason: None,
            },
        };
        let mut no_auth = preparation(&tool, &frozen);
        let decision = authorize_preparation(Some(&ctx), None, Some(&allow), &mut no_auth);
        assert!(!decision.allowed);
    }

    #[test]
    fn preparation_without_owner_context_keeps_the_existing_denial() {
        let tool = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let mut request = preparation(&tool, Path::new("/"));
        let before = request.clone();
        let decision = authorize_preparation(None, None, None, &mut request);
        assert!(!decision.allowed);
        assert_eq!(
            decision.reason.as_deref(),
            Some(crate::execution_policy::ADMISSION_UNAVAILABLE)
        );
        assert_eq!(request.policy_id, before.policy_id);
        assert_eq!(request.executable, before.executable);
    }

    #[test]
    fn apply_owner_resolves_runtime_capture_tool_to_the_pinned_canonical_path() {
        let probe_root = std::env::temp_dir();
        let Ok(resolved) = resolve_request(
            &probe_root,
            super::super::resolver::RUNTIME_CAPTURE_TOOL,
            &[],
        ) else {
            return;
        };
        let Ok(tool) = std::fs::canonicalize(&resolved.executable) else {
            return;
        };
        let (ctx, digest, frozen) = context(&tool);
        let mut request = base(&tool, &frozen);
        request.executable = super::super::resolver::RUNTIME_CAPTURE_TOOL.into();
        apply_owner(&ctx, &probe_root, PROVIDER, PLAN, &mut request).unwrap();
        assert_admissible(&request, &ctx, &digest);
        let mut wrong_plan_request = base(&tool, &frozen);
        wrong_plan_request.executable = super::super::resolver::RUNTIME_CAPTURE_TOOL.into();
        assert!(apply_owner(
            &ctx,
            &probe_root,
            PROVIDER,
            "different-plan",
            &mut wrong_plan_request
        )
        .is_err());
    }
}
