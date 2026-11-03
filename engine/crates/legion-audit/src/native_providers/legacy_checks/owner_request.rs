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
    owner_authorizer: Option<&dyn rightkit_evidence_effects::PolicyAuthorizer>,
    fixture_authorizer: Option<&dyn rightkit_evidence_effects::PolicyAuthorizer>,
    preparation: &mut ExternalToolRequest,
) -> rightkit_evidence_effects::PolicyDecision {
    use rightkit_evidence_effects::PolicyAuthorizer;
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
    pub inner: &'a dyn rightkit_code_audit_provider_sdk::ExternalProjectTool,
    pub ctx: std::sync::Arc<OwnerRequestContext>,
}

#[async_trait::async_trait]
impl rightkit_code_audit_provider_sdk::ExternalProjectTool for OwnerPinnedTool<'_> {
    async fn execute(
        &self,
        mut request: ExternalToolRequest,
        cancellation: tokio_util::sync::CancellationToken,
    ) -> rightkit_code_audit_provider_sdk::ExecutionReceipt {
        use rightkit_code_audit_provider_sdk::{ExecutionReceipt, ExecutionState};
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
