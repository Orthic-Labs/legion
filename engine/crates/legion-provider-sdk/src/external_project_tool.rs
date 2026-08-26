//! Typed provider seam for project-owned external tools.
//!
//! Process execution, policy evaluation, version probing, and receipt production remain owned by
//! `legion-effects`; providers only receive this injected boundary.

use async_trait::async_trait;
use legion_effects::{
    artifact::ArtifactSink,
    executor::{EffectExecutor, PolicyAuthorizer},
    platform::PlatformProcess,
};
pub use legion_effects::{
    receipt::{ExecutionReceipt, ExecutionState},
    request::ExternalToolRequest,
};
use tokio_util::sync::CancellationToken;

#[async_trait]
pub trait ExternalProjectTool: Send + Sync {
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> ExecutionReceipt;
}

#[async_trait]
impl<P, A, G> ExternalProjectTool for EffectExecutor<P, A, G>
where
    P: PlatformProcess + Send + Sync,
    A: ArtifactSink + Send + Sync,
    G: PolicyAuthorizer + Send + Sync,
{
    async fn execute(
        &self,
        request: ExternalToolRequest,
        cancellation: CancellationToken,
    ) -> ExecutionReceipt {
        self.execute_with_cancellation(&request, cancellation).await
    }
}
