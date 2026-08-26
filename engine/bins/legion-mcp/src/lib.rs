#![forbid(unsafe_code)]

//! Reusable, client-owned stdio MCP transport for the native Legion API.
//!
//! The transport deliberately owns neither release verification nor application
//! composition. Callers provide both through stable traits, allowing the CLI
//! and installed integrations to share one API instance for their full session.

mod error;
mod server;
mod tools;

use std::sync::Arc;

use legion_application::NativeApplication;

pub use error::McpError;
pub use server::{
    run_stdio, BindingFailure, RejectingBindingGate, ReleaseBindingGate, Server,
    VerifiedReleaseBinding,
};
pub use tools::{
    EngineAdapter, NativeApi, NativeApplicationEngine, NativeEngine, NativeFuture, ToolService,
};

/// Start the MCP transport over one already-composed native application.
///
/// The caller owns release verification through `binding_gate`; this library
/// only gates MCP initialization and never opens a listener or spawns a child
/// process.
pub async fn run_with_application<G>(
    application: Arc<NativeApplication>,
    binding_gate: Arc<G>,
) -> std::io::Result<()>
where
    G: ReleaseBindingGate + 'static,
{
    let engine = Arc::new(NativeApplicationEngine::new(application));
    run_stdio(Arc::new(EngineAdapter::new(engine)), binding_gate).await
}

/// Start MCP with one explicitly bound repository identity for installed use.
pub async fn run_with_repository_application<G>(
    application: Arc<NativeApplication>,
    repository_id: impl Into<String>,
    binding_gate: Arc<G>,
) -> std::io::Result<()>
where
    G: ReleaseBindingGate + 'static,
{
    let engine = Arc::new(NativeApplicationEngine::for_repository(
        application,
        repository_id,
    ));
    run_stdio(Arc::new(EngineAdapter::new(engine)), binding_gate).await
}
