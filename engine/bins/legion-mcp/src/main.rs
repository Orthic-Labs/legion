#![forbid(unsafe_code)]

use std::sync::Arc;

use legion_application::{NativeApplication, NativeApplicationConfig};
use legion_mcp::{run_with_application, RejectingBindingGate};

/// Start MCP against one explicitly composed native application. All tools
/// share this instance, so policy/provider state cannot diverge by request.
async fn run_binary(application: Arc<NativeApplication>) -> std::io::Result<()> {
    // M1 release binding is supplied by the later CLI composition layer. Until
    // then the standalone binary fails closed instead of advertising tools
    // without a verified installed release identity.
    run_with_application(
        application,
        Arc::new(RejectingBindingGate::new("legion setup --repair")),
    )
    .await
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let input = std::env::var("LEGION_NATIVE_APPLICATION_CONFIG").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "versioned native application configuration is missing",
        )
    })?;
    let application = NativeApplicationConfig::from_versioned_source(&input)
        .and_then(NativeApplicationConfig::build)
        .map(Arc::new)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "versioned native application configuration is invalid",
            )
        })?;
    run_binary(application).await
}
