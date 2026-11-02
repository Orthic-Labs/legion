#![forbid(unsafe_code)]

use std::sync::Arc;

use legion_application::NativeApplication;
use legion_mcp::{run_with_application, RejectingBindingGate};

/// Start MCP against one explicitly composed native application. All tools
/// share this instance, so policy/provider state cannot diverge by request.
async fn run_binary(application: Arc<NativeApplication>) -> std::io::Result<()> {
    // M1 release binding is supplied by the later CLI composition layer. Until
    // then the standalone binary fails closed instead of advertising tools
    // without a verified installed release identity.
    eprintln!(
        "legion-mcp: this standalone binary serves no tools without a verified release binding; \
         `legion serve --stdio` is the supported entry point"
    );
    run_with_application(
        application,
        Arc::new(RejectingBindingGate::new("legion setup repair --confirm")),
    )
    .await
}

/// Compose the application from the injected native application configuration.
/// The environment injection is a test seam that exists only in builds with
/// debug assertions and is compiled out of release builds (Orthic-Labs/legion#127).
#[cfg(debug_assertions)]
fn compose_application() -> std::io::Result<Arc<NativeApplication>> {
    use legion_application::NativeApplicationConfig;

    let input = std::env::var("LEGION_NATIVE_APPLICATION_CONFIG").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "versioned native application configuration is missing",
        )
    })?;
    NativeApplicationConfig::from_versioned_source(&input)
        .and_then(NativeApplicationConfig::build)
        .map(Arc::new)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "versioned native application configuration is invalid",
            )
        })
}

/// A release build has no injected configuration, which is the same fail-closed
/// outcome this standalone binary already reports when none is supplied.
#[cfg(not(debug_assertions))]
fn compose_application() -> std::io::Result<Arc<NativeApplication>> {
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "versioned native application configuration is missing",
    ))
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let application = compose_application()?;
    run_binary(application).await
}
