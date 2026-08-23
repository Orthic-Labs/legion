#![forbid(unsafe_code)]

mod error;
mod server;
mod tools;

use std::sync::Arc;

use legion_application::{NativeApplication, NativeApplicationConfig};

/// Start MCP against one explicitly composed native application. All tools
/// share this instance, so policy/provider state cannot diverge by request.
pub async fn run_with_application(application: Arc<NativeApplication>) -> std::io::Result<()> {
    server::run_stdio(Arc::new(tools::EngineAdapter::new(Arc::new(
        tools::NativeApplicationEngine::new(application),
    ))))
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
    let application = NativeApplicationConfig::from_versioned_json(&input)
        .and_then(NativeApplicationConfig::build)
        .map(Arc::new)
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "versioned native application configuration is invalid",
            )
        })?;
    run_with_application(application).await
}
