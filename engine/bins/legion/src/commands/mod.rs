pub mod audit;
pub mod catalog;
pub mod decision;
pub mod handoff;
pub mod host;
pub mod policy;
pub mod research;
pub mod review;
use serde_json::Value;
use std::sync::Arc;
pub type CommandResult = Result<Value, CommandError>;
pub fn native_application_for(
    repository_id: &str,
) -> Result<Arc<legion_application::NativeApplication>, CommandError> {
    if let Ok(input) = std::env::var("LEGION_NATIVE_APPLICATION_CONFIG") {
        return legion_application::NativeApplicationConfig::from_versioned_json(&input)
            .and_then(legion_application::NativeApplicationConfig::build)
            .map(Arc::new)
            .map_err(|error| {
                CommandError::incomplete(format!("native application rejected: {error}"))
            });
    }
    legion_application::NativeApplicationConfig::default_for_repository(repository_id)
        .map(Arc::new)
        .map_err(|error| CommandError::incomplete(format!("native default rejected: {error}")))
}
#[derive(Debug)]
pub struct CommandError {
    pub code: i32,
    pub message: String,
}
impl CommandError {
    pub fn usage(message: impl Into<String>) -> Self {
        Self {
            code: 4,
            message: message.into(),
        }
    }
    pub fn incomplete(message: impl Into<String>) -> Self {
        Self {
            code: 2,
            message: message.into(),
        }
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: 3,
            message: message.into(),
        }
    }
    pub fn cancelled() -> Self {
        Self {
            code: 2,
            message: "CANCELLED: task cancelled by Ctrl-C".into(),
        }
    }
    pub fn integrity(message: impl Into<String>) -> Self {
        Self {
            code: 5,
            message: message.into(),
        }
    }
    pub fn policy(message: impl Into<String>) -> Self {
        Self {
            code: 1,
            message: message.into(),
        }
    }
}
pub fn io_error(error: impl std::fmt::Display) -> CommandError {
    CommandError::internal(error.to_string())
}
