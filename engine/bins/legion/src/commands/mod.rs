pub mod assurance;
pub mod audit;
pub mod completion;
pub mod contract;
pub mod doctor;
pub mod catalog;
pub mod init;
pub mod explain;
pub mod hooks;
pub mod minimize;
pub mod mcp_config;
pub mod fix;
pub mod governance;
pub mod harness;
pub mod authority;
pub mod bind;
pub mod budget;
pub mod decision;
pub mod handoff;
pub mod host;
pub mod host_runtime;
pub mod policy;
pub mod plan;
pub mod providers;
pub mod research;
pub mod review;
pub mod report;
pub mod rules;
pub mod run;
pub mod schedule;
pub mod script;
pub mod setup;
pub mod skills;
pub mod state;
pub mod topology;
pub mod languages;
pub mod verify;
use legion_audit::InventorySource as _;
use serde_json::Value;
use std::{path::{Path, PathBuf}, sync::Arc};
pub type CommandResult = Result<Value, CommandError>;

pub fn display_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text))
}
pub fn native_application_for(
    repository_id: &str,
) -> Result<Arc<legion_application::NativeApplication>, CommandError> {
    if let Ok(configured) = std::env::var("LEGION_NATIVE_APPLICATION_CONFIG") {
        return legion_application::NativeApplicationConfig::from_versioned_source(&configured)
            .and_then(legion_application::NativeApplicationConfig::build)
            .map(Arc::new)
            .map_err(|error| {
                CommandError::incomplete(format!("native application rejected: {error}"))
            });
    }
    Err(CommandError::incomplete(format!(
        "native application config is required for repository {repository_id}"
    )))
}
pub fn audit_signing_key() -> Result<Vec<u8>, CommandError> {
    std::env::var_os("AUDIT_PLAN_SIGNING_KEY")
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string_lossy().as_bytes().to_vec())
        .ok_or_else(|| {
            CommandError::incomplete("native audit requires host-injected AUDIT_PLAN_SIGNING_KEY")
        })
}
/// Legion's sole inventory source: a read-only local filesystem walk. Legion
/// (Rust) has no dependency on an external context engine — there is no
/// packet to consume, so there is no degraded/fallback path to report on.
pub fn audit_inventory_source(
    root: &Path,
) -> Result<Arc<legion_audit::FilesystemInventorySource>, CommandError> {
    legion_audit::FilesystemInventorySource::new(root)
        .map(Arc::new)
        .map_err(|error| CommandError::incomplete(error.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `audit_inventory_source` is Legion's sole inventory source: a local
    /// filesystem walk, with no packet, no fallback, and no degradation
    /// reporting (there is nothing external to degrade from). This
    /// replaces the retired `blueprint_degradation_is_per_dependent_provider`
    /// coverage of the removed Blueprint-packet degradation path.
    #[test]
    fn audit_inventory_source_walks_the_local_filesystem_only() {
        let root = std::env::temp_dir().join(format!(
            "legion-command-inventory-source-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::write(root.join("src/lib.rs"), "fn one() {}\n").unwrap();
        let root = std::fs::canonicalize(root).unwrap();

        let source = audit_inventory_source(&root).unwrap();
        let inventory = source.inventory(&root.to_string_lossy()).unwrap();
        assert_eq!(inventory.paths().collect::<Vec<_>>(), ["src/lib.rs"]);
        assert!(inventory.generation.starts_with("filesystem:sha256:"));

        std::fs::remove_dir_all(root).unwrap();
    }
}
