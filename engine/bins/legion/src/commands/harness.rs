use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use legion_harness::{
    capabilities_response, detect_value, install_response, list_value, matrix_value,
    uninstall_response, verify_response, HarnessError, HarnessRegistry,
};
use std::path::{Path, PathBuf};

const USAGE: &str = "Usage:
  legion harness list                         known adapters
  legion harness detect [root]                harnesses detected in a repo
  legion harness capabilities <id> [root]     declared surface fidelity
  legion harness matrix [root]                fidelity across every harness
  legion harness install <id> [root]          project skills + register surfaces
  legion harness verify <id> [root]           check an installation
  legion harness uninstall <id> [root]        remove what install wrote
";

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let sub = argv.first().map(String::as_str);
    if sub.is_none() || sub == Some("help") {
        return Ok(serde_json::json!({ "__raw": USAGE }));
    }
    let registry = HarnessRegistry::load().map_err(map_harness_error)?;
    let cwd = std::env::current_dir().map_err(super::io_error)?;
    match sub {
        Some("list") => Ok(list_value(&registry)),
        Some("detect") => {
            let root = resolve_root(argv.get(1), &cwd);
            Ok(detect_value(&registry, &root))
        }
        Some("matrix") => {
            let root = resolve_root(argv.get(1), &cwd);
            Ok(matrix_value(&registry, &root).map_err(map_harness_error)?)
        }
        Some("capabilities") => {
            let id = argv.get(1).ok_or_else(|| {
                CommandError::usage(format!(
                    "harness capabilities requires a harness id (one of {})",
                    registry.adapter_ids().join(", ")
                ))
            })?;
            let root = resolve_root(argv.get(2), &cwd);
            capabilities_response(&registry, id, &root).map_err(map_harness_error)
        }
        Some("install") => {
            let id = required_id(&registry, argv.get(1))?;
            let root = resolve_root(argv.get(2), &cwd);
            install_response(&registry, &id, &root).map_err(map_harness_error)
        }
        Some("verify") => {
            let id = required_id(&registry, argv.get(1))?;
            let root = resolve_root(argv.get(2), &cwd);
            let (value, _ok) = verify_response(&registry, &id, &root).map_err(map_harness_error)?;
            Ok(value)
        }
        Some("uninstall") => {
            let id = required_id(&registry, argv.get(1))?;
            let root = resolve_root(argv.get(2), &cwd);
            uninstall_response(&registry, &id, &root).map_err(map_harness_error)
        }
        Some(other) => Err(CommandError::usage(format!(
            "unknown harness subcommand: {other}"
        ))),
        None => Err(CommandError::usage("harness requires a subcommand")),
    }
}

fn required_id(registry: &HarnessRegistry, id: Option<&String>) -> Result<String, CommandError> {
    id.cloned().ok_or_else(|| {
        CommandError::usage(format!(
            "harness command requires a harness id (one of {})",
            registry.adapter_ids().join(", ")
        ))
    })
}

fn resolve_root(path: Option<&String>, cwd: &Path) -> PathBuf {
    path.map(|value| {
        let candidate = PathBuf::from(value);
        if candidate.is_absolute() {
            candidate
        } else {
            cwd.join(candidate)
        }
    })
    .unwrap_or_else(|| cwd.to_path_buf())
}

fn map_harness_error(error: HarnessError) -> CommandError {
    match error {
        HarnessError::Usage { message } | HarnessError::DescriptorInvalid { message } => {
            CommandError::usage(message)
        }
        HarnessError::Conflict { message } => CommandError::policy(message),
        HarnessError::Internal { message } => CommandError::incomplete(message),
    }
}
