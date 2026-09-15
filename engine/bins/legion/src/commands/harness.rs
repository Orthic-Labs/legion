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
            let mut value = install_response(&registry, &id, &root).map_err(map_harness_error)?;
            reorder_surfaces(&mut value);
            relativize_skill_target(&mut value, &root);
            Ok(value)
        }
        Some("verify") => {
            let id = required_id(&registry, argv.get(1))?;
            let root = resolve_root(argv.get(2), &cwd);
            let (mut value, _ok) = verify_response(&registry, &id, &root).map_err(map_harness_error)?;
            // Node emits surfaces in descriptor order. The registry's
            // internal map is sorted for deterministic lookup, so restore
            // wire order at this boundary.
            reorder_surfaces(&mut value);
            Ok(value)
        }
        Some("uninstall") => {
            let id = required_id(&registry, argv.get(1))?;
            let root = resolve_root(argv.get(2), &cwd);
            uninstall_response(&registry, &id, &root).map_err(map_harness_error)
        }
        Some(other) => Err(CommandError::usage(format!(
            "harness {other} requires a harness id (one of {})",
            registry.adapter_ids().join(", ")
        ))),
        None => Err(CommandError::usage("harness requires a subcommand")),
    }
}

fn reorder_surfaces(value: &mut serde_json::Value) {
    let Some(surfaces) = value.get_mut("surfaces").and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    let existing = std::mem::take(surfaces);
    let mut ordered = serde_json::Map::new();
    for name in ["instructions", "skills", "agents", "mcp", "hooks"] {
        if let Some(surface) = existing.get(name) {
            ordered.insert(name.to_owned(), surface.clone());
        }
    }
    for (name, surface) in existing {
        ordered.entry(name).or_insert(surface);
    }
    *surfaces = ordered;
}

fn relativize_skill_target(value: &mut serde_json::Value, root: &Path) {
    let Some(target) = value.pointer_mut("/surfaces/skills/skills/targetDir") else {
        return;
    };
    let Some(path) = target.as_str() else { return; };
    if let Ok(relative) = Path::new(path).strip_prefix(root) {
        *target = serde_json::Value::String(relative.to_string_lossy().replace('/', "\\"));
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
