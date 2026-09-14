use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use serde_json::json;
use std::path::PathBuf;

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let action = argv.first().map(String::as_str);
    match action {
        Some("print-config") => {
            let executable = std::env::current_exe()
                .map_err(super::io_error)?
                .to_string_lossy()
                .into_owned();
            Ok(json!({
                "schemaVersion": 1,
                "kind": "legion-mcp-config",
                "transport": "stdio",
                "command": executable,
                "args": ["serve", "--stdio"],
                "tools": ["legion_m1_status", "legion_m1_invoke"],
                "implemented": true,
            }))
        }
        Some("install") if argv.iter().any(|value| value == "--preview") => Ok(json!({
            "schemaVersion": 1,
            "kind": "legion-mcp-install-preview",
            "host": "unspecified",
            "wouldWrite": "unspecified MCP client config",
            "config": mcp_install_config(),
            "dryRun": true,
        })),
        _ => Err(CommandError::usage(
            "mcp requires print-config or install --preview",
        )),
    }
}

fn mcp_install_config() -> serde_json::Value {
    let executable = std::env::current_exe()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| PathBuf::from("legion").to_string_lossy().into_owned());
    json!({
        "mcpServers": {
            "legion": {
                "command": executable,
                "args": ["serve", "--stdio"]
            }
        }
    })
}
