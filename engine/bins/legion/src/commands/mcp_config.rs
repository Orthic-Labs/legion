use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use serde_json::json;

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let action = argv.first().map(String::as_str);
    match action {
        Some("print-config") => {
            Ok(json!({
                "schemaVersion": 1,
                "kind": "legion-mcp-config",
                "transport": "stdio",
                "command": "legion",
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
    json!({
        "mcpServers": {
            "legion": {
                "command": "legion",
                "args": ["serve", "--stdio"]
            }
        }
    })
}
