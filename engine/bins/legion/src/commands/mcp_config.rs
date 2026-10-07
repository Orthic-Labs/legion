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
            let mut tools = vec!["legion_m1_status".to_owned(), "legion_m1_invoke".to_owned()];
            tools.extend(
                crate::apple_mcp::tool_definitions()
                    .iter()
                    .filter_map(|tool| tool.get("name").and_then(serde_json::Value::as_str))
                    .map(str::to_owned),
            );
            Ok(json!({
                "schemaVersion": 1,
                "kind": "legion-mcp-config",
                "transport": "stdio",
                "command": "legion",
                "args": ["serve", "--stdio"],
                "tools": tools,
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
            "note": "preview only: nothing was written. Merge `config` into your MCP client config yourself; `legion mcp install` without --preview is not implemented.",
        })),
        _ => Err(CommandError::usage(
            "mcp requires print-config or install --preview (install without --preview is not implemented)",
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
