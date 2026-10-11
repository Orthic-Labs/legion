use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use serde_json::json;
use std::path::Path;
use tokio_util::sync::CancellationToken;

pub async fn run(args: CommonArgs, cancellation: CancellationToken) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let home = super::hooks::home_dir();
    let project = std::env::current_dir().ok();
    run_with(&argv, &home, project.as_deref(), cancellation).await
}

async fn run_with(
    argv: &[String],
    home: &Path,
    project: Option<&Path>,
    cancellation: CancellationToken,
) -> CommandResult {
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
                // True only when `legion serve` can bind a release; otherwise
                // the served server would list no tools.
                "implemented": crate::cli::serve_binding_available(),
            }))
        }
        Some("install") => install(&argv[1..], home, project, cancellation).await,
        _ => Err(CommandError::usage(
            "mcp requires print-config | install [--preview] [--client <id>] [--confirm]",
        )),
    }
}

/// `mcp install`: preview by default (`--preview`, or no `--confirm`);
/// `--confirm` registers the server through `legion setup repair`, the setup
/// registry's MCP registration. Refuses when the targeted client already has a
/// registration at another scope, naming where.
async fn install(
    argv: &[String],
    home: &Path,
    project: Option<&Path>,
    cancellation: CancellationToken,
) -> CommandResult {
    let mut client = None;
    let mut confirm = false;
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--confirm" => confirm = true,
            "--preview" | "--json" => {}
            "--client" => {
                client = Some(
                    iter.next()
                        .ok_or_else(|| CommandError::usage("--client requires a value"))?
                        .clone(),
                )
            }
            other => {
                return Err(CommandError::usage(format!(
                    "unknown mcp install argument: {other}"
                )))
            }
        }
    }
    let existing = super::hooks::mcp_registrations(home, project)
        .into_iter()
        .filter(|item| client.as_deref().map_or(true, |client| client == item.host))
        .collect::<Vec<_>>();
    let rows = existing
        .iter()
        .map(|item| json!({"host": item.host, "scope": item.scope, "path": item.path}))
        .collect::<Vec<_>>();
    // The setup registry writes user-scope entries. A plugin or project-scope
    // registration already starts the server, and a second entry would list
    // every tool twice, so install refuses instead of adding another.
    let conflicts = existing
        .iter()
        .filter(|item| item.scope != "user")
        .map(|item| {
            format!(
                "{} ({} scope: {})",
                item.host,
                item.scope,
                item.path.display()
            )
        })
        .collect::<Vec<_>>();
    if confirm && !conflicts.is_empty() {
        return Err(CommandError::usage(format!(
            "Legion MCP server is already registered at another scope: {}. Remove that registration first or use it; not adding a duplicate.",
            conflicts.join("; ")
        )));
    }
    let mut setup_argv = vec!["repair".to_owned()];
    if let Some(client) = &client {
        setup_argv.extend(["--client".into(), client.clone()]);
    }
    setup_argv.push(if confirm { "--confirm" } else { "--dry-run" }.into());
    if !confirm {
        return Ok(json!({
            "schemaVersion": 1,
            "kind": "legion-mcp-install-preview",
            "host": client.clone().unwrap_or_else(|| "all-detected".into()),
            "wouldRun": format!("legion setup {}", setup_argv.join(" ").replace("--dry-run", "--confirm")),
            "config": mcp_install_config(),
            "existingRegistrations": rows,
            "conflicts": conflicts,
            "dryRun": true,
            "note": "preview only: nothing was written. Re-run with --confirm to register.",
        }));
    }
    let result = super::fix::run_setup(setup_argv.clone(), cancellation).await?;
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-mcp-install",
        "host": client.unwrap_or_else(|| "all-detected".into()),
        "delegatedTo": format!("legion setup {}", setup_argv.join(" ")),
        "existingRegistrations": rows,
        "dryRun": false,
        "result": result,
    }))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_home() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("legion-mcp-{}", std::process::id()));
        let path = path.join(format!("{:?}", std::thread::current().id()).replace(['(', ')'], ""));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[tokio::test]
    async fn install_without_confirm_previews_and_writes_nothing() {
        let home = temp_home();
        let value = run_with(
            &["install".into(), "--client".into(), "codex".into()],
            &home,
            None,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(value["kind"], "legion-mcp-install-preview");
        assert_eq!(value["dryRun"], true);
        assert!(!home.join(".codex").exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[tokio::test]
    async fn confirm_refuses_registration_at_another_scope() {
        let home = temp_home();
        let plugin = home.join(".claude/skills/legion/.claude-plugin");
        std::fs::create_dir_all(&plugin).unwrap();
        std::fs::write(plugin.join("plugin.json"), "{}").unwrap();
        let error = run_with(
            &[
                "install".into(),
                "--client".into(),
                "claude-code".into(),
                "--confirm".into(),
            ],
            &home,
            None,
            CancellationToken::new(),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, 4);
        assert!(error.message.contains("plugin scope"), "{}", error.message);
        assert!(error.message.contains("plugin.json"), "{}", error.message);
        // The preview reports the same conflict without failing.
        let preview = run_with(
            &["install".into(), "--client".into(), "claude-code".into()],
            &home,
            None,
            CancellationToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(preview["conflicts"].as_array().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&home);
    }
}
