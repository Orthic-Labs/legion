use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// `legion hooks status|install|remove`: host-registered Legion hooks.
///
/// `status` reads the same host config files `legion doctor` reads. `install`
/// and `remove` delegate to the setup registry (`legion setup repair|remove`),
/// the only code that registers Legion hooks in a host: Devin hook entries are
/// written by the registry itself, Claude Code and Codex hooks ship inside the
/// plugin projection the same lifecycle installs. Mutation needs `--confirm`;
/// without it the command previews through `setup --dry-run`.
pub async fn run(args: CommonArgs, cancellation: CancellationToken) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let home = home_dir();
    run_with(&argv, &home, cancellation).await
}

pub(super) async fn run_with(
    argv: &[String],
    home: &Path,
    cancellation: CancellationToken,
) -> CommandResult {
    let usage = "hooks requires status | install [--client <id>] [--confirm] | remove [--client <id>] [--confirm]";
    let Some(action) = argv.first().map(String::as_str) else {
        return Err(CommandError::usage(usage));
    };
    let options = parse_options(&argv[1..])?;
    match action {
        "status" => {
            if options.confirm {
                return Err(CommandError::usage("hooks status does not take --confirm"));
            }
            Ok(status_value(home, options.client.as_deref()))
        }
        "install" | "remove" => {
            let setup_action = if action == "install" {
                "repair"
            } else {
                "remove"
            };
            let mut setup_argv = vec![setup_action.to_owned()];
            if let Some(client) = &options.client {
                setup_argv.extend(["--client".into(), client.clone()]);
            }
            if options.confirm {
                setup_argv.push("--confirm".into());
            } else {
                setup_argv.push("--dry-run".into());
            }
            let result = super::fix::run_setup(setup_argv.clone(), cancellation).await?;
            Ok(json!({
                "schemaVersion": 1,
                "kind": "legion-hooks-lifecycle",
                "action": action,
                "dryRun": !options.confirm,
                "delegatedTo": format!("legion setup {}", setup_argv.join(" ")),
                "scope": "setup registry client lifecycle: hooks are registered together with the client's projection and MCP entry",
                "result": result,
                "hosts": hook_registrations(home),
            }))
        }
        _ => Err(CommandError::usage(usage)),
    }
}

struct Options {
    client: Option<String>,
    confirm: bool,
}

fn parse_options(argv: &[String]) -> Result<Options, CommandError> {
    let mut options = Options {
        client: None,
        confirm: false,
    };
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--confirm" => options.confirm = true,
            "--client" => {
                options.client = Some(
                    iter.next()
                        .ok_or_else(|| CommandError::usage("--client requires a value"))?
                        .clone(),
                )
            }
            "--json" => {}
            other => {
                return Err(CommandError::usage(format!(
                    "unknown hooks argument: {other}"
                )))
            }
        }
    }
    Ok(options)
}

fn status_value(home: &Path, client: Option<&str>) -> Value {
    let hosts = hook_registrations(home)
        .into_iter()
        .filter(|row| client.map_or(true, |client| row["host"] == client))
        .collect::<Vec<_>>();
    let registered = hosts.iter().any(|row| row["registered"] == true);
    json!({
        "schemaVersion": 1,
        "kind": "legion-hooks-status",
        "registered": registered,
        "hosts": hosts,
    })
}

pub(super) fn home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&std::fs::read(path).ok()?).ok()
}

pub(super) fn devin_config_root(home: &Path) -> PathBuf {
    if cfg!(windows) {
        home.join("AppData").join("Roaming").join("devin")
    } else {
        home.join(".config").join("devin")
    }
}

fn row(host: &str, sources: Vec<Value>) -> Value {
    json!({
        "host": host,
        "registered": !sources.is_empty(),
        "sources": sources,
    })
}

/// One row per host that can carry Legion hooks. A host is registered when a
/// host config file it owns references Legion's hooks.
pub(super) fn hook_registrations(home: &Path) -> Vec<Value> {
    let mut claude = Vec::new();
    let settings = home.join(".claude").join("settings.json");
    if read_json(&settings)
        .and_then(|value| value.get("hooks").cloned())
        .is_some_and(|hooks| hooks.to_string().contains("legion"))
    {
        claude.push(json!({"scope": "user-settings", "path": settings}));
    }
    let plugin_hooks = home
        .join(".claude")
        .join("skills")
        .join("legion")
        .join("hooks")
        .join("hooks.json");
    if plugin_hooks.is_file() {
        claude.push(json!({"scope": "skills-dir-plugin", "path": plugin_hooks}));
    }
    let installed = home
        .join(".claude")
        .join("plugins")
        .join("installed_plugins.json");
    if read_json(&installed).is_some_and(|value| {
        value
            .get("plugins")
            .and_then(Value::as_object)
            .is_some_and(|plugins| plugins.keys().any(|key| key.starts_with("legion@")))
    }) {
        claude.push(json!({"scope": "installed-plugin", "path": installed}));
    }

    let mut codex = Vec::new();
    let codex_config = home.join(".codex").join("config.toml");
    if let Some(value) = std::fs::read_to_string(&codex_config)
        .ok()
        .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
    {
        let registered = value
            .get("hooks")
            .and_then(|hooks| hooks.get("state"))
            .and_then(toml::Value::as_table)
            .is_some_and(|state| {
                state.iter().any(|(key, entry)| {
                    let lowered = key.to_ascii_lowercase();
                    (lowered.starts_with("legion@") || lowered.contains("/legion/"))
                        && entry.get("enabled").and_then(toml::Value::as_bool) != Some(false)
                })
            });
        if registered {
            codex.push(json!({"scope": "user-config", "path": codex_config}));
        }
    }

    let mut devin = Vec::new();
    let devin_config = devin_config_root(home).join("config.json");
    if read_json(&devin_config)
        .and_then(|value| value.get("hooks").cloned())
        .is_some_and(|hooks| hooks.to_string().contains("legion-hook"))
    {
        devin.push(json!({"scope": "user-config", "path": devin_config}));
    }

    vec![
        row("claude-code", claude),
        row("codex", codex),
        row("devin", devin),
    ]
}

/// A Legion MCP server entry found in a host config.
pub(super) struct McpRegistration {
    pub(super) host: &'static str,
    pub(super) scope: &'static str,
    pub(super) path: PathBuf,
}

/// Every place a Legion MCP server is registered, across hosts and scopes.
pub(super) fn mcp_registrations(home: &Path, project_root: Option<&Path>) -> Vec<McpRegistration> {
    let mut found = Vec::new();
    let has_server = |path: &Path| {
        read_json(path)
            .and_then(|value| {
                value
                    .get("mcpServers")
                    .and_then(|s| s.get("legion"))
                    .cloned()
            })
            .is_some()
    };
    let user = home.join(".claude.json");
    if has_server(&user) {
        found.push(McpRegistration {
            host: "claude-code",
            scope: "user",
            path: user,
        });
    }
    if let Some(root) = project_root {
        let project = root.join(".mcp.json");
        if has_server(&project) {
            found.push(McpRegistration {
                host: "claude-code",
                scope: "project",
                path: project,
            });
        }
    }
    let skills_plugin = home
        .join(".claude")
        .join("skills")
        .join("legion")
        .join(".claude-plugin")
        .join("plugin.json");
    if skills_plugin.is_file() {
        found.push(McpRegistration {
            host: "claude-code",
            scope: "plugin",
            path: skills_plugin,
        });
    }
    let installed = home
        .join(".claude")
        .join("plugins")
        .join("installed_plugins.json");
    if read_json(&installed).is_some_and(|value| {
        value
            .get("plugins")
            .and_then(Value::as_object)
            .is_some_and(|plugins| plugins.keys().any(|key| key.starts_with("legion@")))
    }) {
        found.push(McpRegistration {
            host: "claude-code",
            scope: "plugin",
            path: installed,
        });
    }
    let codex = home.join(".codex").join("config.toml");
    if std::fs::read_to_string(&codex)
        .ok()
        .and_then(|text| toml::from_str::<toml::Value>(&text).ok())
        .and_then(|value| {
            value
                .get("mcp_servers")
                .and_then(toml::Value::as_table)
                .cloned()
        })
        .is_some_and(|servers| servers.contains_key("legion"))
    {
        found.push(McpRegistration {
            host: "codex",
            scope: "user",
            path: codex,
        });
    }
    let devin = devin_config_root(home).join("mcp_config.json");
    if has_server(&devin) {
        found.push(McpRegistration {
            host: "devin",
            scope: "user",
            path: devin,
        });
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    pub(crate) fn temp_home(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "legion-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn status_reads_host_configs_without_writing() {
        let home = temp_home("hooks-status");
        let empty = status_value(&home, None);
        assert_eq!(empty["registered"], false);
        assert_eq!(empty["hosts"].as_array().unwrap().len(), 3);

        let devin = devin_config_root(&home);
        std::fs::create_dir_all(&devin).unwrap();
        std::fs::write(
            devin.join("config.json"),
            r#"{"hooks":{"PreToolUse":[{"hooks":[{"command":"/x/legion-hook"}]}]}}"#,
        )
        .unwrap();
        let after = status_value(&home, None);
        assert_eq!(after["registered"], true);
        let hosts = after["hosts"].as_array().unwrap();
        assert_eq!(
            hosts.iter().find(|row| row["host"] == "devin").unwrap()["registered"],
            true
        );
        assert_eq!(
            hosts.iter().find(|row| row["host"] == "codex").unwrap()["registered"],
            false
        );
        let filtered = status_value(&home, Some("codex"));
        assert_eq!(filtered["hosts"].as_array().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn mcp_registrations_report_each_scope() {
        let home = temp_home("mcp-scopes");
        std::fs::write(
            home.join(".claude.json"),
            r#"{"mcpServers":{"legion":{"command":"legion"}}}"#,
        )
        .unwrap();
        let project = temp_home("mcp-project");
        std::fs::write(
            project.join(".mcp.json"),
            r#"{"mcpServers":{"legion":{"command":"legion"}}}"#,
        )
        .unwrap();
        let found = mcp_registrations(&home, Some(&project));
        let scopes = found.iter().map(|item| item.scope).collect::<Vec<_>>();
        assert_eq!(scopes, vec!["user", "project"]);
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&project);
    }

    #[test]
    fn unknown_action_and_flags_are_usage_errors() {
        assert!(parse_options(&["--bogus".into()]).is_err());
        assert!(parse_options(&["--client".into()]).is_err());
        let parsed =
            parse_options(&["--client".into(), "devin".into(), "--confirm".into()]).unwrap();
        assert!(parsed.confirm);
        assert_eq!(parsed.client.as_deref(), Some("devin"));
    }
}
