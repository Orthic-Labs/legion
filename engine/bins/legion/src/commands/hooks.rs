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
/// written by the registry itself; Claude Code and Codex hooks ship inside the
/// native plugin each lifecycle installs. Codex still requires user trust for
/// bundled hooks, and the shipped Codex events do not provide pre-tool gating.
/// Mutation needs `--confirm`;
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
                )));
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
        "registrationMeaning": "host configuration references only; not proof of enforcement",
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

/// Inspect projected commands only. File presence and trust records cannot
/// establish that a host trusted or delivered an event.
fn projected_legion_events(config: &Value) -> Option<Vec<String>> {
    fn contains_hook(value: &Value) -> bool {
        match value {
            Value::Object(fields) => {
                fields
                    .get("command")
                    .and_then(Value::as_str)
                    .is_some_and(|command| command.contains("legion-hook"))
                    || fields.values().any(contains_hook)
            }
            Value::Array(values) => values.iter().any(contains_hook),
            _ => false,
        }
    }
    Some(
        config
            .get("hooks")?
            .as_object()?
            .iter()
            .filter(|(_, handlers)| contains_hook(handlers))
            .map(|(event, _)| event.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect(),
    )
}

fn enforcement_facts(
    supported_events: Option<&[&str]>,
    projected_events: Option<Vec<String>>,
    pre_effect_supported: Option<bool>,
    scope: &str,
) -> Value {
    json!({
        "supportedEvents": supported_events,
        "supportedEventsScope": "shipped host projection; not all parser-accepted events",
        "projectedEvents": projected_events,
        "projectedEventsScope": "inspected hook files only",
        "preEffectInterception": {
            "supported": pre_effect_supported,
            "observed": "unknown",
        },
        "hostTrust": "unknown",
        "eventDelivery": "unknown",
        "activeRoleAuthentication": "unavailable",
        "scope": scope,
    })
}

fn codex_plugin_hooks_path(plugin: &Path) -> Option<PathBuf> {
    let manifest = read_json(&plugin.join("plugin.json"))?;
    let declared = manifest.pointer("/extensions/com.openai/hooks")?.as_str()?;
    let relative = Path::new(declared.strip_prefix("./").unwrap_or(declared));
    if relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    Some(plugin.join(relative))
}

/// One row per host that can carry Legion hooks. A host is registered when a
/// host config file it owns references Legion's hooks.
pub(super) fn hook_registrations(home: &Path) -> Vec<Value> {
    let codex_home = std::env::var_os("CODEX_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".codex"));
    hook_registrations_with_codex_home(home, &codex_home)
}

fn hook_registrations_with_codex_home(home: &Path, codex_home: &Path) -> Vec<Value> {
    let mut claude = Vec::new();
    let claude_config = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| home.join(".claude"));
    let settings = claude_config.join("settings.json");
    let claude_settings = read_json(&settings);
    if claude_settings
        .as_ref()
        .and_then(|value| value.get("hooks"))
        .is_some_and(|hooks| hooks.to_string().contains("legion"))
    {
        claude.push(json!({"scope": "user-settings", "path": settings}));
    }
    let plugin_hooks = claude_config
        .join("skills")
        .join("legion")
        .join("hooks")
        .join("hooks.json");
    if plugin_hooks.is_file() {
        claude.push(json!({"scope": "skills-dir-plugin", "path": &plugin_hooks}));
    }
    let installed = claude_config.join("plugins/installed_plugins.json");
    if read_json(&installed).is_some_and(|value| {
        value
            .get("plugins")
            .and_then(Value::as_object)
            .is_some_and(|plugins| plugins.keys().any(|key| key.starts_with("legion@")))
    }) {
        claude.push(json!({"scope": "installed-plugin", "path": installed}));
    }

    let codex_config = codex_home.join("config.toml");
    let codex_lookup = legion_host::find_codex_plugin_cache(&codex_config, &codex_home);
    let (codex_cache_state, codex_plugin) = match &codex_lookup {
        Ok(legion_host::CodexCacheLookup::NotConfigured) => ("not-configured", None),
        Ok(legion_host::CodexCacheLookup::Missing) => ("missing", None),
        Ok(legion_host::CodexCacheLookup::Found(path)) => ("found", Some(path.as_path())),
        Ok(legion_host::CodexCacheLookup::Ambiguous(_)) => ("ambiguous", None),
        Err(_) => ("incomplete", None),
    };
    let codex_hooks = codex_plugin.and_then(codex_plugin_hooks_path);
    let hook_state_prefix = codex_hooks
        .as_ref()
        .and_then(|path| codex_plugin.and_then(|root| path.strip_prefix(root).ok()))
        .map(|path| {
            format!(
                "legion@legion-installed:{}:",
                path.to_string_lossy().replace('\\', "/")
            )
        });
    let codex_config_value = std::fs::read_to_string(&codex_config)
        .ok()
        .and_then(|text| toml::from_str::<toml::Value>(&text).ok());
    let plugin_enabled = codex_config_value
        .as_ref()
        .and_then(|value| value.get("plugins"))
        .and_then(|value| value.get("legion@legion-installed"))
        .and_then(|value| value.get("enabled"))
        .and_then(toml::Value::as_bool);
    let hook_state = codex_config_value
        .as_ref()
        .and_then(|value| value.get("hooks"))
        .and_then(|value| value.get("state"))
        .and_then(toml::Value::as_table);
    let active_entries = hook_state
        .into_iter()
        .flat_map(|state| state.iter())
        .filter(|(key, entry)| {
            hook_state_prefix.as_ref().is_some_and(|prefix| {
                key.to_ascii_lowercase()
                    .starts_with(&prefix.to_ascii_lowercase())
            }) && entry.get("enabled").and_then(toml::Value::as_bool) != Some(false)
        })
        .collect::<Vec<_>>();
    let trust_recorded = active_entries.iter().any(|(_, entry)| {
        entry
            .get("trusted_hash")
            .and_then(toml::Value::as_str)
            .and_then(|hash| hash.strip_prefix("sha256:"))
            .is_some_and(|hash| {
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    });
    let plugin_installed = codex_plugin.is_some();
    let codex_hooks_present = codex_hooks.as_ref().is_some_and(|path| path.is_file());
    let codex_sources = if plugin_installed || codex_config_value.is_some() {
        vec![json!({
            "scope": "native-plugin-cache",
            "path": codex_plugin.map(Path::to_path_buf),
            "cacheLookup": codex_cache_state,
            "cacheLookupError": codex_lookup.as_ref().err(),
            "hooksPath": codex_hooks.clone(),
            "pluginInstalled": plugin_installed,
            "pluginEnabled": plugin_enabled,
            "hooksPresent": codex_hooks_present,
            "registeredHookCount": active_entries.len(),
            "trustRecorded": trust_recorded,
            "trustState": if trust_recorded { "recorded" } else { "not-recorded" },
        })]
    } else {
        Vec::new()
    };
    let codex_registered = !active_entries.is_empty() && plugin_enabled != Some(false);

    let mut devin = Vec::new();
    let devin_config = devin_config_root(home).join("config.json");
    let devin_settings = read_json(&devin_config);
    if devin_settings
        .as_ref()
        .and_then(|value| value.get("hooks"))
        .is_some_and(|hooks| hooks.to_string().contains("legion-hook"))
    {
        devin.push(json!({"scope": "user-config", "path": devin_config}));
    }

    let claude_projections = [claude_settings, read_json(&plugin_hooks)]
        .iter()
        .filter_map(|config| config.as_ref().and_then(projected_legion_events))
        .collect::<Vec<_>>();
    let claude_events = (!claude_projections.is_empty()).then(|| {
        claude_projections
            .into_iter()
            .flatten()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    });
    let mut claude_row = row("claude-code", claude);
    claude_row["enforcement"] = enforcement_facts(
        Some(&[
            "SessionStart",
            "SubagentStart",
            "SubagentStop",
            "UserPromptSubmit",
            "PostCompact",
            "PreToolUse",
            "PostToolUse",
            "PostToolUseFailure",
            "Stop",
        ]),
        claude_events,
        Some(true),
        "Legion's Claude hook projection supports matched pre-tool events; registration does not prove host trust or delivery",
    );
    let codex_events = codex_hooks
        .as_ref()
        .and_then(|path| read_json(path))
        .as_ref()
        .and_then(projected_legion_events);
    let codex_enforcement = enforcement_facts(
        Some(&["UserPromptSubmit", "Stop"]),
        codex_events,
        Some(false),
        "Legion's Codex projection covers prompt submission and stop only; no pre-effect interception",
    );
    let mut devin_row = row("devin", devin);
    devin_row["enforcement"] = enforcement_facts(
        None,
        devin_settings.as_ref().and_then(projected_legion_events),
        None,
        "Configured Legion handlers only; host event support is unverified",
    );
    vec![
        claude_row,
        json!({"host":"codex","registered":codex_registered,"sources":codex_sources,"enforcement":codex_enforcement}),
        devin_row,
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
        let devin = hosts.iter().find(|row| row["host"] == "devin").unwrap();
        assert_eq!(
            devin["enforcement"]["projectedEvents"],
            json!(["PreToolUse"])
        );
        assert_eq!(devin["enforcement"]["supportedEvents"], Value::Null);
        assert_eq!(
            devin["enforcement"]["preEffectInterception"]["supported"],
            Value::Null
        );
        assert_eq!(devin["enforcement"]["eventDelivery"], "unknown");
        assert_eq!(
            hosts.iter().find(|row| row["host"] == "codex").unwrap()["registered"],
            false
        );
        let filtered = status_value(&home, Some("codex"));
        assert_eq!(filtered["hosts"].as_array().unwrap().len(), 1);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn codex_hook_status_reports_native_cache_and_host_trust() {
        let home = temp_home("codex-native-hooks");
        let codex = home.join(".codex");
        let plugin = codex.join("plugins/cache/legion-installed/legion/1.0.0");
        std::fs::create_dir_all(plugin.join("hooks")).unwrap();
        std::fs::create_dir_all(plugin.join(".codex-plugin")).unwrap();
        std::fs::write(
            plugin.join(".codex-plugin/plugin.json"),
            r#"{"name":"legion","version":"1.0.0"}"#,
        )
        .unwrap();
        std::fs::write(
            plugin.join("plugin.json"),
            r#"{"name":"legion","extensions":{"com.openai":{"hooks":"./hooks/codex-hooks.json"}}}"#,
        )
        .unwrap();
        std::fs::write(
            plugin.join("hooks/codex-hooks.json"),
            r#"{"hooks":{"UserPromptSubmit":[{"hooks":[{"command":"legion-hook --host codex --event UserPromptSubmit"}]}],"Stop":[{"hooks":[{"command":"legion-hook --host codex --event Stop"}]}]}}"#,
        )
        .unwrap();
        std::fs::write(
            codex.join("config.toml"),
            "[plugins.\"legion@legion-installed\"]\nenabled = true\n",
        )
        .unwrap();
        let row = hook_registrations_with_codex_home(&home, &codex)
            .into_iter()
            .find(|row| row["host"] == "codex")
            .unwrap();
        assert_eq!(row["registered"], false);
        let source = &row["sources"][0];
        assert_eq!(source["pluginInstalled"], true);
        assert_eq!(source["pluginEnabled"], true);
        assert_eq!(source["cacheLookup"], "found");
        assert_eq!(source["hooksPresent"], true);
        let selected_hooks = PathBuf::from(source["hooksPath"].as_str().unwrap());
        assert_eq!(selected_hooks, plugin.join("hooks/codex-hooks.json"));
        assert_eq!(source["trustState"], "not-recorded");
        assert_eq!(
            row["enforcement"]["supportedEvents"],
            json!(["UserPromptSubmit", "Stop"])
        );
        assert_eq!(
            row["enforcement"]["projectedEvents"],
            json!(["Stop", "UserPromptSubmit"])
        );
        assert_eq!(
            row["enforcement"]["preEffectInterception"]["supported"],
            false
        );
        assert_eq!(
            row["enforcement"]["activeRoleAuthentication"],
            "unavailable"
        );
        assert_eq!(row["enforcement"]["hostTrust"], "unknown");
        assert_eq!(row["enforcement"]["eventDelivery"], "unknown");

        let hash = format!("sha256:{}", "a".repeat(64));
        std::fs::write(
            codex.join("config.toml"),
            format!(
                "[plugins.\"legion@legion-installed\"]\nenabled = false\n\n[hooks.state.\"legion@legion-installed:hooks/codex-hooks.json:Stop:0:0\"]\ntrusted_hash = \"{hash}\"\n\n[hooks.state.\"legion@legion-installed:hooks/codex-hooks.json:UserPromptSubmit:0:0\"]\ntrusted_hash = \"{hash}\"\n"
            ),
        )
        .unwrap();
        let row = hook_registrations_with_codex_home(&home, &codex)
            .into_iter()
            .find(|row| row["host"] == "codex")
            .unwrap();
        assert_eq!(row["registered"], false);
        assert_eq!(row["sources"][0]["pluginEnabled"], false);
        assert_eq!(row["sources"][0]["trustState"], "recorded");
        assert_eq!(row["enforcement"]["hostTrust"], "unknown");
        assert_eq!(
            row["enforcement"]["preEffectInterception"]["observed"],
            "unknown"
        );

        let stale = codex.join("plugins/cache/legion-installed/legion/0.9.0");
        std::fs::create_dir_all(stale.join(".codex-plugin")).unwrap();
        std::fs::write(
            stale.join(".codex-plugin/plugin.json"),
            r#"{"name":"legion","version":"0.9.0"}"#,
        )
        .unwrap();
        let row = hook_registrations_with_codex_home(&home, &codex)
            .into_iter()
            .find(|row| row["host"] == "codex")
            .unwrap();
        assert_eq!(row["registered"], false);
        assert_eq!(row["sources"][0]["cacheLookup"], "ambiguous");
        assert_eq!(row["sources"][0]["hooksPath"], Value::Null);
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn hook_projection_facts_do_not_promote_registration_to_protection() {
        let home = temp_home("hook-boundaries");
        for host in hook_registrations_with_codex_home(&home, &home.join(".codex")) {
            assert_eq!(
                host["enforcement"]["activeRoleAuthentication"],
                "unavailable"
            );
            assert_eq!(host["enforcement"]["hostTrust"], "unknown");
            assert_eq!(host["enforcement"]["eventDelivery"], "unknown");
            assert_eq!(
                host["enforcement"]["preEffectInterception"]["observed"],
                "unknown"
            );
            if host["host"] == "claude-code" {
                assert_eq!(
                    host["enforcement"]["preEffectInterception"]["supported"],
                    true
                );
                assert!(host["enforcement"]["supportedEvents"]
                    .as_array()
                    .unwrap()
                    .contains(&json!("PreToolUse")));
            }
        }
        assert_eq!(projected_legion_events(&json!({})), None);
        assert_eq!(
            projected_legion_events(&json!({"hooks": {
                "PreToolUse": [{"hooks": [{"command": "unrelated-hook"}]}],
                "Stop": [{"hooks": [{"command": "legion-hook"}]}]
            }})),
            Some(vec!["Stop".into()]),
        );
        let _ = std::fs::remove_dir_all(home);
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
