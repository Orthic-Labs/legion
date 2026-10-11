use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tokio_util::sync::CancellationToken;

/// `legion fix`: classify what Legion can repair and, with `--apply`, run the
/// existing applier for each class. The default is a dry-run listing.
///
/// Every applier is existing machinery (`legion setup repair --confirm`);
/// classes without one are listed as `manual` with the command to run. With
/// `--plan <file>` the command validates a sealed remediation plan instead;
/// applying such a plan stays with the Alchemist and is reported as manual.
pub async fn run(args: CommonArgs, cancellation: CancellationToken) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if argv.iter().any(|value| value == "--help") {
        return Ok(json!({
            "__raw": "Usage: legion fix [--apply] [--class <id>] [--client <id>]\n       legion fix --plan <sealed-remediation-plan> [--apply]\nDry-run by default: lists fix classes and their appliers. --apply runs each existing applier (`legion setup repair --confirm`). Classes without an applier are listed as manual. --plan validates a sealed remediation plan; applying it is manual (Alchemist).\n--json is accepted for compatibility; output is always JSON.\n"
        }));
    }
    let options = parse_fix_options(&argv)?;
    if let Some(plan_path) = options.plan.clone() {
        return plan_mode(&plan_path, options.apply);
    }
    let home = super::hooks::home_dir();
    let project = std::env::current_dir().ok();
    let classes = fix_classes(&home, project.as_deref(), options.client.as_deref());
    if let Some(class) = &options.class {
        if !classes.iter().any(|item| item.id == class.as_str()) {
            return Err(CommandError::usage(format!(
                "unknown fix class {class}; known: {}",
                classes
                    .iter()
                    .map(|item| item.id)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
    }
    let selected = select_actions(&classes, options.apply, options.class.as_deref());
    let mut outcomes = serde_json::Map::new();
    let mut mutated = false;
    let mut failed = false;
    for index in &selected {
        let class = &classes[*index];
        let argv = class.applier.clone().unwrap_or_default();
        match run_setup(argv, cancellation.clone()).await {
            Ok(result) => {
                // The applier ran, so it may have changed state; but a setup
                // result reporting failure is not an applied class.
                mutated = true;
                let setup_status = result.get("status").cloned();
                let setup_failed = matches!(
                    setup_status.as_ref().and_then(Value::as_str),
                    Some("failed" | "fail" | "unavailable" | "incomplete" | "partial" | "denied")
                );
                if setup_failed {
                    failed = true;
                    outcomes.insert(
                        class.id.into(),
                        json!({"status": "failed", "setupStatus": setup_status}),
                    );
                } else {
                    outcomes.insert(
                        class.id.into(),
                        json!({"status": "applied", "setupStatus": setup_status}),
                    );
                }
            }
            Err(error) => {
                failed = true;
                outcomes.insert(
                    class.id.into(),
                    json!({"status": "failed", "error": error.message}),
                );
            }
        }
    }
    let rows = classes
        .iter()
        .enumerate()
        .map(|(index, class)| {
            let applied = outcomes.get(class.id).cloned();
            let status = match (&applied, class.applier.is_some(), class.detected) {
                (Some(outcome), _, _) => outcome["status"].as_str().unwrap_or("failed").to_owned(),
                (None, false, _) => "manual".to_owned(),
                (None, true, Some(false)) => "not-detected".to_owned(),
                (None, true, _) if options.apply && !selected.contains(&index) => {
                    "skipped".to_owned()
                }
                (None, true, _) => "planned".to_owned(),
            };
            json!({
                "id": class.id,
                "description": class.description,
                "detected": class.detected,
                "evidence": class.evidence,
                "status": status,
                "applier": class.applier.as_ref().map(|argv| format!("legion setup {}", argv.join(" "))),
                "coveredBy": class.covered_by,
                "manual": class.manual,
                "outcome": applied,
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schemaVersion": 1,
        "kind": "legion-fix",
        "dryRun": !options.apply,
        "status": if failed {
            "failed"
        } else if !options.apply {
            "dry-run"
        } else if mutated {
            "applied"
        } else {
            "nothing-to-apply"
        },
        "mutationApplied": mutated,
        "classes": rows,
    }))
}

struct FixOptions {
    apply: bool,
    class: Option<String>,
    client: Option<String>,
    plan: Option<PathBuf>,
}

fn parse_fix_options(argv: &[String]) -> Result<FixOptions, CommandError> {
    let mut options = FixOptions {
        apply: false,
        class: None,
        client: None,
        plan: None,
    };
    let mut iter = argv.iter();
    while let Some(arg) = iter.next() {
        let mut value = |name: &str| {
            iter.next()
                .cloned()
                .ok_or_else(|| CommandError::usage(format!("{name} requires a value")))
        };
        match arg.as_str() {
            "--apply" => options.apply = true,
            // Output is always JSON; the flag is accepted and changes nothing.
            "--json" => {}
            "--class" => options.class = Some(value("--class")?),
            "--client" => options.client = Some(value("--client")?),
            "--plan" => options.plan = Some(PathBuf::from(value("--plan")?)),
            other => {
                return Err(CommandError::usage(format!(
                    "unknown fix argument: {other}"
                )))
            }
        }
    }
    if options.plan.is_some() && (options.class.is_some() || options.client.is_some()) {
        return Err(CommandError::usage(
            "fix --plan cannot be combined with --class or --client",
        ));
    }
    Ok(options)
}

fn plan_mode(plan_path: &Path, apply: bool) -> CommandResult {
    let bytes = std::fs::read(plan_path)
        .map_err(|error| CommandError::usage(format!("cannot read remediation plan: {error}")))?;
    let plan: Value = serde_json::from_slice(&bytes)
        .map_err(|error| CommandError::usage(format!("invalid remediation plan: {error}")))?;
    validate_remediation_plan(&plan)?;
    let action_count = plan
        .get("actions")
        .and_then(Value::as_array)
        .map(|actions| actions.len())
        .unwrap_or(0);
    let plan_digest = plan
        .get("planDigest")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    Ok(json!({
        "status": if apply { "manual" } else { "validated" },
        "plan": plan_path,
        "planDigest": plan_digest,
        "actionCount": action_count,
        "mutationApplied": false,
        "manual": if apply {
            json!("sealed remediation plans are applied by the Alchemist, never by this command; run /audit-fix against the frozen report")
        } else {
            Value::Null
        },
    }))
}

/// One repair class. `applier` is a `legion setup` argv; a class without one is
/// manual and carries the command to run.
#[derive(Debug, Clone)]
struct FixClass {
    id: &'static str,
    description: &'static str,
    /// `None` when the class cannot be detected without a live host probe.
    detected: Option<bool>,
    evidence: Value,
    applier: Option<Vec<String>>,
    covered_by: Option<&'static str>,
    manual: Option<&'static str>,
}

fn repair_argv(client: Option<&str>) -> Vec<String> {
    let mut argv = vec!["repair".to_owned()];
    if let Some(client) = client {
        argv.extend(["--client".into(), client.to_owned()]);
    }
    argv.push("--confirm".into());
    argv
}

fn fix_classes(home: &Path, project: Option<&Path>, client: Option<&str>) -> Vec<FixClass> {
    let registrations = super::hooks::mcp_registrations(home, project);
    let claude_user = registrations
        .iter()
        .any(|item| item.host == "claude-code" && item.scope == "user");
    let claude_plugin = registrations
        .iter()
        .any(|item| item.host == "claude-code" && item.scope == "plugin");
    let duplicate = claude_user && claude_plugin;
    vec![
        FixClass {
            id: "projection-repair",
            description: "Stale or degraded host projections, MCP registrations and hooks (skills, plugin files, host config entries)",
            detected: None,
            evidence: json!("probe with `legion setup status`; repair is idempotent"),
            applier: Some(repair_argv(client)),
            covered_by: None,
            manual: None,
        },
        FixClass {
            id: "duplicate-mcp-registration",
            description: "Legion MCP server registered at user scope while the Claude Code plugin already starts it (every tool listed twice)",
            detected: Some(duplicate),
            evidence: json!(registrations
                .iter()
                .map(|item| json!({"host": item.host, "scope": item.scope, "path": item.path}))
                .collect::<Vec<_>>()),
            applier: Some(repair_argv(Some("claude-code"))),
            covered_by: if client.is_none() { Some("projection-repair") } else { None },
            manual: None,
        },
        FixClass {
            id: "legacy-mcp-binding",
            description: "Legacy or conflicting MCP bindings reported by `legion doctor`",
            detected: None,
            evidence: json!("see `legion doctor` mcp naming findings"),
            applier: None,
            covered_by: None,
            manual: Some("legion bind --write (review the preview first)"),
        },
        FixClass {
            id: "remediation-plan",
            description: "Findings from a frozen audit report",
            detected: None,
            evidence: Value::Null,
            applier: None,
            covered_by: None,
            manual: Some("legion fix --plan <sealed-remediation-plan> validates; /audit-fix applies"),
        },
    ]
}

/// Indices of the classes `--apply` runs. Dry-run runs nothing. Without
/// `--class`, every class that has an applier and is not known clean runs
/// unless another selected class already covers it.
fn select_actions(classes: &[FixClass], apply: bool, only: Option<&str>) -> Vec<usize> {
    if !apply {
        return Vec::new();
    }
    let mut chosen = classes
        .iter()
        .enumerate()
        .filter(|(_, class)| class.applier.is_some())
        .filter(|(_, class)| match only {
            Some(id) => class.id == id,
            None => class.detected != Some(false),
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if only.is_none() {
        let ids = chosen
            .iter()
            .map(|index| classes[*index].id)
            .collect::<Vec<_>>();
        chosen.retain(|index| {
            classes[*index]
                .covered_by
                .map_or(true, |cover| !ids.contains(&cover))
        });
    }
    chosen
}

#[derive(clap::Parser)]
struct SetupInvocation {
    #[command(flatten)]
    inner: super::setup::SetupArgs,
}

/// Run `legion setup <argv>` in-process. This is the single delegation point
/// for `fix`, `hooks` and `mcp`: no repair logic lives outside the setup
/// registry.
pub(super) async fn run_setup(argv: Vec<String>, cancellation: CancellationToken) -> CommandResult {
    use clap::Parser;
    let parsed = SetupInvocation::try_parse_from(
        std::iter::once("setup".to_owned()).chain(argv.into_iter()),
    )
    .map_err(|error| CommandError::usage(error.to_string()))?;
    super::setup::run(parsed.inner, cancellation).await
}

fn validate_remediation_plan(plan: &Value) -> Result<(), CommandError> {
    let schema_version = plan.get("schemaVersion").and_then(Value::as_u64);
    let kind = plan.get("kind").and_then(Value::as_str);
    if schema_version != Some(1)
        || !matches!(
            kind,
            Some("legion-remediation-plan") | Some("legion-sealed-remediation-plan")
        )
    {
        return Err(CommandError::usage("invalid remediation plan contract"));
    }
    if !plan.get("binding").is_some()
        || !plan.get("actions").and_then(Value::as_array).is_some()
        || plan.get("planDigest").and_then(Value::as_str).is_none()
    {
        return Err(CommandError::usage(
            "remediation plan requires binding actions and digest",
        ));
    }
    let digest = plan
        .get("planDigest")
        .and_then(Value::as_str)
        .ok_or_else(|| CommandError::usage("remediation plan requires digest"))?;
    let mut subject = plan.clone();
    if let Some(object) = subject.as_object_mut() {
        object.remove("planDigest");
    }
    let expected = legion_contracts::canonical_digest(&subject)
        .map_err(|error| CommandError::usage(error.to_string()))?;
    if digest != expected {
        return Err(CommandError::usage("remediation plan digest mismatch"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn temp_home() -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "legion-fix-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn with_duplicate(home: &Path) {
        std::fs::write(
            home.join(".claude.json"),
            r#"{"mcpServers":{"legion":{"command":"legion"}}}"#,
        )
        .unwrap();
        let plugin = home.join(".claude/skills/legion/.claude-plugin");
        std::fs::create_dir_all(&plugin).unwrap();
        std::fs::write(plugin.join("plugin.json"), "{}").unwrap();
    }

    #[test]
    fn dry_run_selects_nothing_and_touches_nothing() {
        let home = temp_home();
        with_duplicate(&home);
        let before = std::fs::read(home.join(".claude.json")).unwrap();
        let classes = fix_classes(&home, None, None);
        assert!(select_actions(&classes, false, None).is_empty());
        assert_eq!(std::fs::read(home.join(".claude.json")).unwrap(), before);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn apply_runs_existing_appliers_once_and_lists_the_rest_manual() {
        let home = temp_home();
        with_duplicate(&home);
        let classes = fix_classes(&home, None, None);
        let duplicate = classes
            .iter()
            .find(|class| class.id == "duplicate-mcp-registration")
            .unwrap();
        assert_eq!(duplicate.detected, Some(true));
        let selected = select_actions(&classes, true, None);
        let ids = selected
            .iter()
            .map(|index| classes[*index].id)
            .collect::<Vec<_>>();
        // The duplicate is covered by the all-client repair, so it runs once.
        assert_eq!(ids, vec!["projection-repair"]);
        assert_eq!(
            classes[selected[0]].applier.as_deref(),
            Some(&["repair".to_owned(), "--confirm".to_owned()][..])
        );
        for class in classes.iter().filter(|class| class.applier.is_none()) {
            assert!(
                class.manual.is_some(),
                "{} needs a manual command",
                class.id
            );
        }
        let only = select_actions(&classes, true, Some("duplicate-mcp-registration"));
        assert_eq!(only.len(), 1);
        assert_eq!(
            classes[only[0]].applier.as_deref().unwrap()[..3],
            [
                "repair".to_owned(),
                "--client".to_owned(),
                "claude-code".to_owned()
            ]
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn clean_home_skips_the_duplicate_class() {
        let home = temp_home();
        let classes = fix_classes(&home, None, None);
        let duplicate = classes
            .iter()
            .find(|class| class.id == "duplicate-mcp-registration")
            .unwrap();
        assert_eq!(duplicate.detected, Some(false));
        let ids = select_actions(&classes, true, None)
            .iter()
            .map(|index| classes[*index].id)
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["projection-repair"]);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn options_reject_unknown_and_conflicting_flags() {
        assert!(parse_fix_options(&["--wat".into()]).is_err());
        assert!(
            parse_fix_options(&["--plan".into(), "p".into(), "--class".into(), "x".into()])
                .is_err()
        );
        let parsed =
            parse_fix_options(&["--apply".into(), "--client".into(), "codex".into()]).unwrap();
        assert!(parsed.apply);
        assert_eq!(parsed.client.as_deref(), Some("codex"));
    }
}
