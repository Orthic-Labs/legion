use super::{CommandError, CommandResult};
use crate::cli::CommonArgs;
use legion_minimize::{
    build_receipt, build_review, decision_receipt, file_exists, read_json, resolve_minimize_paths,
    validate_decision, verify_decision, verify_receipt, write_json, GitContext, MinimizeError,
};
use serde_json::json;
use std::path::{Path, PathBuf};

pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let domain = argv.first().map(String::as_str);
    let action = argv.get(1).map(String::as_str);
    let rest = argv.iter().skip(2).cloned().collect::<Vec<_>>();
    let cwd = std::env::current_dir().map_err(super::io_error)?;
    let git = GitContext::new(cwd.clone());
    let paths = resolve_minimize_paths().map_err(map_minimize_error)?;

    match domain {
        Some("decision") => run_decision(action, &rest, &cwd, &paths),
        Some("commit") => run_commit(action, &rest, &cwd, &git, &paths),
        _ => Err(CommandError::usage(format!(
            "minimize requires a domain: commit|decision (got {})",
            domain.unwrap_or("<none>")
        ))),
    }
}

fn run_decision(
    action: Option<&str>,
    rest: &[String],
    cwd: &Path,
    paths: &legion_minimize::MinimizePaths,
) -> CommandResult {
    let positionals = rest
        .iter()
        .map(|value| resolve_path(cwd, value))
        .collect::<Vec<_>>();
    match action {
        Some("validate") => {
            if positionals.len() != 1 {
                return Err(CommandError::usage(
                    "usage: legion minimize decision validate <decision.json>",
                ));
            }
            map_minimize(validate_decision(
                &map_minimize(read_json(&positionals[0]))?,
                &[],
                &[],
            ))?;
            pass()
        }
        Some("receipt") => {
            if positionals.len() != 2 {
                return Err(CommandError::usage(
                    "usage: legion minimize decision receipt <decision.json> <receipt.json>",
                ));
            }
            write_json(
                &positionals[1],
                &map_minimize(decision_receipt(&positionals[0], paths))?,
            )
                .map_err(map_minimize_error)?;
            pass()
        }
        Some("verify") => {
            if positionals.len() != 2 {
                return Err(CommandError::usage(
                    "usage: legion minimize decision verify <decision.json> <receipt.json>",
                ));
            }
            map_minimize(verify_decision(&positionals[0], &positionals[1], paths))?;
            pass()
        }
        _ => Err(CommandError::usage(format!(
            "minimize decision requires an action: validate|receipt|verify (got {})",
            action.unwrap_or("<none>")
        ))),
    }
}

fn run_commit(
    action: Option<&str>,
    rest: &[String],
    cwd: &Path,
    git: &GitContext,
    paths: &legion_minimize::MinimizePaths,
) -> CommandResult {
    let positionals = rest
        .iter()
        .map(|value| resolve_path(cwd, value))
        .collect::<Vec<_>>();
    match action {
        Some("init-review") => {
            if positionals.len() != 1 {
                return Err(CommandError::usage(
                    "usage: legion minimize commit init-review <review.json>",
                ));
            }
            write_json(&positionals[0], &map_minimize(build_review(git))?)
                .map_err(map_minimize_error)?;
            pass()
        }
        Some("receipt") => {
            if positionals.len() != 2 {
                return Err(CommandError::usage(
                    "usage: legion minimize commit receipt <review.json> <receipt.json>",
                ));
            }
            write_json(
                &positionals[1],
                &map_minimize(build_receipt(git, &positionals[0], paths))?,
            )
                .map_err(map_minimize_error)?;
            pass()
        }
        Some("verify") => {
            if positionals.len() != 1 {
                return Err(CommandError::usage(
                    "usage: legion minimize commit verify <receipt.json>",
                ));
            }
            if !file_exists(&positionals[0]) {
                return Err(map_minimize_error(MinimizeError::new(format!(
                    "missing commit receipt: {}",
                    positionals[0].display()
                ))));
            }
            map_minimize(verify_receipt(
                git,
                &map_minimize(read_json(&positionals[0]))?,
                paths,
            ))?;
            pass()
        }
        _ => Err(CommandError::usage(format!(
            "minimize commit requires an action: init-review|receipt|verify (got {})",
            action.unwrap_or("<none>")
        ))),
    }
}

fn resolve_path(cwd: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        cwd.join(path)
    }
}

fn pass() -> CommandResult {
    Ok(json!({"__raw": "MINIMIZE PASS\n"}))
}

fn map_minimize<T>(result: Result<T, MinimizeError>) -> Result<T, CommandError> {
    result.map_err(map_minimize_error)
}

fn map_minimize_error(error: MinimizeError) -> CommandError {
    CommandError::policy(format!("MINIMIZE FAIL: {}", error))
}
