use super::CommandResult;
use crate::cli::CommonArgs;

/// `legion hooks` is about git hooks (pre-commit / pre-push), not Claude Code
/// hooks (those are registered by the plugin's `hooks/hooks.json` and checked
/// with `legion bind --registrations`). No git-hook generator exists, so the
/// command fails with a non-zero exit instead of reporting a fake success.
pub fn run(args: CommonArgs) -> CommandResult {
    let argv = args
        .args
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let action = argv.first().map(String::as_str);
    if !matches!(action, Some("install") | Some("uninstall")) {
        return Err(super::CommandError::usage(
            "hooks requires install|uninstall [--pre-commit|--pre-push] (git hooks, not Claude Code hooks)",
        ));
    }
    Err(super::CommandError::incomplete(format!(
        "hooks {} is not implemented: Legion does not generate git hooks yet. \
         Claude Code hooks are registered by the plugin (see `legion bind --registrations`)",
        action.unwrap_or_default()
    )))
}
