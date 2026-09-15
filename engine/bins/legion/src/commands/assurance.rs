use super::{CommandError, CommandResult};
use clap::Args;

/// The historical Node CLI advertised `assurance` in help, but its dispatcher
/// intentionally had no route for it. Keep that observable edge explicit: this
/// command is not a second assurance implementation and must never inspect or
/// mutate a repository merely because the help inventory mentions it.
#[derive(Debug, Args)]
#[command(disable_help_flag = true)]
pub struct AssuranceArgs {
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub arguments: Vec<String>,
}

pub fn run(_args: AssuranceArgs) -> CommandResult {
    Err(CommandError::usage("unknown command: assurance"))
}
