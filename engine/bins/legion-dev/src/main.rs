mod checks;
mod repo;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

/// `legion-dev` — repository-contract checks, ported from `scripts/*.mjs`.
///
/// Each subcommand mirrors one `pnpm legion:check` step: same stdout/stderr
/// wording, same exit-code semantics (0 = pass, non-zero = fail).
#[derive(Parser)]
#[command(name = "legion-dev")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Port of `scripts/check-portability.mjs`.
    CheckPortability {
        #[arg(long)]
        json: bool,
    },
    /// Port of `scripts/check-version-parity.mjs`.
    CheckVersionParity {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        stable: bool,
    },
    /// Port of `scripts/check-publication-surface.mjs`.
    CheckPublicationSurface,
    /// Port of `scripts/check-authority-parity.mjs`.
    CheckAuthorityParity,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let root = match repo::find_root() {
        Ok(root) => root,
        Err(err) => {
            eprintln!("legion-dev: {err}");
            return ExitCode::FAILURE;
        }
    };

    let ok = match cli.command {
        Command::CheckPortability { json } => checks::portability::run(&root, json),
        Command::CheckVersionParity { json, stable } => {
            checks::version_parity::run(&root, json, stable)
        }
        Command::CheckPublicationSurface => checks::publication_surface::run(&root),
        Command::CheckAuthorityParity => checks::authority_parity::run(&root),
    };

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
