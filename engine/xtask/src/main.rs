//! `xtask`: Rust-native entry point for Legion's release/packaging pipeline.
//!
//! Ported so far: `verify-release` (schema/digest/path validation, matching
//! `scripts/verify-release.mjs`) and the `process_boundary` helpers used by
//! several release scripts. Every other stage still delegates to its
//! original Node script under `scripts/` — those scripts are untouched, and
//! this binary just gives them one Rust-native call surface while the rest
//! of the port lands incrementally. See engine/xtask's crate doc comment on
//! each module for exact porting status.

mod process_boundary;
mod verify_release;

use std::path::PathBuf;
use std::process::{Command, ExitCode};

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "Legion release/packaging pipeline")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate a release manifest (native Rust port of verify-release.mjs).
    VerifyRelease {
        manifest_path: PathBuf,
        #[arg(long)]
        dist_dir: Option<PathBuf>,
    },
    /// Not yet ported to Rust: delegates to the original Node script.
    /// Remaining scope is tracked in engine/xtask; see crate docs.
    AssembleNativeRelease { args: Vec<String> },
    PackageWindowsRelease { args: Vec<String> },
    PrepareWindowsCandidateFinalization { args: Vec<String> },
    FinalizeMacosCandidate { args: Vec<String> },
    QualifyWindowsRelease { args: Vec<String> },
    NativeInstalledSmoke { args: Vec<String> },
}

fn repo_root() -> PathBuf {
    // engine/xtask -> engine -> repo root
    let mut dir = std::env::current_dir().expect("cwd");
    // Prefer CARGO_MANIFEST_DIR when run via `cargo run -p xtask`.
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        dir = PathBuf::from(manifest_dir);
    }
    dir.pop(); // engine
    dir.pop(); // repo root
    dir
}

fn delegate_to_node(script_rel: &str, args: &[String]) -> ExitCode {
    let root = repo_root();
    let script = root.join(script_rel);
    eprintln!(
        "xtask: {script_rel} is not yet ported to Rust; delegating to Node ({}).",
        script.display()
    );
    let status = Command::new("node").arg(&script).args(args).current_dir(&root).status();
    match status {
        Ok(status) => {
            if status.success() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(status.code().unwrap_or(1) as u8)
            }
        }
        Err(err) => {
            eprintln!("xtask: failed to launch node for {script_rel}: {err}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::VerifyRelease { manifest_path, dist_dir } => {
            match verify_release::verify_release_manifest(&manifest_path, dist_dir.as_deref()) {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    if result.valid {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(1)
                    }
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(2)
                }
            }
        }
        Commands::AssembleNativeRelease { args } => {
            delegate_to_node("scripts/assemble-native-release.mjs", &args)
        }
        Commands::PackageWindowsRelease { args } => {
            delegate_to_node("scripts/package-windows-release.mjs", &args)
        }
        Commands::PrepareWindowsCandidateFinalization { args } => {
            delegate_to_node("scripts/prepare-windows-candidate-finalization.mjs", &args)
        }
        Commands::FinalizeMacosCandidate { args } => {
            delegate_to_node("scripts/finalize-macos-candidate.mjs", &args)
        }
        Commands::QualifyWindowsRelease { args } => {
            delegate_to_node("scripts/qualify-windows-release.mjs", &args)
        }
        Commands::NativeInstalledSmoke { args } => {
            delegate_to_node("scripts/ci/native-installed-smoke.mjs", &args)
        }
    }
}
