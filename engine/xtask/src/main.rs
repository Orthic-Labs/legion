//! `xtask`: Rust-native entry point for Legion's release/packaging pipeline.
//!
//! Ported so far: `verify-release` (schema/digest/path validation, matching
//! `scripts/verify-release.mjs`) and the `process_boundary` helpers used by
//! several release scripts. Every other stage still delegates to its
//! original Node script under `scripts/` — those scripts are untouched, and
//! this binary just gives them one Rust-native call surface while the rest
//! of the port lands incrementally. See engine/xtask's crate doc comment on
//! each module for exact porting status.

mod assemble_native_release;
mod finalize_macos_candidate;
mod native_installed_smoke;
mod portable_core;
mod prepare_unsigned_candidate;
mod prepare_windows_candidate_finalization;
mod process_boundary;
mod release;
mod rightkit_release_bridge;
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
    /// Native Rust port of scripts/assemble-native-release.mjs.
    AssembleNativeRelease {
        #[arg(long)]
        platform: Option<String>,
        #[arg(long)]
        architecture: Option<String>,
        #[arg(long)]
        profile: Option<String>,
        #[arg(long)]
        target: Option<String>,
        #[arg(long = "bin-dir")]
        bin_dir: Option<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
        #[arg(long)]
        force: bool,
        #[arg(long = "finalize-signed")]
        finalize_signed: bool,
        #[arg(long)]
        provenance: Option<String>,
    },
    PackageWindowsRelease { args: Vec<String> },
    /// Native Rust port of scripts/ci/prepare-unsigned-candidate.mjs.
    /// createPortableArchive/SBOM/provenance calls delegate to the external
    /// @rightkit/release npm package as a subprocess.
    PrepareUnsignedCandidate {
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long = "output", alias = "out")]
        output: Option<PathBuf>,
        #[arg(long)]
        platform: Option<String>,
        #[arg(long, alias = "arch")]
        architecture: Option<String>,
        #[arg(long = "source-revision", alias = "source-sha")]
        source_revision: Option<String>,
        #[arg(long)]
        version: Option<String>,
        #[arg(long = "created-at")]
        created_at: Option<String>,
        #[arg(long)]
        check: bool,
    },
    /// Native Rust port of scripts/prepare-windows-candidate-finalization.mjs.
    PrepareWindowsCandidateFinalization {
        #[arg(long)]
        candidate: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        architecture: Option<String>,
        #[arg(long = "source-revision")]
        source_revision: Option<String>,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        receipt: Option<PathBuf>,
    },
    /// Native Rust port of scripts/finalize-macos-candidate.mjs (both the
    /// `--package`/rebind mode and the default prepare mode).
    FinalizeMacosCandidate {
        #[arg(long)]
        package: bool,
        #[arg(long)]
        candidate: Option<PathBuf>,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long = "notarization-archive")]
        notarization_archive: Option<PathBuf>,
        #[arg(long, default_value = "arm64")]
        architecture: String,
        #[arg(long = "source-revision")]
        source_revision: Option<String>,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        receipt: Option<PathBuf>,
    },
    QualifyWindowsRelease { args: Vec<String> },
    /// Native Rust port of installer-release-chain.mjs's `admission`
    /// subcommand (Gate 0A). Reads its inputs from the process environment,
    /// matching the JS `admitRelease(process.env)` default.
    ReleaseAdmission,
    /// Native Rust port of installer-release-chain.mjs's `stage-summary`
    /// subcommand.
    ReleaseStageSummary,
    /// Native Rust port of installer-release-chain.mjs's
    /// `evidence-verification` subcommand.
    ReleaseEvidenceVerification,
    /// Native Rust port of installer-release-chain.mjs's `finalize-windows`
    /// subcommand.
    ReleaseFinalizeWindows,
    /// Native Rust port of installer-release-chain.mjs's `finalize-macos`
    /// subcommand.
    ReleaseFinalizeMacos,
    /// Native Rust port of installer-release-chain.mjs's `qualify-installed`
    /// subcommand.
    ReleaseQualifyInstalled,
    /// Native Rust port of installer-release-chain.mjs's `publish-qualified`
    /// subcommand.
    ReleasePublishQualified,
    /// Native Rust port of local-windows-development.mjs.
    ReleaseLocalWindowsDevelopment {
        #[arg(long = "build-only")]
        build_only: bool,
    },
    /// Native Rust port of scripts/ci/native-installed-smoke.mjs.
    NativeInstalledSmoke {
        #[arg(long = "candidate", alias = "input")]
        candidate: Option<PathBuf>,
        #[arg(long = "isolated-root", alias = "workspace", alias = "root")]
        isolated_root: Option<PathBuf>,
        /// Positional fallback: <candidate-root> [isolated-root]
        positional: Vec<PathBuf>,
    },
}

/// Lightweight `new Date().toISOString()`-shaped UTC timestamp for
/// evidence metadata (this crate has no `chrono` workspace dependency).
fn chrono_like_now_iso() -> String {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let (h, m, s) = (time_of_day / 3600, (time_of_day % 3600) / 60, time_of_day % 60);
    let mut year = 1970i64;
    let mut remaining_days = days as i64;
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let year_days = if leap { 366 } else { 365 };
        if remaining_days < year_days {
            break;
        }
        remaining_days -= year_days;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_lengths = if leap { [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] } else { [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] };
    let mut month = 1;
    for len in month_lengths {
        if remaining_days < len {
            break;
        }
        remaining_days -= len;
        month += 1;
    }
    let day = remaining_days + 1;
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}.{millis:03}Z")
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
        Commands::AssembleNativeRelease {
            platform,
            architecture,
            profile,
            target,
            bin_dir,
            out,
            force,
            finalize_signed,
            provenance,
        } => {
            let repo_root = repo_root();
            let args = assemble_native_release::AssembleArgs {
                platform,
                architecture,
                profile,
                target,
                bin_dir,
                out,
                force,
                finalize_signed,
                provenance,
            };
            match assemble_native_release::run(&repo_root, args) {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::PackageWindowsRelease { args } => {
            delegate_to_node("scripts/package-windows-release.mjs", &args)
        }
        Commands::PrepareUnsignedCandidate {
            input,
            output,
            platform,
            architecture,
            source_revision,
            version,
            created_at,
            check,
        } => {
            let repo_root = repo_root();
            let result = if check {
                prepare_unsigned_candidate::check_unsigned_candidate(
                    &repo_root,
                    prepare_unsigned_candidate::CheckArgs { output_root: output, platform, architecture, source_revision, version },
                )
            } else {
                prepare_unsigned_candidate::prepare_unsigned_candidate(
                    &repo_root,
                    prepare_unsigned_candidate::PrepareArgs {
                        input,
                        output_root: output,
                        platform,
                        architecture,
                        source_revision,
                        version,
                        created_at,
                    },
                )
            };
            match result {
                Ok(value) => {
                    println!("{}", serde_json::to_string_pretty(&value).unwrap());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::PrepareWindowsCandidateFinalization { candidate, output, architecture, source_revision, version, receipt } => {
            let repo_root = repo_root();
            let candidate = candidate.or_else(|| std::env::var("LEGION_UNSIGNED_CANDIDATE_ROOT").ok().map(PathBuf::from));
            let architecture = architecture.or_else(|| std::env::var("LEGION_WINDOWS_ARCH").ok()).or_else(|| Some("x86_64".to_string()));
            let source_revision = source_revision.or_else(|| std::env::var("LEGION_SOURCE_REVISION").ok());
            match prepare_windows_candidate_finalization::prepare_windows_candidate_finalization(
                &repo_root,
                prepare_windows_candidate_finalization::PrepareArgs {
                    candidate_root: candidate,
                    output_root: output,
                    architecture,
                    source_revision,
                    version,
                    receipt_path: receipt,
                },
            ) {
                Ok(value) => {
                    println!("{}", serde_json::to_string(&value).unwrap());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::FinalizeMacosCandidate {
            package,
            candidate,
            input,
            output,
            notarization_archive,
            architecture,
            source_revision,
            version,
            receipt,
        } => {
            let repo_root = repo_root();
            let source_revision = source_revision.or_else(|| std::env::var("LEGION_SOURCE_REVISION").ok());
            let result = if package {
                (|| {
                    let input = input.ok_or_else(|| "--input is required".to_string())?;
                    let output = output.ok_or_else(|| "--output is required".to_string())?;
                    let notarization_archive = notarization_archive.ok_or_else(|| "--notarization-archive is required".to_string())?;
                    let version = version.ok_or_else(|| "--version is required".to_string())?;
                    let source_revision = source_revision.ok_or_else(|| "--source-revision is required".to_string())?;
                    finalize_macos_candidate::package_macos_candidate(
                        &repo_root,
                        finalize_macos_candidate::PackageArgs { input_root: input, output_root: output, notarization_archive, version, architecture, source_revision },
                    )
                })()
            } else {
                let candidate = candidate.or_else(|| std::env::var("LEGION_UNSIGNED_CANDIDATE_ROOT").ok().map(PathBuf::from));
                finalize_macos_candidate::prepare_macos_candidate_finalization(
                    &repo_root,
                    finalize_macos_candidate::PrepareArgs {
                        candidate_root: candidate,
                        output_root: output,
                        architecture,
                        source_revision,
                        version,
                        receipt_path: receipt,
                    },
                )
            };
            match result {
                Ok(value) => {
                    println!("{}", serde_json::to_string(&value).unwrap());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::QualifyWindowsRelease { args } => {
            delegate_to_node("scripts/qualify-windows-release.mjs", &args)
        }
        Commands::ReleaseAdmission => {
            let env: std::collections::HashMap<String, String> = std::env::vars().collect();
            match release::admission::admit_release(&env, &repo_root()) {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::ReleaseStageSummary => {
            let env: std::collections::HashMap<String, String> = std::env::vars().collect();
            match release::admission::write_stage_summary(&env) {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::ReleaseEvidenceVerification => {
            let env: std::collections::HashMap<String, String> = std::env::vars().collect();
            match release::admission::verify_evidence(&env) {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::ReleaseFinalizeWindows => {
            let repo_root = repo_root();
            let env: std::collections::HashMap<String, String> = std::env::vars().collect();
            let runner: release::paths::CommandRunner<'_> = &release::paths::spawn_sync;
            let inno_template = match std::fs::read_to_string(repo_root.join("scripts/release/windows/legion.iss")) {
                Ok(v) => v,
                Err(err) => {
                    eprintln!("xtask: failed to read legion.iss: {err}");
                    return ExitCode::from(1);
                }
            };
            let activation_script = repo_root.join("scripts/release/windows/activate.ps1");
            match release::installer_release_chain::finalization_manifest(
                "windows",
                release::installer_release_chain::FinalizationManifestOptions {
                    env: &env,
                    runner,
                    repository_root: &repo_root,
                    inno_template: &inno_template,
                    activation_script: &activation_script,
                    swift_source: &repo_root.join("scripts/release/macos/LegionInstaller.swift"),
                    developer_id: env.get("APPLE_DEVELOPER_ID").map(|s| s.as_str()),
                    api_key_path: env.get("APPLE_API_KEY_PATH").map(|s| s.as_str()),
                    api_key: env.get("APPLE_API_KEY").map(|s| s.as_str()),
                    api_issuer: env.get("APPLE_API_ISSUER").map(|s| s.as_str()),
                    now: &|| chrono_like_now_iso(),
                },
            ) {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::ReleaseFinalizeMacos => {
            let repo_root = repo_root();
            let env: std::collections::HashMap<String, String> = std::env::vars().collect();
            let runner: release::paths::CommandRunner<'_> = &release::paths::spawn_sync;
            let inno_template = std::fs::read_to_string(repo_root.join("scripts/release/windows/legion.iss")).unwrap_or_default();
            let activation_script = repo_root.join("scripts/release/windows/activate.ps1");
            match release::installer_release_chain::finalization_manifest(
                "macos",
                release::installer_release_chain::FinalizationManifestOptions {
                    env: &env,
                    runner,
                    repository_root: &repo_root,
                    inno_template: &inno_template,
                    activation_script: &activation_script,
                    swift_source: &repo_root.join("scripts/release/macos/LegionInstaller.swift"),
                    developer_id: env.get("APPLE_DEVELOPER_ID").map(|s| s.as_str()),
                    api_key_path: env.get("APPLE_API_KEY_PATH").map(|s| s.as_str()),
                    api_key: env.get("APPLE_API_KEY").map(|s| s.as_str()),
                    api_issuer: env.get("APPLE_API_ISSUER").map(|s| s.as_str()),
                    now: &|| chrono_like_now_iso(),
                },
            ) {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::ReleaseQualifyInstalled => {
            let env: std::collections::HashMap<String, String> = std::env::vars().collect();
            let runner: release::paths::CommandRunner<'_> = &release::paths::spawn_sync;
            let is_windows = std::env::consts::OS == "windows" || env.get("RIGHT_GIT_TEST_PLATFORM").map(|s| s.as_str()) == Some("win32");
            match release::installer_release_chain::qualify_installed(runner, &env, is_windows) {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::ReleasePublishQualified => {
            let repo_root = repo_root();
            let env: std::collections::HashMap<String, String> = std::env::vars().collect();
            let runner: release::paths::CommandRunner<'_> = &release::paths::spawn_sync;
            match release::installer_release_chain::publish_qualified(release::installer_release_chain::PublishQualifiedOptions {
                env: &env,
                runner,
                repository_root: &repo_root,
                download_root: None,
            }) {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::ReleaseLocalWindowsDevelopment { build_only } => {
            let repo_root = repo_root();
            let env: std::collections::HashMap<String, String> = std::env::vars().collect();
            let runner: release::paths::CommandRunner<'_> = &release::paths::spawn_sync;
            let inno_template = match std::fs::read_to_string(repo_root.join("scripts/release/windows/legion.iss")) {
                Ok(v) => v,
                Err(err) => {
                    eprintln!("xtask: failed to read legion.iss: {err}");
                    return ExitCode::from(1);
                }
            };
            let activation_script = repo_root.join("scripts/release/windows/activate.ps1");
            let xtask_binary = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("xtask"));
            let where_exe = || -> Option<String> {
                Command::new("where.exe").arg("iscc.exe").output().ok().and_then(|o| {
                    let text = String::from_utf8_lossy(&o.stdout).lines().next().map(|s| s.to_string());
                    if o.status.success() { text } else { None }
                })
            };
            match release::local_windows_development::run_local_windows_development(release::local_windows_development::RunLocalWindowsDevelopmentOptions {
                build_only,
                is_windows_host: std::env::consts::OS == "windows",
                runner,
                env: &env,
                repository_root: &repo_root,
                xtask_binary: &xtask_binary,
                inno_template: &inno_template,
                activation_script: &activation_script,
                where_exe: &where_exe,
            }) {
                Ok(result) => {
                    println!("{}", serde_json::to_string_pretty(&result).unwrap());
                    ExitCode::SUCCESS
                }
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::NativeInstalledSmoke { candidate, isolated_root, positional } => {
            let candidate = candidate.or_else(|| positional.get(0).cloned());
            let isolated_root = isolated_root.or_else(|| positional.get(1).cloned());
            let Some(candidate) = candidate else {
                eprintln!(
                    "usage: xtask native-installed-smoke <candidate-root> [isolated-root] (or --candidate <path> --isolated-root <path>)"
                );
                return ExitCode::from(1);
            };
            match native_installed_smoke::native_installed_smoke(&candidate, isolated_root.as_deref()) {
                Ok(()) => ExitCode::SUCCESS,
                Err(err) => {
                    eprintln!("{err}");
                    ExitCode::from(1)
                }
            }
        }
    }
}
