mod checks;
mod generators;
mod native_cli_gate;
mod repo;
mod shared;

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
    /// Port of `scripts/generate-catalogs.mjs`.
    GenerateCatalogs {
        #[arg(long)]
        check: bool,
    },
    /// Port of `scripts/check-canonical-names.mjs`.
    CheckCanonicalNames {
        #[arg(long)]
        json: bool,
    },
    /// Port of `scripts/check-blueprint-config.mjs`.
    CheckBlueprintConfig {
        #[arg(long)]
        json: bool,
    },
    /// Port of `scripts/check-publication-policy.mjs`.
    CheckPublicationPolicy {
        #[arg(long)]
        channel: Option<String>,
    },
    /// Port of `scripts/check-distribution-contract.mjs`.
    CheckDistributionContract,
    /// Port of `scripts/check-release-obligations.mjs`.
    CheckReleaseObligations,
    /// Port of `scripts/generate-schemas.mjs`.
    GenerateSchemas {
        #[arg(long)]
        check: bool,
    },
    /// Port of `scripts/generate-manifest.mjs`.
    GenerateManifest {
        #[arg(long)]
        check: bool,
        #[arg(long)]
        registry: Option<std::path::PathBuf>,
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
    /// Port of `scripts/normalize-provider-result.mjs`.
    NormalizeProviderResult {
        /// Path to a JSON plan-contract fragment (`{id, denominator, benchmark}`).
        #[arg(long)]
        contract: Option<std::path::PathBuf>,
        /// Path to the raw provider output JSON to normalize.
        #[arg(long)]
        raw: Option<std::path::PathBuf>,
        /// Run the JS file's embedded self-test instead of normalizing files.
        #[arg(long)]
        self_test: bool,
    },
    /// Port of `scripts/native-cli/inventory.mjs`.
    NativeCliInventory,
    /// Port of `scripts/check-native-cli-surface.mjs`.
    CheckNativeCliSurface {
        #[arg(long, default_value = "record")]
        phase: String,
    },
    /// Port of `scripts/generate-host-projection.mjs`.
    GenerateHostProjection {
        #[arg(long)]
        check: bool,
    },
    /// Port of `scripts/generate-skill-catalog.mjs`.
    GenerateSkillCatalog {
        #[arg(long)]
        check: bool,
    },
    /// Port of `scripts/generate-codex-skill-sidecars.mjs`.
    GenerateCodexSkillSidecars {
        #[arg(long)]
        check: bool,
    },
    /// Port of `scripts/refresh-local-skill-manifests.mjs`.
    RefreshLocalSkillManifests {
        #[arg(long)]
        check: bool,
    },
    /// Port of `scripts/verify-plugin-parity.mjs`.
    VerifyPluginParity {
        #[arg(long)]
        check: bool,
        #[arg(long)]
        structural_only: bool,
    },
    /// Port of `scripts/report-to-sarif.mjs`.
    ReportToSarif {
        #[arg(long)]
        report: std::path::PathBuf,
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
    /// Port of `scripts/plugin-dev.mjs`.
    PluginDev,
    /// Port of `scripts/check-dependency-closure.mjs`.
    CheckDependencyClosure,
    /// Port of `scripts/check-packed-import-closure.mjs`.
    CheckPackedImportClosure,
    /// Port of `scripts/native-cli/run-installed-parity.mjs`. Windows-only
    /// (qualifies the installer-owned stable `legion.exe`); fails immediately
    /// off Windows.
    NativeCliParityInstalled,
    /// Port of `scripts/native-cli/run-rust-characterization.mjs`.
    NativeCliCaptureRust {
        #[arg(long)]
        diagnostic: bool,
    },
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
        Command::GenerateCatalogs { check } => generators::catalogs::run(&root, check),
        Command::CheckCanonicalNames { json } => checks::canonical_names::run(&root, json),
        Command::CheckBlueprintConfig { json } => checks::blueprint_config::run(&root, json),
        Command::CheckPublicationPolicy { channel } => {
            checks::publication_policy::run(&root, channel.as_deref())
        }
        Command::CheckDistributionContract => checks::distribution_contract::run(&root),
        Command::CheckReleaseObligations => checks::release_obligations::run(&root),
        Command::GenerateSchemas { check } => generators::schemas::run(&root, check),
        Command::GenerateManifest { check, registry, out } => {
            generators::manifest::run(&root, check, registry.as_deref(), out.as_deref())
        }
        Command::NormalizeProviderResult { contract, raw, self_test } => {
            generators::provider_result_cli::run(contract.as_deref(), raw.as_deref(), self_test)
        }
        Command::NativeCliInventory => generators::native_cli_inventory::run(&root),
        Command::CheckNativeCliSurface { phase } => {
            checks::native_cli_surface::run(&root, &phase)
        }
        Command::GenerateHostProjection { check } => generators::host_projection::run(&root, check),
        Command::GenerateSkillCatalog { check } => generators::skill_catalog::run(&root, check),
        Command::GenerateCodexSkillSidecars { check } => generators::codex_skill_sidecars::run(&root, check),
        Command::RefreshLocalSkillManifests { check } => generators::refresh_local_skill_manifests::run(&root, check),
        Command::VerifyPluginParity { check, structural_only } => {
            generators::verify_plugin_parity::run_opts(&root, check, structural_only)
        }
        Command::ReportToSarif { report, out } => generators::report_to_sarif::run(&report, out.as_deref()),
        Command::PluginDev => generators::plugin_dev::run(&root),
        Command::CheckDependencyClosure => checks::dependency_closure::run(&root),
        Command::CheckPackedImportClosure => checks::packed_import_closure::run(&root),
        Command::NativeCliParityInstalled => {
            generators::native_cli_installed_parity::run(&root)
        }
        Command::NativeCliCaptureRust { diagnostic } => {
            generators::native_cli_rust_characterization::run(&root, diagnostic)
        }
    };

    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
