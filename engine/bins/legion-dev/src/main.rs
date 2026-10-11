#[cfg(test)]
mod apple_skill_integrity;
mod checks;
mod generators;
mod native_cli_gate;
mod repo;
mod shared;

use clap::{Parser, Subcommand};
use std::process::ExitCode;

/// `legion-dev` — repository-contract checks and generators for Legion.
///
/// Each check exits 0 on pass and non-zero on fail.
#[derive(Parser)]
#[command(name = "legion-dev")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Fail when a tracked file contains a developer-local path or username that is not allowlisted.
    CheckPortability {
        #[arg(long)]
        json: bool,
    },
    /// Check that every version-bearing file matches `release/version.json`; `--stable` rejects development versions.
    CheckVersionParity {
        #[arg(long)]
        json: bool,
        #[arg(long)]
        stable: bool,
    },
    /// Check that `package.json#files` and `MANIFEST.package.json#allowlistedTopLevel` are identical and every entry exists.
    CheckPublicationSurface,
    /// Dead-reference gate: skill markdown links, `legion script` names,
    /// deleted-script mentions, and `hostRequirements` ids.
    CheckSkillReferences,
    /// Structural gate for `skills/**/evals/*.json`; model-graded cases are
    /// reported as `requires-model`, never as passed.
    CheckSkillEvals,
    /// Execute skill-eval routing cases deterministically. The only native
    /// router is explicit slash-alias resolution; natural-language cases are
    /// `requires-model` and never fail. Nonzero exit on any mismatch.
    RunSkillEvals {
        #[arg(long = "bundle")]
        bundles: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Every path deleted under skills/, scripts/, hooks/, doctrine/,
    /// docs/agent-rules*, or engine/bins/*/src/commands/ since the baseline
    /// commit needs a row in `docs/provenance/retirements.md`.
    CheckRetirements,
    /// Check that `agents/<role>.md` matches `src/roster/<role>.md` and that `doctrine/<role>.md` declares no description.
    CheckAuthorityParity,
    /// Grade recorded role decisions against independently labelled replay cases.
    EvaluateAuthorityReplay {
        #[arg(
            long,
            default_value = "src/evals/architecture/authority-adoption.jsonl"
        )]
        cases: std::path::PathBuf,
        #[arg(long)]
        observations: std::path::PathBuf,
    },
    /// Rebuild `qualification/generated-catalogs.json`; `--check` fails on drift.
    GenerateCatalogs {
        #[arg(long)]
        check: bool,
    },
    /// Scan tracked files for retired role names and verify canonical naming invariants.
    CheckCanonicalNames {
        #[arg(long)]
        json: bool,
    },
    /// Check that `.agent/config.json` is a regular JSON file declaring every required `ignoredPrefixes` entry.
    CheckBlueprintConfig {
        #[arg(long)]
        json: bool,
    },
    /// Check that public channels have an explicit grant bound to the current shipped surface.
    CheckPublicationPolicy {
        #[arg(long)]
        channel: Option<String>,
    },
    /// Cross-validate distribution, publication, channel, package, and release config against the frozen invariants.
    CheckDistributionContract,
    /// Validate `release/obligations.json`: each obligation names a real evidence producer or an explicit gap.
    CheckReleaseObligations,
    /// Generate the committed JSON schemas from the code-owned contract enums; `--check` fails on drift.
    GenerateSchemas {
        #[arg(long)]
        check: bool,
    },
    /// Generate the package manifest from the provider registry; `--check` fails on drift.
    GenerateManifest {
        #[arg(long)]
        check: bool,
        #[arg(long)]
        registry: Option<std::path::PathBuf>,
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
    /// Normalize raw provider output against a plan-contract fragment.
    NormalizeProviderResult {
        /// Path to a JSON plan-contract fragment (`{id, denominator, benchmark}`).
        #[arg(long)]
        contract: Option<std::path::PathBuf>,
        /// Path to the raw provider output JSON to normalize.
        #[arg(long)]
        raw: Option<std::path::PathBuf>,
        /// Run the built-in self-test instead of normalizing files.
        #[arg(long)]
        self_test: bool,
    },
    /// Freeze the Node/Rust CLI command and nested-route inventory.
    NativeCliInventory,
    /// Fail on retained Node Legion CLI entrypoints and product tests that invoke them.
    /// `--phase` accepts exactly `enforce` (fails on any issue) or `record` (reports only); any other value is a usage error.
    CheckNativeCliSurface {
        #[arg(long, default_value = "record")]
        phase: String,
    },
    /// Generate host projections from roster and skill sources; `--check` fails on drift.
    GenerateHostProjection {
        #[arg(long)]
        check: bool,
    },
    /// Generate the skill catalog; `--check` fails on drift.
    GenerateSkillCatalog {
        #[arg(long)]
        check: bool,
    },
    /// Generate the Codex skill sidecar files; `--check` fails on drift.
    GenerateCodexSkillSidecars {
        #[arg(long)]
        check: bool,
    },
    /// Refresh the `skills/manifests` digests for the named bundles.
    RefreshLocalSkillManifests {
        #[arg(long)]
        check: bool,
        #[arg(value_name = "BUNDLE")]
        bundles: Vec<String>,
    },
    /// Verify the plugin tree matches its packaged sources; `--structural-only` skips installed-binary checks.
    VerifyPluginParity {
        #[arg(long)]
        check: bool,
        #[arg(long)]
        structural_only: bool,
    },
    /// Convert a Legion report JSON into SARIF; `--report` and `--out` are both required.
    ReportToSarif {
        #[arg(long)]
        report: std::path::PathBuf,
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Verify the live plugin surface, then print the steps to load it for development.
    PluginDev,
    /// Verify each bundle's dependency declaration and resource closure.
    CheckDependencyClosure {
        /// Assembled portable plugin tree; also require `skills/_shared/*` dependencies there.
        #[arg(long)]
        plugin_root: Option<std::path::PathBuf>,
    },
    /// Verify static relative ESM imports resolve inside the packed npm tarball.
    CheckPackedImportClosure,
    /// Check installed native CLI parity. Windows-only
    /// (qualifies the installer-owned stable `legion.exe`); fails immediately
    /// off Windows.
    NativeCliParityInstalled,
    /// Capture native CLI characterization from the Rust build. `--diagnostic` never fails on
    /// fixture mismatches (setup and capture errors still fail) and its output does not qualify.
    NativeCliCaptureRust {
        #[arg(long)]
        diagnostic: bool,
    },
}

fn main() -> ExitCode {
    // `pnpm <script> -- --flag` forwards a literal `--` separator; drop it so clap sees the flags.
    let mut argv: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if argv.len() > 2 && argv[2] == "--" {
        argv.remove(2);
    }
    let cli = Cli::parse_from(argv);
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
        Command::CheckSkillReferences => checks::skill_references::run(&root),
        Command::CheckSkillEvals => checks::skill_evals::run(&root),
        Command::RunSkillEvals { bundles, json } => {
            checks::run_skill_evals::run(&root, &bundles, json)
        }
        Command::CheckRetirements => checks::retirements::run(&root),
        Command::CheckAuthorityParity => checks::authority_parity::run(&root),
        Command::EvaluateAuthorityReplay {
            cases,
            observations,
        } => checks::authority_replay::run(&root, &cases, &observations),
        Command::GenerateCatalogs { check } => generators::catalogs::run(&root, check),
        Command::CheckCanonicalNames { json } => checks::canonical_names::run(&root, json),
        Command::CheckBlueprintConfig { json } => checks::blueprint_config::run(&root, json),
        Command::CheckPublicationPolicy { channel } => {
            checks::publication_policy::run(&root, channel.as_deref())
        }
        Command::CheckDistributionContract => checks::distribution_contract::run(&root),
        Command::CheckReleaseObligations => checks::release_obligations::run(&root),
        Command::GenerateSchemas { check } => generators::schemas::run(&root, check),
        Command::GenerateManifest {
            check,
            registry,
            out,
        } => generators::manifest::run(&root, check, registry.as_deref(), out.as_deref()),
        Command::NormalizeProviderResult {
            contract,
            raw,
            self_test,
        } => generators::provider_result_cli::run(contract.as_deref(), raw.as_deref(), self_test),
        Command::NativeCliInventory => generators::native_cli_inventory::run(&root),
        Command::CheckNativeCliSurface { phase } => checks::native_cli_surface::run(&root, &phase),
        Command::GenerateHostProjection { check } => generators::host_projection::run(&root, check),
        Command::GenerateSkillCatalog { check } => generators::skill_catalog::run(&root, check),
        Command::GenerateCodexSkillSidecars { check } => {
            generators::codex_skill_sidecars::run(&root, check)
        }
        Command::RefreshLocalSkillManifests { check, bundles } => {
            generators::refresh_local_skill_manifests::run_with_args(&root, check, &bundles)
        }
        Command::VerifyPluginParity {
            check,
            structural_only,
        } => generators::verify_plugin_parity::run_opts(&root, check, structural_only),
        Command::ReportToSarif { report, out } => generators::report_to_sarif::run(&report, &out),
        Command::PluginDev => generators::plugin_dev::run(&root),
        Command::CheckDependencyClosure { plugin_root } => {
            checks::dependency_closure::run(&root, plugin_root.as_deref())
        }
        Command::CheckPackedImportClosure => checks::packed_import_closure::run(&root),
        Command::NativeCliParityInstalled => generators::native_cli_installed_parity::run(&root),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refresh_local_skill_manifests_accepts_bundle_arguments() {
        let cli = Cli::try_parse_from([
            "legion-dev",
            "refresh-local-skill-manifests",
            "audit",
            "--check",
        ])
        .expect("bundle positional argument should parse");
        match cli.command {
            Command::RefreshLocalSkillManifests { check, bundles } => {
                assert!(check);
                assert_eq!(bundles, vec!["audit"]);
            }
            _ => panic!("unexpected command parsed"),
        }
    }
}
