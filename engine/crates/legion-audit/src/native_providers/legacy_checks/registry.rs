//! Frozen registry projection for all 32 `legacy-check` providers.

use super::contracts::{CommandShape, LegacyCheckSpec};

const ALWAYS: &str = r#"{"op":"always"}"#;
const SOURCE: &str = r#"{"op":"sourceFilesAtLeast","count":1}"#;
const PACKAGE: &str = r#"{"op":"anyPath","patterns":["**/package.json"]}"#;
const CARGO: &str = r#"{"op":"anyPath","patterns":["**/Cargo.lock"]}"#;
const RUST_SOURCES: &str = r#"{"op":"anyPath","patterns":["**/Cargo.toml","**/*.rs"]}"#;
const APPLE: &str = r#"{"op":"anyExtension","extensions":["swift","m","mm"]}"#;
const PYTHON: &str =
    r#"{"op":"anyPath","patterns":["**/pyproject.toml","**/requirements*.txt","**/setup.py"]}"#;
const TAURI: &str = r#"{"op":"anyPath","patterns":["src-tauri/**"]}"#;

const NATIVE: CommandShape = CommandShape::Native {
    operation: "registry-check",
};

/// Exact provider projection from `src/registry/providers.json`.
pub const LEGACY_CHECK_SPECS: &[LegacyCheckSpec] = &[
    LegacyCheckSpec {
        provider_id: "legacy.apple.platform",
        check: "apple_platform",
        phase: "source",
        role: "candidate-generator",
        tool: "fs",
        selector: APPLE,
        command: NATIVE,
    },
    LegacyCheckSpec {
        provider_id: "legacy.architecture.decomposition",
        check: "decomposition",
        phase: "source",
        role: "deterministic",
        tool: "loc",
        selector: SOURCE,
        command: NATIVE,
    },
    LegacyCheckSpec {
        provider_id: "legacy.core.repo",
        check: "repo",
        phase: "source",
        role: "deterministic",
        tool: "git",
        selector: ALWAYS,
        command: CommandShape::Named {
            tool: "git",
            args: &["status", "--porcelain=v1"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.quality.build",
        check: "build",
        phase: "source",
        role: "deterministic",
        tool: "<project build>",
        selector: r#"{"op":"any","selectors":[{"op":"anyPackageScript","names":["build"]},{"op":"anyPath","patterns":["**/Cargo.toml"]}]}"#,
        command: CommandShape::Named {
            tool: "project-build",
            args: &[],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.quality.test",
        check: "test",
        phase: "source",
        role: "deterministic",
        tool: "project-test",
        selector: r#"{"op":"any","selectors":[{"op":"anyPackageScript","names":["test"]},{"op":"anyPath","patterns":["package.json","Cargo.toml","src-tauri/Cargo.toml"]}]}"#,
        command: CommandShape::Named {
            tool: "project-test",
            args: &[],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.quality.dead-code",
        check: "dead_code",
        phase: "source",
        role: "deterministic",
        tool: "knip",
        selector: PACKAGE,
        command: CommandShape::Named {
            tool: "knip",
            args: &["--reporter", "json"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.quality.debt-markers",
        check: "debt_markers",
        phase: "source",
        role: "deterministic",
        tool: "git grep",
        selector: SOURCE,
        command: CommandShape::Named {
            tool: "git",
            args: &["grep", "-nIE", "(ponytail:|TODO|FIXME|HACK|XXX)"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.quality.duplication",
        check: "duplication",
        phase: "source",
        role: "deterministic",
        tool: "jscpd",
        selector: SOURCE,
        command: CommandShape::Named {
            tool: "jscpd",
            args: &[".", "--reporters", "json", "--min-lines", "20", "--silent"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.quality.lint",
        check: "lint",
        phase: "source",
        role: "deterministic",
        tool: "biome|eslint|ruff|clippy",
        selector: SOURCE,
        command: CommandShape::Named {
            tool: "project-lint",
            args: &["--json"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.quality.negative-space",
        check: "negative_space",
        phase: "source",
        role: "deterministic",
        tool: "fs",
        selector: ALWAYS,
        command: NATIVE,
    },
    LegacyCheckSpec {
        provider_id: "legacy.quality.rust-unused-deps",
        check: "cargo_unused_deps",
        phase: "source",
        role: "deterministic",
        tool: "cargo-machete",
        selector: RUST_SOURCES,
        command: CommandShape::Named {
            tool: "cargo-machete",
            args: &["--with-metadata"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.quality.swift-lint",
        check: "swift_lint",
        phase: "source",
        role: "deterministic",
        tool: "swiftlint",
        selector: APPLE,
        command: CommandShape::Named {
            tool: "swiftlint",
            args: &["lint", "--quiet", "--reporter", "json"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.quality.tool-coverage",
        check: "tool_coverage",
        phase: "source",
        role: "deterministic",
        tool: "fs",
        selector: ALWAYS,
        command: NATIVE,
    },
    LegacyCheckSpec {
        provider_id: "legacy.quality.types",
        check: "types",
        phase: "source",
        role: "deterministic",
        tool: "tsc|basedpyright|mypy",
        selector: r#"{"op":"anyExtension","extensions":["ts","tsx","py"]}"#,
        command: CommandShape::Named {
            tool: "project-types",
            args: &["--json"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.react.hooks-config",
        check: "react_hooks",
        phase: "source",
        role: "deterministic",
        tool: "fs",
        selector: r#"{"op":"anyDependency","names":["react","react-dom"]}"#,
        command: NATIVE,
    },
    LegacyCheckSpec {
        provider_id: "legacy.runtime.app",
        check: "runtime",
        phase: "runtime",
        role: "deterministic",
        tool: "audit-runtime.mjs",
        selector: r#"{"op":"anyPackageScript","names":["dev","start","preview","qa:browser"]}"#,
        // Host-owned capture: the running Legion executable's own browser
        // route, resolved by `resolver::RUNTIME_CAPTURE_TOOL`. The per-surface
        // `--url`/viewport/`--actions` arguments are appended at run time by
        // `runtime_capture` from the plan-sealed `runner.runtime` inputs.
        command: CommandShape::Named {
            tool: "legion-qa-shot",
            args: &["script", "qa/qa-functional"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.binary-pins",
        check: "binary_pins",
        phase: "source",
        role: "candidate-generator",
        tool: "grep+github-api",
        selector: SOURCE,
        command: NATIVE,
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.dependency-pinning",
        check: "dep_pinning",
        phase: "source",
        role: "candidate-generator",
        tool: "grep",
        selector: SOURCE,
        command: NATIVE,
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.docker",
        check: "docker",
        phase: "source",
        role: "candidate-generator",
        tool: "hadolint",
        selector: r#"{"op":"anyPath","patterns":["**/Dockerfile","**/Containerfile"]}"#,
        command: CommandShape::Named {
            tool: "hadolint",
            args: &["--format", "json", "Dockerfile"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.github-actions-lint",
        check: "ci_lint",
        phase: "source",
        role: "candidate-generator",
        tool: "actionlint",
        selector: r#"{"op":"anyPath","patterns":[".github/workflows/**"]}"#,
        command: CommandShape::Named {
            tool: "actionlint",
            args: &["-format", "{{json .}}"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.js-licenses",
        check: "js_licenses",
        phase: "source",
        role: "candidate-generator",
        tool: "license-checker",
        selector: PACKAGE,
        command: CommandShape::Named {
            tool: "license-checker",
            args: &["--json", "--production"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.node-dependencies",
        check: "deps_cve",
        phase: "source",
        role: "candidate-generator",
        tool: "npm|pnpm|yarn audit",
        selector: PACKAGE,
        command: CommandShape::Named {
            tool: "package-audit",
            args: &["--json"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.python-dependencies",
        check: "py_deps_cve",
        phase: "source",
        role: "candidate-generator",
        tool: "pip-audit",
        selector: PYTHON,
        command: CommandShape::Named {
            tool: "pip-audit",
            args: &["--format", "json"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.rust-advisories",
        check: "cargo_audit",
        phase: "source",
        role: "candidate-generator",
        tool: "cargo-audit",
        selector: CARGO,
        command: CommandShape::Named {
            tool: "cargo-audit",
            args: &["--json"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.rust-policy",
        check: "cargo_deny",
        phase: "source",
        role: "candidate-generator",
        tool: "cargo-deny",
        selector: RUST_SOURCES,
        command: CommandShape::Named {
            tool: "cargo-deny",
            args: &["--format", "json", "check"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.rust-unsafe",
        check: "cargo_unsafe",
        phase: "source",
        role: "candidate-generator",
        tool: "cargo-geiger",
        selector: RUST_SOURCES,
        command: CommandShape::Named {
            tool: "cargo-geiger",
            args: &["--output-format", "Json", "--quiet"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.sast",
        check: "sast",
        phase: "source",
        role: "candidate-generator",
        tool: "semgrep",
        selector: SOURCE,
        command: CommandShape::Named {
            tool: "semgrep",
            args: &[
                "--config",
                "auto",
                "--json",
                "--quiet",
                "--exclude",
                "vendor",
                "--exclude",
                "qwik",
                "--exclude",
                ".audit",
                "--exclude",
                ".agent",
                "--exclude",
                "dist",
            ],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.secrets",
        check: "secrets",
        phase: "source",
        role: "candidate-generator",
        tool: "gitleaks",
        selector: ALWAYS,
        command: CommandShape::Named {
            tool: "gitleaks",
            // `git` (history) is swapped for `dir` by the executor when the root
            // is not a repository. gitleaks only writes a report when given a
            // destination; `-` is stdout, so the JSON is captured as the
            // receipt's stdout artifact. `--redact` keeps secret material out
            // of that artifact.
            args: &[
                "git",
                ".",
                "--report-format",
                "json",
                "--report-path",
                "-",
                "--redact",
                "--no-banner",
            ],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.security.vendored-dependencies",
        check: "vendored_deps",
        phase: "source",
        role: "candidate-generator",
        tool: "fs",
        selector: SOURCE,
        command: NATIVE,
    },
    LegacyCheckSpec {
        provider_id: "legacy.stack.node-outdated",
        check: "outdated",
        phase: "source",
        role: "deterministic",
        tool: "npm|pnpm outdated",
        selector: PACKAGE,
        command: CommandShape::Named {
            tool: "package-outdated",
            args: &["--json"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.stack.rust-outdated",
        check: "cargo_outdated",
        phase: "source",
        role: "deterministic",
        tool: "cargo-outdated",
        selector: CARGO,
        command: CommandShape::Named {
            tool: "cargo-outdated",
            args: &["--format", "json", "--root-deps-only"],
        },
    },
    LegacyCheckSpec {
        provider_id: "legacy.tauri.capabilities",
        check: "tauri_capabilities",
        phase: "source",
        role: "candidate-generator",
        tool: "fs",
        selector: TAURI,
        command: NATIVE,
    },
    LegacyCheckSpec {
        provider_id: "legacy.tauri.contract-mirror",
        check: "contract_mirror",
        phase: "source",
        role: "candidate-generator",
        tool: "grep",
        selector: TAURI,
        command: NATIVE,
    },
];

pub fn spec(provider_id: &str) -> Option<&'static LegacyCheckSpec> {
    LEGACY_CHECK_SPECS
        .iter()
        .find(|item| item.provider_id == provider_id)
}

pub fn specs() -> &'static [LegacyCheckSpec] {
    LEGACY_CHECK_SPECS
}

/// Capability class of an external scanner a legacy check may need on the host.
///
/// The class decides what a missing tool means for the run. It is typed here,
/// next to the frozen check projection, so the outcome is decided by the same
/// table that names the tool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapabilityClass {
    /// A native provider or lens covers the same domain. A missing tool is a
    /// `capability-absent:<tool>` note and never blocks the run.
    Substitutable { substitute: &'static str },
    /// No native substitute exists. A missing tool leaves the run incomplete
    /// through `unavailable:host-capability:<tool>`.
    Advisory,
    /// Adds information only. A missing tool is a note and never blocks.
    Informational,
}

/// Host capability declaration for one scanner tool named by the registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostCapability {
    pub tool: &'static str,
    pub class: CapabilityClass,
}

impl CapabilityClass {
    /// Native substitute that covers the domain when the tool is absent.
    pub const fn substitute(self) -> Option<&'static str> {
        match self {
            Self::Substitutable { substitute } => Some(substitute),
            Self::Advisory | Self::Informational => None,
        }
    }
}

/// Scanner tools whose absence has a declared meaning. Tools not listed here
/// keep the existing `unavailable:tool-missing:<tool>` behaviour.
pub const HOST_CAPABILITIES: &[HostCapability] = &[
    HostCapability {
        tool: "gitleaks",
        class: CapabilityClass::Substitutable {
            substitute: "security.credentials",
        },
    },
    HostCapability {
        tool: "semgrep",
        class: CapabilityClass::Substitutable {
            substitute: "native security detectors and the security lens",
        },
    },
    HostCapability {
        tool: "jscpd",
        class: CapabilityClass::Substitutable {
            substitute: "minimize lens",
        },
    },
    HostCapability {
        tool: "knip",
        class: CapabilityClass::Substitutable {
            substitute: "dead-file lens",
        },
    },
    HostCapability {
        tool: "cargo-machete",
        class: CapabilityClass::Substitutable {
            substitute: "minimize lens",
        },
    },
    HostCapability {
        tool: "swiftlint",
        class: CapabilityClass::Substitutable {
            substitute: "security.agentic-ci and ai-slop lens",
        },
    },
    HostCapability {
        tool: "actionlint",
        class: CapabilityClass::Substitutable {
            substitute: "security.agentic-ci",
        },
    },
    HostCapability {
        tool: "cargo-audit",
        class: CapabilityClass::Advisory,
    },
    HostCapability {
        tool: "pip-audit",
        class: CapabilityClass::Advisory,
    },
    HostCapability {
        tool: "cargo-deny",
        class: CapabilityClass::Advisory,
    },
    HostCapability {
        tool: "cargo-geiger",
        class: CapabilityClass::Informational,
    },
    HostCapability {
        tool: "cargo-outdated",
        class: CapabilityClass::Informational,
    },
    HostCapability {
        tool: "license-checker",
        class: CapabilityClass::Informational,
    },
];

/// Declared host capability for `tool`, if the scanner has one.
pub fn host_capability(tool: &str) -> Option<&'static HostCapability> {
    HOST_CAPABILITIES.iter().find(|item| item.tool == tool)
}

/// What an absent declared tool means for the run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AbsenceOutcome {
    /// Blocking gap reason, emitted as `unavailable:<reason>`.
    Blocking(String),
    /// Non-blocking coverage note.
    NonBlocking(String),
}

/// Outcome of a missing tool, or `None` when the tool has no declared class.
pub fn absence_outcome(tool: &str) -> Option<AbsenceOutcome> {
    match host_capability(tool)?.class {
        CapabilityClass::Advisory => Some(AbsenceOutcome::Blocking(format!(
            "host-capability:{tool}"
        ))),
        CapabilityClass::Substitutable { .. } | CapabilityClass::Informational => Some(
            AbsenceOutcome::NonBlocking(format!("capability-absent:{tool}")),
        ),
    }
}

#[cfg(test)]
mod capability_tests {
    use super::*;

    #[test]
    fn missing_substitutable_tool_does_not_block() {
        for tool in [
            "gitleaks",
            "semgrep",
            "jscpd",
            "knip",
            "cargo-machete",
            "swiftlint",
            "actionlint",
        ] {
            assert_eq!(
                absence_outcome(tool),
                Some(AbsenceOutcome::NonBlocking(format!("capability-absent:{tool}"))),
                "{tool} must note, not block"
            );
        }
    }

    #[test]
    fn missing_cargo_audit_blocks_when_its_provider_applies() {
        // The rust-advisories provider selects only when Cargo.lock exists, so
        // the absent-tool outcome is reached only in that case.
        assert_eq!(
            absence_outcome("cargo-audit"),
            Some(AbsenceOutcome::Blocking(
                "host-capability:cargo-audit".into()
            ))
        );
    }

    #[test]
    fn informational_tools_only_note() {
        for tool in ["cargo-geiger", "cargo-outdated", "license-checker"] {
            assert!(matches!(
                absence_outcome(tool),
                Some(AbsenceOutcome::NonBlocking(_))
            ));
        }
    }

    #[test]
    fn undeclared_tools_keep_existing_behaviour() {
        assert_eq!(absence_outcome("cargo-fmt"), None);
    }
}
