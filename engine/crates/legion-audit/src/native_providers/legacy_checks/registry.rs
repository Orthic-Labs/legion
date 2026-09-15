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
            args: &["--format", "json"],
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
        command: CommandShape::Named {
            tool: "audit-runtime",
            args: &["--json"],
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
            args: &["--format", "json"],
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
            args: &["-format", "json"],
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
            args: &["--output-format", "Json"],
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
            args: &["--json"],
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
            args: &["git", ".", "--report-format", "json", "--no-banner"],
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
