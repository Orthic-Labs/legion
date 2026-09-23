//! Parity tests for `legacy_checks::registry` command shapes against the
//! historical JS collector (`tools/audit/collect-facts.mjs`) this frozen
//! registry projects. Each assertion below pins a concrete argv bug that
//! was found by diffing registry.rs against collect-facts.mjs and is now
//! fixed in registry.rs; these tests exist on the PRODUCTION lookup path
//! (`legacy_checks::spec`), not on a private helper, so a regression here
//! is a regression in the exact command Legion launches.

use legion_audit::native_providers::legacy_checks::{spec, CommandShape};

fn named_args(provider_id: &str) -> (&'static str, &'static [&'static str]) {
    let found = spec(provider_id).unwrap_or_else(|| panic!("no spec for {provider_id}"));
    match found.command {
        CommandShape::Named { tool, args } => (tool, args),
        other => panic!("expected Named command for {provider_id}, got {other:?}"),
    }
}

/// collect-facts.mjs: `cargo geiger --output-format Json --quiet`.
/// Missing `--quiet` lets cargo build noise interleave with the JSON line,
/// which is exactly the failure mode `--quiet` exists to avoid upstream.
#[test]
fn cargo_unsafe_matches_js_quiet_flag() {
    let (tool, args) = named_args("legacy.security.rust-unsafe");
    assert_eq!(tool, "cargo-geiger");
    assert_eq!(args, &["--output-format", "Json", "--quiet"]);
}

/// collect-facts.mjs: `actionlint -format "{{json .}}"`. actionlint's
/// `-format` flag takes a Go template, not a bare reporter name — passing
/// the literal string "json" is not a valid actionlint invocation.
#[test]
fn ci_lint_uses_actionlint_json_template() {
    let (tool, args) = named_args("legacy.security.github-actions-lint");
    assert_eq!(tool, "actionlint");
    assert_eq!(args, &["-format", "{{json .}}"]);
}

/// collect-facts.mjs: `hadolint --format json Dockerfile`. Without the
/// filename argument hadolint reads stdin and blocks/produces nothing.
#[test]
fn docker_check_targets_dockerfile() {
    let (tool, args) = named_args("legacy.security.docker");
    assert_eq!(tool, "hadolint");
    assert_eq!(args, &["--format", "json", "Dockerfile"]);
}

/// collect-facts.mjs: `semgrep --config auto --json --quiet --exclude vendor
/// --exclude qwik --exclude .audit --exclude .agent --exclude dist`.
/// Without `--config auto` semgrep has no ruleset and scans nothing.
#[test]
fn sast_matches_js_semgrep_flags() {
    let (tool, args) = named_args("legacy.security.sast");
    assert_eq!(tool, "semgrep");
    assert_eq!(
        args,
        &[
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
        ]
    );
}

/// collect-facts.mjs: `jscpd . --reporters json --min-lines 20 --silent
/// --output "<dir>"`. The prior registry entry used `--format json`, which
/// is not a jscpd flag (the correct flag is `--reporters`) and omitted the
/// scan root and `--min-lines` threshold entirely.
///
/// `--output` is intentionally not pinned here: it needs a per-run
/// temporary directory, which a `&'static [&'static str]` argv cannot
/// express. That gap is a known follow-up, not silently claimed as fixed.
#[test]
fn duplication_uses_jscpd_reporters_flag() {
    let (tool, args) = named_args("legacy.quality.duplication");
    assert_eq!(tool, "jscpd");
    assert_eq!(
        args,
        &[".", "--reporters", "json", "--min-lines", "20", "--silent"]
    );
}

/// Every `Named` command in the registry resolves through the frozen
/// `spec()`/`specs()` production lookup, not a copy of the table, so a
/// provider_id typo cannot silently diverge between the two.
#[test]
fn spec_lookup_is_consistent_with_specs_listing() {
    use legion_audit::native_providers::legacy_checks::specs;
    for entry in specs() {
        let found = spec(entry.provider_id)
            .unwrap_or_else(|| panic!("spec() cannot find {}", entry.provider_id));
        assert_eq!(found.check, entry.check);
        assert_eq!(found.command, entry.command);
    }
}
