//! Applicability of the family providers whose inventory holds no file of
//! their family.
//!
//! A family with no source file and no family manifest in the frozen
//! inventory has nothing to inspect. Reporting it as a denominator gap made
//! every single-language repository read incomplete. Such a provider is
//! not-applicable instead: no context, tool, or denominator gap, no
//! degradation, and a summary that says so. It is never a clean pass of
//! inspected code.
//!
//! The rule is deliberately narrow:
//!
//! * an empty inventory was never scanned and keeps the existing accounting;
//! * any file of the family, selectable or not, keeps every gap that family
//!   produces today;
//! * `code.long-tail` keeps its own rule (files no family claims).
//!
//! The not-applicable result uses the engine's inapplicable shape
//! (`applicable: false`, `ProviderStatus::Ok`, no coverage), the same shape the
//! plan-level not-applicable path produces.

use super::evidence;
use crate::{inventory::InventoryEntry, AuditError};
use legion_contracts::{ProviderId, ProviderResult, ProviderStatus};
use serde_json::json;
use std::collections::BTreeMap;

/// `details` key holding the applicability verdict.
pub const APPLICABILITY_DETAIL: &str = "applicability";
/// Value of [`APPLICABILITY_DETAIL`] for a provider that does not apply.
pub const NOT_APPLICABLE: &str = "not-applicable";
/// Boolean `details` flag, the same one the plan-level not-applicable result sets.
pub const NOT_APPLICABLE_FLAG: &str = "notApplicable";
/// `details` key holding the typed reason, `no-<subject>-files-in-inventory`.
pub const NOT_APPLICABLE_REASON: &str = "notApplicableReason";
/// `details` key holding the human summary.
pub const SUMMARY_DETAIL: &str = "summary";

/// The typed reason when `provider_id` has no file of its family in
/// `entries`, or `None` when the family applies (or the rule does not).
pub fn family_absence(provider_id: &str, entries: &[InventoryEntry]) -> Option<String> {
    let family = provider_id.strip_prefix("code.")?;
    if family == "long-tail" || entries.is_empty() {
        return None;
    }
    let config = evidence::config_for(provider_id)?;
    let present = entries.iter().any(|entry| {
        let name = file_name(&entry.path);
        config
            .extensions
            .contains(&extension_of(&entry.path).as_str())
            || is_family_manifest(provider_id, name)
    });
    (!present).then(|| format!("no-{family}-files-in-inventory"))
}

/// The not-applicable result for `provider_id`. `subject` names what was
/// absent in the summary (`"c-family"`, `"frontend"`, ...).
pub fn not_applicable_result(
    provider_id: &str,
    required: bool,
    subject: &str,
    reason: &str,
) -> Result<ProviderResult, AuditError> {
    Ok(ProviderResult {
        schema_version: 1,
        provider: ProviderId::new(provider_id.to_owned())?,
        applicable: false,
        required,
        status: ProviderStatus::Ok,
        complete: false,
        coverage: None,
        findings: Vec::new(),
        coverage_gaps: Vec::new(),
        degradation: Vec::new(),
        details: BTreeMap::from([
            (APPLICABILITY_DETAIL.to_owned(), json!(NOT_APPLICABLE)),
            (NOT_APPLICABLE_FLAG.to_owned(), json!(true)),
            (NOT_APPLICABLE_REASON.to_owned(), json!(reason)),
            (
                SUMMARY_DETAIL.to_owned(),
                json!(format!("not applicable: no {subject} files")),
            ),
        ]),
    })
}

/// Manifests that make a family applicable even without a source file. The
/// lists stay conservative: a manifest that is present keeps the gaps.
/// `Makefile` is deliberately absent because it appears in repositories of
/// every language.
fn is_family_manifest(provider_id: &str, name: &str) -> bool {
    match provider_id {
        "code.c-family" => matches!(
            name,
            "compile_commands.json" | "CMakeLists.txt" | "meson.build"
        ),
        "code.dotnet" => {
            [".csproj", ".fsproj", ".vbproj", ".sln"]
                .iter()
                .any(|suffix| name.ends_with(*suffix))
                || matches!(name, "Directory.Build.props" | "Directory.Build.targets")
        }
        "code.go" => matches!(name, "go.mod" | "go.work"),
        "code.javascript" => matches!(name, "package.json" | "tsconfig.json" | "jsconfig.json"),
        "code.jvm" => matches!(
            name,
            "pom.xml"
                | "build.gradle"
                | "build.gradle.kts"
                | "settings.gradle"
                | "settings.gradle.kts"
                | "gradlew"
                | "mvnw"
        ),
        "code.mobile" => matches!(name, "Package.swift" | "project.pbxproj" | "Podfile"),
        "code.php-ruby" => matches!(name, "composer.json" | "composer.lock" | "Gemfile"),
        "code.python" => {
            matches!(
                name,
                "pyproject.toml" | "setup.py" | "setup.cfg" | "Pipfile"
            ) || (name.starts_with("requirements") && name.ends_with(".txt"))
        }
        "code.rust" => matches!(name, "Cargo.toml" | "Cargo.lock"),
        _ => false,
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Same rule as the producer's extension selection, so applicability and
/// selection can never disagree about what counts as a family source file.
fn extension_of(path: &str) -> String {
    file_name(path)
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str) -> InventoryEntry {
        InventoryEntry {
            path: path.into(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
            package_scripts: Vec::new(),
            source_file: true,
            digest: None,
        }
    }

    #[test]
    fn family_without_any_file_is_absent_with_a_typed_reason() {
        let entries = [entry("package.json"), entry("src/app.js")];
        assert_eq!(
            family_absence("code.c-family", &entries).as_deref(),
            Some("no-c-family-files-in-inventory")
        );
        assert_eq!(
            family_absence("code.mobile", &entries).as_deref(),
            Some("no-mobile-files-in-inventory")
        );
        assert_eq!(family_absence("code.javascript", &entries), None);
    }

    #[test]
    fn a_single_family_file_or_manifest_keeps_the_family_applicable() {
        assert_eq!(
            family_absence("code.c-family", &[entry("src/main.C")]),
            None,
            "extension match is case-insensitive"
        );
        assert_eq!(
            family_absence("code.python", &[entry("requirements-dev.txt")]),
            None
        );
        assert_eq!(family_absence("code.rust", &[entry("Cargo.toml")]), None);
    }

    #[test]
    fn empty_inventory_and_long_tail_keep_their_own_rules() {
        assert_eq!(family_absence("code.go", &[]), None);
        assert_eq!(
            family_absence("code.long-tail", &[entry("README.md")]),
            None
        );
    }

    #[test]
    fn not_applicable_result_is_inapplicable_and_carries_no_gap() {
        let result = not_applicable_result(
            "code.dotnet",
            false,
            "dotnet",
            "no-dotnet-files-in-inventory",
        )
        .unwrap();
        assert!(!result.applicable);
        assert!(!result.complete);
        assert_eq!(result.status, ProviderStatus::Ok);
        assert!(result.coverage.is_none());
        assert!(result.coverage_gaps.is_empty());
        assert!(result.degradation.is_empty());
        assert_eq!(
            result.details[APPLICABILITY_DETAIL],
            json!("not-applicable")
        );
        assert_eq!(
            result.details[SUMMARY_DETAIL],
            json!("not applicable: no dotnet files")
        );
        result.validate().unwrap();
    }
}
