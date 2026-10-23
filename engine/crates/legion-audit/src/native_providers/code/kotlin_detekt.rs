//! Independent Kotlin detekt coverage: source & typed modes (A04).
//!
//! Two proposed providers, independent selectors & outcomes:
//!
//! * `code.kotlin.detekt-source` — plain Kotlin sources with a pinned detekt
//!   distribution on a pinned JVM and an audit-owned rule config. It never
//!   requires `legion-jvm-sdk.json`, a pinned Gradle wrapper, repo plugins or
//!   repo scripts: a plain Kotlin repo yields source evidence when the tool
//!   is admitted.
//! * `code.kotlin.detekt-typed` — same scanner plus exact classpath,
//!   generated-source, compilation-target & variant evidence from an admitted
//!   build or an authenticated import. Missing or incompatible classpath is
//!   `typed-classpath-*` incomplete; it can never silently fall back and
//!   claim typed coverage, and the source result stays usable on its own.
//!
//! This module is planner + parser only (edit-only packet). Execution goes
//! through root's `tools.rs` dispatch over the sandboxed
//! `ExternalProjectTool` route; [`DetektPlan::runner_record`] is the record
//! root translates into a planned tool run. Nothing here runs a process,
//! reads the audited tree, or turns a missing JDK/detekt, a version
//! mismatch, malformed/truncated output, or a nonzero operational exit into
//! clean.
//!
//! Supported machine report: detekt SARIF (`--report sarif:<path>`), SARIF
//! `2.1.0`, tool driver `detekt` at exactly [`PINNED_DETEKT_VERSION`]. Any
//! other report version, driver, or tool version is a named gap. The pinned
//! detekt exit contract for that version is `0` = no issues at/above the
//! owned config's `maxIssues: 0` gate, `2` = issues found; every other exit
//! (or no exit — signal/timeout) is an operational/tool failure regardless
//! of any report bytes. Root must qualify these exit semantics with the
//! pinned distribution before production admission.

use super::{common::LanguageConfig, evidence::NativeFinding};
use crate::inventory::InventoryEntry;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

pub const SOURCE_PROVIDER_ID: &str = "code.kotlin.detekt-source";
pub const TYPED_PROVIDER_ID: &str = "code.kotlin.detekt-typed";
/// Generic provider whose diagnostics overlap; both execution records stay.
pub const GENERIC_JVM_PROVIDER_ID: &str = "code.jvm";
pub const TOOL_ID: &str = "detekt";
/// Proposed root pin-catalog entry; not an installed/qualified claim.
pub const PINNED_DETEKT_VERSION: &str = "1.23.8";
/// JDK line already pinned in `scripts/ci/audit-jvm-sdk-inputs.json`.
pub const PINNED_JDK_VERSION: &str = "21.0.9+10";
/// Frozen default for `--language-version`; overridable only via the pin.
pub const DEFAULT_KOTLIN_LANGUAGE_VERSION: &str = "2.0";
pub const DEFAULT_JVM_TARGET: &str = "17";
pub const SUPPORTED_SARIF_VERSION: &str = "2.1.0";
pub const REPORT_FORMAT: &str = "sarif";
pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_ISSUES_FOUND: i32 = 2;
/// Findings kept per outcome; the rest is a counted truncation gap
/// (mirrors `tools::MAX_TOOL_FINDINGS`).
pub const MAX_DETEKT_FINDINGS: usize = 200;
const MAX_MESSAGE_CHARS: usize = 300;

/// Audit-owned detekt config, frozen by digest into every plan. Source mode
/// loads only this file (staged by root into scratch); a repository
/// `detekt.yml`, baseline, plugin or build script is never consulted.
/// `maxIssues: 0` makes any weighted finding fail the detekt build gate, so
/// exit `2` and a findings report must agree. Root qualification must
/// validate this config against the pinned distribution before admission.
pub const OWNED_CONFIG_YAML: &str = "\
build:
  maxIssues: 0
  excludeCorrectable: false
config:
  validation: true
  warningsAsErrors: true
processors:
  active: true
console-reports:
  active: false
output-reports:
  active: false
comments:
  active: true
complexity:
  active: true
coroutines:
  active: false
empty-blocks:
  active: true
exceptions:
  active: true
naming:
  active: true
performance:
  active: true
potential-bugs:
  active: true
style:
  active: true
";

pub fn owned_config_digest() -> String {
    sha256_hex(OWNED_CONFIG_YAML.as_bytes())
}

/// Analyzer accounting for source mode. `required_context` is empty on
/// purpose: no `legion-jvm-sdk.json`, wrapper or source-set contract.
pub const SOURCE_CONFIG: LanguageConfig = LanguageConfig::new(
    "kotlin.detekt-source",
    &["kt"],
    &[("kotlin", &["kt"])],
    &[TOOL_ID],
    &[],
);
/// Typed mode demands `typedClasspath` context proven outside this module.
pub const TYPED_CONFIG: LanguageConfig = LanguageConfig::new(
    "kotlin.detekt-typed",
    &["kt"],
    &[("kotlin", &["kt"])],
    &[TOOL_ID],
    &["typedClasspath"],
);

pub fn analyze_source(input: &Value) -> Value {
    super::common::analyze_language(&SOURCE_CONFIG, input)
}

pub fn analyze_typed(input: &Value) -> Value {
    super::common::analyze_language(&TYPED_CONFIG, input)
}

/// Independent frozen-denominator selector shared by both modes; mode
/// independence comes from separate provider ids, plans and outcomes.
/// `.kts` is selected so it is accounted for, then reported as unsupported
/// syntax by selection — never silently dropped from the denominator.
pub fn provider_selector() -> Value {
    json!({"op": "anyExtension", "extensions": ["kt", "kts"]})
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn gap(provider_id: &str, kind: &str) -> String {
    format!("{provider_id}:{kind}")
}

fn extension_of(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    match name.rfind('.') {
        Some(index) => name[index + 1..].to_ascii_lowercase(),
        None => String::new(),
    }
}

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn dir_of(path: &str) -> String {
    match path.rfind('/') {
        Some(index) => path[..index].to_string(),
        None => String::new(),
    }
}

/// Segment glob: `**` spans path segments, `*`/`?` stay inside one segment.
/// Paths are repository-relative with `/` separators (inventory form).
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let pattern: Vec<&str> = pattern.split('/').collect();
    let path: Vec<&str> = path.split('/').collect();
    glob_segments(&pattern, &path)
}

fn glob_segments(pattern: &[&str], path: &[&str]) -> bool {
    if pattern.is_empty() {
        return path.is_empty();
    }
    if pattern[0] == "**" {
        return (0..=path.len()).any(|skip| glob_segments(&pattern[1..], &path[skip..]));
    }
    if path.is_empty() || !glob_segment(pattern[0], path[0]) {
        return false;
    }
    glob_segments(&pattern[1..], &path[1..])
}

fn glob_segment(pattern: &str, segment: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let segment: Vec<char> = segment.chars().collect();
    // Classic wildcard match with backtracking on the last '*'.
    let (mut p, mut s) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while s < segment.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == segment[s]) {
            p += 1;
            s += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            mark = s;
            p += 1;
        } else if let Some(star_at) = star {
            p = star_at + 1;
            mark += 1;
            s = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}

// ---------------------------------------------------------------------------
// Pin, selection & frozen scope
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetektMode {
    Source,
    Typed,
}

impl DetektMode {
    pub fn provider_id(self) -> &'static str {
        match self {
            DetektMode::Source => SOURCE_PROVIDER_ID,
            DetektMode::Typed => TYPED_PROVIDER_ID,
        }
    }
}

/// Pinned detekt distribution + JVM identity, supplied by root's pin
/// catalog. A pin is an identity claim, not proof of installation: root's
/// runner still resolves, digests and version-probes the executable.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetektToolPin {
    pub detekt_version: String,
    /// `sha256:<hex>` of the pinned distribution archive/jar.
    pub distribution_digest: String,
    pub jdk_version: String,
    /// Frozen `--language-version` value.
    pub kotlin_language_version: String,
    /// Frozen `--jvm-target` value.
    pub jvm_target: String,
}

impl DetektToolPin {
    pub fn pinned() -> Self {
        Self {
            detekt_version: PINNED_DETEKT_VERSION.into(),
            // Root fills the real catalog digest; empty can never validate.
            distribution_digest: String::new(),
            jdk_version: PINNED_JDK_VERSION.into(),
            kotlin_language_version: DEFAULT_KOTLIN_LANGUAGE_VERSION.into(),
            jvm_target: DEFAULT_JVM_TARGET.into(),
        }
    }
}

/// Named gaps for a pin; empty means the pin is internally admissible.
/// Any gap means no executable argv is planned — never a best-effort run
/// under a mismatched identity.
pub fn validate_pin(pin: &DetektToolPin, provider_id: &str) -> Vec<String> {
    let mut gaps = Vec::new();
    if pin.detekt_version != PINNED_DETEKT_VERSION {
        gaps.push(gap(
            provider_id,
            &format!("detekt-version-mismatch:{}", pin.detekt_version),
        ));
    }
    if !is_sha256_digest(&pin.distribution_digest) {
        gaps.push(gap(provider_id, "detekt-distribution-digest-missing"));
    }
    if pin.jdk_version.trim().is_empty() {
        gaps.push(gap(provider_id, "jdk-version-missing"));
    }
    if pin.kotlin_language_version.trim().is_empty() {
        gaps.push(gap(provider_id, "kotlin-language-version-missing"));
    }
    if pin.jvm_target.trim().is_empty() {
        gaps.push(gap(provider_id, "jvm-target-missing"));
    }
    gaps
}

/// Extract the version from `detekt --version` output (`1.23.8` alone or
/// `detekt version 1.23.8`). Unrecognized output is `None`, which callers
/// must treat as a version gap, not as a pass.
pub fn parse_version_output(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    for line in text.lines() {
        let line = line.trim();
        let candidate = line
            .strip_prefix("detekt version ")
            .or_else(|| line.strip_prefix("detekt "))
            .unwrap_or(line)
            .trim();
        let mut parts = candidate.split('.');
        if candidate.len() <= 32
            && parts.clone().count() == 3
            && parts.all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        {
            return Some(candidate.to_string());
        }
    }
    None
}

pub fn version_gaps(probed: Option<&str>, pin: &DetektToolPin, provider_id: &str) -> Vec<String> {
    match probed {
        Some(version) if version == pin.detekt_version => Vec::new(),
        Some(version) => vec![gap(
            provider_id,
            &format!("detekt-version-mismatch:{version}"),
        )],
        None => vec![gap(provider_id, "detekt-version-unproven")],
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenKotlinFile {
    pub path: String,
    /// Inventory digest when frozen; `None` is itself reported by planners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetektExclusion {
    /// Repository-relative glob (`**`/`*`/`?`), e.g. `**/generated/**`.
    pub pattern: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExcludedFile {
    pub path: String,
    pub pattern: String,
}

/// Denominator accounting for one mode: every selected Kotlin path is
/// scanned, excluded (with the frozen pattern that claimed it), or named
/// unsupported. Nothing selected is dropped silently.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct KotlinSelection {
    pub scanned: Vec<FrozenKotlinFile>,
    pub excluded: Vec<ExcludedFile>,
    /// `.kts` scripts: detekt/Kotlin-script syntax is not claimed here.
    pub unsupported: Vec<String>,
    /// Module root (nearest build-file directory, `""` = repo root) to its
    /// scanned paths; multi-module repos stay separately accountable.
    pub modules: BTreeMap<String, Vec<String>>,
}

const BUILD_FILES: &[&str] = &[
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
    "pom.xml",
];

pub fn select_kotlin_files(
    entries: &[InventoryEntry],
    exclusions: &[DetektExclusion],
) -> KotlinSelection {
    let build_dirs: Vec<String> = entries
        .iter()
        .filter(|entry| BUILD_FILES.contains(&name_of(&entry.path)))
        .map(|entry| dir_of(&entry.path))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let module_of = |path: &str| -> String {
        build_dirs
            .iter()
            .filter(|dir| dir.is_empty() || path.starts_with(&format!("{dir}/")))
            .max_by_key(|dir| dir.len())
            .cloned()
            .unwrap_or_default()
    };
    let mut selection = KotlinSelection::default();
    let mut kotlin: Vec<&InventoryEntry> = entries
        .iter()
        .filter(|entry| matches!(extension_of(&entry.path).as_str(), "kt" | "kts"))
        .collect();
    kotlin.sort_by(|left, right| left.path.cmp(&right.path));
    for entry in kotlin {
        if extension_of(&entry.path) == "kts" {
            selection.unsupported.push(entry.path.clone());
            continue;
        }
        if let Some(exclusion) = exclusions
            .iter()
            .find(|exclusion| glob_match(&exclusion.pattern, &entry.path))
        {
            selection.excluded.push(ExcludedFile {
                path: entry.path.clone(),
                pattern: exclusion.pattern.clone(),
            });
            continue;
        }
        selection
            .modules
            .entry(module_of(&entry.path))
            .or_default()
            .push(entry.path.clone());
        selection.scanned.push(FrozenKotlinFile {
            path: entry.path.clone(),
            digest: entry.digest.clone(),
        });
    }
    selection
}

// ---------------------------------------------------------------------------
// Typed-mode evidence & plugin qualification
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClasspathEntry {
    pub path: String,
    /// `sha256:<hex>` of the exact jar/classes directory seal.
    pub digest: String,
}

pub fn compute_classpath_digest(classpath: &[ClasspathEntry]) -> String {
    let mut items: Vec<&ClasspathEntry> = classpath.iter().collect();
    items.sort_by(|left, right| left.path.cmp(&right.path));
    let canonical = items
        .iter()
        .map(|entry| format!("{}\0{}", entry.path, entry.digest))
        .collect::<Vec<_>>()
        .join("\n");
    sha256_hex(canonical.as_bytes())
}

/// How typed evidence was produced. `AuthenticatedImport.authenticated`
/// must be set only by root's importer after provenance verification; this
/// module never infers it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum TypedProvenance {
    #[serde(rename_all = "camelCase")]
    AdmittedBuild {
        receipt_id: String,
        artifact_digest: String,
    },
    #[serde(rename_all = "camelCase")]
    AuthenticatedImport {
        artifact_digest: String,
        attestor: String,
        authenticated: bool,
    },
}

/// Exact typed inputs from an admitted build or authenticated import.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TypedClasspathEvidence {
    pub classpath: Vec<ClasspathEntry>,
    /// Recomputed must equal `compute_classpath_digest(classpath)`.
    pub classpath_digest: String,
    pub generated_sources: Vec<FrozenKotlinFile>,
    /// e.g. `android-35`, `jvm-17`; must equal the frozen expectation.
    pub compilation_target: String,
    /// e.g. `debug`/`release`/flavor combination; exact match required.
    pub variant: String,
    pub provenance: TypedProvenance,
}

/// Typed classpath input built from an owner-admitted Gradle model. The
/// untrusted JSON may carry only classpath, generatedSources, compilationTarget
/// and variant; `classpathDigest` is always recomputed here and provenance is
/// always the caller's owner-bound value, so a model can never self-attest.
pub fn typed_evidence_from_model_value(
    value: &Value,
    provenance: TypedProvenance,
) -> Result<TypedClasspathEvidence, String> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Raw {
        classpath: Vec<ClasspathEntry>,
        #[serde(default)]
        generated_sources: Vec<FrozenKotlinFile>,
        compilation_target: String,
        variant: String,
    }
    let raw: Raw = serde_json::from_value(value.clone())
        .map_err(|error| format!("typed classpath model: {error}"))?;
    let classpath_digest = compute_classpath_digest(&raw.classpath);
    Ok(TypedClasspathEvidence {
        classpath: raw.classpath,
        classpath_digest,
        generated_sources: raw.generated_sources,
        compilation_target: raw.compilation_target,
        variant: raw.variant,
        provenance,
    })
}

/// Named typed gaps; empty means typed argv may be planned. Wrong/missing
/// variant classpath is incomplete here — callers keep the source result.
pub fn validate_typed_evidence(
    evidence: Option<&TypedClasspathEvidence>,
    expected_target: &str,
    expected_variant: &str,
    provider_id: &str,
) -> Vec<String> {
    let Some(evidence) = evidence else {
        return vec![gap(provider_id, "typed-classpath-missing")];
    };
    let mut gaps = Vec::new();
    if evidence.classpath.is_empty() {
        gaps.push(gap(provider_id, "typed-classpath-empty"));
    }
    for entry in &evidence.classpath {
        if entry.path.trim().is_empty() || !is_sha256_digest(&entry.digest) {
            gaps.push(gap(
                provider_id,
                &format!("typed-classpath-entry-unsealed:{}", entry.path),
            ));
        }
    }
    if evidence.classpath_digest != compute_classpath_digest(&evidence.classpath) {
        gaps.push(gap(provider_id, "typed-classpath-digest-mismatch"));
    }
    for generated in &evidence.generated_sources {
        if generated
            .digest
            .as_deref()
            .is_none_or(|d| !is_sha256_digest(d))
        {
            gaps.push(gap(
                provider_id,
                &format!("typed-generated-source-unsealed:{}", generated.path),
            ));
        }
    }
    if expected_target.is_empty() || evidence.compilation_target != expected_target {
        gaps.push(gap(
            provider_id,
            &format!("typed-target-mismatch:{}", evidence.compilation_target),
        ));
    }
    if expected_variant.is_empty() || evidence.variant != expected_variant {
        gaps.push(gap(
            provider_id,
            &format!("typed-variant-mismatch:{}", evidence.variant),
        ));
    }
    match &evidence.provenance {
        TypedProvenance::AdmittedBuild {
            receipt_id,
            artifact_digest,
        } => {
            if receipt_id.trim().is_empty() {
                gaps.push(gap(provider_id, "typed-build-receipt-missing"));
            }
            if !is_sha256_digest(artifact_digest) {
                gaps.push(gap(provider_id, "typed-build-artifact-unsealed"));
            }
        }
        TypedProvenance::AuthenticatedImport {
            artifact_digest,
            attestor,
            authenticated,
        } => {
            if !authenticated || attestor.trim().is_empty() {
                gaps.push(gap(provider_id, "typed-import-unauthenticated"));
            }
            if !is_sha256_digest(artifact_digest) {
                gaps.push(gap(provider_id, "typed-import-artifact-unsealed"));
            }
        }
    }
    gaps.sort();
    gaps.dedup();
    gaps
}

/// Actual rule/plugin qualification for non-default rulesets. Coroutine &
/// Compose rules ship as plugins outside the pinned default distribution;
/// without a record naming the exact qualified rule ids, no
/// coroutine/Compose coverage may be claimed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PluginQualification {
    pub plugin_id: String,
    pub version: String,
    pub distribution_digest: String,
    /// Exact SARIF rule ids this plugin is qualified for.
    pub rules: Vec<String>,
}

fn plugin_qualification_gaps(plugins: &[PluginQualification], provider_id: &str) -> Vec<String> {
    let mut gaps = Vec::new();
    for plugin in plugins {
        if plugin.plugin_id.trim().is_empty()
            || plugin.version.trim().is_empty()
            || !is_sha256_digest(&plugin.distribution_digest)
            || plugin.rules.is_empty()
        {
            gaps.push(gap(
                provider_id,
                &format!("detekt-plugin-unqualified:{}", plugin.plugin_id),
            ));
        }
    }
    gaps
}

/// Rule-id namespaces that are plugin claims, not default-ruleset claims.
fn plugin_namespace(rule_id: &str) -> Option<&'static str> {
    let normalized = rule_id.to_ascii_lowercase();
    if normalized.contains("coroutine") {
        Some("coroutines")
    } else if normalized.contains("compose") {
        Some("compose")
    } else {
        None
    }
}

fn rule_qualified(rule_id: &str, plugins: &[PluginQualification]) -> bool {
    if plugin_namespace(rule_id).is_none() {
        return true;
    }
    plugins
        .iter()
        .any(|plugin| plugin.rules.iter().any(|rule| rule == rule_id))
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct DetektOptions {
    pub exclusions: Vec<DetektExclusion>,
    /// Program root resolves & digests (candidate name only, e.g. `java`).
    pub java_program: String,
    /// Pinned distribution jar, as staged by root (argv value, not a repo path).
    pub distribution_jar: String,
    /// Owned config path as staged by root into scratch.
    pub owned_config_path: String,
    /// SARIF report path inside scratch.
    pub report_path: String,
    /// `--base-path` so SARIF uris are repository-relative.
    pub base_path: String,
    /// Qualified plugin jars (argv values) paired by index with `plugins`.
    pub plugin_jars: Vec<String>,
    pub plugins: Vec<PluginQualification>,
    pub max_findings: usize,
}

impl Default for DetektOptions {
    fn default() -> Self {
        Self {
            exclusions: Vec::new(),
            java_program: "java".into(),
            distribution_jar: "detekt-cli-all.jar".into(),
            owned_config_path: "detekt-owned.yml".into(),
            report_path: "detekt.sarif".into(),
            base_path: ".".into(),
            plugin_jars: Vec::new(),
            plugins: Vec::new(),
            max_findings: MAX_DETEKT_FINDINGS,
        }
    }
}

/// Everything frozen before execution. `scope_digest` is the denominator
/// digest root binds into plan/report evidence (A02 `denominatorDigest`).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenDetektScope {
    pub provider_id: String,
    pub mode: DetektMode,
    pub tool_version: String,
    pub config_digest: String,
    pub kotlin_language_version: String,
    pub jvm_target: String,
    /// Actual scanned files, with inventory digests.
    pub scanned: Vec<FrozenKotlinFile>,
    pub excluded: Vec<ExcludedFile>,
    pub unsupported: Vec<String>,
    pub modules: BTreeMap<String, Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub typed_classpath_digest: Option<String>,
    pub qualified_rules: Vec<String>,
    pub scope_digest: String,
}

fn scope_digest(scope: &FrozenDetektScope) -> String {
    let files = scope
        .scanned
        .iter()
        .map(|file| format!("{}\0{}", file.path, file.digest.as_deref().unwrap_or("")))
        .collect::<Vec<_>>()
        .join("\n");
    let excluded = scope
        .excluded
        .iter()
        .map(|file| format!("{}\0{}", file.path, file.pattern))
        .collect::<Vec<_>>()
        .join("\n");
    let modules = scope
        .modules
        .iter()
        .map(|(module, paths)| format!("{module}\0{}", paths.join(",")))
        .collect::<Vec<_>>()
        .join("\n");
    sha256_hex(
        format!(
            "{}\0{:?}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            scope.provider_id,
            scope.mode,
            scope.tool_version,
            scope.config_digest,
            scope.kotlin_language_version,
            scope.jvm_target,
            files,
            excluded,
            scope.unsupported.join("\n"),
            scope.typed_classpath_digest.as_deref().unwrap_or(""),
            modules,
            scope.qualified_rules.join("\n"),
        )
        .as_bytes(),
    )
}

/// One planned (or refused) detekt run. `argv` is `None` exactly when the
/// plan is incomplete before execution (bad pin, zero scanned files, or
/// unproven typed evidence); gaps name why. Typed refusal never borrows
/// the source argv.
#[derive(Clone, Debug)]
pub struct DetektPlan {
    pub provider_id: &'static str,
    pub mode: DetektMode,
    pub program: String,
    pub argv: Option<Vec<String>>,
    pub version_argv: Vec<String>,
    pub accepted_exit_codes: Vec<i32>,
    pub report_path: String,
    /// True when argv lists every scanned file as its own `--input`, which
    /// is the scanned-set proof [`parse_sarif_report`] accepts alongside
    /// SARIF artifacts (root proves it from the sealed receipt argv).
    pub explicit_input_list: bool,
    pub scope: FrozenDetektScope,
    pub gaps: Vec<String>,
}

impl DetektPlan {
    pub fn is_runnable(&self) -> bool {
        self.argv.is_some()
    }

    /// Runner record for root's `tools.rs/code` dispatch & registry wiring.
    /// This is a plan, never an execution receipt.
    pub fn runner_record(&self) -> Value {
        json!({
            "providerId": self.provider_id,
            "tool": TOOL_ID,
            "mode": match self.mode { DetektMode::Source => "source", DetektMode::Typed => "typed" },
            "programCandidates": [self.program],
            "argv": self.argv,
            "versionArgv": self.version_argv,
            "acceptedExitCodes": self.accepted_exit_codes,
            "parser": "detekt-sarif-2.1.0",
            "reportPath": self.report_path,
            "explicitInputList": self.explicit_input_list,
            "scopeDigest": self.scope.scope_digest,
            "configDigest": self.scope.config_digest,
            "executed": false,
            "gaps": self.gaps,
        })
    }
}

fn build_argv(
    options: &DetektOptions,
    pin: &DetektToolPin,
    scope: &FrozenDetektScope,
    typed: Option<&TypedClasspathEvidence>,
) -> Vec<String> {
    let mut argv = vec![
        "-jar".to_string(),
        options.distribution_jar.clone(),
        "--config".to_string(),
        options.owned_config_path.clone(),
        "--base-path".to_string(),
        options.base_path.clone(),
        "--language-version".to_string(),
        pin.kotlin_language_version.clone(),
        "--jvm-target".to_string(),
        pin.jvm_target.clone(),
        "--report".to_string(),
        format!("{REPORT_FORMAT}:{}", options.report_path),
    ];
    // Every frozen scanned file is an explicit input: detekt directory
    // discovery (which would follow repo config) is never used, and the
    // sealed argv proves the scanned set.
    for file in &scope.scanned {
        argv.push("--input".to_string());
        argv.push(file.path.clone());
    }
    if let Some(evidence) = typed {
        argv.push("--classpath".to_string());
        argv.push(
            evidence
                .classpath
                .iter()
                .map(|entry| entry.path.clone())
                .collect::<Vec<_>>()
                .join(if cfg!(windows) { ";" } else { ":" }),
        );
        for generated in &evidence.generated_sources {
            argv.push("--input".to_string());
            argv.push(generated.path.clone());
        }
    }
    // Plugins only from root-staged qualified jars; source mode without a
    // qualification record gets none. No repo plugin/script is ever named.
    for jar in &options.plugin_jars {
        argv.push("--plugins".to_string());
        argv.push(jar.clone());
    }
    argv
}

fn plan(
    mode: DetektMode,
    entries: &[InventoryEntry],
    pin: &DetektToolPin,
    options: &DetektOptions,
    typed: Option<&TypedClasspathEvidence>,
    typed_gaps: Vec<String>,
) -> DetektPlan {
    let provider_id = mode.provider_id();
    let selection = select_kotlin_files(entries, &options.exclusions);
    let mut gaps = validate_pin(pin, provider_id);
    gaps.extend(plugin_qualification_gaps(&options.plugins, provider_id));
    if options.plugin_jars.len() != options.plugins.len() {
        gaps.push(gap(provider_id, "detekt-plugin-jar-unqualified"));
    }
    gaps.extend(typed_gaps);
    if selection.scanned.is_empty() {
        gaps.push(gap(provider_id, "detekt-zero-files-selected"));
    }
    for file in &selection.scanned {
        if file.digest.as_deref().is_none_or(|d| !is_sha256_digest(d)) {
            gaps.push(gap(
                provider_id,
                &format!("detekt-scanned-file-unsealed:{}", file.path),
            ));
        }
    }
    // Unsupported `.kts` is a coverage gap on the outcome, not a reason to
    // refuse scanning the `.kt` files (most plain Kotlin repos carry a
    // `build.gradle.kts`); `blocking` alone decides argv.
    let blocking_gaps = gaps.len();
    for path in &selection.unsupported {
        gaps.push(gap(
            provider_id,
            &format!("detekt-unsupported-syntax:{path}"),
        ));
    }
    let mut scope = FrozenDetektScope {
        provider_id: provider_id.into(),
        mode,
        tool_version: pin.detekt_version.clone(),
        config_digest: owned_config_digest(),
        kotlin_language_version: pin.kotlin_language_version.clone(),
        jvm_target: pin.jvm_target.clone(),
        scanned: selection.scanned,
        excluded: selection.excluded,
        unsupported: selection.unsupported,
        modules: selection.modules,
        typed_classpath_digest: typed.map(|evidence| evidence.classpath_digest.clone()),
        qualified_rules: options
            .plugins
            .iter()
            .flat_map(|plugin| plugin.rules.clone())
            .collect(),
        scope_digest: String::new(),
    };
    scope.scope_digest = scope_digest(&scope);
    gaps.sort();
    gaps.dedup();
    let argv = (blocking_gaps == 0).then(|| build_argv(options, pin, &scope, typed));
    DetektPlan {
        provider_id,
        mode,
        program: options.java_program.clone(),
        argv,
        version_argv: vec![
            "-jar".into(),
            options.distribution_jar.clone(),
            "--version".into(),
        ],
        accepted_exit_codes: vec![EXIT_CLEAN, EXIT_ISSUES_FOUND],
        report_path: options.report_path.clone(),
        explicit_input_list: true,
        scope,
        gaps,
    }
}

/// Source mode: no `legion-jvm-sdk.json`, Gradle wrapper, repo plugin or
/// repo script is consulted at any point.
pub fn plan_source(
    entries: &[InventoryEntry],
    pin: &DetektToolPin,
    options: &DetektOptions,
) -> DetektPlan {
    plan(DetektMode::Source, entries, pin, options, None, Vec::new())
}

/// Typed mode: refuses (no argv) unless exact classpath/target/variant
/// evidence validates. The refusal does not touch any source-mode plan.
pub fn plan_typed(
    entries: &[InventoryEntry],
    pin: &DetektToolPin,
    options: &DetektOptions,
    typed: Option<&TypedClasspathEvidence>,
    expected_target: &str,
    expected_variant: &str,
) -> DetektPlan {
    let gaps = validate_typed_evidence(typed, expected_target, expected_variant, TYPED_PROVIDER_ID);
    let typed_arg = if gaps.is_empty() { typed } else { None };
    plan(DetektMode::Typed, entries, pin, options, typed_arg, gaps)
}

// ---------------------------------------------------------------------------
// SARIF parsing & run classification
// ---------------------------------------------------------------------------

/// Link back to the sealed execution that produced a report. A parse with
/// no receipt link can be inspected but never read as complete evidence.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReceiptLink {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_artifact_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_digest: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetektCandidate {
    /// SARIF rule id verbatim, e.g. `detekt.style.MagicNumber`.
    pub rule_id: String,
    /// `sha256:` over provider/rule/path/line/column — dedupe identity.
    pub evidence_identity: String,
    /// SARIF level verbatim: `error`/`warning`/`note`/`none`.
    pub severity: String,
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub end_line: usize,
    pub end_column: usize,
    pub message: String,
    /// False only for coroutine/Compose plugin rules with no qualification
    /// record; such candidates never count as qualified coverage.
    pub qualified: bool,
    pub receipt_id: Option<String>,
}

/// Per-file accounting: rule findings stay distinct from compiler/tool
/// diagnostics on the same file.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileDiagnostics {
    pub rule_findings: usize,
    pub compiler_errors: Vec<String>,
    pub unsupported_syntax: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetektStatus {
    /// Proven scanned set, valid report, zero candidates, no gaps.
    Clean,
    Findings,
    ZeroFileScan,
    MalformedReport,
    ToolFailure,
    CompilerFailure,
    UnsupportedSyntax,
    /// Report parsed but coverage is not proven (gaps name why).
    Incomplete,
}

#[derive(Clone, Debug)]
pub struct DetektOutcome {
    pub provider_id: String,
    pub status: DetektStatus,
    pub complete: bool,
    pub candidates: Vec<DetektCandidate>,
    pub per_file: BTreeMap<String, FileDiagnostics>,
    /// Files the report proves were scanned (SARIF artifacts when present).
    pub reported_scanned: Vec<String>,
    pub findings_truncated: usize,
    pub gaps: Vec<String>,
    pub report_digest: String,
    pub receipt: ReceiptLink,
    pub scope_digest: String,
}

impl DetektOutcome {
    fn refused(
        scope: &FrozenDetektScope,
        status: DetektStatus,
        gaps: Vec<String>,
        report_digest: String,
        receipt: ReceiptLink,
    ) -> Self {
        Self {
            provider_id: scope.provider_id.clone(),
            status,
            complete: false,
            candidates: Vec::new(),
            per_file: BTreeMap::new(),
            reported_scanned: Vec::new(),
            findings_truncated: 0,
            gaps,
            report_digest,
            receipt,
            scope_digest: scope.scope_digest.clone(),
        }
    }

    /// Native findings for `code.*` evidence plumbing. Only qualified rule
    /// candidates convert; unqualified plugin candidates stay gaps.
    pub fn native_findings(&self) -> Vec<NativeFinding> {
        self.candidates
            .iter()
            .filter(|candidate| candidate.qualified)
            .map(|candidate| NativeFinding {
                rule: Cow::Owned(candidate.rule_id.clone()),
                severity: match candidate.severity.as_str() {
                    "error" => "error",
                    "note" => "note",
                    "none" => "note",
                    _ => "warning",
                },
                path: candidate.path.clone(),
                line: candidate.line,
                message: candidate.message.clone(),
            })
            .collect()
    }
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = bytes.get(index + 1..index + 3)?;
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Normalize a SARIF artifact uri to an inventory path. Percent-escapes
/// (Unicode/space paths) decode; `file:` prefixes and a root-supplied
/// absolute `base_prefix` are stripped; anything still absolute or
/// escaping (`..`, backslashes) is rejected by returning `None`.
pub fn normalize_report_path(uri: &str, base_prefix: Option<&str>) -> Option<String> {
    let decoded = percent_decode(uri)?;
    let mut path = decoded.as_str();
    for prefix in ["file:///", "file://", "file:"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            path = rest;
            break;
        }
    }
    if let Some(base) = base_prefix.filter(|base| !base.is_empty()) {
        let base = base.trim_end_matches('/');
        let unslashed = base.trim_start_matches('/');
        if let Some(rest) = path
            .strip_prefix(&format!("{base}/"))
            .or_else(|| path.strip_prefix(&format!("/{unslashed}/")))
            .or_else(|| path.strip_prefix(&format!("{unslashed}/")))
        {
            path = rest;
        }
    }
    let path = path.trim_start_matches("./");
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|segment| segment == ".." || segment.is_empty())
    {
        return None;
    }
    Some(path.to_string())
}

fn candidate_identity(
    provider_id: &str,
    rule_id: &str,
    path: &str,
    line: usize,
    column: usize,
) -> String {
    sha256_hex(format!("{provider_id}\0{rule_id}\0{path}\0{line}\0{column}").as_bytes())
}

fn truncated_message(message: &str) -> String {
    let message = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if message.chars().count() <= MAX_MESSAGE_CHARS {
        message
    } else {
        message.chars().take(MAX_MESSAGE_CHARS).collect()
    }
}

/// Parse one detekt SARIF report against the frozen scope. Distinguishes
/// rule findings, malformed/truncated report, zero-file scan, compiler/
/// tool notifications and unsupported syntax. `explicit_input_list_proven`
/// must come from root's sealed receipt argv (every scanned file was an
/// individual `--input`); without it or matching SARIF artifacts, a
/// findings-free report is `detekt-scanned-set-unproven`, never clean.
pub fn parse_sarif_report(
    bytes: &[u8],
    scope: &FrozenDetektScope,
    pin: &DetektToolPin,
    plugins: &[PluginQualification],
    receipt: ReceiptLink,
    base_prefix: Option<&str>,
    explicit_input_list_proven: bool,
    max_findings: usize,
) -> DetektOutcome {
    let provider_id = scope.provider_id.as_str();
    let report_digest = sha256_hex(bytes);
    if scope.scope_digest != scope_digest(scope) {
        return DetektOutcome::refused(
            scope,
            DetektStatus::Incomplete,
            vec![gap(provider_id, "detekt-scope-digest-mismatch")],
            report_digest,
            receipt,
        );
    }
    let malformed = |detail: &str| {
        DetektOutcome::refused(
            scope,
            DetektStatus::MalformedReport,
            vec![gap(
                provider_id,
                &format!("detekt-malformed-report:{detail}"),
            )],
            report_digest.clone(),
            receipt.clone(),
        )
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        return malformed("not-utf8");
    };
    let Ok(root) = serde_json::from_str::<Value>(text) else {
        return malformed("invalid-json");
    };
    if root.get("version").and_then(Value::as_str) != Some(SUPPORTED_SARIF_VERSION) {
        return DetektOutcome::refused(
            scope,
            DetektStatus::MalformedReport,
            vec![gap(provider_id, "detekt-unsupported-report-version")],
            report_digest,
            receipt,
        );
    }
    let Some(runs) = root.get("runs").and_then(Value::as_array) else {
        return malformed("runs-missing");
    };
    if runs.len() != 1 {
        return malformed("runs-not-single");
    }
    let run = &runs[0];
    let driver = &run["tool"]["driver"];
    if driver.get("name").and_then(Value::as_str) != Some("detekt") {
        return malformed("driver-not-detekt");
    }
    let mut gaps = Vec::new();
    match driver.get("version").and_then(Value::as_str) {
        Some(version) if version == pin.detekt_version => {}
        Some(version) => gaps.push(gap(
            provider_id,
            &format!("detekt-version-mismatch:{version}"),
        )),
        None => gaps.push(gap(provider_id, "detekt-version-unproven")),
    }
    if receipt.receipt_id.as_deref().is_none_or(str::is_empty)
        || receipt
            .report_artifact_digest
            .as_deref()
            .is_none_or(|digest| digest != report_digest)
    {
        gaps.push(gap(provider_id, "detekt-receipt-link-missing"));
    }
    let declared_rules: BTreeSet<String> = driver
        .get("rules")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .filter_map(|rule| rule.get("id").and_then(Value::as_str).map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    let scanned_set: BTreeSet<String> =
        scope.scanned.iter().map(|file| file.path.clone()).collect();
    let reported_scanned: Vec<String> = run
        .get("artifacts")
        .and_then(Value::as_array)
        .map(|artifacts| {
            artifacts
                .iter()
                .filter_map(|artifact| {
                    artifact["location"]
                        .get("uri")
                        .and_then(Value::as_str)
                        .and_then(|uri| normalize_report_path(uri, base_prefix))
                })
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        })
        .unwrap_or_default();
    let artifacts_present = run.get("artifacts").and_then(Value::as_array).is_some();
    if artifacts_present {
        let reported_set: BTreeSet<&String> = reported_scanned.iter().collect();
        for missing in scanned_set
            .iter()
            .filter(|path| !reported_set.contains(path))
        {
            gaps.push(gap(
                provider_id,
                &format!("detekt-file-not-in-report:{missing}"),
            ));
        }
        for extra in reported_set
            .iter()
            .filter(|path| !scanned_set.contains(**path))
        {
            gaps.push(gap(
                provider_id,
                &format!("detekt-report-outside-denominator:{extra}"),
            ));
        }
    } else if !explicit_input_list_proven {
        gaps.push(gap(provider_id, "detekt-scanned-set-unproven"));
    }
    let mut per_file: BTreeMap<String, FileDiagnostics> = BTreeMap::new();
    for path in &scanned_set {
        per_file.insert(path.clone(), FileDiagnostics::default());
    }
    for path in &scope.unsupported {
        per_file.entry(path.clone()).or_default().unsupported_syntax = true;
        gaps.push(gap(
            provider_id,
            &format!("detekt-unsupported-syntax:{path}"),
        ));
    }
    // Compiler/tool execution notifications are diagnostics, not findings.
    let mut compiler_failures = 0usize;
    if let Some(invocations) = run.get("invocations").and_then(Value::as_array) {
        for invocation in invocations {
            if invocation
                .get("executionSuccessful")
                .and_then(Value::as_bool)
                == Some(false)
            {
                gaps.push(gap(provider_id, "detekt-invocation-unsuccessful"));
            }
            let Some(notifications) = invocation
                .get("toolExecutionNotifications")
                .and_then(Value::as_array)
            else {
                continue;
            };
            for notification in notifications {
                if notification.get("level").and_then(Value::as_str) != Some("error") {
                    continue;
                }
                compiler_failures += 1;
                let message = truncated_message(
                    notification["message"]
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or("detekt compiler/tool error"),
                );
                let path = notification["locations"][0]["physicalLocation"]["artifactLocation"]
                    .get("uri")
                    .and_then(Value::as_str)
                    .and_then(|uri| normalize_report_path(uri, base_prefix));
                match path {
                    Some(path) if scanned_set.contains(&path) => {
                        per_file
                            .entry(path.clone())
                            .or_default()
                            .compiler_errors
                            .push(message);
                        gaps.push(gap(provider_id, &format!("detekt-compiler-failure:{path}")));
                    }
                    _ => gaps.push(gap(provider_id, "detekt-compiler-failure:unlocated")),
                }
            }
        }
    }
    let Some(results) = run.get("results").and_then(Value::as_array) else {
        return malformed("results-missing");
    };
    let mut candidates = Vec::new();
    let mut findings_truncated = 0usize;
    let mut unsupported_syntax_seen = !scope.unsupported.is_empty();
    for result in results {
        let Some(rule_id) = result.get("ruleId").and_then(Value::as_str) else {
            gaps.push(gap(provider_id, "detekt-result-missing-rule"));
            continue;
        };
        let location = &result["locations"][0]["physicalLocation"];
        let path = location["artifactLocation"]
            .get("uri")
            .and_then(Value::as_str)
            .and_then(|uri| normalize_report_path(uri, base_prefix));
        let (Some(path), Some(region)) = (path, location.get("region")) else {
            gaps.push(gap(provider_id, "detekt-result-missing-location"));
            continue;
        };
        let line = region
            .get("startLine")
            .and_then(Value::as_u64)
            .filter(|line| *line >= 1);
        let Some(line) = line.map(|line| line as usize) else {
            gaps.push(gap(provider_id, "detekt-result-missing-location"));
            continue;
        };
        let column = region
            .get("startColumn")
            .and_then(Value::as_u64)
            .unwrap_or(1) as usize;
        let message = truncated_message(
            result["message"]
                .get("text")
                .and_then(Value::as_str)
                .unwrap_or(rule_id),
        );
        // Compiler errors surface as undeclared-rule error results; keep
        // them per-file diagnostics, never rule candidates.
        let is_compiler = rule_id.to_ascii_lowercase().contains("compiler")
            || (!declared_rules.is_empty()
                && !declared_rules.contains(rule_id)
                && result.get("level").and_then(Value::as_str) == Some("error"));
        if is_compiler {
            compiler_failures += 1;
            if scanned_set.contains(&path) {
                per_file
                    .entry(path.clone())
                    .or_default()
                    .compiler_errors
                    .push(message);
                gaps.push(gap(provider_id, &format!("detekt-compiler-failure:{path}")));
            } else {
                gaps.push(gap(provider_id, "detekt-compiler-failure:unlocated"));
            }
            continue;
        }
        if rule_id.to_ascii_lowercase().contains("unsupported")
            || message.to_ascii_lowercase().contains("unsupported syntax")
        {
            unsupported_syntax_seen = true;
            per_file.entry(path.clone()).or_default().unsupported_syntax = true;
            gaps.push(gap(
                provider_id,
                &format!("detekt-unsupported-syntax:{path}"),
            ));
            continue;
        }
        if !scanned_set.contains(&path) {
            gaps.push(gap(
                provider_id,
                &format!("detekt-diagnostic-outside-denominator:{path}"),
            ));
            continue;
        }
        let qualified = rule_qualified(rule_id, plugins);
        if !qualified {
            gaps.push(gap(
                provider_id,
                &format!(
                    "detekt-unqualified-plugin-rule:{}:{rule_id}",
                    plugin_namespace(rule_id).unwrap_or("plugin")
                ),
            ));
        }
        per_file.entry(path.clone()).or_default().rule_findings += 1;
        if candidates.len() >= max_findings {
            findings_truncated += 1;
            continue;
        }
        candidates.push(DetektCandidate {
            rule_id: rule_id.to_string(),
            evidence_identity: candidate_identity(provider_id, rule_id, &path, line, column),
            severity: result
                .get("level")
                .and_then(Value::as_str)
                .filter(|level| matches!(*level, "error" | "warning" | "note" | "none"))
                .unwrap_or("warning")
                .to_string(),
            path,
            line,
            column,
            end_line: region
                .get("endLine")
                .and_then(Value::as_u64)
                .map(|value| value as usize)
                .unwrap_or(line),
            end_column: region
                .get("endColumn")
                .and_then(Value::as_u64)
                .map(|value| value as usize)
                .unwrap_or(column),
            message,
            qualified,
            receipt_id: receipt.receipt_id.clone(),
        });
    }
    if findings_truncated > 0 {
        gaps.push(gap(
            provider_id,
            &format!("detekt-findings-truncated:{findings_truncated}"),
        ));
    }
    gaps.sort();
    gaps.dedup();
    let zero_file = scope.scanned.is_empty() || (artifacts_present && reported_scanned.is_empty());
    let status = if zero_file {
        DetektStatus::ZeroFileScan
    } else if compiler_failures > 0 {
        DetektStatus::CompilerFailure
    } else if unsupported_syntax_seen && candidates.is_empty() {
        DetektStatus::UnsupportedSyntax
    } else if !candidates.is_empty() {
        DetektStatus::Findings
    } else if gaps.is_empty() {
        DetektStatus::Clean
    } else {
        DetektStatus::Incomplete
    };
    DetektOutcome {
        provider_id: scope.provider_id.clone(),
        status,
        complete: status == DetektStatus::Clean
            || (status == DetektStatus::Findings && gaps.is_empty()),
        candidates,
        per_file,
        reported_scanned,
        findings_truncated,
        gaps,
        report_digest,
        receipt,
        scope_digest: scope.scope_digest.clone(),
    }
}

/// Combine a parsed report with the sealed process exit. A nonzero
/// operational exit (anything but `0`/`2`, or no exit at all) is a tool
/// failure even if report bytes parse. Exit/report disagreement under the
/// owned `maxIssues: 0` config is incomplete, never clean.
pub fn classify_run(outcome: DetektOutcome, exit_code: Option<i32>) -> DetektOutcome {
    let mut outcome = outcome;
    let provider_id = outcome.provider_id.clone();
    match exit_code {
        Some(EXIT_CLEAN) => {
            if !outcome.candidates.is_empty() {
                outcome.gaps.push(gap(
                    &provider_id,
                    "detekt-exit-report-mismatch:clean-with-findings",
                ));
            }
        }
        Some(EXIT_ISSUES_FOUND) => {
            if outcome.candidates.is_empty()
                && !matches!(
                    outcome.status,
                    DetektStatus::CompilerFailure | DetektStatus::UnsupportedSyntax
                )
            {
                outcome.gaps.push(gap(
                    &provider_id,
                    "detekt-exit-report-mismatch:issues-without-findings",
                ));
            }
        }
        Some(code) => {
            outcome.gaps.push(gap(
                &provider_id,
                &format!("detekt-tool-failed:exit-{code}"),
            ));
            outcome.status = DetektStatus::ToolFailure;
        }
        None => {
            outcome
                .gaps
                .push(gap(&provider_id, "detekt-tool-failed:no-exit"));
            outcome.status = DetektStatus::ToolFailure;
        }
    }
    outcome.gaps.sort();
    outcome.gaps.dedup();
    if !outcome.gaps.is_empty() {
        outcome.complete = false;
        if outcome.status == DetektStatus::Clean {
            outcome.status = DetektStatus::Incomplete;
        }
    }
    outcome
}

// ---------------------------------------------------------------------------
// Deduplication against generic JVM diagnostics
// ---------------------------------------------------------------------------

/// Generic-JVM evidence rule a detekt rule duplicates, when identity is
/// known. Unknown rules keep their own identity — never guessed away.
fn rule_family(rule_id: &str) -> String {
    let tail = rule_id
        .rsplit(['.', '/'])
        .next()
        .unwrap_or(rule_id)
        .to_ascii_lowercase();
    match tail.as_str() {
        "emptycatchblock" | "emptycatch" => "empty-catch".into(),
        "printstacktrace" | "println" => "debug-leftover".into(),
        other => other.to_string(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DuplicateLink {
    pub detekt_evidence_identity: String,
    pub detekt_rule_id: String,
    /// Generic provider's rule id (`code.jvm` execution record is kept).
    pub generic_rule_id: String,
    pub path: String,
    pub line: usize,
}

#[derive(Clone, Debug)]
pub struct DedupOutcome {
    /// Detekt candidates kept as individual candidates.
    pub kept: Vec<DetektCandidate>,
    /// Detekt candidates proven duplicates of a generic JVM diagnostic by
    /// evidence/rule identity + path + line. Both provider execution
    /// records remain; only candidate double-counting is suppressed.
    pub duplicates: Vec<DuplicateLink>,
}

pub fn dedupe_against_jvm(
    candidates: Vec<DetektCandidate>,
    jvm_findings: &[NativeFinding],
) -> DedupOutcome {
    let mut kept = Vec::new();
    let mut duplicates = Vec::new();
    for candidate in candidates {
        let family = rule_family(&candidate.rule_id);
        let duplicate = jvm_findings.iter().find(|finding| {
            finding.path == candidate.path
                && finding.line == candidate.line
                && rule_family(&finding.rule) == family
        });
        match duplicate {
            Some(finding) => duplicates.push(DuplicateLink {
                detekt_evidence_identity: candidate.evidence_identity.clone(),
                detekt_rule_id: candidate.rule_id.clone(),
                generic_rule_id: finding.rule.clone().into_owned(),
                path: candidate.path.clone(),
                line: candidate.line,
            }),
            None => kept.push(candidate),
        }
    }
    DedupOutcome { kept, duplicates }
}
