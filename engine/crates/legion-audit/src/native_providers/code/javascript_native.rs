//! Node-free JavaScript/TypeScript native lint coverage (A07).
//!
//! `code.javascript.native` plans direct invocations of a pinned Oxlint or
//! Biome binary with an audit-owned JSON configuration and a frozen native
//! rule subset. Repository ESLint/Biome/Oxlint configs, plugins, package
//! scripts, and `package.json` lifecycle hooks are never loaded or executed;
//! their presence is reported as ignored coverage context. No npx/pnpm
//! launcher, JS plugin, TS config, package installation, or Node/Python
//! child is planned here.
//!
//! This module is planner + parser + capability metadata only (edit-only
//! packet). Root wires dispatch through `tools.rs` and the sandboxed
//! `ExternalProjectTool` route and owns binary admission. Nothing here runs a
//! process or reads the audited tree except through the caller-supplied frozen
//! reader ([`frozen_reader`] verifies inventory `sha256:` digests). A missing
//! pin, unproven tool version, unsealed input, zero-file denominator, invalid
//! config, unknown rule, malformed report, non-accepted exit, or unproven
//! scanned set is never clean.
//!
//! Framework facts (Qwik, React, Next) come from manifests and lockfiles read
//! as data; nothing is executed. Qwik lexer matches are leads for A13 only.
//! Optimizer, resumability, and runtime obligations stay uncovered here and
//! require authenticated upstream evidence (A03) or runtime evidence (A16).
//! No ESLint-plugin or Qwik-compiler equivalence is claimed.
//!
//! Checks not run: root integration owns all verification of this module.

use super::evidence::NativeFinding;
use crate::inventory::InventoryEntry;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

pub const PROVIDER_ID: &str = "code.javascript.native";
pub const COVERAGE_SCHEMA: &str = "legion-javascript-native-coverage/1";
pub const MAX_NATIVE_FINDINGS: usize = 200;
/// Oxlint and Biome both exit `1` when they report lint errors; any other
/// exit is an operational failure regardless of report bytes.
pub const ACCEPTED_EXIT_CODES: &[i32] = &[0, 1];
pub const OXLINT_CONFIG_FILE: &str = "legion-owned-oxlint.json";
pub const BIOME_CONFIG_FILE: &str = "biome.json";

const MAX_MESSAGE_CHARS: usize = 300;
const MAX_SOURCE_BYTES: u64 = 512 * 1024;
const MAX_FILES_PER_UNIT: usize = 2000;
const MAX_QWIK_FILES: usize = 4000;
const MAX_LEAD_TEXT_CHARS: usize = 120;
const BIOME_MAX_DIAGNOSTICS: usize = 1000;
const JS_EXTENSIONS: &[&str] = &["js", "jsx", "ts", "tsx", "mjs", "cjs", "mts", "cts"];
/// Generated, vendored, or build-output segments. Never denominator sources.
const EXCLUDED_SEGMENTS: &[&str] = &[
    "node_modules",
    "dist",
    ".next",
    ".output",
    ".qwik",
    "coverage",
];
const LOCKFILES: &[&str] = &["pnpm-lock.yaml", "package-lock.json", "yarn.lock"];
/// Repository lint configs that are ignored (never loaded) but reported as
/// coverage context for every package they apply to.
const REPO_CONFIG_NAMES: &[&str] = &[
    "biome.json",
    "biome.jsonc",
    "oxlintrc.json",
    ".oxlintrc.json",
    "eslint.config.js",
    "eslint.config.mjs",
    "eslint.config.cjs",
    "eslint.config.ts",
    "eslint.config.mts",
    "eslint.config.cts",
    ".eslintrc",
    ".eslintrc.js",
    ".eslintrc.cjs",
    ".eslintrc.json",
    ".eslintrc.yml",
    ".eslintrc.yaml",
];
const FRAMEWORK_PACKAGES: &[(&str, &str)] = &[
    ("qwik", "@builder.io/qwik"),
    ("qwik-city", "@builder.io/qwik-city"),
    ("react", "react"),
    ("react-dom", "react-dom"),
    ("next", "next"),
];
/// Lowercased stderr fragments naming an invalid owned configuration.
const CONFIG_MARKERS: &[&str] = &[
    "failed to parse configuration",
    "invalid configuration",
    "configuration error",
];
/// Lowercased stderr fragments naming a rule the pinned binary rejects.
const UNSUPPORTED_RULE_MARKERS: &[&str] =
    &["rule not found", "unknown rule", "not a supported rule"];

// ---------------------------------------------------------------------------
// Linter identity & pin
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Linter {
    Oxlint,
    Biome,
}

impl Linter {
    /// Executable name root resolves and digests (never a package launcher).
    pub fn tool_id(self) -> &'static str {
        match self {
            Linter::Oxlint => "oxlint",
            Linter::Biome => "biome",
        }
    }

    pub fn parser_id(self) -> &'static str {
        match self {
            Linter::Oxlint => "oxlint-json-1",
            Linter::Biome => "biome-json-reporter",
        }
    }

    pub fn config_file(self) -> &'static str {
        match self {
            Linter::Oxlint => OXLINT_CONFIG_FILE,
            Linter::Biome => BIOME_CONFIG_FILE,
        }
    }
}

/// Pinned binary identity supplied by root's pin catalog. A pin is an
/// identity claim, not proof of installation: root still resolves, digests,
/// and version-probes the executable before any run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeLinterPin {
    pub linter: Linter,
    pub version: String,
    /// `sha256:<hex>` of the pinned executable.
    pub distribution_digest: String,
}

impl NativeLinterPin {
    /// Identity left empty on purpose: every validation names a gap.
    pub fn unpinned(linter: Linter) -> Self {
        Self {
            linter,
            version: String::new(),
            distribution_digest: String::new(),
        }
    }
}

fn gap(kind: &str) -> String {
    format!("{PROVIDER_ID}:{kind}")
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

/// Named gaps for a pin; empty means the pin is internally admissible.
pub fn validate_pin(pin: &NativeLinterPin) -> Vec<String> {
    let tool = pin.linter.tool_id();
    let mut gaps = Vec::new();
    if pin.version.trim().is_empty() {
        gaps.push(gap(&format!("{tool}-version-unpinned")));
    }
    if !is_sha256_digest(&pin.distribution_digest) {
        gaps.push(gap(&format!("{tool}-distribution-digest-missing")));
    }
    gaps
}

/// First `x.y.z` in the first lines of `--version` output. Unrecognized
/// output is `None`, which callers must treat as a version gap, not a pass.
pub fn parse_version_output(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    let version = Regex::new(r"\b(\d+\.\d+\.\d+)\b").expect("constant regex");
    text.lines()
        .take(4)
        .find_map(|line| version.captures(line).map(|found| found[1].to_string()))
}

pub fn version_gaps(probed: Option<&str>, pin: &NativeLinterPin) -> Vec<String> {
    let tool = pin.linter.tool_id();
    match probed {
        Some(version) if version == pin.version => Vec::new(),
        Some(version) => vec![gap(&format!("{tool}-version-mismatch:{version}"))],
        None => vec![gap(&format!("{tool}-version-unproven"))],
    }
}

// ---------------------------------------------------------------------------
// Native rule catalog & owned configuration
// ---------------------------------------------------------------------------

/// One enabled native rule and the concern it supports. Oxlint and Biome ids
/// name the same concern; neither is an ESLint-plugin equivalence claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeRule {
    pub oxlint: &'static str,
    pub biome: &'static str,
    pub concern: &'static str,
}

/// The exact enabled subset. Every id must resolve in the pinned binary
/// before admission (root probe); an unresolved id is `unsupported-rule`.
pub const NATIVE_RULES: &[NativeRule] = &[
    NativeRule {
        oxlint: "eslint/no-debugger",
        biome: "lint/suspicious/noDebugger",
        concern: "debugging-leftover",
    },
    NativeRule {
        oxlint: "eslint/no-eval",
        biome: "lint/security/noGlobalEval",
        concern: "code-injection-sink",
    },
    NativeRule {
        oxlint: "eslint/eqeqeq",
        biome: "lint/suspicious/noDoubleEquals",
        concern: "correctness",
    },
    NativeRule {
        oxlint: "eslint/no-unused-vars",
        biome: "lint/correctness/noUnusedVariables",
        concern: "correctness",
    },
    NativeRule {
        oxlint: "eslint/no-dupe-keys",
        biome: "lint/suspicious/noDuplicateObjectKeys",
        concern: "correctness",
    },
    NativeRule {
        oxlint: "eslint/no-unreachable",
        biome: "lint/correctness/noUnreachable",
        concern: "correctness",
    },
    NativeRule {
        oxlint: "react/rules-of-hooks",
        biome: "lint/correctness/useHookAtTopLevel",
        concern: "react-hooks",
    },
    NativeRule {
        oxlint: "react/exhaustive-deps",
        biome: "lint/correctness/useExhaustiveDependencies",
        concern: "react-hooks",
    },
    NativeRule {
        oxlint: "react/jsx-key",
        biome: "lint/correctness/useJsxKeyInIterable",
        concern: "react-lists",
    },
    NativeRule {
        oxlint: "react/no-danger",
        biome: "lint/security/noDangerouslySetInnerHtml",
        concern: "xss-sink",
    },
    NativeRule {
        oxlint: "jsx-a11y/alt-text",
        biome: "lint/a11y/useAltText",
        concern: "a11y",
    },
    NativeRule {
        oxlint: "jsx-a11y/anchor-is-valid",
        biome: "lint/a11y/useValidAnchor",
        concern: "a11y",
    },
    NativeRule {
        oxlint: "jsx-a11y/click-events-have-key-events",
        biome: "lint/a11y/useKeyWithClickEvents",
        concern: "a11y",
    },
    NativeRule {
        oxlint: "jsx-a11y/no-static-element-interactions",
        biome: "lint/a11y/noStaticElementInteractions",
        concern: "a11y",
    },
    NativeRule {
        oxlint: "jsx-a11y/label-has-associated-control",
        biome: "lint/a11y/noLabelWithoutControl",
        concern: "a11y",
    },
    NativeRule {
        oxlint: "jsx-a11y/heading-has-content",
        biome: "lint/a11y/useHeadingContent",
        concern: "a11y",
    },
    NativeRule {
        oxlint: "typescript/no-explicit-any",
        biome: "lint/suspicious/noExplicitAny",
        concern: "type-safety",
    },
    NativeRule {
        oxlint: "typescript/no-non-null-assertion",
        biome: "lint/style/noNonNullAssertion",
        concern: "type-safety",
    },
];

/// Concerns native lint cannot discharge, with the evidence that would and
/// the owning packet. Listed so they stay visible in every profile.
pub const UNCOVERED_CONCERNS: &[(&str, &str, &str)] = &[
    ("typescript-semantics", "build", "A03"),
    ("bundle-graph", "build", "A03"),
    ("unit-test-behaviour", "test", "A03"),
    ("qwik-optimizer", "build", "A03+A13"),
    ("qwik-resumability", "runtime", "A16"),
    ("react-hydration-runtime", "runtime", "A16"),
    ("rendered-accessibility", "runtime", "A16"),
];

/// Owned Oxlint configuration: native plugins only, every enabled rule at
/// `error`, no `extends`, no JS plugins, no nested configs.
pub fn owned_oxlint_config() -> Value {
    let mut rules = Map::new();
    let mut plugins = BTreeSet::new();
    for rule in NATIVE_RULES {
        if let Some((plugin, _)) = rule.oxlint.split_once('/') {
            plugins.insert(plugin);
        }
        rules.insert(rule.oxlint.to_string(), json!("error"));
    }
    json!({
        "plugins": plugins.into_iter().collect::<Vec<_>>(),
        "rules": Value::Object(rules),
    })
}

/// Owned Biome configuration: recommended set off, only the enabled subset
/// at `error`. Formatter, organize-imports and VCS integration are disabled.
pub fn owned_biome_config() -> Value {
    let mut groups: BTreeMap<String, Map<String, Value>> = BTreeMap::new();
    for rule in NATIVE_RULES {
        let mut parts = rule.biome.split('/');
        let (_lint, group, name) = (parts.next(), parts.next(), parts.next());
        if let (Some(group), Some(name)) = (group, name) {
            groups
                .entry(group.to_string())
                .or_default()
                .insert(name.to_string(), json!("error"));
        }
    }
    let mut rules = Map::new();
    rules.insert("recommended".into(), json!(false));
    for (group, names) in groups {
        rules.insert(group, Value::Object(names));
    }
    json!({
        "formatter": {"enabled": false},
        "organizeImports": {"enabled": false},
        "linter": {"enabled": true, "rules": Value::Object(rules)},
    })
}

pub fn owned_config_text(linter: Linter) -> String {
    let value = match linter {
        Linter::Oxlint => owned_oxlint_config(),
        Linter::Biome => owned_biome_config(),
    };
    serde_json::to_string_pretty(&value).expect("owned config serializes")
}

pub fn owned_config_digest(linter: Linter) -> String {
    sha256_hex(owned_config_text(linter).as_bytes())
}

fn uncovered_concerns_value() -> Vec<Value> {
    UNCOVERED_CONCERNS
        .iter()
        .map(|(concern, evidence, owner)| {
            json!({"concern": concern, "requiredEvidence": evidence, "owner": owner})
        })
        .collect()
}

/// Capability metadata root wires into selection and the report. Describes
/// what native lint covers and what it cannot; never a clean claim.
pub fn coverage_manifest() -> Value {
    let rules: Vec<Value> = NATIVE_RULES
        .iter()
        .map(|rule| json!({"oxlint": rule.oxlint, "biome": rule.biome, "concern": rule.concern}))
        .collect();
    let covered: BTreeSet<&str> = NATIVE_RULES.iter().map(|rule| rule.concern).collect();
    let hooks_and_a11y: Vec<&str> = NATIVE_RULES
        .iter()
        .filter(|rule| matches!(rule.concern, "react-hooks" | "a11y"))
        .map(|rule| rule.oxlint)
        .collect();
    json!({
        "schema": COVERAGE_SCHEMA,
        "providerId": PROVIDER_ID,
        "tools": [
            {"tool": Linter::Oxlint.tool_id(), "parser": Linter::Oxlint.parser_id(), "configFile": OXLINT_CONFIG_FILE, "configDigest": owned_config_digest(Linter::Oxlint)},
            {"tool": Linter::Biome.tool_id(), "parser": Linter::Biome.parser_id(), "configFile": BIOME_CONFIG_FILE, "configDigest": owned_config_digest(Linter::Biome)},
        ],
        "enabledRules": rules,
        "reactHooksAndA11yRules": hooks_and_a11y,
        "coveredConcerns": covered,
        "uncoveredConcerns": uncovered_concerns_value(),
        "ruleQualification": "every enabled rule must resolve in the pinned binary before admission; an unresolved rule is unsupported-rule, never clean",
        "claimsEslintPluginEquivalence": false,
        "claimsQwikCompilerEquivalence": false,
        "nativeScanSatisfiesQwikOptimizerResumabilityRuntime": false,
    })
}

/// Legacy Node-based JavaScript checks are excluded from a no-node profile,
/// while every uncovered concern stays visible.
pub const LEGACY_NODE_TOOLS: &[&str] = &["type", "lint", "build", "test"];

pub fn no_node_coverage() -> Value {
    json!({
        "profile": "no-node",
        "excludedLegacyNodeTools": LEGACY_NODE_TOOLS
            .iter()
            .map(|tool| format!("code.javascript:{tool}"))
            .collect::<Vec<_>>(),
        "nativeLinters": [Linter::Oxlint.tool_id(), Linter::Biome.tool_id()],
        "uncoveredConcerns": uncovered_concerns_value(),
    })
}

// ---------------------------------------------------------------------------
// Frozen input access & path helpers
// ---------------------------------------------------------------------------

fn safe_relative(value: &str) -> bool {
    !value.is_empty()
        && !value.contains('\\')
        && !Path::new(value).is_absolute()
        && Path::new(value)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

/// Reader over the frozen inventory: returns bytes only when the file is a
/// bounded regular file whose content hashes to its inventory `sha256:`
/// digest. Anything else is `None`, which callers name as a gap.
pub fn frozen_reader<'a>(
    root: &'a Path,
    entries: &'a [InventoryEntry],
) -> impl Fn(&str) -> Option<Vec<u8>> + 'a {
    let digests: BTreeMap<&str, &str> = entries
        .iter()
        .filter_map(|entry| {
            entry
                .digest
                .as_deref()
                .map(|digest| (entry.path.as_str(), digest))
        })
        .collect();
    move |path: &str| {
        if !safe_relative(path) {
            return None;
        }
        let expected = digests.get(path)?;
        if !expected.starts_with("sha256:") {
            return None;
        }
        let full = root.join(path);
        let meta = fs::symlink_metadata(&full).ok()?;
        if !meta.is_file() || meta.len() > MAX_SOURCE_BYTES {
            return None;
        }
        let bytes = fs::read(&full).ok()?;
        (sha256_hex(&bytes) == *expected).then_some(bytes)
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

fn join(dir: &str, name: &str) -> String {
    if dir.is_empty() {
        name.to_string()
    } else {
        format!("{}/{}", dir.trim_end_matches('/'), name)
    }
}

fn label(dir: &str) -> &str {
    if dir.is_empty() {
        "."
    } else {
        dir
    }
}

/// `a/b` yields `["a/b", "a", ""]`; the root directory yields `[""]`.
fn ancestors(dir: &str) -> Vec<String> {
    let mut out = vec![dir.to_string()];
    let mut current = dir;
    while let Some(index) = current.rfind('/') {
        current = &current[..index];
        out.push(current.to_string());
    }
    if !dir.is_empty() {
        out.push(String::new());
    }
    out
}

fn excluded_segment(path: &str) -> Option<&str> {
    path.split('/')
        .find(|segment| EXCLUDED_SEGMENTS.contains(segment))
}

fn extension_of(path: &str) -> String {
    match name_of(path).rfind('.') {
        Some(index) => name_of(path)[index + 1..].to_ascii_lowercase(),
        None => String::new(),
    }
}

fn is_js_source(path: &str) -> bool {
    JS_EXTENSIONS.contains(&extension_of(path).as_str())
}

fn truncated_message(message: &str) -> String {
    let message = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if message.chars().count() <= MAX_MESSAGE_CHARS {
        message
    } else {
        message.chars().take(MAX_MESSAGE_CHARS).collect()
    }
}

// ---------------------------------------------------------------------------
// Framework & package discovery (data only; nothing executed)
// ---------------------------------------------------------------------------

/// A framework version fact. `version_proven` is true only for exactly one
/// locked version; a manifest range is a declaration, never a proof.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameworkFact {
    pub framework: String,
    pub package_name: String,
    pub package_dir: String,
    pub manifest_range: Option<String>,
    pub locked_version: Option<String>,
    pub lockfile: Option<String>,
    pub version_proven: bool,
    pub gaps: Vec<String>,
}

/// One `package.json` owner. Monorepo roots keep their own `dir`; a source
/// belongs to its nearest ancestor package.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JsPackage {
    pub dir: String,
    pub frameworks: Vec<FrameworkFact>,
    pub lockfile: Option<String>,
    /// Repository lint configs that apply here; ignored, reported as context.
    pub applicable_repo_configs: Vec<String>,
    pub gaps: Vec<String>,
}

fn declared_dependencies(manifest: &Value) -> BTreeMap<String, String> {
    let mut declared = BTreeMap::new();
    for key in ["dependencies", "devDependencies", "peerDependencies"] {
        if let Some(map) = manifest.get(key).and_then(Value::as_object) {
            for (name, range) in map {
                if let Some(range) = range.as_str() {
                    declared
                        .entry(name.clone())
                        .or_insert_with(|| range.to_string());
                }
            }
        }
    }
    declared
}

fn applicable_configs(entries: &[InventoryEntry], dir: &str) -> Vec<String> {
    let mut configs: Vec<String> = entries
        .iter()
        .filter(|entry| {
            REPO_CONFIG_NAMES.contains(&name_of(&entry.path))
                && excluded_segment(&entry.path).is_none()
        })
        .filter(|entry| {
            let config_dir = dir_of(&entry.path);
            config_dir.is_empty() || dir == config_dir || dir.starts_with(&format!("{config_dir}/"))
        })
        .map(|entry| entry.path.clone())
        .collect();
    configs.sort();
    configs
}

/// Locked versions of one package in one lockfile. Several distinct versions
/// are returned as several entries; the caller treats that as ambiguous.
pub fn locked_versions(lockfile_name: &str, text: &str, package_name: &str) -> Vec<String> {
    let name = regex::escape(package_name);
    let pattern = match lockfile_name {
        "package-lock.json" => format!(
            r#""node_modules/{name}"\s*:\s*\{{[^}}]*?"version"\s*:\s*"(\d+\.\d+\.\d+[^"]*)""#
        ),
        "yarn.lock" => format!(r#"(?m)^"?{name}@[^\n]*\n\s+version:?\s+"?(\d+\.\d+\.\d+[^"\s]*)"#),
        _ => format!(r#"(?m)^\s*'?/?{name}@(\d+\.\d+\.\d+[^\s'":(]*)"#),
    };
    let Ok(pattern) = Regex::new(&pattern) else {
        return Vec::new();
    };
    let mut versions: BTreeSet<String> = BTreeSet::new();
    for found in pattern.captures_iter(text) {
        versions.insert(found[1].to_string());
    }
    versions.into_iter().collect()
}

fn discover_packages(
    entries: &[InventoryEntry],
    reader: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> BTreeMap<String, JsPackage> {
    let paths: BTreeSet<&str> = entries.iter().map(|entry| entry.path.as_str()).collect();
    let mut packages: BTreeMap<String, JsPackage> = BTreeMap::new();
    for entry in entries {
        if name_of(&entry.path) != "package.json"
            || excluded_segment(&entry.path).is_some()
            || !safe_relative(&entry.path)
        {
            continue;
        }
        let dir = dir_of(&entry.path);
        let mut package = JsPackage {
            dir: dir.clone(),
            applicable_repo_configs: applicable_configs(entries, &dir),
            ..JsPackage::default()
        };
        let manifest =
            reader(&entry.path).and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        match manifest {
            None => package.gaps.push(gap(&format!(
                "javascript-manifest-unreadable:{}",
                label(&dir)
            ))),
            Some(manifest) => {
                let declared = declared_dependencies(&manifest);
                for (framework, package_name) in FRAMEWORK_PACKAGES {
                    if let Some(range) = declared.get(*package_name) {
                        package.frameworks.push(FrameworkFact {
                            framework: framework.to_string(),
                            package_name: package_name.to_string(),
                            package_dir: dir.clone(),
                            manifest_range: Some(range.clone()),
                            locked_version: None,
                            lockfile: None,
                            version_proven: false,
                            gaps: Vec::new(),
                        });
                    }
                }
            }
        }
        packages.insert(dir, package);
    }

    let dirs: Vec<String> = packages.keys().cloned().collect();
    for dir in dirs {
        let lockfile = ancestors(&dir).into_iter().find_map(|candidate| {
            LOCKFILES
                .iter()
                .map(|name| join(&candidate, name))
                .find(|path| paths.contains(path.as_str()))
        });
        let Some(package) = packages.get_mut(&dir) else {
            continue;
        };
        let Some(lockfile) = lockfile else {
            for fact in package.frameworks.iter_mut() {
                fact.gaps.push(gap("framework-lockfile-missing"));
            }
            continue;
        };
        let lock_name = name_of(&lockfile).to_string();
        let text = reader(&lockfile).map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
        package.lockfile = Some(lockfile.clone());
        for fact in package.frameworks.iter_mut() {
            fact.lockfile = Some(lockfile.clone());
            let Some(text) = text.as_deref() else {
                fact.gaps.push(gap("framework-lockfile-unreadable"));
                continue;
            };
            let versions = locked_versions(&lock_name, text, &fact.package_name);
            match versions.as_slice() {
                [] => fact.gaps.push(gap("framework-version-unlocked")),
                [version] => {
                    fact.locked_version = Some(version.clone());
                    fact.version_proven = true;
                }
                _ => fact.gaps.push(gap("framework-version-ambiguous")),
            }
        }
    }
    packages
}

/// Version facts for the A13 Qwik semantic owner. Each is a framework fact,
/// not an optimizer, resumability or runtime result.
pub fn qwik_version_facts(packages: &[JsPackage]) -> Vec<Value> {
    packages
        .iter()
        .flat_map(|package| package.frameworks.iter())
        .filter(|fact| fact.framework.starts_with("qwik"))
        .map(|fact| serde_json::to_value(fact).expect("serializable fact"))
        .collect()
}

/// Lexer leads for Qwik serialization boundaries. A `$`-suffixed boundary
/// with a non-serializable constructor on the same line is a candidate to
/// verify, never a finding and never proof of resumability.
pub fn qwik_leads(
    entries: &[InventoryEntry],
    reader: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Vec<Value> {
    let boundary = Regex::new(r"\b[A-Za-z_][A-Za-z0-9_]*\$\s*[(=]").expect("constant regex");
    let constructor = Regex::new(
        r"\bnew\s+(?:Map|Set|WeakMap|WeakSet|Date|RegExp|Error|Promise)\s*\(|\bnew\s+[A-Z][A-Za-z0-9_]*\s*\(|\bnoSerialize\s*\(",
    )
    .expect("constant regex");
    let mut leads = Vec::new();
    let mut visited = 0usize;
    for entry in entries {
        if !is_js_source(&entry.path)
            || excluded_segment(&entry.path).is_some()
            || !safe_relative(&entry.path)
        {
            continue;
        }
        if visited >= MAX_QWIK_FILES {
            break;
        }
        visited += 1;
        let Some(bytes) = reader(&entry.path) else {
            continue;
        };
        let text = String::from_utf8_lossy(&bytes);
        for (index, line) in text.lines().enumerate() {
            if !boundary.is_match(line) {
                continue;
            }
            if let Some(token) = constructor.find(line) {
                let token: String = token
                    .as_str()
                    .trim()
                    .chars()
                    .take(MAX_LEAD_TEXT_CHARS)
                    .collect();
                leads.push(json!({
                    "kind": "qwik-serialization-boundary-lead",
                    "path": entry.path,
                    "line": index + 1,
                    "token": token,
                    "leadOnly": true,
                    "satisfiesObligations": false,
                }));
            }
        }
    }
    leads
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FrozenSourceFile {
    pub path: String,
    /// Inventory `sha256:` digest; unsealed sources never reach this list.
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExcludedSource {
    pub path: String,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct NativeLintOptions {
    pub linter: Linter,
    /// Scratch directory root stages the owned config into (argv value).
    pub staged_config_dir: String,
    pub max_findings: usize,
}

impl NativeLintOptions {
    pub fn new(linter: Linter, staged_config_dir: &str) -> Self {
        Self {
            linter,
            staged_config_dir: staged_config_dir.to_string(),
            max_findings: MAX_NATIVE_FINDINGS,
        }
    }
}

/// One package's native lint invocation. `cwd` is the repository root and
/// paths are repository-relative. Root stages `config_text` as `config_file`
/// under the staged directory before any run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeLintUnit {
    pub package_dir: String,
    pub linter: Linter,
    pub program: &'static str,
    pub version_argv: Vec<String>,
    pub argv: Vec<String>,
    pub accepted_exit_codes: &'static [i32],
    pub files: Vec<FrozenSourceFile>,
    pub config_file: &'static str,
    pub config_text: String,
    pub config_digest: String,
    pub ignored_repo_configs: Vec<String>,
    pub scope_digest: String,
    pub gaps: Vec<String>,
}

impl NativeLintUnit {
    /// A unit is runnable only with at least one sealed file and no gaps.
    pub fn runnable(&self) -> bool {
        !self.files.is_empty() && self.gaps.is_empty()
    }

    /// Record root translates into a planned tool run. `executed` is always
    /// false here: planning never launches anything.
    pub fn runner_record(&self) -> Value {
        json!({
            "providerId": PROVIDER_ID,
            "tool": self.program,
            "packageDir": label(&self.package_dir),
            "programCandidates": [self.program],
            "versionArgv": self.version_argv,
            "argv": self.argv,
            "acceptedExitCodes": self.accepted_exit_codes,
            "parser": self.linter.parser_id(),
            "configFile": self.config_file,
            "configDigest": self.config_digest,
            "fileCount": self.files.len(),
            "ignoredRepoConfigs": self.ignored_repo_configs,
            "scopeDigest": self.scope_digest,
            "runnable": self.runnable(),
            "executed": false,
            "gaps": self.gaps,
        })
    }
}

#[derive(Clone, Debug)]
pub struct NativeLintPlan {
    pub provider_id: &'static str,
    pub linter: Linter,
    pub packages: Vec<JsPackage>,
    pub units: Vec<NativeLintUnit>,
    /// Generated, vendored, or build-output sources, with the reason.
    pub excluded: Vec<ExcludedSource>,
    /// JS sources with no owning `package.json`; never silently dropped.
    pub unowned: Vec<ExcludedSource>,
    pub gaps: Vec<String>,
    pub max_findings: usize,
}

#[derive(Default)]
struct Slot {
    files: Vec<FrozenSourceFile>,
    gaps: Vec<String>,
}

fn owner_of(path: &str, package_dirs: &BTreeSet<String>) -> Option<String> {
    let dir = dir_of(path);
    ancestors(&dir)
        .into_iter()
        .find(|candidate| package_dirs.contains(candidate))
}

fn build_argv(options: &NativeLintOptions, files: &[FrozenSourceFile]) -> Vec<String> {
    let mut argv = match options.linter {
        Linter::Oxlint => vec![
            "--config".to_string(),
            join(&options.staged_config_dir, options.linter.config_file()),
            "--format".to_string(),
            "json".to_string(),
            "--disable-nested-config".to_string(),
        ],
        Linter::Biome => vec![
            "lint".to_string(),
            "--config-path".to_string(),
            options.staged_config_dir.clone(),
            "--reporter".to_string(),
            "json".to_string(),
            format!("--max-diagnostics={BIOME_MAX_DIAGNOSTICS}"),
        ],
    };
    argv.extend(files.iter().map(|file| file.path.clone()));
    argv
}

fn unit_scope_digest(
    linter: Linter,
    dir: &str,
    pin_version: &str,
    config_digest: &str,
    files: &[FrozenSourceFile],
) -> String {
    let listing = files
        .iter()
        .map(|file| format!("{}\0{}", file.path, file.digest))
        .collect::<Vec<_>>()
        .join("\n");
    sha256_hex(
        format!(
            "{}\n{}\n{}\n{}\n{}",
            linter.tool_id(),
            label(dir),
            pin_version,
            config_digest,
            listing
        )
        .as_bytes(),
    )
}

/// Plan one native lint unit per package (including zero-file packages, so
/// an empty package is visible as `zero-files`, not omitted). Plans only;
/// nothing is executed and no pin is assumed valid.
pub fn plan_native_lint(
    entries: &[InventoryEntry],
    reader: &dyn Fn(&str) -> Option<Vec<u8>>,
    pin: &NativeLinterPin,
    options: &NativeLintOptions,
) -> NativeLintPlan {
    let mut pin_gaps = validate_pin(pin);
    if pin.linter != options.linter {
        pin_gaps.push(gap("pin-linter-mismatch"));
    }
    let packages = discover_packages(entries, reader);
    let package_dirs: BTreeSet<String> = packages.keys().cloned().collect();

    let mut slots: BTreeMap<String, Slot> = BTreeMap::new();
    let mut excluded = Vec::new();
    let mut unowned = Vec::new();
    let mut gaps = Vec::new();
    for entry in entries {
        if !is_js_source(&entry.path) {
            continue;
        }
        if !safe_relative(&entry.path) || entry.path.starts_with('-') {
            gaps.push(gap(&format!(
                "javascript-source-path-unsafe:{}",
                entry.path
            )));
            continue;
        }
        if let Some(segment) = excluded_segment(&entry.path) {
            excluded.push(ExcludedSource {
                path: entry.path.clone(),
                reason: format!("excluded-segment:{segment}"),
            });
            continue;
        }
        let Some(owner) = owner_of(&entry.path, &package_dirs) else {
            unowned.push(ExcludedSource {
                path: entry.path.clone(),
                reason: "no-owning-package".to_string(),
            });
            continue;
        };
        let slot = slots.entry(owner).or_default();
        match entry.digest.as_deref() {
            Some(digest) if digest.starts_with("sha256:") => slot.files.push(FrozenSourceFile {
                path: entry.path.clone(),
                digest: digest.to_string(),
            }),
            _ => slot
                .gaps
                .push(gap(&format!("javascript-source-unsealed:{}", entry.path))),
        }
    }
    if !unowned.is_empty() {
        gaps.push(gap(&format!("javascript-unowned-source:{}", unowned.len())));
    }

    let config_text = owned_config_text(options.linter);
    let config_digest = sha256_hex(config_text.as_bytes());
    let mut units = Vec::new();
    for (dir, package) in &packages {
        let mut slot = slots.remove(dir).unwrap_or_default();
        slot.files.sort_by(|left, right| left.path.cmp(&right.path));
        let mut unit_gaps = pin_gaps.clone();
        unit_gaps.extend(slot.gaps);
        unit_gaps.extend(package.gaps.iter().cloned());
        let over_cap = slot.files.len() > MAX_FILES_PER_UNIT;
        if over_cap {
            unit_gaps.push(gap(&format!(
                "javascript-file-cap:{}:{}",
                label(dir),
                slot.files.len()
            )));
        }
        let argv = if over_cap {
            Vec::new()
        } else {
            build_argv(options, &slot.files)
        };
        let scope_digest = unit_scope_digest(
            options.linter,
            dir,
            &pin.version,
            &config_digest,
            &slot.files,
        );
        units.push(NativeLintUnit {
            package_dir: dir.clone(),
            linter: options.linter,
            program: options.linter.tool_id(),
            version_argv: vec!["--version".to_string()],
            argv,
            accepted_exit_codes: ACCEPTED_EXIT_CODES,
            files: slot.files,
            config_file: options.linter.config_file(),
            config_text: config_text.clone(),
            config_digest: config_digest.clone(),
            ignored_repo_configs: package.applicable_repo_configs.clone(),
            scope_digest,
            gaps: unit_gaps,
        });
    }

    NativeLintPlan {
        provider_id: PROVIDER_ID,
        linter: options.linter,
        packages: packages.into_values().collect(),
        units,
        excluded,
        unowned,
        gaps,
        max_findings: options.max_findings,
    }
}

// ---------------------------------------------------------------------------
// Report parsing
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeDiagnostic {
    pub rule: String,
    pub severity: String,
    pub path: String,
    /// `0` when the line could not be resolved (counted in the report).
    pub line: usize,
    pub message: String,
    /// Configuration-class diagnostic (invalid owned config), not a finding.
    pub config_error: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NativeReport {
    pub diagnostics: Vec<NativeDiagnostic>,
    /// Checked-file count when the report proves it.
    pub files_scanned: Option<usize>,
    pub diagnostics_not_printed: usize,
    pub unresolved_lines: usize,
}

fn severity_label(value: &str) -> String {
    match value {
        "error" | "fatal" => "error".to_string(),
        "warning" => "warning".to_string(),
        _ => "note".to_string(),
    }
}

/// `eslint(no-debugger)` becomes `eslint/no-debugger`; other codes pass as is.
fn oxlint_rule_id(code: &str) -> String {
    match (code.find('('), code.strip_suffix(')')) {
        (Some(open), Some(stripped)) => format!("{}/{}", &code[..open], &stripped[open + 1..]),
        _ => code.to_string(),
    }
}

fn line_at(text: &[u8], offset: usize) -> Option<usize> {
    if offset > text.len() {
        return None;
    }
    Some(text[..offset].iter().filter(|byte| **byte == b'\n').count() + 1)
}

/// Parse Oxlint `--format json` output. `number_of_files` proves the scanned
/// set when present; absence leaves it unproven.
pub fn parse_oxlint_report(bytes: &[u8]) -> Result<NativeReport, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "native-lint-report-not-json".to_string())?;
    let items = value
        .get("diagnostics")
        .and_then(Value::as_array)
        .ok_or_else(|| "native-lint-report-shape".to_string())?;
    let mut report = NativeReport {
        files_scanned: value
            .get("number_of_files")
            .and_then(Value::as_u64)
            .map(|count| count as usize),
        ..NativeReport::default()
    };
    for item in items {
        let code = item.get("code").and_then(Value::as_str).unwrap_or("");
        let line = item
            .pointer("/labels/0/span/line")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        if line == 0 {
            report.unresolved_lines += 1;
        }
        report.diagnostics.push(NativeDiagnostic {
            rule: oxlint_rule_id(code),
            severity: severity_label(item.get("severity").and_then(Value::as_str).unwrap_or("")),
            path: item
                .get("filename")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            line,
            message: truncated_message(item.get("message").and_then(Value::as_str).unwrap_or("")),
            config_error: false,
        });
    }
    Ok(report)
}

/// Parse Biome JSON reporter output. Biome's reporter does not prove the
/// checked-file count, so `files_scanned` stays `None`. Byte-offset spans are
/// mapped to lines from `sourceCode` or the frozen `sources` reader.
pub fn parse_biome_report(
    bytes: &[u8],
    sources: &dyn Fn(&str) -> Option<Vec<u8>>,
) -> Result<NativeReport, String> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "native-lint-report-not-json".to_string())?;
    let items = value
        .get("diagnostics")
        .and_then(Value::as_array)
        .ok_or_else(|| "native-lint-report-shape".to_string())?;
    let mut report = NativeReport {
        diagnostics_not_printed: value
            .pointer("/summary/diagnosticsNotPrinted")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize,
        ..NativeReport::default()
    };
    for item in items {
        let category = item
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let location = item.get("location");
        let path = location
            .and_then(|found| found.get("path"))
            .and_then(|found| {
                found.as_str().map(str::to_string).or_else(|| {
                    found
                        .get("file")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
            })
            .unwrap_or_default();
        let inline_source = location
            .and_then(|found| found.get("sourceCode"))
            .and_then(Value::as_str)
            .map(|text| text.as_bytes().to_vec());
        let offset = location
            .and_then(|found| found.get("span"))
            .and_then(Value::as_array)
            .and_then(|span| span.first())
            .and_then(Value::as_u64);
        let text = inline_source.or_else(|| sources(path.as_str()));
        let line = match (offset, text) {
            (Some(offset), Some(text)) => line_at(&text, offset as usize),
            _ => None,
        };
        if line.is_none() {
            report.unresolved_lines += 1;
        }
        let config_error =
            category.starts_with("internalError") || category.starts_with("configuration");
        report.diagnostics.push(NativeDiagnostic {
            severity: severity_label(item.get("severity").and_then(Value::as_str).unwrap_or("")),
            message: truncated_message(
                item.get("description")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
            ),
            rule: category,
            path,
            line: line.unwrap_or(0),
            config_error,
        });
    }
    Ok(report)
}

// ---------------------------------------------------------------------------
// Outcome classification
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeLintStatus {
    /// Proven scanned set, valid report, zero diagnostics, no gaps.
    Clean,
    Findings,
    /// Frozen denominator is empty; nothing was run.
    ZeroFiles,
    InvalidConfig,
    UnsupportedRule,
    MalformedReport,
    OperationalFailure,
    /// Planning gaps, unproven scanned set, truncation or unresolved lines.
    Incomplete,
}

impl NativeLintStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            NativeLintStatus::Clean => "clean",
            NativeLintStatus::Findings => "findings",
            NativeLintStatus::ZeroFiles => "zero-files",
            NativeLintStatus::InvalidConfig => "invalid-config",
            NativeLintStatus::UnsupportedRule => "unsupported-rule",
            NativeLintStatus::MalformedReport => "malformed-report",
            NativeLintStatus::OperationalFailure => "operational-failure",
            NativeLintStatus::Incomplete => "incomplete",
        }
    }
}

#[derive(Clone, Debug)]
pub struct NativeLintOutcome {
    pub provider_id: &'static str,
    pub tool: &'static str,
    pub package_dir: String,
    pub status: NativeLintStatus,
    pub findings: Vec<NativeFinding>,
    pub findings_truncated: usize,
    pub files_expected: usize,
    pub files_scanned: Option<usize>,
    pub gaps: Vec<String>,
    pub report_digest: String,
    pub scope_digest: String,
    /// Ignored repository configs, reported as coverage context only.
    pub ignored_repo_configs: Vec<String>,
}

/// Classify one completed run. `exit_code` is `None` for a signal or timeout.
/// `sources` resolves Biome byte spans to lines. Every path not proven
/// complete resolves to a non-clean status with the named gap.
pub fn classify_run(
    unit: &NativeLintUnit,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
    sources: &dyn Fn(&str) -> Option<Vec<u8>>,
    max_findings: usize,
) -> NativeLintOutcome {
    let mut outcome = NativeLintOutcome {
        provider_id: PROVIDER_ID,
        tool: unit.program,
        package_dir: label(&unit.package_dir).to_string(),
        status: NativeLintStatus::Incomplete,
        findings: Vec::new(),
        findings_truncated: 0,
        files_expected: unit.files.len(),
        files_scanned: None,
        gaps: unit.gaps.clone(),
        report_digest: sha256_hex(stdout),
        scope_digest: unit.scope_digest.clone(),
        ignored_repo_configs: unit.ignored_repo_configs.clone(),
    };
    if unit.files.is_empty() {
        outcome.status = NativeLintStatus::ZeroFiles;
        return outcome;
    }
    if !unit.runnable() {
        return outcome;
    }
    let stderr_text = String::from_utf8_lossy(stderr).to_lowercase();
    if CONFIG_MARKERS
        .iter()
        .any(|marker| stderr_text.contains(marker))
    {
        outcome.status = NativeLintStatus::InvalidConfig;
        return outcome;
    }
    if UNSUPPORTED_RULE_MARKERS
        .iter()
        .any(|marker| stderr_text.contains(marker))
    {
        outcome.status = NativeLintStatus::UnsupportedRule;
        return outcome;
    }
    let Some(code) = exit_code else {
        outcome.gaps.push(gap("native-lint-no-exit"));
        outcome.status = NativeLintStatus::OperationalFailure;
        return outcome;
    };
    if !ACCEPTED_EXIT_CODES.contains(&code) {
        outcome.gaps.push(gap(&format!("native-lint-exit:{code}")));
        outcome.status = NativeLintStatus::OperationalFailure;
        return outcome;
    }
    let parsed = match unit.linter {
        Linter::Oxlint => parse_oxlint_report(stdout),
        Linter::Biome => parse_biome_report(stdout, sources),
    };
    let report = match parsed {
        Ok(report) => report,
        Err(reason) => {
            outcome.gaps.push(gap(&reason));
            outcome.status = NativeLintStatus::MalformedReport;
            return outcome;
        }
    };
    if report
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.config_error)
    {
        outcome.status = NativeLintStatus::InvalidConfig;
        return outcome;
    }
    outcome.files_scanned = report.files_scanned;
    match (unit.linter, report.files_scanned) {
        (Linter::Oxlint, Some(count)) if count == unit.files.len() => {}
        (Linter::Oxlint, Some(count)) => outcome.gaps.push(gap(&format!(
            "native-lint-scanned-set-mismatch:{count}/{}",
            unit.files.len()
        ))),
        (Linter::Oxlint, None) => outcome.gaps.push(gap("native-lint-scanned-set-unproven")),
        (Linter::Biome, _) => outcome.gaps.push(gap("biome-scanned-set-unproven")),
    }
    if report.diagnostics_not_printed > 0 {
        outcome.gaps.push(gap(&format!(
            "native-lint-diagnostics-truncated:{}",
            report.diagnostics_not_printed
        )));
    }
    if report.unresolved_lines > 0 {
        outcome.gaps.push(gap(&format!(
            "native-lint-line-unresolved:{}",
            report.unresolved_lines
        )));
    }
    if code == 1 && report.diagnostics.is_empty() {
        outcome
            .gaps
            .push(gap("native-lint-exit-without-diagnostics"));
        outcome.status = NativeLintStatus::OperationalFailure;
        return outcome;
    }

    let mut diagnostics = report.diagnostics;
    diagnostics.sort_by(|left, right| {
        (left.path.as_str(), left.line, left.rule.as_str()).cmp(&(
            right.path.as_str(),
            right.line,
            right.rule.as_str(),
        ))
    });
    if diagnostics.is_empty() {
        outcome.status = if outcome.gaps.is_empty() {
            NativeLintStatus::Clean
        } else {
            NativeLintStatus::Incomplete
        };
        return outcome;
    }
    outcome.findings_truncated = diagnostics.len().saturating_sub(max_findings);
    outcome.findings = diagnostics
        .into_iter()
        .take(max_findings)
        .map(|diagnostic| {
            let severity = match diagnostic.severity.as_str() {
                "error" => "error",
                "warning" => "warning",
                _ => "note",
            };
            NativeFinding {
                rule: Cow::Owned(diagnostic.rule),
                severity,
                path: diagnostic.path,
                line: diagnostic.line,
                message: diagnostic.message,
            }
        })
        .collect();
    outcome.status = NativeLintStatus::Findings;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oxlint_rule_ids_are_plugin_slash_rule() {
        assert_eq!(oxlint_rule_id("eslint(no-debugger)"), "eslint/no-debugger");
        assert_eq!(oxlint_rule_id("plain"), "plain");
    }

    #[test]
    fn ancestors_walk_to_root() {
        assert_eq!(ancestors("a/b"), vec!["a/b", "a", ""]);
        assert_eq!(ancestors(""), vec![""]);
    }

    #[test]
    fn unpinned_identity_always_names_gaps() {
        let gaps = validate_pin(&NativeLinterPin::unpinned(Linter::Oxlint));
        assert!(gaps
            .iter()
            .any(|gap| gap.ends_with("oxlint-version-unpinned")));
        assert!(gaps
            .iter()
            .any(|gap| gap.ends_with("oxlint-distribution-digest-missing")));
    }
}
