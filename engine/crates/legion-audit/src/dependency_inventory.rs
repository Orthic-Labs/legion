//! Native dependency inventory over frozen lock inputs (A08).
//! Parsing is pure: no package-manager execution, install hooks, network access,
//! or advisory/registry refresh. Missing, stale, partial, unsupported or unparsed
//! evidence is an explicit gap and never becomes a clean or current result.

use super::native_providers::security::{
    common::{array, digest, digest_json},
    supply_chain_documents::{lock_kind, parse_lock},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const DEPENDENCY_INVENTORY_SCHEMA_VERSION: u32 = 1;
pub const DEPENDENCY_INVENTORY_BOUND: &str = "dependencyInventoryV1";

const UNRECORDED: &str = "unrecorded";
const LOCAL: &str = "local";
const DEFAULT_SCOPE: &str = "default";
const UNSUPPORTED_LOCKS: [&str; 8] = [
    "uv.lock",
    "composer.lock",
    "Gemfile.lock",
    "Pipfile.lock",
    "packages.lock.json",
    "Podfile.lock",
    "pubspec.lock",
    "mix.lock",
];
const DECLARED_ONLY: [&str; 4] = [
    "pom.xml",
    "libs.versions.toml",
    "build.gradle",
    "build.gradle.kts",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Ecosystem {
    Cargo,
    Npm,
    Golang,
    Pypi,
    Swift,
    Gradle,
}

impl Ecosystem {
    pub fn label(self) -> &'static str {
        match self {
            Self::Cargo => "cargo",
            Self::Npm => "npm",
            Self::Golang => "golang",
            Self::Pypi => "pypi",
            Self::Swift => "swift",
            Self::Gradle => "gradle",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DependencyRole {
    Runtime,
    Development,
    Build,
    Test,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceStatus {
    Current,
    Stale,
    Partial,
    Unknown,
    Absent,
}

impl SourceStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Stale => "stale",
            Self::Partial => "partial",
            Self::Unknown => "unknown",
            Self::Absent => "absent",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Maintenance {
    Active,
    Abandoned,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingKind {
    Vulnerable,
    LatestDiffers,
    Deprecated,
    Abandoned,
    Duplicate,
}

/// Frozen dependency file. `target` names the build target or variant it belongs to.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestInput {
    pub path: String,
    pub raw: String,
    pub target: String,
}

/// One advisory match candidate, namespaced by ecosystem and registry.
/// `range_events` is true when the advisory also carries range bounds that are
/// not evaluated here; exact `affected_versions` remain authoritative.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisoryRecord {
    pub id: String,
    pub ecosystem: Ecosystem,
    pub registry: String,
    pub name: String,
    pub affected_versions: Vec<String>,
    pub fixed_versions: Vec<String>,
    pub range_events: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvisoryDatabase {
    pub version: String,
    pub digest: String,
    pub status: SourceStatus,
    pub records: Vec<AdvisoryRecord>,
}

/// Frozen registry metadata for one package name. Only `Current` records may
/// produce latest-version, deprecation or maintenance findings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryMetadata {
    pub ecosystem: Ecosystem,
    pub registry: String,
    pub name: String,
    pub latest_version: Option<String>,
    pub deprecated: Option<bool>,
    pub maintenance: Maintenance,
    pub status: SourceStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyPackage {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    /// Registry host or crates.io/npm identity; `git:<url>` for git sources; `unrecorded` when the format omits it.
    pub registry: String,
    pub revision: Option<String>,
    /// Namespaced identity: `<ecosystem>|<registry>|<name>@<version>[#<revision>]`.
    pub identity: String,
    pub scope: String,
    pub manifest: String,
    pub role: DependencyRole,
    /// `None` when directness is not proven by the frozen lock.
    pub direct: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnsupportedFormat {
    pub path: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyFinding {
    pub kind: FindingKind,
    pub scope: String,
    pub package: String,
    pub manifest: String,
    pub advisory: Option<String>,
    pub fixed_versions: Vec<String>,
    pub detail: Option<String>,
    /// Reachability is never inferred from a lock; it stays `unknown`.
    pub reachability: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyGap {
    pub kind: String,
    pub path: Option<String>,
    pub subject: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Freshness {
    pub advisory: SourceStatus,
    pub registry: SourceStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestRecord {
    pub path: String,
    pub scope: String,
    pub digest: String,
    pub format: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyInventory {
    pub schema_version: u32,
    pub packages: Vec<DependencyPackage>,
    pub manifests: Vec<ManifestRecord>,
    pub unsupported: Vec<UnsupportedFormat>,
    pub findings: Vec<DependencyFinding>,
    pub gaps: Vec<DependencyGap>,
    pub freshness: Freshness,
    pub graph_digest: String,
    pub source_digest: String,
    pub metadata_digest: Option<String>,
    /// True only when no gap and no unsupported input remains.
    pub complete: bool,
}

/// Builds the inventory from frozen inputs. Pure and deterministic.
pub fn inventory(
    manifests: &[ManifestInput],
    advisory: Option<&AdvisoryDatabase>,
    metadata: &[RegistryMetadata],
) -> DependencyInventory {
    let mut gaps = Vec::new();
    let mut unsupported = Vec::new();
    let mut packages: Vec<DependencyPackage> = Vec::new();
    let mut records = Vec::new();
    let mut seen = BTreeSet::new();
    if manifests.is_empty() {
        gaps.push(gap("dependency-manifest-denominator-zero", None, None));
    }
    for input in manifests {
        let Some(parsed) = parse_input(&input.path, &input.raw) else {
            continue;
        };
        let scope = if input.target.is_empty() {
            DEFAULT_SCOPE.to_owned()
        } else {
            input.target.clone()
        };
        if !seen.insert((scope.clone(), input.path.clone())) {
            gaps.push(gap(
                "dependency-manifest-duplicate",
                Some(input.path.as_str()),
                None,
            ));
            continue;
        }
        match parsed {
            Ok(rows) => {
                records.push(ManifestRecord {
                    path: input.path.clone(),
                    scope: scope.clone(),
                    digest: digest(input.raw.as_bytes()),
                    format: file_name(&input.path).to_owned(),
                });
                // Transitive edges are not modelled by this inventory; that is explicit.
                gaps.push(gap(
                    "dependency-graph-edges-unmodelled",
                    Some(input.path.as_str()),
                    None,
                ));
                for mut row in rows {
                    row.scope = scope.clone();
                    row.manifest = input.path.clone();
                    packages.push(row);
                }
            }
            Err(reason) => unsupported.push(UnsupportedFormat {
                path: input.path.clone(),
                reason,
            }),
        }
    }
    let mut keys = BTreeSet::new();
    packages.retain(|p| keys.insert((p.scope.clone(), p.manifest.clone(), p.identity.clone())));
    packages.sort_by(|a, b| {
        (&a.scope, &a.manifest, &a.identity).cmp(&(&b.scope, &b.manifest, &b.identity))
    });

    let mut coverage = BTreeSet::new();
    for package in &packages {
        if let Some(reason) = advisory_gap_reason(package) {
            coverage.insert((package.manifest.clone(), reason));
        }
    }
    for (path, reason) in &coverage {
        gaps.push(gap(
            "advisory-coverage-unproven",
            Some(path.as_str()),
            Some(*reason),
        ));
    }

    let mut findings = Vec::new();
    match advisory {
        None => gaps.push(gap("advisory-database-absent", None, None)),
        Some(db) if db.status != SourceStatus::Current => gaps.push(gap(
            &format!("advisory-database-{}", db.status.label()),
            None,
            Some(db.version.as_str()),
        )),
        Some(_) => {}
    }
    if let Some(db) = advisory {
        for package in &packages {
            if advisory_gap_reason(package).is_some() {
                continue;
            }
            for record in db.records.iter().filter(|r| {
                r.ecosystem == package.ecosystem
                    && r.registry == package.registry
                    && r.name == package.name
            }) {
                if record
                    .affected_versions
                    .iter()
                    .any(|v| v == &package.version)
                {
                    findings.push(finding(
                        FindingKind::Vulnerable,
                        package,
                        Some(record.id.clone()),
                        record.fixed_versions.clone(),
                        None,
                    ));
                } else if record.range_events
                    && !record.fixed_versions.iter().any(|v| v == &package.version)
                {
                    gaps.push(gap(
                        "advisory-range-unevaluated",
                        Some(package.manifest.as_str()),
                        Some(record.id.as_str()),
                    ));
                }
            }
        }
    }

    for package in &packages {
        if advisory_gap_reason(package).is_some() {
            continue;
        }
        let Some(meta) = metadata.iter().find(|m| {
            m.ecosystem == package.ecosystem
                && m.registry == package.registry
                && m.name == package.name
        }) else {
            gaps.push(gap(
                "registry-metadata-absent",
                Some(package.manifest.as_str()),
                Some(package.name.as_str()),
            ));
            continue;
        };
        if meta.status != SourceStatus::Current {
            gaps.push(gap(
                &format!("registry-metadata-{}", meta.status.label()),
                Some(package.manifest.as_str()),
                Some(package.name.as_str()),
            ));
            continue;
        }
        match meta.latest_version.as_deref() {
            Some(latest) if latest != package.version.as_str() => findings.push(finding(
                FindingKind::LatestDiffers,
                package,
                None,
                Vec::new(),
                Some(latest.to_owned()),
            )),
            Some(_) => {}
            None => gaps.push(gap(
                "latest-version-unavailable",
                Some(package.manifest.as_str()),
                Some(package.name.as_str()),
            )),
        }
        match meta.deprecated {
            Some(true) => findings.push(finding(
                FindingKind::Deprecated,
                package,
                None,
                Vec::new(),
                None,
            )),
            Some(false) => {}
            None => gaps.push(gap(
                "deprecation-status-unknown",
                Some(package.manifest.as_str()),
                Some(package.name.as_str()),
            )),
        }
        match meta.maintenance {
            Maintenance::Abandoned => findings.push(finding(
                FindingKind::Abandoned,
                package,
                None,
                Vec::new(),
                None,
            )),
            Maintenance::Active => {}
            Maintenance::Unknown => gaps.push(gap(
                "maintenance-unknown",
                Some(package.manifest.as_str()),
                Some(package.name.as_str()),
            )),
        }
    }

    // Duplicate versions of one name within one registry, per manifest and scope.
    let mut versions: BTreeMap<(String, String, String, String, String), BTreeSet<String>> =
        BTreeMap::new();
    for package in &packages {
        if package.registry == UNRECORDED || package.registry.starts_with("git:") {
            continue;
        }
        versions
            .entry((
                package.scope.clone(),
                package.manifest.clone(),
                package.ecosystem.label().to_owned(),
                package.registry.clone(),
                package.name.clone(),
            ))
            .or_default()
            .insert(package.version.clone());
    }
    for ((scope, manifest, ecosystem, registry, name), set) in versions {
        if set.len() > 1 {
            findings.push(DependencyFinding {
                kind: FindingKind::Duplicate,
                scope,
                package: format!("{ecosystem}|{registry}|{name}"),
                manifest,
                advisory: None,
                fixed_versions: Vec::new(),
                detail: Some(set.into_iter().collect::<Vec<_>>().join(", ")),
                reachability: "unknown".to_owned(),
            });
        }
    }

    // Unused-symbol and license-policy analysis need inputs this pure inventory does not own.
    gaps.push(gap("unused-analysis-unsupported", None, None));
    gaps.push(gap("license-policy-not-evaluated", None, None));

    records.sort_by(|a: &ManifestRecord, b: &ManifestRecord| {
        (&a.path, &a.scope).cmp(&(&b.path, &b.scope))
    });
    let source_digest = digest_json(&serde_json::to_value(&records).unwrap_or(Value::Null));
    let graph_digest = digest_json(&serde_json::to_value(&packages).unwrap_or(Value::Null));
    let metadata_digest = if advisory.is_none() && metadata.is_empty() {
        None
    } else {
        Some(digest_json(&json!({
            "advisory": advisory.map(|db| json!({
                "version": db.version,
                "digest": db.digest,
                "status": db.status,
                "records": db.records,
            })),
            "registry": metadata,
        })))
    };
    let freshness = Freshness {
        advisory: advisory.map_or(SourceStatus::Absent, |db| db.status),
        registry: worst_status(metadata.iter().map(|m| m.status)),
    };
    let complete = gaps.is_empty() && unsupported.is_empty();
    DependencyInventory {
        schema_version: DEPENDENCY_INVENTORY_SCHEMA_VERSION,
        packages,
        manifests: records,
        unsupported,
        findings,
        gaps,
        freshness,
        graph_digest,
        source_digest,
        metadata_digest,
        complete,
    }
}

/// `None` for unrecognised files (not dependency inputs); `Err` for unsupported or unparsed inputs.
fn parse_input(path: &str, raw: &str) -> Option<Result<Vec<DependencyPackage>, String>> {
    let name = file_name(path);
    Some(match name {
        "Cargo.lock" => parse_cargo(path, raw),
        "package-lock.json" | "npm-shrinkwrap.json" => parse_npm(path, raw),
        "Package.resolved" => parse_swift(path, raw),
        "gradle.lockfile" => parse_gradle(path, raw),
        _ if UNSUPPORTED_LOCKS.contains(&name) => Err("lock-format-unsupported".to_owned()),
        _ if DECLARED_ONLY.contains(&name) || name.ends_with(".csproj") => {
            Err("declared-not-resolved".to_owned())
        }
        _ if lock_kind(path).is_some() => parse_shared(path, raw),
        _ => return None,
    })
}

fn parse_cargo(path: &str, raw: &str) -> Result<Vec<DependencyPackage>, String> {
    let fail = || format!("dependency-manifest-unparsed:{path}");
    let doc: toml::Value = toml::from_str(raw).map_err(|_| fail())?;
    let rows = doc
        .get("package")
        .and_then(toml::Value::as_array)
        .ok_or_else(fail)?;
    // Sourceless packages are workspace or path members; their dependency lists name direct edges.
    let mut direct_names = BTreeSet::new();
    for row in rows.iter().filter(|row| row.get("source").is_none()) {
        let dependencies = row.get("dependencies").and_then(toml::Value::as_array);
        for dependency in dependencies
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
        {
            if let Some(name) = dependency.split_whitespace().next() {
                direct_names.insert(name.to_owned());
            }
        }
    }
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for row in rows {
        if let Some(name) = row.get("name").and_then(toml::Value::as_str) {
            *counts.entry(name).or_insert(0) += 1;
        }
    }
    let mut out = Vec::new();
    for row in rows {
        let name = row
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(fail)?;
        let version = row
            .get("version")
            .and_then(toml::Value::as_str)
            .ok_or_else(fail)?;
        let source = row.get("source").and_then(toml::Value::as_str);
        let (registry, revision) = match source {
            None => (LOCAL.to_owned(), None),
            Some(source) => cargo_source(source).ok_or_else(fail)?,
        };
        let mut package = new_row(
            Ecosystem::Cargo,
            name.to_owned(),
            version.to_owned(),
            registry,
            revision,
        );
        if source.is_some() && counts.get(&name) == Some(&1) {
            package.direct = Some(direct_names.contains(name));
        }
        out.push(package);
    }
    Ok(out)
}

fn cargo_source(source: &str) -> Option<(String, Option<String>)> {
    if let Some(url) = source.strip_prefix("registry+") {
        let registry = if url.contains("crates.io-index") || url.contains("index.crates.io") {
            "crates.io".to_owned()
        } else {
            url.to_owned()
        };
        return Some((registry, None));
    }
    let rest = source.strip_prefix("git+")?;
    let (url, revision) = rest.rsplit_once('#')?;
    if revision.is_empty() {
        return None;
    }
    let url = url.split('?').next().unwrap_or(url);
    Some((format!("git:{url}"), Some(revision.to_owned())))
}

fn parse_npm(path: &str, raw: &str) -> Result<Vec<DependencyPackage>, String> {
    let fail = || format!("dependency-manifest-unparsed:{path}");
    let doc: Value = serde_json::from_str(raw).map_err(|_| fail())?;
    let version = doc
        .get("lockfileVersion")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let rows = match doc.get("packages").and_then(Value::as_object) {
        Some(rows) if version >= 2 => rows,
        _ => return Err(format!("dependency-lock-version-unsupported:{path}")),
    };
    let root = rows.get("");
    let mut runtime_roots = object_keys(root.and_then(|r| r.get("dependencies")));
    runtime_roots.extend(object_keys(
        root.and_then(|r| r.get("optionalDependencies")),
    ));
    runtime_roots.extend(object_keys(root.and_then(|r| r.get("peerDependencies"))));
    let dev_roots = object_keys(root.and_then(|r| r.get("devDependencies")));
    let mut out = Vec::new();
    for (key, row) in rows {
        if key.is_empty() {
            continue;
        }
        if row.get("link").and_then(Value::as_bool) == Some(true) {
            return Err(format!("dependency-lock-link-unsupported:{path}"));
        }
        let name = key
            .rsplit_once("node_modules/")
            .map(|(_, n)| n)
            .ok_or_else(fail)?;
        let version = row
            .get("version")
            .and_then(Value::as_str)
            .ok_or_else(fail)?;
        let (registry, revision) = npm_source(row.get("resolved").and_then(Value::as_str));
        let mut package = new_row(
            Ecosystem::Npm,
            name.to_owned(),
            version.to_owned(),
            registry,
            revision,
        );
        if row.get("dev").and_then(Value::as_bool) == Some(true) {
            package.role = DependencyRole::Development;
        } else {
            package.role = DependencyRole::Runtime;
        }
        // Only the top-level (hoisted) entry can be a direct dependency of the root.
        if key.strip_prefix("node_modules/") == Some(name) {
            package.direct = Some(runtime_roots.contains(name) || dev_roots.contains(name));
        }
        out.push(package);
    }
    Ok(out)
}

fn object_keys(value: Option<&Value>) -> BTreeSet<String> {
    value
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|map| map.keys().cloned())
        .collect()
}

fn npm_source(resolved: Option<&str>) -> (String, Option<String>) {
    let Some(resolved) = resolved else {
        return (UNRECORDED.to_owned(), None);
    };
    if resolved.starts_with("git") || resolved.contains("github:") {
        let (url, revision) = match resolved.rsplit_once('#') {
            Some((url, revision)) if !revision.is_empty() => {
                (url, Some(revision.to_owned()))
            }
            _ => (resolved, None),
        };
        return (format!("git:{url}"), revision);
    }
    match resolved
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
    {
        Some(host) if !host.is_empty() => (host.to_owned(), None),
        _ => (UNRECORDED.to_owned(), None),
    }
}

fn parse_swift(path: &str, raw: &str) -> Result<Vec<DependencyPackage>, String> {
    let fail = || format!("dependency-manifest-unparsed:{path}");
    let doc: Value = serde_json::from_str(raw).map_err(|_| fail())?;
    let pins = match doc.get("version").and_then(Value::as_u64) {
        Some(2) | Some(3) => array(doc.get("pins")),
        Some(1) => array(doc.pointer("/object/pins")),
        _ => return Err(format!("dependency-lock-version-unsupported:{path}")),
    };
    let mut out = Vec::new();
    for pin in &pins {
        let identity = pin
            .get("identity")
            .or_else(|| pin.get("package"))
            .and_then(Value::as_str)
            .ok_or_else(fail)?;
        let location = pin
            .get("location")
            .or_else(|| pin.get("repositoryURL"))
            .and_then(Value::as_str)
            .ok_or_else(fail)?;
        let state = pin.get("state").ok_or_else(fail)?;
        let revision = state
            .get("revision")
            .and_then(Value::as_str)
            .ok_or_else(fail)?;
        let version = state
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or(revision);
        out.push(new_row(
            Ecosystem::Swift,
            identity.to_owned(),
            version.to_owned(),
            format!("git:{location}"),
            Some(revision.to_owned()),
        ));
    }
    if out.is_empty() {
        return Err(fail());
    }
    Ok(out)
}

fn parse_gradle(path: &str, raw: &str) -> Result<Vec<DependencyPackage>, String> {
    let fail = || format!("dependency-manifest-unparsed:{path}");
    let mut out = Vec::new();
    for line in raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let Some((coordinates, _configurations)) = line.split_once('=') else {
            return Err(fail());
        };
        if coordinates == "empty" {
            continue;
        }
        let parts: Vec<&str> = coordinates.split(':').collect();
        if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
            return Err(fail());
        }
        out.push(new_row(
            Ecosystem::Gradle,
            format!("{}:{}", parts[0], parts[1]),
            parts[2].to_owned(),
            UNRECORDED.to_owned(),
            None,
        ));
    }
    if out.is_empty() {
        return Err(fail());
    }
    Ok(out)
}

/// Formats handled by the shared lock parser (pnpm, yarn, go, pip, poetry).
/// Those formats omit registry/source, so every row stays `unrecorded`.
fn parse_shared(path: &str, raw: &str) -> Result<Vec<DependencyPackage>, String> {
    let identities = parse_lock(path, raw)?;
    identities
        .iter()
        .map(|purl| shared_row(purl))
        .collect()
}

fn shared_row(purl: &str) -> Result<DependencyPackage, String> {
    let fail = || format!("dependency-identity-invalid:{purl}");
    let body = purl.strip_prefix("pkg:").ok_or_else(fail)?;
    let (kind, rest) = body.split_once('/').ok_or_else(fail)?;
    let (name, version) = rest.rsplit_once('@').ok_or_else(fail)?;
    let ecosystem = match kind {
        "npm" => Ecosystem::Npm,
        "golang" => Ecosystem::Golang,
        "pypi" => Ecosystem::Pypi,
        "cargo" => Ecosystem::Cargo,
        _ => return Err(fail()),
    };
    Ok(new_row(
        ecosystem,
        name.replace("%40", "@"),
        version.to_owned(),
        UNRECORDED.to_owned(),
        None,
    ))
}

fn new_row(
    ecosystem: Ecosystem,
    name: String,
    version: String,
    registry: String,
    revision: Option<String>,
) -> DependencyPackage {
    let mut identity = format!("{}|{}|{}@{}", ecosystem.label(), registry, name, version);
    if let Some(revision) = &revision {
        identity.push('#');
        identity.push_str(revision);
    }
    DependencyPackage {
        ecosystem,
        name,
        version,
        registry,
        revision,
        identity,
        scope: String::new(),
        manifest: String::new(),
        role: DependencyRole::Unknown,
        direct: None,
    }
}

/// `Some(reason)` when a package cannot be matched against advisories, so the gap stays explicit.
fn advisory_gap_reason(package: &DependencyPackage) -> Option<&'static str> {
    if package.registry == UNRECORDED {
        Some("source-unrecorded")
    } else if package.registry.starts_with("git:") {
        Some("git-source")
    } else if matches!(package.ecosystem, Ecosystem::Swift | Ecosystem::Gradle) {
        Some("ecosystem-unsupported")
    } else if !matches!(
        (package.ecosystem, package.registry.as_str()),
        (Ecosystem::Cargo, "crates.io")
            | (Ecosystem::Npm, "registry.npmjs.org")
            | (Ecosystem::Golang, "proxy.golang.org")
            | (Ecosystem::Pypi, "pypi.org")
    ) {
        // Private or mirrored registries share names with public advisories without proving identity.
        Some("registry-not-advisory-covered")
    } else {
        None
    }
}

fn finding(
    kind: FindingKind,
    package: &DependencyPackage,
    advisory: Option<String>,
    fixed_versions: Vec<String>,
    detail: Option<String>,
) -> DependencyFinding {
    DependencyFinding {
        kind,
        scope: package.scope.clone(),
        package: package.identity.clone(),
        manifest: package.manifest.clone(),
        advisory,
        fixed_versions,
        detail,
        reachability: "unknown".to_owned(),
    }
}

fn gap(kind: &str, path: Option<&str>, subject: Option<&str>) -> DependencyGap {
    DependencyGap {
        kind: kind.to_owned(),
        path: path.map(str::to_owned),
        subject: subject.map(str::to_owned),
    }
}

fn worst_status(statuses: impl Iterator<Item = SourceStatus>) -> SourceStatus {
    let mut any = false;
    for status in statuses {
        if status != SourceStatus::Current {
            return status;
        }
        any = true;
    }
    if any {
        SourceStatus::Current
    } else {
        SourceStatus::Absent
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}
