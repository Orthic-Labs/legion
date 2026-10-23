//! `code.apple.targets` (A06): Xcode workspace/project/scheme/destination
//! coverage beyond SwiftPM.
//!
//! This module is a pure interpreter. It launches nothing, signs nothing,
//! archives nothing and installs nothing. Callers hand it frozen-snapshot
//! bytes (`path -> bytes`, repository-relative, `/` separated) and optional
//! authenticated A03 evidence; it returns an inventory, explicit gaps and an
//! obligation status. A macOS SwiftPM compile can never discharge an iOS scheme
//! obligation: evidence must match container, scheme, configuration,
//! destination/SDK, test plan and the digest of every bound input.
//!
//! Execution (xcodebuild build/test) is reached only through
//! [`AppleTargetBridge`], whose absence is an explicit
//! `apple-bridge-unconfigured` gap and never a pass. The bridge is a request
//! to root for the existing Apple host boundary (`project.build` /
//! `project.test`); the audit crate does not depend on the CLI binary.
//!
//! Absence of evidence, findings or inputs is never reported as clean: the
//! only terminal "good" status is `satisfied`, reachable solely through a
//! verified, fresh, scheme-linked test/build envelope with an xcresult summary.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::artifact_evidence::{
    verify_artifact_evidence, ArtifactBinding, ArtifactEvidenceEnvelope, CommandBinding,
    EvidenceOutcome, ExpectedEvidence, ImportKind, ImportVerdict, ImportedEvidenceRecord,
    ProvenanceVerifier, ReplayPolicy, RepositoryBinding, RetainedArtifact, TrustEnrollment,
};
use crate::error::AuditError;

pub const PROVIDER_ID: &str = "code.apple.targets";
pub const SCHEMA_VERSION: u32 = 1;
const MAX_PARSE_DEPTH: usize = 64;
const MAX_FINDINGS: usize = 2000;

/// Frozen-snapshot bytes keyed by repository-relative path.
pub type SnapshotFiles = BTreeMap<String, Vec<u8>>;

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

// ---------------------------------------------------------------------------
// Gaps
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Gap {
    pub code: String,
    pub detail: String,
}

fn gap(code: &str, detail: impl Into<String>) -> Gap {
    Gap {
        code: code.to_string(),
        detail: detail.into(),
    }
}

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Join and normalise; `None` when the result would leave the repository root.
fn norm_join(dir: &str, rel: &str) -> Option<String> {
    let mut parts: Vec<&str> = Vec::new();
    if !rel.starts_with('/') {
        for part in dir.split('/') {
            push_part(&mut parts, part)?;
        }
    }
    for part in rel.split('/') {
        push_part(&mut parts, part)?;
    }
    Some(parts.join("/"))
}

fn push_part<'a>(parts: &mut Vec<&'a str>, part: &'a str) -> Option<()> {
    match part {
        "" | "." => {}
        ".." => {
            parts.pop()?;
        }
        other => parts.push(other),
    }
    Some(())
}

fn parent_dir(path: &str) -> String {
    path.rsplit_once('/')
        .map(|(parent, _)| parent.to_string())
        .unwrap_or_default()
}

fn base_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// ---------------------------------------------------------------------------
// OpenStep property list (project.pbxproj)
// ---------------------------------------------------------------------------

struct Openstep<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Openstep<'a> {
    fn skip(&mut self) {
        loop {
            while self.at < self.bytes.len() && self.bytes[self.at].is_ascii_whitespace() {
                self.at += 1;
            }
            let rest = &self.bytes[self.at.min(self.bytes.len())..];
            if rest.starts_with(b"//") {
                while self.at < self.bytes.len() && self.bytes[self.at] != b'\n' {
                    self.at += 1;
                }
            } else if rest.starts_with(b"/*") {
                self.at += 2;
                while self.at < self.bytes.len() && !self.bytes[self.at..].starts_with(b"*/") {
                    self.at += 1;
                }
                self.at = (self.at + 2).min(self.bytes.len());
            } else {
                return;
            }
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        self.skip();
        if self.bytes.get(self.at) == Some(&byte) {
            self.at += 1;
            Ok(())
        } else {
            Err(format!("expected '{}' at byte {}", byte as char, self.at))
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.skip();
        match self.bytes.get(self.at) {
            None => Err("unexpected end of plist".into()),
            Some(b'"') => {
                self.at += 1;
                let mut out: Vec<u8> = Vec::new();
                while let Some(&byte) = self.bytes.get(self.at) {
                    self.at += 1;
                    match byte {
                        b'"' => return Ok(String::from_utf8_lossy(&out).into_owned()),
                        b'\\' => {
                            let next = *self.bytes.get(self.at).ok_or("dangling escape")?;
                            self.at += 1;
                            out.push(match next {
                                b'n' => b'\n',
                                b't' => b'\t',
                                other => other,
                            });
                        }
                        other => out.push(other),
                    }
                }
                Err("unterminated quoted string".into())
            }
            Some(_) => {
                let start = self.at;
                while self.at < self.bytes.len()
                    && !self.bytes[self.at].is_ascii_whitespace()
                    && !matches!(
                        self.bytes[self.at],
                        b';' | b',' | b'=' | b'(' | b')' | b'{' | b'}' | b'"'
                    )
                {
                    self.at += 1;
                }
                if start == self.at {
                    return Err(format!("unexpected byte at {}", self.at));
                }
                Ok(String::from_utf8_lossy(&self.bytes[start..self.at]).into_owned())
            }
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        if depth > MAX_PARSE_DEPTH {
            return Err("plist nesting too deep".into());
        }
        self.skip();
        match self.bytes.get(self.at) {
            Some(b'{') => {
                self.at += 1;
                let mut map = Map::new();
                loop {
                    self.skip();
                    if self.bytes.get(self.at) == Some(&b'}') {
                        self.at += 1;
                        return Ok(Value::Object(map));
                    }
                    let key = self.string()?;
                    self.expect(b'=')?;
                    let value = self.value(depth + 1)?;
                    self.expect(b';')?;
                    map.insert(key, value);
                }
            }
            Some(b'(') => {
                self.at += 1;
                let mut items = Vec::new();
                loop {
                    self.skip();
                    if self.bytes.get(self.at) == Some(&b')') {
                        self.at += 1;
                        return Ok(Value::Array(items));
                    }
                    items.push(self.value(depth + 1)?);
                    self.skip();
                    if self.bytes.get(self.at) == Some(&b',') {
                        self.at += 1;
                    }
                }
            }
            _ => self.string().map(Value::String),
        }
    }
}

pub fn parse_openstep_plist(bytes: &[u8]) -> Result<Value, String> {
    let mut parser = Openstep { bytes, at: 0 };
    let value = parser.value(0)?;
    parser.skip();
    if parser.at != bytes.len() {
        return Err("trailing bytes after plist".into());
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// Minimal XML tokenizer (schemes, workspace data, XML plists)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Tok {
    Open {
        name: String,
        attrs: BTreeMap<String, String>,
        selfclose: bool,
    },
    Close(String),
    Text(String),
}

fn xml_unescape(text: &str) -> String {
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

fn xml_tokens(text: &str) -> Vec<Tok> {
    let bytes = text.as_bytes();
    let mut tokens = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] != b'<' {
            let start = at;
            while at < bytes.len() && bytes[at] != b'<' {
                at += 1;
            }
            let chunk = String::from_utf8_lossy(&bytes[start..at]);
            if !chunk.trim().is_empty() {
                tokens.push(Tok::Text(xml_unescape(chunk.trim())));
            }
            continue;
        }
        let rest = &bytes[at..];
        if rest.starts_with(b"<?") {
            at = find_seq(bytes, at, b"?>")
                .map(|end| end + 2)
                .unwrap_or(bytes.len());
        } else if rest.starts_with(b"<!--") {
            at = find_seq(bytes, at, b"-->")
                .map(|end| end + 3)
                .unwrap_or(bytes.len());
        } else if rest.starts_with(b"<!") {
            at = find_seq(bytes, at, b">")
                .map(|end| end + 1)
                .unwrap_or(bytes.len());
        } else if rest.starts_with(b"</") {
            let end = find_seq(bytes, at, b">")
                .unwrap_or(bytes.len())
                .max(at + 2)
                .min(bytes.len());
            let name = String::from_utf8_lossy(&bytes[at + 2..end])
                .trim()
                .to_string();
            tokens.push(Tok::Close(name));
            at = end + 1;
        } else {
            at += 1;
            let start = at;
            while at < bytes.len()
                && !bytes[at].is_ascii_whitespace()
                && bytes[at] != b'/'
                && bytes[at] != b'>'
            {
                at += 1;
            }
            let name = String::from_utf8_lossy(&bytes[start..at]).into_owned();
            let mut attrs = BTreeMap::new();
            let mut selfclose = false;
            loop {
                while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                    at += 1;
                }
                match bytes.get(at) {
                    None => break,
                    Some(b'>') => {
                        at += 1;
                        break;
                    }
                    Some(b'/') => {
                        selfclose = true;
                        at += 1;
                    }
                    Some(_) => {
                        let key_start = at;
                        while at < bytes.len()
                            && !bytes[at].is_ascii_whitespace()
                            && !matches!(bytes[at], b'=' | b'>' | b'/')
                        {
                            at += 1;
                        }
                        let key = String::from_utf8_lossy(&bytes[key_start..at]).into_owned();
                        while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                            at += 1;
                        }
                        if bytes.get(at) == Some(&b'=') {
                            at += 1;
                            while at < bytes.len() && bytes[at].is_ascii_whitespace() {
                                at += 1;
                            }
                            if let Some(&quote) =
                                bytes.get(at).filter(|q| **q == b'"' || **q == b'\'')
                            {
                                at += 1;
                                let value_start = at;
                                while at < bytes.len() && bytes[at] != quote {
                                    at += 1;
                                }
                                let value = String::from_utf8_lossy(&bytes[value_start..at]);
                                attrs.insert(key, xml_unescape(&value));
                                at += 1;
                            }
                        } else if key.is_empty() {
                            at += 1;
                        }
                    }
                }
            }
            tokens.push(Tok::Open {
                name,
                attrs,
                selfclose,
            });
        }
    }
    tokens
}

fn find_seq(bytes: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || from >= bytes.len() {
        return None;
    }
    bytes[from..]
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| from + offset)
}

fn text_and_close(tokens: &[Tok], at: &mut usize) -> String {
    let mut text = String::new();
    if let Some(Tok::Text(value)) = tokens.get(*at) {
        text = value.clone();
        *at += 1;
    }
    if matches!(tokens.get(*at), Some(Tok::Close(_))) {
        *at += 1;
    }
    text
}

fn plist_value(tokens: &[Tok], at: &mut usize, depth: usize) -> Option<Value> {
    if depth > MAX_PARSE_DEPTH {
        return None;
    }
    let (name, selfclose) = match tokens.get(*at)? {
        Tok::Open {
            name, selfclose, ..
        } => (name.clone(), *selfclose),
        _ => return None,
    };
    *at += 1;
    match name.as_str() {
        "true" => {
            if !selfclose {
                text_and_close(tokens, at);
            }
            Some(Value::Bool(true))
        }
        "false" => {
            if !selfclose {
                text_and_close(tokens, at);
            }
            Some(Value::Bool(false))
        }
        "dict" => {
            let mut map = Map::new();
            if selfclose {
                return Some(Value::Object(map));
            }
            loop {
                match tokens.get(*at)? {
                    Tok::Close(_) => {
                        *at += 1;
                        return Some(Value::Object(map));
                    }
                    Tok::Open { name, .. } if name == "key" => {
                        *at += 1;
                        let key = text_and_close(tokens, at);
                        let value = plist_value(tokens, at, depth + 1)?;
                        map.insert(key, value);
                    }
                    _ => return None,
                }
            }
        }
        "array" => {
            let mut items = Vec::new();
            if selfclose {
                return Some(Value::Array(items));
            }
            loop {
                if matches!(tokens.get(*at)?, Tok::Close(_)) {
                    *at += 1;
                    return Some(Value::Array(items));
                }
                items.push(plist_value(tokens, at, depth + 1)?);
            }
        }
        "integer" => {
            let text = if selfclose {
                String::new()
            } else {
                text_and_close(tokens, at)
            };
            Some(
                text.parse::<i64>()
                    .map(Value::from)
                    .unwrap_or(Value::String(text)),
            )
        }
        "string" | "real" | "date" | "data" => Some(Value::String(if selfclose {
            String::new()
        } else {
            text_and_close(tokens, at)
        })),
        _ => None,
    }
}

/// XML property list (Info.plist, entitlements, PrivacyInfo.xcprivacy) to JSON.
pub fn parse_xml_plist(bytes: &[u8]) -> Result<Value, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "plist is not UTF-8".to_string())?;
    let tokens = xml_tokens(text);
    let mut at = tokens
        .iter()
        .position(|token| matches!(token, Tok::Open { name, .. } if name == "plist"))
        .ok_or("no <plist> element (binary plists are not interpreted)")?
        + 1;
    plist_value(&tokens, &mut at, 0).ok_or_else(|| "malformed XML plist".to_string())
}

// ---------------------------------------------------------------------------
// Inventory model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetInfo {
    pub name: String,
    pub product_type: String,
    pub is_app: bool,
    pub is_test: bool,
    /// Configuration name -> effective whitelisted build settings (target
    /// settings over project settings). Conditional `[sdk=...]` keys are not
    /// evaluated and are listed in `conditional_settings`.
    pub settings: BTreeMap<String, BTreeMap<String, String>>,
    pub conditional_settings: Vec<String>,
    /// Repository-relative source files from the explicit Sources phase.
    pub source_files: Vec<String>,
    pub generated_sources: Vec<String>,
    /// Xcode 16 synchronized folders: membership is directory-derived and not
    /// exactly enumerable here, so membership claims stay inexact.
    pub synchronized_roots: Vec<String>,
    pub membership_exact: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectInfo {
    /// Repository-relative `X.xcodeproj` path.
    pub path: String,
    pub digest: String,
    pub configurations: Vec<String>,
    pub targets: Vec<TargetInfo>,
    pub package_reference_count: usize,
    /// `.swift` files under the project directory in no explicit Sources
    /// phase and no synchronized root (candidates, not defects).
    pub unreferenced_swift_sources: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceInfo {
    pub path: String,
    pub digest: String,
    /// Repository-relative project paths referenced by the workspace.
    pub projects: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildableRef {
    pub blueprint_name: String,
    pub buildable_name: String,
    pub container: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchemeInfo {
    pub path: String,
    pub name: String,
    pub digest: String,
    pub shared: bool,
    pub build_targets: Vec<BuildableRef>,
    pub testables: Vec<BuildableRef>,
    pub skipped_testables: Vec<String>,
    pub test_configuration: Option<String>,
    pub launch_configuration: Option<String>,
    /// `(reference-as-written, is-default)`.
    pub test_plans: Vec<(String, bool)>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestPlanInfo {
    pub path: String,
    pub name: String,
    pub digest: String,
    pub test_targets: Vec<String>,
    pub configurations: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackagePin {
    pub identity: String,
    pub location: String,
    pub revision: Option<String>,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageResolvedInfo {
    pub path: String,
    pub digest: String,
    pub pins: Vec<PackagePin>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XcodeInventory {
    pub schema_version: u32,
    pub workspaces: Vec<WorkspaceInfo>,
    pub projects: Vec<ProjectInfo>,
    pub schemes: Vec<SchemeInfo>,
    pub test_plans: Vec<TestPlanInfo>,
    pub package_resolved: Vec<PackageResolvedInfo>,
    /// Parse/inventory problems. Never silently dropped.
    pub issues: Vec<Gap>,
}

// ---------------------------------------------------------------------------
// pbxproj interpretation
// ---------------------------------------------------------------------------

const WHITELIST: &[&str] = &[
    "SDKROOT",
    "SUPPORTED_PLATFORMS",
    "IPHONEOS_DEPLOYMENT_TARGET",
    "MACOSX_DEPLOYMENT_TARGET",
    "SWIFT_VERSION",
    "SWIFT_STRICT_CONCURRENCY",
    "SWIFT_DEFAULT_ACTOR_ISOLATION",
    "OTHER_SWIFT_FLAGS",
    "CODE_SIGN_ENTITLEMENTS",
    "INFOPLIST_FILE",
    "GENERATE_INFOPLIST_FILE",
    "PRODUCT_BUNDLE_IDENTIFIER",
    "TARGETED_DEVICE_FAMILY",
];

fn str_of<'a>(object: &'a Value, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn strings_of(object: &Value, key: &str) -> Vec<String> {
    object
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn settings_of(
    objects: &Map<String, Value>,
    list_id: Option<&str>,
    conditional: &mut BTreeSet<String>,
) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    let Some(list) = list_id.and_then(|id| objects.get(id)) else {
        return out;
    };
    for config_id in strings_of(list, "buildConfigurations") {
        let Some(config) = objects.get(&config_id) else {
            continue;
        };
        let name = str_of(config, "name").unwrap_or_default().to_string();
        let mut settings = BTreeMap::new();
        if let Some(map) = config.get("buildSettings").and_then(Value::as_object) {
            for (key, value) in map {
                if key.contains('[') {
                    conditional.insert(format!("{name}:{key}"));
                    continue;
                }
                if !WHITELIST.contains(&key.as_str()) {
                    continue;
                }
                let text = match value {
                    Value::String(text) => text.clone(),
                    Value::Array(items) => items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(" "),
                    _ => continue,
                };
                settings.insert(key.clone(), text);
            }
        }
        out.insert(name, settings);
    }
    out
}

fn walk_groups(
    id: &str,
    prefix: &str,
    objects: &Map<String, Value>,
    out: &mut BTreeMap<String, String>,
    depth: usize,
) {
    if depth > MAX_PARSE_DEPTH {
        return;
    }
    let Some(object) = objects.get(id) else {
        return;
    };
    let tree = str_of(object, "sourceTree").unwrap_or("<group>");
    let here = match (str_of(object, "path"), tree) {
        (Some(path), "<group>") => {
            if prefix.is_empty() {
                path.to_string()
            } else {
                format!("{prefix}/{path}")
            }
        }
        (Some(path), "SOURCE_ROOT") => path.to_string(),
        (Some(path), other) => format!("unresolved:{other}/{path}"),
        (None, _) => prefix.to_string(),
    };
    out.insert(id.to_string(), here.clone());
    for child in strings_of(object, "children") {
        walk_groups(&child, &here, objects, out, depth + 1);
    }
}

fn looks_generated(path: &str) -> bool {
    path.starts_with("unresolved:")
        || path.contains("/Generated/")
        || path.contains("/DerivedData/")
        || path.contains("/.build/")
        || path.ends_with(".generated.swift")
}

fn parse_project(
    path: &str,
    bytes: &[u8],
    files: &SnapshotFiles,
    issues: &mut Vec<Gap>,
) -> Option<ProjectInfo> {
    let container = parent_dir(path);
    let project_dir = parent_dir(&container);
    let root = match parse_openstep_plist(bytes) {
        Ok(value) => value,
        Err(error) => {
            issues.push(gap("pbxproj-unparseable", format!("{path}: {error}")));
            return None;
        }
    };
    let Some(objects) = root.get("objects").and_then(Value::as_object) else {
        issues.push(gap(
            "pbxproj-unparseable",
            format!("{path}: no objects table"),
        ));
        return None;
    };
    let Some(project) = objects
        .values()
        .find(|object| str_of(object, "isa") == Some("PBXProject"))
    else {
        issues.push(gap("pbxproj-unparseable", format!("{path}: no PBXProject")));
        return None;
    };

    let mut paths: BTreeMap<String, String> = BTreeMap::new();
    if let Some(main) = str_of(project, "mainGroup") {
        walk_groups(main, "", objects, &mut paths, 0);
    }
    let mut conditional = BTreeSet::new();
    let project_settings = settings_of(
        objects,
        str_of(project, "buildConfigurationList"),
        &mut conditional,
    );
    let configurations: Vec<String> = project_settings.keys().cloned().collect();

    let package_reference_count = objects
        .values()
        .filter(|object| {
            matches!(
                str_of(object, "isa"),
                Some("XCRemoteSwiftPackageReference" | "XCLocalSwiftPackageReference")
            )
        })
        .count();

    let mut targets = Vec::new();
    for target_id in strings_of(project, "targets") {
        let Some(target) = objects.get(&target_id) else {
            continue;
        };
        if str_of(target, "isa") != Some("PBXNativeTarget") {
            continue;
        }
        let product_type = str_of(target, "productType")
            .unwrap_or_default()
            .to_string();
        let mut target_conditional = BTreeSet::new();
        let own = settings_of(
            objects,
            str_of(target, "buildConfigurationList"),
            &mut target_conditional,
        );
        let mut effective: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        for config in &configurations {
            let mut merged = project_settings.get(config).cloned().unwrap_or_default();
            if let Some(overrides) = own.get(config) {
                merged.extend(overrides.clone());
            }
            effective.insert(config.clone(), merged);
        }
        let mut source_files = Vec::new();
        for phase_id in strings_of(target, "buildPhases") {
            let Some(phase) = objects.get(&phase_id) else {
                continue;
            };
            if str_of(phase, "isa") != Some("PBXSourcesBuildPhase") {
                continue;
            }
            for build_file in strings_of(phase, "files") {
                let file_ref = objects
                    .get(&build_file)
                    .and_then(|object| str_of(object, "fileRef"));
                if let Some(relative) = file_ref.and_then(|id| paths.get(id)) {
                    source_files.push(if relative.starts_with("unresolved:") {
                        relative.clone()
                    } else {
                        norm_join(&project_dir, relative)
                            .unwrap_or_else(|| format!("unresolved:{relative}"))
                    });
                }
            }
        }
        source_files.sort();
        source_files.dedup();
        let generated_sources = source_files
            .iter()
            .filter(|p| looks_generated(p))
            .cloned()
            .collect();
        let synchronized_roots: Vec<String> = strings_of(target, "fileSystemSynchronizedGroups")
            .iter()
            .filter_map(|id| paths.get(id))
            .filter_map(|relative| norm_join(&project_dir, relative))
            .collect();
        let mut all_conditional: BTreeSet<String> = conditional.clone();
        all_conditional.extend(target_conditional);
        targets.push(TargetInfo {
            name: str_of(target, "name").unwrap_or_default().to_string(),
            is_app: product_type == "com.apple.product-type.application",
            is_test: product_type.contains("bundle.unit-test")
                || product_type.contains("bundle.ui-testing"),
            product_type,
            settings: effective,
            conditional_settings: all_conditional.into_iter().collect(),
            source_files,
            generated_sources,
            membership_exact: synchronized_roots.is_empty(),
            synchronized_roots,
        });
    }

    let mut members: BTreeSet<&str> = BTreeSet::new();
    for target in &targets {
        members.extend(target.source_files.iter().map(String::as_str));
    }
    let roots: Vec<&str> = targets
        .iter()
        .flat_map(|target| target.synchronized_roots.iter().map(String::as_str))
        .collect();
    let prefix = format!("{project_dir}/");
    let unreferenced_swift_sources = files
        .keys()
        .filter(|candidate| {
            candidate.ends_with(".swift")
                && (project_dir.is_empty() || candidate.starts_with(&prefix))
                && !members.contains(candidate.as_str())
                && !roots
                    .iter()
                    .any(|root| candidate.starts_with(&format!("{root}/")))
        })
        .cloned()
        .collect();

    Some(ProjectInfo {
        path: container,
        digest: sha256_bytes(bytes),
        configurations,
        targets,
        package_reference_count,
        unreferenced_swift_sources,
    })
}

// ---------------------------------------------------------------------------
// Scheme / workspace / test plan / Package.resolved
// ---------------------------------------------------------------------------

fn parse_scheme(path: &str, bytes: &[u8]) -> Option<SchemeInfo> {
    let text = std::str::from_utf8(bytes).ok()?;
    let tokens = xml_tokens(text);
    let mut scheme = SchemeInfo {
        path: path.to_string(),
        name: base_name(path).trim_end_matches(".xcscheme").to_string(),
        digest: sha256_bytes(bytes),
        shared: path.contains("/xcshareddata/xcschemes/"),
        ..SchemeInfo::default()
    };
    let mut section = String::new();
    let mut skipped_testable = false;
    let mut saw_scheme = false;
    for token in &tokens {
        match token {
            Tok::Open { name, attrs, .. } => match name.as_str() {
                "Scheme" => saw_scheme = true,
                "BuildAction" | "TestAction" | "LaunchAction" | "ProfileAction"
                | "AnalyzeAction" | "ArchiveAction" => {
                    section = name.clone();
                    let configuration = attrs.get("buildConfiguration").cloned();
                    if name == "TestAction" {
                        scheme.test_configuration = configuration;
                    } else if name == "LaunchAction" {
                        scheme.launch_configuration = configuration;
                    }
                }
                "TestableReference" => {
                    skipped_testable = attrs
                        .get("skipped")
                        .is_some_and(|v| v.eq_ignore_ascii_case("YES"));
                }
                "TestPlanReference" if section == "TestAction" => {
                    if let Some(reference) = attrs.get("reference") {
                        let default = attrs
                            .get("default")
                            .is_some_and(|v| v.eq_ignore_ascii_case("YES"));
                        scheme.test_plans.push((reference.clone(), default));
                    }
                }
                "BuildableReference" => {
                    let buildable = BuildableRef {
                        blueprint_name: attrs.get("BlueprintName").cloned().unwrap_or_default(),
                        buildable_name: attrs.get("BuildableName").cloned().unwrap_or_default(),
                        container: attrs
                            .get("ReferencedContainer")
                            .map(|c| c.trim_start_matches("container:").to_string())
                            .unwrap_or_default(),
                    };
                    match section.as_str() {
                        "BuildAction" => scheme.build_targets.push(buildable),
                        "TestAction" => {
                            if skipped_testable {
                                scheme
                                    .skipped_testables
                                    .push(buildable.blueprint_name.clone());
                            } else {
                                scheme.testables.push(buildable);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            Tok::Close(name) => {
                if *name == section {
                    section.clear();
                }
                if name == "TestableReference" {
                    skipped_testable = false;
                }
            }
            Tok::Text(_) => {}
        }
    }
    saw_scheme.then_some(scheme)
}

fn parse_workspace(path: &str, bytes: &[u8], issues: &mut Vec<Gap>) -> Option<WorkspaceInfo> {
    let text = std::str::from_utf8(bytes).ok()?;
    let workspace = parent_dir(path);
    let base = parent_dir(&workspace);
    let mut projects = Vec::new();
    for token in xml_tokens(text) {
        if let Tok::Open { name, attrs, .. } = token {
            if name != "FileRef" {
                continue;
            }
            let Some(location) = attrs.get("location") else {
                continue;
            };
            let Some((kind, rel)) = location.split_once(':') else {
                continue;
            };
            if !rel.ends_with(".xcodeproj") {
                continue;
            }
            let resolved = match kind {
                "group" | "container" => norm_join(&base, rel),
                "self" => norm_join(&workspace, rel),
                _ => None,
            };
            match resolved {
                Some(project) => projects.push(project),
                None => issues.push(gap(
                    "workspace-project-unresolved",
                    format!("{path}: cannot resolve {location} inside the frozen snapshot"),
                )),
            }
        }
    }
    projects.sort();
    projects.dedup();
    Some(WorkspaceInfo {
        path: workspace,
        digest: sha256_bytes(bytes),
        projects,
    })
}

fn parse_test_plan(path: &str, bytes: &[u8]) -> Option<TestPlanInfo> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let test_targets = value
        .get("testTargets")
        .and_then(Value::as_array)?
        .iter()
        .filter(|entry| entry.get("skipped").and_then(Value::as_bool) != Some(true))
        .filter_map(|entry| {
            entry
                .get("target")?
                .get("name")?
                .as_str()
                .map(str::to_string)
        })
        .collect();
    let configurations = value
        .get("configurations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("name").and_then(Value::as_str).map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Some(TestPlanInfo {
        path: path.to_string(),
        name: base_name(path).trim_end_matches(".xctestplan").to_string(),
        digest: sha256_bytes(bytes),
        test_targets,
        configurations,
    })
}

fn parse_package_resolved(path: &str, bytes: &[u8]) -> Option<PackageResolvedInfo> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let version = value.get("version").and_then(Value::as_u64).unwrap_or(1);
    let raw: Vec<Value> = if version >= 2 {
        value.get("pins")?.as_array()?.clone()
    } else {
        value.get("object")?.get("pins")?.as_array()?.clone()
    };
    let mut pins = Vec::new();
    for pin in raw {
        let state = pin.get("state").cloned().unwrap_or(Value::Null);
        let package = pin
            .get("package")
            .and_then(Value::as_str)
            .map(str::to_string);
        let identity = str_of(&pin, "identity")
            .map(str::to_string)
            .or(package)
            .unwrap_or_default();
        let location = str_of(&pin, "location")
            .or_else(|| str_of(&pin, "repositoryURL"))
            .unwrap_or_default()
            .to_string();
        pins.push(PackagePin {
            identity,
            location,
            revision: str_of(&state, "revision").map(str::to_string),
            version: str_of(&state, "version").map(str::to_string),
        });
    }
    pins.sort();
    Some(PackageResolvedInfo {
        path: path.to_string(),
        digest: sha256_bytes(bytes),
        pins,
    })
}

impl PartialOrd for PackagePin {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PackagePin {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (
            &self.identity,
            &self.location,
            &self.revision,
            &self.version,
        )
            .cmp(&(
                &other.identity,
                &other.location,
                &other.revision,
                &other.version,
            ))
    }
}

/// Inventory every Xcode input present in the frozen snapshot.
pub fn inventory_xcode(files: &SnapshotFiles) -> XcodeInventory {
    let mut inventory = XcodeInventory {
        schema_version: SCHEMA_VERSION,
        ..XcodeInventory::default()
    };
    for (path, bytes) in files {
        if path.ends_with(".xcodeproj/project.pbxproj") {
            if let Some(project) = parse_project(path, bytes, files, &mut inventory.issues) {
                inventory.projects.push(project);
            }
        } else if path.ends_with(".xcworkspace/contents.xcworkspacedata") {
            if let Some(workspace) = parse_workspace(path, bytes, &mut inventory.issues) {
                inventory.workspaces.push(workspace);
            }
        } else if path.ends_with(".xcscheme") {
            match parse_scheme(path, bytes) {
                Some(scheme) => inventory.schemes.push(scheme),
                None => inventory
                    .issues
                    .push(gap("scheme-unparseable", path.clone())),
            }
        } else if path.ends_with(".xctestplan") {
            match parse_test_plan(path, bytes) {
                Some(plan) => inventory.test_plans.push(plan),
                None => inventory
                    .issues
                    .push(gap("test-plan-unparseable", path.clone())),
            }
        } else if base_name(path) == "Package.resolved" {
            match parse_package_resolved(path, bytes) {
                Some(resolved) => inventory.package_resolved.push(resolved),
                None => inventory
                    .issues
                    .push(gap("package-resolved-unparseable", path.clone())),
            }
        }
    }
    inventory
}

// ---------------------------------------------------------------------------
// Obligations
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestinationSpec {
    /// `iOS Simulator`, `macOS`, ... as Xcode names the destination platform.
    pub platform: String,
    pub sdk: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
}

impl DestinationSpec {
    /// Platform/SDK pairs this provider can interpret and import evidence for.
    /// Everything else (device, tvOS, watchOS, visionOS, Catalyst) is an
    /// explicit unsupported gap; device execution is host-qualified separately.
    pub fn supported(&self) -> bool {
        matches!(
            (self.platform.as_str(), self.sdk.as_str()),
            ("iOS Simulator", "iphonesimulator") | ("macOS", "macosx")
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct XcodeObligation {
    pub id: String,
    /// Repository-relative `.xcworkspace` or `.xcodeproj`.
    pub container: String,
    pub scheme: String,
    pub configuration: String,
    pub destination: DestinationSpec,
    /// Test plan name (without extension). `None` requires the scheme to use
    /// no test plans.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_plan: Option<String>,
    /// Required `SWIFT_STRICT_CONCURRENCY` effective mode (`complete`...).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_concurrency: Option<String>,
    #[serde(default)]
    pub require_entitlements: bool,
    #[serde(default)]
    pub require_privacy_manifest: bool,
}

impl XcodeObligation {
    pub fn evidence_target(&self) -> String {
        format!("xcode:{}#{}", self.container, self.scheme)
    }

    pub fn evidence_variant(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.configuration,
            self.destination.platform,
            self.destination.sdk,
            self.destination.name.as_deref().unwrap_or("-"),
            self.destination.os.as_deref().unwrap_or("-"),
            self.test_plan.as_deref().unwrap_or("-"),
        )
    }
}

fn version_tuple(text: &str) -> Vec<u64> {
    text.split('.')
        .map(|part| part.parse().unwrap_or(0))
        .collect()
}

fn version_gt(left: &str, right: &str) -> bool {
    let (mut l, mut r) = (version_tuple(left), version_tuple(right));
    let len = l.len().max(r.len());
    l.resize(len, 0);
    r.resize(len, 0);
    l > r
}

/// Effective compiler concurrency mode for one configuration's settings.
pub fn effective_concurrency(settings: &BTreeMap<String, String>) -> String {
    if let Some(mode) = settings.get("SWIFT_STRICT_CONCURRENCY") {
        return mode.clone();
    }
    if let Some(flags) = settings.get("OTHER_SWIFT_FLAGS") {
        if let Some(mode) = flags
            .split_whitespace()
            .find_map(|flag| flag.strip_prefix("-strict-concurrency="))
        {
            return mode.to_string();
        }
    }
    if settings
        .get("SWIFT_VERSION")
        .is_some_and(|version| version_tuple(version).first().copied().unwrap_or(0) >= 6)
    {
        return "complete".into();
    }
    "minimal".into()
}

fn platform_sdks(settings: &BTreeMap<String, String>) -> BTreeSet<String> {
    let mut sdks = BTreeSet::new();
    if let Some(list) = settings.get("SUPPORTED_PLATFORMS") {
        sdks.extend(list.split_whitespace().map(str::to_string));
    }
    match settings.get("SDKROOT").map(String::as_str) {
        Some("auto") | None => {}
        Some(single) => {
            sdks.insert(single.to_string());
            if single == "iphoneos" {
                sdks.insert("iphonesimulator".into());
            }
        }
    }
    sdks
}

/// Static input coverage for one obligation. `gaps` empty means the declared
/// inputs bind exactly; it never means the scheme was built or tested.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaticCoverage {
    pub gaps: Vec<Gap>,
    pub bound_inputs: BTreeMap<String, String>,
    pub scheme_path: Option<String>,
    pub targets: Vec<String>,
    pub effective_concurrency: BTreeMap<String, String>,
    pub config_digest: Option<String>,
    pub test_selection_digest: Option<String>,
    pub dependency_graph_digest: Option<String>,
}

fn container_projects<'a>(inventory: &'a XcodeInventory, container: &str) -> Vec<&'a ProjectInfo> {
    if container.ends_with(".xcworkspace") {
        inventory
            .workspaces
            .iter()
            .find(|workspace| workspace.path == container)
            .map(|workspace| {
                inventory
                    .projects
                    .iter()
                    .filter(|project| workspace.projects.contains(&project.path))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        inventory
            .projects
            .iter()
            .filter(|project| project.path == container)
            .collect()
    }
}

fn scheme_candidates<'a>(
    inventory: &'a XcodeInventory,
    container: &str,
    projects: &[&ProjectInfo],
    scheme: &str,
) -> Vec<&'a SchemeInfo> {
    let mut dirs: Vec<String> = vec![container.to_string()];
    dirs.extend(projects.iter().map(|project| project.path.clone()));
    inventory
        .schemes
        .iter()
        .filter(|candidate| {
            candidate.name == scheme
                && dirs
                    .iter()
                    .any(|dir| candidate.path.starts_with(&format!("{dir}/")))
        })
        .collect()
}

fn bind_plist(
    files: &SnapshotFiles,
    path: &str,
    label: &str,
    gaps: &mut Vec<Gap>,
    bound: &mut BTreeMap<String, String>,
    missing_code: &str,
) -> Option<Value> {
    let Some(bytes) = files.get(path) else {
        gaps.push(gap(
            missing_code,
            format!("{label} `{path}` is not in the frozen snapshot"),
        ));
        return None;
    };
    bound.insert(path.to_string(), sha256_bytes(bytes));
    match parse_xml_plist(bytes) {
        Ok(value) => Some(value),
        Err(error) => {
            gaps.push(gap(
                &format!("{label}-unparseable")
                    .to_lowercase()
                    .replace(' ', "-"),
                format!("{path}: {error}"),
            ));
            None
        }
    }
}

/// Evaluate every statically checkable input of one obligation.
pub fn evaluate_static(
    inventory: &XcodeInventory,
    files: &SnapshotFiles,
    obligation: &XcodeObligation,
) -> StaticCoverage {
    let mut out = StaticCoverage::default();
    let gaps = &mut out.gaps;
    gaps.extend(inventory.issues.iter().cloned());

    if !obligation.destination.supported() {
        gaps.push(gap(
            "unsupported-destination",
            format!(
                "destination `{}`/`{}` is not interpretable by {PROVIDER_ID}; device, tvOS, watchOS, visionOS and Catalyst remain host-qualified and unmet",
                obligation.destination.platform, obligation.destination.sdk
            ),
        ));
    }

    let projects = container_projects(inventory, &obligation.container);
    if projects.is_empty() {
        gaps.push(gap(
            "container-missing",
            format!(
                "`{}` has no parsed project in the frozen snapshot",
                obligation.container
            ),
        ));
        return out;
    }

    let schemes = scheme_candidates(
        inventory,
        &obligation.container,
        &projects,
        &obligation.scheme,
    );
    let shared: Vec<&&SchemeInfo> = schemes.iter().filter(|scheme| scheme.shared).collect();
    let scheme = match shared.as_slice() {
        [one] => Some(**one),
        [] if schemes.is_empty() => {
            gaps.push(gap(
                "scheme-missing",
                format!("scheme `{}` not found", obligation.scheme),
            ));
            None
        }
        [] => {
            gaps.push(gap(
                "scheme-not-shared",
                format!(
                    "scheme `{}` exists only as a user scheme",
                    obligation.scheme
                ),
            ));
            None
        }
        _ => {
            gaps.push(gap(
                "scheme-ambiguous",
                format!("scheme `{}` is defined more than once", obligation.scheme),
            ));
            None
        }
    };

    for project in &projects {
        if !project.configurations.contains(&obligation.configuration) {
            gaps.push(gap(
                "configuration-missing",
                format!(
                    "`{}` has no configuration `{}`",
                    project.path, obligation.configuration
                ),
            ));
        }
        out.bound_inputs.insert(
            project.path.clone() + "/project.pbxproj",
            project.digest.clone(),
        );
    }

    let Some(scheme) = scheme else {
        return out;
    };
    out.scheme_path = Some(scheme.path.clone());
    out.bound_inputs
        .insert(scheme.path.clone(), scheme.digest.clone());

    if scheme.test_configuration.as_deref() != Some(obligation.configuration.as_str()) {
        gaps.push(gap(
            "scheme-configuration-mismatch",
            format!(
                "scheme test action uses `{}`, obligation requires `{}`",
                scheme.test_configuration.as_deref().unwrap_or("<none>"),
                obligation.configuration
            ),
        ));
    }

    // Test plan selection must match the planned obligation exactly.
    let mut selection: Vec<String> = Vec::new();
    match (&obligation.test_plan, scheme.test_plans.is_empty()) {
        (Some(wanted), _) => {
            let referenced = scheme.test_plans.iter().any(|(reference, _)| {
                base_name(reference.trim_start_matches("container:"))
                    .trim_end_matches(".xctestplan")
                    == wanted
            });
            if !referenced {
                gaps.push(gap(
                    "test-plan-not-in-scheme",
                    format!(
                        "scheme `{}` does not reference test plan `{wanted}`",
                        scheme.name
                    ),
                ));
            }
            let container_dir = parent_dir(&obligation.container);
            let plan = inventory.test_plans.iter().find(|plan| {
                plan.name == *wanted
                    && (container_dir.is_empty()
                        || plan.path.starts_with(&format!("{container_dir}/")))
            });
            match plan {
                None => gaps.push(gap(
                    "test-plan-missing",
                    format!("test plan `{wanted}` not in snapshot"),
                )),
                Some(plan) => {
                    out.bound_inputs
                        .insert(plan.path.clone(), plan.digest.clone());
                    if plan.test_targets.is_empty() {
                        gaps.push(gap(
                            "test-plan-empty",
                            format!("test plan `{wanted}` selects no test target"),
                        ));
                    }
                    selection.extend(plan.test_targets.iter().map(|name| format!("plan:{name}")));
                }
            }
        }
        (None, false) => gaps.push(gap(
            "test-plan-unspecified",
            format!(
                "scheme `{}` uses test plans but the obligation names none",
                scheme.name
            ),
        )),
        (None, true) => {
            selection.extend(
                scheme
                    .testables
                    .iter()
                    .map(|t| format!("testable:{}", t.blueprint_name)),
            );
        }
    }
    if selection.is_empty() && !gaps.iter().any(|g| g.code == "test-plan-empty") {
        gaps.push(gap(
            "no-test-targets",
            "no executable test target is selected by the scheme/plan",
        ));
    }
    selection.sort();

    // Resolve targets and check SDK, deployment target, concurrency and inputs.
    let mut names: BTreeSet<String> = scheme
        .build_targets
        .iter()
        .chain(scheme.testables.iter())
        .map(|buildable| buildable.blueprint_name.clone())
        .collect();
    for item in &selection {
        if let Some(name) = item.strip_prefix("plan:") {
            names.insert(name.to_string());
        }
    }
    let mut config_inputs = Map::new();
    for name in &names {
        let target = projects
            .iter()
            .flat_map(|project| project.targets.iter().map(move |target| (*project, target)))
            .find(|(_, target)| target.name == *name);
        let Some((project, target)) = target else {
            gaps.push(gap(
                "target-missing",
                format!("scheme target `{name}` not found in container"),
            ));
            continue;
        };
        out.targets.push(name.clone());
        let settings = target
            .settings
            .get(&obligation.configuration)
            .cloned()
            .unwrap_or_default();
        let sdks = platform_sdks(&settings);
        if !sdks.contains(&obligation.destination.sdk) {
            gaps.push(gap(
                "target-sdk-mismatch",
                format!(
                    "target `{name}` supports [{}], destination requires `{}`",
                    sdks.iter().cloned().collect::<Vec<_>>().join(", "),
                    obligation.destination.sdk
                ),
            ));
        }
        let deployment_key = if obligation.destination.sdk.starts_with("iphone") {
            "IPHONEOS_DEPLOYMENT_TARGET"
        } else {
            "MACOSX_DEPLOYMENT_TARGET"
        };
        match settings.get(deployment_key) {
            None => gaps.push(gap(
                "deployment-target-missing",
                format!("target `{name}` has no effective {deployment_key}"),
            )),
            Some(deployment) => {
                if let Some(os) = &obligation.destination.os {
                    if version_gt(deployment, os) {
                        gaps.push(gap(
                            "deployment-target-above-destination",
                            format!(
                                "target `{name}` requires {deployment}; destination OS is {os}"
                            ),
                        ));
                    }
                }
            }
        }
        let mode = effective_concurrency(&settings);
        if let Some(required) = &obligation.required_concurrency {
            if &mode != required || mode.contains("$(") {
                gaps.push(gap(
                    "concurrency-mode-mismatch",
                    format!(
                        "target `{name}` effective concurrency `{mode}`, required `{required}`"
                    ),
                ));
            }
        }
        out.effective_concurrency.insert(name.clone(), mode.clone());
        if !target.membership_exact {
            gaps.push(gap(
                "source-membership-inexact",
                format!("target `{name}` uses synchronized folders; per-file membership is not enumerated"),
            ));
        }
        if !target.conditional_settings.is_empty() {
            gaps.push(gap(
                "conditional-build-settings-unevaluated",
                format!(
                    "target `{name}`: {}",
                    target.conditional_settings.join(", ")
                ),
            ));
        }
        if !target.generated_sources.is_empty() {
            gaps.push(gap(
                "generated-sources-unbound",
                format!(
                    "target `{name}` compiles generated inputs: {}",
                    target.generated_sources.join(", ")
                ),
            ));
        }
        let project_dir = parent_dir(&project.path);
        let mut input_digests = BTreeMap::new();
        for source in &target.source_files {
            match files.get(source) {
                Some(bytes) => {
                    input_digests.insert(source.clone(), sha256_bytes(bytes));
                }
                None => gaps.push(gap(
                    "source-input-missing",
                    format!("target `{name}` source `{source}` is not in the frozen snapshot"),
                )),
            }
        }
        if target.is_app {
            let generated = settings
                .get("GENERATE_INFOPLIST_FILE")
                .is_some_and(|v| v == "YES");
            match (settings.get("INFOPLIST_FILE"), generated) {
                (Some(rel), _) => {
                    let path = norm_join(&project_dir, rel).unwrap_or_else(|| rel.clone());
                    if let Some(info) = bind_plist(files, &path, "Info.plist", gaps, &mut out.bound_inputs, "info-plist-missing") {
                        input_digests.insert(path.clone(), out.bound_inputs[&path].clone());
                        if info.get("CFBundleIdentifier").is_none() && !settings.contains_key("PRODUCT_BUNDLE_IDENTIFIER") {
                            gaps.push(gap("bundle-identifier-missing", format!("target `{name}`")));
                        }
                    }
                }
                (None, true) => {}
                (None, false) => gaps.push(gap(
                    "info-plist-missing",
                    format!("target `{name}` neither sets INFOPLIST_FILE nor GENERATE_INFOPLIST_FILE=YES"),
                )),
            }
            if obligation.require_entitlements {
                match settings.get("CODE_SIGN_ENTITLEMENTS") {
                    None => gaps.push(gap(
                        "entitlements-input-missing",
                        format!("target `{name}` declares no CODE_SIGN_ENTITLEMENTS"),
                    )),
                    Some(rel) => {
                        let path = norm_join(&project_dir, rel).unwrap_or_else(|| rel.clone());
                        if bind_plist(
                            files,
                            &path,
                            "entitlements",
                            gaps,
                            &mut out.bound_inputs,
                            "entitlements-input-missing",
                        )
                        .is_some()
                        {
                            input_digests.insert(path.clone(), out.bound_inputs[&path].clone());
                        }
                    }
                }
            }
            if obligation.require_privacy_manifest {
                let prefix = format!("{project_dir}/");
                let manifest = files.keys().find(|path| {
                    base_name(path) == "PrivacyInfo.xcprivacy"
                        && (project_dir.is_empty() || path.starts_with(&prefix))
                });
                match manifest {
                    None => gaps.push(gap(
                        "privacy-manifest-missing",
                        format!(
                            "target `{name}` has no PrivacyInfo.xcprivacy under `{project_dir}`"
                        ),
                    )),
                    Some(path) => {
                        let path = path.clone();
                        if bind_plist(
                            files,
                            &path,
                            "privacy manifest",
                            gaps,
                            &mut out.bound_inputs,
                            "privacy-manifest-missing",
                        )
                        .is_some()
                        {
                            input_digests.insert(path.clone(), out.bound_inputs[&path].clone());
                        }
                    }
                }
            }
        }
        for (path, digest) in &input_digests {
            out.bound_inputs.insert(path.clone(), digest.clone());
        }
        config_inputs.insert(
            name.clone(),
            json!({
                "settings": settings,
                "concurrency": mode,
                "inputs": input_digests,
            }),
        );
    }

    // Package graph.
    let package_count: usize = projects
        .iter()
        .map(|project| project.package_reference_count)
        .sum();
    let mut resolved: Vec<&PackageResolvedInfo> = inventory
        .package_resolved
        .iter()
        .filter(|resolved| {
            resolved
                .path
                .starts_with(&format!("{}/", obligation.container))
                || projects
                    .iter()
                    .any(|project| resolved.path.starts_with(&format!("{}/", project.path)))
                || parent_dir(&resolved.path) == parent_dir(&obligation.container)
        })
        .collect();
    resolved.sort_by(|a, b| a.path.cmp(&b.path));
    if package_count > 0 && resolved.is_empty() {
        gaps.push(gap(
            "package-resolved-missing",
            "project declares Swift package references but no Package.resolved is in the snapshot",
        ));
    }
    for item in &resolved {
        out.bound_inputs
            .insert(item.path.clone(), item.digest.clone());
    }
    let pins: Vec<&Vec<PackagePin>> = resolved.iter().map(|item| &item.pins).collect();
    out.dependency_graph_digest =
        crate::integrity::digest(&json!({ "packageResolved": pins })).ok();
    out.test_selection_digest = crate::integrity::digest(&json!({
        "testPlan": obligation.test_plan,
        "selection": selection,
        "configurations": obligation.test_plan.as_ref().and_then(|name| inventory.test_plans.iter().find(|p| &p.name == name)).map(|p| p.configurations.clone()),
    }))
    .ok();
    out.config_digest = crate::integrity::digest(&json!({
        "container": obligation.container,
        "scheme": obligation.scheme,
        "configuration": obligation.configuration,
        "destination": obligation.destination,
        "targets": config_inputs,
        "boundInputs": out.bound_inputs,
    }))
    .ok();
    out.gaps.sort();
    out.gaps.dedup();
    out
}

// ---------------------------------------------------------------------------
// Evidence expectation and linking
// ---------------------------------------------------------------------------

/// Root-supplied frozen-plan facts that A03 expectations need beyond what the
/// Xcode inputs themselves determine.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpectedContext {
    pub kind: ImportKind,
    pub repositories: Vec<RepositoryBinding>,
    /// Exact toolchain label, e.g. `xcode-16.2/iphonesimulator18.2`.
    pub toolchain: String,
    pub command: CommandBinding,
    pub required_scope: Vec<String>,
    pub replay_policy: ReplayPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_runtime: Option<String>,
}

pub const ROLE_XCRESULT: &str = "xcresult";
pub const ROLE_TEST_SUMMARY: &str = "test-summary";

/// Build the exact A03 expectation for an obligation. Refuses (error) rather
/// than guessing when static inputs have gaps that prevent binding.
pub fn expected_evidence(
    obligation: &XcodeObligation,
    coverage: &StaticCoverage,
    context: &ExpectedContext,
) -> Result<ExpectedEvidence, AuditError> {
    if !matches!(context.kind, ImportKind::Build | ImportKind::Test) {
        return Err(AuditError::Invalid(
            "xcode expectation kind must be build or test".into(),
        ));
    }
    if !coverage.gaps.is_empty() {
        return Err(AuditError::Invalid(format!(
            "xcode obligation `{}` has unresolved input gaps: {}",
            obligation.id,
            coverage
                .gaps
                .iter()
                .map(|g| g.code.clone())
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }
    let missing = || AuditError::Invalid("static coverage lacks binding digests".into());
    Ok(ExpectedEvidence {
        kind: context.kind,
        repositories: context.repositories.clone(),
        target: obligation.evidence_target(),
        variant: Some(obligation.evidence_variant()),
        toolchain: context.toolchain.clone(),
        config_digest: coverage.config_digest.clone().ok_or_else(missing)?,
        test_selection_digest: if context.kind == ImportKind::Test {
            Some(coverage.test_selection_digest.clone().ok_or_else(missing)?)
        } else {
            None
        },
        dependency_graph_digest: coverage
            .dependency_graph_digest
            .clone()
            .ok_or_else(missing)?,
        workload_digest: None,
        command: context.command.clone(),
        required_scope: context.required_scope.clone(),
        required_artifacts: Vec::<ArtifactBinding>::new(),
        replay_policy: context.replay_policy,
        upstream_runtime: context.upstream_runtime.clone(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct XcresultSummary {
    pub result: String,
    pub total_tests: u64,
    pub passed_tests: u64,
    pub failed_tests: u64,
    pub skipped_tests: u64,
    /// `(platform, osVersion, deviceName)` entries the run executed on.
    pub devices: Vec<(String, String, String)>,
}

/// Parse `xcresulttool get test-results summary --format json` output that an
/// upstream run retained as an immutable artifact.
pub fn parse_xcresult_summary(bytes: &[u8]) -> Result<XcresultSummary, String> {
    let value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    let count = |key: &str| value.get(key).and_then(Value::as_u64);
    let devices = value
        .get("devicesAndConfigurations")
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get("device"))
                .map(|device| {
                    let field = |key: &str| str_of(device, key).unwrap_or_default().to_string();
                    (field("platform"), field("osVersion"), field("deviceName"))
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(XcresultSummary {
        result: str_of(&value, "result")
            .ok_or("summary has no result")?
            .to_string(),
        total_tests: count("totalTestCount").ok_or("summary has no totalTestCount")?,
        passed_tests: count("passedTests").unwrap_or(0),
        failed_tests: count("failedTests").unwrap_or(0),
        skipped_tests: count("skippedTests").unwrap_or(0),
        devices,
    })
}

fn expected_xcresult_platform(destination: &DestinationSpec) -> &'static str {
    match destination.sdk.as_str() {
        "iphonesimulator" => "iOS Simulator",
        "macosx" => "macOS",
        _ => "",
    }
}

/// Link an A03-verified record (and its retained summary artifact) to one
/// obligation. Returns gaps; empty iff the evidence exactly covers it.
pub fn link_evidence(
    obligation: &XcodeObligation,
    expected: &ExpectedEvidence,
    record: &ImportedEvidenceRecord,
    raw_artifacts: &BTreeMap<String, Vec<u8>>,
    now_rfc3339_utc: &str,
) -> Vec<Gap> {
    let mut gaps = Vec::new();
    if record.target.starts_with("swiftpm:") || record.target.starts_with("spm:") {
        gaps.push(gap(
            "swiftpm-evidence-cannot-discharge-xcode-scheme",
            format!(
                "evidence target `{}` is SwiftPM; scheme `{}` unmet",
                record.target, obligation.scheme
            ),
        ));
    }
    if !record.authenticated {
        gaps.push(gap(
            "evidence-unauthenticated",
            "imported evidence is not authenticated",
        ));
    }
    if record.target != expected.target {
        gaps.push(gap(
            "evidence-target-mismatch",
            format!(
                "evidence `{}` != obligation `{}`",
                record.target, expected.target
            ),
        ));
    }
    if record.variant != expected.variant {
        gaps.push(gap(
            "evidence-variant-mismatch",
            format!(
                "evidence variant `{}` != planned `{}` (configuration, destination, SDK, test plan)",
                record.variant.as_deref().unwrap_or("<none>"),
                expected.variant.as_deref().unwrap_or("<none>")
            ),
        ));
    }
    if record.kind != expected.kind {
        gaps.push(gap(
            "evidence-kind-mismatch",
            format!("{:?} != {:?}", record.kind, expected.kind),
        ));
    }
    if record.toolchain != expected.toolchain {
        gaps.push(gap(
            "evidence-toolchain-mismatch",
            "toolchain/SDK label differs from plan",
        ));
    }
    if record.outcome != EvidenceOutcome::Passed {
        gaps.push(gap(
            "evidence-outcome-not-passed",
            format!("outcome {:?}", record.outcome),
        ));
    }
    if !record.missing_scope.is_empty() {
        gaps.push(gap(
            "evidence-scope-incomplete",
            record.missing_scope.join(", "),
        ));
    }
    if record.fresh_until.as_str() < now_rfc3339_utc {
        gaps.push(gap(
            "evidence-stale",
            format!("fresh until {}", record.fresh_until),
        ));
    }
    let xcresult = record.artifacts.iter().find(|a| a.role == ROLE_XCRESULT);
    if xcresult.is_none() {
        gaps.push(gap(
            "xcresult-artifact-missing",
            "no retained artifact with role `xcresult`",
        ));
    }
    if expected.kind == ImportKind::Test {
        let summary = record
            .artifacts
            .iter()
            .find(|a| a.role == ROLE_TEST_SUMMARY);
        match summary.and_then(|a| raw_artifacts.get(&a.path).map(|bytes| (a, bytes))) {
            None => gaps.push(gap(
                "xcresult-summary-missing",
                "tests are not linked: retained test summary artifact absent",
            )),
            Some((artifact, bytes)) => {
                if sha256_bytes(bytes) != artifact.digest {
                    gaps.push(gap(
                        "xcresult-summary-digest-mismatch",
                        artifact.path.clone(),
                    ));
                }
                match parse_xcresult_summary(bytes) {
                    Err(error) => gaps.push(gap("xcresult-summary-unparseable", error)),
                    Ok(summary) => {
                        if summary.total_tests == 0 {
                            gaps.push(gap("no-tests-executed", "xcresult reports zero tests"));
                        }
                        if summary.failed_tests > 0
                            || !summary.result.eq_ignore_ascii_case("passed")
                        {
                            gaps.push(gap(
                                "xcresult-not-passed",
                                format!(
                                    "result {} ({} failed)",
                                    summary.result, summary.failed_tests
                                ),
                            ));
                        }
                        let platform = expected_xcresult_platform(&obligation.destination);
                        if summary.devices.is_empty()
                            || summary.devices.iter().any(|(p, _, _)| p != platform)
                        {
                            gaps.push(gap(
                                "wrong-destination-evidence",
                                format!(
                                    "xcresult devices {:?} do not match `{platform}`",
                                    summary.devices
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }
    gaps.sort();
    gaps.dedup();
    gaps
}

// ---------------------------------------------------------------------------
// Apple bridge seam (execution is never performed here)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AppleOperation {
    Build,
    Test,
}

/// Archive, export, notarize, upload, install and provisioning are not
/// representable: the only signing posture is `Disabled`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CodeSigningPosture {
    Disabled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppleOperationRequest {
    pub operation: AppleOperation,
    pub container: String,
    pub scheme: String,
    pub configuration: String,
    pub destination: DestinationSpec,
    pub test_plan: Option<String>,
    pub code_signing: CodeSigningPosture,
    /// `evidence_target` / `evidence_variant` the result must carry.
    pub expected_target: String,
    pub expected_variant: String,
}

/// Evidence basis recorded when the host itself ran the operation through the
/// owner-admitted contained runtime (not an imported attestation).
pub const EVIDENCE_BASIS_HOST_EXECUTED: &str = "host-executed";
/// Evidence basis for A03-verified imports.
pub const EVIDENCE_BASIS_IMPORTED: &str = "imported-attestation";

/// One owner-admitted process run, as recorded from the owner's execution
/// receipt (never from the tool's own claims).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerRunRef {
    pub receipt_id: String,
    pub request_id: String,
    pub executable: String,
    /// Digest of the executable bytes as the executor verified them against
    /// the host-policy pin.
    pub executable_digest: String,
    pub argv_digest: String,
    /// Debug name of the executor `ExecutionState`; only `Completed` counts.
    pub state: String,
    pub exit_code: Option<i32>,
    pub stdout_digest: Option<String>,
    pub stderr_digest: Option<String>,
    pub sandbox_id: Option<String>,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub tree_reaped: bool,
}

/// Self-attested host execution receipt. Its digest binds the evidence to the
/// owner receipts of the runs that produced it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostExecutionReceipt {
    pub schema_version: u32,
    /// Always [`EVIDENCE_BASIS_HOST_EXECUTED`].
    pub basis: String,
    pub owner_id: String,
    pub plan_id: String,
    pub operation: AppleOperation,
    pub target: String,
    pub variant: String,
    /// `<pinned xcode version>/<sdk><os>`.
    pub toolchain: String,
    pub output_root: String,
    /// Exact `xcodebuild` arguments that ran.
    pub args: Vec<String>,
    pub build_run: OwnerRunRef,
    pub summary_run: Option<OwnerRunRef>,
    pub artifacts: Vec<ArtifactBinding>,
    pub outcome: EvidenceOutcome,
}

impl HostExecutionReceipt {
    pub fn digest(&self) -> Result<String, AuditError> {
        crate::integrity::digest(self)
    }
}

/// Evidence the host produced by running the operation itself.
#[derive(Clone, Debug)]
pub struct HostExecutedEvidence {
    pub receipt: HostExecutionReceipt,
    /// `receipt.digest()`; recomputed and compared at discharge.
    pub receipt_digest: String,
    pub raw_artifacts: BTreeMap<String, Vec<u8>>,
}

/// Result returned by a bridge. `Imported` is the authenticated envelope that
/// A03 verifies; `HostExecuted` is host-run evidence bound to an owner receipt.
#[derive(Clone, Debug)]
pub enum AppleBridgeResult {
    Imported {
        envelope: ArtifactEvidenceEnvelope,
        raw_artifacts: BTreeMap<String, Vec<u8>>,
        attestation: Vec<u8>,
    },
    HostExecuted(HostExecutedEvidence),
}

/// Root implements this over the existing Apple host operations
/// (`project.build` / `project.test` behind PolicyAuthorizer/ExternalProjectTool).
pub trait AppleTargetBridge {
    fn bridge_id(&self) -> &str;
    fn execute(&self, request: &AppleOperationRequest) -> Result<AppleBridgeResult, Gap>;
    /// `(xcodebuild policy version, xcodebuild policy digest)` when backed by a
    /// host policy pin; used to derive the evidence context on the host.
    fn host_binding(&self) -> Option<(String, String)> {
        None
    }
}

pub struct UnconfiguredAppleBridge;

impl AppleTargetBridge for UnconfiguredAppleBridge {
    fn bridge_id(&self) -> &str {
        "unconfigured"
    }

    fn execute(&self, _request: &AppleOperationRequest) -> Result<AppleBridgeResult, Gap> {
        Err(gap(
            "apple-bridge-unconfigured",
            "no admitted Apple host adapter; xcodebuild was not run and the obligation stays unmet",
        ))
    }
}

pub fn request_for(
    obligation: &XcodeObligation,
    operation: AppleOperation,
) -> AppleOperationRequest {
    AppleOperationRequest {
        operation,
        container: obligation.container.clone(),
        scheme: obligation.scheme.clone(),
        configuration: obligation.configuration.clone(),
        destination: obligation.destination.clone(),
        test_plan: obligation.test_plan.clone(),
        code_signing: CodeSigningPosture::Disabled,
        expected_target: obligation.evidence_target(),
        expected_variant: obligation.evidence_variant(),
    }
}

pub const ADAPTER_ID_TEST: &str = "apple.project.test";
pub const ADAPTER_ID_BUILD: &str = "apple.project.build";
const ARGV_RESULT_BUNDLE: &str = "$RESULT_BUNDLE";
const ARGV_DERIVED_DATA: &str = "$DERIVED_DATA";

/// Toolchain label bound into evidence: `<policy xcodebuild version>/<sdk><os>`.
pub fn toolchain_label(xcodebuild_version: &str, destination: &DestinationSpec) -> String {
    format!(
        "{xcodebuild_version}/{}{}",
        destination.sdk,
        destination.os.as_deref().unwrap_or("")
    )
}

/// Digest of the canonical command for `request`: the exact xcodebuild argv
/// with the container kept repository-relative and the two run-specific output
/// paths replaced by fixed placeholders, so it is stable across runs.
pub fn canonical_command_digest(request: &AppleOperationRequest) -> Result<String, Gap> {
    let argv = xcodebuild_argv(
        request,
        Path::new(&request.container),
        Path::new(ARGV_RESULT_BUNDLE),
        Path::new(ARGV_DERIVED_DATA),
    )?;
    crate::integrity::digest(&argv)
        .map_err(|error| gap("command-digest-unavailable", error.to_string()))
}

/// The same canonical digest computed from an argv that actually ran.
/// Absolute container / output paths are normalised to the canonical form.
pub fn executed_command_digest(request: &AppleOperationRequest, argv: &[String]) -> Option<String> {
    let mut normalised = Vec::with_capacity(argv.len());
    let mut index = 0;
    while index < argv.len() {
        let arg = &argv[index];
        normalised.push(arg.clone());
        index += 1;
        let replacement = match arg.as_str() {
            "-project" | "-workspace" => Some(request.container.clone()),
            "-resultBundlePath" => Some(ARGV_RESULT_BUNDLE.to_string()),
            "-derivedDataPath" => Some(ARGV_DERIVED_DATA.to_string()),
            _ => None,
        };
        if let Some(replacement) = replacement {
            argv.get(index)?;
            normalised.push(replacement);
            index += 1;
        }
    }
    crate::integrity::digest(&normalised).ok()
}

/// Host-owned binding facts the evidence context is derived from. Nothing in
/// it comes from repository input: repositories from the frozen inventory,
/// the xcodebuild version/digest from the host policy pin.
#[derive(Clone, Debug)]
pub struct HostEvidenceBinding {
    pub repositories: Vec<RepositoryBinding>,
    pub xcodebuild_version: String,
    pub xcodebuild_digest: String,
}

/// Deterministic expected-evidence context for one obligation, derived on the
/// host. Always `Test` (xcodebuild test builds first; a scheme with no tests
/// cannot satisfy it), replay denied.
pub fn host_expected_context(
    obligation: &XcodeObligation,
    coverage: &StaticCoverage,
    binding: &HostEvidenceBinding,
) -> Result<ExpectedContext, Gap> {
    let request = request_for(obligation, AppleOperation::Test);
    let mut scope = coverage.targets.clone();
    scope.sort();
    scope.dedup();
    if scope.is_empty() {
        return Err(gap("xcode-required-scope-empty", obligation.scheme.clone()));
    }
    Ok(ExpectedContext {
        kind: ImportKind::Test,
        repositories: binding.repositories.clone(),
        toolchain: toolchain_label(&binding.xcodebuild_version, &obligation.destination),
        command: CommandBinding {
            adapter_id: ADAPTER_ID_TEST.into(),
            command_digest: canonical_command_digest(&request)?,
            executable_digest: Some(binding.xcodebuild_digest.clone()),
        },
        required_scope: scope,
        replay_policy: ReplayPolicy::Deny,
        upstream_runtime: None,
    })
}

/// `-destination` value for an obligation. Only the two supported simulator /
/// host destinations are representable; free-form values are refused so a
/// destination cannot smuggle extra specifier keys.
pub fn destination_string(destination: &DestinationSpec) -> Result<String, Gap> {
    let clean = |value: &str| {
        !value.is_empty()
            && value.chars().all(|c| {
                c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '_' | '-' | '(' | ')')
            })
    };
    if !destination.supported() {
        return Err(gap(
            "destination-unsupported",
            format!("{} / {}", destination.platform, destination.sdk),
        ));
    }
    match destination.sdk.as_str() {
        "macosx" => Ok("platform=macOS".into()),
        _ => {
            let name = destination
                .name
                .as_deref()
                .filter(|n| clean(n))
                .ok_or_else(|| gap("destination-name-invalid", "simulator name required"))?;
            let mut out = format!("platform=iOS Simulator,name={name}");
            if let Some(os) = &destination.os {
                if !clean(os) {
                    return Err(gap("destination-os-invalid", os.clone()));
                }
                out.push_str(&format!(",OS={os}"));
            }
            Ok(out)
        }
    }
}

fn operation_word(operation: AppleOperation) -> &'static str {
    match operation {
        AppleOperation::Build => "build",
        AppleOperation::Test => "test",
    }
}

/// The only `xcodebuild` argv this module builds: one `build`/`test` action,
/// signing disabled, destination exactly from the obligation, and result
/// bundle / derived data under the caller's owner output root.
pub fn xcodebuild_argv(
    request: &AppleOperationRequest,
    container: &Path,
    result_bundle: &Path,
    derived_data: &Path,
) -> Result<Vec<String>, Gap> {
    let mut argv = vec![operation_word(request.operation).to_string()];
    let flag = if request.container.ends_with(".xcworkspace") {
        "-workspace"
    } else if request.container.ends_with(".xcodeproj") {
        "-project"
    } else {
        return Err(gap("container-kind-unsupported", request.container.clone()));
    };
    let text = |p: &Path| p.to_string_lossy().into_owned();
    argv.extend([flag.into(), text(container)]);
    argv.extend(["-scheme".into(), request.scheme.clone()]);
    argv.extend(["-configuration".into(), request.configuration.clone()]);
    argv.extend([
        "-destination".into(),
        destination_string(&request.destination)?,
    ]);
    if let Some(plan) = &request.test_plan {
        argv.extend(["-testPlan".into(), plan.clone()]);
    }
    argv.extend(["-resultBundlePath".into(), text(result_bundle)]);
    argv.extend(["-derivedDataPath".into(), text(derived_data)]);
    argv.push("CODE_SIGNING_ALLOWED=NO".into());
    argv.push("CODE_SIGN_IDENTITY=".into());
    Ok(argv)
}

/// Refuse any argv that is not exactly a signing-disabled `build`/`test` of
/// the requested scheme/configuration/destination with outputs inside
/// `output_root`. Used by the bridge before launch and again at discharge.
pub fn validate_xcodebuild_argv(
    request: &AppleOperationRequest,
    argv: &[String],
    output_root: &Path,
) -> Result<(), Gap> {
    let refuse = |code: &str, detail: String| Err(gap(code, detail));
    if request.code_signing != CodeSigningPosture::Disabled {
        return refuse("signing-enabled", "request does not disable signing".into());
    }
    let want_dest = destination_string(&request.destination)?;
    let mut action: Option<String> = None;
    let mut container: Option<(String, Option<String>)> = None;
    let mut scheme: Option<String> = None;
    let mut configuration: Option<String> = None;
    let mut destination: Option<Option<String>> = None;
    let mut plan: Option<String> = None;
    let mut bundle: Option<String> = None;
    let mut derived: Option<String> = None;
    let (mut signing_allowed, mut identity) = (false, false);
    let mut index = 0;
    while index < argv.len() {
        let arg = argv[index].as_str();
        index += 1;
        let mut value = || -> Option<String> {
            let next = argv.get(index).cloned();
            index += 1;
            next
        };
        match arg {
            "build" | "test" => {
                if action.replace(arg.to_string()).is_some() {
                    return refuse("xcodebuild-multiple-actions", arg.into());
                }
            }
            "-project" | "-workspace" => {
                if container.replace((arg.to_string(), value())).is_some() {
                    return refuse("xcodebuild-duplicate-argument", arg.into());
                }
            }
            "-scheme" => scheme = value(),
            "-configuration" => configuration = value(),
            "-destination" => {
                if destination.replace(value()).is_some() {
                    return refuse("xcodebuild-duplicate-argument", arg.into());
                }
            }
            "-testPlan" => plan = value(),
            "-resultBundlePath" => bundle = value(),
            "-derivedDataPath" => derived = value(),
            "CODE_SIGNING_ALLOWED=NO" => signing_allowed = true,
            "CODE_SIGN_IDENTITY=" => identity = true,
            other if other.starts_with("CODE_SIGN") || other.contains("PROVISIONING") => {
                return refuse("signing-enabled", other.into());
            }
            other => {
                return refuse(
                    "xcodebuild-argument-not-allowed",
                    format!("`{other}` (only build/test with signing disabled)"),
                );
            }
        }
    }
    if action.as_deref() != Some(operation_word(request.operation)) {
        return refuse(
            "xcodebuild-action-mismatch",
            format!("{action:?} != {}", operation_word(request.operation)),
        );
    }
    if !(signing_allowed && identity) {
        return refuse(
            "signing-not-disabled",
            "CODE_SIGNING_ALLOWED=NO and CODE_SIGN_IDENTITY= are required".into(),
        );
    }
    match destination {
        Some(Some(got)) if got == want_dest => {}
        got => return refuse("destination-mismatch", format!("{got:?} != `{want_dest}`")),
    }
    let kind_ok = match &container {
        Some((flag, Some(path))) => {
            path.ends_with(&request.container)
                && ((flag == "-workspace") == request.container.ends_with(".xcworkspace"))
        }
        _ => false,
    };
    if !kind_ok {
        return refuse("container-mismatch", request.container.clone());
    }
    if scheme.as_deref() != Some(request.scheme.as_str())
        || configuration.as_deref() != Some(request.configuration.as_str())
        || plan != request.test_plan
    {
        return refuse(
            "xcodebuild-binding-mismatch",
            "scheme, configuration or test plan differ from the obligation".into(),
        );
    }
    for (name, path) in [("resultBundlePath", bundle), ("derivedDataPath", derived)] {
        let inside = path.as_deref().is_some_and(|p| {
            let p = Path::new(p);
            p.is_absolute()
                && p.starts_with(output_root)
                && !p
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
        });
        if !inside {
            return refuse("output-outside-owner-root", name.into());
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObligationOutcome {
    pub id: String,
    /// `unmet` or `satisfied`. There is no clean status.
    pub status: String,
    pub gaps: Vec<Gap>,
    pub evidence_id: Option<String>,
    pub newly_executed: bool,
    /// `host-executed` or `imported-attestation` when satisfied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_basis: Option<String>,
    /// Owner execution receipt digest for host-executed evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_receipt_digest: Option<String>,
}

fn unmet(obligation: &XcodeObligation, gaps: Vec<Gap>) -> ObligationOutcome {
    ObligationOutcome {
        id: obligation.id.clone(),
        status: "unmet".into(),
        gaps,
        evidence_id: None,
        newly_executed: false,
        evidence_basis: None,
        owner_receipt_digest: None,
    }
}

/// Resolve one obligation through the bridge. Execution failure, verifier
/// absence, mismatch or any static gap leaves it `unmet`.
#[allow(clippy::too_many_arguments)]
pub fn discharge_via_bridge(
    bridge: &dyn AppleTargetBridge,
    obligation: &XcodeObligation,
    coverage: &StaticCoverage,
    context: &ExpectedContext,
    trust: &TrustEnrollment,
    verifier: &dyn ProvenanceVerifier,
    now_rfc3339_utc: &str,
) -> ObligationOutcome {
    let expected = match expected_evidence(obligation, coverage, context) {
        Ok(expected) => expected,
        Err(_) => return unmet(obligation, coverage.gaps.clone()),
    };
    let operation = if context.kind == ImportKind::Test {
        AppleOperation::Test
    } else {
        AppleOperation::Build
    };
    let request = request_for(obligation, operation);
    let result = match bridge.execute(&request) {
        Ok(result) => result,
        Err(gap) => return unmet(obligation, vec![gap]),
    };
    let (envelope, raw_artifacts, attestation) = match result {
        AppleBridgeResult::HostExecuted(host) => {
            return discharge_host_executed(
                obligation,
                &request,
                &expected,
                context,
                &host,
                now_rfc3339_utc,
            );
        }
        AppleBridgeResult::Imported {
            envelope,
            raw_artifacts,
            attestation,
        } => (envelope, raw_artifacts, attestation),
    };
    let verdict: ImportVerdict = verify_artifact_evidence(
        &envelope,
        &raw_artifacts,
        &attestation,
        &expected,
        trust,
        verifier,
        now_rfc3339_utc,
    );
    let Some(record) = verdict
        .record
        .as_ref()
        .filter(|_| verdict.satisfies_obligation)
    else {
        let mut gaps: Vec<Gap> = verdict
            .reasons
            .iter()
            .map(|reason| gap(reason, "A03 verification"))
            .collect();
        if gaps.is_empty() {
            gaps.push(gap(
                "evidence-not-satisfying",
                "A03 verdict did not satisfy the obligation",
            ));
        }
        return unmet(obligation, gaps);
    };
    let gaps = link_evidence(
        obligation,
        &expected,
        record,
        &raw_artifacts,
        now_rfc3339_utc,
    );
    if gaps.is_empty() {
        ObligationOutcome {
            id: obligation.id.clone(),
            status: "satisfied".into(),
            gaps,
            evidence_id: Some(record.evidence_id.clone()),
            newly_executed: record.newly_executed,
            evidence_basis: Some(EVIDENCE_BASIS_IMPORTED.into()),
            owner_receipt_digest: None,
        }
    } else {
        unmet(obligation, gaps)
    }
}

fn host_artifact<'a>(receipt: &'a HostExecutionReceipt, role: &str) -> Option<&'a ArtifactBinding> {
    receipt.artifacts.iter().find(|a| a.role == role)
}

/// Host-executed evidence is fresh for 24 hours after the run completes.
pub const HOST_EVIDENCE_FRESH_SECONDS: u64 = 24 * 60 * 60;

/// Verify host-executed evidence against its owner receipt, build the
/// host-authenticated record, then link it exactly like imported evidence.
/// Nothing the bridge asserts is trusted beyond what the receipt digest, the
/// re-validated argv, and the retained artifact bytes prove.
fn discharge_host_executed(
    obligation: &XcodeObligation,
    request: &AppleOperationRequest,
    expected: &ExpectedEvidence,
    context: &ExpectedContext,
    host: &HostExecutedEvidence,
    now_rfc3339_utc: &str,
) -> ObligationOutcome {
    let receipt = &host.receipt;
    let mut gaps = Vec::new();
    match receipt.digest() {
        Ok(digest) if digest == host.receipt_digest => {}
        _ => gaps.push(gap(
            "host-receipt-digest-mismatch",
            "host execution receipt does not hash to its bound digest",
        )),
    }
    if receipt.basis != EVIDENCE_BASIS_HOST_EXECUTED || receipt.owner_id.trim().is_empty() {
        gaps.push(gap(
            "host-receipt-basis-invalid",
            "receipt is not a host-executed owner receipt",
        ));
    }
    if receipt.operation != request.operation
        || receipt.target != expected.target
        || Some(&receipt.variant) != expected.variant.as_ref()
    {
        gaps.push(gap(
            "host-receipt-binding-mismatch",
            "receipt operation/target/variant differ from the obligation",
        ));
    }
    if receipt.toolchain != expected.toolchain {
        gaps.push(gap(
            "evidence-toolchain-mismatch",
            "toolchain/SDK label differs from plan",
        ));
    }
    if let Err(argv_gap) =
        validate_xcodebuild_argv(request, &receipt.args, Path::new(&receipt.output_root))
    {
        gaps.push(argv_gap);
    }
    match crate::integrity::digest(&receipt.args) {
        Ok(digest) if digest == receipt.build_run.argv_digest => {}
        _ => gaps.push(gap(
            "host-receipt-argv-mismatch",
            "recorded argv digest differs from the argv that ran",
        )),
    }
    let run_ok = |run: &OwnerRunRef| {
        run.state == "Completed"
            && run.tree_reaped
            && run.sandbox_id.is_some()
            && run.executable_digest.starts_with("sha256:")
    };
    if !run_ok(&receipt.build_run) {
        gaps.push(gap(
            "host-receipt-run-incomplete",
            "xcodebuild owner run is not a completed, contained, reaped run",
        ));
    }
    // The planned command binding must equal the digest of the argv that
    // actually ran (container/output paths normalised), never a recorded claim.
    match executed_command_digest(request, &receipt.args) {
        Some(ran) if ran == expected.command.command_digest => {}
        _ => gaps.push(gap(
            "command-digest-mismatch",
            "planned command digest differs from the host-executed argv digest",
        )),
    }
    if let Some(want) = expected.command.executable_digest.as_deref() {
        if want != receipt.build_run.executable_digest {
            gaps.push(gap(
                "executable-digest-mismatch",
                "xcodebuild digest differs from the planned executable digest",
            ));
        }
    }
    if context.kind == ImportKind::Test {
        match &receipt.summary_run {
            None => gaps.push(gap(
                "host-receipt-summary-run-missing",
                "no owner-admitted xcresulttool run recorded",
            )),
            Some(run) => {
                if !run_ok(run) || run.exit_code != Some(0) {
                    gaps.push(gap(
                        "host-receipt-run-incomplete",
                        "xcresulttool owner run is not a completed, contained, reaped run",
                    ));
                }
                let summary = host_artifact(receipt, ROLE_TEST_SUMMARY);
                if summary.map(|a| a.digest.as_str()) != run.stdout_digest.as_deref() {
                    gaps.push(gap(
                        "xcresult-summary-digest-mismatch",
                        "test summary is not the owner-recorded xcresulttool output",
                    ));
                }
            }
        }
    }
    for artifact in &receipt.artifacts {
        match host.raw_artifacts.get(&artifact.path) {
            Some(bytes)
                if bytes.len() as u64 == artifact.bytes
                    && sha256_bytes(bytes) == artifact.digest => {}
            _ => gaps.push(gap("artifact-substitution", artifact.path.clone())),
        }
    }
    if !gaps.is_empty() {
        gaps.sort();
        gaps.dedup();
        return unmet(obligation, gaps);
    }
    let completed_seconds = receipt.build_run.completed_at_ms / 1000;
    let issued =
        crate::p12_pipeline::store::format_utc(completed_seconds.min(i64::MAX as u64) as i64);
    let fresh_until = crate::p12_pipeline::store::format_utc(
        (completed_seconds + HOST_EVIDENCE_FRESH_SECONDS).min(i64::MAX as u64) as i64,
    );
    let primary = host_artifact(receipt, ROLE_XCRESULT)
        .map(|a| a.digest.clone())
        .unwrap_or_default();
    let denominator_digest = crate::integrity::digest(&json!({
        "required": expected.required_scope,
        "examined": context.required_scope,
        "missing": Vec::<String>::new(),
    }))
    .unwrap_or_default();
    let record = ImportedEvidenceRecord {
        schema_version: 1,
        evidence_id: format!("host-executed:{}", host.receipt_digest),
        claims_digest: host.receipt_digest.clone(),
        kind: context.kind,
        // Host-executed under the owner's contained runtime: authenticated by
        // the owner receipt, not by an issuer attestation.
        authenticated: true,
        attestor: format!("host-executed:{}", receipt.owner_id),
        trust_root_id: receipt.build_run.sandbox_id.clone().unwrap_or_default(),
        verifier_id: "host-execution-receipt".into(),
        outcome: receipt.outcome,
        repositories: expected.repositories.clone(),
        target: receipt.target.clone(),
        variant: Some(receipt.variant.clone()),
        toolchain: receipt.toolchain.clone(),
        upstream_runtime: expected.upstream_runtime.clone(),
        artifacts: receipt
            .artifacts
            .iter()
            .map(|a| RetainedArtifact {
                path: a.path.clone(),
                digest: a.digest.clone(),
                bytes: a.bytes,
                role: a.role.clone(),
                immutable: true,
            })
            .collect(),
        artifact_digest: primary,
        denominator_digest,
        examined_scope: context.required_scope.clone(),
        missing_scope: Vec::new(),
        newly_executed: true,
        replay_of: None,
        issued_at: issued,
        fresh_until,
    };
    let gaps = link_evidence(
        obligation,
        expected,
        &record,
        &host.raw_artifacts,
        now_rfc3339_utc,
    );
    if gaps.is_empty() {
        ObligationOutcome {
            id: obligation.id.clone(),
            status: "satisfied".into(),
            gaps,
            evidence_id: Some(record.evidence_id.clone()),
            newly_executed: true,
            evidence_basis: Some(EVIDENCE_BASIS_HOST_EXECUTED.into()),
            owner_receipt_digest: Some(host.receipt_digest.clone()),
        }
    } else {
        unmet(obligation, gaps)
    }
}

/// Provider JSON: inventory plus static coverage for each obligation. Status
/// is `unmet` until evidence is linked; this entry point can never say clean.
pub fn analyze_targets(files: &SnapshotFiles, obligations: &[XcodeObligation]) -> Value {
    let inventory = inventory_xcode(files);
    let coverage: Vec<Value> = obligations
        .iter()
        .map(|obligation| {
            let statics = evaluate_static(&inventory, files, obligation);
            json!({
                "id": obligation.id,
                "status": "unmet",
                "reason": if statics.gaps.is_empty() { "inputs-bound-awaiting-execution-evidence" } else { "input-gaps" },
                "evidenceTarget": obligation.evidence_target(),
                "evidenceVariant": obligation.evidence_variant(),
                "coverage": statics,
            })
        })
        .collect();
    json!({
        "providerId": PROVIDER_ID,
        "schemaVersion": SCHEMA_VERSION,
        "status": "inventoried",
        "inventory": inventory,
        "obligations": coverage,
    })
}

// ---------------------------------------------------------------------------
// Swift diagnostics (strict concurrency), SwiftLint and Periphery imports
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticContext {
    pub scheme: String,
    pub configuration: String,
    pub sdk: String,
    /// Effective mode of the compiled target; absence of findings is evidence
    /// only when this is `complete`.
    pub concurrency_mode: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwiftDiagnostic {
    pub path: String,
    pub line: u32,
    pub column: u32,
    pub severity: String,
    pub message: String,
    pub category: Option<String>,
    pub concurrency: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiagnosticReport {
    pub context: DiagnosticContext,
    pub findings: Vec<SwiftDiagnostic>,
    pub concurrency_findings: usize,
    pub outside_source_root: usize,
    pub truncated: bool,
    /// True only when the context compiled with complete checking; otherwise
    /// zero concurrency findings says nothing.
    pub absence_is_evidence: bool,
    pub status: String,
}

fn diagnostic_regex() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| {
        Regex::new(r"^(.+?):(\d+):(\d+): (warning|error): (.*)$").expect("diagnostic regex")
    })
}

fn is_concurrency_message(message: &str) -> bool {
    let lower = message.to_lowercase();
    [
        "sendable",
        "isolat",
        "data race",
        "mainactor",
        "main actor",
        "sendingrisks",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

/// Parse compiler output; `source_root` is stripped so findings carry
/// snapshot-relative paths. Paths outside it (SDK, DerivedData) are counted,
/// not attributed to source.
pub fn parse_swift_diagnostics(
    output: &str,
    source_root: &str,
    context: DiagnosticContext,
) -> DiagnosticReport {
    let root = source_root.trim_end_matches('/');
    let mut findings = Vec::new();
    let mut outside = 0usize;
    let mut truncated = false;
    for line in output.lines() {
        let Some(captures) = diagnostic_regex().captures(line.trim_end()) else {
            continue;
        };
        let raw = &captures[1];
        let Some(relative) = raw.strip_prefix(&format!("{root}/")) else {
            outside += 1;
            continue;
        };
        if findings.len() >= MAX_FINDINGS {
            truncated = true;
            break;
        }
        let message = captures[5].to_string();
        let category = message
            .rsplit_once(" [#")
            .and_then(|(_, tail)| tail.strip_suffix(']'))
            .map(str::to_string);
        findings.push(SwiftDiagnostic {
            path: relative.to_string(),
            line: captures[2].parse().unwrap_or(0),
            column: captures[3].parse().unwrap_or(0),
            severity: captures[4].to_string(),
            concurrency: is_concurrency_message(&message),
            message,
            category,
        });
    }
    let concurrency_findings = findings.iter().filter(|f| f.concurrency).count();
    let absence_is_evidence = context.concurrency_mode == "complete";
    let status = if truncated {
        "truncated"
    } else if concurrency_findings > 0 {
        "concurrency-findings"
    } else if !absence_is_evidence {
        "no-evidence-concurrency-not-complete"
    } else {
        "no-concurrency-findings-observed"
    };
    DiagnosticReport {
        context,
        findings,
        concurrency_findings,
        outside_source_root: outside,
        truncated,
        absence_is_evidence,
        status: status.into(),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwiftLintPin {
    pub version: String,
    pub executable_digest: String,
    pub config_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SwiftLintRun {
    pub version: String,
    pub executable_digest: String,
    pub config_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LintFinding {
    pub path: String,
    pub line: u64,
    pub column: u64,
    pub severity: String,
    pub rule_id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LintReport {
    pub qualified: bool,
    pub gaps: Vec<Gap>,
    pub findings: Vec<LintFinding>,
    /// `findings`, `unqualified` or `no-findings-in-qualified-run`; never clean.
    pub status: String,
}

pub fn parse_swiftlint_json(
    bytes: &[u8],
    source_root: &str,
    run: &SwiftLintRun,
    pin: &SwiftLintPin,
) -> Result<LintReport, AuditError> {
    let items: Vec<Value> = serde_json::from_slice(bytes)
        .map_err(|error| AuditError::Invalid(format!("swiftlint json: {error}")))?;
    let root = source_root.trim_end_matches('/');
    let mut gaps = Vec::new();
    if run.version != pin.version {
        gaps.push(gap(
            "swiftlint-version-unpinned",
            format!("{} != {}", run.version, pin.version),
        ));
    }
    if run.executable_digest != pin.executable_digest {
        gaps.push(gap(
            "swiftlint-executable-unpinned",
            "executable digest differs from pin",
        ));
    }
    if run.config_digest != pin.config_digest {
        gaps.push(gap(
            "swiftlint-config-unpinned",
            "configuration digest differs from pin",
        ));
    }
    let mut findings = Vec::new();
    for item in items.iter().take(MAX_FINDINGS) {
        let file = str_of(item, "file").unwrap_or_default();
        findings.push(LintFinding {
            path: file
                .strip_prefix(&format!("{root}/"))
                .unwrap_or(file)
                .to_string(),
            line: item.get("line").and_then(Value::as_u64).unwrap_or(0),
            column: item.get("character").and_then(Value::as_u64).unwrap_or(0),
            severity: str_of(item, "severity").unwrap_or_default().to_lowercase(),
            rule_id: str_of(item, "rule_id").unwrap_or_default().to_string(),
            reason: str_of(item, "reason").unwrap_or_default().to_string(),
        });
    }
    if items.len() > MAX_FINDINGS {
        gaps.push(gap(
            "swiftlint-output-truncated",
            format!("{} findings", items.len()),
        ));
    }
    let qualified = gaps.is_empty();
    let status = if !qualified {
        "unqualified"
    } else if findings.is_empty() {
        "no-findings-in-qualified-run"
    } else {
        "findings"
    };
    Ok(LintReport {
        qualified,
        gaps,
        findings,
        status: status.into(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeripheryContext {
    pub scheme: String,
    pub variant: String,
    /// Digest of the retained index store; required for a qualified run.
    pub index_store_digest: Option<String>,
    /// A03 evidence id of the build whose index produced the store.
    pub build_evidence_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnusedCandidate {
    pub kind: String,
    pub name: String,
    pub path: String,
    pub line: u64,
    pub column: u64,
    pub accessibility: String,
    /// Always `candidate`: unused-symbol analysis is heuristic.
    pub confidence: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeripheryReport {
    pub qualified: bool,
    pub gaps: Vec<Gap>,
    pub candidates: Vec<UnusedCandidate>,
    pub status: String,
}

pub fn parse_periphery_json(
    bytes: &[u8],
    source_root: &str,
    context: &PeripheryContext,
) -> Result<PeripheryReport, AuditError> {
    let items: Vec<Value> = serde_json::from_slice(bytes)
        .map_err(|error| AuditError::Invalid(format!("periphery json: {error}")))?;
    let root = source_root.trim_end_matches('/');
    let mut gaps = Vec::new();
    if context.index_store_digest.is_none() {
        gaps.push(gap(
            "periphery-index-context-missing",
            "no retained index store digest",
        ));
    }
    if context.build_evidence_id.is_none() {
        gaps.push(gap(
            "periphery-build-evidence-missing",
            "no linked scheme build evidence",
        ));
    }
    let mut candidates = Vec::new();
    for item in items.iter().take(MAX_FINDINGS) {
        let location = str_of(item, "location").unwrap_or_default();
        let mut parts = location.rsplitn(3, ':');
        let column = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let line = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let file = parts.next().unwrap_or(location);
        candidates.push(UnusedCandidate {
            kind: str_of(item, "kind").unwrap_or_default().to_string(),
            name: str_of(item, "name").unwrap_or_default().to_string(),
            path: file
                .strip_prefix(&format!("{root}/"))
                .unwrap_or(file)
                .to_string(),
            line,
            column,
            accessibility: str_of(item, "accessibility")
                .unwrap_or_default()
                .to_string(),
            confidence: "candidate".into(),
        });
    }
    let qualified = gaps.is_empty();
    let status = if !qualified {
        "unqualified-candidates"
    } else if candidates.is_empty() {
        "no-candidates-in-qualified-run"
    } else {
        "candidates"
    };
    Ok(PeripheryReport {
        qualified,
        gaps,
        candidates,
        status: status.into(),
    })
}
