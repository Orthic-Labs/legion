//! Android variants, Lint & platform obligations (A05).
//!
//! Provider `code.android.lint` is separate from `code.jvm`,
//! `code.mobile` and the Kotlin detekt providers. This module is planner,
//! safe parser and evaluator only (edit-only packet): it launches no
//! process, reads no audited tree and never turns a missing SDK, Gradle
//! model, variant, baseline, receipt or authentication into clean.
//!
//! Model of the work:
//!
//! 1. [`infer_applicability`] decides Android applicability from AGP
//!    plugin markers, manifests and resources and records ambiguity.
//! 2. [`plan_lint`] derives one [`LintObligation`] per required
//!    (module, variant) pair from a qualified [`AndroidBuildModel`]
//!    (Gradle model receipt or authenticated import). The Lint task
//!    identity comes from the model; `./gradlew lint` is never assumed to
//!    be whole-product proof. Every build type, flavor combination, SDK
//!    level, source set and generated-resource seal is frozen into a
//!    per-obligation scope digest.
//! 3. [`evaluate_lint`] binds offered [`LintEvidence`] to obligations.
//!    Evidence satisfies an obligation only when it is an admitted local
//!    run (receipt-linked) or an authenticated A03 import for that exact
//!    module, variant, task, toolchain and scope. A bare local report file
//!    ([`LintEvidenceSource::UnsignedFile`]) never does.
//! 4. Lint success claims static Lint for the named variant only. Compile,
//!    tests, device/lifecycle and package/security stay separate
//!    unevidenced obligations ([`adjacent_obligations`]).
//!
//! Execution is routed through the existing admitted project-tool seam.
//! [`ExecutionRoute::NotAdmitted`] keeps missing admission an explicit,
//! named gap; A01 admission receipts are consumed as an opaque id.

use super::{
    evidence::NativeFinding,
    kotlin_detekt::{normalize_report_path, ReceiptLink, TypedProvenance},
};
use crate::artifact_evidence::{
    is_rfc3339_utc_second, EvidenceOutcome, ImportKind, ImportedEvidenceRecord,
};
use crate::inventory::InventoryEntry;
use crate::profiles::AuditProfile;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};

pub const PROVIDER_ID: &str = "code.android.lint";
pub const TOOL_ID: &str = "android-lint";
pub const CONCERN: &str = "android-lint";
pub const MODEL_SCHEMA_VERSION: u32 = 1;
pub const SUPPORTED_XML_FORMATS: &[&str] = &["5", "6"];
pub const SUPPORTED_SARIF_VERSION: &str = "2.1.0";
pub const SARIF_DRIVER: &str = "Android Lint";
pub const MAX_LINT_FINDINGS: usize = 200;
pub const MAX_XML_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_XML_DEPTH: usize = 64;
pub const MAX_XML_ELEMENTS: usize = 500_000;
pub const MAX_ATTR_BYTES: usize = 64 * 1024;
const MAX_MESSAGE_CHARS: usize = 300;
pub const EXIT_OK: i32 = 0;
/// Gradle build failure: lint errors with `abortOnError`, but also a
/// compile/resolution failure. Accepted only alongside an error-level issue.
pub const EXIT_BUILD_FAILED: i32 = 1;

/// Coarse selector only: applicability is inferred by
/// [`infer_applicability`], never by extension alone.
pub fn provider_selector() -> Value {
    json!({"op": "anyExtension", "extensions": ["kt", "java", "xml"]})
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

fn gap(kind: impl AsRef<str>) -> String {
    format!("{PROVIDER_ID}:{}", kind.as_ref())
}

fn name_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn truncated_message(message: &str) -> String {
    let message = message.split_whitespace().collect::<Vec<_>>().join(" ");
    if message.chars().count() <= MAX_MESSAGE_CHARS {
        message
    } else {
        message.chars().take(MAX_MESSAGE_CHARS).collect()
    }
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

// ---------------------------------------------------------------------------
// Safe bounded XML
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct XmlElement {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<XmlElement>,
}

impl XmlElement {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlElement> {
        self.children.iter().filter(move |child| child.name == name)
    }
}

fn decode_entities(raw: &str) -> Result<String, String> {
    if !raw.contains('&') {
        return Ok(raw.to_string());
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let after = &rest[at + 1..];
        let end = after
            .find(';')
            .filter(|end| *end <= 10)
            .ok_or_else(|| "bad-entity".to_string())?;
        let entity = &after[..end];
        let decoded = match entity {
            "lt" => '<',
            "gt" => '>',
            "amp" => '&',
            "quot" => '"',
            "apos" => '\'',
            numeric if numeric.starts_with("#x") || numeric.starts_with("#X") => {
                u32::from_str_radix(&numeric[2..], 16)
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or_else(|| "bad-entity".to_string())?
            }
            numeric if numeric.starts_with('#') => numeric[1..]
                .parse::<u32>()
                .ok()
                .and_then(char::from_u32)
                .ok_or_else(|| "bad-entity".to_string())?,
            // Custom entities are only definable via DTD, which is refused.
            _ => return Err("unknown-entity".into()),
        };
        out.push(decoded);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

fn attach(
    stack: &mut Vec<XmlElement>,
    root: &mut Option<XmlElement>,
    element: XmlElement,
) -> Result<(), String> {
    if let Some(parent) = stack.last_mut() {
        parent.children.push(element);
        return Ok(());
    }
    if root.is_some() {
        return Err("multiple-roots".into());
    }
    *root = Some(element);
    Ok(())
}

fn valid_xml_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'.' | b'-'))
}

/// Parse a bounded, DTD-free XML document into a minimal element tree.
/// DOCTYPE/ENTITY declarations (entity-expansion & external-entity
/// vectors) are rejected outright; text content is ignored; depth, element
/// count, attribute size and document size are bounded.
pub fn parse_xml(bytes: &[u8]) -> Result<XmlElement, String> {
    if bytes.len() > MAX_XML_BYTES {
        return Err("too-large".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "not-utf8".to_string())?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let b = text.as_bytes();
    let mut i = 0usize;
    let mut stack: Vec<XmlElement> = Vec::new();
    let mut root: Option<XmlElement> = None;
    let mut count = 0usize;
    while i < b.len() {
        if b[i] != b'<' {
            let next = text[i..].find('<').map(|at| i + at).unwrap_or(b.len());
            if stack.is_empty() && !text[i..next].trim().is_empty() {
                return Err("text-outside-root".into());
            }
            i = next;
            continue;
        }
        let rest = &text[i..];
        if rest.starts_with("<?") {
            let end = rest.find("?>").ok_or("unterminated-pi")?;
            i += end + 2;
        } else if rest.starts_with("<!--") {
            let end = rest.find("-->").ok_or("unterminated-comment")?;
            i += end + 3;
        } else if rest.starts_with("<![CDATA[") {
            if stack.is_empty() {
                return Err("cdata-outside-root".into());
            }
            let end = rest.find("]]>").ok_or("unterminated-cdata")?;
            i += end + 3;
        } else if rest.starts_with("<!") {
            return Err("doctype-or-entity-forbidden".into());
        } else if rest.starts_with("</") {
            let end = rest.find('>').ok_or("unterminated-end-tag")?;
            let name = rest[2..end].trim();
            let element = stack.pop().ok_or("unbalanced-end-tag")?;
            if element.name != name {
                return Err("mismatched-end-tag".into());
            }
            attach(&mut stack, &mut root, element)?;
            i += end + 1;
        } else {
            i += 1;
            let name_end = text[i..]
                .find(|c: char| c.is_whitespace() || c == '/' || c == '>')
                .map(|at| i + at)
                .ok_or("unterminated-start-tag")?;
            let name = &text[i..name_end];
            if !valid_xml_name(name) {
                return Err("bad-element-name".into());
            }
            i = name_end;
            let mut element = XmlElement {
                name: name.to_string(),
                ..XmlElement::default()
            };
            let self_closing;
            loop {
                while i < b.len() && (b[i] as char).is_whitespace() {
                    i += 1;
                }
                if i >= b.len() {
                    return Err("unterminated-start-tag".into());
                }
                if b[i] == b'/' {
                    if b.get(i + 1) != Some(&b'>') {
                        return Err("bad-empty-tag".into());
                    }
                    i += 2;
                    self_closing = true;
                    break;
                }
                if b[i] == b'>' {
                    i += 1;
                    self_closing = false;
                    break;
                }
                let key_end = text[i..]
                    .find(|c: char| c == '=' || c.is_whitespace() || c == '>' || c == '/')
                    .map(|at| i + at)
                    .ok_or("unterminated-attribute")?;
                let key = &text[i..key_end];
                if !valid_xml_name(key) {
                    return Err("bad-attribute-name".into());
                }
                i = key_end;
                while i < b.len() && (b[i] as char).is_whitespace() {
                    i += 1;
                }
                if b.get(i) != Some(&b'=') {
                    return Err("attribute-without-value".into());
                }
                i += 1;
                while i < b.len() && (b[i] as char).is_whitespace() {
                    i += 1;
                }
                let quote = *b.get(i).ok_or("unterminated-attribute")?;
                if quote != b'"' && quote != b'\'' {
                    return Err("unquoted-attribute".into());
                }
                i += 1;
                let value_end = text[i..]
                    .find(quote as char)
                    .map(|at| i + at)
                    .ok_or("unterminated-attribute")?;
                let raw = &text[i..value_end];
                if raw.len() > MAX_ATTR_BYTES {
                    return Err("attribute-too-large".into());
                }
                if raw.contains('<') {
                    return Err("lt-in-attribute".into());
                }
                if element.attrs.iter().any(|(existing, _)| existing == key) {
                    return Err("duplicate-attribute".into());
                }
                element.attrs.push((key.to_string(), decode_entities(raw)?));
                i = value_end + 1;
            }
            count += 1;
            if count > MAX_XML_ELEMENTS {
                return Err("too-many-elements".into());
            }
            if stack.len() >= MAX_XML_DEPTH {
                return Err("too-deep".into());
            }
            if self_closing {
                attach(&mut stack, &mut root, element)?;
            } else {
                stack.push(element);
            }
        }
    }
    if !stack.is_empty() {
        return Err("unterminated-element".into());
    }
    root.ok_or_else(|| "no-root".to_string())
}

// ---------------------------------------------------------------------------
// Applicability
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Applicability {
    Applicable,
    NotApplicable,
    /// Partial evidence only. Never treated as not-applicable.
    Ambiguous,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApplicabilityDecision {
    pub applicability: Applicability,
    pub reasons: Vec<String>,
    /// Manifest paths under a source set (`.../src/<set>/AndroidManifest.xml`).
    pub manifests: Vec<String>,
    /// Build files carrying an Android Gradle plugin marker.
    pub agp_build_files: Vec<String>,
    /// Module directories (`""` = repo root) that own a manifest.
    pub manifest_module_dirs: Vec<String>,
    pub gaps: Vec<String>,
}

fn is_build_file(name: &str) -> bool {
    matches!(name, "build.gradle" | "build.gradle.kts")
}

fn agp_marker(text: &str) -> bool {
    [
        "com.android.application",
        "com.android.library",
        "com.android.dynamic-feature",
        "com.android.test",
        "com.android.tools.build:gradle",
        "com.android.kotlin.multiplatform.library",
        "libs.plugins.android.",
    ]
    .iter()
    .any(|marker| text.contains(marker))
}

fn in_build_output(path: &str) -> bool {
    path.split('/').any(|segment| segment == "build")
}

fn manifest_module_dir(path: &str) -> Option<String> {
    if name_of(path) != "AndroidManifest.xml" || in_build_output(path) {
        return None;
    }
    if let Some(rest) = path.strip_prefix("src/") {
        return rest.contains('/').then(String::new);
    }
    let at = path.find("/src/")?;
    path[at + 5..].contains('/').then(|| path[..at].to_string())
}

/// `build_texts` maps build-file path to its bounded text, read by root.
/// A build file present in the inventory but absent from `build_texts` is
/// recorded as unread and can only make the decision more ambiguous.
pub fn infer_applicability(
    entries: &[InventoryEntry],
    build_texts: &BTreeMap<String, String>,
) -> ApplicabilityDecision {
    let mut manifests = Vec::new();
    let mut manifest_dirs = BTreeSet::new();
    let mut agp = Vec::new();
    let mut gaps = Vec::new();
    let mut resources = 0usize;
    for entry in entries {
        if let Some(dir) = manifest_module_dir(&entry.path) {
            manifests.push(entry.path.clone());
            manifest_dirs.insert(dir);
        }
        if is_build_file(name_of(&entry.path)) {
            match build_texts.get(&entry.path) {
                Some(text) if agp_marker(text) => agp.push(entry.path.clone()),
                Some(_) => {}
                None => gaps.push(gap(format!("android-build-file-unread:{}", entry.path))),
            }
        }
        if entry.path.contains("/res/")
            && entry.path.ends_with(".xml")
            && !in_build_output(&entry.path)
        {
            resources += 1;
        }
    }
    manifests.sort();
    agp.sort();
    let mut reasons = Vec::new();
    let applicability = match (agp.is_empty(), manifests.is_empty()) {
        (false, false) => {
            reasons.push("agp-plugin-and-manifest".to_string());
            Applicability::Applicable
        }
        (false, true) => {
            reasons.push("agp-plugin-without-manifest".to_string());
            gaps.push(gap("android-applicability-ambiguous:agp-without-manifest"));
            Applicability::Ambiguous
        }
        (true, false) => {
            reasons.push("manifest-without-agp-plugin".to_string());
            gaps.push(gap("android-applicability-ambiguous:manifest-without-agp"));
            Applicability::Ambiguous
        }
        (true, true) => {
            if resources > 0 {
                reasons.push("android-resources-only".to_string());
                gaps.push(gap("android-applicability-ambiguous:resources-only"));
                Applicability::Ambiguous
            } else if gaps.is_empty() {
                reasons.push("no-android-evidence".to_string());
                Applicability::NotApplicable
            } else {
                // Unread build files could still carry the plugin.
                reasons.push("build-files-unread".to_string());
                Applicability::Ambiguous
            }
        }
    };
    ApplicabilityDecision {
        applicability,
        reasons,
        manifests,
        agp_build_files: agp,
        manifest_module_dirs: manifest_dirs.into_iter().collect(),
        gaps: sorted_unique(gaps),
    }
}

// ---------------------------------------------------------------------------
// Qualified Gradle model
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SdkIdentity {
    pub compile_sdk: u32,
    /// `sha256:` seal of the installed platform (`android.jar` +
    /// `package.xml`); empty or unsealed is a gap.
    pub platform_digest: String,
    pub build_tools_version: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SealedPath {
    pub path: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SourceSetRef {
    pub name: String,
    /// Repository-relative directory; its inventory digest is recomputed.
    pub dir: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VariantModel {
    /// e.g. `phoneRelease`.
    pub name: String,
    pub build_type: String,
    #[serde(default)]
    pub flavors: Vec<String>,
    /// Exact Gradle task, e.g. `:app:lintPhoneRelease`.
    pub lint_task: String,
    pub min_sdk: u32,
    pub target_sdk: u32,
    pub source_sets: Vec<SourceSetRef>,
    #[serde(default)]
    pub generated_resources: Vec<SealedPath>,
    /// Expected report location, interpreted per `report_root`.
    pub report_xml_path: String,
    /// `""`: repository-relative (legacy, authored models). `owner-output`:
    /// relative to the owner output root, where the extraction's init script
    /// redirects every build directory; the model reports the redirected
    /// location, never the module's own `build/`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub report_root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_sarif_path: Option<String>,
}

/// The only accepted non-empty `report_root`.
pub const REPORT_ROOT_OWNER_OUTPUT: &str = "owner-output";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModuleModel {
    /// Gradle path, e.g. `:app`.
    pub path: String,
    /// Repository-relative directory, `""` for the root project.
    pub dir: String,
    /// `application` | `library` | `dynamic-feature` | `test`.
    pub kind: String,
    #[serde(default)]
    pub lint_excluded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclusion_reason: Option<String>,
    /// Gradle dependency/configuration resolution failure message, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution_failure: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub baseline: Option<SealedPath>,
    /// `lint.xml` suppression/severity configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lint_config: Option<SealedPath>,
    pub variants: Vec<VariantModel>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AndroidBuildModel {
    pub schema_version: u32,
    pub agp_version: String,
    pub gradle_version: String,
    pub jdk_version: String,
    /// Lint tool version the report's `by="lint X"` must equal.
    pub lint_version: String,
    /// Project-runner program from the model receipt (e.g. the pinned
    /// wrapper); never assumed by this module.
    pub gradle_program: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sdk: Option<SdkIdentity>,
    pub modules: Vec<ModuleModel>,
    /// Reused A04 provenance: admitted build receipt or authenticated
    /// import. `authenticated` is set only by root's importer.
    pub provenance: TypedProvenance,
}

impl AndroidBuildModel {
    pub fn from_value(value: &Value) -> Result<Self, String> {
        let model: Self = serde_json::from_value(value.clone())
            .map_err(|error| format!("android model: {error}"))?;
        if model.schema_version != MODEL_SCHEMA_VERSION {
            return Err("unsupported android model schemaVersion".into());
        }
        Ok(model)
    }

    /// Toolchain label evidence must carry verbatim.
    pub fn toolchain_label(&self) -> String {
        format!(
            "agp-{}+gradle-{}+jdk-{}+lint-{}+compileSdk-{}",
            self.agp_version,
            self.gradle_version,
            self.jdk_version,
            self.lint_version,
            self.sdk
                .as_ref()
                .map(|sdk| sdk.compile_sdk.to_string())
                .unwrap_or_else(|| "missing".into()),
        )
    }

    pub fn digest(&self) -> String {
        sha256_hex(serde_json::to_string(self).unwrap_or_default().as_bytes())
    }
}

fn provenance_gaps(provenance: &TypedProvenance) -> Vec<String> {
    let mut gaps = Vec::new();
    match provenance {
        TypedProvenance::AdmittedBuild {
            receipt_id,
            artifact_digest,
        } => {
            if receipt_id.trim().is_empty() {
                gaps.push(gap("android-model-receipt-missing"));
            }
            if !is_sha256_digest(artifact_digest) {
                gaps.push(gap("android-model-artifact-unsealed"));
            }
        }
        TypedProvenance::AuthenticatedImport {
            artifact_digest,
            attestor,
            authenticated,
        } => {
            if !authenticated || attestor.trim().is_empty() {
                gaps.push(gap("android-model-import-unauthenticated"));
            }
            if !is_sha256_digest(artifact_digest) {
                gaps.push(gap("android-model-artifact-unsealed"));
            }
        }
    }
    gaps
}

/// Binding values for the A04 typed detekt provider so Lint and typed
/// detekt cover the identical variant: `(compilation_target, variant)`.
pub fn detekt_typed_binding(model: &AndroidBuildModel, variant: &str) -> Option<(String, String)> {
    let sdk = model.sdk.as_ref()?;
    Some((format!("android-{}", sdk.compile_sdk), variant.to_string()))
}

/// Digest of the inventory files under a source-set directory.
pub fn compute_source_set_digest(entries: &[InventoryEntry], dir: &str) -> Option<String> {
    let prefix = format!("{}/", dir.trim_end_matches('/'));
    let mut files: Vec<(&str, &str)> = Vec::new();
    for entry in entries.iter().filter(|e| e.path.starts_with(&prefix)) {
        files.push((entry.path.as_str(), entry.digest.as_deref()?));
    }
    if files.is_empty() {
        return None;
    }
    files.sort();
    let canonical = files
        .iter()
        .map(|(path, digest)| format!("{path}\0{digest}"))
        .collect::<Vec<_>>()
        .join("\n");
    Some(sha256_hex(canonical.as_bytes()))
}

fn capitalize(value: &str) -> String {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn expected_lint_task(module_path: &str, variant: &str) -> String {
    format!("{module_path}:lint{}", capitalize(variant))
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub enum RequiredVariants {
    /// Every modelled variant whose build type is listed (e.g. `release`).
    BuildTypes(Vec<String>),
    /// Exactly these `(module path, variant)` pairs; unknown pairs are gaps.
    Explicit(Vec<(String, String)>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExecutionRoute {
    /// Execution admitted by root/A01 for this plan; opaque receipt id.
    AdmittedProject { admission_receipt_id: String },
    /// Evidence must arrive as an authenticated import; nothing runs here.
    AuthenticatedImport,
    /// No admission and no import route: an explicit, deferrable gap.
    NotAdmitted,
}

#[derive(Clone, Debug)]
pub struct AndroidLintOptions {
    pub profile: AuditProfile,
    pub required: RequiredVariants,
    pub route: ExecutionRoute,
    /// Absolute checkout root as seen by the tool, for report paths.
    pub base_prefix: Option<String>,
    pub max_findings: usize,
}

impl AndroidLintOptions {
    pub fn new(profile: AuditProfile, route: ExecutionRoute) -> Self {
        Self {
            profile,
            required: RequiredVariants::BuildTypes(vec!["release".into()]),
            route,
            base_prefix: None,
            max_findings: MAX_LINT_FINDINGS,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LintObligation {
    /// `android-lint:<module>:<variant>`; unique per module and variant.
    pub id: String,
    pub module: String,
    pub module_dir: String,
    pub variant: String,
    pub build_type: String,
    pub flavors: Vec<String>,
    pub lint_task: String,
    pub compile_sdk: Option<u32>,
    pub min_sdk: u32,
    pub target_sdk: u32,
    pub report_xml_path: String,
    pub report_root: String,
    pub report_sarif_path: Option<String>,
    pub scope_digest: String,
    pub scope_items: Vec<String>,
    /// Structural gaps frozen at plan time; any entry blocks `Satisfied`.
    pub plan_gaps: Vec<String>,
    pub runner: Option<RunnerPlan>,
}

impl LintObligation {
    /// A02 `ObligationId.target`; module goes in `variant()` so two
    /// modules sharing a variant name never share evidence.
    pub fn obligation_target(&self) -> String {
        format!("android:{}", self.variant)
    }

    pub fn obligation_variant(&self) -> String {
        self.module.clone()
    }

    pub fn concern(&self) -> &'static str {
        CONCERN
    }

    /// Scope items an examined-scope claim (A03 `required_scope`) or a
    /// local receipt must contain verbatim.
    pub fn expected_scope(&self) -> Vec<String> {
        self.scope_items.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunnerPlan {
    pub program: String,
    pub argv: Vec<String>,
    pub accepted_exit_codes: Vec<i32>,
    pub report_path: String,
    /// See [`VariantModel::report_root`]; the runner reads `report_path` under it.
    pub report_root: String,
}

#[derive(Clone, Debug)]
pub struct AndroidLintPlan {
    pub profile: AuditProfile,
    pub applicability: ApplicabilityDecision,
    pub toolchain: Option<String>,
    pub model_digest: Option<String>,
    pub obligations: Vec<LintObligation>,
    /// Plan-wide gaps (model missing, SDK missing, module absent, ...).
    pub gaps: Vec<String>,
    pub route: ExecutionRoute,
    pub base_prefix: Option<String>,
    pub max_findings: usize,
    pub model: Option<AndroidBuildModel>,
}

impl AndroidLintPlan {
    pub fn is_applicable(&self) -> bool {
        self.applicability.applicability != Applicability::NotApplicable
    }

    /// Runner records for root's `tools.rs` dispatch. A plan, never a receipt.
    pub fn runner_records(&self) -> Vec<Value> {
        self.obligations
            .iter()
            .map(|obligation| {
                json!({
                    "providerId": PROVIDER_ID,
                    "tool": TOOL_ID,
                    "obligationId": obligation.id,
                    "module": obligation.module,
                    "variant": obligation.variant,
                    "lintTask": obligation.lint_task,
                    "programCandidates": obligation.runner.as_ref().map(|r| vec![r.program.clone()]),
                    "argv": obligation.runner.as_ref().map(|r| r.argv.clone()),
                    "acceptedExitCodes": obligation.runner.as_ref().map(|r| r.accepted_exit_codes.clone()),
                    "parser": "android-lint-xml|sarif",
                    "reportPath": obligation.report_xml_path,
                    "reportRoot": obligation.report_root,
                    "scopeDigest": obligation.scope_digest,
                    "executed": false,
                    "gaps": obligation.plan_gaps,
                })
            })
            .collect()
    }
}

fn module_inventory_gaps(module: &ModuleModel, entries: &[InventoryEntry]) -> Vec<String> {
    let mut gaps = Vec::new();
    if module.lint_excluded {
        gaps.push(gap(format!(
            "android-module-excluded:{}:{}",
            module.path,
            module.exclusion_reason.as_deref().unwrap_or("no-reason")
        )));
    }
    if let Some(message) = &module.resolution_failure {
        gaps.push(gap(format!(
            "android-gradle-resolution-failed:{}:{}",
            module.path,
            truncated_message(message)
        )));
    }
    if module.variants.is_empty() {
        gaps.push(gap(format!("android-module-no-variants:{}", module.path)));
    }
    let prefix = if module.dir.is_empty() {
        String::new()
    } else {
        format!("{}/", module.dir)
    };
    for (kind, declared, name) in [
        ("baseline", &module.baseline, "lint-baseline.xml"),
        ("config", &module.lint_config, "lint.xml"),
    ] {
        let exists = entries.iter().any(|e| e.path == format!("{prefix}{name}"));
        if exists && declared.is_none() {
            gaps.push(gap(format!(
                "android-lint-{kind}-undeclared:{}",
                module.path
            )));
        }
        if let Some(sealed) = declared {
            if !is_sha256_digest(&sealed.digest) {
                gaps.push(gap(format!("android-lint-{kind}-unsealed:{}", module.path)));
            }
        }
    }
    gaps
}

fn variant_gaps(
    model: &AndroidBuildModel,
    module: &ModuleModel,
    variant: &VariantModel,
    entries: &[InventoryEntry],
) -> Vec<String> {
    let mut gaps = Vec::new();
    let id = format!("{}:{}", module.path, variant.name);
    if variant.lint_task != expected_lint_task(&module.path, &variant.name) {
        gaps.push(gap(format!(
            "android-lint-task-identity-mismatch:{id}:{}",
            variant.lint_task
        )));
    }
    if variant.min_sdk == 0 || variant.target_sdk == 0 || variant.min_sdk > variant.target_sdk {
        gaps.push(gap(format!("android-sdk-range-invalid:{id}")));
    }
    if let Some(sdk) = &model.sdk {
        if variant.target_sdk > sdk.compile_sdk {
            gaps.push(gap(format!("android-target-sdk-above-compile-sdk:{id}")));
        }
    }
    if variant.source_sets.is_empty() {
        gaps.push(gap(format!("android-source-sets-missing:{id}")));
    }
    for set in &variant.source_sets {
        match compute_source_set_digest(entries, &set.dir) {
            None => gaps.push(gap(format!("android-source-set-empty:{id}:{}", set.name))),
            Some(actual) if actual != set.digest => gaps.push(gap(format!(
                "android-source-set-digest-mismatch:{id}:{}",
                set.name
            ))),
            Some(_) => {}
        }
    }
    for generated in &variant.generated_resources {
        if !is_sha256_digest(&generated.digest) {
            gaps.push(gap(format!(
                "android-generated-resource-unsealed:{id}:{}",
                generated.path
            )));
        }
    }
    if variant.report_xml_path.trim().is_empty() {
        gaps.push(gap(format!("android-report-path-missing:{id}")));
    }
    if !variant.report_root.is_empty() && variant.report_root != REPORT_ROOT_OWNER_OUTPUT {
        gaps.push(gap(format!("android-report-root-unknown:{id}")));
    }
    gaps
}

fn scope_items(module: &ModuleModel, variant: &VariantModel) -> Vec<String> {
    let mut items = vec![
        format!("task:{}", variant.lint_task),
        format!("module:{}", module.path),
        format!("variant:{}", variant.name),
        format!("build-type:{}", variant.build_type),
    ];
    for flavor in &variant.flavors {
        items.push(format!("flavor:{flavor}"));
    }
    for set in &variant.source_sets {
        items.push(format!("source-set:{}:{}", set.name, set.digest));
    }
    for generated in &variant.generated_resources {
        items.push(format!(
            "generated-resource:{}:{}",
            generated.path, generated.digest
        ));
    }
    items.push(format!(
        "baseline:{}",
        module
            .baseline
            .as_ref()
            .map(|b| b.digest.as_str())
            .unwrap_or("none")
    ));
    items.push(format!(
        "lint-config:{}",
        module
            .lint_config
            .as_ref()
            .map(|c| c.digest.as_str())
            .unwrap_or("none")
    ));
    items.sort();
    items
}

fn obligation_scope_digest(
    model: &AndroidBuildModel,
    module: &ModuleModel,
    variant: &VariantModel,
    items: &[String],
) -> String {
    let sdk = model
        .sdk
        .as_ref()
        .map(|sdk| {
            format!(
                "{}\0{}\0{}",
                sdk.compile_sdk, sdk.platform_digest, sdk.build_tools_version
            )
        })
        .unwrap_or_default();
    sha256_hex(
        format!(
            "{PROVIDER_ID}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            model.toolchain_label(),
            module.path,
            module.dir,
            variant.name,
            variant.min_sdk,
            variant.target_sdk,
            sdk,
            variant.report_root,
            variant.report_xml_path,
            items.join("\n"),
        )
        .as_bytes(),
    )
}

fn select_variants<'a>(
    model: &'a AndroidBuildModel,
    required: &RequiredVariants,
    gaps: &mut Vec<String>,
) -> Vec<(&'a ModuleModel, &'a VariantModel)> {
    let mut selected = Vec::new();
    match required {
        RequiredVariants::BuildTypes(build_types) => {
            for module in &model.modules {
                let before = selected.len();
                for variant in &module.variants {
                    if build_types.iter().any(|bt| *bt == variant.build_type) {
                        selected.push((module, variant));
                    }
                }
                if selected.len() == before {
                    gaps.push(gap(format!("android-no-required-variant:{}", module.path)));
                }
            }
        }
        RequiredVariants::Explicit(pairs) => {
            for (module_path, variant_name) in pairs {
                let found = model
                    .modules
                    .iter()
                    .find(|module| module.path == *module_path)
                    .and_then(|module| {
                        module
                            .variants
                            .iter()
                            .find(|variant| variant.name == *variant_name)
                            .map(|variant| (module, variant))
                    });
                match found {
                    Some(pair) => selected.push(pair),
                    None => gaps.push(gap(format!(
                        "android-required-variant-unknown:{module_path}:{variant_name}"
                    ))),
                }
            }
        }
    }
    selected
}

/// Build the frozen Lint plan. Without a model, an applicable project gets
/// exactly one `android-model-missing` gap and zero obligations — never
/// `./gradlew lint` as a stand-in.
pub fn plan_lint(
    entries: &[InventoryEntry],
    build_texts: &BTreeMap<String, String>,
    model: Option<&AndroidBuildModel>,
    options: &AndroidLintOptions,
) -> AndroidLintPlan {
    let applicability = infer_applicability(entries, build_texts);
    let mut gaps = applicability.gaps.clone();
    let mut plan = AndroidLintPlan {
        profile: options.profile,
        applicability: applicability.clone(),
        toolchain: None,
        model_digest: None,
        obligations: Vec::new(),
        gaps: Vec::new(),
        route: options.route.clone(),
        base_prefix: options.base_prefix.clone(),
        max_findings: options.max_findings,
        model: None,
    };
    if applicability.applicability == Applicability::NotApplicable {
        return plan;
    }
    let Some(model) = model else {
        gaps.push(gap("android-model-missing"));
        plan.gaps = sorted_unique(gaps);
        return plan;
    };
    gaps.extend(provenance_gaps(&model.provenance));
    for (label, value) in [
        ("agp-version", &model.agp_version),
        ("gradle-version", &model.gradle_version),
        ("jdk-version", &model.jdk_version),
        ("lint-version", &model.lint_version),
        ("gradle-program", &model.gradle_program),
    ] {
        if value.trim().is_empty() {
            gaps.push(gap(format!("android-{label}-missing")));
        }
    }
    match &model.sdk {
        None => gaps.push(gap("android-sdk-missing")),
        Some(sdk) => {
            if sdk.compile_sdk == 0 {
                gaps.push(gap("android-sdk-missing"));
            }
            if !is_sha256_digest(&sdk.platform_digest) {
                gaps.push(gap("android-sdk-platform-unsealed"));
            }
            if sdk.build_tools_version.trim().is_empty() {
                gaps.push(gap("android-build-tools-missing"));
            }
        }
    }
    // Modules that own a manifest but are absent from the model.
    let modelled_dirs: BTreeSet<&str> = model.modules.iter().map(|m| m.dir.as_str()).collect();
    for dir in &applicability.manifest_module_dirs {
        if !modelled_dirs.contains(dir.as_str()) {
            gaps.push(gap(format!(
                "android-module-missing-from-model:{}",
                if dir.is_empty() { "." } else { dir }
            )));
        }
    }
    let selected = select_variants(model, &options.required, &mut gaps);
    let mut seen = BTreeSet::new();
    for (module, variant) in selected {
        let id = format!("android-lint:{}:{}", module.path, variant.name);
        if !seen.insert(id.clone()) {
            gaps.push(gap(format!(
                "android-variant-duplicate:{}:{}",
                module.path, variant.name
            )));
            continue;
        }
        let mut plan_gaps = module_inventory_gaps(module, entries);
        plan_gaps.extend(variant_gaps(model, module, variant, entries));
        plan_gaps.extend(
            gaps.iter()
                .filter(|g| {
                    // Model-wide structural failures poison every obligation.
                    g.contains("android-sdk-")
                        || g.contains("android-model-")
                        || g.contains("-version-missing")
                        || g.contains("android-gradle-program")
                        || g.contains("android-build-tools")
                })
                .cloned(),
        );
        let items = scope_items(module, variant);
        let scope_digest = obligation_scope_digest(model, module, variant, &items);
        let plan_gaps = sorted_unique(plan_gaps);
        let route_ok = matches!(options.route, ExecutionRoute::AdmittedProject { .. });
        let runner = (route_ok && plan_gaps.is_empty()).then(|| RunnerPlan {
            program: model.gradle_program.clone(),
            argv: vec![
                variant.lint_task.clone(),
                "--no-daemon".into(),
                "--console=plain".into(),
            ],
            accepted_exit_codes: vec![EXIT_OK, EXIT_BUILD_FAILED],
            report_path: variant.report_xml_path.clone(),
            report_root: variant.report_root.clone(),
        });
        plan.obligations.push(LintObligation {
            id,
            module: module.path.clone(),
            module_dir: module.dir.clone(),
            variant: variant.name.clone(),
            build_type: variant.build_type.clone(),
            flavors: variant.flavors.clone(),
            lint_task: variant.lint_task.clone(),
            compile_sdk: model.sdk.as_ref().map(|sdk| sdk.compile_sdk),
            min_sdk: variant.min_sdk,
            target_sdk: variant.target_sdk,
            report_xml_path: variant.report_xml_path.clone(),
            report_root: variant.report_root.clone(),
            report_sarif_path: variant.report_sarif_path.clone(),
            scope_digest,
            scope_items: items,
            plan_gaps,
            runner,
        });
    }
    if matches!(options.route, ExecutionRoute::NotAdmitted) {
        gaps.push(gap("android-lint-execution-not-admitted"));
    }
    plan.toolchain = Some(model.toolchain_label());
    plan.model_digest = Some(model.digest());
    plan.model = Some(model.clone());
    plan.gaps = sorted_unique(gaps);
    plan
}

/// Plan from an owner-contained Gradle model extraction. An extraction
/// failure keeps its explicit gaps on top of the `android-model-missing` plan;
/// success rewrites each runner to the owner-pinned JDK launching the
/// digest-checked wrapper jar (never `gradlew`), offline.
pub fn plan_with_owner(
    entries: &[InventoryEntry],
    build_texts: &BTreeMap<String, String>,
    extraction: Result<&super::gradle_model::ExtractedAndroidModel, &[String]>,
    options: &AndroidLintOptions,
) -> AndroidLintPlan {
    match extraction {
        Err(extra) => {
            let mut plan = plan_lint(entries, build_texts, None, options);
            if plan.is_applicable() {
                let mut gaps = plan.gaps.clone();
                gaps.extend(extra.iter().cloned());
                plan.gaps = sorted_unique(gaps);
            }
            plan
        }
        Ok(extracted) => {
            let mut plan = plan_lint(entries, build_texts, Some(&extracted.model), options);
            for obligation in &mut plan.obligations {
                if let Some(runner) = obligation.runner.as_mut() {
                    let mut argv = extracted.runner_argv_prefix.clone();
                    argv.extend(
                        runner
                            .argv
                            .iter()
                            .filter(|a| *a != "--no-daemon" && *a != "--console=plain")
                            .cloned(),
                    );
                    runner.program = extracted.runner_program.clone();
                    runner.argv = argv;
                }
            }
            plan
        }
    }
}

/// Compile, tests, device/lifecycle and package/security stay separate
/// obligations that Lint evidence never discharges.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdjacentObligation {
    pub family: &'static str,
    pub module: String,
    pub variant: String,
    pub target: String,
    pub status: &'static str,
}

pub fn adjacent_obligations(plan: &AndroidLintPlan) -> Vec<AdjacentObligation> {
    let mut out = Vec::new();
    for obligation in &plan.obligations {
        for family in ["compile", "tests", "device-lifecycle", "package-security"] {
            out.push(AdjacentObligation {
                family,
                module: obligation.module.clone(),
                variant: obligation.variant.clone(),
                target: obligation.obligation_target(),
                status: "not-evidenced-by-lint",
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Report parsing
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LintIssue {
    pub rule_id: String,
    /// Normalized: `error` | `warning` | `note`.
    pub severity: &'static str,
    pub severity_raw: String,
    pub category: String,
    pub raw_path: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
}

#[derive(Clone, Debug, Default)]
pub struct ParsedLintReport {
    pub format: String,
    /// `X.Y.Z` from `by="lint X.Y.Z"` / SARIF driver version.
    pub lint_version: Option<String>,
    pub issues: Vec<LintIssue>,
    pub gaps: Vec<String>,
    pub report_digest: String,
}

fn normalize_severity(raw: &str) -> &'static str {
    match raw.to_ascii_lowercase().as_str() {
        "fatal" | "error" => "error",
        "warning" => "warning",
        _ => "note",
    }
}

/// Parse an Android Lint XML report. Malformed, truncated or DTD-bearing
/// documents return a parse with a named gap and no issues.
pub fn parse_lint_xml(bytes: &[u8]) -> ParsedLintReport {
    let mut parsed = ParsedLintReport {
        report_digest: sha256_hex(bytes),
        ..ParsedLintReport::default()
    };
    let root = match parse_xml(bytes) {
        Ok(root) => root,
        Err(error) => {
            parsed
                .gaps
                .push(gap(format!("android-lint-malformed-report:{error}")));
            return parsed;
        }
    };
    if root.name != "issues" {
        parsed
            .gaps
            .push(gap("android-lint-malformed-report:root-not-issues"));
        return parsed;
    }
    let format = root.attr("format").unwrap_or("").to_string();
    if !SUPPORTED_XML_FORMATS.contains(&format.as_str()) {
        parsed.gaps.push(gap(format!(
            "android-lint-unsupported-report-format:{format}"
        )));
        parsed.format = format;
        return parsed;
    }
    parsed.format = format;
    parsed.lint_version = root
        .attr("by")
        .and_then(|by| by.strip_prefix("lint "))
        .map(|v| v.trim().to_string());
    if parsed.lint_version.is_none() {
        parsed.gaps.push(gap("android-lint-version-unproven"));
    }
    for issue in root.children_named("issue") {
        let Some(rule_id) = issue.attr("id").filter(|id| !id.is_empty()) else {
            parsed.gaps.push(gap("android-lint-result-missing-rule"));
            continue;
        };
        let Some(location) = issue.children_named("location").next() else {
            parsed
                .gaps
                .push(gap("android-lint-result-missing-location"));
            continue;
        };
        let Some(file) = location.attr("file").filter(|f| !f.is_empty()) else {
            parsed
                .gaps
                .push(gap("android-lint-result-missing-location"));
            continue;
        };
        let line = location
            .attr("line")
            .and_then(|l| l.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1);
        let column = location
            .attr("column")
            .and_then(|c| c.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1);
        let severity_raw = issue.attr("severity").unwrap_or("Warning").to_string();
        parsed.issues.push(LintIssue {
            rule_id: rule_id.to_string(),
            severity: normalize_severity(&severity_raw),
            severity_raw,
            category: issue.attr("category").unwrap_or("").to_string(),
            raw_path: file.to_string(),
            line,
            column,
            message: truncated_message(issue.attr("message").unwrap_or(rule_id)),
        });
    }
    parsed
}

/// Parse an Android Lint SARIF 2.1.0 report (driver `Android Lint`).
pub fn parse_lint_sarif(bytes: &[u8]) -> ParsedLintReport {
    let mut parsed = ParsedLintReport {
        report_digest: sha256_hex(bytes),
        format: "sarif".into(),
        ..ParsedLintReport::default()
    };
    let malformed = |parsed: &mut ParsedLintReport, detail: &str| {
        parsed
            .gaps
            .push(gap(format!("android-lint-malformed-report:{detail}")));
    };
    let Ok(text) = std::str::from_utf8(bytes) else {
        malformed(&mut parsed, "not-utf8");
        return parsed;
    };
    let Ok(root) = serde_json::from_str::<Value>(text) else {
        malformed(&mut parsed, "invalid-json");
        return parsed;
    };
    if root.get("version").and_then(Value::as_str) != Some(SUPPORTED_SARIF_VERSION) {
        malformed(&mut parsed, "unsupported-sarif-version");
        return parsed;
    }
    let Some(runs) = root
        .get("runs")
        .and_then(Value::as_array)
        .filter(|r| r.len() == 1)
    else {
        malformed(&mut parsed, "runs-not-single");
        return parsed;
    };
    let run = &runs[0];
    let driver = &run["tool"]["driver"];
    if driver.get("name").and_then(Value::as_str) != Some(SARIF_DRIVER) {
        malformed(&mut parsed, "driver-not-android-lint");
        return parsed;
    }
    parsed.lint_version = driver
        .get("version")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if parsed.lint_version.is_none() {
        parsed.gaps.push(gap("android-lint-version-unproven"));
    }
    let Some(results) = run.get("results").and_then(Value::as_array) else {
        malformed(&mut parsed, "results-missing");
        return parsed;
    };
    for result in results {
        let Some(rule_id) = result.get("ruleId").and_then(Value::as_str) else {
            parsed.gaps.push(gap("android-lint-result-missing-rule"));
            continue;
        };
        let location = &result["locations"][0]["physicalLocation"];
        let uri = location["artifactLocation"]
            .get("uri")
            .and_then(Value::as_str);
        let line = location["region"]
            .get("startLine")
            .and_then(Value::as_u64)
            .filter(|l| *l >= 1);
        let (Some(uri), Some(line)) = (uri, line) else {
            parsed
                .gaps
                .push(gap("android-lint-result-missing-location"));
            continue;
        };
        let raw_level = result
            .get("level")
            .and_then(Value::as_str)
            .unwrap_or("warning");
        parsed.issues.push(LintIssue {
            rule_id: rule_id.to_string(),
            severity: normalize_severity(raw_level),
            severity_raw: raw_level.to_string(),
            category: String::new(),
            raw_path: uri.to_string(),
            line: line as usize,
            column: location["region"]
                .get("startColumn")
                .and_then(Value::as_u64)
                .unwrap_or(1) as usize,
            message: truncated_message(
                result["message"]
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or(rule_id),
            ),
        });
    }
    parsed
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BaselineEntry {
    pub rule_id: String,
    pub file: String,
    pub message: String,
}

/// Baseline XML (`lint-baseline.xml`): suppressed issues stay visible.
pub fn parse_baseline_xml(bytes: &[u8]) -> Result<Vec<BaselineEntry>, String> {
    let root = parse_xml(bytes)?;
    if root.name != "issues" {
        return Err("root-not-issues".into());
    }
    let mut entries = Vec::new();
    for issue in root.children_named("issue") {
        let rule_id = issue.attr("id").ok_or("baseline-issue-missing-id")?;
        let file = issue
            .children_named("location")
            .next()
            .and_then(|location| location.attr("file"))
            .unwrap_or("");
        entries.push(BaselineEntry {
            rule_id: rule_id.to_string(),
            file: file.to_string(),
            message: truncated_message(issue.attr("message").unwrap_or("")),
        });
    }
    Ok(entries)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigSuppression {
    pub rule_id: String,
    /// `severity-ignore` | `path-ignore`.
    pub kind: &'static str,
    pub detail: String,
}

/// `lint.xml`: only suppressions are extracted, and they stay visible.
pub fn parse_lint_config(bytes: &[u8]) -> Result<Vec<ConfigSuppression>, String> {
    let root = parse_xml(bytes)?;
    if root.name != "lint" {
        return Err("root-not-lint".into());
    }
    let mut out = Vec::new();
    for issue in root.children_named("issue") {
        let id = issue.attr("id").unwrap_or("all").to_string();
        if issue
            .attr("severity")
            .map(|s| s.eq_ignore_ascii_case("ignore"))
            == Some(true)
        {
            out.push(ConfigSuppression {
                rule_id: id.clone(),
                kind: "severity-ignore",
                detail: String::new(),
            });
        }
        for ignore in issue.children_named("ignore") {
            out.push(ConfigSuppression {
                rule_id: id.clone(),
                kind: "path-ignore",
                detail: ignore
                    .attr("path")
                    .or_else(|| ignore.attr("regexp"))
                    .unwrap_or("")
                    .to_string(),
            });
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Evidence & evaluation
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReportFormat {
    Xml,
    Sarif,
}

#[derive(Clone, Debug)]
pub enum LintEvidenceSource {
    /// Admitted local run, linked to its sealed execution receipt.
    LocalRun {
        receipt: ReceiptLink,
        exit_code: Option<i32>,
    },
    /// A03-verified import. Only `record.authenticated` (set solely by
    /// `verify_artifact_evidence`) can satisfy an obligation.
    Import { record: ImportedEvidenceRecord },
    /// A report file with no receipt or attestation. Never satisfies.
    UnsignedFile,
}

#[derive(Clone, Debug)]
pub struct LintEvidence {
    pub module: String,
    pub variant: String,
    pub lint_task: String,
    pub toolchain: String,
    /// Scope items the producing run attests it covered (local runs);
    /// imports use the verified record's examined/missing scope instead.
    pub examined_scope: Vec<String>,
    pub format: ReportFormat,
    pub report: Vec<u8>,
    pub source: LintEvidenceSource,
}

/// Module-level auxiliary files root read from the frozen tree.
#[derive(Clone, Debug, Default)]
pub struct AuxFiles {
    /// Module Gradle path to `lint-baseline.xml` bytes.
    pub baselines: BTreeMap<String, Vec<u8>>,
    pub lint_configs: BTreeMap<String, Vec<u8>>,
    /// Previously reviewed baseline digest per module; a differing digest
    /// is `android-lint-baseline-changed`, an absent one `-unreviewed`.
    pub approved_baseline_digests: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ObligationStatus {
    /// Qualified evidence, zero findings, no gaps.
    Satisfied,
    /// Qualified evidence with findings, no gaps.
    Findings,
    /// No evidence offered for this module/variant.
    Missing,
    /// Evidence offered but not qualifying; gaps say why.
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LintCandidate {
    pub module: String,
    pub variant: String,
    pub rule_id: String,
    pub severity: &'static str,
    pub path: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub generated: bool,
    pub evidence_identity: String,
}

#[derive(Clone, Debug)]
pub struct ObligationResult {
    pub obligation_id: String,
    pub module: String,
    pub variant: String,
    pub status: ObligationStatus,
    pub authenticated: bool,
    pub candidates: Vec<LintCandidate>,
    pub baseline_suppressed: Vec<BaselineEntry>,
    pub config_suppressions: Vec<ConfigSuppression>,
    pub gaps: Vec<String>,
    pub report_digest: Option<String>,
    pub scope_digest: String,
}

#[derive(Clone, Debug)]
pub struct AndroidLintEvaluation {
    pub profile: AuditProfile,
    pub applicable: bool,
    pub obligations: Vec<ObligationResult>,
    /// Plan-wide plus evidence-matching gaps.
    pub gaps: Vec<String>,
    /// Every obligation qualified and no gap anywhere.
    pub complete: bool,
    /// True only when `complete` and no findings.
    pub clean: bool,
    /// Lint-deferred obligations (pre-pr only); never counted as complete.
    pub deferred: Vec<String>,
    /// Whether the selected profile may proceed. Release/Repository need
    /// `complete`; pre-pr may proceed while only deferrable gaps remain.
    pub profile_satisfied: bool,
    pub claim_limits: Vec<&'static str>,
}

fn is_deferrable(gap_text: &str) -> bool {
    [
        "android-model-missing",
        "android-lint-evidence-missing",
        "android-lint-execution-not-admitted",
    ]
    .iter()
    .any(|kind| gap_text.ends_with(&format!(":{kind}")) || gap_text.contains(&format!(":{kind}:")))
}

/// Resolve a report/baseline path to an inventory path, or a build-output
/// path (generated). `None` means unresolved or outside the denominator.
fn resolve_path(
    raw: &str,
    base_prefix: Option<&str>,
    module_dir: &str,
    inventory: &BTreeSet<&str>,
) -> Option<(String, bool)> {
    let path = normalize_report_path(raw, base_prefix)?;
    if inventory.contains(path.as_str()) {
        return Some((path, false));
    }
    if !module_dir.is_empty() && !path.starts_with(&format!("{module_dir}/")) {
        let joined = format!("{module_dir}/{path}");
        if inventory.contains(joined.as_str()) {
            return Some((joined, false));
        }
        if in_build_output(&path) {
            return Some((joined, true));
        }
    }
    if in_build_output(&path) {
        return Some((path, true));
    }
    None
}

fn candidate_identity(obligation: &LintObligation, issue: &LintIssue, path: &str) -> String {
    sha256_hex(
        format!(
            "{PROVIDER_ID}\0{}\0{}\0{}\0{path}\0{}\0{}",
            obligation.module, obligation.variant, issue.rule_id, issue.line, issue.column
        )
        .as_bytes(),
    )
}

struct ModuleAux {
    gaps: Vec<String>,
    suppressed: Vec<BaselineEntry>,
    config: Vec<ConfigSuppression>,
}

fn module_aux(
    plan: &AndroidLintPlan,
    module_path: &str,
    module_dir: &str,
    aux: &AuxFiles,
    inventory: &BTreeSet<&str>,
) -> ModuleAux {
    let mut out = ModuleAux {
        gaps: Vec::new(),
        suppressed: Vec::new(),
        config: Vec::new(),
    };
    let Some(module) = plan
        .model
        .as_ref()
        .and_then(|model| model.modules.iter().find(|m| m.path == module_path))
    else {
        return out;
    };
    match (&module.baseline, aux.baselines.get(module_path)) {
        (Some(declared), Some(bytes)) => {
            let digest = sha256_hex(bytes);
            if digest != declared.digest {
                out.gaps
                    .push(gap(format!("android-lint-baseline-mismatch:{module_path}")));
            }
            match aux.approved_baseline_digests.get(module_path) {
                Some(approved) if *approved == digest => {}
                Some(_) => out
                    .gaps
                    .push(gap(format!("android-lint-baseline-changed:{module_path}"))),
                None => out.gaps.push(gap(format!(
                    "android-lint-baseline-unreviewed:{module_path}"
                ))),
            }
            match parse_baseline_xml(bytes) {
                Ok(entries) => {
                    for entry in &entries {
                        let live = !entry.file.is_empty()
                            && resolve_path(&entry.file, None, module_dir, inventory)
                                .map(|(_, generated)| !generated)
                                .unwrap_or(false);
                        if !entry.file.is_empty() && !live {
                            out.gaps.push(gap(format!(
                                "android-lint-baseline-stale:{module_path}:{}:{}",
                                entry.rule_id, entry.file
                            )));
                        }
                    }
                    out.suppressed = entries;
                }
                Err(error) => out.gaps.push(gap(format!(
                    "android-lint-baseline-malformed:{module_path}:{error}"
                ))),
            }
        }
        (Some(_), None) => out
            .gaps
            .push(gap(format!("android-lint-baseline-unread:{module_path}"))),
        (None, Some(_)) => out.gaps.push(gap(format!(
            "android-lint-baseline-undeclared:{module_path}"
        ))),
        (None, None) => {}
    }
    match (&module.lint_config, aux.lint_configs.get(module_path)) {
        (Some(declared), Some(bytes)) => {
            if sha256_hex(bytes) != declared.digest {
                out.gaps
                    .push(gap(format!("android-lint-config-mismatch:{module_path}")));
            }
            match parse_lint_config(bytes) {
                Ok(config) => out.config = config,
                Err(error) => out.gaps.push(gap(format!(
                    "android-lint-config-malformed:{module_path}:{error}"
                ))),
            }
        }
        (Some(_), None) => out
            .gaps
            .push(gap(format!("android-lint-config-unread:{module_path}"))),
        (None, Some(_)) => out
            .gaps
            .push(gap(format!("android-lint-config-undeclared:{module_path}"))),
        (None, None) => {}
    }
    out.gaps = sorted_unique(out.gaps);
    out
}

fn check_evidence(
    plan: &AndroidLintPlan,
    obligation: &LintObligation,
    evidence: &LintEvidence,
    now: &str,
    gaps: &mut Vec<String>,
    parsed: &ParsedLintReport,
) -> bool {
    let id = &obligation.id;
    if evidence.lint_task != obligation.lint_task {
        gaps.push(gap(format!("android-lint-task-mismatch:{id}")));
    }
    if plan.toolchain.as_deref() != Some(evidence.toolchain.as_str()) {
        gaps.push(gap(format!("android-lint-toolchain-mismatch:{id}")));
    }
    let (examined, missing): (Vec<String>, Vec<String>) = match &evidence.source {
        LintEvidenceSource::Import { record } => {
            (record.examined_scope.clone(), record.missing_scope.clone())
        }
        _ => (evidence.examined_scope.clone(), Vec::new()),
    };
    let examined: BTreeSet<&String> = examined.iter().collect();
    for item in &obligation.scope_items {
        if !examined.contains(item) {
            gaps.push(gap(format!("android-lint-scope-incomplete:{id}:{item}")));
        }
    }
    if !missing.is_empty() {
        gaps.push(gap(format!("android-lint-scope-missing:{id}")));
    }
    if let Some(model) = &plan.model {
        match parsed.lint_version.as_deref() {
            Some(version) if version == model.lint_version => {}
            Some(version) => {
                gaps.push(gap(format!("android-lint-version-mismatch:{id}:{version}")))
            }
            None => {}
        }
    }
    let has_error = parsed.issues.iter().any(|issue| issue.severity == "error");
    let mut authenticated = false;
    match &evidence.source {
        LintEvidenceSource::UnsignedFile => {
            gaps.push(gap(format!("android-lint-evidence-unauthenticated:{id}")));
        }
        LintEvidenceSource::LocalRun { receipt, exit_code } => {
            if !matches!(plan.route, ExecutionRoute::AdmittedProject { .. }) {
                gaps.push(gap(format!("android-lint-local-run-not-admitted:{id}")));
            }
            if receipt.receipt_id.as_deref().is_none_or(str::is_empty)
                || receipt.report_artifact_digest.as_deref() != Some(parsed.report_digest.as_str())
            {
                gaps.push(gap(format!("android-lint-receipt-link-missing:{id}")));
            }
            if receipt
                .executable_digest
                .as_deref()
                .is_none_or(|digest| !is_sha256_digest(digest))
            {
                gaps.push(gap(format!("android-lint-executable-unsealed:{id}")));
            }
            match exit_code {
                Some(EXIT_OK) => {}
                Some(EXIT_BUILD_FAILED) => {
                    if !has_error {
                        gaps.push(gap(format!("android-lint-exit-without-errors:{id}")));
                    }
                }
                Some(code) => gaps.push(gap(format!("android-lint-tool-failed:{id}:exit-{code}"))),
                None => gaps.push(gap(format!("android-lint-tool-failed:{id}:no-exit"))),
            }
            authenticated = !gaps.iter().any(|g| g.contains("receipt-link-missing"));
        }
        LintEvidenceSource::Import { record } => {
            if !record.authenticated {
                gaps.push(gap(format!("android-lint-evidence-unauthenticated:{id}")));
            }
            authenticated = record.authenticated;
            if !matches!(record.kind, ImportKind::Sarif | ImportKind::Artifact) {
                gaps.push(gap(format!(
                    "android-lint-import-kind:{id}:{}",
                    record.kind.label()
                )));
            }
            if record.target != obligation.obligation_target()
                || record.variant.as_deref() != Some(obligation.module.as_str())
            {
                gaps.push(gap(format!("android-lint-import-subject-mismatch:{id}")));
            }
            if record.toolchain != evidence.toolchain {
                gaps.push(gap(format!("android-lint-toolchain-mismatch:{id}")));
            }
            if !record
                .artifacts
                .iter()
                .any(|artifact| artifact.digest == parsed.report_digest)
            {
                gaps.push(gap(format!("android-lint-import-artifact-mismatch:{id}")));
            }
            if matches!(
                record.outcome,
                EvidenceOutcome::Failed | EvidenceOutcome::Error
            ) {
                gaps.push(gap(format!("android-lint-import-outcome:{id}")));
            }
            if !record.newly_executed || record.replay_of.is_some() {
                gaps.push(gap(format!("android-lint-replayed-evidence:{id}")));
            }
            if !is_rfc3339_utc_second(now) || record.fresh_until.as_str() < now {
                gaps.push(gap(format!("android-lint-evidence-stale:{id}")));
            }
        }
    }
    authenticated
}

/// Evaluate offered evidence against the frozen plan, one obligation at a
/// time. Evidence for one variant or module never discharges another.
pub fn evaluate_lint(
    plan: &AndroidLintPlan,
    entries: &[InventoryEntry],
    evidence: &[LintEvidence],
    aux: &AuxFiles,
    now: &str,
) -> AndroidLintEvaluation {
    let inventory: BTreeSet<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    let mut gaps = plan.gaps.clone();
    let mut by_key: BTreeMap<(&str, &str), Vec<&LintEvidence>> = BTreeMap::new();
    for item in evidence {
        by_key
            .entry((item.module.as_str(), item.variant.as_str()))
            .or_default()
            .push(item);
    }
    let known: BTreeSet<(&str, &str)> = plan
        .obligations
        .iter()
        .map(|o| (o.module.as_str(), o.variant.as_str()))
        .collect();
    for (module, variant) in by_key.keys() {
        if !known.contains(&(*module, *variant)) {
            gaps.push(gap(format!(
                "android-lint-evidence-unmatched:{module}:{variant}"
            )));
        }
    }
    let mut results = Vec::new();
    for obligation in &plan.obligations {
        let mut ob_gaps = obligation.plan_gaps.clone();
        let module_aux = module_aux(
            plan,
            &obligation.module,
            &obligation.module_dir,
            aux,
            &inventory,
        );
        ob_gaps.extend(module_aux.gaps.clone());
        let offered = by_key
            .get(&(obligation.module.as_str(), obligation.variant.as_str()))
            .cloned()
            .unwrap_or_default();
        let mut result = ObligationResult {
            obligation_id: obligation.id.clone(),
            module: obligation.module.clone(),
            variant: obligation.variant.clone(),
            status: ObligationStatus::Missing,
            authenticated: false,
            candidates: Vec::new(),
            baseline_suppressed: module_aux.suppressed,
            config_suppressions: module_aux.config,
            gaps: Vec::new(),
            report_digest: None,
            scope_digest: obligation.scope_digest.clone(),
        };
        if offered.len() > 1 {
            ob_gaps.push(gap(format!(
                "android-lint-evidence-duplicate:{}",
                obligation.id
            )));
        }
        let Some(item) = offered.first() else {
            ob_gaps.push(gap(format!(
                "android-lint-evidence-missing:{}",
                obligation.id
            )));
            result.gaps = sorted_unique(ob_gaps);
            results.push(result);
            continue;
        };
        let mut parsed = match item.format {
            ReportFormat::Xml => parse_lint_xml(&item.report),
            ReportFormat::Sarif => parse_lint_sarif(&item.report),
        };
        ob_gaps.extend(parsed.gaps.clone());
        result.report_digest = Some(parsed.report_digest.clone());
        result.authenticated = check_evidence(plan, obligation, item, now, &mut ob_gaps, &parsed);
        let mut truncated = 0usize;
        let issues = std::mem::take(&mut parsed.issues);
        for issue in &issues {
            let Some((path, generated)) = resolve_path(
                &issue.raw_path,
                plan.base_prefix.as_deref(),
                &obligation.module_dir,
                &inventory,
            ) else {
                ob_gaps.push(gap(format!(
                    "android-lint-location-unresolved:{}:{}",
                    obligation.id, issue.raw_path
                )));
                continue;
            };
            if result.candidates.len() >= plan.max_findings {
                truncated += 1;
                continue;
            }
            result.candidates.push(LintCandidate {
                module: obligation.module.clone(),
                variant: obligation.variant.clone(),
                rule_id: issue.rule_id.clone(),
                severity: issue.severity,
                evidence_identity: candidate_identity(obligation, issue, &path),
                path,
                line: issue.line,
                column: issue.column,
                message: issue.message.clone(),
                generated,
            });
        }
        if truncated > 0 {
            ob_gaps.push(gap(format!(
                "android-lint-findings-truncated:{}:{truncated}",
                obligation.id
            )));
        }
        // A report that names issues in files the plan did not freeze is
        // not rescued by a clean-looking remainder.
        result.gaps = sorted_unique(ob_gaps);
        result.status = if !result.gaps.is_empty() {
            ObligationStatus::Rejected
        } else if result.candidates.is_empty() {
            ObligationStatus::Satisfied
        } else {
            ObligationStatus::Findings
        };
        results.push(result);
    }
    let mut deferred = Vec::new();
    let mut all_gaps = gaps;
    for result in &results {
        all_gaps.extend(result.gaps.clone());
    }
    let all_gaps = sorted_unique(all_gaps);
    let obligations_ok = results.iter().all(|r| {
        matches!(
            r.status,
            ObligationStatus::Satisfied | ObligationStatus::Findings
        )
    });
    let applicable = plan.is_applicable();
    let complete = applicable && !results.is_empty() && obligations_ok && all_gaps.is_empty();
    let any_findings = results.iter().any(|r| !r.candidates.is_empty());
    let profile_satisfied = if !applicable {
        true
    } else if complete {
        true
    } else if plan.profile == AuditProfile::PrePr && all_gaps.iter().all(|g| is_deferrable(g)) {
        for obligation in &plan.obligations {
            deferred.push(obligation.id.clone());
        }
        if plan.obligations.is_empty() {
            deferred.push("android-lint:all-variants-unenumerated".to_string());
        }
        true
    } else {
        false
    };
    AndroidLintEvaluation {
        profile: plan.profile,
        applicable,
        obligations: results,
        gaps: all_gaps,
        complete,
        clean: complete && !any_findings,
        deferred,
        profile_satisfied,
        claim_limits: vec!["compile", "tests", "device-lifecycle", "package-security"],
    }
}

impl AndroidLintEvaluation {
    /// Findings for `code.*` evidence plumbing; only from obligations whose
    /// evidence qualified (no gaps).
    pub fn native_findings(&self) -> Vec<NativeFinding> {
        self.obligations
            .iter()
            .filter(|r| {
                matches!(
                    r.status,
                    ObligationStatus::Satisfied | ObligationStatus::Findings
                )
            })
            .flat_map(|r| r.candidates.iter())
            .map(|candidate| NativeFinding {
                rule: Cow::Owned(format!("android-lint/{}", candidate.rule_id)),
                severity: candidate.severity,
                path: candidate.path.clone(),
                line: candidate.line,
                message: format!(
                    "[{}:{}] {}",
                    candidate.module, candidate.variant, candidate.message
                ),
            })
            .collect()
    }

    /// Projection root maps onto A02 obligation evidence.
    pub fn to_value(&self) -> Value {
        json!({
            "providerId": PROVIDER_ID,
            "profile": self.profile.as_str(),
            "applicable": self.applicable,
            "complete": self.complete,
            "clean": self.clean,
            "profileSatisfied": self.profile_satisfied,
            "deferred": self.deferred,
            "gaps": self.gaps,
            "claimLimits": self.claim_limits,
            "obligations": self.obligations.iter().map(|r| json!({
                "obligationId": r.obligation_id,
                "module": r.module,
                "variant": r.variant,
                "status": r.status,
                "authenticated": r.authenticated,
                "findings": r.candidates.len(),
                "baselineSuppressed": r.baseline_suppressed.len(),
                "configSuppressions": r.config_suppressions.len(),
                "reportDigest": r.report_digest,
                "scopeDigest": r.scope_digest,
                "gaps": r.gaps,
            })).collect::<Vec<_>>(),
        })
    }
}

// ---------------------------------------------------------------------------
// Platform facts for security/platform lenses
// ---------------------------------------------------------------------------

/// A parsed fact, never a finding or a clean claim. Existing
/// security/platform lenses decide what a fact means.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformFact {
    pub lens: &'static str,
    pub kind: String,
    pub subject: String,
    pub detail: String,
    pub path: String,
    pub line: Option<usize>,
}

fn fact(kind: &str, subject: &str, detail: &str, path: &str, lens: &'static str) -> PlatformFact {
    PlatformFact {
        lens,
        kind: kind.into(),
        subject: subject.into(),
        detail: detail.into(),
        path: path.into(),
        line: None,
    }
}

const COMPONENT_TAGS: &[&str] = &[
    "activity",
    "activity-alias",
    "service",
    "receiver",
    "provider",
];

/// Extract exported-component, permission, cleartext, debuggable, backup
/// and deep-link facts from one manifest.
pub fn manifest_facts(path: &str, bytes: &[u8]) -> Result<Vec<PlatformFact>, String> {
    let root = parse_xml(bytes)?;
    if root.name != "manifest" {
        return Err("root-not-manifest".into());
    }
    let mut facts = Vec::new();
    for tag in ["uses-permission", "uses-permission-sdk-23"] {
        for permission in root.children_named(tag) {
            if let Some(name) = permission.attr("android:name") {
                facts.push(fact("permission-requested", name, "", path, "security"));
            }
        }
    }
    for application in root.children_named("application") {
        for (attr, kind) in [
            ("android:usesCleartextTraffic", "cleartext-traffic"),
            ("android:debuggable", "debuggable"),
            ("android:allowBackup", "backup"),
        ] {
            if let Some(value) = application.attr(attr) {
                facts.push(fact(kind, "application", value, path, "security"));
            }
        }
        for component in application
            .children
            .iter()
            .filter(|child| COMPONENT_TAGS.contains(&child.name.as_str()))
        {
            let name = component.attr("android:name").unwrap_or("");
            let has_filter = component.children_named("intent-filter").next().is_some();
            let exported = component.attr("android:exported");
            match exported {
                Some("true") => {
                    facts.push(fact(
                        "exported-component",
                        name,
                        &component.name,
                        path,
                        "security",
                    ));
                    if component.attr("android:permission").is_none() {
                        facts.push(fact(
                            "exported-without-permission",
                            name,
                            &component.name,
                            path,
                            "security",
                        ));
                    }
                }
                None if has_filter => facts.push(fact(
                    "implicit-export-undeclared",
                    name,
                    &component.name,
                    path,
                    "platform",
                )),
                _ => {}
            }
            for filter in component.children_named("intent-filter") {
                let browsable = filter.children_named("category").any(|category| {
                    category.attr("android:name") == Some("android.intent.category.BROWSABLE")
                });
                let view = filter.children_named("action").any(|action| {
                    action.attr("android:name") == Some("android.intent.action.VIEW")
                });
                if browsable && view {
                    for data in filter.children_named("data") {
                        let scheme = data.attr("android:scheme").unwrap_or("");
                        let host = data.attr("android:host").unwrap_or("");
                        facts.push(fact(
                            "deep-link",
                            name,
                            &format!(
                                "{scheme}://{host} autoVerify={}",
                                filter.attr("android:autoVerify").unwrap_or("false")
                            ),
                            path,
                            "security",
                        ));
                    }
                }
            }
        }
    }
    Ok(facts)
}

/// Line-level WebView facts from Kotlin/Java source text.
pub fn webview_source_facts(path: &str, text: &str) -> Vec<PlatformFact> {
    const MARKERS: &[(&str, &str)] = &[
        ("setJavaScriptEnabled(true)", "webview-javascript-enabled"),
        ("javaScriptEnabled = true", "webview-javascript-enabled"),
        ("addJavascriptInterface", "webview-javascript-interface"),
        ("setAllowFileAccess(true)", "webview-file-access"),
        ("allowFileAccess = true", "webview-file-access"),
        (
            "setAllowUniversalAccessFromFileURLs(true)",
            "webview-universal-file-access",
        ),
        ("loadUrl(\"http://", "webview-cleartext-url"),
        (
            "MIXED_CONTENT_ALWAYS_ALLOW",
            "webview-mixed-content-allowed",
        ),
    ];
    let mut facts = Vec::new();
    for (index, line) in text.lines().enumerate() {
        for (marker, kind) in MARKERS {
            if line.contains(marker) {
                let mut found = fact(kind, "WebView", line.trim(), path, "security");
                found.line = Some(index + 1);
                facts.push(found);
            }
        }
    }
    facts
}
