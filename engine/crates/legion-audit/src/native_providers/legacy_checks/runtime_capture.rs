//! Runtime capture for `legacy.runtime.app`.
//!
//! The historical `audit-runtime` tool is not shipped. This module replaces it
//! with the running Legion executable's own browser route (`legion script
//! qa/qa-functional`): one authorized external-tool invocation per requested
//! surface, each carrying a real process receipt. Per surface the route loads
//! the URL at the requested viewport, verifies the document actually loaded
//! (not a browser error page, no HTTP error status), writes a screenshot into
//! the run's scratch (or `--out`) directory and reports console errors and
//! exceptions seen during the load.
//!
//! Each surface captures navigation, viewport screenshot, console output,
//! navigation/paint metrics, and axe WCAG 2 A/AA findings. Metrics and axe
//! output come from `[qa] N:eval value <json>` lines before `actions complete`,
//! so console text cannot fake evidence. Missing or invalid results become
//! typed gaps; a failed axe action does not discard completed screenshot or
//! performance evidence. Findings are bounded, with excess axe output marked
//! as truncated rather than clean.
//!
//! `wf_port::wf064::runtime::ChromeRuntimeDriver` is deliberately not used:
//! it holds an in-process browser outside the process-receipt path, types
//! and clicks into the audited app, and injects its instrumentation before
//! navigation, where it does not survive.
//!
//! - a11y: axe-core 4.14.0 is bundled as the default; a project-installed copy
//!   overrides it. Both run the historical WCAG 2 A/AA tag set.
//!
//! Frozen fixture interactions use RightKit's owned `FixtureSession`, with
//! native confinement, session-issued attestations & terminal cleanup evidence.
//! Fixture-only requests require no external-tool capability; fixture probes
//! never count as live screenshot, accessibility or performance evidence.
//!
//! Inputs (`--url`, `--surfaces`, `--width`, `--height`) arrive through the
//! provider's frozen `runner.runtime` object, so they are covered by the plan
//! seal. Without a URL the provider is `unavailable:runtime-url-not-supplied`.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::atomic::Ordering,
};

use legion_contracts::{Coverage, ProviderId, ProviderResult, ProviderStatus};
use legion_provider_sdk::{
    ExecutionReceipt, ExecutionState, ExternalProjectTool, ExternalToolRequest,
};
use rightkit_browser::{
    actions_digest as fixture_actions_digest, FixtureAction, FixtureAttestation, FixtureBundle,
    FixtureCancellation, FixtureFile, FixtureIntent, FixtureOutcome, FixtureOutcomeStatus,
    FixtureRunFailure, FixtureServer, FixtureSession, FIXTURE_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::{
    audit_environment, command_parts, empty_output, push_finding, readable_artifact,
    resolver::RUNTIME_CAPTURE_TOOL, safe_location, spec, LegacyCheckInput,
    NativeLegacyCheckExecutor, AUDIT_ARTIFACT_SEQUENCE,
};
use crate::{error::AuditError, native_providers::availability, plan::AuditProvider};

/// Reason reported when the operator supplied no `--url`.
pub(super) const UNAVAILABLE_URL: &str = "runtime-url-not-supplied";

const MAX_EXTRA_SURFACES: usize = 32;
const MAX_INTERACTIONS: usize = 8;
const MAX_ACTIONS_PER_INTERACTION: usize = 8;
const MAX_INTERACTION_ACTIONS: usize = 32;
const MAX_INTERACTION_STRING: usize = 2048;
const MAX_FROZEN_INTERACTION_CONFIG_BYTES: usize = 16 * 1024 * 1024;
const MAX_DIMENSION: u64 = 16_384;
const DEFAULT_WIDTH: u32 = 1280;
const DEFAULT_HEIGHT: u32 = 800;
const BUNDLED_AXE_VERSION: &str = "4.14.0";
const BUNDLED_AXE_SOURCE: &str = include_str!("../../../assets/axe-core-4.14.0.min.js");

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

/// Evaluated in the loaded page before the screenshot. It fails the run when
/// the browser is showing its own error page (connection refused, DNS, TLS)
/// or the navigation response carried an HTTP error status.
const LOAD_CHECK: &str = "(() => { const nav = performance.getEntriesByType('navigation')[0]; const status = nav && nav.responseStatus ? nav.responseStatus : 0; return { ok: !location.href.startsWith('chrome-error:') && !(status >= 400), href: location.href, status: status }; })()";

/// The route's 1-based label for the performance action: the third action
/// of every surface (see `capture_surface`), printed as `[qa] 3:eval value`.
const PERFORMANCE_ACTION_LABEL: usize = 3;
/// The fourth action runs axe after screenshot capture, preserving legacy
/// action indices for load, screenshot, and performance.
const A11Y_ACTION_LABEL: usize = 4;

/// Evaluated after the screenshot. It returns
/// one object of numbers, with `null` for entries the browser did not expose. It
/// never throws (a throw would fail the whole surface, screenshot included), and
/// it carries no `ok` key, so the route never treats it as a failed assertion.
const PERFORMANCE_METRICS: &str = "(() => { try { const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? Math.round(v * 100) / 100 : null); const nav = performance.getEntriesByType('navigation')[0]; const fcp = performance.getEntriesByType('paint').find((e) => e.name === 'first-contentful-paint'); const resources = performance.getEntriesByType('resource'); let transfer = 0; for (const e of resources) { transfer += typeof e.transferSize === 'number' ? e.transferSize : 0; } return { domContentLoaded: nav ? num(nav.domContentLoadedEventEnd) : null, loadEventEnd: nav ? num(nav.loadEventEnd) : null, responseStart: nav ? num(nav.responseStart) : null, ttfb: nav ? num(nav.responseStart) : null, firstContentfulPaint: fcp ? num(fcp.startTime) : null, transferSize: num(transfer), resourceCount: resources.length }; } catch (e) { return null; } })()";

/// Validated inputs of one runtime capture (`runner.runtime`).
#[derive(Clone, Debug, Eq, PartialEq)]
struct RuntimeParams {
    url: String,
    /// Additional surfaces beyond the entry URL: `(label, url)`.
    surfaces: Vec<(String, String)>,
    width: u32,
    height: u32,
    unsupported: Vec<String>,
    interactions: Vec<InteractionProbe>,
    artifact_dir: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InteractionProbe {
    id: String,
    surface_label: String,
    surface_url: String,
    fixture_id: String,
    fixture_source_digest: String,
    fixture_inventory_digest: String,
    fixture_files: Vec<Value>,
    probe_id: String,
    actions_digest: String,
    isolation_binding_id: String,
    expires_after_ms: u64,
    actions: Vec<Value>,
}

impl RuntimeParams {
    /// `Ok(None)` when no URL was supplied; `Err(reason)` for invalid inputs.
    fn from_value(value: &Value) -> Result<Option<Self>, String> {
        let Some(object) = value.as_object() else {
            return Ok(None);
        };
        let url = match object.get("url").and_then(Value::as_str) {
            Some(url) if !url.trim().is_empty() => url.trim().to_owned(),
            _ => return Ok(None),
        };
        check_url(&url)?;
        let width = dimension(object.get("width"), DEFAULT_WIDTH, "width")?;
        let height = dimension(object.get("height"), DEFAULT_HEIGHT, "height")?;
        let mut surfaces = Vec::new();
        if let Some(items) = object.get("surfaces") {
            let items = items
                .as_array()
                .ok_or_else(|| "surfaces-not-an-array".to_owned())?;
            if items.len() > MAX_EXTRA_SURFACES {
                return Err("too-many-surfaces".into());
            }
            for item in items {
                let label = item
                    .get("label")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|label| !label.is_empty())
                    .ok_or_else(|| "surface-label-missing".to_owned())?;
                let surface_url = item
                    .get("url")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .ok_or_else(|| "surface-url-missing".to_owned())?;
                check_url(surface_url)?;
                surfaces.push((label.to_owned(), surface_url.to_owned()));
            }
        }
        let unsupported = match object.get("unsupportedSurfaces") {
            None | Some(Value::Null) => Vec::new(),
            Some(items) => items
                .as_array()
                .ok_or_else(|| "unsupported-surfaces-not-an-array".to_owned())?
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
        };
        let interactions = parse_interactions(object.get("interactions"), &url, &surfaces)?;
        let artifact_dir = match object.get("artifactDir") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let path = PathBuf::from(
                    value
                        .as_str()
                        .ok_or_else(|| "artifact-dir-not-a-string".to_owned())?,
                );
                if !path.is_absolute() {
                    return Err("artifact-dir-not-absolute".into());
                }
                Some(path)
            }
        };
        Ok(Some(Self {
            url,
            surfaces,
            width,
            height,
            unsupported,
            interactions,
            artifact_dir,
        }))
    }

    fn from_provider(provider: &AuditProvider) -> Result<Option<Self>, String> {
        match provider
            .configuration
            .get("runner")
            .and_then(|runner| runner.get("runtime"))
        {
            Some(value) => Self::from_value(value),
            None => Ok(None),
        }
    }

    /// Entry surface first, then the requested extras, in order.
    fn all_surfaces(&self) -> Vec<(String, String)> {
        let mut all = vec![("entry".to_owned(), self.url.clone())];
        all.extend(self.surfaces.iter().cloned());
        all
    }

    fn fixture_bound_surface_urls(&self) -> BTreeSet<String> {
        self.interactions
            .iter()
            .map(|probe| probe.surface_url.clone())
            .collect()
    }

    fn live_surfaces(&self) -> Vec<(usize, String, String)> {
        let fixture_urls = self.fixture_bound_surface_urls();
        self.all_surfaces()
            .into_iter()
            .enumerate()
            .filter(|(_, (_, url))| !fixture_urls.contains(url))
            .map(|(index, (label, url))| (index, label, url))
            .collect()
    }

    fn to_value(&self) -> Value {
        json!({
            "url": self.url,
            "width": self.width,
            "height": self.height,
            "surfaces": self.surfaces.iter().map(|(label, url)| json!({"label": label, "url": url})).collect::<Vec<_>>(),
            "unsupportedSurfaces": self.unsupported,
            "interactions": self.interactions.iter().map(InteractionProbe::to_value).collect::<Vec<_>>(),
            "artifactDir": self.artifact_dir.as_ref().map(|path| path.to_string_lossy().into_owned()),
        })
    }
}

impl InteractionProbe {
    fn to_value(&self) -> Value {
        json!({
            "id": self.id,
            "surface": {"label": self.surface_label, "url": self.surface_url},
            "fixture": {
                "id": self.fixture_id,
                "sourceDigest": self.fixture_source_digest,
                "inventoryDigest": self.fixture_inventory_digest,
                "files": self.fixture_files,
            },
            "probe": {"id": self.probe_id, "actionsDigest": self.actions_digest},
            "isolationBindingId": self.isolation_binding_id,
            "expiresAfterMs": self.expires_after_ms,
            "actions": self.actions,
        })
    }

    fn result_value(&self) -> Value {
        let mut value = self.to_value();
        value["fixture"] = json!({
            "id": self.fixture_id,
            "sourceDigest": self.fixture_source_digest,
            "inventoryDigest": self.fixture_inventory_digest,
            "fileCount": self.fixture_files.len(),
        });
        value["status"] = json!("unavailable");
        value["reason"] = json!("rightkit-fixture-api-unavailable");
        value
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn exact_keys(value: &Value, required: &[&str], optional: &[&str]) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    required.iter().all(|key| object.contains_key(*key))
        && object
            .keys()
            .all(|key| required.contains(&key.as_str()) || optional.contains(&key.as_str()))
}

fn json_encoded_len(value: &Value) -> Option<usize> {
    match value {
        Value::Null => Some(4),
        Value::Bool(value) => Some(if *value { 4 } else { 5 }),
        Value::Number(value) => Some(value.to_string().len()),
        Value::String(value) => serde_json::to_string(value).ok().map(|text| text.len()),
        Value::Array(values) => values.iter().try_fold(
            2usize.saturating_add(values.len().saturating_sub(1)),
            |size, value| size.checked_add(json_encoded_len(value)?),
        ),
        Value::Object(values) => values.iter().try_fold(
            2usize.saturating_add(values.len().saturating_sub(1)),
            |size, (key, value)| {
                size.checked_add(serde_json::to_string(key).ok()?.len())?
                    .checked_add(1)?
                    .checked_add(json_encoded_len(value)?)
            },
        ),
    }
}

fn action_string<'a>(action: &'a Value, key: &str) -> Option<&'a str> {
    action
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty() && value.len() <= MAX_INTERACTION_STRING)
}

fn valid_probe_action(action: &Value) -> bool {
    let Some(kind) = action.get("type").and_then(Value::as_str) else {
        return false;
    };
    match kind {
        "click" => {
            exact_keys(action, &["type", "selector"], &[])
                && action_string(action, "selector").is_some()
        }
        "type" => {
            exact_keys(action, &["type", "text"], &[]) && action_string(action, "text").is_some()
        }
        "press" => {
            exact_keys(action, &["type", "key"], &[])
                && action
                    .get("key")
                    .and_then(Value::as_str)
                    .is_some_and(|key| {
                        matches!(
                            key,
                            "Tab" | "Escape" | "ArrowUp" | "ArrowDown" | "ArrowLeft" | "ArrowRight"
                        )
                    })
        }
        "assertVisible" => {
            exact_keys(action, &["type", "selector"], &["timeout"])
                && action_string(action, "selector").is_some()
                && action.get("timeout").is_none_or(|timeout| {
                    timeout
                        .as_u64()
                        .is_some_and(|value| (1..=5000).contains(&value))
                })
        }
        "assertText" => {
            exact_keys(action, &["type", "selector", "text"], &[])
                && action_string(action, "selector").is_some()
                && action_string(action, "text").is_some()
        }
        _ => false,
    }
}

fn valid_fixture_source_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_INTERACTION_STRING
        && !value.contains('\\')
        && !std::path::Path::new(value).is_absolute()
        && std::path::Path::new(value)
            .components()
            .all(|component| matches!(component, std::path::Component::Normal(_)))
        && std::path::Path::new(value)
            .to_string_lossy()
            .replace('\\', "/")
            == value
}

fn valid_fixture_url_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= MAX_INTERACTION_STRING
        && value.is_ascii()
        && !value
            .chars()
            .any(|character| matches!(character, '\\' | '?' | '#' | '%') || character.is_control())
        && !value
            .split('/')
            .skip(1)
            .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
        && value.bytes().all(|byte| {
            byte == b'/' || byte.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=@:".contains(&byte)
        })
}

fn exact_fixture_url_path(value: &str) -> Option<&str> {
    let remainder = value.strip_prefix("http://")?;
    let authority_end = remainder.find('/').unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    let port = authority.strip_prefix("127.0.0.1:")?;
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port_number = port.parse::<u16>().ok()?;
    if port_number == 0 {
        return None;
    }
    let raw_path = if authority_end == remainder.len() {
        "/"
    } else {
        &remainder[authority_end..]
    };
    if !valid_fixture_url_path(raw_path) {
        return None;
    }
    Some(raw_path)
}

fn validate_frozen_fixture_files(files: &[Value], expected_digest: &str) -> Result<(), String> {
    if files.is_empty() || files.len() > 64 {
        return Err("runtime-interaction-fixture-file-count-invalid".into());
    }
    let mut url_paths = BTreeSet::new();
    let mut source_paths = BTreeSet::new();
    let mut total_bytes = 0usize;
    let mut digest_files = Vec::with_capacity(files.len());
    for file in files {
        if !exact_keys(
            file,
            &["sourcePath", "sourceDigest", "path", "contentType", "body"],
            &[],
        ) {
            return Err("runtime-interaction-fixture-file-invalid".into());
        }
        let source_path = file.get("sourcePath").and_then(Value::as_str).unwrap_or("");
        let source_digest = file
            .get("sourceDigest")
            .and_then(Value::as_str)
            .unwrap_or("");
        let path = file.get("path").and_then(Value::as_str).unwrap_or("");
        let content_type = file
            .get("contentType")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !valid_fixture_source_path(source_path)
            || !valid_sha256(source_digest)
            || !valid_fixture_url_path(path)
            || content_type.trim().is_empty()
            || content_type.len() > MAX_INTERACTION_STRING
            || !content_type.is_ascii()
            || content_type
                .chars()
                .any(|character| matches!(character, '\r' | '\n'))
            || !url_paths.insert(path.to_owned())
            || !source_paths.insert(source_path.to_owned())
        {
            return Err("runtime-interaction-fixture-file-invalid".into());
        }
        let body = file
            .get("body")
            .and_then(Value::as_array)
            .ok_or("runtime-interaction-fixture-body-invalid")?;
        if body
            .iter()
            .any(|value| value.as_u64().is_none_or(|byte| byte > u8::MAX as u64))
        {
            return Err("runtime-interaction-fixture-body-invalid".into());
        }
        total_bytes = total_bytes
            .checked_add(body.len())
            .ok_or("runtime-interaction-fixture-byte-count-overflow")?;
        if total_bytes > 16 * 1024 * 1024 {
            return Err("runtime-interaction-fixture-byte-limit-exceeded".into());
        }
        let bytes = body
            .iter()
            .map(|value| value.as_u64().unwrap_or_default() as u8)
            .collect::<Vec<_>>();
        if sha256_label(&bytes) != source_digest {
            return Err("runtime-interaction-fixture-source-digest-mismatch".into());
        }
        digest_files.push(json!({"body":body,"contentType":content_type,"path":path}));
    }
    digest_files.sort_by(|left, right| {
        left.get("path")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .as_bytes()
            .cmp(
                right
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .as_bytes(),
            )
    });
    let actual_digest = legion_contracts::canonical_digest(&json!({"files":digest_files}))
        .map_err(|error| format!("runtime-interaction-fixture-canonical:{error}"))?;
    if actual_digest != expected_digest {
        return Err("runtime-interaction-fixture-digest-mismatch".into());
    }
    Ok(())
}

fn parse_interactions(
    value: Option<&Value>,
    entry_url: &str,
    surfaces: &[(String, String)],
) -> Result<Vec<InteractionProbe>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let items = value
        .as_array()
        .ok_or_else(|| "runtime-interactions-not-an-array".to_owned())?;
    if items.len() > MAX_INTERACTIONS {
        return Err("runtime-too-many-interactions".into());
    }
    let serialized_size =
        json_encoded_len(value).ok_or("runtime-interactions-serialization-failed")?;
    if serialized_size > MAX_FROZEN_INTERACTION_CONFIG_BYTES {
        return Err("runtime-interactions-expanded-config-too-large".into());
    }
    let known_surfaces = std::iter::once(("entry".to_owned(), entry_url.to_owned()))
        .chain(surfaces.iter().cloned())
        .collect::<BTreeSet<_>>();
    let mut ids = BTreeSet::new();
    let mut total_actions = 0usize;
    let mut probes = Vec::with_capacity(items.len());
    for item in items {
        if !exact_keys(
            item,
            &[
                "id",
                "surface",
                "fixture",
                "probe",
                "isolationBindingId",
                "expiresAfterMs",
                "actions",
            ],
            &[],
        ) {
            return Err("runtime-interaction-shape-invalid".into());
        }
        let get_id = |field: &str| {
            item.get(field)
                .and_then(Value::as_str)
                .filter(|value| valid_id(value))
                .map(ToOwned::to_owned)
                .ok_or_else(|| format!("runtime-interaction-{field}-invalid"))
        };
        let id = get_id("id")?;
        if !ids.insert(id.clone()) {
            return Err("runtime-interaction-id-duplicate".into());
        }
        let surface = item
            .get("surface")
            .ok_or("runtime-interaction-surface-missing")?;
        if !exact_keys(surface, &["label", "url"], &[]) {
            return Err("runtime-interaction-surface-invalid".into());
        }
        let label = surface.get("label").and_then(Value::as_str).unwrap_or("");
        let url = surface.get("url").and_then(Value::as_str).unwrap_or("");
        let exact_path =
            exact_fixture_url_path(url).ok_or("runtime-interaction-surface-url-not-loopback")?;
        if !known_surfaces.contains(&(label.to_owned(), url.to_owned())) {
            return Err("runtime-interaction-surface-not-frozen".into());
        }
        let fixture = item
            .get("fixture")
            .ok_or("runtime-interaction-fixture-missing")?;
        if !exact_keys(
            fixture,
            &["id", "sourceDigest", "inventoryDigest", "files"],
            &[],
        ) {
            return Err("runtime-interaction-fixture-invalid".into());
        }
        let fixture_id = fixture.get("id").and_then(Value::as_str).unwrap_or("");
        let fixture_source_digest = fixture
            .get("sourceDigest")
            .and_then(Value::as_str)
            .unwrap_or("");
        let fixture_inventory_digest = fixture
            .get("inventoryDigest")
            .and_then(Value::as_str)
            .unwrap_or("");
        let fixture_files = fixture
            .get("files")
            .and_then(Value::as_array)
            .ok_or("runtime-interaction-fixture-files-invalid")?;
        if !valid_id(fixture_id)
            || !valid_sha256(fixture_source_digest)
            || !valid_sha256(fixture_inventory_digest)
        {
            return Err("runtime-interaction-fixture-identity-invalid".into());
        }
        validate_frozen_fixture_files(fixture_files, fixture_source_digest)?;
        if !fixture_files
            .iter()
            .any(|file| file.get("path").and_then(Value::as_str) == Some(exact_path))
        {
            return Err("runtime-interaction-fixture-url-path-mismatch".into());
        }
        let probe = item
            .get("probe")
            .ok_or("runtime-interaction-probe-missing")?;
        if !exact_keys(probe, &["id", "actionsDigest"], &[]) {
            return Err("runtime-interaction-probe-invalid".into());
        }
        let probe_id = probe.get("id").and_then(Value::as_str).unwrap_or("");
        let actions_digest = probe
            .get("actionsDigest")
            .and_then(Value::as_str)
            .unwrap_or("");
        if !valid_id(probe_id) || !valid_sha256(actions_digest) {
            return Err("runtime-interaction-probe-identity-invalid".into());
        }
        let isolation_binding_id = get_id("isolationBindingId")?;
        let expires_after_ms = item
            .get("expiresAfterMs")
            .and_then(Value::as_u64)
            .filter(|expiry| (1..=30_000).contains(expiry))
            .ok_or("runtime-interaction-expiry-invalid")?;
        let actions = item
            .get("actions")
            .and_then(Value::as_array)
            .ok_or("runtime-interaction-actions-invalid")?;
        total_actions = total_actions.saturating_add(actions.len());
        if actions.is_empty()
            || actions.len() > MAX_ACTIONS_PER_INTERACTION
            || total_actions > MAX_INTERACTION_ACTIONS
            || !actions.iter().all(valid_probe_action)
        {
            return Err("runtime-interaction-actions-invalid".into());
        }
        let actual_actions_digest = legion_contracts::canonical_digest(actions)
            .map_err(|error| format!("runtime-interaction-actions-canonical:{error}"))?;
        if actual_actions_digest != actions_digest {
            return Err("runtime-interaction-actions-digest-mismatch".into());
        }
        probes.push(InteractionProbe {
            id,
            surface_label: label.to_owned(),
            surface_url: url.to_owned(),
            fixture_id: fixture_id.to_owned(),
            fixture_source_digest: fixture_source_digest.to_owned(),
            fixture_inventory_digest: fixture_inventory_digest.to_owned(),
            fixture_files: fixture_files.clone(),
            probe_id: probe_id.to_owned(),
            actions_digest: actions_digest.to_owned(),
            isolation_binding_id,
            expires_after_ms,
            actions: actions.clone(),
        });
    }
    Ok(probes)
}

fn check_url(url: &str) -> Result<(), String> {
    let lower = url.to_ascii_lowercase();
    let rest = if lower.starts_with("http://") {
        &url[7..]
    } else if lower.starts_with("https://") {
        &url[8..]
    } else {
        return Err("url-scheme-not-http".into());
    };
    if rest.is_empty() || url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("url-malformed".into());
    }
    Ok(())
}

fn check_loopback_url(url: &str) -> Result<(), String> {
    check_url(url)?;
    let lower = url.to_ascii_lowercase();
    let authority = if lower.starts_with("http://") {
        &url[7..]
    } else if lower.starts_with("https://") {
        &url[8..]
    } else {
        return Err("runtime-interaction-surface-url-invalid".into());
    };
    let authority = authority.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err("runtime-interaction-surface-url-not-loopback".into());
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| "runtime-interaction-surface-url-invalid".to_owned())?;
        let suffix = &bracketed[end + 1..];
        let port = if suffix.is_empty() {
            None
        } else if let Some(port) = suffix.strip_prefix(':') {
            Some(port)
        } else {
            return Err("runtime-interaction-surface-url-invalid".into());
        };
        (&bracketed[..end], port)
    } else {
        match authority.split_once(':') {
            Some((host, port)) if !port.contains(':') => (host, Some(port)),
            Some(_) => return Err("runtime-interaction-surface-url-invalid".into()),
            None => (authority, None),
        }
    };
    if port.is_some_and(|port| {
        port.is_empty()
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.parse::<u16>().is_err()
    }) {
        return Err("runtime-interaction-surface-url-invalid".into());
    }
    let loopback = matches!(
        host.to_ascii_lowercase().as_str(),
        "localhost" | "127.0.0.1" | "::1"
    );
    if loopback {
        Ok(())
    } else {
        Err("runtime-interaction-surface-url-not-loopback".into())
    }
}

fn dimension(value: Option<&Value>, default: u32, name: &str) -> Result<u32, String> {
    match value {
        None | Some(Value::Null) => Ok(default),
        Some(value) => match value.as_u64() {
            Some(number) if (1..=MAX_DIMENSION).contains(&number) => Ok(number as u32),
            _ => Err(format!("{name}-invalid")),
        },
    }
}

/// Validate the CLI inputs and build the `runner.runtime` object that is
/// frozen into the plan. `surfaces` are the extra `(label, url)` pairs beyond
/// the entry URL; `unsupported` names requested surfaces that cannot be
/// captured by URL navigation (click targets).
pub fn runtime_inputs(
    url: &str,
    surfaces: &[(String, String)],
    unsupported: &[String],
    width: u32,
    height: u32,
    artifact_dir: Option<&str>,
) -> Result<Value, String> {
    let candidate = json!({
        "url": url,
        "width": width,
        "height": height,
        "surfaces": surfaces.iter().map(|(label, surface_url)| json!({"label": label, "url": surface_url})).collect::<Vec<_>>(),
        "unsupportedSurfaces": unsupported,
        "artifactDir": artifact_dir,
    });
    match RuntimeParams::from_value(&candidate)? {
        Some(params) => Ok(params.to_value()),
        None => Err("runtime-url-empty".into()),
    }
}

/// What the QA route printed for one invocation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct QaOutput {
    screenshot: Option<String>,
    actions_complete: bool,
    no_console_issues: bool,
    console_total: Option<usize>,
    console_entries: Vec<String>,
    gaps: Vec<String>,
    /// `(action index, JSON text)` of each `[qa] N:eval value <json>` line printed
    /// before `actions complete`.
    eval_values: Vec<(usize, String)>,
}

/// Matches `N:eval value <json>` at the start of a `[qa] ` line body, returning the
/// 1-based action label and the JSON text that follows.
fn eval_value_line(rest: &str) -> Option<(usize, &str)> {
    let digits = rest.bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    let (number, tail) = rest.split_at(digits);
    let json = tail.strip_prefix(":eval value ")?;
    Some((number.parse().ok()?, json))
}

/// The metrics object of a performance line. Anything else is rejected: unparsable
/// JSON, a non-object, an empty object, a value that is not a number or `null`, and
/// the route's `{"truncated":true,...}` marker.
fn parse_performance(json: &str) -> Option<Value> {
    let value: Value = serde_json::from_str(json).ok()?;
    let object = value.as_object()?;
    if object.is_empty() || object.contains_key("truncated") {
        return None;
    }
    if !object.values().all(|v| v.is_number() || v.is_null()) {
        return None;
    }
    Some(value)
}

/// Parse the `[qa] ...` lines the route prints (see `wf_port::r54::run`).
fn parse_qa_output(text: &str) -> QaOutput {
    let mut out = QaOutput::default();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("[qa] ") else {
            continue;
        };
        if let Some((index, json)) = eval_value_line(rest) {
            // The route prints action output before `actions complete`; console text
            // comes after it, so a forged line there is never a metric.
            if !out.actions_complete {
                out.eval_values.push((index, json.to_owned()));
            }
        } else if let Some(path) = rest.strip_prefix("screenshot ") {
            if out.screenshot.is_none() {
                out.screenshot = Some(path.trim().to_owned());
            }
        } else if rest.starts_with("actions complete") {
            out.actions_complete = true;
        } else if rest.starts_with("no console errors or warnings") {
            out.no_console_issues = true;
        } else if rest.contains("console error/warning(s)") {
            out.console_total = rest
                .split_whitespace()
                .next()
                .and_then(|count| count.parse::<usize>().ok());
        } else if let Some(name) = rest.strip_prefix("gap ") {
            let name = name.trim();
            if !name.is_empty() {
                out.gaps.push(name.to_owned());
            }
        } else if rest.starts_with("  ") {
            let entry = rest.trim();
            if entry.starts_with("console.") || entry.starts_with("exception:") {
                out.console_entries.push(entry.to_owned());
            }
        }
    }
    out
}

fn is_console_warning(entry: &str) -> bool {
    entry.starts_with("console.warning")
}

/// Classify a failed invocation from the route's own messages. Returns an
/// `unavailable:<reason>` reason when the browser itself is missing, and the
/// gap to record.
fn classify_failure(label: &str, state: &str, text: &str) -> (Option<String>, String) {
    if text.contains("No Chrome/Edge executable found")
        || text.contains("CHROME_PATH/QA_BROWSER set but not found")
    {
        return (
            Some("browser-not-found".to_owned()),
            format!("runtime-browser-not-found:{label}"),
        );
    }
    if text.contains("eval returned not ok") || text.contains("Timed out loading") {
        return (None, format!("runtime-surface-load-failed:{label}"));
    }
    (
        None,
        format!("runtime-surface-capture-failed:{label}:{state}"),
    )
}

fn first_line(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| line.chars().take(200).collect())
}

fn sha256_label(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Same projection `execution_from_receipt` records; the external-receipt
/// validator in `execution.rs` requires exactly these fields.
fn receipt_json(receipt: &ExecutionReceipt) -> Value {
    let mut value = json!({
        "schemaVersion": receipt.schema_version, "receiptId": receipt.receipt_id,
        "requestId": receipt.request_id, "providerId": receipt.provider_id,
        "planId": receipt.plan_id, "policyId": receipt.policy_id,
        "policy": receipt.policy.as_ref().map(|p| json!({"id":p.id,"version":p.version,"digest":p.digest,"allowed":p.allowed,"reason":p.reason})),
        "taskId": receipt.task_id, "state": receipt.state.as_str(), "complete": receipt.complete,
        "executable": receipt.executable.as_ref().map(|e| json!({"requestedPath":e.requested_path,"canonicalPath":e.canonical_path,"digest":e.digest,"digestState":format!("{:?}", e.digest_state).to_ascii_lowercase(),"signature":format!("{:?}", e.signature).to_ascii_lowercase(),"version":{"args":e.version.args,"output":e.version.output,"exitCode":e.version.exit_code,"qualified":e.version.qualified}})),
        "command": receipt.command.as_ref().map(|c| json!({"executable":c.executable,"args":c.args,"environmentNames":c.environment_names,"redactedArgumentIndexes":c.redacted_argument_indexes,"redactedEnvironmentNames":c.redacted_environment_names})),
        "cwd": receipt.cwd, "environmentNames": receipt.environment_names,
        "sandbox": {"required":receipt.sandbox.required,"receiptId":receipt.sandbox.receipt_id,"networkEnabled":receipt.sandbox.network_enabled},
        "processTree": {"started":receipt.process_tree.started,"terminated":receipt.process_tree.terminated,"hardKilled":receipt.process_tree.hard_killed,"reaped":receipt.process_tree.reaped,"detail":receipt.process_tree.detail},
        "timing": {"startedAtMs":receipt.timing.started_at_ms,"completedAtMs":receipt.timing.completed_at_ms,"durationMs":receipt.timing.duration_ms},
        "exitCode": receipt.exit_code, "signal": receipt.signal,
        "stdout": receipt.stdout.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "stderr": receipt.stderr.as_ref().map(|a| json!({"path":a.path,"digest":a.digest,"bytes":a.bytes,"immutable":a.immutable})),
        "parser": {"attempted":receipt.parser.attempted,"succeeded":receipt.parser.succeeded,"error":receipt.parser.error}, "gaps": receipt.gaps,
    });
    crate::execution_policy::project_binding(&mut value);
    value
}

fn bound_u64(provider: &AuditProvider, key: &str) -> Option<u64> {
    provider.bounds.get(key).and_then(Value::as_u64)
}

/// Request for one invocation. Legion's own executable is the tool, so the
/// origin is `LegionOwned`; nothing here executes target-project code, and the
/// working directory is a scratch directory, never the audited tree.
fn base_request(
    provider: &AuditProvider,
    plan_digest: &str,
    input: &LegacyCheckInput,
    suffix: &str,
    cwd: &Path,
    args: Vec<String>,
) -> ExternalToolRequest {
    ExternalToolRequest {
        request_id: format!(
            "audit:{}:{}:{}:{}",
            provider.id, plan_digest, input.inventory_digest, suffix
        ),
        provider_id: provider.id.clone(),
        plan_id: plan_digest.to_owned(),
        policy_id: provider
            .configuration
            .get("policyId")
            .and_then(Value::as_str)
            .unwrap_or("audit")
            .into(),
        task_id: Some("runtime".into()),
        executable: RUNTIME_CAPTURE_TOOL.into(),
        args,
        cwd: cwd.to_string_lossy().into_owned(),
        origin: legion_effects::ToolOrigin::LegionOwned,
        shell: false,
        accepted_exit_codes: [0].into_iter().collect(),
        timeout_ms: bound_u64(provider, "timeoutMs").unwrap_or(120_000),
        stdout_limit: bound_u64(provider, "stdoutLimit").unwrap_or(8 * 1024 * 1024) as usize,
        stderr_limit: bound_u64(provider, "stderrLimit").unwrap_or(8 * 1024 * 1024) as usize,
        ..ExternalToolRequest::default()
    }
}

/// Everything one surface invocation produced.
struct SurfaceOutcome {
    index: usize,
    label: String,
    url: String,
    /// `captured` | `failed` | `unavailable`
    status: &'static str,
    screenshot: Option<Value>,
    /// Page performance metrics, when the surface's metric line was valid.
    performance: Option<Value>,
    /// `ran` with compact axe violations, or typed `unavailable`/`error`.
    accessibility: Value,
    console_errors: Vec<String>,
    console_warnings: Vec<String>,
    gaps: Vec<String>,
    failure: Option<String>,
    unavailable: Option<String>,
    receipt: Value,
    receipt_complete: bool,
    process_state: String,
    exit_code: Option<i32>,
}

impl SurfaceOutcome {
    fn new(index: usize, label: &str, url: &str, receipt: &ExecutionReceipt) -> Self {
        Self {
            index,
            label: label.to_owned(),
            url: url.to_owned(),
            status: "failed",
            screenshot: None,
            performance: None,
            accessibility: json!({"status": "unavailable", "reason": "surface-not-captured"}),
            console_errors: Vec::new(),
            console_warnings: Vec::new(),
            gaps: Vec::new(),
            failure: None,
            unavailable: None,
            receipt: receipt_json(receipt),
            receipt_complete: receipt.is_complete(),
            process_state: receipt.state.as_str().to_owned(),
            exit_code: receipt.exit_code,
        }
    }
}

struct Ctx<'a> {
    tool: &'a dyn ExternalProjectTool,
    provider: &'a AuditProvider,
    input: &'a LegacyCheckInput,
    plan_digest: &'a str,
    params: &'a RuntimeParams,
    axe_expression: String,
    base_args: &'a [String],
    environment: &'a BTreeMap<String, String>,
    allowlist: &'a BTreeSet<String>,
    work_dir: &'a Path,
    shot_dir: &'a Path,
    roots: &'a [&'a Path],
    cancellation: &'a CancellationToken,
}

/// Prefer axe-core from the audited project's Node dependency tree, then use
/// Legion's pinned bundled copy so runtime a11y remains available by default.
fn load_axe_source(root: &Path) -> (String, String) {
    let mut current = Some(root);
    while let Some(dir) = current {
        let candidate = dir.join("node_modules/axe-core/axe.min.js");
        if candidate.exists() {
            if let Ok(source) = std::fs::read_to_string(&candidate) {
                return (source, "project node_modules/axe-core".into());
            }
        }
        current = dir.parent();
    }
    (
        BUNDLED_AXE_SOURCE.to_owned(),
        format!("Legion bundled axe-core@{BUNDLED_AXE_VERSION}"),
    )
}

/// Evaluate axe WCAG 2 A/AA and return compact, actionable evidence.
fn axe_expression(source: Option<&str>, unavailable_reason: &str) -> String {
    let Some(source) = source else {
        let reason = serde_json::to_string(unavailable_reason)
            .unwrap_or_else(|_| "\"axe-core-not-installed\"".into());
        return format!("({{status:'unavailable',reason:{reason}}})");
    };
    format!(
        "(async()=>{{try{{{source}\n;const r=await window.axe.run(document,{{resultTypes:['violations'],runOnly:{{type:'tag',values:['wcag2a','wcag2aa']}}}});const total=r.violations.length;const violations=r.violations.slice(0,32).map(v=>({{id:String(v.id||'unknown').slice(0,80),impact:String(v.impact||'unknown').slice(0,20),help:String(v.help||'axe violation').slice(0,240),count:v.nodes.length,target:String(((v.nodes[0]||{{}}).target||[])[0]||'document').slice(0,320),helpUrl:String(v.helpUrl||'').slice(0,320)}}));const truncated=total>violations.length;return {{status:truncated?'error':'ran',reason:truncated?'axe-results-truncated':undefined,totalViolations:total,truncated,violations}}}}catch(e){{return {{status:'error',reason:String((e&&e.message)||e).slice(0,160)}}}}}})()"
    )
}

/// Validate bounded QA eval output before treating any accessibility count as
/// evidence. The QA engine's oversize marker and malformed payloads are typed
/// failures; truncated results retain their bounded violations for findings.
fn parse_accessibility_result(text: &str) -> Value {
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => return json!({"status": "error", "reason": "axe-result-malformed"}),
    };
    if value.get("truncated").and_then(Value::as_bool) == Some(true)
        && value.get("status").is_none()
    {
        return json!({
            "status": "error",
            "reason": "axe-result-truncated",
            "reportedBytes": value.get("bytes").and_then(Value::as_u64),
        });
    }
    let Some(status) = value.get("status").and_then(Value::as_str) else {
        return json!({"status": "error", "reason": "axe-result-status-missing"});
    };
    if matches!(status, "error" | "unavailable") {
        let Some(reason) = value.get("reason").and_then(Value::as_str) else {
            return json!({"status": "error", "reason": "axe-result-reason-missing"});
        };
        if status == "unavailable" {
            return json!({"status": "unavailable", "reason": reason});
        }
        if value.get("violations").is_none() {
            return json!({"status": "error", "reason": reason});
        }
        if reason != "axe-results-truncated" {
            return json!({"status": "error", "reason": "axe-result-error-with-violations"});
        }
    }
    let is_truncated_error = status == "error"
        && value.get("reason").and_then(Value::as_str) == Some("axe-results-truncated");
    if (status != "ran" && !is_truncated_error)
        || (status == "ran" && value.get("reason").is_some())
    {
        return json!({"status": "error", "reason": "axe-result-status-invalid"});
    }
    let Some(violations) = value.get("violations").and_then(Value::as_array) else {
        return json!({"status": "error", "reason": "axe-violations-not-an-array"});
    };
    let Some(total) = value.get("totalViolations").and_then(Value::as_u64) else {
        return json!({"status": "error", "reason": "axe-total-invalid"});
    };
    let Some(truncated) = value.get("truncated").and_then(Value::as_bool) else {
        return json!({"status": "error", "reason": "axe-truncated-flag-invalid"});
    };
    if total < violations.len() as u64
        || truncated != (total > violations.len() as u64)
        || truncated != is_truncated_error
    {
        return json!({"status": "error", "reason": "axe-total-inconsistent"});
    }
    for violation in violations {
        let valid = violation.is_object()
            && violation
                .get("id")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            && violation
                .get("impact")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
            && violation.get("help").and_then(Value::as_str).is_some()
            && violation.get("target").and_then(Value::as_str).is_some()
            && violation.get("helpUrl").and_then(Value::as_str).is_some()
            && violation
                .get("count")
                .and_then(Value::as_u64)
                .is_some_and(|count| count > 0);
        if !valid {
            return json!({"status": "error", "reason": "axe-violation-invalid"});
        }
    }
    if truncated {
        json!({
            "status": "error",
            "reason": "axe-results-truncated",
            "totalViolations": total,
            "truncated": true,
            "violations": violations,
        })
    } else {
        value
    }
}

async fn capture_surface(ctx: &Ctx<'_>, index: usize, label: &str, url: &str) -> SurfaceOutcome {
    let dir = ctx.work_dir.join(format!("surface-{index}"));
    let shot_path = ctx.shot_dir.join(format!("runtime-shot-{index}.png"));
    let actions_path = dir.join("actions.json");
    let mut args: Vec<String> = ctx.base_args.to_vec();
    args.extend([
        "--url".to_owned(),
        url.to_owned(),
        "--actions".to_owned(),
        actions_path.to_string_lossy().into_owned(),
        "--width".to_owned(),
        ctx.params.width.to_string(),
        "--height".to_owned(),
        ctx.params.height.to_string(),
    ]);
    let mut request = base_request(
        ctx.provider,
        ctx.plan_digest,
        ctx.input,
        &format!("surface-{index}"),
        &dir,
        args,
    );
    request.environment = ctx.environment.clone();
    request.environment_allowlist = ctx.allowlist.clone();

    let setup = (|| -> Result<(), String> {
        std::fs::create_dir_all(&dir).map_err(|error| format!("work-dir: {error}"))?;
        std::fs::create_dir_all(ctx.shot_dir).map_err(|error| format!("artifact-dir: {error}"))?;
        // A stale file must never be mistaken for this run's capture.
        let _ = std::fs::remove_file(&shot_path);
        let actions = json!([
            {"type": "eval", "expression": LOAD_CHECK},
            {"type": "screenshot", "out": shot_path.to_string_lossy().into_owned()},
            {"type": "eval", "expression": PERFORMANCE_METRICS},
            {"type": "eval", "expression": ctx.axe_expression},
        ]);
        let bytes = serde_json::to_vec(&actions).map_err(|error| error.to_string())?;
        std::fs::write(&actions_path, bytes).map_err(|error| format!("actions-file: {error}"))
    })();
    if let Err(detail) = setup {
        let gap = format!("runtime-surface-setup-failed:{label}");
        let receipt = ExecutionReceipt::failure(&request, ExecutionState::Blocked, gap.clone());
        let mut outcome = SurfaceOutcome::new(index, label, url, &receipt);
        outcome.gaps.push(gap);
        outcome.failure = Some(detail);
        return outcome;
    }
    if ctx.cancellation.is_cancelled() {
        let gap = format!("runtime-surface-capture-failed:{label}:cancelled");
        let receipt = ExecutionReceipt::failure(&request, ExecutionState::Cancelled, "cancelled");
        let mut outcome = SurfaceOutcome::new(index, label, url, &receipt);
        outcome.gaps.push(gap);
        return outcome;
    }

    let receipt = ctx.tool.execute(request, ctx.cancellation.clone()).await;
    let mut outcome = SurfaceOutcome::new(index, label, url, &receipt);
    let stdout = receipt
        .stdout
        .as_ref()
        .and_then(|artifact| readable_artifact(ctx.roots, artifact))
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    let stderr = receipt
        .stderr
        .as_ref()
        .and_then(|artifact| readable_artifact(ctx.roots, artifact))
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .unwrap_or_default();
    let qa = parse_qa_output(&stdout);
    for entry in &qa.console_entries {
        if is_console_warning(entry) {
            outcome.console_warnings.push(entry.clone());
        } else {
            outcome.console_errors.push(entry.clone());
        }
    }
    for gap in &qa.gaps {
        outcome.gaps.push(format!("runtime-qa-gap:{label}:{gap}"));
    }

    outcome.performance = qa
        .eval_values
        .iter()
        .find(|(index, _)| *index == PERFORMANCE_ACTION_LABEL)
        .and_then(|(_, json)| parse_performance(json));
    outcome.accessibility = qa
        .eval_values
        .iter()
        .find(|(index, _)| *index == A11Y_ACTION_LABEL)
        .map(|(_, text)| parse_accessibility_result(text))
        .unwrap_or_else(|| json!({"status": "error", "reason": "axe-result-not-reported"}));
    let a11y_status = outcome.accessibility.get("status").and_then(Value::as_str);
    if matches!(a11y_status, Some("unavailable" | "error")) {
        let reason = outcome
            .accessibility
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        outcome.gaps.push(format!(
            "runtime-a11y-{}:{}:{}",
            a11y_status.unwrap(),
            label,
            reason
        ));
    }

    let expected_shot = shot_path.to_string_lossy().into_owned();
    let load_succeeded = qa
        .eval_values
        .iter()
        .find(|(index, _)| *index == 1)
        .and_then(|(_, text)| serde_json::from_str::<Value>(text).ok())
        .and_then(|value| value.get("ok").and_then(Value::as_bool))
        == Some(true);
    let screenshot_valid = if qa.screenshot.as_deref() != Some(expected_shot.as_str()) {
        outcome
            .gaps
            .push(format!("runtime-screenshot-not-reported:{label}"));
        false
    } else {
        match std::fs::read(&shot_path) {
            Ok(bytes) if !bytes.is_empty() && bytes.starts_with(PNG_MAGIC) => {
                outcome.screenshot = Some(json!({
                    "path": expected_shot,
                    "sha256": sha256_label(&bytes),
                    "bytes": bytes.len(),
                }));
                true
            }
            Ok(_) => {
                outcome
                    .gaps
                    .push(format!("runtime-screenshot-invalid:{label}"));
                false
            }
            Err(error) => {
                outcome
                    .gaps
                    .push(format!("runtime-screenshot-missing:{label}"));
                outcome.failure = Some(error.to_string());
                false
            }
        }
    };
    let core_capture_succeeded = load_succeeded && screenshot_valid;

    let ran_clean = receipt.state == ExecutionState::Completed
        && receipt.complete
        && receipt.exit_code == Some(0);
    if !ran_clean {
        if receipt.state == ExecutionState::UnauthorizedEffect
            && !receipt.process_tree.started
            && receipt.policy.as_ref().is_some_and(|policy| {
                policy.id == crate::execution_policy::POLICY_ID
                    && !policy.allowed
                    && policy.reason.as_deref()
                        == Some(crate::execution_policy::ADMISSION_UNAVAILABLE)
            })
        {
            outcome.unavailable = Some(crate::execution_policy::ADMISSION_UNAVAILABLE.into());
            outcome.status = "unavailable";
            outcome.gaps.push(format!(
                "unavailable:{}",
                crate::execution_policy::ADMISSION_UNAVAILABLE
            ));
            return outcome;
        }
        if receipt.state == ExecutionState::MissingExecutable {
            outcome.unavailable = Some("legion-executable-unavailable".to_owned());
            outcome.gaps.push(format!(
                "runtime-surface-capture-failed:{label}:missing_executable"
            ));
            outcome.status = "unavailable";
            outcome.failure = first_line(&receipt.gaps.join("\n"));
            return outcome;
        }
        let combined = format!("{stderr}\n{stdout}");
        let (unavailable, gap) = classify_failure(label, receipt.state.as_str(), &combined);
        outcome.gaps.push(gap);
        outcome.failure = first_line(&stderr)
            .or_else(|| first_line(&stdout))
            .or_else(|| first_line(&receipt.gaps.join("\n")));
        if let Some(reason) = unavailable {
            outcome.unavailable = Some(reason);
            outcome.status = "unavailable";
        }
        if !core_capture_succeeded {
            return outcome;
        }
        // An axe timeout or protocol failure must not erase the already
        // completed navigation, screenshot, and performance evidence.
        outcome.status = "captured";
    } else if !qa.actions_complete {
        outcome.gaps.push(format!(
            "runtime-surface-capture-failed:{label}:actions-incomplete"
        ));
        return outcome;
    }
    // The route prints at most 20 entries; a larger total is a truncated view.
    if let Some(total) = qa.console_total {
        if qa.console_entries.len() < total {
            outcome
                .gaps
                .push(format!("runtime-console-truncated:{label}:{total}"));
        }
    } else if !qa.no_console_issues {
        outcome
            .gaps
            .push(format!("runtime-console-report-missing:{label}"));
    }
    if core_capture_succeeded {
        outcome.status = "captured";
    }
    outcome
}

/// Result for a provider that could not run at all (`unavailable:<reason>`):
/// no process was started, so the terminal receipt is a non-started `blocked`
/// receipt carrying the reason, exactly as the effect layer reports a refused
/// request.
fn unavailable_result(
    executor: &NativeLegacyCheckExecutor,
    provider: &AuditProvider,
    input: &LegacyCheckInput,
    plan_digest: &str,
    reason: &str,
) -> Result<ProviderResult, AuditError> {
    let gap = availability::unavailable_gap(reason);
    let args = command_parts(spec(&provider.id).expect("validated above").command).1;
    let request = base_request(
        provider,
        plan_digest,
        input,
        "unavailable",
        &executor.root,
        args,
    );
    let receipt = ExecutionReceipt::failure(&request, ExecutionState::Blocked, gap.clone());
    let provider_id =
        ProviderId::new(&provider.id).map_err(|error| AuditError::Provider(error.to_string()))?;
    let mut details = BTreeMap::new();
    details.insert("check".to_owned(), Value::String("runtime".into()));
    details.insert("tool".to_owned(), Value::String("audit-runtime.mjs".into()));
    details.insert(
        "processState".to_owned(),
        Value::String(receipt.state.as_str().into()),
    );
    details.insert("exitCode".to_owned(), Value::Null);
    details.insert("commandShape".to_owned(), Value::String("named".into()));
    details.insert("candidates".to_owned(), Value::Array(Vec::new()));
    details.insert("executionReceipt".to_owned(), receipt_json(&receipt));
    details.insert(
        "receiptId".to_owned(),
        Value::String(receipt.receipt_id.clone()),
    );
    let mut result = ProviderResult {
        schema_version: 1,
        provider: provider_id,
        applicable: true,
        required: provider.required,
        status: ProviderStatus::Partial,
        complete: false,
        coverage: Some(Coverage {
            denominator_digest: input.denominator.digest.clone(),
            expected: input.denominator.entries.len() as u64,
            examined: 0,
            gaps: vec![gap.clone()],
        }),
        findings: Vec::new(),
        coverage_gaps: vec![gap],
        degradation: Vec::new(),
        details,
    };
    availability::mark_unavailable(&mut result, reason);
    result
        .validate()
        .map_err(|error| AuditError::Provider(error.to_string()))?;
    Ok(result)
}

fn fixture_cleanup_complete(attestation: &FixtureAttestation) -> bool {
    let cleanup = &attestation.output_cleanup;
    cleanup.browser_stopped
        && cleanup.transport_stopped
        && cleanup.proxy_stopped
        && cleanup.server_stopped
        && cleanup.profile_removed
}

fn fixture_attestation_matches(attestation: &FixtureAttestation, probe: &InteractionProbe) -> bool {
    let backend_matches = (cfg!(target_os = "macos")
        && matches!(
            attestation.confinement_backend,
            rightkit_browser::FixtureConfinementBackend::MacosSeatbeltProxy
        ))
        || (cfg!(windows)
            && matches!(
                attestation.confinement_backend,
                rightkit_browser::FixtureConfinementBackend::WindowsAppcontainerPipeFulfillment
            ));
    backend_matches
        && attestation.schema == "rightkit.browser.fixture-attestation.v1"
        && !attestation.host_binding_id.is_empty()
        && !attestation.server_instance_id.is_empty()
        && !attestation.browser_process_instance.is_empty()
        && attestation.browser_pid > 0
        && !attestation.profile_identity.is_empty()
        && !attestation.browser_session_id.is_empty()
        && !attestation.page_id.is_empty()
        && !attestation.frame_id.is_empty()
        && !attestation.loader_id.is_empty()
        && !attestation.unique_context_id.is_empty()
        && valid_sha256(&attestation.policy_digest)
        && probe
            .surface_url
            .strip_prefix("http://")
            .and_then(|url| url.split('/').next())
            == Some(attestation.server_endpoint.as_str())
        && attestation.fixture_id == probe.fixture_id
        && attestation.fixture_source_digest == probe.fixture_source_digest
        && attestation.exact_url == probe.surface_url
        && attestation.probe_id == probe.probe_id
        && attestation.actions_digest == probe.actions_digest
}

/// Only cleanup may change between the host-issued launch binding & terminal evidence.
fn fixture_terminal_binding_matches(
    issued: &FixtureAttestation,
    terminal: &FixtureAttestation,
    probe: &InteractionProbe,
) -> bool {
    let mut identity = terminal.clone();
    identity.output_cleanup = issued.output_cleanup.clone();
    fixture_attestation_matches(issued, probe) && identity == *issued
}

fn fixture_attestation_unexpired(attestation: &FixtureAttestation) -> bool {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    attestation.expires_at_unix_ms > now_ms
        && attestation.expires_at_unix_ms <= now_ms.saturating_add(30_000)
}

fn interaction_outcomes(params: &RuntimeParams, outcomes: &[Value]) -> Vec<Value> {
    params
        .interactions
        .iter()
        .enumerate()
        .map(|(index, probe)| {
            outcomes
                .get(index)
                .cloned()
                .unwrap_or_else(|| probe.result_value())
        })
        .collect()
}

fn passed_interaction_count(outcomes: &[Value]) -> usize {
    outcomes
        .iter()
        .filter(|outcome| outcome.get("status").and_then(Value::as_str) == Some("passed"))
        .count()
}

fn interaction_gaps(params: &RuntimeParams, outcomes: &[Value]) -> Vec<String> {
    params
        .interactions
        .iter()
        .enumerate()
        .filter_map(|(index, probe)| {
            let outcome = outcomes.get(index);
            if outcome
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                == Some("passed")
            {
                None
            } else {
                let reason = outcome
                    .and_then(|value| value.get("reason"))
                    .and_then(Value::as_str)
                    .unwrap_or("rightkit-fixture-api-unavailable");
                Some(format!("runtime-probe-unavailable:{}:{reason}", probe.id))
            }
        })
        .collect()
}

fn fixture_surface_records(params: &RuntimeParams, outcomes: &[Value]) -> Vec<Value> {
    params
        .interactions
        .iter()
        .enumerate()
        .map(|(index, probe)| {
            let status = outcomes
                .get(index)
                .and_then(|outcome| outcome.get("status"))
                .and_then(Value::as_str)
                .unwrap_or("unavailable");
            json!({
                "label": probe.surface_label,
                "url": probe.surface_url,
                "status": format!("fixture-probe-{status}"),
                "coverage": "fixture-only-not-live-surface-evidence",
            })
        })
        .collect()
}

fn fixture_files(probe: &InteractionProbe) -> Result<Vec<FixtureFile>, String> {
    probe
        .fixture_files
        .iter()
        .map(|file| {
            let path = file
                .get("path")
                .and_then(Value::as_str)
                .ok_or_else(|| "runtime-interaction-fixture-file-invalid".to_owned())?;
            let content_type = file
                .get("contentType")
                .and_then(Value::as_str)
                .ok_or_else(|| "runtime-interaction-fixture-file-invalid".to_owned())?;
            let body = file
                .get("body")
                .and_then(Value::as_array)
                .ok_or_else(|| "runtime-interaction-fixture-body-invalid".to_owned())?
                .iter()
                .map(|byte| {
                    byte.as_u64()
                        .filter(|byte| *byte <= u8::MAX as u64)
                        .map(|byte| byte as u8)
                        .ok_or_else(|| "runtime-interaction-fixture-body-invalid".to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(FixtureFile {
                path: path.to_owned(),
                content_type: content_type.to_owned(),
                body,
            })
        })
        .collect()
}

fn fixture_actions(probe: &InteractionProbe) -> Result<Vec<FixtureAction>, String> {
    let actions: Vec<FixtureAction> =
        serde_json::from_value(Value::Array(probe.actions.clone()))
            .map_err(|_| "runtime-interaction-actions-invalid".to_owned())?;
    let digest = fixture_actions_digest(&actions)
        .map_err(|_| "runtime-interaction-actions-invalid".to_owned())?;
    if digest != probe.actions_digest {
        return Err("runtime-interaction-actions-digest-mismatch".into());
    }
    Ok(actions)
}

async fn launch_fixture_probe(probe: &InteractionProbe) -> Result<FixtureSession, String> {
    // Consume only frozen bytes; sourcePath is provenance, never a runtime filesystem read.
    let files = fixture_files(probe)?;
    let actions = fixture_actions(probe)?;
    let bundle = FixtureBundle::verify(
        probe.fixture_id.clone(),
        &probe.fixture_source_digest,
        files,
    )
    .map_err(|error| format!("fixture-bundle-invalid:{error}"))?;
    let intent = FixtureIntent {
        schema: FIXTURE_SCHEMA.to_owned(),
        fixture_id: probe.fixture_id.clone(),
        fixture_source_digest: probe.fixture_source_digest.clone(),
        probe_id: probe.probe_id.clone(),
        actions_digest: probe.actions_digest.clone(),
        exact_url: probe.surface_url.clone(),
        actions,
        expires_after_ms: probe.expires_after_ms,
    };
    let server = FixtureServer::prepare_at(bundle, &probe.surface_url)
        .await
        .map_err(|error| format!("fixture-server-unavailable:{error}"))?;
    FixtureSession::launch(server, intent)
        .await
        .map_err(|error| format!("fixture-launch-failed:{error}"))
}

async fn execute_fixture_probe(
    probe: &InteractionProbe,
    cancellation: &CancellationToken,
) -> Value {
    let result = async {
        if cancellation.is_cancelled() {
            return Err("fixture-cancelled-before-start".to_owned());
        }
        let session = launch_fixture_probe(probe).await?;
        Ok(execute_fixture_session(probe, session, cancellation).await)
    }
    .await;
    fixture_probe_value(probe, result)
}

async fn execute_fixture_session(
    probe: &InteractionProbe,
    session: FixtureSession,
    cancellation: &CancellationToken,
) -> Value {
    let issued = session.attestation().clone();
    let cancellation_signal = FixtureCancellation::new();
    if cancellation.is_cancelled() || !fixture_attestation_matches(&issued, probe) {
        cancellation_signal.cancel();
    }
    let run = session.run_with_cancel(cancellation_signal.clone());
    tokio::pin!(run);
    // Never drop a running session on cancellation: await its cleanup receipt.
    let terminal = tokio::select! {
        result = &mut run => result,
        _ = cancellation.cancelled() => {
            cancellation_signal.cancel();
            run.await
        }
    };
    fixture_terminal_value(probe, &issued, terminal, cancellation.is_cancelled())
}

fn fixture_terminal_value(
    probe: &InteractionProbe,
    issued: &FixtureAttestation,
    terminal: Result<FixtureOutcome, FixtureRunFailure>,
    cancelled: bool,
) -> Value {
    let expected_actions = probe.actions.len();
    match terminal {
        Ok(outcome) => {
            let identity_bound =
                fixture_terminal_binding_matches(issued, &outcome.attestation, probe);
            let bound = outcome.schema == "rightkit.browser.fixture-outcome.v1"
                && outcome.status == FixtureOutcomeStatus::Passed
                && outcome.fixture_id == probe.fixture_id
                && outcome.probe_id == probe.probe_id
                && outcome.completed_actions == expected_actions
                && outcome.cleanup_complete
                && !cancelled
                && identity_bound
                && fixture_attestation_unexpired(&outcome.attestation)
                && fixture_cleanup_complete(&outcome.attestation);
            if !bound {
                return json!({
                    "status": "integrity-failed",
                    "reason": "fixture-outcome-binding-or-cleanup-invalid",
                    "completedActions": outcome.completed_actions,
                    "expectedActions": expected_actions,
                    "cleanupComplete": identity_bound && outcome.cleanup_complete && fixture_cleanup_complete(&outcome.attestation),
                    "attestation": outcome.attestation,
                });
            }
            json!({
                "status": "passed",
                "completedActions": outcome.completed_actions,
                "expectedActions": expected_actions,
                "cleanupComplete": true,
                "attestation": outcome.attestation,
            })
        }
        Err(failure) => {
            let bound = fixture_terminal_binding_matches(issued, &failure.attestation, probe);
            let reason = if bound {
                failure.cause.to_string()
            } else {
                "fixture-failure-attestation-binding-invalid".to_owned()
            };
            let cause = serde_json::to_value(&failure.cause).unwrap_or(Value::Null);
            let cleanup_error = failure
                .cleanup_error
                .as_ref()
                .and_then(|error| serde_json::to_value(error).ok());
            json!({
                "status": if bound { "failed" } else { "integrity-failed" },
                "reason": reason,
                "cause": cause,
                "completedActions": failure.completed_actions,
                "expectedActions": expected_actions,
                "cleanupComplete": bound && failure.cleanup_complete && fixture_cleanup_complete(&failure.attestation),
                "cleanupError": cleanup_error,
                "attestation": failure.attestation,
            })
        }
    }
}

fn fixture_probe_value(probe: &InteractionProbe, result: Result<Value, String>) -> Value {
    let (status, reason, result) = match result {
        Ok(value) => {
            let status = value
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("failed")
                .to_owned();
            let reason = value
                .get("reason")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned);
            (status, reason, value)
        }
        Err(reason) => (
            "unavailable".to_owned(),
            Some(reason.clone()),
            json!({
                "status": "unavailable",
                "reason": reason,
                "completedActions": 0,
                "expectedActions": probe.actions.len(),
                "cleanupComplete": false,
            }),
        ),
    };
    let mut output = probe.to_value();
    output["fixture"] = json!({
        "id": probe.fixture_id,
        "sourceDigest": probe.fixture_source_digest,
        "inventoryDigest": probe.fixture_inventory_digest,
        "fileCount": probe.fixture_files.len(),
    });
    output["status"] = json!(status);
    if let Some(reason) = reason {
        output["reason"] = json!(reason);
    }
    if let Some(object) = result.as_object() {
        for (key, value) in object {
            if key != "status" && key != "reason" {
                output[key] = value.clone();
            }
        }
    }
    output
}

fn unavailable_with_interactions(
    executor: &NativeLegacyCheckExecutor,
    provider: &AuditProvider,
    input: &LegacyCheckInput,
    plan_digest: &str,
    params: &RuntimeParams,
    reason: &str,
    fixture_outcomes: &[Value],
) -> Result<ProviderResult, AuditError> {
    let mut result = unavailable_result(executor, provider, input, plan_digest, reason)?;
    if params.interactions.is_empty() {
        return Ok(result);
    }
    let interaction_gaps = interaction_gaps(params, fixture_outcomes);
    let unsupported_gaps = params
        .unsupported
        .iter()
        .map(|label| format!("runtime-surface-unsupported:{label}"))
        .collect::<Vec<_>>();
    result
        .coverage_gaps
        .extend(interaction_gaps.iter().cloned());
    result
        .coverage_gaps
        .extend(unsupported_gaps.iter().cloned());
    if let Some(coverage) = result.coverage.as_mut() {
        coverage.gaps.extend(interaction_gaps.iter().cloned());
        coverage.gaps.extend(unsupported_gaps.iter().cloned());
    }
    let fixture_surfaces = fixture_surface_records(params, fixture_outcomes);
    result.details.insert(
        "runtime".into(),
        json!({
            "schemaVersion": 1,
            "kind": "audit-runtime",
            "url": params.url,
            "status": "unproven",
            "complete": false,
            "incomplete": true,
            "surfaces": [],
            "unsupportedSurfaces": params.unsupported,
            "fixtureBoundSurfaces": fixture_surfaces,
            "interactions": interaction_outcomes(params, fixture_outcomes),
            "interactionCoverage": {
                "expected": params.interactions.len(),
                "examined": fixture_outcomes.len(),
                "passed": passed_interaction_count(fixture_outcomes),
                "gaps": interaction_gaps,
            },
            "denominator": {
                "kind": "runtime-surfaces-and-probes",
                "expected": params.live_surfaces().len() + params.unsupported.len() + params.interactions.len(),
                "examined": passed_interaction_count(fixture_outcomes),
            },
        }),
    );
    result.coverage_gaps.sort();
    result.coverage_gaps.dedup();
    if let Some(coverage) = result.coverage.as_mut() {
        coverage.gaps.sort();
        coverage.gaps.dedup();
    }
    result
        .validate()
        .map_err(|error| AuditError::Provider(error.to_string()))?;
    Ok(result)
}

fn accessibility_summary(accessibility: &[&Value]) -> (&'static str, Option<u64>, Option<u64>) {
    let ran = accessibility
        .iter()
        .filter(|result| result.get("status").and_then(Value::as_str) == Some("ran"))
        .collect::<Vec<_>>();
    let all_ran = !accessibility.is_empty() && ran.len() == accessibility.len();
    let observed_total = (!ran.is_empty()).then(|| {
        ran.iter()
            .map(|result| {
                result
                    .get("totalViolations")
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            })
            .sum()
    });
    let any_error = accessibility
        .iter()
        .any(|result| result.get("status").and_then(Value::as_str) == Some("error"));
    let status = if all_ran {
        "ran"
    } else if !ran.is_empty() {
        "partial"
    } else if any_error {
        "error"
    } else if accessibility.is_empty() {
        "not-run"
    } else {
        "unavailable"
    };
    let total = all_ran.then_some(observed_total).flatten();
    (status, total, observed_total)
}

/// Attach runtime observation metadata to a finding without promoting the
/// captured artifact into a repository source location or anchor.
fn push_runtime_finding(
    output: &mut super::LegacyCheckOutput,
    rule: &str,
    severity: &str,
    path: &str,
    line: usize,
    message: &str,
    outcome: &SurfaceOutcome,
) {
    push_finding(output, rule, severity, path, line, message);
    let Some(finding) = output.findings.last() else {
        return;
    };
    let finding_id = finding.id.to_string();
    let Some(evidence) = output
        .details
        .get_mut("findingEvidence")
        .and_then(Value::as_object_mut)
        .and_then(|findings| findings.get_mut(&finding_id))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    evidence.insert(
        "runtimeCapture".into(),
        json!({
            "surface": outcome.label.as_str(),
            "url": outcome.url.as_str(),
            "screenshot": outcome.screenshot.as_ref(),
        }),
    );
}

pub(super) async fn execute(
    executor: &NativeLegacyCheckExecutor,
    plan: &crate::FrozenPlan,
    provider: &AuditProvider,
    input: &LegacyCheckInput,
    cancellation: CancellationToken,
) -> Result<ProviderResult, AuditError> {
    let plan_digest = plan.digest().to_string();
    let params = match RuntimeParams::from_provider(provider) {
        Ok(Some(params)) => params,
        Ok(None) => {
            return unavailable_result(executor, provider, input, &plan_digest, UNAVAILABLE_URL);
        }
        Err(reason) => {
            return unavailable_result(
                executor,
                provider,
                input,
                &plan_digest,
                &format!("runtime-inputs-invalid:{reason}"),
            );
        }
    };
    if !params.interactions.is_empty() {
        let mut request = base_request(
            provider,
            &plan_digest,
            input,
            "fixture-browser-admission",
            &executor.root,
            params
                .interactions
                .iter()
                .flat_map(|probe| {
                    [
                        "--fixture".into(),
                        probe.fixture_id.clone(),
                        "--source-digest".into(),
                        probe.fixture_source_digest.clone(),
                        "--probe".into(),
                        probe.probe_id.clone(),
                        "--actions-digest".into(),
                        probe.actions_digest.clone(),
                    ]
                })
                .collect(),
        );
        request.executable = "rightweb-fixture-browser".into();
        request.task_id = Some("runtime-fixture-browser-session".into());
        let decision = match &executor.fixture_policy_authorizer {
            Some(authorizer) => authorizer.authorize(&request),
            None => legion_effects::PolicyAuthorizer::authorize(
                &crate::execution_policy::OwnerAdmissionRequired,
                &request,
            ),
        };
        if !decision.allowed {
            // The same effect executor issues the real denial receipt before
            // FixtureServer preparation or browser/session launch.
            #[cfg(unix)]
            let process = legion_effects::platform::unix::UnixProcess::new();
            #[cfg(windows)]
            let process = legion_effects::platform::windows::WindowsProcess::default();
            let scratch = executor.scratch()?;
            let effects = legion_effects::EffectExecutor::new(
                process,
                legion_effects::ArtifactWriter::new(scratch.artifacts_dir()),
                legion_effects::StaticPolicy { decision },
            );
            let receipt = effects
                .execute_with_cancellation(&request, cancellation)
                .await;
            let contract = spec(&provider.id).expect("validated above");
            let execution = super::execution_from_receipt(
                input,
                contract.command,
                &[executor.root.as_path()],
                receipt,
                super::ReportSource::Stdout,
                None,
                None,
            );
            return super::LegacyCheckDispatcher::new()
                .project_result(provider, input, execution)
                .map_err(|error| AuditError::Provider(error.to_string()));
        }
    }
    let mut fixture_outcomes = Vec::with_capacity(params.interactions.len());
    for probe in &params.interactions {
        fixture_outcomes.push(execute_fixture_probe(probe, &cancellation).await);
    }
    if fixture_only(&params) {
        let mut result = assemble(
            provider,
            input,
            &params,
            Vec::new(),
            "not-run",
            fixture_outcomes,
        )?;
        // This receipt covers only the refused external live-project route.
        // FixtureSession launch, identity & cleanup remain in fixture attestations.
        let args = command_parts(spec(&provider.id).expect("validated above").command).1;
        let request = base_request(
            provider,
            &plan_digest,
            input,
            "fixture-only-live-capture",
            &executor.root,
            args,
        );
        let state = if cancellation.is_cancelled() {
            ExecutionState::Cancelled
        } else {
            ExecutionState::Blocked
        };
        let receipt = ExecutionReceipt::failure(
            &request,
            state,
            "runtime-live-capture-disabled-for-frozen-fixtures",
        );
        result
            .details
            .insert("executionReceipt".into(), receipt_json(&receipt));
        result
            .details
            .insert("receiptId".into(), json!(receipt.receipt_id));
        result
            .details
            .insert("processState".into(), json!(receipt.state.as_str()));
        return Ok(result);
    }
    let Some(tool) = executor.external_project_tool.clone() else {
        return unavailable_with_interactions(
            executor,
            provider,
            input,
            &plan_digest,
            &params,
            "external-project-tool-capability-unavailable",
            &fixture_outcomes,
        );
    };
    let scratch = executor.scratch()?;
    let (mut environment, mut allowlist) = audit_environment(&scratch);
    // The route locates the browser from these, when the operator set them.
    for name in ["CHROME_PATH", "QA_BROWSER"] {
        if let Ok(value) = std::env::var(name) {
            environment.insert(name.to_owned(), value);
            allowlist.insert(name.to_owned());
        }
    }
    let sequence = AUDIT_ARTIFACT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let work_dir = scratch.tmp_dir().join(format!("runtime-{sequence}"));
    let shot_dir = params
        .artifact_dir
        .clone()
        .unwrap_or_else(|| work_dir.join("shots"));
    let artifacts_dir = scratch.artifacts_dir();
    let roots = [artifacts_dir.as_path(), executor.root.as_path()];
    let base_args = command_parts(spec(&provider.id).expect("validated above").command).1;

    let (axe_source, axe_source_label) = load_axe_source(&executor.root);
    let axe_expression = axe_expression(Some(&axe_source), "");
    let ctx = Ctx {
        tool: &*tool,
        provider,
        input,
        plan_digest: &plan_digest,
        params: &params,
        axe_expression,
        base_args: &base_args,
        environment: &environment,
        allowlist: &allowlist,
        work_dir: &work_dir,
        shot_dir: &shot_dir,
        roots: &roots,
        cancellation: &cancellation,
    };
    let mut outcomes = Vec::new();
    for (index, label, url) in params.live_surfaces() {
        outcomes.push(capture_surface(&ctx, index, &label, &url).await);
    }
    assemble(
        provider,
        input,
        &params,
        outcomes,
        &axe_source_label,
        fixture_outcomes,
    )
}

fn fixture_only(params: &RuntimeParams) -> bool {
    !params.interactions.is_empty() && params.live_surfaces().is_empty()
}

fn assemble(
    provider: &AuditProvider,
    input: &LegacyCheckInput,
    params: &RuntimeParams,
    mut outcomes: Vec<SurfaceOutcome>,
    axe_source: &str,
    fixture_outcomes: Vec<Value>,
) -> Result<ProviderResult, AuditError> {
    let provider_id =
        ProviderId::new(&provider.id).map_err(|error| AuditError::Provider(error.to_string()))?;
    let expected_surfaces = params.live_surfaces().len();
    let passed_probes = passed_interaction_count(&fixture_outcomes);
    let captured = outcomes
        .iter()
        .filter(|outcome| outcome.status == "captured")
        .count();

    // Findings: console errors and exceptions of captured surfaces. Locations
    // must lie inside the frozen denominator, so they point at its first entry;
    // the surface and URL are in the message and in `details.runtime`.
    let mut output = empty_output(Vec::new());
    let location = safe_location(input, "");
    let mut seen = BTreeSet::new();
    let mut console_total = 0_usize;
    let accessibility = outcomes
        .iter()
        .map(|outcome| &outcome.accessibility)
        .collect::<Vec<_>>();
    let (a11y_status, a11y_total, a11y_observed_total) = accessibility_summary(&accessibility);
    for outcome in outcomes.iter().filter(|o| o.status == "captured") {
        console_total += outcome.console_errors.len() + outcome.console_warnings.len();
        for entry in &outcome.console_errors {
            let digest = hex::encode(Sha256::digest(entry.as_bytes()));
            let key = (outcome.index, digest.clone());
            if !seen.insert(key) {
                continue;
            }
            let rule = format!("runtime.console-error:{}:{}", outcome.index, &digest[..12]);
            let message = format!("{} ({}): {}", outcome.label, outcome.url, entry);
            push_runtime_finding(
                &mut output,
                &rule,
                "warning",
                &location,
                1,
                &message,
                outcome,
            );
        }
        if let Some(violations) = outcome
            .accessibility
            .get("violations")
            .and_then(Value::as_array)
        {
            for violation in violations {
                let id = violation
                    .get("id")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let impact = violation
                    .get("impact")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown");
                let help = violation
                    .get("help")
                    .and_then(Value::as_str)
                    .unwrap_or("axe violation");
                let target = violation
                    .get("target")
                    .and_then(Value::as_str)
                    .unwrap_or("document");
                let count = violation.get("count").and_then(Value::as_u64).unwrap_or(1);
                let help_url = violation
                    .get("helpUrl")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let rule = format!("runtime.a11y:{id}:{}", outcome.index);
                let message = format!(
                    "{} ({}): {id} [{impact}] {help}; target {target}; {count} node(s){}",
                    outcome.label,
                    outcome.url,
                    if help_url.is_empty() {
                        String::new()
                    } else {
                        format!("; {help_url}")
                    }
                );
                let severity = if matches!(impact, "critical" | "serious") {
                    "error"
                } else {
                    "warning"
                };
                push_runtime_finding(
                    &mut output,
                    &rule,
                    severity,
                    &location,
                    1,
                    &message,
                    outcome,
                );
            }
        }
    }
    let findings = std::mem::take(&mut output.findings);
    let mut details: BTreeMap<String, Value> = std::mem::take(&mut output.details);

    let mut gaps: Vec<String> = Vec::new();
    for label in &params.unsupported {
        gaps.push(format!("runtime-surface-unsupported:{label}"));
    }
    for outcome in &mut outcomes {
        if outcome.performance.is_none() {
            outcome.gaps.push(format!(
                "runtime-performance-not-captured:{}",
                outcome.label
            ));
        }
    }
    for outcome in &outcomes {
        gaps.extend(outcome.gaps.iter().cloned());
    }
    let interaction_gaps = interaction_gaps(params, &fixture_outcomes);
    gaps.extend(interaction_gaps.iter().cloned());
    let mut degradation: Vec<String> = Vec::new();
    for outcome in &outcomes {
        if outcome.status != "captured" || !outcome.receipt_complete {
            degradation.push(format!(
                "external-process:{}:{}",
                outcome.label, outcome.process_state
            ));
        }
    }
    let unavailable_reason = if captured == 0 {
        outcomes
            .iter()
            .find_map(|outcome| outcome.unavailable.clone())
            .or_else(|| {
                if fixture_only(params) && passed_probes == 0 {
                    fixture_outcomes.iter().find_map(|outcome| {
                        if outcome.get("status").and_then(Value::as_str) == Some("unavailable") {
                            outcome
                                .get("reason")
                                .and_then(Value::as_str)
                                .map(str::to_owned)
                        } else {
                            None
                        }
                    })
                } else {
                    None
                }
            })
    } else {
        None
    };
    gaps.sort();
    gaps.dedup();
    degradation.sort();
    degradation.dedup();

    let expected = input.denominator.entries.len() as u64;
    let all_captured = captured == expected_surfaces
        && (expected_surfaces > 0 || !params.interactions.is_empty())
        && passed_probes == params.interactions.len()
        && params.unsupported.is_empty();
    let status = if captured > 0
        || passed_probes > 0
        || unavailable_reason.is_some()
        || !params.interactions.is_empty()
    {
        ProviderStatus::Partial
    } else {
        ProviderStatus::Failed
    };

    let surfaces_json: Vec<Value> = outcomes
        .iter()
        .map(|outcome| {
            json!({
                "index": outcome.index,
                "label": outcome.label,
                "url": outcome.url,
                "viewport": {"width": params.width, "height": params.height},
                "status": outcome.status,
                "screenshot": outcome.screenshot,
                "performance": outcome.performance.clone().unwrap_or(Value::Null),
                "accessibility": outcome.accessibility,
                "consoleErrors": outcome.console_errors,
                "consoleWarnings": outcome.console_warnings,
                "gaps": outcome.gaps,
                "failure": outcome.failure,
                "receiptId": outcome.receipt.get("receiptId"),
                "processState": outcome.process_state,
                "exitCode": outcome.exit_code,
            })
        })
        .collect();
    let fixture_bound_surfaces = fixture_surface_records(params, &fixture_outcomes);
    details.insert(
        "runtime".to_owned(),
        json!({
            "schemaVersion": 1,
            "kind": "audit-runtime",
            "source": if fixture_only(params) { "rightkit-browser/fixture-session" }
                else if params.interactions.is_empty() { "legion script qa/qa-functional" }
                else { "legion script qa/qa-functional+rightkit-browser/fixture-session" },
            "url": params.url,
            "viewport": {"width": params.width, "height": params.height},
            "status": "unproven",
            "complete": false,
            "incomplete": true,
            "surfaces": surfaces_json,
            "fixtureBoundSurfaces": fixture_bound_surfaces,
            "interactions": interaction_outcomes(params, &fixture_outcomes),
            "interactionCoverage": {
                "expected": params.interactions.len(),
                "examined": fixture_outcomes.len(),
                "passed": passed_probes,
                "gaps": interaction_gaps,
            },
            "unsupportedSurfaces": params.unsupported,
            "denominator": {
                "kind": if params.interactions.is_empty() { "runtime-surfaces" } else { "runtime-surfaces-and-probes" },
                "expected": expected_surfaces + params.unsupported.len() + params.interactions.len(),
                "examined": captured + passed_probes,
            },
            "console_total": console_total,
            "a11y_axe": a11y_status,
            "axeCoreSource": axe_source,
            "a11y_violations_total": a11y_total,
            "a11y_violations_observed_total": a11y_observed_total,
            "coverageGaps": gaps,
            "degradation": degradation,
        }),
    );
    let representative = outcomes
        .iter()
        .find(|outcome| !outcome.receipt_complete)
        .or_else(|| outcomes.first());
    if let Some(outcome) = representative {
        details.insert("executionReceipt".to_owned(), outcome.receipt.clone());
        if let Some(id) = outcome.receipt.get("receiptId").and_then(Value::as_str) {
            details.insert("receiptId".to_owned(), Value::String(id.to_owned()));
        }
    }
    details.insert(
        "executionReceipts".to_owned(),
        Value::Array(outcomes.iter().map(|o| o.receipt.clone()).collect()),
    );
    details.insert("check".to_owned(), Value::String("runtime".into()));
    details.insert("tool".to_owned(), Value::String("audit-runtime.mjs".into()));
    details.insert("commandShape".to_owned(), Value::String("named".into()));
    details.insert("candidates".to_owned(), Value::Array(Vec::new()));
    let process_state = outcomes
        .iter()
        .find(|outcome| outcome.process_state != "completed")
        .map(|outcome| outcome.process_state.clone())
        .unwrap_or_else(|| {
            if outcomes.is_empty() {
                "not-used"
            } else {
                "completed"
            }
            .to_owned()
        });
    details.insert("processState".to_owned(), Value::String(process_state));
    details.insert(
        "exitCode".to_owned(),
        outcomes
            .first()
            .and_then(|outcome| outcome.exit_code)
            .map(Value::from)
            .unwrap_or(Value::Null),
    );

    let mut result = ProviderResult {
        schema_version: 1,
        provider: provider_id,
        applicable: true,
        required: provider.required,
        status,
        complete: false,
        coverage: Some(Coverage {
            denominator_digest: input.denominator.digest.clone(),
            expected,
            examined: if all_captured { expected } else { 0 },
            gaps: gaps.clone(),
        }),
        findings,
        coverage_gaps: gaps,
        degradation,
        details,
    };
    if let Some(reason) = &unavailable_reason {
        availability::mark_unavailable(&mut result, reason);
    }
    result
        .validate()
        .map_err(|error| AuditError::Provider(error.to_string()))?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_test_params(actions: Value) -> RuntimeParams {
        // Allocate an unused exact endpoint, then let FixtureServer exclusively bind it.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/index.html", listener.local_addr().unwrap());
        drop(listener);
        let body = b"<!doctype html><meta charset=utf-8><link rel=icon href=data:,><input id=value><p id=frozen>Frozen source</p>";
        let files = vec![json!({
            "sourcePath":"never-read-from-live-root.html",
            "sourceDigest":sha256_label(body),
            "path":"/index.html",
            "contentType":"text/html; charset=utf-8",
            "body":body.to_vec(),
        })];
        let source_digest = FixtureBundle::source_digest(&[FixtureFile {
            path: "/index.html".into(),
            content_type: "text/html; charset=utf-8".into(),
            body: body.to_vec(),
        }])
        .unwrap();
        RuntimeParams::from_value(&json!({
            "url":url,
            "interactions":[{
                "id":"native-fixture",
                "surface":{"label":"entry","url":url},
                "fixture":{
                    "id":"native-fixture",
                    "sourceDigest":source_digest,
                    "inventoryDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "files":files,
                },
                "probe":{"id":"native-probe","actionsDigest":legion_contracts::canonical_digest(&actions).unwrap()},
                "isolationBindingId":"frozen-source-only",
                "expiresAfterMs":30000,
                "actions":actions,
            }],
        })).unwrap().unwrap()
    }

    async fn execute_test_runtime(
        params: &RuntimeParams,
        cancellation: CancellationToken,
    ) -> ProviderResult {
        execute_test_runtime_with_admission(params, cancellation, true).await
    }

    async fn execute_test_runtime_with_admission(
        params: &RuntimeParams,
        cancellation: CancellationToken,
        admitted: bool,
    ) -> ProviderResult {
        let root = std::env::current_dir().unwrap();
        let inventory = crate::inventory::InventoryEnvelope::new(
            "fixture-only-runtime",
            "generation",
            vec![crate::inventory::InventoryEntry {
                path: "index.html".into(),
                symbols: Vec::new(),
                dependencies: Vec::new(),
                package_scripts: Vec::new(),
                source_file: true,
                digest: None,
            }],
        )
        .unwrap();
        let provider_spec: legion_contracts::ProviderSpec = serde_json::from_value(json!({
            "schemaVersion":2,
            "id":"legacy.runtime.app",
            "providerVersion":"2.0.0",
            "family":"performance",
            "role":"deterministic",
            "phase":"runtime",
            "lensIds":["runtime"],
            "dependsOn":[],
            "consumes":[],
            "produces":["provider-result"],
            "selector":{"op":"always"},
            "denominatorKind":"runnable app",
            "runner":{"kind":"legacy-check","check":"runtime","runtime":params.to_value()},
            "hostCapabilities":[],
            "execution":{},
            "reasoning":{},
            "benchmark":{"status":"unproven","requiredForCleanClaim":false},
            "cleanClaim":"evidence-only",
            "controlIds":[],
            "scopes":[],
            "selectable":true
        }))
        .unwrap();
        let plan = crate::plan::AuditPlan::compile(&inventory, &[provider_spec])
            .unwrap()
            .freeze(Some(b"fixture-only-runtime"))
            .unwrap();
        let provider = plan.provider("legacy.runtime.app").unwrap();
        let input = crate::native_providers::legacy_checks::LegacyCheckDispatcher::new()
            .input(provider, &inventory, &root, None, None, &Value::Null)
            .unwrap();
        let mut executor = NativeLegacyCheckExecutor::new(root);
        if admitted {
            executor = executor.with_fixture_policy_authorizer(std::sync::Arc::new(
                legion_effects::StaticPolicy {
                    decision: legion_effects::PolicyDecision {
                        allowed: true,
                        policy_id: "runtime-fixture-test".into(),
                        policy_version: 1,
                        policy_digest: format!("sha256:{}", "f".repeat(64)),
                        reason: None,
                    },
                },
            ));
        }
        let result = execute(&executor, &plan, provider, &input, cancellation)
            .await
            .unwrap();
        crate::execution::validate_external_receipt_projection(
            &provider.id,
            &result.details,
            result.complete,
        )
        .unwrap();
        result
    }

    #[tokio::test]
    async fn default_fixture_admission_denies_before_server_browser_and_actions() {
        let params = fixture_test_params(json!([{"type":"assertVisible","selector":"#frozen"}]));
        let result =
            execute_test_runtime_with_admission(&params, CancellationToken::new(), false).await;
        assert_eq!(result.status, ProviderStatus::Partial);
        assert!(!result.complete);
        assert_eq!(
            result.details["availability"]["reason"],
            crate::execution_policy::ADMISSION_UNAVAILABLE
        );
        let receipt = &result.details["executionReceipt"];
        assert_eq!(receipt["state"], "unauthorized_effect");
        assert_eq!(receipt["processTree"]["started"], false);
        assert_eq!(receipt["executable"], Value::Null);
        assert_eq!(receipt["command"]["executable"], "rightweb-fixture-browser");
        assert!(receipt["command"]["args"]
            .as_array()
            .unwrap()
            .contains(&json!(params.interactions[0].actions_digest)));
        assert_eq!(
            receipt["executionPolicy"],
            crate::execution_policy::resolved_policy()
        );
        assert!(result
            .coverage
            .as_ref()
            .is_some_and(|coverage| coverage.expected > 0 && coverage.examined == 0));
        assert!(
            !result.details.contains_key("runtime"),
            "no fixture session or action was executed"
        );
    }

    #[test]
    fn params_without_url_are_not_supplied() {
        assert_eq!(RuntimeParams::from_value(&Value::Null), Ok(None));
        assert_eq!(RuntimeParams::from_value(&json!({})), Ok(None));
        assert_eq!(RuntimeParams::from_value(&json!({"url": "  "})), Ok(None));
    }

    #[test]
    fn params_validate_url_viewport_and_surfaces() {
        let params = RuntimeParams::from_value(&json!({
            "url": "http://127.0.0.1:1422/?qa=1",
            "width": 390,
            "height": 844,
            "surfaces": [{"label": "settings", "url": "http://127.0.0.1:1422/settings"}],
            "unsupportedSurfaces": ["editor"],
        }))
        .unwrap()
        .unwrap();
        assert_eq!(params.width, 390);
        assert_eq!(params.height, 844);
        assert_eq!(
            params.all_surfaces(),
            vec![
                ("entry".to_owned(), "http://127.0.0.1:1422/?qa=1".to_owned()),
                (
                    "settings".to_owned(),
                    "http://127.0.0.1:1422/settings".to_owned()
                ),
            ]
        );
        assert_eq!(params.unsupported, vec!["editor".to_owned()]);
        // Defaults when the viewport is absent.
        let defaults = RuntimeParams::from_value(&json!({"url": "https://example.test/"}))
            .unwrap()
            .unwrap();
        assert_eq!((defaults.width, defaults.height), (1280, 800));
    }

    #[test]
    fn frozen_interactions_are_digest_bound_and_cancellation_prevents_launch() {
        let fixture_body = serde_json::to_value(b"<main>fixture</main>").unwrap();
        let fixture_file = json!({
            "sourcePath":"index.html",
            "sourceDigest":sha256_label(b"<main>fixture</main>"),
            "path":"/index.html",
            "contentType":"text/html",
            "body":fixture_body,
        });
        let fixture_digest = legion_contracts::canonical_digest(&json!({
            "files":[{"body":fixture_file["body"],"contentType":"text/html","path":"/index.html"}]
        }))
        .unwrap();
        let fixture = json!({
            "id":"profile-fixture",
            "sourceDigest":fixture_digest,
            "inventoryDigest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "files":[fixture_file],
        });
        let actions = json!([
            {"type":"click","selector":"button.save"},
            {"type":"type","text":"fixture value"},
            {"type":"press","key":"Tab"},
            {"type":"assertVisible","selector":".status","timeout":100},
            {"type":"assertText","selector":".status","text":"Saved"}
        ]);
        let action_digest = legion_contracts::canonical_digest(&actions).unwrap();
        let mut descriptor = json!({
            "id":"profile-save",
            "surface":{"label":"entry","url":"http://127.0.0.1:1422/index.html"},
            "fixture":fixture,
            "probe":{"id":"save-probe","actionsDigest":action_digest},
            "isolationBindingId":"isolated-profile-fixture",
            "expiresAfterMs":30000,
            "actions":actions,
        });
        let params = RuntimeParams::from_value(&json!({
            "url":"http://127.0.0.1:1422/index.html",
            "unsupportedSurfaces":["editor"],
            "interactions":[descriptor.clone()],
        }))
        .unwrap()
        .unwrap();
        assert_eq!(params.interactions.len(), 1);
        assert!(params.live_surfaces().is_empty());
        assert!(fixture_only(&params));

        let mixed = RuntimeParams::from_value(&json!({
            "url":"http://127.0.0.1:1422/index.html",
            "surfaces":[{"label":"settings","url":"http://127.0.0.1:1422/settings"}],
            "interactions":[descriptor.clone()],
        }))
        .unwrap()
        .unwrap();
        assert!(!fixture_only(&mixed));

        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(execute_test_runtime(&params, cancellation));
        assert!(!result.complete);
        assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
        assert_eq!(result.details["executionReceipts"], json!([]));
        assert_eq!(result.details["executionReceipt"]["state"], "cancelled");
        assert_eq!(result.details["processState"], "cancelled");
        assert_eq!(
            result.details["executionReceipt"]["processTree"]["started"],
            false
        );
        assert_eq!(
            result.details["executionReceipt"]["gaps"],
            json!(["runtime-live-capture-disabled-for-frozen-fixtures"])
        );
        assert!(result.details["runtime"]["interactions"][0]
            .get("attestation")
            .is_none());
        assert!(result
            .coverage_gaps
            .iter()
            .any(|gap| gap
                == "runtime-probe-unavailable:profile-save:fixture-cancelled-before-start"));
        assert!(result
            .coverage_gaps
            .iter()
            .any(|gap| gap == "runtime-surface-unsupported:editor"));
        assert_eq!(
            result.details["runtime"]["unsupportedSurfaces"],
            json!(["editor"])
        );
        assert_eq!(
            result.details["runtime"]["interactionCoverage"]["examined"],
            1
        );
        assert_eq!(result.details["runtime"]["denominator"]["expected"], 2);
        assert_eq!(result.details["runtime"]["denominator"]["examined"], 0);
        assert_eq!(
            result.details["runtime"]["interactions"][0]["reason"],
            "fixture-cancelled-before-start"
        );
        assert_eq!(
            result.details["runtime"]["interactions"][0]["fixture"]["id"],
            "profile-fixture"
        );
        assert_eq!(
            result.details["runtime"]["interactions"][0]["fixture"]["fileCount"],
            1
        );
        assert_eq!(
            result.details["runtime"]["fixtureBoundSurfaces"][0]["coverage"],
            "fixture-only-not-live-surface-evidence"
        );
        assert_eq!(
            fixture_actions_digest(&fixture_actions(&params.interactions[0]).unwrap()).unwrap(),
            params.interactions[0].actions_digest
        );
        let fixture_record = fixture_surface_records(&params, &[json!({"status":"passed"})]);
        assert_eq!(fixture_record[0]["status"], "fixture-probe-passed");
        assert_eq!(
            fixture_record[0]["coverage"],
            "fixture-only-not-live-surface-evidence"
        );
        let result = params.interactions[0].result_value();
        assert_eq!(result["status"], "unavailable");
        assert_eq!(result["reason"], "rightkit-fixture-api-unavailable");
        assert_eq!(
            params.to_value()["interactions"][0]["fixture"]["files"][0]["body"],
            fixture_body
        );

        let mut invalid_expiry = descriptor.clone();
        invalid_expiry["expiresAfterMs"] = json!(0);
        assert_eq!(
            RuntimeParams::from_value(&json!({
                "url":"http://127.0.0.1:1422/index.html",
                "interactions":[invalid_expiry],
            })),
            Err("runtime-interaction-expiry-invalid".into())
        );

        let mut path_mismatch = descriptor.clone();
        path_mismatch["surface"] =
            json!({"label":"other","url":"http://127.0.0.1:1422/other.html"});
        assert_eq!(
            RuntimeParams::from_value(&json!({
                "url":"http://127.0.0.1:1422/index.html",
                "surfaces":[{"label":"other","url":"http://127.0.0.1:1422/other.html"}],
                "interactions":[path_mismatch],
            })),
            Err("runtime-interaction-fixture-url-path-mismatch".into())
        );

        descriptor["actions"] = json!([{"type":"eval","expression":"fetch('/mutate')"}]);
        descriptor["probe"]["actionsDigest"] =
            json!(legion_contracts::canonical_digest(&descriptor["actions"]).unwrap());
        let eval = RuntimeParams::from_value(&json!({
            "url":"http://127.0.0.1:1422/index.html",
            "interactions":[descriptor],
        }));
        assert_eq!(eval, Err("runtime-interaction-actions-invalid".into()));

        let mut non_loopback = json!({
            "id":"external",
            "surface":{"label":"entry","url":"https://example.test/"},
            "fixture":fixture,
            "probe":{"id":"p","actionsDigest":action_digest},
            "isolationBindingId":"binding",
            "expiresAfterMs":30000,
            "actions":[{"type":"click","selector":"button"}],
        });
        let one_action = json!([{"type":"click","selector":"button"}]);
        non_loopback["probe"]["actionsDigest"] =
            json!(legion_contracts::canonical_digest(&one_action).unwrap());
        assert_eq!(
            RuntimeParams::from_value(&json!({
                "url":"http://127.0.0.1:1422/index.html",
                "interactions":[non_loopback],
            })),
            Err("runtime-interaction-surface-url-not-loopback".into())
        );

        for url in [
            "http://127.0.0.2/",
            "http://localhost:/",
            "http://[::1]example.test/",
        ] {
            assert!(check_loopback_url(url).is_err(), "{url}");
        }
        for url in [
            "http://localhost/",
            "http://127.0.0.1:8080/",
            "https://[::1]/",
        ] {
            assert!(check_loopback_url(url).is_ok(), "{url}");
        }

        let action_order_a: Value =
            serde_json::from_str(r#"[{"type":"click","selector":"button"}]"#).unwrap();
        let action_order_b: Value =
            serde_json::from_str(r#"[{"selector":"button","type":"click"}]"#).unwrap();
        assert_eq!(
            legion_contracts::canonical_digest(&action_order_a).unwrap(),
            legion_contracts::canonical_digest(&action_order_b).unwrap()
        );
    }

    #[test]
    fn fixture_exact_url_requires_an_explicit_unencoded_bundle_path() {
        assert_eq!(
            exact_fixture_url_path("http://127.0.0.1:1422/index.html"),
            Some("/index.html")
        );
        for url in [
            "http://127.0.0.1:1422/",
            "http://127.0.0.1:1422/%69ndex.html",
            "http://127.0.0.1:1422/index.html?x=1",
            "http://127.0.0.1:1422/index.html#top",
            "http://127.0.0.1:0/index.html",
        ] {
            assert_eq!(exact_fixture_url_path(url), None, "{url}");
        }
    }

    #[test]
    fn frozen_fixture_bytes_reject_tampering_and_missing_resources() {
        let params = fixture_test_params(json!([{"type":"assertVisible","selector":"#frozen"}]));
        let probe = &params.interactions[0];
        assert_eq!(fixture_files(probe).unwrap()[0].body,
            b"<!doctype html><meta charset=utf-8><link rel=icon href=data:,><input id=value><p id=frozen>Frozen source</p>");
        let mut changed = params.to_value();
        changed["interactions"][0]["fixture"]["files"][0]["body"][0] = json!(0);
        assert_eq!(
            RuntimeParams::from_value(&changed),
            Err("runtime-interaction-fixture-source-digest-mismatch".into())
        );
        let mut missing = params.to_value();
        missing["url"] = json!(probe.surface_url.replace("index.html", "absent.html"));
        missing["interactions"][0]["surface"]["url"] = missing["url"].clone();
        assert_eq!(
            RuntimeParams::from_value(&missing),
            Err("runtime-interaction-fixture-url-path-mismatch".into())
        );
    }

    #[cfg(any(target_os = "macos", windows))]
    async fn assert_native_fixture_cleanup(value: &Value) {
        assert_eq!(value["cleanupComplete"], true, "{value}");
        let attestation: FixtureAttestation =
            serde_json::from_value(value["attestation"].clone()).unwrap();
        assert!(fixture_cleanup_complete(&attestation));
        assert!(
            !Path::new(&attestation.profile_identity).exists(),
            "profile survived cleanup"
        );
        let endpoint = attestation.server_endpoint.parse().unwrap();
        assert!(
            std::net::TcpStream::connect_timeout(&endpoint, std::time::Duration::from_millis(300))
                .is_err(),
            "fixture listener survived cleanup"
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        let listener = loop {
            match std::net::TcpListener::bind(endpoint) {
                Ok(listener) => break listener,
                Err(_) if tokio::time::Instant::now() < deadline => {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                Err(error) => panic!("fixture socket failed to rebind after cleanup: {error}"),
            }
        };
        drop(listener);
        #[cfg(target_os = "macos")]
        let status = std::process::Command::new("kill")
            .args(["-0", &attestation.browser_pid.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        #[cfg(windows)]
        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &format!(
                "if (Get-Process -Id {} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}",
                attestation.browser_pid)])
            .status().unwrap();
        assert!(!status.success(), "fixture browser survived cleanup");
    }

    /// CI explicitly runs this selector with --ignored on both supported hosts.
    /// Missing assets fail qualification; no synthetic host identity or skipped success.
    #[cfg(any(target_os = "macos", windows))]
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "requires provisioned Chrome for Testing; Windows also needs headless shell"]
    async fn native_fixture_qualification() {
        rightkit_browser::chrome_for_testing_path(None)
            .expect("native fixture assets must be provisioned");
        let actions = json!([
            {"type":"click","selector":"#value"},
            {"type":"type","text":"native input"},
            {"type":"press","key":"Tab"},
            {"type":"assertText","selector":"#frozen","text":"Frozen source"},
        ]);
        let params = fixture_test_params(actions.clone());
        let result = execute_test_runtime(&params, CancellationToken::new()).await;
        let evidence = &result.details["runtime"]["interactions"][0];
        assert_eq!(evidence["status"], "passed", "{result:?}");
        assert_native_fixture_cleanup(evidence).await;
        assert_eq!(
            result.details["runtime"]["source"],
            "rightkit-browser/fixture-session"
        );
        assert_eq!(result.details["runtime"]["denominator"]["expected"], 1);
        assert_eq!(result.details["runtime"]["denominator"]["examined"], 1);
        assert_eq!(
            result.coverage.as_ref().unwrap().examined,
            result.coverage.as_ref().unwrap().expected
        );
        assert!(result.coverage_gaps.is_empty(), "{result:?}");
        assert_eq!(result.details["runtime"]["a11y_axe"], "not-run");
        assert!(result.details["runtime"]["a11y_violations_total"].is_null());
        assert_eq!(result.details["executionReceipts"], json!([]));
        assert_eq!(result.details["executionReceipt"]["state"], "blocked");
        assert_eq!(
            result.details["executionReceipt"]["processTree"]["started"],
            false
        );
        assert_eq!(
            result.details["executionReceipt"]["gaps"],
            json!(["runtime-live-capture-disabled-for-frozen-fixtures"])
        );
        assert!(!result.complete); // Evidence-only provider never claims whole-app cleanliness.

        let mut mixed = fixture_test_params(actions.clone());
        mixed
            .surfaces
            .push(("live".into(), "http://127.0.0.1:9/live".into()));
        let mixed_result = execute_test_runtime(&mixed, CancellationToken::new()).await;
        assert_eq!(
            mixed_result.details["runtime"]["interactionCoverage"]["passed"],
            1
        );
        assert_native_fixture_cleanup(&mixed_result.details["runtime"]["interactions"][0]).await;
        assert_eq!(
            mixed_result.details["runtime"]["denominator"]["expected"],
            2
        );
        assert_eq!(
            mixed_result.details["runtime"]["denominator"]["examined"],
            1
        );
        assert!(mixed_result
            .coverage_gaps
            .iter()
            .any(|gap| gap.contains("external-project-tool-capability-unavailable")));

        let params = fixture_test_params(actions);
        let probe = &params.interactions[0];
        let session = launch_fixture_probe(probe).await.expect("native session");
        let issued = session.attestation().clone();
        let outcome = session
            .run_with_cancel(FixtureCancellation::new())
            .await
            .expect("real successful outcome");
        let accepted = fixture_terminal_value(probe, &issued, Ok(outcome.clone()), false);
        assert_eq!(accepted["status"], "passed");
        assert_native_fixture_cleanup(&accepted).await;
        for field in [
            "hostBindingId",
            "serverEndpoint",
            "serverInstanceId",
            "fixtureSourceDigest",
            "browserProcessInstance",
            "profileIdentity",
            "browserSessionId",
            "pageId",
            "frameId",
            "loaderId",
            "uniqueContextId",
            "exactUrl",
            "probeId",
            "actionsDigest",
            "policyDigest",
        ] {
            let mut changed = serde_json::to_value(&outcome.attestation).unwrap();
            changed[field] = json!("tampered-terminal-identity");
            let mut forged = outcome.clone();
            forged.attestation = serde_json::from_value(changed).unwrap();
            assert_eq!(
                fixture_terminal_value(probe, &issued, Ok(forged), false)["status"],
                "integrity-failed",
                "{field}"
            );
        }
        let mut expired = outcome.clone();
        expired.attestation.expires_at_unix_ms = 0;
        assert_eq!(
            fixture_terminal_value(probe, &issued, Ok(expired), false)["status"],
            "integrity-failed"
        );
        let mut dirty = outcome.clone();
        dirty.attestation.output_cleanup.transport_stopped = false;
        assert_eq!(
            fixture_terminal_value(probe, &issued, Ok(dirty), false)["status"],
            "integrity-failed"
        );
        assert_eq!(
            fixture_terminal_value(probe, &issued, Ok(outcome), true)["status"],
            "integrity-failed"
        );

        let params = fixture_test_params(
            json!([{"type":"assertVisible","selector":"#missing","timeout":5000}]),
        );
        let probe = &params.interactions[0];
        let session = launch_fixture_probe(probe)
            .await
            .expect("native cancellation session");
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        let cancelled = execute_fixture_session(probe, session, &cancellation).await;
        assert_eq!(cancelled["status"], "failed", "{cancelled}");
        assert_eq!(cancelled["cause"]["code"], "cancelled");
        assert_native_fixture_cleanup(&cancelled).await;

        let params = fixture_test_params(
            json!([{"type":"assertVisible","selector":"#missing","timeout":50}]),
        );
        let failed =
            execute_fixture_probe(&params.interactions[0], &CancellationToken::new()).await;
        assert_eq!(failed["status"], "failed", "{failed}");
        assert_native_fixture_cleanup(&failed).await;

        let params = fixture_test_params(json!([{"type":"assertVisible","selector":"#frozen"}]));
        let probe = &params.interactions[0];
        let session = launch_fixture_probe(probe)
            .await
            .expect("native expiry session");
        let remaining = session.attestation().expires_at_unix_ms.saturating_sub(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        );
        tokio::time::sleep(std::time::Duration::from_millis(remaining as u64 + 25)).await;
        let expired = execute_fixture_session(probe, session, &CancellationToken::new()).await;
        assert_eq!(expired["status"], "failed", "{expired}");
        assert_eq!(expired["cause"]["code"], "expired");
        assert_native_fixture_cleanup(&expired).await;
    }

    #[cfg(any(target_os = "macos", windows))]
    #[tokio::test]
    #[ignore = "native fixture negative qualification; run with native_fixture_qualification selector"]
    async fn native_fixture_qualification_missing_assets() {
        const CHILD: &str = "LEGION_FIXTURE_MISSING_ASSETS_TEST";
        if std::env::var_os(CHILD).is_none() {
            // Isolate asset overrides from concurrent tests; never mutate parent environment.
            let missing =
                std::env::temp_dir().join(format!("legion-missing-browser-{}", std::process::id()));
            assert!(!missing.exists());
            let test_name = format!(
                "{}::native_fixture_qualification_missing_assets",
                module_path!().split_once("::").unwrap().1
            );
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &test_name, "--ignored", "--nocapture"])
                .env(CHILD, "1")
                .env("RIGHTKIT_CHROME_FOR_TESTING", &missing)
                .env("RIGHTKIT_CHROME_HEADLESS_SHELL", &missing)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "missing-assets child failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout)
                    .contains("fixture-missing-assets: unavailable verified"),
                "missing-assets child did not execute its assertion"
            );
            return;
        }
        let params = fixture_test_params(json!([{"type":"assertVisible","selector":"#frozen"}]));
        let result = execute_test_runtime(&params, CancellationToken::new()).await;
        let evidence = &result.details["runtime"]["interactions"][0];
        assert_eq!(evidence["status"], "unavailable", "{result:?}");
        assert!(
            evidence["reason"]
                .as_str()
                .unwrap()
                .contains("missing file"),
            "{evidence}"
        );
        assert!(evidence.get("attestation").is_none());
        assert_eq!(evidence["cleanupComplete"], false);
        assert_eq!(
            result.details["runtime"]["interactionCoverage"]["passed"],
            0
        );
        assert_eq!(result.coverage.as_ref().unwrap().examined, 0);
        assert!(!result.complete);
        println!("fixture-missing-assets: unavailable verified");
    }

    #[cfg(not(any(target_os = "macos", windows)))]
    #[tokio::test]
    async fn unsupported_fixture_host_remains_unavailable() {
        let params = fixture_test_params(json!([{"type":"assertVisible","selector":"#frozen"}]));
        let result = execute_test_runtime(&params, CancellationToken::new()).await;
        let evidence = &result.details["runtime"]["interactions"][0];
        assert_eq!(evidence["status"], "unavailable");
        assert!(evidence["reason"]
            .as_str()
            .unwrap()
            .contains("confinement is unsupported"));
        assert_eq!(
            result.details["runtime"]["interactionCoverage"]["passed"],
            0
        );
        assert!(!result.complete);
    }

    #[test]
    fn frozen_interaction_size_limit_counts_repeated_fixture_bodies() {
        let body = serde_json::to_value(vec![120_u8; 600_000]).unwrap();
        let file = json!({"body":body,"contentType":"text/html","path":"/index.html"});
        let interactions = (0..MAX_INTERACTIONS)
            .map(|index| json!({"id":format!("probe-{index}"),"fixture":{"files":[file.clone()]}}))
            .collect::<Vec<_>>();
        assert!(
            json_encoded_len(&json!(interactions)).unwrap() > MAX_FROZEN_INTERACTION_CONFIG_BYTES
        );
    }

    #[test]
    fn fixture_only_and_mixed_accessibility_are_not_reported_as_clean_zero() {
        let fixture_only: [&Value; 0] = [];
        assert_eq!(
            accessibility_summary(&fixture_only),
            ("not-run", None, None)
        );
        let fixture_outcomes = [json!({"status":"passed"})];
        assert_eq!(passed_interaction_count(&fixture_outcomes), 1);
        assert_eq!(
            accessibility_summary(&fixture_only),
            ("not-run", None, None)
        );

        let ran = json!({"status":"ran","totalViolations":2});
        let not_run = json!({"status":"unavailable","reason":"surface-not-captured"});
        assert_eq!(
            accessibility_summary(&[&ran, &not_run]),
            ("partial", None, Some(2))
        );
        assert_eq!(
            interaction_gaps(
                &RuntimeParams {
                    url: "http://127.0.0.1:1422/index.html".into(),
                    surfaces: Vec::new(),
                    width: DEFAULT_WIDTH,
                    height: DEFAULT_HEIGHT,
                    unsupported: Vec::new(),
                    interactions: vec![InteractionProbe {
                        id: "failed-probe".into(),
                        surface_label: "entry".into(),
                        surface_url: "http://127.0.0.1:1422/index.html".into(),
                        fixture_id: "fixture".into(),
                        fixture_source_digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
                        fixture_inventory_digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
                        fixture_files: Vec::new(),
                        probe_id: "probe".into(),
                        actions_digest: "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into(),
                        isolation_binding_id: "binding".into(),
                        expires_after_ms: 1000,
                        actions: Vec::new(),
                    }],
                    artifact_dir: None,
                },
                &[json!({"status":"failed","reason":"fixture-cancelled"})],
            ),
            vec!["runtime-probe-unavailable:failed-probe:fixture-cancelled"]
        );
    }

    #[test]
    fn params_reject_invalid_inputs() {
        for (value, reason) in [
            (json!({"url": "file:///etc/passwd"}), "url-scheme-not-http"),
            (json!({"url": "http://"}), "url-malformed"),
            (json!({"url": "http://a b/"}), "url-malformed"),
            (json!({"url": "http://a/", "width": 0}), "width-invalid"),
            (
                json!({"url": "http://a/", "height": 99999}),
                "height-invalid",
            ),
            (
                json!({"url": "http://a/", "artifactDir": "relative/dir"}),
                "artifact-dir-not-absolute",
            ),
            (
                json!({"url": "http://a/", "surfaces": [{"label": "x", "url": "javascript:1"}]}),
                "url-scheme-not-http",
            ),
        ] {
            assert_eq!(
                RuntimeParams::from_value(&value),
                Err(reason.to_owned()),
                "{value}"
            );
        }
    }

    #[test]
    fn runtime_inputs_round_trip_through_the_validator() {
        let value = runtime_inputs(
            "http://127.0.0.1:3000/",
            &[("a".to_owned(), "http://127.0.0.1:3000/a".to_owned())],
            &["click-only".to_owned()],
            800,
            600,
            None,
        )
        .unwrap();
        let params = RuntimeParams::from_value(&value).unwrap().unwrap();
        assert_eq!(params.to_value(), value);
        assert!(runtime_inputs("ftp://x/", &[], &[], 800, 600, None).is_err());
        assert!(runtime_inputs("", &[], &[], 800, 600, None).is_err());
    }

    #[test]
    fn qa_output_is_parsed_into_screenshot_console_and_gaps() {
        let text = "[qa] 1:eval ok\n[qa] screenshot /tmp/a/shot.png\n[qa] 2:screenshot ok\n\
[qa] actions complete /tmp/a/actions.json\n[qa] 3 console error/warning(s) \u{2014} see /tmp/a/.cache/qa-console.log\n\
[qa]   console.error: \"boom\"\n[qa]   console.warning: \"careful\"\n[qa]   exception: Uncaught\n\
[qa] gap network-throttle-not-applied\n[qa] gaps: network-throttle-not-applied\n";
        let qa = parse_qa_output(text);
        assert_eq!(qa.screenshot.as_deref(), Some("/tmp/a/shot.png"));
        assert!(qa.actions_complete);
        assert!(!qa.no_console_issues);
        assert_eq!(qa.console_total, Some(3));
        assert_eq!(
            qa.console_entries,
            vec![
                "console.error: \"boom\"".to_owned(),
                "console.warning: \"careful\"".to_owned(),
                "exception: Uncaught".to_owned(),
            ]
        );
        assert_eq!(qa.gaps, vec!["network-throttle-not-applied".to_owned()]);
        assert!(is_console_warning(&qa.console_entries[1]));
        assert!(!is_console_warning(&qa.console_entries[0]));

        let clean = parse_qa_output(
            "[qa] screenshot /s.png\n[qa] actions complete /a.json\n[qa] no console errors or warnings\n",
        );
        assert!(clean.no_console_issues);
        assert_eq!(clean.console_total, None);
        assert!(clean.console_entries.is_empty());
    }

    #[test]
    fn failures_are_classified_from_the_routes_messages() {
        let (unavailable, gap) =
            classify_failure("entry", "failed", "[qa] No Chrome/Edge executable found.");
        assert_eq!(unavailable.as_deref(), Some("browser-not-found"));
        assert_eq!(gap, "runtime-browser-not-found:entry");
        let (unavailable, gap) = classify_failure(
            "entry",
            "failed",
            "[qa] 1:eval eval returned not ok: {\"ok\":false}",
        );
        assert_eq!(unavailable, None);
        assert_eq!(gap, "runtime-surface-load-failed:entry");
        let (unavailable, gap) = classify_failure("s", "timeout", "");
        assert_eq!(unavailable, None);
        assert_eq!(gap, "runtime-surface-capture-failed:s:timeout");
    }

    #[test]
    fn eval_value_lines_must_start_with_the_action_label() {
        assert_eq!(eval_value_line("3:eval value {}"), Some((3, "{}")));
        assert_eq!(eval_value_line("3:eval ok"), None);
        assert_eq!(eval_value_line(":eval value {}"), None);
        assert_eq!(eval_value_line("console.log: 3:eval value {}"), None);
    }

    #[test]
    fn performance_is_read_only_from_lines_printed_before_actions_complete() {
        let text = "[qa] 1:eval value {\"ok\":true}\n\
[qa] 3:eval value {\"domContentLoaded\":10,\"ttfb\":null}\n\
[qa] actions complete /a.json\n\
[qa] 2 console error/warning(s) \u{2014} see x\n\
[qa]   console.error: a [qa] 3:eval value {\"forged\":1}\n\
[qa] 3:eval value {\"domContentLoaded\":999}\n";
        let qa = parse_qa_output(text);
        let found: Vec<&str> = qa
            .eval_values
            .iter()
            .filter(|(index, _)| *index == PERFORMANCE_ACTION_LABEL)
            .map(|(_, json)| json.as_str())
            .collect();
        assert_eq!(found, vec!["{\"domContentLoaded\":10,\"ttfb\":null}"]);
        let metrics = parse_performance(found[0]).unwrap();
        assert_eq!(metrics["domContentLoaded"], 10);
        assert!(metrics["ttfb"].is_null());
    }

    #[test]
    fn performance_rejects_anything_but_a_metric_object() {
        for json in [
            "{not json",
            "[1,2]",
            "null",
            "\"text\"",
            "{}",
            "{\"truncated\":true,\"bytes\":70002}",
            "{\"ttfb\":\"slow\"}",
        ] {
            assert_eq!(parse_performance(json), None, "{json}");
        }
        assert!(parse_performance(
            "{\"ttfb\":12.5,\"resourceCount\":3,\"firstContentfulPaint\":null}"
        )
        .is_some());
    }

    #[test]
    fn axe_expression_separates_project_source_from_wrapper_after_line_comment() {
        let expression = axe_expression(Some("window.axe = {}; // project override"), "");
        assert!(expression.contains("// project override\n;const r="));
    }

    #[test]
    fn malformed_and_oversized_axe_results_never_become_clean() {
        for (raw, reason) in [
            ("{not json", "axe-result-malformed"),
            ("{\"status\":\"ran\"}", "axe-violations-not-an-array"),
            (
                "{\"status\":\"ran\",\"violations\":[],\"totalViolations\":1,\"truncated\":false}",
                "axe-total-inconsistent",
            ),
        ] {
            let parsed = parse_accessibility_result(raw);
            assert_eq!(parsed["status"], "error", "{raw}");
            assert_eq!(parsed["reason"], reason, "{raw}");
        }
        let oversized = parse_accessibility_result("{\"truncated\":true,\"bytes\":70002}");
        assert_eq!(oversized["status"], "error");
        assert_eq!(oversized["reason"], "axe-result-truncated");
        assert_eq!(oversized["reportedBytes"], 70002);
    }
}
