//! Port of `src/lib/verification/arcane/advisory-certification.mjs`
//! (packet r62, 2026-09-24): minting and verifying the two-receipt
//! producer/certifier chain for an advisory artifact — the artifact
//! receipt (`mintAdvisoryArtifactReceipt`/`verifyAdvisoryArtifactReceipt`)
//! and the independent certification receipt on top of it
//! (`mintAdvisoryCertificationReceipt`/`verifyAdvisoryCertification`/
//! `findCurrentAdvisoryCertification`).
//!
//! Reuses this crate's existing HMAC signing/verification
//! (`crate::receipt_auth::{sign_record, verify_record}`, itself already the
//! Rust port of `guard/compat/audit/receipt-auth.mjs`) and
//! `legion_contracts::canonical_digest` (the `sha256:<hex>` "digestValue"
//! form used throughout this file's `.mjs` source, byte-for-byte the same
//! canonical-JSON-then-SHA-256 scheme as `contracts/arcane/canonical.mjs`).
//!
//! **Ported faithfully:** every export of `advisory-certification.mjs` —
//! `ADVISORY_ARTIFACT_BOUND_FIELDS`, `ADVISORY_CERTIFICATION_BOUND_FIELDS`,
//! `mintAdvisoryArtifactReceipt`, `verifyAdvisoryArtifactReceipt`,
//! `mintAdvisoryCertificationReceipt`, `verifyAdvisoryCertification`,
//! `findCurrentAdvisoryCertification`, plus the module-private helpers
//! (`rejectCallerAuthority`, `requireBinding`, `freshness`,
//! `verifyStoredBinding`, `commonReceipt`, `exactKeys`, `validExecution`,
//! `validInputs`, `validBinding`, `validChecklist`).
//!
//! GAP: `authorityBindingStore` and `receiptStore` are JS duck-typed
//! objects (`findLatest`, `list`, `verifyChain`) with no concrete
//! implementation in `advisory-certification.mjs` itself (they are
//! injected by callers). This port expresses them as the
//! [`AuthorityBindingStore`] and [`CertificationReceiptStore`] traits;
//! [`CertificationReceiptStore`] is implemented here for this crate's own
//! [`crate::receipt_store::ReceiptStore`] (whose `verify_chain`/`list`
//! shapes already match what `findCurrentAdvisoryCertification` needs), and
//! callers supply their own `AuthorityBindingStore` (no concrete host
//! binding store exists anywhere in this workspace — see
//! `crate::session_binding` for the closest sibling, which is
//! session-keyed rather than adapter+session+authority-keyed and cannot be
//! reused as-is without changing its shape).

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use crate::decision::{decision, deny};
use crate::error::ArcaneError;
use crate::key_ring::KeyRing;
use crate::receipt_auth::{sign_record, verify_record};
use crate::receipt_store::ReceiptStore;

pub const ADVISORY_ARTIFACT_BOUND_FIELDS: &[&str] = &[
    "schemaVersion", "kind", "receiptId", "artifactDigest", "briefDigest", "bundleId", "bundleVersion",
    "profileId", "manifestDigest", "profileDigest", "producerAgentIdDigest", "runId", "taskId",
    "contractId", "contractVersion", "contractDigest", "sourceRevision", "binding", "issuedAt",
    "expiresAt", "nonce",
];

pub const ADVISORY_CERTIFICATION_BOUND_FIELDS: &[&str] = &[
    "schemaVersion", "kind", "receiptId", "artifactReceiptDigest", "artifactDigest", "briefDigest",
    "bundleId", "bundleVersion", "profileId", "manifestDigest", "profileDigest", "producerAgentIdDigest",
    "certifierAgentIdDigest", "runId", "taskId", "contractId", "contractVersion", "contractDigest",
    "sourceRevision", "checklistEvidence", "verdict", "binding", "issuedAt", "expiresAt", "nonce",
];

const ARTIFACT_DOMAIN: &str = "arcane.advisory-artifact-receipt.v1";
const CERTIFICATION_DOMAIN: &str = "arcane.advisory-certification-receipt.v1";
const EXECUTION_FIELDS: &[&str] =
    &["runId", "taskId", "contractId", "contractVersion", "contractDigest", "sourceRevision"];
const INPUT_FIELDS: &[&str] =
    &["artifactDigest", "briefDigest", "bundleId", "bundleVersion", "profileId", "manifestDigest", "profileDigest"];

const DEFAULT_FRESHNESS_MS: i64 = 86_400_000;

/// Port of `isDigest`: `typeof value === "string" && DIGEST_PATTERN.test(value)`.
fn is_digest(value: Option<&Value>) -> bool {
    match value.and_then(Value::as_str) {
        Some(s) => {
            s.len() == 71
                && s.starts_with("sha256:")
                && s[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        None => false,
    }
}

fn nonempty(value: Option<&Value>) -> bool {
    matches!(value.and_then(Value::as_str), Some(s) if !s.is_empty())
}

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    match value.as_object() {
        Some(map) => map.len() == keys.len() && keys.iter().all(|k| map.contains_key(*k)),
        None => false,
    }
}

fn digest_value(value: &Value) -> Result<String, ArcaneError> {
    Ok(legion_contracts::canonical_digest(value)?)
}

fn valid_execution(value: &Value) -> bool {
    nonempty(value.get("runId"))
        && nonempty(value.get("taskId"))
        && nonempty(value.get("contractId"))
        && matches!(value.get("contractVersion"), Some(Value::Number(n)) if n.as_i64().is_some_and(|v| v > 0))
        && is_digest(value.get("contractDigest"))
        && nonempty(value.get("sourceRevision"))
}

fn valid_inputs(value: &Value) -> bool {
    is_digest(value.get("artifactDigest"))
        && is_digest(value.get("briefDigest"))
        && nonempty(value.get("bundleId"))
        && nonempty(value.get("bundleVersion"))
        && nonempty(value.get("profileId"))
        && is_digest(value.get("manifestDigest"))
        && is_digest(value.get("profileDigest"))
}

fn valid_binding(value: &Value) -> bool {
    exact_keys(value, &["adapter", "sessionId", "bindingDigest"])
        && nonempty(value.get("adapter"))
        && nonempty(value.get("sessionId"))
        && is_digest(value.get("bindingDigest"))
}

fn valid_checklist(value: &Value) -> bool {
    let Some(items) = value.as_array() else { return false };
    if items.is_empty() {
        return false;
    }
    let mut seen = BTreeSet::new();
    for item in items {
        if !exact_keys(item, &["criterionId", "evidenceDigest"]) {
            return false;
        }
        if !nonempty(item.get("criterionId")) || !is_digest(item.get("evidenceDigest")) {
            return false;
        }
        let id = item.get("criterionId").and_then(Value::as_str).unwrap_or_default();
        if !seen.insert(id.to_string()) {
            return false;
        }
    }
    true
}

/// Port of `AuthorityBindingStore.findLatest({ adapter, sessionId, authority })`.
/// The returned value is the raw stored binding record (must include an
/// `agentIdDigest` field); its `digestValue` is what `binding.bindingDigest`
/// is checked against.
pub trait AuthorityBindingStore {
    fn find_latest(&self, adapter: &str, session_id: &str, authority: &str) -> Option<Value>;
}

/// Port of `receiptStore` as used by `findCurrentAdvisoryCertification`
/// (`verifyChain()` + `list({ runId })`).
pub trait CertificationReceiptStore {
    fn verify_chain_ok(&self) -> bool;
    fn list(&self, run_id: Option<&str>) -> Vec<Value>;
}

impl CertificationReceiptStore for ReceiptStore {
    fn verify_chain_ok(&self) -> bool {
        self.verify_chain().get("ok").and_then(Value::as_bool) == Some(true)
    }
    fn list(&self, run_id: Option<&str>) -> Vec<Value> {
        let records = ReceiptStore::list(self);
        match run_id {
            Some(id) => records
                .into_iter()
                .filter(|r| r.get("runId").and_then(Value::as_str) == Some(id))
                .collect(),
            None => records,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CertificationError {
    #[error("caller field '{0}' is forbidden")]
    AuthorityClaimed(&'static str),
    #[error("invalid advisory artifact input")]
    SchemaInvalid,
    #[error("host {0} binding is unavailable")]
    AuthorityNotAsserted(String),
    #[error("certification requires checklist evidence and host session")]
    CertificationSchemaInvalid,
    #[error("producer cannot certify its own artifact")]
    ClaimPrerequisiteUnmet,
    #[error("{0}")]
    Verify(String),
    #[error(transparent)]
    Arcane(#[from] ArcaneError),
}

/// Port of `rejectCallerAuthority(input)`.
fn reject_caller_authority(value: &Value) -> Result<(), CertificationError> {
    for field in ["authentication", "receiptId", "producerAgentIdDigest", "certifierAgentIdDigest", "binding"] {
        if value.get(field).is_some() {
            return Err(CertificationError::AuthorityClaimed(field_static(field)));
        }
    }
    Ok(())
}

fn field_static(field: &str) -> &'static str {
    match field {
        "authentication" => "authentication",
        "receiptId" => "receiptId",
        "producerAgentIdDigest" => "producerAgentIdDigest",
        "certifierAgentIdDigest" => "certifierAgentIdDigest",
        "binding" => "binding",
        _ => "unknown",
    }
}

/// Port of `requireBinding(authorityBindingStore, { adapter, sessionId, authority })`.
fn require_binding(
    store: &dyn AuthorityBindingStore,
    adapter: &str,
    session_id: &str,
    authority: &str,
) -> Result<Value, CertificationError> {
    let binding = store
        .find_latest(adapter, session_id, authority)
        .ok_or_else(|| CertificationError::AuthorityNotAsserted(authority.to_string()))?;
    if !is_digest(binding.get("agentIdDigest")) {
        return Err(CertificationError::AuthorityNotAsserted(authority.to_string()));
    }
    Ok(binding)
}

/// Port of `freshness(receipt, now, freshnessMs)`. `now_ms` is the current
/// time as Unix milliseconds (caller-supplied, mirrors JS `Date.now()`/a
/// passed `Date`/number).
fn freshness(receipt: &Value, now_ms: i64, freshness_ms: i64) -> bool {
    let issued = receipt.get("issuedAt").and_then(Value::as_str).and_then(parse_rfc3339_ms);
    let expires = receipt.get("expiresAt").and_then(Value::as_str).and_then(parse_rfc3339_ms);
    match (issued, expires) {
        (Some(issued), Some(expires)) => {
            issued <= now_ms && expires > now_ms && expires - issued <= freshness_ms
        }
        _ => false,
    }
}

/// Minimal RFC 3339 UTC parser (`YYYY-MM-DDTHH:MM:SS(.sss)?Z`), sufficient
/// for the ISO strings this module itself produces via `clock()`. Returns
/// Unix milliseconds.
fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z').unwrap_or(s);
    let (date, time) = s.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: i64 = date_parts.next()?.parse().ok()?;
    let day: i64 = date_parts.next()?.parse().ok()?;
    let (time, millis) = match time.split_once('.') {
        Some((t, frac)) => {
            let ms: i64 = format!("{:0<3}", &frac[..frac.len().min(3)]).parse().ok()?;
            (t, ms)
        }
        None => (time, 0),
    };
    let mut time_parts = time.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.parse().ok()?;
    let days = days_from_civil(year, month, day);
    Some(((days * 86_400 + hour * 3600 + minute * 60 + second) * 1000) + millis)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as i64;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Port of `verifyStoredBinding(receipt, authority, authorityBindingStore)`.
fn verify_stored_binding(receipt: &Value, authority: &str, store: &dyn AuthorityBindingStore) -> bool {
    let Some(binding) = receipt.get("binding") else { return false };
    if !valid_binding(binding) {
        return false;
    }
    let adapter = binding.get("adapter").and_then(Value::as_str).unwrap_or_default();
    let session_id = binding.get("sessionId").and_then(Value::as_str).unwrap_or_default();
    let Some(stored) = store.find_latest(adapter, session_id, authority) else { return false };
    let Ok(stored_digest) = digest_value(&stored) else { return false };
    let expected_digest = binding.get("bindingDigest").and_then(Value::as_str).unwrap_or_default();
    let agent_field = if authority == "oracle" { "certifierAgentIdDigest" } else { "producerAgentIdDigest" };
    stored_digest == expected_digest
        && stored.get("agentIdDigest").and_then(Value::as_str)
            == receipt.get(agent_field).and_then(Value::as_str)
}

/// Port of `commonReceipt(core, { binding, clock, freshnessMs })`.
fn common_receipt(mut core: Map<String, Value>, binding: &Value, issued_at: String, freshness_ms: i64) -> Result<Value, ArcaneError> {
    let issued_ms = parse_rfc3339_ms(&issued_at).unwrap_or(0);
    let expires_at = format_rfc3339_ms(issued_ms + freshness_ms);
    let binding_digest = digest_value(binding)?;
    let adapter = core.remove("adapter").unwrap_or(Value::Null);
    let session_id = core.remove("sessionId").unwrap_or(Value::Null);
    let mut unsigned = Map::new();
    unsigned.insert("schemaVersion".into(), json!(1));
    for (k, v) in core {
        unsigned.insert(k, v);
    }
    unsigned.insert(
        "binding".into(),
        json!({"adapter": adapter, "sessionId": session_id, "bindingDigest": binding_digest}),
    );
    unsigned.insert("issuedAt".into(), Value::String(issued_at));
    unsigned.insert("expiresAt".into(), Value::String(expires_at));
    unsigned.insert("nonce".into(), Value::String(random_nonce_hex()));
    let receipt_id = digest_value(&Value::Object(unsigned.clone()))?;
    unsigned.insert("receiptId".into(), Value::String(receipt_id));
    Ok(Value::Object(unsigned))
}

fn format_rfc3339_ms(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// 16 random bytes as lowercase hex, matching `randomBytes(16).toString('hex')`.
/// No external RNG crate is added for this (out of the port brief's allowed
/// list); this draws from the process's address-space/time entropy the same
/// way `session_binding.rs`'s `run_id` derivation already does elsewhere in
/// this crate, which is adequate for a replay-nonce (never used as key
/// material) but is documented here as a narrower source than Node's CSPRNG.
fn random_nonce_hex() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let mut hasher_input = Vec::with_capacity(32);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    hasher_input.extend_from_slice(&now.as_nanos().to_le_bytes());
    hasher_input.extend_from_slice(&(std::process::id() as u64).to_le_bytes());
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let count = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    hasher_input.extend_from_slice(&count.to_le_bytes());
    let addr = &hasher_input as *const _ as usize as u64;
    hasher_input.extend_from_slice(&addr.to_le_bytes());
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&hasher_input);
    hex::encode(&digest[..16])
}

fn strip_receipt_id_and_auth(receipt: &Value) -> Value {
    let mut map = receipt.as_object().cloned().unwrap_or_default();
    map.remove("receiptId");
    map.remove("authentication");
    Value::Object(map)
}

/// Port of `mintAdvisoryArtifactReceipt(input, options)`.
pub fn mint_advisory_artifact_receipt(
    input: &Value,
    key_ring: &KeyRing,
    key_id: &str,
    store: &dyn AuthorityBindingStore,
    producer_authority: &str,
    issued_at: String,
    freshness_ms: i64,
) -> Result<Value, CertificationError> {
    reject_caller_authority(input)?;
    let artifact_input_keys: Vec<&str> = INPUT_FIELDS
        .iter()
        .chain(EXECUTION_FIELDS.iter())
        .chain(["adapter", "sessionId"].iter())
        .copied()
        .collect();
    if !exact_keys(input, &artifact_input_keys)
        || !valid_inputs(input)
        || !valid_execution(input)
        || !nonempty(input.get("adapter"))
        || !nonempty(input.get("sessionId"))
    {
        return Err(CertificationError::SchemaInvalid);
    }
    let adapter = input.get("adapter").and_then(Value::as_str).unwrap_or_default();
    let session_id = input.get("sessionId").and_then(Value::as_str).unwrap_or_default();
    let binding = require_binding(store, adapter, session_id, producer_authority)?;

    let mut core = input.as_object().cloned().unwrap_or_default();
    core.insert("kind".into(), Value::String("arcane-advisory-artifact-receipt".into()));
    core.insert(
        "producerAgentIdDigest".into(),
        binding.get("agentIdDigest").cloned().unwrap_or(Value::Null),
    );
    let receipt = common_receipt(core, &binding, issued_at, freshness_ms)?;
    let auth = sign_record(&receipt, key_ring, key_id, ADVISORY_ARTIFACT_BOUND_FIELDS, Some(ARTIFACT_DOMAIN))
        .map_err(CertificationError::Arcane)?;
    let mut object = receipt.as_object().cloned().unwrap_or_default();
    object.insert("authentication".into(), auth);
    Ok(Value::Object(object))
}

/// Port of `verifyAdvisoryArtifactReceipt(receipt, expected, options)`.
/// Returns the `decision(...)`-shaped `Value` (never an `Err`, matching the
/// original's fail-closed-but-returned-not-thrown contract).
pub fn verify_advisory_artifact_receipt(
    receipt: &Value,
    expected: &Value,
    key_ring: &KeyRing,
    store: &dyn AuthorityBindingStore,
    producer_authority: &str,
    now_ms: i64,
    freshness_ms: i64,
) -> Value {
    let artifact_keys: Vec<&str> = ADVISORY_ARTIFACT_BOUND_FIELDS.iter().chain(["authentication"].iter()).copied().collect();
    let nonce_ok = receipt
        .get("nonce")
        .and_then(Value::as_str)
        .is_some_and(|n| n.len() == 32 && n.bytes().all(|b| b.is_ascii_hexdigit() && (b.is_ascii_digit() || b.is_ascii_lowercase())));
    if !exact_keys(receipt, &artifact_keys)
        || receipt.get("schemaVersion") != Some(&json!(1))
        || receipt.get("kind").and_then(Value::as_str) != Some("arcane-advisory-artifact-receipt")
        || !valid_inputs(receipt)
        || !valid_execution(receipt)
        || !receipt.get("binding").is_some_and(valid_binding)
        || !is_digest(receipt.get("receiptId"))
        || !is_digest(receipt.get("producerAgentIdDigest"))
        || !nonce_ok
    {
        return deny("ARC_SCHEMA_INVALID", "advisory artifact receipt is invalid", json!({}));
    }
    let projected = strip_receipt_id_and_auth(receipt);
    match digest_value(&projected) {
        Ok(digest) if receipt.get("receiptId").and_then(Value::as_str) == Some(digest.as_str()) => {}
        _ => return deny("ARC_AUTH_FORGED", "advisory artifact receipt identifier does not match content", json!({})),
    }
    if !freshness(receipt, now_ms, freshness_ms) {
        return deny("ARC_REPLAY_STALE", "advisory artifact receipt is stale or from the future", json!({}));
    }
    if !verify_stored_binding(receipt, producer_authority, store) {
        return deny("ARC_AUTHORITY_NOT_ASSERTED", "artifact producer binding is unavailable", json!({}));
    }
    let expected_binding = expected.as_object().cloned().unwrap_or_default();
    let auth = match verify_record(
        receipt,
        receipt.get("authentication"),
        key_ring,
        ADVISORY_ARTIFACT_BOUND_FIELDS,
        &expected_binding,
        Some(ARTIFACT_DOMAIN),
    ) {
        Ok(decision) => decision,
        Err(_) => return deny("ARC_AUTH_FORGED", "advisory artifact receipt authentication is unverifiable", json!({})),
    };
    if !auth.allowed {
        return deny(auth.code.unwrap_or("ARC_AUTH_FORGED"), auth.message.as_deref().unwrap_or(""), json!({}));
    }
    for field in INPUT_FIELDS.iter().chain(EXECUTION_FIELDS.iter()) {
        if let Some(expected_value) = expected.get(*field) {
            if receipt.get(*field) != Some(expected_value) {
                return deny("ARC_BINDING_MISMATCH", "artifact receipt differs from expected input", json!({"field": field}));
            }
        }
    }
    decision(
        true,
        None,
        None,
        json!({
            "receiptId": receipt.get("receiptId"),
            "artifactDigest": receipt.get("artifactDigest"),
            "producerAgentIdDigest": receipt.get("producerAgentIdDigest"),
        }),
    )
}

/// Port of `mintAdvisoryCertificationReceipt({ artifactReceipt,
/// checklistEvidence, adapter, sessionId }, options)`.
#[allow(clippy::too_many_arguments)]
pub fn mint_advisory_certification_receipt(
    artifact_receipt: &Value,
    checklist_evidence: &Value,
    adapter: &str,
    session_id: &str,
    key_ring: &KeyRing,
    key_id: &str,
    store: &dyn AuthorityBindingStore,
    now_ms: i64,
    issued_at: String,
    freshness_ms: i64,
) -> Result<Value, CertificationError> {
    let artifact = verify_advisory_artifact_receipt(artifact_receipt, &json!({}), key_ring, store, "alchemist", now_ms, freshness_ms);
    if artifact.get("allowed") != Some(&Value::Bool(true)) {
        return Err(CertificationError::Verify(
            artifact.get("message").and_then(Value::as_str).unwrap_or("artifact receipt invalid").to_string(),
        ));
    }
    if !valid_checklist(checklist_evidence) || !nonempty(Some(&json!(adapter))) || !nonempty(Some(&json!(session_id))) {
        return Err(CertificationError::CertificationSchemaInvalid);
    }
    let binding = require_binding(store, adapter, session_id, "oracle")?;
    if binding.get("agentIdDigest") == artifact_receipt.get("producerAgentIdDigest") {
        return Err(CertificationError::ClaimPrerequisiteUnmet);
    }
    let mut copied = Map::new();
    for field in INPUT_FIELDS.iter().chain(EXECUTION_FIELDS.iter()) {
        copied.insert((*field).to_string(), artifact_receipt.get(*field).cloned().unwrap_or(Value::Null));
    }
    copied.insert("kind".into(), Value::String("arcane-advisory-certification-receipt".into()));
    copied.insert("artifactReceiptDigest".into(), Value::String(digest_value(artifact_receipt)?));
    copied.insert("producerAgentIdDigest".into(), artifact_receipt.get("producerAgentIdDigest").cloned().unwrap_or(Value::Null));
    copied.insert("certifierAgentIdDigest".into(), binding.get("agentIdDigest").cloned().unwrap_or(Value::Null));
    let checklist_items: Vec<Value> = checklist_evidence
        .as_array()
        .unwrap()
        .iter()
        .map(|item| json!({"criterionId": item.get("criterionId"), "evidenceDigest": item.get("evidenceDigest")}))
        .collect();
    copied.insert("checklistEvidence".into(), Value::Array(checklist_items));
    copied.insert("verdict".into(), Value::String("PASS".into()));
    copied.insert("adapter".into(), Value::String(adapter.to_string()));
    copied.insert("sessionId".into(), Value::String(session_id.to_string()));
    let receipt = common_receipt(copied, &binding, issued_at, freshness_ms)?;
    let auth = sign_record(&receipt, key_ring, key_id, ADVISORY_CERTIFICATION_BOUND_FIELDS, Some(CERTIFICATION_DOMAIN))
        .map_err(CertificationError::Arcane)?;
    let mut object = receipt.as_object().cloned().unwrap_or_default();
    object.insert("authentication".into(), auth);
    Ok(Value::Object(object))
}

/// Port of `verifyAdvisoryCertification({ artifactReceipt,
/// certificationReceipt, expected }, options)`.
#[allow(clippy::too_many_arguments)]
pub fn verify_advisory_certification(
    artifact_receipt: &Value,
    certification_receipt: &Value,
    expected: &Value,
    key_ring: &KeyRing,
    store: &dyn AuthorityBindingStore,
    producer_authority: &str,
    now_ms: i64,
    freshness_ms: i64,
) -> Value {
    let artifact = verify_advisory_artifact_receipt(artifact_receipt, expected, key_ring, store, producer_authority, now_ms, freshness_ms);
    if artifact.get("allowed") != Some(&Value::Bool(true)) {
        return artifact;
    }
    let receipt = certification_receipt;
    let certification_keys: Vec<&str> =
        ADVISORY_CERTIFICATION_BOUND_FIELDS.iter().chain(["authentication"].iter()).copied().collect();
    let nonce_ok = receipt
        .get("nonce")
        .and_then(Value::as_str)
        .is_some_and(|n| n.len() == 32 && n.bytes().all(|b| b.is_ascii_hexdigit() && (b.is_ascii_digit() || b.is_ascii_lowercase())));
    if !exact_keys(receipt, &certification_keys)
        || receipt.get("schemaVersion") != Some(&json!(1))
        || receipt.get("kind").and_then(Value::as_str) != Some("arcane-advisory-certification-receipt")
        || !valid_inputs(receipt)
        || !valid_execution(receipt)
        || !receipt.get("binding").is_some_and(valid_binding)
        || !receipt.get("checklistEvidence").is_some_and(valid_checklist)
        || receipt.get("verdict").and_then(Value::as_str) != Some("PASS")
        || !is_digest(receipt.get("receiptId"))
        || !is_digest(receipt.get("certifierAgentIdDigest"))
        || !is_digest(receipt.get("producerAgentIdDigest"))
        || !is_digest(receipt.get("artifactReceiptDigest"))
        || !nonce_ok
    {
        return deny("ARC_EVIDENCE_INSUFFICIENT", "independent advisory certification is missing or invalid", json!({}));
    }
    let projected = strip_receipt_id_and_auth(receipt);
    match digest_value(&projected) {
        Ok(digest) if receipt.get("receiptId").and_then(Value::as_str) == Some(digest.as_str()) => {}
        _ => return deny("ARC_AUTH_FORGED", "advisory certification identifier does not match content", json!({})),
    }
    if !freshness(receipt, now_ms, freshness_ms) {
        return deny("ARC_REPLAY_STALE", "advisory certification is stale or from the future", json!({}));
    }
    if !verify_stored_binding(receipt, "oracle", store) {
        return deny("ARC_AUTHORITY_NOT_ASSERTED", "Oracle certifier binding is unavailable", json!({}));
    }
    let expected_binding = expected.as_object().cloned().unwrap_or_default();
    let auth = match verify_record(
        receipt,
        receipt.get("authentication"),
        key_ring,
        ADVISORY_CERTIFICATION_BOUND_FIELDS,
        &expected_binding,
        Some(CERTIFICATION_DOMAIN),
    ) {
        Ok(decision) => decision,
        Err(_) => return deny("ARC_AUTH_FORGED", "advisory certification authentication is unverifiable", json!({})),
    };
    if !auth.allowed {
        return deny(auth.code.unwrap_or("ARC_AUTH_FORGED"), auth.message.as_deref().unwrap_or(""), json!({}));
    }
    if receipt.get("producerAgentIdDigest") == receipt.get("certifierAgentIdDigest") {
        return deny("ARC_CLAIM_PREREQUISITE_UNMET", "producer cannot certify its own artifact", json!({}));
    }
    match digest_value(artifact_receipt) {
        Ok(digest) if receipt.get("artifactReceiptDigest").and_then(Value::as_str) == Some(digest.as_str()) => {}
        _ => {
            return deny(
                "ARC_BINDING_MISMATCH",
                "certification targets a different artifact receipt",
                json!({"field": "artifactReceiptDigest"}),
            )
        }
    }
    for field in INPUT_FIELDS.iter().chain(EXECUTION_FIELDS.iter()).chain(["producerAgentIdDigest"].iter()) {
        if receipt.get(*field) != artifact_receipt.get(*field) {
            return deny("ARC_BINDING_MISMATCH", "certification differs from artifact receipt", json!({"field": field}));
        }
    }
    decision(
        true,
        None,
        None,
        json!({
            "artifactReceiptId": artifact_receipt.get("receiptId"),
            "certificationReceiptId": receipt.get("receiptId"),
            "artifactDigest": receipt.get("artifactDigest"),
        }),
    )
}

/// Port of `findCurrentAdvisoryCertification({ receiptStore, artifactDigest, expected }, options)`.
pub fn find_current_advisory_certification(
    receipt_store: &dyn CertificationReceiptStore,
    artifact_digest: &str,
    expected: &Value,
    key_ring: &KeyRing,
    store: &dyn AuthorityBindingStore,
    producer_authority: &str,
    now_ms: i64,
    freshness_ms: i64,
) -> Value {
    if !is_digest(Some(&json!(artifact_digest))) {
        return deny("ARC_EVIDENCE_INSUFFICIENT", "receipt store and artifact digest are required", json!({}));
    }
    if !receipt_store.verify_chain_ok() {
        return deny("ARC_STORE_CORRUPT", "advisory receipt chain is unavailable or corrupt", json!({}));
    }
    let run_id = expected.get("runId").and_then(Value::as_str);
    let records = receipt_store.list(run_id);
    let mut artifacts: Vec<&Value> = records
        .iter()
        .filter(|r| {
            r.get("kind").and_then(Value::as_str) == Some("arcane-advisory-artifact-receipt")
                && r.get("artifactDigest").and_then(Value::as_str) == Some(artifact_digest)
        })
        .collect();
    artifacts.reverse();
    let mut certifications: Vec<&Value> = records
        .iter()
        .filter(|r| {
            r.get("kind").and_then(Value::as_str) == Some("arcane-advisory-certification-receipt")
                && r.get("artifactDigest").and_then(Value::as_str) == Some(artifact_digest)
        })
        .collect();
    certifications.reverse();
    for artifact_receipt in &artifacts {
        for certification_receipt in &certifications {
            let result = verify_advisory_certification(
                artifact_receipt,
                certification_receipt,
                expected,
                key_ring,
                store,
                producer_authority,
                now_ms,
                freshness_ms,
            );
            if result.get("allowed") == Some(&Value::Bool(true)) {
                return result;
            }
        }
    }
    deny(
        "ARC_EVIDENCE_INSUFFICIENT",
        "current independent advisory certification is unavailable",
        json!({"artifactDigest": artifact_digest}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::HashMap;

    struct FakeBindingStore {
        bindings: RefCell<HashMap<(String, String, String), Value>>,
    }

    impl FakeBindingStore {
        fn new() -> Self {
            Self { bindings: RefCell::new(HashMap::new()) }
        }
        fn set(&self, adapter: &str, session_id: &str, authority: &str, agent_id_digest: &str) {
            self.bindings.borrow_mut().insert(
                (adapter.to_string(), session_id.to_string(), authority.to_string()),
                json!({"agentIdDigest": agent_id_digest}),
            );
        }
    }

    impl AuthorityBindingStore for FakeBindingStore {
        fn find_latest(&self, adapter: &str, session_id: &str, authority: &str) -> Option<Value> {
            self.bindings
                .borrow()
                .get(&(adapter.to_string(), session_id.to_string(), authority.to_string()))
                .cloned()
        }
    }

    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn keyring() -> KeyRing {
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "legion-arcane-advisory-certification-test-{}-{}",
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("k1.key"), hex::encode([7u8; 32])).unwrap();
        KeyRing::load_dir(&dir).unwrap()
    }

    fn digest(seed: &str) -> String {
        legion_contracts::canonical_digest(&json!(seed)).unwrap()
    }

    fn sample_input(adapter: &str, session_id: &str) -> Value {
        json!({
            "artifactDigest": digest("artifact"),
            "briefDigest": digest("brief"),
            "bundleId": "bundle-1",
            "bundleVersion": "1.0.0",
            "profileId": "profile-1",
            "manifestDigest": digest("manifest"),
            "profileDigest": digest("profile"),
            "runId": "run-1",
            "taskId": "task-1",
            "contractId": "contract-1",
            "contractVersion": 1,
            "contractDigest": digest("contract"),
            "sourceRevision": "rev-1",
            "adapter": adapter,
            "sessionId": session_id,
        })
    }

    #[test]
    fn mint_and_verify_artifact_receipt_round_trip() {
        let ring = keyring();
        let store = FakeBindingStore::new();
        store.set("cli", "sess-1", "alchemist", &digest("producer"));
        let input = sample_input("cli", "sess-1");
        let receipt = mint_advisory_artifact_receipt(
            &input, &ring, "k1", &store, "alchemist",
            "2026-09-24T00:00:00.000Z".to_string(), DEFAULT_FRESHNESS_MS,
        )
        .unwrap();
        let now_ms = parse_rfc3339_ms("2026-09-24T00:00:01.000Z").unwrap();
        let result = verify_advisory_artifact_receipt(&receipt, &json!({}), &ring, &store, "alchemist", now_ms, DEFAULT_FRESHNESS_MS);
        assert_eq!(result["allowed"], true, "{result:?}");
    }

    #[test]
    fn reject_caller_authority_rejects_forbidden_fields() {
        let mut input = sample_input("cli", "sess-1");
        input["receiptId"] = json!("forged");
        let err = reject_caller_authority(&input).unwrap_err();
        assert!(matches!(err, CertificationError::AuthorityClaimed("receiptId")));
    }

    #[test]
    fn certification_rejects_self_certification() {
        let ring = keyring();
        let store = FakeBindingStore::new();
        let same_agent = digest("same-agent");
        store.set("cli", "sess-1", "alchemist", &same_agent);
        store.set("cli", "sess-1", "oracle", &same_agent);
        let input = sample_input("cli", "sess-1");
        let artifact_receipt = mint_advisory_artifact_receipt(
            &input, &ring, "k1", &store, "alchemist",
            "2026-09-24T00:00:00.000Z".to_string(), DEFAULT_FRESHNESS_MS,
        )
        .unwrap();
        let now_ms = parse_rfc3339_ms("2026-09-24T00:00:01.000Z").unwrap();
        let checklist = json!([{"criterionId": "c1", "evidenceDigest": digest("evidence")}]);
        let err = mint_advisory_certification_receipt(
            &artifact_receipt, &checklist, "cli", "sess-1", &ring, "k1", &store,
            now_ms, "2026-09-24T00:00:01.000Z".to_string(), DEFAULT_FRESHNESS_MS,
        )
        .unwrap_err();
        assert!(matches!(err, CertificationError::ClaimPrerequisiteUnmet));
    }

    #[test]
    fn mint_and_verify_certification_round_trip_with_distinct_agents() {
        let ring = keyring();
        let store = FakeBindingStore::new();
        store.set("cli", "sess-1", "alchemist", &digest("producer"));
        store.set("cli", "sess-1", "oracle", &digest("certifier"));
        let input = sample_input("cli", "sess-1");
        let artifact_receipt = mint_advisory_artifact_receipt(
            &input, &ring, "k1", &store, "alchemist",
            "2026-09-24T00:00:00.000Z".to_string(), DEFAULT_FRESHNESS_MS,
        )
        .unwrap();
        let now1 = parse_rfc3339_ms("2026-09-24T00:00:01.000Z").unwrap();
        let checklist = json!([{"criterionId": "c1", "evidenceDigest": digest("evidence")}]);
        let certification_receipt = mint_advisory_certification_receipt(
            &artifact_receipt, &checklist, "cli", "sess-1", &ring, "k1", &store,
            now1, "2026-09-24T00:00:01.000Z".to_string(), DEFAULT_FRESHNESS_MS,
        )
        .unwrap();
        let now2 = parse_rfc3339_ms("2026-09-24T00:00:02.000Z").unwrap();
        let result = verify_advisory_certification(
            &artifact_receipt, &certification_receipt, &json!({}), &ring, &store, "alchemist", now2, DEFAULT_FRESHNESS_MS,
        );
        assert_eq!(result["allowed"], true, "{result:?}");
    }

    #[test]
    fn is_digest_rejects_non_digest_strings() {
        assert!(!is_digest(Some(&json!("not-a-digest"))));
        assert!(is_digest(Some(&json!(digest("x")))));
    }

    #[test]
    fn rfc3339_round_trip() {
        let ms = parse_rfc3339_ms("2026-09-24T12:34:56.789Z").unwrap();
        assert_eq!(format_rfc3339_ms(ms), "2026-09-24T12:34:56.789Z");
    }
}
