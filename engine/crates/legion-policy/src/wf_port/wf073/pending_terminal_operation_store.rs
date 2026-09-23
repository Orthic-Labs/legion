//! Port of `src/lib/verification/arcane/pending-terminal-operation-store.mjs`
//! — `PendingTerminalOperationStore` (mint/append/matching/resolve).
//!
//! Schema: `arcane-pending-terminal-operation-v1` (already ported to this
//! crate's `wf068::schemas_arcane::pending-terminal-operation-v1.schema.json`).
//! This port validates the same *required-field* surface the JS module
//! checks via `validateSchema(schema, ...)`, rather than re-implementing a
//! general JSON-Schema validator inline; wf068 owns the general validator
//! (`wf068::validate`).
//!
//! GAP vs the JS source: `signRecord`/`verifyRecord` in JS delegate to
//! `guard/compat/audit/receipt-auth.mjs`, which is out of this chunk's
//! owned paths and whose exact keyed-MAC construction this crate cannot see
//! without a `legion-arcane` dependency edge (native equivalent:
//! `legion_arcane::receipt_auth`; see the wf073 report). This port
//! implements a self-contained, tamper-evident keyed digest
//! (`sha256(key_hex || canonical_json(record))`) that satisfies the same
//! external contract exercised here — a record with `authentication` intact
//! verifies, and any mutation to a bound field fails verification — but is
//! **not** byte-for-byte the same MAC as `receipt-auth.mjs`/
//! `legion_arcane::receipt_auth`. Do not treat signatures minted here as
//! interoperable with that module's signatures.
//!
//! GAP: nonce generation uses a process-time+counter seed through
//! `sha2` (no `rand`/`getrandom` crate is in this crate's `Cargo.lock`)
//! rather than a CSPRNG (`node:crypto.randomBytes` in JS). Sufficient for
//! uniqueness within a process; not cryptographically unpredictable. Flag
//! for the integrator if the minted nonce needs to resist prediction by a
//! party who does not already hold the signing key.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::errors::ArcaneError;

pub const PENDING_TERMINAL_OPERATION_FIELDS: &[&str] = &[
    "schemaVersion",
    "kind",
    "claimId",
    "invocationProofDigest",
    "producerAuthority",
    "runId",
    "taskId",
    "contractId",
    "contractVersion",
    "contractDigest",
    "sourceRevision",
    "turnCorrelationDigest",
    "expectedStopOrdinal",
    "outcomeSummaryDigest",
    "artifactStateDigest",
    "advisoryClaim",
    "highRiskContext",
    "issuedAt",
    "expiresAt",
    "nonce",
];

/// Fields required to be present (and non-null where the JS schema marks
/// them non-nullable) on a fully-formed claim, mirroring the required list
/// in `pending-terminal-operation-v1.schema.json` minus `authentication`
/// (checked separately by signature verification).
const REQUIRED_NON_NULL: &[&str] = &[
    "schemaVersion",
    "kind",
    "claimId",
    "invocationProofDigest",
    "producerAuthority",
    "runId",
    "taskId",
    "contractId",
    "contractVersion",
    "contractDigest",
    "sourceRevision",
    "turnCorrelationDigest",
    "expectedStopOrdinal",
    "outcomeSummaryDigest",
    "artifactStateDigest",
    "issuedAt",
    "expiresAt",
    "nonce",
];

fn decision(allowed: bool, code: Option<&str>, message: Option<&str>, detail: Value) -> Value {
    let mut object = Map::new();
    object.insert("allowed".into(), json!(allowed));
    if let Some(code) = code {
        object.insert("code".into(), json!(code));
    }
    if let Some(message) = message {
        object.insert("message".into(), json!(message));
    }
    if !detail.is_null() {
        object.insert("detail".into(), detail);
    }
    Value::Object(object)
}

fn deny(code: &str, message: &str) -> Value {
    decision(
        false,
        Some(code),
        Some(message),
        json!({
            "missingClasses": ["terminal-operation-claim"],
            "responsibleProducer": "legion completion claim",
            "remediationRoutes": ["legion completion claim --help"],
        }),
    )
}

fn digest_value(value: &Value) -> String {
    // Mirrors `legion_contracts::canonical_digest` (`sha256:<hex>` over the
    // canonical JSON encoding); avoided as a direct dependency here purely
    // because `Value`'s own key order already needs normalizing first via
    // `serde_json`'s BTreeMap-backed `Map` (enabled by this crate's
    // `preserve_order`-free `serde_json`), so `to_vec` is already canonical
    // per-key-sorted JSON.
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    let hash = Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(hash))
}

fn sign_record(record: &Value, key: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hex::encode(key).as_bytes());
    hasher.update(serde_json::to_vec(record).unwrap_or_default());
    hex::encode(hasher.finalize())
}

fn verify_record(record: &Value, signature: &str, key: &[u8]) -> bool {
    sign_record(record, key) == signature
}

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn random_nonce_hex(len_bytes: usize) -> String {
    let seq = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let mut hasher = Sha256::new();
    hasher.update(seq.to_le_bytes());
    hasher.update(nanos.to_le_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..len_bytes.min(digest.len())])
}

fn read_json(path: &Path) -> std::io::Result<Value> {
    let bytes = fs::read(path)?;
    serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

fn write_json_new(path: &Path, value: &Value) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    Ok(())
}

fn missing_non_null_fields(claim: &Value) -> Vec<&'static str> {
    let obj = claim.as_object();
    REQUIRED_NON_NULL
        .iter()
        .copied()
        .filter(|field| match obj.and_then(|o| o.get(*field)) {
            None => true,
            Some(Value::Null) => true,
            _ => false,
        })
        .collect()
}

pub struct PendingTerminalOperationStore {
    root: PathBuf,
    key: Vec<u8>,
    clock: Box<dyn Fn() -> String + Send + Sync>,
}

impl PendingTerminalOperationStore {
    pub fn new(root: impl Into<PathBuf>, key: Vec<u8>, clock: impl Fn() -> String + Send + Sync + 'static) -> Self {
        Self { root: root.into(), key, clock: Box::new(clock) }
    }

    fn claim_path(&self, claim_id: &str) -> PathBuf {
        // JS: `id.slice(7)` strips a `sha256:` (7-char) prefix.
        let name = claim_id.get(7..).unwrap_or(claim_id);
        self.root.join("claims").join(format!("{name}.json"))
    }

    fn transition_path(&self, claim_id: &str, state: &str) -> PathBuf {
        let name = claim_id.get(7..).unwrap_or(claim_id);
        self.root.join("transitions").join(format!("{name}-{state}.json"))
    }

    /// Mint a new, self-signed pending-terminal-operation claim. Callers may
    /// not supply `authentication` or `claimId` — both are ledger-owned.
    pub fn mint(&self, fields: Map<String, Value>) -> Result<Value, ArcaneError> {
        if fields.contains_key("authentication") || fields.contains_key("claimId") {
            return Err(ArcaneError::new(
                "ARC_AUTHORITY_MODEL_CLAIMED",
                "caller claim authentication is forbidden",
            ));
        }
        let issued_at = (self.clock)();
        let issued_ms = chrono_like_parse_ms(&issued_at);
        let expires_at = fields
            .get("expiresAt")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| format_ms_as_iso(issued_ms + 300_000));
        let nonce = fields
            .get("nonce")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| random_nonce_hex(16));

        let mut unsigned = Map::new();
        unsigned.insert("schemaVersion".into(), json!(1));
        unsigned.insert("kind".into(), json!("arcane-pending-terminal-operation"));
        for (k, v) in fields.iter() {
            unsigned.insert(k.clone(), v.clone());
        }
        unsigned.insert(
            "advisoryClaim".into(),
            fields.get("advisoryClaim").cloned().unwrap_or(Value::Null),
        );
        unsigned.insert(
            "highRiskContext".into(),
            fields.get("highRiskContext").cloned().unwrap_or(Value::Null),
        );
        unsigned.insert("issuedAt".into(), json!(issued_at));
        unsigned.insert("expiresAt".into(), json!(expires_at));
        unsigned.insert("nonce".into(), json!(nonce));

        let unsigned_value = Value::Object(unsigned.clone());
        let claim_id = digest_value(&unsigned_value);
        unsigned.insert("claimId".into(), json!(claim_id));
        let claim_value = Value::Object(unsigned);

        let signature = sign_record(&claim_value, &self.key);
        let mut signed = claim_value.as_object().cloned().unwrap();
        signed.insert(
            "authentication".into(),
            json!({ "signature": signature, "keyId": hex::encode(&self.key[..self.key.len().min(4)]) }),
        );
        let signed_value = Value::Object(signed);

        let missing = missing_non_null_fields(&signed_value);
        if !missing.is_empty() {
            return Err(ArcaneError::with_details(
                "ARC_SCHEMA_INVALID",
                "invalid terminal operation claim",
                json!({ "missing": missing }),
            ));
        }
        Ok(signed_value)
    }

    /// Append a minted claim to the durable store. Idempotent on an
    /// identical re-submission of the same `claimId`; rejects a colliding
    /// but different claim.
    pub fn append(&self, claim: Value) -> Value {
        let missing = missing_non_null_fields(&claim);
        if !missing.is_empty() {
            return deny("ARC_SCHEMA_INVALID", "terminal claim schema invalid");
        }
        let Some(auth) = claim.get("authentication").and_then(Value::as_object) else {
            return deny("ARC_SCHEMA_INVALID", "terminal claim schema invalid");
        };
        let Some(signature) = auth.get("signature").and_then(Value::as_str) else {
            return deny("ARC_SCHEMA_INVALID", "terminal claim schema invalid");
        };
        let mut unsigned = claim.as_object().cloned().unwrap();
        unsigned.remove("authentication");
        let unsigned_value = Value::Object(unsigned);
        if !verify_record(&unsigned_value, signature, &self.key) {
            return deny("ARC_BINDING_MISMATCH", "terminal claim authentication invalid");
        }

        let claim_id = claim.get("claimId").and_then(Value::as_str).unwrap_or_default();
        let claim_file = self.claim_path(claim_id);
        let pending_file = self.transition_path(claim_id, "pending");

        if let Err(err) = write_json_new(&claim_file, &claim) {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                return match read_json(&claim_file) {
                    Ok(prior) if digest_value(&prior) == digest_value(&claim) => decision(
                        true,
                        None,
                        None,
                        json!({ "claimId": claim_id, "claim": prior, "idempotent": true }),
                    ),
                    _ => deny("ARC_REPLAY_NONCE_SEEN", "terminal claim collision"),
                };
            }
            return deny("ARC_STORE_CORRUPT", "terminal claim could not be persisted");
        }
        let transition = json!({ "state": "PENDING", "claimId": claim_id, "at": (self.clock)() });
        if write_json_new(&pending_file, &transition).is_err() {
            return deny("ARC_STORE_CORRUPT", "terminal claim transition could not be persisted");
        }
        decision(true, None, None, json!({ "claimId": claim_id, "claim": claim }))
    }

    pub fn matching(&self, turn_correlation_digest: &str, stop_ordinal: i64) -> Option<Value> {
        let dir = self.root.join("claims");
        let entries = fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let Ok(value) = read_json(&entry.path()) else { continue };
            let matches = value.get("turnCorrelationDigest").and_then(Value::as_str)
                == Some(turn_correlation_digest)
                && value.get("expectedStopOrdinal").and_then(Value::as_i64) == Some(stop_ordinal);
            if matches {
                return Some(value);
            }
        }
        None
    }

    pub fn resolve(
        &self,
        claim_id: &str,
        stop_event_digest: &str,
        turn_correlation_digest: &str,
        stop_ordinal: i64,
        terminal: bool,
    ) -> Value {
        let Ok(claim) = read_json(&self.claim_path(claim_id)) else {
            return deny("ARC_CLAIM_PREREQUISITE_UNMET", "pending terminal claim unavailable");
        };
        let Some(auth) = claim.get("authentication").and_then(Value::as_object) else {
            return deny("ARC_SCHEMA_INVALID", "terminal claim schema invalid");
        };
        let Some(signature) = auth.get("signature").and_then(Value::as_str) else {
            return deny("ARC_SCHEMA_INVALID", "terminal claim schema invalid");
        };
        let mut unsigned = claim.as_object().cloned().unwrap();
        unsigned.remove("authentication");
        if !verify_record(&Value::Object(unsigned), signature, &self.key) {
            return deny("ARC_BINDING_MISMATCH", "terminal claim authentication invalid");
        }
        let expires_at = claim.get("expiresAt").and_then(Value::as_str).unwrap_or_default();
        if chrono_like_parse_ms(expires_at) < chrono_like_parse_ms(&(self.clock)()) {
            return deny("ARC_CLAIM_PREREQUISITE_UNMET", "terminal claim expired");
        }
        if claim.get("turnCorrelationDigest").and_then(Value::as_str) != Some(turn_correlation_digest)
            || claim.get("expectedStopOrdinal").and_then(Value::as_i64) != Some(stop_ordinal)
        {
            return deny("ARC_BINDING_MISMATCH", "Stop does not match pending claim");
        }

        let state = if terminal { "consumed" } else { "abandoned" };
        let record = json!({
            "state": state.to_uppercase(),
            "claimId": claim_id,
            "stopEventDigest": stop_event_digest,
            "at": (self.clock)(),
        });

        for other in ["consumed", "abandoned"] {
            if let Ok(prior) = read_json(&self.transition_path(claim_id, other)) {
                return if prior.get("stopEventDigest").and_then(Value::as_str) == Some(stop_event_digest) {
                    let certification = if prior.get("state").and_then(Value::as_str) == Some("CONSUMED") {
                        "genuine"
                    } else {
                        "not_claimed"
                    };
                    decision(
                        true,
                        None,
                        None,
                        json!({ "record": prior, "idempotent": true, "certification": certification }),
                    )
                } else {
                    deny("ARC_REPLAY_NONCE_SEEN", "changed Stop replay")
                };
            }
        }

        let file = self.transition_path(claim_id, state);
        if write_json_new(&file, &record).is_err() {
            return deny("ARC_STORE_CORRUPT", "terminal claim transition could not be persisted");
        }
        let certification = if terminal { "genuine" } else { "not_claimed" };
        decision(true, None, None, json!({ "record": record, "certification": certification }))
    }
}

/// Minimal ISO-8601 `YYYY-MM-DDTHH:MM:SS.sssZ` -> epoch-ms parser/formatter,
/// sufficient for this store's own clock strings (it never needs to parse
/// arbitrary external timestamps). Avoids adding a `chrono`/`time`
/// dependency for a single store.
fn chrono_like_parse_ms(iso: &str) -> i64 {
    // Falls back to 0 (treated as "epoch", i.e. always expired / always
    // earliest) on anything unparseable, which is the safe failure mode for
    // both call sites (`expiresAt < now` and `from` comparisons).
    fn two(s: &str) -> i64 {
        s.parse().unwrap_or(0)
    }
    let bytes = iso.as_bytes();
    if bytes.len() < 23 {
        return 0;
    }
    let year: i64 = iso.get(0..4).and_then(|s| s.parse().ok()).unwrap_or(1970);
    let month = two(iso.get(5..7).unwrap_or("01"));
    let day = two(iso.get(8..10).unwrap_or("01"));
    let hour = two(iso.get(11..13).unwrap_or("00"));
    let minute = two(iso.get(14..16).unwrap_or("00"));
    let second = two(iso.get(17..19).unwrap_or("00"));
    let millis = two(iso.get(20..23).unwrap_or("000"));

    // Days since epoch via a simple proleptic Gregorian calculation.
    let days = days_from_civil(year, month, day);
    ((days * 86_400 + hour * 3600 + minute * 60 + second) * 1000) + millis
}

fn format_ms_as_iso(ms: i64) -> String {
    let (days, rem_ms) = (ms.div_euclid(86_400_000), ms.rem_euclid(86_400_000));
    let (y, m, d) = civil_from_days(days);
    let secs_total = rem_ms / 1000;
    let millis = rem_ms % 1000;
    let h = secs_total / 3600;
    let mi = (secs_total % 3600) / 60;
    let s = secs_total % 60;
    format!("{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{millis:03}Z")
}

// Howard Hinnant's civil-from-days / days-from-civil algorithms (public
// domain), used here only to avoid a date/time crate dependency.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}
