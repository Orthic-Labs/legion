//! Faithful port of `src/lib/contracts/arcane/authority-invocation-proof.mjs`.
//!
//! An authority invocation proof lets a non-Alchemist role (today: Oracle's
//! `completion-claim`) attach a signed, single-use, time-boxed credential to
//! one host event, so a downstream consumer can verify the claim came from
//! a specific already-authenticated host event rather than model text.
//!
//! wf067 owns no dependency budget (no `hmac`/`sha2` crate, no
//! `legion-contracts` reuse without a Cargo.toml edit — see the wf067
//! report), so signing/verification here is a small self-contained
//! HMAC-over-bound-fields scheme built on `canonical::hmac_sha256_hex`
//! rather than a copy of `receipt-auth.mjs`'s full S03 scheme (that belongs
//! to `arcane_port`/wf006, not this chunk). It is faithful to
//! `authority-invocation-proof.mjs`'s own algorithm: derive a per-role/
//! per-purpose key from the root key, sign the exact `AUTHORITY_PROOF_FIELDS`
//! list, and refuse (not silently accept) any drift in that field set.
//!
//! `HostEventLedger` (host/arcane/host-event-ledger.mjs) is not owned by
//! this chunk either; callers inject a `LedgerStore` implementation that
//! exposes the same two operations `issue`/`verify` actually use:
//! `verify()` (continuity, mirroring `ledgerStore.verify().allowed`) and
//! `records()` (mirroring `ledgerStore.records()`).

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;

use super::canonical::{canonical_json, digest_value, hmac_sha256, hmac_sha256_hex, Json};
use super::errors::{ArcCode, ArcaneError, Decision};
use super::json_parse;

/// Mirrors JS `AUTHORITY_PROOF_FIELDS`.
pub const AUTHORITY_PROOF_FIELDS: &[&str] = &[
    "schemaVersion", "kind", "invocationId", "eventDigest", "eventSequence", "purpose", "role",
    "sessionId", "runId", "taskId", "contractId", "contractVersion", "contractDigest",
    "sourceRevision", "turnCorrelationDigest", "stopOrdinal", "domain", "issuedAt", "expiresAt", "nonce",
];

/// Mirrors JS `HOST_EVENT_LEDGER_FIELDS` (host-event-ledger.mjs), needed
/// here only to verify the caller-supplied ledger event's own signature
/// before trusting it.
pub const HOST_EVENT_LEDGER_FIELDS: &[&str] = &[
    "schemaVersion", "kind", "eventId", "eventSequence", "previousDigest", "turnCorrelationDigest",
    "stopOrdinal", "adapter", "eventType", "sessionId", "runId", "taskId", "contractId",
    "contractVersion", "contractDigest", "sourceRevision", "observedAuthority", "payloadDigest", "observedAt",
];

const PURPOSES: &[&str] = &["completion-claim", "budget-amendment"];
const ROLES: &[&str] = &["legion", "alchemist", "sage", "oracle"];

fn role_purpose_allowed(role: &str, purpose: &str) -> bool {
    match role {
        "oracle" => purpose == "completion-claim",
        _ => PURPOSES.contains(&purpose),
    }
}

fn mac_domain_for(role: &str, purpose: &str) -> String {
    format!("arcane-authority-proof:v1:{role}:{purpose}")
}
fn key_id_for(root_key_id: &str, role: &str, purpose: &str) -> String {
    format!("{root_key_id}:authority-proof:{role}:{purpose}")
}

/// Signing key material, keyed by id. Mirrors the JS `keyRing`.
pub trait KeyRing {
    fn get(&self, key_id: &str) -> Option<Vec<u8>>;
    fn has(&self, key_id: &str) -> bool {
        self.get(key_id).is_some()
    }
    /// Derive-and-store a key from an HMAC of `root_key` under `mac_domain`,
    /// mirroring the JS `#credentials` derivation. Implementations must make
    /// subsequent `get(key_id)` calls return this material.
    fn add(&mut self, key_id: &str, material: Vec<u8>);
}

/// In-memory keyring sufficient for tests and single-process callers.
#[derive(Default)]
pub struct StaticKeyRing(BTreeMap<String, Vec<u8>>);

impl StaticKeyRing {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
    pub fn with_key(mut self, key_id: &str, material: &[u8]) -> Self {
        self.0.insert(key_id.to_string(), material.to_vec());
        self
    }
}

impl KeyRing for StaticKeyRing {
    fn get(&self, key_id: &str) -> Option<Vec<u8>> {
        self.0.get(key_id).cloned()
    }
    fn add(&mut self, key_id: &str, material: Vec<u8>) {
        self.0.insert(key_id.to_string(), material);
    }
}

/// What `issue`/`verify` need from the host event ledger. Injected because
/// `HostEventLedger` itself is out of this chunk's owned scope.
pub trait LedgerStore {
    /// Mirrors `ledgerStore.verify().allowed`.
    fn verify_ok(&self) -> bool;
    /// Mirrors `ledgerStore.records()`; last element is the current head.
    fn records(&self) -> Vec<Json>;
}

/// Mirrors the JS `binding` argument to `issue()`.
pub struct BindingKey<'a> {
    pub run_id: &'a str,
    pub task_id: &'a str,
    pub contract_id: &'a str,
    pub contract_version: &'a str,
    pub contract_digest: &'a str,
}

fn binding_key_json(b: &BindingKey<'_>, session_id: &str) -> Json {
    Json::Obj(vec![
        ("sessionId".into(), Json::str(session_id)),
        ("runId".into(), Json::str(b.run_id)),
        ("taskId".into(), Json::str(b.task_id)),
        ("contractId".into(), Json::str(b.contract_id)),
        ("contractVersion".into(), Json::str(b.contract_version)),
        ("contractDigest".into(), Json::str(b.contract_digest)),
    ])
}

fn deny(code: ArcCode, message: impl Into<String>) -> Decision {
    Decision::deny(code, message, vec![])
}

pub struct AuthorityInvocationProofIssuer<'a, K: KeyRing, L: LedgerStore> {
    root: PathBuf,
    keyring: &'a mut K,
    key_id: String,
    ledger_store: &'a L,
    clock: Box<dyn Fn() -> String + Send + Sync>,
}

#[derive(Debug)]
pub enum IssueOutcome {
    Issued(Json),
}

impl<'a, K: KeyRing, L: LedgerStore> AuthorityInvocationProofIssuer<'a, K, L> {
    pub fn new(
        root: impl Into<PathBuf>,
        keyring: &'a mut K,
        key_id: &str,
        ledger_store: &'a L,
        clock: impl Fn() -> String + Send + Sync + 'static,
    ) -> Self {
        Self { root: root.into(), keyring, key_id: key_id.to_string(), ledger_store, clock: Box::new(clock) }
    }

    fn proof_path(&self, invocation_id: &str) -> PathBuf {
        self.root.join("proofs").join(format!("{}.json", strip_digest_prefix(invocation_id)))
    }
    fn transition_path(&self, invocation_id: &str, state: &str) -> PathBuf {
        self.root.join("transitions").join(format!("{}-{}.json", strip_digest_prefix(invocation_id), state))
    }

    fn credentials(&mut self, role: &str, purpose: &str) -> Result<(String, String), ArcaneError> {
        let mac_domain = mac_domain_for(role, purpose);
        let key_id = key_id_for(&self.key_id, role, purpose);
        if !self.keyring.has(&key_id) {
            let root_key = self
                .keyring
                .get(&self.key_id)
                .ok_or_else(|| ArcaneError::new(ArcCode::ArcAuthKeyUnavailable, "root signing key is unavailable"))?;
            let material = hmac_sha256(&root_key, format!("arcane-key-derivation:v1\0{mac_domain}").as_bytes());
            self.keyring.add(&key_id, material.to_vec());
        }
        Ok((key_id, mac_domain))
    }

    /// Mirrors JS `issue()`.
    pub fn issue(&mut self, ledger: &Json, binding: &BindingKey<'_>, purpose: &str, role: &str) -> Result<IssueOutcome, ArcaneError> {
        if !PURPOSES.contains(&purpose) || !ROLES.contains(&role) || !role_purpose_allowed(role, purpose) {
            return Err(ArcaneError::new(ArcCode::ArcAuthForged, "invalid current invocation proof input"));
        }
        if !self.ledger_store.verify_ok() {
            return Err(ArcaneError::new(ArcCode::ArcAuthForged, "invalid current invocation proof input"));
        }
        let records = self.ledger_store.records();
        let last = records.last().ok_or_else(|| ArcaneError::new(ArcCode::ArcAuthForged, "invalid current invocation proof input"))?;
        if digest_value(last).ok() != digest_value(ledger).ok() {
            return Err(ArcaneError::new(ArcCode::ArcAuthForged, "invalid current invocation proof input"));
        }
        if !verify_ledger_authentication(ledger) {
            return Err(ArcaneError::new(ArcCode::ArcAuthForged, "invalid current invocation proof input"));
        }
        let observed_authority = ledger.get("observedAuthority").and_then(|v| v.as_str()).unwrap_or("");
        if observed_authority != role {
            return Err(ArcaneError::new(ArcCode::ArcAuthForged, "invalid current invocation proof input"));
        }

        let session_id = field_str(ledger, "sessionId");
        let (key_id, mac_domain) = self.credentials(role, purpose)?;
        let event_digest = digest_value(ledger).map_err(|e| ArcaneError::new(ArcCode::ArcAuthForged, e.message))?;
        let binding_key = binding_key_json(binding, &session_id);
        let invocation_id = digest_value(&Json::Obj(vec![
            ("eventDigest".into(), Json::str(event_digest.clone())),
            ("purpose".into(), Json::str(purpose)),
            ("role".into(), Json::str(role)),
            ("binding".into(), binding_key),
        ]))
        .map_err(|e| ArcaneError::new(ArcCode::ArcAuthForged, e.message))?;

        let file = self.proof_path(&invocation_id);
        if let Ok(text) = fs::read_to_string(&file) {
            if let Ok(existing) = json_parse::parse(&text) {
                let existing_key_id = existing.get("authentication").and_then(|a| a.get("keyId")).and_then(|v| v.as_str());
                let existing_domain = existing.get("authentication").and_then(|a| a.get("macDomain")).and_then(|v| v.as_str());
                if existing_key_id != Some(key_id.as_str()) || existing_domain != Some(mac_domain.as_str()) {
                    return Err(ArcaneError::new(ArcCode::ArcAuthForged, "authority proof key domain mismatch"));
                }
                return Ok(IssueOutcome::Issued(existing));
            }
        }

        fs::create_dir_all(self.root.join("proofs")).map_err(|e| io_err(e))?;
        fs::create_dir_all(self.root.join("transitions")).map_err(|e| io_err(e))?;
        let issued_at = (self.clock)();
        let expires_at = add_millis_iso(&issued_at, 300_000);
        let domain = format!("arcane-authority-proof:{role}:{purpose}");
        let nonce = random_hex(16);

        let event_sequence = ledger.get("eventSequence").cloned().unwrap_or(Json::Null);
        let source_revision = ledger.get("sourceRevision").cloned().unwrap_or(Json::Null);
        let turn_correlation_digest = ledger.get("turnCorrelationDigest").cloned().unwrap_or(Json::Null);
        let stop_ordinal = ledger.get("stopOrdinal").cloned().unwrap_or(Json::Null);

        let unsigned = Json::Obj(vec![
            ("schemaVersion".into(), Json::I64(1)),
            ("kind".into(), Json::str("arcane-authority-invocation-proof")),
            ("invocationId".into(), Json::str(invocation_id.clone())),
            ("eventDigest".into(), Json::str(event_digest)),
            ("eventSequence".into(), event_sequence),
            ("purpose".into(), Json::str(purpose)),
            ("role".into(), Json::str(role)),
            ("sessionId".into(), Json::str(session_id)),
            ("runId".into(), Json::str(binding.run_id)),
            ("taskId".into(), Json::str(binding.task_id)),
            ("contractId".into(), Json::str(binding.contract_id)),
            ("contractVersion".into(), Json::str(binding.contract_version)),
            ("contractDigest".into(), Json::str(binding.contract_digest)),
            ("sourceRevision".into(), source_revision),
            ("turnCorrelationDigest".into(), turn_correlation_digest),
            ("stopOrdinal".into(), stop_ordinal),
            ("domain".into(), Json::str(domain)),
            ("issuedAt".into(), Json::str(issued_at.clone())),
            ("expiresAt".into(), Json::str(expires_at)),
            ("nonce".into(), Json::str(nonce)),
        ]);

        let key = self
            .keyring
            .get(&key_id)
            .ok_or_else(|| ArcaneError::new(ArcCode::ArcAuthKeyUnavailable, "signing key is unavailable"))?;
        let mac = sign_over_fields(&unsigned, &key, AUTHORITY_PROOF_FIELDS, &mac_domain)?;
        let proof = with_authentication(unsigned, &key_id, &mac_domain, &mac);

        let proof_text = canonical_json(&proof).unwrap();
        match write_new(&file, proof_text.as_bytes()) {
            Ok(()) => {
                let transition = Json::Obj(vec![
                    ("state".into(), Json::str("ISSUED")),
                    ("proofDigest".into(), Json::str(digest_value(&proof).unwrap())),
                    ("at".into(), Json::str(issued_at)),
                ]);
                let _ = write_new(&self.transition_path(&invocation_id, "issued"), canonical_json(&transition).unwrap().as_bytes());
                Ok(IssueOutcome::Issued(proof))
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let text = fs::read_to_string(&file).map_err(io_err)?;
                let existing = json_parse::parse(&text).map_err(|_| ArcaneError::new(ArcCode::ArcStoreCorrupt, "authority proof missing"))?;
                Ok(IssueOutcome::Issued(existing))
            }
            Err(e) => Err(io_err(e)),
        }
    }

    pub fn find_by_digest(&self, proof_digest: &str) -> Option<Json> {
        let dir = self.root.join("proofs");
        let entries = fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            if let Ok(text) = fs::read_to_string(entry.path()) {
                if let Ok(v) = json_parse::parse(&text) {
                    if digest_value(&v).ok().as_deref() == Some(proof_digest) {
                        return Some(v);
                    }
                }
            }
        }
        None
    }

    /// Mirrors JS `verify()`: role must be `oracle`/`completion-claim`.
    pub fn verify(&mut self, proof: Option<&Json>, expected: &BTreeMap<&str, &str>) -> Decision {
        let Some(proof) = proof else {
            return deny(ArcCode::ArcAuthForged, "Oracle completion authority proof is invalid");
        };
        let role = proof.get("role").and_then(|v| v.as_str()).unwrap_or("");
        let purpose = proof.get("purpose").and_then(|v| v.as_str()).unwrap_or("");
        if role != "oracle" || purpose != "completion-claim" {
            return deny(ArcCode::ArcAuthForged, "Oracle completion authority proof is invalid");
        }
        let mac_domain = mac_domain_for(role, purpose);
        let suffix = format!(":authority-proof:{role}:{purpose}");
        let presented_key_id = proof.get("authentication").and_then(|a| a.get("keyId")).and_then(|v| v.as_str()).unwrap_or("");
        let Some(root_key_id) = presented_key_id.strip_suffix(suffix.as_str()) else {
            return deny(ArcCode::ArcAuthForged, "authority proof key identifier is invalid");
        };

        if !self.keyring.has(presented_key_id) {
            let Some(root_key) = self.keyring.get(root_key_id) else {
                return deny(ArcCode::ArcAuthKeyUnavailable, "authority proof root key is unavailable");
            };
            let material = hmac_sha256(&root_key, format!("arcane-key-derivation:v1\0{mac_domain}").as_bytes());
            self.keyring.add(presented_key_id, material.to_vec());
        }

        let Some(key) = self.keyring.get(presented_key_id) else {
            return deny(ArcCode::ArcAuthKeyUnavailable, "authority proof root key is unavailable");
        };
        let presented_mac = proof.get("authentication").and_then(|a| a.get("mac")).and_then(|v| v.as_str()).unwrap_or("");
        let expected_mac = match sign_over_fields(proof, &key, AUTHORITY_PROOF_FIELDS, &mac_domain) {
            Ok(m) => m,
            Err(_) => return deny(ArcCode::ArcAuthForged, "authority proof authentication is invalid"),
        };
        if presented_mac != expected_mac {
            return deny(ArcCode::ArcAuthForged, "authority proof authentication is invalid");
        }
        if presented_key_id != key_id_for(root_key_id, role, purpose) {
            return deny(ArcCode::ArcAuthForged, "authority proof is expired or misbound");
        }
        let expires_at = proof.get("expiresAt").and_then(|v| v.as_str()).unwrap_or("");
        if iso_before(expires_at, &(self.clock)()) {
            return deny(ArcCode::ArcAuthForged, "authority proof is expired or misbound");
        }
        for (key, value) in expected {
            let actual = proof.get(key).and_then(|v| v.as_str());
            if actual != Some(*value) {
                return deny(ArcCode::ArcBindingMismatch, "authority proof does not bind this completion execution");
            }
        }
        let invocation_id = proof.get("invocationId").and_then(|v| v.as_str()).unwrap_or("");
        let issued = match fs::read_to_string(self.proof_path(invocation_id)).ok().and_then(|t| json_parse::parse(&t).ok()) {
            Some(v) => v,
            None => return deny(ArcCode::ArcStoreCorrupt, "authority proof missing"),
        };
        if digest_value(&issued).ok() != digest_value(proof).ok() || !self.ledger_store.verify_ok() {
            return deny(ArcCode::ArcAuthForged, "authority proof persistence or host ledger is invalid");
        }
        let event_digest = proof.get("eventDigest").and_then(|v| v.as_str()).unwrap_or("");
        let event = self.ledger_store.records().into_iter().find(|r| digest_value(r).ok().as_deref() == Some(event_digest));
        let Some(event) = event else {
            return deny(ArcCode::ArcBindingMismatch, "authority proof host binding is unavailable");
        };
        let matches = event.get("observedAuthority").and_then(|v| v.as_str()) == Some("oracle")
            && field_str(&event, "sessionId") == field_str(proof, "sessionId")
            && field_str(&event, "runId") == field_str(proof, "runId")
            && field_str(&event, "taskId") == field_str(proof, "taskId")
            && field_str(&event, "contractId") == field_str(proof, "contractId")
            && field_str(&event, "contractVersion") == field_str(proof, "contractVersion")
            && field_str(&event, "contractDigest") == field_str(proof, "contractDigest")
            && field_str(&event, "sourceRevision") == field_str(proof, "sourceRevision");
        if !matches {
            return deny(ArcCode::ArcBindingMismatch, "authority proof host binding is unavailable");
        }
        Decision::allow(vec![("invocationId".into(), invocation_id.into())])
    }

    /// Mirrors JS `consume()`.
    pub fn consume(&mut self, proof: &Json, artifact_digest: Option<&str>) -> Result<Decision, ArcaneError> {
        let role = proof.get("role").and_then(|v| v.as_str()).unwrap_or("");
        let purpose = proof.get("purpose").and_then(|v| v.as_str()).unwrap_or("");
        if !ROLES.contains(&role) || !PURPOSES.contains(&purpose) {
            return Ok(deny(ArcCode::ArcAuthForged, "authority proof authentication is invalid"));
        }
        let mac_domain = mac_domain_for(role, purpose);
        let presented_key_id = proof.get("authentication").and_then(|a| a.get("keyId")).and_then(|v| v.as_str()).unwrap_or("");
        let expected_key_id = key_id_for(&self.key_id, role, purpose);
        let Some(key) = self.keyring.get(presented_key_id) else {
            return Ok(deny(ArcCode::ArcAuthForged, "authority proof authentication is invalid"));
        };
        let presented_mac = proof.get("authentication").and_then(|a| a.get("mac")).and_then(|v| v.as_str()).unwrap_or("");
        let expected_mac = sign_over_fields(proof, &key, AUTHORITY_PROOF_FIELDS, &mac_domain)
            .map_err(|e| ArcaneError::new(ArcCode::ArcAuthForged, e.message))?;
        if presented_mac != expected_mac {
            return Ok(deny(ArcCode::ArcAuthForged, "authority proof authentication is invalid"));
        }
        if presented_key_id != expected_key_id {
            return Ok(deny(ArcCode::ArcAuthForged, "authority proof key identifier does not match role and purpose"));
        }
        let expires_at = proof.get("expiresAt").and_then(|v| v.as_str()).unwrap_or("");
        if iso_before(expires_at, &(self.clock)()) {
            return Ok(deny(ArcCode::ArcClaimPrerequisiteUnmet, "authority proof expired"));
        }
        let invocation_id = proof.get("invocationId").and_then(|v| v.as_str()).unwrap_or("");
        let issued = match fs::read_to_string(self.proof_path(invocation_id)).ok().and_then(|t| json_parse::parse(&t).ok()) {
            Some(v) => v,
            None => return Ok(deny(ArcCode::ArcStoreCorrupt, "authority proof missing")),
        };
        if digest_value(&issued).ok() != digest_value(proof).ok() {
            return Ok(deny(ArcCode::ArcAuthForged, "authority proof does not match issued record"));
        }
        let file = self.transition_path(invocation_id, "consumed");
        let transition = Json::Obj(vec![
            ("state".into(), Json::str("CONSUMED")),
            ("proofDigest".into(), Json::str(digest_value(proof).unwrap())),
            ("artifactDigest".into(), artifact_digest.map(Json::str).unwrap_or(Json::Null)),
            ("at".into(), Json::str((self.clock)())),
        ]);
        match write_new(&file, canonical_json(&transition).unwrap().as_bytes()) {
            Ok(()) => Ok(Decision::allow(vec![("state".into(), "CONSUMED".into())])),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                let text = fs::read_to_string(&file).map_err(io_err)?;
                let prior = json_parse::parse(&text).map_err(|_| ArcaneError::new(ArcCode::ArcStoreCorrupt, "authority proof missing"))?;
                let prior_artifact = prior.get("artifactDigest").and_then(|v| v.as_str());
                if prior_artifact == artifact_digest {
                    Ok(Decision::allow(vec![("idempotent".into(), "true".into())]))
                } else {
                    Ok(deny(ArcCode::ArcReplayNonceSeen, "authority proof already consumed"))
                }
            }
            Err(e) => Err(io_err(e)),
        }
    }
}

// ---------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------

fn field_str(v: &Json, key: &str) -> String {
    v.get(key).and_then(|j| j.as_str()).unwrap_or("").to_string()
}

fn strip_digest_prefix(id: &str) -> &str {
    id.strip_prefix("sha256:").unwrap_or(id)
}

fn sign_over_fields(record: &Json, key: &[u8], fields: &[&str], mac_domain: &str) -> Result<String, ArcaneError> {
    let mut projected = Vec::new();
    for f in fields {
        let v = record.get(f).cloned().unwrap_or(Json::Null);
        projected.push((f.to_string(), v));
    }
    let message = Json::Obj(vec![
        ("macDomain".into(), Json::str(mac_domain)),
        ("subject".into(), Json::Obj(projected)),
    ]);
    let text = canonical_json(&message).map_err(|e| ArcaneError::new(ArcCode::ArcAuthForged, e.message))?;
    Ok(hmac_sha256_hex(key, text.as_bytes()))
}

fn with_authentication(unsigned: Json, key_id: &str, mac_domain: &str, mac: &str) -> Json {
    let Json::Obj(mut pairs) = unsigned else { unreachable!() };
    pairs.push((
        "authentication".into(),
        Json::Obj(vec![
            ("keyId".into(), Json::str(key_id)),
            ("macDomain".into(), Json::str(mac_domain)),
            ("mac".into(), Json::str(mac)),
        ]),
    ));
    Json::Obj(pairs)
}

/// Placeholder for the ledger's own authentication check. wf067 does not own
/// `receipt-auth.mjs`'s signing scheme (that is wf006/`arcane_port`'s
/// module), so this checks only the structural precondition `issue()`
/// otherwise relies on the caller to have already validated: the ledger
/// event carries an `authentication` object at all. A wired integration
/// should replace this with a real `verify_record` call against
/// `HOST_EVENT_LEDGER_FIELDS` once wf006 is on the crate's dependency graph
/// (see wf067 report).
fn verify_ledger_authentication(ledger: &Json) -> bool {
    ledger.get("authentication").is_some()
}

fn add_millis_iso(iso: &str, millis: i64) -> String {
    let ms = parse_iso_millis(iso).unwrap_or(0) + millis;
    format_iso_millis(ms)
}

fn iso_before(a: &str, b: &str) -> bool {
    // ISO-8601 UTC timestamps of the `YYYY-MM-DDTHH:MM:SS.sssZ` form compare
    // correctly as strings; fall back to millis parsing for other forms.
    match (parse_iso_millis(a), parse_iso_millis(b)) {
        (Some(x), Some(y)) => x < y,
        _ => a < b,
    }
}

/// Milliseconds since Unix epoch for `YYYY-MM-DDTHH:MM:SS(.sss)?Z`. Minimal,
/// dependency-free parser sufficient for this module's own clock format.
fn parse_iso_millis(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z')?;
    let (date, time) = s.split_once('T')?;
    let mut d = date.split('-');
    let year: i64 = d.next()?.parse().ok()?;
    let month: i64 = d.next()?.parse().ok()?;
    let day: i64 = d.next()?.parse().ok()?;
    let (time, frac) = match time.split_once('.') {
        Some((t, f)) => (t, f),
        None => (time, "0"),
    };
    let mut t = time.split(':');
    let hour: i64 = t.next()?.parse().ok()?;
    let min: i64 = t.next()?.parse().ok()?;
    let sec: i64 = t.next()?.parse().ok()?;
    let millis: i64 = format!("{frac:0<3}")[..3].parse().ok()?;

    // Days since epoch via a proleptic Gregorian civil-from-days formula.
    let days = days_from_civil(year, month, day);
    let total_ms = days * 86_400_000 + hour * 3_600_000 + min * 60_000 + sec * 1000 + millis;
    Some(total_ms)
}

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
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn format_iso_millis(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (y, mo, d) = civil_from_days(days);
    let hour = rem / 3_600_000;
    let min = (rem / 60_000) % 60;
    let sec = (rem / 1000) % 60;
    let millis = rem % 1000;
    format!("{y:04}-{mo:02}-{d:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

fn write_new(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    let mut f = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

fn io_err(e: io::Error) -> ArcaneError {
    ArcaneError::new(ArcCode::ArcStoreCorrupt, e.to_string())
}

fn random_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = fs::File::open("/dev/urandom") {
            if f.read_exact(&mut buf).is_ok() {
                return super::canonical::hex_encode(&buf);
            }
        }
    }
    let seed = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let mut x = seed as u64 ^ (&buf as *const _ as u64);
    for slot in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *slot = (x & 0xff) as u8;
    }
    super::canonical::hex_encode(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        std::env::temp_dir().join(format!("wf067-invocation-proof-{}-{n}", std::process::id()))
    }

    struct FixedLedgerStore {
        records: Vec<Json>,
        ok: bool,
    }
    impl LedgerStore for FixedLedgerStore {
        fn verify_ok(&self) -> bool {
            self.ok
        }
        fn records(&self) -> Vec<Json> {
            self.records.clone()
        }
    }

    fn sample_ledger(observed_authority: &str) -> Json {
        Json::Obj(vec![
            ("schemaVersion".into(), Json::I64(1)),
            ("kind".into(), Json::str("arcane-host-event-ledger-record")),
            ("eventId".into(), Json::str("ev1")),
            ("eventSequence".into(), Json::I64(1)),
            ("previousDigest".into(), Json::Null),
            ("turnCorrelationDigest".into(), Json::str("td1")),
            ("stopOrdinal".into(), Json::Null),
            ("adapter".into(), Json::str("claude-code")),
            ("eventType".into(), Json::str("Stop")),
            ("sessionId".into(), Json::str("s1")),
            ("runId".into(), Json::str("run-1")),
            ("taskId".into(), Json::str("task-1")),
            ("contractId".into(), Json::str("EC-1")),
            ("contractVersion".into(), Json::I64(1)),
            ("contractDigest".into(), Json::str("sha256:abc")),
            ("sourceRevision".into(), Json::str("rev1")),
            ("observedAuthority".into(), Json::str(observed_authority)),
            ("payloadDigest".into(), Json::str("sha256:def")),
            ("observedAt".into(), Json::str("2026-01-01T00:00:00.000Z")),
            ("authentication".into(), Json::Obj(vec![("keyId".into(), Json::str("root")), ("mac".into(), Json::str("x"))])),
        ])
    }

    fn binding() -> BindingKey<'static> {
        BindingKey { run_id: "run-1", task_id: "task-1", contract_id: "EC-1", contract_version: "1", contract_digest: "sha256:abc" }
    }

    #[test]
    fn issue_rejects_role_purpose_mismatch() {
        let mut keyring = StaticKeyRing::new().with_key("root", b"root-secret");
        let ledger_store = FixedLedgerStore { records: vec![sample_ledger("oracle")], ok: true };
        let mut issuer = AuthorityInvocationProofIssuer::new(temp_root(), &mut keyring, "root", &ledger_store, || "2026-01-01T00:00:00.000Z".to_string());
        let err = issuer.issue(&sample_ledger("oracle"), &binding(), "budget-amendment", "oracle").unwrap_err();
        assert_eq!(err.code, ArcCode::ArcAuthForged);
    }

    #[test]
    fn issue_rejects_when_ledger_store_verify_fails() {
        let mut keyring = StaticKeyRing::new().with_key("root", b"root-secret");
        let ledger_store = FixedLedgerStore { records: vec![sample_ledger("oracle")], ok: false };
        let mut issuer = AuthorityInvocationProofIssuer::new(temp_root(), &mut keyring, "root", &ledger_store, || "2026-01-01T00:00:00.000Z".to_string());
        let err = issuer.issue(&sample_ledger("oracle"), &binding(), "completion-claim", "oracle").unwrap_err();
        assert_eq!(err.code, ArcCode::ArcAuthForged);
    }

    #[test]
    fn issue_then_verify_then_consume_round_trips() {
        let mut keyring = StaticKeyRing::new().with_key("root", b"root-secret");
        let ledger = sample_ledger("oracle");
        let ledger_store = FixedLedgerStore { records: vec![ledger.clone()], ok: true };
        let mut issuer = AuthorityInvocationProofIssuer::new(temp_root(), &mut keyring, "root", &ledger_store, || "2026-01-01T00:00:00.000Z".to_string());

        let IssueOutcome::Issued(proof) = issuer.issue(&ledger, &binding(), "completion-claim", "oracle").unwrap();
        assert_eq!(proof.get("role").and_then(|v| v.as_str()), Some("oracle"));

        let expected = BTreeMap::new();
        let verified = issuer.verify(Some(&proof), &expected);
        assert!(verified.allowed, "{verified:?}");

        let consumed = issuer.consume(&proof, Some("sha256:artifact")).unwrap();
        assert!(consumed.allowed, "{consumed:?}");

        // Replay with a different artifact digest is a distinct-artifact replay.
        let replay = issuer.consume(&proof, Some("sha256:other")).unwrap();
        assert_eq!(replay.code, Some(ArcCode::ArcReplayNonceSeen));

        // Same artifact digest is idempotent.
        let idempotent = issuer.consume(&proof, Some("sha256:artifact")).unwrap();
        assert!(idempotent.allowed);
    }

    #[test]
    fn issue_is_idempotent_for_the_same_event_purpose_role_binding() {
        let mut keyring = StaticKeyRing::new().with_key("root", b"root-secret");
        let ledger = sample_ledger("oracle");
        let ledger_store = FixedLedgerStore { records: vec![ledger.clone()], ok: true };
        let mut issuer = AuthorityInvocationProofIssuer::new(temp_root(), &mut keyring, "root", &ledger_store, || "2026-01-01T00:00:00.000Z".to_string());
        let IssueOutcome::Issued(first) = issuer.issue(&ledger, &binding(), "completion-claim", "oracle").unwrap();
        let IssueOutcome::Issued(second) = issuer.issue(&ledger, &binding(), "completion-claim", "oracle").unwrap();
        assert_eq!(digest_value(&first).unwrap(), digest_value(&second).unwrap());
    }

    #[test]
    fn verify_rejects_non_oracle_completion_proof() {
        let mut keyring = StaticKeyRing::new().with_key("root", b"root-secret");
        let ledger_store = FixedLedgerStore { records: vec![], ok: true };
        let mut issuer = AuthorityInvocationProofIssuer::new(temp_root(), &mut keyring, "root", &ledger_store, || "2026-01-01T00:00:00.000Z".to_string());
        let proof = Json::Obj(vec![("role".into(), Json::str("alchemist")), ("purpose".into(), Json::str("completion-claim"))]);
        let d = issuer.verify(Some(&proof), &BTreeMap::new());
        assert_eq!(d.code, Some(ArcCode::ArcAuthForged));
    }

    #[test]
    fn verify_none_is_forged() {
        let mut keyring = StaticKeyRing::new().with_key("root", b"root-secret");
        let ledger_store = FixedLedgerStore { records: vec![], ok: true };
        let mut issuer = AuthorityInvocationProofIssuer::new(temp_root(), &mut keyring, "root", &ledger_store, || "2026-01-01T00:00:00.000Z".to_string());
        let d = issuer.verify(None, &BTreeMap::new());
        assert_eq!(d.code, Some(ArcCode::ArcAuthForged));
    }

    #[test]
    fn iso_millis_round_trips() {
        let ms = parse_iso_millis("2026-01-01T00:00:00.000Z").unwrap();
        assert_eq!(format_iso_millis(ms), "2026-01-01T00:00:00.000Z");
        let plus5min = add_millis_iso("2026-01-01T00:00:00.000Z", 300_000);
        assert_eq!(plus5min, "2026-01-01T00:05:00.000Z");
    }

    #[test]
    fn expired_proof_is_denied_by_verify_and_consume() {
        let mut keyring = StaticKeyRing::new().with_key("root", b"root-secret");
        let ledger = sample_ledger("oracle");
        let ledger_store = FixedLedgerStore { records: vec![ledger.clone()], ok: true };
        let mut issuer = AuthorityInvocationProofIssuer::new(temp_root(), &mut keyring, "root", &ledger_store, || "2026-01-01T00:00:00.000Z".to_string());
        let IssueOutcome::Issued(proof) = issuer.issue(&ledger, &binding(), "completion-claim", "oracle").unwrap();

        // Re-open with a clock 10 minutes later (proof lifetime is 5 minutes).
        let mut keyring2 = StaticKeyRing::new().with_key("root", b"root-secret");
        let mut later = AuthorityInvocationProofIssuer::new(issuer_root(&issuer), &mut keyring2, "root", &ledger_store, || "2026-01-01T00:10:00.000Z".to_string());
        let d = later.verify(Some(&proof), &BTreeMap::new());
        assert_eq!(d.code, Some(ArcCode::ArcAuthForged));
        let c = later.consume(&proof, None).unwrap();
        assert_eq!(c.code, Some(ArcCode::ArcClaimPrerequisiteUnmet));
    }

    fn issuer_root<K: KeyRing, L: LedgerStore>(issuer: &AuthorityInvocationProofIssuer<'_, K, L>) -> PathBuf {
        issuer.root.clone()
    }
}
