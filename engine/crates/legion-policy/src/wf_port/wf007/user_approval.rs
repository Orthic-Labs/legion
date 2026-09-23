//! Port of `src/lib/guard/compat/effects/user-approval.mjs`.
//!
//! Host-held, transcript-derived approval authority: no model payload can
//! mint one. A record is bound (via HMAC) to a fixed field list
//! ([`BOUND_FIELDS`]) and is only ever accepted by [`UserApprovalAuthority::consume`]
//! when every bound field matches what the caller independently computes
//! from `expected`, the record's MAC verifies against a host-held key, and
//! the record has not already been consumed (in-process replay guard keyed
//! by `keyId:mac`).
//!
//! Differences from the JS source, both forced by this crate's dependency
//! graph (see the wf007 report's "shared-file patches" section for the
//! proposed amendments):
//!   - Key custody: JS reads a `KeyRing` from `guard/compat/host/keys.mjs`.
//!     `legion-arcane::key_ring::KeyRing` already exists and is
//!     ALREADY-NATIVE-VERIFIED for that file, but it lives in a sibling
//!     crate (`legion-arcane`) this chunk does not depend on and may not add
//!     as a dependency. [`KeyLookup`] is a minimal trait standing in for it;
//!     wiring an adapter over `legion_arcane::KeyRing` is a follow-up for
//!     whoever owns that `Cargo.toml` edit.
//!   - `classifyLatestUserIntent`/`latestExternalUserTurn` are ported in
//!     `super::user_intent` (wf002 declined them for lack of `regex`, which
//!     this crate has).
//!   - Transcript reading takes an already-loaded `&str` rather than a
//!     filesystem path, since file I/O is a policy question for the host
//!     adapter, not this pure-logic port.

use std::collections::BTreeSet;

use super::canon::{constant_time_equal, digest_value_domain, hmac_sha256_hex};
use super::user_intent::{classify_latest_user_intent, Intent};

/// TTL for a derived approval record. Mirrors JS `TTL_SECONDS`.
pub const TTL_SECONDS: i64 = 900;

/// Fields bound into the HMAC over an approval record. Order and membership
/// match JS `BOUND_FIELDS` exactly.
pub const BOUND_FIELDS: &[&str] = &[
    "schemaVersion",
    "kind",
    "keyId",
    "sessionDigest",
    "runId",
    "taskId",
    "contractId",
    "contractVersion",
    "contractDigest",
    "effectClass",
    "targetDigest",
    "userTurnDigest",
    "issuedAt",
    "expiresAt",
];

/// Key material lookup. Stands in for `legion-arcane::KeyRing` (see module
/// doc): `get` returns the raw key bytes for a `keyId`, `Err` on
/// unknown/revoked (mirrors `ARC_AUTH_KEY_UNAVAILABLE`); `active_key_id`
/// returns the newest non-revoked key id.
pub trait KeyLookup {
    fn get(&self, key_id: &str) -> Result<Vec<u8>, ()>;
    fn active_key_id(&self) -> Option<String>;
}

/// An approval record, field-for-field with the JS `record` shape. Numeric
/// `contractVersion` is `i64` (JS validates it as `Number.isInteger(...) &&
/// >= 1`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecord {
    pub schema_version: i64,
    pub kind: String,
    pub key_id: String,
    pub session_digest: String,
    pub run_id: String,
    pub task_id: String,
    pub contract_id: String,
    pub contract_version: i64,
    pub contract_digest: String,
    pub effect_class: String,
    pub target_digest: String,
    pub user_turn_digest: String,
    pub issued_at: String,
    pub expires_at: String,
    pub mac: String,
}

/// The binding a caller expects an approval record to satisfy, i.e. the JS
/// `expected` argument to `consume(record, expected)` / `derive(...)`.
#[derive(Debug, Clone)]
pub struct ExpectedBinding<'a> {
    pub transcript_text: Option<&'a str>,
    pub session_id: &'a str,
    pub run_id: &'a str,
    pub task_id: &'a str,
    pub contract_id: &'a str,
    pub contract_version: i64,
    pub contract_digest: &'a str,
    pub effect_class: &'a str,
    pub target: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalDenial {
    pub code: &'static str,
    pub message: String,
}

impl ApprovalDenial {
    fn new(code: &'static str, message: &str) -> Self {
        Self { code, message: message.to_string() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalGrant {
    pub approval_digest: String,
    pub record: ApprovalRecord,
}

fn digest_session(session_id: &str) -> String {
    digest_value_domain("arcane.user-approval.session.v1", &[Some(session_id)])
}
fn digest_target(target: &str) -> String {
    digest_value_domain("arcane.user-approval.target.v1", &[Some(target)])
}
fn digest_turn(turn: &str) -> String {
    digest_value_domain("arcane.user-approval.turn.v1", &[Some(turn)])
}

/// Canonical JSON (per `super::canon`) over exactly `BOUND_FIELDS`, in that
/// order — mirrors `macFor` building the MAC input from
/// `canonicalJson(Object.fromEntries(BOUND_FIELDS.map(...)))`.
fn mac_input(record: &ApprovalRecord) -> super::canon::Json {
    use super::canon::Json;
    Json::Obj(vec![
        ("schemaVersion", Json::I64(record.schema_version)),
        ("kind", Json::str(record.kind.clone())),
        ("keyId", Json::str(record.key_id.clone())),
        ("sessionDigest", Json::str(record.session_digest.clone())),
        ("runId", Json::str(record.run_id.clone())),
        ("taskId", Json::str(record.task_id.clone())),
        ("contractId", Json::str(record.contract_id.clone())),
        ("contractVersion", Json::I64(record.contract_version)),
        ("contractDigest", Json::str(record.contract_digest.clone())),
        ("effectClass", Json::str(record.effect_class.clone())),
        ("targetDigest", Json::str(record.target_digest.clone())),
        ("userTurnDigest", Json::str(record.user_turn_digest.clone())),
        ("issuedAt", Json::str(record.issued_at.clone())),
        ("expiresAt", Json::str(record.expires_at.clone())),
    ])
}

fn mac_for(record: &ApprovalRecord, key: &[u8]) -> String {
    let input = super::canon::canonical_json(&mac_input(record));
    hmac_sha256_hex(key, input.as_bytes())
}

/// `contractVersion` in JS's `digestValue({..., values: [...]})` is a raw
/// number, not a string, so a helper over `Option<&str>` values can't
/// represent it faithfully; this builds the exact array (`[keyId,
/// sessionDigest, runId, taskId, contractId, contractVersion,
/// contractDigest, effectClass, targetDigest, userTurnDigest, issuedAt,
/// expiresAt, mac]`) with `contractVersion` as `Json::I64`, matching
/// `approvalDigestFor` in the JS source exactly.
fn approval_digest_for(record: &ApprovalRecord) -> String {
    use super::canon::{digest_value, Json};
    digest_value(&Json::Obj(vec![
        ("domain", Json::str("arcane.user-approval.digest.v1")),
        (
            "values",
            Json::Arr(vec![
                Json::str(record.key_id.clone()),
                Json::str(record.session_digest.clone()),
                Json::str(record.run_id.clone()),
                Json::str(record.task_id.clone()),
                Json::str(record.contract_id.clone()),
                Json::I64(record.contract_version),
                Json::str(record.contract_digest.clone()),
                Json::str(record.effect_class.clone()),
                Json::str(record.target_digest.clone()),
                Json::str(record.user_turn_digest.clone()),
                Json::str(record.issued_at.clone()),
                Json::str(record.expires_at.clone()),
                Json::str(record.mac.clone()),
            ]),
        ),
    ]))
}

fn approval_denial(code: &'static str, message: &str) -> ApprovalDenial {
    ApprovalDenial::new(code, message)
}

pub struct UserApprovalAuthority<K: KeyLookup> {
    key_ring: Option<K>,
    approval_required: BTreeSet<String>,
    used: std::cell::RefCell<BTreeSet<String>>,
}

impl<K: KeyLookup> UserApprovalAuthority<K> {
    pub fn new(key_ring: Option<K>, approval_required_effect_classes: impl IntoIterator<Item = String>) -> Self {
        Self {
            key_ring,
            approval_required: approval_required_effect_classes.into_iter().collect(),
            used: std::cell::RefCell::new(BTreeSet::new()),
        }
    }

    fn requires_approval(&self, effect_class: &str) -> bool {
        self.approval_required.contains(effect_class)
    }

    fn latest_approved_turn(&self, transcript_text: Option<&str>) -> Option<String> {
        let text = transcript_text?;
        if text.is_empty() {
            return None;
        }
        let intent = classify_latest_user_intent(text);
        let turn = super::user_intent::latest_external_user_turn(text)?;
        match intent.intent {
            Intent::Execute | Intent::Continue => Some(turn),
            _ => None,
        }
    }

    /// Mirrors JS `deriveRecord`: `None` whenever the JS source would
    /// `return null` (approval not required, binding incomplete/invalid, no
    /// approved turn, or key ring unavailable).
    pub fn derive_record(
        &self,
        expected: &ExpectedBinding<'_>,
        now_ms: i64,
    ) -> Option<ApprovalRecord> {
        if !self.requires_approval(expected.effect_class) {
            return None;
        }
        if expected.session_id.is_empty()
            || expected.run_id.is_empty()
            || expected.task_id.is_empty()
            || expected.contract_id.is_empty()
            || expected.contract_digest.is_empty()
            || expected.target.is_empty()
            || expected.contract_version < 1
        {
            return None;
        }
        let turn = self.latest_approved_turn(expected.transcript_text)?;

        let issued_at = iso8601_from_epoch_ms(now_ms);
        let expires_at = iso8601_from_epoch_ms(now_ms + TTL_SECONDS * 1000);
        let key_ring = self.key_ring.as_ref()?;
        let key_id = key_ring.active_key_id()?;
        let key = key_ring.get(&key_id).ok()?;

        let mut record = ApprovalRecord {
            schema_version: 1,
            kind: "arcane-user-approval".to_string(),
            key_id,
            session_digest: digest_session(expected.session_id),
            run_id: expected.run_id.to_string(),
            task_id: expected.task_id.to_string(),
            contract_id: expected.contract_id.to_string(),
            contract_version: expected.contract_version,
            contract_digest: expected.contract_digest.to_string(),
            effect_class: expected.effect_class.to_string(),
            target_digest: digest_target(expected.target),
            user_turn_digest: digest_turn(&turn),
            issued_at,
            expires_at,
            mac: String::new(),
        };
        record.mac = mac_for(&record, &key);
        Some(record)
    }

    /// Mirrors JS `consume(record, expected)`.
    pub fn consume(&self, record: Option<&ApprovalRecord>, expected: &ExpectedBinding<'_>, now_ms: i64) -> Result<ApprovalGrant, ApprovalDenial> {
        let record = record.ok_or_else(|| approval_denial("ARC_APPROVAL_REQUIRED", "required user approval is missing"))?;

        if expected.session_id.is_empty()
            || expected.run_id.is_empty()
            || expected.task_id.is_empty()
            || expected.contract_id.is_empty()
            || expected.contract_digest.is_empty()
            || expected.target.is_empty()
            || expected.contract_version < 1
            || !self.requires_approval(expected.effect_class)
        {
            return Err(approval_denial("ARC_APPROVAL_REQUIRED", "required user approval binding is invalid"));
        }

        let turn = self
            .latest_approved_turn(expected.transcript_text)
            .ok_or_else(|| approval_denial("ARC_APPROVAL_REQUIRED", "latest external user turn does not approve this effect"))?;

        let issued = parse_iso8601_to_epoch_ms(&record.issued_at);
        let expires = parse_iso8601_to_epoch_ms(&record.expires_at);
        let (issued, expires) = match (issued, expires) {
            (Some(i), Some(e)) => (i, e),
            _ => return Err(approval_denial("ARC_APPROVAL_REQUIRED", "required user approval is expired or unreadable")),
        };
        if expires - issued > TTL_SECONDS * 1000 || expires <= issued || now_ms < issued || now_ms >= expires {
            return Err(approval_denial("ARC_APPROVAL_REQUIRED", "required user approval is expired or unreadable"));
        }

        let bound_session_digest = digest_session(expected.session_id);
        let bound_target_digest = digest_target(expected.target);
        let bound_turn_digest = digest_turn(&turn);
        if record.session_digest != bound_session_digest
            || record.run_id != expected.run_id
            || record.task_id != expected.task_id
            || record.contract_id != expected.contract_id
            || record.contract_version != expected.contract_version
            || record.contract_digest != expected.contract_digest
            || record.effect_class != expected.effect_class
            || record.target_digest != bound_target_digest
            || record.user_turn_digest != bound_turn_digest
        {
            return Err(approval_denial("ARC_BINDING_MISMATCH", "user approval binding differs"));
        }

        let key_ring = self
            .key_ring
            .as_ref()
            .ok_or_else(|| approval_denial("ARC_AUTH_KEY_UNAVAILABLE", "approval key unavailable"))?;
        let key = key_ring
            .get(&record.key_id)
            .map_err(|_| approval_denial("ARC_AUTH_KEY_UNAVAILABLE", "approval key unavailable"))?;

        let expected_mac = mac_for(record, &key);
        if !constant_time_equal(expected_mac.as_bytes(), record.mac.as_bytes()) {
            return Err(approval_denial("ARC_AUTH_FORGED", "user approval authentication failed"));
        }

        let replay_key = format!("{}:{}", record.key_id, record.mac);
        if self.used.borrow().contains(&replay_key) {
            return Err(approval_denial("ARC_REPLAY_NONCE_SEEN", "user approval was already consumed"));
        }
        self.used.borrow_mut().insert(replay_key);

        Ok(ApprovalGrant { approval_digest: approval_digest_for(record), record: record.clone() })
    }

    /// Mirrors JS `derive(effectRequest, ctx)`: derives a fresh record from
    /// the transcript and immediately consumes it. `None` in the returned
    /// tuple's grant.record mirrors JS `evidence: null` when approval is not
    /// required for this effect class at all.
    pub fn derive(&self, expected: &ExpectedBinding<'_>, now_ms: i64) -> Result<Option<ApprovalGrant>, ApprovalDenial> {
        if !self.requires_approval(expected.effect_class) {
            return Ok(None);
        }
        let record = self.derive_record(expected, now_ms);
        self.consume(record.as_ref(), expected, now_ms).map(Some)
    }
}

// --- minimal ISO 8601 <-> epoch-ms round-trip (UTC only, millisecond
// precision) sufficient for the timestamps this module itself mints and
// reads back. Not a general date library. ---------------------------------

pub(super) fn iso8601_from_epoch_ms(ms: i64) -> String {
    let (days, rem_ms) = {
        let total_seconds = ms.div_euclid(1000);
        let millis = ms.rem_euclid(1000);
        (total_seconds.div_euclid(86_400), (total_seconds.rem_euclid(86_400), millis))
    };
    let (secs_of_day, millis) = rem_ms;
    let (y, m, d) = civil_from_days(days);
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
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

fn parse_iso8601_to_epoch_ms(input: &str) -> Option<i64> {
    // Reuses the RFC 3339 parser in `replay.rs` (crate-visible) to avoid a
    // second hand-rolled date parser in this chunk.
    super::replay::parse_rfc3339_ms(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct TestKeyRing {
        keys: BTreeMap<String, Vec<u8>>,
        active: Option<String>,
    }
    impl KeyLookup for TestKeyRing {
        fn get(&self, key_id: &str) -> Result<Vec<u8>, ()> {
            self.keys.get(key_id).cloned().ok_or(())
        }
        fn active_key_id(&self) -> Option<String> {
            self.active.clone()
        }
    }

    fn ring() -> TestKeyRing {
        let mut keys = BTreeMap::new();
        keys.insert("k1".to_string(), vec![7u8; 32]);
        TestKeyRing { keys, active: Some("k1".to_string()) }
    }

    fn user_execute_transcript() -> String {
        r#"{"type":"user","message":{"content":[{"type":"text","text":"please fix the login flow"}]}}"#.to_string()
    }

    fn expected<'a>(transcript: &'a str) -> ExpectedBinding<'a> {
        ExpectedBinding {
            transcript_text: Some(transcript),
            session_id: "sess-1",
            run_id: "run-1",
            task_id: "task-1",
            contract_id: "contract-1",
            contract_version: 1,
            contract_digest: "sha256:aaaa",
            effect_class: "FILE_DELETE",
            target: "/tmp/x",
        }
    }

    #[test]
    fn derive_and_consume_round_trip_succeeds() {
        let authority = UserApprovalAuthority::new(Some(ring()), vec!["FILE_DELETE".to_string()]);
        let transcript = user_execute_transcript();
        let exp = expected(&transcript);
        let now = 1_767_225_600_000;
        let record = authority.derive_record(&exp, now).expect("record derived");
        let grant = authority.consume(Some(&record), &exp, now).expect("consumed");
        assert!(!grant.approval_digest.is_empty());
    }

    #[test]
    fn consume_rejects_replay_of_same_record() {
        let authority = UserApprovalAuthority::new(Some(ring()), vec!["FILE_DELETE".to_string()]);
        let transcript = user_execute_transcript();
        let exp = expected(&transcript);
        let now = 1_767_225_600_000;
        let record = authority.derive_record(&exp, now).unwrap();
        authority.consume(Some(&record), &exp, now).unwrap();
        let second = authority.consume(Some(&record), &exp, now).unwrap_err();
        assert_eq!(second.code, "ARC_REPLAY_NONCE_SEEN");
    }

    #[test]
    fn consume_rejects_missing_record() {
        let authority = UserApprovalAuthority::new(Some(ring()), vec!["FILE_DELETE".to_string()]);
        let transcript = user_execute_transcript();
        let exp = expected(&transcript);
        let denial = authority.consume(None, &exp, 0).unwrap_err();
        assert_eq!(denial.code, "ARC_APPROVAL_REQUIRED");
    }

    #[test]
    fn consume_rejects_tampered_mac() {
        let authority = UserApprovalAuthority::new(Some(ring()), vec!["FILE_DELETE".to_string()]);
        let transcript = user_execute_transcript();
        let exp = expected(&transcript);
        let now = 1_767_225_600_000;
        let mut record = authority.derive_record(&exp, now).unwrap();
        record.mac = "0".repeat(64);
        let denial = authority.consume(Some(&record), &exp, now).unwrap_err();
        assert_eq!(denial.code, "ARC_AUTH_FORGED");
    }

    #[test]
    fn consume_rejects_binding_mismatch() {
        let authority = UserApprovalAuthority::new(Some(ring()), vec!["FILE_DELETE".to_string()]);
        let transcript = user_execute_transcript();
        let exp = expected(&transcript);
        let now = 1_767_225_600_000;
        let record = authority.derive_record(&exp, now).unwrap();
        let mut exp2 = expected(&transcript);
        exp2.target = "/tmp/other";
        let denial = authority.consume(Some(&record), &exp2, now).unwrap_err();
        assert_eq!(denial.code, "ARC_BINDING_MISMATCH");
    }

    #[test]
    fn derive_record_none_when_effect_class_not_approval_required() {
        let authority = UserApprovalAuthority::new(Some(ring()), Vec::<String>::new());
        let transcript = user_execute_transcript();
        let exp = expected(&transcript);
        assert!(authority.derive_record(&exp, 0).is_none());
    }

    #[test]
    fn derive_record_none_without_approving_turn() {
        let authority = UserApprovalAuthority::new(Some(ring()), vec!["FILE_DELETE".to_string()]);
        let transcript = r#"{"type":"user","message":{"content":[{"type":"text","text":"what does this function do?"}]}}"#;
        let exp = expected(transcript);
        assert!(authority.derive_record(&exp, 0).is_none());
    }

    #[test]
    fn iso8601_round_trips_through_epoch_ms() {
        let ms = 1_767_225_600_123;
        let s = iso8601_from_epoch_ms(ms);
        assert_eq!(s, "2026-01-01T00:00:00.123Z");
        assert_eq!(parse_iso8601_to_epoch_ms(&s), Some(ms));
    }
}
