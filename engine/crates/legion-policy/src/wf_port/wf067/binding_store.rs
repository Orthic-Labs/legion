//! Faithful port of `src/lib/contracts/arcane/authority-binding-store.mjs`.
//!
//! A binding is routing metadata, never authority: it lets a later turn
//! (which knows only `adapter`/`sessionId`/`agentId`) recover which Legion
//! authority (`legion`/`sage`/`alchemist`/`oracle`) a prior `SubagentStart`
//! or `SessionStart` observed for that identity, so `assertForTurn` can
//! mint a per-turn `AuthorityLedger` assertion from it. Creation is
//! append-only and idempotent (create-then-hardlink, matching the JS
//! `openSync('wx')` + `linkSync` + `unlinkSync` dance) so two racing
//! observers of the same identity converge on one record rather than
//! silently overwriting each other.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::authority::{AssertForTurnInput, Assertion, AuthorityLedger};
use super::canonical::{canonical_json, digest, Json};
use super::errors::{ArcCode, ArcaneError};
use super::json_parse;

fn authority_for_agent_type(agent_type: &str) -> Option<&'static str> {
    match agent_type {
        "legion" => Some("legion"),
        "sage" => Some("sage"),
        "alchemist" => Some("alchemist"),
        "oracle" => Some("oracle"),
        _ => None,
    }
}

fn dig(domain: &str, values: &[Option<&str>]) -> String {
    let arr = Json::Arr(values.iter().map(|v| v.map(Json::str).unwrap_or(Json::Null)).collect());
    let obj = Json::Obj(vec![("domain".into(), Json::str(domain)), ("values".into(), arr)]);
    digest(canonical_json(&obj).unwrap().as_bytes())
}

/// A persisted binding record. Mirrors the JS record shape written to disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRecord {
    pub schema_version: i64,
    pub kind: String,
    pub adapter: String,
    pub session_id_digest: String,
    pub agent_id_digest: String,
    pub agent_type: String,
    pub authority: String,
    pub observed_event_id: String,
    pub observed_at: String,
}

impl BindingRecord {
    fn to_json(&self) -> Json {
        Json::Obj(vec![
            ("schemaVersion".into(), Json::I64(self.schema_version)),
            ("kind".into(), Json::str(self.kind.clone())),
            ("adapter".into(), Json::str(self.adapter.clone())),
            ("sessionIdDigest".into(), Json::str(self.session_id_digest.clone())),
            ("agentIdDigest".into(), Json::str(self.agent_id_digest.clone())),
            ("agentType".into(), Json::str(self.agent_type.clone())),
            ("authority".into(), Json::str(self.authority.clone())),
            ("observedEventId".into(), Json::str(self.observed_event_id.clone())),
            ("observedAt".into(), Json::str(self.observed_at.clone())),
        ])
    }

    fn from_json(v: &Json) -> Option<Self> {
        if v.get("kind").and_then(|k| k.as_str()) != Some("arcane-authority-binding") {
            return None;
        }
        Some(Self {
            schema_version: match v.get("schemaVersion") {
                Some(Json::I64(n)) => *n,
                _ => 1,
            },
            kind: "arcane-authority-binding".to_string(),
            adapter: v.get("adapter")?.as_str()?.to_string(),
            session_id_digest: v.get("sessionIdDigest")?.as_str()?.to_string(),
            agent_id_digest: v.get("agentIdDigest")?.as_str()?.to_string(),
            agent_type: v.get("agentType")?.as_str()?.to_string(),
            authority: v.get("authority")?.as_str()?.to_string(),
            observed_event_id: v.get("observedEventId")?.as_str()?.to_string(),
            observed_at: v.get("observedAt")?.as_str()?.to_string(),
        })
    }
}

pub struct ObserveInput<'a> {
    pub adapter: &'a str,
    pub session_id: &'a str,
    pub agent_id: Option<&'a str>,
    pub agent_type: &'a str,
    pub event_id: &'a str,
    pub session_root: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObserveResult {
    pub bound: bool,
    pub created: bool,
    pub reason: Option<&'static str>,
    pub record: Option<BindingRecord>,
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
    let seed = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let mut x = seed as u64 ^ (&buf as *const _ as u64);
    for slot in buf.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *slot = (x & 0xff) as u8;
    }
    super::canonical::hex_encode(&buf)
}

pub struct AuthorityBindingStore {
    root: PathBuf,
    clock: Box<dyn Fn() -> String + Send + Sync>,
}

impl AuthorityBindingStore {
    pub fn new(root: impl Into<PathBuf>, clock: impl Fn() -> String + Send + Sync + 'static) -> Self {
        Self { root: root.into(), clock: Box::new(clock) }
    }

    /// Mirrors JS `key()`: the binding digest with the `sha256:` prefix
    /// stripped (7 bytes), used as the record's filename stem.
    pub fn key(&self, adapter: &str, session_id: &str, agent_id: Option<&str>) -> String {
        dig("arcane.authority.binding-key.v1", &[Some(adapter), Some(session_id), agent_id])[7..].to_string()
    }

    pub fn path(&self, adapter: &str, session_id: &str, agent_id: Option<&str>) -> PathBuf {
        self.root.join(format!("{}.json", self.key(adapter, session_id, agent_id)))
    }

    /// Mirrors JS `observe()`: idempotent create of a binding record.
    pub fn observe(&self, input: ObserveInput<'_>) -> Result<ObserveResult, ArcaneError> {
        if input.agent_id.is_none() {
            return Ok(ObserveResult { bound: false, created: false, reason: Some("missing-identity"), record: None });
        }
        let agent_id = input.agent_id.unwrap();
        let Some(authority) = authority_for_agent_type(input.agent_type) else {
            return Ok(ObserveResult { bound: false, created: false, reason: Some("unsupported-agent-type"), record: None });
        };
        if input.agent_type == "legion" && !input.session_root {
            return Ok(ObserveResult { bound: false, created: false, reason: Some("unsupported-agent-type"), record: None });
        }

        let key = self.key(input.adapter, input.session_id, Some(agent_id));
        let path = self.root.join(format!("{key}.json"));
        let record = BindingRecord {
            schema_version: 1,
            kind: "arcane-authority-binding".to_string(),
            adapter: input.adapter.to_string(),
            session_id_digest: dig("arcane.authority.session.v1", &[Some(input.adapter), Some(input.session_id)]),
            agent_id_digest: dig("arcane.authority.agent.v1", &[Some(input.adapter), Some(input.session_id), Some(agent_id)]),
            agent_type: input.agent_type.to_string(),
            authority: authority.to_string(),
            observed_event_id: input.event_id.to_string(),
            observed_at: (self.clock)(),
        };

        fs::create_dir_all(&self.root).map_err(|e| io_err(e, "creating binding store root"))?;
        let text = format!("{}\n", canonical_json(&record.to_json()).unwrap());
        let temp = self.root.join(format!(".create-{}-{}", std::process::id(), random_hex(6)));

        let created_result = write_new_exclusive(&temp, text.as_bytes());
        match created_result {
            Ok(()) => match fs::hard_link(&temp, &path) {
                Ok(()) => {
                    let _ = fs::remove_file(&temp);
                    Ok(ObserveResult { bound: true, created: true, reason: None, record: Some(record) })
                }
                Err(e) => {
                    let _ = fs::remove_file(&temp);
                    self.resolve_existing(input.adapter, input.session_id, agent_id, &record, e)
                }
            },
            Err(e) => {
                let _ = fs::remove_file(&temp);
                self.resolve_existing(input.adapter, input.session_id, agent_id, &record, e)
            }
        }
    }

    fn resolve_existing(
        &self,
        adapter: &str,
        session_id: &str,
        agent_id: &str,
        record: &BindingRecord,
        error: io::Error,
    ) -> Result<ObserveResult, ArcaneError> {
        // AlreadyExists / permission-denied class errors mean a racing
        // observer got there first (or the record already existed); anything
        // else propagates. `fs::hard_link` on an existing destination
        // surfaces as AlreadyExists on all supported platforms.
        if matches!(error.kind(), io::ErrorKind::AlreadyExists) || error.raw_os_error() == Some(libc_eperm()) {
            let existing = self.get(adapter, session_id, Some(agent_id))?;
            let Some(existing) = existing else {
                return Err(ArcaneError::new(ArcCode::ArcStoreCorrupt, "binding record corrupt"));
            };
            if existing.adapter != record.adapter
                || existing.session_id_digest != record.session_id_digest
                || existing.agent_id_digest != record.agent_id_digest
                || existing.agent_type != record.agent_type
                || existing.authority != record.authority
            {
                return Err(ArcaneError::new(ArcCode::ArcBindingMismatch, "binding identity conflict"));
            }
            if existing.observed_event_id != record.observed_event_id {
                return Err(ArcaneError::new(ArcCode::ArcBindingMismatch, "binding provenance is immutable"));
            }
            return Ok(ObserveResult { bound: true, created: false, reason: None, record: Some(existing) });
        }
        Err(io_err(error, "creating binding record"))
    }

    pub fn observe_legion_session(&self, adapter: &str, session_id: &str, event_id: &str) -> Result<ObserveResult, ArcaneError> {
        self.observe(ObserveInput {
            adapter,
            session_id,
            agent_id: Some("legion-session-root"),
            agent_type: "legion",
            event_id,
            session_root: true,
        })
    }

    /// Mirrors JS `rollback()`.
    pub fn rollback(
        &self,
        adapter: &str,
        session_id: &str,
        agent_id: Option<&str>,
        record: Option<&BindingRecord>,
    ) -> Result<bool, ArcaneError> {
        let path = self.path(adapter, session_id, agent_id);
        let Some(existing) = self.get(adapter, session_id, agent_id)? else {
            return Ok(false);
        };
        let mismatch = match record {
            None => true,
            Some(r) => {
                existing.adapter != r.adapter
                    || existing.session_id_digest != r.session_id_digest
                    || existing.agent_id_digest != r.agent_id_digest
                    || existing.observed_event_id != r.observed_event_id
            }
        };
        if mismatch {
            return Err(ArcaneError::new(ArcCode::ArcBindingMismatch, "binding rollback provenance conflict"));
        }
        fs::remove_file(&path).map_err(|e| io_err(e, "rolling back binding"))?;
        Ok(true)
    }

    /// Mirrors JS `get()`.
    pub fn get(&self, adapter: &str, session_id: &str, agent_id: Option<&str>) -> Result<Option<BindingRecord>, ArcaneError> {
        let path = self.path(adapter, session_id, agent_id);
        match fs::read_to_string(&path) {
            Ok(text) => {
                let value = json_parse::parse(&text).map_err(|_| ArcaneError::new(ArcCode::ArcStoreCorrupt, "binding record corrupt"))?;
                Ok(BindingRecord::from_json(&value))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(ArcaneError::new(ArcCode::ArcStoreCorrupt, "binding record corrupt")),
        }
    }

    /// Mirrors JS `recover()`: quarantine an unreadable binding. Safe on a
    /// read-only path because a binding is routing metadata, never
    /// authority — this removes a bad lookup but cannot mint an authority
    /// assertion or widen a later mutation.
    pub fn recover(&self, adapter: &str, session_id: &str, agent_id: Option<&str>) -> bool {
        let path = self.path(adapter, session_id, agent_id);
        if !path.exists() {
            return false;
        }
        let dest = self.root.join(format!(
            "{}.corrupt-{}",
            path.file_name().and_then(|s| s.to_str()).unwrap_or("binding"),
            random_hex(6)
        ));
        fs::rename(&path, &dest).is_ok()
    }

    /// Mirrors JS `findLatest()`: scan by session digest since the raw
    /// agentId is never stored, only its digest.
    pub fn find_latest(&self, adapter: &str, session_id: &str, authority: Option<&str>) -> Result<Option<BindingRecord>, ArcaneError> {
        let want = dig("arcane.authority.session.v1", &[Some(adapter), Some(session_id)]);
        let entries = match fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err(e, "scanning binding store")),
        };
        let mut best: Option<BindingRecord> = None;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&path) else { continue };
            let Ok(value) = json_parse::parse(&text) else { continue };
            let Some(record) = BindingRecord::from_json(&value) else { continue };
            if record.adapter != adapter || record.session_id_digest != want {
                continue;
            }
            if let Some(a) = authority {
                if record.authority != a {
                    continue;
                }
            }
            let better = match &best {
                None => true,
                Some(b) => record.observed_at.as_str() > b.observed_at.as_str(),
            };
            if better {
                best = Some(record);
            }
        }
        Ok(best)
    }

    /// Mirrors JS `assertForTurn()`.
    #[allow(clippy::too_many_arguments)]
    pub fn assert_for_turn(
        &self,
        adapter: &str,
        session_id: &str,
        agent_id: Option<&str>,
        turn_id: &str,
        ledger: &mut AuthorityLedger,
        key_id: Option<&str>,
        authority: Option<&str>,
        record: Option<&BindingRecord>,
    ) -> Result<Assertion, ArcaneError> {
        if authority.is_some() {
            return Err(ArcaneError::new(ArcCode::ArcAuthorityModelClaimed, "caller authority forbidden"));
        }
        let Some(key_id) = key_id else {
            return Err(ArcaneError::new(ArcCode::ArcAuthKeyUnavailable, "key required"));
        };
        if let Some(r) = record {
            let expected_session_digest = dig("arcane.authority.session.v1", &[Some(adapter), Some(session_id)]);
            if r.adapter != adapter || r.session_id_digest != expected_session_digest {
                return Err(ArcaneError::new(ArcCode::ArcBindingMismatch, "binding identity conflict"));
            }
        }
        let resolved = match record {
            Some(r) => Some(r.clone()),
            None => self.get(adapter, session_id, agent_id)?,
        };
        let Some(rec) = resolved else {
            return Err(ArcaneError::new(ArcCode::ArcAuthorityNotAsserted, "binding missing"));
        };
        ledger.assert_for_turn(AssertForTurnInput {
            turn_id,
            authority: &rec.authority,
            asserted_by: &format!("{adapter}:{}", rec.agent_id_digest),
            verification_method: "capability-signature",
            per_message: true,
            source: "host",
        })
        .and_then(|a| {
            let _ = key_id; // key presence already validated above, matching JS (keyId is threaded to the caller's signer, not used by the ledger itself)
            Ok(a)
        })
    }
}

fn write_new_exclusive(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let mut f = fs::OpenOptions::new().write(true).create_new(true).open(path)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        Ok(())
    }
}

#[cfg(unix)]
fn libc_eperm() -> i32 {
    1 // EPERM, matching the JS check for error.code === 'EPERM' (hard-linking across devices, etc).
}
#[cfg(not(unix))]
fn libc_eperm() -> i32 {
    -1
}

fn io_err(e: io::Error, context: &str) -> ArcaneError {
    ArcaneError::new(ArcCode::ArcStoreCorrupt, format!("{context}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("wf067-binding-store-{}-{n}", std::process::id()));
        dir
    }

    fn store() -> AuthorityBindingStore {
        AuthorityBindingStore::new(temp_root(), || "2026-01-01T00:00:00.000Z".to_string())
    }

    #[test]
    fn observe_missing_agent_id_is_unbound() {
        let s = store();
        let r = s
            .observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: None, agent_type: "alchemist", event_id: "e1", session_root: false })
            .unwrap();
        assert!(!r.bound);
        assert_eq!(r.reason, Some("missing-identity"));
    }

    #[test]
    fn observe_unsupported_agent_type_is_unbound() {
        let s = store();
        let r = s
            .observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "operator", event_id: "e1", session_root: false })
            .unwrap();
        assert!(!r.bound);
        assert_eq!(r.reason, Some("unsupported-agent-type"));
    }

    #[test]
    fn observe_legion_requires_session_root() {
        let s = store();
        let r = s
            .observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "legion", event_id: "e1", session_root: false })
            .unwrap();
        assert!(!r.bound);
        assert_eq!(r.reason, Some("unsupported-agent-type"));
    }

    #[test]
    fn observe_creates_then_is_idempotent_on_replay() {
        let s = store();
        let first = s
            .observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "alchemist", event_id: "e1", session_root: false })
            .unwrap();
        assert!(first.bound && first.created);

        let second = s
            .observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "alchemist", event_id: "e1", session_root: false })
            .unwrap();
        assert!(second.bound && !second.created);
        assert_eq!(second.record.unwrap().observed_event_id, "e1");
    }

    #[test]
    fn observe_conflicting_event_id_is_binding_mismatch() {
        let s = store();
        s.observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "alchemist", event_id: "e1", session_root: false }).unwrap();
        let err = s
            .observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "alchemist", event_id: "e2", session_root: false })
            .unwrap_err();
        assert_eq!(err.code, ArcCode::ArcBindingMismatch);
    }

    #[test]
    fn observe_conflicting_identity_is_binding_mismatch() {
        let s = store();
        s.observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "alchemist", event_id: "e1", session_root: false }).unwrap();
        let err = s
            .observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "oracle", event_id: "e1", session_root: false })
            .unwrap_err();
        assert_eq!(err.code, ArcCode::ArcBindingMismatch);
    }

    #[test]
    fn get_returns_none_for_missing_record() {
        let s = store();
        assert_eq!(s.get("claude-code", "s1", Some("a1")).unwrap(), None);
    }

    #[test]
    fn rollback_removes_matching_record_and_rejects_mismatch() {
        let s = store();
        let r = s
            .observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "alchemist", event_id: "e1", session_root: false })
            .unwrap();
        let record = r.record.unwrap();
        let err = s.rollback("claude-code", "s1", Some("a1"), None).unwrap_err();
        assert_eq!(err.code, ArcCode::ArcBindingMismatch);
        assert!(s.rollback("claude-code", "s1", Some("a1"), Some(&record)).unwrap());
        assert_eq!(s.get("claude-code", "s1", Some("a1")).unwrap(), None);
    }

    #[test]
    fn rollback_missing_record_returns_false() {
        let s = store();
        assert!(!s.rollback("claude-code", "s1", Some("a1"), None).unwrap());
    }

    #[test]
    fn find_latest_scans_by_session_digest_and_filters_by_authority() {
        let s = store();
        s.observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "alchemist", event_id: "e1", session_root: false }).unwrap();
        s.observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a2"), agent_type: "oracle", event_id: "e2", session_root: false }).unwrap();

        let alchemist = s.find_latest("claude-code", "s1", Some("alchemist")).unwrap().unwrap();
        assert_eq!(alchemist.authority, "alchemist");

        let any = s.find_latest("claude-code", "s1", None).unwrap();
        assert!(any.is_some());

        let other_session = s.find_latest("claude-code", "s-none", None).unwrap();
        assert!(other_session.is_none());
    }

    #[test]
    fn observe_legion_session_binds_session_root() {
        let s = store();
        let r = s.observe_legion_session("claude-code", "s1", "e1").unwrap();
        assert!(r.bound);
        assert_eq!(r.record.unwrap().authority, "legion");
    }

    #[test]
    fn assert_for_turn_rejects_caller_supplied_authority() {
        let s = store();
        let mut ledger = AuthorityLedger::new(|| 0);
        let err = s
            .assert_for_turn("claude-code", "s1", Some("a1"), "t1", &mut ledger, Some("k1"), Some("alchemist"), None)
            .unwrap_err();
        assert_eq!(err.code, ArcCode::ArcAuthorityModelClaimed);
    }

    #[test]
    fn assert_for_turn_requires_key_id() {
        let s = store();
        let mut ledger = AuthorityLedger::new(|| 0);
        let err = s.assert_for_turn("claude-code", "s1", Some("a1"), "t1", &mut ledger, None, None, None).unwrap_err();
        assert_eq!(err.code, ArcCode::ArcAuthKeyUnavailable);
    }

    #[test]
    fn assert_for_turn_errors_when_binding_missing() {
        let s = store();
        let mut ledger = AuthorityLedger::new(|| 0);
        let err = s.assert_for_turn("claude-code", "s1", Some("a1"), "t1", &mut ledger, Some("k1"), None, None).unwrap_err();
        assert_eq!(err.code, ArcCode::ArcAuthorityNotAsserted);
    }

    #[test]
    fn assert_for_turn_asserts_ledger_from_stored_binding() {
        let s = store();
        s.observe(ObserveInput { adapter: "claude-code", session_id: "s1", agent_id: Some("a1"), agent_type: "alchemist", event_id: "e1", session_root: false }).unwrap();
        let mut ledger = AuthorityLedger::new(|| 0);
        let assertion = s.assert_for_turn("claude-code", "s1", Some("a1"), "t1", &mut ledger, Some("k1"), None, None).unwrap();
        assert_eq!(assertion.authority, "alchemist");
        assert_eq!(ledger.current("t1").unwrap().authority, "alchemist");
    }
}
