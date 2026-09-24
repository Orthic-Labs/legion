use crate::{
    receipt_auth::{sign_record, verify_record},
    KeyRing,
};
use hmac::{Hmac, KeyInit, Mac};
use legion_contracts::canonical_digest;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const PROOF_FIELDS: [&str; 20] = [
    "schemaVersion",
    "kind",
    "invocationId",
    "eventDigest",
    "eventSequence",
    "purpose",
    "role",
    "sessionId",
    "runId",
    "taskId",
    "contractId",
    "contractVersion",
    "contractDigest",
    "sourceRevision",
    "turnCorrelationDigest",
    "stopOrdinal",
    "domain",
    "issuedAt",
    "expiresAt",
    "nonce",
];
/// 300000ms (5 minutes), in nanoseconds, matching JS's
/// `Date.parse(issuedAt) + 300000`.
const EXPIRY_WINDOW_NS: u128 = 300_000_000_000;

/// Host seam for `ledgerStore.verify()`/`ledgerStore.records()`, the one
/// collaborator `verify(proof, {expected})` needs that this crate has no
/// existing type for (`src/lib/host/arcane/host-event-ledger.mjs`'s
/// `HOST_EVENT_LEDGER_FIELDS`-bound ledger store is out of this packet).
/// Modeled as a trait per the port rules so [`AuthorityInvocationProofIssuer::verify`]
/// is fully testable with a fake.
pub trait LedgerStore {
    /// Mirrors `ledgerStore.verify().allowed`.
    fn verify(&self) -> bool;
    /// Mirrors `ledgerStore.records()`.
    fn records(&self) -> Vec<Value>;
}

pub struct AuthorityInvocationProofIssuer {
    root: PathBuf,
    key_ring: KeyRing,
    key_id: String,
}
impl AuthorityInvocationProofIssuer {
    pub fn new(root: PathBuf, key_ring: KeyRing, key_id: String) -> Self {
        Self {
            root,
            key_ring,
            key_id,
        }
    }
    fn proof_path(&self, id: &str) -> PathBuf {
        self.root
            .join("proofs")
            .join(format!("{}.json", id.trim_start_matches("sha256:")))
    }
    fn transition_path(&self, id: &str) -> PathBuf {
        self.root.join("transitions").join(format!(
            "{}-consumed.json",
            id.trim_start_matches("sha256:")
        ))
    }
    pub fn issue(
        &self,
        event: &Value,
        binding: &Value,
        purpose: &str,
        role: &str,
    ) -> Result<Value, String> {
        if !matches!(purpose, "completion-claim" | "budget-amendment")
            || !matches!(role, "legion" | "alchemist" | "sage" | "oracle")
            || (role == "oracle" && purpose != "completion-claim")
            || event["observedAuthority"] != role
        {
            return Err("ARC_AUTHORITY_NOT_ASSERTED".into());
        }
        let key_id = format!("{}:authority-proof:{}:{}", self.key_id, role, purpose);
        let domain = format!("arcane-authority-proof:v1:{}:{}", role, purpose);
        if !self.key_ring.has(&key_id) {
            let root = self
                .key_ring
                .get(&self.key_id)
                .map_err(|e| e.code().to_owned())?;
            let mut mac = Hmac::<Sha256>::new_from_slice(&root.key)
                .map_err(|_| "ARC_AUTH_FORGED".to_owned())?;
            mac.update(format!("arcane-key-derivation:v1\0{}", domain).as_bytes());
            self.key_ring
                .add(
                    key_id.clone(),
                    mac.finalize().into_bytes().to_vec(),
                    "",
                    "derived",
                    "active",
                )
                .map_err(|e| e.code().to_owned())?;
        }
        let event_digest =
            canonical_digest(event).map_err(|_| "ARC_CANONICALIZATION_FAILED".to_owned())?;
        let binding_key = json!({"sessionId":event["sessionId"],"runId":binding["runId"],"taskId":binding["taskId"],"contractId":binding["contractId"],"contractVersion":binding["contractVersion"],"contractDigest":binding["contractDigest"]});
        let invocation_id=canonical_digest(&json!({"eventDigest":event_digest,"purpose":purpose,"role":role,"binding":binding_key})).map_err(|_|"ARC_CANONICALIZATION_FAILED".to_owned())?;
        let path = self.proof_path(&invocation_id);
        if path.exists() {
            return serde_json::from_slice(
                &fs::read(path).map_err(|_| "ARC_STORE_CORRUPT".to_owned())?,
            )
            .map_err(|_| "ARC_STORE_CORRUPT".into());
        }
        fs::create_dir_all(path.parent().unwrap()).map_err(|_| "ARC_STORE_CORRUPT")?;
        fs::create_dir_all(self.root.join("transitions")).map_err(|_| "ARC_STORE_CORRUPT")?;
        // Mirrors `issuedAt = clock()` and `expiresAt = new
        // Date(Date.parse(issuedAt) + 300000).toISOString()` — a fixed
        // 5-minute (300000ms) validity window from the same instant.
        // `timestamp()`/`now()` in this port represent an instant as
        // nanoseconds-since-epoch rather than JS's ISO-8601 string; both
        // `issuedAt`/`expiresAt` are computed from one `issued_ns` read so
        // they never drift apart from two separate clock reads.
        let issued_ns = timestamp();
        let issued_at = issued_ns.to_string();
        let expires_at = (issued_ns + EXPIRY_WINDOW_NS).to_string();
        let mut unsigned = json!({"schemaVersion":1,"kind":"arcane-authority-invocation-proof","invocationId":invocation_id,"eventDigest":event_digest,"eventSequence":event["eventSequence"],"purpose":purpose,"role":role,"sessionId":event["sessionId"],"runId":binding["runId"],"taskId":binding["taskId"],"contractId":binding["contractId"],"contractVersion":binding["contractVersion"],"contractDigest":binding["contractDigest"],"sourceRevision":event["sourceRevision"],"turnCorrelationDigest":event["turnCorrelationDigest"],"stopOrdinal":event["stopOrdinal"],"domain":format!("arcane-authority-proof:{}:{}",role,purpose),"issuedAt":issued_at,"expiresAt":expires_at,"nonce":format!("{}-{}",std::process::id(),timestamp())});
        let auth = sign_record(
            &unsigned,
            &self.key_ring,
            &key_id,
            &PROOF_FIELDS,
            Some(&domain),
        )
        .map_err(|e| e.code().to_owned())?;
        unsigned["authentication"] = auth;
        fs::write(
            &path,
            serde_json::to_vec(&unsigned).map_err(|_| "ARC_STORE_CORRUPT")?,
        )
        .map_err(|_| "ARC_STORE_CORRUPT")?;
        Ok(unsigned)
    }
    pub fn consume(&self, proof: &Value, artifact_digest: Option<&str>) -> Result<Value, String> {
        let role = proof["role"].as_str().ok_or("ARC_AUTH_FORGED")?;
        let purpose = proof["purpose"].as_str().ok_or("ARC_AUTH_FORGED")?;
        let domain = format!("arcane-authority-proof:v1:{}:{}", role, purpose);
        let decision = verify_record(
            proof,
            proof.get("authentication"),
            &self.key_ring,
            &PROOF_FIELDS,
            &Map::new(),
            Some(&domain),
        )
        .map_err(|e| e.code().to_owned())?;
        if !decision.allowed {
            return Err(decision.code.unwrap_or("ARC_AUTH_FORGED").to_owned());
        };
        let id = proof["invocationId"].as_str().ok_or("ARC_AUTH_FORGED")?;
        let path = self.transition_path(id);
        let digest = artifact_digest.unwrap_or("");
        if path.exists() {
            let old: Value =
                serde_json::from_slice(&fs::read(&path).map_err(|_| "ARC_STORE_CORRUPT")?)
                    .map_err(|_| "ARC_STORE_CORRUPT")?;
            if old["artifactDigest"].as_str() == Some(digest) {
                return Ok(json!({"allowed":true,"idempotent":true}));
            }
            return Err("ARC_REPLAY_NONCE_SEEN".into());
        };
        fs::create_dir_all(path.parent().unwrap()).map_err(|_| "ARC_STORE_CORRUPT")?;
        fs::write(path,serde_json::to_vec(&json!({"state":"CONSUMED","proofDigest":canonical_digest(proof).unwrap_or_default(),"artifactDigest":digest,"at":now()})).map_err(|_|"ARC_STORE_CORRUPT")?).map_err(|_|"ARC_STORE_CORRUPT")?;
        Ok(json!({"allowed":true}))
    }

    /// Mirrors `findByDigest(proofDigest)`: linear-scans every stored proof
    /// file and returns the first whose digest matches, or `null` on any
    /// read/parse failure (mirrors the JS `try { ... } catch { return
    /// null; }`).
    pub fn find_by_digest(&self, proof_digest: &str) -> Option<Value> {
        let dir = self.root.join("proofs");
        let entries = fs::read_dir(&dir).ok()?;
        for entry in entries.flatten() {
            let Ok(bytes) = fs::read(entry.path()) else {
                continue;
            };
            let Ok(proof) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            if canonical_digest(&proof).ok().as_deref() == Some(proof_digest) {
                return Some(proof);
            }
        }
        None
    }

    /// Mirrors `verify(proof, {expected})`. Returns the same `{allowed,
    /// code, message, detail}` decision shape `deny`/the success branch
    /// build in JS (via `decision({allowed, ...})`; this crate's
    /// `receipt_auth::verify_record` already returns that shape for the
    /// authentication check, reused here for the two `deny(...)` calls this
    /// port emits by hand).
    pub fn verify(
        &self,
        proof: &Value,
        expected: &Map<String, Value>,
        ledger_store: &dyn LedgerStore,
    ) -> Value {
        fn deny(code: &str, message: &str) -> Value {
            json!({"allowed": false, "code": code, "message": message, "detail": {}})
        }

        if proof.get("role").and_then(Value::as_str) != Some("oracle")
            || proof.get("purpose").and_then(Value::as_str) != Some("completion-claim")
        {
            return deny("ARC_AUTH_FORGED", "Oracle completion authority proof is invalid");
        }
        let role = "oracle";
        let purpose = "completion-claim";
        let mac_domain = format!("arcane-authority-proof:v1:{role}:{purpose}");
        let suffix = format!(":authority-proof:{role}:{purpose}");
        let key_id = match proof.get("authentication").and_then(|a| a.get("keyId")).and_then(Value::as_str) {
            Some(k) => k,
            None => return deny("ARC_AUTH_FORGED", "authority proof key identifier is invalid"),
        };
        let Some(root_key_id) = key_id.strip_suffix(suffix.as_str()) else {
            return deny("ARC_AUTH_FORGED", "authority proof key identifier is invalid");
        };
        if root_key_id.is_empty() {
            return deny("ARC_AUTH_FORGED", "authority proof key identifier is invalid");
        }

        if !self.key_ring.has(key_id) {
            let root = match self.key_ring.get(root_key_id) {
                Ok(k) => k,
                Err(_) => return deny("ARC_AUTH_KEY_UNAVAILABLE", "authority proof root key is unavailable"),
            };
            let mac = Hmac::<Sha256>::new_from_slice(&root.key);
            let mut mac = match mac {
                Ok(m) => m,
                Err(_) => return deny("ARC_AUTH_KEY_UNAVAILABLE", "authority proof root key is unavailable"),
            };
            mac.update(format!("arcane-key-derivation:v1\0{mac_domain}").as_bytes());
            if self
                .key_ring
                .add(key_id.to_string(), mac.finalize().into_bytes().to_vec(), "", "derived", "active")
                .is_err()
            {
                return deny("ARC_AUTH_KEY_UNAVAILABLE", "authority proof root key is unavailable");
            }
        }

        let decision = match verify_record(
            proof,
            proof.get("authentication"),
            &self.key_ring,
            &PROOF_FIELDS,
            &Map::new(),
            Some(&mac_domain),
        ) {
            Ok(d) => d,
            Err(_) => return deny("ARC_AUTH_FORGED", "authority proof authentication is invalid"),
        };
        if !decision.allowed {
            return deny("ARC_AUTH_FORGED", "authority proof authentication is invalid");
        }

        let expected_key_id = format!("{root_key_id}:authority-proof:{role}:{purpose}");
        let expires_at_ns: u128 = proof.get("expiresAt").and_then(Value::as_str).and_then(|s| s.parse().ok()).unwrap_or(0);
        if key_id != expected_key_id || expires_at_ns < timestamp() {
            return deny("ARC_AUTH_FORGED", "authority proof is expired or misbound");
        }

        for (key, value) in expected.iter() {
            if proof.get(key) != Some(value) {
                return deny("ARC_BINDING_MISMATCH", "authority proof does not bind this completion execution");
            }
        }

        let invocation_id = match proof.get("invocationId").and_then(Value::as_str) {
            Some(id) => id,
            None => return deny("ARC_STORE_CORRUPT", "authority proof missing"),
        };
        let issued: Option<Value> = fs::read(self.proof_path(invocation_id))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok());
        let Some(issued) = issued else {
            return deny("ARC_STORE_CORRUPT", "authority proof missing");
        };
        let issued_digest = canonical_digest(&issued).unwrap_or_default();
        let proof_digest = canonical_digest(proof).unwrap_or_default();
        if issued_digest != proof_digest || !ledger_store.verify() {
            return deny("ARC_AUTH_FORGED", "authority proof persistence or host ledger is invalid");
        }

        let event_digest = proof.get("eventDigest").and_then(Value::as_str).unwrap_or("");
        let event = ledger_store
            .records()
            .into_iter()
            .find(|record| canonical_digest(record).unwrap_or_default() == event_digest);
        let bound = match &event {
            Some(event) => {
                event.get("observedAuthority").and_then(Value::as_str) == Some("oracle")
                    && event.get("sessionId") == proof.get("sessionId")
                    && event.get("runId") == proof.get("runId")
                    && event.get("taskId") == proof.get("taskId")
                    && event.get("contractId") == proof.get("contractId")
                    && event.get("contractVersion") == proof.get("contractVersion")
                    && event.get("contractDigest") == proof.get("contractDigest")
                    && event.get("sourceRevision") == proof.get("sourceRevision")
            }
            None => false,
        };
        if !bound {
            return deny("ARC_BINDING_MISMATCH", "authority proof host binding is unavailable");
        }

        json!({"allowed": true, "detail": {"proof": proof}})
    }
}
fn timestamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
fn now() -> String {
    format!("{}", timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir(label: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "legion-r44-authority-invocation-{}-{}-{}",
            std::process::id(),
            n,
            label
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn key_ring_with_root(dir: &Path, key_id: &str, material: &[u8]) -> KeyRing {
        fs::write(dir.join(format!("{key_id}.key")), hex::encode(material)).unwrap();
        KeyRing::load_dir(dir).unwrap()
    }

    struct FakeLedger {
        allowed: bool,
        records: Vec<Value>,
    }
    impl LedgerStore for FakeLedger {
        fn verify(&self) -> bool {
            self.allowed
        }
        fn records(&self) -> Vec<Value> {
            self.records.clone()
        }
    }

    fn base_event() -> Value {
        json!({
            "observedAuthority": "oracle",
            "sessionId": "s1",
            "eventSequence": 1,
            "sourceRevision": "rev1",
            "turnCorrelationDigest": "t1",
            "stopOrdinal": 1,
        })
    }

    fn base_binding() -> Value {
        json!({
            "runId": "r1",
            "taskId": "task1",
            "contractId": "c1",
            "contractVersion": 1,
            "contractDigest": "cd1",
        })
    }

    #[test]
    fn issue_sets_a_five_minute_expiry_window_from_issued_at() {
        let key_dir = temp_dir("keys");
        let store_dir = temp_dir("store");
        let key_ring = key_ring_with_root(&key_dir, "root", b"root-secret-material");
        let issuer = AuthorityInvocationProofIssuer::new(store_dir, key_ring, "root".to_string());
        let proof = issuer.issue(&base_event(), &base_binding(), "completion-claim", "oracle").unwrap();
        let issued_at: u128 = proof["issuedAt"].as_str().unwrap().parse().unwrap();
        let expires_at: u128 = proof["expiresAt"].as_str().unwrap().parse().unwrap();
        assert_eq!(expires_at - issued_at, EXPIRY_WINDOW_NS);
    }

    #[test]
    fn find_by_digest_locates_an_issued_proof() {
        let key_dir = temp_dir("keys");
        let store_dir = temp_dir("store");
        let key_ring = key_ring_with_root(&key_dir, "root", b"root-secret-material");
        let issuer = AuthorityInvocationProofIssuer::new(store_dir, key_ring, "root".to_string());
        let proof = issuer.issue(&base_event(), &base_binding(), "completion-claim", "oracle").unwrap();
        let proof_digest = canonical_digest(&proof).unwrap();
        let found = issuer.find_by_digest(&proof_digest);
        assert_eq!(found, Some(proof));
    }

    #[test]
    fn find_by_digest_returns_none_when_no_proof_matches() {
        let store_dir = temp_dir("store-empty");
        fs::create_dir_all(store_dir.join("proofs")).unwrap();
        let key_dir = temp_dir("keys-unused");
        let key_ring = key_ring_with_root(&key_dir, "root", b"unused");
        let issuer = AuthorityInvocationProofIssuer::new(store_dir, key_ring, "root".to_string());
        assert!(issuer.find_by_digest("sha256:deadbeef").is_none());
    }

    #[test]
    fn verify_accepts_a_freshly_issued_oracle_completion_proof() {
        let key_dir = temp_dir("keys");
        let store_dir = temp_dir("store");
        let key_ring = key_ring_with_root(&key_dir, "root", b"root-secret-material");
        let issuer = AuthorityInvocationProofIssuer::new(store_dir, key_ring, "root".to_string());
        let event = base_event();
        let binding = base_binding();
        let proof = issuer.issue(&event, &binding, "completion-claim", "oracle").unwrap();
        let ledger = FakeLedger { allowed: true, records: vec![event] };
        let decision = issuer.verify(&proof, &Map::new(), &ledger);
        assert_eq!(decision["allowed"], json!(true));
    }

    #[test]
    fn verify_rejects_a_non_oracle_role() {
        let key_dir = temp_dir("keys");
        let store_dir = temp_dir("store");
        let key_ring = key_ring_with_root(&key_dir, "root", b"root-secret-material");
        let issuer = AuthorityInvocationProofIssuer::new(store_dir, key_ring, "root".to_string());
        let bogus = json!({"role": "legion", "purpose": "completion-claim"});
        let ledger = FakeLedger { allowed: true, records: vec![] };
        let decision = issuer.verify(&bogus, &Map::new(), &ledger);
        assert_eq!(decision["allowed"], json!(false));
        assert_eq!(decision["code"], json!("ARC_AUTH_FORGED"));
    }

    #[test]
    fn verify_rejects_when_ledger_store_is_unavailable() {
        let key_dir = temp_dir("keys");
        let store_dir = temp_dir("store");
        let key_ring = key_ring_with_root(&key_dir, "root", b"root-secret-material");
        let issuer = AuthorityInvocationProofIssuer::new(store_dir, key_ring, "root".to_string());
        let event = base_event();
        let binding = base_binding();
        let proof = issuer.issue(&event, &binding, "completion-claim", "oracle").unwrap();
        let ledger = FakeLedger { allowed: false, records: vec![event] };
        let decision = issuer.verify(&proof, &Map::new(), &ledger);
        assert_eq!(decision["allowed"], json!(false));
    }

    #[test]
    fn verify_rejects_expected_binding_mismatch() {
        let key_dir = temp_dir("keys");
        let store_dir = temp_dir("store");
        let key_ring = key_ring_with_root(&key_dir, "root", b"root-secret-material");
        let issuer = AuthorityInvocationProofIssuer::new(store_dir, key_ring, "root".to_string());
        let event = base_event();
        let binding = base_binding();
        let proof = issuer.issue(&event, &binding, "completion-claim", "oracle").unwrap();
        let ledger = FakeLedger { allowed: true, records: vec![event] };
        let mut expected = Map::new();
        expected.insert("taskId".to_string(), json!("some-other-task"));
        let decision = issuer.verify(&proof, &expected, &ledger);
        assert_eq!(decision["allowed"], json!(false));
        assert_eq!(decision["code"], json!("ARC_BINDING_MISMATCH"));
    }
}
