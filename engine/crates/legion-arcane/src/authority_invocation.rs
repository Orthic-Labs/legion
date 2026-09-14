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
        let now = now();
        let mut unsigned = json!({"schemaVersion":1,"kind":"arcane-authority-invocation-proof","invocationId":invocation_id,"eventDigest":event_digest,"eventSequence":event["eventSequence"],"purpose":purpose,"role":role,"sessionId":event["sessionId"],"runId":binding["runId"],"taskId":binding["taskId"],"contractId":binding["contractId"],"contractVersion":binding["contractVersion"],"contractDigest":binding["contractDigest"],"sourceRevision":event["sourceRevision"],"turnCorrelationDigest":event["turnCorrelationDigest"],"stopOrdinal":event["stopOrdinal"],"domain":format!("arcane-authority-proof:{}:{}",role,purpose),"issuedAt":now,"expiresAt":now,"nonce":format!("{}-{}",std::process::id(),timestamp())});
        unsigned["expiresAt"] = Value::String(now.clone());
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
