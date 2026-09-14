use crate::{
    receipt_auth::{sign_record, verify_record},
    KeyRing, SessionBindingStore,
};
use legion_contracts::canonical_digest;
use serde_json::{json, Map, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub const TRANSITION_FIELDS: [&str; 14] = [
    "schemaVersion",
    "kind",
    "transactionId",
    "action",
    "state",
    "sessionId",
    "runId",
    "predecessorBinding",
    "successorBinding",
    "predecessorDigest",
    "successorDigest",
    "deliveryDigest",
    "createdAt",
    "nonce",
];
pub struct ContractLifecycle {
    root: PathBuf,
    bindings: SessionBindingStore,
    key_ring: KeyRing,
    key_id: String,
}
impl ContractLifecycle {
    pub fn new(
        root: PathBuf,
        bindings: SessionBindingStore,
        key_ring: KeyRing,
        key_id: String,
    ) -> Self {
        Self {
            root,
            bindings,
            key_ring,
            key_id,
        }
    }
    fn path(&self, session: &str) -> PathBuf {
        let d = canonical_digest(
            &json!({"domain":"arcane.contract-transition.v1","sessionId":session}),
        )
        .unwrap_or_default();
        self.root
            .join(format!("{}.jsonl", d.trim_start_matches("sha256:")))
    }
    fn records(&self, session: &str) -> Result<Vec<Value>, String> {
        let path = self.path(session);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(path).map_err(|_| "ARC_STORE_CORRUPT".to_owned())?;
        if !text.is_empty() && !text.ends_with('\n') {
            return Err("ARC_STORE_CORRUPT".into());
        }
        let mut prev = Value::Null;
        let mut out = Vec::new();
        for line in text.lines() {
            let v: Value =
                serde_json::from_str(line).map_err(|_| "ARC_STORE_CORRUPT".to_owned())?;
            let auth = v.get("authentication").ok_or("ARC_STORE_CORRUPT")?;
            let mut expected = Map::new();
            expected.insert("sessionId".into(), Value::String(session.into()));
            let d = verify_record(
                &v,
                Some(auth),
                &self.key_ring,
                &TRANSITION_FIELDS,
                &expected,
                Some("arcane.contract-transition.v1"),
            )
            .map_err(|_| "ARC_STORE_CORRUPT")?;
            if !d.allowed || v.get("previousReceiptDigest") != Some(&prev) {
                return Err("ARC_STORE_CORRUPT".into());
            }
            prev = Value::String(canonical_digest(&v).map_err(|_| "ARC_STORE_CORRUPT")?);
            out.push(v)
        }
        Ok(out)
    }
    fn append(&self, unsigned: Value) -> Result<Value, String> {
        let auth = sign_record(
            &unsigned,
            &self.key_ring,
            &self.key_id,
            &TRANSITION_FIELDS,
            Some("arcane.contract-transition.v1"),
        )
        .map_err(|e| e.code().to_owned())?;
        let mut obj = unsigned.as_object().cloned().ok_or("ARC_SCHEMA_INVALID")?;
        obj.insert("authentication".into(), auth);
        let record = Value::Object(obj);
        fs::create_dir_all(&self.root).map_err(|_| "ARC_STORE_CORRUPT")?;
        use std::io::Write;
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(
                self.path(
                    record
                        .get("sessionId")
                        .and_then(Value::as_str)
                        .unwrap_or_default(),
                ),
            )
            .map_err(|_| "ARC_STORE_CORRUPT")?;
        writeln!(
            f,
            "{}",
            serde_json::to_string(&record).map_err(|_| "ARC_STORE_CORRUPT")?
        )
        .map_err(|_| "ARC_STORE_CORRUPT")?;
        Ok(record)
    }
    fn receipt(
        &self,
        action: &str,
        state: &str,
        tx: &str,
        session: &str,
        predecessor: &Value,
        successor: &Value,
        previous: Value,
    ) -> Value {
        let now = now();
        json!({"schemaVersion":1,"kind":"arcane-contract-transition-receipt","transactionId":tx,"action":action,"state":state,"sessionId":session,"runId":predecessor["runId"],"predecessorBinding":predecessor,"successorBinding":successor,"predecessorDigest":canonical_digest(predecessor).unwrap_or_default(),"successorDigest":canonical_digest(successor).unwrap_or_default(),"deliveryDigest":canonical_digest(predecessor.get("delivery").unwrap_or(&Value::Null)).unwrap_or_default(),"createdAt":now,"nonce":tx,"previousReceiptDigest":previous})
    }
    pub fn transition(
        &self,
        action: &str,
        session: &str,
        tx: &str,
        target: Option<(String, u64, Option<String>)>,
        seal_root: &Path,
    ) -> Result<Value, String> {
        if !["suspend", "supersede"].contains(&action) || tx.len() < 16 {
            return Err("ARC_SCHEMA_INVALID".into());
        }
        let records = self.records(session)?;
        if let Some(found) = records.iter().find(|r| r["transactionId"] == tx) {
            if found["state"] == "COMMITTED" {
                return Err("ARC_REPLAY_NONCE_SEEN".into());
            }
            return self.repair_inner(session, &records);
        }
        if records.iter().any(|r| r["state"] == "PREPARED") {
            return Err("ARC_REPLAY_NONCE_SEEN".into());
        }
        let predecessor = self.bindings.get(session).ok_or("ARC_BINDING_MISMATCH")?;
        if predecessor["contractId"].is_null() {
            return Err("ARC_BINDING_MISMATCH".into());
        }
        let successor = if action == "suspend" {
            let mut x = predecessor.clone();
            x["lifecycle"] = json!({"state":"suspended","transactionId":tx});
            x
        } else {
            let (id, version, task) = target.ok_or("ARC_SCHEMA_INVALID")?;
            let path = crate::state_paths::state_file(
                &seal_root.to_path_buf(),
                "arcane.contract-seal.key.v1",
                &[id.clone(), version.to_string()],
            )
            .map_err(|_| "ARC_STORE_CORRUPT")?;
            let seal: Value =
                serde_json::from_slice(&fs::read(path).map_err(|_| "ARC_NO_CONTRACT")?)
                    .map_err(|_| "ARC_STORE_CORRUPT")?;
            let mut x = predecessor.clone();
            x["contractId"] = seal["contractId"].clone();
            x["contractVersion"] = seal["version"].clone();
            x["contractDigest"] = seal["contractDigest"].clone();
            if let Some(t) = task {
                x["taskId"] = Value::String(t)
            };
            x["lifecycle"] = json!({"state":"active","transactionId":tx});
            x
        };
        let previous = records
            .last()
            .map(|r| Value::String(canonical_digest(r).unwrap_or_default()))
            .unwrap_or(Value::Null);
        let prepared = self.append(self.receipt(
            action,
            "PREPARED",
            tx,
            session,
            &predecessor,
            &successor,
            previous,
        ))?;
        self.bindings
            .compare_and_swap(session, &predecessor, &successor)
            .map_err(|e| e.to_owned())?;
        let prev = Value::String(canonical_digest(&prepared).unwrap_or_default());
        self.append(self.receipt(
            action,
            "COMMITTED",
            tx,
            session,
            &predecessor,
            &successor,
            prev,
        ))
    }
    fn repair_inner(&self, session: &str, records: &[Value]) -> Result<Value, String> {
        let pending = records
            .iter()
            .rev()
            .find(|r| r["state"] == "PREPARED")
            .ok_or("ARC_BINDING_MISMATCH")?;
        let current = self.bindings.get(session).ok_or("ARC_BINDING_MISMATCH")?;
        if canonical_digest(&current).ok() != canonical_digest(&pending["predecessorBinding"]).ok()
            && canonical_digest(&current).ok()
                != canonical_digest(&pending["successorBinding"]).ok()
        {
            return Err("ARC_BINDING_MISMATCH".into());
        };
        if canonical_digest(&current).ok() == canonical_digest(&pending["predecessorBinding"]).ok()
        {
            let _ = self.bindings
                .compare_and_swap(session, &current, &pending["successorBinding"])
                .map_err(|e| e.to_owned())?;
        };
        let prev = Value::String(canonical_digest(records.last().unwrap()).unwrap_or_default());
        self.append(self.receipt(
            pending["action"].as_str().unwrap_or_default(),
            "COMMITTED",
            pending["transactionId"].as_str().unwrap_or_default(),
            session,
            &pending["predecessorBinding"],
            &pending["successorBinding"],
            prev,
        ))
    }
    pub fn repair(&self, session: &str) -> Result<Value, String> {
        let records = self.records(session)?;
        self.repair_inner(session, &records)
    }
}
fn now() -> String {
    let s = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{s}")
}
