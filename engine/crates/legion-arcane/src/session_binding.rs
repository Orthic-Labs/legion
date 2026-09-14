use legion_contracts::canonical_digest;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct SessionBindingStore {
    root: PathBuf,
}

impl SessionBindingStore {
    pub fn new(root: impl AsRef<Path>) -> Self {
        Self {
            root: root.as_ref().to_owned(),
        }
    }
    fn path(&self, session: &str) -> PathBuf {
        let mut h = Sha256::new();
        h.update(session.as_bytes());
        self.root
            .join(format!("{}.json", hex::encode(h.finalize())))
    }
    pub fn get(&self, session: &str) -> Option<Value> {
        if session.is_empty() {
            return None;
        }
        let value: Value = serde_json::from_slice(&fs::read(self.path(session)).ok()?).ok()?;
        let obj = value.as_object()?;
        if obj.get("runId").and_then(Value::as_str).is_none() {
            return None;
        }
        let trio = ["contractId", "contractVersion", "contractDigest"];
        let present = trio
            .iter()
            .filter(|k| obj.get(**k).is_some_and(|v| !v.is_null()))
            .count();
        if present != 0 && present != 3 {
            return None;
        }
        Some(value)
    }
    pub fn ensure(&self, session: &str) -> Option<Value> {
        if let Some(value) = self.get(session) {
            return Some(value);
        }
        fs::create_dir_all(&self.root).ok()?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_nanos();
        let mut h = Sha256::new();
        h.update(format!("{}:{}:{}", session, now, std::process::id()));
        let run_id = format!("run_{}", crockford(&h.finalize())[..26].to_owned());
        let record = json!({"runId":run_id,"taskId":Value::Null,"contractId":Value::Null,"contractVersion":Value::Null,"contractDigest":Value::Null});
        let path = self.path(session);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                use std::io::Write;
                file.write_all(serde_json::to_string(&record).ok()?.as_bytes())
                    .ok()?;
                Some(record)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => self.get(session),
            Err(_) => None,
        }
    }
    pub fn put(&self, session: &str, record: &Value) -> Option<Value> {
        let run = record.get("runId")?.as_str()?;
        if run.is_empty() {
            return None;
        }
        fs::create_dir_all(&self.root).ok()?;
        let tmp = self.root.join(format!(".tmp-{}", std::process::id()));
        fs::write(&tmp, serde_json::to_vec(record).ok()?).ok()?;
        fs::rename(tmp, self.path(session)).ok()?;
        Some(record.clone())
    }
    pub fn compare_and_swap(
        &self,
        session: &str,
        expected: &Value,
        next: &Value,
    ) -> Result<Value, &'static str> {
        let current = self.get(session).ok_or("ARC_BINDING_MISMATCH")?;
        if canonical_digest(&current).ok() != canonical_digest(expected).ok() {
            return Err("ARC_BINDING_MISMATCH");
        }
        self.put(session, next).ok_or("ARC_STORE_CORRUPT")
    }
}

fn crockford(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut out = String::new();
    let mut n = 0u128;
    let mut bits = 0;
    for byte in bytes {
        n = (n << 8) | *byte as u128;
        bits += 8;
        while bits >= 5 && out.len() < 26 {
            bits -= 5;
            out.push(ALPHABET[((n >> bits) & 31) as usize] as char);
        }
    }
    while out.len() < 26 {
        out.push('0');
    }
    out
}
