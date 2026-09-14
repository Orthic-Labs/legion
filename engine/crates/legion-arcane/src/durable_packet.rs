use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

#[derive(Clone)]
struct PacketState {
    revision: u64,
    packet_digests: Vec<String>,
}

fn packet_state(value: &Value) -> Option<PacketState> {
    let revision = value.get("revision").and_then(Value::as_u64)?;
    let digests = value
        .get("packetDigests")
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|digest| digest.as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    if digests.iter().any(|digest| digest.is_empty()) {
        return None;
    }
    if digests.len() != digests.iter().collect::<std::collections::HashSet<_>>().len() {
        return None;
    }
    Some(PacketState {
        revision,
        packet_digests: digests,
    })
}

pub struct DurablePacketAdmissionStore {
    state_path: PathBuf,
    lock_path: PathBuf,
}

impl DurablePacketAdmissionStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, String> {
        let root = root.as_ref();
        fs::create_dir_all(root).map_err(|error| error.to_string())?;
        let store = Self {
            state_path: root.join("packet-admissions.json"),
            lock_path: root.join("packet-admissions.lock"),
        };
        store.read_store()?;
        Ok(store)
    }

    fn read_store(&self) -> Result<PacketState, String> {
        if !self.state_path.is_file() {
            return Ok(PacketState {
                revision: 0,
                packet_digests: Vec::new(),
            });
        }
        let bytes = fs::read(&self.state_path).map_err(|error| error.to_string())?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| {
            "ARC_PACKET_STORE_CORRUPT: durable packet state is invalid".to_string()
        })?;
        packet_state(&value).ok_or_else(|| {
            "ARC_PACKET_STORE_CORRUPT: durable packet state is invalid".to_string()
        })
    }

    fn persist_store(&self, state: &PacketState) -> Result<(), String> {
        let payload = json!({
            "schemaVersion": 1,
            "revision": state.revision,
            "packetDigests": state.packet_digests,
        });
        let bytes = serde_json::to_vec(&payload).map_err(|error| error.to_string())?;
        let temporary = self
            .state_path
            .with_extension(format!("{}.tmp", std::process::id()));
        fs::write(&temporary, bytes).map_err(|error| error.to_string())?;
        fs::rename(&temporary, &self.state_path).map_err(|error| error.to_string())?;
        Ok(())
    }

    pub fn admit(&self, packet_digest: &str) -> Value {
        if packet_digest.is_empty() {
            return json!({
                "allowed": false,
                "code": "ARC_PACKET_DIGEST_REQUIRED",
                "packetDigest": Value::Null,
            });
        }
        let lock = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.lock_path)
        {
            Ok(lock) => lock,
            Err(_) => {
                return json!({
                    "allowed": false,
                    "code": "ARC_PACKET_STORE_LOCKED",
                    "consumable": false,
                    "packetDigest": packet_digest,
                });
            }
        };
        let result: Result<Value, String> = (|| {
            let state = self.read_store()?;
            if state.packet_digests.iter().any(|digest| digest == packet_digest) {
                return Ok(json!({
                    "allowed": false,
                    "code": "ARC_PACKET_DIGEST_REPLAY",
                    "packetDigest": packet_digest,
                }));
            }
            let next = PacketState {
                revision: state.revision + 1,
                packet_digests: state
                    .packet_digests
                    .iter()
                    .chain(std::iter::once(&packet_digest.to_string()))
                    .cloned()
                    .collect(),
            };
            self.persist_store(&next)?;
            Ok(json!({
                "outcome": "PACKET_ADMITTED",
                "packetDigest": packet_digest,
                "revision": next.revision,
                "consumable": true,
            }))
        })();
        let _ = fs::remove_file(&self.lock_path);
        let _ = lock;
        match result {
            Ok(value) => value,
            Err(message) => {
                let code = message
                    .split(':')
                    .next()
                    .unwrap_or("ARC_PACKET_ADMISSION_PERSIST_FAILED");
                json!({
                    "allowed": false,
                    "code": code,
                    "consumable": false,
                    "packetDigest": packet_digest,
                })
            }
        }
    }
}
