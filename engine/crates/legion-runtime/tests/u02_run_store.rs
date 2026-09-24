//! Packet U02 integration test: `RunArtifactStore` (port of
//! `src/lib/artifacts/run-store.mjs`) against the real filesystem via
//! `StdFs`, exercising `init`/`write_json`/`write_bytes`/`records`/
//! `read_verified` end to end in a throwaway temp directory. No network or
//! subprocess use.

use legion_runtime::wf_port::u02::{RunArtifactStore, WriteJsonSpec};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root() -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!(
        "legion-u02-run-store-{}-{}-{}",
        std::process::id(),
        nanos,
        n
    ))
}

#[test]
fn init_then_write_json_then_read_verified_round_trips() {
    let root = temp_root();
    let store = RunArtifactStore::new(&root);
    store.init().expect("init");

    let record = store
        .write_json(WriteJsonSpec {
            path: "artifacts/receipt.json".to_string(),
            kind: "receipt".to_string(),
            producer: "u02-integration-test".to_string(),
            producer_version: None,
            schema_version: Some("1".to_string()),
            binding: None,
            denominator_digest: None,
            value_json: "{\n  \"ok\": true\n}".to_string(),
        })
        .expect("write_json");

    assert_eq!(record.path, "artifacts/receipt.json");
    assert_eq!(record.media_type, "application/json");

    let bytes = store.read_verified("artifacts/receipt.json").expect("read_verified");
    assert_eq!(bytes, b"{\n  \"ok\": true\n}\n");

    let records = store.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].digest, record.digest);

    let _ = std::fs::remove_dir_all(&root);
}
