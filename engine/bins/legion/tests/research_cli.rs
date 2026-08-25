use sha2::{Digest, Sha256};
use std::process::Command;

#[test]
fn research_consumes_host_injected_sources_with_receipts() {
    let text = "Source-grounded native research evidence.";
    let source = |id: &str, provider: &str, receipt: &str| {
        serde_json::json!({
            "schema_version": 1,
            "source_id": id,
            "kind": "web",
            "provider": provider,
            "uri": "https://example.test/source",
            "title": "Fixture source",
            "retrieved_at": "2026-08-25T00:00:00Z",
            "content_digest": format!("sha256:{:x}", Sha256::digest(text.as_bytes())),
            "byte_length": text.len(),
            "text": text,
            "metadata": {"request_receipt": receipt}
        })
    };
    let path_one = std::env::temp_dir().join(format!(
        "legion-native-research-{}-{}-one.json",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    let path_two = path_one.with_file_name(format!(
        "legion-native-research-{}-{}-two.json",
        std::process::id(),
        std::thread::current().name().unwrap_or("test")
    ));
    std::fs::write(
        &path_one,
        serde_json::to_vec(&source("source-1", "host-web-a", "fixture-request-1")).unwrap(),
    )
    .unwrap();
    std::fs::write(
        &path_two,
        serde_json::to_vec(&source("source-2", "host-web-b", "fixture-request-2")).unwrap(),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "research",
            "--query",
            "fixture query",
            "--source-record",
            path_one.to_str().unwrap(),
            "--source-record",
            path_two.to_str().unwrap(),
        ])
        .output()
        .expect("native Legion research must execute");
    let _ = std::fs::remove_file(&path_one);
    let _ = std::fs::remove_file(&path_two);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "ok");
    assert_eq!(value["externalRequests"], 2);
    assert_eq!(value["independentProviders"], 2);
    assert_eq!(value["receipt"]["source_successes"], 2);
    assert_eq!(value["evidence"].as_array().unwrap().len(), 2);
    assert_eq!(value["claims"].as_array().unwrap().len(), 2);
}
