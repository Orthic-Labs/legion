use legion_research::{ResearchNumber, ResearchPatient, ResearchRoute, ResearchValue};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, process::Command};

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
    assert_eq!(value["externalRequests"], 4);
    assert_eq!(value["independentProviders"], 2);
    assert_eq!(value["receipt"]["source_successes"], 2);
    assert_eq!(value["receipt"]["selected_provider_denominator"], 2);
    assert_eq!(
        value["receipt"]["approval_receipt_ids"],
        serde_json::json!([])
    );
    assert_eq!(value["route"]["provider"], "local-corpus");
    assert!(value["receipt"]["route_digest"].as_str().is_some());
    assert_eq!(value["evidence"].as_array().unwrap().len(), 2);
    assert_eq!(value["claims"].as_array().unwrap().len(), 2);
}

#[test]
fn research_missing_sources_returns_validated_unproven_receipt() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["research", "--query", "missing host evidence"])
        .output()
        .expect("native Legion research must execute");

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "unproven");
    assert_eq!(value["verdict"], "UNPROVEN");
    assert_eq!(value["incomplete"], true);
    assert_eq!(value["receipt"]["status"], "unproven");
    assert_eq!(value["receipt"]["selected_provider_denominator"], 1);
    assert_eq!(
        value["receipt"]["stages"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["stage"],
        "unproven"
    );
    assert_eq!(
        value["receipt"]["stages"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()["completed"],
        true
    );
    assert!(value["receipt"]["stages"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("approval_receipts:not-required"));
    assert!(!value["receipt"]["stages"][0]["detail"]
        .as_str()
        .unwrap()
        .contains("approval_receipt:recorded"));
}

#[test]
fn research_route_extensions_round_trip_and_bind_digest() {
    let mut route = ResearchRoute::host_injected("extension query");
    route.subject.extensions.insert(
        "subject_extension".into(),
        ResearchValue::Object(BTreeMap::from([
            ("enabled".into(), ResearchValue::Bool(true)),
            (
                "items".into(),
                ResearchValue::Array(vec![
                    ResearchValue::Null,
                    ResearchValue::Number(ResearchNumber::Unsigned(7)),
                    ResearchValue::String("nested".into()),
                ]),
            ),
        ])),
    );
    route.subject.patient = Some(ResearchPatient {
        kind: "anonymous".into(),
        extensions: BTreeMap::from([(
            "patient_extension".into(),
            ResearchValue::Object(BTreeMap::from([
                ("enabled".into(), ResearchValue::Bool(false)),
                (
                    "threshold".into(),
                    ResearchValue::Number(ResearchNumber::Float(1.25f64.to_bits())),
                ),
            ])),
        )]),
        ..ResearchPatient::default()
    });
    let encoded = serde_json::to_string(&route).unwrap();
    let decoded: ResearchRoute = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded, route);
    assert_eq!(decoded.digest().unwrap(), route.digest().unwrap());
    assert!(encoded.contains("subject_extension"));
    assert!(encoded.contains("patient_extension"));
}
