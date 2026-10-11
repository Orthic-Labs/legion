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
            "content_digest": format!(
                "sha256:{}",
                hex::encode(Sha256::digest(text.as_bytes()))
            ),
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

fn step_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "legion-research-step-{}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("step fixture directory");
    dir
}

const GOOD_EVIDENCE: &str = r#"{"id":"e1","url":"https://a.test/1","publisher":"Vendor","retrieved_at":"2026-08-01","locator":"section 2","suggested_by":"search","seed_chain":["seed"],"instructionPolicy":"data_only","body_plain":"The vendor price is 10 dollars per seat per month.","source_type":"web"}"#;
const GOOD_CLAIM: &str = r#"{"id":"c1","claim_type":"observation","text":"The vendor price is 10 dollars per seat","confidence":"low","as_of":"2026-08-01","source_ids":["e1"]}"#;

#[test]
fn research_step_ledger_check_reports_ok_for_a_sound_ledger() {
    let dir = step_dir("ledger-check");
    let evidence = dir.join("evidence.jsonl");
    let claims = dir.join("claims.jsonl");
    std::fs::write(&evidence, format!("{GOOD_EVIDENCE}\n")).unwrap();
    std::fs::write(&claims, format!("{GOOD_CLAIM}\n")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "research",
            "--step",
            "ledger-check",
            "--evidence",
            evidence.to_str().unwrap(),
            "--claims",
            claims.to_str().unwrap(),
        ])
        .output()
        .expect("native Legion research must execute");
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "ok");
    assert_eq!(value["step"], "ledger-check");
    assert_eq!(value["result"]["overall_ok"], true);
    assert_eq!(value["result"]["clusters"].as_array().unwrap().len(), 1);
}

#[test]
fn research_step_ledger_render_writes_the_brief_when_clean() {
    let dir = step_dir("ledger-render");
    let evidence = dir.join("evidence.jsonl");
    let claims = dir.join("claims.jsonl");
    let out = dir.join("draft.md");
    std::fs::write(&evidence, format!("{GOOD_EVIDENCE}\n")).unwrap();
    std::fs::write(&claims, format!("{GOOD_CLAIM}\n")).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "research",
            "--step",
            "ledger-render",
            "--evidence",
            evidence.to_str().unwrap(),
            "--claims",
            claims.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
            "--title",
            "Brief",
        ])
        .output()
        .expect("native Legion research must execute");
    let draft = std::fs::read_to_string(&out).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "ok");
    assert!(draft.starts_with("# Brief\n"));
    assert!(draft.contains("[+e1]"));
}

#[test]
fn research_step_citecheck_fails_an_unsupported_number() {
    let dir = step_dir("citecheck");
    let evidence = dir.join("evidence.jsonl");
    let draft = dir.join("draft.md");
    std::fs::write(&evidence, format!("{GOOD_EVIDENCE}\n")).unwrap();
    std::fs::write(&draft, "The vendor price is 99 dollars per seat [+e1].\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "research",
            "--step",
            "citecheck",
            "--draft",
            draft.to_str().unwrap(),
            "--evidence",
            evidence.to_str().unwrap(),
        ])
        .output()
        .expect("native Legion research must execute");
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "failed");
    assert_eq!(value["result"]["ok"], false);
    assert_eq!(value["result"]["summary"]["unsupported_or_partial"], 1);
}

#[test]
fn research_step_retraction_without_network_is_a_typed_gap() {
    let dir = step_dir("retraction");
    let dois = dir.join("dois.txt");
    std::fs::write(&dois, "10.1/example\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "research",
            "--step",
            "retraction",
            "--dois",
            dois.to_str().unwrap(),
        ])
        .output()
        .expect("native Legion research must execute");
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "unavailable");
    assert_eq!(value["reason"], "unavailable:network-step-not-run");
    assert_eq!(value["result"]["unknown_count"], 1);
}

#[test]
fn research_step_meter_refusal_exits_non_zero_and_is_not_persisted() {
    let dir = step_dir("meter");
    let state = dir.join("state.json");
    std::fs::write(
        &state,
        r#"{"budget":{"external_requests":1,"workers":1},"usage":{"external_requests":1,"workers_active":0,"workers_started":0}}"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "research",
            "--step",
            "meter",
            "--meter-state",
            state.to_str().unwrap(),
            "--effect",
            "external_request",
        ])
        .output()
        .expect("native Legion research must execute");
    let _ = std::fs::remove_dir_all(&dir);

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "failed");
    assert_eq!(value["result"]["ok"], false);
    assert_eq!(value["result"]["events"][0]["type"], "budget.refused");
    assert_eq!(value["result"]["persisted"], false);
}

#[test]
fn research_without_query_or_step_is_refused_before_running() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["research"])
        .output()
        .expect("native Legion research must execute");
    assert!(!output.status.success());
}

#[test]
fn research_unknown_step_is_a_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["research", "--step", "not-a-step"])
        .output()
        .expect("native Legion research must execute");
    assert_eq!(output.status.code(), Some(4));
}
