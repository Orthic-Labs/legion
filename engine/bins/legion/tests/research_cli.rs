use legion_research::{ResearchNumber, ResearchPatient, ResearchRoute, ResearchValue};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, process::Command};

#[test]
fn research_consumes_host_injected_sources_with_receipts() {
    let text = "Source-grounded native research evidence.";
    let source = |id: &str, provider: &str, receipt: &str, uri: &str| {
        serde_json::json!({
            "schema_version": 1,
            "source_id": id,
            "kind": "web",
            "provider": provider,
            "uri": uri,
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
        serde_json::to_vec(&source(
            "source-1",
            "host-web-a",
            "fixture-request-1",
            "https://alpha.example/source",
        ))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        &path_two,
        serde_json::to_vec(&source(
            "source-2",
            "host-web-b",
            "fixture-request-2",
            "https://beta.example/source",
        ))
        .unwrap(),
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
            "--offline",
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

#[test]
fn research_issue_patch_and_apply_patch_are_reachable_from_cli() {
    let dir = step_dir("patch-round-trip");
    let draft = dir.join("draft.md");
    let key = dir.join("key.bin");
    let receipt = dir.join("patch-receipt.json");
    let diff = dir.join("patch.diff");
    let unrelated = dir.join("keep.txt");
    std::fs::write(&draft, "alpha\nbeta\ngamma\n").unwrap();
    std::fs::write(&key, [0x42u8; 32]).unwrap();
    std::fs::write(&unrelated, "untouched\n").unwrap();

    let issue = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["research", "--step", "issue-patch", "--draft"])
        .arg(&draft)
        .args(["--run-id", "run-2026-10-12", "--key-file"])
        .arg(&key)
        .arg("--out")
        .arg(&receipt)
        .output()
        .expect("native Research patch issuer must execute");
    assert!(
        issue.status.success(),
        "{}",
        String::from_utf8_lossy(&issue.stderr)
    );
    let issued: serde_json::Value = serde_json::from_slice(&issue.stdout).unwrap();
    assert_eq!(issued["step"], "issue-patch");
    assert_eq!(issued["status"], "ok");
    let receipt_value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&receipt).unwrap()).unwrap();
    assert_eq!(receipt_value["assurance"], "ambient-cli");
    assert_eq!(
        receipt_value["allowed_tools"],
        serde_json::json!(["Read", "Edit"])
    );
    let receipt_text = std::fs::read_to_string(&receipt).unwrap();
    assert!(!receipt_text.contains(&hex::encode([0x42u8; 32])));
    assert!(!String::from_utf8_lossy(&issue.stdout).contains(&hex::encode([0x42u8; 32])));

    std::fs::write(
        &diff,
        "--- a/draft.md\n+++ b/draft.md\n@@ -2,1 +2,1 @@\n-beta\n+BETA\n",
    )
    .unwrap();
    let applied = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["research", "--step", "apply-patch", "--draft"])
        .arg(&draft)
        .args(["--run-id", "run-2026-10-12", "--key-file"])
        .arg(&key)
        .arg("--receipt")
        .arg(&receipt)
        .arg("--diff")
        .arg(&diff)
        .output()
        .expect("native Research patch applier must execute");
    assert!(
        applied.status.success(),
        "{}",
        String::from_utf8_lossy(&applied.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&applied.stdout).unwrap();
    assert_eq!(result["step"], "apply-patch");
    assert_eq!(result["status"], "ok");
    assert_eq!(result["result"]["applied_hunks"], 1);
    assert_eq!(
        std::fs::read_to_string(&draft).unwrap(),
        "alpha\nBETA\ngamma\n"
    );
    assert_eq!(std::fs::read_to_string(unrelated).unwrap(), "untouched\n");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn research_apply_patch_rejects_wrong_run_and_multifile_diff_without_writes() {
    let dir = step_dir("patch-reject");
    let draft = dir.join("draft.md");
    let key = dir.join("key.bin");
    let receipt = dir.join("patch-receipt.json");
    let diff = dir.join("patch.diff");
    let original = "alpha\nbeta\ngamma\n";
    std::fs::write(&draft, original).unwrap();
    std::fs::write(&key, [0x23u8; 32]).unwrap();
    let issue = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["research", "--step", "issue-patch", "--draft"])
        .arg(&draft)
        .args(["--run-id", "right-run", "--key-file"])
        .arg(&key)
        .arg("--out")
        .arg(&receipt)
        .output()
        .expect("native Research patch issuer must execute");
    assert!(issue.status.success());

    std::fs::write(
        &diff,
        "--- a/draft.md\n+++ b/draft.md\n@@ -2,1 +2,1 @@\n-beta\n+BETA\n",
    )
    .unwrap();
    let wrong_run = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["research", "--step", "apply-patch", "--draft"])
        .arg(&draft)
        .args(["--run-id", "wrong-run", "--key-file"])
        .arg(&key)
        .arg("--receipt")
        .arg(&receipt)
        .arg("--diff")
        .arg(&diff)
        .output()
        .unwrap();
    assert_eq!(wrong_run.status.code(), Some(4));
    assert_eq!(std::fs::read_to_string(&draft).unwrap(), original);

    std::fs::write(
        &diff,
        "diff --git a/draft.md b/draft.md\n--- a/draft.md\n+++ b/draft.md\n@@ -2,1 +2,1 @@\n-beta\n+BETA\ndiff --git a/other.md b/other.md\n",
    )
    .unwrap();
    let multifile = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(["research", "--step", "apply-patch", "--draft"])
        .arg(&draft)
        .args(["--run-id", "right-run", "--key-file"])
        .arg(&key)
        .arg("--receipt")
        .arg(&receipt)
        .arg("--diff")
        .arg(&diff)
        .output()
        .unwrap();
    assert_eq!(multifile.status.code(), Some(4));
    assert_eq!(std::fs::read_to_string(&draft).unwrap(), original);
    let _ = std::fs::remove_dir_all(dir);
}

fn run_independence(
    tag: &str,
    rows: &[(&str, &str)],
    extra: &[&str],
) -> (Option<i32>, serde_json::Value) {
    let text = "Source-grounded native research evidence.";
    let mut args = vec![
        "research".to_string(),
        "--query".into(),
        "fixture query".into(),
    ];
    let mut paths = Vec::new();
    for (index, (provider, uri)) in rows.iter().enumerate() {
        let path = std::env::temp_dir().join(format!(
            "legion-research-indep-{}-{tag}-{index}.json",
            std::process::id()
        ));
        let record = serde_json::json!({
            "schema_version": 1,
            "source_id": format!("source-{index}"),
            "kind": "web",
            "provider": provider,
            "uri": uri,
            "title": "Fixture source",
            "retrieved_at": "2026-08-25T00:00:00Z",
            "text": text,
            "metadata": {"request_receipt": format!("req-{index}")}
        });
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        args.push("--source-record".into());
        args.push(path.to_str().unwrap().into());
        paths.push(path);
    }
    args.extend(extra.iter().map(|value| value.to_string()));
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args(&args)
        .output()
        .expect("native Legion research must execute");
    for path in paths {
        let _ = std::fs::remove_file(path);
    }
    (
        output.status.code(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

#[test]
fn research_independence_ignores_provider_label() {
    let (code, same_label) = run_independence(
        "labels-same",
        &[
            ("webfetch", "https://alpha.example/a"),
            ("webfetch", "https://beta.example/b"),
        ],
        &["--provider", "webfetch"],
    );
    assert_eq!(code, Some(0), "{same_label}");
    assert_eq!(same_label["independentProviders"], 2);

    let (code, relabeled) = run_independence(
        "relabel",
        &[
            ("one", "https://www.alpha.example/a"),
            ("two", "https://alpha.example:8443/b"),
        ],
        &[],
    );
    assert_eq!(code, Some(2));
    assert_eq!(relabeled["status"], "unproven");
    assert_eq!(relabeled["independentProviders"], 1);
}

#[test]
fn research_independence_without_url_is_self_declared_and_unmet() {
    let rows = [("one", "corpus/doc-1.txt"), ("two", "corpus/doc-2.txt")];
    let (code, strict) = run_independence("nourl", &rows, &[]);
    assert_eq!(code, Some(2));
    assert_eq!(strict["status"], "unproven");
    assert_eq!(strict["independentProviders"], 0);
    assert_eq!(strict["independence"]["selfDeclared"], true);

    let (code, allowed) = run_independence(
        "nourl-allowed",
        &rows,
        &["--allow-self-declared-independence"],
    );
    assert_eq!(code, Some(0), "{allowed}");
    assert_eq!(allowed["independence"]["selfDeclared"], true);
    assert_eq!(allowed["independence"]["selfDeclaredCounted"], true);
}

#[test]
fn medical_convenience_flags_create_anonymous_route_and_report() {
    let dir = step_dir("medical-convenience");
    let mut command = Command::new(env!("CARGO_BIN_EXE_legion"));
    command.args([
        "research",
        "--query",
        "fixture medical query",
        "--domain",
        "medical",
        "--sensitivity",
        "private",
    ]);
    for (index, url) in ["https://alpha.test/source", "https://beta.test/source"]
        .iter()
        .enumerate()
    {
        let path = dir.join(format!("source-{index}.json"));
        let record = serde_json::json!({
            "schema_version": 1,
            "source_id": format!("medical-source-{index}"),
            "kind": "web",
            "provider": format!("fixture-{index}"),
            "uri": url,
            "title": "Fixture source",
            "retrieved_at": "2026-08-25T00:00:00Z",
            "text": "The source describes general adult dosing evidence for review.",
            "metadata": {"request_receipt": format!("fixture-request-{index}")}
        });
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        command.arg("--source-record").arg(path);
    }
    let output = command
        .output()
        .expect("native Legion research must execute");
    let _ = std::fs::remove_dir_all(dir);

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "ok");
    assert_eq!(value["report"]["query"], "fixture medical query");
    assert_eq!(value["route"]["provider"], "local-corpus");
    assert_eq!(value["route"]["domain"], "medical");
    assert_eq!(value["route"]["subject"]["query"], "fixture medical query");
    assert_eq!(value["route"]["subject"]["issue"], "fixture medical query");
    assert_eq!(value["route"]["subject"]["patient"]["kind"], "anonymous");
    assert_eq!(
        value["route"]["subject"]["patient"]["history_available"],
        false
    );
    assert!(value["route"]["subject"]["patient"]
        .get("history_source")
        .is_none());
    assert_eq!(value["evidence"].as_array().unwrap().len(), 2);
    assert!(!value["claims"].as_array().unwrap().is_empty());
}

#[test]
fn anonymous_medical_host_records_run_with_frozen_browser_and_domain_default_routes() {
    let dir = step_dir("medical-host-record-routes");
    let text = "The source describes general adult dosing evidence for review.";
    let mut paths = Vec::new();
    for (index, url) in [
        "https://alpha.test/source",
        "https://beta.test/source",
        "https://gamma.test/source",
    ]
    .iter()
    .enumerate()
    {
        let path = dir.join(format!("source-{index}.json"));
        let record = serde_json::json!({
            "schema_version": 1,
            "source_id": format!("medical-source-{index}"),
            "kind": "web",
            "provider": "webfetch",
            "uri": url,
            "title": "Fixture source",
            "retrieved_at": "2026-08-25T00:00:00Z",
            "text": text,
            "metadata": {"request_receipt": format!("fixture-request-{index}")}
        });
        std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        paths.push(path);
    }

    for provider in ["browser", "domain-default"] {
        let mut route =
            ResearchRoute::host_injected_with("fixture medical query", "medical", "public");
        route.operation = "advise".into();
        route.methods = vec!["web".into(), "authority".into()];
        route.provider = provider.into();
        route.allowed_effects = vec![
            "search".into(),
            "fetch".into(),
            "extract".into(),
            "synthesize".into(),
        ];
        route.subject.issue = Some("fixture medical query".into());
        route.subject.patient = Some(ResearchPatient {
            kind: "anonymous".into(),
            history_available: Some(false),
            ..ResearchPatient::default()
        });
        let route_path = dir.join(format!("{provider}-route.json"));
        std::fs::write(&route_path, serde_json::to_vec(&route).unwrap()).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_legion"));
        command.args([
            "research",
            "--query",
            "fixture medical query",
            "--route-json",
            route_path.to_str().unwrap(),
            "--provider",
            "webfetch",
            "--min-independent-providers",
            "3",
        ]);
        for path in &paths {
            command.arg("--source-record").arg(path);
        }
        let output = command
            .output()
            .expect("native Legion research must execute");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["status"], "ok");
        assert_eq!(value["route"], serde_json::to_value(route).unwrap());
        assert_eq!(value["route"]["provider"], provider);
        assert_eq!(value["route"]["allowed_effects"][0], "search");
        assert_eq!(value["independentProviders"], 3);
        assert_eq!(value["evidence"].as_array().unwrap().len(), 3);
        assert!(!value["claims"].as_array().unwrap().is_empty());
        assert_eq!(value["digestComputedByRoute"], true);
        assert_eq!(
            value["digestComputedSourceIds"].as_array().unwrap().len(),
            3
        );
        assert_eq!(
            value["independence"]["sourceIdentityKeys"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
    }

    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn unsupported_routes_remain_unavailable_without_implicit_rewrite() {
    let dir = step_dir("unsupported-routes");
    let mut routes = Vec::new();
    let mut browser = ResearchRoute::host_injected("fixture query");
    browser.provider = "browser".into();
    routes.push(("browser-no-records", browser));
    let mut notebooklm = ResearchRoute::host_injected("fixture query");
    notebooklm.provider = "notebooklm".into();
    routes.push(("notebooklm", notebooklm));
    let mut stateful = ResearchRoute::host_injected("fixture query");
    stateful.operation = "manage-corpus".into();
    routes.push(("stateful", stateful));

    for (name, route) in routes {
        let route_path = dir.join(format!("{name}.json"));
        std::fs::write(&route_path, serde_json::to_vec(&route).unwrap()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_legion"))
            .args([
                "research",
                "--query",
                "fixture query",
                "--route-json",
                route_path.to_str().unwrap(),
            ])
            .output()
            .expect("native Legion research must execute");
        assert_eq!(output.status.code(), Some(2));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["status"], "unavailable");
        assert_eq!(value["route"], serde_json::to_value(route).unwrap());
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn browser_route_without_fetch_grant_is_refused() {
    let dir = step_dir("browser-fetch-grant");
    let source_path = dir.join("source.json");
    let route_path = dir.join("route.json");
    let source = serde_json::json!({
        "schema_version": 1,
        "source_id": "fixture-source",
        "kind": "web",
        "provider": "webfetch",
        "uri": "https://alpha.test/source",
        "title": "Fixture source",
        "retrieved_at": "2026-08-25T00:00:00Z",
        "text": "A source describes a fixture result.",
        "metadata": {"request_receipt": "fixture-request"}
    });
    let mut route = ResearchRoute::host_injected("fixture query");
    route.provider = "browser".into();
    route.allowed_effects = vec!["search".into(), "extract".into(), "synthesize".into()];
    std::fs::write(&source_path, serde_json::to_vec(&source).unwrap()).unwrap();
    std::fs::write(&route_path, serde_json::to_vec(&route).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "research",
            "--query",
            "fixture query",
            "--route-json",
            route_path.to_str().unwrap(),
            "--min-independent-providers",
            "1",
            "--source-record",
            source_path.to_str().unwrap(),
        ])
        .output()
        .expect("native Legion research must execute");
    let _ = std::fs::remove_dir_all(dir);

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "unproven");
    assert!(value["failures"].as_array().unwrap().iter().any(|failure| {
        failure["reason"] == "effect_denied:fetch_not_route_allowed_or_granted"
    }));
}

#[test]
fn route_json_query_conflict_is_a_usage_error() {
    let dir = step_dir("route-query-conflict");
    let path = dir.join("route.json");
    let route = ResearchRoute::host_injected("different fixture query");
    std::fs::write(&path, serde_json::to_vec(&route).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "research",
            "--query",
            "fixture query",
            "--route-json",
            path.to_str().unwrap(),
        ])
        .output()
        .expect("native Legion research must execute");
    let _ = std::fs::remove_dir_all(dir);

    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn explicit_personal_medical_routes_still_require_confirmation_receipts() {
    let dir = step_dir("personal-medical-gates");
    let source_path = dir.join("source.json");
    let source = serde_json::json!({
        "schema_version": 1,
        "source_id": "fixture-source",
        "kind": "web",
        "provider": "webfetch",
        "uri": "https://alpha.test/source",
        "title": "Fixture source",
        "retrieved_at": "2026-08-25T00:00:00Z",
        "text": "A source describes a fixture result.",
        "metadata": {"request_receipt": "fixture-request"}
    });
    std::fs::write(&source_path, serde_json::to_vec(&source).unwrap()).unwrap();

    for kind in ["self", "other-identified"] {
        let mut route = ResearchRoute::host_injected_with("fixture query", "medical", "private");
        route.subject.issue = Some("fixture issue".into());
        route.subject.patient = Some(ResearchPatient {
            kind: kind.into(),
            history_available: Some(true),
            history_source: Some(legion_research::NullableString::Value(
                "fixture-source-record".into(),
            )),
            ..ResearchPatient::default()
        });
        route.human_gates = vec!["confirm-personal-medical-route".into()];
        route
            .allowed_effects
            .extend(["read-sensitive".into(), "load-medical-history".into()]);
        let route_path = dir.join(format!("{kind}-route.json"));
        std::fs::write(&route_path, serde_json::to_vec(&route).unwrap()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_legion"))
            .args([
                "research",
                "--query",
                "fixture query",
                "--route-json",
                route_path.to_str().unwrap(),
                "--min-independent-providers",
                "1",
                "--source-record",
                source_path.to_str().unwrap(),
            ])
            .output()
            .expect("native Legion research must execute");
        assert_eq!(output.status.code(), Some(2));
        let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["status"], "unproven");
        assert_eq!(value["route"]["subject"]["patient"]["kind"], kind);
        assert!(value["failures"].as_array().unwrap().iter().any(|failure| {
            failure["reason"] == "route_gate_denied:approval_receipt_identity_missing"
        }));
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn invalid_host_record_is_reported_alongside_valid_source_evidence() {
    let dir = step_dir("invalid-host-record");
    let good = dir.join("good.json");
    let invalid = dir.join("invalid.json");
    let record = serde_json::json!({
        "schema_version": 1,
        "source_id": "valid-source",
        "kind": "web",
        "provider": "webfetch",
        "uri": "https://alpha.test/source",
        "title": "Fixture source",
        "retrieved_at": "2026-08-25T00:00:00Z",
        "text": "A source describes an observed fixture result.",
        "metadata": {"request_receipt": "fixture-request"}
    });
    let mut route = ResearchRoute::host_injected_with("fixture query", "medical", "public");
    route.provider = "domain-default".into();
    route.operation = "advise".into();
    route.methods = vec!["web".into(), "authority".into()];
    route.allowed_effects = vec![
        "search".into(),
        "fetch".into(),
        "extract".into(),
        "synthesize".into(),
    ];
    route.subject.issue = Some("fixture query".into());
    route.subject.patient = Some(ResearchPatient {
        kind: "anonymous".into(),
        history_available: Some(false),
        ..ResearchPatient::default()
    });
    let route_path = dir.join("route.json");
    std::fs::write(&good, serde_json::to_vec(&record).unwrap()).unwrap();
    std::fs::write(&invalid, b"not-json").unwrap();
    std::fs::write(&route_path, serde_json::to_vec(&route).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_legion"))
        .args([
            "research",
            "--query",
            "fixture query",
            "--route-json",
            route_path.to_str().unwrap(),
            "--min-independent-providers",
            "1",
            "--source-record",
            good.to_str().unwrap(),
            "--source-record",
            invalid.to_str().unwrap(),
        ])
        .output()
        .expect("native Legion research must execute");
    let _ = std::fs::remove_dir_all(dir);

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "partial");
    assert_eq!(value["evidence"].as_array().unwrap().len(), 1);
    assert!(value["failures"].as_array().unwrap().iter().any(|failure| {
        failure["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("invalid source record"))
    }));
}
