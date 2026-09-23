//! Integration-level parity tests for the wf025 packet: faithful Rust ports
//! of `src/lib/research-core/{events,gap_critic,independence,ledger,manifest}.py`.
//! No dedicated Python test files exist for these five scripts under
//! `src/lib/research-core/tests`, so these exercise the ported public API
//! end to end (independence clustering feeding the ledger, the ledger
//! feeding gap_critic, and a full manifest run lifecycle) rather than
//! porting fixed Python test assertions.
//!
//! NOTE: this file depends on `pub mod wf_port;` (with `pub mod wf025;`
//! inside it) landing in `src/lib.rs` — a shared file this packet does not
//! own. Until the integrator applies that wiring (see the packet report),
//! this file will not compile, mirroring wf024's `research_port_stopping.rs`
//! precedent.

use legion_research::wf_port::wf025::{
    gap_critic_review, independence_cluster, ledger_check, ledger_render, record_event,
};
use legion_research::wf_port::wf025::manifest::{
    approve, attach_artifact, create_run, finalize, load_run, resume_position, set_stage,
};
use serde_json::json;

fn ok_evidence(id: &str, url: &str) -> serde_json::Value {
    json!({
        "id": id, "url": url, "publisher": "Example", "retrieved_at": "2024-01-01",
        "locator": "p1", "suggested_by": "user", "seed_chain": ["seed"],
        "instructionPolicy": "data_only", "quote_or_paraphrase": "some passage text",
        "is_primary": true
    })
}

#[test]
fn independence_then_ledger_then_gap_critic_pipeline() {
    // Two evidence rows that are the same URL modulo tracking params: they
    // land in one independence cluster, so a benchmark claim citing both
    // still only has one independent cluster and is downgraded from high.
    let evidence = vec![
        ok_evidence("e1", "https://example.com/report?utm_source=x"),
        ok_evidence("e2", "https://example.com/report"),
    ];
    let clustered = independence_cluster(&evidence);
    assert_eq!(clustered.unique_voices, 1);

    // gap_critic.py's `review` derives each claim's cluster count from
    // `s.get('independence_cluster') or s['id']` — it reads the field the
    // independence pass attaches, falling back to the source id (which
    // would wrongly count e1/e2 as two separate clusters). Downstream
    // callers must therefore pass the clustered evidence (with
    // `independence_cluster` set), not the raw input rows.
    let evidence = clustered.evidence.clone();

    let claims = vec![json!({
        "id": "c1", "claim_type": "benchmark", "text": "Product X leads the benchmark",
        "confidence": "high", "status": "supported", "as_of": "2024-01-01",
        "source_ids": ["e1", "e2"]
    })];
    let checked = ledger_check(&evidence, &claims);
    assert!(checked.overall_ok, "ledger should not block on a clean row");
    assert_eq!(checked.claims[0]["confidence"], "medium");

    // gap_critic should still flag the benchmark claim as needing a second
    // independent cluster, since the ledger downgraded rather than removed
    // the gap.
    let gaps = gap_critic_review(&claims, &evidence, None);
    assert!(!gaps.complete);
    assert!(gaps.findings[0]
        .gaps
        .iter()
        .any(|g| g.contains("independent evidence clusters")));
}

#[test]
fn ledger_render_produces_findings_and_sources_sections() {
    let evidence = vec![ok_evidence("e1", "https://example.com/a")];
    let claims = vec![json!({
        "id": "c1", "claim_type": "observation", "text": "The sky is blue",
        "confidence": "low", "status": "supported", "as_of": "2024-01-01",
        "source_ids": ["e1"]
    })];
    let rendered = ledger_render(&evidence, &claims, "Sky brief").expect("clean ledger renders");
    assert!(rendered.starts_with("# Sky brief"));
    assert!(rendered.contains("[OBS] The sky is blue"));
    assert!(rendered.contains("[+e1]"));
    assert!(rendered.contains("## Sources"));
    assert!(rendered.contains("cluster:"));
}

#[test]
fn manifest_run_lifecycle_blocks_approves_and_finalizes() {
    let mut root = std::env::temp_dir();
    root.push(format!("legion-wf025-integration-{}", std::process::id()));

    let route = json!({"kind": "integration-test"});
    let budget = json!({"external_requests": 8, "workers": 1});
    let manifest = create_run("integration test query", &route, &budget, Some(&root))
        .expect("create_run should succeed");
    let run_id = manifest["run_id"].as_str().unwrap().to_string();
    assert_eq!(manifest["status"], "running");
    assert_eq!(manifest["stages"]["route"]["status"], "done");

    let resume = resume_position(&manifest);
    assert_eq!(resume["next_stage"], "acquire");

    record_event(&run_id, "custom.checkpoint", Some(&json!({"note": "started"})), Some(&root))
        .expect("record_event should append");

    let blocked = set_stage(&run_id, "acquire", "blocked", Some("needs-human"), Some(&root))
        .expect("set_stage should succeed");
    assert_eq!(blocked["status"], "blocked");
    assert_eq!(blocked["blocked_on"][0], "needs-human");

    let approved = approve(&run_id, "needs-human", "approved by operator", "adrian", Some(&root))
        .expect("approve should succeed");
    assert_eq!(approved["status"], "running");
    assert!(approved["blocked_on"].as_array().unwrap().is_empty());
    assert_eq!(approved["approvals"]["needs-human"]["actor"], "adrian");

    set_stage(&run_id, "acquire", "done", None, Some(&root)).expect("set_stage done");
    let with_artifact = attach_artifact(&run_id, "report", "runs/report.md", Some("deadbeef"), Some(&root))
        .expect("attach_artifact should succeed");
    assert_eq!(with_artifact["artifacts"]["report"]["path"], "runs/report.md");

    let receipt = finalize(&run_id, "ship", &json!({"ledger_ok": true}), Some(&root))
        .expect("finalize should succeed");
    assert_eq!(receipt["verdict"], "ship");
    let final_manifest = load_run(&run_id, Some(&root)).expect("load_run should succeed");
    assert_eq!(final_manifest["status"], "done");

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn manifest_finalize_block_verdict_sets_ship_gate() {
    let mut root = std::env::temp_dir();
    root.push(format!("legion-wf025-integration-block-{}", std::process::id()));

    let manifest = create_run("q", &json!({}), &json!({}), Some(&root)).unwrap();
    let run_id = manifest["run_id"].as_str().unwrap().to_string();

    let receipt = finalize(&run_id, "block", &json!({"ledger_ok": false}), Some(&root)).unwrap();
    assert_eq!(receipt["verdict"], "block");
    let final_manifest = load_run(&run_id, Some(&root)).unwrap();
    assert_eq!(final_manifest["status"], "blocked");
    assert_eq!(final_manifest["blocked_on"][0], "ship-gate");

    let _ = std::fs::remove_dir_all(&root);
}
