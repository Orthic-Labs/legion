use legion_arcane::{
    dispatch_governance_judgment, JudgmentControlCapability, ReceiptStore,
};
use serde_json::json;
use std::path::PathBuf;

fn temp_cwd(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "legion-judgment-{}-{}",
        name,
        ((std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()).wrapping_shl(20) | ({ static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0); u128::from(SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)) }))
    ));
    std::fs::create_dir_all(&path).expect("temp cwd");
    path
}

#[test]
fn verify_closure_without_host_fn_is_internal_error() {
    let cwd = temp_cwd("closure");
    let capability = JudgmentControlCapability::from_cwd(&cwd, None).expect("capability");
    let result = dispatch_governance_judgment(
        &json!({
            "operation": "finding.verify-closure",
            "payload": {},
        }),
        Some(&capability),
    );
    assert_eq!(result["allowed"], false);
    assert_eq!(result["code"], "ARC_INTERNAL_ERROR");
}

#[test]
fn deficit_classify_without_host_fn_is_internal_error() {
    let cwd = temp_cwd("deficit");
    let capability = JudgmentControlCapability::from_cwd(&cwd, None).expect("capability");
    let result = dispatch_governance_judgment(
        &json!({
            "operation": "deficit.classify",
            "payload": {},
        }),
        Some(&capability),
    );
    assert_eq!(result["allowed"], false);
    assert_eq!(result["code"], "ARC_INTERNAL_ERROR");
}

#[test]
fn finding_upsert_persists_across_invocations() {
    let cwd = temp_cwd("upsert");
    let capability = JudgmentControlCapability::from_cwd(&cwd, None).expect("capability");
    let request = json!({
        "operation": "finding.upsert",
        "payload": {
            "finding": {
                "controlId": "C-1",
                "subjectId": "src/a.ts",
                "severity": 2,
            },
            "reviewRoundId": "RR-1",
        },
    });
    let first = dispatch_governance_judgment(&request, Some(&capability));
    assert_eq!(first["allowed"], true);
    let second = dispatch_governance_judgment(
        &json!({
            "operation": "finding.records",
            "payload": {},
        }),
        Some(&capability),
    );
    assert_eq!(second["allowed"], true);
    assert_eq!(
        second["detail"]["records"].as_array().map(|items| items.len()),
        Some(1)
    );
    let receipt_root = cwd.join(".audit").join("arcane").join("receipts");
    let store = ReceiptStore::new(receipt_root).expect("receipt store");
    let reloaded = JudgmentControlCapability::from_cwd(&cwd, None).expect("reload");
    let third = dispatch_governance_judgment(
        &json!({
            "operation": "finding.records",
            "payload": {},
        }),
        Some(&reloaded),
    );
    assert_eq!(
        third["detail"]["records"].as_array().map(|items| items.len()),
        Some(1)
    );
    assert!(
        store
            .list()
            .iter()
            .any(|record| record.get("kind") == Some(&json!("arcane-governance-finding-state")))
    );
}
