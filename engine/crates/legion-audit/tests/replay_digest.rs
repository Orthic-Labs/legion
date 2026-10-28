//! Replay-equivalence digest: volatile-only differences compare equal; any
//! semantic difference does not; byte-integrity digests stay distinct.

use legion_audit::{replay_differences, replay_digest, replay_normalize};
use serde_json::json;

fn run(started: &str, tmp: &str, ms: u64, extra_finding: bool) -> serde_json::Value {
    let mut findings = vec![
        json!({"id": "b", "severity": "high", "path": "src/b.rs"}),
        json!({"id": "a", "severity": "low", "path": "src/a.rs"}),
    ];
    if extra_finding {
        findings.push(json!({"id": "c", "severity": "high", "path": "src/c.rs"}));
    }
    json!({
        "report.json": {
            "status": "findings",
            "generatedAt": started,
            "durationMs": ms,
            "findings": findings,
            "gaps": ["gap-two", "gap-one"],
            "claims": {"executionRoot": format!("{tmp}/work"), "note": format!("scanned {tmp}/x/src")},
        },
        "plan.json": {
            "seal": {"digest": "sha256:aa", "signature": format!("hmac-sha256:{started}")},
            "planKey": {"runId": started, "keyId": started},
            "epoch": {"digest": started},
            "providers": ["p2", "p1"],
        }
    })
}

#[test]
fn volatile_only_differences_are_replay_equivalent() {
    let a = run("2026-10-23T01:00:00Z", "/private/tmp/aaa111", 120, false);
    let b = run("2026-10-24T09:30:00Z", "/tmp/bbb222", 9_999, false);
    assert_eq!(replay_digest(&a).unwrap(), replay_digest(&b).unwrap());
    assert!(replay_differences(&a, &b).is_empty());
    // Temp paths embedded in prose collapse to the same token.
    let note = |value: &serde_json::Value| {
        replay_normalize(value)["report.json"]["claims"]["note"].clone()
    };
    assert_eq!(note(&a), note(&b));
}

#[test]
fn semantic_differences_change_the_digest_and_name_the_field() {
    let a = run("t1", "/tmp/a", 1, false);
    let b = run("t2", "/tmp/b", 2, true);
    assert_ne!(replay_digest(&a).unwrap(), replay_digest(&b).unwrap());
    let paths = replay_differences(&a, &b);
    assert!(
        paths.iter().any(|p| p.starts_with("/report.json/findings")),
        "{paths:?}"
    );
    // A changed severity is also caught.
    let mut c = run("t1", "/tmp/a", 1, false);
    c["report.json"]["findings"][0]["severity"] = json!("critical");
    assert_ne!(replay_digest(&a).unwrap(), replay_digest(&c).unwrap());
    // A missing artifact never equals a present one.
    let mut d = run("t1", "/tmp/a", 1, false);
    d["plan.json"] = serde_json::Value::Null;
    assert_ne!(replay_digest(&a).unwrap(), replay_digest(&d).unwrap());
}

#[test]
fn replay_digest_is_distinct_from_byte_integrity_digest() {
    let value = run("t1", "/tmp/a", 1, false);
    let replay = replay_digest(&value).unwrap();
    let integrity = legion_audit::digest(&value).unwrap();
    assert!(replay.starts_with("replay-sha256:"));
    assert!(integrity.starts_with("sha256:"));
    assert_ne!(replay.trim_start_matches("replay-"), integrity);
    // Byte integrity still sees the volatile difference.
    let other = run("t2", "/tmp/a", 1, false);
    assert_ne!(
        legion_audit::digest(&value).unwrap(),
        legion_audit::digest(&other).unwrap()
    );
}

#[test]
fn configured_bounds_are_semantic_but_known_timestamps_are_ignored() {
    let a = json!({"provider": {"timeoutMs": 1000}, "createdAt": "a", "durationMs": 1});
    let b = json!({"provider": {"timeoutMs": 2000}, "createdAt": "b", "durationMs": 2});
    assert_ne!(replay_digest(&a).unwrap(), replay_digest(&b).unwrap());
    let c = json!({"provider": {"timeoutMs": 1000}, "createdAt": "z", "durationMs": 9});
    assert_eq!(replay_digest(&a).unwrap(), replay_digest(&c).unwrap());
}

#[test]
fn temp_path_rewrite_keeps_message_and_distinct_subpaths() {
    let msg = |t: &str| json!({"note": t});
    assert_ne!(
        replay_digest(&msg("writes /tmp/x.sh then deletes data")).unwrap(),
        replay_digest(&msg("writes /tmp/x.sh then reads data")).unwrap()
    );
    assert_ne!(
        replay_digest(&msg("/tmp/a/f")).unwrap(),
        replay_digest(&msg("/tmp/b/f")).unwrap()
    );
}

fn windows_syft_receipts(scratch: &str) -> serde_json::Value {
    let receipt = |format: &str| {
        json!({
            "providerId": "supply-chain.license-sbom-provenance",
            "state": "unauthorized-effect",
            "command": {
                "executable": "syft",
                "args": ["scan", "dir:.", "--config", format!(r"<run>\{scratch}\syft-native.yaml"),
                    "--override-default-catalogers", "all", "-o", format, "-q"],
            },
            "timeoutMs": 120000,
        })
    };
    json!({
        "executionReceipt": receipt("cyclonedx-json"),
        "executionReceipts": [receipt("cyclonedx-json"), receipt("spdx-json")],
    })
}

#[test]
fn windows_syft_scratch_directories_are_replay_equivalent_without_mutating_receipts() {
    let a = windows_syft_receipts("legion-audit-security-8180-1793195200123456789-2");
    let b = windows_syft_receipts("legion-audit-security-9440-1793195200987654321-7");
    let original_a = serde_json::to_vec(&a).unwrap();
    let original_b = serde_json::to_vec(&b).unwrap();
    assert_eq!(replay_digest(&a).unwrap(), replay_digest(&b).unwrap());
    assert!(replay_differences(&a, &b).is_empty());
    assert_eq!(
        replay_normalize(&a)["executionReceipt"]["command"]["args"][3],
        r"<run>\legion-audit-security-N-N-N\syft-native.yaml"
    );
    assert_eq!(serde_json::to_vec(&a).unwrap(), original_a);
    assert_eq!(serde_json::to_vec(&b).unwrap(), original_b);
    assert_ne!(
        legion_audit::digest(&a).unwrap(),
        legion_audit::digest(&b).unwrap()
    );
}

#[test]
fn windows_syft_replay_keeps_semantic_command_and_receipt_differences() {
    let a = windows_syft_receipts("legion-audit-security-8180-1793195200123456789-2");
    let replacement = r"<run>\legion-audit-security-9999-1793195200987654321-7\changed.yaml";
    let mut filename = a.clone();
    filename["executionReceipt"]["command"]["args"][3] = json!(replacement);
    let mut argument = a.clone();
    argument["executionReceipt"]["command"]["args"][7] = json!("other-format");
    let mut bound = a.clone();
    bound["executionReceipt"]["timeoutMs"] = json!(120001);
    let mut kind = a.clone();
    kind["executionReceipt"]["command"]["args"][3] =
        json!(r"<run>\legion-audit-other-8180-1793195200123456789-2\syft-native.yaml");
    for changed in [filename, argument, bound, kind] {
        assert_ne!(replay_digest(&a).unwrap(), replay_digest(&changed).unwrap());
        assert!(!replay_differences(&a, &changed).is_empty());
    }
}

#[test]
fn windows_scratch_rewrite_preserves_unrecognized_names_separators_and_prose() {
    let note = |text: &str| replay_normalize(&json!({"note": text}))["note"].clone();
    for text in [
        r"<run>\legion-audit-other-123-456-7\syft-native.yaml",
        r"<run>\legion-audit-security-123-456\syft-native.yaml",
        r"<run>\legion-audit-security-123-456-7-8\syft-native.yaml",
        r"<run>\legion-audit-security-123-456-x\syft-native.yaml",
        r"<run>\legion-audit-security-123--7\syft-native.yaml",
        r"<run>\legion-audit-security-123-456-7.yaml",
        r"<run>\prefix-legion-audit-security-123-456-7\syft-native.yaml",
        "generated legion-audit-security-123-456-7 then scanned 42 files",
    ] {
        assert_eq!(note(text), json!(text), "{text}");
    }
    assert_eq!(
        note(
            r"scanned '<run>\legion-audit-security-123-456-7\syft-native.yaml' then kept 42 findings"
        ),
        r"scanned '<run>\legion-audit-security-N-N-N\syft-native.yaml' then kept 42 findings"
    );
    assert_eq!(
        note(r"<run>\\legion-audit-security-123-456-7\syft-native.yaml"),
        r"<run>\\legion-audit-security-N-N-N\syft-native.yaml"
    );
    assert_ne!(
        note(r"scanned <run>\legion-audit-security-123-456-7\syft-native.yaml then deleted data"),
        note(r"scanned <run>\legion-audit-security-890-987-6\syft-native.yaml then retained data")
    );
}
