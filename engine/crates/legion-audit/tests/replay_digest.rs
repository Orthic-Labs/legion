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
