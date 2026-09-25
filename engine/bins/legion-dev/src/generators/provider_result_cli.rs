//! CLI surface over `legion_contracts::provider_result`, ported from
//! `scripts/normalize-provider-result.mjs`'s direct-run self-test block
//! (the JS file is a library; run directly it prints
//! `OK: normalize-provider-result.mjs self-test passed`) plus a
//! `--contract`/`--raw` file-normalizing mode for actual pipeline use.

use std::path::Path;

use legion_contracts::provider_result::{normalize_provider_result, validate_provider_result};
use serde_json::json;

fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn self_test() -> bool {
    let test_result = normalize_provider_result(
        &json!({"id": "test.provider", "denominator": {"pathDigest": "sha256:test"}, "benchmark": {"requiredForCleanClaim": true}}),
        &json!({"status": "pass", "complete": true, "findings": []}),
    );
    let test_result = match test_result {
        Ok(v) => v,
        Err(e) => {
            eprintln!("FAIL: self-test normalize failed: {e}");
            return false;
        }
    };
    let mut ok = true;
    ok &= assert_eq_print(test_result["provider"] == "test.provider", "provider preserved");
    ok &= assert_eq_print(test_result["status"] == "pass", "status preserved");
    ok &= assert_eq_print(test_result["coverage"]["denominatorDigest"] == "sha256:test", "digest bound");
    ok &= assert_eq_print(test_result["required"] == true, "required from contract");
    ok &= assert_eq_print(test_result["degradation"].is_array(), "degradation normalized to array");

    match validate_provider_result(&json!({"schemaVersion": 1, "provider": "x", "status": "invalid-status", "complete": true})) {
        Ok(()) => {
            eprintln!("FAIL: should have rejected invalid status");
            ok = false;
        }
        Err(e) => ok &= assert_eq_print(e.field == "status", "rejected invalid status"),
    }

    match validate_provider_result(&json!({"schemaVersion": 1, "provider": "x", "status": "pass", "complete": true, "findings": null})) {
        Ok(()) => {
            eprintln!("FAIL: should have rejected null findings");
            ok = false;
        }
        Err(e) => ok &= assert_eq_print(e.field == "findings", "rejected null findings array"),
    }

    if ok {
        println!("OK: normalize-provider-result.mjs self-test passed");
    }
    ok
}

fn assert_eq_print(cond: bool, label: &str) -> bool {
    if !cond {
        eprintln!("assertion failed: {label}");
    }
    cond
}

/// `legion-dev normalize-provider-result [--contract PATH --raw PATH | --self-test]`
pub fn run(contract: Option<&Path>, raw: Option<&Path>, self_test_flag: bool) -> bool {
    if self_test_flag || (contract.is_none() && raw.is_none()) {
        return self_test();
    }
    let contract_value = match contract.map(read_json) {
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            eprintln!("normalize-provider-result: {e}");
            return false;
        }
        None => serde_json::Value::Null,
    };
    let raw_value = match raw.map(read_json) {
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            eprintln!("normalize-provider-result: {e}");
            return false;
        }
        None => serde_json::Value::Null,
    };
    match normalize_provider_result(&contract_value, &raw_value) {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            true
        }
        Err(e) => {
            eprintln!("normalize-provider-result: {e}");
            false
        }
    }
}
