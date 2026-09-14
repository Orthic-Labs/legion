use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

fn digest(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|value| {
        value.len() == 71
            && value.starts_with("sha256:")
            && value[7..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn same_binding(actual: Option<&Value>, expected: Option<&Value>) -> bool {
    let Some(actual) = actual.and_then(Value::as_object) else {
        return false;
    };
    let Some(expected) = expected.and_then(Value::as_object) else {
        return false;
    };
    actual.get("repositoryRevision") == expected.get("repositoryRevision")
        && actual.get("digest") == expected.get("digest")
}

fn expired(value: &str, now: Option<&str>) -> bool {
    // Node uses Date.parse.  This accepts the canonical UTC forms used by
    // evidence receipts while remaining dependency-free in the audit crate.
    fn parse(raw: &str) -> Option<i64> {
        let normalized = raw.strip_suffix('Z').unwrap_or(raw);
        let parts = normalized.split(['-', 'T', ':', '.']).collect::<Vec<_>>();
        if parts.len() < 6 {
            return None;
        }
        let nums = parts[..6]
            .iter()
            .map(|item| item.parse::<i64>().ok())
            .collect::<Option<Vec<_>>>()?;
        // Howard Hinnant's civil-date conversion.
        let (year, month) = (nums[0], nums[1]);
        let adjusted = year - i64::from(month <= 2);
        let era = (if adjusted >= 0 {
            adjusted
        } else {
            adjusted - 399
        }) / 400;
        let year_of_era = adjusted - era * 400;
        let month_prime = month + if month > 2 { -3 } else { 9 };
        let day_of_year = (153 * month_prime + 2) / 5 + nums[2] - 1;
        let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
        Some((era * 146097 + day_of_era - 719468) * 86400 + nums[3] * 3600 + nums[4] * 60 + nums[5])
    }
    let Some(expiry) = parse(value) else {
        return true;
    };
    let Some(current) = now.and_then(parse) else {
        return true;
    };
    expiry <= current
}

/// Port of `validateEvidenceRefs` from `evidence-authority.mjs`.
pub fn validate_refs(refs: Option<&Value>, authority: &Value) -> Vec<String> {
    let Some(refs) = refs.and_then(Value::as_array) else {
        return vec!["evidence-refs-empty".into()];
    };
    if refs.is_empty() {
        return vec!["evidence-refs-empty".into()];
    }
    let index = authority.get("evidenceIndex").and_then(Value::as_object);
    let root = authority.get("root").and_then(Value::as_str);
    let binding = authority.get("binding");
    let now = authority.get("now").and_then(Value::as_str);
    let mut errors = Vec::new();
    for item in refs {
        let reference = item
            .as_str()
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| item.to_string());
        let Some(record) = index
            .and_then(|items| items.get(&reference))
            .and_then(Value::as_object)
        else {
            errors.push(format!("evidence-ref-missing:{reference}"));
            continue;
        };
        if !digest(record.get("digest")) {
            errors.push(format!("evidence-digest-invalid:{reference}"));
        }
        if !same_binding(record.get("binding"), binding) {
            errors.push(format!("evidence-binding-mismatch:{reference}"));
        }
        if let Some(expires) = record.get("expiresAt").and_then(Value::as_str) {
            if expired(expires, now) {
                errors.push(format!("evidence-expired:{reference}"));
            }
        }
        let path = record.get("path").and_then(Value::as_str);
        if root.is_none() || path.is_none() {
            errors.push(format!("evidence-path-missing:{reference}"));
        } else {
            let path = Path::new(root.unwrap()).join(path.unwrap());
            match std::fs::read(path) {
                Ok(bytes) => {
                    let actual = format!("sha256:{}", hex::encode(Sha256::digest(bytes)));
                    if Some(actual.as_str()) != record.get("digest").and_then(Value::as_str) {
                        errors.push(format!("evidence-bytes-mismatch:{reference}"));
                    }
                }
                Err(_) => errors.push(format!("evidence-bytes-missing:{reference}")),
            }
        }
        if record
            .get("storageReceipt")
            .and_then(Value::as_object)
            .and_then(|o| o.get("immutable"))
            .and_then(Value::as_bool)
            != Some(true)
        {
            errors.push(format!("evidence-storage-unproven:{reference}"));
        }
        if record
            .get("toolReceipt")
            .and_then(Value::as_object)
            .and_then(|o| o.get("complete"))
            .and_then(Value::as_bool)
            != Some(true)
            || !digest(
                record
                    .get("toolReceipt")
                    .and_then(Value::as_object)
                    .and_then(|o| o.get("tool"))
                    .and_then(Value::as_object)
                    .and_then(|o| o.get("executableDigest")),
            )
        {
            errors.push(format!("evidence-tool-unproven:{reference}"));
        }
    }
    errors
}

pub fn authority(
    plan: Option<&Value>,
    artifacts: Option<&Value>,
    root: Option<&Value>,
    now: Option<&str>,
) -> Value {
    let mut object = Map::new();
    if let Some(root) = root.and_then(Value::as_str).or_else(|| {
        artifacts
            .and_then(|value| value.get("root"))
            .and_then(Value::as_str)
    }) {
        object.insert("root".into(), Value::String(root.into()));
    }
    if let Some(index) = artifacts.and_then(|value| value.get("evidenceIndex")) {
        object.insert("evidenceIndex".into(), index.clone());
    }
    if let Some(binding) = plan.and_then(|value| value.get("binding")) {
        object.insert("binding".into(), binding.clone());
    }
    if let Some(now) = now {
        object.insert("now".into(), Value::String(now.into()));
    }
    Value::Object(object)
}
