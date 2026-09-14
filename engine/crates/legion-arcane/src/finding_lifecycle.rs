use crate::decision::decision;
use legion_contracts::canonical_digest;
use serde_json::{json, Map, Value};
use std::sync::Mutex;

fn id(value: &Value, camel: &str, snake: &str) -> Option<String> {
    value
        .get(camel)
        .or_else(|| value.get(snake))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn finding_identity(finding: &Value) -> Result<Map<String, Value>, String> {
    let control_id = id(finding, "controlId", "control_id")
        .or_else(|| id(finding, "ruleId", "rule_id"))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "finding controlId or ruleId is required".to_string())?;
    let subject_id = id(finding, "subjectId", "subject_id")
        .or_else(|| finding.get("file").and_then(Value::as_str).map(str::to_owned))
        .or_else(|| finding.get("path").and_then(Value::as_str).map(str::to_owned))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "finding subjectId is required".to_string())?;
    let semantic_key = id(finding, "semanticKey", "semantic_key").or_else(|| {
        id(finding, "conditionFingerprint", "condition_fingerprint")
    });
    let mut object = Map::new();
    object.insert("control_id".into(), json!(control_id));
    object.insert("subject_id".into(), json!(subject_id));
    if let Some(key) = semantic_key {
        object.insert("semantic_key".into(), json!(key));
    }
    Ok(object)
}

pub fn fingerprint_finding(finding: &Value) -> Result<String, String> {
    canonical_digest(&finding_identity(finding)?).map_err(|error| error.to_string())
}

pub fn upsert_finding(records: &[Value], finding: &Value, review_round_id: &str) -> Value {
    let stable_fingerprint = fingerprint_finding(finding).unwrap_or_default();
    let existing = records.iter().find(|record| {
        record.get("stable_fingerprint").and_then(Value::as_str) == Some(&stable_fingerprint)
            || record.get("stableFingerprint").and_then(Value::as_str) == Some(&stable_fingerprint)
    });
    let mut observation = finding_identity(finding).unwrap_or_default();
    observation.insert("stable_fingerprint".into(), json!(stable_fingerprint));
    let record = json!({
        "id": existing
            .and_then(|value| value.get("id").cloned())
            .unwrap_or(json!(stable_fingerprint)),
        "stable_fingerprint": stable_fingerprint,
        "review_round_id": existing
            .and_then(|value| value.get("review_round_id").or_else(|| value.get("reviewRoundId")).cloned())
            .unwrap_or(json!(review_round_id)),
        "status": existing
            .and_then(|value| value.get("status").cloned())
            .unwrap_or(json!("OPEN")),
        "observation": observation,
    });
    let next = if existing.is_some() {
        records
            .iter()
            .map(|item| {
                if item.get("stable_fingerprint").and_then(Value::as_str) == Some(&stable_fingerprint)
                    || item.get("stableFingerprint").and_then(Value::as_str) == Some(&stable_fingerprint)
                {
                    record.clone()
                } else {
                    item.clone()
                }
            })
            .collect::<Vec<_>>()
    } else {
        records.iter().cloned().chain([record.clone()]).collect()
    };
    json!({
        "records": next,
        "record": record,
        "disposition": if existing.is_some() { "EXISTING_RECORD" } else { "NEW_RECORD" },
        "event": {
            "event_type": "FINDING_UPSERTED",
            "payload": record,
        },
    })
}

pub struct FindingLifecycleStore {
    records: Mutex<Vec<Value>>,
}

impl FindingLifecycleStore {
    pub fn new(records: Vec<Value>) -> Self {
        Self {
            records: Mutex::new(records),
        }
    }

    pub fn records(&self) -> Vec<Value> {
        self.records.lock().unwrap().clone()
    }

    pub fn upsert(&self, finding: &Value, review_round_id: &str) -> Value {
        let records = self.records.lock().unwrap().clone();
        let result = upsert_finding(&records, finding, review_round_id);
        if let Some(next) = result.get("records").and_then(Value::as_array) {
            *self.records.lock().unwrap() = next.clone();
        }
        result
    }
}

fn evidence_value(evidence: &Value, camel: &str, snake: &str) -> Option<String> {
    evidence
        .get(camel)
        .or_else(|| evidence.get(snake))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

pub fn verify_finding_closure(input: &Value) -> Value {
    let finding = input.get("finding").unwrap_or(&Value::Null);
    let closure = input.get("closure").unwrap_or(&Value::Null);
    let evidence = input.get("evidence").unwrap_or(&Value::Null);
    let finding_fingerprint = fingerprint_finding(finding).unwrap_or_default();
    let fix_author_id = id(closure, "fixAuthorId", "fix_author_id");
    let reviewer_id = id(closure, "reviewerId", "reviewer_id");
    let evidence_reviewer_id = evidence_value(evidence, "reviewerId", "reviewer_id");
    let evidence_finding_fingerprint =
        evidence_value(evidence, "findingFingerprint", "finding_fingerprint");
    let evidence_id = evidence_value(evidence, "evidenceId", "evidence_id");
    let expected_artifact_fingerprint =
        evidence_value(closure, "artifactFingerprint", "artifact_fingerprint");
    let observed_artifact_fingerprint =
        evidence_value(evidence, "artifactFingerprint", "artifact_fingerprint");
    if fix_author_id.is_none()
        || reviewer_id.is_none()
        || evidence_reviewer_id.is_none()
        || evidence_finding_fingerprint.is_none()
        || evidence_id.is_none()
        || expected_artifact_fingerprint.is_none()
        || observed_artifact_fingerprint.is_none()
    {
        return decision(
            false,
            Some("ARC_EVIDENCE_INSUFFICIENT"),
            Some("fresh independent evidence is required for finding closure"),
            json!({ "finding_fingerprint": finding_fingerprint }),
        );
    }
    if fix_author_id == reviewer_id || fix_author_id.as_ref() == evidence_reviewer_id.as_ref() {
        return decision(
            false,
            Some("ARC_SELF_CERTIFICATION"),
            Some("fix author cannot close own finding; fresh independent evidence is required"),
            json!({
                "finding_fingerprint": finding_fingerprint,
                "fix_author_id": fix_author_id,
            }),
        );
    }
    if reviewer_id.as_ref() != evidence_reviewer_id.as_ref()
        || evidence_finding_fingerprint.as_deref() != Some(finding_fingerprint.as_str())
        || expected_artifact_fingerprint.as_ref() != observed_artifact_fingerprint.as_ref()
    {
        return decision(
            false,
            Some("ARC_BINDING_MISMATCH"),
            Some("closure evidence does not match finding or observed artifact"),
            json!({ "finding_fingerprint": finding_fingerprint }),
        );
    }
    let payload = json!({
        "id": finding_fingerprint,
        "finding_fingerprint": finding_fingerprint,
        "status": "VERIFIED_CLOSED",
        "artifact_fingerprint": observed_artifact_fingerprint,
        "reviewer_id": reviewer_id,
        "evidence_id": evidence_id,
    });
    decision(
        true,
        None,
        Some("finding closure verified from independent artifact evidence"),
        json!({
            "finding": payload,
            "event": {
                "event_type": "FINDING_UPSERTED",
                "payload": payload,
            },
        }),
    )
}

pub fn filter_findings_by_threshold(input: &Value) -> Result<Value, String> {
    let threshold = input
        .get("threshold")
        .and_then(Value::as_i64)
        .filter(|value| *value >= 0)
        .ok_or_else(|| "threshold must be a non-negative integer".to_string())?;
    let findings = input
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let retained = findings
        .into_iter()
        .map(|finding| {
            let severity = severity_value(&finding)?;
            let disposition = if severity >= threshold {
                "BLOCKING"
            } else {
                "INFORMATIONAL"
            };
            let mut object = finding.as_object().cloned().unwrap_or_default();
            object.insert("disposition".into(), json!(disposition));
            Ok(Value::Object(object))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let blocking = retained
        .iter()
        .filter(|finding| finding.get("disposition") == Some(&json!("BLOCKING")))
        .cloned()
        .collect::<Vec<_>>();
    let informational = retained
        .iter()
        .filter(|finding| finding.get("disposition") == Some(&json!("INFORMATIONAL")))
        .cloned()
        .collect::<Vec<_>>();
    Ok(json!({
        "findings": retained,
        "blocking": blocking,
        "informational": informational,
        "deterministic_filter": { "severity_threshold": threshold },
    }))
}

fn severity_value(finding: &Value) -> Result<i64, String> {
    if let Some(value) = finding.get("severity").and_then(Value::as_i64) {
        if value >= 0 {
            return Ok(value);
        }
    }
    if let Some(text) = finding.get("severity").and_then(Value::as_str) {
        let mapped = match text.to_ascii_lowercase().as_str() {
            "informational" => 0,
            "low" => 1,
            "medium" => 2,
            "high" => 3,
            "critical" => 4,
            _ => return Err("finding severity must be a non-negative integer or known severity".into()),
        };
        return Ok(mapped);
    }
    Err("finding severity must be a non-negative integer or known severity".into())
}

pub fn apply_scoped_recheck(input: &Value) -> Result<Value, String> {
    let targets = input
        .get("targetFindingFingerprints")
        .or_else(|| input.get("target_finding_fingerprints"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if targets.is_empty() {
        return Err("scoped recheck requires targetFindingFingerprints".into());
    }
    let target_set = targets
        .iter()
        .filter_map(Value::as_str)
        .collect::<std::collections::HashSet<_>>();
    let records = input
        .get("records")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let closures = input
        .get("closures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let closure_by_fingerprint = closures
        .iter()
        .filter_map(|closure| {
            let fingerprint = closure
                .get("finding_fingerprint")
                .or_else(|| closure.get("findingFingerprint"))
                .and_then(Value::as_str)?;
            Some((fingerprint, closure))
        })
        .collect::<std::collections::HashMap<_, _>>();
    let updated = records
        .iter()
        .map(|record| {
            let fingerprint = record
                .get("stable_fingerprint")
                .or_else(|| record.get("stableFingerprint"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if !target_set.contains(fingerprint) {
                return record.clone();
            }
            let closure = closure_by_fingerprint.get(fingerprint);
            if closure.and_then(|value| value.get("allowed")).and_then(Value::as_bool) != Some(true) {
                return record.clone();
            }
            let mut object = record.as_object().cloned().unwrap_or_default();
            object.insert("status".into(), json!("VERIFIED_CLOSED"));
            if let Some(closure) = closure {
                object.insert(
                    "closure_event".into(),
                    closure
                        .pointer("/detail/event")
                        .cloned()
                        .unwrap_or(Value::Null),
                );
            }
            Value::Object(object)
        })
        .collect::<Vec<_>>();
    let closed = updated
        .iter()
        .filter(|record| {
            let fingerprint = record
                .get("stable_fingerprint")
                .or_else(|| record.get("stableFingerprint"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            target_set.contains(fingerprint) && record.get("status") == Some(&json!("VERIFIED_CLOSED"))
        })
        .cloned()
        .collect::<Vec<_>>();
    let deferred = input
        .get("discoveredFindings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|finding| {
            let mut object = finding.as_object().cloned().unwrap_or_default();
            object.insert("disposition".into(), json!("DEFERRED_INFORMATIONAL"));
            Value::Object(object)
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "records": updated,
        "closed": closed,
        "deferred": deferred,
        "events": closed.iter().map(|record| json!({
            "event_type": "FINDING_UPSERTED",
            "payload": {
                "id": record.get("id").cloned().unwrap_or(Value::Null),
                "stable_fingerprint": record.get("stable_fingerprint").or_else(|| record.get("stableFingerprint")).cloned().unwrap_or(Value::Null),
                "status": record.get("status").cloned().unwrap_or(Value::Null),
            }
        })).collect::<Vec<_>>(),
    }))
}
