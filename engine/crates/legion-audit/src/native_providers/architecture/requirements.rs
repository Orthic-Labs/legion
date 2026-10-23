use super::{
    common::{gap, object_input, truthy, Analysis},
    evidence::validate_refs,
};
use crate::assurance::SnapshotRef;
use crate::domain_contract::{
    BindingStatus, ContractFileInput, DomainContextBinding, DomainContractSet,
};
use serde_json::Value;
const STATES: &[&str] = &[
    "implemented-and-verified",
    "implemented-unverified",
    "missing",
    "contradicted",
    "ambiguous",
    "superseded",
    "deferred",
    "unproven",
    "aspirational",
];

pub fn trace_requirement(value: &Value) -> Result<Value, String> {
    let object = object_input(value)?;
    if !truthy(object.get("id"))
        || !truthy(object.get("authority"))
        || !truthy(object.get("owner"))
        || !object
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| STATES.contains(&status))
    {
        return Err("invalid requirement disposition".into());
    }
    let evidence = object
        .get("evidence")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if object["status"] == "implemented-and-verified" && evidence.is_empty() {
        return Err("verified requirement requires evidence".into());
    }
    let mut result = object.clone();
    result.insert("evidence".into(), Value::Array(evidence));
    if !result.contains_key("edges") || result["edges"].is_null() {
        result.insert("edges".into(), Value::Array(Vec::new()));
    }
    Ok(Value::Object(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn requirement(status: Value) -> Value {
        json!({
            "id": "req-1",
            "authority": "product",
            "owner": "team",
            "status": status,
        })
    }

    #[test]
    fn accepts_every_requirement_status() {
        for status in STATES {
            let mut value = requirement(json!(status));
            if *status == "implemented-and-verified" {
                value["evidence"] = json!(["evidence-1"]);
            }
            assert!(trace_requirement(&value).is_ok(), "{status}");
        }
    }

    #[test]
    fn rejects_missing_non_string_and_unknown_statuses() {
        for status in [None, Some(json!(42)), Some(json!("unknown"))] {
            let mut value = requirement(status.clone().unwrap_or(Value::Null));
            if status.is_none() {
                value.as_object_mut().unwrap().remove("status");
            }
            assert!(trace_requirement(&value).is_err());
        }
    }

    #[test]
    fn rejects_missing_required_metadata() {
        for field in ["id", "authority", "owner"] {
            let mut value = requirement(json!("missing"));
            value.as_object_mut().unwrap().remove(field);
            assert!(trace_requirement(&value).is_err(), "{field}");
        }
    }

    #[test]
    fn verified_requires_non_empty_evidence() {
        for evidence in [None, Some(json!([]))] {
            let mut value = requirement(json!("implemented-and-verified"));
            if let Some(evidence) = evidence {
                value["evidence"] = evidence;
            }
            assert!(trace_requirement(&value).is_err());
        }
    }

    #[test]
    fn verified_accepts_non_empty_evidence_array() {
        let value = requirement(json!("implemented-and-verified"));
        let value = {
            let mut value = value;
            value["evidence"] = json!(["evidence-1"]);
            value
        };
        let output = trace_requirement(&value).unwrap();
        assert_eq!(output["evidence"], json!(["evidence-1"]));
    }

    #[test]
    fn non_verified_missing_evidence_normalizes_to_empty_array() {
        let output = trace_requirement(&requirement(json!("missing"))).unwrap();
        assert_eq!(output["evidence"], json!([]));
    }
}

pub fn analyze(input: &Value) -> Result<Analysis, String> {
    let object = object_input(input)?;
    let requirements = object
        .get("artifacts")
        .and_then(|v| v.get("requirements"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let authority = super::evidence::authority(
        object.get("plan"),
        object.get("artifacts"),
        object.get("root"),
        object.get("now").and_then(Value::as_str),
    );
    let mut normalized = Vec::new();
    let mut gaps = Vec::new();
    for requirement in &requirements {
        match trace_requirement(requirement) {
            Ok(row) => {
                if row["status"] == "implemented-and-verified" {
                    let errors = validate_refs(row.get("evidence"), &authority);
                    if !errors.is_empty() {
                        gaps.push(serde_json::json!({"kind":"requirement-trace-invalid","reason":errors.join(",")}));
                        continue;
                    }
                }
                normalized.push(row)
            }
            Err(error) => {
                gaps.push(serde_json::json!({"kind":"requirement-trace-invalid","reason":error}))
            }
        }
    }
    if requirements.is_empty() {
        gaps.push(gap("requirement-denominator-zero"));
    }
    let domain = domain_contracts(object.get("artifacts"), &mut normalized, &mut gaps);
    let findings = normalized
        .iter()
        .filter(|row| {
            !matches!(
                row["status"].as_str(),
                Some("implemented-and-verified" | "superseded" | "deferred" | "aspirational")
            )
        })
        .cloned()
        .collect();
    let mut result = Analysis::new(
        if gaps.is_empty() { "pass" } else { "unproven" },
        gaps.is_empty(),
        serde_json::json!({"kind":"requirements","expected":requirements.len(),"examined":normalized.len()}),
    );
    result.findings = findings;
    if let Some(evaluation) = domain {
        // Domain candidates are scoped SPEC-axis findings; STANDARDS verdicts
        // stay with their own lens (see TermDisposition.standards).
        for candidate in &evaluation.candidates {
            let mut value = serde_json::to_value(candidate).unwrap_or(Value::Null);
            if let Some(map) = value.as_object_mut() {
                map.insert(
                    "kind".into(),
                    Value::String("domain-contract-violation".into()),
                );
            }
            result.findings.push(value);
        }
        result
            .extras
            .insert("domainContracts".into(), evaluation.to_value());
        result.complete = result.complete && gaps.is_empty();
    }
    result.coverage_gaps = gaps;
    Ok(result)
}

/// Evaluate `artifacts.domainContracts` when present. Absent key means the
/// caller asked for no domain check: nothing is invented. Present-but-
/// unresolved input becomes coverage gaps (never clean). Requirement rows
/// listing `domainTerms` are bound to the scoped contract digest; unresolved
/// terms add a gap rather than a guessed mapping.
///
/// Expected shape:
/// `{required, snapshots:[{repositoryId,snapshotDigest}],
///   files:[{repositoryId,path,content,digest?}], priorBinding?}`
fn domain_contracts(
    artifacts: Option<&Value>,
    rows: &mut [Value],
    gaps: &mut Vec<Value>,
) -> Option<crate::domain_contract::DomainEvaluation> {
    let spec = artifacts?.get("domainContracts")?;
    let required = spec
        .get("required")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let snapshots: Vec<SnapshotRef> = match spec
        .get("snapshots")
        .cloned()
        .map(serde_json::from_value)
        .unwrap_or_else(|| Ok(Vec::new()))
    {
        Ok(snapshots) => snapshots,
        Err(error) => {
            gaps.push(serde_json::json!({"kind":"domain-contract-unresolved","reason":format!("invalid snapshots: {error}")}));
            Vec::new()
        }
    };
    let files: Vec<ContractFileInput> = spec
        .get("files")
        .and_then(Value::as_array)
        .map(|files| {
            files
                .iter()
                .map(|file| ContractFileInput {
                    repository_id: file
                        .get("repositoryId")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                    path: file
                        .get("path")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned(),
                    bytes: file
                        .get("content")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .as_bytes()
                        .to_vec(),
                    expected_digest: file
                        .get("digest")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                })
                .collect()
        })
        .unwrap_or_default();
    let set = DomainContractSet::build(&files, &snapshots, required);
    for boundary in &set.unresolved {
        gaps.push(serde_json::json!({
            "kind": "domain-contract-unresolved",
            "boundary": boundary.kind,
            "termId": boundary.term_id,
            "repositoryId": boundary.repository_id,
            "reason": boundary.detail,
        }));
    }
    if let Some(prior) = spec.get("priorBinding") {
        match serde_json::from_value::<DomainContextBinding>(prior.clone()) {
            Ok(binding) => {
                if let BindingStatus::Invalidated { reasons } = binding.verify_against(&set) {
                    gaps.push(serde_json::json!({"kind":"domain-contract-binding-invalidated","reason":reasons.join("; ")}));
                }
            }
            Err(error) => gaps.push(serde_json::json!({"kind":"domain-contract-binding-invalidated","reason":format!("unreadable prior binding: {error}")})),
        }
    }
    for row in rows.iter_mut() {
        let ids: Vec<String> = row
            .get("domainTerms")
            .and_then(Value::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        if ids.is_empty() {
            continue;
        }
        for id in &ids {
            if !set.terms.contains_key(id) {
                gaps.push(serde_json::json!({"kind":"requirement-domain-term-unresolved","reason":format!("{id} has no authoritative contract term")}));
            }
        }
        if let Some(map) = row.as_object_mut() {
            map.insert(
                "domainContractDigest".into(),
                Value::String(set.scoped_digest(&ids)),
            );
        }
    }
    let evaluation = set.evaluate();
    // Term dispositions flow through the existing traceability validator;
    // terms without owner/authority cannot become rows and stay gaps above.
    for disposition in &evaluation.dispositions {
        if disposition.owner.is_empty() || disposition.authority.is_empty() {
            continue;
        }
        let row = serde_json::json!({
            "id": disposition.term_id,
            "authority": disposition.authority,
            "owner": disposition.owner,
            "status": disposition.status,
            "spec": disposition.spec,
            "standards": disposition.standards,
            "evidence": [],
            "domainContractDigest": disposition.scoped_digest,
        });
        if let Err(error) = trace_requirement(&row) {
            gaps.push(serde_json::json!({"kind":"requirement-trace-invalid","reason":error}));
        }
    }
    Some(evaluation)
}
