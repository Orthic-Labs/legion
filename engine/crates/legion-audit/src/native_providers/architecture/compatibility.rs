use super::{
    common::{gap, object_input, truthy, Analysis},
    evidence::{limit_runtime_evidence, validate_refs},
};
use crate::artifact_evidence::{ObservationKind, ObservationVerdict};
use serde_json::Value;

/// Compare supplied values; this does not authenticate either observation.
pub fn compatibility_finding(value: &Value) -> Result<Value, String> {
    let object = object_input(value)?;
    for key in ["producerVersion", "consumerVersion", "platform", "contract"] {
        if !truthy(object.get(key)) {
            return Err("bound compatibility context required".into());
        }
    }
    if object.get("expected").is_none()
        || object.get("observed").is_none()
        || !object
            .get("evidenceRefs")
            .and_then(Value::as_array)
            .is_some_and(|items| !items.is_empty())
    {
        return Err("expected observed compatibility evidence required".into());
    }
    Ok(
        serde_json::json!({"producerVersion":object["producerVersion"],"consumerVersion":object["consumerVersion"],"platform":object["platform"],"contract":object["contract"],"expected":object["expected"],"observed":object["observed"],"evidenceRefs":object["evidenceRefs"],"status":if object["expected"] == object["observed"] {"compatible"} else {"incompatible"},"certificationClaim":false,"comparisonScope":"caller-supplied-values"}),
    )
}

pub fn analyze(input: &Value) -> Result<Analysis, String> {
    let object = object_input(input)?;
    let records = object
        .get("artifacts")
        .and_then(|value| value.get("compatibility"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let authority = super::evidence::authority(
        object.get("plan"),
        object.get("artifacts"),
        object.get("root"),
        object.get("now").and_then(Value::as_str),
    );
    let mut result = Analysis::new(
        "unproven",
        false,
        serde_json::json!({"kind":"compatibility-contracts","expected":records.len(),"examined":0}),
    );
    if records.is_empty() {
        result.status = "unproven".into();
        result.complete = false;
        result
            .coverage_gaps
            .push(gap("compatibility-denominator-unavailable"));
    }
    let mut examined = 0;
    let mut comparisons = Vec::new();
    for record in &records {
        match compatibility_finding(record) {
            Ok(normalized) => {
                let errors = validate_refs(normalized.get("evidenceRefs"), &authority);
                if errors.is_empty() {
                    examined += 1;
                    comparisons.push(normalized);
                } else {
                    result.coverage_gaps.push(serde_json::json!({"kind":"compatibility-evidence-invalid","reason":errors.join(",")}));
                }
            }
            Err(error) => result
                .coverage_gaps
                .push(serde_json::json!({"kind":"compatibility-evidence-invalid","reason":error})),
        }
    }
    result.extras.insert("protocolValidation".into(), serde_json::json!({
        "scope":"caller-supplied-values-and-reference-metadata", "expected":records.len(), "examined":examined
    }));
    result
        .extras
        .insert("comparisons".into(), Value::Array(comparisons));
    limit_runtime_evidence(&mut result);
    Ok(result)
}

/// Shared interpretation of verified runtime observations of one kind. Returns
/// the observation projections plus the named gaps and failed-probe findings;
/// empty when no verdict of `kind` was supplied (the default path is
/// untouched).
pub(super) struct ObservationSummary {
    pub verified: Vec<Value>,
    pub gaps: Vec<Value>,
    pub findings: Vec<Value>,
    pub any: bool,
    /// At least one verified observation and every supplied one verified with
    /// every named probe passing.
    pub all_probes_satisfied: bool,
    pub satisfied_probe_count: usize,
}

pub(super) fn summarize_observations(
    kind: ObservationKind,
    finding_prefix: &str,
    verdicts: &[ObservationVerdict],
) -> ObservationSummary {
    let mut summary = ObservationSummary {
        verified: Vec::new(),
        gaps: Vec::new(),
        findings: Vec::new(),
        any: false,
        all_probes_satisfied: true,
        satisfied_probe_count: 0,
    };
    for verdict in verdicts.iter().filter(|verdict| verdict.kind == kind) {
        summary.any = true;
        match verdict.observation() {
            Some(observation) => {
                summary.verified.push(observation.to_value());
                summary.satisfied_probe_count += observation.satisfied_probes().len();
                for probe in observation.failed_probes() {
                    summary.all_probes_satisfied = false;
                    summary.findings.push(serde_json::json!({
                        "id": format!("{finding_prefix}:{probe}"),
                        "severity": "high",
                        "probe": probe,
                        "observationClaims": observation.claims_digest(),
                        "target": observation.target(),
                        "scope": "named-probes-only",
                    }));
                }
            }
            None => {
                summary.all_probes_satisfied = false;
                summary.gaps.push(serde_json::json!({
                    "kind": format!(
                        "runtime-observation-rejected:{}:{}",
                        kind.label(),
                        verdict.reasons.join(",")
                    ),
                }));
            }
        }
    }
    if summary.any && summary.verified.is_empty() {
        summary.all_probes_satisfied = false;
    }
    summary
}

/// Fold verified compatibility-run observations into an analysis. Satisfies
/// exactly the plan-named probes against the bound subject; never certifies
/// general compatibility. Rejected or failing observations keep the result
/// unproven with named gaps/findings. No verdict: the analysis is unchanged.
pub fn apply_observations(analysis: &mut Analysis, verdicts: &[ObservationVerdict]) {
    let summary = summarize_observations(
        ObservationKind::CompatibilityRun,
        "compatibility-probe-failed",
        verdicts,
    );
    if !summary.any {
        return;
    }
    let had_caller_records = analysis
        .denominator
        .get("expected")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        > 0;
    analysis.findings.extend(summary.findings);
    for gap in summary.gaps {
        if !analysis.coverage_gaps.contains(&gap) {
            analysis.coverage_gaps.push(gap);
        }
    }
    analysis
        .extras
        .insert("runtimeObservations".into(), Value::Array(summary.verified));
    analysis
        .extras
        .insert("certificationClaim".into(), Value::Bool(false));
    analysis.extras.insert(
        "runtimeObservationScope".into(),
        Value::String("named-probes-only".into()),
    );
    if summary.all_probes_satisfied && !had_caller_records {
        // The denominator is now the named probes, all satisfied by signed
        // evidence; the two gaps below existed only for their absence.
        analysis.coverage_gaps.retain(|gap| {
            !matches!(
                gap.get("kind").and_then(Value::as_str),
                Some("compatibility-denominator-unavailable")
                    | Some("runtime-evidence-trust-unavailable")
            )
        });
        analysis.denominator = serde_json::json!({
            "kind": "compatibility-runtime-probes",
            "expected": summary.satisfied_probe_count,
            "examined": summary.satisfied_probe_count,
        });
        if analysis.coverage_gaps.is_empty() && analysis.findings.is_empty() {
            analysis.status = "pass".into();
            analysis.complete = true;
        }
    }
}
