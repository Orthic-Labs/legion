use std::collections::BTreeMap;

use legion_contracts::{ProviderId, ProviderResult as ContractProviderResult, ProviderStatus};

use crate::error::{ProviderError, ProviderErrorKind};

pub type ProviderResult = ContractProviderResult;
pub type ResultStatus = ProviderStatus;

pub use legion_contracts::{Coverage, FindingRef};

pub fn normalize_result(mut result: ProviderResult) -> Result<ProviderResult, ProviderError> {
    result
        .findings
        .sort_by(|left, right| left.id.cmp(&right.id));
    result.coverage_gaps.sort();
    let missing_gaps: Vec<_> = result
        .coverage
        .as_ref()
        .map(|coverage| {
            let mut gaps = coverage.gaps.clone();
            gaps.sort();
            gaps.into_iter()
                .filter(|gap| !result.coverage_gaps.contains(gap))
                .collect()
        })
        .unwrap_or_else(|| vec!["provider-denominator-unreported".into()]);
    result.coverage_gaps.extend(missing_gaps);
    result.coverage_gaps.sort();
    result.coverage_gaps.dedup();
    let proven = result
        .coverage
        .as_ref()
        .map(Coverage::complete)
        .unwrap_or(false)
        && result.coverage_gaps.is_empty();
    if result.complete && !proven {
        result.complete = false;
        if matches!(result.status, ProviderStatus::Ok | ProviderStatus::Complete) {
            result.status = ProviderStatus::Partial;
        }
    }
    if result.complete {
        result.status = ProviderStatus::Complete;
    }
    result
        .validate()
        .map_err(|error| ProviderError::new(ProviderErrorKind::InvalidResult, error.to_string()))?;
    Ok(result)
}

pub fn empty_result(
    provider: ProviderId,
    required: bool,
    denominator_digest: impl Into<String>,
    expected: u64,
) -> ProviderResult {
    ProviderResult {
        schema_version: 1,
        provider,
        applicable: true,
        required,
        status: ProviderStatus::Partial,
        complete: false,
        coverage: Some(Coverage {
            denominator_digest: denominator_digest.into(),
            expected,
            examined: 0,
            gaps: vec!["provider produced no examined findings".into()],
        }),
        findings: Vec::new(),
        coverage_gaps: vec!["provider produced no examined findings".into()],
        degradation: vec!["provider produced no examined findings".into()],
        details: BTreeMap::new(),
    }
}

pub fn failed_result(
    provider: ProviderId,
    required: bool,
    reason: impl Into<String>,
) -> ProviderResult {
    let reason = reason.into();
    ProviderResult {
        schema_version: 1,
        provider,
        applicable: true,
        required,
        status: ProviderStatus::Failed,
        complete: false,
        coverage: Some(Coverage {
            denominator_digest: "sha256:".to_owned() + &"0".repeat(64),
            expected: 0,
            examined: 0,
            gaps: vec![reason.clone()],
        }),
        findings: Vec::<FindingRef>::new(),
        coverage_gaps: vec![reason.clone()],
        degradation: vec![reason],
        details: BTreeMap::new(),
    }
}
