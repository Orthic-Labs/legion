use legion_contracts::ProviderResult;

pub fn normalize(mut result: ProviderResult) -> ProviderResult {
    result.findings.sort_by(|a, b| a.id.cmp(&b.id));
    result.coverage_gaps.sort();
    result.coverage_gaps.dedup();
    result.degradation.sort();
    result.degradation.dedup();
    result
}

pub fn normalize_all(results: impl IntoIterator<Item = ProviderResult>) -> Vec<ProviderResult> {
    let mut output: Vec<_> = results.into_iter().map(normalize).collect();
    output.sort_by(|a, b| a.provider.cmp(&b.provider));
    output
}
