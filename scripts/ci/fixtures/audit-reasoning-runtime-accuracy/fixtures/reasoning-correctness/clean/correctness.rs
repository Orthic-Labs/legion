fn average(values: &[u64]) -> Option<u64> {
    if values.is_empty() { return None; }
    let total = values.iter().try_fold(0u64, |sum, value| sum.checked_add(*value))?;
    Some(total / values.len() as u64)
}
