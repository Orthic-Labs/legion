fn average(values: &[u64]) -> u64 {
    let total: u64 = values.iter().sum();
    (total / values.len() as u64)
}
