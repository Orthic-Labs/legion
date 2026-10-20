fn contains(items: &[String], wanted: &[String]) -> bool {
    let set: std::collections::HashSet<_> = items.iter().collect();
    wanted.iter().all(|w| set.contains(w))
}
