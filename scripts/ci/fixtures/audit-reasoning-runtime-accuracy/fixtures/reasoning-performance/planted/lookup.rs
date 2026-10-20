// Inputs are unbounded; this runs for every requested key.
fn contains(items: &[String], wanted: &[String]) -> bool {
    wanted.iter().all(|w| items.iter().any(|item| item == w))
}
