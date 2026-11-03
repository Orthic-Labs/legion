//! Port of `parse_dependency_contract()` from `validate-dispatch.py`
//! (lines ~983-1010).

use std::collections::BTreeSet;

type DependencyContract = (BTreeSet<String>, BTreeSet<(String, String)>);

/// Port of `parse_dependency_contract()`. Returns `(roots, edges)` or
/// `None` when the value is empty or malformed, matching the Python
/// function's `None` return.
pub fn parse_dependency_contract(value: &str) -> Option<DependencyContract> {
    let compact: String = value
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_uppercase();
    if compact.is_empty() {
        return None;
    }
    let mut roots: BTreeSet<String> = BTreeSet::new();
    let mut edges: BTreeSet<(String, String)> = BTreeSet::new();
    let parts: Vec<&str> = compact.split(';').filter(|p| !p.is_empty()).collect();
    let single_part = parts.len() == 1;
    for part in &parts {
        if let Some(rest) = part.strip_prefix("START:") {
            for item in rest.split(',') {
                if !item.is_empty() {
                    roots.insert(item.to_string());
                }
            }
            continue;
        }
        let rest = part.strip_prefix("EDGES:")?;
        let chains: Vec<&str> = rest.split(',').filter(|c| !c.is_empty()).collect();
        for chain in chains {
            let nodes: Vec<&str> = chain.split("->").filter(|n| !n.is_empty()).collect();
            if nodes.len() < 2 {
                return None;
            }
            for pair in nodes.windows(2) {
                edges.insert((pair[0].to_string(), pair[1].to_string()));
            }
            if single_part {
                roots.insert(nodes[0].to_string());
            }
        }
    }
    if roots.is_empty() {
        let targets: BTreeSet<&str> = edges.iter().map(|(_, t)| t.as_str()).collect();
        let sources: BTreeSet<&str> = edges.iter().map(|(s, _)| s.as_str()).collect();
        roots = sources
            .difference(&targets)
            .map(|s| s.to_string())
            .collect();
    }
    Some((roots, edges))
}
