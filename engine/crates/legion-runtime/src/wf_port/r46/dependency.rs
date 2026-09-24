//! Port of `parse_dependency_contract()` from `validate-dispatch.py`
//! (lines ~983-1010).

use std::collections::BTreeSet;

/// Port of `parse_dependency_contract()`. Returns `(roots, edges)` or
/// `None` when the value is empty or malformed, matching the Python
/// function's `None` return.
pub fn parse_dependency_contract(
    value: &str,
) -> Option<(BTreeSet<String>, BTreeSet<(String, String)>)> {
    let compact: String = value.chars().filter(|c| !c.is_whitespace()).collect::<String>().to_uppercase();
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
        let rest = match part.strip_prefix("EDGES:") {
            Some(rest) => rest,
            None => return None,
        };
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
        roots = sources.difference(&targets).map(|s| s.to_string()).collect();
    }
    Some((roots, edges))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_value_is_none() {
        assert!(parse_dependency_contract("").is_none());
    }

    #[test]
    fn malformed_part_is_none() {
        assert!(parse_dependency_contract("BOGUS:x").is_none());
    }

    #[test]
    fn single_edges_part_infers_roots_from_chain_head() {
        let (roots, edges) = parse_dependency_contract("EDGES:A->B->C").unwrap();
        assert_eq!(roots, BTreeSet::from(["A".to_string()]));
        assert_eq!(
            edges,
            BTreeSet::from([("A".to_string(), "B".to_string()), ("B".to_string(), "C".to_string())])
        );
    }

    #[test]
    fn start_and_edges_combined() {
        let (roots, edges) = parse_dependency_contract("START:A;EDGES:A->B,A->C").unwrap();
        assert_eq!(roots, BTreeSet::from(["A".to_string()]));
        assert_eq!(
            edges,
            BTreeSet::from([("A".to_string(), "B".to_string()), ("A".to_string(), "C".to_string())])
        );
    }

    #[test]
    fn chain_with_fewer_than_two_nodes_is_none() {
        assert!(parse_dependency_contract("EDGES:A").is_none());
    }
}
