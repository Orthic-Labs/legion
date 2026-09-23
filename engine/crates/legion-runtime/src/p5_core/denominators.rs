//! Ported from src/lib/core/denominators.mjs (packet P5-runtime-core).
//!
//! Faithful port of `reconcileDenominator`: dedupes `expected` and `examined`,
//! sorts both lexicographically, and reports which expected ids were never
//! examined. Sort order matches JS `Array.prototype.sort()` default (string
//! comparison of the ids as given).

use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenominatorReconciliation {
    pub expected: Vec<String>,
    pub examined: Vec<String>,
    pub missing: Vec<String>,
}

/// Port of `reconcileDenominator(expected = [], examined = [])`.
pub fn reconcile_denominator<I, J, S, T>(expected: I, examined: J) -> DenominatorReconciliation
where
    I: IntoIterator<Item = S>,
    J: IntoIterator<Item = T>,
    S: Into<String>,
    T: Into<String>,
{
    let expected_set: BTreeSet<String> = expected.into_iter().map(Into::into).collect();
    let examined_set: BTreeSet<String> = examined.into_iter().map(Into::into).collect();

    let missing: Vec<String> = expected_set
        .iter()
        .filter(|id| !examined_set.contains(*id))
        .cloned()
        .collect();

    DenominatorReconciliation {
        expected: expected_set.into_iter().collect(),
        examined: examined_set.into_iter().collect(),
        missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_inputs_reconcile_to_empty() {
        let result = reconcile_denominator(Vec::<String>::new(), Vec::<String>::new());
        assert!(result.expected.is_empty());
        assert!(result.examined.is_empty());
        assert!(result.missing.is_empty());
    }

    #[test]
    fn dedupes_and_sorts_both_sides() {
        let result = reconcile_denominator(
            vec!["b", "a", "a", "c"],
            vec!["c", "c", "a"],
        );
        assert_eq!(result.expected, vec!["a", "b", "c"]);
        assert_eq!(result.examined, vec!["a", "c"]);
        assert_eq!(result.missing, vec!["b"]);
    }

    #[test]
    fn missing_is_empty_when_examined_is_superset() {
        let result = reconcile_denominator(vec!["a", "b"], vec!["a", "b", "extra"]);
        assert_eq!(result.expected, vec!["a", "b"]);
        assert_eq!(result.examined, vec!["a", "b", "extra"]);
        assert!(result.missing.is_empty());
    }
}
