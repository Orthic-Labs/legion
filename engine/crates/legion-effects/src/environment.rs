use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnvironmentSnapshot {
    pub values: BTreeMap<String, String>,
    pub names: BTreeSet<String>,
    pub redacted_names: BTreeSet<String>,
}

/// Copy only explicitly permitted names. Values never enter receipts.
pub fn allowlisted_environment(
    source: &BTreeMap<String, String>,
    allowlist: &BTreeSet<String>,
    sensitive: &BTreeSet<String>,
) -> EnvironmentSnapshot {
    let values = source
        .iter()
        .filter(|(name, _)| allowlist.contains(*name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<BTreeMap<_, _>>();
    let names = values.keys().cloned().collect::<BTreeSet<_>>();
    let redacted_names = names.intersection(sensitive).cloned().collect();
    EnvironmentSnapshot {
        values,
        names,
        redacted_names,
    }
}
