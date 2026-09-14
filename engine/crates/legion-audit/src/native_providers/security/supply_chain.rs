use serde_json::{json, Value};

use super::common::{array, same_binding, valid_digest};

pub fn reconcile_sbom(
    lock_packages: &[String],
    sbom_packages: &[String],
    provenance: Option<&Value>,
) -> Value {
    let present = sbom_packages
        .iter()
        .collect::<std::collections::BTreeSet<_>>();
    let missing = lock_packages
        .iter()
        .filter(|package| !present.contains(package))
        .cloned()
        .collect::<Vec<_>>();
    json!({"complete":missing.is_empty(),"missing":missing,"provenance":if provenance.is_some(){"present"}else{"absent"}})
}

pub fn analyze(input: &Value) -> Value {
    let chain = input
        .get("artifacts")
        .and_then(|a| a.get("supplyChain"))
        .unwrap_or(&Value::Null);
    let lock = array(chain.get("lockPackages"))
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let sbom = array(chain.get("sbomPackages"))
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    let provenance = chain.get("provenance");
    let receipt = reconcile_sbom(&lock, &sbom, provenance);
    let mut gaps = receipt
        .get("missing")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|name| json!({"kind":"sbom-package-missing","name":name}))
        .collect::<Vec<_>>();
    if lock.is_empty() {
        gaps.push(json!({"kind":"dependency-inventory-missing"}));
    }
    if !valid_digest(chain.get("cycloneDxDigest")) || !valid_digest(chain.get("spdxDigest")) {
        gaps.push(json!({"kind":"sbom-artifact-missing"}));
    }
    let valid = provenance.is_some_and(|p| {
        same_binding(
            p.get("binding"),
            input.get("plan").and_then(|v| v.get("binding")),
        ) && p
            .get("executionReceipt")
            .and_then(|r| r.get("complete"))
            .and_then(Value::as_bool)
            == Some(true)
            && valid_digest(
                p.get("executionReceipt")
                    .and_then(|r| r.get("tool"))
                    .and_then(|t| t.get("executableDigest")),
            )
            && valid_digest(p.get("subjectDigest"))
    });
    if !valid {
        gaps.push(json!({"kind":"supply-chain-provenance-invalid"}));
    }
    json!({"status":if gaps.is_empty(){"pass"}else{"unproven"},"complete":gaps.is_empty(),"denominator":{"kind":"lockfile-packages","expected":lock.len(),"examined":sbom.len()},"findings":[],"coverageGaps":gaps})
}
