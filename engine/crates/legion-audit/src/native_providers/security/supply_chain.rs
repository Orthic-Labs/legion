//! Native dual SBOM & explicit license decisions with target provenance gaps.
//! Host JSON cannot establish authenticated target build provenance.
use super::{
    common::{array, digest},
    supply_chain_documents::{parse_lock, reconcile},
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// Inventory observation only; presence is never attestation verification.
pub fn reconcile_sbom(
    lock_packages: &[String],
    sbom_packages: &[String],
    provenance: Option<&Value>,
) -> Value {
    let present = sbom_packages.iter().collect::<BTreeSet<_>>();
    let missing = lock_packages
        .iter()
        .filter(|p| !present.contains(p))
        .cloned()
        .collect::<Vec<_>>();
    json!({"complete":missing.is_empty(),"missing":missing,"provenance":if provenance.is_some(){"unverified"}else{"absent"}})
}
fn bound_native_document(
    document: &Value,
    format: &str,
    binding: &Value,
    configuration: &Value,
) -> Option<Vec<u8>> {
    let raw = document.get("raw")?.as_str()?.as_bytes().to_vec();
    if document["digest"].as_str() != Some(digest(&raw).as_str()) {
        return None;
    }
    let receipt = &document["receipt"];
    let args = receipt.pointer("/command/args")?.as_array()?;
    let output = if format == "cyclonedx" {
        "cyclonedx-json"
    } else {
        "spdx-json"
    };
    if configuration["raw"] != super::supply_chain_documents::SYFT_CONFIGURATION
        || configuration["digest"].as_str()
            != Some(digest(super::supply_chain_documents::SYFT_CONFIGURATION.as_bytes()).as_str())
    {
        return None;
    }
    let expected = json!([
        "scan",
        "dir:.",
        "--config",
        configuration["path"],
        "--override-default-catalogers",
        "all",
        "-o",
        output,
        "-q"
    ]);
    let wrapped = args.len() >= 4 && args[0] == "-f" && args[2] == "--";
    let suffix = if wrapped { &args[4..] } else { args.as_slice() };
    if json!(suffix) != expected
        || receipt["providerId"] != "supply-chain.license-sbom-provenance"
        || receipt["planId"] != binding["digest"]
        || receipt["state"] != "completed"
        || receipt["complete"] != true
        || receipt["exitCode"] != 0
        || receipt["signal"] != Value::Null
        || receipt["gaps"] != json!([])
        || receipt.pointer("/policy/allowed") != Some(&json!(true))
        || receipt.pointer("/sandbox/required") != Some(&json!(true))
        || receipt.pointer("/sandbox/networkEnabled") != Some(&json!(true))
        || receipt.pointer("/processTree/started") != Some(&json!(true))
        || receipt.pointer("/processTree/reaped") != Some(&json!(true))
        || receipt.pointer("/processTree/terminated") != Some(&json!(true))
        || receipt.pointer("/processTree/hardKilled") != Some(&json!(false))
        || receipt.pointer("/stdout/digest").and_then(Value::as_str) != Some(digest(&raw).as_str())
        || receipt.pointer("/stdout/bytes").and_then(Value::as_u64) != Some(raw.len() as u64)
        || receipt.pointer("/stdout/immutable") != Some(&json!(true))
        || receipt.pointer("/executable/version/qualified") != Some(&json!(true))
    {
        return None;
    }
    Some(raw)
}
pub fn analyze(input: &Value) -> Value {
    let chain = &input["artifacts"]["supplyChain"];
    let mut gaps = array(chain.get("producerGaps"));
    let mut lock = BTreeSet::new();
    let mut lock_paths = BTreeSet::new();
    let before = &chain["sourceBefore"];
    let after = &chain["sourceAfter"];
    let selected: BTreeSet<_> = array(input.pointer("/projection/files"))
        .into_iter()
        .filter_map(|v| v["path"].as_str().map(str::to_owned))
        .collect();
    let observed: BTreeSet<_> = before["files"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.keys().cloned())
        .collect();
    let source_bound = chain["schema"] == "legion-supply-chain-native-evidence/1"
        && before["complete"] == true
        && after["complete"] == true
        && before["files"] == after["files"]
        && selected == observed
        && !selected.is_empty();
    if !source_bound {
        gaps.push(json!({"kind":"supply-chain-source-binding-invalid"}));
    }
    gaps.extend(array(before.get("coverageGaps")));
    gaps.extend(array(after.get("coverageGaps")));
    for row in array(chain.get("lockfiles")) {
        let (Some(path), Some(raw)) = (row["path"].as_str(), row["raw"].as_str()) else {
            gaps.push(json!({"kind":"dependency-manifest-unparsed"}));
            continue;
        };
        if !lock_paths.insert(path.to_owned())
            || before["files"][path] != row["digest"]
            || row["digest"].as_str() != Some(digest(raw.as_bytes()).as_str())
        {
            gaps.push(json!({"kind":"supply-chain-lock-binding-invalid","path":path}));
            continue;
        }
        match parse_lock(path, raw) {
            Ok(packages) => lock.extend(packages),
            Err(reason) => gaps
                .push(json!({"kind":"dependency-manifest-unparsed","path":path,"reason":reason})),
        }
    }
    let expected_locks: BTreeSet<_> = selected
        .iter()
        .filter(|p| super::supply_chain_documents::lock_kind(p).is_some())
        .cloned()
        .collect();
    if expected_locks != lock_paths {
        gaps.push(json!({"kind":"supply-chain-lock-denominator-invalid"}));
    }
    let declared: BTreeSet<_> = array(chain.get("lockPackages"))
        .into_iter()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    if declared != lock {
        gaps.push(json!({"kind":"supply-chain-lock-inventory-invalid"}));
    }
    let binding = &input["plan"]["binding"];
    let cdx = bound_native_document(
        &chain["documents"]["cyclonedx"],
        "cyclonedx",
        binding,
        &chain["syftConfiguration"],
    );
    let spdx = bound_native_document(
        &chain["documents"]["spdx"],
        "spdx",
        binding,
        &chain["syftConfiguration"],
    );
    let reconciliation = match (cdx, spdx) {
        (Some(cdx), Some(spdx)) => reconcile(&lock, &cdx, &spdx, &chain["licensePolicy"]),
        _ => {
            gaps.push(json!({"kind":"sbom-native-receipt-or-artifact-invalid"}));
            reconcile(&lock, &[], &[], &chain["licensePolicy"])
        }
    };
    let sbom_license_complete =
        source_bound && gaps.is_empty() && reconciliation["complete"] == true;
    gaps.extend(array(reconciliation.get("coverageGaps")));
    // No supported shared build-attestation authority is installed/composed.
    // A complete scanner receipt, digest-shaped subject, a signed SBOM or a
    // RightRelease catalog is insufficient evidence of how bytes were built.
    gaps.push(json!({"kind":"supply-chain-provenance-invalid"}));
    gaps.push(json!({"kind":"supply-chain-provenance-authority-unavailable","reason":"build-attestation-verification-owner-unavailable"}));
    let provenance = super::supply_chain_documents::provenance_observation(chain, binding);
    let mut findings = array(reconciliation.get("findings"));
    for finding in &mut findings {
        if let Some(path) = lock_paths.iter().find(|path| {
            chain["lockfiles"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|row| {
                    row["path"].as_str() == Some(path.as_str())
                        && row["raw"]
                            .as_str()
                            .and_then(|raw| parse_lock(path, raw).ok())
                            .is_some_and(|packages| {
                                packages.contains(finding["package"].as_str().unwrap_or(""))
                            })
                })
        }) {
            finding["file"] = json!(path);
            finding["line"] = json!(1);
            finding["message"] = json!(format!(
                "Explicit license policy denies {} for {}",
                finding["license"], finding["package"]
            ));
        }
    }
    json!({"status":"unproven","complete":false,"denominator":{"kind":"lockfile-packages","expected":lock.len(),"examined":reconciliation["examined"]},
        "findings":findings,"coverageGaps":gaps,"sbomLicenseComplete":sbom_license_complete,
        "sourceCoverage":{"validatedPaths":if source_bound {json!(selected)}else{json!([])},"complete":source_bound},
        "reconciliation":reconciliation,"provenance":provenance})
}
