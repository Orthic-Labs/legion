//! Bind cargo-outdated's one executed root package to its selected frozen lockfile.
use super::{LegacyCheckExecution, LegacyCheckInput, LegacyCheckProcessState};
use crate::inventory::InventoryEnvelope;
use legion_contracts::{Coverage, ProviderStatus};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(super) fn capture(
    input: &LegacyCheckInput,
    inventory: &InventoryEnvelope,
    cwd: &Path,
) -> Result<Value, String> {
    let root = std::fs::canonicalize(&input.root).map_err(|_| "root-unavailable")?;
    let resolved = std::fs::canonicalize(cwd).map_err(|_| "cwd-unavailable")?;
    let relative = resolved
        .strip_prefix(&root)
        .map_err(|_| "cwd-outside-root")?;
    let read = |name: &str| -> Result<(String, String, Vec<u8>), String> {
        let relative = relative.join(name).to_string_lossy().replace('\\', "/");
        let entry = inventory
            .entries
            .iter()
            .find(|entry| entry.path == relative)
            .ok_or_else(|| format!("source-outside-inventory:{relative}"))?;
        let mut path = root.clone();
        for part in Path::new(&relative).components() {
            if !matches!(part, std::path::Component::Normal(_)) {
                return Err("unsafe-source-path".into());
            }
            path.push(part);
            if std::fs::symlink_metadata(&path)
                .map_err(|_| "source-unavailable")?
                .file_type()
                .is_symlink()
            {
                return Err("source-symlink".into());
            }
        }
        if std::fs::canonicalize(&path).map_err(|_| "source-unavailable")? != path {
            return Err("source-alias-or-reparse-point".into());
        }
        let metadata = std::fs::metadata(&path).map_err(|_| "source-unavailable")?;
        if !metadata.is_file() || metadata.len() > 1_048_576 {
            return Err("source-size-or-type".into());
        }
        let bytes = std::fs::read(&path).map_err(|_| "source-unreadable")?;
        if bytes.len() > 1_048_576 {
            return Err("source-size-limit".into());
        }
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&bytes)));
        if entry.digest.as_deref() != Some(digest.as_str()) {
            return Err(format!("source-digest-unproven:{relative}"));
        }
        Ok((relative, digest, bytes))
    };
    let (manifest_path, manifest_digest, manifest_bytes) = read("Cargo.toml")?;
    let (lock_path, lock_digest, _) = read("Cargo.lock")?;
    if !input.denominator.entries.iter().any(|entry| {
        entry.path == lock_path && entry.digest.as_deref() == Some(lock_digest.as_str())
    }) {
        return Err("executed-lock-outside-denominator".into());
    }
    let manifest: toml::Value = std::str::from_utf8(&manifest_bytes)
        .ok()
        .and_then(|text| toml::from_str(text).ok())
        .ok_or("manifest-unparseable")?;
    let name = manifest
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(toml::Value::as_str)
        .filter(|name| !name.is_empty())
        .ok_or("root-package-unproven")?;
    Ok(
        json!({"cwd":resolved,"manifest":{"path":manifest_path,"digest":manifest_digest,"name":name},"lock":{"path":lock_path,"digest":lock_digest},"denominatorDigest":input.denominator.digest,"analysisScope":"executed-root-package-direct-dependencies"}),
    )
}

pub(super) fn reconcile(
    input: &LegacyCheckInput,
    inventory: &InventoryEnvelope,
    before: Result<Value, String>,
    execution: &mut LegacyCheckExecution,
) {
    let Some(output) = execution.output.as_mut() else {
        return;
    };
    let mut proven_lock = None;
    match before {
        Ok(binding) => {
            let receipt_cwd = output
                .details
                .get("executionReceipt")
                .and_then(|receipt| receipt.get("cwd"))
                .and_then(Value::as_str);
            let matches_after = receipt_cwd.is_some_and(|cwd| {
                capture(input, inventory, Path::new(cwd)).is_ok_and(|after| after == binding)
            });
            let document = serde_json::from_slice::<Value>(&execution.stdout).ok();
            let root_matches = document.as_ref().and_then(|value| value.get("crate_name"))
                == binding
                    .get("manifest")
                    .and_then(|manifest| manifest.get("name"));
            if matches_after
                && root_matches
                && execution.state == LegacyCheckProcessState::Completed
                && execution.exit_code == Some(0)
                && output.complete
            {
                proven_lock = binding["lock"]["path"].as_str().map(str::to_owned);
            } else {
                output
                    .coverage_gaps
                    .push("cargo-outdated-input-or-report-unproven".into());
            }
            // Retain actual pre-execution source identity even if the run failed.
            output.details.insert("rustOutdatedInput".into(), binding);
        }
        Err(reason) => output
            .coverage_gaps
            .push(format!("cargo-outdated-input-unproven:{reason}")),
    }
    for entry in &input.denominator.entries {
        if proven_lock.as_deref() != Some(entry.path.as_str()) {
            output
                .coverage_gaps
                .push(format!("cargo-outdated-lock-uncovered:{}", entry.path));
        }
    }
    if let Some(path) = proven_lock.as_ref() {
        // Recreate aggregate evidence against the executed lock, rather than
        // the first (possibly unrelated) selected lock. Raw report is retained.
        if let Some(count) = output
            .details
            .get("findingsCount")
            .and_then(Value::as_u64)
            .filter(|count| *count > 0)
        {
            output.findings.clear();
            output.details.remove("findingEvidence");
            output.details.remove("findingLocations");
            super::push_finding(
                output,
                "legacy.cargo_outdated.cargo-outdated",
                "low",
                path,
                1,
                &format!("cargo_outdated reported {count} finding(s)"),
            );
            if let Some(locations) = output
                .details
                .get_mut("findingLocations")
                .and_then(Value::as_object_mut)
            {
                for locations in locations.values_mut() {
                    *locations = json!([path]);
                }
            }
        }
    }
    output.coverage_gaps.sort();
    output.coverage_gaps.dedup();
    output.coverage = Some(Coverage {
        denominator_digest: input.denominator.digest.clone(),
        expected: input.denominator.entries.len() as u64,
        examined: u64::from(proven_lock.is_some()),
        gaps: output.coverage_gaps.clone(),
    });
    if !output.coverage_gaps.is_empty() {
        output.complete = false;
        output.status = ProviderStatus::Partial;
    }
}
