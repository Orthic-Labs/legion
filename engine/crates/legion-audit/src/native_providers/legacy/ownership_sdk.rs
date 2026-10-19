//! Authenticated native RightKit ownership consumer. No scanner rules or admission live here.
//!
//! Host enrollment pins an executable wrapping `rightkit_ownership::Scanner` with its
//! embedded catalog. Three SDK calls retain real input probes & protected scan output.
//! Production registry has no enrollment by default; its existing denial path remains.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};

use legion_contracts::{ProviderResult, ProviderStatus};
use legion_provider_sdk::{ExecutionReceipt, ExternalProjectTool, ExternalToolRequest};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use super::{
    common::{denominator, digest_bytes, finding, result, ProviderInput},
    governance_ownership,
};
use crate::{AuditError, FrozenPlan};

const LIMIT: usize = 64 * 1024 * 1024;
const TOTAL_LIMIT: usize = 256 * 1024 * 1024;
const PROTOCOL: &str = "legion-rightkit-ownership-native/1";

/// Host-side binary enrollment, distinct from policy admission. Never read from findings JSON.
#[derive(Clone, Debug)]
pub struct NativeOwner {
    executable: PathBuf,
    executable_digest: String,
}

impl NativeOwner {
    pub fn pin(executable: &Path) -> Result<Self, String> {
        let executable = fs::canonicalize(executable).map_err(|e| e.to_string())?;
        let executable_digest = digest_bytes(&read_bounded(&executable, TOTAL_LIMIT)?);
        Ok(Self {
            executable,
            executable_digest,
        })
    }

    /// Frozen plan must carry this whole identity as `ownershipNativeOwner`.
    pub fn identity(&self) -> Value {
        json!({"protocol":PROTOCOL,"executable":self.executable,"executableDigest":self.executable_digest,
            "ownerCrate":"rightkit-ownership","ownerVersion":"0.3.1",
            "scannerVersion":rightkit_ownership::SCANNER_VERSION,
            "scannerPolicyDigest":rightkit_ownership::scanner_policy_digest(),
            "catalogDigest":rightkit_ownership::scan::catalog_digest(rightkit_ownership::catalog_value())})
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    fn verify(&self) -> Result<(), String> {
        if digest_bytes(&read_bounded(&self.executable, TOTAL_LIMIT)?) != self.executable_digest {
            return Err("ownership-native-owner-drift".into());
        }
        Ok(())
    }
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > limit {
        return Err("ownership-input-limit".into());
    }
    Ok(bytes)
}

fn relative(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\\', ':'])
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}

fn snapshot(input: &ProviderInput<'_>) -> Result<BTreeMap<String, String>, String> {
    let root = fs::canonicalize(input.root).map_err(|e| e.to_string())?;
    let entries = denominator(input).map_err(|e| e.to_string())?.entries;
    let mut out = BTreeMap::new();
    let mut total = 0;
    for entry in entries {
        if !relative(&entry.path) {
            return Err("ownership-denominator-path-invalid".into());
        }
        let mut path = root.clone();
        for part in Path::new(&entry.path).components() {
            path.push(part.as_os_str());
            if fs::symlink_metadata(&path)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
            {
                return Err(format!("ownership-denominator-symlink:{}", entry.path));
            }
        }
        let bytes = read_bounded(&path, LIMIT)?;
        total += bytes.len();
        if total > TOTAL_LIMIT {
            return Err("ownership-input-total-limit".into());
        }
        let digest = digest_bytes(&bytes);
        if entry.digest.as_deref() != Some(&digest) {
            return Err(format!("ownership-denominator-drift:{}", entry.path));
        }
        if out.insert(entry.path, digest).is_some() {
            return Err("ownership-denominator-duplicate".into());
        }
    }
    Ok(out)
}

fn artifact(root: &Path, receipt: &ExecutionReceipt) -> Result<Vec<u8>, String> {
    let item = receipt.stdout.as_ref().ok_or("ownership-stdout-missing")?;
    if !item.immutable || item.bytes > LIMIT || !relative(&item.path) {
        return Err("ownership-stdout-invalid".into());
    }
    let canonical_root = fs::canonicalize(root).map_err(|e| e.to_string())?;
    let path = fs::canonicalize(canonical_root.join(&item.path)).map_err(|e| e.to_string())?;
    if !path.starts_with(&canonical_root) {
        return Err("ownership-stdout-outside-sink".into());
    }
    let bytes = read_bounded(&path, LIMIT)?;
    if bytes.len() != item.bytes || digest_bytes(&bytes) != item.digest {
        return Err("ownership-stdout-drift".into());
    }
    Ok(bytes)
}

/// Validate a genuine wrapper result against full frozen Audit denominator. Exposed to
/// source-owned malformed/outside-scope controls; JSON alone never enters execution.
pub fn validate_envelope(
    document: &Value,
    expected_files: &BTreeMap<String, String>,
    owner: &NativeOwner,
    root: &Path,
    scan: bool,
) -> Result<(), String> {
    if document["protocol"] != PROTOCOL
        || document["root"] != json!(root)
        || document["identity"] != owner.identity()
    {
        return Err("ownership-native-envelope-identity".into());
    }
    let rows = document["inputInventory"]["files"]
        .as_array()
        .ok_or("ownership-input-inventory-missing")?;
    if document["inputInventory"]["complete"] != true {
        return Err("ownership-input-inventory-incomplete".into());
    }
    let mut actual = BTreeMap::new();
    for row in rows {
        let path = row["path"].as_str().ok_or("ownership-input-path-missing")?;
        let digest = row["digest"]
            .as_str()
            .ok_or("ownership-input-digest-missing")?;
        if !relative(path) || actual.insert(path.to_owned(), digest.to_owned()).is_some() {
            return Err("ownership-input-inventory-invalid".into());
        }
    }
    if &actual != expected_files {
        return Err("ownership-input-denominator-mismatch".into());
    }
    let envelope = &document["owner"];
    if let Some(code) = envelope["code"].as_str() {
        return Err(format!("ownership-owner-refused:{code}"));
    }
    let inputs = &envelope["inputs"];
    if document["inputInventory"]["ownerContentDigest"] != inputs["contentDigest"] {
        return Err("ownership-input-content-binding".into());
    }
    rightkit_ownership::ownership_cache_key(inputs)
        .map_err(|e| format!("ownership-inputs-invalid:{}", e.message))?;
    if inputs["catalogDigest"] != owner.identity()["catalogDigest"]
        || inputs["scannerPolicyDigest"] != owner.identity()["scannerPolicyDigest"]
    {
        return Err("ownership-owner-policy-mismatch".into());
    }
    if !scan {
        if envelope["complete"] != true || envelope["enrollmentPending"] != false {
            return Err("ownership-owner-inputs-unverified".into());
        }
        return Ok(());
    }
    let report = &envelope["report"];
    let trust = &envelope["trust"];
    let evidence = &envelope["evidence"];
    if evidence["source"] != "committed-git-tree"
        || evidence["trustEnrolled"] != true
        || evidence["floorOk"] != true
        || evidence["schema"] != 1
        || report["enrollmentPending"] != false
    {
        return Err("ownership-evidence-unverified".into());
    }
    let verdict = rightkit_ownership::ownership_verdict(report, trust);
    if envelope["verdict"]["admit"] != verdict.admit
        || envelope["verdict"]["code"] != verdict.code
        || envelope["verdict"]["problems"] != json!(verdict.problems)
    {
        return Err("ownership-verdict-mismatch".into());
    }
    if ![
        rightkit_ownership::codes::CLEAN,
        rightkit_ownership::codes::ADVISORY,
        rightkit_ownership::codes::VIOLATION,
    ]
    .contains(&verdict.code)
    {
        return Err(format!("ownership-verdict-incomplete:{}", verdict.code));
    }
    for key in [
        "repositoryIdentity",
        "commit",
        "tree",
        "catalogDigest",
        "scannerVersion",
        "catalogVersion",
    ] {
        if evidence[key].as_str().is_none_or(str::is_empty)
            || evidence[key] != report["metadata"][key]
        {
            return Err(format!("ownership-evidence-binding:{key}"));
        }
    }
    if evidence["catalogDigest"] != inputs["catalogDigest"] {
        return Err("ownership-evidence-catalog-drift".into());
    }
    for key in ["repositoryIdentity", "commit", "tree"] {
        if evidence[key] != document["inputInventory"]["sourceIdentity"][key] {
            return Err(format!("ownership-evidence-source-identity:{key}"));
        }
    }
    let content = report["metadata"]["contentDigests"]
        .as_array()
        .ok_or("ownership-content-digests-missing")?;
    if evidence["contentDigest"] != rightkit_ownership::approval::sha256_value(&json!(content)) {
        return Err("ownership-evidence-content-drift".into());
    }
    if report["metadata"]["pathBase"] != "repository" || report["metadata"]["pathPrefix"] != "" {
        return Err("ownership-report-path-base".into());
    }
    let mut unique_content = BTreeSet::new();
    for key in ["findings", "violations", "covered"] {
        for row in report[key]
            .as_array()
            .ok_or_else(|| format!("ownership-report-list-missing:{key}"))?
        {
            let path = row["file"]
                .as_str()
                .ok_or("ownership-finding-file-missing")?;
            if !relative(path) || !expected_files.contains_key(path) {
                return Err(format!("ownership-finding-outside-scope:{path}"));
            }
            if row["line"]
                .as_u64()
                .is_none_or(|line| line > usize::MAX as u64)
            {
                return Err("ownership-finding-line-invalid".into());
            }
        }
    }
    for row in content {
        let path = row["path"]
            .as_str()
            .ok_or("ownership-content-path-missing")?;
        if !relative(path) || !expected_files.contains_key(path) {
            return Err(format!("ownership-content-outside-scope:{path}"));
        }
        if !unique_content.insert(path) {
            return Err("ownership-content-duplicate".into());
        }
    }
    Ok(())
}

/// A supplied SDK authorizer decides each request. This function grants no admission,
/// performs no process fallback & preserves default registry refusal without enrollment.
pub async fn execute(
    input: &ProviderInput<'_>,
    plan: &FrozenPlan,
    owner: &NativeOwner,
    tool: &dyn ExternalProjectTool,
    artifacts_root: &Path,
    cancellation: CancellationToken,
) -> Result<ProviderResult, AuditError> {
    let denom = denominator(input)?;
    let mut details = BTreeMap::new();
    let mut gaps = Vec::<String>::new();
    let mut documents = Vec::new();
    let before = snapshot(input);
    let root = fs::canonicalize(input.root).map_err(|e| AuditError::Provider(e.to_string()))?;
    let argv = vec![
        owner.executable.to_string_lossy().into_owned(),
        root.to_string_lossy().into_owned(),
    ];
    let raw = std::env::var(governance_ownership::COMMAND_ENV).unwrap_or_default();
    if governance_ownership::parse_argv(&raw).as_ref() != Some(&argv)
        || input
            .provider
            .configuration
            .get("hostDeclaration")
            .and_then(|v| v["commandDigest"].as_str())
            != Some(governance_ownership::command_digest(&raw).as_str())
    {
        gaps.push("ownership-scan-declaration-drift".into());
    }
    if input.provider.configuration.get("ownershipNativeOwner") != Some(&owner.identity()) {
        gaps.push("ownership-native-owner-not-frozen".into());
    }
    if plan.plan().inventory_digest != input.inventory.digest
        || !plan.providers().iter().any(|p| p == input.provider)
    {
        gaps.push("ownership-plan-binding-mismatch".into());
    }
    if let Err(gap) = &before {
        gaps.push(gap.clone());
    }
    if let Err(gap) = owner.verify() {
        gaps.push(gap);
    }
    let mut receipts = Vec::new();
    if gaps.is_empty() {
        for (sequence, mode) in ["inputs-before", "scan", "inputs-after"]
            .into_iter()
            .enumerate()
        {
            let request = ExternalToolRequest {
                request_id: format!(
                    "legion-audit/{}",
                    digest_bytes(
                        format!("{}:{}:{mode}", plan.digest(), input.inventory.digest).as_bytes()
                    )
                    .trim_start_matches("sha256:")
                ),
                provider_id: input.provider.id.clone(),
                plan_id: plan.digest().into(),
                policy_id: crate::execution_policy::POLICY_ID.into(),
                task_id: Some(format!("ownership-{mode}")),
                executable: owner.executable.to_string_lossy().into_owned(),
                args: if mode == "scan" {
                    vec![root.to_string_lossy().into_owned()]
                } else {
                    vec![root.to_string_lossy().into_owned(), "--inputs".into()]
                },
                cwd: root.to_string_lossy().into_owned(),
                origin: legion_effects::ToolOrigin::System,
                expected_digest: Some(owner.executable_digest.clone()),
                skip_version_probe: true,
                stdout_limit: LIMIT,
                stderr_limit: LIMIT,
                ..ExternalToolRequest::default()
            };
            let receipt = tool
                .execute(request.clone(), cancellation.child_token())
                .await;
            let identity_ok = receipt.request_id == request.request_id
                && receipt.provider_id == input.provider.id
                && receipt.plan_id == plan.digest()
                && receipt.policy_id == request.policy_id
                && receipt
                    .policy
                    .as_ref()
                    .is_some_and(|p| p.allowed && p.id == request.policy_id)
                && receipt.command.as_ref() == Some(&request.redacted())
                && receipt.cwd.as_deref() == Some(request.cwd.as_str())
                && receipt.executable.as_ref().is_some_and(|e| {
                    e.sealed()
                        && e.canonical_path.as_deref() == Some(owner.executable.as_path())
                        && e.digest.as_deref() == Some(owner.executable_digest.as_str())
                })
                && receipt.process_tree.started
                && receipt.process_tree.reaped;
            let decoded = if receipt.is_complete() && identity_ok {
                artifact(artifacts_root, &receipt).and_then(|b| {
                    serde_json::from_slice::<Value>(&b)
                        .map_err(|e| format!("ownership-output-invalid:{e}"))
                })
            } else {
                Err(format!(
                    "ownership-sdk-incomplete:{}",
                    receipt.state.as_str()
                ))
            };
            receipts.push(crate::execution_policy::receipt_json(&receipt));
            match decoded {
                Ok(document) => {
                    let check = if input.provider.configuration.get("ownershipSourceIdentity")
                        != Some(&document["inputInventory"]["sourceIdentity"])
                    {
                        Err("ownership-source-identity-not-frozen".into())
                    } else {
                        validate_envelope(
                            &document,
                            before.as_ref().expect("checked above"),
                            owner,
                            &root,
                            sequence == 1,
                        )
                    };
                    documents.push(document);
                    if let Err(gap) = check {
                        gaps.push(gap);
                        break;
                    }
                }
                Err(gap) => {
                    gaps.push(gap);
                    break;
                }
            }
        }
    }
    if let Err(gap) = owner.verify() {
        gaps.push(gap);
    }
    match (&before, snapshot(input)) {
        (Ok(before), Ok(after)) if before == &after => {}
        (_, Err(gap)) => gaps.push(gap),
        _ => gaps.push("ownership-input-closure-changed".into()),
    }
    if documents.len() == 3 {
        for document in &documents[1..] {
            if document["owner"]["inputs"] != documents[0]["owner"]["inputs"]
                || document["owner"]["trust"] != documents[0]["owner"]["trust"]
                || document["inputInventory"] != documents[0]["inputInventory"]
            {
                gaps.push("ownership-owner-inputs-changed".into());
            }
        }
    } else if gaps.is_empty() {
        gaps.push("ownership-owner-scan-not-observed".into());
    }
    let mut findings = Vec::new();
    let mut ev = serde_json::Map::new();
    let mut locations = serde_json::Map::new();
    let mut messages = serde_json::Map::new();
    let mut seen = BTreeSet::new();
    if gaps.is_empty() {
        // Only owner violations become advisory Audit findings. Covered exceptions stay
        // in retained report; detecting a harmless fingerprint never invents a conflict.
        for row in documents[1]["owner"]["report"]["violations"]
            .as_array()
            .expect("validated")
        {
            let path = row["file"].as_str().expect("validated");
            let raw_line = row["line"]
                .as_u64()
                .expect("owner verdict validates ordinal");
            let line = raw_line.max(1);
            let rule = row["fingerprint"]
                .as_str()
                .expect("owner verdict validates fingerprint");
            let item = finding(
                &format!("governance.capability-ownership:{rule}"),
                "warning",
                path,
                line as usize,
            );
            if !seen.insert(item.id.to_string()) {
                continue;
            }
            let message = format!(
                "{} duplicates RightKit owner {}",
                row["capability"].as_str().unwrap(),
                row["package"].as_str().unwrap()
            );
            ev.insert(item.id.to_string(), json!({"path":path,"line":line,"lineKnown":raw_line > 0,"rule":rule,
                "message":message,"capability":row["capability"],"owner":row["package"],"ownerFinding":row,
                "ownerEvidence":documents[1]["owner"]["evidence"],"ownerIdentity":owner.identity()}));
            locations.insert(item.id.to_string(), json!([format!("{path}:{line}")]));
            messages.insert(item.id.to_string(), json!(message));
            findings.push(item);
        }
    }
    details.insert("findingEvidence".into(), json!(ev));
    details.insert("findingLocations".into(), json!(locations));
    details.insert("findingMessages".into(), json!(messages));
    details.insert("nativeOwnerIdentity".into(), owner.identity());
    details.insert("ownerDocuments".into(), json!(documents));
    details.insert("executionReceipts".into(), json!(receipts));
    details.insert("frozenInputFiles".into(), json!(before.ok()));
    details.insert("hostDeclared".into(), json!(!raw.is_empty()));
    let complete = gaps.is_empty();
    result(
        input,
        if complete {
            ProviderStatus::Complete
        } else {
            ProviderStatus::Partial
        },
        complete,
        &denom,
        if complete { denom.entries.len() } else { 0 },
        findings,
        gaps.clone(),
        gaps,
        details,
    )
}
