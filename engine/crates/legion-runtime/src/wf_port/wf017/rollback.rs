//! Port of src/lib/remediation/rollback.mjs (B7-034).
//!
//! Like apply, the mutation is the host's; this module owns the contract. A
//! rollback that did not restore the expected fingerprint is reported as
//! failed with exact recovery data - it is never suppressed.

use super::digest_of;
use async_trait::async_trait;
use serde::Serialize;

/// What `rollbackApply` needs from a prior apply receipt. Only the fields the
/// JS source reads (`proposalId`, `reversePatchDigest`, `beforeFingerprint`,
/// `digest`) are represented.
#[derive(Debug, Clone, Default)]
pub struct ApplyReceipt {
    pub proposal_id: Option<String>,
    pub reverse_patch_digest: Option<String>,
    pub before_fingerprint: Option<String>,
    pub digest: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RestoreRequest {
    pub proposal_id: Option<String>,
    pub reverse_patch_digest: Option<String>,
    pub expected_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct RestoreResult {
    pub ok: bool,
    pub fingerprint: Option<String>,
    pub error: Option<String>,
}

/// The host mutator that actually restores the working tree. The audit
/// engine never mutates repositories itself; rollback fails loudly if no
/// mutator is supplied.
#[async_trait]
pub trait Mutator: Send + Sync {
    async fn restore(&self, request: RestoreRequest) -> RestoreResult;
}

#[derive(Debug, Clone)]
pub struct MissingMutator;

impl std::fmt::Display for MissingMutator {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("rollback requires a host mutator; the audit engine does not mutate repositories")
    }
}
impl std::error::Error for MissingMutator {}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryHint {
    pub command: Option<Vec<String>>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RollbackReceipt {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: &'static str,
    #[serde(rename = "proposalId")]
    pub proposal_id: Option<String>,
    #[serde(rename = "applyDigest")]
    pub apply_digest: Option<String>,
    #[serde(rename = "reversePatchDigest")]
    pub reverse_patch_digest: Option<String>,
    #[serde(rename = "expectedFingerprint")]
    pub expected_fingerprint: Option<String>,
    #[serde(rename = "restoredFingerprint")]
    pub restored_fingerprint: Option<String>,
    pub restored: bool,
    pub error: Option<String>,
    pub recovery: RecoveryHint,
    pub digest: String,
}

/// `rollbackApply({ applyReceipt, mutator, expectedFingerprint })`.
/// `mutator` is `Option<&dyn Mutator>` here rather than an optional field on
/// an input struct, matching the JS `typeof mutator?.restore !== 'function'`
/// guard, which throws before doing anything else.
pub async fn rollback_apply(
    apply_receipt: &ApplyReceipt,
    mutator: Option<&dyn Mutator>,
    expected_fingerprint: Option<String>,
) -> Result<RollbackReceipt, MissingMutator> {
    let mutator = mutator.ok_or(MissingMutator)?;
    let target = expected_fingerprint.or_else(|| apply_receipt.before_fingerprint.clone());

    let result = mutator
        .restore(RestoreRequest {
            proposal_id: apply_receipt.proposal_id.clone(),
            reverse_patch_digest: apply_receipt.reverse_patch_digest.clone(),
            expected_fingerprint: target.clone(),
        })
        .await;

    let restored_fingerprint = result.fingerprint.clone();
    let restored = result.ok && restored_fingerprint == target;
    let error = if restored {
        None
    } else {
        Some(
            result
                .error
                .unwrap_or_else(|| "restored fingerprint does not match the pre-apply state".to_string()),
        )
    };
    let recovery = if restored {
        RecoveryHint {
            command: None,
            description: "no recovery needed".to_string(),
        }
    } else {
        RecoveryHint {
            command: Some(vec![
                "legion".to_string(),
                "remediation".to_string(),
                "restore-checkpoint".to_string(),
                "--proposal".to_string(),
                apply_receipt
                    .proposal_id
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string()),
            ]),
            description: "the working tree is NOT at the pre-apply fingerprint; restore from the sandbox checkpoint before continuing".to_string(),
        }
    };

    let mut receipt = RollbackReceipt {
        schema_version: 1,
        kind: "legion-remediation-rollback-receipt",
        proposal_id: apply_receipt.proposal_id.clone(),
        apply_digest: apply_receipt.digest.clone(),
        reverse_patch_digest: apply_receipt.reverse_patch_digest.clone(),
        expected_fingerprint: target,
        restored_fingerprint,
        restored,
        error,
        recovery,
        digest: String::new(),
    };
    receipt.digest = digest_of("rollback", &receipt);
    Ok(receipt)
}
