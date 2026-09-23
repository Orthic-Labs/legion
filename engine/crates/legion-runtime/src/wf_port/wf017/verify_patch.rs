//! Port of src/lib/remediation/verify-patch.mjs.
//!
//! Neutral patch verification per SNIP-FIX-01: the patch producer never
//! verifies its own result. Verification reruns the affected provider
//! closure plus required baseline gates.

use serde::Serialize;

#[derive(Debug, Clone)]
pub struct AffectedProviderResult {
    pub complete: bool,
    pub status: String,
}

#[derive(Debug, Clone)]
pub struct BaselineGate {
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CoverageGap {
    pub kind: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatchVerification {
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    pub kind: &'static str,
    #[serde(rename = "proposalId")]
    pub proposal_id: Option<String>,
    #[serde(rename = "patchDigest")]
    pub patch_digest: Option<String>,
    #[serde(rename = "verifiedBy")]
    pub verified_by: &'static str,
    #[serde(rename = "providersPass")]
    pub providers_pass: bool,
    #[serde(rename = "gatesPass")]
    pub gates_pass: bool,
    pub valid: bool,
    #[serde(rename = "coverageGaps")]
    pub coverage_gaps: Vec<CoverageGap>,
}

pub struct VerifyPatchInput {
    pub proposal_id: Option<String>,
    pub patch_digest: Option<String>,
    pub affected_provider_results: Vec<AffectedProviderResult>,
    pub baseline_gates: Vec<BaselineGate>,
}

pub fn verify_patch(input: VerifyPatchInput) -> PatchVerification {
    let providers_pass = input
        .affected_provider_results
        .iter()
        .all(|result| result.complete && result.status == "pass");
    let gates_pass = input.baseline_gates.iter().all(|gate| gate.passed);

    let mut coverage_gaps = Vec::new();
    if !providers_pass {
        coverage_gaps.push(CoverageGap {
            kind: "affected-provider-failed",
        });
    }
    if !gates_pass {
        coverage_gaps.push(CoverageGap {
            kind: "baseline-gate-failed",
        });
    }

    PatchVerification {
        schema_version: 1,
        kind: "legion-patch-verification",
        proposal_id: input.proposal_id,
        patch_digest: input.patch_digest,
        verified_by: "neutral-verification", // never the patch producer
        providers_pass,
        gates_pass,
        valid: providers_pass && gates_pass,
        coverage_gaps,
    }
}
