//! Port of the small self-contained src/lib/core files (packet P5a-core):
//! completeness.mjs, judgment-packets.mjs, reviewer-policy.mjs,
//! claim-levels.mjs, run-layout.mjs, and src/lib/core/plan-stages/registry.mjs.

use serde_json::Value;
use std::collections::BTreeSet;

// ---- completeness.mjs: reconcileClaim ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimReconciliation {
    pub complete: bool,
    pub status: &'static str,
    pub gaps: Vec<String>,
}

/// Port of `reconcileClaim({ requiredEvidence, evidence })`. `evidence`
/// items are either bare IDs or `{id, ...}` records in JS; callers here
/// pass the resolved ID strings directly.
pub fn reconcile_claim(
    required_evidence: &[String],
    evidence_ids: &[String],
) -> ClaimReconciliation {
    let available: BTreeSet<&str> = evidence_ids.iter().map(String::as_str).collect();
    let gaps: Vec<String> = required_evidence
        .iter()
        .filter(|id| !available.contains(id.as_str()))
        .cloned()
        .collect();
    ClaimReconciliation {
        complete: gaps.is_empty(),
        status: if gaps.is_empty() {
            "pass"
        } else {
            "incomplete"
        },
        gaps,
    }
}

// ---- judgment-packets.mjs: buildJudgmentPacket ----

pub const JUDGMENT_VERDICTS: [&str; 4] = ["confirmed", "rejected", "unproven", "needs-human"];

#[derive(Debug, Clone)]
pub struct JudgmentPacketInput {
    pub subject: Value,
    pub evidence: Vec<Value>,
    pub omitted: Vec<Value>,
    pub reviewer_role: String,
    pub budget: Value,
    pub lens: Option<Value>,
}

/// Port of `buildJudgmentPacket`. JS deep-clones `subject` via
/// `JSON.parse(JSON.stringify(...))`; `Value` clone is already a deep copy
/// of owned data, so `.clone()` on the input is equivalent.
pub fn build_judgment_packet(input: JudgmentPacketInput) -> Value {
    let mut packet = serde_json::Map::new();
    packet.insert("schemaVersion".into(), Value::from(1));
    packet.insert("subject".into(), input.subject);
    packet.insert("evidence".into(), Value::Array(input.evidence));
    packet.insert("omitted".into(), Value::Array(input.omitted));
    packet.insert("reviewerRole".into(), Value::String(input.reviewer_role));
    if let Some(lens) = input.lens {
        packet.insert("lens".into(), lens);
    }
    packet.insert(
        "verdicts".into(),
        Value::Array(
            JUDGMENT_VERDICTS
                .iter()
                .map(|v| Value::String((*v).to_string()))
                .collect(),
        ),
    );
    packet.insert("budget".into(), input.budget);
    Value::Object(packet)
}

// ---- reviewer-policy.mjs: reviewerPolicy ----

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewerPolicy {
    pub producer: String,
    pub reviewer: String,
    pub context_id: String,
    pub fresh: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewerPolicyError {
    SelfAdjudication,
    ContextReuse,
}

impl std::fmt::Display for ReviewerPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewerPolicyError::SelfAdjudication => {
                write!(f, "reviewer self-adjudication forbidden")
            }
            ReviewerPolicyError::ContextReuse => write!(f, "reviewer context reuse forbidden"),
        }
    }
}
impl std::error::Error for ReviewerPolicyError {}

/// Port of `reviewerPolicy`.
pub fn reviewer_policy(
    producer: &str,
    reviewer: &str,
    context_id: &str,
    used_contexts: &[String],
) -> Result<ReviewerPolicy, ReviewerPolicyError> {
    if producer == reviewer {
        return Err(ReviewerPolicyError::SelfAdjudication);
    }
    if used_contexts.iter().any(|c| c == context_id) {
        return Err(ReviewerPolicyError::ContextReuse);
    }
    Ok(ReviewerPolicy {
        producer: producer.to_string(),
        reviewer: reviewer.to_string(),
        context_id: context_id.to_string(),
        fresh: true,
    })
}

// ---- claim-levels.mjs: CLAIM_LEVELS, achievedClaimLevel ----

pub const CLAIM_LEVELS: [&str; 5] = ["inventory", "source", "runtime", "product", "release"];

/// Port of `achievedClaimLevel(decisions)`: the highest claim level whose
/// decision (and every lower level's decision, per JS's left-to-right
/// `reduce`) is `"pass"`. `decisions` maps claim-level name to decision
/// string.
pub fn achieved_claim_level(
    decisions: &std::collections::BTreeMap<String, String>,
) -> Option<&'static str> {
    let mut level: Option<&'static str> = None;
    for candidate in CLAIM_LEVELS {
        if decisions.get(candidate).map(String::as_str) == Some("pass") {
            level = Some(candidate);
        }
    }
    level
}

// ---- run-layout.mjs: RUN_DIRECTORIES, runLayout ----

pub const RUN_DIRECTORIES: [&str; 13] = [
    "plan",
    "inventory/product-portfolio",
    "inventory/components",
    "inventory/stacks",
    "inventory/external-systems",
    "controls",
    "scenarios",
    "facts",
    "provider-results",
    "raw-outputs",
    "reports",
    "verification",
    "remediation",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLayout {
    pub root: String,
    pub directories: Vec<String>,
}

/// Port of `runLayout(root)`.
pub fn run_layout(root: impl Into<String>) -> RunLayout {
    RunLayout {
        root: root.into(),
        directories: RUN_DIRECTORIES.iter().map(|d| d.to_string()).collect(),
    }
}

// ---- plan-stages/registry.mjs: PLANNING_STAGE_IDS, requiredStagesFor ----

pub const PLANNING_STAGE_IDS: [&str; 12] = [
    "repository-binding",
    "blueprint-packet",
    "product-portfolio",
    "component-graph",
    "stack-external-system-graph",
    "release-contract-product-context",
    "control-baseline",
    "evidence-capabilities",
    "scenario-matrices",
    "family-lens-provider-rule-selection",
    "provider-dag",
    "plan-sealing",
];

/// Port of the `REQUIRED` table in plan-stages/registry.mjs: which stage IDs
/// are mandatory for a given claim level.
pub fn required_stages_for(claim_level: &str) -> &'static [&'static str] {
    const INVENTORY: [&str; 3] = [
        "repository-binding",
        "blueprint-packet",
        "product-portfolio",
    ];
    const SOURCE: [&str; 9] = [
        "repository-binding",
        "blueprint-packet",
        "product-portfolio",
        "component-graph",
        "stack-external-system-graph",
        "release-contract-product-context",
        "control-baseline",
        "evidence-capabilities",
        "scenario-matrices",
    ];
    match claim_level {
        "inventory" => &INVENTORY,
        "source" => &SOURCE,
        "runtime" | "product" | "release" => &PLANNING_STAGE_IDS,
        _ => &[],
    }
}
