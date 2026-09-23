//! Port of `src/lib/verification/arcane/review-disposition-policy.mjs` —
//! evidence-only policy decisions used by S11 architecture evaluators.
//! Inputs are explicit structured observations; corpus prose and expected
//! outcomes never participate in any decision.

pub const REVIEW_DISPOSITION_POLICY_IDS: [&str; 3] = [
    "AE-HANDOFF-004",
    "AE-REVIEW-VERDICT-SECURITY-002",
    "AE-REVIEW-VERDICT-SECURITY-005",
];

pub fn review_disposition_policy_ids() -> &'static [&'static str] {
    &REVIEW_DISPOSITION_POLICY_IDS
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Status {
    Allow,
    Deny,
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageDisposition {
    pub status: Status,
    pub disposition: &'static str,
    pub claimed_areas: Vec<String>,
    pub inspected_areas: Vec<String>,
    pub missing_areas: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReviewDispositionDecision {
    Invalid { policy: &'static str, reason: &'static str },
    Handoff { status: Status, disposition: &'static str, reason: &'static str },
    ExploitChain { status: Status, disposition: &'static str, reason: Option<&'static str>, link_count: Option<usize>, unsupported_link_count: Option<usize>, coverage: CoverageDisposition },
    ReviewReopen { status: Status, disposition: &'static str, reason: &'static str, advisory_count: Option<usize>, blocking_finding_ids: Vec<String> },
}

impl ReviewDispositionDecision {
    pub fn status(&self) -> &Status {
        match self {
            ReviewDispositionDecision::Invalid { .. } => &Status::Deny,
            ReviewDispositionDecision::Handoff { status, .. } => status,
            ReviewDispositionDecision::ExploitChain { status, .. } => status,
            ReviewDispositionDecision::ReviewReopen { status, .. } => status,
        }
    }

    pub fn disposition(&self) -> Option<&'static str> {
        match self {
            ReviewDispositionDecision::Invalid { .. } => None,
            ReviewDispositionDecision::Handoff { disposition, .. } => Some(disposition),
            ReviewDispositionDecision::ExploitChain { disposition, .. } => Some(disposition),
            ReviewDispositionDecision::ReviewReopen { disposition, .. } => Some(disposition),
        }
    }
}

fn non_empty(value: &str) -> bool {
    !value.trim().is_empty()
}

fn unique_strings(values: &[String]) -> bool {
    if values.iter().any(|v| !non_empty(v)) {
        return false;
    }
    let set: std::collections::HashSet<&String> = values.iter().collect();
    set.len() == values.len()
}

pub struct HandoffEvidence {
    pub irreversible: bool,
    pub uncertainty: bool,
    pub review_budget_exhausted: bool,
    pub external_block: bool,
    pub budget_stop: bool,
}

fn handoff_decision(evidence: Option<&HandoffEvidence>) -> ReviewDispositionDecision {
    let Some(evidence) = evidence else {
        return ReviewDispositionDecision::Invalid {
            policy: "handoff",
            reason: "irreversibility, uncertainty, review budget, external block, and budget stop must be explicit booleans",
        };
    };
    if !evidence.irreversible || !evidence.uncertainty {
        return ReviewDispositionDecision::Handoff {
            status: Status::Allow,
            disposition: "CONTINUE",
            reason: "no unresolved irreversible decision",
        };
    }
    if evidence.budget_stop {
        return ReviewDispositionDecision::Handoff {
            status: Status::Block,
            disposition: "BUDGET_STOP",
            reason: "review budget stop is recorded",
        };
    }
    if evidence.external_block {
        return ReviewDispositionDecision::Handoff {
            status: Status::Block,
            disposition: "BLOCKED_EXTERNAL",
            reason: "external dependency is recorded",
        };
    }
    if evidence.review_budget_exhausted {
        return ReviewDispositionDecision::Handoff {
            status: Status::Block,
            disposition: "NEEDS_SPIKE",
            reason: "irreversible uncertainty remains after recorded review budget exhaustion",
        };
    }
    ReviewDispositionDecision::Handoff {
        status: Status::Block,
        disposition: "NEEDS_REVIEW",
        reason: "irreversible uncertainty remains within review budget",
    }
}

pub struct Coverage {
    pub claimed_areas: Vec<String>,
    pub inspected_areas: Vec<String>,
}

fn coverage_disposition(coverage: Option<&Coverage>) -> Result<CoverageDisposition, ReviewDispositionDecision> {
    let Some(coverage) = coverage else {
        return Err(ReviewDispositionDecision::Invalid {
            policy: "review-coverage",
            reason: "claimed and inspected areas must be unique non-empty string arrays",
        });
    };
    if !unique_strings(&coverage.claimed_areas) || !unique_strings(&coverage.inspected_areas) {
        return Err(ReviewDispositionDecision::Invalid {
            policy: "review-coverage",
            reason: "claimed and inspected areas must be unique non-empty string arrays",
        });
    }
    let inspected: std::collections::HashSet<&String> = coverage.inspected_areas.iter().collect();
    let missing: Vec<String> = coverage
        .claimed_areas
        .iter()
        .filter(|a| !inspected.contains(a))
        .cloned()
        .collect();
    let status = if missing.is_empty() { Status::Allow } else { Status::Deny };
    let disposition = if missing.is_empty() { "COVERAGE_SUPPORTED" } else { "INCOMPLETE_COVERAGE" };
    Ok(CoverageDisposition {
        status,
        disposition,
        claimed_areas: coverage.claimed_areas.clone(),
        inspected_areas: coverage.inspected_areas.clone(),
        missing_areas: missing,
    })
}

pub struct ExploitLink {
    pub from: String,
    pub to: String,
    pub demonstrated: bool,
    pub evidence_id: String,
}

pub struct ExploitChainEvidence {
    pub nodes: Vec<String>,
    pub links: Vec<ExploitLink>,
    pub coverage: Option<Coverage>,
}

fn demonstrated_link(link: &ExploitLink, known_nodes: &std::collections::HashSet<&String>) -> bool {
    non_empty(&link.from)
        && non_empty(&link.to)
        && known_nodes.contains(&link.from)
        && known_nodes.contains(&link.to)
        && non_empty(&link.evidence_id)
        && link.demonstrated
}

fn exploit_chain_decision(evidence: Option<&ExploitChainEvidence>) -> ReviewDispositionDecision {
    let Some(evidence) = evidence else {
        return ReviewDispositionDecision::Invalid {
            policy: "exploit-chain",
            reason: "nodes and links must be explicit structured evidence",
        };
    };
    if !unique_strings(&evidence.nodes) {
        return ReviewDispositionDecision::Invalid {
            policy: "exploit-chain",
            reason: "nodes and links must be explicit structured evidence",
        };
    }
    let node_set: std::collections::HashSet<&String> = evidence.nodes.iter().collect();
    let invalid_links = evidence.links.iter().filter(|l| !demonstrated_link(l, &node_set)).count();
    let coverage = match coverage_disposition(evidence.coverage.as_ref()) {
        Ok(c) => c,
        Err(invalid) => return invalid,
    };
    if invalid_links > 0 || evidence.links.is_empty() {
        return ReviewDispositionDecision::ExploitChain {
            status: Status::Deny,
            disposition: "NO_EXPLOIT_CHAIN",
            reason: Some("every exploit-chain edge needs demonstrated, identified evidence"),
            link_count: None,
            unsupported_link_count: Some(if invalid_links > 0 { invalid_links } else { 1 }),
            coverage,
        };
    }
    ReviewDispositionDecision::ExploitChain {
        status: Status::Allow,
        disposition: "EXPLOIT_CHAIN_SUPPORTED",
        reason: None,
        link_count: Some(evidence.links.len()),
        unsupported_link_count: None,
        coverage,
    }
}

pub struct Finding {
    pub id: String,
    pub blocking: bool,
    pub disposition: String,
}

pub struct ReviewReopenEvidence {
    pub findings: Vec<Finding>,
    pub review_closed: bool,
}

fn review_reopen_decision(evidence: Option<&ReviewReopenEvidence>) -> ReviewDispositionDecision {
    let Some(evidence) = evidence else {
        return ReviewDispositionDecision::Invalid {
            policy: "review-reopen",
            reason: "review closure and findings must be explicit",
        };
    };
    let malformed = evidence.findings.iter().any(|f| !non_empty(&f.id) || !non_empty(&f.disposition));
    if malformed {
        return ReviewDispositionDecision::Invalid {
            policy: "review-reopen",
            reason: "each finding needs id, blocking flag, and disposition",
        };
    }
    let blocking: Vec<String> = evidence
        .findings
        .iter()
        .filter(|f| f.blocking || f.disposition != "ADVISORY")
        .map(|f| f.id.clone())
        .collect();
    if !evidence.review_closed {
        return ReviewDispositionDecision::ReviewReopen {
            status: Status::Allow,
            disposition: "REVIEW_OPEN",
            reason: "review is already open",
            advisory_count: None,
            blocking_finding_ids: Vec::new(),
        };
    }
    if blocking.is_empty() {
        return ReviewDispositionDecision::ReviewReopen {
            status: Status::Allow,
            disposition: "NO_REOPEN",
            reason: "closed review has advisory findings only",
            advisory_count: Some(evidence.findings.len()),
            blocking_finding_ids: Vec::new(),
        };
    }
    ReviewDispositionDecision::ReviewReopen {
        status: Status::Block,
        disposition: "REOPEN_REQUIRED",
        reason: "closed review contains non-advisory or blocking finding",
        advisory_count: None,
        blocking_finding_ids: blocking,
    }
}

pub enum CaseEvidence<'a> {
    Handoff(&'a HandoffEvidence),
    ExploitChain(&'a ExploitChainEvidence),
    ReviewReopen(&'a ReviewReopenEvidence),
    Missing,
}

pub fn evaluate_review_disposition_case(id: &str, evidence: CaseEvidence) -> Option<ReviewDispositionDecision> {
    match id {
        "AE-HANDOFF-004" => Some(handoff_decision(match evidence {
            CaseEvidence::Handoff(e) => Some(e),
            _ => None,
        })),
        "AE-REVIEW-VERDICT-SECURITY-002" => Some(exploit_chain_decision(match evidence {
            CaseEvidence::ExploitChain(e) => Some(e),
            _ => None,
        })),
        "AE-REVIEW-VERDICT-SECURITY-005" => Some(review_reopen_decision(match evidence {
            CaseEvidence::ReviewReopen(e) => Some(e),
            _ => None,
        })),
        _ => None,
    }
}

pub fn validate_review_disposition_decision(id: &str, decision: &ReviewDispositionDecision) -> bool {
    match id {
        "AE-HANDOFF-004" => matches!(
            decision,
            ReviewDispositionDecision::Handoff { status: Status::Block, disposition, .. }
                if matches!(*disposition, "NEEDS_SPIKE" | "BLOCKED_EXTERNAL" | "BUDGET_STOP")
        ),
        "AE-REVIEW-VERDICT-SECURITY-002" => matches!(
            decision,
            ReviewDispositionDecision::ExploitChain { status: Status::Deny, disposition: "NO_EXPLOIT_CHAIN", coverage, .. }
                if coverage.disposition == "INCOMPLETE_COVERAGE"
        ),
        "AE-REVIEW-VERDICT-SECURITY-005" => matches!(
            decision,
            ReviewDispositionDecision::ReviewReopen { status: Status::Allow, disposition: "NO_REOPEN", .. }
        ),
        _ => false,
    }
}
