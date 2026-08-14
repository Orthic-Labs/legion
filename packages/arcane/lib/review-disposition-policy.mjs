// Evidence-only policy decisions used by S11 architecture evaluators.
// Inputs are explicit structured observations; corpus prose & expected outcomes
// never participate in any decision.

const NON_EMPTY = (value) => typeof value === 'string' && value.trim().length > 0;
const uniqueStrings = (value) => Array.isArray(value) && value.every(NON_EMPTY) && new Set(value).size === value.length;

function frozen(value) { return Object.freeze(value); }

function invalid(policy, reason) {
  return frozen({ policy, status: 'DENY', code: 'ARC_POLICY_EVIDENCE_INVALID', reason });
}

function handoffDecision(evidence) {
  if (!evidence || typeof evidence !== 'object') return invalid('handoff', 'structured handoff evidence is required');
  const { irreversible, uncertainty, reviewBudget, externalBlock, budgetStop } = evidence;
  if (typeof irreversible !== 'boolean' || typeof uncertainty !== 'boolean' || typeof externalBlock !== 'boolean' || typeof budgetStop !== 'boolean' || !reviewBudget || typeof reviewBudget.exhausted !== 'boolean') {
    return invalid('handoff', 'irreversibility, uncertainty, review budget, external block, and budget stop must be explicit booleans');
  }
  if (!irreversible || !uncertainty) {
    return frozen({ policy: 'handoff', status: 'ALLOW', disposition: 'CONTINUE', reason: 'no unresolved irreversible decision' });
  }
  if (budgetStop) return frozen({ policy: 'handoff', status: 'BLOCK', disposition: 'BUDGET_STOP', reason: 'review budget stop is recorded' });
  if (externalBlock) return frozen({ policy: 'handoff', status: 'BLOCK', disposition: 'BLOCKED_EXTERNAL', reason: 'external dependency is recorded' });
  if (reviewBudget.exhausted) return frozen({ policy: 'handoff', status: 'BLOCK', disposition: 'NEEDS_SPIKE', reason: 'irreversible uncertainty remains after recorded review budget exhaustion' });
  return frozen({ policy: 'handoff', status: 'BLOCK', disposition: 'NEEDS_REVIEW', reason: 'irreversible uncertainty remains within review budget' });
}

function demonstratedLink(link, knownNodes) {
  return link && typeof link === 'object' && NON_EMPTY(link.from) && NON_EMPTY(link.to)
    && knownNodes.has(link.from) && knownNodes.has(link.to)
    && NON_EMPTY(link.evidenceId) && link.demonstrated === true;
}

function coverageDisposition(coverage) {
  if (!coverage || typeof coverage !== 'object' || !uniqueStrings(coverage.claimedAreas) || !uniqueStrings(coverage.inspectedAreas)) {
    return invalid('review-coverage', 'claimed and inspected areas must be unique non-empty string arrays');
  }
  const inspected = new Set(coverage.inspectedAreas);
  const missing = coverage.claimedAreas.filter((area) => !inspected.has(area));
  return frozen({
    policy: 'review-coverage',
    status: missing.length === 0 ? 'ALLOW' : 'DENY',
    disposition: missing.length === 0 ? 'COVERAGE_SUPPORTED' : 'INCOMPLETE_COVERAGE',
    claimedAreas: coverage.claimedAreas,
    inspectedAreas: coverage.inspectedAreas,
    missingAreas: frozen(missing),
  });
}

function exploitChainDecision(evidence) {
  if (!evidence || typeof evidence !== 'object' || !uniqueStrings(evidence.nodes) || !Array.isArray(evidence.links)) {
    return invalid('exploit-chain', 'nodes and links must be explicit structured evidence');
  }
  const nodeSet = new Set(evidence.nodes);
  const invalidLinks = evidence.links.filter((link) => !demonstratedLink(link, nodeSet));
  const coverage = coverageDisposition(evidence.coverage);
  if (coverage.code) return coverage;
  if (invalidLinks.length > 0 || evidence.links.length === 0) {
    return frozen({
      policy: 'exploit-chain', status: 'DENY', disposition: 'NO_EXPLOIT_CHAIN',
      reason: 'every exploit-chain edge needs demonstrated, identified evidence',
      unsupportedLinkCount: invalidLinks.length || 1,
      coverage,
    });
  }
  return frozen({
    policy: 'exploit-chain', status: 'ALLOW', disposition: 'EXPLOIT_CHAIN_SUPPORTED',
    linkCount: evidence.links.length, coverage,
  });
}

function reviewReopenDecision(evidence) {
  if (!evidence || typeof evidence !== 'object' || !Array.isArray(evidence.findings) || typeof evidence.reviewClosed !== 'boolean') {
    return invalid('review-reopen', 'review closure and findings must be explicit');
  }
  const malformed = evidence.findings.some((finding) => !finding || typeof finding !== 'object' || !NON_EMPTY(finding.id) || typeof finding.blocking !== 'boolean' || !NON_EMPTY(finding.disposition));
  if (malformed) return invalid('review-reopen', 'each finding needs id, blocking flag, and disposition');
  const blocking = evidence.findings.filter((finding) => finding.blocking || finding.disposition !== 'ADVISORY');
  if (!evidence.reviewClosed) return frozen({ policy: 'review-reopen', status: 'ALLOW', disposition: 'REVIEW_OPEN', reason: 'review is already open' });
  if (blocking.length === 0) return frozen({ policy: 'review-reopen', status: 'ALLOW', disposition: 'NO_REOPEN', reason: 'closed review has advisory findings only', advisoryCount: evidence.findings.length });
  return frozen({ policy: 'review-reopen', status: 'BLOCK', disposition: 'REOPEN_REQUIRED', reason: 'closed review contains non-advisory or blocking finding', blockingFindingIds: frozen(blocking.map(({ id }) => id)) });
}

export function evaluateReviewDispositionCase(id, evidence) {
  if (id === 'AE-HANDOFF-004') return handoffDecision(evidence);
  if (id === 'AE-REVIEW-VERDICT-SECURITY-002') return exploitChainDecision(evidence);
  if (id === 'AE-REVIEW-VERDICT-SECURITY-005') return reviewReopenDecision(evidence);
  return null;
}

export function validateReviewDispositionDecision(id, decision) {
  if (!decision || typeof decision !== 'object') return false;
  if (id === 'AE-HANDOFF-004') return decision.status === 'BLOCK' && ['NEEDS_SPIKE', 'BLOCKED_EXTERNAL', 'BUDGET_STOP'].includes(decision.disposition);
  if (id === 'AE-REVIEW-VERDICT-SECURITY-002') return decision.status === 'DENY' && decision.disposition === 'NO_EXPLOIT_CHAIN' && decision.coverage?.disposition === 'INCOMPLETE_COVERAGE';
  if (id === 'AE-REVIEW-VERDICT-SECURITY-005') return decision.status === 'ALLOW' && decision.disposition === 'NO_REOPEN';
  return false;
}

export const reviewDispositionPolicyIds = frozen([
  'AE-HANDOFF-004',
  'AE-REVIEW-VERDICT-SECURITY-002',
  'AE-REVIEW-VERDICT-SECURITY-005',
]);
