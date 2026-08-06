// Attack-path reconciliation per Security Appendix §25. Paths become eligible
// for chain adjudication only when every mandatory primitive survives; a path
// is never marked PROVEN during reconciliation.

import { assertArtifactBinding, bindingFromPlan } from './contracts.mjs';

const SURVIVING = new Set(['TRUE_POSITIVE', 'LIKELY_TRUE_POSITIVE']);
const HARD_REFUTE = new Set(['FALSE_POSITIVE', 'OUT_OF_SCOPE']);

export function reconcileAttackPaths({ plan, hypothesesArtifact, adjudication }) {
  const binding = bindingFromPlan(plan);
  assertArtifactBinding(hypothesesArtifact, binding, 'attack paths');
  assertArtifactBinding(adjudication, binding, 'security adjudication');
  const verdictByCandidate = new Map(
    (adjudication.verdicts ?? []).map((verdict) => [verdict.candidateId, verdict]),
  );

  const hypotheses = hypothesesArtifact.hypotheses.map((path) => {
    const stepVerdicts = path.steps.map((step) => ({
      candidateId: step.candidateId,
      verdict: verdictByCandidate.get(step.candidateId) ?? null,
    }));
    const missing = stepVerdicts.filter((item) => item.verdict === null);
    const refuted = stepVerdicts.filter((item) => HARD_REFUTE.has(item.verdict?.verdict));
    const unsupported = stepVerdicts.filter((item) =>
      item.verdict && !SURVIVING.has(item.verdict.verdict));

    let status = 'PARTIALLY_SUPPORTED';
    let reason = 'all primitive steps survived; composition has not been adjudicated';
    if (missing.length > 0) {
      status = 'UNPROVEN';
      reason = 'one or more primitive steps have no verdict';
    } else if (refuted.length > 0) {
      status = 'REFUTED';
      reason = 'one or more mandatory primitive steps were refuted';
    } else if (unsupported.length > 0) {
      status = 'UNPROVEN';
      reason = 'one or more steps did not survive as vulnerabilities';
    }

    return {
      ...path,
      status,
      reconciliation: {
        reason,
        stepVerdicts,
        eligibleForChainAdjudication: status === 'PARTIALLY_SUPPORTED',
      },
    };
  });

  return {
    ...hypothesesArtifact,
    kind: 'reconciled-attack-path-hypotheses',
    hypotheses,
    complete: adjudication.complete === true && hypothesesArtifact.complete === true,
  };
}
