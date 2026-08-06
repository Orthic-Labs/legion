// Semantic variant analysis engine per Security Appendix §34. Repository-wide
// enumeration under a frozen denominator with complete dispositions. Exact/
// same-rule search alone can never complete a receipt.

import {
  assertArtifactBinding,
  bindingFromPlan,
  digest,
  stableId,
} from './contracts.mjs';

function summarize(matches) {
  const count = (value) => matches.filter((item) => item.disposition === value).length;
  return {
    enumerated: matches.length,
    examined: matches.filter((item) => item.disposition !== 'UNRESOLVED').length,
    confirmed: count('CONFIRMED'),
    rejected: count('REJECTED'),
    duplicates: count('DUPLICATE'),
    outOfScope: count('OUT_OF_SCOPE'),
    unresolved: count('UNRESOLVED'),
  };
}

function missingStrategyReceipt({ candidate, verdict, binding }) {
  return {
    schemaVersion: 2,
    kind: 'security-variant-receipt',
    findingId: candidate.id,
    ruleId: candidate.ruleId,
    rootCauseSignature: verdict.rootCauseSignature ?? null,
    provider: 'security.variant-analysis',
    providerVersion: '2',
    binding,
    denominator: null,
    strategies: [],
    matches: [],
    summary: { enumerated: 0, examined: 0, confirmed: 0, rejected: 0, duplicates: 0, outOfScope: 0, unresolved: 0 },
    complete: false,
    coverageGaps: ['missing-variant-strategy'],
  };
}

export function analyzeVariants({
  plan,
  model,
  candidates,
  adjudication,
  packByProvider,
}) {
  const binding = bindingFromPlan(plan);
  for (const [label, artifact] of Object.entries({ model, candidates, adjudication })) {
    assertArtifactBinding(artifact, binding, label);
  }
  const candidateById = new Map(candidates.candidates.map((item) => [item.id, item]));
  const receipts = [];

  for (const verdict of adjudication.verdicts ?? []) {
    if (!['TRUE_POSITIVE', 'LIKELY_TRUE_POSITIVE'].includes(verdict.verdict)) continue;
    const candidate = candidateById.get(verdict.candidateId);
    if (!candidate) throw new Error(`missing candidate ${verdict.candidateId}`);
    const pack = packByProvider.get(candidate.provider);
    const strategy = pack?.variantStrategies?.[candidate.ruleId];
    if (!strategy) {
      receipts.push(missingStrategyReceipt({ candidate, verdict, binding }));
      continue;
    }

    const rootCauseSignature = verdict.rootCauseSignature
      ?? strategy.rootCause(candidate, verdict);
    const result = strategy.enumerate({
      plan,
      model,
      candidate,
      verdict,
      binding,
    }, rootCauseSignature);

    const matches = (result.matches ?? []).map((match) => ({
      ...match,
      id: match.id ?? stableId('security-variant-match', {
        findingId: candidate.id,
        semanticFingerprint: match.semanticFingerprint,
        file: match.file,
        line: match.line,
      }),
    }));
    const summary = summarize(matches);
    const denominator = result.denominator;
    const strategies = result.strategies ?? [];
    const coverageGaps = result.coverageGaps ?? [];
    const complete = Boolean(
      denominator
      && denominator.expected === denominator.examined
      && (denominator.unexamined ?? []).length === 0
      && summary.enumerated === matches.length
      && summary.examined === matches.length
      && summary.unresolved === 0
      && strategies.every((item) => item.complete)
      && coverageGaps.length === 0
    );

    receipts.push({
      schemaVersion: 2,
      kind: 'security-variant-receipt',
      findingId: candidate.id,
      ruleId: candidate.ruleId,
      rootCauseSignature,
      provider: 'security.variant-analysis',
      providerVersion: '2',
      binding,
      denominator,
      strategies,
      matches,
      summary,
      complete,
      coverageGaps,
      receiptDigest: digest({
        findingId: candidate.id,
        rootCauseSignature,
        denominator,
        strategies,
        matches,
      }),
    });
  }

  return {
    schemaVersion: 2,
    kind: 'security-variant-results',
    provider: 'security.variant-analysis',
    providerVersion: '2',
    binding,
    complete: receipts.every((item) => item.complete),
    receipts,
    coverageGaps: receipts
      .filter((item) => !item.complete)
      .map((item) => ({ kind: 'variant-incomplete', findingId: item.findingId })),
  };
}
