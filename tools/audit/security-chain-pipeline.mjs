// Chain bundle pipeline per Security Appendix §29. Prepares one fresh-context
// packet per eligible path and finalizes verdicts; duplicates are invalid.

import { randomUUID } from 'node:crypto';
import {
  createChainAdjudicationPacket,
  finalizeChainVerdict,
} from '../../src/adapters/security-chain-adjudication.mjs';

export function prepareChainAdjudicationBundle({
  plan,
  reconciledPaths,
  candidates,
  candidateAdjudication,
  model,
  synthesizerContextId = 'attack-path-synthesis',
}) {
  const eligible = reconciledPaths.hypotheses.filter(
    (path) => path.reconciliation?.eligibleForChainAdjudication,
  );
  const packets = eligible.map((path) => createChainAdjudicationPacket({
    plan,
    path: { ...path, synthesisContextId: synthesizerContextId },
    candidates,
    candidateAdjudication,
    model,
    adjudicator: {
      provider: 'security.chain-adjudication',
      contextId: `chain-${path.id.slice(-12)}-${randomUUID()}`,
      contextStrategy: 'one-context-per-path',
    },
  }));
  return {
    schemaVersion: 1,
    kind: 'security-chain-adjudication-bundle',
    binding: reconciledPaths.binding,
    complete: true,
    contextStrategy: 'one-context-per-path',
    packets,
  };
}

export function finalizeChainAdjudicationBundle(bundle, rawResults) {
  const rawVerdicts = rawResults?.verdicts ?? [];
  const resultByPath = new Map(rawVerdicts.map((item) => [item.pathId, item]));
  const verdicts = [];
  const missingVerdicts = [];
  const invalidVerdicts = [];
  const seenPaths = new Set();

  // Duplicate path verdicts are invalid — never let the last value win.
  const countByPath = new Map();
  for (const raw of rawVerdicts) {
    countByPath.set(raw?.pathId, (countByPath.get(raw?.pathId) ?? 0) + 1);
  }
  for (const [pathId, count] of countByPath) {
    if (count > 1) invalidVerdicts.push({ pathId, error: 'duplicate path verdict' });
  }

  for (const packet of bundle.packets) {
    const raw = resultByPath.get(packet.pathId);
    if (!raw) {
      missingVerdicts.push(packet.pathId);
      continue;
    }
    if (seenPaths.has(packet.pathId)) {
      invalidVerdicts.push({ pathId: packet.pathId, error: 'duplicate path verdict' });
      continue;
    }
    if (invalidVerdicts.some((item) => item.pathId === packet.pathId && /duplicate/.test(item.error))) {
      continue;
    }
    seenPaths.add(packet.pathId);
    try {
      verdicts.push(finalizeChainVerdict(packet, raw));
    } catch (error) {
      invalidVerdicts.push({ pathId: packet.pathId, error: error.message });
    }
  }

  return {
    schemaVersion: 1,
    kind: 'security-chain-adjudication-result',
    binding: bundle.binding,
    complete: missingVerdicts.length === 0 && invalidVerdicts.length === 0,
    verdicts,
    missingVerdicts,
    invalidVerdicts,
  };
}
