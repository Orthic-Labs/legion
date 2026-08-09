// Neutral proposal verification (B7-033).
//
// Verification is adversarial by construction: the verifier identity must
// differ from the producer, every producer-supplied pass claim is discarded,
// and a verification with no providers and no gates while the effect graph
// shows real effects is rejected as vacuous rather than accepted as clean.

import { createHash } from 'node:crypto';
import { assertProducerIsNotVerifier } from './reasoning-packets.mjs';
import { blocksAutoApply } from './effect-graph.mjs';

export const VERIFICATION_SCHEMA_VERSION = 1;

function digestOf(value) {
  return `sha256:${createHash('sha256').update(`verification\0${JSON.stringify(value)}`).digest('hex')}`;
}

function hasEffects(effectGraph) {
  return (effectGraph.changedFiles ?? []).length > 0
    || (effectGraph.changedSymbols ?? []).length > 0
    || (effectGraph.changedConfig ?? []).length > 0
    || (effectGraph.contentItems ?? []).length > 0;
}

export function verifyProposal({ proposal, effectGraph, verifier, providerResults = [], gateResults = [], binding }) {
  if (!verifier?.id) throw new TypeError('verification requires a verifier identity');
  assertProducerIsNotVerifier(proposal, verifier);

  const coverageGaps = [];
  const resultByProvider = new Map(providerResults.map((result) => [result.provider, result]));
  const gateById = new Map(gateResults.map((gate) => [gate.id, gate]));

  for (const providerId of effectGraph.requiredProviders ?? []) {
    const result = resultByProvider.get(providerId);
    if (!result) {
      coverageGaps.push({ kind: 'missing-affected-provider', provider: providerId });
      continue;
    }
    if (result.complete !== true) {
      coverageGaps.push({ kind: 'affected-provider-incomplete', provider: providerId, status: result.status ?? null });
      continue;
    }
    if (result.status !== 'pass') {
      coverageGaps.push({ kind: 'affected-provider-failed', provider: providerId, status: result.status ?? null });
    }
  }

  for (const gateId of effectGraph.requiredGates ?? []) {
    const gate = gateById.get(gateId);
    if (!gate) {
      coverageGaps.push({ kind: 'missing-baseline-gate', gate: gateId });
      continue;
    }
    if (gate.passed !== true) coverageGaps.push({ kind: 'baseline-gate-failed', gate: gateId });
  }

  if (hasEffects(effectGraph) && providerResults.length === 0 && gateResults.length === 0) {
    coverageGaps.push({ kind: 'vacuous-verification', reason: 'effects exist but no provider or gate evidence was supplied' });
  }

  if (blocksAutoApply(effectGraph)) {
    coverageGaps.push({
      kind: 'unplanned-public-surface-change',
      surfaces: [...(effectGraph.unplannedPublicSurfaceChanges ?? [])],
    });
  }

  const body = {
    schemaVersion: VERIFICATION_SCHEMA_VERSION,
    kind: 'legion-remediation-verification',
    proposalId: proposal.id,
    patchDigest: proposal.patch?.digest ?? null,
    effectGraphDigest: effectGraph.digest ?? null,
    verifiedBy: 'neutral-verification',
    verifier: { id: verifier.id, contextId: verifier.contextId ?? null },
    producer: { id: proposal.producer?.id ?? null, contextId: proposal.producer?.contextId ?? null },
    // Producer-supplied pass claims are never read; this states so on the record.
    trustedProducerAssertions: false,
    providersChecked: (effectGraph.requiredProviders ?? []).length,
    gatesChecked: (effectGraph.requiredGates ?? []).length,
    coverageGaps: coverageGaps.sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
    valid: coverageGaps.length === 0,
    binding,
  };
  return { ...body, digest: digestOf(body) };
}

export function buildVerificationSchema() {
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://orthic.dev/schemas/remediation/verification-v1.json',
    title: 'RemediationVerificationV1',
    type: 'object',
    required: [
      'schemaVersion', 'kind', 'proposalId', 'patchDigest', 'effectGraphDigest', 'verifiedBy', 'verifier',
      'producer', 'trustedProducerAssertions', 'providersChecked', 'gatesChecked',
      'coverageGaps', 'valid', 'binding', 'digest',
    ],
    properties: {
      schemaVersion: { const: VERIFICATION_SCHEMA_VERSION },
      kind: { const: 'legion-remediation-verification' },
      proposalId: { type: 'string' },
      patchDigest: { type: ['string', 'null'] },
      effectGraphDigest: { type: ['string', 'null'] },
      verifiedBy: { const: 'neutral-verification' },
      verifier: {
        type: 'object',
        required: ['id', 'contextId'],
        properties: { id: { type: 'string', minLength: 1 }, contextId: { type: ['string', 'null'] } },
        additionalProperties: false,
      },
      producer: {
        type: 'object',
        required: ['id', 'contextId'],
        properties: { id: { type: ['string', 'null'] }, contextId: { type: ['string', 'null'] } },
        additionalProperties: false,
      },
      trustedProducerAssertions: { const: false },
      providersChecked: { type: 'integer', minimum: 0 },
      gatesChecked: { type: 'integer', minimum: 0 },
      coverageGaps: { type: 'array', items: { type: 'object' } },
      valid: { type: 'boolean' },
      binding: { type: 'object' },
      digest: { type: 'string', pattern: '^sha256:' },
    },
    additionalProperties: false,
  };
}
