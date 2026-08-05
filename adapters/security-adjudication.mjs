import { randomUUID } from 'node:crypto';
import { canonicalJson, sha256 } from '../registry/provider-registry.mjs';

const VERDICTS = new Set([
  'TRUE_POSITIVE',
  'LIKELY_TRUE_POSITIVE',
  'LIKELY_FALSE_POSITIVE',
  'FALSE_POSITIVE',
  'OUT_OF_SCOPE',
  'HARDENING_GAP',
  'MISUSE_HAZARD',
]);

export function createSecurityCandidate(input) {
  if (!input?.id || !input?.provider || !input?.contextId || !input?.claim) {
    throw new Error('security candidate requires id, provider, contextId, and exact claim');
  }
  if (!Array.isArray(input.evidence) || !input.evidence.length) {
    throw new Error(`security candidate ${input.id} requires evidence`);
  }
  return {
    schemaVersion: 1,
    kind: 'security-candidate',
    id: input.id,
    provider: input.provider,
    contextId: input.contextId,
    claim: input.claim,
    allegedRootCause: input.allegedRootCause ?? null,
    allegedTrigger: input.allegedTrigger ?? null,
    allegedImpact: input.allegedImpact ?? null,
    evidence: input.evidence,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
  };
}

export function createAdjudicationPacket(candidate, input) {
  if (candidate?.kind !== 'security-candidate') throw new Error('adjudication requires a security candidate');
  if (!input?.provider) throw new Error('adjudication provider is required');
  const contextId = input.contextId ?? randomUUID();
  if (input.provider === candidate.provider) {
    throw new Error(`provider ${input.provider} may not adjudicate its own candidate ${candidate.id}`);
  }
  if (contextId === candidate.contextId) {
    throw new Error(`candidate ${candidate.id} must be adjudicated in a fresh context`);
  }
  const body = {
    schemaVersion: 1,
    kind: 'security-adjudication-packet',
    candidate,
    adjudicator: {
      provider: input.provider,
      contextId,
      contextStartedAt: input.contextStartedAt ?? new Date().toISOString(),
    },
    requiredEvidence: [
      'threat model and attacker capability',
      'attacker-controlled source',
      'trust-boundary trace',
      'validation and authorization between source and sink',
      'reachability',
      'primary controls and environmental mitigations',
      'real security impact',
      'reproduction, trace, PoC sketch, or mathematical proof',
      'devils-advocate false-positive challenge',
    ],
  };
  return { ...body, packetDigest: sha256(body) };
}

export function verifyAdjudicationPacket(packet) {
  if (packet?.kind !== 'security-adjudication-packet') return false;
  const unsigned = { ...packet };
  delete unsigned.packetDigest;
  return packet.packetDigest === sha256(unsigned)
    && packet.candidate.provider !== packet.adjudicator.provider
    && packet.candidate.contextId !== packet.adjudicator.contextId;
}

export function finalizeSecurityVerdict(packet, result) {
  if (!verifyAdjudicationPacket(packet)) throw new Error('invalid or self-adjudicated security packet');
  if (!VERDICTS.has(result?.verdict)) throw new Error(`unsupported security verdict ${result?.verdict}`);
  if (!result.threatModel || !result.reachability || !result.impact) {
    throw new Error('security verdict requires threatModel, reachability, and impact');
  }
  const surviving = new Set(['TRUE_POSITIVE', 'LIKELY_TRUE_POSITIVE']);
  if (surviving.has(result.verdict) && !result.severity) {
    throw new Error(`surviving security verdict ${result.verdict} requires severity`);
  }
  if (!surviving.has(result.verdict) && result.severity) {
    throw new Error(`non-surviving security verdict ${result.verdict} must not carry vulnerability severity`);
  }
  if (surviving.has(result.verdict)) {
    if (!result.attackerControl || result.attackerControl === 'unproven') {
      throw new Error(`surviving security verdict ${result.verdict} requires attackerControl above unproven`);
    }
    if (!result.proof) {
      throw new Error(`surviving security verdict ${result.verdict} requires proof (reproduction, trace, PoC, or mathematical proof)`);
    }
    const strengthRank = { possible: 0, observed: 1, verified: 2 };
    if ((strengthRank[result.evidenceStrength] ?? 0) <= 0) {
      throw new Error(`surviving security verdict ${result.verdict} requires evidenceStrength above possible`);
    }
    if (!result.devilsAdvocate) {
      throw new Error(`surviving security verdict ${result.verdict} requires devilsAdvocate false-positive challenge`);
    }
  }
  const verdict = {
    schemaVersion: 1,
    kind: 'security-verdict',
    candidateId: packet.candidate.id,
    candidateProvider: packet.candidate.provider,
    adjudicatorProvider: packet.adjudicator.provider,
    adjudicatorContextId: packet.adjudicator.contextId,
    evidenceStrength: result.evidenceStrength ?? 'possible',
    verdict: result.verdict,
    severity: result.severity ?? null,
    exploitability: result.exploitability ?? null,
    threatModel: result.threatModel,
    attackerControl: result.attackerControl ?? 'unproven',
    reachability: result.reachability,
    trustBoundaries: result.trustBoundaries ?? [],
    sink: result.sink ?? null,
    primaryControls: result.primaryControls ?? [],
    mitigations: result.mitigations ?? [],
    proof: result.proof ?? null,
    impact: result.impact,
    rationale: result.rationale ?? null,
    devilsAdvocate: result.devilsAdvocate ?? null,
    variantAnalysisRequired: surviving.has(result.verdict),
  };
  return { ...verdict, verdictDigest: sha256(canonicalJson(verdict)) };
}
