import { digestValue } from './canonical.mjs';
import { decision } from './errors.mjs';

// A packet transports frozen material, never a producer's conclusion.
export function buildAssurancePacket({ frozenContract, artifacts = [], producerAuthority, reviewerAuthority, integratedState }) {
  if (!frozenContract || !integratedState || !producerAuthority || !reviewerAuthority) return decision({ allowed: false, code: 'ARC_SCHEMA_INVALID', message: 'assurance packet requires frozen contract, exact state, producer, and reviewer', detail: {} });
  if (producerAuthority === reviewerAuthority) return decision({ allowed: false, code: 'ARC_SELF_CERTIFICATION', message: 'producer cannot independently certify its own outcome', detail: { producerAuthority } });
  if (!artifacts.length || artifacts.some((artifact) => artifact.authenticated !== true || JSON.stringify(artifact.integratedState) !== JSON.stringify(integratedState))) return decision({ allowed: false, code: 'ARC_EVIDENCE_INSUFFICIENT', message: 'assurance packet lacks authenticated exact-state artifacts', detail: {} });
  const packet = Object.freeze({ kind: 'arcane-assurance-packet', contractDigest: digestValue(frozenContract), integratedState, producerAuthority, reviewerAuthority, artifacts: artifacts.map(({ producerNarrative: _drop, ...artifact }) => artifact) });
  return decision({ allowed: true, message: 'independent assurance packet compiled', detail: { packet, packetDigest: digestValue(packet) } });
}
