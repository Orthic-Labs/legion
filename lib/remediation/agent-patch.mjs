// Bounded agent patch generation per SNIP-FIX-01 and the Security Appendix.
// Legion itself never calls a model; an external host agent produces a patch
// only through a bounded packet inside an isolated worktree. The patch
// producer never verifies its own result.

import { fixProposal } from './fix-contract.mjs';

export function agentPatchPacket({ finding, worktreePath, scope, maxBatches = 4 }) {
  return {
    schemaVersion: 1,
    kind: 'legion-agent-patch-packet',
    findingId: finding.id,
    rootCauseDigest: finding.rootCauseDigest ?? null,
    worktreePath,
    scope: [...(scope ?? [])].sort(),
    maxBatches,
    bounded: true,
    // Explicit instruction: the producer must not verify its own result.
    verification: 'performed by neutral verification after the packet returns',
  };
}

export function agentPatchProposal({ finding, packet, patch }) {
  return fixProposal({
    findingId: finding.id,
    rootCauseDigest: finding.rootCauseDigest ?? null,
    producer: { kind: 'agent-guided', packetId: packet?.packetId ?? null, modelIdentity: packet?.modelIdentity ?? null },
    targetPaths: [...(patch?.targetPaths ?? [])].sort(),
    preconditions: ['packet is bounded', 'worktree is isolated', 'scope grant is explicit'],
    patch: { path: patch?.path ?? 'patches/agent.patch', digest: patch?.digest ?? null },
    expectedBehavior: patch?.expectedBehavior ?? [],
    risks: patch?.risks ?? [],
    validationCommands: patch?.validationCommands ?? [],
    tier: 'AGENT_GUIDED',
  });
}
