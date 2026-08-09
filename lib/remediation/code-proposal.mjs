// Code-agent remediation proposals (B7-032). A bounded source patch inside the
// packet's scope. Legion never calls a model here — an external host agent
// fills the packet, and this module only validates and shapes the result.

import { reasoningProposal } from './reasoning-packets.mjs';

export function codeProposal({ packet, changes, binding }) {
  return reasoningProposal({
    packet,
    owner: 'code',
    changes,
    binding,
    extra: {
      expectedBehavior: ['the finding no longer reproduces and no unrelated behavior changes'],
      affectedFamilies: ['security', 'code'],
      validationPlan: ['parse-check', 'affected-provider-rerun', 'baseline-gate-recheck'],
      patch: changes.find((change) => change.patch)?.patch ?? null,
    },
  });
}
