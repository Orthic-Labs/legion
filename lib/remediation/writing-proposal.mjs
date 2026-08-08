// Writing remediation proposals (B7-032). Words only — a writing proposal that
// touches style, layout, or source is rejected outright rather than trimmed.

import { assertOwnerAuthority, reasoningProposal } from './reasoning-packets.mjs';

export function writingProposal({ packet, changes, binding }) {
  for (const change of changes ?? []) {
    // Authority first: a non-text change is rejected as an authority breach,
    // not as a missing-field problem.
    assertOwnerAuthority('writing', change);
    if (!change.contentItemId) {
      throw new Error('every writing change must name the content item it rewrites');
    }
  }
  return reasoningProposal({
    packet,
    owner: 'writing',
    changes,
    binding,
    extra: {
      expectedBehavior: ['the named content items read as proposed and remain claim-supported'],
      affectedFamilies: ['copy', 'narrative'],
      validationPlan: ['affected-provider-rerun:copy', 'affected-provider-rerun:narrative', 'claim-proof-recheck'],
      contentItemIds: [...new Set(changes.map((change) => change.contentItemId))].sort(),
    },
  });
}
