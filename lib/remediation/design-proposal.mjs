// Designer remediation proposals (B7-032). Layout, style, and assets only —
// and every approved text digest the packet declared must come back unchanged,
// so a visual fix can never quietly reword the product.

import { reasoningProposal } from './reasoning-packets.mjs';

function assertApprovedTextPreserved(packet, preservedTextDigests) {
  for (const [contentItemId, approved] of Object.entries(packet.approvedTextDigests ?? {})) {
    const returned = preservedTextDigests?.[contentItemId];
    if (returned !== approved) {
      throw new Error(`approved text digest for ${contentItemId} changed: a designer proposal may not alter approved text`);
    }
  }
  return true;
}

export function designProposal({ packet, changes, preservedTextDigests = {}, binding }) {
  assertApprovedTextPreserved(packet, preservedTextDigests);
  return reasoningProposal({
    packet,
    owner: 'designer',
    changes,
    binding,
    extra: {
      expectedBehavior: ['the named surfaces render as proposed with approved text intact'],
      affectedFamilies: ['design', 'ux', 'visual'],
      validationPlan: ['affected-provider-rerun:visual', 'affected-provider-rerun:ux', 'approved-text-digest-recheck'],
      preservedTextDigests: { ...preservedTextDigests },
    },
  });
}
