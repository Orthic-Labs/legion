import { createHash } from 'node:crypto';

function digest(value) { return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`; }

export function buildReviewPacket(input = {}) {
  const packet = { schemaVersion: 1, kind: 'legion-visual-review-packet', scope: input.stateGroup ? 'state-group' : 'surface', surfaceId: input.surfaceId,
    stateGroup: input.stateGroup ?? null, screenshots: input.screenshots ?? [], route: input.route, state: input.state, viewport: input.viewport,
    designContext: input.designContext ?? null, geometry: input.geometry ?? null, accessibility: input.accessibility ?? null, copyItemIds: input.copyItemIds ?? [],
    baselineResults: input.baselineResults ?? null, omittedEvidence: input.omittedEvidence ?? [] };
  return { ...packet, digest: digest(packet) };
}

export function validateJudgmentReceipt(packet, input = {}) {
  const reviewer = input.reviewer ?? {};
  const independent = reviewer.fresh === true && reviewer.provider && reviewer.provider !== input.rendererIdentity && reviewer.provider !== input.implementerIdentity && reviewer.contextId;
  const evidenceValid = (input.evidenceRefs ?? []).every((reference) => (packet.screenshots ?? []).includes(reference) || reference === packet.digest);
  const valid = Boolean(independent && evidenceValid && input.counterargument && Array.isArray(input.uncertainty));
  const claimLimits = packet.designContext ? [] : ['brand-context-missing'];
  const receipt = { schemaVersion: 1, kind: 'legion-judgment-receipt', family: 'visual', subjectId: packet.surfaceId, candidateId: packet.digest,
    reviewer, evidenceRefs: input.evidenceRefs ?? [], omittedEvidence: packet.omittedEvidence, verdict: input.verdict ?? 'UNPROVEN', rationaleClaims: input.rationaleClaims ?? [],
    counterargument: input.counterargument ?? null, uncertainty: input.uncertainty ?? [], claimLimits, policyEffect: input.policyEffect ?? 'advisory', binding: input.binding ?? {} };
  return { valid, errors: [!independent ? 'reviewer-not-independent-or-fresh' : null, !evidenceValid ? 'evidence-reference-invalid' : null, !input.counterargument ? 'counterargument-missing' : null].filter(Boolean), receipt: { ...receipt, digest: digest(receipt) } };
}
