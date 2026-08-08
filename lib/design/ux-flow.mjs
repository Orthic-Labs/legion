import { createHash } from 'node:crypto';

function digest(value) { return `sha256:${createHash('sha256').update(JSON.stringify(value)).digest('hex')}`; }

export function buildUxFlow(input = {}) {
  const steps = (input.steps ?? []).map((step, index) => ({ index, surfaceId: step.surfaceId ?? null, componentId: step.componentId ?? null, action: step.action,
    expectedState: step.expectedState ?? null, actualState: step.actualState ?? null, errorPath: step.errorPath ?? null, recoveryPath: step.recoveryPath ?? null,
    prerequisites: step.prerequisites ?? [], sideEffects: step.sideEffects ?? [], evidenceRefs: step.evidenceRefs ?? [] }));
  const identity = { goal: input.goal, cohort: input.cohort ?? 'unspecified', entrySurfaceId: input.entrySurfaceId, steps };
  const terminalState = input.terminalState === 'success' && !input.behaviorEvidence ? 'unproven' : input.terminalState ?? 'unproven';
  return { schemaVersion: 1, kind: 'nemesis-ux-flow', id: digest(identity), goal: input.goal, goalSource: input.goalSource ?? 'explicit',
    goalInferred: (input.goalSource ?? 'explicit') !== 'explicit', cohort: input.cohort ?? 'unspecified', context: input.context ?? null,
    priorKnowledge: input.priorKnowledge ?? null, assistance: input.assistance ?? null, successCriteria: input.successCriteria ?? [], expectedEffort: input.expectedEffort ?? null,
    entrySurfaceId: input.entrySurfaceId, steps, alternatePaths: input.alternatePaths ?? [], terminalState,
    measurements: input.measurements ?? null, denominatorDigest: input.denominatorDigest ?? digest(identity), binding: input.binding ?? {} };
}
