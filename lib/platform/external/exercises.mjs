export function exerciseReceipt(input = {}) {
  const status = input.executed === true && input.result ? input.result : 'unproven';
  return { schemaVersion: 1, kind: 'nemesis-external-exercise-receipt', exercise: input.exercise, status, environment: input.environment ?? null,
    targetId: input.targetId ?? null, artifactDigest: input.artifactDigest ?? null, evidenceRefs: input.evidenceRefs ?? [], limitations: input.limitations ?? [] };
}
