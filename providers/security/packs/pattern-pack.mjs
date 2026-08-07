function artifactFor(context, file) {
  return context.model.entities.find((entity) =>
    entity.kind === 'repository-artifact' && entity.attributes?.path === file);
}

function resetAndMatch(pattern, text) {
  pattern.lastIndex = 0;
  return pattern.test(text);
}

export function createPatternPack({ id, family, description, rules }) {
  if (!id?.startsWith('security.') || !family || !rules?.length) {
    throw new TypeError('pattern pack requires security id, family, and rules');
  }
  return Object.freeze({
    id,
    version: '1.0.0',
    candidateClass: family,
    description,
    rules: rules.map(({ id: ruleId }) => ({ id: ruleId })),
    analyze(context) {
      const observations = [];
      for (const file of context.files) {
        const text = context.readFile(file) ?? '';
        if (!text) continue;
        const artifact = artifactFor(context, file);
        for (const rule of rules) {
          if (!resetAndMatch(rule.pattern, text)) continue;
          observations.push({
            ruleId: rule.id,
            candidateClass: family,
            claim: rule.claim,
            severityHint: rule.severityHint ?? 'medium',
            sources: artifact ? [artifact.id] : [],
            sinks: artifact ? [artifact.id] : [],
            attackerCapabilities: rule.attackerCapabilities ?? ['control-request-input'],
            preconditions: rule.preconditions ?? [{
              kind: 'attacker-position', subject: 'actor:external', action: 'supply-input',
              scope: null, environment: 'application', tenant: null,
            }],
            effects: [{
              kind: rule.effectKind ?? 'control-bypass',
              subject: 'actor:external', action: rule.effectAction ?? 'bypass',
              object: artifact?.id ?? null, scope: rule.effectScope ?? family,
              environment: rule.environment ?? 'application', tenant: null,
            }],
            assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
            chainRoles: rule.chainRoles ?? ['starter', 'impact'],
            evidenceRefs: artifact?.evidenceRefs ?? [],
            detectorMetadata: { file, patternFamily: family },
            uncertainty: rule.uncertainty ?? ['Reachability and compensating controls require independent adjudication.'],
          });
        }
      }
      return observations;
    },
    variantStrategies: {},
  });
}
