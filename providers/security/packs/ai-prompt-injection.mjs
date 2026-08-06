// AI prompt-injection security pack per Security Appendix §50.7. Untrusted
// content entering prompts without trust labeling; dynamic tool schemas from
// untrusted content; durable memory writes.

export default Object.freeze({
  id: 'security.ai-prompt-injection',
  version: '1.0.0',
  candidateClass: 'ai-prompt-injection',
  description: 'Untrusted content influencing model decisions.',
  rules: [{ id: 'ai.prompt-injection.indirect-untrusted-content' }],
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes.path === file);
      // Untrusted content (request/issue/PR/document) mixed into a prompt.
      if (/(?:prompt|messages|system_prompt|instructions?)\s*[:=]\s*[^\n]*(?:request|input|issue|body|content|document|description)/i.test(text)
        && !/trust_label|sanitize|escape|allowlist/.test(text)) {
        observations.push({
          ruleId: 'ai.prompt-injection.indirect-untrusted-content',
          candidateClass: 'ai-prompt-injection',
          claim: 'Untrusted content is mixed into a model prompt without a visible trust label.',
          severityHint: 'high',
          sources: artifact ? [artifact.id] : [],
          sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: ['control-untrusted-content'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'supply-content', environment: 'agent' }],
          effects: [{ kind: 'control-bypass', subject: 'actor:external', action: 'influence-model', object: artifact?.id ?? null, environment: 'agent', tenant: null }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: ['starter'],
          evidenceRefs: [],
          detectorMetadata: { file, sourceKind: 'untrusted-content', sinkKind: 'prompt' },
          uncertainty: ['Influence alone is not tool compromise; downstream output handling must be adjudicated.'],
        });
      }
    }
    return observations;
  },
  variantStrategies: {},
});
