// AI output-handling security pack per Security Appendix §50.8. Model output
// reaching HTML/shell/SQL/URL/fs/template/email/patch/tool sinks.

const OUTPUT_SINKS = [
  { id: 'ai.output-handling.model-output-to-shell', pattern: /(?:exec|spawn|system|child_process)\s*\([^\n]*(?:model|output|completion|response|message|tool_result)/i, severityHint: 'high', sinkKind: 'shell' },
  { id: 'ai.output-handling.model-output-to-html', pattern: /(?:innerHTML|dangerouslySetInnerHTML|v-html|render_template_string|\.html_safe)\s*[^\n]*(?:model|output|completion|response|message)/i, severityHint: 'high', sinkKind: 'html' },
  { id: 'ai.output-handling.model-output-to-sql', pattern: /(?:execute|query|raw|FromSqlRaw)\s*\([^\n]*(?:model|output|completion|response|message|tool_result)/i, severityHint: 'high', sinkKind: 'sql' },
  { id: 'ai.output-handling.model-output-to-path', pattern: /(?:writeFile|open|readFile|fs\.write|Path\.)\s*\([^\n]*(?:model|output|completion|response|message)/i, severityHint: 'high', sinkKind: 'filesystem' },
];

export default Object.freeze({
  id: 'security.ai-output-handling',
  version: '1.0.0',
  candidateClass: 'ai-output-handling',
  description: 'Model output reaching security-sensitive sinks.',
  rules: OUTPUT_SINKS.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes.path === file);
      for (const rule of OUTPUT_SINKS) {
        if (!rule.pattern.test(text)) continue;
        observations.push({
          ruleId: rule.id,
          candidateClass: 'ai-output-handling',
          claim: `Model output may reach a ${rule.sinkKind} sink without visible schema validation or sanitization.`,
          severityHint: rule.severityHint,
          sources: artifact ? [artifact.id] : [],
          sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: ['influence-model-output'],
          preconditions: [{ kind: 'control-bypass', subject: 'actor:external', action: 'influence-model', environment: 'agent' }],
          effects: [{ kind: 'code-execution', subject: 'actor:external', action: 'execute', object: artifact?.id ?? null, scope: 'sink-process', environment: 'application', tenant: null }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: ['enabler', 'impact'],
          evidenceRefs: [],
          detectorMetadata: { file, sinkKind: rule.sinkKind },
          uncertainty: ['Output must be schema-validated/allowlisted; adjudication decides reachability.'],
        });
      }
    }
    return observations;
  },
  variantStrategies: {},
});
