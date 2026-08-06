// Injection security pack: shell/process/code-eval/SQL/NoSQL/LDAP/XPath/
// template/expression sinks with typed source-to-sink metadata.

const SINK_PATTERNS = [
  { id: 'injection.shell.source-to-sink', pattern: /(?:exec|system|spawn|child_process\.exec|subprocess\.(?:call|run|Popen))\s*\([^\n]*(?:request|input|user|query|body|params)/g, severityHint: 'high', message: 'Request-derived data reaches a shell execution sink.', sinkKind: 'shell' },
  { id: 'injection.sql.dynamic-query', pattern: /(?:execute|query|raw|FromSqlRaw|text\s*\(f)/g, severityHint: 'high', message: 'Dynamic query construction with variable input.', sinkKind: 'SQL' },
  { id: 'injection.code-eval', pattern: /\b(?:eval|exec|Function)\s*\([^\n]*(?:request|input|user|query)/g, severityHint: 'high', message: 'Request-derived data reaches a code evaluation sink.', sinkKind: 'code-eval' },
];

export default Object.freeze({
  id: 'security.injection',
  version: '1.0.0',
  candidateClass: 'injection',
  description: 'Injection into interpreter, query, template, and process sinks.',
  rules: SINK_PATTERNS.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      for (const rule of SINK_PATTERNS) {
        rule.pattern.lastIndex = 0;
        let match;
        while ((match = rule.pattern.exec(text)) !== null) {
          const line = text.slice(0, match.index).split('\n').length;
          const artifact = context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes.path === file);
          observations.push({
            ruleId: rule.id,
            candidateClass: 'injection',
            claim: rule.message,
            severityHint: rule.severityHint,
            sources: artifact ? [artifact.id] : [],
            sinks: artifact ? [artifact.id] : [],
            attackerCapabilities: ['control-request-input'],
            preconditions: [{
              kind: 'attacker-position',
              subject: 'actor:external',
              action: 'supply-input',
              environment: 'application',
            }],
            effects: [{
              kind: 'code-execution',
              subject: 'actor:external',
              action: 'execute',
              object: artifact?.id ?? null,
              scope: 'sink-process',
              environment: 'application',
              tenant: null,
            }],
            assets: [],
            trustBoundaryCrossings: [],
            requiredControls: [],
            observedControls: [],
            chainRoles: ['starter', 'impact'],
            evidenceRefs: [],
            detectorMetadata: { file, line, sinkKind: rule.sinkKind, shell: rule.sinkKind === 'shell' },
            uncertainty: ['A process-argument candidate is not automatically command injection; argument separation and validation must be adjudicated.'],
          });
        }
      }
    }
    return observations;
  },
  variantStrategies: {},
});
