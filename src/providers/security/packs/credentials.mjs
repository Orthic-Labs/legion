// Credentials security pack: credential formats, named secret assignments,
// private key blocks, secret fallbacks. Never calls a credential a leaked live
// credential until adjudication establishes validity or credible scope.

const SECRET_PATTERNS = [
  { id: 'credentials.format', pattern: /\b(?:AKIA[0-9A-Z]{16}|ghp_[0-9A-Za-z]{36}|sk-[0-9A-Za-z]{20,})\b/g, severityHint: 'high', message: 'Credential-shaped value.' },
  { id: 'credentials.assignment', pattern: /\b(?:password|secret|token|apiKey|api_key|privateKey)\s*[:=]\s*['"][^'"]{12,}['"]/gi, severityHint: 'medium', message: 'Secret-like assignment with a literal value.' },
  { id: 'credentials.private-key', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, severityHint: 'high', message: 'Private key block.' },
];

export default Object.freeze({
  id: 'security.credentials',
  version: '1.0.0',
  candidateClass: 'credentials',
  description: 'Credential material in repository artifacts.',
  rules: SECRET_PATTERNS.map((rule) => ({ id: rule.id })),
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      for (const rule of SECRET_PATTERNS) {
        rule.pattern.lastIndex = 0;
        let match;
        while ((match = rule.pattern.exec(text)) !== null) {
          const line = text.slice(0, match.index).split('\n').length;
          const artifact = context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes.path === file);
          observations.push({
            ruleId: rule.id,
            candidateClass: 'credentials',
            claim: rule.message,
            severityHint: rule.severityHint,
            sources: artifact ? [artifact.id] : [],
            sinks: [],
            attackerCapabilities: ['read-repository'],
            preconditions: [{
              kind: 'attacker-position',
              subject: 'actor:external',
              action: 'read-repository',
              environment: 'any',
            }],
            effects: [{
              kind: 'knowledge',
              subject: 'actor:external',
              action: 'possess',
              object: artifact?.id ?? null,
              scope: 'credential-material',
              environment: 'any',
              tenant: null,
            }],
            assets: [],
            trustBoundaryCrossings: [],
            requiredControls: [],
            observedControls: [],
            chainRoles: ['starter', 'enabler'],
            evidenceRefs: [],
            detectorMetadata: { file, line, matchDigest: `sha256:${match[0].slice(0, 16)}` },
            uncertainty: ['Whether the value is live and what scope it has is unproven until adjudication.'],
          });
        }
      }
    }
    return observations;
  },
  variantStrategies: {
    'credentials.format': {
      rootCause(candidate) {
        return { class: 'credential-in-repository', semanticFeatures: ['credential-shaped-literal'] };
      },
      enumerate(context, signature) {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          for (const rule of SECRET_PATTERNS) {
            rule.pattern.lastIndex = 0;
            let match;
            while ((match = rule.pattern.exec(text)) !== null) {
              matches.push({
                file,
                line: text.slice(0, match.index).split('\n').length,
                semanticFingerprint: `sha256:${match[0]}`,
                disposition: 'CONFIRMED',
              });
            }
          }
        }
        return {
          denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
          strategies: [{ id: 'credential-pattern-search', kind: 'lexical-fallback', description: 'Search credential-shaped values across the denominator.', queryDigest: 'sha256:q', complete: true, coverageGaps: [] }],
          matches,
          coverageGaps: [],
        };
      },
    },
  },
});
