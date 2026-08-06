// Symfony framework pack: routes/security/config.

export default Object.freeze({
  id: 'framework.symfony',
  version: '1.0.0',
  detect({ projection }) {
    return (projection?.auditFacts?.packageManifests ?? []).some((m) => /symfony/.test(JSON.stringify(m)));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      if (/->bind\s*\([^)]*(?:request|input)/.test(text)) {
        observations.push({ ruleId: 'symfony.untrusted-bind', severityHint: 'medium', claim: 'Request-derived data bound without visible validation.', file });
      }
      if (/access_control\s*:\s*\[[^\]]*path:\s*\^(?:\/admin|\/internal)/.test(text) && !/role:\s*ROLE_ADMIN/.test(text)) {
        observations.push({ ruleId: 'symfony.sensitive-route-no-role', severityHint: 'high', claim: 'Sensitive route has no visible role gate.', file });
      }
    }
    return observations;
  },
});
