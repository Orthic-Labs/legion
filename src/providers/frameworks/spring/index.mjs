// Spring framework pack: Spring Security/web/data/SpEL/config coverage.

export default Object.freeze({
  id: 'framework.spring',
  version: '1.0.0',
  detect({ projection }) {
    const deps = projection?.auditFacts?.packageManifests ?? [];
    return deps.some((m) => /spring/.test(JSON.stringify(m)));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      if (/csrf\s*\([^)]*\)\s*\.disable\s*\(|csrf\s*\{[^}]*disable\s*\(|csrf\s*\([^)]*csrf\s*\.disable\s*\(/s.test(text)) {
        observations.push({ ruleId: 'spring.csrf-disabled', severityHint: 'medium', claim: 'Spring Security CSRF is disabled.', file });
      }
      if (/requestMatchers\s*\([^)]*(?:admin|internal|actuator)[^)]*\)\s*\.permitAll\s*\(/is.test(text)) {
        observations.push({ ruleId: 'spring.sensitive-permit-all', severityHint: 'high', claim: 'Sensitive route is permitAll.', file });
      }
      if (/SpelExpressionParser[\s\S]{0,500}parseExpression\s*\(\s*(?:request|input|value|expression)/.test(text)) {
        observations.push({ ruleId: 'spring.spel-input', severityHint: 'high', claim: 'Variable input reaches a SpEL parser.', file });
      }
      if (/@RequestParam\s*\([^)]*\)/.test(text) && !/valid|@Valid/.test(text)) {
        observations.push({ ruleId: 'spring.unvalidated-param', severityHint: 'medium', claim: 'Request parameter lacks visible validation.', file });
      }
    }
    return observations;
  },
});
