// Ktor framework pack: routing/auth/CORS/forwarded-header coverage.

export default Object.freeze({
  id: 'framework.ktor',
  version: '1.0.0',
  detect({ projection }) {
    const deps = projection?.auditFacts?.packageManifests ?? [];
    return deps.some((m) => /ktor/.test(JSON.stringify(m)));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      const text = readFile(file) ?? '';
      if (/anyHost\s*\(\s*\)/.test(text)) {
        observations.push({ ruleId: 'ktor.cors-any-host', severityHint: 'medium', claim: 'CORS permits any host.', file });
      }
      if (/XForwardedHeaders/.test(text)) {
        observations.push({ ruleId: 'ktor.forwarded-headers', severityHint: 'low', claim: 'Forwarded headers trusted; verify proxy boundaries.', file });
      }
      // Route with request body but no auth guard.
      if (/route\s*\(\s*["'][^"']*(?:admin|internal|api\/admin)/.test(text) && !/authenticate|validate|session/.test(text)) {
        observations.push({ ruleId: 'ktor.sensitive-route-no-auth', severityHint: 'high', claim: 'Sensitive route has no visible auth.', file });
      }
    }
    return observations;
  },
});
