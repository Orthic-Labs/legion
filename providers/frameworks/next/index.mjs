// Next.js framework pack: route/server action/cache/auth/image/deployment
// checks. Deterministic structural rules over frozen denominator paths.

export default Object.freeze({
  id: 'framework.next',
  version: '1.0.0',
  detect({ projection }) {
    const deps = projection?.auditFacts?.packageManifests ?? [];
    return deps.some((manifest) => JSON.stringify(manifest).includes('next'));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      if (!/\.(js|ts|jsx|tsx)$/.test(file)) continue;
      const text = readFile(file) ?? '';
      // Route handler / server action without visible auth.
      if (/(?:export\s+async\s+function\s+\w+\s*\([^)]*\)|export\s+const\s+\w+\s*=\s*(?:async\s*)?\([^)]*\)\s*(?:=>)?\s*\{)/.test(text)
        && /params|searchParams/.test(text)
        && !/auth|session|getServerSession|requireAuth/.test(text)) {
        observations.push({
          ruleId: 'next.route.missing-auth',
          severityHint: 'high',
          claim: 'A route handler consumes request parameters without visible authentication.',
          file,
        });
      }
      // Cache revalidation: fetch without revalidate bounds.
      if (/fetch\s*\([^)]*\)(?![\s\S]{0,200}next:\s*\{[\s\S]{0,60}revalidate)/.test(text)) {
        observations.push({
          ruleId: 'next.cache.unbounded-revalidate',
          severityHint: 'medium',
          claim: 'A fetch has no visible revalidation policy.',
          file,
        });
      }
      // Image: no width/height or fill on next/image.
      if (/<Image\b(?![\s\S]{0,200}(?:width|height|fill)\s*=)/.test(text)) {
        observations.push({
          ruleId: 'next.image.unbounded',
          severityHint: 'low',
          claim: 'next/image lacks explicit dimensions or fill.',
          file,
        });
      }
    }
    return observations;
  },
});
