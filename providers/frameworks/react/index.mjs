// React framework pack: hooks/effects/state/performance/a11y/security and
// changed-scope parity fixtures. Deterministic structural rules only; no
// proprietary rule copying.

export default Object.freeze({
  id: 'framework.react',
  version: '1.0.0',
  detect({ projection }) {
    const deps = projection?.auditFacts?.packageManifests ?? [];
    return deps.some((manifest) => JSON.stringify(manifest).includes('react'));
  },
  analyze({ files, readFile }) {
    const observations = [];
    for (const file of files) {
      if (!/\.(jsx|tsx|js|ts)$/.test(file)) continue;
      const text = readFile(file) ?? '';
      // Hooks rule: conditional hook calls violate the rules of hooks.
      if (/if\s*\([^)]*\)\s*\{\s*(?:useState|useEffect|useMemo|useCallback)\s*\(/.test(text)) {
        observations.push({
          ruleId: 'react.hooks.conditional-call',
          severityHint: 'high',
          claim: 'A React hook is called conditionally, violating the rules of hooks.',
          file,
        });
      }
      // Effects rule: missing dependency array.
      if (/useEffect\s*\(\s*\(\)\s*=>\s*\{[\s\S]{0,600}?\}\s*\)(?!\s*,\s*\[)/.test(text)) {
        observations.push({
          ruleId: 'react.effects.missing-deps',
          severityHint: 'medium',
          claim: 'useEffect is called without a dependency array.',
          file,
        });
      }
      // A11y: images without alt.
      if (/<img\b(?![\s\S]{0,200}alt=)/.test(text)) {
        observations.push({
          ruleId: 'react.a11y.img-alt',
          severityHint: 'medium',
          claim: 'An img element has no alt attribute.',
          file,
        });
      }
      // Security: dangerouslySetInnerHTML.
      if (/dangerouslySetInnerHTML\s*=/.test(text)) {
        observations.push({
          ruleId: 'react.security.dangerous-html',
          severityHint: 'high',
          claim: 'Raw HTML rendering requires a proven sanitization boundary.',
          file,
        });
      }
    }
    return observations;
  },
});
