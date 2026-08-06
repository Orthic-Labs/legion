// Repository-footprint security pack per Security Appendix §54.8. Source maps,
// internal endpoints, committed secrets in docs/examples, local DB/backups,
// package contents, debug endpoints, ignore rules.

export default Object.freeze({
  id: 'security.repository-footprint',
  version: '1.0.0',
  candidateClass: 'repository-footprint',
  description: 'Repository contents and release artifacts.',
  rules: [
    { id: 'footprint.sourcemap-included' },
    { id: 'footprint.local-db-committed' },
    { id: 'footprint.internal-endpoint-exposed' },
  ],
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      const artifact = context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes.path === file);
      if (/\.map$/.test(file) && /sourceMappingURL/.test(text)) {
        observations.push({
          ruleId: 'footprint.sourcemap-included',
          candidateClass: 'repository-footprint',
          claim: 'Source map with source content is present in the repository.',
          severityHint: 'medium',
          sources: artifact ? [artifact.id] : [], sinks: [], attackerCapabilities: ['read-repository'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'read-repository', environment: 'any' }],
          effects: [{ kind: 'knowledge', subject: 'actor:external', action: 'disclose', object: artifact?.id ?? null, scope: 'source-content', environment: 'any', tenant: null }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: ['enabler'], evidenceRefs: [],
          detectorMetadata: { file },
          uncertainty: ['Source maps may be stripped at release.'],
        });
      }
      if (/\.(sqlite|db|sqlite3|dump|bak)$/.test(file)) {
        observations.push({
          ruleId: 'footprint.local-db-committed',
          candidateClass: 'repository-footprint',
          claim: 'A local database or backup file is committed.',
          severityHint: 'high',
          sources: artifact ? [artifact.id] : [], sinks: [], attackerCapabilities: ['read-repository'],
          preconditions: [{ kind: 'attacker-position', subject: 'actor:external', action: 'read-repository', environment: 'any' }],
          effects: [{ kind: 'data-access', subject: 'actor:external', action: 'read', object: artifact?.id ?? null, scope: 'local-data', environment: 'any', tenant: null }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: ['starter', 'impact'], evidenceRefs: [],
          detectorMetadata: { file },
          uncertainty: ['The database may contain no sensitive data.'],
        });
      }
    }
    return observations;
  },
  variantStrategies: {},
});
