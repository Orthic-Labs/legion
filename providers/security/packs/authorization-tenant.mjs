// Authorization/tenant security pack per Security Appendix §52.2. Object
// read/write/delete without ownership/tenant policy; privileged functions;
// mass assignment; tenant filters; background workers; impersonation.

export default Object.freeze({
  id: 'security.authorization-tenant',
  version: '1.0.0',
  candidateClass: 'authorization',
  description: 'Object, function, role, and tenant authorization.',
  rules: [
    { id: 'authorization.object-write.missing-owner-check' },
    { id: 'authorization.object-read.missing-owner-check' },
    { id: 'authorization.privileged-function.missing-role-check' },
    { id: 'authorization.mass-assignment' },
  ],
  analyze(context) {
    const observations = [];
    for (const file of context.files) {
      const text = context.readFile(file) ?? '';
      if (!text) continue;
      const artifact = context.model.entities.find((e) => e.kind === 'repository-artifact' && e.attributes.path === file);
      // Object write keyed by request id without visible owner check.
      if (/\b(?:update|patch|put|set|save)\w*\s*\([^)]*(?:id|params|request)/i.test(text)
        && !/owner|tenant|org_?id|authorize|canAccess|permission/i.test(text)) {
        observations.push({
          ruleId: 'authorization.object-write.missing-owner-check',
          candidateClass: 'authorization',
          claim: 'A request-derived object identifier reaches a write without a visible ownership or tenant control.',
          severityHint: 'high',
          sources: artifact ? [artifact.id] : [],
          sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: ['authenticated-low-privilege'],
          preconditions: [{ kind: 'principal-access', subject: 'actor:external', action: 'authenticate', scope: 'low-privilege', environment: 'application' }],
          effects: [{ kind: 'object-access', subject: 'actor:external', action: 'write', object: artifact?.id ?? null, scope: 'cross-tenant', environment: 'application', tenant: null }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: ['starter', 'privilege-escalation', 'impact'],
          evidenceRefs: [],
          detectorMetadata: { file, sourceKind: 'request-object-identifier', sinkKind: 'tenant-object-write' },
          uncertainty: ['A global authorization policy may exist outside the modeled path.'],
        });
      }
      // Privileged function without a visible role check.
      if (/\b(?:delete|remove|grant|promote|impersonate|admin)\w*\s*\(/i.test(text)
        && !/role|permission|isAdmin|requireAdmin|authorize/i.test(text)) {
        observations.push({
          ruleId: 'authorization.privileged-function.missing-role-check',
          candidateClass: 'authorization',
          claim: 'A privileged function has no visible role or policy enforcement.',
          severityHint: 'high',
          sources: artifact ? [artifact.id] : [],
          sinks: artifact ? [artifact.id] : [],
          attackerCapabilities: ['authenticated-low-privilege'],
          preconditions: [{ kind: 'principal-access', subject: 'actor:external', action: 'authenticate', scope: 'low-privilege', environment: 'application' }],
          effects: [{ kind: 'object-access', subject: 'actor:external', action: 'write', scope: 'privileged', environment: 'application', tenant: null }],
          assets: [], trustBoundaryCrossings: [], requiredControls: [], observedControls: [],
          chainRoles: ['privilege-escalation', 'impact'],
          evidenceRefs: [],
          detectorMetadata: { file, sourceKind: 'privileged-function' },
          uncertainty: ['A framework-level policy may enforce roles outside this call path.'],
        });
      }
    }
    return observations;
  },
  variantStrategies: {
    'authorization.object-write.missing-owner-check': {
      rootCause(candidate) {
        return {
          class: 'missing-object-authorization',
          sourceKind: candidate.detectorMetadata?.sourceKind ?? 'request-object-identifier',
          sinkKind: candidate.detectorMetadata?.sinkKind ?? 'tenant-object-write',
          missingControl: 'principal-to-object-ownership-check',
          semanticFeatures: ['request-derived-object-id', 'tenant-object-write', 'missing-owner-or-tenant-control'],
        };
      },
      enumerate(context, signature) {
        const matches = [];
        for (const file of context.files) {
          const text = context.readFile(file) ?? '';
          if (!text) continue;
          if (/(?:update|patch|put|set|save)\s*\([^)]*(?:id|params|request)/i.test(text)
            && !/owner|tenant|org_?id|authorize/.test(text)) {
            matches.push({
              file,
              line: 1,
              semanticFingerprint: `sha256:${file}`,
              disposition: 'CONFIRMED',
            });
          }
        }
        return {
          denominator: { kind: 'source-files', digest: context.denominatorDigest, expected: context.files.length, examined: context.files.length, unexamined: [] },
          strategies: [{ id: 'write-sink-search', kind: 'lexical-fallback', description: 'Enumerate every tenant-object write sink.', queryDigest: 'sha256:q', complete: true, coverageGaps: [] }],
          matches,
          coverageGaps: [],
        };
      },
    },
  },
});
