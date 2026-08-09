const STATES = new Set(['deterministic-measured', 'interpretive-measured', 'experimental', 'unproven', 'unavailable']);

export function generateClaims(qualifications = []) {
  return qualifications.map((item) => {
    const state = item.state ?? 'unproven';
    if (!STATES.has(state)) throw new Error(`unknown claim state: ${state}`);
    const identity = { artifactDigest: item.artifactDigest, corpusDigest: item.corpusDigest, providerDigest: item.providerDigest };
    const expected = item.expectedIdentity ?? null;
    const qualified = Boolean(expected && identity.artifactDigest && identity.corpusDigest && identity.providerDigest && Object.keys(identity).every((key) => identity[key] === expected[key]));
    return {
      id: item.id,
      subject: item.subject,
      state: qualified ? state : 'unproven',
      qualification: qualified ? identity : null,
      limitations: item.limitations ?? (qualified ? [] : (expected ? ['qualification identity mismatch'] : ['qualification identity incomplete'])),
      hostCapabilities: item.hostCapabilities ?? [],
      resourceConstraints: item.resourceConstraints ?? {},
      reasoningRequirements: item.reasoningRequirements ?? [],
      authorityLimits: item.authorityLimits ?? [],
    };
  });
}

export function renderSupportMarkdown(claims = []) {
  return `# Generated support claims\n\n${claims.map((claim) => `- **${claim.subject ?? claim.id}** — ${claim.state}${claim.limitations.length ? `; limitations: ${claim.limitations.join(', ')}` : ''}`).join('\n')}\n`;
}

export function generateClaimsFromQualification(qualification, expectedIdentity) {
  const records = qualification?.claims ?? qualification?.features ?? [];
  return {
    schemaVersion: 1,
    kind: 'legion-generated-claims',
    qualificationIdentity: expectedIdentity ?? null,
    claims: generateClaims(records.map((record) => ({ ...record, expectedIdentity }))),
    knownGaps: expectedIdentity ? [] : ['exact qualification identity is absent'],
  };
}
