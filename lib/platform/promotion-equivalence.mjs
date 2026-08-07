export function promotionEquivalence({ qaCandidate, promotedArtifacts = [] } = {}) {
  const checks = promotedArtifacts.map((artifact) => {
    const source = qaCandidate?.artifacts?.find((item) => item.id === artifact.sourceArtifactId || item.path === artifact.sourcePath);
    return { artifact: artifact.path ?? artifact.id, expectedDigest: source?.digest ?? null, actualDigest: artifact.digest ?? null,
      status: source?.digest && source.digest === artifact.digest ? 'pass' : source ? 'fail' : 'unproven' };
  });
  return { schemaVersion: 1, kind: 'nemesis-promotion-equivalence', qaCandidateDigest: qaCandidate?.digest ?? null, checks,
    status: checks.length && checks.every((check) => check.status === 'pass') ? 'pass' : checks.some((check) => check.status === 'fail') ? 'fail' : 'unproven' };
}
