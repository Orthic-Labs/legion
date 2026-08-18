import { sha256 } from './contracts.mjs';

export function createReleaseCandidate(input = {}) {
  const artifacts = (input.artifacts ?? []).map((artifact) => ({ ...artifact, digest: artifact.digest ?? null }));
  const missing = artifacts.filter((artifact) => !artifact.path || !artifact.digest).map((artifact) => artifact.path ?? 'unknown');
  return { schemaVersion: 1, kind: 'legion-release-candidate', sourceRevision: input.sourceRevision ?? null, buildId: input.buildId ?? null,
    version: input.version ?? null, toolchain: input.toolchain ?? {}, configuration: input.configuration ?? {}, dependencies: input.dependencies ?? {},
    backendEnvironment: input.backendEnvironment ?? null, artifacts, signatures: input.signatures ?? [], storeIdentity: input.storeIdentity ?? null,
    promotionChannel: input.promotionChannel ?? null, binding: input.binding ?? {}, complete: missing.length === 0, coverageGaps: missing.map((path) => ({ kind: 'artifact-digest-missing', path })),
    digest: sha256({ sourceRevision: input.sourceRevision ?? null, buildId: input.buildId ?? null, artifacts }) };
}

export function verifyCandidateArtifact(candidate, artifact) {
  const expected = candidate.artifacts?.find((item) => item.path === artifact.path || item.id === artifact.id);
  if (!expected) return { status: 'unproven', reason: 'artifact-not-in-candidate' };
  if (!expected.digest || expected.digest !== artifact.digest) return { status: 'fail', reason: 'artifact-digest-mismatch', expected: expected.digest ?? null, actual: artifact.digest ?? null };
  return { status: 'pass', artifact: expected.path };
}
