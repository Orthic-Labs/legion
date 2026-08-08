// Release manifests bind every distributable byte to a version and source
// revision.  They intentionally model absent channels as BLOCKED evidence.

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';

export function sha256(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function fileDigest(path) {
  return existsSync(path) ? sha256(readFileSync(path)) : null;
}

export function safeRelativePath(root, path) {
  const value = relative(root, resolve(root, path));
  if (!value || value === '..' || value.startsWith(`..${sep}`) || value.includes('\0')) {
    throw new Error(`release artifact path escapes distribution root: ${path}`);
  }
  return value.split(sep).join('/');
}

const bindRecords = (root, records) => records.map((record) => {
  const path = safeRelativePath(root, record.path);
  return { ...record, path, digest: record.digest ?? fileDigest(resolve(root, path)) };
});

export function buildReleaseManifest({ root, version, sourceRevision, artifacts = [], channels = [], checksums = [], sboms = [], notices = [], signatures = [], notarization = [], qualificationArtifacts = [] }) {
  if (!root || !version || !sourceRevision) throw new Error('root, version, and sourceRevision are required');
  const normalized = artifacts.map((artifact) => {
    const path = safeRelativePath(root, artifact.path);
    const digest = artifact.digest ?? fileDigest(resolve(root, path));
    if (!digest) throw new Error(`release artifact is missing: ${path}`);
    return { ...artifact, path, digest };
  });
  return {
    schemaVersion: 1,
    kind: 'nemesis-release-manifest',
    version,
    sourceRevision,
    artifacts: normalized,
    checksums: bindRecords(root, checksums), sboms: bindRecords(root, sboms), notices: bindRecords(root, notices),
    signatures: bindRecords(root, signatures), notarization: bindRecords(root, notarization), qualificationArtifacts: bindRecords(root, qualificationArtifacts),
    channels: channels.map((channel) => ({ ...channel, decision: channel.decision ?? 'BLOCKED', artifacts: normalized.map((artifact) => ({ path: artifact.path, decision: channel.artifactDecisions?.[artifact.path] ?? channel.decision ?? 'BLOCKED' })) })),
  };
}
