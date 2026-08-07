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

export function buildReleaseManifest({ root, version, sourceRevision, artifacts = [], channels = [] }) {
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
    channels: channels.map((channel) => ({ ...channel, decision: channel.decision ?? 'BLOCKED' })),
  };
}
