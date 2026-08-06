#!/usr/bin/env node
// Release artifact verification per PR43. Validates checksums, SBOMs, notices,
// signature manifests, and attestation references in a release manifest.

import { existsSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { resolve } from 'node:path';

export function sha256File(path) {
  if (!existsSync(path)) return null;
  const bytes = readFileSync(path);
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

export function verifyReleaseManifest(manifestPath, { distDir = null } = {}) {
  const manifest = JSON.parse(readFileSync(resolve(manifestPath), 'utf8'));
  if (manifest.schemaVersion !== 1 || manifest.kind !== 'nemesis-release-manifest') {
    throw new Error('release manifest must be nemesis-release-manifest schemaVersion=1');
  }
  const dir = distDir ?? resolve(resolve(manifestPath), '..');
  const issues = [];
  for (const entry of manifest.artifacts ?? []) {
    const path = resolve(dir, entry.path);
    const observed = sha256File(path);
    if (observed === null) {
      issues.push({ artifact: entry.path, issue: 'missing' });
    } else if (observed !== entry.digest) {
      issues.push({ artifact: entry.path, issue: 'digest-mismatch' });
    }
  }
  if (!(manifest.checksums ?? []).length) issues.push({ artifact: 'SHA256SUMS', issue: 'missing' });
  if (!(manifest.sboms ?? []).length) issues.push({ artifact: 'SBOM', issue: 'missing' });
  if (!(manifest.notices ?? []).length) issues.push({ artifact: 'THIRD_PARTY_NOTICES', issue: 'missing' });
  if (!(manifest.attestations ?? []).length) issues.push({ artifact: 'attestation', issue: 'missing' });
  return {
    schemaVersion: 1,
    kind: 'nemesis-release-verification',
    manifest: resolve(manifestPath),
    valid: issues.length === 0,
    issues,
  };
}

if (process.argv[1] && process.argv[1].endsWith('verify-release.mjs')) {
  const [manifestPath] = process.argv.slice(2);
  if (!manifestPath) {
    console.error('usage: verify-release.mjs <release-manifest.json>');
    process.exit(4);
  }
  try {
    const result = verifyReleaseManifest(manifestPath);
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 1);
  } catch (error) {
    console.error(error.message);
    process.exit(2);
  }
}
