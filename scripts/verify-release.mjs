#!/usr/bin/env node
// Release artifact verification per PR43. Validates checksums, SBOMs, notices,
// signature manifests, and attestation references in a release manifest.

import { existsSync, readFileSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';
import { fileDigest } from '../lib/distribution/release-manifest.mjs';

export function sha256File(path) {
  return fileDigest(path);
}

function resolvedArtifact(root, path) {
  if (typeof path !== 'string' || !path || path.includes('\0')) return null;
  const absolute = resolve(root, path);
  const rel = relative(root, absolute);
  return rel && rel !== '..' && !rel.startsWith(`..${sep}`) ? absolute : null;
}

function verifyReferenced(root, entries, type, issues) {
  for (const entry of entries ?? []) {
    const record = typeof entry === 'string' ? { path: entry } : entry;
    const path = resolvedArtifact(root, record.path);
    if (!path || !existsSync(path)) issues.push({ artifact: record.path ?? type, issue: 'missing' });
    else if (record.digest && sha256File(path) !== record.digest) issues.push({ artifact: record.path, issue: 'digest-mismatch' });
  }
}

export function verifyReleaseManifest(manifestPath, { distDir = null } = {}) {
  const manifest = JSON.parse(readFileSync(resolve(manifestPath), 'utf8'));
  if (manifest.schemaVersion !== 1 || manifest.kind !== 'nemesis-release-manifest') {
    throw new Error('release manifest must be nemesis-release-manifest schemaVersion=1');
  }
  const dir = resolve(distDir ?? resolve(resolve(manifestPath), '..'));
  const issues = [];
  for (const entry of manifest.artifacts ?? []) {
    const path = resolvedArtifact(dir, entry.path);
    if (!path) { issues.push({ artifact: entry.path, issue: 'path-escape' }); continue; }
    const observed = sha256File(path);
    if (observed === null) {
      issues.push({ artifact: entry.path, issue: 'missing' });
    } else if (observed !== entry.digest) {
      issues.push({ artifact: entry.path, issue: 'digest-mismatch' });
    }
  }
  for (const [field, label] of [['checksums', 'SHA256SUMS'], ['sboms', 'SBOM'], ['notices', 'THIRD_PARTY_NOTICES'], ['attestations', 'attestation']]) {
    if (!(manifest[field] ?? []).length) issues.push({ artifact: label, issue: 'missing' });
    else verifyReferenced(dir, manifest[field], label, issues);
  }
  if (!manifest.version || !manifest.sourceRevision) issues.push({ artifact: 'manifest', issue: 'identity-missing' });
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
