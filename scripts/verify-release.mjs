#!/usr/bin/env node
// Release artifact verification per PR43. Validates checksums, SBOMs, notices,
// signature manifests, and attestation references in a release manifest.

import { existsSync, readFileSync } from 'node:fs';
import { relative, resolve, sep } from 'node:path';
import { fileDigest } from '../src/lib/distribution/release-manifest.mjs';

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
    else if (!record.digest) issues.push({ artifact: record.path, issue: 'digest-missing' });
    else if (sha256File(path) !== record.digest) issues.push({ artifact: record.path, issue: 'digest-mismatch' });
  }
}

export function verifyReleaseManifest(manifestPath, { distDir = null } = {}) {
  const manifest = JSON.parse(readFileSync(resolve(manifestPath), 'utf8'));
  return verifyReleaseManifestObject(manifest, { root: resolve(distDir ?? resolve(resolve(manifestPath), '..')), manifestPath });
}

export function verifyReleaseManifestObject(manifest, { root, manifestPath = null } = {}) {
  if (manifest.schemaVersion !== 1 || manifest.kind !== 'legion-release-manifest') {
    throw new Error('release manifest must be legion-release-manifest schemaVersion=1');
  }
  const dir = resolve(root);
  const issues = [];
  for (const entry of manifest.artifacts ?? []) {
    const path = resolvedArtifact(dir, entry.path);
    if (!path) { issues.push({ artifact: entry.path, issue: 'path-escape' }); continue; }
    const observed = sha256File(path);
    if (observed === null) {
      issues.push({ artifact: entry.path, issue: 'missing' });
    } else if (!entry.digest) {
      issues.push({ artifact: entry.path, issue: 'digest-missing' });
    } else if (observed !== entry.digest) {
      issues.push({ artifact: entry.path, issue: 'digest-mismatch' });
    }
  }
  for (const [field, label] of [['checksums', 'SHA256SUMS'], ['sboms', 'SBOM'], ['notices', 'THIRD_PARTY_NOTICES'], ['signatures', 'signature'], ['notarization', 'notarization'], ['qualificationArtifacts', 'qualification']]) {
    if (!(manifest[field] ?? []).length) issues.push({ artifact: label, issue: 'missing' });
    else verifyReferenced(dir, manifest[field], label, issues);
  }
  for (const entry of manifest.sboms ?? []) {
    const path = resolvedArtifact(dir, entry.path);
    if (path && existsSync(path)) {
      try { const value = JSON.parse(readFileSync(path, 'utf8')); if (!(value.components ?? value.packages ?? []).length) issues.push({ artifact: entry.path, issue: 'empty-sbom' }); }
      catch { issues.push({ artifact: entry.path, issue: 'invalid-sbom' }); }
    }
  }
  for (const signature of manifest.signatures ?? []) {
    if (!signature.digest) issues.push({ artifact: signature.path ?? 'signature', issue: 'signature-digest-missing' });
    if (signature.status == null || signature.status === 'placeholder' || signature.status === 'missing') issues.push({ artifact: signature.path ?? 'signature', issue: 'placeholder-signature' });
  }
  for (const entry of manifest.notarization ?? []) {
    if (!entry.digest) issues.push({ artifact: entry.path ?? 'notarization', issue: 'notarization-digest-missing' });
    if (entry.status == null || entry.status === 'placeholder' || entry.status === 'missing') issues.push({ artifact: entry.path ?? 'notarization', issue: 'notarization-status-unresolved' });
  }
  for (const artifact of manifest.artifacts ?? []) {
    if (artifact.type === 'native' && !artifact.platform) issues.push({ artifact: artifact.path, issue: 'platform-missing' });
    if (artifact.semanticEquivalent === false) issues.push({ artifact: artifact.path, issue: 'semantic-equivalence-failed' });
  }
  for (const channel of manifest.channels ?? []) if ((channel.artifacts ?? []).length !== (manifest.artifacts ?? []).length) issues.push({ artifact: channel.id ?? 'channel', issue: 'artifact-decision-missing' });
  if (!manifest.version || !manifest.sourceRevision) issues.push({ artifact: 'manifest', issue: 'identity-missing' });
  return {
    schemaVersion: 1,
    kind: 'legion-release-verification',
    manifest: manifestPath ? resolve(manifestPath) : null,
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
